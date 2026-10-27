/**
 * `mission_endpoint`: propose with deterministic approval, the exact-byte
 * blob and its `s256` (AAuth -11 Section 8.2), and the owner's read of
 * `{mission_endpoint}/{mission_s256}` with ownership-first confinement
 * (Section 8.7; the binding's Native Reference rule; fixture P1).
 */
import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { rfc3339 } from "../src/index.js";
import {
  type Agent,
  approve,
  claims,
  HELPER,
  issuedCount,
  makeAgent,
  PLANNER,
  propose,
  RS,
  RS2,
  STRANGER,
  shape,
  signed,
  type World,
  world,
} from "./helpers.js";

let w: World;
let assistant: Agent;
let planner: Agent;

beforeEach(async () => {
  w = await world();
  assistant = await makeAgent(w.ap, w.clock);
  planner = await makeAgent(w.ap, w.clock, PLANNER);
});
afterEach(async () => {
  await w.close();
});

const decode = (mission: string) => Buffer.from(mission, "base64url");
const blobOf = (mission: string) => JSON.parse(decode(mission).toString("utf8"));
const read = (agent: Agent, s256: string) =>
  signed(w.clock, "GET", `${w.origin}/mission/${s256}`, agent);

describe("mission_endpoint: propose and approve", () => {
  it("returns s256 as the SHA-256 of the exact bytes mission decodes to", async () => {
    const r = await propose(w, assistant, {
      description: "# Quarterly report\n\nSummarize   the report.",
      tools: [{ name: "Read", description: "Read files" }],
    });
    expect(r.status).toBe(200);
    const bytes = decode(r.body.mission as string);
    expect(createHash("sha256").update(bytes).digest("base64url")).toBe(r.body.s256);
    const blob = blobOf(r.body.mission as string);
    expect(blob.agent).toBe(assistant.id);
    expect(blob.description).toBe("# Quarterly report\n\nSummarize   the report.");
    expect(blob.approved_tools).toEqual([{ name: "Read", description: "Read files" }]);
    expect(typeof blob.approved_at).toBe("string");
  });

  it("persists the bytes it returned and serves the same bytes to the owner", async () => {
    const approval = await approve(w, assistant);
    const r = await read(assistant, approval.s256);
    expect(r.status).toBe(200);
    expect(r.body).toEqual({ s256: approval.s256, mission: approval.mission });
  });

  it("returns a recorded, Mission-bound person token for each proposed resource", async () => {
    const r = await propose(w, assistant, {
      description: "Compare two reports",
      resources: [RS, RS2],
    });
    expect(r.status).toBe(200);
    const tokens = r.body.person_tokens as Record<string, string>;
    expect(Object.keys(tokens).sort()).toEqual([RS, RS2]);
    for (const [resource, jwt] of Object.entries(tokens)) {
      const c = claims(jwt);
      expect(c.aud).toBe(resource);
      expect(c.mission_s256).toBe(r.body.s256);
    }
    expect(blobOf(r.body.mission as string).approved_resources).toEqual([RS, RS2]);
    const records = w.ps.store.issuedTokens();
    expect(records.map((t) => t.jti).sort()).toEqual(
      Object.values(tokens)
        .map((jwt) => claims(jwt).jti)
        .sort(),
    );
    expect(records.every((t) => t.kind === "person" && t.missionS256 === r.body.s256)).toBe(true);
  });

  it("omits person_tokens when the proposal names no resources", async () => {
    const r = await propose(w, assistant, { description: "Summarize the report" });
    expect(r.status).toBe(200);
    expect(r.body.person_tokens).toBeUndefined();
    expect(issuedCount(w)).toBe(0);
  });

  it("sets expires_at from deployment policy when the proposal requests none", async () => {
    const r = await propose(w, assistant, { description: "Summarize the report" });
    expect(blobOf(r.body.mission as string).expires_at).toBe(rfc3339(w.clock.s + 86400));
  });

  it("approves a requested expires_at within the maximum", async () => {
    const requested = rfc3339(w.clock.s + 7200);
    const r = await propose(w, assistant, { description: "Summarize", expires_at: requested });
    expect(blobOf(r.body.mission as string).expires_at).toBe(requested);
  });

  it("caps a requested expires_at at the deployment maximum", async () => {
    const r = await propose(w, assistant, {
      description: "Summarize",
      expires_at: rfc3339(w.clock.s + 30 * 86400),
    });
    expect(blobOf(r.body.mission as string).expires_at).toBe(rfc3339(w.clock.s + 604800));
  });

  it("refuses an expires_at not later than approval: invalid_request", async () => {
    const r = await propose(w, assistant, {
      description: "Summarize",
      expires_at: rfc3339(w.clock.s - 60),
    });
    expect(r.status).toBe(400);
    expect(r.body.error).toBe("invalid_request");
    expect(r.body.detail).toBe("expires_at is not later than approval");
  });

  it("refuses an expires_at that is not an RFC 3339 date-time: invalid_request", async () => {
    const r = await propose(w, assistant, { description: "Summarize", expires_at: "tomorrow" });
    expect(r.status).toBe(400);
    expect(r.body.detail).toBe("expires_at is not an RFC 3339 date-time");
  });

  it("refuses a proposal without a description: invalid_request", async () => {
    const r = await propose(w, assistant, { tools: [] });
    expect(r.status).toBe(400);
    expect(r.body).toEqual({ error: "invalid_request", detail: "description is required" });
  });

  it("refuses a resource that is not a server identifier: invalid_request", async () => {
    const r = await propose(w, assistant, {
      description: "Summarize",
      resources: ["https://rs.test:8443"],
    });
    expect(r.status).toBe(400);
    expect(r.body.detail).toBe("each resource must be a server identifier");
    expect(issuedCount(w)).toBe(0);
  });

  it("refuses an agent the allowlist does not name: user_unreachable", async () => {
    const stranger = await makeAgent(w.ap, w.clock, STRANGER);
    const r = await propose(w, stranger, { description: "Summarize", resources: [RS] });
    expect(r.status).toBe(403);
    expect(r.body.error).toBe("user_unreachable");
    expect(r.headers.get("signature-error")).toBeNull();
    expect(issuedCount(w)).toBe(0);
  });

  it("denies a description a deny rule matches, case-insensitively: denied", async () => {
    const r = await propose(w, assistant, {
      description: "Make a Wire Transfer to the vendor",
      resources: [RS],
    });
    expect(r.status).toBe(403);
    expect(r.body).toEqual({ error: "denied", detail: "the approver denied the mission proposal" });
    expect(issuedCount(w)).toBe(0);
  });
});

describe("mission_endpoint: the default decision", () => {
  it("denies when no rule matches and the default is deny, and an approve rule admits", async () => {
    await w.close();
    w = await world({
      config: (doc) => {
        doc.default_decision = "deny";
        doc.description_rules = [{ contains: "report", decision: "approve" }];
      },
    });
    assistant = await makeAgent(w.ap, w.clock);
    expect((await propose(w, assistant, { description: "Book a flight" })).status).toBe(403);
    expect((await propose(w, assistant, { description: "Summarize the report" })).status).toBe(200);
  });
});

describe("{mission_endpoint}/{mission_s256}: the owner's read", () => {
  it("refuses a malformed path segment: invalid_request", async () => {
    const r = await read(assistant, "not-a-digest");
    expect(r.status).toBe(400);
    expect(r.body).toEqual({
      error: "invalid_request",
      detail: "the mission_s256 path segment is malformed",
    });
  });

  it("answers an absent mission with mission_not_found", async () => {
    const r = await read(assistant, createHash("sha256").update("absent").digest("base64url"));
    expect(r.status).toBe(404);
    expect(r.body).toEqual({ error: "mission_not_found", detail: "no such mission" });
  });

  it("P1: answers another agent's active mission exactly as an absent one", async () => {
    const theirs = await approve(w, planner);
    const absent = await read(assistant, createHash("sha256").update("absent").digest("base64url"));
    const foreign = await read(assistant, theirs.s256);
    expect(shape(foreign)).toEqual(shape(absent));
  });

  it("P1: answers another agent's terminated mission exactly as an absent one, never mission_terminated", async () => {
    const theirs = await approve(w, planner);
    w.ps.store.terminate(PLANNER, theirs.s256, "revoked", w.clock.s);
    const absent = await read(assistant, createHash("sha256").update("absent").digest("base64url"));
    const foreign = await read(assistant, theirs.s256);
    expect(shape(foreign)).toEqual(shape(absent));
    expect(foreign.body.error).toBe("mission_not_found");
  });

  it("tells the owner its mission terminated, with the reason", async () => {
    const mine = await approve(w, assistant);
    w.ps.store.terminate(assistant.id, mine.s256, "revoked", w.clock.s);
    const r = await read(assistant, mine.s256);
    expect(r.status).toBe(403);
    expect(r.body).toEqual({
      error: "mission_terminated",
      detail: "the mission is no longer active",
      mission_status: "terminated",
      termination_reason: "revoked",
    });
  });

  it("treats the owner's mission past expires_at as terminated, reason expired, and records it", async () => {
    const mine = await approve(w, assistant, {
      description: "Summarize",
      expires_at: rfc3339(w.clock.s + 120),
    });
    w.clock.advance(120);
    const r = await read(assistant, mine.s256);
    expect(r.status).toBe(403);
    expect(r.body.termination_reason).toBe("expired");
    expect(w.ps.store.findOwnedMission(assistant.id, mine.s256)?.state).toBe("terminated");
  });

  it("fails closed when the persisted blob no longer digests to its s256", async () => {
    const mine = await approve(w, assistant);
    w.faults.tamperBlobs = true;
    const r = await read(assistant, mine.s256);
    expect(r.status).toBe(500);
    expect(r.body).toEqual({ error: "server_error", detail: "mission state is unavailable" });
    expect(w.ps.securityEvents.map((e) => e.type)).toContain("mission_integrity_failure");
  });

  it("does not implement update or completion: POST at the mission URL is 405", async () => {
    const mine = await approve(w, assistant);
    const r = await signed(w.clock, "POST", `${w.origin}/mission/${mine.s256}`, assistant, {
      action: "update",
      description: "changed",
    });
    expect(r.status).toBe(405);
    expect(r.headers.get("allow")).toBe("GET");
  });

  it("serves missions to their owner whatever the agent's governance mode", async () => {
    const helper = await makeAgent(w.ap, w.clock, HELPER);
    const mine = await approve(w, helper);
    expect((await read(helper, mine.s256)).status).toBe(200);
  });
});
