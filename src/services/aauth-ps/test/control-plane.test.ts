/**
 * The mission control plane (AAuth Mission Management): `status` and
 * `terminate` at `{mission_control_endpoint}/{mission_s256}` for the
 * owning agent and configured administrators; anti-oracle equivalence for
 * absent and unauthorized references (fixture P2); the request checks;
 * the atomic, idempotent, serialized transition and its log; and local
 * gating from the moment termination commits. Every refusal leaves the
 * mission, its log, its revocation work and the issued tokens unchanged.
 */
import { createHash, randomUUID } from "node:crypto";
import { JwksResolver, signRequest } from "@mission/aauth-wire";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { rfc3339, SCHEDULER } from "../src/index.js";
import {
  ADMIN,
  type Admin,
  type Agent,
  ASSISTANT,
  approve,
  claims,
  control,
  HELPER,
  issuedCount,
  makeAdmin,
  makeAgent,
  observable,
  PLANNER,
  personToken,
  prepare,
  prepareAdmin,
  type Reply,
  RS,
  requestAuthToken,
  requestPersonToken,
  resourceTokenFor,
  STRANGER,
  send,
  signed,
  terminateBody,
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
  vi.restoreAllMocks();
  await w.close();
});

const absent = createHash("sha256").update("no such mission").digest("base64url");
const url = (s256: string) => `${w.origin}/mission-control/${s256}`;
const blobOf = (mission: string) =>
  JSON.parse(Buffer.from(mission, "base64url").toString("utf8")) as Record<string, string>;

/** Everything a refusal must leave as it was. */
function snapshot(s256: string) {
  return {
    mission: w.durable.findOwnedMission(blobAgent(s256), s256),
    log: w.durable.missionLog(s256),
    revocations: w.durable.revocations(s256),
    issued: w.durable.issuedTokens(),
  };
}
const owners = new Map<string, string>();
const blobAgent = (s256: string) => owners.get(s256) ?? ASSISTANT;

async function mission(agent: Agent, proposal?: Record<string, unknown>) {
  const approval = await approve(w, agent, proposal);
  owners.set(approval.s256, agent.id);
  return approval;
}

function refusedWith(r: Reply, status: number, error: string): void {
  expect(r.status, JSON.stringify(r.body)).toBe(status);
  expect(r.body.error).toBe(error);
  expect(r.body).not.toHaveProperty("mission_status");
}

describe("control plane: status", () => {
  it("reports an active mission's lifecycle facts to its owning agent, and no more", async () => {
    const { s256, mission: bytes } = await mission(assistant);
    const blob = blobOf(bytes);
    const r = await control(w, assistant, s256, { action: "status" });
    expect(r.status).toBe(200);
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(r.body).toEqual({
      mission_s256: s256,
      mission_status: "active",
      approved_at: blob.approved_at,
      expires_at: blob.expires_at,
      observed_at: rfc3339(w.clock.s),
      fresh_until: rfc3339(w.clock.s + 30),
      accepted_updates: 0,
    });
    const read = w.durable.missionLog(s256).at(-1);
    expect(read).toEqual({
      s256,
      at: w.clock.s,
      event: "status_read",
      detail: {
        actor: { id: ASSISTANT, role: "owning_agent" },
        decision: "permit",
        policy: "owning-agent",
      },
    });
  });

  it("reports a terminated mission's reason, time and token residual", async () => {
    const { s256 } = await mission(assistant);
    const at = w.clock.s;
    w.durable.terminate(ASSISTANT, s256, "revoked", at);
    const r = await control(w, assistant, s256, { action: "status" });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({
      mission_status: "terminated",
      terminated_at: rfc3339(at),
      termination_reason: "revoked",
      accepted_updates: 0,
      token_residual: {
        tracked: 0,
        revocation_attempted: 0,
        revocation_confirmed: 0,
        complete: true,
      },
    });
    expect(r.body).not.toHaveProperty("latest_update_s256");
    expect(r.body).not.toHaveProperty("mission");
  });

  it("applies expiry before reading state, attributed to the PS scheduler", async () => {
    const expiresAt = w.clock.s + 100;
    const { s256 } = await mission(assistant, {
      description: "Summarize",
      expires_at: rfc3339(expiresAt),
    });
    w.clock.advance(200);
    const r = await control(w, assistant, s256, { action: "status" });
    expect(r.body).toMatchObject({
      mission_status: "terminated",
      termination_reason: "expired",
      terminated_at: rfc3339(expiresAt),
    });
    const ended = w.durable.missionLog(s256).find((e) => e.event === "terminated");
    expect(ended?.at).toBe(expiresAt);
    expect(ended?.detail).toEqual({
      reason: "expired",
      actor: SCHEDULER,
      decision: "permit",
      policy: "expires_at",
    });
  });

  it("attributes an expiry an issuance endpoint finds to the PS scheduler as well", async () => {
    const expiresAt = w.clock.s + 100;
    const { s256 } = await mission(assistant, {
      description: "Summarize",
      expires_at: rfc3339(expiresAt),
    });
    w.clock.advance(200);
    const r = await requestPersonToken(w, assistant, { resource: RS, mission_s256: s256 });
    expect([r.status, r.body.termination_reason]).toEqual([403, "expired"]);
    expect(w.durable.missionLog(s256).find((e) => e.event === "terminated")).toEqual({
      s256,
      at: expiresAt,
      event: "terminated",
      detail: { reason: "expired", actor: SCHEDULER, decision: "permit", policy: "expires_at" },
    });
  });

  it("answers an administrator for a mission of a person it governs, and logs it as such", async () => {
    const { s256 } = await mission(assistant);
    const r = await control(w, w.admins.alice, s256, { action: "status" });
    expect(r.status).toBe(200);
    expect(r.body.mission_status).toBe("active");
    expect(w.durable.missionLog(s256).at(-1)?.detail).toEqual({
      actor: { id: ADMIN, role: "administrator" },
      decision: "permit",
      policy: `administrator:${ADMIN}`,
    });
  });

  it("lets a status-only administrator read but never terminate", async () => {
    const { s256 } = await mission(assistant);
    expect((await control(w, w.admins.auditor, s256, { action: "status" })).status).toBe(200);
    const before = snapshot(s256);
    const r = await control(
      w,
      w.admins.auditor,
      s256,
      terminateBody("administrative", { purpose: "x" }),
    );
    refusedWith(r, 404, "mission_not_found");
    expect(snapshot(s256)).toEqual(before);
  });
});

describe("control plane: an absent mission and an unauthorized one are answered alike (P2)", () => {
  it("within the owning-agent class: another agent's mission, active or terminated, a stranger, a sub-agent", async () => {
    const mine = await mission(assistant);
    const theirs = await mission(planner);
    const ended = await mission(planner, { description: "Plan the offsite" });
    w.durable.terminate(PLANNER, ended.s256, "revoked", w.clock.s);
    const stranger = await makeAgent(w.ap, w.clock, STRANGER);
    const sub = await makeAgent(w.ap, w.clock, ASSISTANT, { parent_agent: "aauth:root@ap.test" });
    const before = [snapshot(theirs.s256), snapshot(ended.s256), snapshot(mine.s256)];

    const baseline = observable(await control(w, assistant, absent, { action: "status" }));
    expect(baseline.status).toBe(404);
    expect(JSON.parse(baseline.text)).toEqual({
      error: "mission_not_found",
      detail: "no such mission",
    });
    const probes: Reply[] = [
      await control(w, assistant, theirs.s256, { action: "status" }),
      await control(w, assistant, ended.s256, { action: "status" }),
      await control(w, assistant, theirs.s256, terminateBody()),
      await control(w, stranger, mine.s256, { action: "status" }),
      await control(w, sub, mine.s256, { action: "status" }),
      await control(w, sub, mine.s256, terminateBody()),
    ];
    for (const probe of probes) expect(observable(probe)).toEqual(baseline);
    expect([snapshot(theirs.s256), snapshot(ended.s256), snapshot(mine.s256)]).toEqual(before);
  });

  it("within the administrator class: a person outside its scope, and an action it lacks", async () => {
    const alices = await mission(assistant);
    const bobs = await mission(await makeAgent(w.ap, w.clock, HELPER));
    const before = snapshot(alices.s256);
    const baseline = observable(await control(w, w.admins.bob, absent, { action: "status" }));
    expect(baseline.status).toBe(404);
    const probes = [
      await control(w, w.admins.bob, alices.s256, { action: "status" }),
      await control(
        w,
        w.admins.bob,
        alices.s256,
        terminateBody("administrative", { purpose: "probe" }),
      ),
      await control(w, w.admins.auditor, alices.s256, terminateBody("revoked", { purpose: "p" })),
    ];
    for (const probe of probes) expect(observable(probe)).toEqual(baseline);
    expect(snapshot(alices.s256)).toEqual(before);
    // Each administrator reaches its own person's missions, and only those.
    expect((await control(w, w.admins.bob, bobs.s256, { action: "status" })).status).toBe(200);
    expect(observable(await control(w, w.admins.alice, bobs.s256, { action: "status" }))).toEqual(
      observable(await control(w, w.admins.alice, absent, { action: "status" })),
    );
  });

  it("admits no agent the allowlist has dropped, even for a mission it owns", async () => {
    const { s256 } = await mission(assistant);
    await w.restart({
      config: (doc) => {
        doc.agents = (doc.agents as { agent: string }[]).filter((a) => a.agent !== ASSISTANT);
      },
    });
    const baseline = observable(await control(w, assistant, absent, { action: "status" }));
    expect(baseline.status).toBe(404);
    expect(observable(await control(w, assistant, s256, { action: "status" }))).toEqual(baseline);
    expect(observable(await control(w, assistant, s256, terminateBody()))).toEqual(baseline);
    expect(w.durable.findOwnedMission(ASSISTANT, s256)?.state).toBe("active");
  });

  it("checks the request before any lookup, so a bad request says nothing about the mission", async () => {
    const theirs = await mission(planner);
    const baseline = observable(
      await control(w, assistant, absent, terminateBody("administrative")),
    );
    expect(baseline.status).toBe(400);
    expect(
      observable(await control(w, assistant, theirs.s256, terminateBody("administrative"))),
    ).toEqual(baseline);
  });

  it("surfaces a miss to operators under a keyed digest, never the reference itself", async () => {
    const theirs = await mission(planner);
    await control(w, assistant, theirs.s256, { action: "status" });
    const event = w.ps.securityEvents.at(-1);
    expect(event?.type).toBe("control_plane_miss");
    expect(event?.agent).toBe(ASSISTANT);
    expect(event?.detail).not.toContain(theirs.s256);
    expect(event?.detail).toMatch(/keyed digest [A-Za-z0-9_-]{22}\)$/);
  });
});

/** A control-plane POST whose body text is exactly `text`, signed by `agent`. */
function rawControl(agent: Agent, s256: string, text: string, contentType = "application/json") {
  w.clock.advance(1);
  const headers: Record<string, string> = { "content-type": contentType };
  const added = signRequest(
    { method: "POST", url: url(s256), headers, body: text },
    {
      alg: agent.key.alg,
      privateKey: agent.key.privateKey,
      signatureKey: { scheme: "jwt", jwt: agent.token },
      created: w.clock.s,
    },
  );
  return send("POST", url(s256), { headers: { ...headers, ...added }, body: text });
}

describe("control plane: request checks", () => {
  it("refuses a malformed path segment: invalid_request", async () => {
    refusedWith(
      await control(w, assistant, "not-a-digest", { action: "status" }),
      400,
      "invalid_request",
    );
    refusedWith(
      await control(w, w.admins.alice, `${absent}x`, { action: "status" }),
      400,
      "invalid_request",
    );
  });

  it("refuses a missing or unrecognized action, including one it does not advertise", async () => {
    const { s256 } = await mission(assistant);
    const before = snapshot(s256);
    const missing = await control(w, assistant, s256, {});
    refusedWith(missing, 400, "invalid_request");
    expect(missing.body.detail).toBe("action is required");
    for (const body of [{ action: "delegation_tree" }, { action: "pause" }, { action: 7 }]) {
      const r = await control(w, assistant, s256, body);
      refusedWith(r, 400, "invalid_request");
      expect(r.body.detail).toBe("action is not recognized");
    }
    expect(snapshot(s256)).toEqual(before);
  });

  it("refuses a body nested beyond its limit rather than scanning it", async () => {
    const { s256 } = await mission(assistant);
    const deep = `${"[".repeat(40)}${"]".repeat(40)}`;
    const r = await rawControl(assistant, s256, `{"action":"status","x":${deep}}`);
    refusedWith(r, 400, "invalid_request");
    expect(r.body.detail).toMatch(/too deep/);
    const shallow = `${"[".repeat(20)}${"]".repeat(20)}`;
    expect((await rawControl(assistant, s256, `{"action":"status","x":${shallow}}`)).status).toBe(
      200,
    );
  });

  it("refuses a body that carries mission_s256, even naming the path's own mission", async () => {
    const { s256 } = await mission(assistant);
    const before = snapshot(s256);
    refusedWith(
      await control(w, assistant, s256, { action: "status", mission_s256: s256 }),
      400,
      "invalid_request",
    );
    refusedWith(
      await control(w, assistant, s256, { ...terminateBody(), mission_s256: s256 }),
      400,
      "invalid_request",
    );
    expect(snapshot(s256)).toEqual(before);
  });

  it("refuses duplicate member names, which JSON.parse would silently resolve", async () => {
    const { s256 } = await mission(assistant);
    const before = snapshot(s256);
    const id = `t-${randomUUID().replaceAll("-", "")}`;
    const r = await rawControl(
      assistant,
      s256,
      `{"action":"status","action":"terminate","reason":"revoked","request_id":"${id}"}`,
    );
    refusedWith(r, 400, "invalid_request");
    expect(r.body.detail).toMatch(/duplicate member/);
    refusedWith(
      await rawControl(assistant, s256, `{"action":"status","\\u0061ction":"status"}`),
      400,
      "invalid_request",
    );
    expect(snapshot(s256)).toEqual(before);
    expect((await rawControl(assistant, s256, `{"action":"status"}`)).status).toBe(200);
  });

  it("refuses a body that is not application/json: invalid_request", async () => {
    const { s256 } = await mission(assistant);
    refusedWith(
      await rawControl(assistant, s256, `{"action":"status"}`, "text/plain"),
      400,
      "invalid_request",
    );
  });

  it("serves POST at a mission's own URL only", async () => {
    const { s256 } = await mission(assistant);
    const get = await signed(w.clock, "GET", url(s256), assistant);
    expect(get.status).toBe(405);
    expect(get.headers.get("allow")).toBe("POST");
    const bare = await signed(w.clock, "POST", `${w.origin}/mission-control`, assistant, {
      action: "status",
    });
    expect(bare.status).toBe(404);
  });

  it("authenticates every request: unsigned, uncovered body and empty body are 401", async () => {
    const { s256 } = await mission(assistant);
    const unsigned = await send("POST", url(s256), {
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ action: "status" }),
    });
    expect(unsigned.status).toBe(401);
    const uncovered = await signed(
      w.clock,
      "POST",
      url(s256),
      assistant,
      { action: "status" },
      {
        components: ["@method", "@authority", "@path", "signature-key", "content-digest"],
      },
    );
    expect(uncovered.status).toBe(401);
    expect(uncovered.body.error).toBe("invalid_input");
    // A body-less POST signed over the base components only: the control
    // plane requires Content-Digest and Content-Type on every request.
    const empty = await send("POST", url(s256), prepare(w.clock, "POST", url(s256), assistant));
    expect(empty.status).toBe(401);
    expect(empty.body.error).toBe("invalid_input");
  });

  it("admits an administrator only under its enrolled key, kid and document", async () => {
    const { s256 } = await mission(assistant);
    const body = { action: "status" };
    const asAdmin = (options: Parameters<typeof prepareAdmin>[4]) =>
      send("POST", url(s256), prepareAdmin(w.clock, url(s256), w.admins.alice, body, options));
    const wrongKid = await asAdmin({ kid: "admin-2" });
    expect([wrongKid.status, wrongKid.body.error]).toEqual([401, "unknown_key"]);
    const otherKey = await asAdmin({ key: makeAdmin(ADMIN).key });
    expect([otherKey.status, otherKey.body.error]).toEqual([401, "invalid_signature"]);
    const aauthDocument = await asAdmin({ dwk: "aauth-person.json" });
    expect([aauthDocument.status, aauthDocument.body.error]).toEqual([401, "invalid_key"]);
    const unregistered: Admin = makeAdmin("https://intruder.ps.test");
    const stranger = await control(w, unregistered, s256, body);
    expect([stranger.status, stranger.body.error]).toEqual([401, "unknown_key"]);
    // Another AAuth server signing in its own right is no administrator either.
    const ps2 = await send(
      "POST",
      url(s256),
      prepareAdmin(
        w.clock,
        url(s256),
        { id: w.ps2.id, dwk: "aauth-person.json", kid: w.ps2.kid, key: w.ps2.key },
        body,
      ),
    );
    expect([ps2.status, ps2.body.error]).toEqual([401, "invalid_key"]);
    expect((await asAdmin({})).status).toBe(200);
  });
});

describe("control plane: terminate", () => {
  it("commits the owning agent's revoked termination, logs it, and closes every issuance path", async () => {
    const approval = await mission(assistant, {
      description: "Summarize the quarterly report",
      resources: [RS],
    });
    const { s256 } = approval;
    const body = terminateBody("revoked", { purpose: "the work is done" });
    const r = await control(w, assistant, s256, body);
    const at = w.clock.s;
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({
      mission_s256: s256,
      mission_status: "terminated",
      terminated_at: rfc3339(at),
      termination_reason: "revoked",
      observed_at: rfc3339(at),
      fresh_until: rfc3339(at + 30),
      accepted_updates: 0,
      token_residual: {
        tracked: 1,
        revocation_attempted: 1,
        revocation_confirmed: 1,
        complete: true,
      },
    });
    const log = w.durable.missionLog(s256);
    const ended = log.filter((e) => e.event === "terminated");
    expect(ended).toEqual([
      {
        s256,
        at,
        event: "terminated",
        detail: {
          reason: "revoked",
          actor: { id: ASSISTANT, role: "owning_agent" },
          decision: "permit",
          policy: "owning-agent",
          request_id: body.request_id,
          purpose: "the work is done",
          token_impact: { tracked: 1, revocation_initiated: 1 },
        },
      },
    ]);
    expect(w.durable.findOwnedMission(ASSISTANT, s256)).toMatchObject({
      state: "terminated",
      terminationReason: "revoked",
      terminatedAt: at,
    });
    // Local gating: every PS endpoint other than the control plane refuses.
    const issued = issuedCount(w);
    const pt = await requestPersonToken(w, assistant, { resource: RS, mission_s256: s256 });
    expect([pt.status, pt.body.error, pt.body.termination_reason]).toEqual([
      403,
      "mission_terminated",
      "revoked",
    ]);
    const presented = approval.person_tokens?.[RS] as string;
    const at2 = await requestAuthToken(w, assistant, {
      resource_token: await resourceTokenFor(w, assistant, presented),
      presented_token: presented,
    });
    expect([at2.status, at2.body.error]).toEqual([403, "mission_terminated"]);
    const read = await signed(w.clock, "GET", `${w.origin}/mission/${s256}`, assistant);
    expect([read.status, read.body.error]).toEqual([403, "mission_terminated"]);
    expect(issuedCount(w)).toBe(issued);
    // The control plane answers terminal status instead.
    expect((await control(w, assistant, s256, { action: "status" })).body.termination_reason).toBe(
      "revoked",
    );
  });

  it("refuses a reason the caller's class may not give: invalid_termination_reason, nothing changes", async () => {
    const { s256 } = await mission(assistant);
    const before = snapshot(s256);
    for (const reason of ["administrative", "superseded", "completed", "expired", "paused"]) {
      refusedWith(
        await control(w, assistant, s256, terminateBody(reason)),
        400,
        "invalid_termination_reason",
      );
    }
    for (const reason of ["completed", "expired"]) {
      refusedWith(
        await control(w, w.admins.alice, s256, terminateBody(reason, { purpose: "p" })),
        400,
        "invalid_termination_reason",
      );
    }
    expect(snapshot(s256)).toEqual(before);
  });

  it("refuses missing or invalid members: invalid_request, nothing changes", async () => {
    const { s256 } = await mission(assistant);
    const before = snapshot(s256);
    const cases: [Agent | Admin, Record<string, unknown>][] = [
      [assistant, { action: "terminate", request_id: terminateBody().request_id }],
      [assistant, { action: "terminate", reason: "revoked" }],
      [assistant, terminateBody("revoked", { request_id: "short-id" })],
      [assistant, terminateBody("revoked", { request_id: `${"x".repeat(21)}` })],
      [assistant, terminateBody("revoked", { purpose: "" })],
      [assistant, terminateBody("revoked", { purpose: 5 })],
      [assistant, terminateBody("revoked", { replacement_s256: absent })],
      [w.admins.alice, terminateBody("administrative")],
      [w.admins.alice, terminateBody("superseded", { purpose: "p" })],
      [w.admins.alice, terminateBody("superseded", { purpose: "p", replacement_s256: "nope" })],
    ];
    for (const [caller, body] of cases) {
      refusedWith(await control(w, caller, s256, body), 400, "invalid_request");
    }
    expect(snapshot(s256)).toEqual(before);
    // 22 visible characters is enough.
    const ok = await control(
      w,
      assistant,
      s256,
      terminateBody("revoked", { request_id: "x".repeat(22) }),
    );
    expect(ok.status).toBe(200);
  });

  it("lets an administrator end a mission administrative, recording its purpose", async () => {
    const { s256 } = await mission(assistant);
    const body = terminateBody("administrative", { purpose: "policy breach review" });
    const r = await control(w, w.admins.alice, s256, body);
    expect(r.body).toMatchObject({
      mission_status: "terminated",
      termination_reason: "administrative",
    });
    expect(w.durable.missionLog(s256).find((e) => e.event === "terminated")?.detail).toMatchObject({
      actor: { id: ADMIN, role: "administrator" },
      policy: `administrator:${ADMIN}`,
      purpose: "policy breach review",
      request_id: body.request_id,
    });
  });

  it("records a superseded termination's replacement, and refuses every bad replacement alike", async () => {
    const old = await mission(assistant);
    const replacement = await mission(assistant, { description: "Summarize the revised report" });
    // A mission of bob's agent: outside the alice administrator's scope.
    const bobs = await mission(await makeAgent(w.ap, w.clock, HELPER));
    const before = snapshot(old.s256);
    const supersede = (replacementS256: string) =>
      control(
        w,
        w.admins.alice,
        old.s256,
        terminateBody("superseded", { purpose: "p", replacement_s256: replacementS256 }),
      );
    const refusals = [
      await supersede(absent),
      await supersede(old.s256),
      await supersede(bobs.s256),
    ];
    const first = observable(refusals[0] as Reply);
    expect(first.status).toBe(400);
    expect(JSON.parse(first.text).error).toBe("invalid_request");
    for (const r of refusals) expect(observable(r)).toEqual(first);
    expect(snapshot(old.s256)).toEqual(before);
    const r = await control(
      w,
      w.admins.alice,
      old.s256,
      terminateBody("superseded", { purpose: "replaced", replacement_s256: replacement.s256 }),
    );
    expect(r.body.termination_reason).toBe("superseded");
    expect(
      w.durable.missionLog(old.s256).find((e) => e.event === "terminated")?.detail,
    ).toMatchObject({
      replacement_s256: replacement.s256,
    });
  });
});

describe("control plane: idempotency and concurrency", () => {
  it("replays an equivalent request: the same receipt, no second event, no new revocation", async () => {
    const { s256 } = await mission(assistant, { description: "Summarize", resources: [RS] });
    const body = terminateBody("revoked", { purpose: "done" });
    const first = await control(w, assistant, s256, body);
    expect(first.status).toBe(200);
    const sent = w.rs.requests;
    const attempts = w.durable.missionLog(s256).filter((e) => e.event === "revocation_attempted");
    w.clock.advance(60);
    // The same members in another order: equal as parsed values.
    const reordered = {
      purpose: body.purpose,
      request_id: body.request_id,
      reason: body.reason,
      action: body.action,
    };
    const replay = await control(w, assistant, s256, reordered);
    expect(replay.status).toBe(200);
    for (const k of ["mission_s256", "mission_status", "terminated_at", "termination_reason"]) {
      expect(replay.body[k]).toEqual(first.body[k]);
    }
    expect(replay.body.observed_at).toBe(rfc3339(w.clock.s));
    expect(replay.body.observed_at).not.toBe(first.body.observed_at);
    const log = w.durable.missionLog(s256);
    expect(log.filter((e) => e.event === "terminated")).toHaveLength(1);
    expect(log.filter((e) => e.event === "revocation_attempted")).toEqual(attempts);
    expect(log.at(-1)).toMatchObject({
      event: "terminate_replayed",
      detail: { request_id: body.request_id, actor: { id: ASSISTANT, role: "owning_agent" } },
    });
    expect(w.rs.requests).toBe(sent);
  });

  it("refuses a request_id reused with different content, or for another mission: idempotency_conflict", async () => {
    const { s256 } = await mission(assistant);
    const other = await mission(assistant, { description: "Draft the summary" });
    const body = terminateBody("revoked", { purpose: "done" });
    expect((await control(w, assistant, s256, body)).status).toBe(200);
    const before = [snapshot(s256), snapshot(other.s256)];
    for (const changed of [
      { ...body, purpose: "something else" },
      { ...body, note: "an unrecognized member still counts" },
      (({ purpose: _p, ...rest }) => rest)(body),
    ]) {
      refusedWith(await control(w, assistant, s256, changed), 409, "idempotency_conflict");
    }
    refusedWith(await control(w, assistant, other.s256, body), 409, "idempotency_conflict");
    expect([snapshot(s256), snapshot(other.s256)]).toEqual(before);
    expect(w.durable.findOwnedMission(ASSISTANT, other.s256)?.state).toBe("active");
    // A reused request_id against an absent mission is still mission_not_found.
    refusedWith(await control(w, assistant, absent, body), 404, "mission_not_found");
    // Another caller's identical request_id is its own.
    const admin = await control(w, w.admins.alice, other.s256, {
      ...body,
      reason: "administrative",
    });
    expect(admin.status).toBe(200);
  });

  it("answers a later request with the first committed outcome, and logs it", async () => {
    const { s256 } = await mission(assistant, { description: "Summarize", resources: [RS] });
    const first = await control(w, assistant, s256, terminateBody("revoked"));
    const sent = w.rs.requests;
    w.clock.advance(10);
    const laterBody = terminateBody("administrative", { purpose: "cleanup" });
    const later = await control(w, w.admins.alice, s256, laterBody);
    expect(later.status).toBe(200);
    expect(later.body.terminated_at).toBe(first.body.terminated_at);
    expect(later.body.termination_reason).toBe("revoked");
    const log = w.durable.missionLog(s256);
    expect(log.filter((e) => e.event === "terminated")).toHaveLength(1);
    expect(log.at(-1)).toMatchObject({
      event: "termination_request_after_terminal",
      detail: {
        actor: { id: ADMIN, role: "administrator" },
        request_id: laterBody.request_id,
        requested_reason: "administrative",
        purpose: "cleanup",
      },
    });
    expect(w.rs.requests).toBe(sent);
    // That request's own receipt is retained: a replay repeats it.
    const replay = await control(w, w.admins.alice, s256, laterBody);
    expect(replay.body.termination_reason).toBe("revoked");
    expect(w.durable.missionLog(s256).at(-1)?.event).toBe("terminate_replayed");
  });

  it("serializes concurrent terminations: exactly one transition, and both see it", async () => {
    const { s256 } = await mission(assistant, { description: "Summarize", resources: [RS] });
    const [a, b] = await Promise.all([
      control(w, assistant, s256, terminateBody("revoked")),
      control(w, w.admins.alice, s256, terminateBody("administrative", { purpose: "race" })),
    ]);
    expect([a?.status, b?.status]).toEqual([200, 200]);
    expect(a?.body.terminated_at).toBe(b?.body.terminated_at);
    expect(a?.body.termination_reason).toBe(b?.body.termination_reason);
    const log = w.durable.missionLog(s256);
    const ended = log.filter((e) => e.event === "terminated");
    expect(ended).toHaveLength(1);
    expect(ended[0]?.detail.reason).toBe(a?.body.termination_reason);
    expect(log.filter((e) => e.event === "termination_request_after_terminal")).toHaveLength(1);
    expect(w.durable.revocations(s256)).toHaveLength(1);
  });

  it("resolves a termination racing expiry to the first committed transition: expired", async () => {
    const expiresAt = w.clock.s + 50;
    const { s256 } = await mission(assistant, {
      description: "Summarize",
      expires_at: rfc3339(expiresAt),
    });
    w.clock.advance(60);
    const r = await control(w, assistant, s256, terminateBody("revoked"));
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({
      termination_reason: "expired",
      terminated_at: rfc3339(expiresAt),
    });
    expect(w.durable.missionLog(s256).map((e) => e.event)).toEqual([
      "approved",
      "terminated",
      "termination_request_after_terminal",
    ]);
  });
});

describe("control plane: local gating as termination commits", () => {
  /** Run `effect` once, after a key of `issuer` resolves inside a request. */
  function duringResolve(issuer: string, effect: () => Promise<void>): void {
    const original = JwksResolver.prototype.resolveKey;
    let fired = false;
    vi.spyOn(JwksResolver.prototype, "resolveKey").mockImplementation(async function (
      this: JwksResolver,
      ...args: Parameters<JwksResolver["resolveKey"]>
    ) {
      const key = await original.apply(this, args);
      if (args[0] === issuer && !fired) {
        fired = true;
        await effect();
      }
      return key;
    });
  }

  it("refuses a person token request in flight when termination commits: mission_terminated", async () => {
    const { s256 } = await mission(assistant);
    const issued = issuedCount(w);
    let terminated: Reply | undefined;
    duringResolve(w.ap.id, async () => {
      terminated = await control(
        w,
        w.admins.alice,
        s256,
        terminateBody("administrative", { purpose: "stop" }),
      );
    });
    const r = await requestPersonToken(w, assistant, { resource: RS, mission_s256: s256 });
    expect(terminated?.status).toBe(200);
    expect([r.status, r.body.error, r.body.termination_reason]).toEqual([
      403,
      "mission_terminated",
      "administrative",
    ]);
    expect(r.body.person_token).toBeUndefined();
    expect(issuedCount(w)).toBe(issued);
  });

  it("refuses an auth token request in flight when termination commits: mission_terminated", async () => {
    const { s256 } = await mission(assistant);
    const presented = await personToken(w, assistant, RS, s256);
    const resourceToken = await resourceTokenFor(w, assistant, presented);
    const issued = issuedCount(w);
    let terminated: Reply | undefined;
    duringResolve(RS, async () => {
      terminated = await control(
        w,
        w.admins.alice,
        s256,
        terminateBody("administrative", { purpose: "stop" }),
      );
    });
    const r = await requestAuthToken(w, assistant, {
      resource_token: resourceToken,
      presented_token: presented,
    });
    expect(terminated?.status).toBe(200);
    expect([r.status, r.body.error]).toEqual([403, "mission_terminated"]);
    expect(r.body.auth_token).toBeUndefined();
    expect(issuedCount(w)).toBe(issued);
    // The person token issued before the commit is a Tracked Credential the termination revoked.
    expect(w.rs.revoked.map((x) => x.jti)).toEqual([claims(presented).jti]);
  });
});
