/**
 * The person token endpoint (AAuth -11 Section 7.1): the request's
 * Mission association (vectors V7-V12, V14 and fixture P1), the issued
 * token's claims and lifetime caps (Section 7.1.2), and its record.
 * Every refusal leaves no issued token and no record.
 */
import { createHash } from "node:crypto";
import { verifyPersonToken } from "@mission/aauth-wire";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { rfc3339 } from "../src/index.js";
import {
  type Agent,
  ASSISTANT,
  approve,
  claims,
  HELPER,
  issuedCount,
  makeAgent,
  PLANNER,
  PS,
  personToken,
  type Reply,
  RS,
  RS2,
  requestPersonToken,
  STRANGER,
  shape,
  signed,
  type World,
  world,
} from "./helpers.js";

let w: World;
let assistant: Agent;

beforeEach(async () => {
  w = await world();
  assistant = await makeAgent(w.ap, w.clock);
});
afterEach(async () => {
  await w.close();
});

const absentS256 = createHash("sha256").update("no such mission").digest("base64url");

function refused(r: Reply, status: number, error: string, before = 0): void {
  expect(r.status, JSON.stringify(r.body)).toBe(status);
  expect(r.body.error).toBe(error);
  expect(r.body.person_token).toBeUndefined();
  expect(issuedCount(w)).toBe(before);
}

describe("person token endpoint: issuance", () => {
  it("issues a Mission-bound person token a resource can verify", async () => {
    const { s256 } = await approve(w, assistant);
    const r = await requestPersonToken(w, assistant, { resource: RS, mission_s256: s256 });
    expect(r.status).toBe(200);
    const jwt = r.body.person_token as string;
    const verified = await verifyPersonToken(jwt, {
      resolver: w.net.resolver(w.clock),
      now: w.clock.now,
      audience: RS,
    });
    expect(verified.header.typ).toBe("aa-person+jwt");
    const c = verified.payload;
    expect(c.iss).toBe(PS);
    expect(c.dwk).toBe("aauth-person.json");
    expect(c.aud).toBe(RS);
    expect(c.mission_s256).toBe(s256);
    expect(c.tenant).toBe("acme");
    expect(c).not.toHaveProperty("scope");
    expect(c).not.toHaveProperty("account");
    expect(c.cnf).toEqual({
      jwk: { kty: "OKP", crv: "Ed25519", x: assistant.key.publicJwk.x, alg: "Ed25519" },
    });
    expect(r.body.expires_in).toBe((c.exp as number) - (c.iat as number));
  });

  it("records the issued token as a Tracked Credential and logs it under the mission", async () => {
    const { s256 } = await approve(w, assistant);
    const jwt = await personToken(w, assistant, RS, s256);
    const c = claims(jwt);
    expect(w.ps.store.issuedTokens()).toEqual([
      {
        iss: PS,
        jti: c.jti,
        kind: "person",
        aud: RS,
        exp: c.exp,
        sub: c.sub,
        agent: assistant.id,
        missionS256: s256,
        issuedAt: c.iat,
      },
    ]);
    expect(w.ps.store.missionLog(s256).map((e) => e.event)).toEqual([
      "approved",
      "person_token_issued",
    ]);
  });

  it("caps the lifetime at one hour", async () => {
    const { s256 } = await approve(w, assistant);
    const c = claims(await personToken(w, assistant, RS, s256));
    expect((c.exp as number) - (c.iat as number)).toBe(3600);
  });

  it("caps exp at the presenting agent token's exp", async () => {
    const { s256 } = await approve(w, assistant);
    const shortLived = { ...assistant, token: "" };
    const fresh = await makeAgent(w.ap, w.clock, assistant.id, {
      cnf: { jwk: assistant.key.publicJwk },
      exp: w.clock.s + 600,
    });
    shortLived.token = fresh.token;
    const c = claims(await personToken(w, shortLived, RS, s256));
    expect(c.exp).toBe(claims(fresh.token).exp);
  });

  it("caps exp at the mission's expires_at", async () => {
    const expiresAt = w.clock.s + 900;
    const { s256 } = await approve(w, assistant, {
      description: "Summarize",
      expires_at: rfc3339(expiresAt),
    });
    const c = claims(await personToken(w, assistant, RS, s256));
    expect(c.exp).toBe(expiresAt);
  });

  it("derives sub per person and resource, never per agent", async () => {
    const planner = await makeAgent(w.ap, w.clock, PLANNER);
    const helper = await makeAgent(w.ap, w.clock, HELPER);
    const mine = await approve(w, assistant);
    const theirs = await approve(w, planner);
    const a = claims(await personToken(w, assistant, RS, mine.s256)).sub;
    expect(claims(await personToken(w, planner, RS, theirs.s256)).sub).toBe(a);
    expect(claims(await personToken(w, assistant, RS2, mine.s256)).sub).not.toBe(a);
    expect(claims(await personToken(w, helper, RS)).sub).not.toBe(a);
  });

  it("copies only the public key members of the agent's cnf.jwk", async () => {
    const { s256 } = await approve(w, assistant);
    const decorated = await makeAgent(w.ap, w.clock, assistant.id, {
      cnf: { jwk: { ...assistant.key.publicJwk, kid: "agent-key-1", use: "sig" } },
    });
    const c = claims(await personToken(w, { ...assistant, token: decorated.token }, RS, s256));
    expect(c.cnf).toEqual({
      jwk: { kty: "OKP", crv: "Ed25519", x: assistant.key.publicJwk.x, alg: "Ed25519" },
    });
  });

  it("V14: issues a missionless person token to an agent admitted missionless", async () => {
    const helper = await makeAgent(w.ap, w.clock, HELPER);
    const c = claims(await personToken(w, helper, RS));
    expect(c).not.toHaveProperty("mission_s256");
    expect(c).not.toHaveProperty("tenant");
    expect(w.ps.store.issuedTokens()[0]?.missionS256).toBeUndefined();
  });
});

describe("person token endpoint: request validation", () => {
  it("refuses a missing resource: invalid_request", async () => {
    const r = await requestPersonToken(w, assistant, {});
    refused(r, 400, "invalid_request");
    expect(r.body.detail).toBe("resource is missing or is not a server identifier");
  });

  it("refuses a resource that is not a server identifier: invalid_request", async () => {
    const { s256 } = await approve(w, assistant);
    for (const resource of ["http://rs.test", "https://rs.test:8443", "https://rs.test/api"]) {
      refused(
        await requestPersonToken(w, assistant, { resource, mission_s256: s256 }),
        400,
        "invalid_request",
      );
    }
  });

  it("refuses upstream_token and subagent_token rather than ignoring them: invalid_request", async () => {
    const { s256 } = await approve(w, assistant);
    for (const extra of [{ upstream_token: "eyJ" }, { subagent_token: "eyJ" }]) {
      const r = await requestPersonToken(w, assistant, {
        resource: RS,
        mission_s256: s256,
        ...extra,
      });
      refused(r, 400, "invalid_request");
      expect(r.body.detail).toBe("call chaining and sub-agent requests are not supported here");
    }
  });

  it("refuses a sub-agent calling directly, even one the allowlist names: denied", async () => {
    await w.close();
    const subAgent = "aauth:assistant+search1@ap.test";
    w = await world({
      config: (doc) => {
        (doc.agents as Record<string, unknown>[]).push({
          agent: subAgent,
          person: "bob",
          mission_governed: false,
        });
      },
    });
    const sub = await makeAgent(w.ap, w.clock, subAgent, { parent_agent: ASSISTANT });
    const r = await requestPersonToken(w, sub, { resource: RS });
    refused(r, 403, "denied");
    expect(r.body.detail).toBe("a sub-agent does not call the person server directly");
    const missions = await signed(w.clock, "POST", `${w.origin}/mission`, sub, {
      description: "Search",
    });
    expect(missions.status).toBe(403);
    expect(missions.body.error).toBe("denied");
  });

  it("refuses an agent the allowlist does not name: user_unreachable, no Signature-Error", async () => {
    const stranger = await makeAgent(w.ap, w.clock, STRANGER);
    const r = await requestPersonToken(w, stranger, { resource: RS });
    refused(r, 403, "user_unreachable");
    expect(r.headers.get("signature-error")).toBeNull();
  });
});

describe("person token endpoint: the Mission association", () => {
  it("V7: refuses a malformed mission_s256: invalid_request", async () => {
    const padded = `${absentS256}=`;
    const badBits = `${absentS256.slice(0, 42)}B`;
    for (const value of ["not-a-digest", padded, badBits, 42, null]) {
      const r = await requestPersonToken(w, assistant, { resource: RS, mission_s256: value });
      refused(r, 400, "invalid_request");
      expect(r.body.detail).toBe("mission_s256 is malformed");
    }
  });

  it("V8: refuses a well-formed mission_s256 that names no mission: invalid_request", async () => {
    const r = await requestPersonToken(w, assistant, { resource: RS, mission_s256: absentS256 });
    refused(r, 400, "invalid_request");
    expect(r.body.detail).toBe("mission_s256 does not name a mission of this agent");
  });

  it("V8 and P1: answers another agent's active mission exactly as an absent one", async () => {
    const planner = await makeAgent(w.ap, w.clock, PLANNER);
    const theirs = await approve(w, planner);
    const absent = await requestPersonToken(w, assistant, {
      resource: RS,
      mission_s256: absentS256,
    });
    const foreign = await requestPersonToken(w, assistant, {
      resource: RS,
      mission_s256: theirs.s256,
    });
    expect(shape(foreign)).toEqual(shape(absent));
    expect(issuedCount(w)).toBe(0);
    const probes = w.ps.securityEvents.filter((e) => e.type === "unowned_mission_reference");
    expect(probes).toHaveLength(2);
    expect(JSON.stringify(probes)).not.toContain(theirs.s256);
  });

  it("P1: answers another agent's terminated mission exactly as an absent one, never mission_terminated", async () => {
    const planner = await makeAgent(w.ap, w.clock, PLANNER);
    const theirs = await approve(w, planner);
    w.ps.store.terminate(PLANNER, theirs.s256, "revoked", w.clock.s);
    const absent = await requestPersonToken(w, assistant, {
      resource: RS,
      mission_s256: absentS256,
    });
    const foreign = await requestPersonToken(w, assistant, {
      resource: RS,
      mission_s256: theirs.s256,
    });
    expect(shape(foreign)).toEqual(shape(absent));
    expect(foreign.body.error).toBe("invalid_request");
  });

  it("V9: refuses a missionless request from an agent under mission governance: denied", async () => {
    const r = await requestPersonToken(w, assistant, { resource: RS });
    refused(r, 403, "denied");
    expect(r.body.detail).toBe(
      "this agent is under mission governance; a missionless request is refused",
    );
  });

  it("V10: refuses a mission that is no longer active: mission_terminated with its reason", async () => {
    const { s256 } = await approve(w, assistant);
    w.ps.store.terminate(assistant.id, s256, "revoked", w.clock.s);
    const r = await requestPersonToken(w, assistant, { resource: RS, mission_s256: s256 });
    refused(r, 403, "mission_terminated");
    expect(r.body.mission_status).toBe("terminated");
    expect(r.body.termination_reason).toBe("revoked");
  });

  it("refuses a mission past its expires_at: mission_terminated, reason expired", async () => {
    const { s256 } = await approve(w, assistant, {
      description: "Summarize",
      expires_at: rfc3339(w.clock.s + 60),
    });
    w.clock.advance(60);
    const r = await requestPersonToken(w, assistant, { resource: RS, mission_s256: s256 });
    refused(r, 403, "mission_terminated");
    expect(r.body.termination_reason).toBe("expired");
  });

  it("treats a mission as active only while the current time precedes its expires_at", async () => {
    const expiresAt = w.clock.s + 60;
    const { s256 } = await approve(w, assistant, {
      description: "Summarize",
      expires_at: rfc3339(expiresAt),
    });
    // Each signed request advances the clock one second before signing.
    w.clock.ms = (expiresAt - 2) * 1000;
    expect(claims(await personToken(w, assistant, RS, s256)).exp).toBe(expiresAt);
    const atExpiry = await requestPersonToken(w, assistant, { resource: RS, mission_s256: s256 });
    refused(atExpiry, 403, "mission_terminated", 1);
  });

  it("V12: refuses when the mission's state cannot be established: server_error", async () => {
    const { s256 } = await approve(w, assistant);
    w.faults.failMissionReads = true;
    const r = await requestPersonToken(w, assistant, { resource: RS, mission_s256: s256 });
    refused(r, 500, "server_error");
    expect(r.body.detail).toBe("mission state is unavailable");
  });

  it("returns no token when its record cannot be written: server_error", async () => {
    const { s256 } = await approve(w, assistant);
    w.faults.failRecords = true;
    const r = await requestPersonToken(w, assistant, { resource: RS, mission_s256: s256 });
    refused(r, 500, "server_error");
    expect(r.body.detail).toBe("the issued token could not be recorded");
  });
});
