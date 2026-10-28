/**
 * The auth token endpoint in PS authorization access (AAuth -11 Section
 * 7.2): resource-token verification (Section 6.7.2 steps 1 and 2),
 * `presented_token` verification with its two substitutions and the claim
 * matches (step 3, per #836's Analysis), `ps` naming this PS, the mission
 * gate (step 4), and direct issuance with `mission_s256` propagated
 * (Section 9.4.1). Vectors V1-V5, V9-V12 and V14. Every refusal leaves no
 * issued token and no record.
 */
import { randomUUID } from "node:crypto";
import { generateSigningKey, jwkThumbprint, mintToken, verifyAuthToken } from "@mission/aauth-wire";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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
  PS2,
  personClaims,
  personToken,
  type Reply,
  RS,
  RS2,
  requestAuthToken,
  resourceClaims,
  resourceTokenFor,
  STRANGER,
  type World,
  whileResolving,
  world,
} from "./helpers.js";

let w: World;
let assistant: Agent;
let helper: Agent;

beforeEach(async () => {
  w = await world();
  assistant = await makeAgent(w.ap, w.clock);
  helper = await makeAgent(w.ap, w.clock, HELPER);
});
afterEach(async () => {
  vi.restoreAllMocks();
  await w.close();
});

/** An approved mission and a person token for `rs` under it. */
async function grant(agent: Agent = assistant, proposal?: Record<string, unknown>) {
  const { s256 } = await approve(w, agent, proposal);
  const pt = await personToken(w, agent, RS, s256);
  return { s256, pt };
}

function refused(r: Reply, status: number, error: string, before: number, detail?: string): void {
  expect(r.status, JSON.stringify(r.body)).toBe(status);
  expect(r.body.error).toBe(error);
  if (detail !== undefined) expect(r.body.detail).toBe(detail);
  expect(r.body.auth_token).toBeUndefined();
  expect(issuedCount(w)).toBe(before);
}

/** A key other than the agent's, and a token signed by it under `kid`. */
async function forge(
  typ: "aa-person+jwt" | "aa-resource+jwt",
  c: Record<string, unknown>,
  kid: string,
) {
  const other = generateSigningKey("Ed25519");
  return mintToken(typ, c, { alg: other.alg, privateKey: other.privateKey, kid });
}

const psKid = () => w.ps.signingKey.publicJwk.kid as string;

describe("V1: the governed path", () => {
  it("issues an auth token bound to the agent's key, with mission_s256 copied", async () => {
    const { s256, pt } = await grant();
    const rt = await resourceTokenFor(w, assistant, pt);
    const r = await requestAuthToken(w, assistant, {
      resource_token: rt,
      presented_token: pt,
      justification: "Read the quarterly report",
    });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    const jwt = r.body.auth_token as string;
    const verified = await verifyAuthToken(jwt, {
      resolver: w.net.resolver(w.clock),
      now: w.clock.now,
      audience: RS,
    });
    const c = verified.payload;
    expect(verified.header.typ).toBe("aa-auth+jwt");
    expect([c.iss, c.ps, c.dwk, c.aud]).toEqual([PS, PS, "aauth-person.json", RS]);
    expect(c.sub).toBe(claims(pt).sub);
    expect(c.mission_s256).toBe(s256);
    expect(c.scope).toBe("data.read");
    expect(c.tenant).toBe("acme");
    expect(await jwkThumbprint((c.cnf as { jwk: Record<string, unknown> }).jwk)).toBe(
      assistant.jkt,
    );
    expect(r.body.expires_in).toBe((c.exp as number) - (c.iat as number));
  });

  it("records the auth token as a Tracked Credential and logs the request under the mission", async () => {
    const { s256, pt } = await grant();
    const rt = await resourceTokenFor(w, assistant, pt);
    const r = await requestAuthToken(w, assistant, {
      resource_token: rt,
      presented_token: pt,
      justification: "Read the quarterly report",
    });
    const c = claims(r.body.auth_token as string);
    expect(w.ps.store.issuedTokens().find((t) => t.kind === "auth")).toEqual({
      iss: PS,
      jti: c.jti,
      kind: "auth",
      aud: RS,
      exp: c.exp,
      sub: c.sub,
      agent: assistant.id,
      missionS256: s256,
      issuedAt: c.iat,
    });
    const entry = w.ps.store.missionLog(s256).find((e) => e.event === "auth_token_issued");
    expect(entry?.detail).toEqual({
      jti: c.jti,
      aud: RS,
      presented_jti: claims(pt).jti,
      scope: "data.read",
      justification: "Read the quarterly report",
    });
  });

  it("V5 positive: accepts a step-up on a presented auth token", async () => {
    const { s256, pt } = await grant();
    const first = await requestAuthToken(w, assistant, {
      resource_token: await resourceTokenFor(w, assistant, pt),
      presented_token: pt,
    });
    const at = first.body.auth_token as string;
    const stepUp = await resourceTokenFor(w, assistant, at, { scope: "data.read data.write" });
    const r = await requestAuthToken(w, assistant, { resource_token: stepUp, presented_token: at });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    const c = claims(r.body.auth_token as string);
    expect(c.mission_s256).toBe(s256);
    expect(c.scope).toBe("data.read data.write");
    expect(c.exp).toBeLessThanOrEqual(claims(at).exp as number);
  });

  it("V14: issues a missionless auth token to an agent admitted missionless", async () => {
    const pt = await personToken(w, helper, RS);
    const rt = await resourceTokenFor(w, helper, pt);
    const r = await requestAuthToken(w, helper, { resource_token: rt, presented_token: pt });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(claims(r.body.auth_token as string)).not.toHaveProperty("mission_s256");
    expect(w.ps.store.issuedTokens().find((t) => t.kind === "auth")?.missionS256).toBeUndefined();
  });
});

describe("auth token lifetime caps", () => {
  it("caps exp at the presented token's exp", async () => {
    const { pt } = await grant();
    w.clock.advance(100);
    const r = await requestAuthToken(w, assistant, {
      resource_token: await resourceTokenFor(w, assistant, pt),
      presented_token: pt,
    });
    expect(claims(r.body.auth_token as string).exp).toBe(claims(pt).exp);
  });

  it("caps the lifetime at one hour", async () => {
    const { s256 } = await approve(w, assistant);
    const pt = await w.psMint(
      "aa-person+jwt",
      personClaims(w, assistant, {
        mission_s256: s256,
        iat: w.clock.s + 300,
        exp: w.clock.s + 3900,
      }),
    );
    const r = await requestAuthToken(w, assistant, {
      resource_token: await resourceTokenFor(w, assistant, pt),
      presented_token: pt,
    });
    const c = claims(r.body.auth_token as string);
    expect((c.exp as number) - (c.iat as number)).toBe(3600);
  });

  it("caps exp at the agent token's exp", async () => {
    const { pt } = await grant();
    const short = await makeAgent(w.ap, w.clock, assistant.id, {
      cnf: { jwk: assistant.key.publicJwk },
      exp: w.clock.s + 600,
    });
    const signer = { ...assistant, token: short.token };
    const r = await requestAuthToken(w, signer, {
      resource_token: await resourceTokenFor(w, assistant, pt),
      presented_token: pt,
    });
    expect(claims(r.body.auth_token as string).exp).toBe(claims(short.token).exp);
  });

  it("caps exp at the mission's expires_at", async () => {
    const expiresAt = w.clock.s + 900;
    const { s256 } = await approve(w, assistant, {
      description: "Summarize",
      expires_at: rfc3339(expiresAt),
    });
    const pt = await w.psMint(
      "aa-person+jwt",
      personClaims(w, assistant, { mission_s256: s256, exp: w.clock.s + 1800 }),
    );
    const r = await requestAuthToken(w, assistant, {
      resource_token: await resourceTokenFor(w, assistant, pt),
      presented_token: pt,
    });
    expect(claims(r.body.auth_token as string).exp).toBe(expiresAt);
  });
});

describe("6.7.2 steps 1 and 2: the resource token", () => {
  it("refuses a resource token whose signature fails: invalid_resource_token", async () => {
    const { pt } = await grant();
    const before = issuedCount(w);
    const rt = await forge("aa-resource+jwt", resourceClaims(w, assistant, pt), w.rs.kid);
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: pt });
    refused(r, 400, "invalid_resource_token", before);
  });

  it("refuses an expired resource token: expired_resource_token", async () => {
    const { pt } = await grant();
    const before = issuedCount(w);
    const rt = await resourceTokenFor(w, assistant, pt, {
      iat: w.clock.s - 300,
      exp: w.clock.s,
    });
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: pt });
    refused(r, 400, "expired_resource_token", before);
  });

  it("step 1: refuses a resource token whose aud is not this PS: invalid_resource_token", async () => {
    const { pt } = await grant();
    const before = issuedCount(w);
    const rt = await resourceTokenFor(w, assistant, pt, { aud: PS2 });
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: pt });
    refused(r, 400, "invalid_resource_token", before, "aud does not name this recipient");
  });

  it("step 2: refuses agent_jkt naming a key other than the request's: invalid_resource_token", async () => {
    const { s256 } = await approve(w, assistant);
    const other = generateSigningKey("Ed25519");
    const pt = await w.psMint(
      "aa-person+jwt",
      personClaims(w, assistant, { mission_s256: s256, cnf: { jwk: other.publicJwk } }),
    );
    const before = issuedCount(w);
    const rt = await resourceTokenFor(w, assistant, pt, {
      agent_jkt: await jwkThumbprint(other.publicJwk),
    });
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: pt });
    refused(
      r,
      400,
      "invalid_resource_token",
      before,
      "agent_jkt does not match the request's signing key",
    );
  });

  it("refuses a resource token whose ps names another person server: invalid_resource_token", async () => {
    const pt = await w.ps2.mint(
      "aa-person+jwt",
      personClaims(w, helper, { iss: PS2, sub: "bob-at-rs", tenant: undefined }),
    );
    const rt = await resourceTokenFor(w, helper, pt);
    expect(claims(rt).ps).toBe(PS2);
    const r = await requestAuthToken(w, helper, { resource_token: rt, presented_token: pt });
    refused(r, 400, "invalid_resource_token", 0, "ps does not name this person server");
  });
});

describe("6.7.2 step 3: presented_token verification", () => {
  it("refuses a presented token that is neither a person token nor an auth token: invalid_presented_token", async () => {
    const { pt } = await grant();
    const before = issuedCount(w);
    const rt = await resourceTokenFor(w, assistant, pt, {
      presented_jti: claims(assistant.token).jti,
    });
    const r = await requestAuthToken(w, assistant, {
      resource_token: rt,
      presented_token: assistant.token,
    });
    refused(r, 400, "invalid_presented_token", before);
  });

  it("refuses a presented token whose signature fails: invalid_presented_token", async () => {
    const { s256 } = await approve(w, assistant);
    const pt = await forge(
      "aa-person+jwt",
      personClaims(w, assistant, { mission_s256: s256 }),
      psKid(),
    );
    const rt = await resourceTokenFor(w, assistant, pt);
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: pt });
    refused(r, 400, "invalid_presented_token", 0, "signature verification failed");
  });

  it("checks aud against the resource token's iss, so a person token for another resource fails: invalid_presented_token", async () => {
    const { s256 } = await approve(w, assistant);
    const forRs2 = await personToken(w, assistant, RS2, s256);
    const before = issuedCount(w);
    const rt = await resourceTokenFor(w, assistant, forRs2);
    expect(claims(rt).iss).toBe(RS);
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: forRs2 });
    refused(r, 400, "invalid_presented_token", before, "aud does not name this recipient");
  });

  it("checks cnf.jwk against the resource token's agent_jkt: invalid_presented_token", async () => {
    const { s256 } = await approve(w, assistant);
    const other = generateSigningKey("Ed25519");
    const pt = await w.psMint(
      "aa-person+jwt",
      personClaims(w, assistant, { mission_s256: s256, cnf: { jwk: other.publicJwk } }),
    );
    const rt = await resourceTokenFor(w, assistant, pt);
    expect(claims(rt).agent_jkt).toBe(assistant.jkt);
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: pt });
    refused(
      r,
      400,
      "invalid_presented_token",
      0,
      "cnf.jwk does not match the resource token's agent_jkt",
    );
  });

  it("answers a presented token that fails only on exp: expired_presented_token", async () => {
    const { pt } = await grant();
    const before = issuedCount(w);
    w.clock.advance(3600);
    const rt = await resourceTokenFor(w, assistant, pt);
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: pt });
    refused(r, 400, "expired_presented_token", before);
  });

  it("answers an expired presented token that also fails another check: invalid_presented_token", async () => {
    const { s256 } = await approve(w, assistant);
    const pt = await forge(
      "aa-person+jwt",
      personClaims(w, assistant, { mission_s256: s256, iat: w.clock.s - 600, exp: w.clock.s }),
      psKid(),
    );
    const rt = await resourceTokenFor(w, assistant, pt);
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: pt });
    refused(r, 400, "invalid_presented_token", 0, "signature verification failed");
  });

  it("V4: refuses a presented token other than the one presented_jti names: invalid_resource_token", async () => {
    const { s256, pt } = await grant();
    const other = await personToken(w, assistant, RS, s256);
    const before = issuedCount(w);
    const rt = await resourceTokenFor(w, assistant, pt);
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: other });
    refused(
      r,
      400,
      "invalid_resource_token",
      before,
      "presented_jti does not name the presented token",
    );
  });

  it("refuses a person token whose iss is not the resource token's ps: invalid_resource_token", async () => {
    const pt = await w.ps2.mint(
      "aa-person+jwt",
      personClaims(w, helper, { iss: PS2, sub: "bob-at-rs", tenant: undefined }),
    );
    const rt = await resourceTokenFor(w, helper, pt, { ps: PS });
    const r = await requestAuthToken(w, helper, { resource_token: rt, presented_token: pt });
    refused(
      r,
      400,
      "invalid_resource_token",
      0,
      "ps does not match the presented token's person server",
    );
  });

  it("refuses an auth token whose ps is not the resource token's ps: invalid_resource_token", async () => {
    const at = await w.ps2.mint("aa-auth+jwt", {
      ...personClaims(w, helper, { iss: PS2, sub: "bob-at-rs", tenant: undefined }),
      ps: PS2,
    });
    const rt = await resourceTokenFor(w, helper, at, { ps: PS });
    const r = await requestAuthToken(w, helper, { resource_token: rt, presented_token: at });
    refused(
      r,
      400,
      "invalid_resource_token",
      0,
      "ps does not match the presented token's person server",
    );
  });

  it("refuses a sub that differs from the presented token's: invalid_resource_token", async () => {
    const { pt } = await grant();
    const before = issuedCount(w);
    const rt = await resourceTokenFor(w, assistant, pt, { sub: "someone-else" });
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: pt });
    refused(r, 400, "invalid_resource_token", before, "sub does not match the presented token");
  });

  it("V2: refuses a resource token stripped of the presented token's mission_s256: invalid_resource_token", async () => {
    const { pt } = await grant();
    const before = issuedCount(w);
    const rt = await resourceTokenFor(w, assistant, pt, { mission_s256: undefined });
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: pt });
    refused(
      r,
      400,
      "invalid_resource_token",
      before,
      "mission_s256 does not match the presented token",
    );
  });

  it("V3: refuses a different mission on the resource token, and surfaces it to operators", async () => {
    const { pt } = await grant();
    const second = await approve(w, assistant, { description: "Another task" });
    const before = issuedCount(w);
    const rt = await resourceTokenFor(w, assistant, pt, { mission_s256: second.s256 });
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: pt });
    refused(
      r,
      400,
      "invalid_resource_token",
      before,
      "mission_s256 does not match the presented token",
    );
    expect(w.ps.securityEvents.map((e) => e.type)).toContain("presented_token_mismatch");
  });

  it("refuses a mission_s256 the presented token does not carry: invalid_resource_token", async () => {
    const { s256 } = await approve(w, helper);
    const pt = await personToken(w, helper, RS);
    const before = issuedCount(w);
    const rt = await resourceTokenFor(w, helper, pt, { mission_s256: s256 });
    const r = await requestAuthToken(w, helper, { resource_token: rt, presented_token: pt });
    refused(
      r,
      400,
      "invalid_resource_token",
      before,
      "mission_s256 does not match the presented token",
    );
  });

  it("V5: refuses a step-up resource token stripped of the auth token's mission_s256: invalid_resource_token", async () => {
    const { pt } = await grant();
    const first = await requestAuthToken(w, assistant, {
      resource_token: await resourceTokenFor(w, assistant, pt),
      presented_token: pt,
    });
    const at = first.body.auth_token as string;
    const before = issuedCount(w);
    const rt = await resourceTokenFor(w, assistant, at, { mission_s256: undefined });
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: at });
    refused(
      r,
      400,
      "invalid_resource_token",
      before,
      "mission_s256 does not match the presented token",
    );
  });

  it("refuses a tenant that differs from, or is missing against, the presented token's: invalid_resource_token", async () => {
    const { pt } = await grant();
    const before = issuedCount(w);
    for (const tenant of ["globex", undefined]) {
      const rt = await resourceTokenFor(w, assistant, pt, { tenant });
      const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: pt });
      refused(
        r,
        400,
        "invalid_resource_token",
        before,
        "tenant does not match the presented token",
      );
    }
  });
});

describe("6.7.2 step 4 and governance", () => {
  it("V10: refuses a mission that is no longer active: mission_terminated with its reason", async () => {
    const { s256, pt } = await grant();
    const before = issuedCount(w);
    w.ps.store.terminate(assistant.id, s256, "revoked", w.clock.s);
    const rt = await resourceTokenFor(w, assistant, pt);
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: pt });
    refused(r, 403, "mission_terminated", before);
    expect(r.body.termination_reason).toBe("revoked");
  });

  it("V11: a mission past expires_at fails at presented-token verification: expired_presented_token", async () => {
    const { pt } = await grant(assistant, {
      description: "Summarize",
      expires_at: rfc3339(w.clock.s + 600),
    });
    const before = issuedCount(w);
    w.clock.advance(600);
    const rt = await resourceTokenFor(w, assistant, pt);
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: pt });
    refused(r, 400, "expired_presented_token", before);
  });

  it("refuses a mission past expires_at even under a presented token still valid: mission_terminated", async () => {
    const { s256 } = await approve(w, assistant, {
      description: "Summarize",
      expires_at: rfc3339(w.clock.s + 120),
    });
    const pt = await w.psMint(
      "aa-person+jwt",
      personClaims(w, assistant, { mission_s256: s256, exp: w.clock.s + 1800 }),
    );
    w.clock.advance(120);
    const rt = await resourceTokenFor(w, assistant, pt);
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: pt });
    refused(r, 403, "mission_terminated", 0);
    expect(r.body.termination_reason).toBe("expired");
  });

  it("refuses a mission of another agent: invalid_resource_token, never mission_terminated", async () => {
    const planner = await makeAgent(w.ap, w.clock, PLANNER);
    const theirs = await approve(w, planner);
    const pt = await w.psMint(
      "aa-person+jwt",
      personClaims(w, assistant, { mission_s256: theirs.s256 }),
    );
    const rt = await resourceTokenFor(w, assistant, pt);
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: pt });
    refused(
      r,
      400,
      "invalid_resource_token",
      0,
      "mission_s256 does not name a mission of this agent",
    );
    w.ps.store.terminate(PLANNER, theirs.s256, "revoked", w.clock.s);
    const again = await requestAuthToken(w, assistant, {
      resource_token: await resourceTokenFor(w, assistant, pt),
      presented_token: pt,
    });
    refused(
      again,
      400,
      "invalid_resource_token",
      0,
      "mission_s256 does not name a mission of this agent",
    );
  });

  it("refuses a mission_s256 that is not a string, matched on both tokens: invalid_resource_token", async () => {
    const pt = await w.psMint("aa-person+jwt", personClaims(w, assistant, { mission_s256: true }));
    const rt = await resourceTokenFor(w, assistant, pt);
    expect(claims(rt).mission_s256).toBe(true);
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: pt });
    refused(
      r,
      400,
      "invalid_resource_token",
      0,
      "mission_s256 does not name a mission of this agent",
    );
  });

  it("V12: refuses when the mission's state cannot be established: server_error", async () => {
    const { pt } = await grant();
    const before = issuedCount(w);
    w.faults.failMissionReads = true;
    const rt = await resourceTokenFor(w, assistant, pt);
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: pt });
    refused(r, 500, "server_error", before, "mission state is unavailable");
  });

  it("V9: refuses a missionless token request from an agent under mission governance: denied", async () => {
    const pt = await w.psMint("aa-person+jwt", personClaims(w, assistant));
    const rt = await resourceTokenFor(w, assistant, pt);
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: pt });
    refused(r, 403, "denied", 0);
  });

  it("returns no token when its record cannot be written: server_error", async () => {
    const { pt } = await grant();
    const before = issuedCount(w);
    w.faults.failRecords = true;
    const rt = await resourceTokenFor(w, assistant, pt);
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: pt });
    refused(r, 500, "server_error", before, "the issued token could not be recorded");
  });
});

describe("the issuance commit: time and mission state rechecked at the current time", () => {
  /** Move the shared clock to the start of second `s`. */
  const reach = (s: number) => () => {
    w.clock.ms = s * 1000;
  };

  it("issues nothing when the mission's expires_at passes while the resource's key is resolved", async () => {
    const expiresAt = w.clock.s + 10;
    const { pt } = await grant(assistant, {
      description: "Summarize the quarterly report",
      expires_at: rfc3339(expiresAt),
    });
    const rt = await resourceTokenFor(w, assistant, pt);
    const before = issuedCount(w);
    whileResolving(RS, reach(expiresAt + 1));
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: pt });
    // The person token was capped at expires_at, so it fails first.
    refused(r, 400, "expired_presented_token", before);
  });

  it("refuses a resource token that expires while its key is resolved: expired_resource_token", async () => {
    const { pt } = await grant();
    const expires = w.clock.s + 10;
    const rt = await resourceTokenFor(w, assistant, pt, { exp: expires });
    const before = issuedCount(w);
    whileResolving(RS, reach(expires + 1));
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: pt });
    refused(r, 400, "expired_resource_token", before, "the resource token has expired");
  });

  it("refuses a presented token that expires while a key is resolved: expired_presented_token", async () => {
    const expires = w.clock.s + 10;
    const pt = await w.psMint(
      "aa-person+jwt",
      personClaims(w, helper, { sub: "bob-at-rs", tenant: undefined, exp: expires }),
    );
    const rt = await resourceTokenFor(w, helper, pt);
    whileResolving(RS, reach(expires + 1));
    const r = await requestAuthToken(w, helper, { resource_token: rt, presented_token: pt });
    refused(r, 400, "expired_presented_token", 0, "the presented token has expired");
  });

  it("refuses a mission terminated while a key is resolved: mission_terminated", async () => {
    const { s256, pt } = await grant();
    const rt = await resourceTokenFor(w, assistant, pt);
    const before = issuedCount(w);
    whileResolving(RS, () => {
      w.ps.store.terminate(assistant.id, s256, "revoked", w.clock.s);
    });
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: pt });
    refused(r, 403, "mission_terminated", before);
    expect(r.body.termination_reason).toBe("revoked");
  });

  it("refuses a mission whose expires_at passes while a key is resolved, under a presented token still valid: mission_terminated", async () => {
    const expiresAt = w.clock.s + 10;
    const { s256 } = await approve(w, assistant, {
      description: "Summarize the quarterly report",
      expires_at: rfc3339(expiresAt),
    });
    const pt = await w.psMint(
      "aa-person+jwt",
      personClaims(w, assistant, { mission_s256: s256, exp: w.clock.s + 1800 }),
    );
    const rt = await resourceTokenFor(w, assistant, pt);
    whileResolving(RS, reach(expiresAt + 1));
    const r = await requestAuthToken(w, assistant, { resource_token: rt, presented_token: pt });
    refused(r, 403, "mission_terminated", 0);
    expect(r.body.termination_reason).toBe("expired");
  });

  it("refuses an agent token that expires while a key is resolved, so no auth token is minted already expired: 401 expired_jwt", async () => {
    const shortLived = await makeAgent(w.ap, w.clock, ASSISTANT, { exp: w.clock.s + 10 });
    const { s256 } = await approve(w, shortLived);
    const pt = await w.psMint(
      "aa-person+jwt",
      personClaims(w, shortLived, { mission_s256: s256, exp: w.clock.s + 1800 }),
    );
    const rt = await resourceTokenFor(w, shortLived, pt);
    whileResolving(RS, reach((claims(shortLived.token).exp as number) + 1));
    const r = await requestAuthToken(w, shortLived, { resource_token: rt, presented_token: pt });
    refused(r, 401, "expired_jwt", 0);
    expect(r.headers.get("signature-error")).toBe("error=expired_jwt");
  });
});

describe("auth token request validation", () => {
  it("refuses a missing resource_token or presented_token: invalid_request", async () => {
    const { pt } = await grant();
    const rt = await resourceTokenFor(w, assistant, pt);
    const before = issuedCount(w);
    refused(
      await requestAuthToken(w, assistant, { presented_token: pt }),
      400,
      "invalid_request",
      before,
    );
    refused(
      await requestAuthToken(w, assistant, { resource_token: rt }),
      400,
      "invalid_request",
      before,
    );
  });

  it("refuses upstream_token and subagent_token rather than ignoring them: invalid_request", async () => {
    const { pt } = await grant();
    const before = issuedCount(w);
    for (const extra of [{ upstream_token: pt }, { subagent_token: assistant.token }]) {
      const rt = await resourceTokenFor(w, assistant, pt);
      const r = await requestAuthToken(w, assistant, {
        resource_token: rt,
        presented_token: pt,
        ...extra,
      });
      refused(r, 400, "invalid_request", before);
    }
  });

  it("refuses an agent the allowlist does not name: user_unreachable", async () => {
    const stranger = await makeAgent(w.ap, w.clock, STRANGER);
    const pt = await w.psMint("aa-person+jwt", personClaims(w, stranger, { jti: randomUUID() }));
    const rt = await resourceTokenFor(w, stranger, pt);
    const r = await requestAuthToken(w, stranger, { resource_token: rt, presented_token: pt });
    refused(r, 403, "user_unreachable", 0);
  });
});
