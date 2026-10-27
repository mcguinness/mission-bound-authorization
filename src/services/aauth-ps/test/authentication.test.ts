/**
 * Caller authentication at every PS endpoint: an HTTP Message Signature
 * under the Signature-Key `jwt` scheme presenting an agent token (AAuth
 * -11 Sections 7 and 11.3), its base built from the PS's own identifier
 * and the raw request target, with Content-Digest and Content-Type
 * covered on a body request, verified by `@mission/aauth-wire`. A failure
 * is 401 with Signature-Error.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  type Agent,
  approve,
  issuedCount,
  makeAgent,
  PS2,
  personToken,
  prepare,
  type Reply,
  RS,
  requestPersonToken,
  send,
  type World,
  world,
} from "./helpers.js";

let w: World;
let assistant: Agent;
let s256: string;

beforeEach(async () => {
  w = await world();
  assistant = await makeAgent(w.ap, w.clock);
  ({ s256 } = await approve(w, assistant));
});
afterEach(async () => {
  await w.close();
});

function unauthenticated(r: Reply, code: string): void {
  expect(r.status, JSON.stringify(r.body)).toBe(401);
  expect(r.headers.get("signature-error")).toContain(`error=${code}`);
  expect(r.body.person_token).toBeUndefined();
  expect(issuedCount(w)).toBe(0);
}

describe("PS caller authentication", () => {
  it("refuses an unsigned request: 401 invalid_signature", async () => {
    const r = await send("POST", `${w.origin}/person`, {
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ resource: RS, mission_s256: s256 }),
    });
    unauthenticated(r, "invalid_signature");
  });

  it("refuses a body request whose signature does not cover Content-Digest: 401 invalid_input", async () => {
    const url = `${w.origin}/person`;
    const prepared = prepare(
      w.clock,
      "POST",
      url,
      assistant,
      { resource: RS, mission_s256: s256 },
      {
        components: ["@method", "@authority", "@path", "signature-key", "content-type"],
      },
    );
    unauthenticated(await send("POST", url, prepared), "invalid_input");
  });

  it("refuses a replayed signed request: 401 invalid_signature", async () => {
    const url = `${w.origin}/person`;
    const prepared = prepare(w.clock, "POST", url, assistant, { resource: RS, mission_s256: s256 });
    expect((await send("POST", url, prepared)).status).toBe(200);
    const replay = await send("POST", url, prepared);
    expect(replay.status).toBe(401);
    expect(replay.headers.get("signature-error")).toContain("error=invalid_signature");
    expect(issuedCount(w)).toBe(1);
  });

  it("verifies against its own identifier, so a request signed for another server fails even with that Host: 401 invalid_signature", async () => {
    const prepared = prepare(w.clock, "POST", `${PS2}/person`, assistant, {
      resource: RS,
      mission_s256: s256,
    });
    const r = await send("POST", `${w.origin}/person`, prepared, { host: "ps2.test" });
    unauthenticated(r, "invalid_signature");
  });

  it("accepts the signed request whatever Host field carries, since Host never enters the base", async () => {
    const url = `${w.origin}/person`;
    const prepared = prepare(w.clock, "POST", url, assistant, { resource: RS, mission_s256: s256 });
    const port = new URL(w.loopback).port;
    const r = await send("POST", url, prepared, { host: `ps.test:${port}` });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
  });

  it("refuses a person token in place of the agent token: 401 invalid_jwt", async () => {
    const pt = await personToken(w, assistant, RS, s256);
    const before = issuedCount(w);
    const r = await requestPersonToken(
      w,
      { ...assistant, token: pt },
      { resource: RS, mission_s256: s256 },
    );
    expect(r.status).toBe(401);
    expect(r.headers.get("signature-error")).toContain("error=invalid_jwt");
    expect(issuedCount(w)).toBe(before);
  });

  it("refuses an agent token from an issuer outside egress admission: 401 unknown_key", async () => {
    const outsider = { ...assistant };
    outsider.token = await w.ap.mint("aa-agent+jwt", {
      iss: "https://elsewhere.test",
      dwk: "aauth-agent.json",
      sub: "aauth:assistant@elsewhere.test",
      jti: "agent-token-1",
      iat: w.clock.s,
      exp: w.clock.s + 600,
      cnf: { jwk: assistant.key.publicJwk },
    });
    unauthenticated(
      await requestPersonToken(w, outsider, { resource: RS, mission_s256: s256 }),
      "unknown_key",
    );
  });

  it("refuses an expired agent token: 401 expired_jwt", async () => {
    const stale = await makeAgent(w.ap, w.clock, assistant.id, {
      cnf: { jwk: assistant.key.publicJwk },
      exp: w.clock.s + 5,
    });
    w.clock.advance(10);
    unauthenticated(
      await requestPersonToken(
        w,
        { ...assistant, token: stale.token },
        {
          resource: RS,
          mission_s256: s256,
        },
      ),
      "expired_jwt",
    );
  });

  it("authenticates the owner's read, a GET without a body", async () => {
    const url = `${w.origin}/mission/${s256}`;
    expect((await send("GET", url, prepare(w.clock, "GET", url, assistant))).status).toBe(200);
    expect((await send("GET", url, { headers: {} })).status).toBe(401);
  });
});

describe("PS metadata", () => {
  it("publishes its issuer, jwks_uri and endpoints, and a JWKS with a fully-specified alg", async () => {
    const metaResponse = await fetch(`${w.loopback}/.well-known/aauth-person.json`);
    expect(metaResponse.headers.get("cache-control")).toBe("max-age=300");
    const meta = await metaResponse.json();
    expect(meta).toEqual({
      issuer: "https://ps.test",
      jwks_uri: "https://ps.test/.well-known/jwks.json",
      person_token_endpoint: "https://ps.test/person",
      auth_token_endpoint: "https://ps.test/token",
      mission_endpoint: "https://ps.test/mission",
    });
    const jwksResponse = await fetch(`${w.loopback}/.well-known/jwks.json`);
    expect(jwksResponse.headers.get("cache-control")).toBe("max-age=300");
    const jwks = (await jwksResponse.json()) as { keys: Record<string, unknown>[] };
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).toMatchObject({
      kty: "OKP",
      crv: "Ed25519",
      alg: "Ed25519",
      kid: "ps-signing-1",
    });
    expect(jwks.keys[0]).not.toHaveProperty("d");
  });
});
