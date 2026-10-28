import { createIssuerStub, decodeClaims, type IssuerStub } from "@mission/aauth-testkit";
import { BASE_COMPONENTS, signRequest } from "@mission/aauth-wire";
import { afterEach, describe, expect, it } from "vitest";
import type { ResourceConfig } from "../src/index.js";
import {
  anotherPs,
  PS,
  RESOURCE,
  requirementOf,
  SwitchableStore,
  shippedConfig,
  type World,
  world,
} from "./helpers.js";

let w: World;
afterEach(() => w?.close());

const DOCS = `${RESOURCE}/api/documents`;
const AUTHORIZE = `${RESOURCE}/authorize`;
const REVOKE = `${RESOURCE}/revoke`;

/** The Resource ran, issued and established nothing. */
const nothingHappened = () => {
  expect(w.resource.effects).toEqual([]);
  expect(w.resource.issuedResourceTokens).toEqual([]);
  expect(w.resource.persons).toEqual([]);
};

/** `{jti, exp}` of a token, as its PS's record holds them. */
const pairOf = (token: string) => {
  const { jti, exp } = decodeClaims(token);
  return { jti: jti as string, exp: exp as number };
};

/** Serve a server that signs under `dwk` at `issuer`, on the world's network. */
async function signer(issuer: string, dwk: string): Promise<IssuerStub> {
  const stub = createIssuerStub({ issuer, dwk });
  await w.net.serve(issuer, stub.handler);
  return stub;
}

function withLimits(limits: Partial<ResourceConfig["revocationLimits"]>): ResourceConfig {
  const config = shippedConfig();
  return { ...config, revocationLimits: { ...config.revocationLimits, ...limits } };
}

describe("the revocation endpoint (@spec aauth#section-11.12.1, aauth#section-11.12.3)", () => {
  it("records a PS's {jti, exp} under its verified identity and answers 200 with no body", async () => {
    w = await world();
    const res = await w.ps.revoke({ jti: "pt-1", exp: w.seconds() + 600 });
    expect(res.status).toBe(200);
    expect(res.body.length).toBe(0);
    expect(res.headers["content-type"]).toBeUndefined();
    expect(w.resource.revocations.entries()).toEqual([
      { iss: PS, jti: "pt-1", exp: w.seconds() + 600, recordedAt: w.seconds() },
    ]);
  });

  it("takes the issuer from the signature, never from a request member", async () => {
    w = await world();
    const res = await w.ps.revoke({
      jti: "pt-1",
      exp: w.seconds() + 600,
      iss: "https://ps2.test",
    });
    expect(res.status).toBe(200);
    expect(w.resource.revocations.entries().map((e) => e.iss)).toEqual([PS]);
  });

  it("records nothing new for a repeat, answers it 200, and keeps the first exp", async () => {
    w = await world();
    const exp = w.seconds() + 600;
    expect((await w.ps.revoke({ jti: "pt-1", exp })).status).toBe(200);
    w.clock.advance(1000);
    const again = await w.ps.revoke({ jti: "pt-1", exp: exp + 3000 });
    expect(again.status).toBe(200);
    expect(again.body.length).toBe(0);
    expect(w.resource.revocations.entries()).toEqual([
      { iss: PS, jti: "pt-1", exp, recordedAt: w.seconds() - 1 },
    ]);
  });

  it.each([
    ["an access server", "https://as.test", "aauth-access.json"],
    ["an agent provider", "https://ap2.test", "aauth-agent.json"],
    ["another resource", "https://rs2.test", "aauth-resource.json"],
  ])(
    "refuses %s with unsupported_iss after its signature verifies, recording nothing",
    async (_what, issuer, dwk) => {
      w = await world();
      const caller = await signer(issuer, dwk);
      const res = await w.ps.revoke({ jti: "x-1", exp: w.seconds() + 600 }, { as: caller });
      expect(res.status).toBe(403);
      expect(res.headers["content-type"]).toBe("application/problem+json");
      expect(res.json()).toMatchObject({ error: "unsupported_iss" });
      expect(res.headers["signature-error"]).toBeUndefined();
      expect(res.headers["accept-signature-scheme"]).toBeUndefined();
      expect(w.resource.revocations.entries()).toEqual([]);
    },
  );

  it("refuses a request signed under the jwt scheme: an agent revokes nothing here", async () => {
    w = await world();
    const pt = await w.ps.personToken(w.agent);
    const res = await w.agent.send(REVOKE, { method: "POST", body: pairOf(pt), token: pt });
    expect(res.status).toBe(401);
    expect(res.headers["signature-error"]).toBe("error=unsupported_scheme");
    expect(res.headers["accept-signature-scheme"]).toBe("jwks_uri");
    expect(w.resource.revocations.entries()).toEqual([]);
  });

  it("requires Content-Digest and Content-Type to be covered", async () => {
    w = await world();
    const res = await w.ps.revoke(
      { jti: "pt-1", exp: w.seconds() + 600 },
      { components: BASE_COMPONENTS },
    );
    expect(res.status).toBe(401);
    expect(res.headers["signature-error"]).toBe(
      'error=invalid_input, required_input=("@method" "@authority" "@path" "signature-key" "content-digest" "content-type")',
    );
    expect(w.resource.revocations.entries()).toEqual([]);
  });

  it("refuses a key the PS does not publish, and a signature by another key", async () => {
    w = await world();
    const exp = w.seconds() + 600;
    const unknown = await w.ps.revoke(
      { jti: "pt-1", exp },
      { signatureKey: { scheme: "jwks_uri", id: PS, dwk: "aauth-person.json", kid: "nope" } },
    );
    expect([unknown.status, unknown.headers["signature-error"]]).toEqual([
      401,
      "error=unknown_key",
    ]);
    // Another key, claiming the PS's identity and key id.
    const forger = createIssuerStub({ issuer: PS, dwk: "aauth-person.json", kid: "ps-key-1" });
    const forged = await w.ps.revoke({ jti: "pt-1", exp }, { as: forger });
    expect([forged.status, forged.headers["signature-error"]]).toEqual([
      401,
      "error=invalid_signature",
    ]);
    expect(w.resource.revocations.entries()).toEqual([]);
  });

  it("refuses a body that is not the one signed", async () => {
    w = await world();
    const url = REVOKE;
    const signed = JSON.stringify({ jti: "pt-1", exp: w.seconds() + 600 });
    const headers = { "content-type": "application/json" };
    const added = signRequest(
      { method: "POST", url, headers, body: signed },
      {
        alg: w.ps.key.alg,
        privateKey: w.ps.key.privateKey,
        signatureKey: { scheme: "jwks_uri", id: PS, dwk: "aauth-person.json", kid: "ps-key-1" },
        created: w.seconds(),
      },
    );
    const res = await w.net.request({
      method: "POST",
      url,
      headers: { ...headers, ...added },
      body: JSON.stringify({ jti: "pt-2", exp: w.seconds() + 600 }),
    });
    expect([res.status, res.headers["signature-error"]]).toEqual([401, "error=invalid_signature"]);
    expect(w.resource.revocations.entries()).toEqual([]);
  });

  it("refuses a replayed revocation, and accepts a second revocation signed in the same second", async () => {
    w = await world();
    const exp = w.seconds() + 600;
    const url = REVOKE;
    const body = JSON.stringify({ jti: "pt-1", exp });
    const headers = { "content-type": "application/json" };
    const added = signRequest(
      { method: "POST", url, headers, body },
      {
        alg: w.ps.key.alg,
        privateKey: w.ps.key.privateKey,
        signatureKey: { scheme: "jwks_uri", id: PS, dwk: "aauth-person.json", kid: "ps-key-1" },
        created: w.seconds(),
      },
    );
    const message = { method: "POST", url, headers: { ...headers, ...added }, body };
    expect((await w.net.request(message)).status).toBe(200);
    const replay = await w.net.request(message);
    expect([replay.status, replay.headers["signature-error"]]).toEqual([
      401,
      "error=invalid_signature",
    ]);
    // Same key, same second, same method, authority and path; another body.
    const second = await w.ps.revoke({ jti: "at-1", exp });
    expect(second.status).toBe(200);
    expect(w.resource.revocations.entries().map((e) => e.jti)).toEqual(["pt-1", "at-1"]);
  });

  it.each([
    ["no members", {}],
    ["no jti", { exp: 2000000000 }],
    ["an empty jti", { jti: "", exp: 2000000000 }],
    ["a jti that is not a string", { jti: 7, exp: 2000000000 }],
    ["no exp", { jti: "pt-1" }],
    ["an exp that is a string", { jti: "pt-1", exp: "2000000000" }],
    ["an exp that is not an integer", { jti: "pt-1", exp: 2000000000.5 }],
    ["an exp that is not a NumericDate", { jti: "pt-1", exp: 0 }],
  ])("refuses %s with invalid_request, recording nothing", async (_what, body) => {
    w = await world();
    const res = await w.ps.revoke(body);
    expect(res.status).toBe(400);
    expect(res.headers["content-type"]).toBe("application/problem+json");
    expect(res.json()).toMatchObject({ error: "invalid_request" });
    expect(w.resource.revocations.entries()).toEqual([]);
  });

  it.each([
    ["malformed JSON", { raw: '{"jti": "pt-1",' }],
    ["a JSON array", { raw: '["pt-1", 2000000000]' }],
    ["a body that is not application/json", { contentType: "text/plain" }],
  ])("refuses %s with invalid_request, recording nothing", async (_what, options) => {
    w = await world();
    const res = await w.ps.revoke({ jti: "pt-1", exp: w.seconds() + 600 }, options);
    expect(res.status).toBe(400);
    expect(res.json()).toMatchObject({ error: "invalid_request" });
    expect(w.resource.revocations.entries()).toEqual([]);
  });

  it("bounds each issuer's requests per minute: rate_limited with Retry-After, recording nothing", async () => {
    w = await world(undefined, { config: withLimits({ requestsPerIssuerPerMinute: 2 }) });
    const exp = w.seconds() + 600;
    expect((await w.ps.revoke({ jti: "a", exp })).status).toBe(200);
    expect((await w.ps.revoke({ jti: "b", exp })).status).toBe(200);
    const limited = await w.ps.revoke({ jti: "c", exp });
    expect(limited.status).toBe(429);
    expect(limited.json()).toMatchObject({ error: "rate_limited" });
    const turn = Math.ceil((60_000 - (w.clock.now() % 60_000)) / 1000);
    expect(limited.headers["retry-after"]).toBe(String(turn));
    expect(w.resource.revocations.entries().map((e) => e.jti)).toEqual(["a", "b"]);
    // Another issuer has its own budget.
    const ps2 = await anotherPs(w, "https://ps2.test");
    expect((await ps2.revoke({ jti: "c", exp })).status).toBe(200);
    // Once the window turns, the first issuer is accepted again.
    w.clock.advance(turn * 1000);
    expect((await w.ps.revoke({ jti: "c", exp })).status).toBe(200);
  });

  it("bounds the entries one issuer holds: rate_limited until its earliest entry lapses", async () => {
    w = await world(undefined, { config: withLimits({ entriesPerIssuer: 2 }) });
    const now = w.seconds();
    expect((await w.ps.revoke({ jti: "a", exp: now + 100 })).status).toBe(200);
    expect((await w.ps.revoke({ jti: "b", exp: now + 200 })).status).toBe(200);
    const full = await w.ps.revoke({ jti: "c", exp: now + 300 });
    expect(full.status).toBe(429);
    expect(full.json()).toMatchObject({ error: "rate_limited" });
    expect(full.headers["retry-after"]).toBe("100");
    // A repeat of a held entry is not a new entry. (Signed a second later:
    // the same bytes in the same second are a replay.)
    w.clock.advance(1000);
    expect((await w.ps.revoke({ jti: "a", exp: now + 100 })).status).toBe(200);
    expect(w.resource.revocations.entries().map((e) => e.jti)).toEqual(["a", "b"]);
    w.clock.advance(99_000);
    expect((await w.ps.revoke({ jti: "c", exp: now + 300 })).status).toBe(200);
    expect(w.resource.revocations.entries().map((e) => e.jti)).toEqual(["b", "c"]);
  });

  it("fails closed when the revoked set cannot record: 500, never 200", async () => {
    let store: SwitchableStore | undefined;
    w = await world(undefined, {
      wrapStore: (inner) => {
        store = new SwitchableStore(inner);
        return store;
      },
    });
    (store as SwitchableStore).failWrites = true;
    const res = await w.ps.revoke({ jti: "pt-1", exp: w.seconds() + 600 });
    expect(res.status).toBe(500);
    expect(res.json()).toMatchObject({ error: "server_error" });
    expect(w.resource.revocations.entries()).toEqual([]);
  });

  it("discards an entry once its exp has passed", async () => {
    w = await world();
    const now = w.seconds();
    await w.ps.revoke({ jti: "a", exp: now + 10 });
    await w.ps.revoke({ jti: "b", exp: now + 1000 });
    w.clock.advance(10_000);
    await w.ps.revoke({ jti: "c", exp: now + 1000 });
    expect(w.resource.revocations.entries().map((e) => e.jti)).toEqual(["b", "c"]);
  });
});

describe("a revoked token presented (@spec aauth#section-11.12.4, aauth#section-11.12.5)", () => {
  it("refuses a revoked person token with revoked_jwt and issues no resource token naming it", async () => {
    w = await world();
    const pt = await w.ps.personToken(w.agent);
    expect((await w.ps.revoke(pairOf(pt))).status).toBe(200);
    const res = await w.agent.send(DOCS, { token: pt });
    expect(res.status).toBe(401);
    expect(res.headers["signature-error"]).toBe("error=revoked_jwt");
    expect(res.headers["aauth-requirement"]).toBeUndefined();
    expect(res.json()).toMatchObject({ error: "revoked_jwt" });
    nothingHappened();
  });

  it("refuses a revoked person token at the authorization endpoint", async () => {
    w = await world();
    const pt = await w.ps.personToken(w.agent);
    await w.ps.revoke(pairOf(pt));
    const res = await w.agent.send(AUTHORIZE, {
      method: "POST",
      body: { scope: "documents.read" },
      token: pt,
    });
    expect([res.status, res.headers["signature-error"]]).toEqual([401, "error=revoked_jwt"]);
    expect(res.json()).not.toHaveProperty("resource_token");
    nothingHappened();
  });

  it("refuses a revoked auth token with revoked_jwt and requirement=person-token, running nothing", async () => {
    w = await world();
    const at = await w.ps.authToken(w.agent);
    expect((await w.agent.send(DOCS, { token: at })).status).toBe(200);
    expect(w.resource.effects).toHaveLength(1);
    await w.ps.revoke(pairOf(at));
    const res = await w.agent.send(DOCS, { method: "POST", body: { title: "x" }, token: at });
    expect(res.status).toBe(401);
    expect(res.headers["signature-error"]).toBe("error=revoked_jwt");
    expect(requirementOf(res)).toEqual({ requirement: "person-token", resourceToken: undefined });
    expect(w.resource.effects).toHaveLength(1);
    expect(w.resource.issuedResourceTokens).toEqual([]);
  });

  it("answers a revoked auth token whose scope falls short with revoked_jwt, never a step-up", async () => {
    w = await world();
    const at = await w.ps.authToken(w.agent, { scope: "documents.read" });
    await w.ps.revoke(pairOf(at));
    const res = await w.agent.send(DOCS, { method: "POST", body: { title: "x" }, token: at });
    expect(res.status).toBe(401);
    expect(res.headers["signature-error"]).toBe("error=revoked_jwt");
    expect(requirementOf(res)).toEqual({ requirement: "person-token", resourceToken: undefined });
    nothingHappened();
  });

  it("keys the revoked set by (iss, jti): another PS revokes only its own token of that jti", async () => {
    w = await world();
    const ps2 = await anotherPs(w, "https://ps2.test");
    const mine = await w.ps.authToken(w.agent, { jti: "shared-jti" });
    const theirs = await ps2.authToken(w.agent, { jti: "shared-jti" });
    await ps2.revoke(pairOf(theirs));
    expect((await w.agent.send(DOCS, { token: mine })).status).toBe(200);
    const refused = await w.agent.send(DOCS, { token: theirs });
    expect([refused.status, refused.headers["signature-error"]]).toEqual([
      401,
      "error=revoked_jwt",
    ]);
    expect(w.resource.effects.map((e) => e.iss)).toEqual([PS]);
  });

  it("refuses only the token revoked: another token of the same PS still runs", async () => {
    w = await world();
    const revoked = await w.ps.authToken(w.agent);
    const other = await w.ps.authToken(w.agent);
    await w.ps.revoke(pairOf(revoked));
    expect((await w.agent.send(DOCS, { token: other })).status).toBe(200);
  });

  it("holds the revocation until the exp it named, then lets the entry lapse", async () => {
    w = await world();
    const at = await w.ps.authToken(w.agent);
    await w.ps.revoke({ jti: pairOf(at).jti, exp: w.seconds() + 100 });
    w.clock.advance(99_000);
    const held = await w.agent.send(DOCS, { token: at });
    expect(held.headers["signature-error"]).toBe("error=revoked_jwt");
    w.clock.advance(1000);
    expect((await w.agent.send(DOCS, { token: at })).status).toBe(200);
  });

  it("is expired, not revoked, once the token's own exp passes", async () => {
    w = await world();
    const pt = await w.ps.personToken(w.agent);
    const { exp } = pairOf(pt);
    await w.ps.revoke(pairOf(pt));
    w.clock.advance((exp - w.seconds() - 1) * 1000);
    const before = await w.agent.send(DOCS, { token: pt });
    expect(before.headers["signature-error"]).toBe("error=revoked_jwt");
    w.clock.advance(1000);
    const after = await w.agent.send(DOCS, { token: pt });
    expect(after.headers["signature-error"]).toBe("error=expired_jwt");
    nothingHappened();
  });

  it("fails closed when the revoked set cannot be read: 500, nothing runs or is issued", async () => {
    let store: SwitchableStore | undefined;
    w = await world(undefined, {
      wrapStore: (inner) => {
        store = new SwitchableStore(inner);
        return store;
      },
    });
    (store as SwitchableStore).failReads = true;
    for (const token of [await w.ps.authToken(w.agent), await w.ps.personToken(w.agent)]) {
      const res = await w.agent.send(DOCS, { token });
      expect(res.status).toBe(500);
      expect(res.json()).toMatchObject({ error: "server_error" });
    }
    nothingHappened();
  });
});

describe("durability", () => {
  it("keeps an acknowledged revocation across a restart", async () => {
    w = await world();
    const pt = await w.ps.personToken(w.agent);
    const at = await w.ps.authToken(w.agent);
    expect((await w.ps.revoke(pairOf(pt))).status).toBe(200);
    expect((await w.ps.revoke(pairOf(at))).status).toBe(200);
    const before = w.resource.revocations.entries();
    await w.restartResource();
    expect(w.resource.revocations.entries()).toEqual(before);
    for (const token of [pt, at]) {
      const res = await w.agent.send(DOCS, { token });
      expect([res.status, res.headers["signature-error"]]).toEqual([401, "error=revoked_jwt"]);
    }
    nothingHappened();
  });
});

describe("unavailable revocation (the testkit's switch)", () => {
  it("answers 503, closes the connection, or answers a malformed 200, recording nothing", async () => {
    w = await world();
    const exp = w.seconds() + 600;
    w.revocationSwitch.mode = "error";
    const failed = await w.ps.revoke({ jti: "a", exp });
    expect(failed.status).toBe(503);
    w.revocationSwitch.mode = "reset";
    await expect(w.ps.revoke({ jti: "b", exp })).rejects.toThrow();
    w.revocationSwitch.mode = "malformed";
    const malformed = await w.ps.revoke({ jti: "c", exp });
    expect(malformed.status).toBe(200);
    expect(() => JSON.parse(malformed.text())).toThrow();
    expect(w.resource.revocations.entries()).toEqual([]);
    expect(w.revocationSwitch.attempts.map((a) => a.mode)).toEqual(["error", "reset", "malformed"]);
    // Other endpoints are unaffected, and switching back restores revocation.
    expect((await w.agent.send(DOCS, { token: await w.ps.authToken(w.agent) })).status).toBe(200);
    w.revocationSwitch.mode = "available";
    expect((await w.ps.revoke({ jti: "d", exp })).status).toBe(200);
    expect(w.resource.revocations.entries().map((e) => e.jti)).toEqual(["d"]);
  });

  it("refuses connections to the whole Resource while the network refuses it", async () => {
    w = await world();
    const exp = w.seconds() + 600;
    await w.net.refuse(RESOURCE);
    await expect(w.ps.revoke({ jti: "a", exp })).rejects.toMatchObject({ code: "ECONNREFUSED" });
    w.net.restore(RESOURCE);
    expect((await w.ps.revoke({ jti: "a", exp })).status).toBe(200);
  });
});
