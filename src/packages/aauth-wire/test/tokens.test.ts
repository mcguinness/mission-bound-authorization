import { randomUUID } from "node:crypto";
import { beforeEach, describe, expect, it } from "vitest";
import {
  generateSigningKey,
  jwkThumbprint,
  mintToken,
  SignatureError,
  type SigningKey,
  type TokenVerificationOptions,
  verifyAgentToken,
  verifyAuthToken,
  verifyPersonToken,
  verifyResourceToken,
} from "../src/index.js";
import { AP, AS, agentToken, FakeNetwork, NOW, NOW_MS, PS, RESOURCE } from "./fixtures.js";

let net: FakeNetwork;
let ap: ReturnType<FakeNetwork["issuer"]>;
let ps: ReturnType<FakeNetwork["issuer"]>;
let resource: ReturnType<FakeNetwork["issuer"]>;
let agentKey: SigningKey;

beforeEach(() => {
  net = new FakeNetwork();
  ap = net.issuer(AP, "aauth-agent.json");
  ps = net.issuer(PS, "aauth-person.json");
  resource = net.issuer(RESOURCE, "aauth-resource.json");
  agentKey = generateSigningKey("Ed25519");
});

const opts = (extra: Partial<TokenVerificationOptions> = {}): TokenVerificationOptions => ({
  resolver: net.resolver(),
  now: () => NOW_MS,
  ...extra,
});

const personClaims = (extra: Record<string, unknown> = {}) => ({
  iss: PS,
  dwk: "aauth-person.json",
  aud: RESOURCE,
  sub: "8f14e45f",
  jti: randomUUID(),
  iat: NOW,
  exp: NOW + 600,
  cnf: { jwk: agentKey.publicJwk },
  ...extra,
});

const authClaims = (extra: Record<string, unknown> = {}) => ({
  iss: PS,
  dwk: "aauth-person.json",
  aud: RESOURCE,
  ps: PS,
  sub: "8f14e45f",
  jti: randomUUID(),
  iat: NOW,
  exp: NOW + 600,
  cnf: { jwk: agentKey.publicJwk },
  ...extra,
});

async function resourceClaims(extra: Record<string, unknown> = {}) {
  return {
    iss: RESOURCE,
    dwk: "aauth-resource.json",
    aud: PS,
    ps: PS,
    sub: "8f14e45f",
    presented_jti: "pt-1",
    agent_jkt: await jwkThumbprint(agentKey.publicJwk),
    jti: randomUUID(),
    iat: NOW,
    exp: NOW + 300,
    ...extra,
  };
}

async function rejects(promise: Promise<unknown>, code: string, detail?: RegExp): Promise<void> {
  const err = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(SignatureError);
  expect((err as SignatureError).code).toBe(code);
  if (detail) expect((err as SignatureError).detail).toMatch(detail);
}

describe("common JWT verification (@spec aauth#section-11.5.2)", () => {
  it("accepts a well-formed agent token", async () => {
    const token = await verifyAgentToken(await agentToken(ap, agentKey), opts());
    expect(token.typ).toBe("aa-agent+jwt");
  });

  it("rejects alg none", async () => {
    const header = Buffer.from(
      JSON.stringify({ alg: "none", typ: "aa-agent+jwt", kid: "key-1" }),
    ).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ iss: AP })).toString("base64url");
    await rejects(verifyAgentToken(`${header}.${payload}.`, opts()), "invalid_jwt", /alg none/);
  });

  it("rejects the polymorphic EdDSA header alg", async () => {
    const jwt = await agentToken(ap, agentKey);
    const [h, p, s] = jwt.split(".");
    const header = JSON.parse(Buffer.from(h ?? "", "base64url").toString());
    const forged = Buffer.from(JSON.stringify({ ...header, alg: "EdDSA" })).toString("base64url");
    await rejects(verifyAgentToken(`${forged}.${p}.${s}`, opts()), "invalid_jwt", /alg EdDSA/);
  });

  it("rejects a token of another typ (a person token where an auth token is required)", async () => {
    const person = await mintToken("aa-person+jwt", personClaims(), ps);
    await rejects(verifyAuthToken(person, { ...opts(), audience: RESOURCE }), "invalid_jwt", /typ/);
  });

  it("rejects an exp that is not in the future, with no skew tolerance", async () => {
    const jwt = await agentToken(ap, agentKey, { exp: NOW });
    await rejects(verifyAgentToken(jwt, opts()), "expired_jwt");
  });

  it("refuses an iat ahead of the clock only when a bound is applied", async () => {
    const jwt = await agentToken(ap, agentKey, { iat: NOW + 120 });
    await verifyAgentToken(jwt, opts());
    await rejects(verifyAgentToken(jwt, opts({ iatSkewSeconds: 60 })), "clock_skew");
  });

  it("rejects the wrong dwk for the type", async () => {
    const jwt = await agentToken(ap, agentKey, { dwk: "aauth-person.json" });
    await rejects(verifyAgentToken(jwt, opts()), "invalid_jwt", /dwk/);
  });

  it("rejects an iss that is not a server identifier, before any fetch", async () => {
    const jwt = await agentToken(ap, agentKey, { iss: "https://AP.example/" });
    await rejects(verifyAgentToken(jwt, opts()), "invalid_jwt", /iss/);
    expect(net.fetched).toEqual([]);
  });

  it("rejects a token signed by a key the issuer does not publish", async () => {
    const forger = { ...generateSigningKey("Ed25519"), kid: ap.kid, id: AP };
    await rejects(
      verifyAgentToken(await agentToken(forger, agentKey), opts()),
      "invalid_jwt",
      /signature/,
    );
  });

  it("rejects an unknown kid as unknown_key", async () => {
    const stranger = { ...generateSigningKey("Ed25519"), kid: "key-9", id: AP };
    await rejects(verifyAgentToken(await agentToken(stranger, agentKey), opts()), "unknown_key");
  });

  it("reports a revoked token only once it verifies", async () => {
    const jwt = await agentToken(ap, agentKey);
    await rejects(verifyAgentToken(jwt, opts({ isRevoked: () => true })), "revoked_jwt");
  });

  it("refreshes a cached key once when it fails verification (key rotation)", async () => {
    let now = NOW_MS;
    const resolver = net.resolver(() => now);
    await verifyAgentToken(await agentToken(ap, agentKey), { resolver, now: () => now });
    const rotated = { ...generateSigningKey("Ed25519", ap.kid), kid: ap.kid, id: AP };
    net.documents.set(`${AP}/jwks.json`, { keys: [rotated.publicJwk] });
    now += 60_000;
    const token = await verifyAgentToken(await agentToken(rotated, agentKey), {
      resolver,
      now: () => now,
    });
    expect(token.typ).toBe("aa-agent+jwt");
  });
});

describe("agent token (@spec aauth#section-5.3.3)", () => {
  it("rejects a sub that is not an agent identifier", async () => {
    const jwt = await agentToken(ap, agentKey, { sub: "My Agent@ap.example" });
    await rejects(verifyAgentToken(jwt, opts()), "invalid_jwt", /agent identifier/);
  });

  it("rejects a ps that is not a server identifier", async () => {
    const jwt = await agentToken(ap, agentKey, { ps: "http://ps.example" });
    await rejects(verifyAgentToken(jwt, opts()), "invalid_jwt", /ps/);
  });
});

describe("person token (@spec aauth#section-7.1.4)", () => {
  it("accepts a person token addressed to this resource", async () => {
    const jwt = await mintToken("aa-person+jwt", personClaims(), ps);
    expect((await verifyPersonToken(jwt, { ...opts(), audience: RESOURCE })).typ).toBe(
      "aa-person+jwt",
    );
  });

  it("rejects the wrong audience", async () => {
    const jwt = await mintToken(
      "aa-person+jwt",
      personClaims({ aud: "https://other.example" }),
      ps,
    );
    await rejects(verifyPersonToken(jwt, { ...opts(), audience: RESOURCE }), "invalid_jwt", /aud/);
  });

  it("rejects a lifetime over one hour", async () => {
    const jwt = await mintToken("aa-person+jwt", personClaims({ exp: NOW + 3601 }), ps);
    await rejects(
      verifyPersonToken(jwt, { ...opts(), audience: RESOURCE }),
      "invalid_jwt",
      /lifetime/,
    );
  });

  it("rejects a person token without cnf.jwk", async () => {
    const jwt = await mintToken("aa-person+jwt", personClaims({ cnf: undefined }), ps);
    await rejects(verifyPersonToken(jwt, { ...opts(), audience: RESOURCE }), "invalid_jwt", /cnf/);
  });

  it("rejects a person token carrying scope", async () => {
    const jwt = await mintToken("aa-person+jwt", personClaims({ scope: "read" }), ps);
    await rejects(
      verifyPersonToken(jwt, { ...opts(), audience: RESOURCE }),
      "invalid_jwt",
      /scope/,
    );
  });
});

describe("resource token (@spec aauth#section-6.7.1)", () => {
  it("accepts a resource token bound to the signing key", async () => {
    const jwt = await mintToken("aa-resource+jwt", await resourceClaims(), resource);
    const agentJkt = await jwkThumbprint(agentKey.publicJwk);
    expect((await verifyResourceToken(jwt, { ...opts(), audience: PS, agentJkt })).typ).toBe(
      "aa-resource+jwt",
    );
  });

  it("rejects an agent_jkt that is not the signing key's thumbprint", async () => {
    const jwt = await mintToken("aa-resource+jwt", await resourceClaims(), resource);
    const other = await jwkThumbprint(generateSigningKey().publicJwk);
    await rejects(
      verifyResourceToken(jwt, { ...opts(), audience: PS, agentJkt: other }),
      "invalid_jwt",
      /agent_jkt/,
    );
  });

  it("rejects a resource token carrying cnf", async () => {
    const jwt = await mintToken(
      "aa-resource+jwt",
      await resourceClaims({ cnf: { jwk: agentKey.publicJwk } }),
      resource,
    );
    await rejects(verifyResourceToken(jwt, { ...opts(), audience: PS }), "invalid_jwt", /cnf/);
  });

  it("rejects a resource token without presented_jti", async () => {
    const jwt = await mintToken(
      "aa-resource+jwt",
      await resourceClaims({ presented_jti: undefined }),
      resource,
    );
    await rejects(
      verifyResourceToken(jwt, { ...opts(), audience: PS }),
      "invalid_jwt",
      /presented_jti/,
    );
  });

  it("rejects a resource token for another PS", async () => {
    const jwt = await mintToken("aa-resource+jwt", await resourceClaims({ aud: AS }), resource);
    await rejects(verifyResourceToken(jwt, { ...opts(), audience: PS }), "invalid_jwt", /aud/);
  });
});

describe("auth token (@spec aauth#section-9.4.3)", () => {
  it("accepts a PS-issued auth token and an AS-issued one", async () => {
    const fromPs = await mintToken("aa-auth+jwt", authClaims(), ps);
    expect((await verifyAuthToken(fromPs, { ...opts(), audience: RESOURCE })).typ).toBe(
      "aa-auth+jwt",
    );
    const as = net.issuer(AS, "aauth-access.json");
    const fromAs = await mintToken(
      "aa-auth+jwt",
      authClaims({ iss: AS, dwk: "aauth-access.json" }),
      as,
    );
    expect((await verifyAuthToken(fromAs, { ...opts(), audience: RESOURCE })).payload.iss).toBe(AS);
  });

  it("rejects a PS-issued auth token whose ps is not its iss", async () => {
    const jwt = await mintToken("aa-auth+jwt", authClaims({ ps: "https://other.example" }), ps);
    await rejects(verifyAuthToken(jwt, { ...opts(), audience: RESOURCE }), "invalid_jwt", /ps/);
  });

  it("rejects an auth token without sub", async () => {
    const jwt = await mintToken("aa-auth+jwt", authClaims({ sub: undefined }), ps);
    await rejects(verifyAuthToken(jwt, { ...opts(), audience: RESOURCE }), "invalid_jwt", /sub/);
  });

  it("rejects a lifetime over one hour", async () => {
    const jwt = await mintToken("aa-auth+jwt", authClaims({ exp: NOW + 3601 }), ps);
    await rejects(
      verifyAuthToken(jwt, { ...opts(), audience: RESOURCE }),
      "invalid_jwt",
      /lifetime/,
    );
  });
});

describe("review hardening: token claims (@spec aauth#section-5.1, aauth#section-9.4.3.2)", () => {
  it("rejects an agent identifier from another agent provider's domain", async () => {
    const jwt = await agentToken(ap, agentKey, { sub: "aauth:assistant@bank.example" });
    await rejects(verifyAgentToken(jwt, opts()), "invalid_jwt", /another agent provider/);
  });

  it("checks cnf.jwk structure in a standalone person token verification", async () => {
    const jwt = await mintToken(
      "aa-person+jwt",
      personClaims({ cnf: { jwk: { kty: "OKP", crv: "Ed25519" } } }),
      ps,
    );
    await rejects(
      verifyPersonToken(jwt, { ...opts(), audience: RESOURCE }),
      "invalid_key",
      /missing members/,
    );
  });

  it("checks the cnf.jwk alg in a standalone auth token verification", async () => {
    const { alg: _alg, ...withoutAlg } = agentKey.publicJwk;
    const jwt = await mintToken("aa-auth+jwt", authClaims({ cnf: { jwk: withoutAlg } }), ps);
    await rejects(verifyAuthToken(jwt, { ...opts(), audience: RESOURCE }), "unsupported_algorithm");
  });
});
