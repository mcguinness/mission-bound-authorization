import { describe, expect, it } from "vitest";
import {
  determineAlgorithm,
  generateSigningKey,
  isAgentIdentifier,
  isServerIdentifier,
  JwksResolver,
  SignatureError,
} from "../src/index.js";
import { AP, FakeNetwork, NOW_MS, PS } from "./fixtures.js";

async function code(promise: Promise<unknown>): Promise<string | undefined> {
  return promise.then(
    () => undefined,
    (e: unknown) => (e as SignatureError).code,
  );
}

describe("issuer key discovery (@spec aauth#section-11.4)", () => {
  it("rejects metadata without issuer as issuer_missing", async () => {
    const net = new FakeNetwork();
    net.issuer(AP, "aauth-agent.json");
    net.documents.set(`${AP}/.well-known/aauth-agent.json`, { jwks_uri: `${AP}/jwks.json` });
    expect(await code(net.resolver().resolveKey(AP, "aauth-agent.json", "key-1"))).toBe(
      "issuer_missing",
    );
  });

  it("selects by kid without requiring other members to be usable", async () => {
    const net = new FakeNetwork();
    const ap = net.issuer(AP, "aauth-agent.json");
    net.documents.set(`${AP}/jwks.json`, {
      keys: [
        { kid: "weird", kty: "XYZ" },
        "not-an-object",
        { kty: "RSA", kid: "rsa", n: "x", e: "AQAB" },
        ap.publicJwk,
      ],
    });
    const key = await net.resolver().resolveKey(AP, "aauth-agent.json", "key-1");
    expect(key.x).toBe(ap.publicJwk.x);
  });

  it("fetches an issuer at most once a minute, refreshing on an unknown kid after that", async () => {
    const net = new FakeNetwork();
    net.issuer(AP, "aauth-agent.json");
    let now = NOW_MS;
    const resolver = net.resolver(() => now);
    await resolver.resolveKey(AP, "aauth-agent.json", "key-1");
    expect(net.fetched).toHaveLength(2);
    net.issuer(AP, "aauth-agent.json", "Ed25519", "key-2");
    expect(await code(resolver.resolveKey(AP, "aauth-agent.json", "key-2"))).toBe("unknown_key");
    expect(net.fetched).toHaveLength(2);
    now += 60_000;
    await resolver.resolveKey(AP, "aauth-agent.json", "key-2");
    expect(net.fetched).toHaveLength(4);
  });

  it("fetches an issuer's JWKS once for all of its documents", async () => {
    const net = new FakeNetwork();
    net.issuer(PS, "aauth-person.json");
    net.issuer(PS, "aauth-access.json", "Ed25519", "key-2");
    const resolver = net.resolver();
    await resolver.resolveKey(PS, "aauth-person.json", "key-1");
    await resolver.resolveKey(PS, "aauth-access.json", "key-2");
    expect(net.fetched).toEqual([
      `${PS}/.well-known/aauth-person.json`,
      `${PS}/jwks.json`,
      `${PS}/.well-known/aauth-access.json`,
    ]);
  });

  it("shares one JWKS fetch between an issuer's documents resolved at the same instant", async () => {
    const net = new FakeNetwork();
    net.issuer(PS, "aauth-person.json");
    net.issuer(PS, "aauth-access.json", "Ed25519", "key-2");
    const resolver = net.resolver();
    await Promise.all([
      resolver.resolveKey(PS, "aauth-person.json", "key-1"),
      resolver.resolveKey(PS, "aauth-access.json", "key-2"),
    ]);
    expect(net.fetched.filter((u) => u === `${PS}/jwks.json`)).toHaveLength(1);
  });

  it("does not fetch a second JWKS for the same issuer within the floor", async () => {
    const net = new FakeNetwork();
    net.issuer(PS, "aauth-person.json");
    net.documents.set(`${PS}/.well-known/aauth-access.json`, {
      issuer: PS,
      jwks_uri: `${PS}/access-jwks.json`,
    });
    net.documents.set(`${PS}/access-jwks.json`, net.documents.get(`${PS}/jwks.json`));
    let now = NOW_MS;
    const resolver = net.resolver(() => now);
    await resolver.resolveKey(PS, "aauth-person.json", "key-1");
    expect(await code(resolver.resolveKey(PS, "aauth-access.json", "key-1"))).toBe("unknown_key");
    expect(net.fetched).not.toContain(`${PS}/access-jwks.json`);
    now += 60_000;
    await resolver.resolveKey(PS, "aauth-access.json", "key-1");
    expect(net.fetched).toContain(`${PS}/access-jwks.json`);
  });

  it("discards cached keys after 24 hours", async () => {
    const net = new FakeNetwork();
    net.issuer(AP, "aauth-agent.json");
    let now = NOW_MS;
    const resolver = net.resolver(() => now);
    await resolver.resolveKey(AP, "aauth-agent.json", "key-1");
    now += 24 * 60 * 60 * 1000 + 1;
    await resolver.resolveKey(AP, "aauth-agent.json", "key-1");
    expect(net.fetched).toHaveLength(4);
  });

  it("serves cached keys when a refresh fails", async () => {
    const net = new FakeNetwork();
    net.issuer(AP, "aauth-agent.json");
    let now = NOW_MS;
    const resolver = net.resolver(() => now);
    await resolver.resolveKey(AP, "aauth-agent.json", "key-1");
    net.documents.clear();
    now += 60_000;
    const key = await resolver.resolveKey(AP, "aauth-agent.json", "key-1", { refresh: true });
    expect(key.kid).toBe("key-1");
  });

  it("applies egress admission before fetching", async () => {
    const net = new FakeNetwork();
    net.issuer(AP, "aauth-agent.json");
    const resolver = new JwksResolver({ fetchJson: net.fetchJson, admitEgress: () => false });
    expect(await code(resolver.resolveKey(AP, "aauth-agent.json", "key-1"))).toBe("unknown_key");
    expect(net.fetched).toEqual([]);
  });

  it("refuses a dwk that would leave /.well-known/", async () => {
    const net = new FakeNetwork();
    expect(await code(net.resolver().resolveKey(AP, "../jwks.json", "key-1"))).toBe("invalid_key");
  });
});

describe("algorithm determination (@spec aauth#section-11.3.1)", () => {
  it("rejects a symmetric key as unsupported_algorithm", () => {
    expect(() => determineAlgorithm({ kty: "oct", k: "c2VjcmV0", alg: "HS256" })).toThrow(
      /unsupported_algorithm: alg HS256/,
    );
  });

  it("rejects an OKP key missing x as invalid_key", () => {
    try {
      determineAlgorithm({ kty: "OKP", crv: "Ed25519", alg: "Ed25519" });
      expect.unreachable();
    } catch (e) {
      expect((e as SignatureError).code).toBe("invalid_key");
      expect((e as SignatureError).detail).toMatch(/missing members/);
    }
  });

  it("answers invalid_key, not a TypeError, for a kty naming an Object.prototype member", () => {
    const { x } = generateSigningKey("Ed25519").publicJwk as { x: string };
    for (const kty of ["constructor", "__proto__", "toString", "hasOwnProperty"]) {
      try {
        determineAlgorithm({ kty, crv: "Ed25519", x, alg: "Ed25519" });
        expect.unreachable();
      } catch (e) {
        expect(e).toBeInstanceOf(SignatureError);
        expect((e as SignatureError).code).toBe("invalid_key");
      }
    }
  });

  it("imports an Ed25519 and an ES256 key", () => {
    expect(determineAlgorithm(generateSigningKey("Ed25519").publicJwk).alg).toBe("Ed25519");
    expect(determineAlgorithm(generateSigningKey("ES256").publicJwk).alg).toBe("ES256");
  });
});

describe("identifiers (@spec aauth#section-11.1.1, aauth#section-5.2)", () => {
  it.each([
    ["https://agent.example", true],
    ["https://xn--nxasmq6b.example", true],
    ["http://agent.example", false],
    ["https://Agent.Example", false],
    ["https://agent.example:8443", false],
    ["https://agent.example/v1", false],
    ["https://agent.example/", false],
    ["https://agent.example?x=1", false],
  ])("server identifier %s is %s", (value, expected) => {
    expect(isServerIdentifier(value)).toBe(expected);
  });

  it.each([
    ["aauth:assistant-v2@agent.example", true],
    ["aauth:planner.7f3c+search1@vendor.example", true],
    ["My Agent@agent.example", false],
    ["aauth:@agent.example", false],
    ["aauth:agent@http://agent.example", false],
  ])("agent identifier %s is %s", (value, expected) => {
    expect(isAgentIdentifier(value)).toBe(expected);
  });
});

describe("resolver bounds and concurrency (@spec signature-key#section-7.2)", () => {
  it("bounds the cache: an evicted issuer is fetched again", async () => {
    const net = new FakeNetwork();
    net.issuer(AP, "aauth-agent.json");
    net.issuer("https://ap2.example", "aauth-agent.json");
    const resolver = net.resolver(() => NOW_MS, 1);
    await resolver.resolveKey(AP, "aauth-agent.json", "key-1");
    await resolver.resolveKey("https://ap2.example", "aauth-agent.json", "key-1");
    await resolver.resolveKey(AP, "aauth-agent.json", "key-1");
    expect(net.fetched).toHaveLength(6);
  });

  it("shares one fetch between concurrent first lookups", async () => {
    const net = new FakeNetwork();
    net.issuer(AP, "aauth-agent.json");
    const resolver = net.resolver();
    const results = await Promise.allSettled([
      resolver.resolveKey(AP, "aauth-agent.json", "key-1"),
      resolver.resolveKey(AP, "aauth-agent.json", "key-1"),
    ]);
    expect(results.map((r) => r.status)).toEqual(["fulfilled", "fulfilled"]);
    expect(net.fetched).toHaveLength(2);
  });
});
