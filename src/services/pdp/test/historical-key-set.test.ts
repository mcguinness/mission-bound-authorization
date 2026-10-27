/**
 * @spec status#historical-key-set, status#signing-key-retention (#831 B3)
 *
 * The PDP, the reference's Mission Status consumer, holding an AS's
 * historical key set: verified only under its configured Status keys, never
 * a source of a key for a current reliance decision, and a reason to refuse a
 * listed key the cached jwks_uri still carries.
 */

import { exportJWK, generateKeyPair, jwtVerify, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { auditKeys, HistoricalKeySetHolder, refreshingStatusKeys, verifyHistoricalKeySet } from "../src/index.js";

const ISSUER = "https://as.test";
const JWKS = `${ISSUER}/jwks`;
const HISTORICAL = `${ISSUER}/historical-jwks`;

async function key(kid: string) {
  const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
  const jwk = { ...(await exportJWK(publicKey)), kid, alg: "ES256", use: "sig" };
  const sign = () =>
    new SignJWT({ iss: ISSUER }).setProtectedHeader({ alg: "ES256", kid, typ: "mission-status-response+jwt" }).sign(privateKey);
  const signSet = (listed: Record<string, unknown>[], typ = "jwk-set+jwt") =>
    new SignJWT({ keys: listed }).setProtectedHeader({ alg: "ES256", kid, typ }).setIssuer(ISSUER).setIssuedAt().sign(privateKey);
  return { kid, jwk, sign, signSet };
}

const revoked = (jwk: Record<string, unknown>) => ({ ...jwk, revoked: { reason: "compromised", revoked_at: 1_800_000_000 } });

/** An issuer: its jwks_uri and its historical key set, each fresh for five minutes; an Error refuses. */
function issuer(state: { published: Record<string, unknown>[]; historical: string | Error | undefined }) {
  const requests: string[] = [];
  const fetch = async (url: string) => {
    requests.push(url);
    if (url === JWKS) {
      return new Response(JSON.stringify({ keys: state.published }), { headers: { "cache-control": "max-age=300" } });
    }
    if (state.historical instanceof Error) throw state.historical;
    if (state.historical === undefined) return new Response("", { status: 404 });
    return new Response(state.historical, {
      headers: { "content-type": "application/jwk-set+jwt", "cache-control": "max-age=300" },
    });
  };
  return { fetch, requests };
}

describe("a historical key set's signer, from the consumer's configuration (@spec status#historical-key-set, #831 B3)", () => {
  it("accepts a set signed under the configured Status key, and refuses one signed under another role's published key or an unconfigured replacement until the configuration names it", async () => {
    const status = await key("as-status");
    const token = await key("as-token");
    const replacement = await key("as-status-2");
    const old = await key("as-status-old");
    const state = { published: [status.jwk, token.jwk, replacement.jwk], historical: undefined as string | undefined };
    const { fetch } = issuer(state);
    let t = 0;
    const { keys, trust } = refreshingStatusKeys(JWKS, ["as-status"], { algs: ["ES256"], fetch, now: () => t });
    const verify = (jws: string) => verifyHistoricalKeySet(jws, { issuer: ISSUER, statusKeys: keys, algs: ["ES256"] });

    const listed = await verify(await status.signSet([revoked(old.jwk)]));
    expect(listed).toEqual([{ kid: "as-status-old", jwk: revoked(old.jwk), revokedAt: 1_800_000_000 }]);
    // Under the access-token key the AS also publishes: refused.
    await expect(verify(await token.signSet([revoked(old.jwk)]))).rejects.toThrow();
    // Not a jwk-set+jwt: refused.
    await expect(verify(await status.signSet([revoked(old.jwk)], "JWT"))).rejects.toThrow();
    // Under the Status key's replacement, before the configuration authorizes it: refused; after, accepted.
    const underReplacement = await replacement.signSet([revoked(status.jwk)]);
    await expect(verify(underReplacement)).rejects.toThrow();
    trust(["as-status", "as-status-2"]);
    t += 1;
    await expect(verify(underReplacement)).resolves.toHaveLength(1);
  });
});

describe("a listed key and a current reliance decision (@spec status#signing-key-retention, status#historical-key-set, #831 B3)", () => {
  it("never verifies a current response under a key the set lists, though a cached jwks_uri still carries it", async () => {
    const status = await key("as-status-2");
    const compromised = await key("as-status");
    // The AS has withdrawn as-status, but this consumer's cached jwks_uri, still fresh, carries it.
    const state = { published: [status.jwk, compromised.jwk], historical: await status.signSet([revoked(compromised.jwk)]) };
    const { fetch } = issuer(state);
    const withSet = refreshingStatusKeys(JWKS, ["as-status", "as-status-2"], {
      algs: ["ES256"],
      fetch,
      historical: { uri: HISTORICAL, issuer: ISSUER },
    });
    // The current Status key verifies a current response.
    await jwtVerify(await status.sign(), withSet.keys);
    // The listed key does not, for current reliance...
    await expect(jwtVerify(await compromised.sign(), withSet.keys)).rejects.toThrow(/withdrawn as compromised/);
    // ...while a consumer holding no set would accept it from its cached jwks_uri: the set is what refuses it.
    const withoutSet = refreshingStatusKeys(JWKS, ["as-status", "as-status-2"], { algs: ["ES256"], fetch });
    await jwtVerify(await compromised.sign(), withoutSet.keys);
  });

  it("never falls back to the set for a current reliance decision once the jwks_uri no longer carries a listed key; only audit verification reads it", async () => {
    const status = await key("as-status-2");
    const compromised = await key("as-status");
    const state = { published: [status.jwk], historical: await status.signSet([revoked(compromised.jwk)]) };
    const { fetch } = issuer(state);
    // The current keys never fall back to the set...
    const refreshed = refreshingStatusKeys(JWKS, ["as-status", "as-status-2"], {
      algs: ["ES256"],
      fetch,
      historical: { uri: HISTORICAL, issuer: ISSUER },
    });
    const archived = await compromised.sign();
    await expect(jwtVerify(archived, refreshed.keys)).rejects.toThrow();
    // ...and only audit verification reads it from the set.
    const listed = await refreshed.historical?.keys();
    expect(listed?.map((k) => k.kid)).toEqual(["as-status"]);
    await jwtVerify(archived, auditKeys(refreshed.keys, listed ?? []));
  });

  it("continues on the jwks_uri rule alone when no set has ever been fetched and verified: nothing is held, and the current keys decide", async () => {
    const status = await key("as-status-2");
    const compromised = await key("as-status");
    const other = await key("as-token");
    for (const historical of [new Error("unreachable"), await other.signSet([revoked(compromised.jwk)])]) {
      const state = { published: [status.jwk, compromised.jwk, other.jwk], historical };
      const { fetch } = issuer(state);
      const held = refreshingStatusKeys(JWKS, ["as-status", "as-status-2"], {
        algs: ["ES256"],
        fetch,
        historical: { uri: HISTORICAL, issuer: ISSUER },
      });
      expect(await held.historical?.keys()).toBeUndefined();
      await jwtVerify(await status.sign(), held.keys);
      // No verified set held: the key the cached jwks_uri carries still verifies, as without a set.
      await jwtVerify(await compromised.sign(), held.keys);
    }
  });

  it("keeps refusing a listed key through an outage of the set once it has verified one: a stale set can only refuse too much", async () => {
    const status = await key("as-status-2");
    const compromised = await key("as-status");
    const other = await key("as-token");
    let t = 0;
    const state: { published: Record<string, unknown>[]; historical: string | Error | undefined } = {
      published: [status.jwk, compromised.jwk],
      historical: await status.signSet([revoked(compromised.jwk)]),
    };
    const { fetch } = issuer(state);
    const held = refreshingStatusKeys(JWKS, ["as-status", "as-status-2"], {
      algs: ["ES256"],
      fetch,
      now: () => t,
      historical: { uri: HISTORICAL, issuer: ISSUER },
    });
    await expect(jwtVerify(await compromised.sign(), held.keys)).rejects.toThrow(/withdrawn as compromised/);
    // The set's lifetime passes and it cannot be refetched: the last verified set still refuses.
    state.historical = new Error("unreachable");
    t += 300_000;
    await expect(jwtVerify(await compromised.sign(), held.keys)).rejects.toThrow(/withdrawn as compromised/);
    expect((await held.historical?.keys())?.map((k) => k.kid)).toEqual(["as-status"]);
    // A set that does not verify keeps it too.
    state.historical = await other.signSet([]);
    await expect(jwtVerify(await compromised.sign(), held.keys)).rejects.toThrow(/withdrawn as compromised/);
    // The current Status key verifies throughout.
    await jwtVerify(await status.sign(), held.keys);
  });
});

describe("what the consumer learns as compromised, it keeps (@spec status#historical-key-set, status#signing-key-retention, #831 B3, D887)", () => {
  async function learned() {
    const status = await key("as-status-2");
    const compromised = await key("as-status");
    let t = 0;
    const state: { published: Record<string, unknown>[]; historical: string | Error | undefined } = {
      // The cached jwks_uri still carries the compromised key throughout.
      published: [status.jwk, compromised.jwk],
      historical: await status.signSet([revoked(compromised.jwk)]),
    };
    const { fetch } = issuer(state);
    const held = refreshingStatusKeys(JWKS, ["as-status", "as-status-2"], {
      algs: ["ES256"],
      fetch,
      now: () => t,
      historical: { uri: HISTORICAL, issuer: ISSUER },
    });
    await expect(jwtVerify(await compromised.sign(), held.keys)).rejects.toThrow(/withdrawn as compromised/);
    return { status, compromised, state, held, later: () => (t += 300_000) };
  }

  it("refuses a replacement set signed under a learned-compromised key, whether it empties the set or lists the current key", async () => {
    const { status, compromised, state, held, later } = await learned();
    // The compromised key signs an empty replacement.
    state.historical = await compromised.signSet([]);
    later();
    await expect(jwtVerify(await compromised.sign(), held.keys)).rejects.toThrow(/withdrawn as compromised/);
    // It signs a set listing the current key: refused whole, so the current key still verifies.
    state.historical = await compromised.signSet([revoked(compromised.jwk), revoked(status.jwk)]);
    later();
    await jwtVerify(await status.sign(), held.keys);
    expect((await held.historical?.keys())?.map((k) => k.kid)).toEqual(["as-status"]);
  });

  it("keeps a learned revocation through a replayed older or empty set the current key signed", async () => {
    const { status, compromised, state, held, later } = await learned();
    // A valid set, signed by the current Status key, from before the compromise: empty.
    state.historical = await status.signSet([]);
    later();
    await expect(jwtVerify(await compromised.sign(), held.keys)).rejects.toThrow(/withdrawn as compromised/);
    await jwtVerify(await status.sign(), held.keys);
    expect((await held.historical?.keys())?.map((k) => k.kid)).toEqual(["as-status"]);
  });
});

describe("the historical key set's refresh, bounded and shared (@spec status#historical-key-set, #831 B3, D887)", () => {
  it("bounds the fetch and its body together, shares one refresh among concurrent uses, and waits out a retry delay after a failure", async () => {
    let t = 0;
    let fetched = 0;
    // Headers arrive; the body never does.
    const fetch = async () => {
      fetched++;
      return new Response(new ReadableStream({ start() {} }), { headers: { "content-type": "application/jwk-set+jwt" } });
    };
    const holder = new HistoricalKeySetHolder({
      uri: HISTORICAL,
      issuer: ISSUER,
      statusKeys: async () => {
        throw new Error("unused");
      },
      algs: ["ES256"],
      fetch,
      now: () => t,
      timeoutMs: 50,
      retryDelayMs: 60_000,
    });
    const started = Date.now();
    expect(await Promise.all([holder.keys(), holder.keys(), holder.keys()])).toEqual([undefined, undefined, undefined]);
    expect(Date.now() - started).toBeLessThan(2000);
    expect(fetched).toBe(1);
    // Within the retry delay: answered from what is held, with no fetch.
    expect(await holder.keys()).toBeUndefined();
    expect(fetched).toBe(1);
    // After it: one more attempt.
    t += 60_000;
    await holder.keys();
    expect(fetched).toBe(2);
  });
});
