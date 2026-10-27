/**
 * @spec #831 C2: the declared Status keys over the issuer's published set
 * rather than a snapshot, held through `IssuerKeys`.
 */
import { exportJWK, generateKeyPair, jwtVerify, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { refreshingStatusKeys } from "../src/index.js";

describe("the declared Status keys over a jwks_uri (@spec #831 C2)", () => {
  it("verifies under a declared kid only, and follows the set the issuer publishes", async () => {
    const make = async (kid: string) => {
      const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
      return {
        jwk: { ...(await exportJWK(publicKey)), kid, alg: "ES256" },
        sign: () => new SignJWT({ iss: "https://as.test" }).setProtectedHeader({ alg: "ES256", kid }).sign(privateKey),
      };
    };
    const status = await make("as-status");
    const token = await make("as-token");
    let t = 0;
    let published = [status.jwk, token.jwk];
    const fetch = async () => new Response(JSON.stringify({ keys: published }), { headers: { "cache-control": "max-age=60" } });
    const { keys, trust } = refreshingStatusKeys("https://as.test/jwks", ["as-status"], { algs: ["ES256"], fetch, now: () => t });
    await jwtVerify(await status.sign(), keys);
    // Published, but not a declared Status key.
    await expect(jwtVerify(await token.sign(), keys)).rejects.toMatchObject({ code: "untrusted_kid" });
    // Withdrawn: still held within the declared lifetime, refused once stale and revalidated.
    published = [token.jwk];
    await jwtVerify(await status.sign(), keys);
    t += 60_000;
    await expect(jwtVerify(await status.sign(), keys)).rejects.toMatchObject({ code: "unknown_kid" });
    // Trusted while running (D825): the token key, now declared, verifies at the next use.
    trust(["as-token"]);
    await jwtVerify(await token.sign(), keys);
  });
});

describe("the Status consumer's jwks_uri freshness (@spec status#signing-key-retention, #831 B3)", () => {
  const make = async (kid: string) => {
    const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
    return {
      jwk: { ...(await exportJWK(publicKey)), kid, alg: "ES256" },
      sign: () => new SignJWT({ iss: "https://as.test" }).setProtectedHeader({ alg: "ES256", kid }).sign(privateKey),
    };
  };

  it("relies on a cached jwks_uri only within the freshness lifetime its response declares", async () => {
    const status = await make("as-status");
    let t = 0;
    let published = [status.jwk];
    let fetched = 0;
    const fetch = async () => {
      fetched++;
      return new Response(JSON.stringify({ keys: published }), { headers: { "cache-control": "max-age=60" } });
    };
    const { keys } = refreshingStatusKeys("https://as.test/jwks", ["as-status"], { algs: ["ES256"], fetch, now: () => t });
    await jwtVerify(await status.sign(), keys);
    published = [];
    t += 59_999;
    // Within the lifetime: the cached copy, unrevalidated.
    await jwtVerify(await status.sign(), keys);
    expect(fetched).toBe(1);
    // At its end: revalidated, then refreshed once more for the trusted kid it
    // no longer finds, and the withdrawn key refused.
    t += 1;
    await expect(jwtVerify(await status.sign(), keys)).rejects.toMatchObject({ code: "unknown_kid" });
    expect(fetched).toBe(3);
  });

  it("gives a jwks_uri response without explicit freshness no lifetime: every verification revalidates", async () => {
    const status = await make("as-status");
    let fetched = 0;
    const fetch = async () => {
      fetched++;
      return new Response(JSON.stringify({ keys: [status.jwk] }));
    };
    const { keys } = refreshingStatusKeys("https://as.test/jwks", ["as-status"], { algs: ["ES256"], fetch, now: () => 0 });
    for (let i = 0; i < 3; i++) await jwtVerify(await status.sign(), keys);
    expect(fetched).toBe(3);
  });

  it("refuses a Status response when the stale jwks_uri cannot be revalidated, never falling back to the stale copy", async () => {
    const status = await make("as-status");
    let t = 0;
    let down = false;
    const fetch = async () => {
      if (down) throw new Error("connection refused");
      return new Response(JSON.stringify({ keys: [status.jwk] }), { headers: { "cache-control": "max-age=60" } });
    };
    const { keys } = refreshingStatusKeys("https://as.test/jwks", ["as-status"], { algs: ["ES256"], fetch, now: () => t });
    await jwtVerify(await status.sign(), keys);
    down = true;
    t += 60_000;
    await expect(jwtVerify(await status.sign(), keys)).rejects.toMatchObject({ code: "unavailable" });
    // Revalidated once the jwks_uri answers again.
    down = false;
    await jwtVerify(await status.sign(), keys);
  });
});
