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
    const keys = refreshingStatusKeys("https://as.test/jwks", ["as-status"], { algs: ["ES256"], fetch, now: () => t });
    await jwtVerify(await status.sign(), keys);
    // Published, but not a declared Status key.
    await expect(jwtVerify(await token.sign(), keys)).rejects.toMatchObject({ code: "untrusted_kid" });
    // Withdrawn: still held within the declared lifetime, refused once stale and revalidated.
    published = [token.jwk];
    await jwtVerify(await status.sign(), keys);
    t += 60_000;
    await expect(jwtVerify(await status.sign(), keys)).rejects.toMatchObject({ code: "unknown_kid" });
  });
});
