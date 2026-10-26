/**
 * @spec #831 C2: the demo stack's RAS trust anchor for the AS issuer: its
 * own cross-domain key resolved locally, every other kid only through the
 * AS's published set.
 */
import { exportJWK, generateKeyPair, jwtVerify, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { composedTrustAnchor } from "../src/ras-trust-anchor.js";

async function signer(kid: string) {
  const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
  return {
    publicKey,
    jwk: { ...(await exportJWK(publicKey)), kid, alg: "ES256" },
    sign: () => new SignJWT({ iss: "https://as.test" }).setProtectedHeader({ alg: "ES256", kid }).sign(privateKey),
  };
}

describe("the RAS trust anchor for the AS issuer (@spec #831 C2)", () => {
  it("resolves the local cross-domain kid locally and every other kid only through the published set", async () => {
    const crossDomain = await signer("as-crossdomain");
    const continuation = await signer("as-continuation-2");
    const asked: string[] = [];
    const anchor = composedTrustAnchor([crossDomain.jwk], async (header) => {
      asked.push(String(header.kid));
      if (header.kid !== "as-continuation-2") throw new Error(`untrusted ${String(header.kid)}`);
      return continuation.publicKey;
    });
    await jwtVerify(await crossDomain.sign(), anchor);
    expect(asked).toEqual([]);
    await jwtVerify(await continuation.sign(), anchor);
    expect(asked).toEqual(["as-continuation-2"]);
    // A kid the published set refuses is refused, whoever signed it.
    const stray = await signer("as-continuation");
    await expect(jwtVerify(await stray.sign(), anchor)).rejects.toThrow(/untrusted as-continuation/);
    expect(asked).toEqual(["as-continuation-2", "as-continuation"]);
  });
});
