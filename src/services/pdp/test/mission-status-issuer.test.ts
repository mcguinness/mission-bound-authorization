/**
 * @spec status#mission-status (#1724 D5): a consumer resolves the Mission
 * Status endpoint from the expected issuer its own configuration names,
 * retrieves that issuer's metadata validated as RFC 8414 Section 3.3 requires,
 * and verifies responses with keys from that issuer's `jwks_uri`
 * (`missionStatusIssuer`, the separated MAS pilot's configuration step).
 */
import { exportJWK, generateKeyPair, jwtVerify, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { missionStatusIssuer } from "../src/index.js";

const ISSUER = "https://as.test";
const STATUS_KID = "as-status";

async function statusKey() {
  const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
  return {
    jwk: { ...(await exportJWK(publicKey)), kid: STATUS_KID, alg: "ES256" },
    sign: () => new SignJWT({ iss: ISSUER }).setProtectedHeader({ alg: "ES256", kid: STATUS_KID }).sign(privateKey),
  };
}

/** Metadata for `issuer`, with its advertised Status endpoint and key set location. */
const metadataOf = (issuer: string, extra: Record<string, unknown> = {}) => ({
  issuer,
  mission_status_endpoint: `${issuer}/mission/status`,
  jwks_uri: "https://keys.as.test/status-jwks",
  ...extra,
});

describe("a consumer configures the Mission Status operation from the issuer it expects (@spec status#mission-status, #1724 D5)", () => {
  it("retrieves the expected issuer's metadata, at that identifier unless the configuration places it elsewhere, and takes the endpoint it advertises", async () => {
    const reads: string[] = [];
    const read = async (url: string) => {
      reads.push(url);
      return metadataOf(ISSUER);
    };
    const direct = await missionStatusIssuer(ISSUER, { read, kids: [STATUS_KID], algs: ["ES256"] });
    expect(direct.statusEndpoint).toBe(`${ISSUER}/mission/status`);
    const placed = await missionStatusIssuer(ISSUER, { read, location: "http://127.0.0.1:9/", kids: [STATUS_KID], algs: ["ES256"] });
    expect(placed.statusEndpoint).toBe(`${ISSUER}/mission/status`);
    expect(reads).toEqual([`${ISSUER}/.well-known/openid-configuration`, "http://127.0.0.1:9/.well-known/openid-configuration"]);
  });

  it("refuses metadata whose issuer is not the identifier it expects, and metadata advertising no Status endpoint or no jwks_uri", async () => {
    const config = { kids: [STATUS_KID], algs: ["ES256"] };
    await expect(missionStatusIssuer(ISSUER, { ...config, read: async () => metadataOf("https://impostor.test") })).rejects.toThrow(
      /names https:\/\/impostor\.test, not the expected issuer https:\/\/as\.test/,
    );
    await expect(missionStatusIssuer(ISSUER, { ...config, read: async () => metadataOf(`${ISSUER}/`) })).rejects.toThrow(
      /not the expected issuer/,
    );
    await expect(
      missionStatusIssuer(ISSUER, { ...config, read: async () => metadataOf(ISSUER, { mission_status_endpoint: undefined }) }),
    ).rejects.toThrow(/advertises no mission_status_endpoint/);
    await expect(missionStatusIssuer(ISSUER, { ...config, read: async () => metadataOf(ISSUER, { jwks_uri: undefined }) })).rejects.toThrow(
      /advertises no jwks_uri/,
    );
  });

  it("verifies only under the declared Status keys at the validated metadata's jwks_uri, never a key served elsewhere", async () => {
    const advertised = await statusKey();
    const elsewhere = await statusKey();
    const served: Record<string, unknown> = {
      "https://keys.as.test/status-jwks": { keys: [advertised.jwk] },
      [`${ISSUER}/jwks`]: { keys: [elsewhere.jwk] },
    };
    const fetched: string[] = [];
    const { keys } = await missionStatusIssuer(ISSUER, {
      read: async () => metadataOf(ISSUER),
      kids: [STATUS_KID],
      algs: ["ES256"],
      fetch: async (url) => {
        fetched.push(String(url));
        return new Response(JSON.stringify(served[String(url)] ?? { keys: [] }), { headers: { "cache-control": "max-age=60" } });
      },
    });
    await jwtVerify(await advertised.sign(), keys);
    await expect(jwtVerify(await elsewhere.sign(), keys)).rejects.toThrow();
    expect(fetched).toEqual(["https://keys.as.test/status-jwks"]);
  });
});
