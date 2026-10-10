/**
 * @spec RFC 9449 Section 4.3, Section 11.1 (#1173, D375)
 *
 * The Resource Server's one DPoP proof verifier: the token endpoint's
 * asymmetric acceptance window (60 s ahead, 240 s behind), and at the replay
 * cache's bound a new proof refused with {@link DpopReplayUnavailableError}
 * (its callers answer the pre-decision `state_unavailable`) while a seen proof
 * stays a replay. Needs no PDP, so it runs everywhere.
 */

import { newDpopProofReplay } from "@mission/core";
import { type CryptoKey, calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { accessTokenHash, DpopReplayUnavailableError, verifyDpopProof } from "../src/dpop.js";

const HTU = "https://rs.test/mcp";
const HTM = "POST";
const ACCESS_TOKEN = "an-access-token";

let keys: { publicKey: CryptoKey; privateKey: CryptoKey };
let jkt: string;

beforeAll(async () => {
  keys = await generateKeyPair("ES256", { extractable: true });
  jkt = await calculateJwkThumbprint(await exportJWK(keys.publicKey));
});

const nowS = (): number => Math.floor(Date.now() / 1000);

async function proof(claims: Record<string, unknown>): Promise<string> {
  return new SignJWT({ htu: HTU, htm: HTM, ath: accessTokenHash(ACCESS_TOKEN), jti: crypto.randomUUID(), ...claims })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .sign(keys.privateKey);
}

function verify(p: string, replay = newDpopProofReplay()): Promise<string> {
  return verifyDpopProof({ proof: p, accessToken: ACCESS_TOKEN, expectedJkt: jkt, htu: HTU, htm: HTM, replay });
}

describe("the Resource Server's DPoP proof verifier (@spec RFC 9449 Section 4.3, Section 11.1, #1173)", () => {
  it("accepts an iat up to 60 s ahead and 240 s behind, and refuses one beyond either bound", async () => {
    await expect(verify(await proof({ iat: nowS() + 50 }))).resolves.toBe(jkt);
    await expect(verify(await proof({ iat: nowS() - 230 }))).resolves.toBe(jkt);
    // Both were inside the old symmetric 300 s window.
    for (const iat of [nowS() + 90, nowS() - 260]) {
      await expect(verify(await proof({ iat }))).rejects.toThrow("outside the acceptance window");
    }
  });

  it("at the replay cache's bound refuses a new proof as replay state unavailable, and a seen proof as a replay", async () => {
    const replay = newDpopProofReplay(300, Date.now, 1);
    const seen = await proof({ iat: nowS() });
    await expect(verify(seen, replay)).resolves.toBe(jkt);
    const refused = await verify(await proof({ iat: nowS() }), replay).catch((e: unknown) => e);
    expect(refused).toBeInstanceOf(DpopReplayUnavailableError);
    expect((refused as DpopReplayUnavailableError).retryAfterS).toBeGreaterThan(0);
    await expect(verify(seen, replay)).rejects.toThrow("missing or replayed");
  });
});
