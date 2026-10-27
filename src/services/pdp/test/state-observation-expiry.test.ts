/**
 * @spec status#mission-status-response (consumer check 9), status#idempotency:
 * the shared Mission Status Response verifier, asked to REPORT expiry rather
 * than refuse it. The mode exists for a Lifecycle client that may accept an
 * expired replay of its own retained request as confirmation of that request's
 * outcome: every other check still decides, as of the response's own `exp`,
 * and the default mode is unchanged.
 */

import { createLocalJWKSet, exportJWK, generateKeyPair, type JWTVerifyGetKey, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { verifyMissionStatusResponse } from "../src/state-observation.js";

const ISSUER = "https://as.example";
const CLIENT_ID = "lifecycle-console";
const MISSION = "msn_expiry_report_0001";
const STATUS_KID = "as-status";
const TOLERANCE_S = 30;

let statusKey: CryptoKey;
let strangerKey: CryptoKey;
let keys: JWTVerifyGetKey;

beforeAll(async () => {
  const status = await generateKeyPair("ES256", { extractable: true });
  const stranger = await generateKeyPair("ES256", { extractable: true });
  statusKey = status.privateKey;
  strangerKey = stranger.privateKey;
  keys = createLocalJWKSet({ keys: [{ ...(await exportJWK(status.publicKey)), kid: STATUS_KID, alg: "ES256" }] });
});

/** A state-only Lifecycle response observed at `iat` (seconds), with `edit` applied. */
function claims(iat: number, edit: (p: Record<string, unknown>) => void = () => {}): Record<string, unknown> {
  const p: Record<string, unknown> = {
    iss: ISSUER,
    aud: CLIENT_ID,
    sub: CLIENT_ID,
    iat,
    exp: iat + 60,
    nonce: "n-1",
    mission: {
      id: MISSION,
      issuer: ISSUER,
      state: "suspended",
      version: 2,
      expires_at: "2027-06-01T00:00:00Z",
      fresh_until: new Date((iat + 60) * 1000).toISOString(),
    },
  };
  edit(p);
  return p;
}

const sign = (p: Record<string, unknown>, key: CryptoKey = statusKey): Promise<string> =>
  new SignJWT(p).setProtectedHeader({ alg: "ES256", kid: STATUS_KID, typ: "mission-status-response+jwt" }).sign(key);

const EXPECTED = { missionId: MISSION, issuer: ISSUER, audience: CLIENT_ID };
const IAT = 1_790_000_000;
/** An instant well past the response's `exp` plus the tolerance. */
const LATER = new Date((IAT + 60 + TOLERANCE_S + 60) * 1000);

describe("the shared Mission Status verifier, reporting expiry on request (@spec status#mission-status-response, status#idempotency)", () => {
  it("refuses a response whose exp has passed by default, and on request returns it marked expired once every other check passes", async () => {
    const jws = await sign(claims(IAT));
    expect(await verifyMissionStatusResponse(jws, EXPECTED, keys, LATER, TOLERANCE_S)).toBeUndefined();
    const reported = await verifyMissionStatusResponse(jws, EXPECTED, keys, LATER, TOLERANCE_S, { expired: "report" });
    expect(reported?.expired).toBe(true);
    expect(reported?.mission).toMatchObject({ id: MISSION, state: "suspended", version: 2 });
    // Within its lifetime the response is not marked, in either mode.
    const current = await verifyMissionStatusResponse(jws, EXPECTED, keys, new Date((IAT + 10) * 1000), TOLERANCE_S, { expired: "report" });
    expect(current).toBeDefined();
    expect("expired" in (current as object)).toBe(false);
  });

  it("still refuses an expired response that fails any other check: another audience, another issuer, another Mission, a fresh_until after exp, or a key it does not hold", async () => {
    const report = { expired: "report" } as const;
    const refused = async (jws: string) => expect(await verifyMissionStatusResponse(jws, EXPECTED, keys, LATER, TOLERANCE_S, report)).toBeUndefined();
    await refused(await sign(claims(IAT, (p) => { p.aud = "another-console"; })));
    await refused(await sign(claims(IAT, (p) => { p.iss = "https://impostor.example"; })));
    await refused(await sign(claims(IAT, (p) => { (p.mission as Record<string, unknown>).id = "msn_another"; })));
    await refused(
      await sign(claims(IAT, (p) => { (p.mission as Record<string, unknown>).fresh_until = new Date((IAT + 120) * 1000).toISOString(); })),
    );
    await refused(await sign(claims(IAT), strangerKey));
  });
});
