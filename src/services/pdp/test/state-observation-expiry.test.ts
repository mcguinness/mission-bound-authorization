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

  it("classifies expiry by exp and the verification time alone: current one second before exp, expired at exp and after it, inside the tolerance and beyond it, at the profile's tolerance and at zero (#1757 review)", async () => {
    const jws = await sign(claims(IAT));
    const exp = IAT + 60;
    const at = (s: number) => new Date(s * 1000);
    const report = { expired: "report" } as const;
    for (const tolerance of [TOLERANCE_S, 0]) {
      const before = await verifyMissionStatusResponse(jws, EXPECTED, keys, at(exp - 1), tolerance, report);
      expect(before, `tolerance ${tolerance}, exp - 1`).toBeDefined();
      expect("expired" in (before as object), `tolerance ${tolerance}, exp - 1`).toBe(false);
      for (const offset of [0, 1, TOLERANCE_S - 1, TOLERANCE_S, TOLERANCE_S + 1, 120]) {
        const reported = await verifyMissionStatusResponse(jws, EXPECTED, keys, at(exp + offset), tolerance, report);
        expect(reported?.expired, `tolerance ${tolerance}, exp + ${offset}`).toBe(true);
        expect(reported?.mission, `tolerance ${tolerance}, exp + ${offset}`).toMatchObject({ id: MISSION, state: "suspended" });
      }
    }
    // The default mode is unchanged: accepted and unmarked inside the
    // tolerance, refused beyond it.
    const inside = await verifyMissionStatusResponse(jws, EXPECTED, keys, at(exp + 1), TOLERANCE_S);
    expect(inside).toBeDefined();
    expect("expired" in (inside as object)).toBe(false);
    expect(await verifyMissionStatusResponse(jws, EXPECTED, keys, at(exp + TOLERANCE_S + 1), TOLERANCE_S)).toBeUndefined();
  });

  it("still refuses an expired response that fails any other check: another audience, another issuer, another Mission, a fresh_until after exp, or a key it does not hold, at its exp, just after it and long after, at the profile's tolerance and at zero", async () => {
    const report = { expired: "report" } as const;
    const instants = [new Date((IAT + 60) * 1000), new Date((IAT + 61) * 1000), LATER];
    const refused = async (jws: string) => {
      for (const tolerance of [TOLERANCE_S, 0]) {
        for (const when of instants) {
          expect(await verifyMissionStatusResponse(jws, EXPECTED, keys, when, tolerance, report), `tolerance ${tolerance}, ${when.toISOString()}`).toBeUndefined();
        }
      }
    };
    // The unedited response verifies at every one of those instants, so each refusal below is its one edit's.
    for (const tolerance of [TOLERANCE_S, 0]) {
      for (const when of instants) {
        const reported = await verifyMissionStatusResponse(await sign(claims(IAT)), EXPECTED, keys, when, tolerance, report);
        expect(reported?.expired, `tolerance ${tolerance}, ${when.toISOString()}`).toBe(true);
      }
    }
    await refused(await sign(claims(IAT, (p) => { p.aud = "another-console"; })));
    await refused(await sign(claims(IAT, (p) => { p.iss = "https://impostor.example"; })));
    await refused(await sign(claims(IAT, (p) => { (p.mission as Record<string, unknown>).id = "msn_another"; })));
    await refused(
      await sign(claims(IAT, (p) => { (p.mission as Record<string, unknown>).fresh_until = new Date((IAT + 120) * 1000).toISOString(); })),
    );
    await refused(await sign(claims(IAT), strangerKey));
  });
});
