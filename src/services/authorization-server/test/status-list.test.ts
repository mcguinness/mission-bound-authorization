import { DERIVATION_POLICY } from "@mission/demo-data";
import {
  type CryptoKey,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify,
  type KeyLike,
} from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  MissionKernel,
  type MissionRecord,
  readStatus,
  readStatusBit,
  signStatusListToken,
  STATUS_INVALID,
  STATUS_SUSPENDED,
  STATUS_VALID,
  statusListUri,
  validateMissionIntent,
  verifyStatusListToken,
} from "../src/index.js";

const ISS = "https://as.test";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource as string;
const URI = statusListUri(ISS);

// A mutable clock so we can advance past an expiry deterministically.
let clock = new Date("2027-06-01T00:00:00Z");
const now = () => clock;

// Anti-oracle guard: a non-sequential, non-creation-order allocator. Distinct
// values that are NOT sorted, so "index != creation order" is observable.
const ALLOC = [41, 7, 88, 3, 60];
let allocCursor = 0;
const allocateStatusIndex = () => ALLOC[allocCursor++ % ALLOC.length] as number;

// Mission 2 (the 3rd) gets an earlier expiry so a single clock advance expires
// it while the later ones stay active — the applyExpiry-enumerator guard.
const EXPIRIES = [
  "2030-01-01T00:00:00Z",
  "2030-01-01T00:00:00Z",
  "2027-07-01T00:00:00Z",
  "2030-01-01T00:00:00Z",
  "2030-01-01T00:00:00Z",
];

let kernel: MissionKernel;
let signingKey: CryptoKey;
let verifyKey: KeyLike | Uint8Array;
const missions: MissionRecord[] = [];
const idxs: number[] = [];

beforeAll(async () => {
  const keys = await generateKeyPair("ES256", { extractable: true });
  signingKey = keys.privateKey;
  const pubJwk = { ...(await exportJWK(keys.publicKey)), kid: "as-status", alg: "ES256", use: "sig" };
  verifyKey = await importJWK(pubJwk, "ES256");

  kernel = new MissionKernel({
    issuer: ISS,
    policy: DERIVATION_POLICY as never,
    statusKey: keys.privateKey,
    statusKid: "as-status",
    now,
    allocateStatusIndex,
  });

  for (let n = 0; n < 5; n++) {
    const raw = JSON.stringify({
      goal: `Pay Acme invoices ${n}`,
      target_resources: [RESOURCE],
      expires_at: EXPIRIES[n],
    });
    const m = kernel.approve({
      intent: validateMissionIntent(raw),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: `sl-apev-${n}`,
    });
    missions.push(m);
    idxs.push(kernel.participateInStatusList(m.id));
  }
});

describe("Mission Status List (@spec status-list#status-list)", () => {
  it("allocates non-sequential, non-creation-order indices (anti-oracle)", () => {
    expect(idxs).toEqual(ALLOC);
    // distinct
    expect(new Set(idxs).size).toBe(idxs.length);
    // NOT sequential / not creation-ordered
    expect(idxs).not.toEqual([...idxs].sort((a, b) => a - b));
    // the status_list reference surfaces on the authoritative projection
    const rec = kernel.get(missions[0].id) as MissionRecord;
    const proj = kernel.introspectionMission(rec) as {
      status_list?: { idx: number; uri: string };
    };
    expect(proj.status_list).toEqual({ idx: idxs[0], uri: URI });
    // idempotent participation returns the same index
    expect(kernel.participateInStatusList(missions[0].id)).toBe(idxs[0]);
  });

  it("publishes a signed statuslist+jwt; every participant reads VALID (0x00)", async () => {
    const jws = await kernel.publishStatusList();

    // Verify against the as-status public JWK.
    const { payload, protectedHeader } = await jwtVerify(jws, verifyKey, { currentDate: clock });
    expect(protectedHeader.typ).toBe("statuslist+jwt");
    expect(protectedHeader.alg).toBe("ES256");
    expect(protectedHeader.kid).toBe("as-status");
    expect(payload.iss).toBe(ISS);
    expect(payload.sub).toBe(URI); // sub MUST equal the list uri
    const sl = payload.status_list as { bits: number; lst: string };
    expect(sl.bits).toBe(2);
    expect(typeof sl.lst).toBe("string");

    const token = await verifyStatusListToken(jws, verifyKey, { uri: URI, now: clock });
    for (const idx of idxs) {
      expect(readStatusBit(token, idx)).toBe(STATUS_VALID); // 0x00
      expect(readStatus(token, idx, clock)).toBe("active");
    }
  });

  it("reflects revoke, suspend, and expiry across the set (applyExpiry-enumerator fix)", async () => {
    kernel.transition(missions[0].id, "revoke"); // -> INVALID (0x01)
    kernel.transition(missions[1].id, "suspend"); // -> SUSPENDED (0x02)
    // mission 2 is never explicitly transitioned; advancing the clock past its
    // expires_at must make the enumerator commit `expired` before packing.
    clock = new Date("2027-08-01T00:00:00Z");

    const jws = await kernel.publishStatusList();
    const token = await verifyStatusListToken(jws, verifyKey, { uri: URI, now: clock });

    expect(readStatusBit(token, idxs[0])).toBe(STATUS_INVALID); // revoked
    expect(readStatusBit(token, idxs[1])).toBe(STATUS_SUSPENDED); // suspended
    expect(readStatusBit(token, idxs[2])).toBe(STATUS_INVALID); // expired (via applyExpiry)
    expect(readStatusBit(token, idxs[3])).toBe(STATUS_VALID); // still active
    expect(readStatusBit(token, idxs[4])).toBe(STATUS_VALID); // still active

    // And the persisted state was actually committed to `expired`.
    expect(kernel.get(missions[2].id)?.state).toBe("expired");
  });

  it("readStatus: VALID -> active; INVALID/SUSPENDED/reserved 0x03/unknown/expired -> non-active", async () => {
    const t0 = new Date("2027-06-01T00:00:00Z");
    // Sign directly with raw bits so we can exercise the reserved 0x03 value,
    // which stateToBit never emits.
    const jws = await signStatusListToken({
      issuer: ISS,
      uri: URI,
      kid: "as-status",
      key: signingKey,
      now: t0,
      entries: [
        { idx: 1, bit: STATUS_VALID },
        { idx: 2, bit: STATUS_INVALID },
        { idx: 3, bit: STATUS_SUSPENDED },
        { idx: 4, bit: 0x03 }, // reserved / unused
      ],
    });
    const token = await verifyStatusListToken(jws, verifyKey, { uri: URI, now: t0 });

    expect(readStatus(token, 1, t0)).toBe("active");
    expect(readStatus(token, 2, t0)).toBe("non-active");
    expect(readStatus(token, 3, t0)).toBe("non-active");
    expect(readStatus(token, 4, t0)).toBe("non-active"); // reserved 0x03
    expect(readStatus(token, 999_999, t0)).toBe("non-active"); // unknown / out of range

    // Past the token's exp, even a VALID entry is non-active (stale != permission).
    const past = new Date(t0.getTime() + 400_000);
    expect(readStatus(token, 1, past)).toBe("non-active");
  });

  it("refuses to enroll a non-active Mission (fail-safe: no VALID bit for a non-active idx)", () => {
    const raw = JSON.stringify({
      goal: "late enroll",
      target_resources: [RESOURCE],
      expires_at: "2030-01-01T00:00:00Z",
    });
    const m = kernel.approve({
      intent: validateMissionIntent(raw),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: "sl-apev-guard",
    });
    kernel.transition(m.id, "revoke");
    expect(() => kernel.participateInStatusList(m.id)).toThrow();
  });
});
