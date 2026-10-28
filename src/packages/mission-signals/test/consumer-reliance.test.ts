/**
 * @spec control-plane#state-surfaces, signals#consumer-behavior (#1747, D942):
 * the Signals receiver as a consumer that relies on push-derived state.
 *
 * Covered here:
 *  - `lease()` gives no lease while the rematerialization latch or a version
 *    gap is open, until a Mission Status refresh covers it;
 *  - a push-only lease carries the issuer's observation time and reliance
 *    bound, the same at every read, and gives no lease past the bound;
 *  - a Mission Status refresh re-establishes a state past its bound, at the
 *    Status observation point;
 *  - an older Status observation never overrides newer retained state, and
 *    version wins over severity;
 *  - a store written before the observation columns gives no lease until a
 *    Status refresh.
 *
 * Package-only: no shipped service constructs a receiver.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { LifecycleCommit } from "@mission/authorization-server";
import { openStore } from "@mission/store";
import { type CryptoKey, exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MissionSignalReceiver, type ReceiverOptions, signLifecycleEvent } from "../src/index.js";

const ISS = "https://as.reliance.test";
const AUD = "https://consumer.reliance.test";
const CLIENT = "consumer-client";
const EXPIRES_AT = "2099-01-01T00:00:00Z";

let setKey: CryptoKey;
let statusKey: CryptoKey;
let jwks: { keys: JWK[] };
const dirs: string[] = [];

beforeAll(async () => {
  const sets = await generateKeyPair("ES256", { extractable: true });
  const status = await generateKeyPair("ES256", { extractable: true });
  setKey = sets.privateKey;
  statusKey = status.privateKey;
  jwks = {
    keys: [
      { ...(await exportJWK(sets.publicKey)), kid: "as-signals", alg: "ES256", use: "sig" },
      { ...(await exportJWK(status.publicKey)), kid: "as-status", alg: "ES256", use: "sig" },
    ],
  };
});

afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

const receiver = (extra: Partial<ReceiverOptions> = {}) =>
  new MissionSignalReceiver({
    jwks,
    issuer: ISS,
    audience: AUD,
    status: { clientId: CLIENT },
    ...extra,
  });

let events = 0;
/** One signed lifecycle-change SET committed at `committedAt` (a fresh `jti`). */
function set(
  missionId: string,
  version: number,
  state: LifecycleCommit["state"],
  committedAt: string | undefined,
  extra: Partial<LifecycleCommit> = {},
): Promise<string> {
  events += 1;
  const commit = {
    id: missionId,
    issuer: ISS,
    state,
    version,
    ...(committedAt !== undefined ? { committed_at: committedAt } : {}),
    expires_at: EXPIRES_AT,
    event_id: `set_reliance_${events}`,
    ...(state === "terminated"
      ? {
          termination: {
            reason: "revoked",
            terminated_at: committedAt ?? "2026-10-01T00:00:00Z",
            version,
          },
        }
      : {}),
    ...extra,
  } as LifecycleCommit;
  return signLifecycleEvent(commit, { audience: AUD, key: setKey, kid: "as-signals" });
}

/** A signed state-only Mission Status response to this consumer's request, observed now. */
function statusResponse(
  missionId: string,
  version: number,
  state: string,
  nonce: string,
): Promise<string> {
  const iat = Math.floor(Date.now() / 1000);
  return new SignJWT({
    sub: CLIENT,
    nonce,
    mission: {
      id: missionId,
      issuer: ISS,
      state,
      version,
      expires_at: EXPIRES_AT,
      fresh_until: new Date((iat + 60) * 1000).toISOString(),
    },
  })
    .setProtectedHeader({ alg: "ES256", kid: "as-status", typ: "mission-status-response+jwt" })
    .setIssuer(ISS)
    .setAudience(CLIENT)
    .setIssuedAt(iat)
    .setExpirationTime(iat + 60)
    .sign(statusKey);
}

async function refresh(
  r: MissionSignalReceiver,
  missionId: string,
  version: number,
  state: string,
) {
  return r.resynchronize(
    missionId,
    await statusResponse(missionId, version, state, r.statusNonce(missionId)),
  );
}

const nowIso = () => new Date().toISOString();
const plus = (iso: string, seconds: number) =>
  new Date(Date.parse(iso) + seconds * 1000).toISOString();

describe("Signals consumer reliance (@spec control-plane#state-surfaces, signals#consumer-behavior, #1747)", () => {
  it("gives no lease while the rematerialization latch is set; a state-only Mission Status refresh does not clear it, only the consumer's acknowledgement does (D950)", async () => {
    const r = receiver();
    try {
      await r.verifyAndApply(await set("msn_a", 1, "active", nowIso()));
      expect(r.lease("msn_a", nowIso())).toMatchObject({ state: "active", version: 1 });
      // A narrowing on the stream: the latch is set, so no lease.
      const narrowed = await r.verifyAndApply(
        await set("msn_a", 2, "active", nowIso(), { authority_changed: true }),
      );
      expect(narrowed).toMatchObject({ status: "applied", rematerialize: true });
      expect(r.lease("msn_a", nowIso())).toBeUndefined();
      // The review's probe: a state-only Status response at the narrowed
      // version re-establishes state, and carries no authority, so the latch
      // stays and there is still no lease.
      expect(await refresh(r, "msn_a", 2, "active")).toMatchObject({
        status: "resynchronized",
        version: 2,
      });
      expect(r.needsRematerialization("msn_a")).toBe(true);
      expect(r.lease("msn_a", nowIso())).toBeUndefined();
      // The consumer acknowledges once it refreshed its effective authority; a
      // stale acknowledgement does not clear the latch.
      expect(r.markRematerialized("msn_a", { version: 1 })).toBe(false);
      expect(r.lease("msn_a", nowIso())).toBeUndefined();
      expect(r.markRematerialized("msn_a", { version: 2 })).toBe(true);
      expect(r.lease("msn_a", nowIso())).toMatchObject({
        state: "active",
        version: 2,
        state_source: "status",
      });
    } finally {
      r.close();
    }
  });

  it("keeps a version gap across later contiguous events until a Mission Status refresh covers it, and latches rematerialization for the missing event (D950)", async () => {
    const r = receiver();
    try {
      await r.verifyAndApply(await set("msn_a", 1, "active", nowIso()));
      // The review's probe: versions 1, 3, 4.
      expect(await r.verifyAndApply(await set("msn_a", 3, "active", nowIso()))).toMatchObject({
        status: "gap",
        rematerialize: true,
      });
      expect(r.hasGap("msn_a")).toBe(true);
      expect(r.lease("msn_a", nowIso())).toBeUndefined();
      expect((await r.verifyAndApply(await set("msn_a", 4, "active", nowIso()))).status).toBe(
        "applied",
      );
      expect(r.hasGap("msn_a")).toBe(true);
      expect(r.lease("msn_a", nowIso())).toBeUndefined();
      // Status covers the gap; the missing event may have narrowed authority,
      // so the latch stays until the consumer acknowledges.
      expect(await refresh(r, "msn_a", 4, "active")).toMatchObject({
        status: "resynchronized",
        version: 4,
      });
      expect(r.hasGap("msn_a")).toBe(false);
      expect(r.needsRematerialization("msn_a")).toBe(true);
      expect(r.lease("msn_a", nowIso())).toBeUndefined();
      expect(r.markRematerialized("msn_a", { version: 2 })).toBe(false);
      expect(r.markRematerialized("msn_a", { version: 4 })).toBe(true);
      expect(r.lease("msn_a", nowIso())).toMatchObject({ state: "active", version: 4 });
    } finally {
      r.close();
    }
  });

  it("reports the issuer's observation time and reliance bound at every read, and gives no lease past the bound", async () => {
    const committed = "2026-11-01T00:00:00.000Z";
    const r = receiver();
    const short = receiver({ maxStaleSeconds: 60 });
    try {
      const event = await set("msn_a", 1, "active", committed);
      await r.verifyAndApply(event);
      await short.verifyAndApply(event);
      const expected = {
        state: "active",
        version: 1,
        status_checked_at: committed,
        status_expires_at: plus(committed, 300),
      };
      // Two reads at different instants: the same observation time and bound.
      expect(r.lease("msn_a", plus(committed, 10))).toMatchObject(expected);
      expect(r.lease("msn_a", plus(committed, 200))).toMatchObject(expected);
      expect(r.lease("msn_a", plus(committed, 299))).toMatchObject(expected);
      expect(r.lease("msn_a", plus(committed, 300))).toBeUndefined();
      expect(r.lease("msn_a", plus(committed, 3600))).toBeUndefined();
      expect(short.lease("msn_a", plus(committed, 59))).toMatchObject({
        status_expires_at: plus(committed, 60),
      });
      expect(short.lease("msn_a", plus(committed, 60))).toBeUndefined();
      // A state that is not active permits nothing; its lease keeps the
      // observation time and the Mission's expiry.
      await r.verifyAndApply(await set("msn_t", 1, "terminated", committed));
      expect(r.lease("msn_t", plus(committed, 86_400))).toMatchObject({
        state: "terminated",
        status_checked_at: committed,
        status_expires_at: EXPIRES_AT,
      });
      // An event without a usable commit time applies, but gives no lease.
      expect((await r.verifyAndApply(await set("msn_n", 1, "active", undefined))).status).toBe(
        "applied",
      );
      expect(r.viewState("msn_n")).toMatchObject({ state: "active", version: 1 });
      expect(r.lease("msn_n", nowIso())).toBeUndefined();
    } finally {
      r.close();
      short.close();
    }
  });

  it("re-establishes a push-only state past its bound from a Mission Status refresh, at the Status observation point", async () => {
    const committed = "2026-10-01T00:00:00.000Z";
    const r = receiver();
    try {
      const event = await set("msn_a", 1, "active", committed);
      await r.verifyAndApply(event);
      expect(r.lease("msn_a", nowIso())).toBeUndefined();
      const before = Math.floor(Date.now() / 1000) * 1000;
      expect(await refresh(r, "msn_a", 1, "active")).toMatchObject({
        status: "resynchronized",
        version: 1,
      });
      const lease = r.lease("msn_a", nowIso());
      expect(lease).toMatchObject({ state: "active", version: 1, state_source: "status" });
      expect(Date.parse(lease?.status_checked_at as string)).toBeGreaterThanOrEqual(before);
      // At the same version the SET that established the state is kept.
      expect(r.retainedSet("msn_a")).toBe(event);
    } finally {
      r.close();
    }
  });

  it("never lets an older Status observation override newer retained state, and takes a newer one whatever its state", async () => {
    const r = receiver();
    try {
      await r.verifyAndApply(await set("msn_a", 1, "active", nowIso()));
      await r.verifyAndApply(await set("msn_a", 2, "active", nowIso()));
      await r.verifyAndApply(await set("msn_a", 3, "suspended", nowIso()));
      // An older, more permissive observation is refused.
      expect(await refresh(r, "msn_a", 2, "active")).toEqual({
        status: "refused",
        reason: "behind",
      });
      expect(r.viewState("msn_a")).toMatchObject({ state: "suspended", version: 3 });
      expect(r.lease("msn_a", nowIso())).toMatchObject({
        state: "suspended",
        version: 3,
        state_source: "signal",
      });
      // A newer one wins on version, not severity: the resume is taken.
      expect(await refresh(r, "msn_a", 4, "active")).toMatchObject({
        status: "resynchronized",
        state: "active",
        version: 4,
      });
      expect(r.viewState("msn_a")).toMatchObject({ state: "active", version: 4 });
      expect(r.lease("msn_a", nowIso())).toMatchObject({
        state: "active",
        version: 4,
        state_source: "status",
      });
    } finally {
      r.close();
    }
  });

  it("gives no lease for a row a store wrote before the observation columns existed, until a Mission Status refresh", async () => {
    const dir = mkdtempSync(join(tmpdir(), "signal-reliance-"));
    dirs.push(dir);
    const file = join(dir, "receiver.db");
    const first = receiver({ store: { file } });
    await first.verifyAndApply(await set("msn_a", 1, "active", nowIso()));
    expect(first.lease("msn_a", nowIso())).toBeDefined();
    first.close();
    // The store as an earlier receiver wrote it: no observation columns.
    const raw = openStore("", { file });
    for (const column of ["observed_at", "reliance_until", "state_source"]) {
      raw.exec(`ALTER TABLE signal_receiver_missions DROP COLUMN ${column}`);
    }
    raw.close();
    const reopened = receiver({ store: { file } });
    try {
      expect(reopened.viewState("msn_a")).toMatchObject({ state: "active", version: 1 });
      expect(reopened.lease("msn_a", nowIso())).toBeUndefined();
      expect(await refresh(reopened, "msn_a", 1, "active")).toMatchObject({
        status: "resynchronized",
      });
      expect(reopened.lease("msn_a", nowIso())).toMatchObject({
        state: "active",
        version: 1,
        state_source: "status",
      });
    } finally {
      reopened.close();
    }
  });
});
