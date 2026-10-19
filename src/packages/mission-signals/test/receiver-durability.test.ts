/**
 * @spec signals#consumer-behavior, control-plane#isolation (#250 step 2,
 * slice B): the receiver's state in the consumer's own store.
 *
 * Covered here, on a file-backed receiver store:
 *  - a restart keeps the version high-water, the cached observation, the gap
 *    and rematerialization markers and the retained SET, and the seen `jti`
 *    values, so a redelivery is still a duplicate;
 *  - a lower or equal `version` never regresses state, before or after a
 *    restart, and a retained termination survives it;
 *  - a storage failure records nothing: the SET is not acknowledged, and its
 *    redelivery is processed afresh;
 *  - duplicate suppression is bounded, and evicting a `jti` never weakens
 *    anti-revival: the evicted SET is refused by the high-water as stale;
 *  - receivers for different issuers or audiences share one file without
 *    reading each other's rows.
 *
 * Package-only: no shipped service constructs a receiver.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { LifecycleCommit } from "@mission/authorization-server";
import { openStore } from "@mission/store";
import { type CryptoKey, exportJWK, generateKeyPair, type JWK } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  MissionSignalReceiver,
  SignalReceiverStorageError,
  signLifecycleEvent,
} from "../src/index.js";

const ISS = "https://as.durable.test";
const OTHER_ISS = "https://as.other.test";
const AUD = "https://consumer.durable.test";
const OTHER_AUD = "https://consumer.other.test";
const EXPIRES_AT = "2027-01-01T00:00:00Z";
const KID = "as-status";

let key: CryptoKey;
let jwks: { keys: JWK[] };
const dirs: string[] = [];

beforeAll(async () => {
  const pair = await generateKeyPair("ES256", { extractable: true });
  key = pair.privateKey;
  jwks = { keys: [{ ...(await exportJWK(pair.publicKey)), kid: KID, alg: "ES256", use: "sig" }] };
});

afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

function storeFile(): string {
  const dir = mkdtempSync(join(tmpdir(), "signal-receiver-"));
  dirs.push(dir);
  return join(dir, "receiver.db");
}

let events = 0;
/** One signed lifecycle-change SET for `audience` (a fresh `jti` unless one is given). */
function set(
  missionId: string,
  version: number,
  state: LifecycleCommit["state"],
  extra: Partial<LifecycleCommit> = {},
  opts: { issuer?: string; audience?: string; jti?: string } = {},
): Promise<string> {
  events += 1;
  const commit: LifecycleCommit = {
    id: missionId,
    issuer: opts.issuer ?? ISS,
    state,
    version,
    committed_at: new Date(Date.UTC(2026, 9, 1, 0, 0, version)).toISOString(),
    expires_at: EXPIRES_AT,
    event_id: opts.jti ?? `set_durable_${events}`,
    ...(state === "terminated"
      ? { termination: { reason: "revoked", terminated_at: "2026-10-01T00:00:00Z", version } }
      : {}),
    ...extra,
  } as LifecycleCommit;
  return signLifecycleEvent(commit, { audience: opts.audience ?? AUD, key, kid: KID });
}

const receiverOn = (
  file: string,
  extra: { issuer?: string; audience?: string; seenCapacity?: number } = {},
) =>
  new MissionSignalReceiver({
    jwks,
    issuer: extra.issuer ?? ISS,
    audience: extra.audience ?? AUD,
    store: { file },
    ...(extra.seenCapacity !== undefined ? { seenCapacity: extra.seenCapacity } : {}),
  });

describe("Signals receiver state in the consumer's store (#250)", () => {
  it("keeps the high-water, the observation, the gap and rematerialization markers, the retained SET and the seen jti values across a restart", async () => {
    const file = storeFile();
    const first = receiverOn(file);
    const activated = await set("msn_restart", 1, "active");
    const narrowed = await set("msn_restart", 2, "active", {
      prior_state: "active",
      authority_changed: true,
    });
    expect((await first.verifyAndApply(activated)).status).toBe("applied");
    expect(await first.verifyAndApply(narrowed)).toMatchObject({
      status: "applied",
      rematerialize: true,
    });
    // A Mission first seen past version 1 is a gap.
    expect((await first.verifyAndApply(await set("msn_gapped", 3, "suspended"))).status).toBe(
      "gap",
    );
    first.close();

    const second = receiverOn(file);
    try {
      expect(second.viewState("msn_restart")).toEqual({
        state: "active",
        version: 2,
        expires_at: EXPIRES_AT,
      });
      expect(second.retainedSet("msn_restart")).toBe(narrowed);
      expect(second.needsRematerialization("msn_restart")).toBe(true);
      expect(second.hasGap("msn_gapped")).toBe(true);
      expect(second.hasGap("msn_restart")).toBe(false);
      // The jti seen before the restart is still a duplicate after it.
      expect((await second.verifyAndApply(narrowed)).status).toBe("duplicate");
      // A stale acknowledgement leaves the latch; a covering one clears it, durably.
      expect(second.markRematerialized("msn_restart", { version: 1 })).toBe(false);
      expect(second.markRematerialized("msn_restart", { version: 2 })).toBe(true);
    } finally {
      second.close();
    }
    const third = receiverOn(file);
    try {
      expect(third.needsRematerialization("msn_restart")).toBe(false);
    } finally {
      third.close();
    }
  });

  it("never regresses on a lower or equal version, before or after a restart, and keeps a retained termination", async () => {
    const file = storeFile();
    const first = receiverOn(file);
    await first.verifyAndApply(await set("msn_term", 1, "active"));
    const terminated = await set("msn_term", 2, "terminated", { prior_state: "active" });
    expect((await first.verifyAndApply(terminated)).status).toBe("applied");
    // A new SET (fresh jti) at an equal or lower version is stale.
    expect(await first.verifyAndApply(await set("msn_term", 2, "active"))).toEqual({
      status: "stale",
      version: 2,
    });
    first.close();

    const second = receiverOn(file);
    try {
      expect(await second.verifyAndApply(await set("msn_term", 1, "active"))).toEqual({
        status: "stale",
        version: 2,
      });
      expect(await second.verifyAndApply(await set("msn_term", 2, "active"))).toEqual({
        status: "stale",
        version: 2,
      });
      expect(second.viewState("msn_term")).toMatchObject({
        state: "terminated",
        termination: { reason: "revoked" },
        version: 2,
      });
      expect(second.retainedSet("msn_term")).toBe(terminated);
      expect(second.lease("msn_term", "2026-10-02T00:00:00Z")).toMatchObject({
        state: "terminated",
        version: 2,
      });
    } finally {
      second.close();
    }
  });

  it("records nothing when its store fails: the SET is not acknowledged and its redelivery is processed afresh", async () => {
    const file = storeFile();
    const receiver = receiverOn(file);
    try {
      await receiver.verifyAndApply(await set("msn_fail", 1, "active"));
      const suspended = await set("msn_fail", 2, "suspended", { prior_state: "active" });
      const side = openStore("", { file });
      side.exec(
        `CREATE TRIGGER fail_receiver BEFORE UPDATE ON signal_receiver_missions
         BEGIN SELECT RAISE(ABORT, 'injected receiver store failure'); END;`,
      );
      await expect(receiver.verifyAndApply(suspended)).rejects.toBeInstanceOf(
        SignalReceiverStorageError,
      );
      expect(receiver.viewState("msn_fail")).toMatchObject({ state: "active", version: 1 });
      side.exec("DROP TRIGGER fail_receiver");
      side.close();
      // Not a duplicate: the failed attempt recorded no jti.
      expect(await receiver.verifyAndApply(suspended)).toMatchObject({
        status: "applied",
        version: 2,
      });
      expect(receiver.viewState("msn_fail")).toMatchObject({ state: "suspended", version: 2 });
    } finally {
      receiver.close();
    }
  });

  it("bounds duplicate suppression, and an evicted SET presented again is refused by the high-water, not applied", async () => {
    const file = storeFile();
    const receiver = receiverOn(file, { seenCapacity: 2 });
    try {
      const v1 = await set("msn_evict", 1, "active");
      const v2 = await set("msn_evict", 2, "suspended", { prior_state: "active" });
      const v3 = await set("msn_evict", 3, "terminated", { prior_state: "suspended" });
      for (const s of [v1, v2, v3])
        expect((await receiver.verifyAndApply(s)).status).toBe("applied");
      const side = openStore("", { file });
      const seen = (
        side.prepare("SELECT COUNT(*) AS n FROM signal_receiver_seen").get() as { n: number }
      ).n;
      side.close();
      expect(seen).toBe(2);
      // v1's jti was evicted: it is no longer a duplicate, and the high-water refuses it.
      expect(await receiver.verifyAndApply(v1)).toEqual({ status: "stale", version: 3 });
      // v3's jti is still held.
      expect((await receiver.verifyAndApply(v3)).status).toBe("duplicate");
      expect(receiver.viewState("msn_evict")).toMatchObject({ state: "terminated", version: 3 });
      expect(receiver.retainedSet("msn_evict")).toBe(v3);
    } finally {
      receiver.close();
    }
  });

  it("keeps receivers for different issuers and audiences apart in one shared file", async () => {
    const file = storeFile();
    const mine = receiverOn(file);
    const otherAudience = receiverOn(file, { audience: OTHER_AUD });
    const otherIssuer = receiverOn(file, { issuer: OTHER_ISS });
    try {
      expect((await mine.verifyAndApply(await set("msn_shared", 1, "active"))).status).toBe(
        "applied",
      );
      expect(otherAudience.viewState("msn_shared")).toBeUndefined();
      expect(otherIssuer.viewState("msn_shared")).toBeUndefined();
      // The same Mission identifier at another issuer has its own sequence.
      expect(
        (
          await otherIssuer.verifyAndApply(
            await set("msn_shared", 1, "active", {}, { issuer: OTHER_ISS }),
          )
        ).status,
      ).toBe("applied");
      expect(
        (
          await mine.verifyAndApply(
            await set("msn_shared", 2, "terminated", { prior_state: "active" }),
          )
        ).status,
      ).toBe("applied");
      expect(otherIssuer.viewState("msn_shared")).toMatchObject({ state: "active", version: 1 });
      // One jti, delivered to two audiences, is a fresh event for each.
      const shared = "set_durable_shared_jti";
      expect(
        (
          await otherAudience.verifyAndApply(
            await set("msn_aud", 1, "active", {}, { audience: OTHER_AUD, jti: shared }),
          )
        ).status,
      ).toBe("applied");
      expect(
        (await mine.verifyAndApply(await set("msn_aud", 1, "active", {}, { jti: shared }))).status,
      ).toBe("applied");
    } finally {
      mine.close();
      otherAudience.close();
      otherIssuer.close();
    }
  });
});
