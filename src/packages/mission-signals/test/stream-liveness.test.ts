/**
 * @spec signals#consumer-behavior (#1896, D1100, D1117): the reference
 * receiver's stream liveness, as a condition in addition to its per-Mission
 * reliance bound (#1747, PR #1824).
 *
 * The receiver verifies the stream's SSF Verification and Stream Updated
 * SETs, records the last verified liveness event, and takes the agreed
 * heartbeat interval with no default. Within the per-Mission bound, an
 * active push-derived state gives no lease while the stream is stale, or
 * once it was held across a stale period, until a Mission Status refresh
 * re-establishes it.
 *
 * Covered here, with a real emitter and receiver on one clock:
 *  - the new check refuses where the per-Mission bound still allows, and
 *    grants with the stream live; a receiver that does not know the interval
 *    never holds its stream verified live;
 *  - a liveness event moves no Mission's observation time or bound;
 *  - a Stream Updated event, paused or enabled, is not liveness;
 *  - the latch: a later heartbeat or lifecycle event does not restore a
 *    stale Mission, a Status refresh does, and a heartbeat clears no gap,
 *    rematerialization or recovery restriction;
 *  - the liveness record and the latch survive a restart;
 *  - before any liveness event, the silence runs from the subscription, the
 *    store's first open, kept across restarts (D1117);
 *  - an agreement change (heartbeat interval or mission_max_stale_seconds)
 *    on restart, made while running or while down, is a break: it clears no
 *    stale-state restriction, and a heartbeat after it does not either
 *    (D1117);
 *  - the store serves one stream id for its issuer and audience, and refuses
 *    to open as another (D1117);
 *  - the reference composition takes the interval from config/signals.json
 *    for both the emitter and the receiver.
 *
 * Package-only: no shipped service constructs a receiver.
 */

import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { LifecycleCommit } from "@mission/authorization-server";
import { MISSION_MAX_STALE_SECONDS, SIGNAL_STREAM_AGREEMENT } from "@mission/demo-data";
import { openStore } from "@mission/store";
import {
  type CryptoKey,
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  type JWK,
  SignJWT,
} from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  type ApplyResult,
  AUTHORITY_CHANGED_CAPABILITY,
  composeSignalStream,
  MissionSignalEmitter,
  MissionSignalReceiver,
  type ReceiverOptions,
  SignalReceiverStreamError,
} from "../src/index.js";

const ISS = "https://as.liveness.test";
const AUD = "https://consumer.liveness.test";
const STREAM = "stream-liveness-1";
const CLIENT = "consumer-client";
const EXPIRES_AT = "2027-01-01T00:00:00Z";
const T0 = Date.parse("2026-09-01T12:00:00Z");
const S = 1000;
/** The issuer's advertised `mission_max_stale_seconds` in these cases. */
const MAX_STALE_SECONDS = 60;

let key: CryptoKey;
let jwks: { keys: JWK[] };
const dirs: string[] = [];

beforeAll(async () => {
  const pair = await generateKeyPair("ES256", { extractable: true });
  key = pair.privateKey;
  jwks = {
    keys: [{ ...(await exportJWK(pair.publicKey)), kid: "as-status", alg: "ES256", use: "sig" }],
  };
});

afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

/** One clock for every emitter and receiver in a case. */
interface Clock {
  t: number;
}

const iso = (ms: number) => new Date(ms).toISOString();

interface Stream {
  emitter: MissionSignalEmitter;
  /** The receiver every SET on the stream is handed to; replaceable, as after a restart. */
  receiver: MissionSignalReceiver;
  /**
   * A new receiver with the same options, over the same store when it has
   * one, and any options in `extra` in their place.
   */
  makeReceiver: (extra?: Partial<ReceiverOptions>) => MissionSignalReceiver;
  /** The receiver's result for each SET, in order. */
  results: ApplyResult[];
  /** Commit a lifecycle transition at the clock and deliver it. */
  commit: (
    missionId: string,
    version: number,
    state: LifecycleCommit["state"],
    extra?: Partial<LifecycleCommit>,
  ) => Promise<void>;
  /** Attest liveness at the clock and deliver it. */
  heartbeat: () => Promise<void>;
  /** Re-establish a Mission from a verified Mission Status response at the clock. */
  refresh: (missionId: string, version: number, state: string) => Promise<unknown>;
  /** The receiver's lease at the clock. */
  lease: (missionId: string) => ReturnType<MissionSignalReceiver["lease"]>;
}

let events = 0;

/**
 * One stream: an emitter whose single consumer is `receiver`, each with its
 * own heartbeat interval (absent when undefined), on the shared clock. The
 * consumer declares `authority_changed` only when `declared` is set, so an
 * undeclared stream is paused by a narrowing (a Stream Updated event).
 */
function stream(
  clock: Clock,
  opts: {
    emitterInterval?: number;
    receiverInterval?: number;
    declared?: boolean;
    receiver?: Partial<ReceiverOptions>;
  } = {},
): Stream {
  const emitter = new MissionSignalEmitter({
    key,
    kid: "as-status",
    issuer: ISS,
    consumers: [
      {
        audience: AUD,
        stream_id: STREAM,
        ...(opts.declared
          ? { mission_capabilities_supported: [AUTHORITY_CHANGED_CAPABILITY] }
          : {}),
      },
    ],
    maxStaleSeconds: MAX_STALE_SECONDS,
    ...(opts.emitterInterval !== undefined
      ? { heartbeatIntervalSeconds: opts.emitterInterval }
      : {}),
    now: () => new Date(clock.t),
  });
  const makeReceiver = (extra: Partial<ReceiverOptions> = {}) =>
    new MissionSignalReceiver({
      jwks,
      issuer: ISS,
      audience: AUD,
      streamId: STREAM,
      maxStaleSeconds: MAX_STALE_SECONDS,
      ...(opts.receiverInterval !== undefined
        ? { heartbeatIntervalSeconds: opts.receiverInterval }
        : {}),
      status: { clientId: CLIENT, keys: createLocalJWKSet(jwks) },
      now: () => new Date(clock.t),
      ...opts.receiver,
      ...extra,
    });
  const s: Stream = {
    emitter,
    receiver: makeReceiver(),
    makeReceiver,
    results: [],
    commit: async (missionId, version, state, extra = {}) => {
      events += 1;
      emitter.onCommit({
        id: missionId,
        issuer: ISS,
        state,
        version,
        committed_at: iso(clock.t),
        expires_at: EXPIRES_AT,
        event_id: `set_liveness_${events}`,
        ...extra,
      } as LifecycleCommit);
      await emitter.drain();
    },
    heartbeat: async () => {
      await emitter.attestLiveness();
      await emitter.drain();
    },
    refresh: async (missionId, version, state) => {
      const iat = Math.floor(clock.t / 1000);
      const response = await new SignJWT({
        sub: CLIENT,
        nonce: s.receiver.statusNonce(missionId),
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
        .sign(key);
      return s.receiver.resynchronize(missionId, response, new Date(clock.t));
    },
    lease: (missionId) => s.receiver.lease(missionId, iso(clock.t)),
  };
  // The receiver reads every SET on its stream; one it holds after a restore
  // is not acknowledged, as the emitter's own registration does.
  emitter.onDeliver(AUD, async (set) => {
    const result = await s.receiver.verifyAndApply(set);
    s.results.push(result);
    if (result.status === "held") throw new Error("held until Mission Status resynchronizes it");
    return result;
  });
  return s;
}

/** No reason other than stream liveness withholds the Mission's lease. */
function onlyStreamLiveness(s: Stream, missionId: string, at: number): void {
  expect(s.receiver.recovering(missionId)).toBe(false);
  expect(s.receiver.hasGap(missionId)).toBe(false);
  expect(s.receiver.needsRematerialization(missionId)).toBe(false);
  expect(s.receiver.streamStale(missionId, iso(at))).toBe(true);
}

describe("the reference receiver's stream liveness (@spec signals#consumer-behavior, #1896, D1100)", () => {
  it("refuses a lease its per-Mission bound still allows once the stream has gone longer than mission_max_stale_seconds without a liveness event, and grants it on a stream verified live; a receiver that does not know the interval never holds its stream verified live, whatever interval the issuer serves", async () => {
    const clock = { t: T0 };
    // The issuer serves every stream with a 120 s interval. The receivers
    // know 120 s, know 10 s, or do not know it.
    const known = stream(clock, { emitterInterval: 120, receiverInterval: 120 });
    const short = stream(clock, { emitterInterval: 120, receiverInterval: 10 });
    const unknown = stream(clock, { emitterInterval: 120 });
    const all = [known, short, unknown];
    try {
      for (const s of all) await s.heartbeat();
      // Right after a heartbeat, only a receiver that knows the interval
      // holds its stream verified live.
      expect(known.receiver.streamLiveness(iso(clock.t))).toMatchObject({
        verifiedLive: true,
        stale: false,
        lastLivenessAt: new Date(T0),
      });
      expect(unknown.receiver.streamLiveness(iso(clock.t))).toMatchObject({
        verifiedLive: false,
        stale: false,
        lastLivenessAt: new Date(T0),
      });
      expect(unknown.receiver.heartbeatIntervalSeconds).toBeUndefined();

      // An active state committed at T0+50: the per-Mission bound is T0+110.
      clock.t = T0 + 50 * S;
      for (const s of all) await s.commit("msn_a", 1, "active");
      // At T0+55 no stream is stale yet: not verified live is not stale.
      clock.t = T0 + 55 * S;
      expect(short.receiver.streamLiveness(iso(clock.t))).toMatchObject({
        verifiedLive: false,
        stale: false,
      });
      for (const s of all) expect(s.lease("msn_a")).toMatchObject({ state: "active", version: 1 });

      // At T0+65 the bound still allows the lease: the receiver that holds
      // its stream verified live gives it, ending at T0+110.
      clock.t = T0 + 65 * S;
      const bound = {
        state: "active",
        version: 1,
        status_checked_at: iso(T0 + 50 * S),
        status_expires_at: iso(T0 + 110 * S),
        state_source: "signal",
      };
      expect(known.lease("msn_a")).toEqual(bound);
      expect(Date.parse(bound.status_expires_at)).toBeGreaterThan(clock.t);
      // The others have gone 65 s without a liveness event: the stream is
      // stale, and only stream liveness withholds the lease.
      for (const s of [short, unknown]) {
        expect(s.receiver.streamLiveness(iso(clock.t))).toMatchObject({
          verifiedLive: false,
          stale: true,
        });
        expect(s.receiver.viewState("msn_a")).toMatchObject({ state: "active", version: 1 });
        onlyStreamLiveness(s, "msn_a", clock.t);
        expect(s.lease("msn_a")).toBeUndefined();
      }

      // A heartbeat ends the silence, not the staleness: the Mission was
      // held across it, so it stays latched though the stream is no longer
      // stale.
      for (const s of all) await s.heartbeat();
      clock.t = T0 + 66 * S;
      expect(short.receiver.streamLiveness(iso(clock.t))).toMatchObject({
        verifiedLive: true,
        stale: false,
      });
      expect(unknown.receiver.streamLiveness(iso(clock.t))).toMatchObject({
        verifiedLive: false,
        stale: false,
        lastLivenessAt: new Date(T0 + 65 * S),
      });
      for (const s of [short, unknown]) {
        onlyStreamLiveness(s, "msn_a", clock.t);
        expect(s.lease("msn_a")).toBeUndefined();
      }
      expect(known.lease("msn_a")).toEqual(bound);

      // The control: state established after that heartbeat, on a stream
      // that is not stale, is relied on.
      for (const s of all) await s.commit("msn_b", 1, "active");
      clock.t = T0 + 67 * S;
      for (const s of all) {
        expect(s.receiver.streamStale("msn_b", iso(clock.t))).toBe(false);
        expect(s.lease("msn_b")).toMatchObject({ state: "active", version: 1 });
      }
    } finally {
      for (const s of all) {
        s.emitter.close();
        s.receiver.close();
      }
    }
  });

  it("counts the silence from the subscription, the store's first open, until a liveness event arrives: a first lifecycle SET more than mission_max_stale_seconds after it finds the stream already stale, with no grace period of its own", async () => {
    const clock = { t: T0 };
    // The receiver subscribes at T0. No SET arrives for 70 s.
    const s = stream(clock, { emitterInterval: 10, receiverInterval: 10 });
    try {
      // The stream's first SET, a lifecycle event at T0+70: its per-Mission
      // bound is T0+130, but the stream has been silent for 70 s.
      clock.t = T0 + 70 * S;
      await s.commit("msn_late", 1, "active");
      expect(s.lease("msn_late")).toBeUndefined();
      expect(s.results).toEqual([
        { status: "applied", state: "active", version: 1, rematerialize: false },
      ]);
      expect(s.receiver.viewState("msn_late")).toMatchObject({ state: "active", version: 1 });
      expect(s.receiver.streamLiveness(iso(clock.t))).toEqual({ verifiedLive: false, stale: true });
      onlyStreamLiveness(s, "msn_late", clock.t);
      // The silence ran from the subscription: the stream was not stale 60 s
      // after it, and was stale from 61 s, before its first SET arrived.
      expect(s.receiver.streamLiveness(iso(T0 + 60 * S))).toEqual({
        verifiedLive: false,
        stale: false,
      });
      expect(s.receiver.streamLiveness(iso(T0 + 61 * S))).toEqual({
        verifiedLive: false,
        stale: true,
      });

      // The heartbeat that ends the silence does not vouch for state that
      // arrived during it.
      clock.t = T0 + 71 * S;
      await s.heartbeat();
      expect(s.receiver.streamLiveness(iso(clock.t))).toMatchObject({
        verifiedLive: true,
        stale: false,
      });
      onlyStreamLiveness(s, "msn_late", clock.t);
      expect(s.lease("msn_late")).toBeUndefined();
      // The control: state that arrives after it is relied on.
      clock.t = T0 + 72 * S;
      await s.commit("msn_after", 1, "active");
      expect(s.receiver.streamStale("msn_after", iso(clock.t))).toBe(false);
      expect(s.lease("msn_after")).toMatchObject({ state: "active", version: 1 });
    } finally {
      s.emitter.close();
      s.receiver.close();
    }
  });

  it("keeps the subscription start across a restart: before any liveness event, the silence still runs from the store's first open, not from the reopen or the first SET", async () => {
    const dir = mkdtempSync(join(tmpdir(), "signal-liveness-subscription-"));
    dirs.push(dir);
    const store = { file: join(dir, "receiver.db") };
    const clock = { t: T0 };
    // The store's first open, at T0, is the subscription.
    const s = stream(clock, { emitterInterval: 10, receiverInterval: 10, receiver: { store } });
    try {
      // A restart at T0+30, then the stream's first SET at T0+40: its
      // per-Mission bound is T0+100.
      s.receiver.close();
      clock.t = T0 + 30 * S;
      s.receiver = s.makeReceiver();
      clock.t = T0 + 40 * S;
      await s.commit("msn_a", 1, "active");
      clock.t = T0 + 60 * S;
      expect(s.lease("msn_a")).toMatchObject({ state: "active", version: 1 });
      // 61 s after the subscription, 31 s after the restart and 21 s after
      // the first SET: stale.
      clock.t = T0 + 61 * S;
      expect(s.lease("msn_a")).toBeUndefined();
      expect(s.receiver.streamLiveness(iso(clock.t))).toEqual({ verifiedLive: false, stale: true });
      onlyStreamLiveness(s, "msn_a", clock.t);
      // Another restart moves nothing.
      s.receiver.close();
      s.receiver = s.makeReceiver();
      expect(s.receiver.streamLiveness(iso(clock.t))).toEqual({ verifiedLive: false, stale: true });
      expect(s.lease("msn_a")).toBeUndefined();
    } finally {
      s.emitter.close();
      s.receiver.close();
    }
  });

  it("never moves a Mission's observation time or reliance bound on a liveness event, and gives no lease past that bound while the stream is verified live", async () => {
    const clock = { t: T0 };
    const s = stream(clock, { emitterInterval: 10, receiverInterval: 10 });
    try {
      await s.heartbeat();
      clock.t = T0 + 5 * S;
      await s.commit("msn_a", 1, "active");
      const bound = {
        state: "active",
        version: 1,
        status_checked_at: iso(T0 + 5 * S),
        status_expires_at: iso(T0 + 65 * S),
        state_source: "signal",
      };
      expect(s.lease("msn_a")).toEqual(bound);
      // Heartbeats every 10 s keep the stream verified live; the lease keeps
      // the observation time and bound the event established.
      for (let t = 15; t <= 55; t += 10) {
        clock.t = T0 + t * S;
        await s.heartbeat();
        expect(s.results.at(-1)).toEqual({ status: "liveness" });
        clock.t += 9 * S;
        expect(s.receiver.streamLiveness(iso(clock.t)).verifiedLive).toBe(true);
        expect(s.lease("msn_a")).toEqual(bound);
      }
      clock.t = T0 + 65 * S - 1;
      expect(s.lease("msn_a")).toEqual(bound);
      // At the bound, a heartbeat that has just arrived gives no lease.
      clock.t = T0 + 65 * S;
      await s.heartbeat();
      expect(s.receiver.streamLiveness(iso(clock.t))).toMatchObject({
        verifiedLive: true,
        stale: false,
        lastLivenessAt: new Date(T0 + 65 * S),
      });
      expect(s.receiver.streamStale("msn_a", iso(clock.t))).toBe(false);
      expect(s.lease("msn_a")).toBeUndefined();
      clock.t = T0 + 75 * S;
      await s.heartbeat();
      expect(s.lease("msn_a")).toBeUndefined();
      // Only a Mission Status refresh re-establishes it, at its own bound.
      expect(await s.refresh("msn_a", 1, "active")).toMatchObject({ status: "resynchronized" });
      expect(s.lease("msn_a")).toMatchObject({
        status_checked_at: iso(T0 + 75 * S),
        status_expires_at: iso(T0 + 135 * S),
        state_source: "status",
      });
    } finally {
      s.emitter.close();
      s.receiver.close();
    }
  });

  it("never counts a Stream Updated event, paused or enabled, as liveness: it neither keeps the stream verified live nor ends or clears its staleness", async () => {
    const clock = { t: T0 };
    // An undeclared stream: a narrowing is withheld and pauses it.
    const s = stream(clock, { emitterInterval: 10, receiverInterval: 10 });
    try {
      await s.heartbeat();
      clock.t = T0 + 30 * S;
      await s.commit("msn_a", 1, "active"); // its bound is T0+90
      // A withheld narrowing of another Mission pauses the stream at T0+35.
      clock.t = T0 + 35 * S;
      await s.commit("msn_n", 1, "active");
      await s.commit("msn_n", 2, "active", { prior_state: "active", authority_changed: true });
      expect(s.results.at(-1)).toEqual({ status: "stream-updated", stream_status: "paused" });
      // The Stream Updated event moved no liveness record.
      expect(s.receiver.streamLiveness(iso(clock.t))).toMatchObject({
        verifiedLive: false,
        stale: false,
        lastLivenessAt: new Date(T0),
        streamStatus: "paused",
      });
      // Six seconds after it, ten seconds after nothing: not verified live.
      clock.t = T0 + 41 * S;
      expect(s.receiver.streamLiveness(iso(clock.t))).toMatchObject({
        verifiedLive: false,
        lastLivenessAt: new Date(T0),
      });
      expect(s.lease("msn_a")).toMatchObject({ state: "active" });
      // The staleness runs from the last verification event, at T0.
      clock.t = T0 + 61 * S;
      expect(s.receiver.streamLiveness(iso(clock.t)).stale).toBe(true);
      onlyStreamLiveness(s, "msn_a", clock.t);
      expect(s.lease("msn_a")).toBeUndefined();
      // The stream is re-enabled: the enabled notice ends no staleness.
      await s.emitter.drain();
      expect(s.results.at(-1)).toEqual({ status: "stream-updated", stream_status: "enabled" });
      clock.t = T0 + 62 * S;
      expect(s.receiver.streamLiveness(iso(clock.t))).toMatchObject({
        verifiedLive: false,
        stale: true,
        lastLivenessAt: new Date(T0),
        streamStatus: "enabled",
      });
      expect(s.lease("msn_a")).toBeUndefined();
      // Nor does the liveness event that follows clear it.
      await s.heartbeat();
      expect(s.results.at(-1)).toEqual({ status: "liveness" });
      clock.t = T0 + 63 * S;
      expect(s.receiver.streamLiveness(iso(clock.t))).toMatchObject({
        verifiedLive: true,
        stale: false,
      });
      onlyStreamLiveness(s, "msn_a", clock.t);
      expect(s.lease("msn_a")).toBeUndefined();
    } finally {
      s.emitter.close();
      s.receiver.close();
    }
  });

  it("keeps a stale Mission latched across later heartbeats and lifecycle events until a verified Mission Status refresh re-establishes it; a heartbeat clears no gap or rematerialization restriction", async () => {
    const clock = { t: T0 };
    const s = stream(clock, { emitterInterval: 10, receiverInterval: 10, declared: true });
    try {
      await s.heartbeat();
      clock.t = T0 + 10 * S;
      await s.commit("msn_a", 1, "active"); // its bound is T0+70
      clock.t = T0 + 61 * S;
      expect(s.lease("msn_a")).toBeUndefined();
      clock.t = T0 + 62 * S;
      await s.heartbeat();
      // Later events for the Mission, contiguous and in order, keep the latch.
      await s.commit("msn_a", 2, "suspended", { prior_state: "active" });
      clock.t = T0 + 63 * S;
      await s.commit("msn_a", 3, "active", { prior_state: "suspended" }); // its bound is T0+123
      clock.t = T0 + 64 * S;
      await s.heartbeat();
      clock.t = T0 + 65 * S;
      expect(s.receiver.streamLiveness(iso(clock.t))).toMatchObject({
        verifiedLive: true,
        stale: false,
      });
      expect(s.receiver.viewState("msn_a")).toMatchObject({ state: "active", version: 3 });
      onlyStreamLiveness(s, "msn_a", clock.t);
      expect(s.lease("msn_a")).toBeUndefined();
      // A verified Mission Status refresh re-establishes current state.
      expect(await s.refresh("msn_a", 3, "active")).toMatchObject({
        status: "resynchronized",
        version: 3,
      });
      expect(s.receiver.streamStale("msn_a", iso(clock.t))).toBe(false);
      expect(s.lease("msn_a")).toMatchObject({
        state: "active",
        version: 3,
        state_source: "status",
      });

      // A version gap holds across a heartbeat on a live stream.
      await s.commit("msn_g", 1, "active");
      await s.commit("msn_g", 3, "active", { prior_state: "active" });
      clock.t = T0 + 66 * S;
      await s.heartbeat();
      expect(s.receiver.streamStale("msn_g", iso(clock.t))).toBe(false);
      expect(s.receiver.hasGap("msn_g")).toBe(true);
      expect(s.lease("msn_g")).toBeUndefined();
      expect(await s.refresh("msn_g", 3, "active")).toMatchObject({ status: "resynchronized" });
      expect(s.receiver.hasGap("msn_g")).toBe(false);
      expect(s.receiver.markRematerialized("msn_g", { version: 3 })).toBe(true);
      expect(s.lease("msn_g")).toMatchObject({ state: "active", version: 3 });

      // So does the rematerialization latch.
      await s.commit("msn_r", 1, "active");
      await s.commit("msn_r", 2, "active", { prior_state: "active", authority_changed: true });
      clock.t = T0 + 67 * S;
      await s.heartbeat();
      expect(s.receiver.streamStale("msn_r", iso(clock.t))).toBe(false);
      expect(s.receiver.needsRematerialization("msn_r")).toBe(true);
      expect(s.lease("msn_r")).toBeUndefined();
      expect(s.receiver.markRematerialized("msn_r", { version: 2 })).toBe(true);
      expect(s.lease("msn_r")).toMatchObject({ state: "active", version: 2 });
    } finally {
      s.emitter.close();
      s.receiver.close();
    }
  });

  it("keeps the liveness record, the silence and the latch across a restart, and gives a Mission held after a restore no lease, whatever liveness arrives, until it is resynchronized", async () => {
    const root = mkdtempSync(join(tmpdir(), "signal-liveness-"));
    dirs.push(root);
    for (const d of ["state", "witness", "backups"]) mkdirSync(join(root, d));
    const store = { file: join(root, "state", "receiver.db") };
    const witness = { file: join(root, "witness", "receiver.witness") };
    const backup = join(root, "backups", "receiver.db");
    const clock = { t: T0 };
    const opts = { receiverInterval: 10, emitterInterval: 10, receiver: { store, witness } };
    const s = stream(clock, opts);
    const reopen = () => {
      s.receiver.close();
      s.receiver = s.makeReceiver();
    };
    try {
      await s.heartbeat();
      clock.t = T0 + 10 * S;
      await s.commit("msn_a", 1, "active"); // its bound is T0+70
      s.receiver.close();
      for (const suffix of ["-wal", "-shm"]) rmSync(`${backup}${suffix}`, { force: true });
      copyFileSync(store.file, backup);
      s.receiver = s.makeReceiver();

      // The stream goes stale; a heartbeat ends the silence, not the latch.
      clock.t = T0 + 62 * S;
      await s.heartbeat();
      clock.t = T0 + 63 * S;
      expect(s.lease("msn_a")).toBeUndefined();

      // A restart keeps the liveness record and the latch.
      reopen();
      expect(s.receiver.streamLiveness(iso(clock.t))).toMatchObject({
        verifiedLive: true,
        stale: false,
        lastLivenessAt: new Date(T0 + 62 * S),
      });
      onlyStreamLiveness(s, "msn_a", clock.t);
      expect(s.lease("msn_a")).toBeUndefined();
      // A restart does not restart the silence either.
      clock.t = T0 + 123 * S;
      reopen();
      expect(s.receiver.streamLiveness(iso(clock.t))).toMatchObject({
        verifiedLive: false,
        stale: true,
        lastLivenessAt: new Date(T0 + 62 * S),
      });

      // A restore of the older store: the Mission is held, and a liveness
      // event releases nothing.
      s.receiver.close();
      for (const suffix of ["-wal", "-shm"]) rmSync(`${store.file}${suffix}`, { force: true });
      copyFileSync(backup, store.file);
      s.receiver = s.makeReceiver();
      expect(s.receiver.recovering("msn_a")).toBe(true);
      await s.heartbeat();
      expect(s.results.at(-1)).toEqual({ status: "liveness" });
      clock.t += 1 * S;
      expect(s.receiver.streamLiveness(iso(clock.t))).toMatchObject({ verifiedLive: true });
      expect(s.receiver.recovering("msn_a")).toBe(true);
      expect(s.lease("msn_a")).toBeUndefined();
      // Resynchronized from Mission Status, it is released.
      expect(await s.refresh("msn_a", 1, "active")).toMatchObject({ status: "resynchronized" });
      expect(s.receiver.recovering("msn_a")).toBe(false);
      expect(s.receiver.markRematerialized("msn_a", { version: 1 })).toBe(true);
      expect(s.lease("msn_a")).toMatchObject({ state: "active", state_source: "status" });
    } finally {
      s.emitter.close();
      s.receiver.close();
    }
  });

  it("keeps a stale Mission latched when the receiver reopens its store with a longer heartbeat interval, and keeps the stream stale until a liveness event arrives: re-evaluating the silence under the new interval ends no stale period", async () => {
    const dir = mkdtempSync(join(tmpdir(), "signal-liveness-interval-"));
    dirs.push(dir);
    const store = { file: join(dir, "receiver.db") };
    const clock = { t: T0 };
    const s = stream(clock, { emitterInterval: 10, receiverInterval: 10, receiver: { store } });
    try {
      await s.heartbeat();
      clock.t = T0 + 50 * S;
      await s.commit("msn_a", 1, "active"); // its bound is T0+110
      clock.t = T0 + 61 * S;
      onlyStreamLiveness(s, "msn_a", clock.t);
      expect(s.lease("msn_a")).toBeUndefined();

      // A restart at T0+62 with the interval raised from 10 to 120 s, with
      // no heartbeat or Status refresh: under 120 s alone the T0 heartbeat
      // would hold the stream verified live.
      s.receiver.close();
      clock.t = T0 + 62 * S;
      s.receiver = s.makeReceiver({ heartbeatIntervalSeconds: 120 });
      expect(s.lease("msn_a")).toBeUndefined();
      expect(s.receiver.heartbeatIntervalSeconds).toBe(120);
      expect(s.receiver.streamLiveness(iso(clock.t))).toEqual({
        verifiedLive: false,
        stale: true,
        lastLivenessAt: new Date(T0),
      });
      expect(s.receiver.viewState("msn_a")).toMatchObject({ state: "active", version: 1 });
      onlyStreamLiveness(s, "msn_a", clock.t);
      // State that arrives before a liveness event arrives on a stale stream.
      clock.t = T0 + 63 * S;
      await s.commit("msn_b", 1, "active");
      expect(s.lease("msn_b")).toBeUndefined();
      onlyStreamLiveness(s, "msn_b", clock.t);

      // The heartbeat ends the stale period, not the latch.
      clock.t = T0 + 64 * S;
      await s.heartbeat();
      expect(s.receiver.streamLiveness(iso(clock.t))).toMatchObject({
        verifiedLive: true,
        stale: false,
      });
      for (const m of ["msn_a", "msn_b"]) {
        expect(s.lease(m)).toBeUndefined();
        onlyStreamLiveness(s, m, clock.t);
      }
      // The control: state after that heartbeat is relied on.
      clock.t = T0 + 65 * S;
      await s.commit("msn_c", 1, "active");
      expect(s.lease("msn_c")).toMatchObject({ state: "active", version: 1 });
      // Only Mission Status re-establishes the latched Mission.
      expect(await s.refresh("msn_a", 1, "active")).toMatchObject({ status: "resynchronized" });
      expect(s.lease("msn_a")).toMatchObject({ state: "active", state_source: "status" });
    } finally {
      s.emitter.close();
      s.receiver.close();
    }
  });

  it("keeps a stale Mission latched when the receiver reopens its store with a longer mission_max_stale_seconds", async () => {
    const dir = mkdtempSync(join(tmpdir(), "signal-liveness-max-stale-"));
    dirs.push(dir);
    const store = { file: join(dir, "receiver.db") };
    const clock = { t: T0 };
    const s = stream(clock, { emitterInterval: 10, receiverInterval: 10, receiver: { store } });
    try {
      await s.heartbeat();
      clock.t = T0 + 50 * S;
      await s.commit("msn_a", 1, "active"); // its bound is T0+110
      clock.t = T0 + 61 * S;
      onlyStreamLiveness(s, "msn_a", clock.t);
      expect(s.lease("msn_a")).toBeUndefined();

      // A restart with mission_max_stale_seconds raised from 60 to 120 s:
      // under 120 s alone the stream's 62 s of silence would not be stale.
      s.receiver.close();
      clock.t = T0 + 62 * S;
      s.receiver = s.makeReceiver({ maxStaleSeconds: 120 });
      expect(s.lease("msn_a")).toBeUndefined();
      expect(s.receiver.streamLiveness(iso(clock.t))).toEqual({
        verifiedLive: false,
        stale: true,
        lastLivenessAt: new Date(T0),
      });
      onlyStreamLiveness(s, "msn_a", clock.t);
      // A heartbeat ends the stale period; the Mission stays latched.
      clock.t = T0 + 63 * S;
      await s.heartbeat();
      expect(s.lease("msn_a")).toBeUndefined();
      expect(s.receiver.streamLiveness(iso(clock.t)).verifiedLive).toBe(true);
      onlyStreamLiveness(s, "msn_a", clock.t);
      expect(await s.refresh("msn_a", 1, "active")).toMatchObject({ status: "resynchronized" });
      expect(s.lease("msn_a")).toMatchObject({ state: "active", state_source: "status" });
    } finally {
      s.emitter.close();
      s.receiver.close();
    }
  });

  it("treats an agreement changed while the receiver was down as a break: a Mission held across it gives no lease after a heartbeat until a Mission Status refresh, whether or not the stream went stale meanwhile", async () => {
    const dir = mkdtempSync(join(tmpdir(), "signal-liveness-down-"));
    dirs.push(dir);
    const clock = { t: T0 };
    // Not stale: the receiver goes down at T0+6 on a stream verified live,
    // and comes back at T0+8 with a 20 s interval.
    const live = stream(clock, {
      emitterInterval: 10,
      receiverInterval: 10,
      receiver: { store: { file: join(dir, "live.db") } },
    });
    // Stale while down: the receiver goes down at T0+55, before the stream
    // goes stale under the 10 s interval and 60 s mission_max_stale_seconds,
    // and comes back at T0+70 with a 120 s interval.
    const down = stream(clock, {
      emitterInterval: 10,
      receiverInterval: 10,
      receiver: { store: { file: join(dir, "down.db") } },
    });
    try {
      for (const s of [live, down]) await s.heartbeat();
      clock.t = T0 + 5 * S;
      await live.commit("msn_a", 1, "active"); // its bound is T0+65
      expect(live.lease("msn_a")).toMatchObject({ state: "active" });
      clock.t = T0 + 6 * S;
      live.receiver.close();
      clock.t = T0 + 8 * S;
      live.receiver = live.makeReceiver({ heartbeatIntervalSeconds: 20 });
      clock.t = T0 + 9 * S;
      await live.heartbeat();
      expect(live.lease("msn_a")).toBeUndefined();
      expect(live.receiver.streamLiveness(iso(clock.t))).toMatchObject({
        verifiedLive: true,
        stale: false,
      });
      onlyStreamLiveness(live, "msn_a", clock.t);
      expect(await live.refresh("msn_a", 1, "active")).toMatchObject({ status: "resynchronized" });
      expect(live.lease("msn_a")).toMatchObject({ state: "active", state_source: "status" });

      clock.t = T0 + 50 * S;
      await down.commit("msn_d", 1, "active"); // its bound is T0+110
      clock.t = T0 + 55 * S;
      expect(down.lease("msn_d")).toMatchObject({ state: "active" });
      down.receiver.close();
      clock.t = T0 + 70 * S;
      down.receiver = down.makeReceiver({ heartbeatIntervalSeconds: 120 });
      expect(down.lease("msn_d")).toBeUndefined();
      expect(down.receiver.streamLiveness(iso(clock.t))).toMatchObject({
        verifiedLive: false,
        stale: true,
      });
      clock.t = T0 + 71 * S;
      await down.heartbeat();
      expect(down.lease("msn_d")).toBeUndefined();
      expect(down.receiver.streamLiveness(iso(clock.t))).toMatchObject({
        verifiedLive: true,
        stale: false,
      });
      onlyStreamLiveness(down, "msn_d", clock.t);
      expect(await down.refresh("msn_d", 1, "active")).toMatchObject({
        status: "resynchronized",
      });
      expect(down.lease("msn_d")).toMatchObject({ state: "active", state_source: "status" });
    } finally {
      for (const s of [live, down]) {
        s.emitter.close();
        s.receiver.close();
      }
    }
  });

  it("refuses to open a store that records another stream id for the same issuer and audience, and leaves that stream's record as it was", async () => {
    const dir = mkdtempSync(join(tmpdir(), "signal-liveness-stream-id-"));
    dirs.push(dir);
    const store = { file: join(dir, "receiver.db") };
    const clock = { t: T0 };
    const s = stream(clock, { emitterInterval: 10, receiverInterval: 10, receiver: { store } });
    try {
      await s.heartbeat();
      await s.commit("msn_a", 1, "active");
      s.receiver.close();
      clock.t = T0 + 1 * S;
      // Another stream's receiver over the same store does not open: the
      // recorded stream's heartbeat is never read as its liveness.
      expect(() => s.makeReceiver({ streamId: "other-stream" })).toThrow(SignalReceiverStreamError);
      expect(() => s.makeReceiver({ streamId: "other-stream" })).toThrow(
        `the store records stream "${STREAM}" for this issuer and audience, not "other-stream"`,
      );
      // So does a receiver that leaves the stream id to its audience default.
      expect(() => s.makeReceiver({ streamId: undefined })).toThrow(SignalReceiverStreamError);
      // The recorded stream's receiver opens with its record unchanged.
      s.receiver = s.makeReceiver();
      expect(s.receiver.streamLiveness(iso(clock.t))).toEqual({
        verifiedLive: true,
        stale: false,
        lastLivenessAt: new Date(T0),
      });
      expect(s.lease("msn_a")).toMatchObject({ state: "active", version: 1 });
    } finally {
      s.emitter.close();
      s.receiver.close();
    }
  });

  it("gives no lease for push-derived state a store wrote before the stream-liveness record existed, whatever liveness arrives, until a Mission Status refresh", async () => {
    const dir = mkdtempSync(join(tmpdir(), "signal-liveness-legacy-"));
    dirs.push(dir);
    const store = { file: join(dir, "receiver.db") };
    const clock = { t: T0 };
    const s = stream(clock, { emitterInterval: 10, receiverInterval: 10, receiver: { store } });
    try {
      await s.heartbeat();
      clock.t = T0 + 1 * S;
      await s.commit("msn_a", 1, "active"); // its bound is T0+61
      clock.t = T0 + 2 * S;
      expect(s.lease("msn_a")).toMatchObject({ state: "active" });
      s.receiver.close();
      // The store as a receiver written before #1896 left it.
      const raw = openStore("", store);
      raw.exec("ALTER TABLE signal_receiver_missions DROP COLUMN liveness_generation");
      raw.exec("DROP TABLE signal_receiver_stream");
      raw.close();
      s.receiver = s.makeReceiver();
      expect(s.receiver.viewState("msn_a")).toMatchObject({ state: "active", version: 1 });
      expect(s.lease("msn_a")).toBeUndefined();
      // A heartbeat on a live stream does not vouch for the older state.
      await s.heartbeat();
      clock.t = T0 + 3 * S;
      expect(s.receiver.streamLiveness(iso(clock.t))).toMatchObject({
        verifiedLive: true,
        stale: false,
      });
      onlyStreamLiveness(s, "msn_a", clock.t);
      expect(s.lease("msn_a")).toBeUndefined();
      // A Mission Status refresh re-establishes it; later push-derived state
      // takes the stream's record.
      expect(await s.refresh("msn_a", 1, "active")).toMatchObject({ status: "resynchronized" });
      expect(s.lease("msn_a")).toMatchObject({ state: "active", state_source: "status" });
      await s.commit("msn_a", 2, "suspended", { prior_state: "active" });
      await s.commit("msn_a", 3, "active", { prior_state: "suspended" });
      expect(s.lease("msn_a")).toMatchObject({ version: 3, state_source: "signal" });
    } finally {
      s.emitter.close();
      s.receiver.close();
    }
  });

  it("builds the emitter and the receiver from the one agreed interval in config/signals.json: both take it, and the receiver holds its stream verified live for exactly that interval", async () => {
    const configured = JSON.parse(
      readFileSync(
        join(dirname(fileURLToPath(import.meta.url)), "../../../config/signals.json"),
        "utf8",
      ),
    ) as { heartbeat_interval_seconds: number };
    expect(SIGNAL_STREAM_AGREEMENT).toEqual({
      heartbeatIntervalSeconds: configured.heartbeat_interval_seconds,
      maxStaleSeconds: MISSION_MAX_STALE_SECONDS,
    });
    let clock = T0;
    const { emitter, receiver } = composeSignalStream(
      SIGNAL_STREAM_AGREEMENT,
      {
        key,
        kid: "as-status",
        issuer: ISS,
        consumers: [{ audience: AUD, stream_id: STREAM }],
        now: () => new Date(clock),
      },
      { jwks, issuer: ISS, audience: AUD, streamId: STREAM, now: () => new Date(clock) },
    );
    try {
      expect(emitter.heartbeatIntervalSeconds).toBe(configured.heartbeat_interval_seconds);
      expect(receiver.heartbeatIntervalSeconds).toBe(configured.heartbeat_interval_seconds);
      // The composition registered the receiver: the heartbeat reaches it.
      await emitter.attestLiveness();
      const interval = configured.heartbeat_interval_seconds * S;
      expect(receiver.streamLiveness(iso(T0 + interval))).toMatchObject({
        verifiedLive: true,
        lastLivenessAt: new Date(T0),
      });
      expect(receiver.streamLiveness(iso(T0 + interval + 1)).verifiedLive).toBe(false);
      // The emitter's window runs for the longer of the two after the
      // withholding that pauses the stream.
      clock = T0 + 1 * S;
      emitter.onCommit({
        id: "msn_cfg",
        issuer: ISS,
        state: "active",
        prior_state: "active",
        version: 2,
        committed_at: iso(clock),
        expires_at: EXPIRES_AT,
        event_id: "set_liveness_cfg",
        authority_changed: true,
      } as LifecycleCommit);
      await emitter.drain();
      expect(emitter.streamStatus(AUD)).toMatchObject({
        status: "paused",
        reenable_after: new Date(T0 + Math.max(MISSION_MAX_STALE_SECONDS * S, interval)),
      });
      expect(receiver.streamLiveness(iso(clock)).streamStatus).toBe("paused");
    } finally {
      emitter.close();
      receiver.close();
    }
  });
});
