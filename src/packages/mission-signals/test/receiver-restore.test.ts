/**
 * @spec control-plane#rollback (#1749, ruled D898): the Signals receiver with
 * a recovery witness. A store restored from an older backup, or replaced by
 * an empty one, is detected when the receiver opens, and every Mission is held
 * until a fresh, authenticated Mission Status read resynchronizes it.
 *
 * Covered here, on a file-backed receiver store with its witness in another
 * directory:
 *  - the owner's replay case: an older backup restored after a termination,
 *    then an old signed `active` event replayed, is held, and the Status read
 *    re-establishes the termination;
 *  - a Mission the restored store never held is held too;
 *  - an unavailable or unverifiable Status response leaves the Mission held;
 *  - an interrupted recovery: a restart before resynchronizing, and a storage
 *    failure inside the resynchronizing transaction, release nothing;
 *  - a response to a request made before a later restore, or one reporting a
 *    version below the store's, releases nothing;
 *  - a missing, unreadable, foreign or behind witness refuses to open and is
 *    never re-created, and a witness write that fails commits nothing.
 *
 * Package-only: no shipped service constructs a receiver.
 */

import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { LifecycleCommit } from "@mission/authorization-server";
import { type CryptoKey, exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  MissionSignalEmitter,
  MissionSignalReceiver,
  type ReceiverOptions,
  type ReceiverWitness,
  SignalReceiverRecoveryError,
  SignalReceiverStorageError,
  signLifecycleEvent,
} from "../src/index.js";

const ISS = "https://as.restore.test";
const AUD = "https://consumer.restore.test";
const CLIENT = "consumer-client";
const EXPIRES_AT = "2027-01-01T00:00:00Z";

let setKey: CryptoKey;
let statusKey: CryptoKey;
let foreignKey: CryptoKey;
let jwks: { keys: JWK[] };
const dirs: string[] = [];

beforeAll(async () => {
  const sets = await generateKeyPair("ES256", { extractable: true });
  const status = await generateKeyPair("ES256", { extractable: true });
  setKey = sets.privateKey;
  statusKey = status.privateKey;
  foreignKey = (await generateKeyPair("ES256")).privateKey;
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

/** A store and its witness in separate directories, and a directory for backups. */
function layout(): { store: string; witness: string; backups: string } {
  const root = mkdtempSync(join(tmpdir(), "signal-restore-"));
  dirs.push(root);
  for (const d of ["state", "witness", "backups"]) mkdirSync(join(root, d));
  return {
    store: join(root, "state", "receiver.db"),
    witness: join(root, "witness", "receiver.witness"),
    backups: join(root, "backups"),
  };
}

/** Copy a closed store aside, or back over the store: a backup and a restore. */
function copyStore(from: string, to: string): void {
  for (const suffix of ["-wal", "-shm"]) rmSync(`${to}${suffix}`, { force: true });
  copyFileSync(from, to);
}

let events = 0;
/** One signed lifecycle-change SET (a fresh `jti`). */
function set(missionId: string, version: number, state: LifecycleCommit["state"]): Promise<string> {
  events += 1;
  const commit = {
    id: missionId,
    issuer: ISS,
    state,
    version,
    committed_at: new Date(Date.UTC(2026, 9, 1, 0, 0, version)).toISOString(),
    expires_at: EXPIRES_AT,
    event_id: `set_restore_${events}`,
    ...(state === "terminated"
      ? { termination: { reason: "revoked", terminated_at: "2026-10-01T00:00:00Z", version } }
      : {}),
  } as LifecycleCommit;
  return signLifecycleEvent(commit, { audience: AUD, key: setKey, kid: "as-signals" });
}

/** A signed state-only Mission Status response to this consumer's request. */
function statusResponse(
  missionId: string,
  version: number,
  state: string,
  nonce: string,
  opts: { key?: CryptoKey; sub?: string; iatOffset?: number; freshFor?: number } = {},
): Promise<string> {
  const iat = Math.floor(Date.now() / 1000) + (opts.iatOffset ?? 0);
  return new SignJWT({
    sub: opts.sub ?? CLIENT,
    nonce,
    mission: {
      id: missionId,
      issuer: ISS,
      state,
      version,
      expires_at: EXPIRES_AT,
      fresh_until: new Date((iat + (opts.freshFor ?? 60)) * 1000).toISOString(),
      ...(state === "terminated"
        ? { termination: { reason: "revoked", terminated_at: "2026-10-01T00:00:00Z", version } }
        : {}),
    },
  })
    .setProtectedHeader({ alg: "ES256", kid: "as-status", typ: "mission-status-response+jwt" })
    .setIssuer(ISS)
    .setAudience(CLIENT)
    .setIssuedAt(iat)
    .setExpirationTime(iat + 60)
    .sign(opts.key ?? statusKey);
}

const options = (
  paths: { store: string; witness: string },
  extra: Partial<ReceiverOptions> = {},
): ReceiverOptions => ({
  jwks,
  issuer: ISS,
  audience: AUD,
  store: { file: paths.store },
  witness: { file: paths.witness },
  status: { clientId: CLIENT },
  ...extra,
});

const open = (paths: { store: string; witness: string }, extra: Partial<ReceiverOptions> = {}) =>
  new MissionSignalReceiver(options(paths, extra));

/** A receiver whose next witness write fails, inside the transaction it guards. */
class FailingReceiver extends MissionSignalReceiver {
  failNext = false;
  protected override persistWitness(file: string, record: ReceiverWitness): void {
    if (this.failNext) {
      this.failNext = false;
      throw new Error("injected: the witness cannot be written");
    }
    super.persistWitness(file, record);
  }
}

/** Resynchronize a held Mission from a Status response at `version`. */
async function resync(r: MissionSignalReceiver, missionId: string, version: number, state: string) {
  const nonce = r.recoveryNonce(missionId) as string;
  expect(nonce).toBeDefined();
  return r.resynchronize(missionId, await statusResponse(missionId, version, state, nonce));
}

describe("Signals receiver restore admission (@spec control-plane#rollback, #1749)", () => {
  it("holds every Mission after an older backup is restored, so a replayed old event is never applied, and the Status read re-establishes the termination", async () => {
    const paths = layout();
    const backup = join(paths.backups, "receiver.db");
    const first = open(paths);
    expect((await first.verifyAndApply(await set("msn_a", 1, "active"))).status).toBe("applied");
    first.close();
    copyStore(paths.store, backup);

    const second = open(paths);
    expect(second.recovering("msn_a")).toBe(false);
    const oldActive = await set("msn_a", 2, "active");
    expect((await second.verifyAndApply(oldActive)).status).toBe("applied");
    expect((await second.verifyAndApply(await set("msn_a", 3, "terminated"))).status).toBe(
      "applied",
    );
    second.close();

    copyStore(backup, paths.store);
    const restored = open(paths);
    try {
      expect(restored.recovering("msn_a")).toBe(true);
      expect(restored.viewState("msn_a")).toBeUndefined();
      expect(restored.lease("msn_a", "2026-10-02T00:00:00Z")).toBeUndefined();
      expect(restored.needsRematerialization("msn_a")).toBe(true);
      // The old signed active event, replayed against the restored store.
      expect(await restored.verifyAndApply(oldActive)).toEqual({
        status: "held",
        reason: "recovery",
      });
      expect(restored.recovering("msn_a")).toBe(true);

      expect(await resync(restored, "msn_a", 3, "terminated")).toMatchObject({
        status: "resynchronized",
        state: "terminated",
        version: 3,
      });
      expect(restored.recovering("msn_a")).toBe(false);
      expect(restored.viewState("msn_a")).toMatchObject({ state: "terminated", version: 3 });
      // Released, but latched at the released version (D950): the restore lost
      // events that may have narrowed authority, so no lease until the
      // consumer acknowledges it rematerialized; a stale acknowledgement fails.
      expect(restored.needsRematerialization("msn_a")).toBe(true);
      expect(restored.lease("msn_a", "2026-10-02T00:00:00Z")).toBeUndefined();
      expect(restored.markRematerialized("msn_a", { version: 2 })).toBe(false);
      expect(restored.markRematerialized("msn_a", { version: 3 })).toBe(true);
      expect(restored.lease("msn_a", "2026-10-02T00:00:00Z")).toMatchObject({
        state: "terminated",
        version: 3,
      });
      // The held SET was not recorded: its redelivery is judged afresh, and
      // refused by the re-established high-water, not taken as a duplicate.
      expect(await restored.verifyAndApply(oldActive)).toEqual({ status: "stale", version: 3 });
    } finally {
      restored.close();
    }
    const after = open(paths);
    try {
      expect(after.recovering("msn_a")).toBe(false);
      expect(after.viewState("msn_a")).toMatchObject({ state: "terminated", version: 3 });
    } finally {
      after.close();
    }
  });

  it("holds a Mission the restored store never held, and a store replaced by an empty one holds every Mission", async () => {
    const paths = layout();
    const backup = join(paths.backups, "receiver.db");
    const first = open(paths);
    await first.verifyAndApply(await set("msn_a", 1, "active"));
    first.close();
    copyStore(paths.store, backup);

    const second = open(paths);
    const firstOfB = await set("msn_b", 1, "active");
    expect((await second.verifyAndApply(firstOfB)).status).toBe("applied");
    expect((await second.verifyAndApply(await set("msn_b", 2, "suspended"))).status).toBe(
      "applied",
    );
    second.close();

    copyStore(backup, paths.store);
    const restored = open(paths);
    try {
      // msn_b has no row in the restored store; its old event is held, not applied as a first event.
      expect(restored.viewState("msn_b")).toBeUndefined();
      expect(restored.recovering("msn_b")).toBe(true);
      expect(await restored.verifyAndApply(firstOfB)).toEqual({
        status: "held",
        reason: "recovery",
      });
      expect(restored.lease("msn_b", "2026-10-02T00:00:00Z")).toBeUndefined();
      expect(await resync(restored, "msn_b", 2, "suspended")).toMatchObject({
        status: "resynchronized",
        version: 2,
      });
      expect(await restored.verifyAndApply(firstOfB)).toEqual({ status: "stale", version: 2 });
    } finally {
      restored.close();
    }

    rmSync(paths.store);
    const emptied = open(paths);
    try {
      for (const id of ["msn_a", "msn_b", "msn_never_seen"])
        expect(emptied.recovering(id), id).toBe(true);
      expect(await emptied.verifyAndApply(await set("msn_never_seen", 1, "active"))).toEqual({
        status: "held",
        reason: "recovery",
      });
    } finally {
      emptied.close();
    }
  });

  it("leaves a Mission held while Mission Status is unavailable or its response does not verify", async () => {
    const paths = layout();
    const backup = join(paths.backups, "receiver.db");
    const first = open(paths);
    await first.verifyAndApply(await set("msn_a", 1, "active"));
    first.close();
    copyStore(paths.store, backup);
    const second = open(paths);
    await second.verifyAndApply(await set("msn_a", 2, "terminated"));
    second.close();
    copyStore(backup, paths.store);

    const restored = open(paths);
    try {
      // No Status read yet: still held.
      expect(restored.recovering("msn_a")).toBe(true);
      const nonce = restored.recoveryNonce("msn_a") as string;
      const otherNonce = restored.recoveryNonce("msn_other") as string;
      const refusals: Array<[string, Promise<string>, string]> = [
        [
          "foreign signature",
          statusResponse("msn_a", 2, "terminated", nonce, { key: foreignKey }),
          "unverified",
        ],
        [
          "another client",
          statusResponse("msn_a", 2, "terminated", nonce, { sub: "someone-else" }),
          "unverified",
        ],
        [
          "expired",
          statusResponse("msn_a", 2, "terminated", nonce, { iatOffset: -600 }),
          "unverified",
        ],
        [
          "a nonce never issued",
          statusResponse("msn_a", 2, "terminated", "rsn_not_issued"),
          "nonce",
        ],
        ["another Mission's nonce", statusResponse("msn_a", 2, "terminated", otherNonce), "nonce"],
      ];
      for (const [label, response, reason] of refusals) {
        expect(await restored.resynchronize("msn_a", await response), label).toEqual({
          status: "refused",
          reason,
        });
        expect(restored.recovering("msn_a"), label).toBe(true);
        expect(restored.lease("msn_a", "2026-10-02T00:00:00Z"), label).toBeUndefined();
      }
    } finally {
      restored.close();
    }
  });

  it("keeps a Mission held across an interrupted recovery: a restart before resynchronizing, and a storage failure inside the resynchronizing transaction", async () => {
    const paths = layout();
    const backup = join(paths.backups, "receiver.db");
    const first = open(paths);
    await first.verifyAndApply(await set("msn_a", 1, "active"));
    first.close();
    copyStore(paths.store, backup);
    const second = open(paths);
    await second.verifyAndApply(await set("msn_a", 2, "terminated"));
    second.close();
    copyStore(backup, paths.store);

    const detected = open(paths);
    expect(detected.recovering("msn_a")).toBe(true);
    detected.close();
    const failing = new FailingReceiver(options(paths));
    try {
      expect(failing.recovering("msn_a")).toBe(true);
      const nonce = failing.recoveryNonce("msn_a") as string;
      const response = await statusResponse("msn_a", 2, "terminated", nonce);
      failing.failNext = true;
      await expect(failing.resynchronize("msn_a", response)).rejects.toThrow(
        SignalReceiverStorageError,
      );
      // Nothing was released, recorded or consumed.
      expect(failing.recovering("msn_a")).toBe(true);
      expect(failing.viewState("msn_a")).toBeUndefined();
      expect(await failing.resynchronize("msn_a", response)).toMatchObject({
        status: "resynchronized",
        version: 2,
      });
    } finally {
      failing.close();
    }
  });

  it("releases nothing for a response to a request made before a later restore, or one reporting a version below the store's", async () => {
    const paths = layout();
    const early = join(paths.backups, "early.db");
    const late = join(paths.backups, "late.db");
    const first = open(paths);
    await first.verifyAndApply(await set("msn_a", 1, "active"));
    first.close();
    copyStore(paths.store, early);
    const second = open(paths);
    await second.verifyAndApply(await set("msn_a", 2, "active"));
    await second.verifyAndApply(await set("msn_a", 3, "suspended"));
    second.close();

    // First restore: the early backup. A nonce is issued for this recovery,
    // and the store is backed up with it.
    copyStore(early, paths.store);
    const firstRecovery = open(paths);
    const staleNonce = firstRecovery.recoveryNonce("msn_a") as string;
    firstRecovery.close();
    copyStore(paths.store, late);
    // More writes advance the witness; then the late backup is restored too.
    const between = open(paths);
    between.recoveryNonce("msn_a");
    between.close();
    copyStore(late, paths.store);

    const secondRecovery = open(paths);
    try {
      expect(secondRecovery.recovering("msn_a")).toBe(true);
      expect(
        await secondRecovery.resynchronize(
          "msn_a",
          await statusResponse("msn_a", 3, "suspended", staleNonce),
        ),
      ).toEqual({
        status: "refused",
        reason: "generation",
      });
      expect(secondRecovery.recovering("msn_a")).toBe(true);
    } finally {
      secondRecovery.close();
    }

    // A store whose row is newer than the Status response: the response is behind.
    const fresh = layout();
    const freshBackup = join(fresh.backups, "receiver.db");
    const r1 = open(fresh);
    await r1.verifyAndApply(await set("msn_c", 1, "active"));
    await r1.verifyAndApply(await set("msn_c", 2, "active"));
    r1.close();
    copyStore(fresh.store, freshBackup);
    const r2 = open(fresh);
    await r2.verifyAndApply(await set("msn_c", 3, "terminated"));
    r2.close();
    copyStore(freshBackup, fresh.store);
    const r3 = open(fresh);
    try {
      expect(await resync(r3, "msn_c", 1, "active")).toEqual({
        status: "refused",
        reason: "behind",
      });
      expect(r3.recovering("msn_c")).toBe(true);
      expect(await resync(r3, "msn_c", 3, "terminated")).toMatchObject({
        status: "resynchronized",
        version: 3,
      });
    } finally {
      r3.close();
    }
  });

  it("refuses to open over a missing, unreadable, foreign or behind witness, and never re-creates it", async () => {
    const paths = layout();
    const first = open(paths);
    await first.verifyAndApply(await set("msn_a", 1, "active"));
    first.close();
    const good = readFileSync(paths.witness, "utf8");
    const earlier = JSON.parse(good) as ReceiverWitness;

    rmSync(paths.witness);
    expect(() => open(paths)).toThrow(SignalReceiverRecoveryError);
    expect(existsSync(paths.witness)).toBe(false);

    writeFileSync(paths.witness, "{");
    expect(() => open(paths)).toThrow(SignalReceiverRecoveryError);
    expect(readFileSync(paths.witness, "utf8")).toBe("{");

    writeFileSync(paths.witness, JSON.stringify({ ...earlier, audience: "https://another.test" }));
    expect(() => open(paths)).toThrow(SignalReceiverRecoveryError);
    writeFileSync(paths.witness, JSON.stringify({ ...earlier, store_id: "srs_another_store" }));
    expect(() => open(paths)).toThrow(SignalReceiverRecoveryError);
    // The witness restored from an older copy: the store is ahead of it.
    writeFileSync(paths.witness, JSON.stringify({ ...earlier, sequence: earlier.sequence - 1 }));
    expect(() => open(paths)).toThrow(SignalReceiverRecoveryError);

    writeFileSync(paths.witness, good);
    const reopened = open(paths);
    expect(reopened.recovering("msn_a")).toBe(false);
    reopened.close();

    expect(() =>
      open(paths, { witness: { file: join(paths.store, "..", "inside.witness") } }),
    ).toThrow(SignalReceiverRecoveryError);
    expect(() => open(paths, { store: {} })).toThrow(SignalReceiverRecoveryError);
    expect(() => open(paths, { status: undefined })).toThrow(SignalReceiverRecoveryError);
  });

  it("the in-process emitter keeps a held SET pending under its backoff, and redelivers it once Mission Status has resynchronized the Mission", async () => {
    const paths = layout();
    const first = open(paths);
    await first.verifyAndApply(await set("msn_e", 1, "active"));
    first.close();
    rmSync(paths.store);
    const restored = open(paths);
    let clock = Date.parse("2026-10-27T00:00:00Z");
    const emitter = new MissionSignalEmitter({
      key: setKey,
      kid: "as-signals",
      consumers: [{ audience: AUD }],
      now: () => new Date(clock),
      retry: { baseMs: 100, capMs: 400 },
    });
    try {
      emitter.register(restored);
      emitter.onCommit({
        id: "msn_e",
        issuer: ISS,
        prior_state: "active",
        state: "suspended",
        version: 2,
        committed_at: "2026-10-27T00:00:00Z",
        expires_at: EXPIRES_AT,
      } as LifecycleCommit);
      await emitter.drain();
      // Held: not acknowledged, so the job stays pending.
      expect(emitter.pending()).toBe(1);
      expect(restored.recovering("msn_e")).toBe(true);
      expect(await resync(restored, "msn_e", 1, "active")).toMatchObject({
        status: "resynchronized",
        version: 1,
      });
      clock += 100;
      await emitter.drain();
      expect(emitter.pending()).toBe(0);
      expect(restored.viewState("msn_e")).toMatchObject({ state: "suspended", version: 2 });
    } finally {
      emitter.close();
      restored.close();
    }
  });

  it("commits nothing when the witness write fails: the SET is not acknowledged, and its redelivery is applied", async () => {
    const paths = layout();
    const receiver = new FailingReceiver(options(paths));
    try {
      const event = await set("msn_a", 1, "active");
      receiver.failNext = true;
      await expect(receiver.verifyAndApply(event)).rejects.toThrow(SignalReceiverStorageError);
      expect(receiver.viewState("msn_a")).toBeUndefined();
      expect((await receiver.verifyAndApply(event)).status).toBe("applied");
    } finally {
      receiver.close();
    }
    // The failed write advanced neither the store nor the witness, and the
    // redelivery advanced both, so the next open finds them equal.
    const reopened = open(paths);
    try {
      expect(reopened.recovering("msn_a")).toBe(false);
    } finally {
      reopened.close();
    }
  });
});

/**
 * @spec control-plane#rollback (D910): the owner's review of #1784. Each test
 * is the review's probe, now refused.
 */
describe("Signals receiver restore admission: review fixes (@spec control-plane#rollback, D910)", () => {
  it("refuses an unwitnessed open of a store this receiver witnesses, so no write escapes the witness, while another audience's receiver still shares the file", async () => {
    const paths = layout();
    const witnessed = open(paths);
    await witnessed.verifyAndApply(await set("msn_a", 1, "active"));
    witnessed.close();
    // The probe: a termination written through an unwitnessed handle, then a
    // restore that loses it, would match the witness. The handle never opens.
    const plain = { jwks, issuer: ISS, audience: AUD, store: { file: paths.store } };
    expect(() => new MissionSignalReceiver(plain)).toThrow(SignalReceiverRecoveryError);
    const other = new MissionSignalReceiver({ ...plain, audience: "https://other.consumer.test" });
    try {
      expect(other.recovering("msn_a")).toBe(false);
    } finally {
      other.close();
    }
    const reopened = open(paths);
    try {
      expect(reopened.recovering("msn_a")).toBe(false);
      expect(reopened.viewState("msn_a")).toMatchObject({ state: "active", version: 1 });
    } finally {
      reopened.close();
    }
  });

  it("admits one witnessed writer: a second handle on the same witness is refused, and so is a handle on a copy of the witness at another path", async () => {
    const paths = layout();
    const first = open(paths);
    try {
      await first.verifyAndApply(await set("msn_a", 1, "active"));
      expect(() => open(paths)).toThrow(SignalReceiverRecoveryError);
      const copy = join(paths.backups, "copied.witness");
      copyFileSync(paths.witness, copy);
      expect(() => open({ store: paths.store, witness: copy })).toThrow(
        SignalReceiverRecoveryError,
      );
    } finally {
      first.close();
    }
    // Released with the first handle: the next writer opens.
    const next = open(paths);
    next.close();
  });

  it("releases nothing for a response past its freshness bound, though its exp is still ahead", async () => {
    const paths = layout();
    const first = open(paths);
    await first.verifyAndApply(await set("msn_a", 1, "active"));
    first.close();
    rmSync(paths.store);
    const restored = open(paths);
    try {
      const nonce = restored.recoveryNonce("msn_a") as string;
      // Signed, nonce-matched, exp a minute ahead, fresh_until ten seconds past.
      const stale = await statusResponse("msn_a", 1, "active", nonce, { freshFor: -10 });
      expect(await restored.resynchronize("msn_a", stale)).toEqual({
        status: "refused",
        reason: "expired",
      });
      expect(restored.recovering("msn_a")).toBe(true);
      expect(await resync(restored, "msn_a", 1, "active")).toMatchObject({
        status: "resynchronized",
        version: 1,
      });
    } finally {
      restored.close();
    }
  });

  it("stops writing when the witness changes underneath a running receiver", async () => {
    const paths = layout();
    const receiver = open(paths);
    try {
      await receiver.verifyAndApply(await set("msn_a", 1, "active"));
      const current = JSON.parse(readFileSync(paths.witness, "utf8")) as ReceiverWitness;
      writeFileSync(paths.witness, JSON.stringify({ ...current, sequence: current.sequence + 5 }));
      await expect(receiver.verifyAndApply(await set("msn_a", 2, "suspended"))).rejects.toThrow(
        SignalReceiverRecoveryError,
      );
      expect(receiver.viewState("msn_a")).toMatchObject({ state: "active", version: 1 });
    } finally {
      receiver.close();
    }
  });
});
