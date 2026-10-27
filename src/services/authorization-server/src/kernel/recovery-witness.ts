/**
 * @spec control-plane#rollback (#250 step 3, comment 14): restore admission for
 * the file-backed single-writer kernel, with a recovery witness kept OUTSIDE the
 * database restore unit.
 *
 * The witness is a small file at a configured path, never inside the store's
 * directory tree, so restoring an older backup of the database cannot roll it
 * back with the data. It holds the store identity, the writer generation, the
 * last committed recovery sequence, while a commit is in flight that commit's
 * intent, and any uncertainty a run detected and could not resolve. The
 * database holds the matching marker row.
 *
 * The witness is owned: a writer holds an exclusive lock on `<witness>.lock` for
 * its lifetime, taken before the witness is read, so a second kernel (on the
 * same store or a copy of it) and an offline reconciliation are refused while
 * one holds it. The lock is a SQLite handle, so the operating system releases
 * it when the process ends.
 *
 * Every outermost write transaction on the kernel database advances both,
 * through the store's commit guard: the witness is read back and must still be
 * the one this writer last wrote, the intent is written durably before the
 * database commit, the marker advances inside the transaction, and the witness
 * is finalized after the commit, before any publication. Every statement that
 * can write (run, get, all and iterate on a statement that is not read-only,
 * the same through a chained builder, and exec) runs inside a guarded
 * transaction. A write that still bypasses the guard is detected at the next
 * guarded transaction, after that write committed, and recorded.
 *
 * Admission at boot compares the marker with the witness, and anything but an
 * exact match with nothing recorded refuses: the kernel does not open.
 * Reconciliation is offline, under the store's and the witness's locks:
 * `init` creates the witness for a store that never had one, `acknowledge`
 * accepts an intent the database committed, `abandon` clears one it did not,
 * and `accept` takes the store as it is under a new generation once a run
 * recorded an uncertainty with no intent pending. Nothing lowers the witness to
 * match an older database.
 *
 * Single host and single writer only. Multi-host failover and multi-process
 * claiming (#641) are not supported.
 */

import { randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import {
  type CommitGuard,
  type Database,
  holdFileLock,
  openStore,
  setCommitGuard,
  withTransaction,
  witnessSharesStoreTree,
  writeDurableFile,
} from "@mission/store";

// The canonical-path containment check lives in `@mission/store` beside the
// durable file writer, shared with the Signals receiver's witness (#1749).
export { witnessSharesStoreTree };

/** Why the kernel's durable state is uncertain. */
export type RecoveryUncertainReason =
  | "uninitialized"
  | "witness_missing"
  | "witness_unreadable"
  | "witness_locked"
  | "witness_moved"
  | "marker_missing"
  | "identity_mismatch"
  | "rollback"
  | "store_ahead"
  | "intent_pending"
  | "escaped_write"
  | "witness_write_failed"
  | "commit_failed";

/** The witness record. `intent` is the sequence of a commit in flight, else null. */
export interface RecoveryWitnessRecord {
  store_id: string;
  generation: number;
  committed: number;
  intent: number | null;
  /** An uncertainty a run detected and could not resolve; only reconciliation clears it. */
  uncertain?: { reason: RecoveryUncertainReason; detail: string };
}

/**
 * The kernel's durable state is uncertain: at boot the kernel does not open,
 * and at run time it refuses every further write. Only offline reconciliation
 * ({@link reconcileKernelRecovery}) or restoring the witnessed state clears it.
 */
export class RecoveryUncertainError extends Error {
  constructor(
    readonly reason: RecoveryUncertainReason,
    detail: string,
  ) {
    super(`kernel recovery state is uncertain (${reason}): ${detail}`);
    this.name = "RecoveryUncertainError";
  }
}

/** A reconciliation that does not apply to the observed state. */
export class RecoveryReconciliationError extends Error {
  constructor(detail: string) {
    super(`recovery reconciliation refused: ${detail}`);
    this.name = "RecoveryReconciliationError";
  }
}

const MARKER_SCHEMA = `
CREATE TABLE IF NOT EXISTS recovery_marker (
  k INTEGER PRIMARY KEY CHECK (k = 1),
  store_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  sequence INTEGER NOT NULL
) STRICT;
`;

interface Marker {
  store_id: string;
  generation: number;
  sequence: number;
}

function readMarker(db: Database): Marker | undefined {
  return db.prepare("SELECT store_id, generation, sequence FROM recovery_marker WHERE k = 1").get() as Marker | undefined;
}

/** The witness at `file`, undefined when the file is absent; a file that cannot be read as a witness is uncertain. */
export function readRecoveryWitness(file: string): RecoveryWitnessRecord | undefined {
  if (!existsSync(file)) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(file, "utf8"));
  } catch (e) {
    throw new RecoveryUncertainError("witness_unreadable", `${file}: ${(e as Error).message}`);
  }
  const w = parsed as Partial<RecoveryWitnessRecord>;
  const sequence = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;
  const uncertain = w?.uncertain as { reason?: unknown; detail?: unknown } | undefined;
  if (
    !w ||
    typeof w !== "object" ||
    typeof w.store_id !== "string" ||
    !w.store_id ||
    !sequence(w.generation) ||
    !sequence(w.committed) ||
    !(w.intent === null || sequence(w.intent)) ||
    (uncertain !== undefined &&
      (typeof uncertain !== "object" || typeof uncertain.reason !== "string" || typeof uncertain.detail !== "string"))
  ) {
    throw new RecoveryUncertainError("witness_unreadable", `${file} is not a recovery witness`);
  }
  return {
    store_id: w.store_id,
    generation: w.generation,
    committed: w.committed,
    intent: w.intent,
    ...(uncertain ? { uncertain: { reason: uncertain.reason as RecoveryUncertainReason, detail: uncertain.detail as string } } : {}),
  };
}

/**
 * Replace the witness durably: write a sibling temporary file, flush it,
 * rename it over the witness, and flush the directory, so a crash leaves the
 * old record or the new one, never a torn file.
 */
export function writeRecoveryWitness(file: string, record: RecoveryWitnessRecord): void {
  writeDurableFile(file, JSON.stringify(record));
}

/**
 * Take the witness's lock, held until the returned handle closes. Refused while
 * any other kernel or reconciliation holds it, whichever store it opened.
 */
function lockWitness(witnessFile: string): Database {
  try {
    return holdFileLock(`${witnessFile}.lock`);
  } catch (e) {
    throw new RecoveryUncertainError("witness_locked", `another writer holds the witness ${witnessFile}: ${(e as Error).message}`);
  }
}

/**
 * Compare the database's marker with the witness. Only an exact match, with no
 * intent in flight and no uncertainty recorded, admits.
 */
function admit(db: Database, witnessFile: string): RecoveryWitnessRecord {
  db.exec(MARKER_SCHEMA);
  const marker = readMarker(db);
  const witness = readRecoveryWitness(witnessFile);
  if (!marker && !witness) {
    throw new RecoveryUncertainError("uninitialized", "neither the store nor the witness was initialized; run the init reconciliation");
  }
  if (!witness) throw new RecoveryUncertainError("witness_missing", `the store has a recovery marker but ${witnessFile} is absent`);
  if (!marker) throw new RecoveryUncertainError("marker_missing", "the witness exists but the store has no recovery marker");
  if (marker.store_id !== witness.store_id || marker.generation !== witness.generation) {
    throw new RecoveryUncertainError(
      "identity_mismatch",
      `the store is ${marker.store_id} generation ${marker.generation}; the witness is ${witness.store_id} generation ${witness.generation}`,
    );
  }
  if (witness.intent !== null) {
    throw new RecoveryUncertainError(
      "intent_pending",
      `a commit was in flight: the witness committed ${witness.committed} with intent ${witness.intent}, and the store is at ${marker.sequence}`,
    );
  }
  if (witness.uncertain) {
    throw new RecoveryUncertainError(
      witness.uncertain.reason,
      `recorded by an earlier run and not reconciled: ${witness.uncertain.detail}`,
    );
  }
  if (marker.sequence < witness.committed) {
    throw new RecoveryUncertainError(
      "rollback",
      `the store is at ${marker.sequence}, older than the witnessed ${witness.committed}: a restored backup cannot be resumed`,
    );
  }
  if (marker.sequence > witness.committed) {
    throw new RecoveryUncertainError("store_ahead", `the store is at ${marker.sequence}, ahead of the witnessed ${witness.committed}`);
  }
  return witness;
}

const sameRecord = (a: RecoveryWitnessRecord | undefined, b: RecoveryWitnessRecord): boolean =>
  a !== undefined &&
  a.store_id === b.store_id &&
  a.generation === b.generation &&
  a.committed === b.committed &&
  a.intent === b.intent &&
  a.uncertain === undefined &&
  b.uncertain === undefined;

/**
 * The commit guard for one admitted kernel database. Fail-stop: any anomaly
 * (a write that bypassed the guard, a witness that changed underneath this
 * writer, a witness write that failed, a commit that failed after its intent)
 * leaves the kernel uncertain, records that in the witness where it can, and
 * every later guarded transaction refuses.
 */
export class RecoveryGuard implements CommitGuard {
  private failure: RecoveryUncertainError | undefined;
  private baseline: number;
  private frameStart = 0;
  private advanced = false;
  /** The record this writer last wrote, the intent included. */
  private written: RecoveryWitnessRecord;
  private readonly totalChangesStmt;
  private readonly advanceMarkerStmt;

  constructor(
    private readonly witnessFile: string,
    private record: RecoveryWitnessRecord,
    prepare: Database["prepare"],
    private readonly lock: Database,
  ) {
    this.written = record;
    this.totalChangesStmt = prepare("SELECT total_changes() AS n");
    this.advanceMarkerStmt = prepare("UPDATE recovery_marker SET sequence = ? WHERE k = 1 AND sequence = ?");
    this.baseline = this.totalChanges();
  }

  /** The uncertainty this kernel ran into, if any. */
  get uncertainty(): RecoveryUncertainError | undefined {
    return this.failure;
  }

  /** The witness as last finalized. */
  get witness(): RecoveryWitnessRecord {
    return { ...this.record };
  }

  /** Release the witness's lock (the kernel closes it with its store). */
  release(): void {
    if (this.lock.open) this.lock.close();
  }

  begin(): void {
    if (this.failure) throw this.failure;
    const now = this.totalChanges();
    if (now !== this.baseline) {
      this.fail("escaped_write", `${now - this.baseline} row change(s) reached the store outside a guarded transaction`);
    }
    this.frameStart = now;
    this.advanced = false;
  }

  beforeCommit(): void {
    if (this.totalChanges() === this.frameStart) return; // nothing written
    let onDisk: RecoveryWitnessRecord | undefined;
    try {
      onDisk = readRecoveryWitness(this.witnessFile);
    } catch (e) {
      this.fail("witness_unreadable", (e as Error).message);
    }
    if (!sameRecord(onDisk, this.record)) {
      this.fail(
        "witness_moved",
        `the witness is not the one this writer last wrote (committed ${this.record.committed}); another writer has written it`,
        onDisk,
      );
    }
    const next = this.record.committed + 1;
    const intent: RecoveryWitnessRecord = { ...this.record, intent: next };
    try {
      this.persist(intent);
    } catch (e) {
      // The intent may have reached the witness: record over it, so a restart
      // still sees the commit that was in flight.
      this.fail("witness_write_failed", `the witness intent could not be written: ${(e as Error).message}`, intent);
    }
    this.written = intent;
    this.advanced = true;
    const moved = this.advanceMarkerStmt.run(next, this.record.committed).changes;
    if (moved !== 1) this.fail("identity_mismatch", "the store's recovery marker moved underneath this writer");
  }

  settled(committed: boolean): void {
    this.baseline = this.totalChanges();
    if (this.advanced && !committed) {
      this.advanced = false;
      this.recordFailure("commit_failed", `the witness holds intent ${this.record.committed + 1} for a transaction that did not commit`);
    }
  }

  afterCommit(): void {
    if (!this.advanced) return;
    this.advanced = false;
    const finalized: RecoveryWitnessRecord = { ...this.record, committed: this.record.committed + 1, intent: null };
    try {
      this.persist(finalized);
    } catch (e) {
      this.fail("witness_write_failed", `the committed sequence ${finalized.committed} could not be finalized: ${(e as Error).message}`);
    }
    this.written = finalized;
    this.record = finalized;
  }

  /** Write the witness: the intent before a commit, the finalized record after it. */
  protected persist(record: RecoveryWitnessRecord): void {
    writeRecoveryWitness(this.witnessFile, record);
  }

  private totalChanges(): number {
    return (this.totalChangesStmt.get() as { n: number }).n;
  }

  /**
   * Become uncertain and record why in the witness, over `base` (by default the
   * record this writer last wrote, so a pending intent is kept). Recording is
   * itself a witness write: when it fails, a pending intent is the durable trace.
   */
  private recordFailure(reason: RecoveryUncertainReason, detail: string, base: RecoveryWitnessRecord | undefined = this.written): RecoveryUncertainError {
    if (!this.failure) {
      this.failure = new RecoveryUncertainError(reason, detail);
      if (base) {
        try {
          this.persist({ ...base, uncertain: { reason, detail } });
        } catch {
          // The witness cannot be written; the failure stays in memory.
        }
      }
    }
    return this.failure;
  }

  private fail(reason: RecoveryUncertainReason, detail: string, base?: RecoveryWitnessRecord): never {
    throw this.recordFailure(reason, detail, base ?? this.written);
  }
}

/**
 * Admit an exclusively opened kernel database against its witness and guard
 * every later write. The witness must be outside the store's directory tree;
 * its lock is taken before it is read. Throws {@link RecoveryUncertainError}
 * when the lock or admission refuses; the caller closes the database.
 */
export function guardKernelStore(db: Database, storeFile: string, witnessFile: string): RecoveryGuard {
  if (witnessSharesStoreTree(storeFile, witnessFile)) {
    throw new Error("the recovery witness must be outside the store's directory, and the store outside the witness's");
  }
  const lock = lockWitness(witnessFile);
  try {
    const record = admit(db, witnessFile);
    const prepare = db.prepare.bind(db);
    const exec = db.exec.bind(db);
    const guard = new RecoveryGuard(witnessFile, record, prepare, lock);
    setCommitGuard(db, guard);
    (db as { prepare: Database["prepare"] }).prepare = ((source: string) =>
      guardStatement(db, prepare(source))) as Database["prepare"];
    (db as { exec: Database["exec"] }).exec = ((source: string) => {
      if (db.inTransaction) exec(source);
      else withTransaction(db, () => exec(source));
      return db;
    }) as Database["exec"];
    return guard;
  } catch (e) {
    lock.close();
    throw e;
  }
}

/**
 * `stmt`, unchanged when it is read-only; otherwise every call that executes
 * it (`run`, `get`, `all`, `iterate`) runs in a guarded transaction when none
 * is open, and a chained builder (`pluck`, `raw`, `bind`, ...) keeps the guard.
 */
function guardStatement<S extends object>(db: Database, stmt: S): S {
  if ((stmt as { readonly?: boolean }).readonly) return stmt;
  const guarded = (fn: () => unknown): unknown => (db.inTransaction ? fn() : withTransaction(db, fn));
  const proxy: S = new Proxy(stmt, {
    get(target, prop) {
      const value = Reflect.get(target, prop, target) as unknown;
      if (typeof value !== "function") return value;
      const method = value as (...args: unknown[]) => unknown;
      if (prop === "run" || prop === "get" || prop === "all") {
        return (...args: unknown[]) => guarded(() => method.apply(target, args));
      }
      if (prop === "iterate") {
        return (...args: unknown[]) =>
          db.inTransaction
            ? method.apply(target, args)
            : (guarded(() => [...(method.apply(target, args) as Iterable<unknown>)]) as unknown[])[Symbol.iterator]();
      }
      return (...args: unknown[]) => {
        const out = method.apply(target, args);
        return out === target ? proxy : out;
      };
    },
  });
  return proxy;
}

/**
 * Refuse a store that has a recovery marker when it is opened WITHOUT its
 * witness: its writes would go unwitnessed, and the next witnessed boot would
 * admit changes nothing recorded. A store that never had a marker opens.
 */
export function refuseUnwitnessedOpen(db: Database): void {
  const table = db
    .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'recovery_marker'")
    .get();
  if (table && readMarker(db)) {
    throw new RecoveryUncertainError(
      "witness_missing",
      "the store has a recovery marker, so it opens only with its recovery witness",
    );
  }
}

/** An offline reconciliation step. */
export type RecoveryReconciliation = "init" | "acknowledge" | "abandon" | "accept";

/**
 * Reconcile a kernel store with its witness, offline. The store is opened
 * exclusively and the witness's lock taken, so this refuses while any kernel
 * holds either: nothing can commit while the decision is made.
 *
 * - `init`: create the marker and the witness for a store that has no marker
 *   (a new store, or one that predates the witness), when no witness exists
 *   or the witness is a fresh one no commit has advanced.
 * - `acknowledge`: an intent is pending and the store is at exactly that
 *   intent: the commit happened, so the witness records it.
 * - `abandon`: an intent is pending and the store is at the committed
 *   sequence: the commit did not happen, so the intent is cleared.
 * - `accept`: a run recorded an uncertainty (an escaped write, a witness that
 *   moved) with no intent pending, and the store is not older than the
 *   witness: the store is taken as it is under a new generation. An accept
 *   interrupted after the store's marker moved is completed by running it again.
 *
 * Anything else refuses. An older store is never accepted: restore one at the
 * witnessed sequence instead.
 */
export function reconcileKernelRecovery(options: {
  storeFile: string;
  witnessFile: string;
  action: RecoveryReconciliation;
}): RecoveryWitnessRecord {
  if (witnessSharesStoreTree(options.storeFile, options.witnessFile)) {
    throw new RecoveryReconciliationError("the witness must be outside the store's directory, and the store outside the witness's");
  }
  let lock: Database;
  try {
    lock = lockWitness(options.witnessFile);
  } catch (e) {
    throw new RecoveryReconciliationError(`the witness is held, so another writer may hold it: ${(e as Error).message}`);
  }
  let db: Database;
  try {
    db = openStore("", { file: options.storeFile, exclusive: true });
  } catch (e) {
    lock.close();
    throw new RecoveryReconciliationError(`the store cannot be opened exclusively, so another writer may hold it: ${(e as Error).message}`);
  }
  try {
    db.exec(MARKER_SCHEMA);
    const marker = readMarker(db);
    const witness = readRecoveryWitness(options.witnessFile);
    switch (options.action) {
      case "init": {
        if (marker) throw new RecoveryReconciliationError("the store already has a recovery marker");
        if (witness && (witness.committed !== 0 || witness.intent !== null || witness.generation !== 1 || witness.uncertain)) {
          throw new RecoveryReconciliationError("the witness has advanced; it belongs to a store that is not this one");
        }
        const record: RecoveryWitnessRecord = witness ?? {
          store_id: `kst_${randomBytes(12).toString("base64url")}`,
          generation: 1,
          committed: 0,
          intent: null,
        };
        // The witness first: an interrupted init leaves a fresh witness and no
        // marker, which a second init completes.
        if (!witness) writeRecoveryWitness(options.witnessFile, record);
        withTransaction(db, () =>
          db
            .prepare("INSERT INTO recovery_marker (k, store_id, generation, sequence) VALUES (1, ?, ?, 0)")
            .run(record.store_id, record.generation),
        );
        return record;
      }
      case "acknowledge":
      case "abandon": {
        if (!witness) throw new RecoveryReconciliationError("there is no witness");
        if (!marker) throw new RecoveryReconciliationError("the store has no recovery marker");
        if (marker.store_id !== witness.store_id || marker.generation !== witness.generation) {
          throw new RecoveryReconciliationError("the store and the witness have different identities");
        }
        if (witness.intent === null) throw new RecoveryReconciliationError("no intent is pending");
        const expected = options.action === "acknowledge" ? witness.intent : witness.committed;
        if (marker.sequence !== expected) {
          throw new RecoveryReconciliationError(
            `${options.action} needs the store at ${expected}, and it is at ${marker.sequence}`,
          );
        }
        const record: RecoveryWitnessRecord = {
          store_id: witness.store_id,
          generation: witness.generation,
          committed: marker.sequence,
          intent: null,
        };
        writeRecoveryWitness(options.witnessFile, record);
        return record;
      }
      case "accept": {
        if (!witness) throw new RecoveryReconciliationError("there is no witness");
        if (!marker) throw new RecoveryReconciliationError("the store has no recovery marker");
        if (!witness.uncertain) throw new RecoveryReconciliationError("no uncertainty is recorded; accept applies only to one");
        if (witness.intent !== null) {
          throw new RecoveryReconciliationError("an intent is pending: acknowledge or abandon it");
        }
        const sameGeneration = marker.generation === witness.generation;
        const interrupted = marker.generation === witness.generation + 1;
        if (marker.store_id !== witness.store_id || !(sameGeneration || interrupted)) {
          throw new RecoveryReconciliationError("the store and the witness have different identities");
        }
        if (marker.sequence < witness.committed) {
          throw new RecoveryReconciliationError(
            `the store is at ${marker.sequence}, older than the witnessed ${witness.committed}: restore the witnessed store`,
          );
        }
        const generation = witness.generation + 1;
        // The marker first: an accept interrupted here leaves the store one
        // generation ahead of a witness that still records the uncertainty, which
        // a second accept completes.
        if (sameGeneration) {
          withTransaction(db, () =>
            db.prepare("UPDATE recovery_marker SET generation = ? WHERE k = 1").run(generation),
          );
        }
        const record: RecoveryWitnessRecord = {
          store_id: witness.store_id,
          generation,
          committed: marker.sequence,
          intent: null,
        };
        writeRecoveryWitness(options.witnessFile, record);
        return record;
      }
    }
  } finally {
    db.close();
    lock.close();
  }
}
