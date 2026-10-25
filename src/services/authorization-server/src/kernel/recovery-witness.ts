/**
 * @spec control-plane#rollback (#250 step 3, comment 14): restore admission for
 * the file-backed single-writer kernel, with a recovery witness kept OUTSIDE the
 * database restore unit.
 *
 * The witness is a small file at a configured path, never inside the database,
 * so restoring an older backup of the database cannot roll it back with the
 * data. It holds the store identity, the writer generation, the last committed
 * recovery sequence and, while a commit is in flight, that commit's intent. The
 * database holds the matching marker row.
 *
 * Every outermost write transaction on the kernel database advances both,
 * through the store's commit guard: the witness intent is written durably
 * before the database commit, the marker advances inside the transaction, and
 * the witness is finalized after the commit, before any publication. Bare
 * statements are run as one-statement guarded transactions, and a write that
 * still bypasses the guard is detected at the next guarded transaction.
 *
 * Admission at boot compares the marker with the witness, and anything but an
 * exact match refuses: the kernel does not open. A missing witness, a missing
 * marker, another identity, an older database (a restored backup), a database
 * ahead of the witness, and an unresolved intent are all uncertain, never
 * initialized or resumed automatically. Reconciliation is offline, under the
 * store's exclusive lock, so no running writer can commit while it decides:
 * `init` creates the witness for a store that never had one, `acknowledge`
 * accepts an intent the database committed, and `abandon` clears one it did
 * not. Nothing lowers the witness to match an older database.
 *
 * Single host and single writer only: the exclusive lock fences a second
 * handle or process on this host, and the witness is a local file. Multi-host
 * failover and multi-process claiming (#641) are not supported.
 */

import { randomBytes } from "node:crypto";
import { closeSync, existsSync, fsyncSync, openSync, readFileSync, renameSync, writeSync } from "node:fs";
import { dirname, join } from "node:path";
import {
  type CommitGuard,
  type Database,
  openStore,
  setCommitGuard,
  withTransaction,
} from "@mission/store";

/** The witness record. `intent` is the sequence of a commit in flight, else null. */
export interface RecoveryWitnessRecord {
  store_id: string;
  generation: number;
  committed: number;
  intent: number | null;
}

/** Why the kernel's durable state is uncertain. */
export type RecoveryUncertainReason =
  | "uninitialized"
  | "witness_missing"
  | "witness_unreadable"
  | "marker_missing"
  | "identity_mismatch"
  | "rollback"
  | "store_ahead"
  | "intent_pending"
  | "escaped_write"
  | "witness_write_failed"
  | "commit_failed";

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
  if (
    !w ||
    typeof w !== "object" ||
    typeof w.store_id !== "string" ||
    !w.store_id ||
    !sequence(w.generation) ||
    !sequence(w.committed) ||
    !(w.intent === null || sequence(w.intent))
  ) {
    throw new RecoveryUncertainError("witness_unreadable", `${file} is not a recovery witness`);
  }
  return { store_id: w.store_id, generation: w.generation, committed: w.committed, intent: w.intent };
}

/**
 * Replace the witness durably: write a sibling temporary file, flush it,
 * rename it over the witness, and flush the directory, so a crash leaves the
 * old record or the new one, never a torn file.
 */
export function writeRecoveryWitness(file: string, record: RecoveryWitnessRecord): void {
  const tmp = join(dirname(file), `.${randomBytes(6).toString("hex")}.witness.tmp`);
  const fd = openSync(tmp, "w", 0o600);
  try {
    writeSync(fd, JSON.stringify(record));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, file);
  const dir = openSync(dirname(file), "r");
  try {
    fsyncSync(dir);
  } finally {
    closeSync(dir);
  }
}

/**
 * Compare the database's marker with the witness. Only an exact match, with
 * no intent in flight, admits; every other combination is uncertain.
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

/**
 * The commit guard for one admitted kernel database. Fail-stop: any anomaly
 * (a write that bypassed the guard, a witness write that failed, a commit that
 * failed after its intent) leaves the kernel uncertain, and every later
 * guarded transaction refuses.
 */
export class RecoveryGuard implements CommitGuard {
  private failure: RecoveryUncertainError | undefined;
  private baseline: number;
  private frameStart = 0;
  private advanced = false;
  private readonly totalChangesStmt;
  private readonly advanceMarkerStmt;

  constructor(
    private readonly witnessFile: string,
    private record: RecoveryWitnessRecord,
    prepare: Database["prepare"],
  ) {
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
    const next = this.record.committed + 1;
    try {
      this.persist({ ...this.record, intent: next });
    } catch (e) {
      this.fail("witness_write_failed", `the witness intent could not be written: ${(e as Error).message}`);
    }
    this.advanced = true;
    const moved = this.advanceMarkerStmt.run(next, this.record.committed).changes;
    if (moved !== 1) this.fail("identity_mismatch", "the store's recovery marker moved underneath this writer");
  }

  settled(committed: boolean): void {
    this.baseline = this.totalChanges();
    if (this.advanced && !committed) {
      this.advanced = false;
      this.failure ??= new RecoveryUncertainError(
        "commit_failed",
        `the witness holds intent ${this.record.committed + 1} for a transaction that did not commit`,
      );
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
    this.record = finalized;
  }

  /** Write the witness: the intent before a commit, the finalized record after it. */
  protected persist(record: RecoveryWitnessRecord): void {
    writeRecoveryWitness(this.witnessFile, record);
  }

  private totalChanges(): number {
    return (this.totalChangesStmt.get() as { n: number }).n;
  }

  private fail(reason: RecoveryUncertainReason, detail: string): never {
    this.failure ??= new RecoveryUncertainError(reason, detail);
    throw this.failure;
  }
}

/**
 * Admit an exclusively opened kernel database against its witness and guard
 * every later write. Bare statements become one-statement guarded
 * transactions. Throws {@link RecoveryUncertainError} when admission refuses;
 * the caller closes the database.
 */
export function guardKernelStore(db: Database, witnessFile: string): RecoveryGuard {
  const record = admit(db, witnessFile);
  const prepare = db.prepare.bind(db);
  const guard = new RecoveryGuard(witnessFile, record, prepare);
  setCommitGuard(db, guard);
  (db as { prepare: Database["prepare"] }).prepare = ((source: string) =>
    guardBareRun(db, prepare(source))) as Database["prepare"];
  return guard;
}

/** `stmt` with `run` wrapped in a guarded transaction when no transaction is open. */
function guardBareRun<S extends object>(db: Database, stmt: S): S {
  return new Proxy(stmt, {
    get(target, prop) {
      const value = Reflect.get(target, prop, target) as unknown;
      if (prop === "run") {
        const run = value as (...args: unknown[]) => unknown;
        return (...args: unknown[]) =>
          db.inTransaction ? run.apply(target, args) : withTransaction(db, () => run.apply(target, args));
      }
      return typeof value === "function" ? (value as (...a: unknown[]) => unknown).bind(target) : value;
    },
  });
}

/** An offline reconciliation step. */
export type RecoveryReconciliation = "init" | "acknowledge" | "abandon";

/**
 * Reconcile a kernel store with its witness, offline. The store is opened
 * exclusively, so this refuses while a kernel holds it: nothing can commit
 * while the decision is made.
 *
 * - `init`: create the marker and the witness for a store that has no marker
 *   (a new store, or one that predates the witness), when no witness exists
 *   or the witness is a fresh one no commit has advanced.
 * - `acknowledge`: an intent is pending and the store is at exactly that
 *   intent: the commit happened, so the witness records it.
 * - `abandon`: an intent is pending and the store is at the committed
 *   sequence: the commit did not happen, so the intent is cleared.
 *
 * Anything else refuses. An older store is never accepted: restore one at the
 * witnessed sequence instead.
 */
export function reconcileKernelRecovery(options: {
  storeFile: string;
  witnessFile: string;
  action: RecoveryReconciliation;
}): RecoveryWitnessRecord {
  let db: Database;
  try {
    db = openStore("", { file: options.storeFile, exclusive: true });
  } catch (e) {
    throw new RecoveryReconciliationError(`the store cannot be opened exclusively, so another writer may hold it: ${(e as Error).message}`);
  }
  try {
    db.exec(MARKER_SCHEMA);
    const marker = readMarker(db);
    const witness = readRecoveryWitness(options.witnessFile);
    switch (options.action) {
      case "init": {
        if (marker) throw new RecoveryReconciliationError("the store already has a recovery marker");
        if (witness && (witness.committed !== 0 || witness.intent !== null || witness.generation !== 1)) {
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
        const record: RecoveryWitnessRecord = { ...witness, committed: marker.sequence, intent: null };
        writeRecoveryWitness(options.witnessFile, record);
        return record;
      }
    }
  } finally {
    db.close();
  }
}
