/**
 * SQLite :memory: repository baseline (decision D27). Each service opens its
 * own in-memory database, applies its schema on boot, and reseeds from
 * demo-data. UNIQUE constraints and transactions carry the invariants the
 * specs imply (idempotency keys, id non-reuse, single-use redemption).
 */

import Database from "better-sqlite3";

export type { Database } from "better-sqlite3";

export interface StoreOptions {
  /** Non-default persistence escape hatch (D27); ':memory:' is the default. */
  file?: string;
  /**
   * Hold the file's lock for this handle's lifetime: `locking_mode=EXCLUSIVE`
   * and `synchronous=FULL`, with no busy wait, so a second handle or process
   * opening the same file is refused at once rather than becoming a second
   * writer. Meaningful only with `file`.
   */
  exclusive?: boolean;
  /**
   * The file's durability, set independently of locking (#1684, D826):
   * `FULL` adds a WAL synchronization at each commit, which supports
   * power-loss durability where the storage stack honors synchronization.
   * The value is read back and the open refused if it did not take. Absent,
   * WAL's default applies, unless `exclusive` asks for FULL.
   */
  synchronous?: "FULL";
}

/** A store whose requested durability did not take: the open is refused. */
export class StoreDurabilityError extends Error {}

export function openStore(schemaSql: string, options: StoreOptions = {}): Database.Database {
  const db = new Database(options.file ?? ":memory:", options.exclusive ? { timeout: 0 } : {});
  if (options.exclusive) db.pragma("locking_mode = EXCLUSIVE");
  db.pragma("journal_mode = WAL");
  if (options.exclusive || options.synchronous === "FULL") {
    db.pragma("synchronous = FULL");
    // 2 is FULL. Verified, not assumed: a build or environment that ignored
    // the pragma would otherwise run with less durability than asked for.
    if (db.pragma("synchronous", { simple: true }) !== 2) {
      db.close();
      throw new StoreDurabilityError("the store did not accept synchronous=FULL");
    }
  }
  db.pragma("foreign_keys = ON");
  // Under EXCLUSIVE, the first write takes the lock and keeps it until close.
  if (options.exclusive) db.transaction(() => undefined).immediate();
  db.exec(schemaSql);
  return db;
}

/**
 * Open an existing store file read-only, for an inspection that must not
 * write (#831 B2: retiring a Status key reads the kernel's standing
 * consents). Refuses a file that does not exist.
 */
export function openStoreReadOnly(file: string): Database.Database {
  return new Database(file, { readonly: true, fileMustExist: true });
}

/**
 * Hold a lock file until the returned handle closes: an exclusive SQLite
 * handle, which the operating system releases with the process, so a crash
 * leaves no stale lock. A second holder, in this process or another, is
 * refused at once. The kernel's recovery witness and the Signals receiver's
 * (#1749) are each held this way by their one writer.
 */
export function holdFileLock(file: string): Database.Database {
  const lock = openStore("", { file, exclusive: true });
  try {
    lock.exec(
      "CREATE TABLE IF NOT EXISTS witness_lock (k INTEGER PRIMARY KEY CHECK (k = 1), held_at TEXT NOT NULL)",
    );
    lock
      .prepare(
        "INSERT INTO witness_lock (k, held_at) VALUES (1, ?) ON CONFLICT(k) DO UPDATE SET held_at = excluded.held_at",
      )
      .run(new Date().toISOString());
  } catch (e) {
    lock.close();
    throw e;
  }
  return lock;
}

/**
 * A durable store that could not be opened safely. Every refusal of
 * {@link openDurableStore} is this error and is fatal at startup: the caller
 * holds no handle, so nothing can fall back to an in-memory best effort.
 */
export class DurableStoreError extends Error {
  constructor(why: string) {
    super(`durable store refused: ${why}`);
    this.name = "DurableStoreError";
  }
}

export interface DurableStoreOptions {
  /**
   * The database file, from configuration. Absent, empty, or an in-memory
   * name refuses: {@link openStore}'s `:memory:` default is exactly the
   * persistence a durable store must never assume.
   */
  file: string | undefined;
  /**
   * Ordered schema migrations. Entry `i` moves `PRAGMA user_version` from
   * `i` to `i + 1`; every pending entry runs in one transaction with the
   * version bump, so a crash leaves the old schema or the new one, never a
   * half-applied migration.
   */
  migrations: readonly string[];
  /**
   * The component that owns this store. Recorded on first open; a later open
   * by a different owner refuses, so one file cannot silently become two
   * components' state.
   */
  owner: string;
  /**
   * Milliseconds to wait for another handle's lock before refusing. Default
   * 0: a store another handle or process holds is refused at once, never
   * shared.
   */
  lockTimeoutMs?: number;
}

const IN_MEMORY_NAMES = new Set([":memory:", "file::memory:"]);

/**
 * Open a durable, single-writer SQLite store (D27's persistence escape hatch,
 * made explicit). The file comes from configuration and is never defaulted.
 * `locking_mode=EXCLUSIVE` with WAL and `synchronous=FULL`: the startup
 * write below takes the exclusive lock, and under EXCLUSIVE it is held until
 * {@link Database.close}, so a second handle or process cannot open the same
 * store while this one lives. A schema newer than `migrations` describes, or
 * a store recorded for a different owner, refuses.
 */
export function openDurableStore(options: DurableStoreOptions): Database.Database {
  const file = options.file;
  if (typeof file !== "string" || file.trim().length === 0)
    throw new DurableStoreError("no store file is configured");
  if (
    IN_MEMORY_NAMES.has(file) ||
    file.startsWith("file::memory:") ||
    /[?&]mode=memory\b/.test(file)
  ) {
    throw new DurableStoreError("an in-memory store is not durable");
  }
  if (!options.owner) throw new DurableStoreError("no owner is named");
  let db: Database.Database;
  try {
    db = new Database(file, { timeout: options.lockTimeoutMs ?? 0 });
  } catch (e) {
    throw new DurableStoreError(`cannot open ${file}: ${(e as Error).message}`);
  }
  try {
    db.pragma("locking_mode = EXCLUSIVE");
    const mode = db.pragma("journal_mode = WAL", { simple: true });
    if (String(mode).toLowerCase() !== "wal")
      throw new DurableStoreError(`journal_mode is ${String(mode)}, not wal`);
    db.pragma("synchronous = FULL");
    db.pragma("foreign_keys = ON");
    db.transaction(() => {
      db.exec("CREATE TABLE IF NOT EXISTS store_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL) STRICT");
      const owner = db.prepare("SELECT v FROM store_meta WHERE k = 'owner'").get() as
        | { v: string }
        | undefined;
      if (owner && owner.v !== options.owner) {
        throw new DurableStoreError(`store is owned by ${owner.v}, not ${options.owner}`);
      }
      const version = db.pragma("user_version", { simple: true }) as number;
      if (version > options.migrations.length) {
        throw new DurableStoreError(
          `schema version ${version} is newer than this build's ${options.migrations.length}`,
        );
      }
      for (const migration of options.migrations.slice(version)) db.exec(migration);
      db.pragma(`user_version = ${options.migrations.length}`);
      // The startup write: it records the owner and takes the exclusive lock
      // that EXCLUSIVE mode then holds for this handle's lifetime.
      db.prepare(
        "INSERT INTO store_meta (k, v) VALUES ('owner', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
      ).run(options.owner);
    }).immediate();
  } catch (e) {
    db.close();
    if (e instanceof DurableStoreError) throw e;
    throw new DurableStoreError(`cannot initialize ${file}: ${(e as Error).message}`);
  }
  return db;
}

export class UniqueViolationError extends Error {
  constructor(readonly detail: string) {
    super(`unique constraint violated: ${detail}`);
  }
}

/**
 * Run fn inside a transaction; SQLITE_CONSTRAINT_* unique failures are
 * mapped to UniqueViolationError so callers can implement idempotency and
 * single-use semantics without string-matching driver errors.
 */
type CommitFrame = { callbacks: Array<() => void> };
const commitFrames = new WeakMap<Database.Database, CommitFrame>();

/** Publish after the outermost managed commit, never after a rolled-back
 * savepoint. Not durable delivery: process-loss recovery still needs an outbox. */
export function afterCommit(db: Database.Database, callback: () => void): void {
  const frame = commitFrames.get(db);
  if (frame) frame.callbacks.push(callback);
  else if (db.inTransaction) throw new Error("afterCommit requires a managed transaction");
  else callback();
}

/**
 * A hook around each OUTERMOST managed transaction on one database, for an
 * owner that keeps an external record of its commits (the kernel's recovery
 * witness, #250): `begin` before it opens, `beforeCommit` as its last step
 * inside it, `settled` once it has committed or rolled back, and
 * `afterCommit` after a commit, before its {@link afterCommit} callbacks. A
 * throw from `afterCommit` skips those callbacks. Savepoints are not hooked.
 */
export interface CommitGuard {
  begin(): void;
  beforeCommit(): void;
  settled(committed: boolean): void;
  afterCommit(): void;
}
const commitGuards = new WeakMap<Database.Database, CommitGuard>();

/** Register `guard` for every outermost {@link withTransaction} on `db`. */
export function setCommitGuard(db: Database.Database, guard: CommitGuard): void {
  commitGuards.set(db, guard);
}

export function withTransaction<T>(db: Database.Database, fn: () => T): T {
  const parent = commitFrames.get(db);
  if (db.inTransaction && !parent)
    throw new Error("withTransaction cannot nest in an unmanaged transaction");
  const guard = parent ? undefined : commitGuards.get(db);
  const frame: CommitFrame = { callbacks: [] };
  commitFrames.set(db, frame);
  let result: T;
  let committed = false;
  try {
    guard?.begin();
    const body = guard
      ? () => {
          const value = fn();
          guard.beforeCommit();
          return value;
        }
      : fn;
    result = db.transaction(body)();
    committed = true;
  } catch (e) {
    if (isUniqueViolation(e)) {
      throw new UniqueViolationError((e as Error).message);
    }
    throw e;
  } finally {
    if (parent) commitFrames.set(db, parent);
    else commitFrames.delete(db);
    guard?.settled(committed);
  }
  if (parent) parent.callbacks.push(...frame.callbacks);
  else {
    guard?.afterCommit();
    for (const callback of frame.callbacks) callback();
  }
  return result;
}

/**
 * Atomic single-use redemption: returns true exactly once per key.
 * Callers create the table via redemptionSchema(name).
 */
export function redeemOnce(
  db: Database.Database,
  table: string,
  key: string,
  epoch: string,
): boolean {
  const stmt = db.prepare(
    `INSERT INTO ${table} (key, epoch, redeemed_at) VALUES (?, ?, unixepoch()) ON CONFLICT(key) DO NOTHING`,
  );
  return stmt.run(key, epoch).changes === 1;
}

export function redemptionSchema(table: string): string {
  return `CREATE TABLE IF NOT EXISTS ${table} (
    key TEXT PRIMARY KEY,
    epoch TEXT NOT NULL,
    redeemed_at INTEGER NOT NULL
  ) STRICT;`;
}

function isUniqueViolation(e: unknown): boolean {
  return (
    typeof e === "object" &&
    e !== null &&
    "code" in e &&
    typeof (e as { code: unknown }).code === "string" &&
    ((e as { code: string }).code === "SQLITE_CONSTRAINT_UNIQUE" ||
      (e as { code: string }).code === "SQLITE_CONSTRAINT_PRIMARYKEY")
  );
}

export { canonicalPath, witnessSharesStoreTree, writeDurableFile } from "./durable-file.js";
