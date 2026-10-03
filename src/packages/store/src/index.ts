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
}

export function openStore(schemaSql: string, options: StoreOptions = {}): Database.Database {
  const db = new Database(options.file ?? ":memory:");
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(schemaSql);
  return db;
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

export function withTransaction<T>(db: Database.Database, fn: () => T): T {
  const parent = commitFrames.get(db);
  if (db.inTransaction && !parent)
    throw new Error("withTransaction cannot nest in an unmanaged transaction");
  const frame: CommitFrame = { callbacks: [] };
  commitFrames.set(db, frame);
  let result: T;
  try {
    result = db.transaction(fn)();
  } catch (e) {
    if (isUniqueViolation(e)) {
      throw new UniqueViolationError((e as Error).message);
    }
    throw e;
  } finally {
    if (parent) commitFrames.set(db, parent);
    else commitFrames.delete(db);
  }
  if (parent) parent.callbacks.push(...frame.callbacks);
  else for (const callback of frame.callbacks) callback();
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
