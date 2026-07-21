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
export function withTransaction<T>(db: Database.Database, fn: () => T): T {
  const tx = db.transaction(fn);
  try {
    return tx();
  } catch (e) {
    if (isUniqueViolation(e)) {
      throw new UniqueViolationError((e as Error).message);
    }
    throw e;
  }
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
