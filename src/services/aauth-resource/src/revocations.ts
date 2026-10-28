import { type Database, openDurableStore } from "@mission/store";

/** One revocation the Resource holds: `(iss, jti)` revoked until `exp`. */
export interface RevocationEntry {
  /** The verified identity of the PS that revoked the token. */
  iss: string;
  jti: string;
  /** Seconds since the epoch: the revoked token's own `exp`, as the revocation named it. */
  exp: number;
  /** Seconds since the epoch. */
  recordedAt: number;
}

/**
 * The outcome of admitting a revocation: recorded now, already held (a
 * repeat records nothing new), or refused because the issuer holds its
 * bound of entries, with the time the earliest of them lapses.
 */
export type AdmitOutcome =
  | { kind: "recorded" }
  | { kind: "repeat" }
  | { kind: "full"; retryAfterSeconds: number };

/**
 * The Resource's revoked set, keyed by `(iss, jti)` where `iss` is the
 * verified identity of the caller (aauth#section-11.12.1). An entry
 * applies while the current time is before its `exp`, and may be
 * discarded after. A read or write that cannot complete throws, and the
 * Resource then fails closed.
 */
export interface RevocationStore {
  /**
   * Admit one revocation atomically: a repeat of a held `(iss, jti)`
   * records nothing new and keeps the first `exp`; otherwise the entry is
   * recorded unless `iss` already holds `maxEntries` unexpired entries.
   *
   * @spec aauth#section-11.12.3
   */
  admit(entry: RevocationEntry, nowMs: number, maxEntries: number): AdmitOutcome;
  /** True while `(iss, jti)` is held with an `exp` later than now. */
  isRevoked(iss: string, jti: string, nowMs: number): boolean;
  /** Discard every entry whose `exp` has passed; returns how many. */
  purge(nowMs: number): number;
  /** Every entry held, oldest first. */
  entries(): RevocationEntry[];
  close(): void;
}

const MIGRATIONS = [
  `CREATE TABLE revocations (
     iss TEXT NOT NULL,
     jti TEXT NOT NULL,
     exp INTEGER NOT NULL,
     recorded_at INTEGER NOT NULL,
     PRIMARY KEY (iss, jti)
   ) STRICT;
   CREATE INDEX revocations_by_exp ON revocations (exp);
   CREATE INDEX revocations_by_issuer ON revocations (iss, exp);`,
];

interface Row {
  iss: string;
  jti: string;
  exp: number;
  recorded_at: number;
}

/**
 * An entry applies while `now < exp`: a token is refused as expired once
 * `exp <= now` (no tolerance), so from then on the entry decides nothing.
 */
const liveAfter = (nowMs: number) => Math.floor(nowMs / 1000);

/**
 * Durable SQLite through `@mission/store`'s `openDurableStore`: single
 * writer, WAL with `synchronous=FULL`, the file named by the caller and
 * never defaulted. A revocation is committed before the Resource answers
 * 200, so an acknowledged revocation survives a restart.
 */
export class SqliteRevocationStore implements RevocationStore {
  private readonly db: Database;

  constructor(file: string) {
    this.db = openDurableStore({ file, migrations: MIGRATIONS, owner: "aauth-resource" });
  }

  admit(entry: RevocationEntry, nowMs: number, maxEntries: number): AdmitOutcome {
    return this.db
      .transaction((): AdmitOutcome => {
        const held = this.db
          .prepare("SELECT 1 FROM revocations WHERE iss = ? AND jti = ?")
          .get(entry.iss, entry.jti);
        if (held) return { kind: "repeat" };
        const live = this.db
          .prepare(
            "SELECT COUNT(*) AS n, MIN(exp) AS first FROM revocations WHERE iss = ? AND exp > ?",
          )
          .get(entry.iss, liveAfter(nowMs)) as { n: number; first: number | null };
        if (live.n >= maxEntries) {
          const first = live.first ?? liveAfter(nowMs) + 1;
          return { kind: "full", retryAfterSeconds: Math.max(1, first - liveAfter(nowMs)) };
        }
        this.db
          .prepare("INSERT INTO revocations (iss, jti, exp, recorded_at) VALUES (?, ?, ?, ?)")
          .run(entry.iss, entry.jti, entry.exp, entry.recordedAt);
        return { kind: "recorded" };
      })
      .immediate();
  }

  isRevoked(iss: string, jti: string, nowMs: number): boolean {
    const row = this.db
      .prepare("SELECT 1 FROM revocations WHERE iss = ? AND jti = ? AND exp > ?")
      .get(iss, jti, liveAfter(nowMs));
    return row !== undefined;
  }

  purge(nowMs: number): number {
    return this.db.prepare("DELETE FROM revocations WHERE exp <= ?").run(liveAfter(nowMs)).changes;
  }

  entries(): RevocationEntry[] {
    const rows = this.db
      .prepare("SELECT * FROM revocations ORDER BY recorded_at, rowid")
      .all() as Row[];
    return rows.map((r) => ({ iss: r.iss, jti: r.jti, exp: r.exp, recordedAt: r.recorded_at }));
  }

  close(): void {
    this.db.close();
  }
}
