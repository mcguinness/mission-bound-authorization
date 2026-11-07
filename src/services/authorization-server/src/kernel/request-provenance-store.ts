/**
 * @spec request-provenance#replay (#939 slice 2a-2, D1119 Q1, Q2 and Q5, #1963)
 *
 * The replay store of the `mission-request-provenance` evidence type: the
 * (`iss`, `jti`) pairs verification step 10 reserves, each with the
 * acceptance record a later step of the accepted submission relies on.
 *
 * - **Reserve** inserts the pair and its complete record only if no other
 *   submission holds it, reserved or committed, in one synchronous step with
 *   no await between the check and the insert: of concurrent submissions,
 *   exactly one reserves.
 * - **Commit** flips a reservation to committed and binds it to the accepted
 *   submission's reference.
 * - **Release** removes a reservation, idempotently. Nothing releases a
 *   committed pair: the store releases only a reservation, and the
 *   admission scope that owns it releases nothing once committed
 *   (`SubmissionAdmission`).
 *
 * A reservation never outlives `exp` plus the clock-skew allowance. A
 * committed pair is retained until the later of that instant and the end of
 * the accepted submission's pending operation, since the steps that rely on
 * its acceptance record run after `exp` (D1119 Q2).
 *
 * Two implementations. {@link SqliteRequestProvenanceStore} keeps the pairs
 * and their records on the kernel's database, so they are as durable as the
 * kernel: in memory without a kernel file, and kept across a restart with
 * one (D1119 Q5, #1963). It is the authorization server's store.
 * {@link InMemoryRequestProvenanceStore} suits explicitly ephemeral
 * demonstrations and unit tests only: a restart forgets every pair, so an
 * unexpired assertion is accepted again and an accepted submission loses its
 * acceptance record. The authorization server refuses a supplied store
 * beside a file-backed kernel store, since only the kernel's own database
 * survives a restart with the kernel.
 */

import { randomBytes } from "node:crypto";
import type { JsonValue } from "@mission/core";
import { type Database, withTransaction } from "@mission/store";
import type { IntentSubmissionPresenter } from "./intent.js";

/** What step 10 reserves: the pair and the acceptance record a later step relies on. */
export interface RequestProvenanceRecord {
  iss: string;
  jti: string;
  /** `exp` plus the clock-skew allowance, in epoch milliseconds. */
  expiresAtMs: number;
  /** This AS's issuer identifier, the intended AS. */
  issuer: string;
  /** The provisional `intent_hash` of the exact Intent the submission carried. */
  intentHash: string;
  /** The presenter the containing exchange established. */
  presenter: IntentSubmissionPresenter;
  /** The assertion exactly as presented. */
  assertion: string;
  /**
   * The evidence entry's `artifact_hash` as the dispatch stamps it. Kept with
   * the record; a later step's entry has the same one exactly when its
   * assertion bytes and the issuer match, which the resume compares.
   */
  artifactHash: string;
  /** The original verification's time (ISO 8601). */
  verifiedAt: string;
  /** The recorded facts (@spec request-provenance#recorded-facts). */
  facts: Record<string, JsonValue>;
}

/** A committed pair: its record, and the accepted submission it belongs to. */
export interface RequestProvenanceAcceptance extends RequestProvenanceRecord {
  /** The carrier's reference for the accepted submission (`par:<jti>`). */
  submissionRef: string;
}

export interface RequestProvenanceStore {
  /**
   * Reserve (`iss`, `jti`) with its record, atomically: resolves to a
   * reservation token, or undefined when another submission has reserved or
   * committed the pair. Pairs past their retention are swept first.
   */
  reserve(record: RequestProvenanceRecord, nowMs: number): Promise<string | undefined>;
  /**
   * Whether the reservation `token` can still commit at `nowMs`: it is held
   * and has not lapsed. Changes nothing; the admission scope asks every hold
   * before it commits any (all or nothing).
   */
  committable(token: string, nowMs: number): boolean;
  /**
   * Commit the reservation `token` for the accepted submission `ref`,
   * retained at least until `retainUntilMs`. False when the reservation is
   * gone at `nowMs` (it lapsed, or was released).
   */
  commit(token: string, ref: string, nowMs: number, retainUntilMs: number): boolean;
  /** Release the reservation `token`. Idempotent; no effect on another token, nor on a committed pair. */
  release(token: string): void;
  /** The committed acceptance of (`iss`, `jti`) while it is retained, else undefined. */
  accepted(iss: string, jti: string, nowMs: number): RequestProvenanceAcceptance | undefined;
}

interface Row {
  token: string;
  state: "reserved" | "committed";
  record: RequestProvenanceRecord;
  submissionRef?: string;
  /** Committed only: the end of the accepted submission's pending operation (epoch ms). */
  retainUntilMs?: number;
}

/** The pair's key: `iss` and `jti` joined by a separator neither can carry ambiguously. */
const pairKey = (iss: string, jti: string): string => JSON.stringify([iss, jti]);

/**
 * The in-memory replay store: explicitly ephemeral (D1119 Q5). Every method
 * is synchronous inside; `reserve` checks and inserts with no await between.
 */
export class InMemoryRequestProvenanceStore implements RequestProvenanceStore {
  readonly #rows = new Map<string, Row>();
  #tokens = 0;

  /** When a row stops holding its pair. */
  static #lapsesAt(row: Row): number {
    return row.state === "committed"
      ? Math.max(row.record.expiresAtMs, row.retainUntilMs ?? 0)
      : row.record.expiresAtMs;
  }

  #sweep(nowMs: number): void {
    for (const [key, row] of this.#rows) {
      if (InMemoryRequestProvenanceStore.#lapsesAt(row) <= nowMs) this.#rows.delete(key);
    }
  }

  async reserve(record: RequestProvenanceRecord, nowMs: number): Promise<string | undefined> {
    this.#sweep(nowMs);
    const key = pairKey(record.iss, record.jti);
    if (this.#rows.has(key)) return undefined;
    this.#tokens += 1;
    const token = `rpr-${this.#tokens}`;
    this.#rows.set(key, { token, state: "reserved", record: structuredClone(record) });
    return token;
  }

  #byToken(token: string): [string, Row] | undefined {
    for (const entry of this.#rows) if (entry[1].token === token) return entry;
    return undefined;
  }

  committable(token: string, nowMs: number): boolean {
    const found = this.#byToken(token);
    return (
      found !== undefined &&
      found[1].state === "reserved" &&
      InMemoryRequestProvenanceStore.#lapsesAt(found[1]) > nowMs
    );
  }

  commit(token: string, ref: string, nowMs: number, retainUntilMs: number): boolean {
    const found = this.#byToken(token);
    if (found === undefined) return false;
    const [, row] = found;
    if (row.state === "committed") return row.submissionRef === ref;
    if (InMemoryRequestProvenanceStore.#lapsesAt(row) <= nowMs) return false;
    row.state = "committed";
    row.submissionRef = ref;
    row.retainUntilMs = retainUntilMs;
    return true;
  }

  release(token: string): void {
    const found = this.#byToken(token);
    // Only a reservation: a committed pair keeps its acceptance record until its retention ends.
    if (found !== undefined && found[1].state === "reserved") this.#rows.delete(found[0]);
  }

  accepted(iss: string, jti: string, nowMs: number): RequestProvenanceAcceptance | undefined {
    const row = this.#rows.get(pairKey(iss, jti));
    if (row === undefined || row.state !== "committed" || row.submissionRef === undefined) return undefined;
    if (InMemoryRequestProvenanceStore.#lapsesAt(row) <= nowMs) return undefined;
    return { ...structuredClone(row.record), submissionRef: row.submissionRef };
  }
}

/**
 * One row per held pair. `UNIQUE (iss, jti)` is what makes a reservation
 * atomic: the reserving `INSERT` is one statement, and a pair another
 * submission holds conflicts in the database itself. `record_json` is the
 * acceptance record exactly as reserved; a committed row adds the accepted
 * submission's reference and the end of its retention.
 */
const SCHEMA = `
CREATE TABLE IF NOT EXISTS request_provenance_pairs (
  iss TEXT NOT NULL,
  jti TEXT NOT NULL,
  token TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL CHECK (state IN ('reserved', 'committed')),
  record_json TEXT NOT NULL,
  submission_ref TEXT,
  expires_at_ms INTEGER NOT NULL,
  retain_until_ms INTEGER,
  UNIQUE (iss, jti),
  CHECK ((state = 'committed') = (submission_ref IS NOT NULL AND retain_until_ms IS NOT NULL))
) STRICT;
`;

/** When a row stops holding its pair: a reservation at `exp` plus skew, a committed pair at the later of that and its retention. */
const LAPSES_AT = "(CASE WHEN state = 'committed' THEN MAX(expires_at_ms, retain_until_ms) ELSE expires_at_ms END)";

interface SqliteRow {
  state: "reserved" | "committed";
  record_json: string;
  submission_ref: string | null;
  expires_at_ms: number;
  retain_until_ms: number | null;
}

/**
 * The replay store on a SQLite database: the authorization server's own, on
 * its kernel's database (`kernel.db`), so it is as durable as the kernel. A
 * file-backed kernel runs WAL with `synchronous=FULL`, and under a recovery
 * witness every write here commits through the kernel's guarded
 * transactions, so a reservation, a commit and a release each survive a
 * restart once they return. Every method is synchronous inside; `reserve`
 * sweeps and inserts with no await between.
 *
 * A reservation whose process ended before it committed or released holds
 * its pair until `exp` plus the clock-skew allowance, as any uncommitted
 * reservation does, and then lapses: nothing at open releases it.
 */
export class SqliteRequestProvenanceStore implements RequestProvenanceStore {
  readonly db: Database;
  readonly #sweep;
  readonly #insert;
  readonly #byToken;
  readonly #commit;
  readonly #release;
  readonly #byPair;

  constructor(db: Database) {
    this.db = db;
    db.exec(SCHEMA);
    this.#sweep = db.prepare(`DELETE FROM request_provenance_pairs WHERE ${LAPSES_AT} <= ?`);
    this.#insert = db.prepare(
      `INSERT INTO request_provenance_pairs (iss, jti, token, state, record_json, expires_at_ms)
       VALUES (?, ?, ?, 'reserved', ?, ?)
       ON CONFLICT (iss, jti) DO NOTHING`,
    );
    this.#byToken = db.prepare(
      "SELECT state, record_json, submission_ref, expires_at_ms, retain_until_ms FROM request_provenance_pairs WHERE token = ?",
    );
    this.#commit = db.prepare(
      `UPDATE request_provenance_pairs SET state = 'committed', submission_ref = ?, retain_until_ms = ?
       WHERE token = ? AND state = 'reserved' AND expires_at_ms > ?`,
    );
    this.#release = db.prepare("DELETE FROM request_provenance_pairs WHERE token = ? AND state = 'reserved'");
    this.#byPair = db.prepare(
      "SELECT state, record_json, submission_ref, expires_at_ms, retain_until_ms FROM request_provenance_pairs WHERE iss = ? AND jti = ?",
    );
  }

  static #lapsesAt(row: SqliteRow): number {
    return row.state === "committed" ? Math.max(row.expires_at_ms, row.retain_until_ms ?? 0) : row.expires_at_ms;
  }

  async reserve(record: RequestProvenanceRecord, nowMs: number): Promise<string | undefined> {
    const token = `rpr_${randomBytes(18).toString("base64url")}`;
    const json = JSON.stringify(record);
    const inserted = withTransaction(this.db, () => {
      this.#sweep.run(nowMs);
      // One statement: a pair another submission holds conflicts here.
      return this.#insert.run(record.iss, record.jti, token, json, record.expiresAtMs).changes === 1;
    });
    return inserted ? token : undefined;
  }

  committable(token: string, nowMs: number): boolean {
    const row = this.#byToken.get(token) as SqliteRow | undefined;
    return row !== undefined && row.state === "reserved" && row.expires_at_ms > nowMs;
  }

  commit(token: string, ref: string, nowMs: number, retainUntilMs: number): boolean {
    if (this.#commit.run(ref, retainUntilMs, token, nowMs).changes === 1) return true;
    const row = this.#byToken.get(token) as SqliteRow | undefined;
    // Committed already: true only for the same accepted submission.
    return row !== undefined && row.state === "committed" && row.submission_ref === ref;
  }

  release(token: string): void {
    // Only a reservation: a committed pair keeps its acceptance record until its retention ends.
    this.#release.run(token);
  }

  accepted(iss: string, jti: string, nowMs: number): RequestProvenanceAcceptance | undefined {
    const row = this.#byPair.get(iss, jti) as SqliteRow | undefined;
    if (row === undefined || row.state !== "committed" || row.submission_ref === null) return undefined;
    if (SqliteRequestProvenanceStore.#lapsesAt(row) <= nowMs) return undefined;
    return { ...(JSON.parse(row.record_json) as RequestProvenanceRecord), submissionRef: row.submission_ref };
  }
}
