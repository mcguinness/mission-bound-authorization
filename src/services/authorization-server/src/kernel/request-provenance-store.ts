/**
 * @spec request-provenance#replay (#939 slice 2a-2, D1119 Q1, Q2 and Q5)
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
 * Only an in-memory implementation exists. It suits explicitly ephemeral
 * demonstrations: a restart forgets every pair, so an unexpired assertion
 * is accepted again and an accepted submission loses its acceptance record
 * (D1119 Q5, #1963). The authorization server therefore refuses to enable
 * the type on a file-backed kernel store.
 */

import type { JsonValue } from "@mission/core";
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
