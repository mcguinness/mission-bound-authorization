/**
 * @spec runtime#idempotency, runtime#permit-binding (#918, D223): the
 * enforcing PEP's reservation and retention store for reversible writes that
 * elect the "short validity window combined with an idempotency key" control.
 *
 * "The PDP makes no claim for a reversible consequential write's
 * idempotency-key control ... The enforcing PEP or the resource MUST instead
 * atomically reserve the (idempotency scope, `idempotency_key`) pair against
 * a concurrent duplicate, and MUST retain the reserved-or-completed record
 * for at least the retention posture the deployment publishes". This store is
 * that domain: one durable, single-writer SQLite file named in configuration
 * (`topology.json` `stores.pepWriteReservations.file`), owned by this PEP. It
 * shares no file, table or transaction with the PDP's claim domain (#917),
 * with D28 redemption (`transaction.ts`) or with the payments store.
 *
 * The reversible effect itself, a payment schedule, lives in the same file,
 * so the effect and its completed reservation and result commit in ONE local
 * transaction: a reservation row exists exactly when its effect does, and an
 * uncertain outcome resolves by reading the row, never by executing again.
 * A schedule moves no money and calls no connector; nothing reads it to pay.
 */

import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalIdempotencyScope, type IdempotencyScope } from "@mission/core";
import { type Database, openDurableStore, withTransaction } from "@mission/store";

/**
 * Schema version 1. A `completed` row carries its result and its retention
 * bound; a `reserved` row is a reservation whose effect is not known to have
 * committed (a two-phase, non-local effect), which no tool here produces and
 * which time never purges.
 */
const MIGRATIONS: readonly string[] = [
  `
CREATE TABLE write_reservations (
  scope_digest TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  scope_json TEXT NOT NULL,
  action TEXT NOT NULL,
  operation_identity TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('reserved', 'completed')),
  result_json TEXT,
  evaluation_id TEXT NOT NULL,
  execution_id TEXT NOT NULL,
  completed_at_ms INTEGER,
  retain_until_ms INTEGER,
  PRIMARY KEY (scope_digest, idempotency_key),
  CHECK (state = 'reserved' OR (result_json IS NOT NULL AND completed_at_ms IS NOT NULL AND retain_until_ms IS NOT NULL))
) STRICT;
CREATE TABLE payment_schedules (
  schedule_id TEXT PRIMARY KEY,
  mission_issuer TEXT NOT NULL,
  mission_id TEXT NOT NULL,
  subject TEXT NOT NULL,
  invoice_id TEXT NOT NULL,
  invoice_version INTEGER NOT NULL,
  vendor_id TEXT NOT NULL,
  amount TEXT NOT NULL,
  currency TEXT NOT NULL,
  payee_account TEXT NOT NULL,
  parameter_digest TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('scheduled', 'cancelled')),
  created_evaluation_id TEXT NOT NULL,
  cancelled_evaluation_id TEXT,
  created_at_ms INTEGER NOT NULL,
  cancelled_at_ms INTEGER
) STRICT;
CREATE UNIQUE INDEX one_active ON payment_schedules (mission_issuer, mission_id, invoice_id) WHERE state = 'scheduled';
`,
];

export type WriteReservationState = "reserved" | "completed";

/** One retained record of a (scope, key) pair. */
export interface WriteReservation {
  scopeDigest: string;
  idempotencyKey: string;
  action: string;
  /** AuthZEN's operation identity of the request the key was first used for. */
  operationIdentity: string;
  state: WriteReservationState;
  /** The original response, retained verbatim; absent on a `reserved` row. */
  result?: unknown;
  evaluationId: string;
  executionId: string;
  completedAtMs?: number;
  retainUntilMs?: number;
}

/** What a reservation is taken under: the pair, the operation it names, and the attempt taking it. */
export interface WriteReservationRequest {
  scope: IdempotencyScope;
  scopeDigest: string;
  idempotencyKey: string;
  action: string;
  operationIdentity: string;
  evaluationId: string;
  executionId: string;
  /** The published retention for this operation, in milliseconds. */
  retentionMs: number;
}

/**
 * A reversible effect's own outcome, decided inside the reservation's
 * transaction. A refusal changed nothing, so it records no reservation.
 */
export type WriteEffectOutcome = { ok: true; result: unknown } | { ok: false; refusal: string };

export type ReserveOutcome =
  /** This attempt won the pair: the effect and its completed reservation committed together. */
  | { kind: "executed"; result: unknown }
  /** The pair was already held, by an earlier attempt or a concurrent winner: no effect. */
  | { kind: "existing"; reservation: WriteReservation }
  /** The effect refused (no such schedule, one already active): nothing committed. */
  | { kind: "refused"; refusal: string };

export interface PaymentSchedule {
  schedule_id: string;
  mission_issuer: string;
  mission_id: string;
  subject: string;
  invoice_id: string;
  invoice_version: number;
  vendor_id: string;
  amount: string;
  currency: string;
  payee_account: string;
  parameter_digest: string;
  state: "scheduled" | "cancelled";
  created_evaluation_id: string;
  cancelled_evaluation_id: string | null;
  created_at_ms: number;
  cancelled_at_ms: number | null;
}

interface ReservationRow {
  scope_digest: string;
  idempotency_key: string;
  action: string;
  operation_identity: string;
  state: WriteReservationState;
  result_json: string | null;
  evaluation_id: string;
  execution_id: string;
  completed_at_ms: number | null;
  retain_until_ms: number | null;
}

function fromRow(row: ReservationRow): WriteReservation {
  return {
    scopeDigest: row.scope_digest,
    idempotencyKey: row.idempotency_key,
    action: row.action,
    operationIdentity: row.operation_identity,
    state: row.state,
    ...(row.result_json !== null ? { result: JSON.parse(row.result_json) as unknown } : {}),
    evaluationId: row.evaluation_id,
    executionId: row.execution_id,
    ...(row.completed_at_ms !== null ? { completedAtMs: row.completed_at_ms } : {}),
    ...(row.retain_until_ms !== null ? { retainUntilMs: row.retain_until_ms } : {}),
  };
}

export interface WriteReservationStoreOptions {
  /** The durable file, from configuration (`topology.json` `stores.pepWriteReservations.file`). */
  file: string | undefined;
  /** The PEP location that owns the store, the statement's `reservation_owner`. */
  owner: string;
  now?: () => Date;
}

/**
 * Open the store. Every refusal is fatal and is `openDurableStore`'s: an
 * absent, empty or in-memory file, a file another handle or process holds, a
 * newer schema, or a file recorded for another owner.
 */
export function openWriteReservationStore(options: WriteReservationStoreOptions): WriteReservationStore {
  const db = openDurableStore({ file: options.file, migrations: MIGRATIONS, owner: options.owner });
  return new WriteReservationStore(db, options.owner, options.now ?? (() => new Date()));
}

/**
 * A store on a fresh file in a new temporary directory, for a demo, eval or
 * test process with no configured store of its own: the same durable,
 * single-writer store on a real file, never `:memory:`. A deployment
 * configures its own file and never this.
 */
export function openEphemeralWriteReservationStore(
  options: Omit<WriteReservationStoreOptions, "file"> & { directory?: string },
): WriteReservationStore {
  const directory = mkdtempSync(join(options.directory ?? tmpdir(), "pep-write-reservations-"));
  return openWriteReservationStore({ ...options, file: join(directory, "write-reservations.sqlite") });
}

export class WriteReservationStore {
  constructor(
    readonly db: Database,
    readonly owner: string,
    private readonly now: () => Date,
  ) {}

  /**
   * Retrieval's read: the retained record of a pair, read-only. A completed
   * record past its retention is outside the guarantee and reads as absent;
   * a `reserved` record never expires by time.
   */
  lookup(scopeDigest: string, idempotencyKey: string): WriteReservation | undefined {
    const row = this.db
      .prepare(
        `SELECT * FROM write_reservations WHERE scope_digest = ? AND idempotency_key = ?
           AND (state = 'reserved' OR retain_until_ms >= ?)`,
      )
      .get(scopeDigest, idempotencyKey, this.now().getTime()) as ReservationRow | undefined;
    return row ? fromRow(row) : undefined;
  }

  /**
   * Reserve, effect and completion in one local transaction with no await
   * inside it. The in-transaction re-read is authoritative: of concurrent
   * attempts that all found the pair free at lookup, exactly one runs the
   * effect, and the rest read its completed record. `inside` is a failpoint
   * for tests: a throw from it rolls the effect and the reservation back
   * together.
   */
  reserve(
    request: WriteReservationRequest,
    effect: (nowMs: number) => WriteEffectOutcome,
    failpoints: { inside?: () => void } = {},
  ): ReserveOutcome {
    return withTransaction(this.db, (): ReserveOutcome => {
      const nowMs = this.now().getTime();
      // A completed record past its retention is outside the guarantee: the
      // key is new again, so its row gives way to this attempt's.
      this.db
        .prepare(
          `DELETE FROM write_reservations WHERE scope_digest = ? AND idempotency_key = ?
             AND state = 'completed' AND retain_until_ms < ?`,
        )
        .run(request.scopeDigest, request.idempotencyKey, nowMs);
      const prior = this.db
        .prepare("SELECT * FROM write_reservations WHERE scope_digest = ? AND idempotency_key = ?")
        .get(request.scopeDigest, request.idempotencyKey) as ReservationRow | undefined;
      if (prior) return { kind: "existing", reservation: fromRow(prior) };
      const outcome = effect(nowMs);
      if (!outcome.ok) return { kind: "refused", refusal: outcome.refusal };
      this.db
        .prepare(
          `INSERT INTO write_reservations (scope_digest, idempotency_key, scope_json, action, operation_identity,
             state, result_json, evaluation_id, execution_id, completed_at_ms, retain_until_ms)
           VALUES (?, ?, ?, ?, ?, 'completed', ?, ?, ?, ?, ?)`,
        )
        .run(
          request.scopeDigest,
          request.idempotencyKey,
          JSON.stringify(canonicalIdempotencyScope(request.scope)),
          request.action,
          request.operationIdentity,
          JSON.stringify(outcome.result),
          request.evaluationId,
          request.executionId,
          nowMs,
          nowMs + request.retentionMs,
        );
      failpoints.inside?.();
      return { kind: "executed", result: outcome.result };
    });
  }

  /**
   * The schedule effect, run inside {@link reserve}'s transaction: one
   * `scheduled` row for this Mission and invoice. An invoice the Mission
   * already holds an active schedule for refuses `schedule_exists` with no
   * change: a different key is a different intended execution, and it never
   * rewrites a schedule another execution created.
   */
  insertSchedule(input: {
    mission: { id: string; issuer: string };
    subject: string;
    invoice: { id: string; version: number; vendor_id: string; payee_account: string };
    amount: { amount: string; currency: string };
    parameterDigest: string;
    evaluationId: string;
    nowMs: number;
  }): WriteEffectOutcome {
    const active = this.activeSchedule(input.mission, input.invoice.id);
    if (active) return { ok: false, refusal: "schedule_exists" };
    const scheduleId = `sch_${randomUUID()}`;
    this.db
      .prepare(
        `INSERT INTO payment_schedules (schedule_id, mission_issuer, mission_id, subject, invoice_id, invoice_version,
           vendor_id, amount, currency, payee_account, parameter_digest, state, created_evaluation_id, created_at_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'scheduled', ?, ?)`,
      )
      .run(
        scheduleId,
        input.mission.issuer,
        input.mission.id,
        input.subject,
        input.invoice.id,
        input.invoice.version,
        input.invoice.vendor_id,
        input.amount.amount,
        input.amount.currency,
        input.invoice.payee_account,
        input.parameterDigest,
        input.evaluationId,
        input.nowMs,
      );
    return {
      ok: true,
      result: { scheduled: true, schedule_id: scheduleId, invoice_id: input.invoice.id, amount: input.amount },
    };
  }

  /**
   * The cancel effect, run inside {@link reserve}'s transaction: the calling
   * Mission's active schedule for the invoice moves to `cancelled` and stays
   * for audit. A schedule another Mission holds, or none at all, refuses
   * `schedule_not_found` with no change.
   */
  cancelActiveSchedule(input: {
    mission: { id: string; issuer: string };
    invoiceId: string;
    evaluationId: string;
    nowMs: number;
  }): WriteEffectOutcome {
    const active = this.activeSchedule(input.mission, input.invoiceId);
    if (!active) return { ok: false, refusal: "schedule_not_found" };
    this.db
      .prepare(
        `UPDATE payment_schedules SET state = 'cancelled', cancelled_evaluation_id = ?, cancelled_at_ms = ?
         WHERE schedule_id = ? AND state = 'scheduled'`,
      )
      .run(input.evaluationId, input.nowMs, active.schedule_id);
    return { ok: true, result: { cancelled: true, schedule_id: active.schedule_id, invoice_id: input.invoiceId } };
  }

  private activeSchedule(mission: { id: string; issuer: string }, invoiceId: string): PaymentSchedule | undefined {
    return this.db
      .prepare(
        `SELECT * FROM payment_schedules WHERE mission_issuer = ? AND mission_id = ? AND invoice_id = ?
           AND state = 'scheduled'`,
      )
      .get(mission.issuer, mission.id, invoiceId) as PaymentSchedule | undefined;
  }

  /** Every schedule, active and cancelled, oldest first. */
  schedules(): PaymentSchedule[] {
    return this.db.prepare("SELECT * FROM payment_schedules ORDER BY created_at_ms, rowid").all() as PaymentSchedule[];
  }

  /** Every retained reservation. */
  reservations(): WriteReservation[] {
    return (this.db.prepare("SELECT * FROM write_reservations ORDER BY rowid").all() as ReservationRow[]).map(fromRow);
  }

  /**
   * Purge every completed record past its retention. A `reserved` record is
   * never purged by time: only reconciliation resolves it.
   */
  sweep(): number {
    return this.db
      .prepare("DELETE FROM write_reservations WHERE state = 'completed' AND retain_until_ms < ?")
      .run(this.now().getTime()).changes;
  }

  close(): void {
    this.db.close();
  }
}
