/**
 * @spec control-plane#serialization — the derivation counter's reservation
 * ledger.
 *
 * The invariant names "counter checks/increments and artifact issuance" as one
 * atomic domain. A conditional counter UPDATE (see
 * `MissionKernel.gateDerivation`) prevents cap overshoot but says nothing about
 * whether the artifact the count paid for was ever issued, so the count and the
 * issuance are still two facts. This store makes the second fact durable and
 * gives the gap between them named recovery states.
 *
 * WHAT "UNRELEASED" MEANS. A reservation with no local acknowledgement is
 * AMBIGUOUS: the artifact may never have been minted, or it may have been
 * minted and accepted with the acknowledgement lost. Those two cases are not
 * distinguishable from inside this process, so an unreleased reservation is
 * NEVER refunded. Boot recovery moves it to `unacknowledged` and keeps the
 * count consumed; fail closed means the Mission spends the derivation.
 *
 * THE TWO WAYS OUT.
 *  - REPLAY. A caller that supplies a durable operation identity gets its
 *    recorded artifact identity and completion material back
 *    ({@link DerivationReservationStore.reserveInCallerTx} returns a `replay`),
 *    so a retried operation never reserves a second derivation.
 *  - RECONCILIATION. An AUTHORITATIVE observation of the issuance outcome
 *    settles an `unacknowledged` row
 *    ({@link DerivationReservationStore.reconcile}). Only an authoritative
 *    NON-acceptance returns the count, and it does so in the same transaction
 *    that records the reconciliation, so a refund is always attributable.
 *
 * WHAT THIS IS NOT. It is not proof that the counter and the artifact commit
 * together. The artifacts here are signed on an asynchronous path, and the
 * OAuth access token is minted by a provider outside this database, so the
 * reservation is a durable record of an issuance INTENT and its settlement, not
 * a cross-store transaction. Recording authoritative issuance state and the
 * artifact material transactionally BEFORE delivery is a possible architecture;
 * this store does not reach it, and does not claim it.
 */

import { randomBytes } from "node:crypto";
import { type Database, UniqueViolationError, withTransaction } from "@mission/store";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS derivation_reservations (
  reservation_id TEXT PRIMARY KEY,
  issuer TEXT NOT NULL,
  mission_id TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  state TEXT NOT NULL,
  artifact_id TEXT,
  completion_json TEXT,
  settled_by TEXT,
  reserved_at INTEGER NOT NULL,
  settled_at INTEGER,
  recovered_at INTEGER,
  expires_at INTEGER NOT NULL,
  UNIQUE (issuer, mission_id, operation_id)
) STRICT;
`;

/**
 * @spec control-plane#serialization, control-plane#tombstones — the reservation
 * ledger outlives the artifact it paid for: it is the record a retry replays
 * from and a reconciliation settles, so it is retained for the deployment's
 * published retry horizon, one day, the horizon creation idempotency already
 * uses.
 */
export const DEFAULT_DERIVATION_RESERVATION_TTL_S = 86400;

/**
 * `reserved` — counted, artifact not acknowledged, this process still running.
 * `released` — the artifact was accepted; the count is settled and correct.
 * `unacknowledged` — a `reserved` row found at boot. Ambiguous, never refunded,
 *   awaiting an authoritative reconciliation.
 * `refunded` — an authoritative observation established that no artifact was
 *   accepted; the count was returned, attributably.
 */
export type DerivationReservationState = "reserved" | "released" | "unacknowledged" | "refunded";

export interface DerivationReservation {
  reservationId: string;
  issuer: string;
  missionId: string;
  operationId: string;
  state: DerivationReservationState;
  artifactId?: string;
  completion?: string;
  settledBy?: string;
}

/** A fresh reservation, or the recorded outcome of one already made. */
export type DerivationReservationResult =
  | { kind: "reserved"; reservation: DerivationReservation }
  | { kind: "replay"; reservation: DerivationReservation };

export class DerivationReservationStore {
  private readonly retentionMs: number;

  constructor(
    private readonly db: Database,
    private readonly options: { now: () => Date; retentionSeconds?: number },
  ) {
    this.db.exec(SCHEMA);
    this.retentionMs = (options.retentionSeconds ?? DEFAULT_DERIVATION_RESERVATION_TTL_S) * 1000;
  }

  /**
   * Reserve one derivation against a DURABLE operation identity. NO OWN
   * TRANSACTION: the caller MUST run this inside the same `withTransaction` as
   * the conditional counter increment, so the count and its reservation commit
   * together or neither does.
   *
   * A repeat of the same `(issuer, mission_id, operation_id)` is a REPLAY: the
   * recorded row comes back and no second derivation is counted, whatever state
   * that row is in. An `unacknowledged` replay is deliberate: the operation was
   * counted once, and re-counting it would punish the Mission for a lost
   * acknowledgement.
   */
  reserveInCallerTx(input: {
    issuer: string;
    missionId: string;
    operationId: string;
    artifactId?: string;
  }): DerivationReservationResult {
    const existing = this.find(input.issuer, input.missionId, input.operationId);
    if (existing) return { kind: "replay", reservation: existing };
    const nowMs = this.options.now().getTime();
    const reservationId = `drv_${randomBytes(12).toString("base64url")}`;
    try {
      this.db
        .prepare(
          `INSERT INTO derivation_reservations (reservation_id, issuer, mission_id, operation_id,
           state, artifact_id, reserved_at, expires_at)
           VALUES (?, ?, ?, ?, 'reserved', ?, ?, ?)`,
        )
        .run(
          reservationId,
          input.issuer,
          input.missionId,
          input.operationId,
          input.artifactId ?? null,
          nowMs,
          nowMs + this.retentionMs,
        );
    } catch (e) {
      // A concurrent duplicate is decided by the datastore, never by the read
      // above: the loser re-reads the winning row and replays it.
      if (e instanceof UniqueViolationError) {
        const winner = this.find(input.issuer, input.missionId, input.operationId);
        if (winner) return { kind: "replay", reservation: winner };
      }
      throw e;
    }
    return {
      kind: "reserved",
      reservation: {
        reservationId,
        issuer: input.issuer,
        missionId: input.missionId,
        operationId: input.operationId,
        state: "reserved",
        ...(input.artifactId ? { artifactId: input.artifactId } : {}),
      },
    };
  }

  /**
   * The artifact was accepted: record its identity and enough completion
   * material for a replay to return the same outcome. Monotone against
   * `refunded` and `released`, so a late acknowledgement cannot un-refund a row
   * an authoritative observation already settled.
   */
  release(reservationId: string, accepted: { artifactId: string; completion?: string }): void {
    withTransaction(this.db, () => {
      this.db
        .prepare(
          `UPDATE derivation_reservations
           SET state = 'released', artifact_id = ?, completion_json = ?, settled_at = ?
           WHERE reservation_id = ? AND state IN ('reserved', 'unacknowledged')`,
        )
        .run(
          accepted.artifactId,
          accepted.completion ?? null,
          this.options.now().getTime(),
          reservationId,
        );
    });
  }

  /**
   * Boot recovery. Every `reserved` row this process left behind becomes
   * `unacknowledged` and KEEPS its count: absence of a local acknowledgement is
   * not evidence that no artifact was accepted. Returns the rows an operator or
   * an authoritative reconciliation still owes an answer for.
   */
  recoverAtBoot(): DerivationReservation[] {
    return withTransaction(this.db, () => {
      const nowMs = this.options.now().getTime();
      const pending = this.db
        .prepare("SELECT * FROM derivation_reservations WHERE state = 'reserved'")
        .all() as Array<Record<string, unknown>>;
      this.db
        .prepare(
          "UPDATE derivation_reservations SET state = 'unacknowledged', recovered_at = ? WHERE state = 'reserved'",
        )
        .run(nowMs);
      return pending.map((row) => ({ ...toReservation(row), state: "unacknowledged" as const }));
    });
  }

  /**
   * Settle an ambiguous reservation from an AUTHORITATIVE observation of the
   * issuance outcome. `accepted` records the artifact and leaves the count
   * spent; `!accepted` is the ONLY path that returns a counted derivation, and
   * it decrements the counter in the same transaction that records who said so.
   * The decrement is itself conditional, so it can never drive the count below
   * zero. Returns false when the row is already settled or unknown.
   */
  reconcile(
    reservationId: string,
    observation: { accepted: boolean; authority: string; artifactId?: string; completion?: string },
  ): boolean {
    return withTransaction(this.db, () => {
      const row = this.db
        .prepare("SELECT * FROM derivation_reservations WHERE reservation_id = ?")
        .get(reservationId) as Record<string, unknown> | undefined;
      if (!row) return false;
      if (row.state !== "reserved" && row.state !== "unacknowledged") return false;
      const nowMs = this.options.now().getTime();
      if (observation.accepted) {
        this.db
          .prepare(
            `UPDATE derivation_reservations
             SET state = 'released', artifact_id = COALESCE(?, artifact_id),
                 completion_json = COALESCE(?, completion_json), settled_by = ?, settled_at = ?
             WHERE reservation_id = ? AND state IN ('reserved', 'unacknowledged')`,
          )
          .run(
            observation.artifactId ?? null,
            observation.completion ?? null,
            observation.authority,
            nowMs,
            reservationId,
          );
        return true;
      }
      const refunded = this.db
        .prepare(
          `UPDATE derivation_reservations SET state = 'refunded', settled_by = ?, settled_at = ?
           WHERE reservation_id = ? AND state IN ('reserved', 'unacknowledged')`,
        )
        .run(observation.authority, nowMs, reservationId);
      if (refunded.changes !== 1) return false;
      this.db
        .prepare(
          "UPDATE missions SET derivation_count = derivation_count - 1 WHERE id = ? AND derivation_count > 0",
        )
        .run(row.mission_id as string);
      return true;
    });
  }

  /** The recorded reservation for one operation identity, if it is still retained. */
  find(issuer: string, missionId: string, operationId: string): DerivationReservation | undefined {
    const row = this.db
      .prepare(
        `SELECT * FROM derivation_reservations
         WHERE issuer = ? AND mission_id = ? AND operation_id = ?`,
      )
      .get(issuer, missionId, operationId) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    if (this.options.now().getTime() > (row.expires_at as number)) return undefined;
    return toReservation(row);
  }

  /** One reservation by its own identifier. */
  get(reservationId: string): DerivationReservation | undefined {
    const row = this.db
      .prepare("SELECT * FROM derivation_reservations WHERE reservation_id = ?")
      .get(reservationId) as Record<string, unknown> | undefined;
    return row ? toReservation(row) : undefined;
  }

  /** Every reservation still awaiting an authoritative answer. */
  unacknowledged(): DerivationReservation[] {
    const rows = this.db
      .prepare(
        "SELECT * FROM derivation_reservations WHERE state = 'unacknowledged' ORDER BY reserved_at",
      )
      .all() as Array<Record<string, unknown>>;
    return rows.map(toReservation);
  }
}

function toReservation(row: Record<string, unknown>): DerivationReservation {
  return {
    reservationId: row.reservation_id as string,
    issuer: row.issuer as string,
    missionId: row.mission_id as string,
    operationId: row.operation_id as string,
    state: row.state as DerivationReservationState,
    ...(row.artifact_id ? { artifactId: row.artifact_id as string } : {}),
    ...(row.completion_json ? { completion: row.completion_json as string } : {}),
    ...(row.settled_by ? { settledBy: row.settled_by as string } : {}),
  };
}
