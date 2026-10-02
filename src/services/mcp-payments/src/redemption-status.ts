/**
 * @spec runtime#idempotency, retransmission condition 6 (#917, owner ruling
 * 2026-10-02): the PEP's read-only answers, from its D28 redemption store,
 * about one `evaluation_id`: was it consumed, and which attempt consumed it.
 *
 * Redemption stays here and `transaction.ts` is unchanged: `status` only
 * reads the operation rows `TransactionEngine.redeemPermit` already writes.
 * The answer is scoped to an epoch, the lifetime of this one in-memory store.
 * Within its own epoch the store holds every redemption that epoch could make,
 * so an identifier with no row was not consumed there: `unconsumed`. For any
 * other epoch (a restarted PEP, another replica) the store cannot speak:
 * `unknown`, which the PDP treats as suppress. The PDP asks only for a
 * retransmission candidate and never caches the answer.
 *
 * #1016 review round 2: the operation row records the permit a redemption
 * consumed, not the attempt that consumed it, and a failed or suppressed
 * outcome proves no effect only for that attempt. {@link recordRedeemingAttempt}
 * is the one seam that records it: a row beside the operation rows, in the
 * same store, written by the executing path in the same synchronous step that
 * took the single use. `redeemer` answers from that row joined to the
 * operation row, never from an evidence record's own members.
 */

import { randomUUID } from "node:crypto";
import type { ConsumptionStatus } from "@mission/pdp";
import type { TransactionEngine } from "./transaction.js";

const REDEEMERS_SCHEMA = `CREATE TABLE IF NOT EXISTS permit_redeemers (
  permit_id TEXT PRIMARY KEY,
  execution_id TEXT NOT NULL,
  epoch TEXT NOT NULL
) STRICT`;

export interface RedemptionStatus {
  /**
   * This store's epoch, sent as the requester's `pep_epoch` on every decision
   * request. Fresh per provider, so it names exactly one store lifetime even
   * where the engine's configured instance epoch is a fixed label.
   */
  readonly epoch: string;
  /** `consumed`, `unconsumed`, or `unknown` for another epoch. Read-only. */
  status(evaluationId: string, pepEpoch: string): ConsumptionStatus;
  /**
   * The `execution_id` of the attempt that redeemed this `evaluation_id`, or
   * `undefined` when this store records none (never redeemed, the linkage was
   * lost, or another epoch). Read-only.
   */
  redeemer(evaluationId: string, pepEpoch: string): string | undefined;
}

/**
 * Record that `executionId` took the single use of `permitId`. Called by the
 * executing path immediately after `redeemPermit` succeeds, with no await in
 * between, so no other attempt can be recorded for the permit first. A
 * process lost between the two leaves no link, so no failed or suppressed
 * outcome can settle that permit: it resolves from the ledger or closes
 * indeterminate.
 */
export function recordRedeemingAttempt(engine: TransactionEngine, permitId: string, executionId: string): void {
  engine.db.exec(REDEEMERS_SCHEMA);
  engine.db
    .prepare("INSERT INTO permit_redeemers (permit_id, execution_id, epoch) VALUES (?, ?, ?) ON CONFLICT(permit_id) DO NOTHING")
    .run(permitId, executionId, engine.instanceEpoch);
}

export function redemptionStatusFor(engine: TransactionEngine): RedemptionStatus {
  const epoch = `${engine.instanceEpoch}:${randomUUID()}`;
  engine.db.exec(REDEEMERS_SCHEMA);
  const redeemed = engine.db.prepare("SELECT 1 AS hit FROM operations WHERE permit_id = ? AND epoch = ?");
  const linked = engine.db.prepare(
    `SELECT r.execution_id AS execution_id FROM permit_redeemers r
     JOIN operations o ON o.permit_id = r.permit_id AND o.epoch = r.epoch
     WHERE r.permit_id = ? AND r.epoch = ?`,
  );
  return {
    epoch,
    status(evaluationId: string, pepEpoch: string): ConsumptionStatus {
      if (pepEpoch !== epoch) return "unknown";
      return redeemed.get(evaluationId, engine.instanceEpoch) ? "consumed" : "unconsumed";
    },
    redeemer(evaluationId: string, pepEpoch: string): string | undefined {
      if (pepEpoch !== epoch) return undefined;
      const row = linked.get(evaluationId, engine.instanceEpoch) as { execution_id: string } | undefined;
      return row?.execution_id;
    },
  };
}
