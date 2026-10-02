/**
 * @spec runtime#idempotency, retransmission condition 6 (#917, owner ruling
 * 2026-10-02): the PEP's read-only answer, from its D28 redemption store,
 * to "was this `evaluation_id` consumed?".
 *
 * Redemption stays here and `transaction.ts` is unchanged: this module only
 * reads the operation rows `TransactionEngine.redeemPermit` already writes.
 * The answer is scoped to an epoch, the lifetime of this one in-memory store.
 * Within its own epoch the store holds every redemption that epoch could make,
 * so an identifier with no row was not consumed there: `unconsumed`. For any
 * other epoch (a restarted PEP, another replica) the store cannot speak:
 * `unknown`, which the PDP treats as suppress. The PDP asks only for a
 * retransmission candidate and never caches the answer.
 */

import { randomUUID } from "node:crypto";
import type { ConsumptionStatus } from "@mission/pdp";
import type { TransactionEngine } from "./transaction.js";

export interface RedemptionStatus {
  /**
   * This store's epoch, sent as the requester's `pep_epoch` on every decision
   * request. Fresh per provider, so it names exactly one store lifetime even
   * where the engine's configured instance epoch is a fixed label.
   */
  readonly epoch: string;
  /** `consumed`, `unconsumed`, or `unknown` for another epoch. Read-only. */
  status(evaluationId: string, pepEpoch: string): ConsumptionStatus;
}

export function redemptionStatusFor(engine: TransactionEngine): RedemptionStatus {
  const epoch = `${engine.instanceEpoch}:${randomUUID()}`;
  const redeemed = engine.db.prepare("SELECT 1 AS hit FROM operations WHERE permit_id = ? AND epoch = ?");
  return {
    epoch,
    status(evaluationId: string, pepEpoch: string): ConsumptionStatus {
      if (pepEpoch !== epoch) return "unknown";
      return redeemed.get(evaluationId, engine.instanceEpoch) ? "consumed" : "unconsumed";
    },
  };
}
