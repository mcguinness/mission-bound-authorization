/**
 * @spec orchestration#state-change-behavior
 *
 * In-flight outcome classification. The four outcome classes and the adapter
 * that maps the transaction-assurance tier's D36 operation state
 * (`OpState`, `services/mcp-payments/src/transaction.ts`) onto them. `unknown`
 * MUST route to human review; for the high-risk reversibility classes it MUST
 * NOT be treated as success or as harmless suppression (draft § in-flight).
 */

import type { OpState } from "@mission/mcp-payments";
import { HIGH_RISK_REVERSIBILITY, type ReversibilityClass } from "./reversibility.js";

export type OutcomeClass = "not_dispatched" | "dispatched_not_committed" | "committed" | "unknown";

/**
 * Adapter: D36 `OpState` -> in-flight outcome class.
 * - `reserved`            -> not_dispatched (the PEP holds the permit; nothing sent)
 * - `permit_consumed`     -> dispatched_not_committed (pre-commit; still cancellable)
 * - `connector_committed` -> committed
 * - `evidence_emitted`    -> committed
 * - `reconciled`          -> committed
 * - `abandoned`           -> unknown (cannot prove non-commit)
 * - undefined / unrecognized -> unknown (fail closed)
 */
export function classifyOutcome(opState: OpState | undefined): OutcomeClass {
  switch (opState) {
    case "reserved":
      return "not_dispatched";
    case "permit_consumed":
      return "dispatched_not_committed";
    case "connector_committed":
    case "evidence_emitted":
    case "reconciled":
      return "committed";
    default:
      // `abandoned` and any unrecognized/undefined state: unknown, fail closed.
      return "unknown";
  }
}

/**
 * Whether an outcome MUST route to human review. An `unknown` outcome always
 * requires review (§ in-flight: "requiring human review unless deployment
 * policy defines a stricter default"); for the high-risk classes this is
 * emphasized as MUST NOT-treat-as-success. `reversibility` is accepted so a
 * caller can apply a stricter per-class default.
 */
export function requiresHumanReview(
  outcome: OutcomeClass,
  reversibility: ReversibilityClass,
): boolean {
  if (outcome === "unknown") return true;
  // Reserved for a deployment's stricter-than-default policy per class.
  void reversibility;
  return false;
}

/** Whether an `unknown` outcome on this class is a high-risk unknown. */
export function isHighRiskUnknown(
  outcome: OutcomeClass,
  reversibility: ReversibilityClass,
): boolean {
  return outcome === "unknown" && HIGH_RISK_REVERSIBILITY.has(reversibility);
}
