import { postureStalenessBound, RUNTIME_POSTURE, type StalenessBound } from "./runtime-posture.js";

/**
 * Deployment policy for the payments estate: action -> FGA relation mapping
 * and per-class staleness bounds (payments-runtime-profile-v1; O-8 numbers).
 */

/**
 * `needsAmount` mirrors the deployment catalog's `amount_bearing` property
 * (config/catalog.json, the single source of truth): true when every request
 * for the action carries an `amount` the PDP can compare. The two are held
 * equal by `services/authorization-server/test/amount-bearing-admission.test.ts`,
 * which also holds both equal to what the payments tools actually supply
 * (`TOOL_ACTIONS.needsInvoice`, mcp-payments/src/pep.ts). `evaluate()` reads
 * only `relation`: enforcement keys on the matched entry's own
 * `constraints.max_amount` presence, never on this flag (@spec
 * runtime#input-parameters).
 */
export const PAYMENTS_RELATIONS: Record<string, { relation: "payer" | "reader"; needsAmount: boolean }> = {
  "payments:invoice.read": { relation: "reader", needsAmount: true },
  "payments:invoice.list": { relation: "reader", needsAmount: false },
  "payments:vendor.read": { relation: "reader", needsAmount: false },
  "payments:payment.schedule": { relation: "payer", needsAmount: true },
  "payments:payment.execute": { relation: "payer", needsAmount: true },
  "payments:remittance.send": { relation: "payer", needsAmount: true },
};

export function relationForAction(action: string) {
  return PAYMENTS_RELATIONS[action] ?? null;
}

/**
 * @spec runtime#ride-through — the enforced bound per action class IS the
 * `max_staleness_seconds` the Enforcement Scope Statement publishes, so the
 * ride-through a caller reads and the window the PDP applies are one number.
 * Published bounds (O-8): tight for high-consequence, looser for reads. A
 * class the statement declares with no active freshness requirement resolves
 * to `none`, and a label the statement does not declare at all resolves to
 * `undeclared`: neither is a zero-second window.
 */
export function stalenessBound(actionClass: string | undefined): StalenessBound {
  return postureStalenessBound(RUNTIME_POSTURE, actionClass);
}
