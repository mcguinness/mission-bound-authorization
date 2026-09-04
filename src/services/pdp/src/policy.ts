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

/** Published staleness bounds (O-8): tight for high-consequence, looser for reads. */
export function stalenessBoundSeconds(actionClass: string | undefined): number {
  switch (actionClass) {
    case "irreversible_action":
      return 30;
    case "external_commitment":
      return 60;
    default:
      return 300;
  }
}
