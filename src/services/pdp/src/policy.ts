/**
 * Deployment policy for the payments estate: action -> FGA relation mapping
 * and per-class staleness bounds (payments-runtime-profile-v1; O-8 numbers).
 */

export const PAYMENTS_RELATIONS: Record<string, { relation: "payer" | "reader"; needsAmount: boolean }> = {
  "payments:invoice.read": { relation: "reader", needsAmount: false },
  "payments:invoice.list": { relation: "reader", needsAmount: false },
  "payments:vendor.read": { relation: "reader", needsAmount: false },
  "payments:payment.schedule": { relation: "payer", needsAmount: true },
  "payments:payment.execute": { relation: "payer", needsAmount: true },
  "payments:remittance.send": { relation: "payer", needsAmount: false },
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
