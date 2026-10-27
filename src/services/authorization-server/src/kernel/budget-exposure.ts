/**
 * @spec mission-template#standing-payment-exception, metering#aggregate-bounds,
 * metering#capacity-across-missions (#813, #816, D830 ruling 7, D877): the
 * AS's read port onto the budget counters a standing payment is metered
 * against, so an approval page can disclose the exposure a raise or a
 * successor is measured against.
 *
 * The counters live in the co-resident PDP's claim domain (`BudgetCounterState`):
 * the shared `standing_consent` counter keyed by the budget's owner and id,
 * and the `mission` counter keyed by the dispatched instance (the first
 * Mission of its successor chain). The deployment wires the port; the AS never
 * reads the PDP's store itself. A page renders consumption to date (the
 * committed total) and the outstanding reservations (reserved, and held
 * pending reconciliation) as read at that rendering. A reading that cannot
 * be made refuses the approval: a raise accounts for outstanding exposure
 * (D830 ruling 7), and an exposure the Approver was never shown is not
 * accounted for.
 */
import type { StandingPaymentAdmission } from "./standing-payment.js";

/** One counter, keyed as the PDP keys it. */
export type BudgetCounterKey =
  | { counter_scope: "standing_consent"; owner: string; budget_id: string }
  | { counter_scope: "mission"; issuer: string; mission_id: string };

/** An amount in a counter's currency. */
export interface CounterAmount {
  amount: string;
  currency: string;
}

/** One counter's totals, as the claim domain reports them. */
export interface BudgetCounterTotals {
  reserved: CounterAmount;
  held: CounterAmount;
  committed: CounterAmount;
}

/**
 * The deployment's read port. `read` returns a counter's totals, or
 * `undefined` for a counter never charged (read as zero), and throws when
 * the counter store cannot be read.
 */
export interface BudgetExposurePort {
  read(key: BudgetCounterKey): BudgetCounterTotals | undefined;
}

/** The counters could not be read; the approval that needed them is refused. */
export class BudgetExposureUnavailableError extends Error {}

/** One counter's exposure as an approval page renders and commits it. */
export interface CounterExposure {
  counter_scope: BudgetCounterKey["counter_scope"];
  /** Consumption to date: the committed total. */
  committed: CounterAmount;
  /** Outstanding reservations still open. */
  reserved: CounterAmount;
  /** Outstanding reservations held pending reconciliation. */
  held: CounterAmount;
}

/**
 * Read one counter through `port`, as zero in `currency` when it was never
 * charged. Any failure, an absent port included, is a
 * {@link BudgetExposureUnavailableError}.
 */
export function readCounterExposure(
  port: BudgetExposurePort | undefined,
  key: BudgetCounterKey,
  currency: string,
): CounterExposure {
  if (!port) throw new BudgetExposureUnavailableError("no budget exposure port is configured");
  let totals: BudgetCounterTotals | undefined;
  try {
    totals = port.read(key);
  } catch (e) {
    throw new BudgetExposureUnavailableError(
      `the ${key.counter_scope} budget counter could not be read: ${(e as Error).message}`,
    );
  }
  // The workflow meters USD at exponent 2 (D814, decision c).
  const zero = { amount: "0.00", currency };
  return {
    counter_scope: key.counter_scope,
    committed: totals ? { ...totals.committed } : zero,
    reserved: totals ? { ...totals.reserved } : zero,
    held: totals ? { ...totals.held } : zero,
  };
}

/** The shared standing-consent counter's key for a budget. */
export const standingConsentKey = (budget: { owner: string; id: string }): BudgetCounterKey => ({
  counter_scope: "standing_consent",
  owner: budget.owner,
  budget_id: budget.id,
});

/** The instance counter's key for a standing-payment lineage, keyed by its dispatched instance. */
export const instanceKey = (
  issuer: string,
  admission: StandingPaymentAdmission,
): BudgetCounterKey => ({
  counter_scope: "mission",
  issuer,
  mission_id: admission.mission_id,
});

/** One rendered line per counter, in the order read. */
export function exposureLines(
  exposures: ReadonlyArray<{ label: string; exposure: CounterExposure }>,
): string[] {
  return exposures.map(
    ({ label, exposure: e }) =>
      `${label}: consumption to date ${e.committed.amount} ${e.committed.currency} committed; outstanding reservations ${e.reserved.amount} ${e.reserved.currency} reserved and ${e.held.amount} ${e.held.currency} held pending reconciliation, as read at this rendering.`,
  );
}
