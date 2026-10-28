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
import { isValidAmount } from "@mission/core";
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
 * the counter store cannot be read. The reading is synchronous: a reading
 * answered later (a Promise) is no reading.
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
 * The counters' unit: the currency and the minor-unit exponent the
 * Enforcement Scope Statement's `budget_metering` declares, which the PDP
 * counts in and renders every total at.
 */
export interface CounterUnit {
  currency: string;
  exponent: number;
}

/** The widest exponent a PDP counter takes, as the PDP bounds it. */
const MAX_EXPONENT = 9;

const isRecord = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * The counter unit `statement` declares for `budget_metering`, or `undefined`
 * when it declares none or one that is not a currency and a whole exponent
 * from 0 to 9.
 */
export function meteringUnitOf(statement: unknown): CounterUnit | undefined {
  const declared =
    isRecord(statement) && isRecord(statement.extensions) ? statement.extensions.budget_metering : undefined;
  const unit = isRecord(declared) ? declared.unit : undefined;
  if (
    !isRecord(unit) ||
    typeof unit.currency !== "string" ||
    !/^[A-Z]{3}$/.test(unit.currency) ||
    typeof unit.exponent !== "number" ||
    !Number.isSafeInteger(unit.exponent) ||
    unit.exponent < 0 ||
    unit.exponent > MAX_EXPONENT
  ) {
    return undefined;
  }
  return { currency: unit.currency, exponent: unit.exponent };
}

/** Zero in `unit`, written as the PDP writes a total: `exponent` fractional digits. */
export const zeroIn = (unit: CounterUnit): CounterAmount => ({
  amount: unit.exponent === 0 ? "0" : `0.${"0".repeat(unit.exponent)}`,
  currency: unit.currency,
});

/** Whether `amount` is a decimal string with exactly `exponent` fractional digits. */
const atExponent = (amount: string, exponent: number): boolean =>
  isValidAmount(amount) && (amount.split(".")[1]?.length ?? 0) === exponent;

/**
 * Read one counter through `port`, as zero in `unit` when it was never
 * charged. A reading is accepted only when it is made now and each of its
 * three totals is a decimal amount in `unit`'s currency at its exponent. Any
 * failure, an absent port or unit, a thrown or deferred reading, or a total
 * of another shape, is a {@link BudgetExposureUnavailableError}.
 */
export function readCounterExposure(
  port: BudgetExposurePort | undefined,
  key: BudgetCounterKey,
  unit: CounterUnit | undefined,
): CounterExposure {
  if (!port) throw new BudgetExposureUnavailableError("no budget exposure port is configured");
  if (!unit) {
    throw new BudgetExposureUnavailableError(
      "the Enforcement Scope Statement declares no budget_metering unit to read the counters in",
    );
  }
  let totals: unknown;
  try {
    totals = port.read(key);
  } catch (e) {
    throw new BudgetExposureUnavailableError(
      `the ${key.counter_scope} budget counter could not be read: ${(e as Error).message}`,
    );
  }
  if (totals !== null && (typeof totals === "object" || typeof totals === "function")) {
    const then = (totals as { then?: unknown }).then;
    if (typeof then === "function") {
      // A rejection the refusal already accounts for is not left unhandled.
      Promise.resolve(totals).catch(() => undefined);
      throw new BudgetExposureUnavailableError(
        `the ${key.counter_scope} budget counter's reading was deferred, not made now`,
      );
    }
  }
  if (totals === undefined) {
    const zero = zeroIn(unit);
    return { counter_scope: key.counter_scope, committed: { ...zero }, reserved: { ...zero }, held: { ...zero } };
  }
  const total = (member: "committed" | "reserved" | "held"): CounterAmount => {
    const value = isRecord(totals) ? totals[member] : undefined;
    if (
      !isRecord(value) ||
      typeof value.amount !== "string" ||
      !atExponent(value.amount, unit.exponent) ||
      value.currency !== unit.currency
    ) {
      throw new BudgetExposureUnavailableError(
        `the ${key.counter_scope} budget counter's ${member} total is not a decimal amount in ${unit.currency} at exponent ${unit.exponent}`,
      );
    }
    return { amount: value.amount, currency: value.currency };
  };
  return {
    counter_scope: key.counter_scope,
    committed: total("committed"),
    reserved: total("reserved"),
    held: total("held"),
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
