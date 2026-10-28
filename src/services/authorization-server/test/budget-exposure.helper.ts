/**
 * @spec mission-template#standing-payment-exception (#813, D877): an in-memory
 * stand-in for the deployment's budget exposure port, the co-resident PDP
 * claim domain's counters, so an AS test can set what an approval page reads
 * and make the reading fail.
 */
import type { BudgetCounterKey, BudgetCounterTotals, BudgetExposurePort } from "../src/index.js";

const keyOf = (key: BudgetCounterKey): string =>
  key.counter_scope === "standing_consent"
    ? `standing_consent:${key.owner}:${key.budget_id}`
    : `mission:${key.issuer}:${key.mission_id}`;

export class FakeBudgetCounters implements BudgetExposurePort {
  private readonly totals = new Map<string, BudgetCounterTotals>();
  /** While set, every read throws, as a claim domain that cannot be read does. */
  failing = false;
  /** How many reads were made. */
  reads = 0;

  read(key: BudgetCounterKey): BudgetCounterTotals | undefined {
    this.reads += 1;
    if (this.failing) throw new Error("the claim domain is unavailable");
    return this.totals.get(keyOf(key));
  }

  /** Set a counter's totals, in USD. */
  set(key: BudgetCounterKey, totals: { committed: string; reserved: string; held: string }): void {
    const usd = (amount: string) => ({ amount, currency: "USD" });
    this.totals.set(keyOf(key), {
      committed: usd(totals.committed),
      reserved: usd(totals.reserved),
      held: usd(totals.held),
    });
  }
}
