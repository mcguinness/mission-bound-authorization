/**
 * @spec mission#authorization-derivation (#743, review #745 finding 1 / P1)
 *
 * Regression for the `/agent/propose` preview's narrowing diff
 * (`proposalDiff`, server.ts), driven through the exact DEFAULT UI proposal:
 * the goal/cap/actions/vendors form values `demo/public/index.html` ships
 * with, run through the SAME `shapeIntent()` + cap-injection path the
 * `/agent/shape` handler runs (server.ts), not a hand-typed literal — so a
 * future change to either the default form values or the shape/cap-injection
 * logic changes this test's input too, instead of a stale copy staying green.
 *
 * The default form proposes read AND money actions in ONE mixed entry,
 * capped at $900 against the shipped $500 money ceiling. Since #743 split
 * the payments ceiling into a read-only entry and a money entry, this one
 * proposed entry now derives into TWO fragments (one per ceiling partition).
 * Before the P1 fix, `derived.find` picked only ONE of them: with the read
 * fragment (no cap of its own; it inherits the proposal's 900 unchanged, ceiling-
 * absent) surfacing first, the preview reported `payment.execute` and
 * `remittance.send` as DROPPED and never surfaced the ceiling's 500 cap.
 * `proposalDiff` now aggregates every applicable fragment, so both are
 * visible.
 */

import { describe, expect, it } from "vitest";
import { shapeIntent } from "@mission/agent";
import { deriveAuthoritySet, validateAuthorityProposal, validateMissionIntent } from "@mission/authorization-server";
import { CANONICAL_RESOURCE, DERIVATION_POLICY } from "@mission/demo-data";
import { proposalDiff } from "../src/server.js";

// The exact default values demo/public/index.html ships on #f_goal, #f_cap,
// #f_actions, #f_vendors (the form the "over-ask so the narrowing is visible"
// lead paragraph describes).
const DEFAULT_GOAL = "Pay Acme and Globex invoices, up to $900";
const DEFAULT_CAP = "900.00";
const DEFAULT_ACTIONS = ["payments:invoice.read", "payments:payment.execute", "payments:remittance.send"];
const DEFAULT_VENDORS = ["acme", "globex"];

/** Mirrors server.ts's /agent/shape handler, then /agent/propose's intake, verbatim. */
function defaultUiProposal() {
  const shaped = shapeIntent({
    goal: DEFAULT_GOAL,
    resources: [CANONICAL_RESOURCE],
    expiresAt: "2027-01-01T00:00:00Z",
    proposedActions: DEFAULT_ACTIONS,
    vendors: DEFAULT_VENDORS,
  });
  const intent = validateMissionIntent(shaped.missionIntent);
  // /agent/shape's cap injection: entries[0].constraints.max_amount = { cap, USD }.
  const entries = JSON.parse(shaped.authorizationDetails as string) as Array<{
    constraints?: Record<string, unknown>;
  }>;
  const first = entries[0];
  if (!first) throw new Error("expected shapeIntent to produce one entry");
  first.constraints = { ...(first.constraints ?? {}), max_amount: { amount: DEFAULT_CAP, currency: "USD" } };
  // /agent/propose's intake: validateProposal against the Intent's own target_resources.
  const proposal = validateAuthorityProposal(JSON.stringify(entries), intent.target_resources);
  return { intent, proposal };
}

describe("/agent/propose preview: default UI proposal (review #745 P1)", () => {
  it("aggregates every derived fragment: no proposed action is misreported as dropped, and the ceiling's tightened cap is surfaced", () => {
    const { intent, proposal } = defaultUiProposal();
    const derived = deriveAuthoritySet(intent, DERIVATION_POLICY as never, proposal);
    // The split ceiling derives two same-resource fragments from this one
    // mixed proposal (a read-only fragment and a money fragment) — the
    // precondition for the bug this test guards against.
    expect(derived.filter((d) => d.resource === CANONICAL_RESOURCE).length).toBe(2);

    const diff = proposalDiff(proposal as never, derived as never);
    expect(diff).toHaveLength(1);
    // Every proposed action is granted by SOME fragment: none dropped.
    expect(diff[0]?.actions_dropped).toEqual([]);
    // The money fragment's ceiling cap (500) is surfaced as a tightening from
    // the proposal's 900, even though it is the SECOND fragment, not the one
    // `derived.find` would have picked.
    expect(diff[0]?.constraints_tightened).toContainEqual({
      name: "max_amount",
      proposed: "900.00 USD",
      granted: "500.00 USD",
    });
  });
});
