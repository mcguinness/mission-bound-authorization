/**
 * @spec mission#max-amount, authzen#pdp-request
 *
 * The PDP's per-action max_amount cap (step 7 of evaluateInner) MUST compare
 * by exact decimal value, never IEEE-754 float, and MUST deny (fail closed)
 * on a malformed amount rather than silently permit. Pure unit test: `fga` is
 * a stub satisfying only the one method `evaluate` calls, so this needs no
 * OpenFGA / Docker and never skips.
 */

import { describe, expect, it } from "vitest";
import type { Fga } from "../src/fga.js";
import { evaluate, type EvaluationRequest, type MissionView, relationForAction, stalenessBoundSeconds } from "../src/index.js";

const RESOURCE = "http://localhost:4403/mcp";
const NOW = new Date("2026-07-22T12:00:00Z");

/** A stub satisfying the one Fga method evaluate() calls; always permits at the FGA layer
 *  so step 7 (the max_amount cap) is what decides the outcome. */
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const view = (maxAmount: string): MissionView => ({
  id: "msn_test_1",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:testhash",
  authority_set: [
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: ["payments:payment.execute"],
      constraints: { max_amount: { amount: maxAmount, currency: "USD" } },
    },
  ],
});

const request = (amount: string): EvaluationRequest => ({
  subject: { id: "alice" },
  resource: { type: "invoice", id: "inv-1", properties: { vendor_id: "acme" } },
  action: { name: "payments:payment.execute" },
  context: {
    audience: RESOURCE,
    mission: { id: "msn_test_1", authority_hash: "sha-256:testhash" },
    amount: { amount, currency: "USD" },
  },
});

const opts = (maxAmount: string) => ({
  view: view(maxAmount),
  fga: alwaysAllowFga,
  modelId: "model-1",
  now: () => NOW,
  stalenessBoundSeconds,
  relationForAction,
});

describe("PDP per-action max_amount cap compares by exact decimal value (@spec mission#max-amount)", () => {
  it("permits an amount within the cap and denies one over it (regression: unchanged behavior)", async () => {
    const within = await evaluate(request("100.00"), opts("500.00"));
    expect(within.decision, JSON.stringify(within.context)).toBe(true);
    const over = await evaluate(request("500.01"), opts("500.00"));
    expect(over.decision).toBe(false);
    expect(over.context.denial_reason).toBe("constraint_exceeded");
  });

  it("a value that float-compares wrong compares correctly under exact decimal comparison", async () => {
    // Both round to the identical IEEE-754 double, so a float-based cap check
    // would wrongly permit the wider amount as "equal to" the cap.
    const cap = "9007199254740992.00";
    const overCap = "9007199254740993.00";
    expect(Number.parseFloat(overCap)).toBe(Number.parseFloat(cap));
    const decision = await evaluate(request(overCap), opts(cap));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("constraint_exceeded");
  });

  it("a malformed request amount is denied (fail closed), never silently permitted", async () => {
    const decision = await evaluate(request("NaN"), opts("500.00"));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("constraint_exceeded");
  });

  it("a malformed cap in the Mission view is denied (fail closed), never treated as unbounded", async () => {
    const decision = await evaluate(request("100.00"), opts("1e300"));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("constraint_exceeded");
  });
});
