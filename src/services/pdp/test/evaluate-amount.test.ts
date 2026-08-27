/**
 * @spec mission#max-amount, authzen#pdp-request, runtime#input-parameters
 *
 * The PDP's per-action max_amount cap (step 7 of evaluateInner) MUST compare
 * by exact decimal value, never IEEE-754 float, and MUST deny (fail closed)
 * on a malformed amount rather than silently permit. Enforcement is keyed on
 * the constraint's OWN presence, never on the mapped action's input schema:
 * a bound max_amount the PDP cannot supply an amount for (absent
 * `context.amount`, including on an action the deployment's own mapping
 * marks `needsAmount: false`) MUST refuse the same as an out-of-bound or
 * malformed one (@spec runtime#input-parameters, "cannot supply the
 * declared inputs for ... MUST cause refusal"); absent a bound max_amount,
 * an absent amount is never itself an error. Pure unit test: `fga` is a stub
 * satisfying only the one method `evaluate` calls, so this needs no OpenFGA
 * / Docker and never skips.
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
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
});

const request = (amount: string, currency = "USD"): EvaluationRequest => ({
  subject: { id: "alice" },
  resource: { type: "invoice", id: "inv-1", properties: { vendor_id: "acme" } },
  action: { name: "payments:payment.execute" },
  context: {
    audience: RESOURCE,
    mission: { id: "msn_test_1", issuer: "https://as.test", authority_hash: "sha-256:testhash" },
    amount: { amount, currency },
  },
});

const opts = (maxAmount: string) => optsFor(view(maxAmount));

const optsFor = (v: MissionView) => ({
  view: v,
  fga: alwaysAllowFga,
  modelId: "model-1",
  now: () => NOW,
  stalenessBoundSeconds,
  relationForAction,
});

/** Same request shape as `request()`, but with no `context.amount` at all
 *  (never an empty/zero amount): the PEP simply did not supply one. */
const requestWithoutAmount = (action = "payments:payment.execute"): EvaluationRequest => ({
  subject: { id: "alice" },
  resource: { type: "invoice", id: "inv-1", properties: { vendor_id: "acme" } },
  action: { name: action },
  context: {
    audience: RESOURCE,
    mission: { id: "msn_test_1", issuer: "https://as.test", authority_hash: "sha-256:testhash" },
  },
});

/** A Mission view whose matched entry binds `max_amount` to an action the
 *  deployment's own mapping (`payments:invoice.read`, PAYMENTS_RELATIONS)
 *  marks `needsAmount: false`: the admission layer let a cap through onto
 *  an action whose input schema carries no amount at all. */
const viewCapOnNonAmountAction = (maxAmount: string): MissionView => ({
  id: "msn_test_1",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:testhash",
  authority_set: [
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: ["payments:invoice.read"],
      constraints: { max_amount: { amount: maxAmount, currency: "USD" } },
    },
  ],
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
});

/** A Mission view whose matched entry binds no `max_amount` at all, on an
 *  action whose mapping otherwise declares `needsAmount: true`. */
const viewNoCap: MissionView = {
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
    },
  ],
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
};

describe("PDP per-action max_amount cap compares by exact decimal value (@spec mission#max-amount)", () => {
  it("permits an amount within the cap and denies one over it (regression: unchanged behavior)", async () => {
    const within = await evaluate(request("100.00"), opts("500.00"));
    expect(within.decision, JSON.stringify(within.context)).toBe(true);
    const over = await evaluate(request("500.01"), opts("500.00"));
    expect(over.decision).toBe(false);
    expect(over.context.denial_reason).toBe("constraint_exceeded");
  });

  it("an amount exactly at the cap permits (the comparison is <=, not <)", async () => {
    const atCap = await evaluate(request("500.00"), opts("500.00"));
    expect(atCap.decision, JSON.stringify(atCap.context)).toBe(true);
  });

  it("a cap denominated in a different currency than the request refuses as incomparable, never converted", async () => {
    const decision = await evaluate(request("100.00", "EUR"), opts("500.00"));
    expect(decision.decision, JSON.stringify(decision.context)).toBe(false);
    expect(decision.context.denial_reason).toBe("constraint_exceeded");
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

describe("a bound max_amount the PDP cannot supply an amount input for refuses, never permits open (@spec runtime#input-parameters)", () => {
  it("a bound max_amount with no context.amount at all is denied, never permitted for lack of an input to check", async () => {
    const decision = await evaluate(requestWithoutAmount(), opts("500.00"));
    expect(decision.decision, JSON.stringify(decision.context)).toBe(false);
    expect(decision.context.denial_reason).toBe("constraint_exceeded");
  });

  it("a max_amount bound to an action the deployment's own mapping marks needsAmount: false is still enforced, not silently unenforceable", async () => {
    // payments:invoice.read (PAYMENTS_RELATIONS) declares needsAmount: false;
    // the matched entry binds max_amount to it anyway. The cap must still be
    // enforceable, so an absent amount refuses exactly as it would on an
    // action the mapping does mark needsAmount: true for.
    const decision = await evaluate(
      requestWithoutAmount("payments:invoice.read"),
      optsFor(viewCapOnNonAmountAction("500.00")),
    );
    expect(decision.decision, JSON.stringify(decision.context)).toBe(false);
    expect(decision.context.denial_reason).toBe("constraint_exceeded");
  });
});

describe("no bound max_amount: an absent amount is never itself an error (regression guard, uncited: this asserts a permit, not the refusal the manifest row's normative sentence names)", () => {
  it("an action whose matched entry binds no max_amount proceeds with no context.amount, even though the mapping marks needsAmount: true", async () => {
    const decision = await evaluate(requestWithoutAmount(), optsFor(viewNoCap));
    expect(decision.decision, JSON.stringify(decision.context)).toBe(true);
  });
});
