/**
 * @spec runtime#decision (deny-terminal-and-gates-independent)
 * @spec runtime#action-approval (approval-not-bearer-grant)
 *
 * "Each gate is independently necessary and none grants, widens, or restores
 * another" (@spec runtime#decision), and "the approval is decision input,
 * not a bearer grant: the runtime decision ... remains authoritative"
 * (@spec runtime#action-approval).
 *
 * Unconditional: a stub `Fga` satisfies the one method evaluate() calls, so
 * this file never skips. The complementary approval-gate-independence arm
 * (authority and FGA permit, but a required approval is missing) is already
 * exercised by evaluate.test.ts's "denies an action the matched entry gates
 * even when deployment policy does not" (live-OpenFGA, CI-only); it is
 * mapped alongside these two unconditional cases in the manifest rather than
 * duplicated here.
 */

import { describe, expect, it } from "vitest";
import type { Fga } from "../src/fga.js";
import { evaluate, type ActionApproval, type EvaluationRequest, type MissionView, relationForAction, stalenessBoundSeconds } from "../src/index.js";

const RESOURCE = "http://localhost:4403/mcp";
const NOW = new Date("2026-07-22T12:00:00Z");

const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const view = (over: Partial<MissionView> = {}): MissionView => ({
  id: "msn_test_1",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:testhash",
  authority_set: [
    { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] },
  ],
  ...over,
});

const req = (over: Partial<EvaluationRequest> = {}): EvaluationRequest => ({
  subject: { id: "alice" },
  resource: { type: "invoice", id: "inv-1", properties: { vendor_id: "acme" } },
  action: { name: "payments:invoice.read" },
  context: {
    audience: RESOURCE,
    mission: { id: "msn_test_1", authority_hash: "sha-256:testhash" },
  },
  ...over,
});

describe("a valid action-bound approval does not expand authority (@spec runtime#action-approval, runtime#decision)", () => {
  it("an action outside the entry's approved actions is denied out_of_authority identically, whether or not a valid fresh approval is presented", async () => {
    // payment.execute is not in the entry's actions (only invoice.read is).
    const outOfAuthorityReq = req({
      action: { name: "payments:payment.execute" },
      context: {
        audience: RESOURCE,
        mission: { id: "msn_test_1", authority_hash: "sha-256:testhash" },
        parameter_digest: "sha-256:pd",
      },
    });
    const opts = {
      view: view(),
      fga: alwaysAllowFga,
      modelId: "unit-test-model",
      now: () => NOW,
      stalenessBoundSeconds,
      relationForAction,
      // Even a deployment policy that ALWAYS requires approval, satisfied by
      // a fresh, correctly-bound approval, must not rescue a missing entry.
      requiresActionApproval: () => true,
      maxApprovalAgeSeconds: 300,
    };
    const withoutApproval = await evaluate(outOfAuthorityReq, opts);

    const approval: ActionApproval = { id: "apr_1", approved_at: NOW.toISOString(), parameter_digest: "sha-256:pd" };
    const withApproval = await evaluate(
      req({
        action: { name: "payments:payment.execute" },
        context: {
          audience: RESOURCE,
          mission: { id: "msn_test_1", authority_hash: "sha-256:testhash" },
          parameter_digest: "sha-256:pd",
          action_approval: approval,
        },
      }),
      opts,
    );

    expect(withoutApproval.decision).toBe(false);
    expect(withoutApproval.context.denial_reason).toBe("out_of_authority");
    // Identical outcome with a valid, matching, fresh approval present: the
    // approval confers nothing on its own, and evaluate() (a stateless pure
    // function, D28) carries no state from the approval past this one call.
    expect(withApproval.decision).toBe(false);
    expect(withApproval.context.denial_reason).toBe("out_of_authority");
  });
});

describe("runtime decision gates are independently necessary (@spec runtime#decision)", () => {
  it("a stale freshness failure denies even though authority and the Resource-policy/FGA check both permit", async () => {
    const dec = await evaluate(
      req({
        action: { name: "payments:invoice.read" },
        context: {
          audience: RESOURCE,
          mission: { id: "msn_test_1", authority_hash: "sha-256:testhash" },
          action_class: "irreversible_action", // 30s staleness bound
          freshness: { observed_at: "2026-07-22T11:58:00Z", source: "status" }, // 120s stale
        },
      }),
      { view: view(), fga: alwaysAllowFga, modelId: "unit-test-model", now: () => NOW, stalenessBoundSeconds, relationForAction },
    );
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("stale_state");
  });

  // The deny-terminal half of this row ("the PEP MUST refuse the action" on
  // a deny) is a PEP duty; evaluate() has no PEP to exercise, so that half
  // is not asserted by any test in this file.
});
