/**
 * @spec runtime#compromise-resistant (action-bound-approval-condition)
 *
 * "each such action requires an action-bound approval" -- under the
 * agent-compromise-resistant claim, every action in the three high-
 * consequence classes requires one. This tests the PDP's share of that
 * claim: the action-bound-approval gate (evaluate.ts step 8) enforces
 * correctly for exactly these three class labels, one at a time, when the
 * deployment's `requiresActionApproval` predicate is wired to require it for
 * the class. Unconditional: a stub `Fga` satisfies the one method evaluate()
 * calls, so this never skips.
 *
 * NOT asserted here: whether a real deployment's `requiresActionApproval`
 * predicate is in fact wired to cover every action it assigns to these three
 * classes (deployment-wide policy completeness is a configuration-audit
 * matter, outside evaluate()'s pure-function boundary).
 */

import { describe, expect, it } from "vitest";
import type { Fga } from "../src/fga.js";
import { evaluate, type ActionApproval, type EvaluationRequest, type MissionView, relationForAction, stalenessBoundSeconds } from "../src/index.js";

const RESOURCE = "http://localhost:4403/mcp";
const NOW = new Date("2026-07-22T12:00:00Z");

const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const view: MissionView = {
  id: "msn_test_1",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:testhash",
  authority_set: [
    { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] },
  ],
};

const HIGH_CONSEQUENCE_CLASSES = ["irreversible_action", "external_commitment", "privileged_administration"];

const reqFor = (actionClass: string, approval?: ActionApproval): EvaluationRequest => ({
  subject: { id: "alice" },
  resource: { type: "invoice", id: "inv-1", properties: { vendor_id: "acme" } },
  action: { name: "payments:invoice.read" },
  context: {
    audience: RESOURCE,
    mission: { id: "msn_test_1", authority_hash: "sha-256:testhash" },
    action_class: actionClass,
    parameter_digest: "sha-256:pd",
    // Fresh state so a high-consequence class clears step 3 and this test
    // keeps exercising the gate it names (step 8's action-bound approval),
    // never the freshness gate (@spec runtime#state-freshness).
    freshness: { observed_at: NOW.toISOString(), source: "status" },
    ...(approval ? { action_approval: approval } : {}),
  },
});

const optsFor = (actionClass: string) => ({
  view,
  fga: alwaysAllowFga,
  modelId: "unit-test-model",
  now: () => NOW,
  stalenessBoundSeconds,
  // Models a deployment claiming agent-compromise-resistant enforcement: the
  // predicate requires approval for exactly the requested high-consequence
  // class, and no other.
  requiresActionApproval: (_action: string, ac: string | undefined) => ac === actionClass,
  maxApprovalAgeSeconds: 300,
  relationForAction,
});

describe("action-bound approval gate, one high-consequence class at a time (@spec runtime#compromise-resistant)", () => {
  it("each of the three high-consequence classes is denied action_approval_required with no approval presented", async () => {
    for (const actionClass of HIGH_CONSEQUENCE_CLASSES) {
      const dec = await evaluate(reqFor(actionClass), optsFor(actionClass));
      expect(dec.decision, actionClass).toBe(false);
      expect(dec.context.denial_reason, actionClass).toBe("action_approval_required");
    }
  });

  it("each of the three high-consequence classes permits once a valid fresh action-bound approval matching the parameters is presented", async () => {
    for (const actionClass of HIGH_CONSEQUENCE_CLASSES) {
      const approval: ActionApproval = { id: `apr_${actionClass}`, approved_at: NOW.toISOString(), parameter_digest: "sha-256:pd" };
      const dec = await evaluate(reqFor(actionClass, approval), optsFor(actionClass));
      expect(dec.decision, JSON.stringify({ actionClass, ctx: dec.context })).toBe(true);
    }
  });
});
