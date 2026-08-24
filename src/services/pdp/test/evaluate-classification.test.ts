/**
 * @spec runtime#classification (no-evasion-and-write-floor)
 *
 * "A deployment MUST NOT ... use classification to evade the floor or a
 * Resource-policy minimum, and once an action is a consequential write or
 * higher it MUST be gated and bound as the table requires."
 *
 * evaluateInner treats `context.action_class` as an opaque label: it is read
 * only to pick a staleness bound, a permit TTL and `conditions.use_limit`
 * (@spec authzen#response-context), and to decide whether an action-bound
 * approval is required (which only ever ADDS a gate).
 * No branch in evaluateInner skips or loosens the authority-entry-match,
 * containment, FGA, amount, or approval gates based on the class label. This
 * test proves that structurally: no action_class value opens a bypass around
 * the entry-match gate. Unconditional: a stub `Fga` satisfies the one method
 * evaluate() calls, so this never skips.
 */

import { describe, expect, it } from "vitest";
import type { Fga } from "../src/fga.js";
import { evaluate, type EvaluationRequest, type MissionView, relationForAction, stalenessBoundSeconds } from "../src/index.js";

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
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
};

const reqFor = (actionClass: string): EvaluationRequest => ({
  subject: { id: "alice" },
  resource: { type: "invoice", id: "inv-1", properties: { vendor_id: "acme" } },
  // Not in the entry's actions, regardless of class: an entry-match failure
  // is the gate a low or unrecognized classification could try to evade.
  action: { name: "payments:payment.execute" },
  context: {
    audience: RESOURCE,
    mission: { id: "msn_test_1", issuer: "https://as.test", authority_hash: "sha-256:testhash" },
    action_class: actionClass,
    // Fresh state so a high-consequence class clears step 3 and this test
    // keeps exercising the gate it names (step 5's entry match), never the
    // freshness gate (@spec runtime#state-freshness).
    freshness: { observed_at: NOW.toISOString(), source: "status" },
  },
});

const opts = {
  view,
  fga: alwaysAllowFga,
  modelId: "unit-test-model",
  now: () => NOW,
  stalenessBoundSeconds,
  relationForAction,
  allowedFreshnessSources: new Set(["status"]),
};

describe("classification cannot be used to evade the floor or a Resource-policy minimum (@spec runtime#classification)", () => {
  it("no action_class label, including the high-consequence and unrecognized ones, opens a bypass around the authority-entry-match gate", async () => {
    for (const actionClass of [
      "non_consequential",
      "consequential_read",
      "consequential_write",
      "irreversible_action",
      "external_commitment",
      "privileged_administration",
      "some_unrecognized_label",
    ]) {
      const dec = await evaluate(reqFor(actionClass), opts);
      expect(dec.decision, actionClass).toBe(false);
      expect(dec.context.denial_reason, actionClass).toBe("out_of_authority");
    }
  });

  // This proves the PDP's own share of the rule: classification never
  // reduces the strictness of the gates evaluate() runs. It does NOT prove
  // the complementary half ("once ... consequential write or higher it MUST
  // be gated" as a call-site guarantee, i.e. that the PEP actually invokes
  // the PDP at all for such an action): that is a PEP-placement / complete-
  // mediation concern (this deployment's static action->class map lives in
  // mcp-payments/src/pep.ts), outside evaluate()'s pure-function boundary.
});
