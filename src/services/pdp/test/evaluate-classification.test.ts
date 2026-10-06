/**
 * @spec runtime#classification (no-evasion-and-write-floor)
 *
 * "A deployment MUST NOT ... use classification to evade the floor or a
 * Resource-policy minimum, and once an action is a consequential write or
 * higher it MUST be gated and bound as the table requires."
 *
 * evaluateInner treats `context.action_class` as an opaque label: it is read
 * only to pick a freshness posture, a permit TTL and `conditions.use_limit`
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
import { evaluate, type EvaluationRequest, type MissionView, relationForAction, stalenessBound } from "../src/index.js";
import { freshKey, openTestClaims } from "./claim-fixture.js";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";

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
  resource: { type: "invoice", id: "inv-1", properties: { audience: RESOURCE, vendor_id: "acme" } },
  // Not in the entry's actions, regardless of class: an entry-match failure
  // is the gate a low or unrecognized classification could try to evade.
  action: { name: "payments:payment.execute" },
  context: {
    mission: { id: "msn_test_1", issuer: "https://as.test", authority_hash: "sha-256:testhash" },
    action_class: actionClass,
    // Fresh state so a high-consequence class clears step 3 and this test
    // keeps exercising the gate it names (step 5's entry match), never the
    // freshness gate (@spec runtime#state-freshness).
    mission_state_observation: { state: "active", mode: "fresh", freshness_at: NOW.toISOString() },
  },
});

// The deployment's own bound function, unwrapped: every declared class
// resolves to a window or to no active freshness, so the gate cases below run
// against the real policy and still reach the gate they name.
const opts = {
  view,
  fga: alwaysAllowFga,
  modelId: "unit-test-model",
  now: () => NOW,
  stalenessBound,
  relationForAction,
  resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
  stateSourcePlacement: "pep" as const,
  // @spec runtime#idempotency (#917): a fixture domain that also mediates
  // privileged administration, which the shipped deployment does not offer.
  claims: openTestClaims({ now: () => NOW }),
};

describe("classification cannot be used to evade the floor or a Resource-policy minimum (@spec runtime#classification)", () => {
  it("privileged administration uses the declared 30-second bound and a single-use permit", async () => {
    const request = reqFor("privileged_administration");
    request.action.name = "payments:invoice.read";
    request.context.parameter_digest = "sha-256:params";
    request.action.properties = { idempotency_key: freshKey() };
    const permit = await evaluate(request, opts);
    expect(permit.decision).toBe(true);
    expect((permit.context.conditions as Record<string, unknown>).use_limit).toBe(1);
    request.context.mission_state_observation!.freshness_at = new Date(NOW.getTime() - 31_000).toISOString();
    expect((await evaluate(request, opts)).context.denial_reason).toBe("stale_state");
  });

  it("a class declared with no active freshness requirement is evaluated with no observation window, never refused as stale", async () => {
    // @spec runtime#state-freshness — the draft's Audit-only row: "No active
    // freshness required". The remaining gates still run, so the refusal is
    // the entry-match one and never `stale_state`. The observation stays
    // present, as the pep placement REQUIRES (#1049 owner ruling), but an
    // hour old: no window applies to it, so its age refuses nothing.
    const hourOld = new Date(NOW.getTime() - 3_600_000).toISOString();
    const request = reqFor("audit_only");
    request.context.mission_state_observation!.freshness_at = hourOld;
    const dec = await evaluate(request, opts);
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("out_of_authority");
    const permitted = reqFor("audit_only");
    permitted.context.mission_state_observation!.freshness_at = hourOld;
    permitted.action.name = "payments:invoice.read";
    expect((await evaluate(permitted, opts)).decision).toBe(true);
  });

  it("an action class the deployment does not declare refuses as a request fault, with any observation or none", async () => {
    // @spec authzen#runtime-denial-classification — the label reaches no
    // declared gate, so the refusal is `out_of_authority` ("Action outside
    // the Authority Set ..., or the request would broaden it"), never
    // `stale_state`, which would assert a freshness fact the PDP never
    // established.
    for (const mutate of [
      (_r: EvaluationRequest) => {},
      (r: EvaluationRequest) => { delete r.context.mission_state_observation; },
      (r: EvaluationRequest) => { r.context.mission_state_observation = { state: "active", mode: "fresh", freshness_at: new Date(NOW.getTime() - 10_000_000).toISOString() }; },
    ]) {
      const request = reqFor("some_unrecognized_label");
      // An action inside the entry, so only the class rule can refuse it.
      request.action.name = "payments:invoice.read";
      mutate(request);
      const dec = await evaluate(request, opts);
      expect(dec.decision).toBe(false);
      expect(dec.context.denial_reason).toBe("out_of_authority");
      expect(dec.context.reason).toBe("out_of_authority");
    }
  });

  it("no action_class label, including the high-consequence and unrecognized ones, opens a bypass around the authority-entry-match gate", async () => {
    for (const actionClass of [
      "non_consequential",
      "consequential_read",
      "consequential_write",
      "irreversible_action",
      "external_commitment",
      "privileged_administration",
      "audit_only",
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
