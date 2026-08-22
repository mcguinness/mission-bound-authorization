/**
 * @spec runtime#decision (deny-terminal-and-gates-independent)
 * @spec runtime#action-approval (approval-not-bearer-grant)
 *
 * "Each gate is independently necessary and none grants, widens, or restores
 * another" (@spec runtime#decision), and "the approval is decision input,
 * not a bearer grant: the runtime decision ... remains authoritative ...
 * a persisted grant beyond the single action is a governance state change
 * the fresh decision observes" (@spec runtime#action-approval).
 *
 * Unconditional: a stub `Fga` satisfies the one method evaluate() calls, so
 * this file never skips. The complementary approval-gate-independence arm
 * (authority and FGA permit, but a required approval is missing) is already
 * exercised by evaluate.test.ts's "denies an action the matched entry gates
 * even when deployment policy does not" (live-OpenFGA, CI-only); it is
 * mapped alongside these two unconditional cases in the manifest rather than
 * duplicated here.
 *
 * deny-terminal-and-gates-independent's anchor carries two sentences: gate
 * independence (asserted here directly) and "the PEP MUST refuse [on a
 * deny]; a deny is terminal" (a PEP behavior evaluate() has no PEP to
 * exercise). This file asserts the former and that a deny carries no
 * permit-shaped fields, not the latter; the manifest row stays partial.
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
    mission: { id: "msn_test_1", issuer: "https://as.test", authority_hash: "sha-256:testhash" },
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
        mission: { id: "msn_test_1", issuer: "https://as.test", authority_hash: "sha-256:testhash" },
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
          mission: { id: "msn_test_1", issuer: "https://as.test", authority_hash: "sha-256:testhash" },
          parameter_digest: "sha-256:pd",
          action_approval: approval,
        },
      }),
      opts,
    );

    expect(withoutApproval.decision).toBe(false);
    expect(withoutApproval.context.denial_reason).toBe("out_of_authority");
    expect(withoutApproval.context.conditions).toBeUndefined();
    // Identical outcome with a valid, matching, fresh approval present: the
    // approval confers nothing on its own, and evaluate() (a stateless pure
    // function, D28) carries no state from the approval past this one call.
    // The deny also hands the PEP nothing permit-shaped to act on either way.
    expect(withApproval.decision).toBe(false);
    expect(withApproval.context.denial_reason).toBe("out_of_authority");
    expect(withApproval.context.conditions).toBeUndefined();
    expect(withApproval.context.entry_digest).toBeUndefined();
  });

  it("a valid approval permits once but is not a standing grant: the identical action, decided fresh without it, denies action_approval_required again", async () => {
    const gatedView: MissionView = {
      ...view(),
      authority_set: [
        {
          type: "mission_resource_access",
          resource: RESOURCE,
          actions: ["payments:invoice.read"],
          constraints: { requires_action_approval: true },
        },
      ],
    };
    const opts = {
      view: gatedView,
      fga: alwaysAllowFga,
      modelId: "unit-test-model",
      now: () => NOW,
      stalenessBoundSeconds,
      relationForAction,
      maxApprovalAgeSeconds: 300,
    };
    const approval: ActionApproval = { id: "apr_1", approved_at: NOW.toISOString(), parameter_digest: "sha-256:pd" };
    const withApproval = await evaluate(
      req({
        context: {
          audience: RESOURCE,
          mission: { id: "msn_test_1", issuer: "https://as.test", authority_hash: "sha-256:testhash" },
          parameter_digest: "sha-256:pd",
          action_approval: approval,
        },
      }),
      opts,
    );
    expect(withApproval.decision, JSON.stringify(withApproval.context)).toBe(true);

    // The identical action, decided fresh, with the approval no longer
    // presented: if it had persisted as a standing grant, this would still
    // permit. It does not, because evaluate() carries no state between calls
    // (@spec runtime#action-approval: "a persisted grant ... is a governance
    // state change the fresh decision observes", never a property of the
    // approval itself).
    const withoutApproval = await evaluate(
      req({
        context: {
          audience: RESOURCE,
          mission: { id: "msn_test_1", issuer: "https://as.test", authority_hash: "sha-256:testhash" },
          parameter_digest: "sha-256:pd",
        },
      }),
      opts,
    );
    expect(withoutApproval.decision).toBe(false);
    expect(withoutApproval.context.denial_reason).toBe("action_approval_required");
  });
});

describe("runtime decision gates are independently necessary (@spec runtime#decision)", () => {
  it("a stale freshness failure denies even though authority and the Resource-policy/FGA check both permit", async () => {
    const dec = await evaluate(
      req({
        action: { name: "payments:invoice.read" },
        context: {
          audience: RESOURCE,
          mission: { id: "msn_test_1", issuer: "https://as.test", authority_hash: "sha-256:testhash" },
          action_class: "irreversible_action", // 30s staleness bound
          freshness: { observed_at: "2026-07-22T11:58:00Z", source: "status" }, // 120s stale
        },
      }),
      { view: view(), fga: alwaysAllowFga, modelId: "unit-test-model", now: () => NOW, stalenessBoundSeconds, relationForAction },
    );
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("stale_state");
    // A deny hands the PEP no permit-shaped fields to act on.
    expect(dec.context.conditions).toBeUndefined();
    expect(dec.context.entry_digest).toBeUndefined();
  });

  // NOT asserted: the deny-terminal half of the anchor's OTHER sentence
  // ("On a deny, the PEP MUST refuse the action; a deny is terminal for the
  // attempted action"). A deny carrying no permit-shaped fields (asserted
  // above and in the approval test) shows the PEP has nothing actionable to
  // proceed on, but terminality itself (no retry, no proceeding on a cached
  // permit past this evaluation) is the PEP's own behavior on receiving that
  // deny, which evaluate() has no PEP to exercise and this file does not
  // assert.
});

/**
 * @spec runtime#read-binding: finding 3 (PR #612 author review), a bound bulk
 * read names a COLLECTION, not one representative object. The request
 * shape's `resource.properties.vendor_ids` is what makes evaluateInner check
 * every named member independently (step 6a); these two unconditional tests
 * use a stub `Fga` that denies one specific vendor object while allowing
 * every other check, which no LIVE OpenFGA check against this domain model
 * can produce (the model's only grant is the ephemeral contextual tuple that
 * always mirrors whichever entry the caller names, and there is no genuine
 * independent Resource-policy denial surface here yet, a known, disclosed
 * limitation; see the manifest row's notes). The stub is what proves the
 * MECHANISM (every named member is actually checked, not just the
 * representative), independent of whether this domain model can produce a
 * real per-member disagreement today.
 */
describe("a bound bulk read's Resource-policy check covers every returned vendor, not just one representative (@spec read-binding)", () => {
  const LIST_RESOURCE = "http://localhost:4403/mcp";
  const listView: MissionView = {
    id: "msn_test_1",
    issuer: "https://as.test",
    state: "active",
    version: 1,
    authority_hash: "sha-256:testhash",
    authority_set: [
      {
        type: "mission_resource_access",
        resource: LIST_RESOURCE,
        actions: ["payments:invoice.list"],
        constraints: { vendors: ["acme", "globex"] },
      },
    ],
  };
  const listReq = (vendorIds: string[]): EvaluationRequest => ({
    subject: { id: "alice" },
    resource: { type: "vendor", id: vendorIds[0] as string, properties: { vendor_id: vendorIds[0], vendor_ids: vendorIds } },
    action: { name: "payments:invoice.list" },
    context: { audience: LIST_RESOURCE, mission: { id: "msn_test_1", issuer: "https://as.test", authority_hash: "sha-256:testhash" } },
  });
  const listOpts = (fga: Fga) => ({
    view: listView,
    fga,
    modelId: "unit-test-model",
    now: () => NOW,
    stalenessBoundSeconds,
    relationForAction,
  });

  it("Mission authority includes two vendors; Resource policy denies one: the whole read denies out_of_authority, never a silently narrowed permit", async () => {
    const denyGlobex = {
      checkWithContext: async (check: { object: string }) => check.object !== "vendor:globex",
    } as unknown as Fga;
    const dec = await evaluate(listReq(["acme", "globex"]), listOpts(denyGlobex));
    expect(dec.decision, JSON.stringify(dec.context)).toBe(false);
    expect(dec.context.denial_reason).toBe("out_of_authority");
    // No permit-shaped fields on this deny: nothing for a PEP to act on.
    expect(dec.context.conditions).toBeUndefined();
  });

  it("Mission authority includes two vendors; Resource policy permits both: the read permits", async () => {
    const allow = { checkWithContext: async () => true } as unknown as Fga;
    const dec = await evaluate(listReq(["acme", "globex"]), listOpts(allow));
    expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
  });

  it("without vendor_ids (a single-object request), only the named representative is checked, unaffected by the collection check", async () => {
    const req: EvaluationRequest = {
      subject: { id: "alice" },
      resource: { type: "vendor", id: "acme", properties: { vendor_id: "acme" } },
      action: { name: "payments:invoice.list" },
      context: { audience: LIST_RESOURCE, mission: { id: "msn_test_1", issuer: "https://as.test", authority_hash: "sha-256:testhash" } },
    };
    const denyGlobex = {
      checkWithContext: async (check: { object: string }) => check.object !== "vendor:globex",
    } as unknown as Fga;
    const dec = await evaluate(req, listOpts(denyGlobex));
    // globex is never named, so its denial is never consulted.
    expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
  });
});
