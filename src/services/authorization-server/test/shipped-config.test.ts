/**
 * @spec mission#authorization-derivation, runtime#input-parameters (issue #743)
 *
 * The SHIPPED `config/policy.json`, run through the real derivation and PDP
 * evaluation path with the demo's own proposal shape (`demo/src/agent-run.ts`).
 * No other test exercises the shipped config directly: every end-to-end
 * fixture builds its own Authority Set, and only `demo-data` reads
 * `config/policy.json`, which is why a configuration that could not
 * authorize its own demo passed CI (#743).
 *
 * The payments ceiling is two entries (money-bearing / read-only), split so
 * a read action stops inheriting a `max_amount` it can never satisfy. The
 * demo's own proposal is split the same way (agent-run.ts): a proposal that
 * still bundled a money constraint onto a mixed read+money entry would
 * re-derive the same defect from the untrusted-proposal side (the ceiling's
 * absent cap does not clamp a proposal's own; it inherits it unchanged, the
 * same rule that makes a ceiling's cap binding when a proposal omits one).
 *
 * @spec review #745 finding 3 — DEMO_PROPOSAL below is DEMO_AGENT_PROPOSAL
 * (@mission/demo-data) run through validateAuthorityProposal, not a
 * hand-copied duplicate of agent-run.ts's literal. agent-run.ts imports the
 * SAME constant, so this test consumes the proposal the shipped demo
 * actually sends: a later change to the demo's proposal shape changes this
 * test's input too, instead of leaving a stale copy green.
 */

import { describe, expect, it } from "vitest";
import { CANONICAL_RESOURCE, DEMO_AGENT_PROPOSAL, DERIVATION_POLICY, MAS_JOIN } from "@mission/demo-data";
import { evaluate, relationForAction, stalenessBoundSeconds, type Fga, type MissionView } from "@mission/pdp";
import { deriveAuthoritySet, validateAuthorityProposal, validateMissionIntent } from "../src/index.js";

const ISS = "https://as.test";
const MISSION_ID = "msn_shipped_config_test";

/** The demo's own PAR proposal (@mission/demo-data's DEMO_AGENT_PROPOSAL, agent-run.ts's single source), validated. */
const DEMO_PROPOSAL = validateAuthorityProposal(JSON.stringify(DEMO_AGENT_PROPOSAL), [CANONICAL_RESOURCE]);

function deriveDemoAuthoritySet() {
  const intent = validateMissionIntent(
    JSON.stringify({
      goal: "Pay the payable Acme invoices within your mission's limits.",
      target_resources: [CANONICAL_RESOURCE],
      expires_at: "2027-01-01T00:00:00Z",
    }),
  );
  return deriveAuthoritySet(intent, DERIVATION_POLICY as never, DEMO_PROPOSAL);
}

const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

function viewFor(authoritySet: ReturnType<typeof deriveDemoAuthoritySet>): MissionView {
  return {
    id: MISSION_ID,
    issuer: ISS,
    state: "active",
    version: 1,
    authority_hash: "sha-256:testhash",
    authority_set: authoritySet,
    subject: { iss: ISS, sub: "alice" },
    client_id: "ap-agent",
  };
}

describe("shipped config/policy.json authorizes its own demo (#743)", () => {
  it("derives a read-only entry with no max_amount and a money entry clamped to the ceiling", () => {
    const derived = deriveDemoAuthoritySet();
    const readEntry = derived.find((e) => e.actions.includes("payments:invoice.list"));
    const payEntry = derived.find((e) => e.actions.includes("payments:payment.execute"));
    // Proves the split did not drop the money action from the Authority Set
    // entirely: the failure mode of matching a mixed proposal against only
    // the FIRST same-resource ceiling entry (the kernel's prior `find`-based
    // matching, fixed alongside the config split).
    expect(payEntry).toBeDefined();
    expect(readEntry?.constraints?.max_amount).toBeUndefined();
    // The ceiling's cap (500) wins over the client's over-ask (999999).
    expect(payEntry?.constraints?.max_amount?.amount).toBe("500.00");
  });

  it("list_invoices authorizes with no context.amount supplied", async () => {
    const derived = deriveDemoAuthoritySet();
    const decision = await evaluate(
      {
        subject: { id: "alice" },
        resource: { type: "vendor", id: "acme", properties: { vendor_id: "acme", vendor_ids: ["acme"] } },
        action: { name: "payments:invoice.list" },
        context: {
          audience: CANONICAL_RESOURCE,
          mission: { id: MISSION_ID, issuer: ISS, authority_hash: "sha-256:testhash" },
          // No context.amount: list_invoices supplies none (needsInvoice:
          // false, mcp-payments/src/pep.ts).
        },
      },
      {
        view: viewFor(derived),
        fga: alwaysAllowFga,
        modelId: "unit-test-model",
        now: () => new Date("2026-07-22T12:00:00Z"),
        stalenessBoundSeconds,
        relationForAction,
      },
    );
    expect(decision.decision).toBe(true);
  });

  it("payment.execute still refuses constraint_exceeded with no context.amount (the #733 guard, unweakened)", async () => {
    const derived = deriveDemoAuthoritySet();
    const decision = await evaluate(
      {
        subject: { id: "alice" },
        resource: { type: "invoice", id: "inv-1", properties: { vendor_id: "acme" } },
        action: { name: "payments:payment.execute" },
        context: {
          audience: CANONICAL_RESOURCE,
          mission: { id: MISSION_ID, issuer: ISS, authority_hash: "sha-256:testhash" },
          // No context.amount: a bound max_amount the PDP cannot evaluate
          // MUST refuse (#733), never fall through as unenforced. This
          // proves the fix did not simply disable the protection.
        },
      },
      {
        view: viewFor(derived),
        fga: alwaysAllowFga,
        modelId: "unit-test-model",
        now: () => new Date("2026-07-22T12:00:00Z"),
        stalenessBoundSeconds,
        relationForAction,
      },
    );
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("constraint_exceeded");
  });
});


/**
 * @spec authority-server#mission-join (#557)
 *
 * The SHIPPED `config/mas-join.json`, read through the same typed loader the
 * demo stack reads it with. Same motivation as the policy block above: the
 * demo stack is the only consumer, so a Join policy that could never
 * authorize its own demo would otherwise pass CI. The MAS-Join shape of that
 * defect is a `scope_actions` map covering no derived Authority Set entry,
 * which refuses `out_of_authority` on every joined request.
 */
describe("shipped config/mas-join.json authorizes a joined read of its own demo (#557)", () => {
  it("declares the payments resource governed, so the demo stack starts a MAS-governed route at all", () => {
    expect(MAS_JOIN.governed_resources).toContain(CANONICAL_RESOURCE);
  });

  it("maps every configured scope to actions this deployment can actually enforce", () => {
    const actions = Object.values(MAS_JOIN.scope_actions).flat();
    expect(actions.length).toBeGreaterThan(0);
    // relationForAction is the PDP's own recognition of an action; a scope
    // naming anything else would carry authority no resource can evaluate.
    for (const action of actions) expect(relationForAction(action), action).toBeDefined();
  });

  it("enumerates each delegate with its own non-negative integer max_depth ceiling (rule 4: explicit, never a default)", () => {
    const entries = Object.entries(MAS_JOIN.delegates);
    expect(entries.length).toBeGreaterThan(0);
    for (const [clientId, delegate] of entries) {
      expect(Number.isInteger(delegate.max_depth), clientId).toBe(true);
      expect(delegate.max_depth, clientId).toBeGreaterThanOrEqual(0);
    }
  });

  it("a shipped scope covers a shipped-derived Authority Set entry, so rule 8's first bound leaves something to permit", () => {
    // The SAME intersection the PEP's bound-1 filter runs
    // (services/mcp-payments/src/pep.ts): an entry survives only when the
    // credential's own authority covers every one of its actions.
    const derived = deriveDemoAuthoritySet();
    const covered = Object.values(MAS_JOIN.scope_actions).some((scopeActions) =>
      derived.some(
        (e) => e.resource === CANONICAL_RESOURCE && e.actions.every((a) => scopeActions.includes(a)),
      ),
    );
    expect(covered, JSON.stringify({ scope_actions: MAS_JOIN.scope_actions, derived })).toBe(true);
  });
});
