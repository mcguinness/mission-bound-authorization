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
import {
  AUTHORITY_SOURCES,
  CANONICAL_RESOURCE,
  DEMO_AGENT_PROPOSAL,
  DERIVATION_POLICY,
  GOVERNED_POLICIES,
  TOPOLOGY,
} from "@mission/demo-data";
import { evaluate, relationForAction, stalenessBoundSeconds, type Fga, type MissionView } from "@mission/pdp";
import {
  buildAuthorizationServer,
  deriveAuthoritySet,
  validateAuthorityProposal,
  validateAuthoritySourceCatalog,
  validateMissionIntent,
} from "../src/index.js";

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
 * @spec mission#authority-sources, mission#approval-event — the SHIPPED
 * `config/authority-sources.json` and `config/governed-policy.json`, and the
 * fact that the real AS assembly is wired with them. The kernel refuses
 * construction without a catalog, so a shipped AS cannot run with no declared
 * sources; these assertions cover the content of the one it does run with.
 */
describe("shipped authority-source catalog (@spec mission#authority-sources)", () => {
  it("declares a trusted source for every shipped client, with no duplicate identity", () => {
    validateAuthoritySourceCatalog(AUTHORITY_SOURCES as never);
    const declared = new Set(AUTHORITY_SOURCES.entries.flatMap((e) => e.clients));
    for (const client of ["ap-agent", "subagent-invoice-extractor", "governed-agent"]) {
      expect(declared.has(client)).toBe(true);
    }
  });

  it("declares the work-product agents as user-delegated, the source their Missions draw on", () => {
    // agent-A1 and parent-P approve for the human Subject alice under bob's
    // approval: an agent acting on a person's delegated authority, so the
    // source is user_delegated. A `service_owned` declaration would misstate
    // the provenance AND refuse at gate 4, alice being a human principal.
    const declared = AUTHORITY_SOURCES.entries.find((e) => e.clients.includes("agent-A1"));
    expect(declared?.type).toBe("user_delegated");
    expect(declared?.clients).toContain("parent-P");
    expect(declared?.activators).toContain("bob");
    expect(AUTHORITY_SOURCES.humanPrincipals).toContain("alice");
  });

  it("resolves the organizational source's ceiling and digest from the governed policy", () => {
    const organizational = AUTHORITY_SOURCES.entries.find((e) => e.type === "organizational");
    expect(organizational).toBeDefined();
    const governed = GOVERNED_POLICIES.find(
      (g) =>
        g.id === organizational?.policy?.id && g.version === organizational?.policy?.version,
    );
    expect(governed).toBeDefined();
    // The ceiling is the governed policy's own, never a second copy (compared
    // through the same CANONICAL_RESOURCE remap the catalog applies, so this
    // holds under MCP_PAYMENTS_RESOURCE too), and the digest is computed at
    // load, never read from the wire.
    const remapped = governed?.ceiling.map((c) =>
      c.resource === TOPOLOGY.resources.payments ? { ...c, resource: CANONICAL_RESOURCE } : c,
    );
    expect(organizational?.ceiling).toEqual(remapped);
    expect(organizational?.policy?.digest).toBe(governed?.digest);
    expect(organizational?.policy?.digest).toMatch(/^sha-256:[A-Za-z0-9_-]{43}$/);
  });

  it("the real AS assembly runs with the shipped catalog and refuses an undeclared client", async () => {
    const as = await buildAuthorizationServer({
      issuer: "http://localhost:14599",
      allowHeadlessAdjudication: true,
    });
    // Gate 1 fail-closed: a client the catalog does not declare resolves no
    // source at all, which only a wired catalog can produce.
    expect(() => as.kernel.authoritySourceEntry("no-such-agent")).toThrow(
      /no trusted authority source is declared/,
    );
    expect(as.kernel.authoritySourceEntry("governed-agent").type).toBe("organizational");
  });
});
