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

import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { CANONICAL_RESOURCE, DEMO_AGENT_PROPOSAL, DERIVATION_POLICY } from "@mission/demo-data";
import { evaluate, relationForAction, stalenessBoundSeconds, type Fga, type MissionView } from "@mission/pdp";
import { deriveAuthoritySet, validateAuthorityProposal, validateMissionIntent } from "../src/index.js";

const ISS = "https://as.test";
const MISSION_ID = "msn_shipped_config_test";

/** The repo-root `config/` directory the reference deployment ships. */
const SHIPPED_CONFIG_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "config",
);

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
 * @spec mission#mission-record (issue #647) — the shipped deployment ceiling on
 * a Mission's granted lifetime, and the loader that validates it. The reference
 * deployment declares NO ceiling of its own (`null`, mirroring
 * `derivation_limit_ceiling`), so the demo's observable Mission lifetimes are
 * exactly the requested ones; the narrowing arm is proven with an injected
 * ceiling in `kernel.test.ts`. What must not regress is the VALIDATION: a
 * lifetime that is not a positive integer is a fail-fast configuration error,
 * never a silently-ignored member.
 */
describe("config/policy.json max_mission_lifetime_s (@spec mission#mission-record)", () => {
  /** Load demo-data afresh against a copy of the shipped config whose
   *  policy.json carries `value` for max_mission_lifetime_s. */
  async function loadWith(value: unknown): Promise<{ max_mission_lifetime_s: number | null }> {
    const dir = mkdtempSync(join(tmpdir(), "mission-policy-"));
    cpSync(SHIPPED_CONFIG_DIR, dir, { recursive: true });
    const policy = JSON.parse(readFileSync(join(dir, "policy.json"), "utf8")) as Record<string, unknown>;
    if (value === undefined) delete policy.max_mission_lifetime_s;
    else policy.max_mission_lifetime_s = value;
    writeFileSync(join(dir, "policy.json"), JSON.stringify(policy));
    const previous = process.env.MISSION_CONFIG_DIR;
    process.env.MISSION_CONFIG_DIR = dir;
    vi.resetModules();
    try {
      const mod = (await import("@mission/demo-data")) as typeof import("@mission/demo-data");
      return mod.DERIVATION_POLICY;
    } finally {
      if (previous === undefined) delete process.env.MISSION_CONFIG_DIR;
      else process.env.MISSION_CONFIG_DIR = previous;
      rmSync(dir, { recursive: true, force: true });
    }
  }

  it("the shipped value loads: this deployment declares no lifetime ceiling", () => {
    expect(DERIVATION_POLICY.max_mission_lifetime_s).toBeNull();
  });

  it("an absent member means the same thing as an explicit null", async () => {
    expect((await loadWith(undefined)).max_mission_lifetime_s).toBeNull();
  });

  it("a positive integer loads as this deployment's ceiling, in seconds", async () => {
    expect((await loadWith(2_592_000)).max_mission_lifetime_s).toBe(2_592_000);
  });

  it("zero, a negative, a non-integer, or a non-number is a ConfigError", async () => {
    for (const bad of [0, -1, 1.5, "3600"]) {
      await expect(loadWith(bad)).rejects.toThrow(
        /policy.max_mission_lifetime_s must be an integer >= 1, or null/,
      );
    }
  });
});

