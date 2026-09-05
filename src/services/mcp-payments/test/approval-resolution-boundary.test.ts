import { describe, expect, it } from "vitest";
import type { Fga } from "@mission/pdp";
import { createEphemeralEvidenceKeys, EvidenceStore, PaymentsStore, Pep, sourceDigestOf, type PepDeps, type TokenFacts } from "../src/index.js";
import { TOOLS } from "../src/server.js";

function build() {
  const keys = createEphemeralEvidenceKeys();
  const evidence = new EvidenceStore(keys.signing, keys.resolver);
  const deps: PepDeps = {
    evidence, payments: new PaymentsStore(), decide: keys.decide,
    fga: { checkWithContext: async () => true } as unknown as Fga,
    modelId: "test", loadView: () => undefined, instanceEpoch: "test-759",
    sourceDigest: sourceDigestOf({ name: "payments" }),
    allowedFreshnessSources: new Set(["load_view"]), requiresActionApproval: () => false, observe: () => {},
  };
  return { pep: new Pep(deps), evidence };
}
const token: TokenFacts = { sub: "alice", clientId: "ap-agent", cnfJkt: "agent-jkt", mission: { id: "claimed-mission", issuer: "https://issuer.test" } };

describe("approval resolution is outside the mediated tool boundary (#759)", () => {
  it("approval-resolution tool names refuse unknown_tool and retain one PEP Refusal Record", async () => {
    for (const tool of ["adjudicate_approval", "approve_task"]) {
      const { pep, evidence } = build();
      expect(await pep.enforce(tool, { decision: "approve", approver: "bob" }, token)).toMatchObject({ permitted: false, refusal_reason: "unknown_tool" });
      expect(evidence.all()).toHaveLength(1);
      expect(evidence.all()[0]).toMatchObject({ kind: "refusal" });
      expect(JSON.stringify(evidence.all()[0])).toContain('"role":"pep"');
    }
  });

  it("the catalog has no approval-resolution action and retained PEP dependencies have no approval capability", () => {
    expect(TOOLS.every(t => !/approv|adjudicat|resolv/i.test(t.action))).toBe(true);
    const { pep } = build();
    const root = (pep as unknown as { deps: PepDeps }).deps;
    const seen = new WeakSet<object>();
    const visit = (value: unknown, path: string) => {
      if (!value || (typeof value !== "object" && typeof value !== "function") || seen.has(value as object)) return;
      seen.add(value as object);
      for (const [name, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
        if (!("value" in descriptor)) continue;
        const member = descriptor.value;
        expect(typeof member === "function" && /^(approve|adjudicate|resolveMissionApproval|completeMissionApproval|denyMissionApproval)$/.test(name), path + "." + name).toBe(false);
        // deps.decide is the legitimate PDP decision function, not approval resolution.
        if (member && typeof member === "object" && (Object.getPrototypeOf(member) === Object.prototype || Array.isArray(member))) visit(member, path + "." + name);
      }
    };
    visit(root, "deps");
  });
});
