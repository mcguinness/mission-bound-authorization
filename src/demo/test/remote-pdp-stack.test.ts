import { describe, expect, it, vi } from "vitest";
import { Fga, type RuntimePosture } from "@mission/pdp";
import type { TokenFacts } from "@mission/mcp-payments";
import { approveDemoMission, composeStack } from "../src/stack.js";

describe("demo configured remote PDP route", () => {
  it("wires a real decision hop behind the flag and fails closed when that PDP stops", async () => {
    // Only the unrelated FGA dependency is stubbed. Kernel approval, catalogs,
    // decision channel, PDP evidence, PEP retention and resource dispatch are real.
    const connect = vi.spyOn(Fga, "connect").mockResolvedValue({ fga: { checkWithContext: async () => true } as unknown as Fga, modelId: "test" });
    const stack = await composeStack({ openfgaUrl: "http://unused.test", presharedKey: "unused", pdpMode: "remote" });
    try {
      const mission = approveDemoMission(stack);
      const view = stack.viewFor(mission.id)!;
      const token: TokenFacts = { sub: "alice", clientId: "ap-agent", cnfJkt: "jkt", mission: { id: view.id, issuer: view.issuer, authority_hash: view.authority_hash } };
      const statement = stack.server.protectedResourceMetadata().enforcement_scope_statement as RuntimePosture;
      expect(statement.state_source.pdp_unavailability_posture).toBe("deny");
      expect(statement.remote_decision_channels).toHaveLength(1);
      expect((await stack.server.callReadTool("get_invoice", { invoice_id: "inv-seed" }, token)).ok).toBe(true);
      await stack.decisionChannel.close();
      const refused = await stack.server.callReadTool("get_invoice", { invoice_id: "inv-seed" }, token);
      expect(refused.refusal_reason).toBe("pdp_unreachable");
      expect(refused.result).toBeUndefined();
      expect(stack.evidence.forMission(view.id).filter(e => e.kind === "refusal")).toHaveLength(1);
    } finally {
      connect.mockRestore();
      await stack.decisionChannel.close();
      await stack.masGovernedChannel?.close();
      stack.authServer?.closeAuthServer();
      stack.payments.db.close();
      stack.kernel.db.close();
    }
  });
});
