/**
 * @spec authzen#context-compensation-link, runtime#compound-actions (#252):
 * the composed stack establishes a compensation's link from its own retained
 * evidence. The PEP re-verifies the committed wire's Decision Evidence and its
 * Execution Evidence through the stack's boundary-bound resolver, so that
 * resolver holds the executor's key as well as the PDP's; without it the
 * Execution Evidence does not verify and no compensation links anything.
 *
 * The demo Mission carries no authority to compensate, so the compensating
 * request reaches the PDP with its link and is denied there, which is the
 * observable here: the link established, recorded on the denial's Decision
 * Evidence, and nothing reversed.
 *
 * Only the OpenFGA client is stubbed, as `outcome-reconciler-stack.test.ts`
 * does, so this file never skips.
 */

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it, type MockInstance, vi } from "vitest";
import { CANONICAL_RESOURCE, credentialAuthorityFrom, type DecisionEvidence, type TokenFacts } from "@mission/mcp-payments";
import { Fga } from "@mission/pdp";
import { approveDemoMission, composeStack, type DemoStack } from "../src/stack.js";

const tempFile = (prefix: string, name: string): string => join(mkdtempSync(join(tmpdir(), prefix)), name);

async function closeStack(stack: DemoStack): Promise<void> {
  await stack.reconciler.stop();
  await stack.decisionChannel.close();
  await stack.masGovernedChannel?.close();
  stack.pdpClaims.close();
  stack.writeReservations.close();
  stack.payments.db.close();
  stack.kernel.db.close();
}

describe("the composed stack links a compensation to its committed original (@spec authzen#context-compensation-link, runtime#compound-actions, #252)", () => {
  let fgaBootstrap: MockInstance;
  beforeAll(() => {
    fgaBootstrap = vi.spyOn(Fga, "bootstrap").mockResolvedValue({
      fga: { checkWithContext: async () => true, checkStored: async () => true, client: { write: async () => ({}) }, modelId: "test" } as unknown as Fga,
      storeId: "test",
      modelId: "test",
    });
  });
  afterAll(() => fgaBootstrap.mockRestore());

  it("re-verifies the committed wire's retained records through the stack's resolver and carries the link to the PDP, which denies a compensation the Mission does not authorize", async () => {
    const stack = await composeStack({
      openfgaUrl: "http://unused.test",
      presharedKey: "unused",
      claimsFile: tempFile("demo-claims-", "claims.sqlite"),
      writeReservationsFile: tempFile("demo-reservations-", "write-reservations.sqlite"),
      resourcePolicyStore: { bootstrap: "development" },
    });
    try {
      const mission = approveDemoMission(stack);
      const view = stack.viewFor(mission.id);
      if (!view) throw new Error("no view");
      // The credential names the compensating action, so the request passes
      // the credential bound and the Mission's own authority decides it.
      const token: TokenFacts = {
        sub: "alice",
        iss: stack.issuer,
        clientId: "ap-agent",
        cnfJkt: "jkt",
        mission: { id: view.id, issuer: view.issuer, authority_hash: view.authority_hash },
        credentialAuthority: credentialAuthorityFrom([
          ...view.authority_set,
          { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:payment.reverse"] },
        ]),
      };
      const wire = await stack.server.callTransactionTool(
        "execute_wire_transfer",
        { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` },
        token,
      );
      expect(wire.ok, JSON.stringify(wire)).toBe(true);
      const records = stack.evidence.forMission(view.id);
      const original = records.find(
        (e): e is DecisionEvidence => e.kind === "decision" && e.content.decision === "permit" && e.content.action_phase === "commit",
      );
      const completed = records.find((e) => e.kind === "execution" && e.content.outcome === "completed");
      if (!original || completed?.kind !== "execution") throw new Error("the wire left no permit or completed record");
      expect(await stack.evidence.verifyRetained(original)).toBe(true);
      expect(await stack.evidence.verifyRetained(completed)).toBe(true);

      const reversed = await stack.server.callTransactionTool(
        "reverse_wire_transfer",
        { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` },
        token,
      );
      expect(reversed).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
      const compensating = stack.evidence
        .forMission(view.id)
        .filter((e): e is DecisionEvidence => e.kind === "decision" && e.content.action.name === "payments:payment.reverse");
      expect(compensating.map((d) => [d.content.decision, d.content.compensates_evaluation_id])).toEqual([
        ["deny", original.content.evaluation_id],
      ]);
      expect(stack.connectors.reversalEntries()).toHaveLength(0);
    } finally {
      await closeStack(stack);
    }
  });
});
