/**
 * The demo console's story steps: the reconciliation Mission the console
 * holds beside its payments Mission derives read-only authority, and the
 * receipt step's rewrite of one retained record is caught by the operator
 * timeline's five-step verification, with the transparency log untouched.
 *
 * Only the OpenFGA client is stubbed, as `compensation-link-stack.test.ts`
 * does, so this file never skips.
 */

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it, type MockInstance, vi } from "vitest";
import { deriveAuthoritySet, validateAuthorityProposal, validateMissionIntent } from "@mission/authorization-server";
import { CANONICAL_RESOURCE, credentialAuthorityFrom, type TokenFacts } from "@mission/mcp-payments";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { Fga } from "@mission/pdp";
import { approveDemoMission, composeStack, type DemoStack } from "../src/stack.js";
import { reconciliationMissionIntent, rewriteExecutionOutcome } from "../src/server.js";

// The stack approves its demo Mission with a fixed expires_at, so the file runs
// on a controlled clock before it (#1968, D1133; D1091), installed before the
// modules that read the time at load.
const controlledClock = await vi.hoisted(async () => {
  const { CONTROLLED_CLOCK_MS, installControlledClock } = await import("./controlled-clock.helper.js");
  return installControlledClock(CONTROLLED_CLOCK_MS);
});
afterAll(() => controlledClock.restore());

const tempFile = (prefix: string, name: string): string => join(mkdtempSync(join(tmpdir(), prefix)), name);

async function closeStack(stack: DemoStack): Promise<void> {
  await stack.reconciler.stop();
  await stack.decisionChannel.close();
  await stack.masGovernedChannel?.close();
  stack.pdpClaims.close();
  stack.writeReservations.close();
  stack.evidenceRetention.close();
  stack.payments.db.close();
  stack.kernel.db.close();
}

describe("the console's reconciliation Mission", () => {
  it("derives read and list authority for Acme only, under the shipped derivation policy", () => {
    const { missionIntent, authorizationDetails } = reconciliationMissionIntent(new Date());
    const intent = validateMissionIntent(JSON.stringify((JSON.parse(missionIntent) as { intent: unknown }).intent));
    const proposal = validateAuthorityProposal(authorizationDetails, intent.target_resources);
    const derived = deriveAuthoritySet(intent, DERIVATION_POLICY as never, proposal);
    expect(derived.flatMap((e) => e.actions).sort()).toEqual(["payments:invoice.list", "payments:invoice.read"]);
    expect(derived.every((e) => e.resource === CANONICAL_RESOURCE)).toBe(true);
    expect(derived.flatMap((e) => (e.constraints as { vendors?: string[] } | undefined)?.vendors ?? [])).toEqual(["acme"]);
  });
});

describe("the console's record rewrite", () => {
  it("rewrites a completed Execution Evidence outcome to failed and names the action its operation key carries", () => {
    const record: Record<string, unknown> = {
      kind: "execution",
      op_key: "op:msn_abc:payments:payment.execute:commit:sha-256:xyz",
      content: { outcome: "completed" },
    };
    expect(rewriteExecutionOutcome(record)).toEqual({
      path: "content.outcome",
      from: "completed",
      to: "failed",
      action: "payments:payment.execute",
    });
    expect((record.content as { outcome: string }).outcome).toBe("failed");
  });

  it("leaves a record with no completed outcome unchanged", () => {
    const failed: Record<string, unknown> = { kind: "execution", content: { outcome: "suppressed" } };
    expect(rewriteExecutionOutcome(failed)).toBeUndefined();
    expect(failed).toEqual({ kind: "execution", content: { outcome: "suppressed" } });
    expect(rewriteExecutionOutcome({ kind: "decision" })).toBeUndefined();
  });
});

describe("an altered retained record fails the operator timeline's verification", () => {
  let fgaBootstrap: MockInstance;
  beforeAll(() => {
    fgaBootstrap = vi.spyOn(Fga, "bootstrap").mockResolvedValue({
      fga: { checkWithContext: async () => true, checkStored: async () => true, client: { write: async () => ({}) }, modelId: "test" } as unknown as Fga,
      storeId: "test",
      modelId: "test",
    });
  });
  afterAll(() => fgaBootstrap.mockRestore());

  it("reports the rewritten execution record as failed at the digest step, every other row verified, and the log unchanged", async () => {
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
      const token: TokenFacts = {
        sub: "alice",
        iss: stack.issuer,
        clientId: "ap-agent",
        cnfJkt: "jkt",
        mission: { id: view.id, issuer: view.issuer, authority_hash: view.authority_hash },
        credentialAuthority: credentialAuthorityFrom(view.authority_set),
      };
      const wire = await stack.server.callTransactionTool(
        "execute_wire_transfer",
        { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` },
        token,
      );
      expect(wire.ok, JSON.stringify(wire)).toBe(true);
      for (const ev of stack.evidence.forMission(view.id)) {
        const type = ev.kind === "decision" ? "decision-evidence" : ev.kind === "execution" ? "execution-evidence" : "refusal-record";
        await stack.publishEvidence(view.id, type, ev as unknown as Record<string, unknown>);
      }
      const operator = stack.bff.sessions.create("olivia", ["operator"]);

      const before = await stack.bff.timeline(operator, view.id);
      expect(before.length).toBeGreaterThan(1);
      expect(before.every((r) => r.verified)).toBe(true);
      const target = before.find((r) => r.evidence_type === "execution-evidence");
      if (!target) throw new Error("the wire published no execution record");

      const changes: Array<ReturnType<typeof rewriteExecutionOutcome>> = [];
      expect(stack.alterRetainedEvidence(target.digest, (ev) => void changes.push(rewriteExecutionOutcome(ev)))).toBe(true);
      expect(changes[0]).toMatchObject({ from: "completed", to: "failed" });

      const after = await stack.bff.timeline(operator, view.id);
      expect(after.map((r) => r.digest)).toEqual(before.map((r) => r.digest));
      const altered = after.find((r) => r.digest === target.digest);
      expect(altered).toMatchObject({ verified: false });
      expect(altered?.detail).toMatch(/^failed at step 5: evidence digest does not match/);
      expect(after.filter((r) => r.digest !== target.digest).every((r) => r.verified)).toBe(true);

      expect(stack.alterRetainedEvidence("sha-256:no-such-digest", () => {})).toBe(false);
    } finally {
      await closeStack(stack);
    }
  });
});
