/**
 * @spec draft-mcguinness-mission-runtime-evidence.md#execution-evidence-object
 * (Retention), draft-mcguinness-mission-runtime.md#record-integrity (#821,
 * D814): the PEP's evidence retention store as `composeStack` opens it, on its
 * configured file, across a restart of the composed stack.
 *
 * A restart is a closed stack recomposed on the same store files. Only the
 * OpenFGA client is stubbed, as `outcome-reconciler-stack.test.ts` does; the
 * kernel, PEP, PDP, stores and decision channel are real, so this file never
 * skips. The kernel is in memory, so no Mission survives the restart: the
 * case reads what the file kept.
 */

import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, type MockInstance, vi } from "vitest";
import { CANONICAL_RESOURCE, credentialAuthorityFrom, type TokenFacts } from "@mission/mcp-payments";
import { type DecisionEvidenceObject, Fga } from "@mission/pdp";
import { approveDemoMission, composeStack, type DemoStack } from "../src/stack.js";

const tempClaimsFile = (): string => join(mkdtempSync(join(tmpdir(), "demo-claims-")), "claims.sqlite");
const tempReservationsFile = (): string =>
  join(mkdtempSync(join(tmpdir(), "demo-reservations-")), "write-reservations.sqlite");

/** Release everything a composed stack without the AS holds, every store file's lock included. */
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

/** A refusal before any decision under one Mission: a PEP-emitted record that takes the PEP's next sequence value. */
const refusalFor = (id: string, issuer: string) => ({
  missionId: id,
  mission: { id, issuer },
  audience: CANONICAL_RESOURCE,
  action: { name: "payments:unknown" },
  denial_reason: "request_unsupported",
});

describe("the composed stack's PEP evidence retention across a restart (@spec runtime-evidence#execution-evidence-object, runtime#record-integrity, #821)", () => {
  let fgaBootstrap: MockInstance;
  beforeAll(() => {
    fgaBootstrap = vi.spyOn(Fga, "bootstrap").mockResolvedValue({
      fga: { checkWithContext: async () => true, checkStored: async () => true, client: { write: async () => ({}) }, modelId: "test" } as unknown as Fga,
      storeId: "test",
      modelId: "test",
    });
  });
  afterAll(() => fgaBootstrap.mockRestore());

  it("a restarted stack reopens the PEP's retention file with the first boot's records, and the PEP's per-Mission sequence continues past the values they carry", async () => {
    const options = {
      openfgaUrl: "http://unused.test",
      presharedKey: "unused",
      claimsFile: tempClaimsFile(),
      writeReservationsFile: tempReservationsFile(),
      resourcePolicyStore: { bootstrap: "development" } as const,
    };
    const before = await composeStack(options);
    let decision: DecisionEvidenceObject;
    let missionId: string;
    let refusalSequence: number;
    try {
      const mission = approveDemoMission(before);
      const view = before.viewFor(mission.id);
      if (!view) throw new Error("no view");
      missionId = view.id;
      const token: TokenFacts = {
        sub: "alice",
        iss: before.issuer,
        clientId: "ap-agent",
        cnfJkt: "jkt",
        mission: { id: view.id, issuer: view.issuer, authority_hash: view.authority_hash },
        credentialAuthority: credentialAuthorityFrom(view.authority_set),
      };
      const permit = await before.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` }, token);
      expect(permit.permitted, JSON.stringify(permit.denial_reason)).toBe(true);
      decision = permit.decision?.context.decision_evidence as DecisionEvidenceObject;
      // A PEP-emitted record under the same Mission: a refusal before any decision.
      const refused = await before.evidence.recordRefusal(CANONICAL_RESOURCE, "pep", refusalFor(view.id, view.issuer));
      refusalSequence = refused.content.sequence;
      expect(before.evidenceRetention.get("decision", decision.evidence_id)).toBeDefined();
    } finally {
      await closeStack(before);
    }

    const after = await composeStack(options);
    try {
      // The first boot's records came back from the file.
      expect(after.evidenceRetention.get("decision", decision.evidence_id)).toBeDefined();
      expect(after.evidence.all().some((e) => e.kind === "decision" && e.content.evidence_id === decision.evidence_id)).toBe(true);
      // The PEP's next record for that Mission takes the value after the one
      // the first boot's refusal carries, never that value again.
      const next = await after.evidence.recordRefusal(CANONICAL_RESOURCE, "pep", refusalFor(missionId, decision.mission.issuer));
      expect(next.content.sequence).toBe(refusalSequence + 1);
    } finally {
      await closeStack(after);
    }
  });
});
