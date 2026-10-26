/**
 * @spec runtime-evidence#decision-evidence-object, runtime#record-integrity
 * (#821, D814): the shipped PDP's Decision Evidence counters, as
 * `composeStack` wires them. The decision point binds its emitter to the
 * claim domain's durable sequence source, so the counters live in the PDP's
 * own claim file (`topology.json` `stores.pdpIdempotencyClaims.file`) and a
 * PDP restarted on that file continues each Mission's stream.
 *
 * Only the OpenFGA client is stubbed, as `outcome-reconciler-stack.test.ts`
 * does; the kernel, PEP, PDP and claim domain are real, so this file never
 * skips.
 */

import { generateKeyPairSync, randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { credentialAuthorityFrom, type TokenFacts } from "@mission/mcp-payments";
import {
  createDecisionEvidenceEmitter,
  type DecisionEvidenceObject,
  evaluationRequestDigest,
  Fga,
  newRecordId,
  openIdempotencyClaimDomain,
  RUNTIME_POSTURE,
} from "@mission/pdp";
import { afterAll, beforeAll, describe, expect, it, type MockInstance, vi } from "vitest";
import { approveDemoMission, composeStack, type DemoStack } from "../src/stack.js";

const tempClaimsFile = (): string => join(mkdtempSync(join(tmpdir(), "demo-claims-")), "claims.sqlite");
const tempReservationsFile = (): string =>
  join(mkdtempSync(join(tmpdir(), "demo-reservations-")), "write-reservations.sqlite");

/** Release everything a composed stack without the AS holds, the claim file's lock included. */
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

describe("the composed stack's PDP keeps its Decision Evidence counters in its claim file (@spec runtime-evidence#decision-evidence-object, runtime#record-integrity, #821)", () => {
  let fgaBootstrap: MockInstance;
  beforeAll(() => {
    fgaBootstrap = vi.spyOn(Fga, "bootstrap").mockResolvedValue({
      fga: { checkWithContext: async () => true, checkStored: async () => true, client: { write: async () => ({}) }, modelId: "test" } as unknown as Fga,
      storeId: "test",
      modelId: "test",
    });
  });
  afterAll(() => fgaBootstrap.mockRestore());

  it("a PDP restarted on the shipped stack's claim file continues a Mission's Decision Evidence sequence where the stack left it", async () => {
    const claimsFile = tempClaimsFile();
    const stack = await composeStack({
      openfgaUrl: "http://unused.test",
      presharedKey: "unused",
      claimsFile,
      writeReservationsFile: tempReservationsFile(),
      resourcePolicyStore: { bootstrap: "development" },
    });
    const records: DecisionEvidenceObject[] = [];
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
      for (let i = 0; i < 2; i += 1) {
        const decided = await stack.pep.enforce(
          "execute_wire_transfer",
          { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` },
          token,
        );
        expect(decided.permitted, JSON.stringify(decided.denial_reason)).toBe(true);
        records.push(decided.decision?.context.decision_evidence as DecisionEvidenceObject);
      }
    } finally {
      await closeStack(stack);
    }
    expect(records.map((r) => r.sequence)).toEqual([0, 1]);
    const [last] = records.slice(-1) as [DecisionEvidenceObject];

    // The restarted PDP: its claim domain reopened on the same file, a fresh
    // emission key, the same emitter id.
    const reopened = openIdempotencyClaimDomain({
      file: claimsFile,
      owner: RUNTIME_POSTURE.pdps[0] as string,
      statement: RUNTIME_POSTURE,
    });
    try {
      const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
      const restarted = createDecisionEvidenceEmitter({
        signer: { kid: "pdp-restarted", key: privateKey },
        emitterId: last.emitter.id,
        audience: last.audience,
        sequences: reopened.evidenceSequences(),
      });
      const evaluation_id = newRecordId("evl");
      const next = await restarted.emit({
        mission: last.mission,
        subject: { id: "alice" },
        resource: last.resource,
        action: last.action,
        audience: last.audience,
        evaluation_id,
        decision: "deny",
        denial_reason: "out_of_authority",
        evaluated_at: new Date().toISOString(),
        evaluation_request_digest: evaluationRequestDigest({ evaluation_id }),
      });
      expect(next.sequence).toBe(2);
    } finally {
      reopened.close();
    }
  });
});
