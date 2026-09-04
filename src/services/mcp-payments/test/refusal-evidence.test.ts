/**
 * @spec runtime-evidence#pre-decision-refusal
 *
 * Refusal Records are per-attempt, immutable, and append-only: a sustained
 * failure condition with a retrying agent yields one signed record per
 * attempt, never a record amended or replaced in place. This exercises
 * Pep.reverify() (the TOCTOU parameter-binding re-check immediately before
 * execution), which needs only the local PaymentsStore and EvidenceStore,
 * not OpenFGA, so it runs unconditionally.
 *
 * @spec draft-mcguinness-mission-runtime-evidence.md#decision-evidence-integrity
 * (issue #649): the retained Refusal Record is now genuinely signed
 * (`EvidenceStore.recordRefusal`); this test still covers only the
 * append-only/immutable/per-attempt half of the clause, not signature
 * verification itself (see `runtime-evidence-integrity.test.ts` for that).
 */

import type { Fga } from "@mission/pdp";
import { describe, expect, it } from "vitest";
import {
  buildEffectiveParams,
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  parameterDigest,
  PaymentsStore,
  Pep,
  sourceDigestOf,
  type TokenFacts,
} from "../src/index.js";

// @spec runtime-evidence#decision-evidence-object (#741): one bundle per
// test module. `signing`/`resolver` wire the PEP's store; `decide` is the
// decision point's entry point, which closes over the PDP's emission path.
const EVIDENCE_KEYS = createEphemeralEvidenceKeys();

const TOKEN: TokenFacts = {
  sub: "alice",
  clientId: "ap-agent",
  mission: { id: "msn_refusal", issuer: "https://as.test", authority_hash: "sha-256:refusalhash" },
  cnfJkt: "jkt-1",
};

describe("Refusal Records are per-attempt, immutable, and append-only", () => {
  it("a sustained parameter-mismatch condition yields one new record per attempt, never an amendment in place", async () => {
    const payments = new PaymentsStore();
    payments.seed(
      [{ id: "acme", name: "Acme", status: "approved" }],
      [
        {
          id: "inv-1",
          vendor_id: "acme",
          amount: "125.00",
          currency: "USD",
          payee_account: "acct-acme",
          status: "payable",
        },
      ],
    );
    const evidence = new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver);
    const pep = new Pep({
      decide: EVIDENCE_KEYS.decide,
      payments,
      evidence,
      // reverify()/recordRefusal() never touch deps.fga or deps.loadView.
      fga: {} as unknown as Fga,
      modelId: "unused",
      loadView: () => undefined,
      instanceEpoch: "epoch-1",
      sourceDigest: sourceDigestOf({ name: "payments" }),
    });

    const invoice = payments.getInvoice("inv-1");
    const vendor = payments.getVendor("acme");
    if (!invoice || !vendor) throw new Error("seed fixture missing");
    const effective = buildEffectiveParams({
      action: "payments:payment.execute",
      invoice,
      vendor,
      resource: CANONICAL_RESOURCE,
    });
    const wrongDigest = "sha-256:deliberately-wrong";
    expect(parameterDigest(effective)).not.toBe(wrongDigest);

    // Attempt 1: the same sustained failure condition (the caller's pinned
    // digest no longer matches the store's authoritative parameters).
    expect(await pep.reverify(effective, wrongDigest, TOKEN)).toBe(false);
    const afterFirst = evidence.forMission(TOKEN.mission.id);
    expect(afterFirst).toHaveLength(1);
    expect(afterFirst[0]?.kind).toBe("refusal");
    // A content snapshot, not a reference: `toBe` on the same array element
    // would pass even if record() mutated it in place later, since nothing
    // ever replaces the element with a different object. Only a snapshot
    // comparison catches an in-place amendment.
    const firstSnapshot = structuredClone(afterFirst[0]);

    // Attempt 2: a retrying agent hits the identical failure condition again.
    expect(await pep.reverify(effective, wrongDigest, TOKEN)).toBe(false);
    const afterSecond = evidence.forMission(TOKEN.mission.id);

    // Append-only: a second, distinct record now exists.
    expect(afterSecond).toHaveLength(2);
    expect(afterSecond[1]).not.toBe(afterSecond[0]);
    // Immutable: the first record's own content is byte-for-byte what it was
    // before the second attempt, never amended or replaced in place.
    expect(afterSecond[0]).toEqual(firstSnapshot);
  });
});
