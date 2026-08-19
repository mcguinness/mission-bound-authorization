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
 * "Signed" is not yet asserted here: EvidenceStore retains plain objects
 * (signing and SCITT registration are M10 future work, per its own header
 * comment), so this covers the append-only/immutable/per-attempt half of
 * the clause, not the signing half.
 */

import type { Fga } from "@mission/pdp";
import { describe, expect, it } from "vitest";
import {
  buildEffectiveParams,
  CANONICAL_RESOURCE,
  EvidenceStore,
  parameterDigest,
  PaymentsStore,
  Pep,
  sourceDigestOf,
  type TokenFacts,
} from "../src/index.js";

const TOKEN: TokenFacts = {
  sub: "alice",
  clientId: "ap-agent",
  mission: { id: "msn_refusal", authority_hash: "sha-256:refusalhash" },
  cnfJkt: "jkt-1",
};

describe("Refusal Records are per-attempt, immutable, and append-only", () => {
  it("a sustained parameter-mismatch condition yields one new record per attempt, never an amendment in place", () => {
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
    const evidence = new EvidenceStore();
    const pep = new Pep({
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
    expect(pep.reverify(effective, wrongDigest, TOKEN)).toBe(false);
    const afterFirst = evidence.forMission(TOKEN.mission.id);
    expect(afterFirst).toHaveLength(1);
    expect(afterFirst[0]?.kind).toBe("refusal");
    const firstRecord = afterFirst[0];

    // Attempt 2: a retrying agent hits the identical failure condition again.
    expect(pep.reverify(effective, wrongDigest, TOKEN)).toBe(false);
    const afterSecond = evidence.forMission(TOKEN.mission.id);

    // Append-only: a second, distinct record now exists.
    expect(afterSecond).toHaveLength(2);
    expect(afterSecond[1]).not.toBe(afterSecond[0]);
    // Immutable: the first record is the SAME object, unamended in place,
    // not a record that got overwritten or replaced.
    expect(afterSecond[0]).toBe(firstRecord);
  });
});
