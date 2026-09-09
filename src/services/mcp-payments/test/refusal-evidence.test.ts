/**
 * @spec runtime-evidence#execution-evidence-object,
 * runtime-evidence#pre-decision-refusal
 *
 * PEP-emitted records are per-attempt, immutable, and append-only: a
 * sustained failure condition with a retrying agent yields one signed record
 * per attempt, never a record amended or replaced in place. This exercises
 * Pep.reverify() (the TOCTOU parameter-binding re-check immediately before
 * execution), which needs only the local PaymentsStore and EvidenceStore,
 * not OpenFGA, so it runs unconditionally.
 *
 * Issue #786 moved the record this path emits from a Refusal Record to
 * Execution Evidence with `outcome` `suppressed`: the re-check runs after a
 * permit was obtained, and "once a PDP has decided, every final disposition
 * of a consequential permit ... is Execution Evidence ... never a Refusal
 * Record". The append-only/immutable/per-attempt clause under test is
 * unchanged; what changed is which carrier it is proven on, plus the
 * execution identity now asserted per attempt.
 *
 * @spec draft-mcguinness-mission-runtime-evidence.md#decision-evidence-integrity
 * (issue #649): the retained record is genuinely signed; this test still
 * covers only the append-only/immutable/per-attempt half of the clause, not
 * signature verification itself (see `runtime-evidence-integrity.test.ts`).
 */

import type { Fga } from "@mission/pdp";
import { describe, expect, it } from "vitest";
import {
  buildEffectiveParams,
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  type ExecutionEvidence,
  parameterDigest,
  PaymentsStore,
  Pep,
  type RefusalRecord,
  type TokenFacts,
} from "../src/index.js";
import { testAttempt } from "./execution-attempt.js";

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
  it("a sustained pre-decision failure condition yields one new Refusal Record per attempt, never an amendment in place", async () => {
    // The PRE-decision half of the clause, on the Refusal Record carrier:
    // an unresolvable target is established before any decision request, so
    // no permit exists and every attempt appends its own signed record.
    // (Issue #786 moved the post-permit half to Execution Evidence, below.)
    const payments = new PaymentsStore();
    const evidence = new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver);
    const view = {
      id: TOKEN.mission.id,
      issuer: TOKEN.mission.issuer,
      state: "active" as const,
      version: 1,
      authority_hash: TOKEN.mission.authority_hash,
      authority_set: [
        {
          type: "mission_resource_access",
          resource: CANONICAL_RESOURCE,
          actions: ["payments:payment.schedule"],
        },
      ],
      subject: { iss: TOKEN.mission.issuer, sub: "alice" },
      client_id: "ap-agent",
    };
    const pep = new Pep({
      decide: EVIDENCE_KEYS.decide,
      payments,
      evidence,
      // Never reached: the invoice lookup fails before any decision request.
      fga: {} as unknown as Fga,
      modelId: "unused",
      loadView: (ref) =>
        ref.id === view.id && ref.issuer === view.issuer
          ? { view: view as never, freshness: { observed_at: new Date().toISOString(), source: "load_view" } }
          : undefined,
      instanceEpoch: "epoch-1",
      allowedFreshnessSources: new Set(["load_view"]),
    });

    const first = await pep.enforce("schedule_payment", { invoice_id: "inv-missing" }, TOKEN);
    // The caller-visible diagnostic is the deployment's own; the signed
    // record carries the enumerated value it maps to.
    expect(first.refusal_reason).toBe("unknown_invoice");
    const afterFirst = evidence.forMission(TOKEN.mission.id);
    expect(afterFirst).toHaveLength(1);
    const record = afterFirst[0] as RefusalRecord;
    expect(record.kind).toBe("refusal");
    expect(record.content.denial_reason).toBe("target_unresolvable");
    const snapshot = structuredClone(afterFirst[0]);

    const second = await pep.enforce("schedule_payment", { invoice_id: "inv-missing" }, TOKEN);
    expect(second.refusal_reason).toBe("unknown_invoice");
    const afterSecond = evidence.forMission(TOKEN.mission.id);
    expect(afterSecond).toHaveLength(2);
    expect(afterSecond[1]).not.toBe(afterSecond[0]);
    expect((afterSecond[1] as RefusalRecord).content.refusal_id).not.toBe(record.content.refusal_id);
    expect(afterSecond[0]).toEqual(snapshot);
  });
});

describe("PEP-emitted execution records are per-attempt, immutable, and append-only", () => {
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
      // reverify()/suppressExecution() never touch deps.fga or deps.loadView.
      fga: {} as unknown as Fga,
      modelId: "unused",
      loadView: () => undefined,
      instanceEpoch: "epoch-1",
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
    const observed = parameterDigest(effective);
    const wrongDigest = "sha-256:deliberately-wrong";
    expect(observed).not.toBe(wrongDigest);

    // One attempt context per disposition attempt, exactly as the enforcement
    // path builds it: the authorized digest is the one the permit bound, and
    // the effective digest is observed freshly at the disposition.
    const attemptFor = () =>
      testAttempt({
        mission: TOKEN.mission,
        action: "payments:payment.execute",
        authorizedParameterDigest: wrongDigest,
        observeEffectiveDigest: () => observed,
      });

    // Attempt 1: the same sustained failure condition (the caller's pinned
    // digest no longer matches the store's authoritative parameters).
    const first = await pep.reverify(effective, wrongDigest, TOKEN, attemptFor());
    expect(first.ok).toBe(false);
    const afterFirst = evidence.forMission(TOKEN.mission.id);
    expect(afterFirst).toHaveLength(1);
    expect(afterFirst[0]?.kind).toBe("execution");
    const firstRecord = afterFirst[0] as ExecutionEvidence;
    expect(firstRecord.content.outcome).toBe("suppressed");
    expect(firstRecord.content.error).toBe("parameter_mismatch");
    // The deviation is recorded as a real digest pair, never as a repeat of
    // the authorized digest: the record says what was authorized and what was
    // actually observed.
    expect(firstRecord.content.authorized_parameter_digest).toBe(wrongDigest);
    expect(firstRecord.content.effective_parameter_digest).toBe(observed);
    // A content snapshot, not a reference: `toBe` on the same array element
    // would pass even if the store mutated it in place later, since nothing
    // ever replaces the element with a different object. Only a snapshot
    // comparison catches an in-place amendment.
    const firstSnapshot = structuredClone(afterFirst[0]);

    // Attempt 2: a retrying agent hits the identical failure condition again.
    const second = await pep.reverify(effective, wrongDigest, TOKEN, attemptFor());
    expect(second.ok).toBe(false);
    const afterSecond = evidence.forMission(TOKEN.mission.id);

    // Append-only: a second, distinct record now exists.
    expect(afterSecond).toHaveLength(2);
    expect(afterSecond[1]).not.toBe(afterSecond[0]);
    // A DISTINCT attempt carries a DISTINCT execution identity, so neither
    // attempt can present itself as the other's disposition (#786).
    expect((afterSecond[1] as ExecutionEvidence).content.execution_id).not.toBe(
      firstRecord.content.execution_id,
    );
    // Immutable: the first record's own content is byte-for-byte what it was
    // before the second attempt, never amended or replaced in place.
    expect(afterSecond[0]).toEqual(firstSnapshot);
  });

  it("a retried emission reuses one execution identity and is deduplicated, while a rejected replay never overwrites a completed record", async () => {
    const evidence = new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver);
    // The completed disposition of an operation, as the transaction path
    // records it at the commit point.
    const completed = await evidence.recordExecution(CANONICAL_RESOURCE, "executor", {
      permitId: "dec_original",
      opKey: "op:msn_refusal:payments:payment.execute:sha-256:d",
      execution_id: "exe_original",
      evaluation_id: "dec_original",
      mission_id: TOKEN.mission.id,
      audience: CANONICAL_RESOURCE,
      authorized_parameter_digest: "sha-256:d",
      effective_parameter_digest: "sha-256:d",
      outcome: "completed",
    });
    // @spec runtime-evidence#execution-evidence-object: "delivery of that
    // record is at-least-once, so a consumer MUST deduplicate on
    // `execution_id`". A retry of the SAME disposition returns the retained
    // record; the store holds one row, not two.
    const retried = await evidence.recordExecution(CANONICAL_RESOURCE, "executor", {
      permitId: "dec_original",
      opKey: "op:msn_refusal:payments:payment.execute:sha-256:d",
      execution_id: "exe_original",
      evaluation_id: "dec_original",
      mission_id: TOKEN.mission.id,
      audience: CANONICAL_RESOURCE,
      authorized_parameter_digest: "sha-256:d",
      effective_parameter_digest: "sha-256:d",
      outcome: "completed",
    });
    expect(retried).toBe(completed);
    expect(evidence.forMission(TOKEN.mission.id)).toHaveLength(1);

    // A rejected replay is a DIFFERENT attempt. Presenting the original
    // identity with a different disposition is refused outright, so no
    // replay can rewrite the completed record.
    await expect(
      evidence.recordExecution(CANONICAL_RESOURCE, "pep", {
        permitId: "dec_replay",
        opKey: "op:msn_refusal:payments:payment.execute:sha-256:d",
        execution_id: "exe_original",
        evaluation_id: "dec_replay",
        mission_id: TOKEN.mission.id,
        audience: CANONICAL_RESOURCE,
        outcome: "suppressed",
        error: "operation_already_claimed",
      }),
    ).rejects.toThrow(/already retained for a different disposition/);
    const records = evidence.forMission(TOKEN.mission.id);
    expect(records).toHaveLength(1);
    expect((records[0] as ExecutionEvidence).content.outcome).toBe("completed");
  });
});
