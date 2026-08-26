/**
 * @spec draft-mcguinness-mission-runtime-evidence.md#mission-receipt (lines
 * 1236-1662 at 41f66a4a), #receipt-verification (1482-1537). Covers build +
 * sign, positive end-to-end verification, and each of steps 1-5 and 7's
 * failure modes. Step 6 (chain) is not implemented (see mission-receipt.ts's
 * file header); a receipt carrying `chain` is rejected as unsupported.
 */

import { generateKeyPairSync } from "node:crypto";
import { canonicalDigest } from "@mission/core";
import { describe, expect, it } from "vitest";
import {
  DECISION_EVIDENCE_MEDIA_TYPE,
  EXECUTION_EVIDENCE_MEDIA_TYPE,
  type EvidenceSigningKey,
  signEvidenceEnvelope,
} from "../src/runtime-evidence-integrity.js";
import type { DecisionEvidenceObject, ExecutionEvidenceObject, RefusalRecordObject } from "../src/evidence.js";
import {
  buildAndSignMissionReceipt,
  type MissionReceiptEvidenceRef,
  type ReceiptResolvedRecord,
  verifyMissionReceipt,
} from "../src/mission-receipt.js";

const pdpKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });
const executorKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });
const receiptKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });

const PDP_SIGNER: EvidenceSigningKey = { kid: "pdp-1", key: pdpKeys.privateKey };
const EXECUTOR_SIGNER: EvidenceSigningKey = { kid: "exec-1", key: executorKeys.privateKey };
const RECEIPT_SIGNER: EvidenceSigningKey = { kid: "receipt-1", key: receiptKeys.privateKey };

const MISSION = { id: "msn_1", issuer: "https://as.example.com", authority_hash: "sha-256:ah" };

async function signedDecision(overrides: Partial<DecisionEvidenceObject> = {}): Promise<DecisionEvidenceObject> {
  const unsigned = {
    evidence_id: "evd_1",
    evaluation_id: "dec_1",
    mission: { id: MISSION.id, issuer: MISSION.issuer, policy_view_id: "pv-1", authority_hash: MISSION.authority_hash },
    subject: { id: "alice" },
    resource: { type: "invoice", id: "inv-1" },
    action: { name: "payments:invoice.read" },
    audience: "https://erp.example.com",
    action_class: "consequential_read" as const,
    class_source: "default" as const,
    parameter_digest: "sha-256:paramdigest",
    decision: "permit" as const,
    entry_digest: "sha-256:entrydigest",
    sequence: 0,
    emitter: { id: "pdp.example.com", role: "pdp" as const },
    evaluated_at: "2026-01-01T00:00:01.000Z",
    ...overrides,
  };
  const evidence_envelope = await signEvidenceEnvelope(unsigned, DECISION_EVIDENCE_MEDIA_TYPE, PDP_SIGNER);
  return { ...unsigned, evidence_envelope };
}

async function signedExecution(overrides: Partial<ExecutionEvidenceObject> = {}): Promise<ExecutionEvidenceObject> {
  const unsigned = {
    execution_id: "exe_1",
    evaluation_id: "dec_1",
    mission_id: MISSION.id,
    audience: "https://erp.example.com",
    authorized_parameter_digest: "sha-256:paramdigest",
    effective_parameter_digest: "sha-256:paramdigest",
    outcome: "completed" as const,
    outcome_at: "2026-01-01T00:00:02.000Z",
    sequence: 0,
    emitter: { id: "pep.example.com", role: "executor" as const },
    ...overrides,
  };
  const evidence_envelope = await signEvidenceEnvelope(unsigned, EXECUTION_EVIDENCE_MEDIA_TYPE, EXECUTOR_SIGNER);
  return { ...unsigned, evidence_envelope };
}

function resolverFor(records: {
  decision?: DecisionEvidenceObject;
  execution?: ExecutionEvidenceObject;
  refusal?: RefusalRecordObject;
}) {
  return (ref: MissionReceiptEvidenceRef): ReceiptResolvedRecord | undefined => {
    if (ref.type === DECISION_EVIDENCE_MEDIA_TYPE && records.decision) return { type: "decision", record: records.decision };
    if (ref.type === EXECUTION_EVIDENCE_MEDIA_TYPE && records.execution) return { type: "execution", record: records.execution };
    if (records.refusal) return { type: "refusal", record: records.refusal };
    return undefined;
  };
}

const resolveEvidenceKey = ({ emitter }: { emitter: { role: string } }) => {
  if (emitter.role === "pdp") return { key: pdpKeys.publicKey };
  if (emitter.role === "executor") return { key: executorKeys.publicKey };
  return undefined;
};
const resolveReceiptKey = ({ emitter }: { emitter: { role: string } }) =>
  emitter.role === "receipt_issuer" ? { key: receiptKeys.publicKey } : undefined;

describe("Mission Receipt digest vector (spec worked example)", () => {
  it("reproduces the exact digest the spec computes over its Execution Evidence stand-in", () => {
    // @spec runtime-evidence.md#mission-receipt-digest-worked (lines 1613-1661).
    const value = {
      audience: "https://erp.example.com",
      emitter: { id: "pep.example.com", role: "executor" },
      evaluation_id: "dec_8K2nP4qV9rL3tY6sB1zN0eF7jB",
      evidence_envelope: {
        format: "jws-compact",
        value:
          "eyJhbGciOiJFUzI1NiIsImtpZCI6InBlcC1rZXktMSJ9.dGhlLXNpZ25lZC1wYXlsb2FkLWJ5dGVzLWFib3Zl.RVMyNTZfc2lnbmF0dXJlX2J5dGVzX2lsbHVzdHJhdGl2ZQ",
      },
      execution_id: "exe_4r9SqLm8tY2pXkV3nR0eF7jB1zN6cQ5w",
      mission_id: "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
      outcome: "completed",
      outcome_at: "2026-11-02T08:14:05Z",
      sequence: 43,
    };
    expect(canonicalDigest(value)).toBe("sha-256:Ims1Xx5FAPYfFB6c6Y2gbqybB-Z2PxCi93yWPcIHmC8");
  });
});

describe("Mission Receipt build + verify", () => {
  it("builds and verifies a 'decision' receipt", async () => {
    const decision = await signedDecision();
    const receipt = await buildAndSignMissionReceipt(
      { kind: "decision", mission: MISSION, decisionEvidence: decision },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    expect(receipt.kind).toBe("decision");
    expect(receipt.evidence).toHaveLength(1);
    const result = await verifyMissionReceipt(
      receipt,
      resolverFor({ decision }),
      resolveReceiptKey,
      resolveEvidenceKey,
    );
    expect(result).toEqual({ valid: true });
  });

  it("builds and verifies an 'execution' receipt, joined on evaluation_id", async () => {
    const decision = await signedDecision();
    const execution = await signedExecution();
    const receipt = await buildAndSignMissionReceipt(
      { kind: "execution", mission: MISSION, decisionEvidence: decision, executionEvidence: execution },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    expect(receipt.evidence).toHaveLength(2);
    expect(receipt.outcome).toBe("completed");
    expect(receipt.decision).toEqual({ id: decision.evidence_id, result: "permit" });
    const result = await verifyMissionReceipt(
      receipt,
      resolverFor({ decision, execution }),
      resolveReceiptKey,
      resolveEvidenceKey,
    );
    expect(result).toEqual({ valid: true });
  });

  it("rejects an 'execution' receipt whose evidence combination is missing the Execution Evidence reference", async () => {
    const decision = await signedDecision();
    const execution = await signedExecution();
    const receipt = await buildAndSignMissionReceipt(
      { kind: "execution", mission: MISSION, decisionEvidence: decision, executionEvidence: execution },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    const truncated = { ...receipt, evidence: receipt.evidence.slice(0, 1) };
    const result = await verifyMissionReceipt(
      truncated,
      resolverFor({ decision, execution }),
      resolveReceiptKey,
      resolveEvidenceKey,
    );
    // The envelope no longer matches the truncated evidence array either, but
    // step 2's combination check is reached only if step 1 somehow passed; a
    // real attacker who also re-signed would be caught by step 2.
    expect(result.valid).toBe(false);
  });

  it("rejects a genuinely mis-signed 'decision' receipt that carries an Execution Evidence reference too (evidence-combination-per-kind)", async () => {
    const decision = await signedDecision();
    const execution = await signedExecution();
    // A malicious/buggy issuer that signs a `kind: "decision"` object but
    // attaches both references anyway: the builder itself never produces
    // this (it enforces the combination), so this constructs it directly to
    // exercise step 2 on a receipt that otherwise DOES verify (its envelope
    // is genuinely signed over exactly these bytes).
    const unsigned = {
      kind: "decision" as const,
      mission: MISSION,
      emitter: { id: "receipts.example.com", role: "receipt_issuer" as const },
      evidence: [
        { type: DECISION_EVIDENCE_MEDIA_TYPE, digest: canonicalDigest(decision as never), evidence_id: decision.evidence_id, emitter: decision.emitter },
        { type: EXECUTION_EVIDENCE_MEDIA_TYPE, digest: canonicalDigest(execution as never), evidence_id: execution.execution_id, emitter: execution.emitter },
      ],
      issued_at: "2026-01-01T00:00:03.000Z",
      decision: { id: decision.evidence_id, result: "permit" as const },
    };
    const evidence_envelope = await signEvidenceEnvelope(unsigned, "application/mission-receipt+json", RECEIPT_SIGNER);
    const badReceipt = { ...unsigned, evidence_envelope };
    const result = await verifyMissionReceipt(
      badReceipt,
      resolverFor({ decision, execution }),
      resolveReceiptKey,
      resolveEvidenceKey,
    );
    expect(result).toEqual({ valid: false, reason: "combination_invalid" });
  });

  it("rejects a copied member mismatch: the receipt's own embedded decision.result disagrees with the resolved Decision Evidence it references (step 5)", async () => {
    const decision = await signedDecision(); // decision: "permit"
    // A malicious/buggy issuer that copies the WRONG result into the
    // receipt's own `decision` member while still referencing (and
    // correctly digesting) the real, unmodified permit Decision Evidence:
    // the builder never produces this (it derives `decision` from the same
    // object it references), so this constructs it directly to exercise
    // step 5 on a receipt whose envelope, combination, digest, identifier,
    // emitter, and mission join all otherwise pass.
    const unsigned = {
      kind: "decision" as const,
      mission: MISSION,
      emitter: { id: "receipts.example.com", role: "receipt_issuer" as const },
      evidence: [
        {
          type: DECISION_EVIDENCE_MEDIA_TYPE,
          digest: canonicalDigest(decision as never),
          evidence_id: decision.evidence_id,
          emitter: decision.emitter,
        },
      ],
      issued_at: "2026-01-01T00:00:03.000Z",
      decision: { id: decision.evidence_id, result: "deny" as const },
    };
    const evidence_envelope = await signEvidenceEnvelope(unsigned, "application/mission-receipt+json", RECEIPT_SIGNER);
    const badReceipt = { ...unsigned, evidence_envelope };
    const result = await verifyMissionReceipt(
      badReceipt,
      resolverFor({ decision }),
      resolveReceiptKey,
      resolveEvidenceKey,
    );
    expect(result).toEqual({ valid: false, reason: "copied_member_mismatch" });
  });

  it("rejects when a referenced record is unresolvable", async () => {
    const decision = await signedDecision();
    const receipt = await buildAndSignMissionReceipt(
      { kind: "decision", mission: MISSION, decisionEvidence: decision },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    const result = await verifyMissionReceipt(receipt, () => undefined, resolveReceiptKey, resolveEvidenceKey);
    expect(result).toEqual({ valid: false, reason: "reference_unresolvable" });
  });

  it("rejects when the referenced record's own signature does not verify", async () => {
    const decision = await signedDecision();
    const receipt = await buildAndSignMissionReceipt(
      { kind: "decision", mission: MISSION, decisionEvidence: decision },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    const tamperedDecision = { ...decision, decision: "deny" as const };
    const result = await verifyMissionReceipt(
      receipt,
      resolverFor({ decision: tamperedDecision }),
      resolveReceiptKey,
      resolveEvidenceKey,
    );
    expect(result).toEqual({ valid: false, reason: "referenced_record_invalid" });
  });

  it("rejects a digest mismatch: the resolved record verifies on its own but does not match the receipt's committed digest", async () => {
    const decision = await signedDecision();
    const receipt = await buildAndSignMissionReceipt(
      { kind: "decision", mission: MISSION, decisionEvidence: decision },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    // A second, independently-signed but genuinely different Decision Evidence
    // record: it verifies (own signature valid) but is not the one this
    // receipt committed to.
    const otherDecision = await signedDecision({ evidence_id: "evd_1", sequence: 1 });
    const result = await verifyMissionReceipt(
      receipt,
      resolverFor({ decision: otherDecision }),
      resolveReceiptKey,
      resolveEvidenceKey,
    );
    expect(result).toEqual({ valid: false, reason: "digest_mismatch" });
  });

  it("rejects a join failure: Execution Evidence's evaluation_id does not match the Decision Evidence it is paired with", async () => {
    const decision = await signedDecision();
    const execution = await signedExecution({ evaluation_id: "dec_DIFFERENT" });
    const receipt = await buildAndSignMissionReceipt(
      { kind: "execution", mission: MISSION, decisionEvidence: decision, executionEvidence: execution },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    const result = await verifyMissionReceipt(
      receipt,
      resolverFor({ decision, execution }),
      resolveReceiptKey,
      resolveEvidenceKey,
    );
    expect(result).toEqual({ valid: false, reason: "join_failure" });
  });

  it("rejects the receipt's own envelope tampering (byte-mismatch, ordered-total-verification)", async () => {
    const decision = await signedDecision();
    const receipt = await buildAndSignMissionReceipt(
      { kind: "decision", mission: MISSION, decisionEvidence: decision },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    const tampered = { ...receipt, mission: { ...receipt.mission, id: "msn_evil" } };
    const result = await verifyMissionReceipt(
      tampered,
      resolverFor({ decision }),
      resolveReceiptKey,
      resolveEvidenceKey,
    );
    expect(result).toEqual({ valid: false, reason: "envelope_invalid" });
  });

  it("rejects an unresolvable receipt-issuer key", async () => {
    const decision = await signedDecision();
    const receipt = await buildAndSignMissionReceipt(
      { kind: "decision", mission: MISSION, decisionEvidence: decision },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    const result = await verifyMissionReceipt(receipt, resolverFor({ decision }), () => undefined, resolveEvidenceKey);
    expect(result).toEqual({ valid: false, reason: "envelope_invalid" });
  });
});
