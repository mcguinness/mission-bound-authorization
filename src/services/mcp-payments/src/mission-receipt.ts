/**
 * @spec draft-mcguinness-mission-runtime-evidence.md#mission-receipt (lines
 * 1236-1662 at 41f66a4a), #receipt-verification (1482-1537), issue #649.
 *
 * The Mission Receipt: a signed manifest projecting Decision Evidence,
 * Execution Evidence, or a Refusal Record (per `kind`), reusing the SAME
 * integrity algorithm as those records ({{decision-evidence-integrity}},
 * line 1311). Implements build + sign, and verification steps 1-5 and 7 of
 * {{receipt-verification}}. Step 6 (chain verification) is NOT implemented:
 * chaining is OPTIONAL in the spec and this deployment does not issue
 * chained receipts, so `chain` never appears on a built receipt and a
 * receipt carrying one is rejected as unimplemented (see
 * `verifyMissionReceipt`'s `chain_not_supported` reason).
 */

import { canonicalDigest, type JsonValue } from "@mission/core";
import type {
  DecisionEvidenceObject,
  ExecutionEvidenceObject,
  RefusalRecordObject,
  RuntimeMissionRefBasic,
} from "./evidence.js";
import {
  DECISION_EVIDENCE_MEDIA_TYPE,
  EXECUTION_EVIDENCE_MEDIA_TYPE,
  type EvidenceEmitterRef,
  type EvidenceEnvelope,
  type EvidenceKeyResolver,
  type EvidenceSigningKey,
  MISSION_RECEIPT_MEDIA_TYPE,
  REFUSAL_RECORD_MEDIA_TYPE,
  signEvidenceEnvelope,
  verifyEvidenceEnvelope,
} from "./runtime-evidence-integrity.js";

export type MissionReceiptKind = "decision" | "execution" | "refusal";

/** @spec runtime-evidence#receipt-evidence (lines 1405-1449): one evidence reference. */
export interface MissionReceiptEvidenceRef {
  type: string;
  digest: string;
  evidence_id: string;
  emitter: EvidenceEmitterRef;
}

/** @spec runtime-evidence#mission-receipt Members (lines 1302-1404): the closed wire object this deployment builds. */
export interface MissionReceiptObject {
  kind: MissionReceiptKind;
  mission: RuntimeMissionRefBasic;
  emitter: { id: string; role: "receipt_issuer" };
  evidence: MissionReceiptEvidenceRef[];
  issued_at: string;
  outcome?: "completed" | "failed" | "suppressed";
  decision?: { id: string; result: "permit" | "deny" };
  evidence_envelope: EvidenceEnvelope;
}

function evidenceRefFor(
  record: DecisionEvidenceObject | ExecutionEvidenceObject | RefusalRecordObject,
  type: string,
  evidence_id: string,
): MissionReceiptEvidenceRef {
  return {
    type,
    // @spec runtime-evidence#receipt-evidence (lines 1417-1427): the digest
    // input is the COMPLETE record, `evidence_envelope` included.
    digest: canonicalDigest(record as unknown as JsonValue),
    evidence_id,
    emitter: record.emitter,
  };
}

export interface BuildMissionReceiptInput {
  kind: MissionReceiptKind;
  mission: RuntimeMissionRefBasic;
  decisionEvidence?: DecisionEvidenceObject;
  executionEvidence?: ExecutionEvidenceObject;
  refusalRecord?: RefusalRecordObject;
}

/**
 * Build and sign a Mission Receipt. Enforces the `kind`'s required evidence
 * combination ({{receipt-kinds}}): `decision` projects Decision Evidence
 * alone; `execution` projects a permit Decision Evidence plus the final
 * Execution Evidence of the same action; `refusal` projects a Refusal Record
 * alone.
 */
export async function buildAndSignMissionReceipt(
  input: BuildMissionReceiptInput,
  emitterId: string,
  signer: EvidenceSigningKey,
): Promise<MissionReceiptObject> {
  const evidence: MissionReceiptEvidenceRef[] = [];

  if (input.kind === "decision" || input.kind === "execution") {
    if (!input.decisionEvidence) {
      throw new Error(`Mission Receipt kind "${input.kind}" requires decisionEvidence`);
    }
    if (input.decisionEvidence.decision !== "permit" && input.kind === "execution") {
      throw new Error('Mission Receipt kind "execution" requires a permit Decision Evidence');
    }
    evidence.push(evidenceRefFor(input.decisionEvidence, DECISION_EVIDENCE_MEDIA_TYPE, input.decisionEvidence.evidence_id));
  }
  if (input.kind === "execution") {
    if (!input.executionEvidence) {
      throw new Error('Mission Receipt kind "execution" requires executionEvidence');
    }
    evidence.push(
      evidenceRefFor(input.executionEvidence, EXECUTION_EVIDENCE_MEDIA_TYPE, input.executionEvidence.execution_id),
    );
  }
  if (input.kind === "refusal") {
    if (!input.refusalRecord) {
      throw new Error('Mission Receipt kind "refusal" requires refusalRecord');
    }
    evidence.push(evidenceRefFor(input.refusalRecord, REFUSAL_RECORD_MEDIA_TYPE, input.refusalRecord.refusal_id));
  }

  const outcome = input.kind === "execution" ? input.executionEvidence?.outcome : undefined;
  const unsigned = {
    kind: input.kind,
    mission: input.mission,
    emitter: { id: emitterId, role: "receipt_issuer" as const },
    evidence,
    issued_at: new Date().toISOString(),
    ...(outcome !== undefined ? { outcome } : {}),
    ...(input.decisionEvidence
      ? { decision: { id: input.decisionEvidence.evidence_id, result: input.decisionEvidence.decision } }
      : {}),
  };
  const evidence_envelope = await signEvidenceEnvelope(
    unsigned as unknown as JsonValue,
    MISSION_RECEIPT_MEDIA_TYPE,
    signer,
  );
  return Object.freeze({ ...unsigned, evidence_envelope }) as MissionReceiptObject;
}

export type ReceiptResolvedRecord =
  | { type: "decision"; record: DecisionEvidenceObject }
  | { type: "execution"; record: ExecutionEvidenceObject }
  | { type: "refusal"; record: RefusalRecordObject };

/** Resolve one evidence reference to the record it names, for verification. */
export type ReceiptRecordResolver = (
  ref: MissionReceiptEvidenceRef,
) => ReceiptResolvedRecord | undefined | Promise<ReceiptResolvedRecord | undefined>;

export type ReceiptVerifyFailure =
  | "envelope_invalid"
  | "combination_invalid"
  | "reference_unresolvable"
  | "referenced_record_invalid"
  | "digest_mismatch"
  | "identifier_mismatch"
  | "emitter_mismatch"
  | "join_failure"
  | "copied_member_mismatch"
  | "chain_not_supported";

export type ReceiptVerifyResult = { valid: true } | { valid: false; reason: ReceiptVerifyFailure };

const CTY_FOR: Record<ReceiptResolvedRecord["type"], string> = {
  decision: DECISION_EVIDENCE_MEDIA_TYPE,
  execution: EXECUTION_EVIDENCE_MEDIA_TYPE,
  refusal: REFUSAL_RECORD_MEDIA_TYPE,
};

/**
 * Verify a Mission Receipt end to end, per {{receipt-verification}} steps
 * 1-5 and 7 (step 6, chain verification, is not implemented: see the file
 * header). `resolveReceiptKey` resolves the receipt issuer's own key;
 * `resolveEvidenceKey` resolves the referenced records' emitter keys (the
 * same resolver a caller already uses to verify Decision/Execution/Refusal
 * records directly).
 */
export async function verifyMissionReceipt(
  receipt: MissionReceiptObject,
  resolveRecord: ReceiptRecordResolver,
  resolveReceiptKey: EvidenceKeyResolver,
  resolveEvidenceKey: EvidenceKeyResolver,
): Promise<ReceiptVerifyResult> {
  if ("chain" in receipt) {
    return { valid: false, reason: "chain_not_supported" };
  }

  // Step 1 (lines 1490-1503): the receipt's own envelope.
  const envelopeResult = await verifyEvidenceEnvelope(
    receipt as unknown as Parameters<typeof verifyEvidenceEnvelope>[0],
    MISSION_RECEIPT_MEDIA_TYPE,
    resolveReceiptKey,
  );
  if (!envelopeResult.valid) {
    return { valid: false, reason: "envelope_invalid" };
  }

  // Step 2 (line 1504-1505, {{receipt-kinds}}, {{receipt-evidence}}): the
  // required evidence combination for this `kind`, no more, no less.
  const expectedTypes =
    receipt.kind === "decision"
      ? [DECISION_EVIDENCE_MEDIA_TYPE]
      : receipt.kind === "execution"
        ? [DECISION_EVIDENCE_MEDIA_TYPE, EXECUTION_EVIDENCE_MEDIA_TYPE]
        : [REFUSAL_RECORD_MEDIA_TYPE];
  const actualTypes = receipt.evidence.map((e) => e.type).sort();
  if (
    actualTypes.length !== expectedTypes.length ||
    !expectedTypes.every((t) => actualTypes.includes(t))
  ) {
    return { valid: false, reason: "combination_invalid" };
  }

  // Step 3 (lines 1506-1510): resolve, verify under the record's own rules,
  // recompute the digest, and require the identifier and emitter to match.
  const resolved: Partial<Record<ReceiptResolvedRecord["type"], ReceiptResolvedRecord["record"]>> = {};
  for (const ref of receipt.evidence) {
    const r = await resolveRecord(ref);
    if (!r) {
      return { valid: false, reason: "reference_unresolvable" };
    }
    const v = await verifyEvidenceEnvelope(
      r.record as unknown as Parameters<typeof verifyEvidenceEnvelope>[0],
      CTY_FOR[r.type],
      resolveEvidenceKey,
    );
    if (!v.valid) {
      return { valid: false, reason: "referenced_record_invalid" };
    }
    const digest = canonicalDigest(r.record as unknown as JsonValue);
    if (digest !== ref.digest) {
      return { valid: false, reason: "digest_mismatch" };
    }
    const idField =
      r.type === "decision"
        ? r.record.evidence_id
        : r.type === "execution"
          ? r.record.execution_id
          : r.record.refusal_id;
    if (idField !== ref.evidence_id) {
      return { valid: false, reason: "identifier_mismatch" };
    }
    if (r.record.emitter.id !== ref.emitter.id || r.record.emitter.role !== ref.emitter.role) {
      return { valid: false, reason: "emitter_mismatch" };
    }
    resolved[r.type] = r.record;
  }

  // Step 4 (lines 1511-1519): cross-record joins.
  const decisionRec = resolved.decision as DecisionEvidenceObject | undefined;
  const executionRec = resolved.execution as ExecutionEvidenceObject | undefined;
  const refusalRec = resolved.refusal as RefusalRecordObject | undefined;

  if (decisionRec && (decisionRec.mission.id !== receipt.mission.id || decisionRec.mission.issuer !== receipt.mission.issuer)) {
    return { valid: false, reason: "join_failure" };
  }
  if (
    refusalRec?.mission &&
    (refusalRec.mission.id !== receipt.mission.id || refusalRec.mission.issuer !== receipt.mission.issuer)
  ) {
    return { valid: false, reason: "join_failure" };
  }
  if (executionRec && decisionRec) {
    if (executionRec.evaluation_id !== decisionRec.evaluation_id) {
      return { valid: false, reason: "join_failure" };
    }
    if (executionRec.audience !== decisionRec.audience) {
      return { valid: false, reason: "join_failure" };
    }
    if (
      decisionRec.parameter_digest !== undefined &&
      executionRec.authorized_parameter_digest !== decisionRec.parameter_digest
    ) {
      return { valid: false, reason: "join_failure" };
    }
  }
  if (receipt.kind === "execution" && executionRec && receipt.outcome !== executionRec.outcome) {
    return { valid: false, reason: "join_failure" };
  }

  // Step 5 (line 1520): every copied optional member equals its source.
  if (receipt.decision && decisionRec) {
    if (receipt.decision.id !== decisionRec.evidence_id || receipt.decision.result !== decisionRec.decision) {
      return { valid: false, reason: "copied_member_mismatch" };
    }
  }

  // Step 6 (chain) intentionally not implemented; step 7 (reject on any
  // failure) is realized by every early return above.
  return { valid: true };
}
