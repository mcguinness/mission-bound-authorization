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

import { canonicalDigest, type JsonValue, type RecoveryProof, type SigningKeyStatus } from "@mission/core";
import type { EvidenceVerificationKey } from "./evidence.js";
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
  type EnforcementScopeStatement,
  validateEnforcementScopeStatement,
  claimsWithinScope,
} from "@mission/pdp";

export type MissionReceiptKind = "decision" | "execution" | "refusal";

type PublishedReceiptKey = EvidenceVerificationKey & { status?: SigningKeyStatus };
const receiptScopes = new WeakMap<EvidenceKeyResolver, EnforcementScopeStatement>();

/** Trusted assembly seam: locations are resolved by the deployment, never from a receipt. */
export function createReceiptIssuerKeyResolver(
  statement: EnforcementScopeStatement,
  publishedKeySets: ReadonlyMap<string, readonly PublishedReceiptKey[]>,
): EvidenceKeyResolver {
  if (validateEnforcementScopeStatement(statement).length) throw new Error("invalid receipt enforcement scope");
  const declaration = statement.extensions?.evidence;
  if (!statement.claims?.includes("evidence") || !declaration || !Array.isArray(declaration.receipt_issuers)) {
    throw new Error("scope does not declare receipt issuers");
  }
  const components = new Set([...statement.pdps, ...statement.mediated_scope.pep_locations]);
  const keys: PublishedReceiptKey[] = [];
  for (const binding of declaration.receipt_issuers) {
    if (!components.has(binding.emitter) || !declaration.signing_key_locations.includes(binding.key_set)) {
      throw new Error("receipt issuer or key set is not named by the scope");
    }
    for (const key of publishedKeySets.get(binding.key_set) ?? []) {
      if (key.role === "receipt_issuer" && key.emitterId === binding.emitter) {
        keys.push({ ...key, ...(key.status ? { status: { ...key.status } } : {}) });
      }
    }
  }
  const resolve: EvidenceKeyResolver = ({ kid, emitter, audience }) => {
    const matches = keys.filter((key) => key.kid === kid && key.emitterId === emitter.id &&
      emitter.role === "receipt_issuer" && (key.audience === undefined || key.audience === audience));
    if (matches.length !== 1) return undefined;
    const key = matches[0]!;
    return { key: key.publicKey, ...(key.status ? { status: { ...key.status } } : {}) };
  };
  receiptScopes.set(resolve, structuredClone(statement));
  return resolve;
}

function objectOf(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}
const nonempty = (value: unknown): value is string => typeof value === "string" && value.length > 0;
function timestamp(value: unknown): boolean {
  if (typeof value !== "string") return false;
  const parts = /^(\d{4})-(\d{2})-(\d{2})T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/i.exec(value);
  if (!parts || !Number.isFinite(Date.parse(value))) return false;
  const year = Number(parts[1]), month = Number(parts[2]), day = Number(parts[3]);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return month >= 1 && month <= 12 && day >= 1 && day <= days[month - 1]!;
}
const integer = (value: unknown): boolean => Number.isSafeInteger(value) && (value as number) >= 0;
const terminal = (value: unknown): boolean => ["completed", "failed", "suppressed"].includes(value as string);

function missionShape(value: unknown, exact = false): boolean {
  const p = objectOf(value);
  return !!p && nonempty(p.id) && nonempty(p.issuer) && (p.authority_hash === undefined || nonempty(p.authority_hash)) &&
    (!exact || Object.keys(p).every((key) => ["id", "issuer", "authority_hash"].includes(key)));
}

function receiptShape(value: unknown): value is MissionReceiptObject {
  const p = objectOf(value), emitter = objectOf(p?.emitter);
  if (!p || !["decision", "execution", "refusal"].includes(p.kind as string) || !missionShape(p.mission, true) ||
      !emitter || !nonempty(emitter.id) || emitter.role !== "receipt_issuer" || !timestamp(p.issued_at) || !Array.isArray(p.evidence)) return false;
  if (p.kind === "execution" ? !terminal(p.outcome) : p.outcome !== undefined) return false;
  if (p.profile !== undefined && !nonempty(p.profile)) return false;
  if (p.issuer_assertions !== undefined && (!nonempty(p.profile) || !objectOf(p.issuer_assertions))) return false;
  if (p.decision !== undefined) {
    const decision = objectOf(p.decision);
    if (!decision || !nonempty(decision.id) || !["permit", "deny"].includes(decision.result as string)) return false;
  }
  return p.evidence.every((value) => {
    const ref = objectOf(value), emitter = objectOf(ref?.emitter);
    return !!ref && nonempty(ref.type) && nonempty(ref.digest) && nonempty(ref.evidence_id) &&
      !!emitter && nonempty(emitter.id) && nonempty(emitter.role);
  });
}

/** Base content checks are distinct from envelope integrity and later cross-record joins. */
function recordShape(type: ReceiptResolvedRecord["type"], value: unknown): boolean {
  const p = objectOf(value), emitter = objectOf(p?.emitter);
  if (!p || !emitter || !nonempty(emitter.id) || !nonempty(p.audience)) return false;
  for (const field of ["actor", "credential", "capability_source", "principal_mapping", "hop_reference"]) {
    if (p[field] !== undefined && !objectOf(p[field])) return false;
  }
  if (type === "decision") {
    const mission = objectOf(p.mission), subject = objectOf(p.subject), resource = objectOf(p.resource), action = objectOf(p.action);
    const conditions = objectOf(p.conditions);
    if (p.conditions !== undefined && (!conditions || !timestamp(conditions.valid_until) ||
      (conditions.use_limit !== undefined && (!integer(conditions.use_limit) || conditions.use_limit === 0)) ||
      (conditions.parameter_digest !== undefined && conditions.parameter_digest !== p.parameter_digest))) return false;
    if (p.decision === "permit" && (!conditions || !timestamp(conditions.valid_until) ||
      (!nonempty(p.entry_digest) && !objectOf(p.authorizing_entry)) ||
      (["irreversible_action", "external_commitment", "privileged_administration"].includes(p.action_class as string) && conditions.use_limit !== 1))) return false;
    if (p.decision === "deny" && !nonempty(p.denial_reason)) return false;
    if (p.parameter_digest === undefined ? !nonempty(p.evaluation_request_digest) : !nonempty(p.parameter_digest) || p.evaluation_request_digest !== undefined) return false;
    return emitter.role === "pdp" && missionShape(mission) && nonempty(mission?.policy_view_id) &&
      nonempty(p.evidence_id) && nonempty(p.evaluation_id) && integer(p.sequence) && timestamp(p.evaluated_at) &&
      !!subject && nonempty(subject.id) && !!resource && nonempty(resource.type) && nonempty(resource.id) && !!action && nonempty(action.name) &&
      ["permit", "deny"].includes(p.decision as string) &&
      ["consequential_read", "consequential_write", "irreversible_action", "external_commitment", "privileged_administration"].includes(p.action_class as string) &&
      ["default", "resource_floor", "deployment"].includes(p.class_source as string);
  }
  if (type === "execution") return ["pep", "executor"].includes(emitter.role as string) &&
    nonempty(p.execution_id) && nonempty(p.evaluation_id) && nonempty(p.mission_id) && terminal(p.outcome) && integer(p.sequence) && timestamp(p.outcome_at) &&
    (p.outcome === "completed" || nonempty(p.error)) && (p.error === undefined || nonempty(p.error));
  const action = objectOf(p.action);
  return ["pep", "pdp"].includes(emitter.role as string) && nonempty(p.refusal_id) && p.decision === "deny" &&
    nonempty(p.denial_reason) && !!action && nonempty(action.name) && timestamp(p.evaluated_at) &&
    (p.mission === undefined || missionShape(p.mission) && integer(p.sequence)) &&
    (p.parameter_digest === undefined ? nonempty(p.evaluation_request_digest) : nonempty(p.parameter_digest) && p.evaluation_request_digest === undefined);
}

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
  if (!["decision", "execution", "refusal"].includes(input.kind)) throw new Error("unknown Mission Receipt kind");
  if (input.kind === "execution" && !terminal(input.executionEvidence?.outcome)) throw new Error("execution receipt requires a final outcome");
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
  | "malformed"
  | "issuer_not_authorized"
  | "envelope_invalid"
  | "combination_invalid"
  | "reference_unresolvable"
  /** The resolver's returned record kind does not equal the reference's own declared `type` (#739 review point 2). */
  | "reference_type_mismatch"
  | "referenced_record_invalid"
  | "digest_mismatch"
  | "identifier_mismatch"
  | "emitter_mismatch"
  | "join_failure"
  | "copied_member_mismatch"
  /** Issuer assertions require a separately authorized profile/policy path not implemented here. */
  | "unimplemented_projection"
  | "chain_not_supported";

export type ReceiptVerifyResult = { valid: true; unauthorized_execution?: true } | { valid: false; reason: ReceiptVerifyFailure };

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
  receipt: unknown,
  resolveRecord: ReceiptRecordResolver,
  resolveReceiptKey: EvidenceKeyResolver,
  resolveEvidenceKey: EvidenceKeyResolver,
  recoveryProof?: RecoveryProof,
): Promise<ReceiptVerifyResult> {
  try {
    return await verifyReceipt(structuredClone(receipt), resolveRecord, resolveReceiptKey, resolveEvidenceKey, recoveryProof);
  } catch {
    return { valid: false, reason: "malformed" };
  }
}

async function verifyReceipt(
  input: unknown, resolveRecord: ReceiptRecordResolver, resolveReceiptKey: EvidenceKeyResolver,
  resolveEvidenceKey: EvidenceKeyResolver, recoveryProof?: RecoveryProof,
): Promise<ReceiptVerifyResult> {
  const scope = receiptScopes.get(resolveReceiptKey);
  if (!scope) return { valid: false, reason: "issuer_not_authorized" };

  // Step 1 (lines 1490-1503): the receipt's own envelope.
  const envelopeResult = await verifyEvidenceEnvelope(
    input,
    MISSION_RECEIPT_MEDIA_TYPE,
    resolveReceiptKey,
    recoveryProof,
  );
  if (!envelopeResult.valid) {
    return { valid: false, reason: "envelope_invalid" };
  }
  if (!receiptShape(input)) return { valid: false, reason: "malformed" };
  const receipt = input;

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
    let r: ReceiptResolvedRecord | undefined;
    try { r = structuredClone(await resolveRecord(ref)); }
    catch { return { valid: false, reason: "reference_unresolvable" }; }
    if (!r) {
      return { valid: false, reason: "reference_unresolvable" };
    }
    // @spec runtime-evidence#receipt-evidence (lines 1409-1415, #739 review
    // point 2): `type` is the reference's OWN declared claim. The resolver's
    // returned kind MUST equal it BEFORE the resolved record is verified at
    // all: otherwise a reference declared as one record kind could be
    // satisfied by a resolver returning a DIFFERENT kind that genuinely
    // verifies under its own `cty` (checked next, against `r.type` rather
    // than `ref.type`), silently swapping what the receipt actually
    // projects. Checked here, ahead of `verifyEvidenceEnvelope` and the
    // digest compare, so this exact substitution is rejected under its own
    // specific reason rather than incidentally caught (and masked) by a
    // later digest mismatch.
    if (!["decision", "execution", "refusal"].includes(r.type) || CTY_FOR[r.type] !== ref.type) {
      return { valid: false, reason: "reference_type_mismatch" };
    }
    const v = await verifyEvidenceEnvelope(
      r.record as unknown as Parameters<typeof verifyEvidenceEnvelope>[0],
      CTY_FOR[r.type],
      resolveEvidenceKey,
    );
    if (!v.valid) {
      return { valid: false, reason: "referenced_record_invalid" };
    }
    if (!recordShape(r.type, r.record) || !claimsWithinScope(scope, {
      resource: r.record.audience,
      ...(r.type === "decision" ? { action_class: r.record.action_class } : {}),
    })) {
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
  // @spec runtime-evidence#receipt-kinds (lines 1291-1300, #739 review point
  // 3): "A `refusal` receipt exists only for a Refusal Record whose own
  // `mission` member carries the verified Mission reference the receipt's
  // REQUIRED `mission` member repeats." Unlike the prior (pre-#739-review)
  // check this replaces, this is NOT conditional on `refusalRec.mission`
  // happening to be present: for a `refusal`-kind receipt specifically, an
  // ABSENT Refusal Record `mission` is itself the join failure (a
  // `mission_context_missing` refusal never becomes a Mission Receipt).
  if (receipt.kind === "refusal") {
    if (
      !refusalRec?.mission ||
      refusalRec.mission.id !== receipt.mission.id ||
      refusalRec.mission.issuer !== receipt.mission.issuer
    ) {
      return { valid: false, reason: "join_failure" };
    }
  }
  if (executionRec) {
    // @spec runtime-evidence#execution-evidence-object `mission_id` (lines
    // 1010-1012, #739 review point 3): "mirrored from the linked Decision
    // Evidence for join-key convenience", so the receipt's own `mission.id`
    // MUST equal it too. The pre-#739-review check joined Decision Evidence
    // and Refusal Record to `receipt.mission` but never checked Execution
    // Evidence's `mission_id` against it at all.
    if (executionRec.mission_id !== receipt.mission.id) {
      return { valid: false, reason: "join_failure" };
    }
    // @spec runtime-evidence#execution-evidence-object `effective_parameter_digest`
    // (lines 1025-1027, #739 review point 3): "REQUIRED whenever
    // `authorized_parameter_digest` is present."
    if (executionRec.authorized_parameter_digest !== undefined && executionRec.effective_parameter_digest === undefined) {
      return { valid: false, reason: "join_failure" };
    }
  }
  if (executionRec && decisionRec) {
    if (executionRec.evaluation_id !== decisionRec.evaluation_id) {
      return { valid: false, reason: "join_failure" };
    }
    if (executionRec.audience !== decisionRec.audience) {
      return { valid: false, reason: "join_failure" };
    }
    // @spec runtime-evidence#execution-evidence-object `authorized_parameter_digest`
    // (lines 1020-1023, #739 review point 3): "REQUIRED when the linked
    // Decision Evidence carries `parameter_digest`; MUST equal it", per the
    // review's explicit "exact mirror" direction enforced in BOTH
    // directions here. The pre-#739-review check only caught the case
    // where `decisionRec.parameter_digest` was present and unequal; it
    // silently passed the reverse case (Execution Evidence asserting an
    // `authorized_parameter_digest` the Decision Evidence never carried at
    // all). `!==` on two `string | undefined` values covers presence and
    // equality together: both absent is not a failure, exactly one present
    // is, and both present-but-different is. The current draft states
    // this biconditional explicitly; the former reverse-direction gap
    // has been closed.
    if (executionRec.authorized_parameter_digest !== decisionRec.parameter_digest) {
      return { valid: false, reason: "join_failure" };
    }
  }
  if (receipt.kind === "execution" && executionRec && receipt.outcome !== executionRec.outcome) {
    return { valid: false, reason: "join_failure" };
  }
  if (receipt.kind === "execution" && decisionRec?.decision !== "permit") return { valid: false, reason: "join_failure" };
  if (receipt.kind === "refusal" && receipt.decision !== undefined) return { valid: false, reason: "copied_member_mismatch" };

  // Step 5 (line 1520): every copied optional member equals its source.
  // @spec runtime-evidence#mission-receipt Members (lines 1361-1383, #739
  // review point 4): `policy`, `executor`, and `target` are each, like
  // `decision`, "a projection from the evidence a receipt of that content
  // already carries" that step 5 MUST verify equal to its source
  // (`profile` and `issuer_assertions` are excluded: the spec calls them
  // "structurally separate from the projections above", issuer-asserted
  // facts with profile-defined semantics, never a copy step 5 checks
  // against a source record; `chain` is step 6, separately unimplemented).
  if ("issuer_assertions" in receipt) {
    return { valid: false, reason: "unimplemented_projection" };
  }
  const projections: Record<string, unknown> = decisionRec ? {
    policy: { pdp_policy_view: decisionRec.mission.policy_view_id,
      ...(decisionRec.mission.policy_version !== undefined ? { mission_policy_version: decisionRec.mission.policy_version } : {}) },
    executor: decisionRec.actor,
    target: { resource: decisionRec.resource, audience: decisionRec.audience },
  } : {};
  for (const member of ["policy", "executor", "target"]) {
    const claimed = (receipt as unknown as Record<string, unknown>)[member];
    if (claimed !== undefined && (!objectOf(claimed) || projections[member] === undefined ||
      canonicalDigest(claimed as JsonValue) !== canonicalDigest(projections[member] as JsonValue))) {
      return { valid: false, reason: "copied_member_mismatch" };
    }
  }
  if (receipt.decision && decisionRec) {
    if (receipt.decision.id !== decisionRec.evidence_id || receipt.decision.result !== decisionRec.decision) {
      return { valid: false, reason: "copied_member_mismatch" };
    }
  }

  // Step 6 (chain) intentionally not implemented; step 7 (reject on any
  // failure) is realized by every early return above.
  if ("chain" in receipt) return { valid: false, reason: "chain_not_supported" };
  const deviation = executionRec && executionRec.outcome !== "suppressed" &&
    executionRec.authorized_parameter_digest !== undefined &&
    executionRec.authorized_parameter_digest !== executionRec.effective_parameter_digest;
  return { valid: true, ...(deviation ? { unauthorized_execution: true as const } : {}) };
}
