/**
 * @spec orchestration#orchestration-evidence
 *
 * The Orchestration Evidence record and its builder: a faithful sibling of the
 * PEP's evidence store (`services/mcp-payments/src/evidence.ts`). The record is
 * a JSON object; `state_source` reuses the shared value space from
 * `@mission/core` (defined by the Harness profile) rather than redefining it.
 * On a `compensate` decision the compensate members are REQUIRED, and an
 * `evidence_envelope` (JWS Compact) is REQUIRED when the compensated step's
 * reversibility class is high-risk, matching the draft.
 */

import { canonicalize, type JsonValue, type StateSource } from "@mission/core";
import type { AuthorityBasis } from "./compensation.js";
import type { OutcomeClass } from "./in-flight.js";
import { HIGH_RISK_REVERSIBILITY, type ReversibilityClass } from "./reversibility.js";

export type OrchestrationDecision =
  | "suppress"
  | "pause"
  | "cancel"
  | "continue_to_safe_point"
  | "compensate"
  | "human_review"
  | "record_only";

/** The local-use `typ` for the Orchestration Evidence envelope. */
export const ORCHESTRATION_EVIDENCE_TYP = "mission-orchestration-evidence";

/** The nested `mission` descriptor, same shape as the Harness Evidence object. */
export interface MissionDescriptor {
  id: string;
  issuer: string;
  authority_hash?: string;
}

export interface OrchestrationEvidence {
  event_id: string;
  mission: MissionDescriptor;
  workflow_id: string;
  step_id?: string;
  mission_state: string;
  state_source: StateSource;
  orchestration_decision: OrchestrationDecision;
  reason: string;
  occurred_at: string;
  linked_evidence?: string[];
  outcome_state?: OutcomeClass;
  unwind_plan_hash?: string;
  authority_basis?: AuthorityBasis;
  compensation_action?: string;
  compensation_outcome?: string;
  /**
   * The reversed step's `evaluation_id` (runtime-profile binding). Its
   * normative home is the compensating runtime decision; surfaced here as its
   * own record member, distinct from `linked_evidence`, which carries only
   * evidence-record identifiers.
   */
  compensates_evaluation_id?: string;
  /** Per-Mission sequence indicator for evidence ordering (§ evidence-ordering). */
  sequence?: number;
  /** JWS Compact integrity protection over the record (payload = JCS minus this). */
  evidence_envelope?: string;
}

/**
 * A deployment-provided signer. Receives the JCS canonical bytes of the record
 * with `evidence_envelope` removed and returns a JWS Compact Serialization
 * whose protected header carries `kid`, `alg`, and `typ`
 * (`mission-orchestration-evidence`).
 */
export type EnvelopeSigner = (payloadCanonicalBytes: string) => string;

export interface BuildOrchestrationEvidenceInput {
  event_id: string;
  mission: MissionDescriptor;
  workflow_id: string;
  step_id?: string;
  mission_state: string;
  state_source: StateSource;
  orchestration_decision: OrchestrationDecision;
  reason: string;
  occurred_at: string;
  linked_evidence?: string[];
  outcome_state?: OutcomeClass;
  unwind_plan_hash?: string;
  authority_basis?: AuthorityBasis;
  compensation_action?: string;
  compensation_outcome?: string;
  compensates_evaluation_id?: string;
  sequence?: number;
  /**
   * The reversibility class of the compensated step. Drives the
   * evidence_envelope REQUIRED-for-high-risk rule; only read when the decision
   * is `compensate`.
   */
  compensated_reversibility?: ReversibilityClass;
}

/**
 * Build an Orchestration Evidence record. On a `compensate` decision the
 * compensate members (`authority_basis`, `compensation_action`,
 * `compensation_outcome`, `linked_evidence`, `compensates_evaluation_id`) are
 * REQUIRED and enforced (fail closed). `linked_evidence` carries only
 * supplied evidence-record identifiers; the compensated evaluation's
 * `evaluation_id` is never folded into it. An `evidence_envelope` is attached
 * whenever a signer is provided, and is REQUIRED (throws when absent) when
 * compensating a high-risk class.
 */
export function buildOrchestrationEvidence(
  input: BuildOrchestrationEvidenceInput,
  opts: { signEnvelope?: EnvelopeSigner } = {},
): OrchestrationEvidence {
  const rec: OrchestrationEvidence = {
    event_id: input.event_id,
    mission: input.mission,
    workflow_id: input.workflow_id,
    ...(input.step_id !== undefined ? { step_id: input.step_id } : {}),
    mission_state: input.mission_state,
    state_source: input.state_source,
    orchestration_decision: input.orchestration_decision,
    reason: input.reason,
    occurred_at: input.occurred_at,
    ...(input.outcome_state !== undefined ? { outcome_state: input.outcome_state } : {}),
    ...(input.unwind_plan_hash !== undefined ? { unwind_plan_hash: input.unwind_plan_hash } : {}),
    ...(input.sequence !== undefined ? { sequence: input.sequence } : {}),
  };

  if (input.orchestration_decision === "compensate") {
    if (input.authority_basis === undefined) {
      throw new Error("compensate evidence REQUIRES authority_basis");
    }
    if (input.compensation_action === undefined) {
      throw new Error("compensate evidence REQUIRES compensation_action");
    }
    if (input.compensation_outcome === undefined) {
      throw new Error("compensate evidence REQUIRES compensation_outcome");
    }
    if (input.compensates_evaluation_id === undefined) {
      throw new Error("compensate evidence REQUIRES compensates_evaluation_id");
    }
    rec.authority_basis = input.authority_basis;
    rec.compensation_action = input.compensation_action;
    rec.compensation_outcome = input.compensation_outcome;
    rec.compensates_evaluation_id = input.compensates_evaluation_id;

    // linked_evidence is REQUIRED for compensate and carries only supplied
    // evidence-record identifiers; the compensated evaluation_id belongs solely
    // in compensates_evaluation_id, never folded in here.
    const linked = input.linked_evidence ?? [];
    if (linked.length === 0) {
      throw new Error("compensate evidence REQUIRES linked_evidence");
    }
    rec.linked_evidence = [...linked];
  } else if (input.linked_evidence !== undefined) {
    rec.linked_evidence = input.linked_evidence;
  }

  const highRiskCompensation =
    input.orchestration_decision === "compensate" &&
    input.compensated_reversibility !== undefined &&
    HIGH_RISK_REVERSIBILITY.has(input.compensated_reversibility);

  const signer = opts.signEnvelope;
  if (highRiskCompensation && signer === undefined) {
    throw new Error(
      "compensate evidence for a high-risk reversibility class REQUIRES an evidence_envelope signer (fail closed)",
    );
  }
  if (signer !== undefined) {
    // Payload is the JCS canonical bytes of the record before the envelope is
    // attached (evidence_envelope is still absent here).
    const payload = canonicalize(rec as unknown as JsonValue);
    rec.evidence_envelope = signer(payload);
  }

  return rec;
}

/**
 * @spec orchestration#authority-narrowing
 *
 * Build an Orchestration Evidence record for a step the authority-narrowing
 * trigger denied. `step_id` is REQUIRED here (only OPTIONAL on the general
 * record): without it the per-step behavior that trigger requires is not
 * externally observable. Delegates to `buildOrchestrationEvidence` for every
 * other rule.
 */
export function buildAuthorityNarrowingEvidence(
  input: Omit<BuildOrchestrationEvidenceInput, "step_id"> & { step_id: string },
  opts: { signEnvelope?: EnvelopeSigner } = {},
): OrchestrationEvidence {
  if (!input.step_id) {
    throw new Error("authority-narrowing evidence REQUIRES step_id");
  }
  return buildOrchestrationEvidence(input, opts);
}
