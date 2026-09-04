/**
 * @spec draft-mcguinness-mission-runtime-evidence.md#decision-evidence-object,
 * #decision-evidence-integrity; draft-mcguinness-mission-runtime.md#agent-isolated-evidence-emission
 * (issue #741): the Decision Evidence Object and the emitter that constructs
 * and signs it.
 *
 * The emitter is the PDP. `emitter` names "the identity of the component
 * that emitted and signed this record", a verifier binds the JWS `kid` to
 * that component, and the PRODUCER bar requires the emitter to sign every
 * record it emits; the runtime profile's evidence-emission condition adds
 * that a caller can supply neither the completed record nor the emitter
 * identity, role, decision, or sequence position. So the record is built
 * here, from the decision the PDP just reached, and signed on the PDP's own
 * emission path. A component that reconstructs a record for a decision it
 * did not reach is not the emitter, whatever key it holds.
 *
 * The counter is emission-plane state: it orders the records this emitter
 * emitted, and is never read back as an input to a decision (D28).
 */

import { randomBytes } from "node:crypto";
import type { ContextActor } from "@mission/actor-chain";
import { canonicalDigest, type JsonValue } from "@mission/core";
import {
  DECISION_EVIDENCE_MEDIA_TYPE,
  type EvidenceEnvelope,
  type EvidenceSigningKey,
  signEvidenceEnvelope,
} from "./runtime-evidence-integrity.js";

/** @spec runtime-evidence#decision-evidence-object mission sub-object (REQUIRES `policy_view_id`). */
export interface RuntimeMissionRef {
  id: string;
  issuer: string;
  policy_view_id: string;
  authority_hash?: string;
  intent_hash?: string;
  policy_version?: string;
}

export interface RuntimeSubjectRef {
  id: string;
  type?: string;
  properties?: { iss?: string };
}

export interface RuntimeResourceRef {
  type: string;
  id: string;
}

export interface RuntimeActionRef {
  name: string;
}

/** @spec runtime-evidence#decision-evidence-object `conditions` (normalized permit form). */
export interface RuntimeConditions {
  valid_until: string;
  use_limit?: number;
  parameter_digest?: string;
}

/** @spec runtime-evidence#decision-evidence-object `action_class` (runtime profile's classes). */
export type RuntimeActionClass =
  | "consequential_read"
  | "consequential_write"
  | "irreversible_action"
  | "external_commitment"
  | "privileged_administration";

/** @spec runtime-evidence#decision-evidence-object `class_source`. */
export type RuntimeClassSource = "default" | "resource_floor" | "deployment";

/** @spec runtime-evidence#decision-evidence-object `hop_reference` (also Refusal/Execution). */
export interface RuntimeHopReference {
  jti: string;
  mission_id: string;
  continuation_handle?: string;
}

/**
 * @spec runtime-evidence#evidence-extensions `principal_mapping`: coordinated
 * extension member, protected references only (never raw `{iss,sub}`), per
 * the privacy rule ({{evidence-pii}}).
 */
export interface RuntimePrincipalMapping {
  origin: string;
  local: string;
  policy: { id: string; version: string };
  observed_at: string;
  valid_until: string;
}

/** @spec runtime-evidence#evidence-extensions `capability_source`: coordinated extension member. */
export interface RuntimeCapabilitySource {
  tool_id: string;
  source_uri: string;
  source_digest: string;
  operation_ref: string;
}

/** @spec runtime-evidence#decision-evidence-object (lines 331-573): the closed wire object. */
export interface DecisionEvidenceObject {
  evidence_id: string;
  evaluation_id: string;
  mission: RuntimeMissionRef;
  subject: RuntimeSubjectRef;
  resource: RuntimeResourceRef;
  action: RuntimeActionRef;
  audience: string;
  action_class: RuntimeActionClass;
  class_source: RuntimeClassSource;
  actor?: ContextActor;
  capability_source?: RuntimeCapabilitySource;
  principal_mapping?: RuntimePrincipalMapping;
  hop_reference?: RuntimeHopReference;
  parameter_digest?: string;
  evaluation_request_digest?: string;
  conditions?: RuntimeConditions;
  decision: "permit" | "deny";
  denial_reason?: string;
  entry_digest?: string;
  sequence: number;
  emitter: { id: string; role: "pdp" };
  evaluated_at: string;
  evidence_envelope: EvidenceEnvelope;
}

/** At least 128 bits of entropy, ABNF `1*64( ALPHA / DIGIT / "-" / "_" )` (runtime-evidence.md, every `*_id` member). */
export function newRecordId(prefix: string): string {
  return `${prefix}_${randomBytes(20).toString("base64url")}`;
}

/**
 * @spec runtime-evidence#request-digest-worked: the `evaluation_request_digest`
 * fallback: a canonical-object digest of exactly the worked example's summary
 * shape (`action`, `audience`, `mission_id`, `resource`, `subject`, all flat
 * strings). Used whenever `parameter_digest` is absent, so Decision Evidence
 * and Refusal Record always carry one or the other as the runtime profile
 * requires. The runtime profile does not standardize the digested request
 * form; this deployment states exactly this input, matching the spec's own
 * non-normative worked value byte-for-byte (pinned in
 * `packages/mission-core/test/canonical-digest.test.ts`).
 */
export function requestDigestFallback(input: {
  action: string;
  audience: string;
  mission_id: string;
  resource: string;
  subject: string;
}): string {
  return canonicalDigest(input as unknown as JsonValue);
}

/**
 * What the PDP's own decision state supplies for one record. Deliberately
 * NOT a seam for `emitter`, `sequence`, `evidence_id`, or `class_source`:
 * those are the emitter's, and a caller that could set them would be
 * asserting an emitter identity, a sequence position, or a classification
 * source it does not own ({{agent-isolated-evidence-emission}}).
 *
 * `capability_source` is absent by construction (#657/#730): the member left
 * the decision request envelope, so no validated PDP-side input carries it.
 * It is OPTIONAL, and a PEP-supplied copy would be exactly the caller-asserted
 * record content this emitter exists to prevent; it returns once #657's
 * per-action capability-binding resolver supplies it from the PDP's own
 * verified inputs.
 */
export interface DecisionEvidenceEmissionInput {
  mission: RuntimeMissionRef;
  subject: RuntimeSubjectRef;
  resource: RuntimeResourceRef;
  action: RuntimeActionRef;
  audience: string;
  evaluation_id: string;
  decision: "permit" | "deny";
  evaluated_at: string;
  action_class?: RuntimeActionClass;
  actor?: ContextActor;
  principal_mapping?: RuntimePrincipalMapping;
  parameter_digest?: string;
  conditions?: RuntimeConditions;
  denial_reason?: string;
  entry_digest?: string;
}

/**
 * The PDP's Decision Evidence emission path: one signing identity, one
 * emitter id, one enforcement scope, and this emitter's own sequence
 * counters. Injected at PDP wiring ({@link EvaluateOptions.evidence}) and
 * held for the process's life, never constructed per call: a per-call
 * emitter is a caller asserting an emitter identity and a sequence position.
 */
export interface DecisionEvidenceEmitter {
  readonly emit: (input: DecisionEvidenceEmissionInput) => Promise<DecisionEvidenceObject>;
}

export interface DecisionEvidenceEmitterConfig {
  /** The emitter's ES256 signing identity: the `kid` a verifier resolves in this emitter's published key set. */
  signer: EvidenceSigningKey;
  /** The exact `emitter.id` this emitter names, and that its published key is registered for. */
  emitterId: string;
  /**
   * The enforcement scope this emitter's key is published for. A decision
   * for any other audience is refused rather than signed: "one component's
   * key cannot sign evidence for a resource, audience, or scope it does not
   * serve" ({{decision-evidence-integrity}}).
   */
  audience: string;
}

/**
 * @spec runtime-evidence#decision-evidence-object (line 508): "each emitter
 * maintains its own monotonically increasing per-Mission sequence."
 * `emitter` is the `{id, role}` object, so the counter is scoped per
 * (Mission, emitter id, role). In-memory and per process: a durable counter
 * and instance-epoch binding are a separate concern from the emission
 * boundary this module establishes.
 */
export function createDecisionEvidenceEmitter(config: DecisionEvidenceEmitterConfig): DecisionEvidenceEmitter {
  const sequences = new Map<string, number>();
  const nextSequence = (missionId: string): number => {
    const key = `${missionId} ${config.emitterId} pdp`;
    const n = sequences.get(key) ?? 0;
    sequences.set(key, n + 1);
    return n;
  };

  return {
    emit: async (input: DecisionEvidenceEmissionInput): Promise<DecisionEvidenceObject> => {
      if (input.audience !== config.audience) {
        throw new Error(
          `DecisionEvidenceEmitter: refusing to sign a record for audience "${input.audience}"; this emitter's key is published for "${config.audience}"`,
        );
      }
      const action_class = input.action_class ?? "consequential_read";
      const class_source: RuntimeClassSource = input.action_class !== undefined ? "deployment" : "default";
      const evaluation_request_digest =
        input.parameter_digest === undefined
          ? requestDigestFallback({
              action: input.action.name,
              audience: input.audience,
              mission_id: input.mission.id,
              resource: input.resource.id,
              subject: input.subject.id,
            })
          : undefined;
      const unsigned = {
        evidence_id: newRecordId("evd"),
        evaluation_id: input.evaluation_id,
        mission: input.mission,
        subject: input.subject,
        resource: input.resource,
        action: input.action,
        audience: input.audience,
        action_class,
        class_source,
        ...(input.actor !== undefined ? { actor: input.actor } : {}),
        ...(input.principal_mapping !== undefined ? { principal_mapping: input.principal_mapping } : {}),
        ...(input.parameter_digest !== undefined ? { parameter_digest: input.parameter_digest } : {}),
        ...(evaluation_request_digest !== undefined ? { evaluation_request_digest } : {}),
        ...(input.conditions !== undefined ? { conditions: input.conditions } : {}),
        decision: input.decision,
        ...(input.denial_reason !== undefined ? { denial_reason: input.denial_reason } : {}),
        ...(input.entry_digest !== undefined ? { entry_digest: input.entry_digest } : {}),
        sequence: nextSequence(input.mission.id),
        emitter: { id: config.emitterId, role: "pdp" as const },
        evaluated_at: input.evaluated_at,
      };
      const evidence_envelope = await signEvidenceEnvelope(
        unsigned as unknown as JsonValue,
        DECISION_EVIDENCE_MEDIA_TYPE,
        config.signer,
      );
      return { ...unsigned, evidence_envelope } as DecisionEvidenceObject;
    },
  };
}
