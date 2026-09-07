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

/** Deployment audit policy: verified issuer/expiry only, never token bytes or confirmation keys. */
export interface RuntimeCredentialRef {
  issuer?: string;
  expires_at?: string;
}

function objectOf(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : undefined;
}

function requiredString(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) throw new Error("Decision Evidence requires a nonempty string");
  return value;
}

/** Runtime allowlist, not a cast: extra claims never enter the signed object. */
export function runtimeCredentialOf(value: unknown): RuntimeCredentialRef | undefined {
  const p = objectOf(value);
  if (!p) return undefined;
  const issuer = typeof p.issuer === "string" && p.issuer.length > 0 ? p.issuer : undefined;
  const expires_at = typeof p.expires_at === "string" && Number.isFinite(Date.parse(p.expires_at)) ? p.expires_at : undefined;
  return issuer || expires_at ? { ...(issuer ? { issuer } : {}), ...(expires_at ? { expires_at } : {}) } : undefined;
}

/** Preserve identifiers and chain order, but no arbitrary hop claims or nested keys. */
function runtimeActorOf(value: unknown): ContextActor | undefined {
  const p = objectOf(value);
  if (!p) return undefined;
  const out: ContextActor = {};
  if (typeof p.client_id === "string") out.client_id = p.client_id;
  if (typeof p.client_instance_id === "string") out.client_instance_id = p.client_instance_id;
  if (p.act !== undefined) {
    if (!Array.isArray(p.act)) return undefined;
    const chain = [];
    for (const value of p.act) {
      const hop = objectOf(value);
      if (!hop || typeof hop.iss !== "string" || typeof hop.sub !== "string") return undefined;
      chain.push({ iss: hop.iss, sub: hop.sub, ...(typeof hop.sub_profile === "string" ? { sub_profile: hop.sub_profile } : {}) });
    }
    out.act = chain;
  }
  return Object.keys(out).length ? out : undefined;
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
  catalog_digest?: string;
  executor?: string;
}

/** Supported prefix is insufficient: require canonical unpadded SHA-256 bytes. */
function capabilityDigest(value: unknown): value is string {
  if (typeof value !== "string" || !/^sha-256:[A-Za-z0-9_-]{43}$/.test(value)) return false;
  const encoded = value.slice("sha-256:".length);
  const bytes = Buffer.from(encoded, "base64url");
  return bytes.length === 32 && bytes.toString("base64url") === encoded;
}

/** Field-by-field narrowing; malformed input is never copied into signed evidence. */
export function runtimeCapabilitySourceOf(presented: unknown): RuntimeCapabilitySource | undefined {
  if (!presented || typeof presented !== "object" || Array.isArray(presented)) return undefined;
  const p = presented as Record<string, unknown>;
  const nonempty = (v: unknown): v is string => typeof v === "string" && v.length > 0;
  if (!nonempty(p.tool_id) || !nonempty(p.source_uri) || !nonempty(p.operation_ref) || !capabilityDigest(p.source_digest)) return undefined;
  if (p.catalog_digest !== undefined && !capabilityDigest(p.catalog_digest)) return undefined;
  if (p.executor !== undefined && !nonempty(p.executor)) return undefined;
  return { tool_id: p.tool_id, source_uri: p.source_uri, source_digest: p.source_digest, operation_ref: p.operation_ref,
    ...(p.catalog_digest !== undefined ? { catalog_digest: p.catalog_digest as string } : {}),
    ...(p.executor !== undefined ? { executor: p.executor as string } : {}),
  };
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
  credential?: RuntimeCredentialRef;
  capability_source?: RuntimeCapabilitySource;
  principal_mapping?: RuntimePrincipalMapping;
  hop_reference?: RuntimeHopReference;
  parameter_digest?: string;
  evaluation_request_digest?: string;
  conditions?: RuntimeConditions;
  decision: "permit" | "deny";
  denial_reason?: string;
  contributing_constraints?: string[];
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
 * `capability_source` is narrowed from the PDP's own evaluated input. A valid
 * mismatch is useful on a drift denial; malformed input is omitted. The
 * fallback request summary and parameter digest do not commit omitted bytes.
 */
export interface DecisionEvidenceEmissionInput {
  capability_source?: RuntimeCapabilitySource;
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
  credential?: RuntimeCredentialRef;
  principal_mapping?: RuntimePrincipalMapping;
  parameter_digest?: string;
  conditions?: RuntimeConditions;
  denial_reason?: string;
  contributing_constraints?: readonly string[];
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
  const nextSequence = (mission: RuntimeMissionRef): number => {
    const key = JSON.stringify([mission.issuer, mission.id, config.emitterId, "pdp"]);
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
      if (input.parameter_digest !== undefined) requiredString(input.parameter_digest);
      if (input.conditions?.use_limit !== undefined && (!Number.isSafeInteger(input.conditions.use_limit) || input.conditions.use_limit < 1)) {
        throw new Error("Decision Evidence use_limit must be a positive integer");
      }
      const classes = ["consequential_read", "consequential_write", "irreversible_action", "external_commitment", "privileged_administration"];
      if (!classes.includes(action_class)) throw new Error("Decision Evidence has an unknown action class");
      if (input.decision === "permit" && (!input.entry_digest || !input.conditions)) {
        throw new Error("Decision Evidence permit requires entry digest and conditions");
      }
      if (input.conditions?.parameter_digest !== input.parameter_digest && input.decision === "permit") {
        throw new Error("Decision Evidence parameter binding differs from wire conditions");
      }
      if (input.decision === "permit" && classes.slice(2).includes(action_class) && input.conditions?.use_limit !== 1) {
        throw new Error("Decision Evidence high-consequence permit requires use_limit 1");
      }
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
      const capability_source = runtimeCapabilitySourceOf(input.capability_source);
      const actor = runtimeActorOf(input.actor);
      const credential = runtimeCredentialOf(input.credential);
      const mission: RuntimeMissionRef = {
        id: requiredString(input.mission.id), issuer: requiredString(input.mission.issuer),
        policy_view_id: requiredString(input.mission.policy_view_id),
        ...(typeof input.mission.authority_hash === "string" ? { authority_hash: input.mission.authority_hash } : {}),
        ...(typeof input.mission.intent_hash === "string" ? { intent_hash: input.mission.intent_hash } : {}),
        ...(typeof input.mission.policy_version === "string" ? { policy_version: input.mission.policy_version } : {}),
      };
      const unsigned = {
        evidence_id: newRecordId("evd"),
        evaluation_id: input.evaluation_id,
        mission,
        subject: { id: requiredString(input.subject.id),
          ...(typeof input.subject.type === "string" ? { type: input.subject.type } : {}),
          ...(typeof input.subject.properties?.iss === "string" ? { properties: { iss: input.subject.properties.iss } } : {}),
        },
        resource: { type: requiredString(input.resource.type), id: requiredString(input.resource.id) },
        action: { name: requiredString(input.action.name) },
        audience: input.audience,
        action_class,
        class_source,
        ...(capability_source ? { capability_source } : {}),
        ...(actor ? { actor } : {}),
        ...(credential ? { credential } : {}),
        ...(input.principal_mapping !== undefined ? { principal_mapping: input.principal_mapping } : {}),
        ...(input.parameter_digest !== undefined ? { parameter_digest: input.parameter_digest } : {}),
        ...(evaluation_request_digest !== undefined ? { evaluation_request_digest } : {}),
        ...(input.conditions !== undefined ? { conditions: {
          valid_until: requiredString(input.conditions.valid_until),
          ...(input.conditions.use_limit !== undefined ? { use_limit: input.conditions.use_limit } : {}),
        } } : {}),
        decision: input.decision,
        ...(input.denial_reason !== undefined ? { denial_reason: input.denial_reason } : {}),
        ...(input.contributing_constraints?.length ? {
          contributing_constraints: [...new Set(input.contributing_constraints.map(requiredString))],
        } : {}),
        ...(input.entry_digest !== undefined ? { entry_digest: input.entry_digest } : {}),
        sequence: nextSequence(mission),
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
