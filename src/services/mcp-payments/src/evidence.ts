/**
 * @spec authzen evidence objects (Decision Evidence, Refusal Record)
 * @spec D13 (trace_id extension member), D32 (producers retain their own)
 * @spec draft-mcguinness-mission-runtime-evidence.md #decision-evidence-object,
 * #pre-decision-refusal, #execution-evidence-object,
 * #decision-evidence-integrity (issue #649, ruling at 41f66a4a): Decision
 * Evidence, Refusal Records, and Execution Evidence are the CURRENT
 * spec-native closed objects (see `DecisionEvidenceObject`,
 * `RefusalRecordObject`, `ExecutionEvidenceObject` below), genuinely signed
 * under runtime-evidence.md's own integrity algorithm
 * (`runtime-evidence-integrity.ts`). `EvidenceStore` fails closed: there is
 * no public unsigned-record path left for these three kinds. Egress and
 * Ingestion (Harness/Containment, issue #649's deferred slices B/C) keep the
 * pre-existing unsigned retention path unchanged.
 *
 * SCITT/transparency registration remains M10 future work.
 */

import { createHash, randomBytes } from "node:crypto";
import type { ContextActor } from "@mission/actor-chain";
import { canonicalDigest, computeAnchor, type JsonValue } from "@mission/core";
import { currentTraceId } from "@mission/telemetry";
import { createLocalJWKSet, type JWK, type JWTPayload, jwtVerify, SignJWT } from "jose";
import {
  DECISION_EVIDENCE_MEDIA_TYPE,
  EXECUTION_EVIDENCE_MEDIA_TYPE,
  type EvidenceEmitterRef,
  type EvidenceEnvelope,
  type EvidenceKeyLike,
  type EvidenceKeyResolver,
  type EvidenceVerifyResult,
  MISSION_RECEIPT_MEDIA_TYPE,
  REFUSAL_RECORD_MEDIA_TYPE,
  RUNTIME_EVIDENCE_JWS_TYP,
  signEvidenceEnvelope,
  verifyEvidenceEnvelope,
} from "./runtime-evidence-integrity.js";

/**
 * @spec authzen `emitter.role`: the coordinated set of enforcement-point roles
 * that emit records under these conventions. The three authzen roles
 * (pdp/pep/executor), the two companion runtime points (harness/egress), and
 * `issuer` for records the AUTHORIZATION SERVER retains itself (protected-event
 * ingestion; the issuer-held Containment Plane).
 */
export type EmitterRole = "pdp" | "pep" | "executor" | "harness" | "egress" | "issuer";

export interface EvidenceBase {
  decision_id?: string;
  /**
   * @spec authzen#response-context: the PDP response's own `evaluation_id`
   * correlation identifier, copied onto the record alongside `decision_id`
   * (additive, not a replacement; `decision_id` stays the permit id
   * downstream). A distinct `evidence_id` identifying the RECORD itself
   * (the draft's other named member here) is a named deferral: this store
   * has no record-identity concept today beyond `trace_id`/`at`.
   */
  evaluation_id?: string;
  mission_id: string;
  /**
   * @spec runtime-evidence#decision-evidence-object, #refusal-record (#702) —
   * OPTIONAL: `authority_hash` is no longer on the baseline `mission` claim,
   * so a Refusal Record emitted before the PEP resolves a `MissionView` (no
   * verified token copy either) carries no `authority_hash`. A Decision
   * Evidence record, produced only after the PEP loads its own `MissionView`,
   * always has one to carry (see the `view.authority_hash` call site).
   */
  authority_hash?: string;
  action: string;
  parameter_digest?: string;
  instance_epoch: string;
  trace_id?: string;
  at: string;
  /**
   * @spec continuation (hop attribution): when the action was taken under a
   * continued credential, the specific continuation hop that authorized it.
   * `jti` is the authorizing token's identifier and `mission_id` the Mission it
   * belongs to; `continuation_handle` is the hop's identity-continuation handle
   * when present. Absent for a non-continued (or non-JWT) credential.
   */
  hop_reference?: { jti: string; mission_id: string; continuation_handle?: string };
  /**
   * @spec authzen `emitter`: the identity and role of the component that
   * emitted this record. `role` covers the authzen roles (pdp/pep/executor)
   * plus the coordinated companion roles for records emitted under these
   * conventions at other enforcement points (harness, egress, issuer).
   */
  emitter?: { id: string; role: EmitterRole };
  /**
   * @spec runtime (Enforcement Scope Statement): the integrity-anchor encoded
   * digest of the scope statement the emitting component enforced under, so a
   * record can be joined to the published enforcement scope after the fact.
   */
  scope_statement_digest?: string;
}

// ---------------------------------------------------------------------------
// Runtime Evidence: spec-native signed objects (issue #649)
// ---------------------------------------------------------------------------
//
// @spec draft-mcguinness-mission-runtime-evidence.md #decision-evidence-object
// (lines 331-573), #pre-decision-refusal (575-773), #execution-evidence-object
// (982-1116), #decision-evidence-integrity (775-872): all anchors at
// 41f66a4a.
//
// Each `*Object` type below is EXACTLY runtime-evidence.md's closed member
// set for that record: the core REQUIRED/OPTIONAL/CONDITIONAL members this
// deployment populates, plus the coordinated extension members it genuinely
// carries (`actor`, `capability_source`, `hop_reference`, `principal_mapping`,
// {{evidence-extensions}}). It is the ONLY thing that gets JCS-canonicalized
// and signed: `signEvidenceEnvelope`/`verifyEvidenceEnvelope` see exactly this
// object (minus `evidence_envelope` while signing), never the wrapper below.
//
// Members this deployment does not yet populate (`contributing_constraints`:
// the PDP does not track which constraint/authorization_details entries a
// decision turned on; `mission_state_version`; `credential` on Decision
// Evidence; `authorizing_entry`, `obligations`, `mission_history`, `taint` on
// Decision Evidence; `compensates_evaluation_id`) are simply absent from the
// type, not stubbed: see the issue #649 PR body for the full list and why.
//
// Store/query bookkeeping that has no home in a closed member set (a flat
// `mission_id` join key even where the spec's own `mission` member is
// nested, or genuinely OPTIONAL on Refusal Record; `trace_id`; the payments
// domain's own `permit_id`/`op_key` correlation) lives OUTSIDE `content`, as
// a plain sibling on the retained `DecisionEvidence` / `RefusalRecord` /
// `ExecutionEvidence` wrapper (the same treatment `trace_id` already had
// (it was never a runtime-evidence.md member either). `mission_id` on the
// wrapper is DERIVED from `content` wherever `content` carries a Mission
// reference; it exists independently of `content` only for a Refusal Record
// whose `mission` is genuinely absent (no Mission established before the
// failure), so the record still files under its CLAIMED mission for
// operator-facing correlation without asserting establishment anywhere.

/** @spec runtime-evidence#decision-evidence-object mission sub-object (REQUIRES `policy_view_id`). */
export interface RuntimeMissionRef {
  id: string;
  issuer: string;
  policy_view_id: string;
  authority_hash?: string;
  intent_hash?: string;
  policy_version?: string;
}

/** @spec runtime-evidence#pre-decision-refusal `mission` member: no `policy_view_id` requirement. */
export interface RuntimeMissionRefBasic {
  id: string;
  issuer: string;
  authority_hash?: string;
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

/** @spec runtime-evidence#pre-decision-refusal (lines 575-773): the closed wire object. */
export interface RefusalRecordObject {
  refusal_id: string;
  audience: string;
  action: RuntimeActionRef;
  resource?: RuntimeResourceRef;
  decision: "deny";
  denial_reason: string;
  evaluated_at: string;
  parameter_digest?: string;
  evaluation_request_digest?: string;
  mission?: RuntimeMissionRefBasic;
  subject?: RuntimeSubjectRef;
  actor?: ContextActor;
  principal_mapping?: RuntimePrincipalMapping;
  hop_reference?: RuntimeHopReference;
  sequence?: number;
  emitter: { id: string; role: "pdp" | "pep" };
  evidence_envelope: EvidenceEnvelope;
}

/** @spec runtime-evidence#execution-evidence-object (lines 982-1116): the closed wire object. */
export interface ExecutionEvidenceObject {
  execution_id: string;
  evaluation_id: string;
  mission_id: string;
  audience: string;
  authorized_parameter_digest?: string;
  effective_parameter_digest?: string;
  outcome: "completed" | "failed" | "suppressed";
  outcome_at: string;
  error?: string;
  obligation_outcomes?: Array<{
    id: string;
    type: string;
    outcome: "fulfilled" | "failed" | "unsupported";
    error?: string;
  }>;
  sequence: number;
  emitter: { id: string; role: "pep" | "executor" };
  hop_reference?: RuntimeHopReference;
  attempted_at?: string;
  completed_at?: string;
  result_summary?: Record<string, JsonValue>;
  evidence_envelope: EvidenceEnvelope;
}

/** The retained Decision Evidence row: `content` is the exact signed spec object. */
export interface DecisionEvidence {
  kind: "decision";
  mission_id: string;
  trace_id?: string;
  at: string;
  content: DecisionEvidenceObject;
}

/** The retained Refusal Record row: `content` is the exact signed spec object. */
export interface RefusalRecord {
  kind: "refusal";
  mission_id: string;
  trace_id?: string;
  at: string;
  content: RefusalRecordObject;
}

/** The retained Execution Evidence row: `content` is the exact signed spec object. */
export interface ExecutionEvidence {
  kind: "execution";
  mission_id: string;
  /** Payments-domain join keys (reconcile.ts); not spec members. */
  permit_id: string;
  op_key: string;
  trace_id?: string;
  at: string;
  content: ExecutionEvidenceObject;
}

/**
 * @spec authzen (emitter role `egress`): the record an egress enforcement
 * point retains for an outbound channel use, on the same evidence base as
 * decision/refusal/execution so one verification path covers all of them.
 */
export interface EgressEvidence extends EvidenceBase {
  kind: "egress";
  channel_class: string;
  destination: string;
  outcome: "permitted" | "refused";
  /** Present when `outcome` is `refused`: the failure condition. */
  refusal_reason?: string;
}

/**
 * @spec containment#protected-events, containment#containment-plane — the
 * record the ISSUER retains for one protected-event report received at the
 * ingestion endpoint. First-class on the UNIFIED evidence contract (emitter
 * role `issuer`), NOT a kernel-local table, so it joins the same verification
 * and activity-log surface as the enforcement-point records.
 *
 * Recorded for BOTH outcomes: fail-closed means an unverifiable or untrusted
 * event is rejected AND recorded, never silently ignored. `outcome: "applied"`
 * carries the ContainmentPolicy `rule_id` that fired; `outcome: "rejected"`
 * carries a `rejection_reason` (e.g. `unknown_event_type`, `bad_signature`,
 * `unknown_source`, `source_not_trusted_for_type`, `mission_mismatch`,
 * `mission_terminal`, `malformed_jws`). `advisory` marks a LOW-TRUST report
 * (a harness-forwarded egress refusal): the in-process egress gate is not a
 * trusted signing source, so its refusals are advisory and the PEP/PDP remain
 * the backstop.
 *
 * Deliberately does NOT extend {@link EvidenceBase}: an issuer-side ingestion
 * record carries no `authority_hash`/`action`/`instance_epoch` (those are
 * enforcement-point members). It reuses the record-envelope conventions
 * (`emitter`, `scope_statement_digest`, `trace_id`, `at`) directly.
 */
export interface IngestionEvidence {
  kind: "ingestion";
  event_type: string;
  source: string;
  outcome: "applied" | "rejected";
  /** Present when `outcome` is `rejected`: why the event was refused. */
  rejection_reason?: string;
  /** The ContainmentPolicy `rule_id` that fired; present when `outcome` is `applied`. */
  rule_id?: string;
  mission_id: string;
  event_id: string;
  /** Low-trust provenance: a harness-forwarded egress report (advisory only). */
  advisory?: boolean;
  emitter?: { id: string; role: EmitterRole };
  scope_statement_digest?: string;
  trace_id?: string;
  at: string;
}

/**
 * @spec work-products#provenance — the WORK-PRODUCT PROVENANCE object: the
 * artifact-scoped companion to the execution-time evidence continuity. It answers
 * "under what approved work did this information come into existence?", NEVER
 * "what may the reader do." A first-class kind on the UNIFIED evidence envelope
 * so one verification/join path carries it, but POLICY-FREE and attribution-only:
 * it carries EXACTLY these five members and no authority claim of any kind.
 *
 * The crucial distinction from the activity-log `producer` (which names the
 * emitting COMPONENT, pdp/pep/executor/...): here `producer` is the producing
 * MISSION's PRINCIPAL/agent. The two are never conflated (the activity-log join
 * maps this onto its own `artifact_producer` field, never `emitter.id`).
 *
 * Deliberately does NOT extend {@link EvidenceBase} (like {@link
 * IngestionEvidence}): a provenance object carries no
 * `authority_hash`/`action`/`instance_epoch` (those are enforcement-point
 * members, and an authority hash on an attribution object would blur the
 * provenance/authority line this object exists to keep sharp). It carries its OWN
 * `created_at` (the artifact's production time), so it is BUILT by {@link
 * buildArtifactEvidence} and travels attached to the work product; it is never
 * emitted through {@link EvidenceStore.record} (which would stamp the envelope's
 * `at`/`trace_id`, members this object intentionally omits).
 */
export interface ArtifactEvidence {
  kind: "artifact";
  /** The producing Mission (attribution of the approved work). */
  mission_id: string;
  /** The Agent Deployment that produced the artifact. */
  deployment_id: string;
  /** The producing principal/agent under that Mission (NOT the emitting component). */
  producer: string;
  /** Production time. */
  created_at: string;
  /** Optional back-reference to the artifact this derived from (provenance chain). */
  parent_artifact?: string;
}

/** The members {@link buildArtifactEvidence} accepts; `created_at` defaults to now. */
export type ArtifactEvidenceInput = {
  mission_id: string;
  deployment_id: string;
  producer: string;
  created_at?: string;
  parent_artifact?: string;
};

/**
 * @spec work-products#provenance — build a work-product provenance object.
 * Policy-free and attribution-only (mirrors {@link
 * buildContainmentEvidence}'s pure-builder shape): it stamps EXACTLY the five
 * provenance members and nothing else. `created_at` defaults to now when the
 * caller does not supply a production time.
 */
export function buildArtifactEvidence(input: ArtifactEvidenceInput): ArtifactEvidence {
  return {
    kind: "artifact",
    mission_id: input.mission_id,
    deployment_id: input.deployment_id,
    producer: input.producer,
    created_at: input.created_at ?? new Date().toISOString(),
    ...(input.parent_artifact !== undefined ? { parent_artifact: input.parent_artifact } : {}),
  };
}

// ---------------------------------------------------------------------------
// Work Product Provenance -> artifact binding (@spec work-products#binding)
// ---------------------------------------------------------------------------
//
// A tamper-evident binding proving a Work Product Provenance object describes a
// SPECIFIC artifact and was attached by a TRUSTED MEDIATOR, WITHOUT making
// provenance authority-bearing. The binding is a SEPARATE signed object beside
// the sealed provenance object above: the five-member ArtifactEvidence object is
// NEVER modified, and no sixth member is ever added to it to carry a digest.
//
// Envelope: the family's own JWS Compact idiom (as used by signed SETs in
// mission-signals and by the child-grant / txn tokens), ES256 with a `kid` and a
// domain-separating `typ`. It profiles in-toto's subject / digest / predicate
// MODEL only (subject = artifact_digest, predicate = the referenced provenance
// object); it is NOT native in-toto DSSE. A byte-compatible DSSE or SLSA-tooling
// translation is future, out-of-scope interop work.

/**
 * @spec work-products#binding — the JOSE `typ` header for a Work Product
 * Provenance binding, the short media-type form the family uses for its own
 * invented token types (compare `oauth-mission-child-grant+jwt`,
 * `mission-txn-token+jwt`). The IANA-registered media type is
 * `application/mission-work-product-binding+jwt`; the `typ` header carries the
 * short form. Domain separation means a binding digest can NEVER be mistaken for
 * an authority artifact.
 */
export const WORK_PRODUCT_BINDING_TYP = "mission-work-product-binding+jwt";

/**
 * @spec work-products#binding — the integrity-anchor `typ` domain separator for
 * the provenance digest. The sealed five-member provenance object is hashed
 * WITHOUT modification under the core integrity-anchor envelope
 * `{ typ, iss, value }` (core's documented extension point for additional
 * committed objects), so the digest transitively binds attribution to artifact.
 */
export const WORK_PRODUCT_PROVENANCE_TYP = "mission-work-product-provenance";

/**
 * @spec work-products#binding — the artifact's opaque byte form. An artifact is
 * opaque content (a file, message, memory entry, queue event), so its digest is
 * over RAW BYTES, NOT a JCS canonicalization (JCS is for the JSON objects the
 * family commits to, never for opaque payloads). A caller holding the true wire
 * bytes SHOULD pass a Uint8Array or string directly. The `JSON.stringify` (in
 * UTF-8, insertion order PRESERVED, deliberately NOT JCS-canonicalized)
 * derivation for structured content is a DOCUMENTED CONVENIENCE, not normative:
 * the digest is over the octets ACTUALLY EXCHANGED, and producer and consumer
 * MUST agree on that byte form.
 */
export function workProductBytes(content: unknown): Uint8Array {
  if (content instanceof Uint8Array) return content;
  if (typeof content === "string") return new TextEncoder().encode(content);
  return new TextEncoder().encode(JSON.stringify(content));
}

/**
 * @spec work-products#binding — the SUBJECT digest: `sha-256:` + base64url (no
 * padding) of SHA-256 over the artifact's raw bytes ({@link workProductBytes}).
 * Matches the family's integrity-anchor encoding.
 */
export function computeArtifactDigest(content: unknown): string {
  const digest = createHash("sha256").update(workProductBytes(content)).digest();
  return `sha-256:${digest.toString("base64url")}`;
}

/**
 * @spec work-products#binding — the provenance digest: the integrity anchor of
 * the sealed five-member provenance object under {@link
 * WORK_PRODUCT_PROVENANCE_TYP}, computed with the SAME {@link computeAnchor}
 * helper used for intent_hash / authority_hash. It binds the attribution object
 * WITHOUT modifying it; `iss` is the Issuer / deployment URL (the same value as
 * the binding's JWS `iss`), so the digest reproduces from the record.
 */
export function computeProvenanceDigest(iss: string, provenance: ArtifactEvidence): string {
  return computeAnchor(WORK_PRODUCT_PROVENANCE_TYP, iss, provenance as unknown as JsonValue);
}

/**
 * @spec work-products#binding — the JWS payload members. The PREDICATE analog
 * (the sealed provenance object) is referenced by `provenance_digest` and
 * carried ALONGSIDE the binding, never copied in, so there is one source of
 * truth. `mediator {id, role}` names the SIGNER (a harness or issuer
 * mediator); it is INDEPENDENT of the JWS `iss`, which is the Issuer /
 * deployment URL under which the signer publishes its key set.
 */
export interface WorkProductBindingPayload {
  artifact_digest: string;
  provenance_digest: string;
  mediator: { id: string; role: "harness" | "issuer" };
}

/** Options for {@link signWorkProductBinding}. */
export interface SignWorkProductBindingOptions {
  /** The sealed provenance object the binding attests to (referenced, not copied). */
  provenance: ArtifactEvidence;
  /** The artifact whose raw bytes are the SUBJECT (unless `artifactBytes` is given). */
  content: unknown;
  /** The true wire bytes of the artifact; wins over `content` derivation when present. */
  artifactBytes?: Uint8Array | string;
  /** The trusted mediator (`harness` | `issuer`) that SIGNS; names the signer only. */
  mediator: { id: string; role: "harness" | "issuer" };
  /**
   * The Issuer / deployment URL under which the mediator publishes its key
   * set (the JWS `iss` AND the provenance-digest anchor `iss`, one value). It
   * is INDEPENDENT of `mediator.id`; a harness mediator MUST NOT place a bare
   * non-URL id here.
   */
  iss: string;
  /** The mediator's ES256 signing key. */
  key: Parameters<SignJWT["sign"]>[0];
  /** The `kid` identifying that key in the deployment's published key set. */
  kid: string;
}

/**
 * @spec work-products#binding — sign the binding with the MEDIATOR's key. This
 * is the low-level PRIMITIVE: it does NOT enforce the producer-is-not-signer
 * custody rule. That rule lives in the kernel `bindWorkProduct` (which refuses
 * before signing) and in {@link verifyWorkProductBinding} (which refuses on
 * receipt), one throw or reason per layer. The JWS `iss` and the provenance
 * digest envelope `iss` are both the caller-supplied Issuer / deployment URL
 * (`opts.iss`), NOT the mediator id, so a verifier reproduces the provenance
 * digest from the record. Payload members: `artifact_digest`,
 * `provenance_digest`, `mediator`, plus the envelope `iss` and `iat`.
 */
export async function signWorkProductBinding(opts: SignWorkProductBindingOptions): Promise<string> {
  const iss = opts.iss;
  return new SignJWT({
    artifact_digest: computeArtifactDigest(opts.artifactBytes ?? opts.content),
    provenance_digest: computeProvenanceDigest(iss, opts.provenance),
    mediator: opts.mediator,
  })
    .setProtectedHeader({ alg: "ES256", kid: opts.kid, typ: WORK_PRODUCT_BINDING_TYP })
    .setIssuer(iss)
    .setIssuedAt()
    .sign(opts.key);
}

/** The result of {@link verifyWorkProductBinding}. */
export type BindingVerifyResult =
  | { valid: true; mediator: { id: string; role: "harness" | "issuer" }; iss: string }
  | {
      valid: false;
      reason:
        | "signature"
        | "malformed"
        | "unrecognized_algorithm"
        | "artifact_digest"
        | "provenance_digest"
        | "self_asserted";
    };

/** Options for {@link verifyWorkProductBinding}. */
export interface VerifyWorkProductBindingOptions {
  /** The JWS Compact binding. */
  jws: string;
  /** The provenance object AS RECEIVED (possibly re-attached to a different artifact). */
  provenance: ArtifactEvidence;
  /** The artifact AS RECEIVED. */
  content: unknown;
  /** The true wire bytes of the received artifact; wins over `content` when present. */
  artifactBytes?: Uint8Array | string;
  /** The mediator's published verification keys. */
  jwks: { keys: JWK[] };
}

/**
 * @spec work-products#binding — verify a binding (receiver order): (1) verify
 * the JWS signature against the mediator's keys with the binding `typ`; (2)
 * shape-check the payload; (3) reject an unrecognized digest algorithm prefix
 * BEFORE any compare (core integrity-anchor rule); (4) recompute the artifact
 * digest over the RECEIVED bytes and match; (5) recompute the provenance digest
 * over the RECEIVED provenance object and match; (6) reject a binding whose
 * signer equals the provenance `producer` (self-attestation defeats the custody
 * boundary regardless of what a local sign path refuses).
 *
 * A valid binding is a PRECONDITION to trusting the attribution, NEVER a PDP
 * permit input: the Receiving Mission MUST still re-evaluate any proposed action
 * under its OWN Authority Set. Attribution integrity narrows what the object can
 * be re-attached to; it never widens what a reader may do.
 */
export async function verifyWorkProductBinding(
  opts: VerifyWorkProductBindingOptions,
): Promise<BindingVerifyResult> {
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(opts.jws, createLocalJWKSet({ keys: opts.jwks.keys } as never), {
      typ: WORK_PRODUCT_BINDING_TYP,
    }));
  } catch {
    return { valid: false, reason: "signature" };
  }
  const iss = payload.iss;
  const artifactDigest = payload.artifact_digest;
  const provenanceDigest = payload.provenance_digest;
  const mediator = payload.mediator as { id?: unknown; role?: unknown } | undefined;
  if (
    typeof iss !== "string" ||
    typeof artifactDigest !== "string" ||
    typeof provenanceDigest !== "string" ||
    !mediator ||
    typeof mediator.id !== "string" ||
    (mediator.role !== "harness" && mediator.role !== "issuer")
  ) {
    return { valid: false, reason: "malformed" };
  }
  if (!artifactDigest.startsWith("sha-256:") || !provenanceDigest.startsWith("sha-256:")) {
    return { valid: false, reason: "unrecognized_algorithm" };
  }
  if (computeArtifactDigest(opts.artifactBytes ?? opts.content) !== artifactDigest) {
    return { valid: false, reason: "artifact_digest" };
  }
  if (computeProvenanceDigest(iss, opts.provenance) !== provenanceDigest) {
    return { valid: false, reason: "provenance_digest" };
  }
  if (opts.provenance.producer === mediator.id) {
    return { valid: false, reason: "self_asserted" };
  }
  return { valid: true, mediator: { id: mediator.id, role: mediator.role }, iss };
}

export type Evidence =
  | DecisionEvidence
  | RefusalRecord
  | ExecutionEvidence
  | EgressEvidence
  | IngestionEvidence
  | ArtifactEvidence;

/** Distributive omit so the union's discriminated shapes are preserved. */
type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;

/**
 * The kinds {@link EvidenceStore.record} still accepts: Egress and Ingestion
 * (issue #649's deferred slices B/C keep the pre-existing unsigned path
 * unchanged) plus Artifact (never emitted through `record` in practice, see
 * {@link buildArtifactEvidence}, kept here only because it always was).
 * Decision/Refusal/Execution are deliberately NOT in this union: there is no
 * public unsigned-record path for them any more. Use {@link
 * EvidenceStore.recordDecision}, {@link EvidenceStore.recordRefusal}, or
 * {@link EvidenceStore.recordExecution}.
 */
type UnsignedEvidence = EgressEvidence | IngestionEvidence | ArtifactEvidence;
export type EvidenceInput = DistributiveOmit<UnsignedEvidence, "trace_id" | "at">;

/** Recursively freezes a plain JSON-shaped value so a caller cannot mutate a retained record after signing. */
function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const v of Object.values(value as Record<string, unknown>)) {
      deepFreeze(v);
    }
  }
  return value;
}

/** At least 128 bits of entropy, ABNF `1*64( ALPHA / DIGIT / "-" / "_" )` (runtime-evidence.md, every `*_id` member). */
function newRecordId(prefix: string): string {
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
function requestDigestFallback(input: {
  action: string;
  audience: string;
  mission_id: string;
  resource: string;
  subject: string;
}): string {
  return canonicalDigest(input as unknown as JsonValue);
}

/** One emitter-scoped ES256 signing identity: a `kid` plus the private key it names. */
export interface EvidenceSigningKey {
  kid: string;
  key: EvidenceKeyLike;
}

/**
 * The signer configuration {@link EvidenceStore} needs to emit signed
 * records. Every role is OPTIONAL at the type level so a deployment that
 * only ever plays some roles configures only those (a store that never
 * issues receipts need not carry a `receipt_issuer` key), but each
 * `record*` method fails closed (throws) if the role IT needs is absent,
 * per runtime-evidence.md's own emitter roles ({{decision-evidence-object}}).
 */
export type EvidenceSigningConfig = Partial<Record<"pdp" | "pep" | "executor" | "receipt_issuer", EvidenceSigningKey>>;

/** Input to {@link EvidenceStore.recordDecision}: everything the caller already knows. */
export interface DecisionEvidenceInput {
  mission: RuntimeMissionRef;
  subject: RuntimeSubjectRef;
  resource: RuntimeResourceRef;
  action: RuntimeActionRef;
  audience: string;
  evaluation_id: string;
  decision: "permit" | "deny";
  /** Absent when the deployment has not classified this action; defaults to `consequential_read` / `class_source: "default"`. */
  action_class?: RuntimeActionClass;
  actor?: ContextActor;
  capability_source?: RuntimeCapabilitySource;
  principal_mapping?: RuntimePrincipalMapping;
  hop_reference?: RuntimeHopReference;
  parameter_digest?: string;
  conditions?: RuntimeConditions;
  denial_reason?: string;
  entry_digest?: string;
  trace_id?: string;
}

/** Input to {@link EvidenceStore.recordRefusal}. `missionId` is store-level correlation only (see the file header note); `mission` is the spec's own OPTIONAL, established-only reference. */
export interface RefusalRecordInput {
  missionId: string;
  audience: string;
  action: RuntimeActionRef;
  resource?: RuntimeResourceRef;
  denial_reason: string;
  parameter_digest?: string;
  mission?: RuntimeMissionRefBasic;
  subject?: RuntimeSubjectRef;
  actor?: ContextActor;
  principal_mapping?: RuntimePrincipalMapping;
  hop_reference?: RuntimeHopReference;
  trace_id?: string;
}

/** Input to {@link EvidenceStore.recordExecution}. `permitId`/`opKey` are payments-domain join keys (reconcile.ts), not spec members. */
export interface ExecutionEvidenceInput {
  permitId: string;
  opKey: string;
  evaluation_id: string;
  mission_id: string;
  audience: string;
  authorized_parameter_digest?: string;
  effective_parameter_digest?: string;
  outcome: "completed" | "failed" | "suppressed";
  error?: string;
  obligation_outcomes?: ExecutionEvidenceObject["obligation_outcomes"];
  hop_reference?: RuntimeHopReference;
  attempted_at?: string;
  completed_at?: string;
  result_summary?: Record<string, JsonValue>;
  trace_id?: string;
}

/**
 * @spec runtime-evidence#decision-evidence-object, runtime-evidence#pre-decision-refusal,
 * runtime-evidence#execution-evidence-object, runtime-evidence#decision-evidence-integrity
 * (issue #649): an append-only, in-memory, per-attempt retained store.
 * `recordDecision`/`recordRefusal`/`recordExecution` build the current
 * spec-native closed object, allocate a cryptographically random record id
 * and a monotonically increasing per-(mission, emitter) `sequence`, JCS
 * canonicalize it without `evidence_envelope`, sign ES256 with the
 * configured emitter role's key, and retain the deep-frozen, complete signed
 * object. There is no public path to retain an UNSIGNED Decision, Refusal,
 * or Execution record: a store with no key configured for the role a call
 * needs throws (fail closed) rather than falling back to an unsigned record.
 * `record` keeps the pre-existing unsigned path for Egress and Ingestion
 * (issue #649's deferred slices B/C).
 *
 * PEP-side and per-request; the Controller-owned Mission Record (approval
 * evidence and lifecycle history, mission-substrate#governance-record) is a
 * separate, not-yet-implemented surface this store does not provide.
 */
export class EvidenceStore {
  private readonly records: Evidence[] = [];
  private readonly sequences = new Map<string, number>();

  constructor(private readonly signer?: EvidenceSigningConfig) {}

  private requireSigner(role: "pdp" | "pep" | "executor" | "receipt_issuer"): EvidenceSigningKey {
    const key = this.signer?.[role];
    if (!key) {
      throw new Error(
        `EvidenceStore: no signer configured for emitter role "${role}" (fail closed: this record kind has no unsigned retention path)`,
      );
    }
    return key;
  }

  /**
   * @spec runtime-evidence#decision-evidence-object (line 508): "each emitter
   * maintains its own monotonically increasing per-Mission sequence."
   * `emitter` is itself the `{id, role}` object ({{decision-evidence-object}}
   * `emitter` member), so the sequence is scoped per (mission, id, role): a
   * component playing multiple roles under one `id` (this deployment's
   * co-located pdp/pep/executor) gets one counter PER ROLE, matching the
   * distinct signing key each role already carries. This reading is stated
   * explicitly in the issue #649 PR body for an owner ruling.
   */
  private nextSequence(missionId: string, emitterId: string, role: string): number {
    const key = `${missionId} ${emitterId} ${role}`;
    const n = this.sequences.get(key) ?? 0;
    this.sequences.set(key, n + 1);
    return n;
  }

  /** @spec runtime-evidence#decision-evidence-object: sign and retain a Decision Evidence Object. */
  async recordDecision(emitterId: string, input: DecisionEvidenceInput): Promise<DecisionEvidence> {
    const signer = this.requireSigner("pdp");
    const missionId = input.mission.id;
    const sequence = this.nextSequence(missionId, emitterId, "pdp");
    const action_class = input.action_class ?? "consequential_read";
    const class_source: RuntimeClassSource = input.action_class !== undefined ? "deployment" : "default";
    const evaluation_request_digest =
      input.parameter_digest === undefined
        ? requestDigestFallback({
            action: input.action.name,
            audience: input.audience,
            mission_id: missionId,
            resource: input.resource.id,
            subject: input.subject.id,
          })
        : undefined;
    const evaluated_at = new Date().toISOString();
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
      ...(input.capability_source !== undefined ? { capability_source: input.capability_source } : {}),
      ...(input.principal_mapping !== undefined ? { principal_mapping: input.principal_mapping } : {}),
      ...(input.hop_reference !== undefined ? { hop_reference: input.hop_reference } : {}),
      ...(input.parameter_digest !== undefined ? { parameter_digest: input.parameter_digest } : {}),
      ...(evaluation_request_digest !== undefined ? { evaluation_request_digest } : {}),
      ...(input.conditions !== undefined ? { conditions: input.conditions } : {}),
      decision: input.decision,
      ...(input.denial_reason !== undefined ? { denial_reason: input.denial_reason } : {}),
      ...(input.entry_digest !== undefined ? { entry_digest: input.entry_digest } : {}),
      sequence,
      emitter: { id: emitterId, role: "pdp" as const },
      evaluated_at,
    };
    const evidence_envelope = await signEvidenceEnvelope(unsigned as unknown as JsonValue, DECISION_EVIDENCE_MEDIA_TYPE, signer);
    const content = deepFreeze({ ...unsigned, evidence_envelope }) as DecisionEvidenceObject;
    const traceId = input.trace_id ?? currentTraceId();
    const record: DecisionEvidence = deepFreeze({
      kind: "decision",
      mission_id: missionId,
      ...(traceId !== undefined ? { trace_id: traceId } : {}),
      at: evaluated_at,
      content,
    });
    this.records.push(record);
    return record;
  }

  /** @spec runtime-evidence#pre-decision-refusal: sign and retain a Refusal Record. */
  async recordRefusal(
    emitterId: string,
    role: "pdp" | "pep",
    input: RefusalRecordInput,
  ): Promise<RefusalRecord> {
    const signer = this.requireSigner(role);
    const sequence = input.mission !== undefined ? this.nextSequence(input.mission.id, emitterId, role) : undefined;
    const evaluation_request_digest =
      input.parameter_digest === undefined
        ? requestDigestFallback({
            action: input.action.name,
            audience: input.audience,
            mission_id: input.mission?.id ?? "",
            resource: input.resource?.id ?? "",
            subject: input.subject?.id ?? "",
          })
        : undefined;
    const evaluated_at = new Date().toISOString();
    const unsigned = {
      refusal_id: newRecordId("ref"),
      audience: input.audience,
      action: input.action,
      ...(input.resource !== undefined ? { resource: input.resource } : {}),
      decision: "deny" as const,
      denial_reason: input.denial_reason,
      evaluated_at,
      ...(input.parameter_digest !== undefined ? { parameter_digest: input.parameter_digest } : {}),
      ...(evaluation_request_digest !== undefined ? { evaluation_request_digest } : {}),
      ...(input.mission !== undefined ? { mission: input.mission } : {}),
      ...(input.subject !== undefined ? { subject: input.subject } : {}),
      ...(input.actor !== undefined ? { actor: input.actor } : {}),
      ...(input.principal_mapping !== undefined ? { principal_mapping: input.principal_mapping } : {}),
      ...(input.hop_reference !== undefined ? { hop_reference: input.hop_reference } : {}),
      ...(sequence !== undefined ? { sequence } : {}),
      emitter: { id: emitterId, role },
    };
    const evidence_envelope = await signEvidenceEnvelope(unsigned as unknown as JsonValue, REFUSAL_RECORD_MEDIA_TYPE, signer);
    const content = deepFreeze({ ...unsigned, evidence_envelope }) as RefusalRecordObject;
    const traceId = input.trace_id ?? currentTraceId();
    const record: RefusalRecord = deepFreeze({
      kind: "refusal",
      mission_id: input.missionId,
      ...(traceId !== undefined ? { trace_id: traceId } : {}),
      at: evaluated_at,
      content,
    });
    this.records.push(record);
    return record;
  }

  /** @spec runtime-evidence#execution-evidence-object: sign and retain an Execution Evidence Object. */
  async recordExecution(
    emitterId: string,
    role: "pep" | "executor",
    input: ExecutionEvidenceInput,
  ): Promise<ExecutionEvidence> {
    const signer = this.requireSigner(role === "executor" ? "executor" : "pep");
    const sequence = this.nextSequence(input.mission_id, emitterId, role);
    const outcome_at = new Date().toISOString();
    const unsigned = {
      execution_id: newRecordId("exe"),
      evaluation_id: input.evaluation_id,
      mission_id: input.mission_id,
      audience: input.audience,
      ...(input.authorized_parameter_digest !== undefined
        ? { authorized_parameter_digest: input.authorized_parameter_digest }
        : {}),
      ...(input.effective_parameter_digest !== undefined
        ? { effective_parameter_digest: input.effective_parameter_digest }
        : {}),
      outcome: input.outcome,
      outcome_at,
      ...(input.error !== undefined ? { error: input.error } : {}),
      ...(input.obligation_outcomes !== undefined ? { obligation_outcomes: input.obligation_outcomes } : {}),
      sequence,
      emitter: { id: emitterId, role },
      ...(input.hop_reference !== undefined ? { hop_reference: input.hop_reference } : {}),
      ...(input.attempted_at !== undefined ? { attempted_at: input.attempted_at } : {}),
      ...(input.completed_at !== undefined ? { completed_at: input.completed_at } : {}),
      ...(input.result_summary !== undefined ? { result_summary: input.result_summary } : {}),
    };
    const evidence_envelope = await signEvidenceEnvelope(unsigned as unknown as JsonValue, EXECUTION_EVIDENCE_MEDIA_TYPE, signer);
    const content = deepFreeze({ ...unsigned, evidence_envelope }) as ExecutionEvidenceObject;
    const traceId = input.trace_id ?? currentTraceId();
    const record: ExecutionEvidence = deepFreeze({
      kind: "execution",
      mission_id: input.mission_id,
      permit_id: input.permitId,
      op_key: input.opKey,
      ...(traceId !== undefined ? { trace_id: traceId } : {}),
      at: outcome_at,
      content,
    });
    this.records.push(record);
    return record;
  }

  /** The pre-existing unsigned path: Egress and Ingestion only (see {@link UnsignedEvidence}). */
  record(e: EvidenceInput): Evidence {
    if ((e.kind as string) === "decision" || (e.kind as string) === "refusal" || (e.kind as string) === "execution") {
      throw new Error(
        `EvidenceStore.record(): kind "${e.kind}" is signed evidence; use recordDecision/recordRefusal/recordExecution (fail closed, no unsigned path)`,
      );
    }
    const full = { ...e, trace_id: currentTraceId(), at: new Date().toISOString() } as Evidence;
    this.records.push(full);
    return full;
  }

  forMission(missionId: string): Evidence[] {
    return this.records.filter((r) => r.mission_id === missionId);
  }

  all(): readonly Evidence[] {
    return this.records;
  }
}

/**
 * Build a {@link EvidenceKeyResolver} that binds each published key to its
 * `kid`, emitter `role`, and (unless `audience` is omitted, e.g. a
 * `receipt_issuer` key) a specific `audience`: the scope/audience binding
 * runtime-evidence.md's integrity algorithm requires of a verifier
 * ({{decision-evidence-integrity}}). A record whose `kid`/`role`/`audience`
 * do not match any entry resolves to `undefined` (rejected upstream as
 * `key_not_resolvable`), covering both an unknown `kid` and a genuine
 * cross-role or cross-audience substitution.
 */
export interface EvidenceVerificationKey {
  kid: string;
  publicKey: EvidenceKeyLike;
  role: "pdp" | "pep" | "executor" | "receipt_issuer";
  /** Omit only for a role (e.g. `receipt_issuer`) whose key is not audience-scoped. */
  audience?: string;
}

export function buildEvidenceKeyResolver(keys: readonly EvidenceVerificationKey[]): EvidenceKeyResolver {
  return ({ kid, emitter, audience }) => {
    const match = keys.find(
      (k) => k.kid === kid && k.role === emitter.role && (k.audience === undefined || k.audience === audience),
    );
    return match ? { key: match.publicKey } : undefined;
  };
}

export {
  DECISION_EVIDENCE_MEDIA_TYPE,
  EXECUTION_EVIDENCE_MEDIA_TYPE,
  MISSION_RECEIPT_MEDIA_TYPE,
  REFUSAL_RECORD_MEDIA_TYPE,
  RUNTIME_EVIDENCE_JWS_TYP,
  verifyEvidenceEnvelope,
};
export type { EvidenceEmitterRef, EvidenceEnvelope, EvidenceKeyLike, EvidenceKeyResolver, EvidenceVerifyResult };
