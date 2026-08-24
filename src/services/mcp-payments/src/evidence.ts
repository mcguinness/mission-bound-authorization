/**
 * @spec authzen evidence objects (Decision Evidence, Refusal Record)
 * @spec D13 (trace_id extension member), D32 (producers retain their own)
 *
 * The PEP retains its own evidence (feed-driven distributed, D32). Signing
 * and SCITT registration land in M10; M4 records the retained objects and
 * the members the operation profile fixes.
 */

import { createHash } from "node:crypto";
import { computeAnchor, type JsonValue } from "@mission/core";
import { currentTraceId } from "@mission/telemetry";
import { createLocalJWKSet, type JWK, type JWTPayload, jwtVerify, SignJWT } from "jose";

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
  authority_hash: string;
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

export interface DecisionEvidence extends EvidenceBase {
  kind: "decision";
  decision: boolean;
  policy_view_id?: string;
  denial_reason?: string;
  /**
   * @spec authzen `entry_digest`: the integrity-anchor encoded digest of the
   * Authority Set entry the decision was evaluated against (the resolved-scope
   * anchor), copied from the PDP's decision context when present.
   */
  entry_digest?: string;
  /**
   * @spec cross-domain#origin-principal-mapping, runtime-evidence#principal_mapping,
   * runtime-evidence#evidence-pii — present whenever the decision evaluated the
   * cross-domain Origin Principal profile's mapping (permit or a later-step
   * denial that still passed the mapping check), never a partial object.
   * `origin`/`local` are PROTECTED subject references (the family anchor
   * idiom, `typ` `mission-origin-subject`, {@link MISSION_ORIGIN_SUBJECT_TYP}),
   * never the raw `{iss, sub}` pair: this is a RETAINED record, and the
   * privacy rule requires a protected reference here, not the ephemeral
   * PDP decision context's raw values.
   *
   * DISCLOSURE (@spec runtime-evidence#evidence-pii): this deployment uses
   * the deterministic-digest form of protected reference (a keyed
   * pseudonym or an opaque, auditor-resolvable reference are the other two
   * forms the spec allows). A deterministic digest of an enumerable
   * identifier is dictionary-attackable: it is correlation infrastructure,
   * not concealment. Anyone who can enumerate candidate `{iss, sub}` pairs
   * (a small, known population) can confirm membership by recomputing the
   * digest; it does not hide WHICH known principal a record is about, only
   * that raw identity is not stored verbatim.
   */
  principal_mapping?: {
    origin: string;
    local: string;
    policy: { id: string; version: string };
    observed_at: string;
    valid_until: string;
  };
}

export interface RefusalRecord extends EvidenceBase {
  kind: "refusal";
  refusal_reason: string;
}

/** @spec authzen Execution Evidence: the outcome joined to the decision. */
export interface ExecutionEvidence extends EvidenceBase {
  kind: "execution";
  permit_id: string;
  op_key: string;
  outcome: "committed" | "deduped";
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
export type EvidenceInput = DistributiveOmit<Evidence, "trace_id" | "at">;

/**
 * @spec runtime-evidence#decision-evidence-object, runtime-evidence#pre-decision-refusal:
 * an append-only, in-memory, per-attempt retained store: `record` only ever
 * pushes, never amends or replaces an existing entry, so a retried refusal
 * or decision yields its own distinct record. PEP-side and per-request; the
 * Controller-owned Mission Record (approval evidence and lifecycle history,
 * mission-substrate#governance-record) is a separate, not-yet-implemented
 * surface this store does not provide.
 */
export class EvidenceStore {
  private readonly records: Evidence[] = [];

  record(e: EvidenceInput): Evidence {
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
