/**
 * @spec draft-mcguinness-oauth-mission-work-products
 *
 * Mission Work Products: the non-transitive Mission-to-Mission handoff. The one
 * invariant it enforces: no authority may be acquired by information propagation
 * alone. An agent may inherit another agent's KNOWLEDGE; it never inherits
 * another agent's AUTHORITY. Information may cross a Mission boundary without
 * authority crossing with it.
 *
 * This is a standalone kernel module (mirrors kernel/cross-domain.ts and
 * kernel/child-delegation.ts). It is DISTINCT from both of them, which is the
 * whole reason it exists as its own seam:
 *   - cross-domain.ts (ID-JAG) preserves the SAME Mission across a trust
 *     boundary: the mission claim (id/issuer/authority_hash) is carried
 *     unchanged and authority projects to the target. Same Mission, authority
 *     travels.
 *   - child-delegation.ts delegates DOWNWARD within a family: a Child Mission is
 *     a new Mission whose authority is a proven strict SUBSET of a parent's.
 *     Authority flows, bounded, through the authority plane.
 *   - work-products.ts moves a produced ARTIFACT between INDEPENDENT Missions:
 *     the receiving Mission re-evaluates every proposed action under its OWN
 *     Authority Set, and the producing Mission's authority does NOT transfer
 *     through the artifact by copying, referencing, embedding, or communicating
 *     it. Different Missions, ONLY information travels.
 *
 * Two functions, both stamped/gated through the kernel but neither touching a
 * Mission's authority:
 *   - {@link produceWorkProduct} stamps the {@link ArtifactEvidence} provenance
 *     object (attribution only, policy-free) on a work product produced under a
 *     Mission, ONLY when attached through a trusted-mediator custody path (@spec
 *     work-products#conformance): it refuses ({@link ProvenanceCustodyError}) a
 *     bare, self-asserted `producer` with no distinct {@link ProvenanceMediator}.
 *   - {@link ingestWorkProduct} ingests that work product into a receiving
 *     Mission as INPUT and returns ONLY the provenance claim plus content
 *     (MUST-level, @spec work-products#handoff), granting NO authority.
 *
 * Both use {@link MissionKernel.gateActive}, NEVER {@link
 * MissionKernel.gateDerivation}: producing or ingesting a work product is not a
 * token derivation and MUST NOT consume a Mission's `derivation_limit`. gateActive
 * is the ONLY kernel state either function touches. Neither reads nor writes any
 * Mission's `authority_set`, containment overlay, or effective Authority Set, so
 * an ingested artifact structurally CANNOT contribute to the receiver's effective
 * authority. Where the receiver needs authority to act on what it read, that
 * authority is obtained only through the authority plane (a Child Mission bounded
 * by the parent, subset rule; see {@link createChildMission}), never here.
 */

import type { JsonValue } from "@mission/core";
import {
  type ArtifactEvidence,
  buildArtifactEvidence,
  signWorkProductBinding,
  type SignWorkProductBindingOptions,
} from "@mission/mcp-payments";
import type { MissionKernel } from "./kernel.js";

/**
 * A produced work product: the durable content plus its {@link ArtifactEvidence}
 * provenance object. The provenance answers "under what approved work did this
 * come into existence"; it never answers "what may the reader do".
 */
export interface WorkProduct<C = JsonValue> {
  /** The provenance object attributing the artifact to its producing Mission. */
  provenance: ArtifactEvidence;
  /** The durable content (a file, message, memory entry, queue event, ...). */
  content: C;
}

/**
 * @spec work-products#conformance — the trusted mediator attaching Work
 * Product Provenance: "an Agent Deployment's execution environment, or the
 * Mission Issuer", the only two competent attachers this document names.
 * `role` reuses the suite's existing evidence-envelope role vocabulary
 * (`EmitterRole` in @mission/mcp-payments: harness = the Agent Deployment's
 * execution environment; issuer = the Mission Issuer) narrowed to those two,
 * rather than inventing a parallel one. `id` MUST be the mediator's OWN
 * identity, distinct from `producer`: the custody boundary this models is
 * "who attaches the object", and a mediator whose `id` equals the producing
 * agent's is that agent self-attaching under another name.
 */
export interface ProvenanceMediator {
  id: string;
  role: "harness" | "issuer";
}

/**
 * @spec work-products#conformance — why {@link produceWorkProduct} refused to
 * attach a Work Product Provenance object.
 */
export type ProvenanceCustodyDenialReason = "self_asserted" | "untrusted_mediator_role";

/**
 * @spec work-products#conformance — the custody boundary refusal: a producing
 * agent MUST NOT self-author or self-assert its own Work Product Provenance.
 */
export class ProvenanceCustodyError extends Error {
  constructor(
    readonly reason: ProvenanceCustodyDenialReason,
    message: string,
  ) {
    super(message);
  }
}

/** The members {@link produceWorkProduct} accepts. */
export interface ProduceWorkProductInput<C = JsonValue> {
  /** The producing Mission (Mission A). */
  missionId: string;
  /** The Agent Deployment that produced the artifact. */
  deploymentId: string;
  /** The producing principal/agent under that Mission (NOT the emitting component). */
  producer: string;
  /**
   * @spec work-products#conformance — the trusted mediator attaching this
   * provenance object, from its OWN record of which Mission's approved work
   * was executing when the artifact was produced. REQUIRED: there is no path
   * through {@link produceWorkProduct} that stamps provenance from a bare,
   * unauthenticated `producer` assertion alone.
   */
  mediator: ProvenanceMediator;
  /** The durable content of the work product. */
  content: C;
  /** Optional provenance-chain back-reference to the artifact this derived from. */
  parentArtifact?: string;
}

/** The members {@link ingestWorkProduct} accepts. */
export interface IngestWorkProductInput<C = JsonValue> {
  /** The work product produced under another (independent) Mission. */
  workProduct: WorkProduct<C>;
  /** The receiving Mission (Mission B) that ingests the artifact as INPUT. */
  receivingMissionId: string;
}

/**
 * What a receiving Mission gets from an ingest: EXACTLY the provenance claim plus
 * the content, and NOTHING that could be authority. The type itself is the
 * contract: there is no member here through which the producing Mission's
 * authority could cross.
 */
export interface IngestedWorkProduct<C = JsonValue> {
  /** The provenance CLAIM (attribution to the PRODUCING Mission), carried unchanged. */
  provenance: ArtifactEvidence;
  /** The content, now INPUT to the receiving Mission. */
  content: C;
}

/**
 * @spec work-products#provenance, #conformance — stamp provenance on a work
 * product produced under Mission A. Production happens under a LIVE Mission
 * (and live lineage): gateActive refuses when the Mission or any ancestor is
 * non-active. It is gateActive, NOT gateDerivation, because producing an
 * artifact is not a token derivation and MUST NOT consume the Mission's
 * derivation cap.
 *
 * The custody boundary (@spec work-products#conformance): the object MUST be
 * attached by a trusted mediator (an Agent Deployment's execution environment
 * or the Mission Issuer), never self-authored by the producing agent. Two
 * independent, MUST-level guards precede the stamp:
 *   - `mediator.role` MUST be one this document recognizes as competent to
 *     attach provenance (`harness` | `issuer`); anything else is refused
 *     `untrusted_mediator_role`.
 *   - `mediator.id` MUST be distinct from `producer`: an attacher asserting
 *     the producing agent's own identity is that agent self-authoring under
 *     another name, refused `self_asserted`.
 * Neither guard touches the stamped object itself: on success the provenance
 * object still carries EXACTLY the five members @spec work-products#provenance
 * defines (the mediator identity is the custody check's input, never a sixth
 * member), so it stays policy-free by construction.
 */
export function produceWorkProduct<C = JsonValue>(
  kernel: MissionKernel,
  input: ProduceWorkProductInput<C>,
): WorkProduct<C> {
  const record = kernel.gateActive(input.missionId);
  if (input.mediator.role !== "harness" && input.mediator.role !== "issuer") {
    throw new ProvenanceCustodyError(
      "untrusted_mediator_role",
      `provenance mediator role '${input.mediator.role}' is not a trusted attacher (harness|issuer)`,
    );
  }
  if (input.mediator.id === input.producer) {
    throw new ProvenanceCustodyError(
      "self_asserted",
      "a producing agent MUST NOT self-author or self-assert its own Work Product Provenance",
    );
  }
  const provenance = buildArtifactEvidence({
    mission_id: record.id,
    deployment_id: input.deploymentId,
    producer: input.producer,
    created_at: kernel.nowDate().toISOString(),
    ...(input.parentArtifact !== undefined ? { parent_artifact: input.parentArtifact } : {}),
  });
  return { provenance, content: input.content };
}

/**
 * @spec work-products#handoff — ingest a work product into a receiving Mission as
 * INPUT, returning ONLY the provenance claim plus content and granting NO
 * authority. The receiving Mission MUST be live to receive input (gateActive,
 * again NOT gateDerivation: ingesting knowledge consumes no derivation cap).
 *
 * gateActive is the ONLY kernel state this function touches. It NEVER reads or
 * writes the receiving Mission's `authority_set`, containment overlay, or
 * effective Authority Set, so the artifact CANNOT contribute to the receiver's
 * effective authority. Any action the receiver then takes on what it read is
 * gated by its OWN Authority Set through the existing PDP/PEP; authority to act is
 * obtained only through the authority plane (a Child Mission bounded by the
 * parent, subset rule), never from this artifact.
 */
export function ingestWorkProduct<C = JsonValue>(
  kernel: MissionKernel,
  input: IngestWorkProductInput<C>,
): IngestedWorkProduct<C> {
  kernel.gateActive(input.receivingMissionId);
  return {
    provenance: input.workProduct.provenance,
    content: input.workProduct.content,
  };
}

/** The members {@link bindWorkProduct} accepts. */
export interface BindWorkProductInput<C = JsonValue> {
  /** The produced work product whose provenance is being bound to its artifact. */
  workProduct: WorkProduct<C>;
  /**
   * @spec work-products#binding, #conformance — the trusted mediator SIGNING the
   * binding: the SAME two competent attachers {@link produceWorkProduct} allows
   * (`harness` = the Agent Deployment's execution environment, or `issuer` = the
   * Mission Issuer). Its `id` MUST differ from the provenance `producer`.
   */
  mediator: ProvenanceMediator;
  /**
   * The Issuer / deployment URL under which the mediator publishes its key set
   * (the binding's JWS `iss` and provenance-digest anchor `iss`). INDEPENDENT of
   * `mediator.id`, so a verifier reproduces the provenance digest from the record.
   */
  iss: string;
  /** The mediator's ES256 signing key. */
  key: SignWorkProductBindingOptions["key"];
  /** The `kid` identifying that key in the mediator's published keys. */
  kid: string;
  /** The true wire bytes of the artifact; wins over the content derivation when present. */
  artifactBytes?: Uint8Array | string;
}

/**
 * @spec work-products#binding — attach a TRUSTED-MEDIATOR-signed binding to a
 * produced work product, proving the provenance object describes THIS specific
 * artifact. The binding is a SEPARATE signed object beside the sealed five-member
 * provenance object; the provenance object is never modified, and this function
 * carries NO authority (a valid binding is a precondition to trusting the
 * attribution, never a PDP permit input; the Receiving Mission still re-evaluates
 * under its OWN Authority Set).
 *
 * The custody boundary mirrors {@link produceWorkProduct}: two independent,
 * MUST-level guards precede the signature, and both reuse {@link
 * ProvenanceCustodyError} and its existing reason vocabulary rather than
 * inventing a parallel one:
 *   - `mediator.role` MUST be a trusted attacher (`harness` | `issuer`); anything
 *     else is refused `untrusted_mediator_role`.
 *   - `mediator.id` MUST differ from the provenance `producer`: a producing agent
 *     signing its own binding is the self-attestation the custody boundary
 *     prevents, refused `self_asserted`.
 *
 * Unlike {@link produceWorkProduct} / {@link ingestWorkProduct}, this function
 * takes NO kernel and performs NO gateActive check: liveness belongs at
 * PRODUCTION (an artifact cannot be produced under a non-live Mission), while
 * binding is a custody SIGNATURE over an already-produced provenance object. A
 * mediator (e.g. the Mission Issuer) may legitimately bind after production, so
 * gating here would assert a rule the profile does not state.
 */
export async function bindWorkProduct<C = JsonValue>(
  input: BindWorkProductInput<C>,
): Promise<string> {
  const { workProduct, mediator } = input;
  if (mediator.role !== "harness" && mediator.role !== "issuer") {
    throw new ProvenanceCustodyError(
      "untrusted_mediator_role",
      `binding mediator role '${mediator.role}' is not a trusted attacher (harness|issuer)`,
    );
  }
  if (mediator.id === workProduct.provenance.producer) {
    throw new ProvenanceCustodyError(
      "self_asserted",
      "a producing agent MUST NOT sign its own Work Product Provenance binding",
    );
  }
  return signWorkProductBinding({
    provenance: workProduct.provenance,
    content: workProduct.content,
    ...(input.artifactBytes !== undefined ? { artifactBytes: input.artifactBytes } : {}),
    mediator: { id: mediator.id, role: mediator.role },
    iss: input.iss,
    key: input.key,
    kid: input.kid,
  });
}
