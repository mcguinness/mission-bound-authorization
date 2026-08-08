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
 *     Mission.
 *   - {@link ingestWorkProduct} ingests that work product into a receiving
 *     Mission as INPUT and returns ONLY the provenance claim plus content,
 *     granting NO authority.
 *
 * Both use {@link MissionKernel.gateActive}, NEVER {@link
 * MissionKernel.gateDerivation}: producing or ingesting a work product is not a
 * token derivation and MUST NOT consume a Mission's `max_derivations`. gateActive
 * is the ONLY kernel state either function touches. Neither reads nor writes any
 * Mission's `authority_set`, containment overlay, or effective Authority Set, so
 * an ingested artifact structurally CANNOT contribute to the receiver's effective
 * authority. Where the receiver needs authority to act on what it read, that
 * authority is obtained only through the authority plane (a Child Mission bounded
 * by the parent, subset rule; see {@link createChildMission}), never here.
 */

import type { JsonValue } from "@mission/core";
import { type ArtifactEvidence, buildArtifactEvidence } from "@mission/mcp-payments";
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

/** The members {@link produceWorkProduct} accepts. */
export interface ProduceWorkProductInput<C = JsonValue> {
  /** The producing Mission (Mission A). */
  missionId: string;
  /** The Agent Deployment that produced the artifact. */
  deploymentId: string;
  /** The producing principal/agent under that Mission (NOT the emitting component). */
  producer: string;
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
 * @spec work-products#provenance — stamp provenance on a work product produced
 * under Mission A. Production happens under a LIVE Mission (and live lineage):
 * gateActive refuses when the Mission or any ancestor is non-active. It is
 * gateActive, NOT gateDerivation, because producing an artifact is not a token
 * derivation and MUST NOT consume the Mission's derivation cap.
 *
 * The provenance object is policy-free and attribution-only: it records the
 * producing Mission, the Agent Deployment, the producing principal, and the
 * production time (plus an optional parent-artifact back-reference), and nothing
 * else. It makes a PROVENANCE claim, never an authority claim.
 */
export function produceWorkProduct<C = JsonValue>(
  kernel: MissionKernel,
  input: ProduceWorkProductInput<C>,
): WorkProduct<C> {
  const record = kernel.gateActive(input.missionId);
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
