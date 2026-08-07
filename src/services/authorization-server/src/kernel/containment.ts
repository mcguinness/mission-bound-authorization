/**
 * Mission Containment evidence: audit material recording one applied contain
 * transition (the issuer-committed, monotonic narrowing of a Mission's
 * effective authority). It grants no authority and restores none. Its
 * canonical bytes are its JCS (RFC 8785) canonicalization; its media type is
 * `application/mission-containment-evidence+json`. Mirrors the Child Evidence
 * conventions in child-delegation.ts (JCS bytes, media-type constant, prefixed
 * random `evidence_id`).
 *
 * This module is the evidence builder only. The contain transition itself
 * (union, idempotency, the version-incrementing metadata-only commit) lives in
 * the kernel ({@link MissionKernel.contain}); the PDP join and the demo
 * trigger land in a follow-up PR.
 */

import { randomBytes } from "node:crypto";
import { canonicalize, type JsonValue } from "@mission/core";

/** The Containment Evidence media type; canonical bytes are the JCS form. */
export const CONTAINMENT_EVIDENCE_MEDIA_TYPE = "application/mission-containment-evidence+json";

/** The Containment Evidence record for one contain transition. */
export interface ContainmentEvidence {
  evidence_id: string;
  /** The Mission and its IMMUTABLE approval-time authority commitment. */
  mission: { id: string; issuer: string; authority_hash: string };
  /** The triggering signal, as submitted (its `event_id` is the idempotency key). */
  event: { type: string; source: string; observed_at: string; event_id: string };
  /** The derivation policy version the Mission was approved under. */
  policy: string;
  /** Mission record version before/after the commit (new = prior + 1; equal on an idempotent repeat). */
  prior_version: number;
  new_version: number;
  /** Containment overlay version before/after (0 = no prior containment). */
  prior_containment_version: number;
  new_containment_version: number;
  /** What this event removed (an entry with no `actions` removes the whole resource). */
  removed: Array<{ resource: string; actions?: string[] }>;
  created_at: string;
}

/** The evidence record's canonical JCS bytes (mirrors childEvidenceBytes). */
export function containmentEvidenceBytes(evidence: ContainmentEvidence): string {
  return canonicalize(evidence as unknown as JsonValue);
}

/** Build a Containment Evidence record with a fresh prefixed `evidence_id`. */
export function buildContainmentEvidence(
  input: Omit<ContainmentEvidence, "evidence_id">,
): ContainmentEvidence {
  return { evidence_id: `cnt_${randomBytes(9).toString("base64url")}`, ...input };
}
