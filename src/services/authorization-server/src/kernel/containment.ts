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

/**
 * @spec containment#containment-policy — the ISSUER-HELD map from a
 * protected-event class to what narrows. Held by the AS (never by the client or
 * a shaper), so a compromised caller cannot shape which capability an event
 * removes: {@link MissionKernel.containOnEvent} looks the incoming event's
 * `type` up here and applies the matched rule's `remove` DETERMINISTICALLY. The
 * manual `remove[]` path on {@link MissionKernel.contain} stays as the explicit
 * break-glass path (its evidence `policy` is "manual", not a rule_id).
 */
export interface ContainmentPolicy {
  policy_version: string;
  rules: Array<{
    rule_id: string;
    event_type: string;
    remove: Array<{ resource: string; actions?: string[] }>;
  }>;
}

/**
 * @spec containment#containment-policy — thrown when {@link
 * MissionKernel.containOnEvent} sees a protected-event `type` that no
 * ContainmentPolicy rule matches (or no policy is configured). The kernel fails
 * CLOSED: nothing is committed. The wire PR maps this to a recorded rejection.
 */
export class UnknownProtectedEventError extends Error {}

/** The Containment Evidence record for one contain transition. */
export interface ContainmentEvidence {
  evidence_id: string;
  /** The Mission and its IMMUTABLE approval-time authority commitment. */
  mission: { id: string; issuer: string; authority_hash: string };
  /** The triggering signal, as submitted (its `event_id` is the idempotency key). */
  event: { type: string; source: string; observed_at: string; event_id: string };
  /** The ContainmentPolicy `rule_id` that fired, or "manual" for the break-glass `remove[]` path. */
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
