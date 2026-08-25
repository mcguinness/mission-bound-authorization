/**
 * @spec mission#local-approved-set-verification, mission#lasv-retrieval
 *
 * Authenticated Complete-Set Retrieval: the two MUST checks the profile
 * defines for a verifying party (a Resource Server or policy decision
 * point) that has already retrieved the complete Authority Set over a
 * channel authenticated to the Mission `issuer`. This module performs no
 * transport or authentication of its own -- retrieval, its authorization
 * gate, and (for Tier 2) the retention of an independently obtained
 * expected `authority_hash` are deployment-provisioned, per the profile
 * ({{lasv-retrieval}}).
 *
 * The subset test between a carried entry and a retrieved (granted) entry
 * is TYPE-OWNED (core's own division, {{subset}}): this module takes it as
 * an injected predicate rather than reimplementing per-type constraint
 * semantics (max_amount tightening, vendor narrowing, and so on), which
 * belong to whichever Authority Set entry type the deployment derives
 * under. This mirrors the existing family convention of taking a
 * type-specific or deployment-specific decision as an injected predicate
 * (e.g. the orchestration profile's `stillAuthorized` resolver) rather than
 * this dependency-free package importing a specific type's comparison.
 */

import { authorityHash } from "./anchors.js";
import type { JsonValue } from "./canonicalize.js";

/**
 * @spec mission#lasv-retrieval — the complete Authority Set and the
 * `authority_hash` it is expected to match, as retrieved by the caller over
 * an issuer-authenticated channel. `authority_set` is generic over the
 * entry shape (bounded only by {@link JsonValue}, matching
 * {@link authorityHash}'s own signature) since this module performs no
 * type-specific interpretation of an entry: it only recomputes the
 * commitment and delegates subset comparison to the caller-supplied
 * predicate.
 */
export interface LocalApprovedSetRetrieval<Entry extends JsonValue = JsonValue> {
  issuer: string;
  authority_set: Entry[];
  authority_hash: string;
}

/** @spec mission#lasv-retrieval — why {@link verifyLocalApprovedSet} refused. */
export type LocalApprovedSetVerificationReason = "commitment_mismatch" | "not_subset";

/**
 * @spec mission#lasv-retrieval — fail-closed: every refusal this module can
 * produce is a thrown instance of this class, carrying a stable `reason`,
 * never a partial or best-effort return value.
 */
export class LocalApprovedSetVerificationError extends Error {
  constructor(
    public readonly reason: LocalApprovedSetVerificationReason,
    message: string,
  ) {
    super(message);
    this.name = "LocalApprovedSetVerificationError";
  }
}

/**
 * @spec mission#lasv-retrieval — Tier 1 (recompute the commitment over the
 * retrieved set and reject on mismatch; verify every carried entry is a
 * subset of an entry in the retrieved set) plus, when `expectedAuthorityHash`
 * is supplied, Tier 2 (the retrieved, recomputed-matching `authority_hash`
 * MUST also equal a value the caller retained from an EARLIER,
 * independently authenticated disclosure -- never derived from the same
 * `retrieved` value being checked here; that independence is the caller's
 * responsibility, this function only compares the two strings).
 *
 * Throws {@link LocalApprovedSetVerificationError} on any failure and
 * returns nothing on success: there is no partial-success return value, so
 * a caller cannot accidentally treat a refusal as a permit.
 */
export function verifyLocalApprovedSet<Entry extends JsonValue>(
  retrieved: LocalApprovedSetRetrieval<Entry>,
  carried: readonly Entry[],
  isSubsetOfGranted: (candidate: Entry, granted: Entry) => boolean,
  expectedAuthorityHash?: string,
): void {
  const recomputed = authorityHash(retrieved.issuer, retrieved.authority_set);
  if (recomputed !== retrieved.authority_hash) {
    throw new LocalApprovedSetVerificationError(
      "commitment_mismatch",
      "recomputed authority_hash does not match the retrieved commitment",
    );
  }
  // @spec mission#lasv-retrieval (Tier 2) — the retrieval channel above is
  // the SAME channel Tier 1 already authenticated; comparing against it
  // again would prove nothing new. `expectedAuthorityHash` must come from
  // the caller's own independently retained value for this check to mean
  // anything (see the retention-point/trust-basis/retention-rule
  // declaration the profile requires of a Tier 2 claim).
  if (expectedAuthorityHash !== undefined && retrieved.authority_hash !== expectedAuthorityHash) {
    throw new LocalApprovedSetVerificationError(
      "commitment_mismatch",
      "retrieved authority_hash does not match the independently retained approval-time commitment",
    );
  }
  for (const entry of carried) {
    if (!retrieved.authority_set.some((granted) => isSubsetOfGranted(entry, granted))) {
      throw new LocalApprovedSetVerificationError(
        "not_subset",
        "a carried authorization_details entry is not a subset of any entry in the retrieved Authority Set",
      );
    }
  }
}
