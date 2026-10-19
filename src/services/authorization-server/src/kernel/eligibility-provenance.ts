/**
 * @spec resource-access#delegate-eligibility (inherited eligibility, #1275, D457)
 * @spec resource-access#subset (the `allowed_delegates` bullet)
 *
 * Delegate eligibility with retained provenance. An approved entry derived
 * from a ceiling entry whose `delegation` carries no `allowed_delegates`
 * inherits the authorization server's delegation-authorization policy
 * decision, and so does every entry derived from it. A list the entry carries
 * (one a proposal added, or a later narrowing) only restricts that decision;
 * it never replaces it.
 *
 * The approved entry's own members cannot show the obligation (a proposal can
 * add a list over a policy-deferring ceiling entry), so the authorization
 * server records each approved entry's ORIGIN when it derives the Authority
 * Set and retains it with the Mission (`MissionRecord.eligibility_provenance`,
 * index-aligned with `authority_set`). It is authorization-server state: no
 * wire member carries it, and it is never inferred later from an entry's list
 * or from an `act` chain.
 *
 * Structural subset comparison (`isSubsetEntry`, `matchersSubset`) stays
 * structural. A structural subset result is never authorization to delegate:
 * eligibility is decided here, at every delegated issuance, against the
 * approved entries a carried entry resolves to and their retained origins.
 */

import type { DelegateCandidate } from "./delegate-matcher.js";
import { delegatePermitted } from "./delegate-matcher.js";
import type { AuthorityEntry } from "./types.js";

/**
 * Where an entry's delegate eligibility is decided.
 *
 * - `list`: the ceiling entry it derives from carries `allowed_delegates`, so
 *   the entry's committed list decides.
 * - `policy`: the ceiling entry's `delegation` carries no `allowed_delegates`,
 *   so the authorization server's delegation-authorization policy decides,
 *   evaluated at every exchange, and every list the entry carries further
 *   restricts that decision.
 */
export type EligibilityOrigin = "list" | "policy";

/**
 * A retained origin, or `null` where the authorization server cannot say (for
 * example an entry derived from a reference whose own provenance is missing).
 * A `null` origin narrows the entry out of every delegated token.
 */
export type RetainedOrigin = EligibilityOrigin | null;

/**
 * The origin a ceiling (or other derivation reference) entry confers on an
 * entry derived from it: `policy` when it grants `delegation` without
 * `allowed_delegates`, otherwise `list`. An entry without `delegation` derives
 * a non-delegable entry, whose origin no gate consults.
 */
export function ceilingOrigin(reference: AuthorityEntry): EligibilityOrigin {
  const delegation = reference.delegation;
  return delegation !== undefined && delegation.allowed_delegates === undefined ? "policy" : "list";
}

/**
 * Combine the origins an entry inherits from more than one reference (a
 * proposal entry that is itself derived, a parent entry, a template ceiling).
 * Every inherited obligation is kept: an unresolved origin stays unresolved,
 * and otherwise any `policy` origin makes the entry `policy`.
 */
export function combineOrigins(...origins: readonly RetainedOrigin[]): RetainedOrigin {
  if (origins.some((o) => o === null)) return null;
  return origins.some((o) => o === "policy") ? "policy" : "list";
}

/** A stored provenance value, read fail-closed: anything but `list` or `policy` is unresolved. */
export function readOrigin(value: unknown): RetainedOrigin {
  return value === "list" || value === "policy" ? value : null;
}

/**
 * The retained origin of each entry of `authoritySet`, from the record's
 * stored provenance. A provenance array that is absent or not aligned with the
 * Authority Set resolves nothing: every entry is unresolved.
 */
export function retainedOrigins(
  authoritySet: readonly AuthorityEntry[],
  provenance: readonly unknown[] | undefined,
): RetainedOrigin[] {
  if (!Array.isArray(provenance) || provenance.length !== authoritySet.length) {
    return authoritySet.map(() => null);
  }
  return provenance.map(readOrigin);
}

/**
 * The origin an entry derived within reference entries inherits from them:
 * its own (derivation) origin combined with that of EVERY reference entry
 * granting `delegation` that the entry falls within (same type and resource,
 * every action covered). Overlapping references therefore never supply a
 * more permissive origin: each one's obligation is kept. A delegable entry
 * that falls within no delegable reference is unresolved.
 */
export function inheritOrigins(
  entries: readonly AuthorityEntry[],
  own: readonly RetainedOrigin[],
  references: ReadonlyArray<{ entry: AuthorityEntry; origin: RetainedOrigin }>,
): RetainedOrigin[] {
  return entries.map((entry, i) => {
    const self = own[i] ?? null;
    if (entry.delegation === undefined) return self;
    const within = references.filter(
      (r) =>
        r.entry.delegation !== undefined &&
        r.entry.type === entry.type &&
        r.entry.resource === entry.resource &&
        entry.actions.every((a) => r.entry.actions.includes(a)),
    );
    if (within.length === 0) return null;
    return combineOrigins(self, ...within.map((r) => r.origin));
  });
}

/** One approved Mission Record entry a carried entry resolves to, with its retained origin. */
export interface ResolvedApprovedEntry {
  entry: AuthorityEntry;
  origin: RetainedOrigin;
}

/**
 * An entry offered for a delegated token, resolved to the approved Mission
 * Record entries it derives from. An empty `approved` list is an entry whose
 * approved entry cannot be resolved.
 */
export interface DelegationCandidate {
  entry: AuthorityEntry;
  approved: readonly ResolvedApprovedEntry[];
}

/**
 * The delegation-authorization policy decision for one approved entry whose
 * eligibility defers to policy, as the gate asks it: evaluated now, never a
 * cached earlier decision.
 */
export type PolicyCheck = (approved: AuthorityEntry, entry: AuthorityEntry) => boolean;

/** The three outcomes of a delegate-eligibility decision (the expected-outcome cases' vocabulary). */
export type EligibilityOutcome = "eligible" | "not-eligible" | "narrowed-out";

/**
 * @spec resource-access#delegate-eligibility: decide whether `delegate` may
 * carry `candidate.entry` in a token issued at accounted delegation depth
 * `depth`.
 *
 * 1. Resolution: the entry must resolve to at least one approved entry, every
 *    one with a retained origin, all the same origin. Otherwise the entry
 *    narrows out (`narrowed-out`): an unresolved approved entry, missing
 *    provenance, or overlapping approved entries of different origins, which
 *    never lend the entry the more permissive one.
 * 2. The carried entry and every approved entry it resolves to carry
 *    `delegation` with `depth` within its `max_depth` (otherwise non-delegable
 *    at this depth).
 * 3. Every retained list permits the delegate: the carried entry's and each
 *    approved entry's. A list never widens; it only restricts.
 * 4. `list` origin: the carried entry's own list decides, and an absent list
 *    denies. `policy` origin: the current policy decision must permit, for
 *    every approved entry; an absent list defers to it and is never a grant.
 *
 * Failing 2, 3 or 4 is `not-eligible`. The policy is asked only once the
 * other conditions hold, and is asked afresh at every call.
 */
export function delegateEligibility(
  candidate: DelegationCandidate,
  delegate: DelegateCandidate,
  depth: number,
  policyPermits: PolicyCheck,
): EligibilityOutcome {
  const { entry, approved } = candidate;
  if (approved.length === 0) return "narrowed-out";
  const origins = new Set(approved.map((a) => a.origin));
  if (origins.has(null) || origins.size !== 1) return "narrowed-out";
  const origin = approved[0]?.origin as EligibilityOrigin;
  const governed = [entry, ...approved.map((a) => a.entry)];
  for (const e of governed) {
    const d = e.delegation;
    if (!d || typeof d.max_depth !== "number" || depth > d.max_depth) return "not-eligible";
  }
  for (const e of governed) {
    const list = e.delegation?.allowed_delegates;
    if (list !== undefined && !delegatePermitted(delegate, list)) return "not-eligible";
  }
  if (origin === "list") {
    return entry.delegation?.allowed_delegates !== undefined ? "eligible" : "not-eligible";
  }
  return approved.every((a) => policyPermits(a.entry, entry) === true) ? "eligible" : "not-eligible";
}

/**
 * @spec mission#delegation-constraints (per-entry enforcement),
 * resource-access#delegate-eligibility: the entries `delegate` may carry at
 * accounted depth `depth`: those {@link delegateEligibility} finds `eligible`.
 * The rest narrow out, consistent with the subset rule; surviving entries keep
 * their `delegation` member intact, so the next hop is evaluated the same way.
 */
export function gateDelegableAuthority(
  candidates: readonly DelegationCandidate[],
  delegate: DelegateCandidate,
  depth: number,
  policyPermits: PolicyCheck,
): AuthorityEntry[] {
  return candidates
    .filter((c) => delegateEligibility(c, delegate, depth, policyPermits) === "eligible")
    .map((c) => c.entry);
}

/**
 * @spec resource-access#delegate-eligibility: the authorization server's
 * delegation-authorization policy, consulted at every delegated issuance for
 * an approved entry whose eligibility defers to it. It returns `true` only to
 * permit; anything else denies.
 */
export type DelegationAuthorizationPolicy = (request: DelegationPolicyRequest) => boolean;

/** What the delegation-authorization policy is asked. */
export interface DelegationPolicyRequest {
  /** The Mission the delegated token is issued under. */
  mission: { id: string; issuer: string; client_id: string; subject: { iss: string; sub: string } };
  /** The approved Mission Record entry whose eligibility defers to policy. */
  approved: AuthorityEntry;
  /** The entry the delegated token would carry. */
  entry: AuthorityEntry;
  /** The authenticated delegate: its client identifier and the AS-asserted profile. */
  delegate: DelegateCandidate;
  /** The accounted delegation depth of the token being issued. */
  depth: number;
}

/**
 * The reference implementation's policy: deny every delegate. An entry whose
 * eligibility defers to policy is therefore never delegable unless a
 * deployment installs a policy that permits.
 */
export const DENY_ALL_DELEGATION_POLICY: DelegationAuthorizationPolicy = () => false;
