/**
 * @spec cross-domain#origin-principal-mapping, cross-domain#origin-principal-continuity
 *
 * A shared, dependency-free reference resolver for the destination-side
 * origin-to-local principal mapping (#539): "A Resource AS consuming a
 * conforming grant or delegation chain establishes a mapping from
 * (`mission.subject.iss`, `mission.subject.sub`) to a destination-local
 * (`iss`, `sub`) under a named local mapping policy." Used by every
 * projection entry point that mints a destination-local `sub` from a
 * registered table (the Cross-Org grant adapter, the ID-JAG RAS redemption
 * path) rather than each reimplementing lookup, ambiguity, and staleness
 * handling independently.
 *
 * Distinct from `PrincipalMappingResolver` (origin-principal.ts): that
 * contract maps to an issuer-qualified LOCAL principal for the PDP's
 * dual-axis check, where the destination's own issuer is implicit context
 * the caller already knows. This one maps to a bare local `sub` in the
 * destination's own namespace, the shape both entry points already mint
 * tokens with.
 */

import type { OriginPrincipal } from "./origin-principal.js";

/** A registered origin-to-local mapping row. */
export interface LocalPrincipalMapping {
  origin: OriginPrincipal;
  /** The destination-local subject this origin principal maps to. */
  local_sub: string;
  /**
   * @spec cross-domain#origin-principal-mapping — "scoped to the destination
   * audience or tenant". Absent matches any audience.
   */
  audience?: string;
  /** @spec cross-domain#origin-principal-continuity — "current disablement". */
  disabled?: boolean;
  /** RFC 3339: when this mapping fact was recorded or confirmed. */
  observed_at: string;
  /** RFC 3339: this mapping's own validity bound. */
  valid_until: string;
}

export interface LocalMappingPolicy {
  id: string;
  version: string;
  entries: LocalPrincipalMapping[];
}

export interface ResolvedLocalPrincipal {
  local_sub: string;
  policy: { id: string; version: string };
  observed_at: string;
  valid_until: string;
}

/**
 * Resolve ONE origin principal to its destination-local mapping. Returns
 * `undefined` for a missing, duplicate/ambiguous, disabled, future-dated,
 * expired, or malformed (empty `local_sub`, empty `audience`, or an
 * unidentified `policy.id`/`policy.version`) mapping: @spec
 * cross-domain#origin-principal-continuity requires the caller to deny
 * uniformly for all of these ("missing, ambiguous, disabled, stale beyond
 * the declared bound"), never distinguishing them at the enforcement point.
 */
export function resolveLocalPrincipal(
  policy: LocalMappingPolicy,
  origin: OriginPrincipal,
  audience: string,
  now: Date,
): ResolvedLocalPrincipal | undefined {
  const candidates = policy.entries.filter(
    (e) =>
      e.origin.iss === origin.iss &&
      e.origin.sub === origin.sub &&
      (e.audience === undefined || e.audience === audience) &&
      !e.disabled,
  );
  if (candidates.length !== 1) return undefined; // zero (missing) or >1 (ambiguous)
  const [entry] = candidates;
  if (!entry) return undefined; // unreachable given the length check above
  // Validate the complete selected mapping -- its own local_sub and audience,
  // and the policy metadata identifying it -- before treating it as an
  // unambiguous current mapping. An empty local_sub or an unidentified
  // policy is a malformed record, never a usable resolution.
  if (typeof entry.local_sub !== "string" || !entry.local_sub) return undefined;
  if (entry.audience !== undefined && (typeof entry.audience !== "string" || !entry.audience))
    return undefined;
  if (typeof policy.id !== "string" || !policy.id) return undefined;
  if (typeof policy.version !== "string" || !policy.version) return undefined;
  const observedMs = Date.parse(entry.observed_at);
  const validMs = Date.parse(entry.valid_until);
  if (!Number.isFinite(observedMs) || !Number.isFinite(validMs)) return undefined;
  const nowMs = now.getTime();
  if (observedMs > nowMs) return undefined; // future-dated observation
  if (validMs < nowMs) return undefined; // expired
  return {
    local_sub: entry.local_sub,
    policy: { id: policy.id, version: policy.version },
    observed_at: entry.observed_at,
    valid_until: entry.valid_until,
  };
}

/**
 * Resolve TWO independently authenticated identities against the same
 * mapping policy and require both to resolve to the SAME destination-local
 * subject: @spec cross-domain#origin-principal-mapping — "the Resource AS
 * MUST establish that the identity grant's subject and `mission.subject`
 * resolve to the same destination-local principal, and MUST refuse ... when
 * they do not; neither value may select a different account than the
 * other." Proof that two claims about "the same actor" agree on one
 * destination-local principal, rather than trusting either claim alone. A
 * mismatch, or either side individually failing to resolve, denies the same
 * way as a single failed resolution.
 */
export function resolveCoResolvedLocalPrincipal(
  policy: LocalMappingPolicy,
  primary: OriginPrincipal,
  secondary: OriginPrincipal,
  audience: string,
  now: Date,
): ResolvedLocalPrincipal | undefined {
  const a = resolveLocalPrincipal(policy, primary, audience, now);
  if (!a) return undefined;
  const b = resolveLocalPrincipal(policy, secondary, audience, now);
  if (!b) return undefined;
  if (a.local_sub !== b.local_sub) return undefined;
  // The more conservative (earlier) validity bound and (later) observation
  // time of the two independently-resolved facts.
  const validUntil =
    Date.parse(a.valid_until) <= Date.parse(b.valid_until) ? a.valid_until : b.valid_until;
  const observedAt =
    Date.parse(a.observed_at) >= Date.parse(b.observed_at) ? a.observed_at : b.observed_at;
  return {
    local_sub: a.local_sub,
    policy: a.policy,
    observed_at: observedAt,
    valid_until: validUntil,
  };
}
