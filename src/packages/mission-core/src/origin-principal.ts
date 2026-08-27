/**
 * @spec cross-domain#mission-subject, cross-domain#origin-principal-mapping,
 * cross-domain#dual-axis, authzen#pdp-request (rule 10)
 *
 * Shared, service-dependency-free contracts for the cross-domain Origin
 * Principal profile's dual-axis authorization: the destination-side mapping
 * from the immutable origin principal to a local subject, and the current
 * entitlement of that mapped principal. Placed here, not in `@mission/pdp`,
 * so a future entry point (the Cross-Org grant, the ID-JAG RAS redemption)
 * can apply the same two contracts without depending on the PDP package.
 * `@mission/pdp`'s `EvaluateOptions` is the first, PDP-authoritative consumer
 * (@spec authzen#pdp-request: "The PDP is authoritative for the mapping in
 * the default placement").
 */

/** @spec cross-domain#mission-subject — the closed `{iss, sub}` shape. */
export interface OriginPrincipal {
  iss: string;
  sub: string;
}

/**
 * @spec cross-domain#origin-principal-mapping,
 * runtime-evidence#principal_mapping — a destination-side mapping result.
 * `local`, `policy`, `observed_at`, and `valid_until` are exactly the
 * `principal_mapping` evidence object's REQUIRED sub-members other than
 * `origin` (which the caller already holds): a resolver that answered only a
 * boolean or a bare local identifier could not support evidence binding or
 * the mapping's own independent staleness bound.
 */
export interface PrincipalMappingObservation {
  /** The destination-local principal the origin principal mapped to. */
  local: OriginPrincipal;
  /** The mapping policy applied, identified and versioned. */
  policy: { id: string; version: string };
  /** RFC 3339 date-time: when the mapping was established or confirmed. */
  observed_at: string;
  /** RFC 3339 date-time: the mapping's own validity bound. */
  valid_until: string;
}

/**
 * @spec cross-domain#origin-principal-mapping — resolves the origin
 * principal to a destination-local mapping scoped to the destination
 * audience. Returns `undefined` for a missing, ambiguous, or disabled
 * mapping: the caller denies uniformly for all three
 * (@spec cross-domain#dual-axis, `principal_mapping_failed`), never
 * distinguishing them at the enforcement point.
 */
export interface PrincipalMappingResolver {
  resolve(input: {
    origin: OriginPrincipal;
    audience: string;
  }): Promise<PrincipalMappingObservation | undefined>;
}

/**
 * @spec cross-domain#dual-axis — the mapped principal's current entitlement.
 * `observed_at` lets the caller enforce entitlement freshness independently
 * of Mission-state freshness ("Mission-state freshness and entitlement
 * freshness are separate declarations and MUST NOT be collapsed into one
 * timestamp").
 */
export interface EntitlementObservation {
  entitled: boolean;
  /** RFC 3339 date-time: when this entitlement was established or confirmed. */
  observed_at: string;
}

/**
 * @spec cross-domain#dual-axis — resolves current entitlement for the
 * mapped local principal at the destination audience. Returns `undefined`
 * when entitlement cannot be established at all; the caller treats that the
 * same as an established-but-negative result (`entitled: false`), since
 * both are "a failed ... result" at the entitlement step
 * (@spec authzen#pdp-request).
 *
 * This contract is an audience-wide, all-or-none entitlement model: a
 * single Boolean gates the complete delegated `authorization_details` set
 * for the mapped principal at that audience. It authorizes or refuses the
 * whole set, and cannot itself narrow individual entries by action or
 * resource -- that narrowing, where a deployment needs it, is the "current
 * resource and deployment policy" arm of {{cross-domain#dual-axis}}'s
 * three-bound intersection, applied downstream of entitlement rather than
 * inside it. A deployment needing per-entry entitlement would return the
 * locally entitled authority subset instead of a bare Boolean; this
 * contract does not.
 */
export interface EntitlementResolver {
  resolve(input: {
    local: OriginPrincipal;
    audience: string;
  }): Promise<EntitlementObservation | undefined>;
}
