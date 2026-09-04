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
  /**
   * @spec cross-domain#dual-axis — OPTIONAL. The mapped principal's
   * currently entitled `(resource, actions)` set at this audience. Absent
   * means the observation is audience-scoped: `entitled` alone gates the
   * complete delegated set, unchanged. Present means the caller intersects
   * the delegated `authorization_details` with this set, per action, and
   * carries only the surviving subset forward ("the effective authority is
   * the intersection of the verified delegated `authorization_details`, the
   * current entitlement of the mapped origin principal, and current
   * resource and deployment policy").
   *
   * `resource` matches exactly, the way an authority entry's `resource`
   * matches everywhere else in the family's authority model; there is no
   * wildcard or prefix form. The entry carries no constraints: entitlement
   * answers who, what, and where, while amount and vendor terms stay owned
   * by the delegated and ceiling axes.
   */
  authority?: EntitlementAuthorityEntry[];
}

/**
 * @spec cross-domain#dual-axis — one currently entitled `(resource,
 * actions)` pair. The same exact-resource, array-of-actions shape an
 * authority entry uses, without its constraint and delegation members.
 */
export interface EntitlementAuthorityEntry {
  resource: string;
  actions: string[];
}

/**
 * @spec cross-domain#dual-axis — whether an entitlement authority set
 * covers one `(resource, action)` pair. Exact match on both members, and
 * total: a malformed row cannot throw, it simply covers nothing.
 */
export function entitlementPermits(
  authority: readonly EntitlementAuthorityEntry[],
  resource: string,
  action: string,
): boolean {
  return authority.some(
    (a) => a?.resource === resource && Array.isArray(a.actions) && a.actions.includes(action),
  );
}

/**
 * @spec cross-domain#dual-axis — intersect a delegated authority set with
 * an entitlement authority set, per action.
 *
 * An entry survives with the actions the entitlement covers for its exact
 * resource, in the delegated order, and is dropped when none survive. A
 * partial match therefore narrows rather than refuses: the caller mints or
 * evaluates the surviving subset, and refuses only on an empty result. Every
 * other member of a surviving entry (constraints, delegation) is carried
 * through unchanged, because entitlement does not own those axes.
 */
export function narrowToEntitledAuthority<T extends { resource: string; actions: string[] }>(
  delegated: readonly T[],
  authority: readonly EntitlementAuthorityEntry[],
): T[] {
  const narrowed: T[] = [];
  for (const entry of delegated) {
    if (!entry || typeof entry.resource !== "string" || !Array.isArray(entry.actions)) continue;
    const actions = entry.actions.filter((a) => entitlementPermits(authority, entry.resource, a));
    if (actions.length > 0) narrowed.push({ ...entry, actions });
  }
  return narrowed;
}

/**
 * @spec cross-domain#dual-axis — resolves current entitlement for the
 * mapped local principal at the destination audience. Returns `undefined`
 * when entitlement cannot be established at all; the caller treats that the
 * same as an established-but-negative result (`entitled: false`), since
 * both are "a failed ... result" at the entitlement step
 * (@spec authzen#pdp-request).
 *
 * The observation carries two grains. A bare Boolean is audience-scoped: it
 * authorizes or refuses the complete delegated `authorization_details` set
 * for the mapped principal at that audience. An observation that also
 * carries `authority` is action- and resource-scoped: the caller
 * intersects the delegated set with it, per action, and carries the
 * surviving subset forward, refusing only when nothing survives.
 * `authority` is OPTIONAL, and absence means the audience-scoped grain, so
 * a deployment that does not populate it behaves exactly as before.
 */
export interface EntitlementResolver {
  resolve(input: {
    local: OriginPrincipal;
    audience: string;
  }): Promise<EntitlementObservation | undefined>;
}
