/**
 * @spec mission#designation (#869, #1274 review, D449): audience separation.
 * A designation names a client in `aud`, so a designated client's identifier
 * must not be an audience that any resource server accepts for this AS's
 * access tokens, aliases included, throughout the designation's lifetime;
 * otherwise a resource server validating a JWT access token's audience
 * (RFC 9068 Section 4) could accept a designation as resource authority.
 *
 * This reference establishes that separation in two parts. The deployment
 * lists the clients it may designate (config/delegation.json), its statement
 * that no resource server accepts their identifiers; and the AS refuses a
 * listed client whose identifier is an audience it knows a resource server
 * accepts: its own issuer (the resource-indicator default), the catalog's and
 * the topology's resources, the scope-projection mapping's audiences, every
 * registered resource server's accepted audiences and aliases, and, at the
 * designation, the Mission's own resources. The set is static per boot, and a
 * designation lives at most 300 s, so it holds for the designation's lifetime.
 */

import { CATALOG_SERVICES, type IntrospectionPrincipal, TOPOLOGY } from "@mission/demo-data";

/** The audiences this AS knows a resource server accepts for its access tokens. */
export function resourceAudiences(input: {
  issuer: string;
  scopeProjection?: { audiences?: Record<string, unknown> } | undefined;
  introspectionPrincipals?: readonly IntrospectionPrincipal[] | undefined;
}): Set<string> {
  const accepted = new Set<string>([
    input.issuer,
    ...CATALOG_SERVICES.map((s) => s.resource),
    ...Object.values(TOPOLOGY.resources),
    ...Object.keys(input.scopeProjection?.audiences ?? {}),
  ]);
  for (const p of input.introspectionPrincipals ?? []) {
    for (const a of p.audiences) accepted.add(a);
    for (const [audience, resources] of Object.entries(p.audience_resources ?? {})) {
      accepted.add(audience);
      for (const r of resources) accepted.add(r);
    }
  }
  return accepted;
}

/** Whether the deployment lists `clientId` as one a designation may name. */
export function separationDeclared(clientId: string, designable: readonly string[] | undefined): boolean {
  return (designable ?? []).includes(clientId);
}

/** Whether `clientId` collides with an accepted audience, or with one of the Mission's own resources. */
export function audienceCollision(
  clientId: string,
  audiences: ReadonlySet<string>,
  missionResources: readonly string[] = [],
): boolean {
  return audiences.has(clientId) || missionResources.includes(clientId);
}
