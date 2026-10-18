/**
 * @spec mission#designation (#869, D449): audience separation. A designation
 * names a client in `aud`, so no client this AS can designate may share its
 * identifier with an audience of the access tokens the AS issues for resource
 * access. Otherwise a resource server validating a JWT access token's
 * audience (RFC 9068 Section 4) could accept a designation as resource
 * authority.
 *
 * The audiences are every target the AS issues resource tokens for: its own
 * issuer (the resource-indicator default), the catalog's and the topology's
 * resources, the scope-projection mapping's audiences, and, at a designation,
 * the resources of the Mission's own Authority Set entries.
 */

import { CATALOG_SERVICES, TOPOLOGY } from "@mission/demo-data";

/** The configured audiences of the access tokens this AS issues for resource access. */
export function resourceAudiences(input: {
  issuer: string;
  scopeProjection?: { audiences?: Record<string, unknown> } | undefined;
}): Set<string> {
  return new Set<string>([
    input.issuer,
    ...CATALOG_SERVICES.map((s) => s.resource),
    ...Object.values(TOPOLOGY.resources),
    ...Object.keys(input.scopeProjection?.audiences ?? {}),
  ]);
}

/** Whether `clientId` collides with a resource audience, or with one of the Mission's own resources. */
export function audienceCollision(
  clientId: string,
  audiences: ReadonlySet<string>,
  missionResources: readonly string[] = [],
): boolean {
  return audiences.has(clientId) || missionResources.includes(clientId);
}

/** Refuse to start when a registered client's identifier is also a resource audience. */
export function assertAudienceSeparation(clientIds: readonly string[], audiences: ReadonlySet<string>): void {
  const collisions = clientIds.filter((id) => audiences.has(id));
  if (collisions.length > 0) {
    throw new Error(
      `audience separation (mission#designation): client identifier(s) ${collisions.join(", ")} ` +
        "are also resource audiences, so a designation naming one could be accepted for resource access",
    );
  }
}
