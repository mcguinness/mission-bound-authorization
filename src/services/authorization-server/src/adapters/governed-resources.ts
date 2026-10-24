/**
 * @spec mission#authority-proposal (#1531, D741): the governed-resource
 * classification. A resource is Mission-governed when the deployment
 * classifies it so, or when protected resource metadata the AS has
 * authenticated (RFC 9728) declares `mission_bound_authorization_required`
 * as `true`. The two sources are joined by OR, so neither can clear the
 * other: metadata that omits the member or sets it to `false` leaves a
 * `governed` classification in force, and a `not_governed` classification
 * leaves metadata declaring the requirement in force.
 *
 * In the reference both sources are static configuration
 * (`config/governed-resources.json`); the AS fetches no metadata.
 */

import type { GovernedResourcePolicy } from "@mission/demo-data";

export type { GovernedResourcePolicy };

/** Whether `resource` is Mission-governed under `policy`. */
export function isMissionGovernedResource(policy: GovernedResourcePolicy, resource: string): boolean {
  const classified = policy.classification[resource] === "governed";
  const declared = policy.authenticated_metadata[resource]?.mission_bound_authorization_required === true;
  return classified || declared;
}

/** The `invalid_target` description for a token request refused under the governed-resource rule. */
export function governedResourceRefusal(resource: string): string {
  return `${resource} is a Mission-governed resource: a token for it is issued only under a Mission`;
}

/**
 * `policy` without any entry for `resource`, in either source: the policy of
 * an AS that has neither classified `resource` nor authenticated its
 * metadata.
 */
export function withoutGovernedResource(policy: GovernedResourcePolicy, resource: string): GovernedResourcePolicy {
  const classification = { ...policy.classification };
  const authenticated_metadata = { ...policy.authenticated_metadata };
  delete classification[resource];
  delete authenticated_metadata[resource];
  return { classification, authenticated_metadata };
}
