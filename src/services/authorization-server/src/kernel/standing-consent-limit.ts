/**
 * @spec derivation-limits#effective-limit, derivation-limits#approval-rendering
 * (#1119, D327) — the per-Mission derivation-limit maximum a standing consent
 * commits. A policy the consent committed (a Mission Template's Dispatch
 * Policy, a Child Delegation entry's `child_creation_policy`) states it in
 * its JSON snapshot as `derivation_limit_ceiling`, the same member and shape
 * as the deployment's own policy ceiling: an integer of at least 1, or `null`.
 * Absent or `null` means the consent guarantees no finite maximum. A Mission
 * created under the consent establishes its own limit from its request and the
 * deployment's current ceiling, then never above a finite committed maximum,
 * so a later raise or removal of the deployment's ceiling cannot lift it.
 */

import type { ActivationPolicySnapshot } from "@mission/core";

/** The snapshot member that states the maximum. */
export const STANDING_CONSENT_LIMIT_MEMBER = "derivation_limit_ceiling";

/** The maximum a committed policy states: a finite value, or none guaranteed. */
export type StandingConsentMaximum = { readonly finite: number } | { readonly finite: null };

/** No finite maximum is guaranteed. */
export const NO_FINITE_MAXIMUM: StandingConsentMaximum = Object.freeze({ finite: null });

/**
 * The maximum `policy` states, or undefined when its statement is unusable: a
 * JSON object whose member is present but neither an integer of at least 1
 * nor `null`. A snapshot that states no such member (not JSON, not a JSON
 * object, or an object without it) guarantees no finite maximum.
 */
export function standingConsentMaximumOf(policy: ActivationPolicySnapshot): StandingConsentMaximum | undefined {
  if (policy.content_type !== "application/json") return NO_FINITE_MAXIMUM;
  let parsed: unknown;
  try {
    const text = typeof policy.content === "string" ? policy.content : new TextDecoder().decode(policy.content);
    parsed = JSON.parse(text);
  } catch {
    return NO_FINITE_MAXIMUM;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return NO_FINITE_MAXIMUM;
  if (!Object.hasOwn(parsed, STANDING_CONSENT_LIMIT_MEMBER)) return NO_FINITE_MAXIMUM;
  const value = (parsed as Record<string, unknown>)[STANDING_CONSENT_LIMIT_MEMBER];
  if (value === null) return NO_FINITE_MAXIMUM;
  if (typeof value === "number" && Number.isInteger(value) && value >= 1) return { finite: value };
  return undefined;
}

/** The strictest of several maxima: the smallest finite value, or none. */
export function strictestMaximum(maxima: readonly StandingConsentMaximum[]): StandingConsentMaximum {
  const finite = maxima.flatMap((m) => (m.finite === null ? [] : [m.finite]));
  return finite.length === 0 ? NO_FINITE_MAXIMUM : { finite: Math.min(...finite) };
}

/**
 * The `derivation_limit` a Mission created under the consent records: the
 * value its request and the deployment's current ceiling resolve to, never
 * above a finite maximum, and never absent where the maximum is finite.
 */
export function withinStandingConsentMaximum(
  resolved: number | null,
  maximum: StandingConsentMaximum,
): number | null {
  if (maximum.finite === null) return resolved;
  return resolved === null ? maximum.finite : Math.min(resolved, maximum.finite);
}
