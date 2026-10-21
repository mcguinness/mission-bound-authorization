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

import type { ActivationPolicyRef, ActivationPolicySnapshot } from "@mission/core";

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

/**
 * @spec child-delegation#derivation-budget (#1119, D327) — the per-child
 * maximum a delegable entry's `children` grant commits, read the same way at
 * the Parent Mission's approval rendering, at its approval decision, and at
 * each child's creation. One reader means the three compute the figure the
 * same way from the same committed state; it does not bind a rendering to the
 * later decision, which re-reads (a figure that cannot be disclosed refuses
 * the approval there). `held` resolves a `child_creation_policy` reference to
 * the snapshot this issuer verifies against its committed digest, or
 * undefined.
 * - `policy`: the entry commits a policy whose snapshot states the maximum;
 * - `deployment`: the entry commits no policy, so the deployment's policy
 *   ceiling for a child's `derivation_limit` is the figure;
 * - `unheld`: the committed policy is not one this issuer holds at that digest;
 * - `unusable`: the held snapshot states a malformed maximum.
 */
export type CommittedPerChildMaximum =
  | { readonly source: "policy"; readonly maximum: StandingConsentMaximum }
  | { readonly source: "deployment" }
  | { readonly source: "unheld"; readonly policy: ActivationPolicyRef }
  | { readonly source: "unusable"; readonly policy: ActivationPolicyRef };

export function committedPerChildMaximum(
  children: { readonly child_creation_policy?: ActivationPolicyRef } | undefined,
  held: (ref: ActivationPolicyRef) => ActivationPolicySnapshot | undefined,
): CommittedPerChildMaximum {
  const policy = children?.child_creation_policy;
  if (!policy) return { source: "deployment" };
  const snapshot = held(policy);
  if (!snapshot) return { source: "unheld", policy };
  const maximum = standingConsentMaximumOf(snapshot);
  return maximum ? { source: "policy", maximum } : { source: "unusable", policy };
}

/**
 * @spec derivation-limits#approval-rendering (#1119, D327) — the consent
 * statements an approval renders, as plain lines: the approval page escapes
 * and renders them, and the template-consent stand-in returns them.
 */
export const ASYNC_FAMILY_STATEMENT =
  "The refreshes of an async delegation family are not counted against this limit.";

/** The established limit of the Mission being approved (its own, not only the requested value). */
export function establishedLimitLines(limit: number | null, opts: { asyncDelegation: boolean }): string[] {
  return [
    limit === null
      ? "No derivation limit is established for this Mission: the number of tokens derived from it is not bounded."
      : `Derivation limit (established): at most ${limit} token derivations from this Mission.`,
    ...(opts.asyncDelegation ? [ASYNC_FAMILY_STATEMENT] : []),
  ];
}

/**
 * The rule and maximum a standing consent commits for each Mission it admits,
 * and the scope statement. `admitted` names those Missions ("child Mission",
 * "dispatched instance").
 */
export function standingConsentLines(
  maximum: StandingConsentMaximum,
  admitted: string,
  opts: { asyncDelegation: boolean },
): string[] {
  const rule =
    maximum.finite === null
      ? `Each ${admitted} created under this consent establishes its own derivation limit from its own request; no finite maximum is guaranteed.`
      : `Each ${admitted} created under this consent establishes its own derivation limit from its own request, never above ${maximum.finite}.`;
  return [
    rule,
    `This maximum is local to each ${admitted}: it is not a budget across the Missions this consent admits, their descendants, or their lifetimes.`,
    ...(opts.asyncDelegation ? [ASYNC_FAMILY_STATEMENT] : []),
  ];
}

/** @spec child-delegation#subtree-rendering — no lineage-keyed budget is deployed in this reference. */
export const SUBTREE_AGGREGATE_STATEMENT =
  "No finite aggregate bound on this entry's subtree is enforced: no limit applies to children created over the Mission's lifetime.";

/** @spec progressive#derivation-limits — the inheritance a ceiling consent discloses. */
export function progressiveInheritanceLine(limit: number | null): string {
  return limit === null
    ? "If you also consent to an authority ceiling, this Mission has no derivation limit, so no finite limit is guaranteed for the successors its drawdown policy creates."
    : `If you also consent to an authority ceiling, the successors its drawdown policy creates carry this Mission's derivation count forward and never exceed its derivation limit of ${limit}.`;
}
