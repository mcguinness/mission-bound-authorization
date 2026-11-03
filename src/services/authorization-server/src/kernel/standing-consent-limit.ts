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
import { within } from "./approved-audience.js";
import type { AuthorityEntry } from "./types.js";

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
 * @spec derivation-limits#effective-limit, derivation-limits#approval-rendering,
 * child-delegation#derivation-budget (#2026, D1249) — the per-child maximum a
 * Mission Record retains for one entry of its Authority Set
 * (`MissionRecord.child_derivation_maxima`, index-aligned with it):
 * - a {@link StandingConsentMaximum}: the figure the human approval behind the
 *   entry rendered for its policy-created children and the Approver accepted,
 *   `{ finite: null }` being an explicitly retained "no finite maximum";
 * - `null`: no figure. Either the entry takes none from the deployment (it
 *   grants no children, or its grant commits a `child_creation_policy`, whose
 *   snapshot states the figure), or, for an entry that does take one, the
 *   figure is unknown.
 * A record with no such member (one stored before it was retained) retains no
 * figure for any entry. An unknown figure is never filled in from the current
 * deployment policy, the record's own `derivation_limit` or a matching
 * `policy_version`: no child is created under the entry until a fresh human
 * approval retains one.
 */
export type RetainedChildMaximum = StandingConsentMaximum | null;

/**
 * Whether an entry's policy-created children take the deployment's figure: it
 * grants children (`delegation.children` is an object) and commits no
 * `child_creation_policy`, the case {@link committedPerChildMaximum} reports
 * as `deployment`.
 */
export function takesDeploymentFigure(entry: AuthorityEntry): boolean {
  const children: unknown = entry.delegation?.children;
  if (children === null || typeof children !== "object" || Array.isArray(children)) return false;
  return !(children as { child_creation_policy?: unknown }).child_creation_policy;
}

/** The maximum the deployment's per-child figure states: a finite value, or none. */
function figureMaximum(deploymentFigure: number | null): StandingConsentMaximum {
  return deploymentFigure === null ? NO_FINITE_MAXIMUM : { finite: deploymentFigure };
}

/**
 * The figures a human approval event retains for the entries it approves:
 * the deployment's per-child figure at that event for each entry that takes
 * one, the figure the approval page rendered (the decision is bound to that
 * rendering's derivation policy content, #1446), and `null` for every other
 * entry.
 */
export function renderedChildMaxima(
  entries: readonly AuthorityEntry[],
  deploymentFigure: number | null,
): RetainedChildMaximum[] {
  return entries.map((entry) => (takesDeploymentFigure(entry) ? figureMaximum(deploymentFigure) : null));
}

/** An entry of earlier authority with the figure it retains: undefined where none is retained. */
export interface ChildMaximumReference {
  readonly entry: AuthorityEntry;
  readonly maximum: RetainedChildMaximum | undefined;
}

/**
 * The references an Authority Set provides, from its retained, index-aligned
 * figures. A list that is absent or not aligned with the entries retains no
 * figure for any of them.
 */
export function childMaximumReferences(
  entries: readonly AuthorityEntry[],
  retained: readonly RetainedChildMaximum[] | undefined,
): ChildMaximumReference[] {
  const aligned = Array.isArray(retained) && retained.length === entries.length;
  return entries.map((entry, i) => ({ entry, maximum: aligned ? retained[i] : undefined }));
}

/**
 * The figure a record retains for its entry at `index`, or undefined where it
 * retains none for that entry: no member, a member not aligned with the
 * Authority Set, or an unknown figure.
 */
export function retainedChildMaximum(
  record: { readonly authority_set: readonly AuthorityEntry[]; readonly child_derivation_maxima?: readonly RetainedChildMaximum[] },
  index: number,
): StandingConsentMaximum | undefined {
  return childMaximumReferences(record.authority_set, record.child_derivation_maxima)[index]?.maximum ?? undefined;
}

/**
 * The figures a record derived from earlier authority retains (a Child
 * Mission, an Expansion successor, a carryover replacement, a ceiling
 * drawdown successor), index-aligned with its entries. Each entry that takes
 * a deployment figure keeps the strictest figure retained by every reference
 * it falls within that takes one too, so overlapping references never lend it
 * a looser figure. It is unknown where any such reference retains none. An
 * entry that falls within no such reference is one this creation adds: it
 * takes `added`, the figure this creation's own approval event establishes,
 * where the creating path has one, and is unknown otherwise. The current
 * deployment policy is never read for an inherited entry.
 */
export function inheritedChildMaxima(
  entries: readonly AuthorityEntry[],
  references: readonly ChildMaximumReference[],
  added?: { readonly deploymentFigure: number | null },
): RetainedChildMaximum[] {
  return entries.map((entry) => {
    if (!takesDeploymentFigure(entry)) return null;
    const containing = references.filter((r) => takesDeploymentFigure(r.entry) && within(entry, r.entry));
    if (containing.length === 0) return added ? figureMaximum(added.deploymentFigure) : null;
    const maxima: StandingConsentMaximum[] = [];
    for (const r of containing) {
      if (!r.maximum) return null;
      maxima.push(r.maximum);
    }
    return strictestMaximum(maxima);
  });
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
