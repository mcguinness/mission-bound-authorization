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

import { type ActivationPolicyRef, type ActivationPolicySnapshot, unsupportedActionFamily } from "@mission/core";
import { within } from "./approved-audience.js";
import { entriesMayOverlap } from "./derive.js";
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
 * child-delegation#derivation-budget (#2026, D1249): the per-child maximum a
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
export function figureMaximum(deploymentFigure: number | null): StandingConsentMaximum {
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

/** Whether an entry grants policy-created children at all (`delegation.children` is an object). */
function grantsChildren(entry: AuthorityEntry): boolean {
  const children: unknown = entry.delegation?.children;
  return children !== null && typeof children === "object" && !Array.isArray(children);
}

/**
 * @spec derivation-limits#effective-limit (#2026 review F1): whether `entry`
 * may carry authority `source` held. False only where the two are provably
 * disjoint ({@link entriesMayOverlap}: no shared action, unrelated
 * resources, or constraints with an empty intersection). An action family
 * on either side, which that literal comparison cannot narrow, or an entry
 * it cannot read, counts as overlapping: what cannot be shown disjoint is
 * treated as carried.
 */
export function mayCarryAuthorityOf(entry: AuthorityEntry, source: AuthorityEntry): boolean {
  if (unsupportedActionFamily(entry) !== undefined || unsupportedActionFamily(source) !== undefined) return true;
  try {
    return entriesMayOverlap(entry, source);
  } catch {
    return true;
  }
}

/**
 * @spec derivation-limits#effective-limit (#2026, D1249; review F1): the
 * figures a record derived from earlier authority retains (a Child Mission,
 * an Expansion successor, a carryover replacement, a ceiling drawdown
 * successor), index-aligned with its entries. A successor can widen or
 * regroup an entry, so an entry is bounded by every earlier entry whose
 * authority it may carry, not only one it falls within whole:
 * - its sources are the earlier entries that granted children and that it
 *   may carry authority from ({@link mayCarryAuthorityOf}: overlapping, or
 *   not provably disjoint);
 * - with any source in unknown state (it retains no figure, or its figure
 *   was stated by a `child_creation_policy` snapshot this record does not
 *   retain), the entry is unknown, so no child is created under it until a
 *   fresh human approval;
 * - otherwise it keeps the strictest of its sources' figures;
 * - where it falls within no single source whole, part of its authority may
 *   be new, so the figure `added` resolves for it bounds it too, where the
 *   creating path adds authority, and an unknown one makes it unknown;
 * - an entry with no source carries no earlier per-child commitment: it
 *   takes the figure `added` resolves for it where the creating path adds
 *   authority, and is unknown otherwise.
 * `added` is the figure the human consent that admits the added authority
 * rendered and retained ({@link AddedChildMaximum}, #2040), never one read at
 * this creation: it never loosens or replaces a known or unknown inherited
 * bound. The current deployment policy is never read here.
 */
export function inheritedChildMaxima(
  entries: readonly AuthorityEntry[],
  references: readonly ChildMaximumReference[],
  added?: AddedChildMaximum,
): RetainedChildMaximum[] {
  return entries.map((entry) => {
    if (!takesDeploymentFigure(entry)) return null;
    const sources = references.filter((r) => grantsChildren(r.entry) && mayCarryAuthorityOf(entry, r.entry));
    if (sources.length === 0) return added ? (addedMaximum(entry, added) ?? null) : null;
    const carried = strictestOfSources(sources);
    if (!carried) return null;
    if (!added || sources.some((r) => within(entry, r.entry))) return carried;
    const extra = addedMaximum(entry, added);
    return extra ? strictestMaximum([carried, extra]) : null;
  });
}

/**
 * @spec derivation-limits#effective-limit, derivation-limits#approval-rendering
 * (#2040, D1260 ruling 3): the per-child figure for authority a creating path
 * adds, as the human consent that admits it rendered and retained it:
 * - `retained`: the one figure a fresh human approval of that authority
 *   rendered and retained with its decision (an Expansion deferral's);
 * - `references`: the figures a standing consent retained for each entry of
 *   the authority it admits (a Mission Template's ceiling, a Progressive
 *   ceiling): the added authority takes the strictest figure of the consented
 *   entries it may carry authority of, and is unknown where any of them is
 *   unknown, commits a `child_creation_policy`, or where none grants children;
 * - `unknown`: the consent that admits it retains no figure (it was approved
 *   before the figure was retained), so no child is created under it until a
 *   fresh human approval retains one. Nothing is inferred from the current
 *   deployment policy, a `policy_version` or a Mission's `derivation_limit`.
 */
export type AddedChildMaximum =
  | { readonly retained: StandingConsentMaximum }
  | { readonly references: readonly ChildMaximumReference[] }
  | { readonly unknown: true };

/** The strictest figure several sources retain, or undefined where any is unknown or commits a policy. */
function strictestOfSources(sources: readonly ChildMaximumReference[]): StandingConsentMaximum | undefined {
  const maxima: StandingConsentMaximum[] = [];
  for (const r of sources) {
    if (!takesDeploymentFigure(r.entry) || !r.maximum) return undefined;
    maxima.push(r.maximum);
  }
  return strictestMaximum(maxima);
}

/** The figure `added` resolves for an entry, or undefined where it is unknown. */
function addedMaximum(entry: AuthorityEntry, added: AddedChildMaximum): StandingConsentMaximum | undefined {
  if ("retained" in added) return added.retained;
  if ("unknown" in added) return undefined;
  const sources = added.references.filter((r) => grantsChildren(r.entry) && mayCarryAuthorityOf(entry, r.entry));
  return sources.length === 0 ? undefined : strictestOfSources(sources);
}

/**
 * @spec derivation-limits#effective-limit (#2026, #2040): a stored list of
 * retained per-child figures, or undefined where it is not a list whose every
 * element is `null`, `{ finite: null }` or `{ finite: n }` with `n` an integer
 * of at least 1. Unreadable state retains no figure, so a child under an entry
 * that takes one is refused, never read as no finite maximum.
 */
export function parseRetainedChildMaxima(value: unknown): RetainedChildMaximum[] | undefined {
  const element = (m: unknown): boolean => {
    if (m === null) return true;
    if (typeof m !== "object" || Array.isArray(m) || Object.keys(m as object).length !== 1 || !Object.hasOwn(m as object, "finite")) {
      return false;
    }
    const finite = (m as { finite: unknown }).finite;
    return finite === null || (typeof finite === "number" && Number.isInteger(finite) && finite >= 1);
  };
  return Array.isArray(value) && value.every(element) ? (value as RetainedChildMaximum[]) : undefined;
}

/** {@link parseRetainedChildMaxima} over stored JSON text: undefined where none is stored or it cannot be read. */
export function retainedChildMaximaOf(text: unknown): RetainedChildMaximum[] | undefined {
  if (typeof text !== "string" || text === "") return undefined;
  try {
    return parseRetainedChildMaxima(JSON.parse(text));
  } catch {
    return undefined;
  }
}

/** One retained figure as stored JSON text, or undefined where it cannot be read. */
export function retainedFigureOf(text: unknown): StandingConsentMaximum | undefined {
  if (typeof text !== "string" || text === "") return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return undefined;
  }
  return parseRetainedChildMaxima([parsed])?.[0] ?? undefined;
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

/**
 * @spec derivation-limits#effective-limit (#2026, D1249 ruling 4; #2040): the
 * statement for a delegable entry whose per-child figure is unknown, because
 * authority it carries was approved before the figure was retained.
 */
export const UNRETAINED_PER_CHILD_STATEMENT =
  "No child Mission is created under this entry: part of its authority was approved before its per-child derivation limit was retained, and only a fresh approval of that authority retains one.";

/**
 * @spec derivation-limits#approval-rendering, child-delegation#subtree-rendering
 * (#1119): why a delegable entry's per-child figure cannot be disclosed, or
 * the empty string when it can. An approval cannot consent to a child grant
 * whose rule and maximum it could not show, so the decision refuses while any
 * is undisclosable; once the policy is held again, a fresh approval discloses it.
 */
export function undisclosableReason(committed: CommittedPerChildMaximum): string {
  return committed.source === "unheld"
    ? `The per-child derivation limit cannot be shown: child creation policy ${committed.policy.id} version ${committed.policy.version} is not one this issuer holds at its committed digest. This approval is refused until it can be shown.`
    : committed.source === "unusable"
      ? `The per-child derivation limit cannot be shown: child creation policy ${committed.policy.id} states a malformed ${STANDING_CONSENT_LIMIT_MEMBER}. This approval is refused until it states a usable one.`
      : "";
}

/** One delegable entry's disclosure: its label and lines, and why its per-child figure cannot be shown, where it cannot. */
export interface ChildGrantDisclosure {
  label: string;
  lines: string[];
  undisclosed?: string;
}

/**
 * @spec derivation-limits#approval-rendering, child-delegation#subtree-rendering,
 * derivation-limits#effective-limit (#1119, D327, #2026, #2040): the
 * disclosure every human approval renders for each entry of `entries` that
 * grants policy-created children: the subtree figures, the per-child rule and
 * maximum, and the aggregate statement. One reader for every approval
 * surface (the Mission approval page and its ceiling consent, the Expansion
 * deferral page and its re-consent, the Mission Template consent), so each
 * computes the figure the same way:
 * - an entry committing a `child_creation_policy` shows the maximum its held
 *   snapshot states, or why it cannot be shown;
 * - any other delegable entry shows `figures[i]`, the figure the approval
 *   retains for it (index-aligned with `entries`), or, where that figure is
 *   unknown (`null`), that no child is created under it.
 * Where the deployment does not implement Derivation Limits (#2018) no
 * per-child line is rendered, and the subtree lines remain.
 */
export function childGrantDisclosures(
  entries: readonly AuthorityEntry[],
  opts: {
    derivationLimits?: boolean;
    figures: readonly RetainedChildMaximum[];
    held: (ref: ActivationPolicyRef) => ActivationPolicySnapshot | undefined;
    asyncDelegation: boolean;
  },
): ChildGrantDisclosure[] {
  const out: ChildGrantDisclosure[] = [];
  entries.forEach((entry, i) => {
    const grant = entry.delegation?.children as
      | { max_children?: number; max_child_depth?: number; child_creation_policy?: ActivationPolicyRef }
      | undefined;
    if (!grant) return;
    const committed = committedPerChildMaximum(grant, opts.held);
    const figure = opts.figures[i];
    const undisclosed = undisclosableReason(committed);
    const perChild =
      opts.derivationLimits === false
        ? []
        : committed.source === "policy"
          ? standingConsentLines(committed.maximum, "child Mission", { asyncDelegation: opts.asyncDelegation })
          : committed.source === "deployment"
            ? figure
              ? standingConsentLines(figure, "child Mission", { asyncDelegation: opts.asyncDelegation })
              : [UNRETAINED_PER_CHILD_STATEMENT]
            : [undisclosed];
    out.push({
      label: `${entry.resource}: ${entry.actions.join(", ")}`,
      lines: [
        grant.max_children === undefined
          ? "Concurrent children: no limit is set on concurrently non-terminal child Missions."
          : `Concurrent children: at most ${grant.max_children} concurrently non-terminal child Missions (a limit on children at one time, not on children created over the Mission's lifetime).`,
        `Child depth: at most ${grant.max_child_depth ?? 1}${grant.max_child_depth === undefined ? " (the default)" : ""}.`,
        ...perChild,
        SUBTREE_AGGREGATE_STATEMENT,
      ],
      ...(undisclosed ? { undisclosed: `${entry.resource}: ${undisclosed}` } : {}),
    });
  });
  return out;
}

/** @spec progressive#derivation-limits — the inheritance a ceiling consent discloses. */
export function progressiveInheritanceLine(limit: number | null): string {
  return limit === null
    ? "If you also consent to an authority ceiling, this Mission has no derivation limit, so no finite limit is guaranteed for the successors its drawdown policy creates."
    : `If you also consent to an authority ceiling, the successors its drawdown policy creates carry this Mission's derivation count forward and never exceed its derivation limit of ${limit}.`;
}
