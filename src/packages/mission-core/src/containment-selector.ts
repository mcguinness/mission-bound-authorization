/**
 * @spec containment#selector-matching, resource-access#resource-matching,
 * resource-access#subset (#1463, D606): the selector-to-entry contract that
 * Mission Containment pairs a contained capability with approved Authority
 * Set entries on.
 *
 * A contained capability is a selector, not an entry identity: it applies to
 * every approved entry whose resource set overlaps its own under Resource
 * Access matching. The audience-overlap helper (`entryOverlapsResource`) is
 * deliberately not reused: it reads a served resource as a service tree, so
 * an `exact` service-root selector would silently become a subtree selector.
 * Here an absent `resource_match` is `exact`, and `prefix` applies only by
 * declaration.
 */

import { resourceWithin } from "./authority-subset.js";
import {
  isAbsoluteUri,
  isEnforceablePrefixBase,
  resourceMatchViolation,
} from "./operation-target.js";

/**
 * A contained-capability entry: `resource` and its matching mode select the
 * approved entries it applies to; `actions`, when present, are the actions it
 * removes from each of them, and when absent it removes each of them whole.
 */
export interface ContainmentSelector {
  resource: string;
  /** `exact` (the default, and the reading when absent) or `prefix`, by declaration only. */
  resource_match?: "exact" | "prefix";
  actions?: string[];
}

/** The members a containment selector may carry; any other member is refused. */
export const CONTAINMENT_SELECTOR_MEMBERS: readonly string[] = Object.freeze([
  "resource",
  "resource_match",
  "actions",
]);

/**
 * Why `value` cannot be admitted as a containment selector, or undefined.
 * Every intake (the containment policy loader, the contain operation and the
 * kernel's contain transition) reads this one rule. A selector the matcher
 * cannot decide would contain nothing, which is the unsafe direction, so it
 * is refused rather than admitted: an unrecognized `resource_match`, a
 * `prefix` base Resource Access refuses ({@link resourceMatchViolation}), an
 * empty or non-string `actions` list, and an unknown member (a misspelled
 * mode would otherwise read as `exact`).
 */
export function containmentSelectorViolation(value: unknown): string | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return "a containment selector must be a JSON object";
  }
  const selector = value as Record<string, unknown>;
  for (const member of Object.keys(selector)) {
    if (!CONTAINMENT_SELECTOR_MEMBERS.includes(member)) {
      return `a containment selector carries ${JSON.stringify(member)}, which is not a selector member`;
    }
  }
  if (typeof selector.resource !== "string" || !isAbsoluteUri(selector.resource)) {
    return "a containment selector's resource must be an absolute URI";
  }
  const mode = resourceMatchViolation({
    resource: selector.resource,
    resource_match: selector.resource_match,
  });
  if (mode !== undefined) return mode;
  if (
    selector.actions !== undefined &&
    (!Array.isArray(selector.actions) ||
      selector.actions.length === 0 ||
      selector.actions.some((a) => typeof a !== "string"))
  ) {
    return "a containment selector's actions, when present, must be a non-empty array of strings";
  }
  return undefined;
}

/** Whether the matcher can decide a resource set: a string `resource` under `exact`, or under an enforceable `prefix` base. */
function decidable(side: {
  readonly resource: unknown;
  readonly resource_match?: unknown;
}): boolean {
  if (typeof side.resource !== "string") return false;
  const mode = side.resource_match;
  if (mode === undefined || mode === "exact") return true;
  return mode === "prefix" && isEnforceablePrefixBase(side.resource);
}

/**
 * @spec containment#selector-matching (#1463, D606): whether `selector`
 * applies to `entry`, that is, whether their resource sets overlap under
 * Resource Access matching. Each set is the one resource an `exact` side
 * names or the tree a `prefix` base admits, so two sets overlap exactly when
 * one is contained in the other under the Subset Rule's resource comparison
 * ({@link resourceWithin}, over `prefixAdmits`): the selector within the
 * entry (a fine selector over a broad `prefix` entry), or the entry within
 * the selector (a broad `prefix` selector over a fine entry).
 *
 * A side the matcher cannot decide (an unrecognized `resource_match`, a
 * `prefix` base it cannot enforce, a non-string `resource`) reads as
 * overlapping: a pairing that cannot be decided over-contains, never
 * under-contains. The intakes refuse such a selector
 * ({@link containmentSelectorViolation}), so this is defense in depth.
 */
export function selectorOverlapsEntry(
  selector: { readonly resource: unknown; readonly resource_match?: unknown },
  entry: { readonly resource: unknown; readonly resource_match?: unknown },
): boolean {
  if (!decidable(selector) || !decidable(entry)) return true;
  return resourceWithin(selector, entry) || resourceWithin(entry, selector);
}

/** What containment removes from one approved entry: the whole entry, or the union of the selected actions. */
export type ContainmentRemoval =
  | { readonly whole: true }
  | { readonly whole: false; readonly actions: ReadonlySet<string> };

/**
 * @spec containment#selector-matching (#1463, D606): what `selectors` remove
 * from `entry`, or undefined when none applies. Every selector that overlaps
 * the entry contributes, never only the first: the removal is the union of
 * their actions, and the whole entry when any of them has no `actions`.
 *
 * The removal is per entry. A selector finer than the entry, such as an
 * `exact` selector for one resource beneath a `prefix` entry, removes its
 * actions across the whole entry, because an entry cannot express "this
 * prefix except that resource". That over-containment is conservative: it
 * removes authority beyond the selector, never less.
 */
export function containmentRemovalFor(
  entry: { readonly resource: unknown; readonly resource_match?: unknown },
  selectors: readonly ContainmentSelector[],
): ContainmentRemoval | undefined {
  let actions: Set<string> | undefined;
  for (const selector of selectors) {
    if (!selectorOverlapsEntry(selector, entry)) continue;
    if (selector.actions === undefined) return { whole: true };
    actions ??= new Set<string>();
    for (const a of selector.actions) actions.add(a);
  }
  return actions === undefined ? undefined : { whole: false, actions };
}

/** The canonical stored form: `resource_match` only when `prefix`, so an `exact` selector keeps its pre-#1463 bytes. */
function canonicalSelector(
  resource: string,
  mode: unknown,
  actions: Iterable<string> | undefined,
): ContainmentSelector {
  return {
    resource,
    ...(mode === "prefix" ? { resource_match: "prefix" as const } : {}),
    ...(actions !== undefined ? { actions: [...actions] } : {}),
  };
}

/**
 * @spec containment#contain-transition, containment#selector-matching (#1463,
 * D606): the monotonic union of selector lists, in order. Selectors merge
 * only when they name the same `resource` under the same mode: their actions
 * union, and one with no `actions` absorbs the rest. Selectors with equal
 * `resource` strings and different modes select different resource sets and
 * stay separate; no selector subsumes another.
 */
export function mergeContainmentSelectors(
  ...lists: ReadonlyArray<readonly ContainmentSelector[]>
): ContainmentSelector[] {
  const merged = new Map<
    string,
    { resource: string; mode: unknown; actions: Set<string> | undefined }
  >();
  for (const list of lists) {
    for (const s of list) {
      const mode = s.resource_match === "prefix" ? "prefix" : "exact";
      const key = JSON.stringify([mode, s.resource]);
      const current = merged.get(key);
      if (current === undefined) {
        merged.set(key, {
          resource: s.resource,
          mode,
          actions: s.actions ? new Set(s.actions) : undefined,
        });
      } else if (current.actions !== undefined) {
        if (s.actions === undefined) current.actions = undefined;
        else for (const a of s.actions) current.actions.add(a);
      }
    }
  }
  return [...merged.values()].map((m) => canonicalSelector(m.resource, m.mode, m.actions));
}

/**
 * @spec containment#selector-matching, child-delegation#child-state (#1463,
 * D606): `selectors` resolved onto `entries`, one selector per affected entry,
 * naming that entry's own `resource` and mode with what the selectors remove
 * from it ({@link containmentRemovalFor}), merged as
 * {@link mergeContainmentSelectors} merges. This is the removal as it lands on
 * the approved entries, the conservative over-containment included: what an
 * existing Child Mission justified by one of those entries must lose, and the
 * per-entry delta a consumer that pairs by an entry's own `resource` reads.
 */
export function containmentAtEntries(
  entries: ReadonlyArray<{ readonly resource: string; readonly resource_match?: unknown }>,
  selectors: readonly ContainmentSelector[],
): ContainmentSelector[] {
  const resolved: ContainmentSelector[] = [];
  for (const entry of entries) {
    const removal = containmentRemovalFor(entry, selectors);
    if (removal === undefined) continue;
    resolved.push(
      canonicalSelector(
        entry.resource,
        entry.resource_match,
        removal.whole ? undefined : removal.actions,
      ),
    );
  }
  return mergeContainmentSelectors(resolved);
}
