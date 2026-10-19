/**
 * @spec child-delegation#fanout (inherited child-actor eligibility, #1304, D486)
 * @spec resource-access#delegate-eligibility (the model this mirrors, D454, D457)
 *
 * Child-actor eligibility with retained provenance. An approved entry derived
 * from a reference entry whose `delegation.children` carries no
 * `allowed_child_actors` inherits the authorization server's child-creation
 * policy decision for the child actor, and so does every entry derived from
 * it. A list the entry carries (one a proposal added, or a later narrowing)
 * only restricts that decision; it never replaces it.
 *
 * The approved entry's own members cannot show the obligation (a proposal can
 * add a list over a `children` grant without one), so the authorization server
 * records each approved entry's child-actor ORIGIN when it derives the
 * Authority Set and retains it with the Mission
 * (`MissionRecord.child_actor_provenance`, index-aligned with
 * `authority_set`). It is recorded separately from the delegate origin
 * (`eligibility_provenance`): one never establishes the other. It is
 * authorization-server state, on no wire member, and never inferred later
 * from an entry's list.
 *
 * The hook here is the authorization server's own child-creation policy. It is
 * distinct from an entry's `child_creation_policy` member, the committed
 * activation policy reference whose digest is verified before each creation.
 */

import { type DelegateCandidate, delegatePermitted } from "./delegate-matcher.js";
import { combineOrigins, type EligibilityOrigin, type RetainedOrigin } from "./eligibility-provenance.js";
import type { AuthorityEntry, ChildFanoutControls } from "./types.js";

/** The `delegation.children` grant of an entry, or undefined when it carries none. */
function childControls(entry: AuthorityEntry): ChildFanoutControls | undefined {
  const c = entry.delegation?.children;
  return c !== null && typeof c === "object" && !Array.isArray(c) ? (c as ChildFanoutControls) : undefined;
}

/** An entry's `allowed_child_actors`, or undefined when its `children` grant carries none. */
function childActorList(entry: AuthorityEntry): ChildFanoutControls["allowed_child_actors"] {
  return childControls(entry)?.allowed_child_actors;
}

/**
 * The child-actor origin a ceiling (or other derivation reference) entry
 * confers on an entry derived from it: `policy` when its `children` grant
 * carries no `allowed_child_actors`, otherwise `list`. An entry without a
 * `children` grant derives an entry that permits no child, whose origin no
 * gate consults.
 */
export function childActorCeilingOrigin(reference: AuthorityEntry): EligibilityOrigin {
  const children = childControls(reference);
  return children !== undefined && children.allowed_child_actors === undefined ? "policy" : "list";
}

/**
 * The child-actor origin an entry derived within reference entries inherits:
 * its own (derivation) origin combined with that of EVERY reference entry
 * granting `children` that the entry falls within (same type and resource,
 * every action covered). Overlapping references never supply a more
 * permissive origin. An entry granting `children` that falls within no
 * reference granting it is unresolved.
 */
export function inheritChildActorOrigins(
  entries: readonly AuthorityEntry[],
  own: readonly RetainedOrigin[],
  references: ReadonlyArray<{ entry: AuthorityEntry; origin: RetainedOrigin }>,
): RetainedOrigin[] {
  return entries.map((entry, i) => {
    const self = own[i] ?? null;
    if (childControls(entry) === undefined) return self;
    const within = references.filter(
      (r) =>
        childControls(r.entry) !== undefined &&
        r.entry.type === entry.type &&
        r.entry.resource === entry.resource &&
        entry.actions.every((a) => r.entry.actions.includes(a)),
    );
    if (within.length === 0) return null;
    return combineOrigins(self, ...within.map((r) => r.origin));
  });
}

/**
 * @spec child-delegation#fanout: the authorization server's child-creation
 * policy, consulted for the child actor at every creation and carryover
 * commit where a justifying parent entry's child-actor eligibility defers to
 * it. It returns `true` only to permit; anything else denies.
 */
export type ChildCreationAuthorizationPolicy = (request: ChildCreationPolicyRequest) => boolean;

/** What the child-creation policy is asked. */
export interface ChildCreationPolicyRequest {
  /** `creation`: a child-creation exchange (never its recovery); `carryover`: a carryover replacement. */
  operation: "creation" | "carryover";
  /** The Parent Mission (for carryover, the prospective parent, possibly not yet committed). */
  parent: { id: string; issuer: string; client_id: string; subject: { iss: string; sub: string } };
  /** The parent's approved entry whose child-actor eligibility defers to policy. */
  approved: AuthorityEntry;
  /** The child actor: its identifier and the AS-asserted profile. */
  child_actor: DelegateCandidate;
  /** The child-generation depth of the child being created. */
  depth: number;
}

/**
 * The reference implementation's policy: deny every child actor. A justifying
 * entry whose child-actor eligibility defers to policy therefore admits no
 * child unless a deployment installs a policy that permits.
 */
export const DENY_ALL_CHILD_CREATION_POLICY: ChildCreationAuthorizationPolicy = () => false;

/** A parent as the child-actor gate sees it: its approved entries and their retained child-actor origins. */
export interface ChildActorParent {
  mission: ChildCreationPolicyRequest["parent"];
  /** The parent's approved Authority Set, the justifying-index basis. */
  approved: readonly AuthorityEntry[];
  /** Each approved entry's retained child-actor origin, index-aligned with `approved`. */
  origins: readonly RetainedOrigin[];
}

/** Why the gate refused: an origin it cannot resolve, or a list or policy that does not permit. */
export interface ChildActorRefusal {
  unresolved: boolean;
  message: string;
}

/**
 * @spec child-delegation#fanout (#1304, D486): decide whether `actor` may
 * receive a Child Mission drawing on the parent entries `drawnOn` (justifying
 * indices into `parent.approved`, attributed first-in-order as fan-out
 * accounting attributes them).
 *
 * 1. Resolution: every justifying entry has a retained child-actor origin.
 *    A missing, unreadable or misaligned origin refuses (`unresolved`).
 * 2. Every retained list permits the actor: each justifying entry's
 *    `allowed_child_actors` where it carries one. An empty list admits nobody.
 * 3. `list` origin: the entry's list decides, and an absent list denies, as
 *    before; the policy is never asked. `policy` origin: the child-creation
 *    policy must permit, asked now for that entry; an absent list defers to
 *    it and is never a grant.
 *
 * The policy is asked only once the other conditions hold for every
 * justifying entry, and is asked afresh at every call. Returns undefined
 * when the actor is eligible.
 */
export function childActorRefusal(
  parent: ChildActorParent,
  drawnOn: readonly number[],
  actor: DelegateCandidate,
  depth: number,
  operation: ChildCreationPolicyRequest["operation"],
  policy: ChildCreationAuthorizationPolicy,
): ChildActorRefusal | undefined {
  const deferred: AuthorityEntry[] = [];
  for (const pi of drawnOn) {
    const approved = parent.approved[pi];
    const origin = parent.origins[pi] ?? null;
    if (!approved || origin === null) {
      return { unresolved: true, message: "a justifying parent entry's child-actor eligibility origin cannot be resolved" };
    }
    const list = childActorList(approved);
    if (list !== undefined && !delegatePermitted(actor, list)) {
      return { unresolved: false, message: "child actor is not permitted by a justifying entry's allowed_child_actors" };
    }
    if (origin === "list") {
      if (list === undefined) {
        return { unresolved: false, message: "a justifying entry whose eligibility is its list carries no allowed_child_actors" };
      }
      continue;
    }
    deferred.push(approved);
  }
  for (const approved of deferred) {
    if (policy({ operation, parent: parent.mission, approved, child_actor: actor, depth }) !== true) {
      return { unresolved: false, message: "the child-creation policy does not permit this child actor for a justifying entry" };
    }
  }
  return undefined;
}

/**
 * @spec child-delegation#attenuation, child-delegation#fanout (#1304): whether
 * a presented token entry's `allowed_child_actors` admits `actor`, where the
 * child entry it is attributed to is justified by a parent entry of retained
 * origin `origin`. A list the token entry carries restricts and must permit;
 * an empty one admits nobody. An absent list defers to the parent's
 * child-creation policy only where that parent entry's eligibility does
 * (`policy`, decided by {@link childActorRefusal} at creation; recovery of a
 * committed creation keeps the decision its commit made); otherwise it
 * denies, as before.
 */
export function presentedChildActorPermitted(
  tokenEntry: AuthorityEntry,
  origin: RetainedOrigin,
  actor: DelegateCandidate,
): boolean {
  const list = childActorList(tokenEntry);
  if (list !== undefined) return delegatePermitted(actor, list);
  return origin === "policy";
}
