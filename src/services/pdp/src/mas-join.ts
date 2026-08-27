/**
 * @spec authority-server#mission-join (#557)
 *
 * The baseline mapping join: an ordinary OAuth credential carrying no
 * `mission` claim, joined against a PEP-supplied Mission reference. This
 * module is the pure resolver over an already-loaded `MissionView` and an
 * already-authenticated credential's subject/client. Its caller is the PDP
 * itself (`evaluate()`, `services/pdp/src/evaluate.ts` step 4b, #557 review
 * point 1): a PEP owns credential authentication, propagated-reference
 * selection (rule 1), and resolving the Mission through the MAS (rule 2,
 * `loadView`), and carries the results onto the decision request
 * (`context.mission_join`) for the PDP to resolve here, rather than calling
 * this resolver itself and handing evaluate() an already-narrowed view. Also
 * independently testable against `MissionView` fixtures without either.
 *
 * Rules implemented: 3 (subject join), 4 (client join, direct or explicit
 * delegate), 5 (delegate narrowing, both the deployment's DelegatePolicy
 * ceiling and each entry's own join_delegation.max_depth), 6 (uniform
 * `mission_mismatch` denial, no fallback), and the Mission-authority half of
 * 8 (the acting credential's own authority and current Resource policy are
 * bounds the CALLER independently intersects; this resolver only ever
 * narrows toward the Mission's own authority, never widens past it).
 *
 * Also exports `deriveJoinDelegation`, a deterministic adapter from the
 * issuance representation's kernel `delegation` shape to `join_delegation`,
 * so a canonical Mission loader can populate the latter from real Mission
 * Record data.
 */

import type { AuthorityEntry, MissionView } from "./policy-view.js";

/**
 * @spec authority-server#mission-join rule 4 — "Delegate authorization MUST
 * be explicit, an enumerated policy, never a default." Keyed by the
 * delegate's authenticated client identifier. `maxDepth`, when present, is
 * this deployment's STATIC ceiling on that delegate's depth (deployment-wide
 * policy, unlike the per-request `delegateDepth` below).
 *
 * @spec observation (#557 review point 1) — `depth` used to live here too,
 * looked up internally by `resolveBaselineJoin`. It is now a caller-supplied
 * `BaselineJoinInput.delegateDepth`: rule 5's currently-recorded actor depth
 * is deployment STATE, evaluated fresh per decision, not a static policy
 * value baked into one config object at construction. Carrying it as an
 * explicit input is also what lets a PDP-side caller place it on the
 * decision request as a request fact, per the review's "carry ... the
 * delegation depth into the PDP request and resolve there".
 */
export interface DelegatePolicy {
  delegates: Record<string, { maxDepth?: number }>;
}

export interface BaselineJoinInput {
  view: MissionView;
  /** The credential's authenticated subject (issuer-qualified). */
  subject: { iss: string; sub: string };
  /** The credential's authenticated client identifier. */
  clientId: string;
  delegatePolicy?: DelegatePolicy;
  /**
   * @spec authority-server#mission-join rule 5 — the deployment's own
   * currently-recorded actor depth for `clientId` under this Mission,
   * "evaluated from the deployment's actor records rather than from a
   * Mission-bound token's `act` chain": the caller resolves it itself and
   * supplies it here; this resolver never reads a token's own `act` chain
   * for it. Absent is treated as unbounded depth, so a `max_depth`-bearing
   * delegate policy or entry (either DelegatePolicy.delegates[...].maxDepth
   * or an entry's own join_delegation.max_depth) denies closed rather than
   * assuming a shallow default.
   */
  delegateDepth?: number;
}

export type BaselineJoinResult =
  | { ok: true; disposition: "direct" | "delegate"; authoritySet: AuthorityEntry[] }
  | { ok: false; reason: "mission_mismatch" };

/**
 * @spec authority-server#mission-join rules 3, 4, 5, 6. Rule 3 (subject
 * join) is byte-equality on the issuer-qualified pair: a deployment whose AS
 * and MAS subject namespaces differ supplies an already-mapped `subject`
 * (its own account-mapping contract, {{mapping-contract}}), never a bare
 * `sub` comparison here. Rule 6: a failed subject or client join returns
 * `mission_mismatch` uniformly, and the caller MUST NOT fall back to
 * evaluating the action against the referenced Mission's authority.
 */
export function resolveBaselineJoin(input: BaselineJoinInput): BaselineJoinResult {
  if (input.view.subject.iss !== input.subject.iss || input.view.subject.sub !== input.subject.sub) {
    return { ok: false, reason: "mission_mismatch" };
  }

  if (input.view.client_id === input.clientId) {
    return { ok: true, disposition: "direct", authoritySet: input.view.authority_set };
  }

  // Rule 4: not the Mission's own client_id -- only an EXPLICIT, enumerated
  // delegate authorization joins from here. No default. maxDepth here is
  // the DEPLOYMENT'S static ceiling (DelegatePolicy); `input.delegateDepth`
  // is the caller-supplied, per-decision current depth (see the type doc).
  const delegateRule = input.delegatePolicy?.delegates[input.clientId];
  if (!delegateRule) return { ok: false, reason: "mission_mismatch" };
  if (delegateRule.maxDepth !== undefined && (input.delegateDepth ?? Number.POSITIVE_INFINITY) > delegateRule.maxDepth) {
    return { ok: false, reason: "mission_mismatch" };
  }

  // Rule 5: narrow to the delegable subset. Entries without a
  // `join_delegation` member are excluded entirely; `allowed_delegates`,
  // when present, MUST name this client. `join_delegation.max_depth` is this
  // ENTRY's own depth ceiling, independent of (and enforced in addition to)
  // the deployment's DelegatePolicy.maxDepth above: an entry declaring
  // `max_depth: 0` must exclude a delegate whose recorded depth is nonzero
  // even where the deployment-wide policy would otherwise permit it (#557
  // review point 3 -- the entry-level bound was previously never checked).
  const narrowed = input.view.authority_set.filter((e) => {
    if (!e.join_delegation) return false;
    if (e.join_delegation.allowed_delegates && !e.join_delegation.allowed_delegates.includes(input.clientId)) return false;
    if (
      e.join_delegation.max_depth !== undefined &&
      (input.delegateDepth ?? Number.POSITIVE_INFINITY) > e.join_delegation.max_depth
    ) {
      return false;
    }
    return true;
  });
  if (narrowed.length === 0) return { ok: false, reason: "mission_mismatch" };
  return { ok: true, disposition: "delegate", authoritySet: narrowed };
}

/**
 * @spec authority-server#mission-join rule 5 (#557 review point 2) — a
 * deterministic adapter from the issuance representation's per-entry
 * delegation policy (the kernel's `AuthorityEntry.delegation`,
 * `authorization-server/src/kernel/types.ts`) to this package's
 * `join_delegation` member, so a canonical Mission loader CAN populate it
 * from a real Mission Record rather than only from a test fixture that sets
 * `join_delegation` by hand. Defined against a LOCAL structural type, never
 * importing `@mission/authorization-server`: this package has no dependency
 * on it (see the module doc above), and a caller holding a genuine kernel
 * `delegation` object satisfies this parameter's shape structurally, with
 * no adapter of its own required on the caller's side.
 *
 * `max_depth` passes through unchanged. `allowed_delegates` is matched by
 * `{sub, sub_profile}` in the issuance representation (an ACTOR identity in
 * a delegation/attenuation chain) but by a bare `client_id` string here
 * (rule 4's directly-authenticated OAuth client): only an exact `sub`
 * matcher with NO `sub_profile` maps deterministically. A `sub_profile`
 * (class) matcher cannot be represented as one string and is DROPPED, never
 * approximated by e.g. matching every client. When every matcher in a
 * non-empty `allowed_delegates` is dropped this way, the result is an EMPTY
 * array, not an absent one: `resolveBaselineJoin`'s `.includes()` check on
 * an empty array excludes every delegate, the fail-closed reading -- a
 * policy this adapter cannot faithfully represent narrows to nothing,
 * never silently widens to "any".
 */
export interface KernelDelegationPolicy {
  max_depth: number;
  allowed_delegates?: Array<{ sub?: string; sub_profile?: string }>;
}

// Overloaded so a caller narrowing its own input to definitely-defined (the
// common `x !== undefined ? deriveJoinDelegation(x) : ...` shape) gets a
// definitely-defined return type back, never `T | undefined` assigned into
// an optional `join_delegation?: T` property (exactOptionalPropertyTypes).
export function deriveJoinDelegation(delegation: KernelDelegationPolicy): NonNullable<AuthorityEntry["join_delegation"]>;
export function deriveJoinDelegation(delegation: undefined): undefined;
export function deriveJoinDelegation(
  delegation: KernelDelegationPolicy | undefined,
): AuthorityEntry["join_delegation"] {
  if (!delegation) return undefined;
  const mapped: { max_depth: number; allowed_delegates?: string[] } = { max_depth: delegation.max_depth };
  if (delegation.allowed_delegates !== undefined) {
    mapped.allowed_delegates = delegation.allowed_delegates
      .filter((m) => m.sub !== undefined && m.sub_profile === undefined)
      .map((m) => m.sub as string);
  }
  return mapped;
}
