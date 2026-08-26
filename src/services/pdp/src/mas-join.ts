/**
 * @spec authority-server#mission-join (#557)
 *
 * The baseline mapping join: an ordinary OAuth credential carrying no
 * `mission` claim, joined against a PEP-supplied Mission reference. This
 * module is the pure resolver over an already-loaded `MissionView` and an
 * already-authenticated credential's subject/client; the caller (a PEP) owns
 * credential authentication, propagated-reference selection (rule 1),
 * resolving the Mission through the MAS (rule 2, `loadView`), and evidence
 * emission. Independently testable against `MissionView` fixtures.
 *
 * Rules implemented: 3 (subject join), 4 (client join, direct or explicit
 * delegate), 5 (delegate narrowing), 6 (uniform `mission_mismatch` denial,
 * no fallback), and the Mission-authority half of 8 (the acting credential's
 * own authority and current Resource policy are bounds the CALLER
 * independently intersects; this resolver only ever narrows toward the
 * Mission's own authority, never widens past it).
 */

import type { AuthorityEntry, MissionView } from "./policy-view.js";

/**
 * @spec authority-server#mission-join rule 4 — "Delegate authorization MUST
 * be explicit, an enumerated policy, never a default." Keyed by the
 * delegate's authenticated client identifier. `depth`, when present, is the
 * deployment's own currently-recorded actor depth for that delegate under
 * this Mission (@spec rule 5: "evaluated from the deployment's actor
 * records rather than from a Mission-bound token's `act` chain") -- the
 * deployment resolves it itself and supplies it here; this resolver never
 * reads a token's own `act` chain for it.
 */
export interface DelegatePolicy {
  delegates: Record<string, { depth?: number; maxDepth?: number }>;
}

export interface BaselineJoinInput {
  view: MissionView;
  /** The credential's authenticated subject (issuer-qualified). */
  subject: { iss: string; sub: string };
  /** The credential's authenticated client identifier. */
  clientId: string;
  delegatePolicy?: DelegatePolicy;
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
  // delegate authorization joins from here. No default.
  const delegateRule = input.delegatePolicy?.delegates[input.clientId];
  if (!delegateRule) return { ok: false, reason: "mission_mismatch" };
  if (delegateRule.maxDepth !== undefined && (delegateRule.depth ?? Number.POSITIVE_INFINITY) > delegateRule.maxDepth) {
    return { ok: false, reason: "mission_mismatch" };
  }

  // Rule 5: narrow to the delegable subset. Entries without a
  // `join_delegation` member are excluded entirely; `allowed_delegates`,
  // when present, MUST name this client.
  const narrowed = input.view.authority_set.filter((e) => {
    if (!e.join_delegation) return false;
    if (e.join_delegation.allowed_delegates && !e.join_delegation.allowed_delegates.includes(input.clientId)) return false;
    return true;
  });
  if (narrowed.length === 0) return { ok: false, reason: "mission_mismatch" };
  return { ok: true, disposition: "delegate", authoritySet: narrowed };
}
