/**
 * @spec actor-profile#delegation-chains (construction + presenter rebind)
 * @spec ai-agent-instance (delegation act population)
 *
 * Delegated issuance: a validated Client Instance Assertion becomes the new
 * outermost actor over the inbound subject_token chain; the issued token's
 * top-level cnf rebinds to the instance key (presenter rebind, O-27). The
 * PDP-facing projection is produced via @mission/actor-chain.
 */

import {
  type ActObject,
  type ContextActor,
  buildContextActor,
  DEFAULT_MAX_DEPTH,
  extendChain,
  flattenActChain,
  validateActChain,
} from "@mission/actor-chain";
import { type DelegateCandidate, delegatePermitted } from "./delegate-matcher.js";
import { InstanceAssertionError, type ValidatedInstance } from "./instance-assertion.js";
import type { AuthorityEntry } from "./types.js";

export interface DelegatedIssuance {
  /** The nested `act` claim for the issued token. */
  act: ActObject;
  /** Top-level cnf for the issued token (presenter rebind to the instance). */
  cnf: { jkt?: string; "x5t#S256"?: string };
  /** Top-level sub of the issued token (preserved from the subject). */
  sub: string;
  /** client_instance_id correlator for context.actor. */
  clientInstanceId: string;
  /**
   * @spec draft-mcguinness-oauth-mission#per-entry-enforcement — when the caller
   * supplies the delegating Mission's Authority Set, the entries the delegate may
   * carry after the `allowed_delegates` gate ({@link gateDelegableAuthority}).
   * Undefined for act-chain-only construction (no authority set supplied).
   */
  delegatedAuthority?: AuthorityEntry[];
}

/**
 * @spec draft-mcguinness-oauth-mission#per-entry-enforcement — the core
 * `allowed_delegates` runtime gate (previously spec'd but UNENFORCED). Given the
 * delegating Mission's Authority Set, the `delegate`, and the delegation `depth`
 * of the token being issued (its resulting `act`-chain length, counted after
 * appending the new outermost actor), return ONLY the entries the delegate may
 * carry. An entry is included iff ALL hold:
 *
 *   1. it carries a `delegation` member (otherwise non-delegable — the default);
 *   2. `depth` <= `delegation.max_depth`; and
 *   3. the delegate is permitted by `delegation.allowed_delegates` under the
 *      SHARED matcher ({@link delegatePermitted}) — an absent list DENIES
 *      (fail-closed), never blanket-grants.
 *
 * Entries failing any test narrow out, consistent with the subset rule. The
 * `delegation` member is policy, not authority: it is carried through on the
 * surviving entries so the next hop is evaluated the same way. This mirrors the
 * child path's use of the same helper for `allowed_child_actors`.
 */
export function gateDelegableAuthority(
  authoritySet: AuthorityEntry[],
  delegate: DelegateCandidate,
  depth: number,
): AuthorityEntry[] {
  return authoritySet.filter((entry) => {
    const d = entry.delegation;
    // (1) non-delegable by default; (2) per-entry max_depth bound (fail-closed on
    // a missing/invalid max_depth).
    if (!d || typeof d.max_depth !== "number" || depth > d.max_depth) return false;
    // (3) the delegate MUST be permitted by the shared matcher.
    return delegatePermitted(delegate, d.allowed_delegates);
  });
}

/**
 * Construct a delegated issuance from a validated instance assertion and the
 * inbound subject token's `act` chain (undefined when the subject token had
 * none). Enforces the local max depth on the resulting chain.
 */
export function constructDelegatedIssuance(input: {
  instance: ValidatedInstance;
  subjectSub: string;
  inboundAct?: ActObject;
  maxDepth?: number;
  /**
   * @spec draft-mcguinness-oauth-mission#per-entry-enforcement — the delegating
   * Mission's Authority Set. When supplied, the issued authority is narrowed by
   * the `allowed_delegates` gate ({@link gateDelegableAuthority}) at the resulting
   * delegation depth, and an empty result refuses with `invalid_target`. Omitted
   * for act-chain-only construction (the current behaviour, unchanged).
   */
  authoritySet?: AuthorityEntry[];
}): DelegatedIssuance {
  const maxDepth = input.maxDepth ?? DEFAULT_MAX_DEPTH;

  // Inbound chain must itself be valid before we extend it.
  validateActChain(input.inboundAct, { maxDepth });

  const newActor = {
    iss: input.instance.iss,
    sub: input.instance.sub,
    sub_profile: input.instance.subProfile,
    // act.cnf is audit metadata only; it always equals top-level cnf by
    // construction (actor-profile#4 stance, D21). Included for correlation.
    cnf: input.instance.cnf,
    agent_instance_id: input.instance.agentInstanceId,
    ...(input.instance.agentPlatform ? { agent_platform: input.instance.agentPlatform } : {}),
    ...(input.instance.agentModel ? { agent_model: input.instance.agentModel } : {}),
  };

  const act = extendChain(newActor, input.inboundAct);

  // @spec actor-profile: reject a resulting chain exceeding the local maximum;
  // MUST NOT silently truncate.
  const flat = flattenActChain(act);
  if (flat.length > maxDepth) {
    throw new InstanceAssertionError(
      "invalid_request",
      `resulting delegation depth ${flat.length} exceeds local maximum ${maxDepth}`,
    );
  }

  // @spec draft-mcguinness-oauth-mission#per-entry-enforcement — when the
  // delegating Authority Set is supplied, apply the core allowed_delegates gate at
  // the resulting delegation depth (flat.length: the token being issued).
  let delegatedAuthority: AuthorityEntry[] | undefined;
  if (input.authoritySet) {
    const delegate: DelegateCandidate = {
      // The `{ "sub": ... }` matcher is a CLIENT IDENTIFIER in the issuing AS's
      // namespace: the authenticated client, NOT the agent_instance_id act-chain
      // leaf. The AS asserts the delegate's `sub_profile` from the validated
      // instance carrier (never a self-asserted claim).
      sub: input.instance.clientId,
      assertedProfile: input.instance.subProfile,
    };
    delegatedAuthority = gateDelegableAuthority(input.authoritySet, delegate, flat.length);
    // @spec draft-mcguinness-oauth-mission#empty-result — narrowing to no entries
    // MUST refuse with invalid_target rather than issue a token with empty
    // authority; the subject grant itself remains valid for other exchanges.
    if (delegatedAuthority.length === 0) {
      throw new InstanceAssertionError(
        "invalid_target",
        "delegated issuance narrowed to empty authority (no entry permits this delegate at this depth)",
      );
    }
  }

  return {
    act,
    cnf: input.instance.cnf, // presenter rebind
    sub: input.subjectSub, // subject preserved
    clientInstanceId: input.instance.agentInstanceId,
    ...(delegatedAuthority ? { delegatedAuthority } : {}),
  };
}

/** The PDP-facing context.actor for a delegated issuance (root-to-leaf). */
export function delegatedContextActor(issuance: DelegatedIssuance, clientId: string): ContextActor {
  return buildContextActor({
    clientId,
    clientInstanceId: issuance.clientInstanceId,
    act: issuance.act,
  });
}
