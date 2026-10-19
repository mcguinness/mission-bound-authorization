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
import type { DelegateCandidate } from "./delegate-matcher.js";
import { InstanceAssertionError, type ValidatedInstance } from "./instance-assertion.js";
import type { AuthorityEntry } from "./types.js";

export {
  type DelegationCandidate,
  delegateEligibility,
  gateDelegableAuthority,
} from "./eligibility-provenance.js";

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
   * @spec draft-mcguinness-oauth-mission#per-entry-enforcement: when the caller
   * supplies the delegation gate, the entries the delegate may carry.
   * Undefined for act-chain-only construction (no gate supplied).
   */
  delegatedAuthority?: AuthorityEntry[];
}

/**
 * @spec mission#delegation-constraints, resource-access#delegate-eligibility
 * (#1275): the entries a delegate may carry at a delegation depth, as the
 * authorization server decides them for the delegating Mission
 * (MissionKernel.delegableEntries: each entry resolved to its approved Mission
 * Record entries and their retained provenance, every retained list, and the
 * current delegation-authorization policy).
 */
export type DelegationGate = (delegate: DelegateCandidate, depth: number) => AuthorityEntry[];

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
   * @spec draft-mcguinness-oauth-mission#per-entry-enforcement,
   * resource-access#delegate-eligibility: the delegating Mission's delegation
   * gate. When supplied, the issued authority is what it returns for this
   * delegate at the resulting delegation depth, and an empty result refuses
   * with `invalid_target`. Omitted for act-chain-only construction.
   */
  gate?: DelegationGate;
  /**
   * @spec mission#delegation-constraints (D198, #869): the delegation depth of
   * the token being issued, from the AS's own issuance accounting, never from
   * the nesting of a presented `act`. Undefined is unknown depth: with a gate
   * supplied, every entry narrows out and the issuance refuses.
   */
  accountedDepth?: number;
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

  // @spec draft-mcguinness-oauth-mission#per-entry-enforcement: when the
  // delegation gate is supplied, apply it at the accounted depth of the token
  // being issued (D198). The chain length above is a structural cap only,
  // never the authorization depth.
  let delegatedAuthority: AuthorityEntry[] | undefined;
  if (input.gate) {
    if (input.accountedDepth === undefined) {
      throw new InstanceAssertionError(
        "invalid_target",
        "the delegation depth of the token being issued cannot be established, so no entry can be delegated",
      );
    }
    const delegate: DelegateCandidate = {
      // The `{ "sub": ... }` matcher is a CLIENT IDENTIFIER in the issuing AS's
      // namespace: the authenticated client, NOT the agent_instance_id act-chain
      // leaf. The AS asserts the delegate's `sub_profile` from the validated
      // instance carrier (never a self-asserted claim).
      sub: input.instance.clientId,
      assertedProfile: input.instance.subProfile,
    };
    delegatedAuthority = input.gate(delegate, input.accountedDepth);
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
