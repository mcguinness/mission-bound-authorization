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
import { InstanceAssertionError, type ValidatedInstance } from "./instance-assertion.js";

export interface DelegatedIssuance {
  /** The nested `act` claim for the issued token. */
  act: ActObject;
  /** Top-level cnf for the issued token (presenter rebind to the instance). */
  cnf: { jkt?: string; "x5t#S256"?: string };
  /** Top-level sub of the issued token (preserved from the subject). */
  sub: string;
  /** client_instance_id correlator for context.actor. */
  clientInstanceId: string;
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

  return {
    act,
    cnf: input.instance.cnf, // presenter rebind
    sub: input.subjectSub, // subject preserved
    clientInstanceId: input.instance.agentInstanceId,
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
