/**
 * @spec authzen#projections, runtime#idempotency (#917): the PDP's internal
 * projections of a validated evaluation request that the idempotency claim
 * and permit retransmission turn on. None is a wire member: each is computed
 * here from members the request already carries, after the PDP validated
 * them, and stored beside the claim rather than sent anywhere.
 *
 * - The idempotency scope (runtime): which (scope, key) namespace a claim
 *   lives in. Request facts the PDP validated, never a domain or dimension
 *   the request names.
 * - Operation identity (AuthZEN): what one key identifies one execution of.
 * - Cache key (AuthZEN): what a returned prior decision must still match.
 *   It is the authorization binding plus the state generation the decision
 *   consulted, and never observation telemetry.
 */

import { canonicalDigest, type IdempotencyScope, idempotencyScopeActor, isActionPhase, type JsonValue } from "@mission/core";
import type { EvaluationRequest } from "./evaluate.js";
import type { MissionView } from "./policy-view.js";

/**
 * @spec runtime#idempotency: the fixed-member scope for a request that
 * reached the claim step, or `undefined` when its actor has no stable
 * identity to key on. `mission` is the request's reference, which the
 * view-consistency check has already held equal to the loaded view; `actor`
 * is the client and, where the immediate (leaf) `act` entry names a
 * delegate, that delegate (`idempotencyScopeActor`), so a new client
 * instance, an instance-profiled leaf, or a longer chain above the leaf does
 * not split the scope; `audience` is `resource.properties.audience`, the
 * member the PDP matched the authority entry against and the remote channel
 * checked against the PEP's authorized scopes (@spec authzen#pdp-request);
 * `phase` is the validated phase, `null` where the operation is no
 * phase of a compound action.
 */
export function idempotencyScopeOf(req: EvaluationRequest): IdempotencyScope | undefined {
  // validateContextActor (step 4) already refused an entry whose iss or sub
  // is not a string; the claim step runs only after it.
  const actor = idempotencyScopeActor(req.context.actor);
  if (!actor) return undefined;
  return {
    mission: { iss: req.context.mission.issuer, id: req.context.mission.id },
    subject: { iss: req.subject.properties?.iss ?? null, sub: req.subject.id },
    actor,
    audience: req.resource.properties.audience,
    action: req.action.name,
    resource: { type: req.resource.type, id: req.resource.id },
    phase: isActionPhase(req.context.action_phase) ? req.context.action_phase : null,
  };
}

/**
 * @spec authzen#projections, "Operation identity": the action, the resource,
 * and the normalized effectful parameters, here committed to by
 * `parameter_digest` (the PEP sends the commitment, not the parameters).
 * The plain JCS digest of that subset, not an anchor envelope.
 */
export function operationIdentity(req: EvaluationRequest): string {
  return canonicalDigest({
    action: req.action.name,
    resource: { type: req.resource.type, id: req.resource.id },
    parameter_digest: req.context.parameter_digest ?? null,
  });
}

/**
 * @spec authzen#projections, "Authorization binding": the subject, the actor,
 * credential-derived facts, the Mission reference, the authority and view
 * identity, the approval, and every policy-relevant context input. The whole
 * validated request is carried except `context.freshness`, which is
 * observation telemetry (when and from where state was read); the authority
 * and view identity are the loaded view's authority commitment and the
 * policy model the decision ran under.
 */
export function authorizationBinding(req: EvaluationRequest, view: MissionView, modelId: string): JsonValue {
  const { freshness: _observationTelemetry, ...context } = req.context;
  return {
    subject: req.subject,
    action: req.action,
    resource: req.resource,
    context,
    view: { authority_hash: view.authority_hash, model_id: modelId },
  } as unknown as JsonValue;
}

/**
 * @spec authzen#projections, "Cache key": the authorization binding plus the
 * explicit state generation the decision consulted, the PDP's tracked
 * `mission_state_version` (the loaded view's `version`), excluding
 * observation telemetry. Deliberately not `policy_view_id`: this reference's
 * view identifier commits the Mission version as well, so the state
 * generation is stated once, here, by name.
 */
export function decisionCacheKey(req: EvaluationRequest, view: MissionView, modelId: string): string {
  return canonicalDigest({
    binding: authorizationBinding(req, view, modelId),
    state_generation: view.version,
  });
}
