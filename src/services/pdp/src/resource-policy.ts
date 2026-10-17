/**
 * @spec runtime#input-resource-policy, authzen#runtime-denial-classification
 * `resource_policy` (#828)
 *
 * The independently administered Resource-policy bound. "The action MUST
 * fail closed unless both Mission authority and Resource policy permit it":
 * the PDP asks this dependency after the Mission-authority gates pass, and a
 * refusal denies `resource_policy` whatever the Mission allows.
 *
 * Independence is structural, not a relabeling of the Mission check. The
 * query carries the authenticated request facts only (the canonical
 * authorization Subject, the authenticated client, the action and every
 * target) and nothing derived from the Mission: no authority entry, no
 * contextual tuple, no approval. The OpenFGA implementation below checks
 * stored entitlement relations (`authorized_reader`, `authorized_payer`)
 * that admit only `user` principals, disjoint from the Mission-context
 * relations (`reader`, `payer`) the Mission check injects per decision.
 *
 * The dependency is bound PDP-side (decision point, remote PDP server), the
 * same way the evidence emitter and the claim domain are: an enforcement
 * component never supplies its own policy.
 */

import { getTracer } from "@mission/telemetry";
import type { Fga } from "./fga.js";
import { relationForAction as paymentsRelationForAction } from "./policy.js";

/** One object the action touches, as the trusted PEP resolved it. */
export interface ResourcePolicyTarget {
  type: string;
  id: string;
}

export interface ResourcePolicyQuery {
  /**
   * The canonical authorization Subject: the verified token subject and the
   * issuer this Resource authenticated it under (`subject.id`,
   * `subject.properties.iss`). Never the Approver. `iss` is absent only when
   * the request did not carry one, and a policy that needs an
   * issuer-qualified principal refuses then.
   */
  subject: { sub: string; iss?: string };
  /**
   * The authenticated client (`context.actor.client_id`, populated by the
   * PEP from the verified credential), for a policy that requires one.
   * Never read from an unverified actor field.
   */
  client?: string;
  action: string;
  /** Every target the action touches; a collection names each member. Never empty. */
  targets: readonly ResourcePolicyTarget[];
}

/**
 * `allowed: false` is a Resource-policy refusal the policy actually reached.
 * A policy that cannot reach an answer throws {@link ResourcePolicyUnavailableError}
 * instead: an unreachable policy is not a refusal, and never a permit.
 */
export type ResourcePolicyResult = { allowed: true } | { allowed: false; target?: ResourcePolicyTarget };

export interface ResourcePolicy {
  check(query: ResourcePolicyQuery): Promise<ResourcePolicyResult>;
}

/**
 * The deployment configured no Resource policy where one is required, or
 * configured something that is not one. A configuration error: the decision
 * point refuses construction, and a decision reached without one throws
 * rather than permitting on the other bounds alone.
 */
export class ResourcePolicyConfigError extends Error {
  constructor(why: string) {
    super(`resource policy configuration refused: ${why}`);
    this.name = "ResourcePolicyConfigError";
  }
}

/**
 * The policy backend could not answer (unreachable, timed out, wrong store
 * or model, malformed response). The PDP issues no decision: co-resident,
 * the decision call throws; remote, the channel answers 503. Either way the
 * PEP records `pdp_unreachable`, nothing executes, and no Decision Evidence
 * claims a policy evaluation that did not happen.
 */
export class ResourcePolicyUnavailableError extends Error {
  constructor(cause: unknown) {
    super(`resource policy unavailable: ${cause instanceof Error ? cause.message : String(cause)}`);
    this.name = "ResourcePolicyUnavailableError";
  }
}

export function isResourcePolicy(value: unknown): value is ResourcePolicy {
  return typeof value === "object" && value !== null && typeof (value as ResourcePolicy).check === "function";
}

/**
 * Ask the policy, normalizing every outcome to exactly one of: a permit, a
 * refusal, or a thrown {@link ResourcePolicyUnavailableError}. A result that
 * is neither `allowed: true` nor `allowed: false` is not an answer.
 */
export async function checkResourcePolicy(policy: ResourcePolicy, query: ResourcePolicyQuery): Promise<ResourcePolicyResult> {
  let result: unknown;
  try {
    result = await policy.check(query);
  } catch (e) {
    throw e instanceof ResourcePolicyUnavailableError ? e : new ResourcePolicyUnavailableError(e);
  }
  const allowed = typeof result === "object" && result !== null ? (result as { allowed?: unknown }).allowed : undefined;
  if (allowed === true) return { allowed: true };
  if (allowed === false) return result as ResourcePolicyResult;
  throw new ResourcePolicyUnavailableError("malformed policy result");
}

/**
 * Maps an authenticated subject to a policy principal, or `undefined` when
 * the subject is not a principal this policy administers.
 */
export type PrincipalMapper = (subject: { sub: string; iss?: string }) => string | undefined;

/**
 * The OpenFGA principal for an issuer-qualified subject: both halves
 * percent-encoded and joined by `|`, which `encodeURIComponent` always
 * escapes, so distinct `(iss, sub)` pairs never share an identifier and no
 * `:`, `#` or whitespace reaches the tuple.
 */
export function principalObject(subject: { iss: string; sub: string }): string {
  return `user:${encodeURIComponent(subject.iss)}|${encodeURIComponent(subject.sub)}`;
}

/**
 * The explicit issuer-local mapping for a single-domain deployment: a
 * subject is a principal only when authenticated under exactly the
 * configured issuer. A request's subject string under any other issuer, or
 * with no issuer, selects no principal, so it can never select another
 * issuer's entitlements.
 */
export function issuerLocalPrincipals(issuer: string): PrincipalMapper {
  if (typeof issuer !== "string" || issuer.length === 0) throw new ResourcePolicyConfigError("issuer-local mapping needs an issuer");
  return (subject) =>
    subject.iss === issuer && typeof subject.sub === "string" && subject.sub.length > 0
      ? principalObject({ iss: issuer, sub: subject.sub })
      : undefined;
}

/**
 * Maps an authenticated client, under the issuer that authenticated the
 * request's subject, to a policy principal, or `undefined` when it is not a
 * client this policy administers (D429).
 */
export type ClientMapper = (client: { client: string | undefined; iss: string | undefined }) => string | undefined;

/**
 * The OpenFGA principal for an issuer-qualified client, encoded as
 * {@link principalObject} encodes a subject, on the model's `client` type.
 */
export function clientObject(client: { iss: string; client: string }): string {
  return `client:${encodeURIComponent(client.iss)}|${encodeURIComponent(client.client)}`;
}

/**
 * The issuer-local client mapping: the authenticated client is a principal
 * only under exactly the configured issuer, the one that authenticated the
 * subject. No client, or a client under any other issuer, selects none.
 */
export function issuerLocalClients(issuer: string): ClientMapper {
  if (typeof issuer !== "string" || issuer.length === 0) throw new ResourcePolicyConfigError("issuer-local client mapping needs an issuer");
  return (c) =>
    c.iss === issuer && typeof c.client === "string" && c.client.length > 0 ? clientObject({ iss: issuer, client: c.client }) : undefined;
}

/** The stored entitlement relation for each Mission-context relation. */
export const ENTITLEMENT_RELATIONS = {
  reader: "authorized_reader",
  payer: "authorized_payer",
} as const;

export type EntitlementRelation = (typeof ENTITLEMENT_RELATIONS)[keyof typeof ENTITLEMENT_RELATIONS];

/** The stored relation a client needs on every target, whatever the action (D429). */
export const CLIENT_ENTITLEMENT = "authorized_client";

/** Target types the stored entitlement model administers. */
const POLICY_TARGET_TYPES = new Set(["invoice", "vendor"]);

/**
 * The OpenFGA-backed Resource policy: for each target, a check of the
 * stored entitlement relation the action maps to for the mapped subject, and
 * a check of `authorized_client` for the mapped client (D429), with no
 * contextual tuples. The model counts a direct grant only for a member of
 * the target's tenant. Every target must be entitled to both; the first that
 * is not refuses the whole action. A subject or client the mappers do not
 * administer, an action with no mapped relation, or a target type the model
 * does not administer refuses rather than skipping the check.
 *
 * Every check is an authoritative read (`HIGHER_CONSISTENCY`) with no cache:
 * the Resource-policy freshness this deployment declares is "current as of
 * the decision", separate from its Mission-state freshness. The read is not
 * atomic with any later business effect.
 */
export function fgaResourcePolicy(
  fga: Pick<Fga, "checkStored">,
  options: {
    principals: PrincipalMapper;
    clients: ClientMapper;
    relationForAction?: (action: string) => { relation: "payer" | "reader" } | null;
  },
): ResourcePolicy {
  const relationOf = options.relationForAction ?? paymentsRelationForAction;
  return {
    async check(query) {
      return getTracer("pdp").startActiveSpan("pdp.resource_policy", async (span) => {
        try {
          const principal = options.principals(query.subject);
          const client = options.clients({ client: query.client, iss: query.subject.iss });
          const mapped = relationOf(query.action);
          if (principal === undefined || client === undefined || mapped === null || query.targets.length === 0) return { allowed: false };
          const relation = ENTITLEMENT_RELATIONS[mapped.relation];
          for (const target of query.targets) {
            if (!POLICY_TARGET_TYPES.has(target.type) || typeof target.id !== "string" || target.id.length === 0) {
              return { allowed: false, target };
            }
            const object = `${target.type}:${target.id}`;
            const subjectAllowed = await fga.checkStored({ user: principal, relation, object }, { higherConsistency: true });
            if (!subjectAllowed) return { allowed: false, target };
            const clientAllowed = await fga.checkStored({ user: client, relation: CLIENT_ENTITLEMENT, object }, { higherConsistency: true });
            if (!clientAllowed) return { allowed: false, target };
          }
          return { allowed: true };
        } catch (e) {
          // A failed read is no answer: never a refusal, never a permit.
          throw e instanceof ResourcePolicyUnavailableError ? e : new ResourcePolicyUnavailableError(e);
        } finally {
          span.end();
        }
      });
    },
  };
}
