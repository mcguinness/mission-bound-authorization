/**
 * @spec runtime#input-resource-policy (#828): named Resource-policy fixtures
 * for unit tests, evals and harnesses that exercise the OTHER bounds.
 * Imported from `@mission/pdp/test-support`, never from the package root, so
 * a deployment's wiring cannot pick one up by accident. A deployment binds a
 * real policy (for example `fgaResourcePolicy`) to its decision point.
 */

import { EvaluationContextBindingDeclarations, MISSION_TXN_TOKEN_TYP } from "@mission/core";
import { currentContractRef } from "@mission/demo-data";
import { createLocalJWKSet, type CryptoKey, exportJWK, generateKeyPair, SignJWT } from "jose";
import { ARAP_APPROVAL_TYP, type ApprovalVerification } from "./approval-binding.js";
import type { ExecutionCapabilityDeclaration } from "./enforcement-scope.js";
import type { ActionApproval, EvaluationRequest } from "./evaluate.js";
import type { MissionView } from "./policy-view.js";
import {
  type ResourcePolicy,
  type ResourcePolicyQuery,
  type ResourcePolicyResult,
  ResourcePolicyUnavailableError,
} from "./resource-policy.js";

/**
 * Permits every query. For a test whose subject is the Mission or credential
 * bound: it holds the Resource-policy bound open by name, so a permit in that
 * test never reads as evidence that Resource policy was evaluated.
 */
export const RESOURCE_POLICY_PERMITS_ALL_FIXTURE: ResourcePolicy = Object.freeze({
  check: async (): Promise<ResourcePolicyResult> => ({ allowed: true }),
});

/** Refuses every query: the Resource-policy bound alone denies. */
export const RESOURCE_POLICY_REFUSES_ALL_FIXTURE: ResourcePolicy = Object.freeze({
  check: async (): Promise<ResourcePolicyResult> => ({ allowed: false }),
});

/** Refuses the queries `refuses` selects and permits the rest; records every query it receives. */
export function resourcePolicyFixture(refuses: (query: ResourcePolicyQuery) => boolean = () => false): ResourcePolicy & {
  queries: ResourcePolicyQuery[];
} {
  const queries: ResourcePolicyQuery[] = [];
  return {
    queries,
    check: async (query) => {
      queries.push(query);
      return refuses(query) ? { allowed: false } : { allowed: true };
    },
  };
}

/**
 * @spec runtime#evaluation-context-binding (#773): a declaration that claims
 * nothing, so it covers no operation. For a unit test whose subject is
 * another decision input on a covered payments operation, bound PDP-side
 * exactly as a deployment's declaration is; the claimed path has its own
 * witnesses (`evaluate-evaluation-context.test.ts`).
 */
export const EVALUATION_CONTEXT_UNCLAIMED_FIXTURE = new EvaluationContextBindingDeclarations({});

/**
 * @spec runtime#classification (#1994): no operation declarations, so a
 * request's class set is its assigned class and no phase is required. For a
 * unit test whose subject is another decision input on a payments operation
 * the shipped statement declares only at phases, bound PDP-side exactly as a
 * deployment's declarations are; the declared sets have their own witnesses
 * (`evaluate-multi-class.test.ts`).
 */
export const OPERATION_DECLARATIONS_NONE_FIXTURE: ReadonlyArray<ExecutionCapabilityDeclaration> = [];


/**
 * @spec runtime#resource-contract (#249, D865): `request` as a PEP that
 * performs the operation under the intended contract sends it, with
 * `resource.properties.resource_contract` set to the current reference for
 * its operation target (else its audience) and action. A request no declared
 * contract covers, or one already carrying a reference, is returned
 * unchanged. Derived from the declarations, never hardcoded.
 */
export function withCurrentContractReference(request: EvaluationRequest): EvaluationRequest {
  const properties = request.resource.properties;
  if (properties.resource_contract !== undefined) return request;
  const ref = currentContractRef({
    resource: properties.operation_target ?? properties.audience,
    actions: [request.action.name],
  });
  if (ref === undefined) return request;
  return { ...request, resource: { ...request.resource, properties: { ...properties, resource_contract: ref } } };
}

/**
 * @spec runtime#resource-contract (#249, D865): `request` as a PEP sends it
 * for a credential carrying the Mission's own entry: with the reference the
 * Mission entry covering its action carries. Unchanged where that entry
 * carries none, or the request already carries one. For a Mission an
 * authorization server approved, pinned only where configuration requires.
 */
export function withMissionContractReference(request: EvaluationRequest, view: MissionView): EvaluationRequest {
  const properties = request.resource.properties;
  if (properties.resource_contract !== undefined) return request;
  const ref = view.authority_set.find((e) => e.actions.includes(request.action.name))?.resource_contract;
  if (ref === undefined) return request;
  return { ...request, resource: { ...request.resource, properties: { ...properties, resource_contract: ref } } };
}

/** Cannot answer: every check throws, as an unreachable policy backend does. */
export const RESOURCE_POLICY_UNAVAILABLE_FIXTURE: ResourcePolicy = Object.freeze({
  check: async (): Promise<ResourcePolicyResult> => {
    throw new ResourcePolicyUnavailableError("fixture backend unavailable");
  },
});

/**
 * @spec authzen#context-approval (#2067, D1313): an Access Request Service
 * stand-in for unit tests and harnesses that present an action approval. It
 * holds a fresh ES256 key, the trust anchor a decision point binds for it
 * (`verification`), and mints approvals whose signed `state` binds the
 * qualified Mission identity it is given, the way the service binds the one
 * its denial binding names. `mission` undefined signs `state` with no Mission
 * claim; `override` signs under another issuer, audience or key, for the
 * refusal tests.
 */
export interface ApprovalSignerFixture {
  issuer: string;
  audience: string;
  verification: ApprovalVerification;
  approve(
    approval: Omit<ActionApproval, "state">,
    mission: { issuer: string; id: string } | undefined,
    override?: { issuer?: string; audience?: string; signingKey?: CryptoKey },
  ): Promise<ActionApproval>;
}

/**
 * @spec authzen#context-approval (#2067, D1313): a decision point's trust
 * anchor for the transaction tokens (`mission-txn-token+jwt`) a test's
 * Transaction Authorization Server stand-in signs. A test generates its
 * signing keys after the decision point is built, so `trust` adds each set to
 * the anchor's key set, which the decision point reads at every verification.
 */
export function txnTokenAnchorFixture(
  issuer: string,
  audience: string,
): { verification: ApprovalVerification; trust(jwks: { keys: readonly Record<string, unknown>[] }): void } {
  const keys: Record<string, unknown>[] = [];
  return {
    verification: {
      issuers: [
        {
          typ: MISSION_TXN_TOKEN_TYP,
          issuer,
          audience,
          keys: (header, token) => createLocalJWKSet({ keys: keys as never })(header, token),
        },
      ],
    },
    trust(jwks) {
      keys.push(...jwks.keys);
    },
  };
}

export async function approvalSignerFixture(
  options: { issuer?: string; audience?: string } = {},
): Promise<ApprovalSignerFixture> {
  const issuer = options.issuer ?? "https://ars.test";
  const audience = options.audience ?? "https://pdp.test";
  const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
  const jwk = { ...(await exportJWK(publicKey)), kid: "ars-approval-fixture", alg: "ES256" };
  return {
    issuer,
    audience,
    verification: { issuers: [{ typ: ARAP_APPROVAL_TYP, issuer, audience, keys: { keys: [jwk] } }] },
    async approve(approval, mission, override = {}) {
      const state = await new SignJWT({ ...approval, ...(mission ? { mission } : {}) })
        .setProtectedHeader({ alg: "ES256", kid: "ars-approval-fixture", typ: ARAP_APPROVAL_TYP })
        .setIssuer(override.issuer ?? issuer)
        .setAudience(override.audience ?? audience)
        .setIssuedAt()
        .sign(override.signingKey ?? privateKey);
      return { ...approval, state };
    },
  };
}
