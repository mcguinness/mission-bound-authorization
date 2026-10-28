import type { EvaluationRequest } from "../src/evaluate.js";

/**
 * Test fixture (@spec authzen#context-credential, #825 PR 2b, D312). The PEP
 * supplies the credential's own authority on every decision. A request built
 * without one gets a neutral credential authority: one entry covering exactly
 * the request's own operation target (#1276, D457) and action, under the
 * request's own `resource_contract` where it carries one (#249, D865), with
 * no constraints, so a test that exercises the Mission bound keeps its
 * meaning. A request that names `authority` itself, including as
 * `undefined`, is passed through as written: that is how the
 * credential-bound tests reach the PDP.
 */
export function withCredential(req: EvaluationRequest): EvaluationRequest {
  return withCredentialAuthority(withActionClass(req));
}

/**
 * Test fixture (@spec runtime#classification, authzen#pdp-consistency-checks,
 * #956, D814). A mediated request reaches the PDP carrying the class its PEP's
 * Operation Profile assigns; one with none is refused before evaluation
 * (`action_class_missing`). A request built without a class gets
 * `consequential_read`, the class these tests exercised when the PDP still
 * defaulted to it, so each keeps its meaning. A request that names
 * `action_class` itself, including as `undefined`, is passed through as
 * written: that is how the missing-class tests reach the PDP.
 */
export function withActionClass(req: EvaluationRequest): EvaluationRequest {
  if ("action_class" in req.context) return req;
  return { ...req, context: { ...req.context, action_class: "consequential_read" } };
}

function withCredentialAuthority(req: EvaluationRequest): EvaluationRequest {
  const credential = req.context.credential;
  if (credential !== undefined && "authority" in credential) return req;
  const contract = req.resource.properties?.resource_contract;
  return {
    ...req,
    context: {
      ...req.context,
      credential: {
        ...credential,
        authority: [
          {
            type: "mission_resource_access",
            resource: req.resource.properties?.operation_target ?? "",
            actions: [req.action.name],
            ...(contract !== undefined ? { resource_contract: contract } : {}),
          },
        ],
      },
    },
  };
}
