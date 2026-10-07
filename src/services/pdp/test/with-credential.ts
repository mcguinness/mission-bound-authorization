import type { EvaluationRequest } from "../src/evaluate.js";

/**
 * Test fixture (@spec authzen#context-credential, #825 PR 2b, D312). The PEP
 * supplies the credential's own authority on every decision. A request built
 * without one gets a neutral credential authority: one entry covering exactly
 * the request's own resource and action, with no constraints, so a test that
 * exercises the Mission bound keeps its meaning. A request that names
 * `authority` itself, including as `undefined`, is passed through as written:
 * that is how the credential-bound tests reach the PDP.
 */
export function withCredential(req: EvaluationRequest): EvaluationRequest {
  const credential = req.context.credential;
  if (credential !== undefined && "authority" in credential) return req;
  return {
    ...req,
    context: {
      ...req.context,
      credential: {
        ...credential,
        authority: [
          {
            type: "mission_resource_access",
            resource: req.resource.properties?.audience ?? "",
            actions: [req.action.name],
          },
        ],
      },
    },
  };
}
