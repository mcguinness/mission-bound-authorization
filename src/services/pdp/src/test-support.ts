/**
 * @spec runtime#input-resource-policy (#828): named Resource-policy fixtures
 * for unit tests, evals and harnesses that exercise the OTHER bounds.
 * Imported from `@mission/pdp/test-support`, never from the package root, so
 * a deployment's wiring cannot pick one up by accident. A deployment binds a
 * real policy (for example `fgaResourcePolicy`) to its decision point.
 */

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

/** Cannot answer: every check throws, as an unreachable policy backend does. */
export const RESOURCE_POLICY_UNAVAILABLE_FIXTURE: ResourcePolicy = Object.freeze({
  check: async (): Promise<ResourcePolicyResult> => {
    throw new ResourcePolicyUnavailableError("fixture backend unavailable");
  },
});
