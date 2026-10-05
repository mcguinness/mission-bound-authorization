/**
 * @spec runtime#input-authority (#825) — a Mission-bound credential's own
 * authority for fixtures that build token facts by hand: every tool this
 * resource serves, with no restriction, so a test exercises the Mission bound
 * it names and not the credential bound. A test of the credential bound
 * itself builds a narrower authority explicitly.
 */

import { CANONICAL_RESOURCE, credentialAuthorityFrom, TOOLS } from "../src/index.js";

export const ALL_ACTIONS_CREDENTIAL = credentialAuthorityFrom([
  { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: [...new Set(TOOLS.map((t) => t.action))] },
]);
