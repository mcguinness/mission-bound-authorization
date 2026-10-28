/**
 * @spec runtime#input-authority (#825) — a Mission-bound credential's own
 * authority for fixtures that build token facts by hand: every tool this
 * resource serves, with no restriction, so a test exercises the Mission bound
 * it names and not the credential bound. A test of the credential bound
 * itself builds a narrower authority explicitly.
 *
 * @spec resource-access#resource-contract (#249, D865): approved against the
 * intended contract, so it carries the current reference a fresh approval
 * records and stands where configuration requires one.
 */

import { pinnedToCurrentContract } from "@mission/demo-data";
import { CANONICAL_RESOURCE, credentialAuthorityFrom, TOOLS } from "../src/index.js";

export const ALL_ACTIONS_CREDENTIAL = credentialAuthorityFrom([
  pinnedToCurrentContract({
    type: "mission_resource_access",
    resource: CANONICAL_RESOURCE,
    actions: [...new Set(TOOLS.map((t) => t.action))],
  }),
]);
