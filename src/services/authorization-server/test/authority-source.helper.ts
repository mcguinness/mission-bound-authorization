/**
 * Test support (NOT a spec file): the trusted authority-source catalog a suite
 * injects into its kernel.
 *
 * @spec mission#authority-sources, mission#approval-event — the catalog is
 * REQUIRED deployment configuration. The kernel refuses construction without
 * one, and gate 1 refuses any Agent the catalog does not declare, so a suite
 * declares the clients whose Missions it approves rather than inheriting a
 * permissive default. The ceiling a suite declares is its OWN derivation
 * ceiling, so gate 3 (the derived Authority Set within the source's own
 * authority) holds exactly where the deployment ceiling holds and the suite
 * keeps testing what it set out to test.
 *
 * The default source is `user_delegated`: these suites approve for a human
 * Subject under a human Approver. A suite exercising workload or
 * organizational provenance builds its catalog inline (see
 * authority-source.test.ts), which is the point of the gates.
 */

import type { AuthoritySourceCatalog } from "../src/index.js";

/** A single user-delegated source over `ceiling`, declaring `clients`. */
export function testAuthoritySourceCatalog(
  ceiling: unknown,
  clients: readonly string[],
  over: {
    /** Approvers permitted to activate. Empty (the default) places no
     *  activation restriction, matching a deployment that does not gate it. */
    activators?: readonly string[];
    humanPrincipals?: readonly string[];
  } = {},
): AuthoritySourceCatalog {
  return {
    humanPrincipals: over.humanPrincipals ?? [],
    entries: [
      {
        id: "test-user-delegated",
        type: "user_delegated",
        clients,
        activators: over.activators ?? [],
        ceiling: ceiling as never,
      },
    ],
  };
}
