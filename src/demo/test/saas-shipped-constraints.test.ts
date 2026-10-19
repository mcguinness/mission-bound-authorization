/**
 * @spec resource-access#rs-enforcement, resource-access#resource-access-type
 * (#1266, review on PR #1298)
 *
 * The SaaS resource fails closed on a `constraints` key it does not enforce,
 * and the demo RAS emits for it only the keys its metadata advertises. Every
 * ceiling the reference deployment ships for the SaaS resource therefore
 * carries only keys SaaS enforces, so the shipped cross-domain grant stays
 * usable there: adding a key SaaS cannot enforce to one of these ceilings
 * fails here rather than silently refusing the exhibit's SaaS read.
 */

import { AUTHORITY_SOURCES, DERIVATION_POLICY, GOVERNED_POLICIES, TOPOLOGY } from "@mission/demo-data";
import { SAAS_ENFORCED_CONSTRAINTS } from "@mission/mcp-saas";
import { describe, expect, it } from "vitest";

describe("shipped SaaS ceilings stay enforceable at the SaaS resource", () => {
  it("every shipped ceiling entry for the SaaS resource carries only constraints keys the SaaS resource enforces", () => {
    const ceilings = [
      ...DERIVATION_POLICY.ceiling,
      ...AUTHORITY_SOURCES.entries.flatMap((source) => source.ceiling),
      ...GOVERNED_POLICIES.flatMap((policy) => policy.ceiling),
    ].filter((entry) => entry.resource === TOPOLOGY.resources.saas);
    expect(ceilings.length).toBeGreaterThan(0);
    for (const entry of ceilings) {
      const keys = Object.keys(entry.constraints ?? {});
      expect(keys.filter((key) => !SAAS_ENFORCED_CONSTRAINTS.includes(key)), JSON.stringify(entry)).toEqual([]);
    }
  });
});
