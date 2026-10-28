/**
 * @spec txn-authorization#resource-challenge, runtime#resource-contract (#249,
 * #1846): the Transaction Authorization Server's registry holds the Operation
 * Profile of every contract version a resource declares, under the version
 * each one's own document names, so a reference resolves to its own profile and
 * resolution, not a missing profile, decides a retired, out-of-retention or
 * uncovered one.
 */
import { CANONICAL_RESOURCE, RESOURCE_CONTRACTS } from "@mission/demo-data";
import { type JsonValue, ResourceContractDeclarations } from "@mission/core";
import { describe, expect, it } from "vitest";
import { contractOperationProfiles } from "../src/index.js";

const RESOURCE = CANONICAL_RESOURCE;
const NOW = new Date();
const [DECLARED] = RESOURCE_CONTRACTS.declarations;
const VERSIONS = DECLARED?.versions ?? [];
const refOf = (version: string) => {
  const v = VERSIONS.find((x) => x.version === version);
  return { id: DECLARED?.id, version, digest: v?.digest };
};
const entry = (action: string, version?: string): JsonValue =>
  ({
    type: "mission_resource_access",
    resource: RESOURCE,
    actions: [action],
    ...(version ? { resource_contract: refOf(version) } : {}),
  }) as JsonValue;

/** The shipped declarations with `version` restated as `state` (its document kept). */
function withState(version: string, state: "retired" | "superseded", retainedUntil?: string): ResourceContractDeclarations {
  return new ResourceContractDeclarations(
    RESOURCE_CONTRACTS.declarations.map((d) => ({
      resource: d.resource,
      ...(d.resource_match !== undefined ? { resource_match: d.resource_match } : {}),
      id: d.id,
      requires_reference: [...d.requires_reference],
      versions: d.versions.map((v) => {
        const restated = v.version === version;
        const nextState = restated ? state : v.state;
        const until = restated ? retainedUntil : v.retained_until;
        return {
          version: v.version,
          state: nextState,
          digest: v.digest,
          ...(nextState === "superseded" && until !== undefined ? { retained_until: until } : {}),
          ...(v.document !== undefined ? { document: v.document } : {}),
        };
      }),
    })),
  );
}

describe("the TAS registry holds every declared contract version's Operation Profile (@spec txn-authorization#resource-challenge, runtime#resource-contract, #249, #1846)", () => {
  it("resolves each declared version's reference to the profile its own document names, never the current one", () => {
    const registry = contractOperationProfiles(RESOURCE);
    expect(VERSIONS.length).toBeGreaterThan(1);
    for (const v of VERSIONS) {
      const admitted = registry.admit(RESOURCE, entry("payments:remittance.send", v.version), NOW);
      expect(admitted, v.version).toMatchObject({ ok: true, version: v.operation_profile });
    }
  });

  it("admits an unpinned entry under the current version's profile", () => {
    const current = VERSIONS.find((v) => v.state === "current");
    expect(contractOperationProfiles(RESOURCE).admit(RESOURCE, entry("payments:remittance.send"), NOW)).toMatchObject({
      ok: true,
      version: current?.operation_profile,
    });
  });

  it("refuses a retired version, and one outside its retention, by resolution rather than by a missing profile", () => {
    const older = VERSIONS.find((v) => v.state === "superseded");
    expect(older).toBeDefined();
    const retired = contractOperationProfiles(RESOURCE, withState(older?.version as string, "retired"));
    expect(retired.admit(RESOURCE, entry("payments:remittance.send", older?.version), NOW)).toEqual({
      ok: false,
      reason: "the resource_contract reference does not resolve (retired)",
    });
    const lapsed = contractOperationProfiles(RESOURCE, withState(older?.version as string, "superseded", "2000-01-01T00:00:00Z"));
    expect(lapsed.admit(RESOURCE, entry("payments:remittance.send", older?.version), NOW)).toEqual({
      ok: false,
      reason: "the resource_contract reference does not resolve (outside_retention)",
    });
  });

  it("refuses an operation the referenced version does not cover, though a later version does", () => {
    const lacking = VERSIONS.find((v) => v.state !== "retired" && !v.operations.includes("payments:payment.reverse"));
    expect(lacking, "a supported version without the reversal").toBeDefined();
    expect(contractOperationProfiles(RESOURCE).admit(RESOURCE, entry("payments:payment.reverse", lacking?.version), NOW)).toEqual({
      ok: false,
      reason: "the resource_contract reference does not resolve (operation_not_covered)",
    });
  });
});
