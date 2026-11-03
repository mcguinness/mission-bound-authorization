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
import { CONTROLLED_CLOCK_MS } from "./controlled-clock.helper.js";

const RESOURCE = CANONICAL_RESOURCE;
/** A controlled instant inside every declared version's retention (#1968, D1133), never the host's date. */
const NOW = new Date(CONTROLLED_CLOCK_MS);
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
    // A read: the shipped configuration requires a reference for the five non-read actions only (#249 C.3b).
    expect(contractOperationProfiles(RESOURCE).admit(RESOURCE, entry("payments:invoice.read"), NOW)).toMatchObject({
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

/** The five non-read payments actions the cutover requires a reference for (D865). */
const CUTOVER = [
  "payments:payment.schedule",
  "payments:payment.schedule.cancel",
  "payments:payment.execute",
  "payments:payment.reverse",
  "payments:remittance.send",
];

/** `base`'s declarations requiring a reference for `actions` (controlled configuration; the shipped one requires none). */
function requiring(actions: readonly string[], base: ResourceContractDeclarations = RESOURCE_CONTRACTS): ResourceContractDeclarations {
  return new ResourceContractDeclarations(
    base.declarations.map((d) => ({
      resource: d.resource,
      ...(d.resource_match !== undefined ? { resource_match: d.resource_match } : {}),
      id: d.id,
      requires_reference: [...actions],
      versions: d.versions.map((v) => ({
        version: v.version,
        state: v.state,
        digest: v.digest,
        ...(v.retained_until !== undefined ? { retained_until: v.retained_until } : {}),
        ...(v.document !== undefined ? { document: v.document } : {}),
      })),
    })),
  );
}

const MISSING = { ok: false, reason: "the resource requires a resource_contract reference for this operation", missingReference: true };
const CURRENT = VERSIONS.find((v) => v.state === "current");
/** The newest supported older version naming another Operation Profile than the current one (2026-10-27 names the live v16, #249, D1155). */
const OLDER = VERSIONS.find((v) => v.state === "superseded" && v.operation_profile !== CURRENT?.operation_profile);

describe("the TAS refuses a missing reference where the challenged operation requires one, at admission and at completion (@spec txn-authorization#resource-challenge, runtime#resource-contract, #249, D1071)", () => {
  it("refuses an unpinned entry for an operation the resource requires a reference for, and admits an unpinned read it does not", () => {
    const registry = contractOperationProfiles(RESOURCE, requiring(CUTOVER));
    for (const action of CUTOVER) expect(registry.admit(RESOURCE, entry(action), NOW), action).toEqual(MISSING);
    expect(registry.admit(RESOURCE, entry("payments:invoice.read"), NOW)).toMatchObject({ ok: true, version: CURRENT?.operation_profile });
  });

  it("admits a supported older reference under its own version's profile where the operation requires one, never the current one", () => {
    expect(OLDER?.operation_profile).not.toBe(CURRENT?.operation_profile);
    const admitted = contractOperationProfiles(RESOURCE, requiring(CUTOVER)).admit(
      RESOURCE,
      entry("payments:remittance.send", OLDER?.version),
      NOW,
    );
    expect(admitted).toMatchObject({ ok: true, version: OLDER?.operation_profile });
  });

  it("refuses at completion an unpinned workflow admitted before the requirement, which completes without it", () => {
    // The configuration before the cutover: the same declarations, requiring no reference.
    const before = contractOperationProfiles(RESOURCE, requiring([]));
    const admitted = before.admit(RESOURCE, entry("payments:remittance.send"), NOW);
    expect(admitted).toMatchObject({ ok: true, version: CURRENT?.operation_profile });
    const version = admitted.ok ? admitted.version : "";
    expect(before.complete(RESOURCE, version, entry("payments:remittance.send"), NOW)).toMatchObject({ ok: true });
    const after = contractOperationProfiles(RESOURCE, requiring(CUTOVER));
    expect(after.complete(RESOURCE, version, entry("payments:remittance.send"), NOW)).toEqual(MISSING);
  });

  it("refuses at completion a workflow admitted before versions were recorded where its operation now requires a reference", () => {
    const legacyOf = (contracts: ResourceContractDeclarations) =>
      contractOperationProfiles(RESOURCE, contracts).bindLegacyType(RESOURCE, "mission_resource_access", CURRENT?.operation_profile as string);
    expect(legacyOf(requiring([])).completeLegacy(RESOURCE, "mission_resource_access", entry("payments:remittance.send"))).toMatchObject({ ok: true });
    expect(legacyOf(requiring(CUTOVER)).completeLegacy(RESOURCE, "mission_resource_access", entry("payments:remittance.send"))).toEqual(MISSING);
  });

  it("refuses at completion a pinned workflow whose version was retired between admission and completion (controlled configuration: no retired version is shipped)", () => {
    const admitted = contractOperationProfiles(RESOURCE, requiring(CUTOVER)).admit(RESOURCE, entry("payments:remittance.send", OLDER?.version), NOW);
    expect(admitted).toMatchObject({ ok: true, version: OLDER?.operation_profile });
    const version = admitted.ok ? admitted.version : "";
    const retired = contractOperationProfiles(RESOURCE, requiring(CUTOVER, withState(OLDER?.version as string, "retired")));
    expect(retired.complete(RESOURCE, version, entry("payments:remittance.send", OLDER?.version), NOW)).toEqual({
      ok: false,
      reason: "the resource_contract reference does not resolve (retired)",
    });
  });
});
