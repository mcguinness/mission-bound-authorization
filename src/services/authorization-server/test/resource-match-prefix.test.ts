/**
 * @spec resource-access#subset, issuance-grant#effective-set-projection (#1276)
 *
 * A `prefix` entry through the authorization server's kernel: approved from
 * a `prefix` ceiling under the subset rule, and projected through the
 * Mission's effective set over the narrower resource set of each pairing, so
 * a `prefix` entry stays `prefix` and an `exact` descendant keeps its own
 * resource. The shipped ceilings are `exact`, so the ceiling here is
 * programmatic; prefix-ceiling-endpoint.test.ts loads a configured one (#1440).
 */

import { type CryptoKey, generateKeyPair } from "jose";
import { isSubsetSetIgnoringCapabilitySources } from "@mission/core";
import { beforeAll, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  MissionKernel,
  projectThroughEffective,
  validateMissionIntent,
} from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISSUER = "https://as.prefix.example";
const SERVICE = "https://erp.example.com";
const INVOICES = `${SERVICE}/invoices`;
const INV1 = `${INVOICES}/inv-1`;
const INV2 = `${INVOICES}/inv-2`;
const SIBLING = `${SERVICE}/invoices-archive/inv-1`;

const at = (resource: string, resource_match?: "exact" | "prefix"): AuthorityEntry => ({
  type: "mission_resource_access",
  resource,
  ...(resource_match ? { resource_match } : {}),
  actions: ["invoices.read"],
});

let statusKey: CryptoKey;
beforeAll(async () => {
  ({ privateKey: statusKey } = await generateKeyPair("ES256", { extractable: true }));
});

describe("a prefix Mission entry through approval and the effective-set projection (@spec resource-access#subset, issuance-grant#effective-set-projection, #1276)", () => {
  function approvedMission() {
    const ceiling = [at(INVOICES, "prefix")];
    const kernel = new MissionKernel({
      issuer: ISSUER,
      policy: { policy_version: "resource-match-prefix-1276", ceiling },
      authoritySourceCatalog: testAuthoritySourceCatalog(ceiling, ["agent"], ["bob"]),
      statusKey,
      statusKid: "prefix-status",
    });
    const mission = kernel.approve({
      intent: validateMissionIntent(
        JSON.stringify({ goal: "Read Q3 invoices", target_resources: [INVOICES, INV1], expires_at: "2099-01-01T00:00:00Z" }),
      ),
      proposedAuthority: [at(INVOICES, "prefix"), at(INV1)],
      subject: { iss: ISSUER, sub: "alice" },
      approver: { iss: ISSUER, sub: "bob" },
      clientId: "agent",
      approvalEventId: "apev-1276-prefix",
    });
    const record = kernel.get(mission.id);
    if (!record) throw new Error("no Mission");
    return { kernel, record };
  }

  it("approves a prefix proposal and an exact descendant under a prefix ceiling, each keeping its own resource and resource_match", () => {
    const { record } = approvedMission();
    expect(record.authority_set).toEqual([at(INVOICES, "prefix"), at(INV1)]);
  });

  it("projects over the narrower resource set: the prefix entry stays prefix, an exact descendant keeps its own resource, and a sibling outside the boundary projects to nothing", () => {
    const { kernel, record } = approvedMission();
    const effective = kernel.effectiveAuthoritySet(record);
    // The approved set through itself is unchanged: prefix is never rebuilt as exact.
    expect(projectThroughEffective(record.authority_set, effective)).toEqual([at(INVOICES, "prefix"), at(INV1)]);
    // A requested descendant the Mission never named passes the subset rule and keeps its own resource.
    expect(isSubsetSetIgnoringCapabilitySources([at(INV2)], effective)).toBe(true);
    expect(projectThroughEffective([at(INV2)], effective)).toEqual([at(INV2)]);
    // A sibling sharing the base's characters is outside every effective entry.
    expect(isSubsetSetIgnoringCapabilitySources([at(SIBLING)], effective)).toBe(false);
    expect(projectThroughEffective([at(SIBLING)], effective)).toEqual([]);
  });

  it("a prefix candidate through an exact effective entry naming its base narrows to that exact entry, and two disjoint resource sets yield no fragment", () => {
    expect(projectThroughEffective([at(INVOICES, "prefix")], [at(INVOICES)])).toEqual([at(INVOICES)]);
    expect(projectThroughEffective([at(INVOICES, "prefix")], [at(`${INVOICES}/2026`, "prefix")])).toEqual([
      at(`${INVOICES}/2026`, "prefix"),
    ]);
    expect(projectThroughEffective([at(`${SERVICE}/vendors`, "prefix")], [at(INVOICES, "prefix")])).toEqual([]);
    expect(projectThroughEffective([at(INVOICES)], [at(INV1)])).toEqual([]);
  });
});
