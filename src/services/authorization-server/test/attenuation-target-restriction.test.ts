/**
 * @spec attenuation#root-mapping, resource-access#resource-matching (#1276,
 * D457): the attenuation root mapping preserves each entry's whole target
 * restriction, for every tool and every audience. The root carries no
 * resource member, so the restriction travels in each tool identifier, and
 * the consumer reads back an `exact` entry naming the same `resource`. A
 * restriction a tool identifier cannot carry leaves that tool out of the
 * mapped ceiling (#1756), and refuses the cross-organization mapping, rather
 * than minting a tool without it. Pure, in-memory, no network.
 */

import { credentialEntriesFromMissionAat, entryMatchesTarget } from "@mission/core";
import { describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  mapAuthorityToCeiling,
  mapAuthorityToTools,
  mapToolsToAuthority,
} from "../src/index.js";
import { TEST_OPERATIONS } from "./attenuation.helper.js";

const SERVICE = "https://r.example/mcp";
const INV1 = `${SERVICE}/invoices/inv-1`;
const INV2 = `${SERVICE}/invoices/inv-2`;

const entry = (resource: string, actions: string[], over: Record<string, unknown> = {}): AuthorityEntry =>
  ({ type: "mission_resource_access", resource, actions, ...over }) as AuthorityEntry;

describe("the attenuation root mapping preserves each entry's whole target restriction (@spec attenuation#root-mapping, #1276)", () => {
  it("every tool carries its entry's resource, so the reverse mapping and the consumer recover the same exact target for every action, whatever the audience", () => {
    const entries = [
      entry(SERVICE, ["res.list"]),
      entry(INV1, ["res.read", "res.pay"], { resource_match: "exact" }),
    ];
    const { tools, missionConstraints } = mapAuthorityToCeiling(entries, TEST_OPERATIONS);
    expect(Object.keys(tools).sort()).toEqual(
      [`${SERVICE}#res.list`, `${INV1}#res.pay`, `${INV1}#res.read`].sort(),
    );
    // The cross-organization wire maps the same tool identifiers.
    expect(Object.keys(mapAuthorityToTools(entries)).sort()).toEqual(Object.keys(tools).sort());
    // The issuer's own reverse mapping (the auditor's check) and the
    // consumer's reading name the same targets, one action each.
    const reversed = mapToolsToAuthority(mapAuthorityToTools(entries)).map((e) => [e.resource, e.actions]);
    const consumed = credentialEntriesFromMissionAat(tools, missionConstraints).map((e) => [
      e.resource,
      e.actions,
      e.resource_match,
    ]);
    expect(reversed).toEqual(
      expect.arrayContaining([
        [SERVICE, ["res.list"]],
        [INV1, ["res.read"]],
        [INV1, ["res.pay"]],
      ]),
    );
    expect(consumed).toEqual(
      expect.arrayContaining([
        [SERVICE, ["res.list"], undefined],
        [INV1, ["res.read"], undefined],
        [INV1, ["res.pay"], undefined],
      ]),
    );
    // The finer entry's tools cover only its own target: not a sibling, and
    // not the service identifier a root `aud` would name.
    for (const e of credentialEntriesFromMissionAat(tools, missionConstraints).filter((c) => c.resource === INV1)) {
      expect(entryMatchesTarget(e, INV1)).toBe(true);
      expect(entryMatchesTarget(e, INV2)).toBe(false);
      expect(entryMatchesTarget(e, SERVICE)).toBe(false);
    }
  });

  it("refuses an entry whose resource_match a tool identifier cannot carry, rather than mapping it as exact", () => {
    for (const resource_match of ["prefix", "glob", null]) {
      const entries = [entry(SERVICE, ["res.read"]), entry(`${SERVICE}/invoices`, ["res.read"], { resource_match })];
      // The ceiling leaves the entry's tool out; the exact entry still maps.
      expect(Object.keys(mapAuthorityToCeiling(entries, TEST_OPERATIONS).tools), String(resource_match)).toEqual([
        `${SERVICE}#res.read`,
      ]);
      expect(() => mapAuthorityToTools(entries), String(resource_match)).toThrow(
        /cannot be carried by a tool identifier/,
      );
    }
  });

  it("refuses an action whose tool identifier would read back as another target, rather than minting it", () => {
    expect(mapAuthorityToCeiling([entry(INV1, ["res.read#x"])], TEST_OPERATIONS).tools).toEqual({});
    expect(() => mapAuthorityToTools([entry(INV1, ["res.read#x"])])).toThrow(/does not carry that target/);
    // Control: the same entry with a plain action maps.
    expect(Object.keys(mapAuthorityToCeiling([entry(INV1, ["res.read"])], TEST_OPERATIONS).tools)).toEqual([
      `${INV1}#res.read`,
    ]);
    expect(Object.keys(mapAuthorityToTools([entry(INV1, ["res.read"])]))).toEqual([`${INV1}#res.read`]);
  });
});
