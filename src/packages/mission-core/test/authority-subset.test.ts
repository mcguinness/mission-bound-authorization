import { describe, expect, it } from "vitest";
import { entryWithinCeiling, isAuthorityEntry, isSubsetSet, isSubsetSetIgnoringCapabilitySources, narrowToCeiling, type AuthorityEntry } from "../src/index.js";

const entry: AuthorityEntry = { type: "mission_resource_access", resource: "https://resource.test", actions: ["read", "write"] };
const binding = { action: "read", tool_id: "read", source_uri: "https://catalog.test", source_digest: "sha-256:" + Buffer.alloc(32).toString("base64url"), operation_ref: "read" };

describe("shared authority ceiling (#762)", () => {
  it("keeps lineage strict while wire and config comparisons ignore issuer provenance", () => {
    const bound = { ...entry, capability_sources: [binding] };
    expect(isSubsetSet([entry], [bound])).toBe(false);
    expect(isSubsetSet([bound], [entry])).toBe(false);
    expect(isSubsetSetIgnoringCapabilitySources([entry], [bound])).toBe(true);
    expect(entryWithinCeiling(bound, [entry])).toBe(true);
    expect(narrowToCeiling([bound], [entry])[0]).toBe(bound);
  });

  it("keeps source assertions all-or-nothing while minting narrows per action", () => {
    const read = { ...entry, actions: ["read"] };
    const write = { ...entry, actions: ["write"] };
    expect(entryWithinCeiling(entry, [read, write])).toBe(false);
    expect(narrowToCeiling([entry], [read, write])).toEqual([entry]);
    expect(narrowToCeiling([entry], [read])).toEqual([read]);
  });

  it("never drops vendor, approval, or completion restrictions to meet a ceiling", () => {
    const constraints = { vendors: ["acme"], requires_action_approval: true, terminal_when: [{ event_type: "paid" }] };
    const ceiling = { ...entry, constraints };
    expect(narrowToCeiling([entry], [ceiling])).toEqual([]);
    const constrained = { ...entry, constraints };
    expect(narrowToCeiling([constrained], [ceiling])[0]).toBe(constrained);
    for (const changed of [{ ...constraints, vendors: ["other"] }, { ...constraints, requires_action_approval: false }, { ...constraints, terminal_when: [{ event_type: "different" }] }]) {
      expect(narrowToCeiling([{ ...entry, constraints: changed }], [ceiling])).toEqual([]);
    }
  });

  it("does not introduce delegation and preserves a narrower supported delegation", () => {
    const delegated = { ...entry, delegation: { max_depth: 1, allowed_delegates: [{ sub: "actor" }] } };
    expect(narrowToCeiling([delegated], [entry])).toEqual([]);
    expect(narrowToCeiling([entry], [delegated])).toEqual([entry]);
    expect(narrowToCeiling([delegated], [{ ...delegated, delegation: { ...delegated.delegation, max_depth: 2 } }])).toEqual([delegated]);
  });

  it("refuses unsupported or malformed restrictions on either operand", () => {
    const malformed = [
      { ...entry, constraints: { unknown: true } },
      { ...entry, constraints: { max_amount: { amount: "NaN", currency: "USD" } } },
      { ...entry, constraints: { max_amount: { amount: "1", currency: "USD", unknown: true } } },
      { ...entry, delegation: { max_depth: 1, allowed_delegates: [{ sub: "actor", sub_profile: 2 }] } },
      { ...entry, delegation: { max_depth: 1, children: { unknown: true } } },
      { ...entry, delegation: { max_depth: 1, children: { child_creation_policy: "opaque-policy" } } },
    ];
    for (const candidate of malformed) {
      expect(isAuthorityEntry(candidate)).toBe(false);
      expect(narrowToCeiling([candidate as AuthorityEntry], [entry])).toEqual([]);
      expect(narrowToCeiling([entry], [candidate as AuthorityEntry])).toEqual([]);
    }
  });
});
