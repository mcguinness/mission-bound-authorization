import { describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  delegateMatcherListViolation,
  entryWithinCeiling,
  isAuthorityEntry,
  isSubsetSet,
  isSubsetSetIgnoringCapabilitySources,
  narrowToCeiling,
} from "../src/index.js";

const entry: AuthorityEntry = {
  type: "mission_resource_access",
  resource: "https://resource.test",
  actions: ["read", "write"],
};
const binding = {
  action: "read",
  tool_id: "read",
  source_uri: "https://catalog.test",
  source_digest: `sha-256:${Buffer.alloc(32).toString("base64url")}`,
  operation_ref: "read",
};

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
    const constraints = {
      vendors: ["acme"],
      requires_action_approval: true,
      terminal_when: [{ event_type: "paid" }],
    };
    const ceiling = { ...entry, constraints };
    expect(narrowToCeiling([entry], [ceiling])).toEqual([]);
    const constrained = { ...entry, constraints };
    expect(narrowToCeiling([constrained], [ceiling])[0]).toBe(constrained);
    for (const changed of [
      { ...constraints, vendors: ["other"] },
      { ...constraints, requires_action_approval: false },
      { ...constraints, terminal_when: [{ event_type: "different" }] },
    ]) {
      expect(narrowToCeiling([{ ...entry, constraints: changed }], [ceiling])).toEqual([]);
    }
  });

  it("does not introduce delegation and preserves a narrower supported delegation", () => {
    const delegated = {
      ...entry,
      delegation: { max_depth: 1, allowed_delegates: [{ sub: "actor" }] },
    };
    expect(narrowToCeiling([delegated], [entry])).toEqual([]);
    expect(narrowToCeiling([entry], [delegated])).toEqual([entry]);
    expect(
      narrowToCeiling(
        [delegated],
        [{ ...delegated, delegation: { ...delegated.delegation, max_depth: 2 } }],
      ),
    ).toEqual([delegated]);
  });

  it("refuses unsupported or malformed restrictions on either operand", () => {
    const malformed = [
      { ...entry, constraints: { unknown: true } },
      { ...entry, constraints: { max_amount: { amount: "NaN", currency: "USD" } } },
      { ...entry, constraints: { max_amount: { amount: "1", currency: "USD", unknown: true } } },
      {
        ...entry,
        delegation: { max_depth: 1, allowed_delegates: [{ sub: "actor", sub_profile: 2 }] },
      },
      { ...entry, delegation: { max_depth: 1, children: { unknown: true } } },
    ];
    for (const candidate of malformed) {
      expect(isAuthorityEntry(candidate)).toBe(false);
      expect(narrowToCeiling([candidate as AuthorityEntry], [entry])).toEqual([]);
      expect(narrowToCeiling([entry], [candidate as AuthorityEntry])).toEqual([]);
    }
  });
});

describe("the shared delegate-matcher rule (@spec resource-access#matching-allowed-delegates, #1373)", () => {
  const MALFORMED: ReadonlyArray<readonly [unknown, string]> = [
    [{ sub_profile: "ai_agent", org: "A" }, "m entries carry no member 'org'"],
    [{}, "m entries must carry sub or sub_profile"],
    [{ sub: "" }, "m.sub must not be empty"],
    [{ sub_profile: "" }, "m.sub_profile must not be empty"],
    [{ sub: 7 }, "m.sub must be a string"],
    [{ sub: "actor", sub_profile: ["ai_agent"] }, "m.sub_profile must be a string"],
    [null, "m entries must be objects"],
  ];
  const VALID = [
    { sub: "actor" },
    { sub_profile: "ai_agent" },
    { sub: "actor", sub_profile: "ai_agent" },
    { sub_profile: "ai_agent client_instance" },
  ];
  const lists = (matchers: unknown[]) => [
    { ...entry, delegation: { max_depth: 1, allowed_delegates: matchers } },
    { ...entry, delegation: { max_depth: 1, children: { allowed_child_actors: matchers } } },
  ];

  it("names each malformed matcher, and isAuthorityEntry refuses it in either list", () => {
    for (const [matcher, violation] of MALFORMED) {
      expect(delegateMatcherListViolation([{ sub: "actor" }, matcher], "m")).toBe(violation);
      for (const candidate of lists([matcher])) {
        expect(isAuthorityEntry(candidate), violation).toBe(false);
      }
    }
    expect(delegateMatcherListViolation({ sub: "actor" }, "m")).toBe("m must be an array");
  });

  it("admits sub, sub_profile, both, and a multi-value sub_profile in either list", () => {
    expect(delegateMatcherListViolation(VALID, "m")).toBeUndefined();
    expect(delegateMatcherListViolation([], "m")).toBeUndefined();
    for (const candidate of lists(VALID)) expect(isAuthorityEntry(candidate)).toBe(true);
  });
});

describe("child_creation_policy in the lineage and ceiling comparison (#787)", () => {
  // @spec mission#standing-consent-bases — an activation policy reference.
  const POLICY = {
    id: "urn:policy:child-drawdown",
    version: "1",
    digest: `sha-256:${"A".repeat(43)}`,
  };
  const children = (extra: Record<string, unknown> = {}): AuthorityEntry => ({
    ...entry,
    delegation: {
      max_depth: 1,
      children: { max_children: 2, ...extra } as NonNullable<
        NonNullable<AuthorityEntry["delegation"]>["children"]
      >,
    },
  });
  const withPolicy = children({ child_creation_policy: POLICY });
  const withoutPolicy = children();

  it("admits the recorded reference as supported input and refuses a malformed one", () => {
    expect(isAuthorityEntry(withPolicy)).toBe(true);
    const malformed = [
      7,
      "",
      "urn:policy:child-drawdown:v1",
      null,
      {},
      ["p"],
      { id: POLICY.id, version: POLICY.version },
      { ...POLICY, digest: "sha-256:short" },
      { ...POLICY, id: "" },
      { ...POLICY, extra: "member" },
    ];
    for (const child_creation_policy of malformed) {
      expect(isAuthorityEntry(children({ child_creation_policy }))).toBe(false);
    }
  });

  it("absent on both sides compares on the other child members alone", () => {
    expect(isSubsetSet([withoutPolicy], [withoutPolicy])).toBe(true);
    expect(narrowToCeiling([withoutPolicy], [withoutPolicy])[0]).toBe(withoutPolicy);
  });

  it("carries an identical reference byte-for-byte", () => {
    expect(isSubsetSet([withPolicy], [withPolicy])).toBe(true);
    expect(narrowToCeiling([withPolicy], [withPolicy])[0]).toBe(withPolicy);
  });

  it("refuses a reference the grantor never recorded", () => {
    expect(isSubsetSet([withPolicy], [withoutPolicy])).toBe(false);
    expect(narrowToCeiling([withPolicy], [withoutPolicy])).toEqual([]);
  });

  it("refuses a changed reference", () => {
    for (const altered of [
      { ...POLICY, version: "2" },
      { ...POLICY, digest: `sha-256:${"B".repeat(43)}` },
      { ...POLICY, id: "urn:policy:other" },
    ]) {
      const changed = children({ child_creation_policy: altered });
      expect(isSubsetSet([changed], [withPolicy])).toBe(false);
      expect(narrowToCeiling([changed], [withPolicy])).toEqual([]);
    }
  });

  it("refuses dropping the reference while the children grant is retained", () => {
    expect(isSubsetSet([withoutPolicy], [withPolicy])).toBe(false);
    expect(narrowToCeiling([withoutPolicy], [withPolicy])).toEqual([]);
  });

  it("passes removal of the whole children grant as narrowing", () => {
    const noChildren: AuthorityEntry = { ...entry, delegation: { max_depth: 1 } };
    for (const narrower of [noChildren, entry]) {
      expect(isSubsetSet([narrower], [withPolicy])).toBe(true);
      expect(narrowToCeiling([narrower], [withPolicy])[0]).toBe(narrower);
    }
  });
});

describe("a foreign entry carrying locations is unsupported (@spec resource-access#entry-validation, #1278)", () => {
  // Decided by presence: the falsy values are refused exactly as a populated array.
  const VALUES: unknown[] = [
    ["https://resource.test"],
    [],
    null,
    "",
    { uri: "https://resource.test" },
  ];

  it("isAuthorityEntry refuses an entry carrying locations, whatever its value", () => {
    for (const locations of VALUES) {
      expect(isAuthorityEntry({ ...entry, locations })).toBe(false);
    }
  });

  it("narrowToCeiling retains no entry carrying locations, on either operand", () => {
    for (const locations of VALUES) {
      const carrying = { ...entry, locations } as AuthorityEntry;
      expect(narrowToCeiling([carrying], [entry])).toEqual([]);
      expect(narrowToCeiling([{ ...carrying, actions: ["read"] }], [entry])).toEqual([]);
      expect(narrowToCeiling([entry], [carrying])).toEqual([]);
    }
  });

  it("an entry without locations, or carrying capability_sources, stays supported", () => {
    const bound = { ...entry, capability_sources: [binding] };
    expect(isAuthorityEntry(entry)).toBe(true);
    expect(isAuthorityEntry(bound)).toBe(true);
    expect(narrowToCeiling([bound], [entry])[0]).toBe(bound);
  });
});
