import { describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  actionFamilyRefusal,
  delegateMatcherListViolation,
  entryWithinCeiling,
  isAuthorityEntry,
  isSubsetEntry,
  isSubsetSet,
  isSubsetSetIgnoringCapabilitySources,
  narrowToCeiling,
  resourceWithin,
  SUPPORTED_ENTRY_MEMBERS,
  unsupportedActionFamily,
  unsupportedEntryMember,
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

describe("a foreign entry carrying an unsupported member is unsupported (@spec mission#subset, #1399)", () => {
  // A restriction-shaped member no specification defines for this type:
  // dropped by a member-by-member rebuild, it would widen the entry.
  const carrying = { ...entry, invoice_ids: ["INV-7"] } as AuthorityEntry;

  it("SUPPORTED_ENTRY_MEMBERS is the type's own members, resource_contract included, and capability_sources", () => {
    expect([...SUPPORTED_ENTRY_MEMBERS].sort()).toEqual([
      "actions",
      "capability_sources",
      "constraints",
      "delegation",
      "resource",
      "resource_contract",
      "resource_match",
      "type",
    ]);
  });

  it("unsupportedEntryMember names a member outside the set by presence, whatever its value, and nothing for a supported entry", () => {
    for (const value of [["INV-7"], [], null, "", { id: "INV-7" }]) {
      expect(unsupportedEntryMember({ ...entry, invoice_ids: value })).toBe("invoice_ids");
    }
    expect(unsupportedEntryMember({ ...entry, locations: [] })).toBe("locations");
    expect(unsupportedEntryMember(entry)).toBeUndefined();
    expect(
      unsupportedEntryMember({
        ...entry,
        resource_match: "exact",
        capability_sources: [binding],
        delegation: { max_depth: 1 },
      }),
    ).toBeUndefined();
  });

  it("isAuthorityEntry refuses an entry carrying an unsupported member", () => {
    expect(isAuthorityEntry(carrying)).toBe(false);
  });

  it("isSubsetEntry refuses a comparison involving an unsupported member, except a byte-identical pair (the equal-entry clause)", () => {
    expect(isSubsetEntry(carrying, entry)).toBe(false);
    expect(isSubsetEntry(entry, carrying)).toBe(false);
    expect(isSubsetEntry({ ...carrying, actions: ["read"] }, carrying)).toBe(false);
    expect(isSubsetSet([entry], [carrying])).toBe(false);
    expect(isSubsetEntry(carrying, { ...carrying })).toBe(true);
    expect(isSubsetEntry(entry, entry)).toBe(true);
  });

  it("narrowToCeiling retains no entry carrying an unsupported member, on either operand", () => {
    expect(narrowToCeiling([carrying], [entry])).toEqual([]);
    expect(narrowToCeiling([{ ...carrying, actions: ["read"] }], [entry])).toEqual([]);
    expect(narrowToCeiling([entry], [carrying])).toEqual([]);
  });
});

describe("resource containment under resource_match (@spec resource-access#subset, #1276)", () => {
  const ORDERS = "https://api.example/orders";
  const at = (resource: string, resource_match?: "exact" | "prefix"): AuthorityEntry => ({
    type: "mission_resource_access",
    resource,
    ...(resource_match ? { resource_match } : {}),
    actions: ["orders.read"],
  });

  it("resourceWithin applies the four resource_match pairings with the resource servers' prefix comparison", () => {
    expect(resourceWithin(at(ORDERS), at(ORDERS, "exact"))).toBe(true);
    expect(resourceWithin(at(`${ORDERS}/1`), at(ORDERS, "prefix"))).toBe(true);
    expect(resourceWithin(at("https://API.EXAMPLE:443/orders/1"), at(ORDERS, "prefix"))).toBe(true);
    expect(resourceWithin(at(`${ORDERS}x/1`), at(ORDERS, "prefix"))).toBe(false);
    expect(resourceWithin(at(`${ORDERS}/2026`, "prefix"), at(ORDERS, "prefix"))).toBe(true);
    expect(resourceWithin(at(ORDERS, "prefix"), at(`${ORDERS}/`, "prefix"))).toBe(false);
    expect(resourceWithin(at(ORDERS, "prefix"), at(ORDERS))).toBe(false);
    expect(resourceWithin(at(ORDERS, "prefix"), at(`${ORDERS}/2026`, "prefix"))).toBe(false);
  });

  it("isSubsetEntry never lets a prefix candidate pass under an exact reference naming the same resource", () => {
    expect(isSubsetEntry(at(ORDERS, "prefix"), at(ORDERS))).toBe(false);
    expect(isSubsetEntry(at(`${ORDERS}/1`), at(ORDERS, "prefix"))).toBe(true);
    expect(narrowToCeiling([at(ORDERS, "prefix")], [at(ORDERS)])).toEqual([]);
    expect(narrowToCeiling([at(`${ORDERS}/1`)], [at(ORDERS, "prefix")])).toEqual([
      at(`${ORDERS}/1`),
    ]);
  });

  it("an unrecognized resource_match, or a prefix base the matcher cannot enforce, is never contained and is not a supported entry", () => {
    for (const odd of [
      { ...at(ORDERS), resource_match: "glob" },
      { ...at(ORDERS), resource_match: null },
      at(`${ORDERS}?tenant=a`, "prefix"),
      at("urn:example:orders", "prefix"),
    ] as AuthorityEntry[]) {
      expect(isAuthorityEntry(odd), JSON.stringify(odd)).toBe(false);
      expect(isSubsetEntry(odd, odd), JSON.stringify(odd)).toBe(false);
      expect(isSubsetEntry(at(ORDERS), odd), JSON.stringify(odd)).toBe(false);
    }
    expect(isAuthorityEntry(at(ORDERS, "prefix"))).toBe(true);
    expect(isAuthorityEntry(at(ORDERS, "exact"))).toBe(true);
  });
});

describe("an action family is unsupported input (@spec resource-access#subset, #1377, D538)", () => {
  // This implementation compares actions literally and implements none of the
  // subset rule's family clauses, so a family is refused, never carried.
  const family = { ...entry, actions: ["read", "invoices.*"] } as AuthorityEntry;

  it("unsupportedActionFamily names the first family an entry's actions carry, and nothing for identifiers", () => {
    expect(unsupportedActionFamily(family)).toBe("invoices.*");
    expect(unsupportedActionFamily({ ...entry, actions: ["invoices.q3.*", "invoices.*"] })).toBe(
      "invoices.q3.*",
    );
    expect(unsupportedActionFamily(entry)).toBeUndefined();
    expect(
      unsupportedActionFamily({ ...entry, actions: ["invoices.read", "invoices."] }),
    ).toBeUndefined();
    expect(actionFamilyRefusal("invoices.*")).toBe(
      "invoices.* is an action family, which this authorization server does not support; refusing it as unsupported input",
    );
  });

  it("isAuthorityEntry refuses an entry carrying an action family", () => {
    expect(isAuthorityEntry(family)).toBe(false);
    expect(isAuthorityEntry({ ...entry, actions: ["read"] })).toBe(true);
  });

  it("isSubsetEntry refuses a comparison involving an action family on either side, even a byte-identical pair", () => {
    expect(isSubsetEntry({ ...entry, actions: ["read"] }, family)).toBe(false);
    expect(isSubsetEntry(family, entry)).toBe(false);
    expect(isSubsetEntry(family, { ...family })).toBe(false);
    expect(isSubsetSet([{ ...entry, actions: ["read"] }], [family])).toBe(false);
    expect(isSubsetEntry({ ...entry, actions: ["read"] }, entry)).toBe(true);
  });

  it("narrowToCeiling retains no entry carrying an action family, on either operand", () => {
    expect(narrowToCeiling([family], [entry])).toEqual([]);
    expect(narrowToCeiling([{ ...entry, actions: ["read"] }], [family])).toEqual([]);
  });
});

// @spec resource-access#initial-common-constraints (#1595, D727): a malformed
// currency is refused, never folded, and a well-formed code compares exactly
// whether or not ISO 4217 assigns it.
describe("a max_amount currency is exactly three upper-case ASCII letters (#1595, D727)", () => {
  const capped = (currency: unknown, amount = "100.00") =>
    ({ ...entry, constraints: { max_amount: { amount, currency } } }) as AuthorityEntry;
  const malformed = ["usd", "Usd", "US", "USDX", "USD\n", " USD", "840", "ÜSD", "", 840];

  it("isAuthorityEntry refuses a malformed currency and admits an unassigned well-formed code", () => {
    for (const currency of malformed) {
      expect(isAuthorityEntry(capped(currency)), JSON.stringify(currency)).toBe(false);
    }
    expect(isAuthorityEntry(capped("USD"))).toBe(true);
    expect(isAuthorityEntry(capped("XYZ"))).toBe(true);
  });

  it("isSubsetEntry compares nothing with a malformed currency on either side, even a byte-identical pair", () => {
    for (const currency of malformed) {
      const label = JSON.stringify(currency);
      expect(isSubsetEntry(capped(currency), capped(currency, "500.00")), label).toBe(false);
      expect(isSubsetEntry(capped(currency), capped("USD", "500.00")), label).toBe(false);
      expect(isSubsetEntry(capped("USD"), capped(currency, "500.00")), label).toBe(false);
    }
  });

  it("isSubsetEntry compares well-formed codes exactly, with no case folding or conversion", () => {
    expect(isSubsetEntry(capped("XYZ"), capped("XYZ", "500.00"))).toBe(true);
    expect(isSubsetEntry(capped("XYZ"), capped("XYA", "500.00"))).toBe(false);
    expect(isSubsetEntry(capped("USD"), capped("EUR", "500.00"))).toBe(false);
  });
});
