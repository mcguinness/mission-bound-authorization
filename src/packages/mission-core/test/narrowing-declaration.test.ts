/**
 * @spec resource-access#qualified-narrowing, mission#transformation-capabilities
 * (#1377, D1025): a qualified `narrowing` declaration, a reader's fail-closed
 * resolution of it, domain applicability, and the subset relation under it.
 */
import { describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  carriedUnder,
  entriesEqual,
  entryWithinDomain,
  isSubsetEntryUnder,
  type JsonValue,
  NARROWING_IN_FULL,
  NARROWING_UNDECLARED,
  type NarrowingDeclaration,
  type NarrowingDomain,
  narrowingDomainDigest,
  narrowingDomainViolation,
  narrowingPermits,
  qualifiedNarrowingViolation,
  resolveNarrowing,
  unimplementedDomainClaim,
} from "../src/index.js";

const ID = "https://as.example/narrowing-domains/exact-only/1";
const EXACT_ONLY = {
  id: ID,
  type: "mission_resource_access",
  capability: "narrowing",
  resource_match: ["exact"],
  members: ["type", "resource", "resource_match", "actions", "constraints"],
  constraints: ["max_amount", "tenant"],
} as const;
const DIGEST = narrowingDomainDigest(EXACT_ONLY as unknown as JsonValue);
const qualified = (digest = DIGEST, id = ID) => ({ domain: { id, digest } });
const documents = (doc: unknown) => (id: string) => (id === ID ? doc : undefined);

const RES = "https://erp.example.com/invoices";
const entry = (extra: Partial<AuthorityEntry> = {}): AuthorityEntry =>
  ({
    type: "mission_resource_access",
    resource: RES,
    actions: ["invoices.read", "invoices.list"],
    ...extra,
  }) as AuthorityEntry;

function domainOf(resolved: ReturnType<typeof resolveNarrowing>): NarrowingDomain {
  const declaration = resolved?.declaration;
  if (declaration?.kind !== "domain")
    throw new Error(`expected a domain declaration, got ${JSON.stringify(resolved)}`);
  return declaration.domain;
}

describe("a reader resolves one carrier's narrowing member (@spec resource-access#qualified-narrowing, mission#transformation-capabilities)", () => {
  it("an absent member declares nothing, so the reader falls through; true and false keep their meanings", () => {
    expect(resolveNarrowing(undefined, documents(EXACT_ONLY))).toBeUndefined();
    expect(resolveNarrowing(true, documents(EXACT_ONLY))?.declaration).toEqual(NARROWING_IN_FULL);
    expect(resolveNarrowing(false, documents(EXACT_ONLY))?.declaration).toEqual(
      NARROWING_UNDECLARED,
    );
  });

  it("a qualified value naming a document of the given form, id and digest declares narrowing for that domain", () => {
    const resolved = resolveNarrowing(qualified(), documents(EXACT_ONLY));
    expect(resolved?.fault).toBeUndefined();
    expect(domainOf(resolved).resource_match).toEqual(["exact"]);
  });

  it("a qualified value the reader cannot validate declares narrowing false, never true and never undeclared", () => {
    const cases: [string, unknown, unknown][] = [
      ["an unknown member", { ...qualified(), scope: "all" }, EXACT_ONLY],
      ["a malformed digest", qualified("sha-256:short"), EXACT_ONLY],
      ["a relative id", qualified(DIGEST, "narrowing-domains/1"), EXACT_ONLY],
      [
        "an unavailable document",
        qualified(DIGEST, "https://as.example/narrowing-domains/other"),
        EXACT_ONLY,
      ],
      ["a mismatched digest", qualified(narrowingDomainDigest({ other: true })), EXACT_ONLY],
      [
        "a document naming another id",
        qualified(),
        { ...EXACT_ONLY, id: "https://as.example/narrowing-domains/2" },
      ],
      ["a document for another type", qualified(), { ...EXACT_ONLY, type: "payment_initiation" }],
      [
        "a document qualifying another capability",
        qualified(),
        { ...EXACT_ONLY, capability: "delegation" },
      ],
      [
        "a document carrying an unknown member",
        qualified(),
        { ...EXACT_ONLY, scope: ["derivation"] },
      ],
      ["a non-object value", "exact-only", EXACT_ONLY],
    ];
    for (const [name, value, doc] of cases) {
      const resolved = resolveNarrowing(value, documents(doc));
      expect(resolved, name).toBeDefined();
      expect(resolved?.declaration, name).toEqual(NARROWING_UNDECLARED);
      expect(resolved?.fault, name).toBeTruthy();
    }
  });
});

describe("the narrowing domain document's form (@spec resource-access#qualified-narrowing)", () => {
  it("admits the form Resource Access gives, and refuses a missing covered member, an unknown matching mode or limitation", () => {
    expect(narrowingDomainViolation(EXACT_ONLY)).toBeUndefined();
    expect(
      narrowingDomainViolation({ ...EXACT_ONLY, limitations: ["delegate-matcher-identity"] }),
    ).toBeUndefined();
    expect(narrowingDomainViolation({ ...EXACT_ONLY, members: ["type", "resource"] })).toMatch(
      /actions/,
    );
    expect(narrowingDomainViolation({ ...EXACT_ONLY, resource_match: ["exact", "glob"] })).toMatch(
      /matching modes/,
    );
    expect(narrowingDomainViolation({ ...EXACT_ONLY, resource_match: [] })).toMatch(/non-empty/);
    expect(narrowingDomainViolation({ ...EXACT_ONLY, limitations: ["loose-currency"] })).toMatch(
      /limitation/,
    );
    expect(qualifiedNarrowingViolation(qualified())).toBeUndefined();
  });

  it("refuses, as an implementation's own claim, a domain listing a constraints key or member it does not implement", () => {
    const resolved = resolveNarrowing(qualified(), documents(EXACT_ONLY));
    expect(unimplementedDomainClaim(domainOf(resolved))).toBeUndefined();
    const claiming = { ...EXACT_ONLY, constraints: ["max_amount", "x_region"] };
    const wider = resolveNarrowing(
      qualified(narrowingDomainDigest(claiming as unknown as JsonValue)),
      documents(claiming),
    );
    expect(unimplementedDomainClaim(domainOf(wider))).toMatch(/x_region/);
  });
});

describe("domain applicability and the subset relation under a declaration (@spec resource-access#qualified-narrowing)", () => {
  const domain = domainOf(resolveNarrowing(qualified(), documents(EXACT_ONLY)));
  const declared: NarrowingDeclaration = { kind: "domain", domain, digest: DIGEST };
  const reference = entry({ constraints: { max_amount: { amount: "500.00", currency: "USD" } } });
  const narrower = entry({
    actions: ["invoices.read"],
    constraints: { max_amount: { amount: "100.00", currency: "USD" } },
  });

  it("an entry is within the domain only when its matching mode, members, constraints keys and literal actions all are", () => {
    expect(entryWithinDomain(reference, domain)).toBe(true);
    expect(
      entryWithinDomain(entry({ resource_match: "exact" } as Partial<AuthorityEntry>), domain),
    ).toBe(true);
    expect(
      entryWithinDomain(entry({ resource_match: "prefix" } as Partial<AuthorityEntry>), domain),
    ).toBe(false);
    expect(
      entryWithinDomain(
        entry({ constraints: { vendors: ["acme"] } } as Partial<AuthorityEntry>),
        domain,
      ),
    ).toBe(false);
    expect(
      entryWithinDomain(entry({ delegation: { max_depth: 1 } } as Partial<AuthorityEntry>), domain),
    ).toBe(false);
    expect(entryWithinDomain(entry({ actions: ["invoices.*"] }), domain)).toBe(false);
  });

  it("within the domain the subset rule narrows; outside it, and undeclared, a subset is established only by equality", () => {
    expect(isSubsetEntryUnder(declared, narrower, reference)).toBe(true);
    expect(isSubsetEntryUnder(NARROWING_IN_FULL, narrower, reference)).toBe(true);
    expect(isSubsetEntryUnder(NARROWING_UNDECLARED, narrower, reference)).toBe(false);
    expect(isSubsetEntryUnder(NARROWING_UNDECLARED, entry({ ...reference }), reference)).toBe(true);
    const prefixRef = entry({ resource_match: "prefix" } as Partial<AuthorityEntry>);
    const prefixNarrower = entry({
      resource: `${RES}/2026`,
      resource_match: "prefix",
    } as Partial<AuthorityEntry>);
    expect(narrowingPermits(declared, prefixNarrower, prefixRef)).toBe(false);
    expect(isSubsetEntryUnder(declared, prefixNarrower, prefixRef)).toBe(false);
    expect(isSubsetEntryUnder(NARROWING_IN_FULL, prefixNarrower, prefixRef)).toBe(true);
    expect(isSubsetEntryUnder(declared, entry({ ...prefixRef }), prefixRef)).toBe(true);
  });

  it("equality is under the canonical form: an explicit exact match equals an absent one, any other difference does not", () => {
    expect(
      entriesEqual(entry({ resource_match: "exact" } as Partial<AuthorityEntry>), entry()),
    ).toBe(true);
    expect(entriesEqual(entry({ actions: ["invoices.list", "invoices.read"] }), entry())).toBe(
      false,
    );
  });

  it("a projection's modified entry is not carried without a declaration that permits narrowing it", () => {
    expect(
      carriedUnder(NARROWING_UNDECLARED, [narrower, entry({ ...reference })], [reference]),
    ).toEqual([reference]);
    expect(carriedUnder(declared, [narrower], [reference])).toEqual([narrower]);
  });
});
