import { describe, expect, it } from "vitest";
import {
  containmentAtEntries,
  containmentRemovalFor,
  containmentSelectorViolation,
  mergeContainmentSelectors,
  selectorOverlapsEntry,
} from "../src/index.js";

const SERVICE = "https://payments.example/mcp";
const INVOICES = `${SERVICE}/invoices`;
const INV1 = `${INVOICES}/inv-1`;
const INV2 = `${INVOICES}/inv-2`;

const exact = (resource: string) => ({ resource });
const prefix = (resource: string) => ({ resource, resource_match: "prefix" as const });

describe("selectorOverlapsEntry: resource-set overlap under Resource Access matching (@spec containment#selector-matching, #1463)", () => {
  it("a broad prefix selector applies to a finer entry, and a fine selector applies to a broader prefix entry", () => {
    expect(selectorOverlapsEntry(prefix(SERVICE), exact(INV1))).toBe(true);
    expect(selectorOverlapsEntry(prefix(SERVICE), prefix(INVOICES))).toBe(true);
    expect(selectorOverlapsEntry(exact(INV1), prefix(`${SERVICE}/`))).toBe(true);
    expect(selectorOverlapsEntry(prefix(INVOICES), prefix(SERVICE))).toBe(true);
  });

  it("an exact selector is never a subtree selector: an exact service root does not apply to a finer entry", () => {
    expect(selectorOverlapsEntry(exact(SERVICE), exact(INV1))).toBe(false);
    expect(selectorOverlapsEntry(exact(SERVICE), prefix(INVOICES))).toBe(false);
    expect(selectorOverlapsEntry(exact(SERVICE), exact(SERVICE))).toBe(true);
    expect(
      selectorOverlapsEntry({ ...exact(SERVICE), resource_match: "exact" }, exact(SERVICE)),
    ).toBe(true);
  });

  it("disjoint siblings and path-segment boundaries do not overlap", () => {
    expect(selectorOverlapsEntry(exact(INV1), exact(INV2))).toBe(false);
    expect(selectorOverlapsEntry(prefix(INVOICES), exact(`${SERVICE}/invoicesx/inv-1`))).toBe(
      false,
    );
    expect(selectorOverlapsEntry(prefix(`${INVOICES}/`), exact(INVOICES))).toBe(false);
    expect(selectorOverlapsEntry(prefix(INVOICES), prefix(`${SERVICE}/vendors`))).toBe(false);
    expect(selectorOverlapsEntry(prefix(SERVICE), exact("https://payments.example/mcpx"))).toBe(
      false,
    );
    expect(
      selectorOverlapsEntry(prefix(SERVICE), exact("https://other.example/mcp/invoices")),
    ).toBe(false);
  });

  it("exact matching is literal, while a prefix side normalizes before comparing", () => {
    expect(selectorOverlapsEntry(exact("https://PAYMENTS.example/mcp"), exact(SERVICE))).toBe(
      false,
    );
    expect(selectorOverlapsEntry(prefix("https://PAYMENTS.example:443/mcp"), exact(INV1))).toBe(
      true,
    );
  });

  it("a side the matcher cannot decide reads as overlapping, so a pairing never under-contains", () => {
    expect(selectorOverlapsEntry({ resource: SERVICE, resource_match: "glob" }, exact(INV1))).toBe(
      true,
    );
    expect(selectorOverlapsEntry(prefix(`${SERVICE}?tenant=a`), exact(INV1))).toBe(true);
    expect(selectorOverlapsEntry(exact(INV1), { resource: INV1, resource_match: "glob" })).toBe(
      true,
    );
  });
});

describe("containmentRemovalFor: the union over every overlapping selector (@spec containment#selector-matching, #1463)", () => {
  it("unions the actions of every overlapping selector, never only the first, and ignores a non-overlapping one", () => {
    const removal = containmentRemovalFor(prefix(INVOICES), [
      { ...exact(INV1), actions: ["send"] },
      { ...prefix(SERVICE), actions: ["execute"] },
      { ...exact(`${SERVICE}/vendors`), actions: ["read"] },
    ]);
    expect(removal).toEqual({ whole: false, actions: new Set(["send", "execute"]) });
  });

  it("removes the whole entry when any overlapping selector has no actions, and nothing when none overlaps", () => {
    expect(
      containmentRemovalFor(exact(INV1), [
        { ...prefix(INVOICES), actions: ["send"] },
        prefix(SERVICE),
      ]),
    ).toEqual({
      whole: true,
    });
    expect(
      containmentRemovalFor(exact(INV2), [{ ...exact(INV1), actions: ["send"] }]),
    ).toBeUndefined();
  });
});

describe("mergeContainmentSelectors and containmentAtEntries (@spec containment#contain-transition, #1463)", () => {
  it("merges only selectors naming the same resource under the same mode, never two modes of one resource string", () => {
    expect(
      mergeContainmentSelectors(
        [{ ...exact(SERVICE), actions: ["send"] }],
        [
          { ...prefix(SERVICE), actions: ["execute"] },
          { ...exact(SERVICE), resource_match: "exact", actions: ["read"] },
          { ...prefix(SERVICE) },
        ],
      ),
    ).toEqual([
      { resource: SERVICE, actions: ["send", "read"] },
      { resource: SERVICE, resource_match: "prefix" },
    ]);
  });

  it("resolves selectors onto the entries they apply to, each naming the entry's own resource and mode", () => {
    const entries = [
      prefix(`${SERVICE}/`),
      exact(`${SERVICE}/vendors/v-1`),
      exact("https://files.example/mcp"),
    ];
    expect(containmentAtEntries(entries, [{ ...exact(INV1), actions: ["send"] }])).toEqual([
      { resource: `${SERVICE}/`, resource_match: "prefix", actions: ["send"] },
    ]);
    expect(containmentAtEntries(entries, [prefix(SERVICE)])).toEqual([
      { resource: `${SERVICE}/`, resource_match: "prefix" },
      { resource: `${SERVICE}/vendors/v-1` },
    ]);
  });
});

describe("containmentSelectorViolation (@spec containment#selector-matching, #1463)", () => {
  it("admits an exact or declared prefix selector, with or without actions", () => {
    expect(containmentSelectorViolation(exact(SERVICE))).toBeUndefined();
    expect(containmentSelectorViolation({ ...prefix(SERVICE), actions: ["send"] })).toBeUndefined();
    expect(
      containmentSelectorViolation({ ...exact(SERVICE), resource_match: "exact" }),
    ).toBeUndefined();
  });

  it("refuses a selector the matcher cannot decide or that would contain nothing", () => {
    expect(containmentSelectorViolation({ resource: SERVICE, resource_match: "glob" })).toMatch(
      /not a value Resource Access defines/,
    );
    expect(containmentSelectorViolation(prefix(`${SERVICE}?tenant=a`))).toMatch(
      /carries a query component/,
    );
    expect(containmentSelectorViolation(prefix("urn:example:invoices"))).toMatch(
      /has no \/\/ authority/,
    );
    expect(containmentSelectorViolation({ resource: "not a uri" })).toMatch(/absolute URI/);
    expect(containmentSelectorViolation({ ...exact(SERVICE), actions: [] })).toMatch(
      /non-empty array of strings/,
    );
    expect(containmentSelectorViolation({ ...exact(SERVICE), resource_matc: "prefix" })).toMatch(
      /not a selector member/,
    );
    expect(containmentSelectorViolation([exact(SERVICE)])).toMatch(/JSON object/);
  });
});
