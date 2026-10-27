// Targeted tests of the general rules behind each check, beyond the current
// case list: decimal grammar and precision, currency grammar and exact
// comparison, instants, A-labels, URI syntax, unsupported-input refusal,
// constraint omission and resource_contract form, approval and preservation.

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  type ConsumerConfig,
  type ContractReference,
  type CurrentContract,
  compareDecimal,
  compareInstant,
  contractApprovalRefusal,
  contractDefinition,
  ENTRY_TYPE,
  entryValidationCheck,
  isCurrencyCode,
  isValidRecipientDomain,
  isWithinDomain,
  parseAbsoluteUri,
  parseCurrentContracts,
  parseDecimal,
  parseEntry,
  parseInstant,
  runCase,
  subsetCheck,
  type VectorCase,
} from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const subsetDir = resolve(here, "../../../../vectors/mission-resource-access-subset");
function contractFileOf(name: string): unknown {
  return JSON.parse(readFileSync(join(subsetDir, name), "utf8"));
}
// The two frozen versions of the payments contract; 2026-10-24 adds
// payments:payment.reverse.
const v20 = contractDefinition(contractFileOf("payments-contract-2026-10-20.json"));
const v24 = contractDefinition(contractFileOf("payments-contract-2026-10-24.json"));
const definitions = [v20, v24];

const RESOURCE = "https://payments.example/mcp";
const reference = v20.reference;
// The general configuration of these tests: 2026-10-20 is current for the
// payments resource and for no other.
const config: ConsumerConfig = {
  currentContracts: [{ resource: RESOURCE, reference }],
  definitions,
};
const base = {
  type: "mission_resource_access",
  resource: RESOURCE,
  actions: ["payments:invoice.read"],
};

function validate(entry: unknown): string {
  return entryValidationCheck(entry, config).outcome;
}

function decimal(text: string) {
  const d = parseDecimal(text);
  if (d === undefined) throw new Error(`not a decimal: ${text}`);
  return d;
}

function instant(text: string) {
  const i = parseInstant(text);
  if (i === undefined) throw new Error(`not an instant: ${text}`);
  return i;
}

function amount(a: string, currency = "USD") {
  return { ...base, constraints: { max_amount: { amount: a, currency } } };
}

describe("decimal values (resource-access#decimal-values)", () => {
  it("admits the grammar, up to 18 fractional digits", () => {
    for (const v of [
      "0",
      "500",
      "500.00",
      "00012.5",
      "1.123456789012345678",
      "123456789012345678901234567890",
    ]) {
      expect(parseDecimal(v), v).toBeDefined();
    }
  });

  it("rejects every other form", () => {
    const malformed = [
      "1.1234567890123456789",
      "1e3",
      "1E3",
      "-1",
      "+1",
      "1,000",
      "1_000",
      "NaN",
      "Infinity",
      " 1",
      "1 ",
      "1\n",
      "1.",
      ".5",
      "",
      "0x10",
      "١٢",
    ];
    for (const v of malformed) expect(parseDecimal(v), JSON.stringify(v)).toBeUndefined();
    expect(parseDecimal(500)).toBeUndefined();
  });

  it("compares exactly in value space", () => {
    expect(compareDecimal(decimal("500"), decimal("500.000000000000000000"))).toBe(0);
    expect(compareDecimal(decimal("0.300000000000000001"), decimal("0.3"))).toBe(1);
    expect(compareDecimal(decimal("9007199254740993"), decimal("9007199254740992"))).toBe(1);
    expect(compareDecimal(decimal("0.1"), decimal("0.10"))).toBe(0);
    expect(compareDecimal(decimal("099.99"), decimal("100"))).toBe(-1);
  });

  it("decides max_amount containment without floating-point rounding", () => {
    // Each pair is equal as IEEE 754 doubles but not as decimals.
    expect(subsetCheck(amount("9007199254740993"), amount("9007199254740992")).outcome).toBe(
      "not-subset",
    );
    expect(subsetCheck(amount("0.300000000000000001"), amount("0.3")).outcome).toBe("not-subset");
    expect(subsetCheck(amount("0.3"), amount("0.300000000000000001")).outcome).toBe("subset");
    expect(subsetCheck(amount("500"), amount("500.000000000000000000")).outcome).toBe("subset");
  });

  it("refuses a malformed amount at intake and in comparison", () => {
    for (const v of ["1e300", "-5", "NaN", "1.0000000000000000001"]) {
      expect(validate(amount(v)), v).toBe("refuse");
      expect(subsetCheck(amount(v), amount("1000")).outcome, v).toBe("refuse");
      expect(subsetCheck(amount("1"), amount(v)).outcome, v).toBe("refuse");
    }
  });

  it("never converts a value to a floating-point number in the source", () => {
    const srcDir = resolve(here, "../src");
    for (const file of readdirSync(srcDir)) {
      const text = readFileSync(join(srcDir, file), "utf8");
      for (const banned of ["parseFloat", "parseInt", "Number(", "Number.parse", "toFixed"]) {
        expect(text.includes(banned), `${file} uses ${banned}`).toBe(false);
      }
    }
  });
});

describe("max_amount currency (resource-access#initial-common-constraints, Currency; D727)", () => {
  const priced = (currency: unknown, a = "100.00") => ({
    ...base,
    constraints: { max_amount: { amount: a, currency } },
  });

  // Non-ASCII forms are built from code points so the source shows which.
  const cp = (...points: number[]) => String.fromCodePoint(...points);
  // MATHEMATICAL BOLD CAPITAL A and S: three UTF-16 code units, two characters.
  const astralThreeUnits = `${cp(0x1d400)}S`;

  // "exactly three characters, each an upper-case ASCII letter (A to Z)". "A
  // value of any other length, one ending in a line terminator included, or
  // carrying any other character is malformed."
  const malformed: Record<string, unknown> = {
    "lower case": "usd",
    "mixed case": "Usd",
    "two letters": "US",
    "four letters": "USDX",
    "the numeric code": "840",
    "a trailing line feed": "USD\n",
    "a trailing carriage return and line feed": "USD\r\n",
    "a trailing line separator (U+2028)": `USD${cp(0x2028)}`,
    "a leading space": " USD",
    "a trailing space": "USD ",
    "an inner space": "U D",
    "a non-ASCII letter (U+00DC)": `${cp(0xdc)}SD`,
    "a Cyrillic homoglyph of S (U+0405)": `U${cp(0x405)}D`,
    "full-width letters (U+FF35 U+FF33 U+FF24)": cp(0xff35, 0xff33, 0xff24),
    "a letter outside the Basic Multilingual Plane, three code units": astralThreeUnits,
    "a letter outside the Basic Multilingual Plane, four code units": `${cp(0x1d400)}SD`,
    "a NUL character": `US${cp(0)}`,
    "a digit": "US1",
    empty: "",
    "a JSON number": 840,
    null: null,
    "an array of letters": ["U", "S", "D"],
    "an object": { code: "USD" },
  };

  // "A well-formed value is admitted for comparison whether or not ISO 4217
  // assigns it."
  const wellFormed = ["USD", "EUR", "XYZ", "QQQ", "AAA", "ZZZ"];

  it("refuses each malformed form at proposal intake with invalid_authorization_details", () => {
    // The astral form has the right length in code units, so only the
    // character test refuses it.
    expect(astralThreeUnits.length).toBe(3);
    for (const [name, v] of Object.entries(malformed)) {
      expect(isCurrencyCode(v), name).toBe(false);
      const result = entryValidationCheck(priced(v), config);
      expect(result.outcome, name).toBe("refuse");
      expect(result.error, name).toBe("invalid_authorization_details");
    }
  });

  it("admits a well-formed code whether or not ISO 4217 assigns it", () => {
    for (const v of wellFormed) {
      expect(isCurrencyCode(v), v).toBe(true);
      expect(validate(priced(v)), v).toBe("valid");
      expect(subsetCheck(priced(v, "1"), priced(v, "2")).outcome, v).toBe("subset");
    }
  });

  it("refuses a comparison with a malformed currency in the candidate, the reference or both", () => {
    const valid = priced("USD", "500.00");
    for (const [name, v] of Object.entries(malformed)) {
      const candidate = subsetCheck(priced(v), valid);
      expect(candidate.outcome, `candidate: ${name}`).toBe("refuse");
      expect(candidate.reason, `candidate: ${name}`).toContain("candidate: invalid input");
      const reference = subsetCheck(priced("USD"), priced(v, "500.00"));
      expect(reference.outcome, `reference: ${name}`).toBe("refuse");
      expect(reference.reason, `reference: ${name}`).toContain("reference: invalid input");
      // Equal malformed values are not comparable either.
      expect(subsetCheck(priced(v), priced(v, "500.00")).outcome, `both: ${name}`).toBe("refuse");
    }
  });

  it("compares exactly, never trimming or folding a value into a match", () => {
    // A malformed value never compares equal to the well-formed one it
    // resembles, in either direction.
    for (const v of ["usd", "Usd", " USD", "USD ", "USD\n", "840"]) {
      expect(subsetCheck(priced(v), priced("USD", "500")).outcome, v).toBe("refuse");
      expect(subsetCheck(priced("USD"), priced(v, "500")).outcome, v).toBe("refuse");
    }
    // Well-formed values that differ in one character fail the relation in
    // both directions; no conversion is defined.
    expect(subsetCheck(priced("XYZ", "1"), priced("XYA", "500")).outcome).toBe("not-subset");
    expect(subsetCheck(priced("XYA", "1"), priced("XYZ", "500")).outcome).toBe("not-subset");
    expect(subsetCheck(priced("XYZ", "1"), priced("XYZ", "500")).outcome).toBe("subset");
    expect(subsetCheck(priced("XYZ", "500"), priced("XYZ", "1")).outcome).toBe("not-subset");
  });
});

describe("instants (resource-access#value-space-comparison)", () => {
  it("normalizes offsets and trailing subsecond zeros", () => {
    expect(
      compareInstant(instant("2026-07-01T02:00:00+02:00"), instant("2026-07-01T00:00:00Z")),
    ).toBe(0);
    expect(
      compareInstant(instant("2026-07-01T00:00:00.000Z"), instant("2026-07-01T00:00:00Z")),
    ).toBe(0);
    expect(
      compareInstant(instant("2026-06-30T19:00:00-05:00"), instant("2026-07-01T00:00:00Z")),
    ).toBe(0);
    expect(compareInstant(instant("2026-07-01t00:00:00z"), instant("2026-07-01T00:00:00Z"))).toBe(
      0,
    );
  });

  it("keeps precision beyond milliseconds", () => {
    expect(
      compareInstant(instant("2026-01-01T00:00:00.0000000001Z"), instant("2026-01-01T00:00:00Z")),
    ).toBe(1);
  });

  it("orders a leap second between 23:59:59 and the next day", () => {
    const leap = instant("2016-12-31T23:59:60Z");
    expect(compareInstant(leap, instant("2016-12-31T23:59:59.999Z"))).toBe(1);
    expect(compareInstant(leap, instant("2017-01-01T00:00:00Z"))).toBe(-1);
    expect(compareInstant(leap, instant("2016-12-31T15:59:60-08:00"))).toBe(0);
    expect(parseInstant("2016-12-31T12:00:60Z")).toBeUndefined();
  });

  it("rejects strings outside RFC 3339 and out-of-range fields", () => {
    const bad = [
      "2026-02-30T00:00:00Z",
      "2100-02-29T00:00:00Z",
      "2026-13-01T00:00:00Z",
      "2026-07-01 00:00:00Z",
      "2026-07-01T00:00:00",
      "2026-07-01T24:00:00Z",
      "2026-07-01T00:60:00Z",
      "2026-07-01T00:00:00+24:00",
      "2026-07-01T00:00:00+0200",
      "2026-07-01",
      "20260701T000000Z",
    ];
    for (const v of bad) expect(parseInstant(v), v).toBeUndefined();
    expect(parseInstant("2024-02-29T00:00:00Z")).toBeDefined();
    expect(parseInstant("2000-02-29T00:00:00Z")).toBeDefined();
  });
});

describe("recipient_domain (resource-access#entry-validation)", () => {
  it("admits ASCII DNS names with A-label internationalized labels, in any case", () => {
    for (const v of [
      "example.com",
      "Mail.XN--exmple-cua.com",
      "xn--exmple-cua.com",
      "localhost",
      "a-b.c0",
    ]) {
      expect(isValidRecipientDomain(v), v).toBe(true);
    }
  });

  it("refuses non-ASCII, trailing dots, malformed labels and fake A-labels", () => {
    const bad = [
      "exämple.com",
      "example.com.",
      "",
      ".com",
      "a..com",
      "-a.com",
      "a-.com",
      "a_b.com",
      `${"a".repeat(64)}.com`,
      "xn--.com",
      "xn--example-.com",
    ];
    for (const v of bad) expect(isValidRecipientDomain(v), v).toBe(false);
  });

  it("compares case-insensitively on whole labels", () => {
    expect(isWithinDomain("mail.example.com", "example.com")).toBe(true);
    expect(isWithinDomain("EXAMPLE.com", "example.COM")).toBe(true);
    expect(isWithinDomain("notexample.com", "example.com")).toBe(false);
    expect(isWithinDomain("example.com", "mail.example.com")).toBe(false);
  });
});

describe("resource syntax (resource-access#entry-validation)", () => {
  it("parses RFC 3986 absolute-URIs only", () => {
    const good = [
      "https://erp.example.com",
      "https://api.example/orders?id=1",
      "urn:example:a",
      "https://[::1]:8443/x",
      "https://[2001:db8::7]/x",
      "https://u@host/x",
      "mailto:",
    ];
    for (const v of good) expect(parseAbsoluteUri(v), v).toBeDefined();
    const bad = [
      "https://api.example/orders#x",
      "api.example/orders",
      "https://api.example/a b",
      "https://exämple.com",
      "1https://x",
      "https://[::1/x",
      "https://host:port/x",
      "https://api.example/%zz",
      "https://[1.2.3.4::]/x",
    ];
    for (const v of bad) expect(parseAbsoluteUri(v), v).toBeUndefined();
  });

  it("applies the http and https authority rule case-insensitively", () => {
    expect(validate({ ...base, resource: "https:///orders" })).toBe("refuse");
    expect(validate({ ...base, resource: "HTTPS:api.example/orders" })).toBe("refuse");
    expect(validate({ ...base, resource: "http://:80/x" })).toBe("refuse");
    expect(validate({ ...base, resource: "urn:example:orders" })).toBe("valid");
  });

  it("refuses an http or https resource carrying userinfo, the scheme compared case-insensitively", () => {
    // resource-access#entry-validation: refused when "its resource is an http
    // or https URI carrying a userinfo subcomponent (Section 4.2.4 of
    // RFC9110)". Any "@" in the authority delimits one, an empty one included.
    const refused = [
      "https://agent@api.example/orders",
      "https://agent:secret@api.example/orders",
      "https://@api.example/orders",
      "https://:@api.example/orders",
      "HTTP://agent@api.example/orders",
      "Https://agent@api.example",
      "http://agent@api.example:8080/orders?id=1",
      "https://a%40b@api.example/orders",
      "https://agent@[2001:db8::7]/orders",
    ];
    for (const resource of refused) {
      // Each is an RFC 3986 absolute-URI, so this rule alone refuses it.
      expect(parseAbsoluteUri(resource), resource).toBeDefined();
      const result = entryValidationCheck({ ...base, resource }, config);
      expect(result.outcome, resource).toBe("refuse");
      expect(result.error, resource).toBe("invalid_authorization_details");
      expect(result.reason, resource).toContain("userinfo");
    }

    // An "@" after the authority is path or query data, not userinfo, and
    // another scheme's userinfo is outside the rule.
    const admitted = [
      "https://api.example/orders/a@b",
      "https://api.example/@",
      "https://api.example/orders?by=a@b",
      "https://api.example?by=a@b",
      "ftp://user@host/x",
      "ftp://user:pw@host/x",
      "urn:example:a@b",
      "mailto:agent@api.example",
    ];
    for (const resource of admitted) {
      expect(validate({ ...base, resource }), resource).toBe("valid");
    }
  });

  it("applies the userinfo rule to an entry's resource only", () => {
    // A subset operand is an entry, so its resource is invalid input there.
    const withUserinfo = { ...base, resource: "https://agent@payments.example/mcp" };
    expect(subsetCheck(withUserinfo, withUserinfo).outcome).toBe("refuse");
    // resource_contract.id is "an absolute URI that names the contract"; the
    // userinfo rule names resource alone.
    const contracted = {
      ...base,
      resource_contract: { ...reference, id: "https://agent@payments.example/contracts/payments" },
    };
    expect(subsetCheck(contracted, contracted).outcome).toBe("subset");
  });
});

describe("unsupported input is refused, never dropped", () => {
  it("refuses input outside the subset at intake", () => {
    const outside = [
      { ...base, resource_match: "prefix" },
      { ...base, actions: ["payments:invoice.*"] },
      { ...base, actions: ["payments:invoice.read", "payments:payment.*"] },
      { ...base, delegation: { max_depth: 1 } },
      { ...base, capability_sources: [] },
      { ...base, x_member: true },
      { ...base, locations: [RESOURCE] },
      { ...base, constraints: { vendors: ["v1"] } },
      { ...base, constraints: { terminal_when: "done" } },
      { ...base, constraints: { tenant: "acme", x_region: "eu" } },
    ];
    for (const entry of outside) {
      const result = entryValidationCheck(entry, config);
      expect(result.outcome, JSON.stringify(entry)).toBe("refuse");
      expect(result.error).toBe("invalid_authorization_details");
    }
  });

  it("refuses a subset comparison on input outside the subset in either entry", () => {
    const plain = { ...base };
    expect(subsetCheck({ ...base, resource_match: "prefix" }, plain).outcome).toBe("refuse");
    expect(subsetCheck(plain, { ...base, resource_match: "prefix" }).outcome).toBe("refuse");
    expect(subsetCheck(plain, { ...base, actions: ["payments:invoice.*"] }).outcome).toBe("refuse");
    expect(subsetCheck({ ...base, constraints: { x_unknown: true } }, plain).outcome).toBe(
      "refuse",
    );
    expect(subsetCheck(plain, { ...base, constraints: { vendors: ["v"] } }).outcome).toBe("refuse");
  });

  it("checks type and resource_match values", () => {
    expect(validate({ ...base, resource_match: "exact" })).toBe("valid");
    expect(validate({ ...base, resource_match: "EXACT" })).toBe("refuse");
    expect(validate({ resource: RESOURCE, actions: ["a"] })).toBe("refuse");
    expect(validate({ ...base, type: "other_type" })).toBe("refuse");
  });

  it("refuses an entry whose type is absent, not a string or another type at intake", () => {
    // resource-access#resource-access-type type: "REQUIRED. A string.
    // mission_resource_access."
    const { type: _type, ...untyped } = base;
    const entries: unknown[] = [
      untyped,
      ...[42, null, true, [ENTRY_TYPE], { name: ENTRY_TYPE }].map((type) => ({ ...base, type })),
      ...["other_type", "Mission_Resource_Access", ""].map((type) => ({ ...base, type })),
    ];
    for (const entry of entries) {
      const result = entryValidationCheck(entry, config);
      expect(result.outcome, JSON.stringify(entry)).toBe("refuse");
      expect(result.error, JSON.stringify(entry)).toBe("invalid_authorization_details");
      expect(result.reason, JSON.stringify(entry)).toMatch(/^type /);
    }
    expect(validate({ ...base, type: ENTRY_TYPE })).toBe("valid");
  });
});

describe("the subset check's three outcomes (vectors README, Checks, subset; D727)", () => {
  interface Entry extends Record<string, unknown> {
    readonly resource: string;
    readonly actions: readonly string[];
    readonly constraints?: Record<string, unknown>;
  }
  const plain: Entry = { ...base };
  const withConstraints = (e: Entry, added: Record<string, unknown>): Entry => ({
    ...e,
    constraints: { ...(e.constraints ?? {}), ...added },
  });

  // Input outside the subset: valid under the draft, unsupported here.
  const unsupported: Record<string, (e: Entry) => Entry> = {
    "prefix resource_match": (e) => ({ ...e, resource_match: "prefix" }),
    "action family": (e) => ({ ...e, actions: [...e.actions, "payments:invoice.*"] }),
    "unknown member": (e) => ({ ...e, x_member: ["v"] }),
    "delegation member": (e) => ({ ...e, delegation: { max_depth: 1 } }),
    "unknown constraints key": (e) => withConstraints(e, { x_unknown: "v" }),
    "deployment-defined key": (e) => withConstraints(e, { vendors: ["v1"] }),
    "Discharge key": (e) => withConstraints(e, { terminal_when: "done" }),
  };
  // An operand that is not a mission_resource_access entry: "one whose type
  // is absent or names another type is malformed input" (vectors README,
  // Checks, subset); type is "REQUIRED. A string. mission_resource_access."
  // (resource-access#resource-access-type).
  const badType: Record<string, (e: Entry) => Entry> = {
    "absent type": ({ type: _type, ...rest }) => rest,
    "numeric type": (e) => ({ ...e, type: 42 }),
    "null type": (e) => ({ ...e, type: null }),
    "boolean type": (e) => ({ ...e, type: true }),
    "array type": (e) => ({ ...e, type: [ENTRY_TYPE] }),
    "object type": (e) => ({ ...e, type: { name: ENTRY_TYPE } }),
    "another type": (e) => ({ ...e, type: "other_type" }),
    "case-variant type": (e) => ({ ...e, type: "Mission_Resource_Access" }),
    "empty type": (e) => ({ ...e, type: "" }),
  };
  // Input the draft makes invalid, which no comparison may parse.
  const invalid: Record<string, (e: Entry) => Entry> = {
    ...badType,
    "malformed amount": (e) =>
      withConstraints(e, { max_amount: { amount: "1,000.00", currency: "USD" } }),
    "malformed currency": (e) =>
      withConstraints(e, { max_amount: { amount: "1.00", currency: "usd" } }),
    "currency with a trailing line feed": (e) =>
      withConstraints(e, { max_amount: { amount: "1.00", currency: "USD\n" } }),
    "inverted window": (e) =>
      withConstraints(e, {
        time_window: { not_before: "2026-06-01T00:00:00Z", not_after: "2026-01-01T00:00:00Z" },
      }),
    locations: (e) => ({ ...e, locations: [e.resource] }),
    "malformed resource_contract": (e) => ({
      ...e,
      resource_contract: { ...reference, digest: "sha-256:short" },
    }),
    "empty actions": (e) => ({ ...e, actions: [] }),
  };
  const uncomparable = { ...unsupported, ...invalid };

  it("refuses unsupported input in the candidate alone, the reference alone, or both", () => {
    for (const [name, taint] of Object.entries(unsupported)) {
      expect(subsetCheck(taint(plain), plain).outcome, `candidate: ${name}`).toBe("refuse");
      expect(subsetCheck(plain, taint(plain)).outcome, `reference: ${name}`).toBe("refuse");
      expect(subsetCheck(taint(plain), taint(plain)).outcome, `both: ${name}`).toBe("refuse");
    }
    for (const [a, taintA] of Object.entries(unsupported)) {
      for (const [b, taintB] of Object.entries(unsupported)) {
        expect(subsetCheck(taintA(plain), taintB(plain)).outcome, `${a} under ${b}`).toBe("refuse");
      }
    }
  });

  it("refuses invalid input in either operand or both", () => {
    for (const [name, taint] of Object.entries(invalid)) {
      expect(subsetCheck(taint(plain), plain).outcome, `candidate: ${name}`).toBe("refuse");
      expect(subsetCheck(plain, taint(plain)).outcome, `reference: ${name}`).toBe("refuse");
      expect(subsetCheck(taint(plain), taint(plain)).outcome, `both: ${name}`).toBe("refuse");
    }
    expect(subsetCheck("not an entry", plain).outcome).toBe("refuse");
    expect(subsetCheck(plain, null).outcome).toBe("refuse");
  });

  // Valid pairs that fail the relation, most without the candidate being
  // broader than the reference.
  const usd = (a: string) => ({ max_amount: { amount: a, currency: "USD" } });
  const eur = (a: string) => ({ max_amount: { amount: a, currency: "EUR" } });
  const mismatches: Record<string, readonly [Entry, Entry]> = {
    "different resources": [{ ...base, resource: "https://other.example/mcp" }, plain],
    "disjoint actions": [{ ...base, actions: ["payments:payment.execute"] }, plain],
    "different currencies": [withConstraints(plain, eur("1")), withConstraints(plain, usd("100"))],
    "a reference key the candidate omits": [plain, withConstraints(plain, { tenant: "acme" })],
    "a removed resource_contract": [plain, { ...base, resource_contract: { ...reference } }],
  };

  it("answers not-subset for valid, supported inputs that fail the relation", () => {
    for (const [name, [a, b]] of Object.entries(mismatches)) {
      expect(subsetCheck(a, b).outcome, name).toBe("not-subset");
    }
    // Disjoint actions and different currencies fail in both directions:
    // neither operand is a superset of the other.
    const read = plain;
    const execute: Entry = { ...base, actions: ["payments:payment.execute"] };
    expect(subsetCheck(read, execute).outcome).toBe("not-subset");
    expect(subsetCheck(execute, read).outcome).toBe("not-subset");
    const inUsd = withConstraints(plain, usd("100"));
    const inEur = withConstraints(plain, eur("100"));
    expect(subsetCheck(inUsd, inEur).outcome).toBe("not-subset");
    expect(subsetCheck(inEur, inUsd).outcome).toBe("not-subset");
  });

  it("never lets an obvious mismatch conceal input it cannot compare in either operand", () => {
    for (const [mismatch, [a, b]] of Object.entries(mismatches)) {
      for (const [name, taint] of Object.entries(uncomparable)) {
        expect(subsetCheck(taint(a), b).outcome, `${mismatch}, candidate: ${name}`).toBe("refuse");
        expect(subsetCheck(a, taint(b)).outcome, `${mismatch}, reference: ${name}`).toBe("refuse");
        expect(subsetCheck(taint(a), taint(b)).outcome, `${mismatch}, both: ${name}`).toBe(
          "refuse",
        );
      }
    }
  });

  it("refuses an operand whose type is absent, not a string or another type", () => {
    const rich = withConstraints(
      { ...plain, resource_contract: { ...reference } },
      { ...usd("100"), tenant: "acme" },
    );
    expect(subsetCheck(rich, rich).outcome).toBe("subset");
    for (const [name, taint] of Object.entries(badType)) {
      for (const e of [plain, rich]) {
        const candidate = subsetCheck(taint(e), e);
        expect(candidate.outcome, `candidate: ${name}`).toBe("refuse");
        expect(candidate.reason, `candidate: ${name}`).toMatch(
          /^not comparable: candidate: invalid input: type /,
        );
        const ref = subsetCheck(e, taint(e));
        expect(ref.outcome, `reference: ${name}`).toBe("refuse");
        expect(ref.reason, `reference: ${name}`).toMatch(
          /^not comparable: reference: invalid input: type /,
        );

        // Byte-identical operands are not certified as a subset.
        const [a, b] = [taint(e), taint(e)];
        expect(JSON.stringify(a), `both: ${name}`).toBe(JSON.stringify(b));
        const both = subsetCheck(a, b);
        expect(both.outcome, `both: ${name}`).toBe("refuse");
        expect(both.reason, `both: ${name}`).toMatch(
          /candidate: invalid input: type .*; reference: invalid input: type /,
        );
      }
      // An obvious mismatch never conceals the operand's type.
      for (const [mismatch, [a, b]] of Object.entries(mismatches)) {
        expect(subsetCheck(a, b).outcome, mismatch).toBe("not-subset");
        expect(subsetCheck(taint(a), b).outcome, `${mismatch}, candidate: ${name}`).toBe("refuse");
        expect(subsetCheck(a, taint(b)).outcome, `${mismatch}, reference: ${name}`).toBe("refuse");
        expect(subsetCheck(taint(a), taint(b)).outcome, `${mismatch}, both: ${name}`).toBe(
          "refuse",
        );
      }
    }
  });

  it("names every operand it cannot compare and carries no error", () => {
    const result = subsetCheck(
      { ...base, resource: "https://other.example/mcp", x_member: true },
      withConstraints(plain, { max_amount: { amount: "1e3", currency: "USD" } }),
    );
    expect(result.outcome).toBe("refuse");
    expect(result.reason).toContain("candidate: unsupported input");
    expect(result.reason).toContain("reference: invalid input");
    expect("error" in result).toBe(false);
    expect("error" in subsetCheck(plain, plain)).toBe(false);
  });
});

describe("constraint omission (resource-access#subset step 3)", () => {
  it("lets only an omission-equivalent reference value be omitted", () => {
    const omitted = { ...base };
    const rar = (v: boolean) => ({ ...base, constraints: { requires_action_approval: v } });
    expect(subsetCheck(omitted, rar(false)).outcome).toBe("subset");
    expect(subsetCheck(omitted, rar(true)).outcome).toBe("not-subset");
    expect(subsetCheck(rar(false), omitted).outcome).toBe("subset");
    for (const constraints of [
      { tenant: "acme" },
      { allowed_tools: [] },
      { data_classification: ["public"] },
      { time_window: { not_after: "2026-12-31T00:00:00Z" } },
      { max_amount: { amount: "0", currency: "USD" } },
    ]) {
      expect(
        subsetCheck(omitted, { ...base, constraints }).outcome,
        JSON.stringify(constraints),
      ).toBe("not-subset");
      expect(
        subsetCheck({ ...base, constraints }, omitted).outcome,
        JSON.stringify(constraints),
      ).toBe("subset");
    }
  });
});

describe("resource_contract (resource-access#resource-contract)", () => {
  const withContract = (rc: unknown, actions = base.actions) => ({
    ...base,
    actions,
    resource_contract: rc,
  });

  it("admits the configured current reference for actions the contract defines", () => {
    expect(validate(withContract({ ...reference }))).toBe("valid");
    expect(
      validate(
        withContract({ ...reference }, ["payments:invoice.list", "payments:payment.execute"]),
      ),
    ).toBe("valid");
  });

  it("refuses a substituted reference or an action the contract does not define", () => {
    expect(validate(withContract({ ...reference, version: "2026-10-01" }))).toBe("refuse");
    expect(
      validate(withContract({ ...reference, id: "https://payments.example/contracts/other" })),
    ).toBe("refuse");
    const otherDigest = `sha-256:${"A".repeat(43)}`;
    expect(validate(withContract({ ...reference, digest: otherDigest }))).toBe("refuse");
    expect(validate(withContract({ ...reference }, ["invoices.read"]))).toBe("refuse");
  });

  it("refuses a reference without exactly its three members in their forms", () => {
    const { digest, ...noDigest } = reference;
    const forms = [
      noDigest,
      { ...reference, extra: "x" },
      { ...reference, version: "" },
      { ...reference, id: "not a uri" },
      { ...reference, digest: `${digest}=` },
      { ...reference, digest: digest.replace("sha-256:", "SHA-256:") },
      { ...reference, digest: `${digest}A` },
      { ...reference, digest: `${digest.slice(0, -1)}R` },
      "https://payments.example/contracts/payments",
    ];
    for (const rc of forms) {
      expect(validate(withContract(rc)), JSON.stringify(rc)).toBe("refuse");
      // The subset comparison applies no approval rule, so a refusal here
      // isolates the form check: a malformed reference is not comparable.
      const e = withContract(rc);
      expect(subsetCheck(e, e).outcome, JSON.stringify(rc)).toBe("refuse");
      expect(subsetCheck(withContract({ ...reference }), e).outcome, JSON.stringify(rc)).toBe(
        "refuse",
      );
    }
    // A well-formed reference that is not configured as current is still
    // comparable.
    const wellFormed = withContract({ ...reference, digest: `sha-256:${"A".repeat(43)}` });
    expect(subsetCheck(wellFormed, wellFormed).outcome).toBe("subset");
  });

  it("is preserved exactly by the subset rule, step 4", () => {
    const a = withContract({ ...reference });
    expect(subsetCheck(a, withContract({ ...reference })).outcome).toBe("subset");
    expect(subsetCheck(base, withContract({ ...reference })).outcome).toBe("not-subset");
    expect(subsetCheck(a, base).outcome).toBe("not-subset");
    expect(subsetCheck(a, withContract({ ...reference, version: "2026-10-01" })).outcome).toBe(
      "not-subset",
    );
    const otherDigest = `sha-256:${"A".repeat(43)}`;
    expect(subsetCheck(withContract({ ...reference, digest: otherDigest }), a).outcome).toBe(
      "not-subset",
    );
  });

  it("does not apply the approval rule in a subset comparison", () => {
    // An older version, approved earlier, is preserved under derivation even
    // when it is not the version current at intake.
    const old = withContract({ ...reference, version: "2026-10-01" });
    expect(subsetCheck(old, old).outcome).toBe("subset");
  });
});

describe("resource_contract currency per resource (resource-access#resource-contract Approval; #249)", () => {
  // The Approval rule refuses "a proposed entry whose resource_contract does
  // not equal, member for member, the reference of a contract its
  // configuration names as current for the entry's resource and that defines
  // every action and action family the entry lists".
  const OTHER = "https://ledger.example/mcp";
  const entryWith = (rc: ContractReference, resource = RESOURCE, actions = base.actions) => ({
    ...base,
    resource,
    actions,
    resource_contract: { ...rc },
  });
  const configured = (...currentContracts: CurrentContract[]): ConsumerConfig => ({
    currentContracts,
    definitions,
  });
  const outcome = (entry: unknown, cfg: ConsumerConfig) => entryValidationCheck(entry, cfg).outcome;
  const current24 = configured({ resource: RESOURCE, reference: v24.reference });

  function parsedEntry(value: unknown) {
    const result = parseEntry(value);
    if (!result.ok) throw new Error(result.reason);
    return result.entry;
  }

  it("reads each frozen contract file into the actions its operations name", () => {
    expect([...v20.actions].sort()).toEqual([
      "payments:invoice.list",
      "payments:invoice.read",
      "payments:payment.execute",
      "payments:payment.schedule",
      "payments:payment.schedule.cancel",
      "payments:remittance.send",
      "payments:vendor.read",
    ]);
    expect([...v24.actions].sort()).toEqual([...v20.actions, "payments:payment.reverse"].sort());
    expect(() => contractDefinition({ format: "mission-resource-access-subset/1" })).toThrow();
    const file = contractFileOf("payments-contract-2026-10-24.json") as Record<string, unknown>;
    expect(() => contractDefinition({ ...file, reference: v20.reference })).toThrow();
  });

  it("admits the reference configuration names as current for the entry's resource", () => {
    const result = entryValidationCheck(entryWith(v24.reference), current24);
    expect(result.outcome).toBe("valid");
    expect(result.error).toBeUndefined();
  });

  it("refuses that reference on a resource configuration names no contract current for", () => {
    const result = entryValidationCheck(entryWith(v24.reference, OTHER), current24);
    expect(result.outcome).toBe("refuse");
    expect(result.error).toBe("invalid_authorization_details");
    // Control: configured as current for that resource too, it is admitted
    // there.
    const both = configured(
      { resource: RESOURCE, reference: v24.reference },
      { resource: OTHER, reference: v24.reference },
    );
    expect(outcome(entryWith(v24.reference, OTHER), both)).toBe("valid");
  });

  it("compares the configured resource character for character", () => {
    const variants = [
      "https://payments.example/mcp/",
      "https://PAYMENTS.example/mcp",
      "HTTPS://payments.example/mcp",
      "https://payments.example:443/mcp",
      "https://payments.example/mcp?x=1",
      "https://payments.example/%6Dcp",
    ];
    for (const resource of variants) {
      expect(outcome(entryWith(v24.reference, resource), current24), resource).toBe("refuse");
      // Control: each variant passes intake, so the contract rule alone
      // refuses it.
      expect(outcome({ ...base, resource }, current24), resource).toBe("valid");
    }
    expect(outcome(entryWith(v24.reference, RESOURCE), current24)).toBe("valid");
  });

  it("refuses a held version configuration does not name as current", () => {
    expect(outcome(entryWith(v20.reference), current24)).toBe("refuse");
    // Control: with 2026-10-20 named current, the same entry is admitted.
    const current20 = configured({ resource: RESOURCE, reference: v20.reference });
    expect(outcome(entryWith(v20.reference), current20)).toBe("valid");
    expect(outcome(entryWith(v24.reference), current20)).toBe("refuse");
  });

  it("requires id, version and digest each to equal the configured reference", () => {
    const r = v24.reference;
    const changed = [
      { ...r, id: "https://payments.example/contracts/payments2" },
      { ...r, version: "2026-10-25" },
      { ...r, digest: v20.reference.digest },
      { ...r, version: v20.reference.version },
    ];
    for (const rc of changed) {
      expect(outcome(entryWith(rc), current24), JSON.stringify(rc)).toBe("refuse");
    }
  });

  it("keeps each resource's current version to that resource", () => {
    const split = configured(
      { resource: RESOURCE, reference: v24.reference },
      { resource: OTHER, reference: v20.reference },
    );
    expect(outcome(entryWith(v24.reference, RESOURCE), split)).toBe("valid");
    expect(outcome(entryWith(v20.reference, OTHER), split)).toBe("valid");
    expect(outcome(entryWith(v20.reference, RESOURCE), split)).toBe("refuse");
    expect(outcome(entryWith(v24.reference, OTHER), split)).toBe("refuse");
  });

  it("names no contract current when configuration lists none", () => {
    const none = configured();
    expect(outcome(entryWith(v24.reference), none)).toBe("refuse");
    expect(outcome(entryWith(v20.reference), none)).toBe("refuse");
    expect(outcome(base, none)).toBe("valid");
  });

  it("leaves an entry without resource_contract unaffected, on any resource", () => {
    for (const cfg of [configured(), current24, config]) {
      expect(outcome(base, cfg)).toBe("valid");
      expect(outcome({ ...base, resource: OTHER }, cfg)).toBe("valid");
    }
    expect(contractApprovalRefusal(parsedEntry(base), configured())).toBeUndefined();
  });

  it("requires the current version to define every action the entry lists", () => {
    // payments:payment.reverse is defined by 2026-10-24 only.
    const reverse = ["payments:invoice.read", "payments:payment.reverse"];
    expect(outcome(entryWith(v24.reference, RESOURCE, reverse), current24)).toBe("valid");
    const current20 = configured({ resource: RESOURCE, reference: v20.reference });
    const refused = entryValidationCheck(entryWith(v20.reference, RESOURCE, reverse), current20);
    expect(refused.outcome).toBe("refuse");
    expect(refused.error).toBe("invalid_authorization_details");
    expect(refused.reason).toMatch(/payments:payment\.reverse/);
  });

  it("refuses a current reference whose document the consumer does not hold", () => {
    const unheld: ConsumerConfig = { ...current24, definitions: [v20] };
    expect(outcome(entryWith(v24.reference), unheld)).toBe("refuse");
    expect(outcome(entryWith(v24.reference), current24)).toBe("valid");
  });

  it("reads a case's contracts as the configuration, an absent one naming none", () => {
    const evCase = (contracts?: unknown): VectorCase => ({
      id: "rules-ev-rc",
      requires: ["member.resource_contract"],
      check: "entry-validation",
      input:
        contracts === undefined
          ? { entry: entryWith(v24.reference) }
          : { entry: entryWith(v24.reference), contracts },
      expected: { outcome: "valid" },
    });
    const listed = (resource: string) => [{ resource, reference: { ...v24.reference } }];
    expect(runCase(evCase(listed(RESOURCE)), definitions).outcome).toBe("valid");
    expect(runCase(evCase(listed(OTHER)), definitions).outcome).toBe("refuse");
    expect(runCase(evCase([]), definitions).outcome).toBe("refuse");
    const absent = runCase(evCase(), definitions);
    expect(absent.outcome).toBe("refuse");
    expect(absent.error).toBe("invalid_authorization_details");
  });

  it("throws on a malformed configuration rather than reading it as none", () => {
    const malformed: unknown[] = [
      {},
      "https://payments.example/mcp",
      [null],
      [[RESOURCE, v24.reference]],
      [{ resource: RESOURCE }],
      [{ reference: v24.reference }],
      [{ resource: 1, reference: v24.reference }],
      [{ resource: RESOURCE, reference: { ...v24.reference, digest: "sha-256:short" } }],
      [{ resource: RESOURCE, resource_match: "prefix", reference: v24.reference }],
    ];
    for (const contracts of malformed) {
      expect(() => parseCurrentContracts(contracts), JSON.stringify(contracts)).toThrow();
    }
    expect(parseCurrentContracts(undefined)).toEqual([]);
    expect(parseCurrentContracts([{ resource: RESOURCE, reference: v24.reference }])).toEqual([
      { resource: RESOURCE, reference: v24.reference },
    ]);
  });
});
