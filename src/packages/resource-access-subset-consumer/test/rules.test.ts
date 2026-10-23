// Targeted tests of the general rules behind each check, beyond the current
// case list: decimal grammar and precision, instants, A-labels, URI syntax,
// unsupported-input refusal, constraint omission and resource_contract form,
// approval and preservation.

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  type ConsumerConfig,
  compareDecimal,
  compareInstant,
  entryValidationCheck,
  isValidRecipientDomain,
  isWithinDomain,
  parseAbsoluteUri,
  parseDecimal,
  parseInstant,
  subsetCheck,
} from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const subsetDir = resolve(here, "../../../../vectors/mission-resource-access-subset");
const contractFile = JSON.parse(
  readFileSync(join(subsetDir, "payments-contract-2026-10-20.json"), "utf8"),
) as {
  reference: { id: string; version: string; digest: string };
  document: { operations: Record<string, { action: string }> };
};
const reference = contractFile.reference;
const config: ConsumerConfig = {
  currentContracts: [
    { reference, actions: Object.values(contractFile.document.operations).map((o) => o.action) },
  ],
};

const RESOURCE = "https://payments.example/mcp";
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

  it("refuses a malformed amount at intake and fails closed in comparison", () => {
    for (const v of ["1e300", "-5", "NaN", "1.0000000000000000001"]) {
      expect(validate(amount(v)), v).toBe("refuse");
      expect(subsetCheck(amount(v), amount("1000")).outcome, v).toBe("not-subset");
      expect(subsetCheck(amount("1"), amount(v)).outcome, v).toBe("not-subset");
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

  it("fails a subset comparison closed on input outside the subset in either entry", () => {
    const plain = { ...base };
    expect(subsetCheck({ ...base, resource_match: "prefix" }, plain).outcome).toBe("not-subset");
    expect(subsetCheck(plain, { ...base, resource_match: "prefix" }).outcome).toBe("not-subset");
    expect(subsetCheck(plain, { ...base, actions: ["payments:invoice.*"] }).outcome).toBe(
      "not-subset",
    );
    expect(subsetCheck({ ...base, constraints: { x_unknown: true } }, plain).outcome).toBe(
      "not-subset",
    );
    expect(subsetCheck(plain, { ...base, constraints: { vendors: ["v"] } }).outcome).toBe(
      "not-subset",
    );
  });

  it("checks type and resource_match values", () => {
    expect(validate({ ...base, resource_match: "exact" })).toBe("valid");
    expect(validate({ ...base, resource_match: "EXACT" })).toBe("refuse");
    expect(validate({ resource: RESOURCE, actions: ["a"] })).toBe("refuse");
    expect(validate({ ...base, type: "other_type" })).toBe("refuse");
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
      expect(subsetCheck(e, e).outcome, JSON.stringify(rc)).toBe("not-subset");
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
