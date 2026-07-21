import { describe, expect, it } from "vitest";
import {
  authorityHash,
  canonicalize,
  DuplicateMemberError,
  intentHash,
  parseStrictJson,
  verifyAnchor,
} from "../src/index.js";

const ISS = "https://as.example.com";

// Core § test-vectors, vector pair 1 + the nested-controls intent of pair 2.
const INTENT_V1 = {
  goal: "Reconcile Q3 invoices",
  resources: ["https://erp.example.com"],
  expires_at: "2026-12-31T23:59:59Z",
};

const AUTHORITY_V1 = [
  {
    type: "mission_resource_access",
    resource: "https://erp.example.com",
    actions: ["invoices.read"],
  },
  {
    type: "mission_resource_access",
    resource: "https://erp.example.com",
    actions: ["journal-entries.write"],
    constraints: { max_amount: { amount: "500.00", currency: "USD" } },
  },
];

const INTENT_V2 = {
  goal: "Reconcile Q3 invoices",
  resources: ["https://erp.example.com"],
  expires_at: "2026-12-31T23:59:59Z",
  controls: { acr: "urn:example:acr:mfa", max_derivations: 20 },
};

describe("canonicalize (JCS)", () => {
  it("matches the core vector 1 intent envelope byte-for-byte", () => {
    const canonical = canonicalize({ typ: "mission-intent", iss: ISS, value: INTENT_V1 });
    expect(canonical).toBe(
      '{"iss":"https://as.example.com","typ":"mission-intent","value":{"expires_at":"2026-12-31T23:59:59Z","goal":"Reconcile Q3 invoices","resources":["https://erp.example.com"]}}',
    );
  });

  it("matches the core vector 1 authority-set envelope byte-for-byte", () => {
    const canonical = canonicalize({ typ: "mission-authority-set", iss: ISS, value: AUTHORITY_V1 });
    expect(canonical).toBe(
      '{"iss":"https://as.example.com","typ":"mission-authority-set","value":[{"actions":["invoices.read"],"resource":"https://erp.example.com","type":"mission_resource_access"},{"actions":["journal-entries.write"],"constraints":{"max_amount":{"amount":"500.00","currency":"USD"}},"resource":"https://erp.example.com","type":"mission_resource_access"}]}',
    );
  });

  it("preserves array order while sorting object members", () => {
    expect(
      canonicalize([
        { b: 1, a: 2 },
        { d: 3, c: 4 },
      ]),
    ).toBe('[{"a":2,"b":1},{"c":4,"d":3}]');
  });
});

describe("integrity anchors (core § test-vectors)", () => {
  it("vector 1 intent_hash", () => {
    expect(intentHash(ISS, INTENT_V1)).toBe("sha-256:6mIFoCz79uCHNzKLfBpBwqFjoFXdpmpuc65486IqimQ");
  });

  it("vector 1 authority_hash", () => {
    expect(authorityHash(ISS, AUTHORITY_V1)).toBe(
      "sha-256:vUCCfjGulit9u0qJ0Z6pQSNerZtXMqRlfJNCr4PzLro",
    );
  });

  it("vector 2 intent_hash (nested controls object, integer member)", () => {
    expect(intentHash(ISS, INTENT_V2)).toBe("sha-256:DHUg4zS3HHnWtXlO6hu9sTN_jX4LyjZ4tOJiTDAvWAI");
  });

  it("verifyAnchor round-trips and rejects unknown algorithm prefixes", () => {
    const anchor = intentHash(ISS, INTENT_V1);
    expect(verifyAnchor(anchor, "mission-intent", ISS, INTENT_V1)).toBe(true);
    expect(verifyAnchor(anchor, "mission-intent", ISS, INTENT_V2)).toBe(false);
    expect(() => verifyAnchor("sha3-256:abc", "mission-intent", ISS, INTENT_V1)).toThrow(
      /unrecognized anchor algorithm prefix/,
    );
  });

  it("domain separation: same value under different typ yields different anchors", () => {
    const a = intentHash(ISS, { x: 1 });
    const b = authorityHash(ISS, [{ x: 1 }] as never);
    expect(a).not.toBe(b);
  });
});

describe("parseStrictJson", () => {
  it("rejects duplicate member names (core § canonicalization)", () => {
    expect(() => parseStrictJson('{"a":1,"a":2}')).toThrow(DuplicateMemberError);
    expect(() => parseStrictJson('{"outer":{"a":1,"a":2}}')).toThrow(DuplicateMemberError);
  });

  it("parses ordinary JSON and round-trips through canonicalize", () => {
    const v = parseStrictJson('{"b": [1, 2.5, true, null], "a": "x\\n"}');
    expect(canonicalize(v)).toBe('{"a":"x\\n","b":[1,2.5,true,null]}');
  });

  it("rejects trailing input", () => {
    expect(() => parseStrictJson('{"a":1} garbage')).toThrow(SyntaxError);
  });
});
