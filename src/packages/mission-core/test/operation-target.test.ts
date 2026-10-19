/**
 * @spec resource-access#resource-matching, resource-access#rs-enforcement
 * (#1276, D447, D457): the operation target and the Resource Access matcher
 * shared by the PDP, the payments PEP and the SaaS resource server. Helper
 * level: the resource-operation witnesses live with each enforcement point.
 */

import { describe, expect, it } from "vitest";
import {
  CredentialAuthorityError,
  credentialAuthorityPermits,
  establishOperationTarget,
  isOperationTarget,
  matchResource,
  parseCredentialAuthority,
  resolveOperationTarget,
} from "../src/index.js";

const T = "https://api.example/orders/123";

describe("operation target well-formedness (@spec resource-access#resource-matching, #1276)", () => {
  it("accepts one absolute URI and returns the value as given, never reserialized", () => {
    for (const v of [
      T,
      "https://API.EXAMPLE:443/orders/123",
      "https://api.example/orders?id=1&view=full",
      "urn:example:payments",
    ]) {
      expect(isOperationTarget(v), v).toBe(true);
    }
  });

  it("refuses a missing, empty, relative, fragment-bearing, space-bearing, non-ASCII or non-string value, and an array of targets", () => {
    for (const v of [
      undefined,
      null,
      "",
      "/orders/123",
      "orders/123",
      `${T}#frag`,
      "https://api.example/a b",
      "https://api.example/ö",
      42,
      [T],
      [T, `${T}4`],
      { target: T },
    ]) {
      expect(isOperationTarget(v), JSON.stringify(v)).toBe(false);
    }
  });

  it("holds the target to RFC 3986 absolute-URI syntax: an invalid percent-encoding, a raw space, a non-ASCII character, a fragment or a relative reference refuses", () => {
    for (const v of [
      // pct-encoded = "%" HEXDIG HEXDIG (Section 2.1): every % begins a full triplet.
      "https://example.com/%zz",
      "https://example.com/%",
      "https://example.com/%4",
      "https://example.com/a%4/b",
      "https://example.com/a?q=%g0",
      "https://ex%zzample.com/",
      "https://u%zz@example.com/",
      // Characters outside the grammar where they appear (Sections 2.2, 2.3, 3.3, 3.4).
      "https://example.com/a b",
      "https://example.com/caf\u00e9",
      "https://example.com/\u0000",
      "https://example.com/a\n",
      "https://example.com/{id}",
      "https://example.com/a|b",
      "https://example.com/a\\b",
      // absolute-URI carries no fragment (Section 4.3).
      "https://example.com/a#",
      "https://example.com/a?q#f",
      // A relative reference is not an absolute URI (Sections 4.2, 4.3).
      "//example.com/a",
      "/a",
      "a",
      "1https://example.com/",
      // Authority (Section 3.2): one userinfo, a digit-only port, a well-formed IP literal.
      "https://a@b@example.com/",
      "https://example.com:80x/",
      "https://[1::2::3]/",
      "https://[1:2:3:4:5:6:7:8:9]/",
      "https://[::1%25eth0]/",
      "https://[::1]x/",
      // http and https name a non-empty host (RFC 9110, Sections 4.2.1 and 4.2.2).
      "https://",
      "https:///a",
      "https:a",
      "HTTP://:443/a",
    ]) {
      expect(isOperationTarget(v), JSON.stringify(v)).toBe(false);
    }
  });

  it("accepts valid percent-encodings, sub-delims and IP literals, and keeps %2F literal: the target is matched as given", () => {
    for (const v of [
      "https://example.com/%41",
      "https://example.com/a%2Fb",
      "https://example.com/a%2fb",
      "https://example.com/p?a=1&b=(2)*;c=$!',+~/?:@",
      "https://u:p@example.com:8443/a",
      "https://[::1]/a",
      "https://[2001:db8::7]:8080/",
      "https://[::ffff:192.0.2.1]/",
      "https://[v1.fe80::a+en1]/",
      "https://1.2.3.256/",
      "urn:example:payments",
      "mailto:ops@example.com",
    ]) {
      expect(isOperationTarget(v), v).toBe(true);
    }
    // The operand is never decoded or reserialized: %2F is not "/", and %41 is not "A".
    expect(establishOperationTarget({ service: "https://example.com/a%2Fb" })).toEqual({
      ok: true,
      target: "https://example.com/a%2Fb",
    });
    expect(
      matchResource({ resource: "https://example.com/a/b" }, "https://example.com/a%2Fb"),
    ).toBe("no-match");
    expect(matchResource({ resource: "https://example.com/A" }, "https://example.com/%41")).toBe(
      "no-match",
    );
    expect(matchResource({ resource: "https://example.com/%41" }, "https://example.com/%41")).toBe(
      "match",
    );
  });
});

describe("the Resource Access matcher (@spec resource-access#resource-matching, #1276)", () => {
  it("exact, stated or by default, matches only the identical string", () => {
    expect(matchResource({ resource: T }, T)).toBe("match");
    expect(matchResource({ resource: T, resource_match: "exact" }, T)).toBe("match");
    for (const spelling of [
      "https://API.EXAMPLE/orders/123",
      "https://api.example:443/orders/123",
      "https://api.example/orders/%31%32%33",
      "https://api.example/orders/123/",
      "https://api.example/orders/123?",
    ]) {
      expect(matchResource({ resource: T }, spelling), spelling).toBe("no-match");
    }
  });

  it("a prefix entry and an unrecognized resource_match are unsupported, never read as exact, even on their own base", () => {
    expect(matchResource({ resource: T, resource_match: "prefix" }, T)).toBe("unsupported");
    expect(matchResource({ resource: T, resource_match: "glob" }, T)).toBe("unsupported");
    expect(matchResource({ resource: T, resource_match: null }, T)).toBe("unsupported");
  });
});

describe("establishing the target from the operation contract (@spec resource-access#resource-matching, #1276)", () => {
  it("an explicit service-level contract establishes its service as the target", () => {
    expect(establishOperationTarget({ service: "https://erp.example.com" })).toEqual({
      ok: true,
      target: "https://erp.example.com",
    });
    expect(establishOperationTarget([{ service: T }, { service: T }])).toEqual({
      ok: true,
      target: T,
    });
  });

  it("no contract establishes nothing: there is no fallback to a metadata identifier", () => {
    for (const declared of [undefined, null, []]) {
      expect(establishOperationTarget(declared)).toEqual({ ok: false, reason: "no_contract" });
    }
  });

  it("a finer or unknown contract form is unsupported, and declarations naming different targets are ambiguous", () => {
    for (const contract of [
      { template: "https://api.example/orders/{order}" },
      { service: T, path: "/orders" },
      "service",
      1,
    ]) {
      expect(establishOperationTarget(contract), JSON.stringify(contract)).toEqual({
        ok: false,
        reason: "unsupported_contract",
      });
    }
    expect(establishOperationTarget([{ service: T }, { service: `${T}4` }])).toEqual({
      ok: false,
      reason: "ambiguous",
    });
    expect(resolveOperationTarget([T, `${T}4`])).toEqual({ ok: false, reason: "ambiguous" });
  });

  it("a contract naming a value that is not one absolute URI is malformed", () => {
    for (const service of ["", "/orders", `${T}#x`, `${T}/%zz`, `${T}%`, "https://", [T]]) {
      expect(establishOperationTarget({ service }), JSON.stringify(service)).toEqual({
        ok: false,
        reason: "malformed",
      });
    }
  });
});

describe("a credential's resource_match is read in full or refused (@spec resource-access#rs-enforcement, #1276)", () => {
  const entry = (over: Record<string, unknown> = {}) => ({
    type: "mission_resource_access",
    resource: T,
    actions: ["orders.read"],
    ...over,
  });
  const target = { resource: T, action: "orders.read", vendorIds: [], approvalEnforced: false };

  it("an exact entry, stated or by default, covers only its own target", () => {
    for (const parsed of [
      parseCredentialAuthority([entry()]),
      parseCredentialAuthority([entry({ resource_match: "exact" })]),
    ]) {
      expect(credentialAuthorityPermits(parsed, target)).toBe(true);
      expect(credentialAuthorityPermits(parsed, { ...target, resource: `${T}/` })).toBe(false);
    }
  });

  it("refuses the whole credential for a prefix or unrecognized resource_match", () => {
    for (const resource_match of ["prefix", "glob", null]) {
      expect(
        () => parseCredentialAuthority([entry(), entry({ resource_match })]),
        String(resource_match),
      ).toThrow(CredentialAuthorityError);
    }
  });
});
