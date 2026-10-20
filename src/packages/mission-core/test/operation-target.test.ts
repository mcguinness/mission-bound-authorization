/**
 * @spec resource-access#resource-matching, resource-access#rs-enforcement
 * (#1276, D447, D457): the operation target and the Resource Access matcher
 * shared by the PDP, the payments PEP and the SaaS resource server. Helper
 * level: the resource-operation witnesses live with each enforcement point.
 */

import { describe, expect, it } from "vitest";
import {
  CredentialAuthorityError,
  contractCanEstablish,
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

describe("an argument-derived contract establishes the target from the operation's validated arguments (@spec resource-access#resource-matching, #1276)", () => {
  const ORDERS = { template: "https://api.example/orders/{order_id}" };
  const FORGED = "https://attacker.example/orders/123";

  it("expands the one argument the template names, percent-encoding every character outside unreserved, and reads no other argument", () => {
    expect(
      establishOperationTarget(ORDERS, {
        order_id: "123",
        operation_target: FORGED,
        resource: FORGED,
      }),
    ).toEqual({ ok: true, target: T });
    for (const [value, target] of [
      // A delimiter in the argument never acts as one: the target stays one segment under /orders/.
      ["../admin", "https://api.example/orders/..%2Fadmin"],
      ["a/b?c#d", "https://api.example/orders/a%2Fb%3Fc%23d"],
      ["%2F", "https://api.example/orders/%252F"],
      ["a b", "https://api.example/orders/a%20b"],
      ["é", "https://api.example/orders/%C3%A9"],
      ["!*'()", "https://api.example/orders/%21%2A%27%28%29"],
      ["A-z_0.9~", "https://api.example/orders/A-z_0.9~"],
    ]) {
      expect(establishOperationTarget(ORDERS, { order_id: value }), value).toEqual({
        ok: true,
        target,
      });
    }
    // The literal after the expression stays: a sub-resource of the object.
    expect(
      establishOperationTarget(
        { template: "https://api.example/orders/{order_id}/lines?view=full" },
        { order_id: "7" },
      ),
    ).toEqual({ ok: true, target: "https://api.example/orders/7/lines?view=full" });
  });

  it("an absent, null or empty argument is missing_argument, never the service identifier", () => {
    for (const args of [
      {},
      { order_id: undefined },
      { order_id: null },
      { order_id: "" },
      { orderId: "123" },
    ]) {
      expect(establishOperationTarget(ORDERS, args), JSON.stringify(args)).toEqual({
        ok: false,
        reason: "missing_argument",
      });
    }
    // An inherited property is not an argument.
    expect(
      establishOperationTarget(
        ORDERS,
        Object.create({ order_id: "123" }) as Record<string, unknown>,
      ),
    ).toEqual({
      ok: false,
      reason: "missing_argument",
    });
  });

  it("an argument carrying a list, or contracts deriving different targets, is ambiguous; contracts agreeing on one target are not", () => {
    for (const order_id of [["123"], ["123", "124"], []]) {
      expect(establishOperationTarget(ORDERS, { order_id }), JSON.stringify(order_id)).toEqual({
        ok: false,
        reason: "ambiguous",
      });
    }
    expect(
      establishOperationTarget([ORDERS, { template: "https://api.example/invoices/{order_id}" }], {
        order_id: "123",
      }),
    ).toEqual({ ok: false, reason: "ambiguous" });
    expect(
      establishOperationTarget([ORDERS, { service: "https://api.example" }], { order_id: "123" }),
    ).toEqual({
      ok: false,
      reason: "ambiguous",
    });
    expect(establishOperationTarget([ORDERS, { service: T }], { order_id: "123" })).toEqual({
      ok: true,
      target: T,
    });
  });

  it("a non-string, dot-segment or unencodable argument is malformed", () => {
    for (const order_id of [123, true, { id: "123" }, ".", "..", "\uD800"]) {
      expect(establishOperationTarget(ORDERS, { order_id }), JSON.stringify(order_id)).toEqual({
        ok: false,
        reason: "malformed",
      });
    }
    // A template whose literal breaks RFC 3986 yields no target.
    expect(
      establishOperationTarget(
        { template: "https://api.example/a b/{order_id}" },
        { order_id: "1" },
      ),
    ).toEqual({
      ok: false,
      reason: "malformed",
    });
  });

  it("a template outside the supported form is unsupported, and every template is unsupported to a caller that supplies no arguments", () => {
    for (const template of [
      "https://api.example/orders",
      "https://api.example/orders/{order_id}/{line}",
      "https://api.example/orders/{order_id,line}",
      "https://api.example/orders/{+order_id}",
      "https://api.example/orders{/order_id}",
      "https://api.example/orders/{order_id*}",
      "https://api.example/orders/{order_id:3}",
      "https://{order_id}.example/orders",
      "https://api.example{order_id}",
      "https://api.example/orders?id={order_id}",
      "https://api.example/orders/}{order_id}",
      "urn:example:{order_id}",
      42,
    ]) {
      expect(establishOperationTarget({ template }, { order_id: "123" }), String(template)).toEqual(
        {
          ok: false,
          reason: "unsupported_contract",
        },
      );
    }
    expect(
      establishOperationTarget({ template: ORDERS.template, service: T }, { order_id: "123" }),
    ).toEqual({
      ok: false,
      reason: "unsupported_contract",
    });
    expect(establishOperationTarget(ORDERS)).toEqual({ ok: false, reason: "unsupported_contract" });
    // The service-level contract needs no argument.
    expect(establishOperationTarget({ service: T }, {})).toEqual({ ok: true, target: T });
  });

  it("contract coverage admits exactly the targets a contract establishes, read as given", () => {
    for (const value of ["123", "../admin", "a b", "é", "!*'()"]) {
      const derived = establishOperationTarget(ORDERS, { order_id: value });
      expect(derived.ok && contractCanEstablish(ORDERS, derived.target), value).toBe(true);
    }
    expect(contractCanEstablish({ service: T }, T)).toBe(true);
    for (const target of [
      "https://api.example/orders/",
      "https://api.example/orders/1/2",
      "https://api.example/orders/a%2fb",
      "https://api.example/orders/%41",
      "https://api.example/orders/.",
      "https://api.example/orders/..",
      "https://api.example/orders/%C3",
      "https://api.example/orders/%zz",
      "https://api.example/orders/1?x",
      "https://API.EXAMPLE/orders/1",
      "https://api.example/admin",
      "https://api.example",
    ]) {
      expect(contractCanEstablish(ORDERS, target), target).toBe(false);
    }
    expect(contractCanEstablish({ service: T }, `${T}/`)).toBe(false);
    expect(contractCanEstablish({ template: "https://api.example/orders/{a}/{b}" }, T)).toBe(false);
    expect(contractCanEstablish({ prefix: "https://api.example/orders" }, T)).toBe(false);
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
