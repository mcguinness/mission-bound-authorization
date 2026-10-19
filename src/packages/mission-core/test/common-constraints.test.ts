/**
 * @spec resource-access#initial-common-constraints, resource-access#value-space-comparison,
 * resource-access#subset, resource-access#common-constraints (#1266, D457)
 *
 * The shared Common Constraint semantics every path reads: value syntax, the
 * subset rule, the intersection rule, and enforcement against authoritative
 * facts. Helper level: the endpoint and resource-server witnesses live with
 * the authorization server and the payments resource.
 */

import { describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  CredentialAuthorityError,
  commonConstraintGates,
  commonConstraintsNoBroader,
  compareInstants,
  credentialAuthorityPermits,
  instantFloorMs,
  instantFromMs,
  intersectCommonConstraints,
  isAuthorityEntry,
  isSubsetEntry,
  parseCredentialAuthority,
  parseRfc3339Instant,
  SUPPORTED_CONSTRAINT_KEYS,
  timeWindowEndMs,
} from "../src/index.js";

const R = "https://payments.example/mcp";
const entry = (constraints?: Record<string, unknown>): AuthorityEntry =>
  ({
    type: "mission_resource_access",
    resource: R,
    actions: ["payments:invoice.read"],
    ...(constraints ? { constraints } : {}),
  }) as AuthorityEntry;

const at = (s: string) => {
  const i = parseRfc3339Instant(s);
  if (!i) throw new Error(`not an instant: ${s}`);
  return i;
};

describe("RFC 3339 instants compare in value space (@spec resource-access#value-space-comparison)", () => {
  it("equates one instant written in different offsets and with trailing subsecond zeros", () => {
    expect(compareInstants(at("2026-07-01T00:00:00Z"), at("2026-07-01T02:00:00+02:00"))).toBe(0);
    expect(compareInstants(at("2026-06-30T19:00:00-05:00"), at("2026-07-01T00:00:00Z"))).toBe(0);
    expect(compareInstants(at("2026-09-30T23:59:59.000Z"), at("2026-09-30T23:59:59Z"))).toBe(0);
    expect(compareInstants(at("2026-09-30t23:59:59z"), at("2026-09-30T23:59:59Z"))).toBe(0);
  });

  it("orders instants exactly, below a millisecond as well", () => {
    expect(compareInstants(at("2026-09-30T23:59:59.0001Z"), at("2026-09-30T23:59:59Z"))).toBe(1);
    expect(compareInstants(at("2026-09-30T23:59:58.9999999Z"), at("2026-09-30T23:59:59Z"))).toBe(
      -1,
    );
    expect(compareInstants(at("2026-07-01T00:00:00+02:00"), at("2026-07-01T00:00:00Z"))).toBe(-1);
  });

  it("refuses anything that is not an RFC 3339 date-time, never parsing it loosely", () => {
    for (const bad of [
      "2026-07-01",
      "2026-07-01T00:00:00",
      "Wed, 01 Jul 2026 00:00:00 GMT",
      "2026-02-30T00:00:00Z",
      "2026-13-01T00:00:00Z",
      "2026-06-30T23:59:60Z",
      "2026-07-01T24:00:00Z",
      "2026-07-01T00:00:00+24:00",
      "2026-07-01T00:00:00.Z",
      " 2026-07-01T00:00:00Z",
      1782864000000,
    ]) {
      expect(parseRfc3339Instant(bad), String(bad)).toBeUndefined();
    }
  });

  it("converts a clock reading exactly and floors an instant to the millisecond", () => {
    const ms = Date.parse("2026-07-01T00:00:00.123Z");
    expect(compareInstants(instantFromMs(ms), at("2026-07-01T00:00:00.123Z"))).toBe(0);
    expect(instantFloorMs(at("2026-07-01T00:00:00.1239Z"))).toBe(ms);
    expect(instantFloorMs(at("2026-07-01T02:00:00+02:00"))).toBe(
      Date.parse("2026-07-01T00:00:00Z"),
    );
  });
});

describe("resource_issued_after and resource_issued_before: subset rule (@spec resource-access#initial-common-constraints)", () => {
  it("a later after-bound and an earlier before-bound are no broader; the reverse is broader", () => {
    const ref = {
      resource_issued_after: "2026-07-01T00:00:00Z",
      resource_issued_before: "2026-09-30T23:59:59Z",
    };
    expect(
      commonConstraintsNoBroader(
        {
          resource_issued_after: "2026-08-01T00:00:00Z",
          resource_issued_before: "2026-09-01T00:00:00Z",
        },
        ref,
      ),
    ).toBe(true);
    expect(
      commonConstraintsNoBroader({ ...ref, resource_issued_after: "2026-06-30T23:59:59Z" }, ref),
    ).toBe(false);
    expect(
      commonConstraintsNoBroader({ ...ref, resource_issued_before: "2026-10-01T00:00:00Z" }, ref),
    ).toBe(false);
  });

  it("an equal instant in another spelling is within the reference (inclusive, value space)", () => {
    expect(
      commonConstraintsNoBroader(
        {
          resource_issued_after: "2026-07-01T02:00:00+02:00",
          resource_issued_before: "2026-09-30T23:59:59.000Z",
        },
        {
          resource_issued_after: "2026-07-01T00:00:00Z",
          resource_issued_before: "2026-09-30T23:59:59Z",
        },
      ),
    ).toBe(true);
  });

  it("a candidate that drops a reference bound is broader, and one that adds a bound narrows", () => {
    expect(commonConstraintsNoBroader({}, { resource_issued_after: "2026-07-01T00:00:00Z" })).toBe(
      false,
    );
    expect(
      commonConstraintsNoBroader(undefined, { resource_issued_before: "2026-07-01T00:00:00Z" }),
    ).toBe(false);
    expect(
      commonConstraintsNoBroader({ resource_issued_before: "2026-07-01T00:00:00Z" }, undefined),
    ).toBe(true);
  });

  it("a malformed value on either side is never a subset", () => {
    expect(
      commonConstraintsNoBroader(
        { resource_issued_after: "2026-07-01" },
        { resource_issued_after: "2026-01-01T00:00:00Z" },
      ),
    ).toBe(false);
    expect(
      commonConstraintsNoBroader(
        { resource_issued_after: "2026-07-01T00:00:00Z" },
        { resource_issued_after: "soon" },
      ),
    ).toBe(false);
    expect(commonConstraintsNoBroader({ resource_issued_before: 20260701 }, undefined)).toBe(false);
  });

  it("isSubsetEntry applies the rule, so every lineage comparison inherits it", () => {
    const ref = entry({ resource_issued_after: "2026-07-01T00:00:00Z" });
    expect(isSubsetEntry(entry({ resource_issued_after: "2026-08-01T00:00:00Z" }), ref)).toBe(true);
    expect(isSubsetEntry(entry({ resource_issued_after: "2026-06-01T00:00:00Z" }), ref)).toBe(
      false,
    );
    expect(isSubsetEntry(entry(), ref)).toBe(false);
  });
});

describe("resource_issued_after and resource_issued_before: intersection rule (@spec resource-access#initial-common-constraints)", () => {
  it("takes the later after-bound and the earlier before-bound, carrying a one-sided bound", () => {
    const r = intersectCommonConstraints(
      { resource_issued_after: "2026-08-01T00:00:00Z" },
      {
        resource_issued_after: "2026-07-01T00:00:00Z",
        resource_issued_before: "2026-09-30T23:59:59Z",
      },
    );
    expect(r).toEqual({
      ok: true,
      values: {
        resource_issued_after: "2026-08-01T00:00:00Z",
        resource_issued_before: "2026-09-30T23:59:59Z",
      },
    });
    const earlier = intersectCommonConstraints(
      { resource_issued_before: "2026-09-01T00:00:00Z" },
      { resource_issued_before: "2026-09-30T23:59:59Z" },
    );
    expect(earlier).toEqual({
      ok: true,
      values: { resource_issued_before: "2026-09-01T00:00:00Z" },
    });
  });

  it("is no broader than either operand", () => {
    const a = {
      resource_issued_after: "2026-08-01T00:00:00Z",
      resource_issued_before: "2026-12-31T00:00:00Z",
    };
    const b = {
      resource_issued_after: "2026-07-01T00:00:00Z",
      resource_issued_before: "2026-09-30T23:59:59Z",
    };
    const r = intersectCommonConstraints(a, b);
    if (!r.ok) throw new Error(r.reason);
    expect(commonConstraintsNoBroader(r.values, a)).toBe(true);
    expect(commonConstraintsNoBroader(r.values, b)).toBe(true);
  });

  it("fails a combination whose issuance window is empty (contradictory windows)", () => {
    const r = intersectCommonConstraints(
      { resource_issued_after: "2026-10-01T00:00:00Z" },
      { resource_issued_before: "2026-09-30T23:59:59Z" },
    );
    expect(r.ok).toBe(false);
    // A single instant is a non-empty window: both bounds are inclusive.
    expect(
      intersectCommonConstraints(
        { resource_issued_after: "2026-09-30T23:59:59Z" },
        { resource_issued_before: "2026-10-01T01:59:59+02:00" },
      ).ok,
    ).toBe(true);
  });

  it("fails on a malformed operand rather than carrying it", () => {
    expect(intersectCommonConstraints({ resource_issued_after: "2026-07-01" }, undefined).ok).toBe(
      false,
    );
  });
});

describe("resource_issued_after and resource_issued_before: enforcement against the resource's issuance fact (@spec resource-access#rs-enforcement)", () => {
  const bounds = {
    resource_issued_after: "2026-07-01T00:00:00Z",
    resource_issued_before: "2026-09-30T23:59:59Z",
  };

  it("permits a resource issued within the window, both bounds inclusive", () => {
    for (const issued of [
      "2026-08-15T12:00:00Z",
      "2026-07-01T02:00:00+02:00",
      "2026-09-30T23:59:59.000Z",
    ]) {
      expect(commonConstraintGates(bounds, { resourceIssuedAt: issued }), issued).toEqual({
        satisfied: true,
        evaluated: ["resource_issued_after", "resource_issued_before"],
      });
    }
  });

  it("refuses a resource issued outside the window, stopping at the first failing gate", () => {
    expect(commonConstraintGates(bounds, { resourceIssuedAt: "2026-06-30T23:59:59.999Z" })).toEqual(
      {
        satisfied: false,
        evaluated: ["resource_issued_after"],
      },
    );
    expect(commonConstraintGates(bounds, { resourceIssuedAt: "2026-09-30T23:59:59.001Z" })).toEqual(
      {
        satisfied: false,
        evaluated: ["resource_issued_after", "resource_issued_before"],
      },
    );
  });

  it("refuses when the resource's issuance fact is missing or malformed", () => {
    expect(commonConstraintGates(bounds, {}).satisfied).toBe(false);
    expect(commonConstraintGates(bounds, { resourceIssuedAt: "2026-08-15" }).satisfied).toBe(false);
    // Each bound alone, so neither gate's refusal hides the other's.
    for (const key of ["resource_issued_after", "resource_issued_before"] as const) {
      const one = { [key]: bounds[key] };
      expect(commonConstraintGates(one, {}).satisfied, key).toBe(false);
      expect(commonConstraintGates(one, { resourceIssuedAt: "2026-08-15" }).satisfied, key).toBe(
        false,
      );
    }
  });

  it("refuses every resource under a contradictory window", () => {
    const contradictory = {
      resource_issued_after: "2026-10-01T00:00:00Z",
      resource_issued_before: "2026-09-30T00:00:00Z",
    };
    for (const issued of ["2026-09-15T00:00:00Z", "2026-10-15T00:00:00Z", "2026-10-01T00:00:00Z"]) {
      expect(
        commonConstraintGates(contradictory, { resourceIssuedAt: issued }).satisfied,
        issued,
      ).toBe(false);
    }
  });

  it("evaluates nothing for an entry carrying no implemented key", () => {
    expect(commonConstraintGates({ vendors: ["acme"] }, {})).toEqual({
      satisfied: true,
      evaluated: [],
    });
  });
});

describe("the supported set, the config and wire validators, and the credential reader agree (@spec resource-access#common-constraints)", () => {
  it("SUPPORTED_CONSTRAINT_KEYS names both issuance bounds", () => {
    expect(SUPPORTED_CONSTRAINT_KEYS).toContain("resource_issued_after");
    expect(SUPPORTED_CONSTRAINT_KEYS).toContain("resource_issued_before");
  });

  it("isAuthorityEntry admits a well-formed bound and refuses a malformed one", () => {
    expect(isAuthorityEntry(entry({ resource_issued_after: "2026-07-01T00:00:00Z" }))).toBe(true);
    expect(isAuthorityEntry(entry({ resource_issued_after: "2026-07-01" }))).toBe(false);
    expect(
      isAuthorityEntry(entry({ resource_issued_before: { at: "2026-07-01T00:00:00Z" } })),
    ).toBe(false);
  });

  it("parseCredentialAuthority keeps a well-formed bound and refuses a malformed one", () => {
    const parsed = parseCredentialAuthority([
      entry({
        resource_issued_after: "2026-07-01T02:00:00+02:00",
        resource_issued_before: "2026-09-30T23:59:59Z",
      }),
    ]);
    expect(parsed[0]?.constraints).toEqual({
      resource_issued_after: "2026-07-01T02:00:00+02:00",
      resource_issued_before: "2026-09-30T23:59:59Z",
    });
    expect(() => parseCredentialAuthority([entry({ resource_issued_before: "tomorrow" })])).toThrow(
      CredentialAuthorityError,
    );
  });

  it("the credential bound enforces the window against the facts the enforcement point established", () => {
    const authority = parseCredentialAuthority([
      entry({ resource_issued_after: "2026-07-01T00:00:00Z" }),
    ]);
    const target = {
      resource: R,
      action: "payments:invoice.read",
      vendorIds: [],
      approvalEnforced: false,
    };
    expect(
      credentialAuthorityPermits(authority, {
        ...target,
        constraintFacts: { resourceIssuedAt: "2026-07-15T00:00:00Z" },
      }),
    ).toBe(true);
    expect(
      credentialAuthorityPermits(authority, {
        ...target,
        constraintFacts: { resourceIssuedAt: "2026-06-15T00:00:00Z" },
      }),
    ).toBe(false);
    expect(credentialAuthorityPermits(authority, target)).toBe(false);
  });
});

describe("tenant (@spec resource-access#initial-common-constraints)", () => {
  it("subset: no broader only when equal, compared as exact strings", () => {
    expect(commonConstraintsNoBroader({ tenant: "acme" }, { tenant: "acme" })).toBe(true);
    expect(commonConstraintsNoBroader({ tenant: "globex" }, { tenant: "acme" })).toBe(false);
    expect(commonConstraintsNoBroader({ tenant: "Acme" }, { tenant: "acme" })).toBe(false);
    expect(commonConstraintsNoBroader({ tenant: "acme " }, { tenant: "acme" })).toBe(false);
    expect(commonConstraintsNoBroader({}, { tenant: "acme" })).toBe(false);
    expect(commonConstraintsNoBroader({ tenant: "acme" }, {})).toBe(true);
  });

  it("intersection: the common value when equal, otherwise no intersection", () => {
    expect(intersectCommonConstraints({ tenant: "acme" }, { tenant: "acme" })).toEqual({
      ok: true,
      values: { tenant: "acme" },
    });
    expect(intersectCommonConstraints({ tenant: "acme" }, undefined)).toEqual({
      ok: true,
      values: { tenant: "acme" },
    });
    expect(intersectCommonConstraints({ tenant: "acme" }, { tenant: "globex" }).ok).toBe(false);
    expect(intersectCommonConstraints({ tenant: "acme" }, { tenant: "ACME" }).ok).toBe(false);
  });

  it("enforcement: the resource's own tenant must equal the bound; an absent tenant refuses", () => {
    expect(commonConstraintGates({ tenant: "acme" }, { tenant: "acme" })).toEqual({
      satisfied: true,
      evaluated: ["tenant"],
    });
    expect(commonConstraintGates({ tenant: "acme" }, { tenant: "globex" }).satisfied).toBe(false);
    expect(commonConstraintGates({ tenant: "acme" }, { tenant: "ACME" }).satisfied).toBe(false);
    expect(commonConstraintGates({ tenant: "acme" }, {}).satisfied).toBe(false);
  });

  it("value syntax: a non-empty string; the validators and the credential reader agree", () => {
    expect(SUPPORTED_CONSTRAINT_KEYS).toContain("tenant");
    expect(isAuthorityEntry(entry({ tenant: "acme" }))).toBe(true);
    for (const bad of ["", 7, ["acme"], null]) {
      expect(isAuthorityEntry(entry({ tenant: bad })), JSON.stringify(bad)).toBe(false);
      expect(() => parseCredentialAuthority([entry({ tenant: bad })]), JSON.stringify(bad)).toThrow(
        CredentialAuthorityError,
      );
    }
    expect(parseCredentialAuthority([entry({ tenant: "acme" })])[0]?.constraints).toEqual({
      tenant: "acme",
    });
  });
});

describe("time_window (@spec resource-access#initial-common-constraints)", () => {
  const JUL = { not_before: "2026-07-01T00:00:00Z", not_after: "2026-07-31T23:59:59Z" };
  const ms = (s: string) => Date.parse(s);

  it("subset: within the reference; an absent candidate bound is unbounded, so broader", () => {
    const ref = {
      time_window: { not_before: "2026-06-01T00:00:00Z", not_after: "2026-08-31T00:00:00Z" },
    };
    expect(commonConstraintsNoBroader({ time_window: JUL }, ref)).toBe(true);
    expect(
      commonConstraintsNoBroader(
        { time_window: { ...JUL, not_after: "2026-09-30T00:00:00Z" } },
        ref,
      ),
    ).toBe(false);
    expect(
      commonConstraintsNoBroader(
        { time_window: { ...JUL, not_before: "2026-05-31T23:59:59Z" } },
        ref,
      ),
    ).toBe(false);
    expect(commonConstraintsNoBroader({ time_window: { not_before: JUL.not_before } }, ref)).toBe(
      false,
    );
    expect(commonConstraintsNoBroader({ time_window: { not_after: JUL.not_after } }, ref)).toBe(
      false,
    );
    expect(commonConstraintsNoBroader({}, ref)).toBe(false);
    // A one-sided reference bounds only its side.
    expect(
      commonConstraintsNoBroader(
        { time_window: JUL },
        { time_window: { not_before: "2026-01-01T00:00:00Z" } },
      ),
    ).toBe(true);
  });

  it("subset compares instants in value space, across offsets", () => {
    expect(
      commonConstraintsNoBroader(
        { time_window: { not_before: "2026-07-01T02:00:00+02:00" } },
        { time_window: { not_before: "2026-07-01T00:00:00Z" } },
      ),
    ).toBe(true);
    expect(
      commonConstraintsNoBroader(
        { time_window: { not_before: "2026-07-01T01:59:59+02:00" } },
        { time_window: { not_before: "2026-07-01T00:00:00Z" } },
      ),
    ).toBe(false);
  });

  it("intersection: the overlap, the later not_before and the earlier not_after", () => {
    expect(
      intersectCommonConstraints(
        { time_window: { not_before: "2026-07-01T00:00:00Z", not_after: "2026-12-31T00:00:00Z" } },
        { time_window: { not_before: "2026-01-01T00:00:00Z", not_after: "2026-07-31T23:59:59Z" } },
      ),
    ).toEqual({ ok: true, values: { time_window: JUL } });
    expect(
      intersectCommonConstraints(
        { time_window: { not_before: JUL.not_before } },
        { time_window: { not_after: JUL.not_after } },
      ),
    ).toEqual({ ok: true, values: { time_window: JUL } });
    expect(intersectCommonConstraints({ time_window: JUL }, undefined)).toEqual({
      ok: true,
      values: { time_window: JUL },
    });
  });

  it("intersection: an empty overlap fails the combination; a single shared instant does not", () => {
    expect(
      intersectCommonConstraints(
        { time_window: { not_before: "2026-08-01T00:00:00Z" } },
        { time_window: { not_after: "2026-07-31T23:59:59Z" } },
      ).ok,
    ).toBe(false);
    expect(
      intersectCommonConstraints(
        { time_window: { not_before: "2026-07-31T23:59:59Z" } },
        { time_window: { not_after: "2026-08-01T01:59:59+02:00" } },
      ).ok,
    ).toBe(true);
  });

  it("enforcement: the current trusted time must lie within the window, both bounds inclusive", () => {
    const gate = (now?: number) =>
      commonConstraintGates({ time_window: JUL }, now === undefined ? {} : { now });
    expect(gate(ms("2026-07-15T12:00:00Z"))).toEqual({
      satisfied: true,
      evaluated: ["time_window"],
    });
    expect(gate(ms(JUL.not_before)).satisfied).toBe(true);
    expect(gate(ms(JUL.not_after)).satisfied).toBe(true);
    expect(gate(ms(JUL.not_before) - 1).satisfied).toBe(false);
    expect(gate(ms(JUL.not_after) + 1).satisfied).toBe(false);
  });

  it("enforcement: an absent or unusable clock reading refuses", () => {
    expect(commonConstraintGates({ time_window: JUL }, {}).satisfied).toBe(false);
    expect(commonConstraintGates({ time_window: JUL }, { now: Number.NaN }).satisfied).toBe(false);
  });

  it("value syntax: an object with one or both RFC 3339 bounds and nothing else", () => {
    expect(SUPPORTED_CONSTRAINT_KEYS).toContain("time_window");
    for (const good of [JUL, { not_before: JUL.not_before }, { not_after: JUL.not_after }]) {
      expect(isAuthorityEntry(entry({ time_window: good })), JSON.stringify(good)).toBe(true);
    }
    for (const bad of [
      {},
      { not_before: "2026-07-01" },
      { ...JUL, tz: "UTC" },
      "2026-07-01T00:00:00Z",
      [JUL],
      null,
    ]) {
      expect(isAuthorityEntry(entry({ time_window: bad })), JSON.stringify(bad)).toBe(false);
      expect(
        () => parseCredentialAuthority([entry({ time_window: bad })]),
        JSON.stringify(bad),
      ).toThrow(CredentialAuthorityError);
    }
    expect(parseCredentialAuthority([entry({ time_window: JUL })])[0]?.constraints).toEqual({
      time_window: JUL,
    });
  });

  it("the window's end, floored to the millisecond, bounds a permit; an open-ended window sets none", () => {
    expect(timeWindowEndMs({ time_window: JUL })).toBe(ms(JUL.not_after));
    expect(timeWindowEndMs({ time_window: { not_after: "2026-07-31T23:59:59.9999Z" } })).toBe(
      ms("2026-07-31T23:59:59.999Z"),
    );
    expect(timeWindowEndMs({ time_window: { not_before: JUL.not_before } })).toBeUndefined();
    expect(timeWindowEndMs({ tenant: "acme" })).toBeUndefined();
  });
});

describe("recipient_domain (@spec resource-access#initial-common-constraints)", () => {
  const rd = (v: string) => ({ recipient_domain: v });

  it("subset: equal or a subdomain on whole labels, case-insensitively", () => {
    expect(commonConstraintsNoBroader(rd("example.com"), rd("example.com"))).toBe(true);
    expect(commonConstraintsNoBroader(rd("mail.example.com"), rd("example.com"))).toBe(true);
    expect(commonConstraintsNoBroader(rd("MAIL.Example.COM"), rd("example.com"))).toBe(true);
    expect(commonConstraintsNoBroader(rd("notexample.com"), rd("example.com"))).toBe(false);
    expect(commonConstraintsNoBroader(rd("example.com"), rd("mail.example.com"))).toBe(false);
    expect(commonConstraintsNoBroader(rd("example.net"), rd("example.com"))).toBe(false);
    expect(commonConstraintsNoBroader({}, rd("example.com"))).toBe(false);
  });

  it("intersection: the narrower value when one is within the other, otherwise none", () => {
    expect(intersectCommonConstraints(rd("example.com"), rd("mail.example.com"))).toEqual({
      ok: true,
      values: rd("mail.example.com"),
    });
    expect(intersectCommonConstraints(rd("Mail.Example.com"), rd("example.COM"))).toEqual({
      ok: true,
      values: rd("Mail.Example.com"),
    });
    expect(intersectCommonConstraints(rd("example.com"), rd("example.net")).ok).toBe(false);
    expect(intersectCommonConstraints(rd("a.example.com"), rd("b.example.com")).ok).toBe(false);
  });

  it("enforcement: every resolved recipient must be within the domain", () => {
    const gate = (recipients?: string[]) =>
      commonConstraintGates(rd("example.com"), recipients === undefined ? {} : { recipients });
    expect(gate(["a@example.com", "b@mail.EXAMPLE.com"])).toEqual({
      satisfied: true,
      evaluated: ["recipient_domain"],
    });
    expect(gate(["a@example.com", "b@example.net"]).satisfied).toBe(false);
    expect(gate(["a@notexample.com"]).satisfied).toBe(false);
  });

  it("enforcement: no recipient, or one that is not a bare address, refuses", () => {
    const gate = (recipients?: string[]) =>
      commonConstraintGates(rd("example.com"), recipients === undefined ? {} : { recipients });
    expect(gate().satisfied).toBe(false);
    expect(gate([]).satisfied).toBe(false);
    for (const bad of [
      "example.com",
      "@example.com",
      "a@b@example.com",
      "a@example.com.",
      "a@exa mple.com",
    ]) {
      expect(gate(["ok@example.com", bad]).satisfied, bad).toBe(false);
    }
  });

  it("value syntax: a DNS name; the validators and the credential reader agree", () => {
    expect(SUPPORTED_CONSTRAINT_KEYS).toContain("recipient_domain");
    for (const good of ["example.com", "Mail.Example.com", "localhost", "xn--bcher-kva.example"]) {
      expect(isAuthorityEntry(entry(rd(good))), good).toBe(true);
    }
    for (const bad of [
      "",
      "-a.com",
      "a..com",
      "example.com.",
      "ex ample.com",
      "a_b.com",
      7,
      null,
    ]) {
      expect(isAuthorityEntry(entry({ recipient_domain: bad })), JSON.stringify(bad)).toBe(false);
      expect(
        () => parseCredentialAuthority([entry({ recipient_domain: bad })]),
        JSON.stringify(bad),
      ).toThrow(CredentialAuthorityError);
    }
    expect(parseCredentialAuthority([entry(rd("example.com"))])[0]?.constraints).toEqual(
      rd("example.com"),
    );
  });
});

describe("data_classification (@spec resource-access#initial-common-constraints)", () => {
  const dc = (v: unknown) => ({ data_classification: v });

  it("subset: the candidate's labels are all among the reference's, as exact strings", () => {
    expect(commonConstraintsNoBroader(dc(["internal"]), dc(["internal", "public"]))).toBe(true);
    expect(commonConstraintsNoBroader(dc([]), dc(["internal"]))).toBe(true);
    expect(commonConstraintsNoBroader(dc(["internal", "secret"]), dc(["internal", "public"]))).toBe(
      false,
    );
    expect(commonConstraintsNoBroader(dc(["Internal"]), dc(["internal"]))).toBe(false);
    expect(commonConstraintsNoBroader({}, dc(["internal"]))).toBe(false);
  });

  it("intersection: the common labels; none in common has no intersection", () => {
    expect(
      intersectCommonConstraints(dc(["public", "internal", "secret"]), dc(["internal", "public"])),
    ).toEqual({
      ok: true,
      values: dc(["public", "internal"]),
    });
    expect(intersectCommonConstraints(dc(["secret"]), dc(["internal"])).ok).toBe(false);
    expect(intersectCommonConstraints(dc([]), dc(["internal"])).ok).toBe(false);
    expect(intersectCommonConstraints(dc(["internal"]), undefined)).toEqual({
      ok: true,
      values: dc(["internal"]),
    });
  });

  it("enforcement: every label the operation touches must be named; no label, or an empty bound, refuses", () => {
    const gate = (bound: string[], labels?: string[]) =>
      commonConstraintGates(dc(bound), labels === undefined ? {} : { dataClassification: labels })
        .satisfied;
    expect(gate(["internal", "public"], ["internal"])).toBe(true);
    expect(gate(["internal", "public"], ["internal", "public"])).toBe(true);
    expect(gate(["internal", "public"], ["internal", "secret"])).toBe(false);
    expect(gate(["internal"], ["Internal"])).toBe(false);
    expect(gate(["internal"])).toBe(false);
    expect(gate(["internal"], [])).toBe(false);
    expect(gate([], ["internal"])).toBe(false);
  });

  it("value syntax: an array of non-empty strings; the validators and the credential reader agree", () => {
    expect(SUPPORTED_CONSTRAINT_KEYS).toContain("data_classification");
    for (const good of [["internal"], [], ["a", "b"]]) {
      expect(isAuthorityEntry(entry(dc(good))), JSON.stringify(good)).toBe(true);
    }
    for (const bad of ["internal", [""], [1], ["a", null], {}]) {
      expect(isAuthorityEntry(entry(dc(bad))), JSON.stringify(bad)).toBe(false);
      expect(() => parseCredentialAuthority([entry(dc(bad))]), JSON.stringify(bad)).toThrow(
        CredentialAuthorityError,
      );
    }
    expect(parseCredentialAuthority([entry(dc(["internal"]))])[0]?.constraints).toEqual(
      dc(["internal"]),
    );
  });
});

describe("allowed_tools (@spec resource-access#initial-common-constraints)", () => {
  const at = (v: unknown) => ({ allowed_tools: v });

  it("subset: the candidate's tools are all among the reference's, as exact strings", () => {
    expect(
      commonConstraintsNoBroader(at(["query_invoices"]), at(["query_invoices", "post_adjustment"])),
    ).toBe(true);
    expect(commonConstraintsNoBroader(at([]), at(["query_invoices"]))).toBe(true);
    expect(commonConstraintsNoBroader(at(["delete_invoice"]), at(["query_invoices"]))).toBe(false);
    expect(commonConstraintsNoBroader(at(["Query_Invoices"]), at(["query_invoices"]))).toBe(false);
    expect(commonConstraintsNoBroader({}, at(["query_invoices"]))).toBe(false);
  });

  it("intersection: the common tools; none in common has no intersection", () => {
    expect(intersectCommonConstraints(at(["a", "b"]), at(["b", "c"]))).toEqual({
      ok: true,
      values: at(["b"]),
    });
    expect(intersectCommonConstraints(at(["a"]), at(["c"])).ok).toBe(false);
    expect(intersectCommonConstraints(at([]), at(["c"])).ok).toBe(false);
  });

  it("enforcement: the dispatched tool must be named; no tool, or an empty bound, refuses", () => {
    const gate = (bound: string[], tool?: string) =>
      commonConstraintGates(at(bound), tool === undefined ? {} : { tool }).satisfied;
    expect(gate(["check_transfer", "get_invoice"], "check_transfer")).toBe(true);
    expect(gate(["check_transfer"], "execute_wire_transfer")).toBe(false);
    expect(gate(["check_transfer"], "Check_Transfer")).toBe(false);
    expect(gate(["check_transfer"])).toBe(false);
    expect(gate([], "check_transfer")).toBe(false);
  });

  it("value syntax: an array of non-empty strings; the validators and the credential reader agree", () => {
    expect(SUPPORTED_CONSTRAINT_KEYS).toContain("allowed_tools");
    for (const good of [["check_transfer"], []]) {
      expect(isAuthorityEntry(entry(at(good))), JSON.stringify(good)).toBe(true);
    }
    for (const bad of ["check_transfer", [""], [7], null]) {
      expect(isAuthorityEntry(entry(at(bad))), JSON.stringify(bad)).toBe(false);
      expect(() => parseCredentialAuthority([entry(at(bad))]), JSON.stringify(bad)).toThrow(
        CredentialAuthorityError,
      );
    }
    expect(parseCredentialAuthority([entry(at(["check_transfer"]))])[0]?.constraints).toEqual(
      at(["check_transfer"]),
    );
  });

  it("every initial Common Constraint is implemented", () => {
    for (const key of [
      "max_amount",
      "resource_issued_after",
      "resource_issued_before",
      "tenant",
      "recipient_domain",
      "time_window",
      "data_classification",
      "allowed_tools",
      "requires_action_approval",
    ]) {
      expect(SUPPORTED_CONSTRAINT_KEYS, key).toContain(key);
    }
  });
});

describe("a combination that admits nothing has no intersection, even from one operand (@spec resource-access#common-constraints)", () => {
  it("an empty window, label list or tool list carried from one operand fails the combination", () => {
    for (const constraints of [
      { time_window: { not_before: "2026-09-01T00:00:00Z", not_after: "2026-08-01T00:00:00Z" } },
      { data_classification: [] },
      { allowed_tools: [] },
    ]) {
      expect(
        intersectCommonConstraints(constraints, undefined).ok,
        JSON.stringify(constraints),
      ).toBe(false);
      expect(
        intersectCommonConstraints(undefined, constraints).ok,
        JSON.stringify(constraints),
      ).toBe(false);
    }
  });

  it("a single-instant window is not empty", () => {
    const instantWindow = {
      time_window: { not_before: "2026-08-01T00:00:00Z", not_after: "2026-08-01T02:00:00+02:00" },
    };
    expect(intersectCommonConstraints(instantWindow, undefined).ok).toBe(true);
  });
});
