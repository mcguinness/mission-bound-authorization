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
