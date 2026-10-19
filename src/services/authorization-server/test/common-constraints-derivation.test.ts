/**
 * @spec resource-access#common-constraints, resource-access#initial-common-constraints,
 * resource-access#scope-projection (#1266, D457)
 *
 * The authorization server's own paths over the implemented Common
 * Constraints, below the endpoints: intake validation and the published
 * schema, derivation intersection (refusal on an empty intersection, no drop
 * of a ceiling key), effective-set projection (intersection, fragment dropped
 * on an empty intersection), and the two projections that cannot carry the
 * key and so refuse it (scope projection, the attenuation root mapping).
 */

import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { scopeValueSafeForEntry, SUPPORTED_CONSTRAINT_KEYS } from "@mission/core";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  type AuthorityEntry,
  deriveAuthoritySet,
  IntentError,
  MISSION_RESOURCE_ACCESS_SCHEMA,
  type MissionIntent,
  mapAuthorityToTools,
  projectThroughEffective,
  validateAuthorityProposal,
} from "../src/index.js";

const R = "https://erp.example.com";
const intent = { target_resources: [R] } as unknown as MissionIntent;
const policy = (ceiling: AuthorityEntry[]) => ({ policy_version: "common-constraints", ceiling });
const entry = (constraints?: Record<string, unknown>, actions = ["invoices.read"]): AuthorityEntry =>
  ({
    type: "mission_resource_access",
    resource: R,
    actions,
    ...(constraints ? { constraints } : {}),
  }) as AuthorityEntry;

function refusal(fn: () => unknown): IntentError {
  try {
    fn();
  } catch (e) {
    if (e instanceof IntentError) return e;
    throw e;
  }
  throw new Error("expected an IntentError refusal");
}

const Q3 = { resource_issued_after: "2026-07-01T00:00:00Z", resource_issued_before: "2026-09-30T23:59:59Z" };

describe("derivation over resource_issued_after and resource_issued_before (@spec resource-access#common-constraints)", () => {
  it("a proposal omitting the ceiling's issuance window derives with the window, never without it", () => {
    const derived = deriveAuthoritySet(intent, policy([entry(Q3)]), [entry()]);
    expect(derived).toEqual([entry(Q3)]);
  });

  it("a proposal narrowing the window derives the intersection: the later after-bound, the earlier before-bound", () => {
    const derived = deriveAuthoritySet(intent, policy([entry(Q3)]), [
      entry({ resource_issued_after: "2026-08-01T00:00:00Z", resource_issued_before: "2026-12-31T00:00:00Z" }),
    ]);
    expect(derived).toEqual([
      entry({ resource_issued_after: "2026-08-01T00:00:00Z", resource_issued_before: "2026-09-30T23:59:59Z" }),
    ]);
  });

  it("a proposal-only bound narrows the derived entry", () => {
    const derived = deriveAuthoritySet(intent, policy([entry()]), [
      entry({ resource_issued_before: "2026-09-30T23:59:59Z" }),
    ]);
    expect(derived).toEqual([entry({ resource_issued_before: "2026-09-30T23:59:59Z" })]);
  });

  it("refuses a proposal whose window does not meet the ceiling's (contradictory windows), never omitting it", () => {
    const e = refusal(() =>
      deriveAuthoritySet(intent, policy([entry({ resource_issued_before: "2026-09-30T23:59:59Z" })]), [
        entry({ resource_issued_after: "2026-10-01T00:00:00Z" }),
      ]),
    );
    expect(e.code).toBe("invalid_authorization_details");
    expect(e.message).toMatch(/issuance window is empty/);
  });

  it("refuses a malformed bound on a directly supplied ceiling entry", () => {
    const e = refusal(() =>
      deriveAuthoritySet(intent, policy([entry({ resource_issued_after: "2026-07-01" })])),
    );
    expect(e.code).toBe("invalid_authorization_details");
  });

  it("configured-mapping mode derives the ceiling entry's window unchanged", () => {
    expect(deriveAuthoritySet(intent, policy([entry(Q3)]))).toEqual([entry(Q3)]);
  });
});

describe("effective-set projection over resource_issued_after and resource_issued_before (@spec issuance-grant#effective-set-projection)", () => {
  it("keeps the credential's window and inherits the effective side's narrower one", () => {
    const projected = projectThroughEffective(
      [entry({ resource_issued_after: "2026-08-01T00:00:00Z" })],
      [entry(Q3)],
    );
    expect(projected).toEqual([
      entry({ resource_issued_after: "2026-08-01T00:00:00Z", resource_issued_before: "2026-09-30T23:59:59Z" }),
    ]);
  });

  it("drops a fragment whose windows do not meet, rather than keeping either side's", () => {
    expect(
      projectThroughEffective(
        [entry({ resource_issued_after: "2026-10-01T00:00:00Z" })],
        [entry({ resource_issued_before: "2026-09-30T23:59:59Z" })],
      ),
    ).toEqual([]);
  });
});

describe("intake and the published schema (@spec mission#authority-proposal, resource-access#entry-validation)", () => {
  const proposal = (constraints: Record<string, unknown>) =>
    JSON.stringify([{ type: "mission_resource_access", resource: R, actions: ["invoices.read"], constraints }]);

  it("admits a well-formed issuance window in any RFC 3339 offset", () => {
    const entries = validateAuthorityProposal(
      proposal({ resource_issued_after: "2026-07-01T02:00:00+02:00", resource_issued_before: "2026-09-30T23:59:59.5Z" }),
      [R],
    );
    expect(entries[0]?.constraints?.resource_issued_after).toBe("2026-07-01T02:00:00+02:00");
  });

  it("refuses a malformed bound invalid_authorization_details", () => {
    for (const bad of ["2026-07-01", "2026-02-30T00:00:00Z", 1782864000, null]) {
      const e = refusal(() => validateAuthorityProposal(proposal({ resource_issued_before: bad }), [R]));
      expect(e.code, String(bad)).toBe("invalid_authorization_details");
    }
  });

  it("publishes exactly the supported constraint keys in the type's schema", () => {
    const constraints = (MISSION_RESOURCE_ACCESS_SCHEMA.properties as Record<string, { properties: object }>)
      .constraints;
    expect(Object.keys(constraints?.properties ?? {}).sort()).toEqual([...SUPPORTED_CONSTRAINT_KEYS].sort());
  });
});

describe("projections that cannot carry the bound refuse it (@spec resource-access#scope-projection, attenuation#root-mapping)", () => {
  const mapping = {
    rights: { type: "mission_resource_access" as const, resource: R, match: "exact" as const, actions: ["invoices.read"] },
    mandatory_controls: {},
  };

  it("scope projection refuses an entry carrying an issuance bound the scope path does not enforce", () => {
    expect(scopeValueSafeForEntry(mapping, entry())).toBe(true);
    expect(scopeValueSafeForEntry(mapping, entry({ resource_issued_after: "2026-07-01T00:00:00Z" }))).toBe(false);
    expect(scopeValueSafeForEntry(mapping, entry({ resource_issued_before: "2026-09-30T23:59:59Z" }))).toBe(false);
  });

  it("the attenuation root mapping refuses the bound rather than dropping it", () => {
    expect(() => mapAuthorityToTools([entry({ resource_issued_after: "2026-07-01T00:00:00Z" })])).toThrow(
      /unknown constraint 'resource_issued_after'/,
    );
  });
});

describe("derivation, projection and intake over tenant (@spec resource-access#initial-common-constraints)", () => {
  it("a proposal omitting the ceiling's tenant derives with it, and one naming it derives unchanged", () => {
    expect(deriveAuthoritySet(intent, policy([entry({ tenant: "acme" })]), [entry()])).toEqual([
      entry({ tenant: "acme" }),
    ]);
    expect(deriveAuthoritySet(intent, policy([entry({ tenant: "acme" })]), [entry({ tenant: "acme" })])).toEqual([
      entry({ tenant: "acme" }),
    ]);
  });

  it("refuses a proposal naming another tenant, or the same name in another case, never omitting it", () => {
    for (const other of ["globex", "Acme"]) {
      const e = refusal(() =>
        deriveAuthoritySet(intent, policy([entry({ tenant: "acme" })]), [entry({ tenant: other })]),
      );
      expect(e.code, other).toBe("invalid_authorization_details");
      expect(e.message, other).toMatch(/tenant values have no intersection/);
    }
  });

  it("projection keeps the shared tenant and drops a fragment whose tenants differ", () => {
    expect(projectThroughEffective([entry()], [entry({ tenant: "acme" })])).toEqual([entry({ tenant: "acme" })]);
    expect(projectThroughEffective([entry({ tenant: "globex" })], [entry({ tenant: "acme" })])).toEqual([]);
  });

  it("intake refuses an empty or non-string tenant", () => {
    for (const bad of ["", 42, ["acme"]]) {
      const e = refusal(() =>
        validateAuthorityProposal(
          JSON.stringify([{ type: "mission_resource_access", resource: R, actions: ["invoices.read"], constraints: { tenant: bad } }]),
          [R],
        ),
      );
      expect(e.code, JSON.stringify(bad)).toBe("invalid_authorization_details");
    }
  });

  it("scope projection and the attenuation root mapping refuse a tenant-bound entry", () => {
    const mapping = {
      rights: { type: "mission_resource_access" as const, resource: R, match: "exact" as const, actions: ["invoices.read"] },
      mandatory_controls: {},
    };
    expect(scopeValueSafeForEntry(mapping, entry({ tenant: "acme" }))).toBe(false);
    expect(() => mapAuthorityToTools([entry({ tenant: "acme" })])).toThrow(/unknown constraint 'tenant'/);
  });
});

describe("derivation, projection and intake over time_window (@spec resource-access#initial-common-constraints)", () => {
  const H2 = { not_before: "2026-07-01T00:00:00Z", not_after: "2026-12-31T23:59:59Z" };

  it("a proposal omitting the ceiling's window inherits it; one narrowing it derives the overlap", () => {
    expect(deriveAuthoritySet(intent, policy([entry({ time_window: H2 })]), [entry()])).toEqual([
      entry({ time_window: H2 }),
    ]);
    expect(
      deriveAuthoritySet(intent, policy([entry({ time_window: H2 })]), [
        entry({ time_window: { not_before: "2026-01-01T00:00:00Z", not_after: "2026-09-30T00:00:00Z" } }),
      ]),
    ).toEqual([entry({ time_window: { not_before: H2.not_before, not_after: "2026-09-30T00:00:00Z" } })]);
  });

  it("refuses a proposal whose window does not overlap the ceiling's, never omitting it", () => {
    const e = refusal(() =>
      deriveAuthoritySet(intent, policy([entry({ time_window: H2 })]), [
        entry({ time_window: { not_before: "2027-01-01T00:00:00Z" } }),
      ]),
    );
    expect(e.code).toBe("invalid_authorization_details");
    expect(e.message).toMatch(/time_window values have no intersection/);
  });

  it("projection takes the overlap and drops a fragment whose windows do not overlap", () => {
    expect(
      projectThroughEffective([entry({ time_window: { not_after: "2026-09-30T00:00:00Z" } })], [entry({ time_window: H2 })]),
    ).toEqual([entry({ time_window: { not_before: H2.not_before, not_after: "2026-09-30T00:00:00Z" } })]);
    expect(
      projectThroughEffective([entry({ time_window: { not_before: "2027-01-01T00:00:00Z" } })], [entry({ time_window: H2 })]),
    ).toEqual([]);
  });

  it("intake refuses an empty window, an unknown member, or a malformed bound", () => {
    for (const bad of [{}, { ...H2, zone: "UTC" }, { not_after: "2026-12-31" }]) {
      const e = refusal(() =>
        validateAuthorityProposal(
          JSON.stringify([{ type: "mission_resource_access", resource: R, actions: ["invoices.read"], constraints: { time_window: bad } }]),
          [R],
        ),
      );
      expect(e.code, JSON.stringify(bad)).toBe("invalid_authorization_details");
    }
  });

  it("scope projection and the attenuation root mapping refuse a windowed entry", () => {
    const mapping = {
      rights: { type: "mission_resource_access" as const, resource: R, match: "exact" as const, actions: ["invoices.read"] },
      mandatory_controls: {},
    };
    expect(scopeValueSafeForEntry(mapping, entry({ time_window: H2 }))).toBe(false);
    expect(() => mapAuthorityToTools([entry({ time_window: H2 })])).toThrow(/unknown constraint 'time_window'/);
  });
});

describe("derivation, projection and intake over recipient_domain (@spec resource-access#initial-common-constraints)", () => {
  const rd = (v: string) => ({ recipient_domain: v });

  it("a proposal omitting the ceiling's domain inherits it; a subdomain proposal derives the subdomain", () => {
    expect(deriveAuthoritySet(intent, policy([entry(rd("example.com"))]), [entry()])).toEqual([
      entry(rd("example.com")),
    ]);
    expect(
      deriveAuthoritySet(intent, policy([entry(rd("example.com"))]), [entry(rd("mail.example.com"))]),
    ).toEqual([entry(rd("mail.example.com"))]);
  });

  it("refuses a proposal naming a domain outside the ceiling's, never omitting it", () => {
    for (const other of ["example.net", "notexample.com"]) {
      const e = refusal(() => deriveAuthoritySet(intent, policy([entry(rd("example.com"))]), [entry(rd(other))]));
      expect(e.code, other).toBe("invalid_authorization_details");
      expect(e.message, other).toMatch(/recipient_domain values have no intersection/);
    }
  });

  it("projection keeps the narrower domain and drops a fragment whose domains do not nest", () => {
    expect(projectThroughEffective([entry(rd("mail.example.com"))], [entry(rd("example.com"))])).toEqual([
      entry(rd("mail.example.com")),
    ]);
    expect(projectThroughEffective([entry(rd("example.net"))], [entry(rd("example.com"))])).toEqual([]);
  });

  it("intake refuses a value that is not a DNS name", () => {
    for (const bad of ["", "a..com", "example.com.", "ex ample.com"]) {
      const e = refusal(() =>
        validateAuthorityProposal(
          JSON.stringify([{ type: "mission_resource_access", resource: R, actions: ["invoices.read"], constraints: rd(bad) }]),
          [R],
        ),
      );
      expect(e.code, bad).toBe("invalid_authorization_details");
    }
  });

  it("scope projection and the attenuation root mapping refuse a recipient-bound entry", () => {
    const mapping = {
      rights: { type: "mission_resource_access" as const, resource: R, match: "exact" as const, actions: ["invoices.read"] },
      mandatory_controls: {},
    };
    expect(scopeValueSafeForEntry(mapping, entry(rd("example.com")))).toBe(false);
    expect(() => mapAuthorityToTools([entry(rd("example.com"))])).toThrow(/unknown constraint 'recipient_domain'/);
  });
});

describe("derivation, projection and intake over data_classification (@spec resource-access#initial-common-constraints)", () => {
  const dc = (v: string[]) => ({ data_classification: v });

  it("a proposal omitting the ceiling's labels inherits them; one naming some derives the common labels", () => {
    expect(deriveAuthoritySet(intent, policy([entry(dc(["internal", "public"]))]), [entry()])).toEqual([
      entry(dc(["internal", "public"])),
    ]);
    expect(
      deriveAuthoritySet(intent, policy([entry(dc(["internal", "public"]))]), [entry(dc(["internal", "secret"]))]),
    ).toEqual([entry(dc(["internal"]))]);
  });

  it("refuses a proposal sharing no label with the ceiling, or proposing none, never omitting it", () => {
    for (const proposed of [["secret"], ["Internal"], []]) {
      const e = refusal(() =>
        deriveAuthoritySet(intent, policy([entry(dc(["internal"]))]), [entry(dc(proposed))]),
      );
      expect(e.code, JSON.stringify(proposed)).toBe("invalid_authorization_details");
      expect(e.message, JSON.stringify(proposed)).toMatch(/data_classification values have no intersection/);
    }
  });

  it("projection keeps the common labels and drops a fragment sharing none", () => {
    expect(projectThroughEffective([entry(dc(["internal", "secret"]))], [entry(dc(["internal"]))])).toEqual([
      entry(dc(["internal"])),
    ]);
    expect(projectThroughEffective([entry(dc(["secret"]))], [entry(dc(["internal"]))])).toEqual([]);
  });

  it("intake refuses a value that is not an array of non-empty strings", () => {
    for (const bad of ["internal", [""], [3]]) {
      const e = refusal(() =>
        validateAuthorityProposal(
          JSON.stringify([{ type: "mission_resource_access", resource: R, actions: ["invoices.read"], constraints: { data_classification: bad } }]),
          [R],
        ),
      );
      expect(e.code, JSON.stringify(bad)).toBe("invalid_authorization_details");
    }
  });

  it("scope projection and the attenuation root mapping refuse a classification-bound entry", () => {
    const mapping = {
      rights: { type: "mission_resource_access" as const, resource: R, match: "exact" as const, actions: ["invoices.read"] },
      mandatory_controls: {},
    };
    expect(scopeValueSafeForEntry(mapping, entry(dc(["internal"])))).toBe(false);
    expect(() => mapAuthorityToTools([entry(dc(["internal"]))])).toThrow(/unknown constraint 'data_classification'/);
  });
});

describe("derivation, projection and intake over allowed_tools (@spec resource-access#initial-common-constraints)", () => {
  const at = (v: string[]) => ({ allowed_tools: v });

  it("a proposal omitting the ceiling's tools inherits them; one naming some derives the common tools", () => {
    expect(deriveAuthoritySet(intent, policy([entry(at(["a", "b"]))]), [entry()])).toEqual([entry(at(["a", "b"]))]);
    expect(deriveAuthoritySet(intent, policy([entry(at(["a", "b"]))]), [entry(at(["b", "z"]))])).toEqual([
      entry(at(["b"])),
    ]);
  });

  it("refuses a proposal sharing no tool with the ceiling, or proposing none, never omitting it", () => {
    for (const proposed of [["z"], []]) {
      const e = refusal(() => deriveAuthoritySet(intent, policy([entry(at(["a"]))]), [entry(at(proposed))]));
      expect(e.code, JSON.stringify(proposed)).toBe("invalid_authorization_details");
      expect(e.message, JSON.stringify(proposed)).toMatch(/allowed_tools values have no intersection/);
    }
  });

  it("projection keeps the common tools and drops a fragment sharing none", () => {
    expect(projectThroughEffective([entry(at(["a", "z"]))], [entry(at(["a"]))])).toEqual([entry(at(["a"]))]);
    expect(projectThroughEffective([entry(at(["z"]))], [entry(at(["a"]))])).toEqual([]);
  });

  it("intake refuses a value that is not an array of non-empty strings", () => {
    for (const bad of ["a", [""], [3]]) {
      const e = refusal(() =>
        validateAuthorityProposal(
          JSON.stringify([{ type: "mission_resource_access", resource: R, actions: ["invoices.read"], constraints: { allowed_tools: bad } }]),
          [R],
        ),
      );
      expect(e.code, JSON.stringify(bad)).toBe("invalid_authorization_details");
    }
  });

  it("scope projection and the attenuation root mapping refuse a tool-bound entry", () => {
    const mapping = {
      rights: { type: "mission_resource_access" as const, resource: R, match: "exact" as const, actions: ["invoices.read"] },
      mandatory_controls: {},
    };
    expect(scopeValueSafeForEntry(mapping, entry(at(["a"])))).toBe(false);
    expect(() => mapAuthorityToTools([entry(at(["a"]))])).toThrow(/unknown constraint 'allowed_tools'/);
  });
});

describe("the typed config loader validates the implemented Common Constraints at load (@spec mission#derivation-policy)", () => {
  const REAL_CONFIG_DIR = fileURLToPath(new URL("../../../config", import.meta.url));
  let previous: string | undefined;
  let dir: string | undefined;

  afterEach(() => {
    if (previous === undefined) delete process.env.MISSION_CONFIG_DIR;
    else process.env.MISSION_CONFIG_DIR = previous;
    if (dir) rmSync(dir, { recursive: true, force: true });
    dir = undefined;
    vi.resetModules();
  });

  /** A copy of the shipped config whose first policy.json ceiling entry gains `constraints`. */
  function withCeilingConstraints(constraints: Record<string, unknown>): void {
    dir = mkdtempSync(join(tmpdir(), "mission-config-1266-load-"));
    const configDir = join(dir, "config");
    cpSync(REAL_CONFIG_DIR, configDir, { recursive: true });
    const file = join(configDir, "policy.json");
    const policy = JSON.parse(readFileSync(file, "utf8")) as { ceiling: { constraints?: Record<string, unknown> }[] };
    const first = policy.ceiling[0] as { constraints?: Record<string, unknown> };
    first.constraints = { ...first.constraints, ...constraints };
    writeFileSync(file, JSON.stringify(policy, null, 2));
    previous = process.env.MISSION_CONFIG_DIR;
    process.env.MISSION_CONFIG_DIR = configDir;
    vi.resetModules();
  }

  it("loads a ceiling entry carrying a well-formed issuance window, unchanged", async () => {
    withCeilingConstraints(Q3);
    const mod = await import("@mission/demo-data");
    expect(mod.DERIVATION_POLICY.ceiling[0]?.constraints).toMatchObject(Q3);
  });

  it("refuses a ceiling entry carrying a malformed issuance bound", async () => {
    withCeilingConstraints({ resource_issued_after: "2026-07-01" });
    await expect(import("@mission/demo-data")).rejects.toThrow(
      /policy\.ceiling\[0\] has malformed or unsupported authority/,
    );
  });
});
