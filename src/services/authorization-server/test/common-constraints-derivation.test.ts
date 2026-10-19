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
