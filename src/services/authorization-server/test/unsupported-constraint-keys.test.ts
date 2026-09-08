/**
 * @spec mission#derivation-policy, mission#common-constraints (issue #784)
 *
 * `intersect`'s fixed four-key rebuild (`derive.ts`) silently dropped any
 * `constraints` member outside {`max_amount`, `vendors`,
 * `requires_action_approval`, `terminal_when`} instead of refusing: a
 * narrowing intent that vanishes silently is a widening. The fix spans THREE
 * boundaries:
 *
 *  1. the typed config loaders (`@mission/demo-data`) — `parseCeilingEntry`
 *     (`policy.json`/`ras-policy.json`) already ran {@link isAuthorityEntry};
 *     `loadCeilingEntries` (`governed-policy.json`/`authority-sources.json`)
 *     did not, and is the loader this issue names as the real defect site.
 *  2. PAR intake (`validateAuthorityProposal` -> `validateProposedEntry` ->
 *     `validateMissionResourceAccessSchema`), whose published JSON Schema
 *     used to leave `constraints` open (`additionalProperties: true`),
 *     silently admitting a key the engine could never narrow.
 *  3. `deriveAuthoritySet` itself (review on PR #803): the first two gate
 *     only the demo JSON loader and PAR intake, but `deriveAuthoritySet` is
 *     exported and a `DerivationPolicy`/proposal can be supplied
 *     programmatically, so neither admission boundary is load-bearing for a
 *     caller that never goes through either. `deriveAuthoritySet` validates
 *     every ceiling and proposal entry itself, before any resource/action
 *     filtering narrows either array, so an entry the filter would discard
 *     untouched cannot carry an unsupported key past it either.
 *
 * `test/kernel.test.ts`'s "still fails closed on a registered-but-unimplemented
 * Common Constraint" case bypasses config load entirely (an `as never` cast
 * builds the ceiling in memory), so it proves nothing about either loader;
 * the cases below exercise the loaders themselves, and (in the last describe
 * block) `deriveAuthoritySet` directly, with no `as never` cast anywhere in
 * that block. Both a wholly unregistered key and a registered-but-unimplemented
 * one (e.g. `time_window`) are covered at every boundary: registration in the
 * Common Constraints registry is not itself support, and an unregistered,
 * deployment-defined key carries the same obligation as a registered one.
 */

import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { type AuthorityEntry, deriveAuthoritySet, IntentError, type MissionIntent, validateAuthorityProposal } from "../src/index.js";

const RESOURCE = CANONICAL_RESOURCE;

/** The shipped config dir the loaders read (src/config). */
const REAL_CONFIG_DIR = fileURLToPath(new URL("../../../config", import.meta.url));

describe("typed config loaders refuse an unsupported constraint key at load (#784)", () => {
  let previous: string | undefined;
  let dir: string | undefined;

  afterEach(() => {
    if (previous === undefined) delete process.env.MISSION_CONFIG_DIR;
    else process.env.MISSION_CONFIG_DIR = previous;
    if (dir) rmSync(dir, { recursive: true, force: true });
    dir = undefined;
    vi.resetModules();
  });

  /** A copy of the shipped config dir with the named file rewritten by `mutate`. */
  function configDirWith(file: string, mutate: (parsed: unknown) => void): string {
    dir = mkdtempSync(join(tmpdir(), "mission-config-784-"));
    const configDir = join(dir, "config");
    cpSync(REAL_CONFIG_DIR, configDir, { recursive: true });
    const filePath = join(configDir, file);
    const parsed: unknown = JSON.parse(readFileSync(filePath, "utf8"));
    mutate(parsed);
    writeFileSync(filePath, JSON.stringify(parsed, null, 2));
    previous = process.env.MISSION_CONFIG_DIR;
    process.env.MISSION_CONFIG_DIR = configDir;
    vi.resetModules();
    return configDir;
  }

  describe("parseCeilingEntry (policy.json)", () => {
    it("rejects a ceiling entry carrying a wholly unregistered constraint key", async () => {
      configDirWith("policy.json", (raw) => {
        const policy = raw as { ceiling: { constraints?: Record<string, unknown> }[] };
        const entry = policy.ceiling.find((e) => e.constraints?.vendors);
        if (entry) entry.constraints = { ...entry.constraints, unregistered_demo_key: true };
      });
      await expect(import("@mission/demo-data")).rejects.toThrow(
        /policy\.ceiling\[\d+\] has malformed or unsupported authority/,
      );
    });

    it("rejects a ceiling entry carrying a registered-but-unimplemented Common Constraint key", async () => {
      configDirWith("policy.json", (raw) => {
        const policy = raw as { ceiling: { constraints?: Record<string, unknown> }[] };
        const entry = policy.ceiling.find((e) => e.constraints?.vendors);
        if (entry) {
          entry.constraints = {
            ...entry.constraints,
            time_window: { not_before: "2026-01-01T00:00:00Z" },
          };
        }
      });
      await expect(import("@mission/demo-data")).rejects.toThrow(
        /policy\.ceiling\[\d+\] has malformed or unsupported authority/,
      );
    });
  });

  describe("loadCeilingEntries (governed-policy.json)", () => {
    it("rejects a governed ceiling entry carrying a wholly unregistered constraint key", async () => {
      configDirWith("governed-policy.json", (raw) => {
        const policies = raw as { ceiling: { constraints?: Record<string, unknown> }[] }[];
        const entry = policies[0]?.ceiling.find((e) => e.constraints?.vendors);
        if (entry) entry.constraints = { ...entry.constraints, unregistered_demo_key: true };
      });
      await expect(import("@mission/demo-data")).rejects.toThrow(
        /governed-policy\[\d+\]\.ceiling\[\d+\] has malformed or unsupported authority/,
      );
    });

    it("rejects a governed ceiling entry carrying a registered-but-unimplemented Common Constraint key", async () => {
      configDirWith("governed-policy.json", (raw) => {
        const policies = raw as { ceiling: { constraints?: Record<string, unknown> }[] }[];
        const entry = policies[0]?.ceiling.find((e) => e.constraints?.vendors);
        if (entry) {
          entry.constraints = {
            ...entry.constraints,
            time_window: { not_before: "2026-01-01T00:00:00Z" },
          };
        }
      });
      await expect(import("@mission/demo-data")).rejects.toThrow(
        /governed-policy\[\d+\]\.ceiling\[\d+\] has malformed or unsupported authority/,
      );
    });

    it("loads the fixture dir, not a cached module (positive control for the four negatives above)", async () => {
      configDirWith("policy.json", (raw) => {
        (raw as { policy_version: string }).policy_version = "unsupported-constraint-keys-fixture-784";
      });
      const mod = await import("@mission/demo-data");
      expect(mod.DERIVATION_POLICY.policy_version).toBe("unsupported-constraint-keys-fixture-784");
    });
  });
});

describe("PAR intake refuses an unsupported constraint key (#784)", () => {
  const proposal = (actions: string[], constraints?: Record<string, unknown>) =>
    JSON.stringify([
      { type: "mission_resource_access", resource: RESOURCE, actions, ...(constraints ? { constraints } : {}) },
    ]);

  it("refuses invalid_authorization_details for a wholly unregistered constraint key", () => {
    try {
      validateAuthorityProposal(
        proposal(["payments:invoice.list"], { unregistered_demo_key: true }),
        [RESOURCE],
      );
      expect.unreachable("an unsupported constraint key must be refused, not silently dropped");
    } catch (e) {
      expect(e).toBeInstanceOf(IntentError);
      expect((e as IntentError).code).toBe("invalid_authorization_details");
      expect((e as IntentError).message).toMatch(/unregistered_demo_key/);
    }
  });

  it("refuses invalid_authorization_details for a registered-but-unimplemented Common Constraint key", () => {
    try {
      validateAuthorityProposal(
        proposal(["payments:invoice.list"], { time_window: { not_before: "2026-01-01T00:00:00Z" } }),
        [RESOURCE],
      );
      expect.unreachable("a registered-but-unimplemented key must be refused, not silently dropped");
    } catch (e) {
      expect(e).toBeInstanceOf(IntentError);
      expect((e as IntentError).code).toBe("invalid_authorization_details");
      expect((e as IntentError).message).toMatch(/time_window/);
    }
  });

  it("still admits requires_action_approval unchanged (no regression from closing the member set)", () => {
    const entries = validateAuthorityProposal(
      proposal(["payments:invoice.list"], { requires_action_approval: true }),
      [RESOURCE],
    );
    expect(entries[0]?.constraints?.requires_action_approval).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Direct derivation (review on PR #803, P2): `deriveAuthoritySet` is exported
// and a `DerivationPolicy`/proposal can be built and supplied programmatically,
// so neither loader above nor PAR intake is load-bearing for a caller that
// never goes through either. Every ceiling/proposal literal below is built
// the way the owner's own reproduction at the PR head was: `constraints` is
// assigned from a plain variable, never an inline object literal, so each
// case type-checks with no `as never` cast anywhere in this block.
// ---------------------------------------------------------------------------
describe("direct derivation (deriveAuthoritySet) refuses an unsupported constraint key with no config loader or PAR intake in the call path (#784, review on PR #803)", () => {
  const intent: MissionIntent = {
    goal: "g",
    target_resources: [RESOURCE],
    expires_at: "2027-01-01T00:00:00Z",
  };

  it("configured-mapping mode refuses a wholly unregistered constraints key on a directly-supplied ceiling entry", () => {
    const constraints = { vendors: ["acme"], review_unknown_limit: 1 };
    const ceiling: AuthorityEntry[] = [
      { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"], constraints },
    ];
    try {
      deriveAuthoritySet(intent, { policy_version: "review", ceiling });
      expect.unreachable("an unsupported constraints key must be refused, not silently dropped");
    } catch (e) {
      expect(e).toBeInstanceOf(IntentError);
      expect((e as IntentError).code).toBe("invalid_authorization_details");
      expect((e as IntentError).message).toMatch(/review_unknown_limit/);
    }
  });

  it("configured-mapping mode refuses a registered-but-unimplemented Common Constraint key on a directly-supplied ceiling entry", () => {
    const constraints = { time_window: { not_before: "2026-01-01T00:00:00Z" } };
    const ceiling: AuthorityEntry[] = [
      { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"], constraints },
    ];
    try {
      deriveAuthoritySet(intent, { policy_version: "review", ceiling });
      expect.unreachable("a registered-but-unimplemented key must be refused, not silently dropped");
    } catch (e) {
      expect(e).toBeInstanceOf(IntentError);
      expect((e as IntentError).code).toBe("invalid_authorization_details");
      expect((e as IntentError).message).toMatch(/time_window/);
    }
  });

  // Positive control (review's "keep positive vendors coverage"): the same
  // direct call, bypassing every loader and PAR intake, still derives a
  // supported vendors-only ceiling entry normally. Without this the two
  // refusals above could pass by making derivation refuse everything.
  it("positive control: a supported vendors-only ceiling entry still derives, narrowed, through the same direct call", () => {
    const constraints = { vendors: ["acme"] };
    const ceiling: AuthorityEntry[] = [
      { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"], constraints },
    ];
    const derived = deriveAuthoritySet(intent, { policy_version: "review", ceiling });
    expect(derived).toHaveLength(1);
    expect(derived[0]?.constraints?.vendors).toEqual(["acme"]);
  });

  // @spec mission#common-constraints (review on PR #803, finding 2) — a
  // proposal entry naming a resource NO ceiling entry shares must still
  // refuse an unsupported key: `matchingCeilings` filters it to nothing, so
  // it would never reach `intersect` even under a fix that validated only at
  // that pairing. A sibling proposal entry that DOES derive successfully
  // proves the whole call would otherwise have returned normally, masking
  // the second entry's violation entirely.
  it("submitted-proposal mode refuses an unsupported key on a proposal entry no ceiling entry shares a resource with, even though a sibling entry derives fine", () => {
    const ceiling: AuthorityEntry[] = [
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:invoice.read"],
        constraints: { vendors: ["acme"] },
      },
    ];
    const badConstraints = { review_unknown_limit: 1 };
    const proposal: AuthorityEntry[] = [
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:invoice.read"],
        constraints: { vendors: ["acme"] },
      },
      {
        type: "mission_resource_access",
        resource: "https://unmapped.example.com",
        actions: ["read"],
        constraints: badConstraints,
      },
    ];
    try {
      deriveAuthoritySet(intent, { policy_version: "review", ceiling }, proposal);
      expect.unreachable("an unsupported key on an unmatched proposal entry must still refuse");
    } catch (e) {
      expect(e).toBeInstanceOf(IntentError);
      expect((e as IntentError).message).toMatch(/review_unknown_limit/);
    }
  });

  // Same shape, ceiling side: a second same-resource ceiling entry whose
  // actions the submitted proposal never names would have its `intersect`
  // pairing return null on the action filter BEFORE any constraint check the
  // prior code ran there, while the FIRST ceiling entry still lets derivation
  // succeed. Only validating the full ceiling array up front catches it.
  it("submitted-proposal mode refuses a registered-but-unimplemented key on a ceiling entry no submitted action overlaps, even though another same-resource entry derives fine", () => {
    const timeWindow = { time_window: { not_before: "2026-01-01T00:00:00Z" } };
    const ceiling: AuthorityEntry[] = [
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:invoice.read"],
        constraints: { vendors: ["acme"] },
      },
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:payment.execute"],
        constraints: timeWindow,
      },
    ];
    const proposal: AuthorityEntry[] = [
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:invoice.read"],
        constraints: { vendors: ["acme"] },
      },
    ];
    try {
      deriveAuthoritySet(intent, { policy_version: "review", ceiling }, proposal);
      expect.unreachable("a registered-but-unimplemented key must refuse even on an action-filtered-out ceiling entry");
    } catch (e) {
      expect(e).toBeInstanceOf(IntentError);
      expect((e as IntentError).message).toMatch(/time_window/);
    }
  });
});
