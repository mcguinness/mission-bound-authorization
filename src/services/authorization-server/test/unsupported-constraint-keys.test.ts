/**
 * @spec mission#derivation-policy, mission#common-constraints (issue #784)
 *
 * `intersect`'s fixed four-key rebuild (`derive.ts`) silently dropped any
 * `constraints` member outside {`max_amount`, `vendors`,
 * `requires_action_approval`, `terminal_when`} instead of refusing: a
 * narrowing intent that vanishes silently is a widening. The fix is at the
 * TWO admission boundaries that feed derivation, so `intersect` never sees an
 * unsupported key in the first place:
 *
 *  1. the typed config loaders (`@mission/demo-data`) — `parseCeilingEntry`
 *     (`policy.json`/`ras-policy.json`) already ran {@link isAuthorityEntry};
 *     `loadCeilingEntries` (`governed-policy.json`/`authority-sources.json`)
 *     did not, and is the loader this issue names as the real defect site.
 *  2. PAR intake (`validateAuthorityProposal` -> `validateProposedEntry` ->
 *     `validateMissionResourceAccessSchema`), whose published JSON Schema
 *     used to leave `constraints` open (`additionalProperties: true`),
 *     silently admitting a key the engine could never narrow.
 *
 * `test/kernel.test.ts`'s "still fails closed on a registered-but-unimplemented
 * Common Constraint" case bypasses config load entirely (an `as never` cast
 * builds the ceiling in memory), so it proves nothing about either loader;
 * the cases below exercise the loaders themselves. Both a wholly unregistered
 * key and a registered-but-unimplemented one (e.g. `time_window`) are covered
 * at each boundary: registration in the Common Constraints registry is not
 * itself support, and an unregistered, deployment-defined key carries the
 * same obligation as a registered one.
 */

import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { IntentError, validateAuthorityProposal } from "../src/index.js";

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
