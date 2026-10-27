/**
 * @spec resource-access#initial-common-constraints, resource-access#entry-validation (#1376, D858)
 *
 * The authorization server generates no Common Constraint value the profile
 * forbids: a configured ceiling entry whose date-time value uses `60` for the
 * seconds field, or whose `recipient_domain` carries an `xn--` label that is
 * not a structurally valid A-label, fails to load, so no entry derived from it
 * is ever issued. PAR's refusal of the same values is in entry-validation.test.ts.
 */

import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";

const REAL_CONFIG_DIR = fileURLToPath(new URL("../../../config", import.meta.url));

describe("a configured ceiling carrying a forbidden Common Constraint value fails to load (#1376, D858)", () => {
  let previous: string | undefined;
  let dir: string | undefined;

  afterEach(() => {
    if (previous === undefined) delete process.env.MISSION_CONFIG_DIR;
    else process.env.MISSION_CONFIG_DIR = previous;
    if (dir) rmSync(dir, { recursive: true, force: true });
    dir = undefined;
    vi.resetModules();
  });

  /** A copy of the shipped config dir whose first policy.json ceiling entry gains `constraints`. */
  function ceilingWith(constraints: Record<string, unknown>): void {
    // Called more than once in one test: keep the original value to restore.
    if (dir) rmSync(dir, { recursive: true, force: true });
    else previous = process.env.MISSION_CONFIG_DIR;
    dir = mkdtempSync(join(tmpdir(), "mission-config-1376-"));
    const configDir = join(dir, "config");
    cpSync(REAL_CONFIG_DIR, configDir, { recursive: true });
    const filePath = join(configDir, "policy.json");
    const parsed = JSON.parse(readFileSync(filePath, "utf8")) as {
      ceiling: { constraints?: Record<string, unknown> }[];
    };
    const first = parsed.ceiling[0] as { constraints?: Record<string, unknown> };
    first.constraints = { ...first.constraints, ...constraints };
    writeFileSync(filePath, JSON.stringify(parsed, null, 2));
    process.env.MISSION_CONFIG_DIR = configDir;
    vi.resetModules();
  }

  const REFUSED = /policy\.ceiling\[0\] has malformed or unsupported authority/;

  it("refuses a date-time value that uses 60 for the seconds field: an actual leap second, its offset equivalent, an invalid :60", async () => {
    for (const constraints of [
      { time_window: { not_after: "2016-12-31T23:59:60Z" } },
      { resource_issued_after: "2017-01-01T00:59:60+01:00" },
      { resource_issued_before: "2026-09-01T12:00:60Z" },
    ]) {
      ceilingWith(constraints);
      await expect(import("@mission/demo-data"), JSON.stringify(constraints)).rejects.toThrow(REFUSED);
    }
  });

  it("refuses a recipient_domain whose xn-- label is not a structurally valid A-label", async () => {
    ceilingWith({ recipient_domain: "xn--mnchen-psa.example" });
    await expect(import("@mission/demo-data")).rejects.toThrow(REFUSED);
  });

  it("loads the same ceiling with ordinary timestamps and a valid A-label, keeping them (positive control)", async () => {
    const constraints = {
      time_window: { not_after: "2016-12-31T23:59:59Z" },
      resource_issued_after: "2017-01-01T00:59:59+01:00",
      recipient_domain: "XN--Mnchen-3YA.example",
    };
    ceilingWith(constraints);
    const mod = await import("@mission/demo-data");
    expect(mod.DERIVATION_POLICY.ceiling[0]?.constraints).toMatchObject(constraints);
  });
});
