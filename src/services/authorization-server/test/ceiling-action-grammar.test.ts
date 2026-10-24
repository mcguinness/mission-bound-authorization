/**
 * @spec resource-access#entry-validation (issue #1625)
 *
 * A configured ceiling entry's `actions` are held to the action grammar
 * proposal intake applies (an action identifier, `[A-Za-z0-9_.:-]+` as a whole,
 * or an action family, an identifier followed by `.*`). Before #1625 both
 * typed ceiling loaders read `actions` as any non-empty strings, so a value no
 * admitted proposal can carry loaded clean and silently granted nothing. Each
 * loader now refuses it at load, naming the entry and the value.
 *
 * The resource rule is resource-uri-syntax.test.ts (#1310); template ceilings
 * are template.test.ts and template-consent-page.test.ts.
 */

import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";

const REAL_CONFIG_DIR = fileURLToPath(new URL("../../../config", import.meta.url));

/** Action values outside the grammar, each of which loaded before #1625. */
const OUTSIDE: readonly string[] = ["invoices/read", "invoices.read ", "invoices read", "invoices.*.read", "*"];

describe("config loaders refuse a ceiling entry whose action is outside the action grammar (#1625)", () => {
  const previous = process.env.MISSION_CONFIG_DIR;
  let dir: string | undefined;

  afterEach(() => {
    if (previous === undefined) delete process.env.MISSION_CONFIG_DIR;
    else process.env.MISSION_CONFIG_DIR = previous;
    if (dir) rmSync(dir, { recursive: true, force: true });
    dir = undefined;
    vi.resetModules();
  });

  /** A copy of the shipped config dir with the named file rewritten by `mutate`. */
  function configDirWith(file: string, mutate: (parsed: unknown) => void): void {
    if (dir) rmSync(dir, { recursive: true, force: true });
    dir = mkdtempSync(join(tmpdir(), "mission-config-1625-"));
    const configDir = join(dir, "config");
    cpSync(REAL_CONFIG_DIR, configDir, { recursive: true });
    const filePath = join(configDir, file);
    const parsed: unknown = JSON.parse(readFileSync(filePath, "utf8"));
    mutate(parsed);
    writeFileSync(filePath, JSON.stringify(parsed, null, 2));
    process.env.MISSION_CONFIG_DIR = configDir;
    vi.resetModules();
  }

  const refused = (file: string, ctx: string, value: string) =>
    `[config:${file}] ${ctx} has action ${JSON.stringify(value)}, which is neither an action identifier nor an action family`;

  /** Appends `value` to the first ceiling entry's actions. */
  const appendAction = (ceiling: Record<string, unknown>[], value: string) => {
    (ceiling[0] as { actions: string[] }).actions.push(value);
  };

  it("parseCeilingEntry (policy.json) rejects each value outside the grammar, naming the entry and the value", async () => {
    for (const value of OUTSIDE) {
      configDirWith("policy.json", (raw) => appendAction((raw as { ceiling: Record<string, unknown>[] }).ceiling, value));
      await expect(import("@mission/demo-data"), JSON.stringify(value)).rejects.toThrow(
        refused("policy.json", "policy.ceiling[0]", value),
      );
    }
  });

  it("parseCeilingEntry (ras-policy.json) rejects an action with a slash, naming the entry and the value", async () => {
    configDirWith("ras-policy.json", (raw) =>
      appendAction((raw as { ceiling: Record<string, unknown>[] }).ceiling, "invoices/read"),
    );
    await expect(import("@mission/demo-data")).rejects.toThrow(
      refused("ras-policy.json", "ras-policy.ceiling[0]", "invoices/read"),
    );
  });

  it("loadCeilingEntries (governed-policy.json) rejects a bare *, naming the entry and the value", async () => {
    configDirWith("governed-policy.json", (raw) =>
      appendAction((raw as { ceiling: Record<string, unknown>[] }[])[0]?.ceiling as Record<string, unknown>[], "*"),
    );
    await expect(import("@mission/demo-data")).rejects.toThrow(
      refused("governed-policy.json", "governed-policy[0].ceiling[0]", "*"),
    );
  });

  it("loadCeilingEntries (authority-sources.json) rejects a family not at the end, naming the entry and the value", async () => {
    const sources = (JSON.parse(readFileSync(join(REAL_CONFIG_DIR, "authority-sources.json"), "utf8")) as {
      sources: { ceiling?: unknown }[];
    }).sources;
    const index = sources.findIndex((s) => Array.isArray(s.ceiling));
    expect(index).toBeGreaterThanOrEqual(0);
    configDirWith("authority-sources.json", (raw) =>
      appendAction(
        (raw as { sources: { ceiling?: unknown }[] }).sources[index]?.ceiling as Record<string, unknown>[],
        "invoices.*.read",
      ),
    );
    await expect(import("@mission/demo-data")).rejects.toThrow(
      refused("authority-sources.json", `authority-sources.sources[${index}].ceiling[0]`, "invoices.*.read"),
    );
  });

  it("the shipped configuration loads, its actions unchanged (positive control for the refusals)", async () => {
    configDirWith("policy.json", (raw) => {
      (raw as { policy_version: string }).policy_version = "action-grammar-fixture-1625";
    });
    const mod = await import("@mission/demo-data");
    expect(mod.DERIVATION_POLICY.policy_version).toBe("action-grammar-fixture-1625");
    const shipped = (JSON.parse(readFileSync(join(REAL_CONFIG_DIR, "policy.json"), "utf8")) as {
      ceiling: { actions: string[] }[];
    }).ceiling.map((e) => e.actions);
    expect(mod.DERIVATION_POLICY.ceiling.map((e) => e.actions)).toEqual(shipped);
  });
});
