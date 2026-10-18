/**
 * @spec resource-access#resource-matching (issue #1264, D446)
 *
 * This deployment implements `exact` resource matching only. Before #1264,
 * an entry naming `resource_match: "prefix"` was admitted and then rebuilt
 * without the member by the config loaders and by derivation's `intersect`,
 * silently becoming an exact entry: narrower for a ceiling or proposal, wider
 * for a containment removal. Every boundary now refuses any value other than
 * `exact`, before approval or issuance. PAR intake is covered in
 * rar-carriage.test.ts; the config loaders and direct derivation are here.
 */

import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { type AuthorityEntry, deriveAuthoritySet, IntentError, type MissionIntent } from "../src/index.js";

const REAL_CONFIG_DIR = fileURLToPath(new URL("../../../config", import.meta.url));
const UNSUPPORTED = /resource_match "prefix"; this deployment implements exact resource matching only/;

describe("config loaders refuse an unsupported resource_match at load (#1264)", () => {
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
  function configDirWith(file: string, mutate: (parsed: unknown) => void): void {
    dir = mkdtempSync(join(tmpdir(), "mission-config-1264-"));
    const configDir = join(dir, "config");
    cpSync(REAL_CONFIG_DIR, configDir, { recursive: true });
    const filePath = join(configDir, file);
    const parsed: unknown = JSON.parse(readFileSync(filePath, "utf8"));
    mutate(parsed);
    writeFileSync(filePath, JSON.stringify(parsed, null, 2));
    previous = process.env.MISSION_CONFIG_DIR;
    process.env.MISSION_CONFIG_DIR = configDir;
    vi.resetModules();
  }

  it("parseCeilingEntry (policy.json) rejects a ceiling entry naming resource_match prefix", async () => {
    configDirWith("policy.json", (raw) => {
      (raw as { ceiling: Record<string, unknown>[] }).ceiling[0].resource_match = "prefix";
    });
    await expect(import("@mission/demo-data")).rejects.toThrow(UNSUPPORTED);
  });

  it("loadCeilingEntries (governed-policy.json) rejects a governed ceiling entry naming resource_match prefix", async () => {
    configDirWith("governed-policy.json", (raw) => {
      (raw as { ceiling: Record<string, unknown>[] }[])[0].ceiling[0].resource_match = "prefix";
    });
    await expect(import("@mission/demo-data")).rejects.toThrow(UNSUPPORTED);
  });

  it("the containment loader rejects a removal entry naming resource_match prefix", async () => {
    configDirWith("containment.json", (raw) => {
      (raw as { rules: { remove: Record<string, unknown>[] }[] }).rules[0].remove[0].resource_match = "prefix";
    });
    await expect(import("@mission/demo-data")).rejects.toThrow(UNSUPPORTED);
  });

  it("an explicit resource_match exact loads (positive control for the three refusals)", async () => {
    configDirWith("policy.json", (raw) => {
      const policy = raw as { policy_version: string; ceiling: Record<string, unknown>[] };
      policy.policy_version = "resource-match-fixture-1264";
      policy.ceiling[0].resource_match = "exact";
    });
    const mod = await import("@mission/demo-data");
    expect(mod.DERIVATION_POLICY.policy_version).toBe("resource-match-fixture-1264");
  });
});

describe("direct derivation (deriveAuthoritySet) refuses an unsupported resource_match (#1264)", () => {
  const intent: MissionIntent = {
    purpose: "Read invoices for the quarterly close",
    target_resources: [CANONICAL_RESOURCE],
  } as MissionIntent;
  const entry = (extra: Record<string, unknown> = {}): AuthorityEntry =>
    ({
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:invoice.read"],
      ...extra,
    }) as AuthorityEntry;
  const policy = (ceiling: AuthorityEntry[]) => ({ policy_version: "resource-match-1264", ceiling });

  function refusal(fn: () => unknown): IntentError {
    try {
      fn();
    } catch (e) {
      if (e instanceof IntentError) return e;
      throw e;
    }
    throw new Error("expected an IntentError");
  }

  it("refuses a ceiling entry naming resource_match prefix", () => {
    const e = refusal(() => deriveAuthoritySet(intent, policy([entry({ resource_match: "prefix" })])));
    expect(e.code).toBe("invalid_authorization_details");
    expect(e.message).toMatch(/resource_match "prefix"/);
  });

  it("refuses a submitted proposal entry naming resource_match prefix", () => {
    const e = refusal(() => deriveAuthoritySet(intent, policy([entry()]), [entry({ resource_match: "prefix" })]));
    expect(e.code).toBe("invalid_authorization_details");
    expect(e.message).toMatch(/resource_match "prefix"/);
  });

  it("derives a proposal naming an explicit resource_match exact (positive control)", () => {
    const derived = deriveAuthoritySet(intent, policy([entry()]), [entry({ resource_match: "exact" })]);
    expect(derived).toHaveLength(1);
    expect(derived[0]?.actions).toEqual(["payments:invoice.read"]);
  });
});
