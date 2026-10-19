/**
 * @spec resource-access#entry-validation, mission#mission-intent (issue #1310, D480)
 *
 * Every resource identifier the issuer accepts is one RFC 3986 absolute URI
 * under one shared check (`isAbsoluteUri`, the grammar operation targets use):
 * a Mission Intent's `target_resources`, and a `mission_resource_access`
 * entry's `resource` at the proposal intake, at configuration load and at
 * direct derivation. Before #1310 the Intent check was a WHATWG `new URL()`
 * parse, which accepts `%zz`, `https:x` and `https:///x` and refuses an
 * IPvFuture literal, and an entry's `resource` was checked only as a string.
 * Validation answers yes or no: an accepted value keeps its spelling.
 *
 * PAR is in rar-carriage.test.ts.
 */

import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import {
  type AuthorityEntry,
  deriveAuthoritySet,
  IntentError,
  MISSION_RESOURCE_ACCESS_TYPE,
  type MissionIntent,
  validateAuthorityProposal,
  validateMissionIntent,
  validateMissionResourceAccessSchema,
} from "../src/index.js";

const REAL_CONFIG_DIR = fileURLToPath(new URL("../../../config", import.meta.url));

/** Values RFC 3986 `absolute-URI` refuses, several of which `new URL()` accepts. */
const MALFORMED: ReadonlyArray<readonly [string, string]> = [
  ["an invalid percent-encoding", "https://erp.example.com/%zz"],
  ["a trailing percent", "https://erp.example.com/a%"],
  ["a truncated percent-encoding", "https://erp.example.com/%4"],
  ["an http(s) URI with no authority", "https:x"],
  ["an http(s) URI with an empty host", "https:///x"],
  ["a raw space", "https://erp.example.com/a b"],
  ["a fragment", "https://erp.example.com/a#b"],
];

/** Well-formed values, recorded with their spelling unchanged. */
const WELL_FORMED: readonly string[] = [
  "https://erp.example.com/%41",
  "https://erp.example.com/a%2Fb",
  "https://[v1.fe80::a+b]/invoices",
  "https://erp.example.com/invoices?q=a&b=$,;",
];

const entry = (resource: string): AuthorityEntry =>
  ({ type: MISSION_RESOURCE_ACCESS_TYPE, resource, actions: ["payments:invoice.read"] }) as AuthorityEntry;

const intentJson = (targetResources: string[]): string =>
  JSON.stringify({
    goal: "Reconcile invoices",
    target_resources: targetResources,
    expires_at: "2099-01-01T00:00:00Z",
  });

function refusal(fn: () => unknown): IntentError {
  try {
    fn();
  } catch (e) {
    if (e instanceof IntentError) return e;
    throw e;
  }
  throw new Error("expected an IntentError");
}

describe("Mission Intent target_resources are RFC 3986 absolute URIs (#1310)", () => {
  it("validateMissionIntent refuses each malformed value with invalid_request", () => {
    for (const [name, value] of MALFORMED) {
      const e = refusal(() => validateMissionIntent(intentJson([CANONICAL_RESOURCE, value])));
      expect(e.code, name).toBe("invalid_request");
      expect(e.message, name).toBe(`resource is not an absolute URI: ${value}`);
    }
  });

  it("admits each well-formed value, keeping its spelling (positive control)", () => {
    const intent = validateMissionIntent(intentJson([CANONICAL_RESOURCE, ...WELL_FORMED]));
    expect(intent.target_resources).toEqual([CANONICAL_RESOURCE, ...WELL_FORMED]);
  });
});

describe("an entry's resource is an RFC 3986 absolute URI at the proposal intake (#1310)", () => {
  it("validateMissionResourceAccessSchema refuses each malformed resource, naming it", () => {
    for (const [name, value] of MALFORMED) {
      expect(validateMissionResourceAccessSchema(entry(value)), name).toBe(
        `resource ${JSON.stringify(value)} is not an RFC 3986 absolute URI`,
      );
    }
  });

  it("validateAuthorityProposal, the PAR and device proposal intake, refuses each with invalid_authorization_details", () => {
    for (const [name, value] of MALFORMED) {
      const e = refusal(() => validateAuthorityProposal(JSON.stringify([entry(value)]), [value]));
      expect(e.code, name).toBe("invalid_authorization_details");
      expect(e.message, name).toMatch(/is not an RFC 3986 absolute URI/);
    }
  });

  it("admits each well-formed resource unchanged (positive control)", () => {
    for (const value of WELL_FORMED) {
      expect(validateMissionResourceAccessSchema(entry(value)), value).toBeUndefined();
      expect(validateAuthorityProposal(JSON.stringify([entry(value)]), [value])).toEqual([entry(value)]);
    }
  });
});

describe("config loaders refuse a ceiling entry whose resource is not an RFC 3986 absolute URI (#1310)", () => {
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
    dir = mkdtempSync(join(tmpdir(), "mission-config-1310-"));
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

  const refused = (file: string, ctx: string, value: string) =>
    `[config:${file}] ${ctx} has resource ${JSON.stringify(value)}, which is not an RFC 3986 absolute URI`;

  it("parseCeilingEntry (policy.json) rejects a ceiling entry with a malformed percent-encoding, naming the entry and the value", async () => {
    configDirWith("policy.json", (raw) => {
      (raw as { ceiling: Record<string, unknown>[] }).ceiling[0].resource = "https://erp.example.com/%zz";
    });
    await expect(import("@mission/demo-data")).rejects.toThrow(
      refused("policy.json", "policy.ceiling[0]", "https://erp.example.com/%zz"),
    );
  });

  it("parseCeilingEntry (ras-policy.json) rejects a ceiling entry with no authority, naming the entry and the value", async () => {
    configDirWith("ras-policy.json", (raw) => {
      (raw as { ceiling: Record<string, unknown>[] }).ceiling[0].resource = "https:x";
    });
    await expect(import("@mission/demo-data")).rejects.toThrow(
      refused("ras-policy.json", "ras-policy.ceiling[0]", "https:x"),
    );
  });

  it("loadCeilingEntries (governed-policy.json) rejects a governed ceiling entry with an empty host, naming the entry and the value", async () => {
    configDirWith("governed-policy.json", (raw) => {
      (raw as { ceiling: Record<string, unknown>[] }[])[0].ceiling[0].resource = "https:///x";
    });
    await expect(import("@mission/demo-data")).rejects.toThrow(
      refused("governed-policy.json", "governed-policy[0].ceiling[0]", "https:///x"),
    );
  });

  it("loadCeilingEntries (authority-sources.json) rejects a source ceiling entry carrying a fragment, naming the entry and the value", async () => {
    const value = `${CANONICAL_RESOURCE}#frag`;
    configDirWith("authority-sources.json", (raw) => {
      const sources = (raw as { sources: { ceiling?: unknown }[] }).sources;
      const index = sources.findIndex((s) => Array.isArray(s.ceiling));
      expect(index).toBeGreaterThanOrEqual(0);
      (sources[index]?.ceiling as Record<string, unknown>[])[0].resource = value;
    });
    const sources = (JSON.parse(readFileSync(join(REAL_CONFIG_DIR, "authority-sources.json"), "utf8")) as {
      sources: { ceiling?: unknown }[];
    }).sources;
    const index = sources.findIndex((s) => Array.isArray(s.ceiling));
    await expect(import("@mission/demo-data")).rejects.toThrow(
      refused("authority-sources.json", `authority-sources.sources[${index}].ceiling[0]`, value),
    );
  });

  it("the shipped configuration loads, its resources unchanged (positive control for the four refusals)", async () => {
    configDirWith("policy.json", (raw) => {
      (raw as { policy_version: string }).policy_version = "resource-uri-fixture-1310";
    });
    const mod = await import("@mission/demo-data");
    expect(mod.DERIVATION_POLICY.policy_version).toBe("resource-uri-fixture-1310");
    const shipped = (JSON.parse(readFileSync(join(REAL_CONFIG_DIR, "policy.json"), "utf8")) as {
      ceiling: { resource: string }[];
    }).ceiling.map((e) => e.resource);
    expect(mod.DERIVATION_POLICY.ceiling.map((e) => e.resource)).toEqual(shipped);
  });
});

describe("direct derivation (deriveAuthoritySet) refuses an entry whose resource is not an RFC 3986 absolute URI (#1310)", () => {
  const intent = (resources: string[]) =>
    ({ goal: "Reconcile invoices", target_resources: resources }) as unknown as MissionIntent;
  const policy = (ceiling: AuthorityEntry[]) => ({ policy_version: "resource-uri-1310", ceiling });

  it("refuses a ceiling entry with each malformed resource", () => {
    for (const [name, value] of MALFORMED) {
      const e = refusal(() => deriveAuthoritySet(intent([CANONICAL_RESOURCE]), policy([entry(CANONICAL_RESOURCE), entry(value)])));
      expect(e.code, name).toBe("invalid_authorization_details");
      expect(e.message, name).toMatch(/is not an RFC 3986 absolute URI/);
    }
  });

  it("refuses a submitted proposal entry with each malformed resource", () => {
    for (const [name, value] of MALFORMED) {
      const e = refusal(() =>
        deriveAuthoritySet(intent([CANONICAL_RESOURCE]), policy([entry(CANONICAL_RESOURCE)]), [entry(value)]),
      );
      expect(e.code, name).toBe("invalid_authorization_details");
      expect(e.message, name).toMatch(/is not an RFC 3986 absolute URI/);
    }
  });

  it("derives from a well-formed resource, keeping its spelling (positive control)", () => {
    for (const value of WELL_FORMED) {
      const derived = deriveAuthoritySet(intent([value]), policy([entry(value)]), [entry(value)]);
      expect(derived.map((e) => e.resource), value).toEqual([value]);
    }
  });
});
