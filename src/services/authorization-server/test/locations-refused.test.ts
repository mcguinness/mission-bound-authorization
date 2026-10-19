/**
 * @spec resource-access#entry-validation (issue #1278, D454, D457)
 *
 * Mission Resource Access does not use the RFC 9396 common `locations` field,
 * and the authorization server refuses an entry carrying it. Before #1278 the
 * advertised schema admitted the member and derivation's member-by-member
 * rebuild dropped it. The refusal is by presence, whatever the value, and by
 * name, so the entry's top level stays open to a member another specification
 * defines for this type (`capability_sources`).
 *
 * The schema, the shared validator, the config loaders and direct derivation
 * are covered here. PAR is in rar-carriage.test.ts, device submission in
 * device-authorization.test.ts, and the deferred, dispatch handoff,
 * async-delegation and template intakes in their own files.
 */

import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import {
  type AuthorityEntry,
  authorizationDetailsTypesMetadata,
  deriveAuthoritySet,
  IntentError,
  MISSION_RESOURCE_ACCESS_TYPE,
  type MissionIntent,
  validateAuthorityProposal,
  validateMissionResourceAccessSchema,
} from "../src/index.js";

const REAL_CONFIG_DIR = fileURLToPath(new URL("../../../config", import.meta.url));
const OTHER_RESOURCE = "https://erp.example.com";

/** Every kind of value the presence check must refuse, including the falsy ones. */
const VALUES: ReadonlyArray<readonly [string, unknown]> = [
  ["a populated array", [CANONICAL_RESOURCE]],
  ["an empty array", []],
  ["null", null],
  ["an empty string", ""],
  ["a malformed object", { uri: CANONICAL_RESOURCE }],
];

const entry = (extra: Record<string, unknown> = {}, resource = CANONICAL_RESOURCE): AuthorityEntry =>
  ({
    type: MISSION_RESOURCE_ACCESS_TYPE,
    resource,
    actions: ["payments:invoice.read"],
    ...extra,
  }) as AuthorityEntry;

/** A well-formed capability-source binding, the shape the trusted catalog records. */
const BINDING = {
  action: "payments:invoice.read",
  tool_id: "mcp://payments.test/tools/get_invoice",
  source_uri: "https://payments.test/.well-known/mcp",
  source_digest: "sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  operation_ref: "get_invoice",
};

function refusal(fn: () => unknown): IntentError {
  try {
    fn();
  } catch (e) {
    if (e instanceof IntentError) return e;
    throw e;
  }
  throw new Error("expected an IntentError");
}

describe("the advertised schema and the runtime validator agree on locations (#1278)", () => {
  it("the published schema prohibits locations by name and leaves the entry's top level open", () => {
    const schema = authorizationDetailsTypesMetadata()[MISSION_RESOURCE_ACCESS_TYPE]?.schema as {
      properties: Record<string, unknown>;
      additionalProperties: unknown;
    };
    expect(schema.properties.locations).toBe(false);
    expect(schema.additionalProperties).toBe(true);
  });

  it("validateMissionResourceAccessSchema refuses an entry carrying locations, whatever its value", () => {
    expect(validateMissionResourceAccessSchema(entry())).toBeUndefined();
    for (const [name, locations] of VALUES) {
      expect(validateMissionResourceAccessSchema(entry({ locations })), name).toMatch(
        /^locations must be absent: the mission_resource_access type does not use this RFC 9396 common field$/,
      );
    }
  });

  it("validateAuthorityProposal, the PAR and device proposal intake, refuses each value with invalid_authorization_details", () => {
    for (const [name, locations] of VALUES) {
      const e = refusal(() => validateAuthorityProposal(JSON.stringify([entry({ locations })]), [CANONICAL_RESOURCE]));
      expect(e.code, name).toBe("invalid_authorization_details");
      expect(e.message, name).toMatch(/locations must be absent/);
    }
  });

  it("admits an entry carrying capability_sources unchanged (positive control: only locations is refused by name)", () => {
    const withBinding = entry({ capability_sources: [BINDING] });
    expect(validateMissionResourceAccessSchema(withBinding)).toBeUndefined();
    const admitted = validateAuthorityProposal(JSON.stringify([withBinding]), [CANONICAL_RESOURCE]);
    expect(admitted).toEqual([withBinding]);
  });
});

describe("config loaders refuse a ceiling entry carrying locations at load (#1278)", () => {
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
    dir = mkdtempSync(join(tmpdir(), "mission-config-1278-"));
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

  const refused = (file: string, ctx: string) =>
    `[config:${file}] ${ctx} carries locations, which the mission_resource_access type does not use`;

  it("parseCeilingEntry (policy.json) rejects a ceiling entry carrying an empty locations array, naming the entry", async () => {
    configDirWith("policy.json", (raw) => {
      (raw as { ceiling: Record<string, unknown>[] }).ceiling[0].locations = [];
    });
    await expect(import("@mission/demo-data")).rejects.toThrow(refused("policy.json", "policy.ceiling[0]"));
  });

  it("parseCeilingEntry (ras-policy.json) rejects a ceiling entry carrying a null locations, naming the entry", async () => {
    configDirWith("ras-policy.json", (raw) => {
      (raw as { ceiling: Record<string, unknown>[] }).ceiling[0].locations = null;
    });
    await expect(import("@mission/demo-data")).rejects.toThrow(refused("ras-policy.json", "ras-policy.ceiling[0]"));
  });

  it("loadCeilingEntries (governed-policy.json) rejects a governed ceiling entry carrying an empty-string locations, naming the entry", async () => {
    configDirWith("governed-policy.json", (raw) => {
      (raw as { ceiling: Record<string, unknown>[] }[])[0].ceiling[0].locations = "";
    });
    await expect(import("@mission/demo-data")).rejects.toThrow(
      refused("governed-policy.json", "governed-policy[0].ceiling[0]"),
    );
  });

  it("loadCeilingEntries (authority-sources.json) rejects a source ceiling entry carrying a populated locations, naming the entry", async () => {
    configDirWith("authority-sources.json", (raw) => {
      const sources = (raw as { sources: { ceiling?: unknown }[] }).sources;
      const index = sources.findIndex((s) => Array.isArray(s.ceiling));
      expect(index).toBeGreaterThanOrEqual(0);
      (sources[index]?.ceiling as Record<string, unknown>[])[0].locations = [CANONICAL_RESOURCE];
    });
    const sources = (JSON.parse(readFileSync(join(REAL_CONFIG_DIR, "authority-sources.json"), "utf8")) as {
      sources: { ceiling?: unknown }[];
    }).sources;
    const index = sources.findIndex((s) => Array.isArray(s.ceiling));
    await expect(import("@mission/demo-data")).rejects.toThrow(
      refused("authority-sources.json", `authority-sources.sources[${index}].ceiling[0]`),
    );
  });

  it("a ceiling entry without locations loads from the fixture dir (positive control for the four refusals)", async () => {
    configDirWith("policy.json", (raw) => {
      (raw as { policy_version: string }).policy_version = "locations-fixture-1278";
    });
    const mod = await import("@mission/demo-data");
    expect(mod.DERIVATION_POLICY.policy_version).toBe("locations-fixture-1278");
  });
});

describe("direct derivation (deriveAuthoritySet) refuses an entry carrying locations (#1278)", () => {
  const intent = {
    purpose: "Read invoices for the quarterly close",
    target_resources: [CANONICAL_RESOURCE, OTHER_RESOURCE],
  } as unknown as MissionIntent;
  const policy = (ceiling: AuthorityEntry[]) => ({ policy_version: "locations-1278", ceiling });

  it("refuses a ceiling entry carrying locations, whatever its value", () => {
    for (const [name, locations] of VALUES) {
      const e = refusal(() => deriveAuthoritySet(intent, policy([entry({ locations })])));
      expect(e.code, name).toBe("invalid_authorization_details");
      expect(e.message, name).toMatch(/carries locations/);
    }
  });

  it("refuses a ceiling entry carrying locations that no submitted proposal entry shares a resource with", () => {
    const ceiling = [entry(), entry({ locations: [] }, OTHER_RESOURCE)];
    const e = refusal(() => deriveAuthoritySet(intent, policy(ceiling), [entry()]));
    expect(e.code).toBe("invalid_authorization_details");
    expect(e.message).toMatch(/carries locations/);
  });

  it("refuses a submitted proposal entry carrying locations, whatever its value", () => {
    for (const [name, locations] of VALUES) {
      const e = refusal(() => deriveAuthoritySet(intent, policy([entry()]), [entry({ locations })]));
      expect(e.code, name).toBe("invalid_authorization_details");
      expect(e.message, name).toMatch(/carries locations/);
    }
  });

  it("derives from a ceiling entry carrying capability_sources (positive control: only locations is refused by name)", () => {
    const derived = deriveAuthoritySet(intent, policy([entry({ capability_sources: [BINDING] })]), [entry()]);
    expect(derived).toHaveLength(1);
    expect(derived[0]?.actions).toEqual(["payments:invoice.read"]);
  });
});
