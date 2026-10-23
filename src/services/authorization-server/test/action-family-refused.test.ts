/**
 * @spec resource-access#subset, resource-access#resource-access-type, mission#subset
 * (issue #1377, D538, D684)
 *
 * This implementation compares action values literally and implements none of
 * the subset rule's action-family clauses, nor a family's consent rendering or
 * breadth handling. Before #1377 it admitted an action family (an identifier
 * followed by `.*`) as an opaque string: the approval page showed it verbatim
 * and derivation never narrowed it. An action family is now unsupported input,
 * refused before approval or transformation at every boundary that admits an
 * entry, through one shared check (`unsupportedActionFamily` in `@mission/core`).
 *
 * The schema, the shared validator, the config loaders, direct derivation and
 * projection are covered here. PAR is in entry-validation.test.ts, refresh
 * narrowing in token-request-rar-narrowing.test.ts, template consent in
 * template-dispatch-endpoint.test.ts, and the RAS in
 * ras/test/mapping-entitlement.test.ts.
 */

import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { actionFamilyRefusal } from "@mission/core";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ACTION_IDENTIFIER,
  ACTION_VALUE,
  type AuthorityEntry,
  authorizationDetailsTypesMetadata,
  deriveAuthoritySet,
  IntentError,
  MISSION_RESOURCE_ACCESS_TYPE,
  type MissionIntent,
  projectThroughEffective,
  validateAuthorityProposal,
  validateMissionResourceAccessSchema,
} from "../src/index.js";

const REAL_CONFIG_DIR = fileURLToPath(new URL("../../../config", import.meta.url));
const OTHER_RESOURCE = "https://erp.example.com";
const READ = "payments:invoice.read";

/** The reproduction: a family over the payments invoice actions. */
const FAMILY = "payments:invoice.*";

const entry = (actions: string[] = [READ], resource = CANONICAL_RESOURCE): AuthorityEntry =>
  ({ type: MISSION_RESOURCE_ACCESS_TYPE, resource, actions }) as AuthorityEntry;

/** Every placement of the family the check must refuse: alone, beside an identifier, last of several. */
const PLACEMENTS: ReadonlyArray<readonly [string, string[]]> = [
  ["alone", [FAMILY]],
  ["beside an identifier", [READ, FAMILY]],
  ["last of several", [READ, "payments:invoice.list", FAMILY]],
];

function refusal(fn: () => unknown): IntentError {
  try {
    fn();
  } catch (e) {
    if (e instanceof IntentError) return e;
    throw e;
  }
  throw new Error("expected an IntentError");
}

describe("the published schema admits action identifiers only, while the grammar still admits a family (#1377)", () => {
  it("publishes the identifier-only items pattern, which a family fails and the draft's grammar admits", () => {
    const schema = authorizationDetailsTypesMetadata()[MISSION_RESOURCE_ACCESS_TYPE]?.schema as {
      properties: { actions: { items: { pattern: string } } };
    };
    expect(schema.properties.actions.items.pattern).toBe(ACTION_IDENTIFIER.source);
    expect(new RegExp(schema.properties.actions.items.pattern).test(FAMILY)).toBe(false);
    expect(new RegExp(schema.properties.actions.items.pattern).test(READ)).toBe(true);
    expect(ACTION_VALUE.test(FAMILY)).toBe(true);
  });
});

describe("the shared validator and the proposal intake refuse an action family as unsupported input (#1377)", () => {
  it("validateMissionResourceAccessSchema refuses an entry carrying an action family, wherever it sits, naming it", () => {
    for (const [name, actions] of PLACEMENTS) {
      expect(validateMissionResourceAccessSchema(entry(actions)), name).toBe(actionFamilyRefusal(FAMILY));
    }
  });

  it("validateAuthorityProposal, the PAR and device proposal intake, refuses it with invalid_authorization_details", () => {
    for (const [name, actions] of PLACEMENTS) {
      const e = refusal(() => validateAuthorityProposal(JSON.stringify([entry(actions)]), [CANONICAL_RESOURCE]));
      expect(e.code, name).toBe("invalid_authorization_details");
      expect(e.message, name).toBe(
        `authorization_details entry fails its published schema: ${actionFamilyRefusal(FAMILY)}`,
      );
    }
  });

  it("admits the same entries with identifiers only (positive control)", () => {
    const identifiers = entry([READ, "payments:invoice.list"]);
    expect(validateMissionResourceAccessSchema(identifiers)).toBeUndefined();
    expect(validateAuthorityProposal(JSON.stringify([identifiers]), [CANONICAL_RESOURCE])).toEqual([identifiers]);
  });
});

describe("config loaders refuse a ceiling entry carrying an action family at load (#1377)", () => {
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
    dir = mkdtempSync(join(tmpdir(), "mission-config-1377-"));
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

  const withFamily = (e: Record<string, unknown>) => {
    e.actions = [...(e.actions as string[]), FAMILY];
  };
  const refused = (file: string, ctx: string) =>
    `[config:${file}] ${ctx} carries the action family ${FAMILY}, which this authorization server does not support`;

  it("parseCeilingEntry (policy.json) rejects a ceiling entry carrying an action family, naming the entry and the family", async () => {
    configDirWith("policy.json", (raw) => withFamily((raw as { ceiling: Record<string, unknown>[] }).ceiling[0]));
    await expect(import("@mission/demo-data")).rejects.toThrow(refused("policy.json", "policy.ceiling[0]"));
  });

  it("parseCeilingEntry (ras-policy.json) rejects a ceiling entry carrying an action family, naming the entry", async () => {
    configDirWith("ras-policy.json", (raw) => withFamily((raw as { ceiling: Record<string, unknown>[] }).ceiling[0]));
    await expect(import("@mission/demo-data")).rejects.toThrow(refused("ras-policy.json", "ras-policy.ceiling[0]"));
  });

  it("loadCeilingEntries (governed-policy.json) rejects a governed ceiling entry carrying an action family, naming the entry", async () => {
    configDirWith("governed-policy.json", (raw) =>
      withFamily((raw as { ceiling: Record<string, unknown>[] }[])[0].ceiling[0]),
    );
    await expect(import("@mission/demo-data")).rejects.toThrow(
      refused("governed-policy.json", "governed-policy[0].ceiling[0]"),
    );
  });

  it("loadCeilingEntries (authority-sources.json) rejects a source ceiling entry carrying an action family, naming the entry", async () => {
    const sources = (
      JSON.parse(readFileSync(join(REAL_CONFIG_DIR, "authority-sources.json"), "utf8")) as {
        sources: { ceiling?: unknown }[];
      }
    ).sources;
    const index = sources.findIndex((s) => Array.isArray(s.ceiling));
    expect(index).toBeGreaterThanOrEqual(0);
    configDirWith("authority-sources.json", (raw) =>
      withFamily(
        ((raw as { sources: { ceiling?: unknown }[] }).sources[index]?.ceiling as Record<string, unknown>[])[0],
      ),
    );
    await expect(import("@mission/demo-data")).rejects.toThrow(
      refused("authority-sources.json", `authority-sources.sources[${index}].ceiling[0]`),
    );
  });

  it("the shipped ceilings, which name identifiers only, load from the fixture dir (positive control for the four refusals)", async () => {
    configDirWith("policy.json", (raw) => {
      (raw as { policy_version: string }).policy_version = "action-family-fixture-1377";
    });
    const mod = await import("@mission/demo-data");
    expect(mod.DERIVATION_POLICY.policy_version).toBe("action-family-fixture-1377");
  });
});

describe("direct derivation (deriveAuthoritySet) refuses an action family in the ceiling or the proposal (#1377)", () => {
  const intent = {
    purpose: "Read invoices for the quarterly close",
    target_resources: [CANONICAL_RESOURCE, OTHER_RESOURCE],
  } as unknown as MissionIntent;
  const policy = (ceiling: AuthorityEntry[]) => ({ policy_version: "action-family-1377", ceiling });

  it("refuses a ceiling entry carrying an action family, wherever it sits", () => {
    for (const [name, actions] of PLACEMENTS) {
      const e = refusal(() => deriveAuthoritySet(intent, policy([entry(actions)])));
      expect(e.code, name).toBe("invalid_authorization_details");
      expect(e.message, name).toBe(actionFamilyRefusal(FAMILY));
    }
  });

  it("refuses a ceiling entry carrying an action family that no submitted proposal entry shares a resource with", () => {
    const ceiling = [entry(), entry([FAMILY], OTHER_RESOURCE)];
    const e = refusal(() => deriveAuthoritySet(intent, policy(ceiling), [entry()]));
    expect(e.code).toBe("invalid_authorization_details");
    expect(e.message).toBe(actionFamilyRefusal(FAMILY));
  });

  it("refuses a submitted proposal entry carrying an action family, wherever it sits", () => {
    for (const [name, actions] of PLACEMENTS) {
      const e = refusal(() => deriveAuthoritySet(intent, policy([entry([READ, "payments:invoice.list"])]), [entry(actions)]));
      expect(e.code, name).toBe("invalid_authorization_details");
      expect(e.message, name).toBe(actionFamilyRefusal(FAMILY));
    }
  });

  it("derives from entries naming identifiers only (positive control)", () => {
    const derived = deriveAuthoritySet(intent, policy([entry([READ, "payments:invoice.list"])]), [entry()]);
    expect(derived).toHaveLength(1);
    expect(derived[0]?.actions).toEqual([READ]);
  });
});

describe("projection drops a pairing that carries an action family (#1377)", () => {
  // Projection fails closed by dropping, never by throwing.
  it("a candidate carrying an action family projects to nothing, even byte-identical to the effective entry", () => {
    for (const [name, actions] of PLACEMENTS) {
      expect(projectThroughEffective([entry(actions)], [entry([READ, "payments:invoice.list"])]), name).toEqual([]);
      expect(projectThroughEffective([entry(actions)], [entry(actions)]), `${name}, byte-identical`).toEqual([]);
    }
  });

  it("an effective entry carrying an action family projects nothing", () => {
    expect(projectThroughEffective([entry()], [entry([READ, FAMILY])])).toEqual([]);
  });

  it("the same candidate without the family projects to the entry (positive control)", () => {
    expect(projectThroughEffective([entry()], [entry([READ, "payments:invoice.list"])])).toEqual([entry()]);
  });
});
