/**
 * @spec mission#subset, resource-access#entry-validation (issue #1399, D538)
 *
 * Where the comparison relation cannot decide (an unrecognized member), the
 * posture is conservative refusal. Before #1399 the reference AS admitted a
 * `mission_resource_access` entry carrying a top-level member outside the
 * type's own members and `capability_sources`, then dropped it wherever it
 * rebuilt the entry member by member: derivation, projection and the config
 * loaders. A restriction expressed in that member was erased, and the token
 * carried a narrower-looking entry that a resource server enforced as broader
 * authority. One shared set (`SUPPORTED_ENTRY_MEMBERS` in `@mission/core`)
 * now backs every boundary.
 *
 * The schema, the shared validator, the config loaders, direct derivation
 * and projection are covered here. PAR is in rar-carriage.test.ts, device
 * submission in device-authorization.test.ts, refresh narrowing in
 * token-request-rar-narrowing.test.ts, and the deferred, dispatch handoff,
 * async-delegation and template intakes in their own files.
 */

import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SUPPORTED_ENTRY_MEMBERS } from "@mission/core";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import {
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

/** A restriction-shaped member no specification defines for this type. */
const UNKNOWN = "invoice_ids";

/** Every kind of value the presence check must refuse, including the falsy ones. */
const VALUES: ReadonlyArray<readonly [string, unknown]> = [
  ["a populated array", ["INV-7"]],
  ["an empty array", []],
  ["null", null],
  ["an empty string", ""],
  ["an object", { id: "INV-7" }],
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

const VIOLATION = `${UNKNOWN} is not a supported member of the mission_resource_access type; refusing rather than dropping it`;

function refusal(fn: () => unknown): IntentError {
  try {
    fn();
  } catch (e) {
    if (e instanceof IntentError) return e;
    throw e;
  }
  throw new Error("expected an IntentError");
}

describe("the published schema closes the entry's top level to the supported members (#1399)", () => {
  it("declares exactly SUPPORTED_ENTRY_MEMBERS, with locations prohibited, and admits no other member", () => {
    const schema = authorizationDetailsTypesMetadata()[MISSION_RESOURCE_ACCESS_TYPE]?.schema as {
      properties: Record<string, unknown>;
      additionalProperties: unknown;
    };
    expect(schema.additionalProperties).toBe(false);
    expect(schema.properties.locations).toBe(false);
    const declared = Object.keys(schema.properties).filter((k) => k !== "locations");
    expect(declared.sort()).toEqual([...SUPPORTED_ENTRY_MEMBERS].sort());
  });

  it("validateMissionResourceAccessSchema refuses an entry carrying an unsupported member, whatever its value, naming it", () => {
    for (const [name, value] of VALUES) {
      expect(validateMissionResourceAccessSchema(entry({ [UNKNOWN]: value })), name).toBe(VIOLATION);
    }
  });

  it("validateAuthorityProposal, the PAR and device proposal intake, refuses each value with invalid_authorization_details", () => {
    for (const [name, value] of VALUES) {
      const e = refusal(() =>
        validateAuthorityProposal(JSON.stringify([entry({ [UNKNOWN]: value })]), [CANONICAL_RESOURCE]),
      );
      expect(e.code, name).toBe("invalid_authorization_details");
      expect(e.message, name).toMatch(/invoice_ids is not a supported member/);
    }
  });

  it("admits resource_match exact and capability_sources unchanged (positive control: only members outside the set are refused)", () => {
    const supported = entry({ resource_match: "exact", capability_sources: [BINDING] });
    expect(validateMissionResourceAccessSchema(supported)).toBeUndefined();
    expect(validateAuthorityProposal(JSON.stringify([supported]), [CANONICAL_RESOURCE])).toEqual([supported]);
  });

  it("mirrors the schema's capability_sources type: a value that is not an array of objects is refused", () => {
    for (const capability_sources of ["x", [1], [null], {}]) {
      expect(validateMissionResourceAccessSchema(entry({ capability_sources }))).toBe(
        "capability_sources must be an array of objects",
      );
    }
  });
});

describe("config loaders refuse a ceiling entry carrying an unsupported member at load (#1399)", () => {
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
    dir = mkdtempSync(join(tmpdir(), "mission-config-1399-"));
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
    `[config:${file}] ${ctx} carries ${UNKNOWN}, which is not a supported member of the mission_resource_access type`;

  it("parseCeilingEntry (policy.json) rejects a ceiling entry carrying an unsupported member, naming the entry and the member", async () => {
    configDirWith("policy.json", (raw) => {
      (raw as { ceiling: Record<string, unknown>[] }).ceiling[0][UNKNOWN] = ["INV-7"];
    });
    await expect(import("@mission/demo-data")).rejects.toThrow(refused("policy.json", "policy.ceiling[0]"));
  });

  it("parseCeilingEntry (ras-policy.json) rejects a ceiling entry carrying a null unsupported member, naming the entry", async () => {
    configDirWith("ras-policy.json", (raw) => {
      (raw as { ceiling: Record<string, unknown>[] }).ceiling[0][UNKNOWN] = null;
    });
    await expect(import("@mission/demo-data")).rejects.toThrow(refused("ras-policy.json", "ras-policy.ceiling[0]"));
  });

  it("loadCeilingEntries (governed-policy.json) rejects a governed ceiling entry carrying an unsupported member, naming the entry", async () => {
    configDirWith("governed-policy.json", (raw) => {
      (raw as { ceiling: Record<string, unknown>[] }[])[0].ceiling[0][UNKNOWN] = [];
    });
    await expect(import("@mission/demo-data")).rejects.toThrow(
      refused("governed-policy.json", "governed-policy[0].ceiling[0]"),
    );
  });

  it("loadCeilingEntries (authority-sources.json) rejects a source ceiling entry carrying an unsupported member, naming the entry", async () => {
    configDirWith("authority-sources.json", (raw) => {
      const sources = (raw as { sources: { ceiling?: unknown }[] }).sources;
      const index = sources.findIndex((s) => Array.isArray(s.ceiling));
      expect(index).toBeGreaterThanOrEqual(0);
      (sources[index]?.ceiling as Record<string, unknown>[])[0][UNKNOWN] = ["INV-7"];
    });
    const sources = (JSON.parse(readFileSync(join(REAL_CONFIG_DIR, "authority-sources.json"), "utf8")) as {
      sources: { ceiling?: unknown }[];
    }).sources;
    const index = sources.findIndex((s) => Array.isArray(s.ceiling));
    await expect(import("@mission/demo-data")).rejects.toThrow(
      refused("authority-sources.json", `authority-sources.sources[${index}].ceiling[0]`),
    );
  });

  it("a ceiling entry carrying only supported members loads from the fixture dir (positive control for the four refusals)", async () => {
    configDirWith("policy.json", (raw) => {
      (raw as { policy_version: string }).policy_version = "unknown-member-fixture-1399";
    });
    const mod = await import("@mission/demo-data");
    expect(mod.DERIVATION_POLICY.policy_version).toBe("unknown-member-fixture-1399");
  });
});

describe("direct derivation (deriveAuthoritySet) refuses an entry carrying an unsupported member (#1399)", () => {
  const intent = {
    purpose: "Read invoices for the quarterly close",
    target_resources: [CANONICAL_RESOURCE, OTHER_RESOURCE],
  } as unknown as MissionIntent;
  const policy = (ceiling: AuthorityEntry[]) => ({ policy_version: "unknown-member-1399", ceiling });
  const carries = /carries invoice_ids, which is not a supported member of the mission_resource_access type/;

  it("refuses a ceiling entry carrying an unsupported member, whatever its value", () => {
    for (const [name, value] of VALUES) {
      const e = refusal(() => deriveAuthoritySet(intent, policy([entry({ [UNKNOWN]: value })])));
      expect(e.code, name).toBe("invalid_authorization_details");
      expect(e.message, name).toMatch(carries);
    }
  });

  it("refuses a ceiling entry carrying an unsupported member that no submitted proposal entry shares a resource with", () => {
    const ceiling = [entry(), entry({ [UNKNOWN]: ["INV-7"] }, OTHER_RESOURCE)];
    const e = refusal(() => deriveAuthoritySet(intent, policy(ceiling), [entry()]));
    expect(e.code).toBe("invalid_authorization_details");
    expect(e.message).toMatch(carries);
  });

  it("refuses a submitted proposal entry carrying an unsupported member, whatever its value", () => {
    for (const [name, value] of VALUES) {
      const e = refusal(() => deriveAuthoritySet(intent, policy([entry()]), [entry({ [UNKNOWN]: value })]));
      expect(e.code, name).toBe("invalid_authorization_details");
      expect(e.message, name).toMatch(carries);
    }
  });

  it("derives from entries carrying resource_match exact and capability_sources (positive control)", () => {
    const derived = deriveAuthoritySet(
      intent,
      policy([entry({ resource_match: "exact", capability_sources: [BINDING] })]),
      [entry({ resource_match: "exact" })],
    );
    expect(derived).toHaveLength(1);
    expect(derived[0]?.actions).toEqual(["payments:invoice.read"]);
  });
});

describe("projection drops a pairing that carries an unsupported member (#1399)", () => {
  // Projection fails closed by dropping, never by throwing: a pairing it
  // cannot prove yields no fragment, rather than a fragment rebuilt without
  // the member.
  it("a candidate carrying an unsupported member projects to nothing, whatever its value", () => {
    for (const [name, value] of VALUES) {
      expect(projectThroughEffective([entry({ [UNKNOWN]: value })], [entry()]), name).toEqual([]);
    }
  });

  it("an effective entry carrying an unsupported member projects nothing", () => {
    expect(projectThroughEffective([entry()], [entry({ [UNKNOWN]: ["INV-7"] })])).toEqual([]);
  });

  it("the same candidate without the member projects to the entry (positive control)", () => {
    expect(projectThroughEffective([entry()], [entry()])).toEqual([entry()]);
    expect(projectThroughEffective([entry({ resource_match: "exact" })], [entry()])).toHaveLength(1);
  });
});
