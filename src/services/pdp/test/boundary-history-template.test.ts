/**
 * @spec runtime#boundary-identifier-change (#853 review): the
 * MCP_PAYMENTS_RESOURCE override templates the payments resource into the
 * statement only where that is configuration. A declaration that retains
 * history keeps every earlier version byte for byte (its boundary, its
 * `replaces` record, its aliases and its emitter identities), because
 * evidence produced under it verifies against exactly those bytes; an
 * override that would rewrite them is refused at load.
 *
 * The load cases copy the shipped `config/` with a declared change appended,
 * point the loader at the copy through `MISSION_CONFIG_DIR`, set the
 * override, and reset the module registry, so each runs the real boot path.
 */

import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const SHIPPED_CONFIG = join(import.meta.dirname, "../../../config");
const SHIPPED = "http://localhost:4403/mcp";
const MOVED = "https://new.example/mcp";

type Statement = {
  mediated_scope: { resources: unknown[] };
  enforcement_boundaries: {
    versions: Array<{
      version: string;
      effective_at: string;
      boundaries: Array<{ boundary: string; pep_locations: string[]; audience_aliases?: unknown[]; evidence_keys: unknown[] }>;
      replaces?: Array<{ boundary: string; previous_version: string; previous_boundary: string }>;
    }>;
  };
};

const shippedStatement = (): Statement =>
  JSON.parse(readFileSync(join(SHIPPED_CONFIG, "enforcement-scope.json"), "utf8")) as Statement;

/** The shipped statement with a declared change of the payments boundary to {@link MOVED} appended. */
function withDeclaredChange(): Statement {
  const statement = shippedStatement();
  const v1 = statement.enforcement_boundaries.versions[0] as Statement["enforcement_boundaries"]["versions"][number];
  statement.enforcement_boundaries.versions.push({
    version: "payments-boundary-v2",
    effective_at: "2026-06-01T00:00:00Z",
    boundaries: [
      {
        boundary: MOVED,
        pep_locations: ["mcp-payments-pep"],
        audience_aliases: [{ issuer: "https://as.test", token_profile: "at+jwt", alias: SHIPPED }],
        evidence_keys: [
          { kid: "pdp-decision-evidence-v2", emitter: MOVED, role: "pdp" },
          { kid: "pep-v2", emitter: MOVED, role: "pep" },
          { kid: "executor-v2", emitter: MOVED, role: "executor" },
        ],
      },
    ],
    replaces: [{ boundary: MOVED, previous_version: v1.version, previous_boundary: SHIPPED }],
  });
  return statement;
}

describe("the payments resource override never rewrites retained boundary history (@spec runtime#boundary-identifier-change, #853)", () => {
  const dirs: string[] = [];
  const original = { dir: process.env.MISSION_CONFIG_DIR, resource: process.env.MCP_PAYMENTS_RESOURCE };

  afterEach(() => {
    if (original.dir === undefined) delete process.env.MISSION_CONFIG_DIR;
    else process.env.MISSION_CONFIG_DIR = original.dir;
    if (original.resource === undefined) delete process.env.MCP_PAYMENTS_RESOURCE;
    else process.env.MCP_PAYMENTS_RESOURCE = original.resource;
    vi.resetModules();
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  const configWith = (statement: Statement): string => {
    const dir = mkdtempSync(join(tmpdir(), "mission-boundary-history-"));
    dirs.push(dir);
    cpSync(SHIPPED_CONFIG, dir, { recursive: true });
    writeFileSync(join(dir, "enforcement-scope.json"), JSON.stringify(statement, null, 2));
    return dir;
  };

  it("loads a retained version verbatim when the override names the declared new boundary", async () => {
    const declared = withDeclaredChange();
    process.env.MISSION_CONFIG_DIR = configWith(declared);
    process.env.MCP_PAYMENTS_RESOURCE = MOVED;
    vi.resetModules();
    const { RUNTIME_SCOPE_CONFIG, CANONICAL_RESOURCE } = await import("@mission/demo-data");
    const loaded = RUNTIME_SCOPE_CONFIG as Statement;
    expect(CANONICAL_RESOURCE).toBe(MOVED);
    const [v1, v2] = loaded.enforcement_boundaries.versions;
    // The owner's reproduction: the retained version and the replaces record keep the old identifier.
    expect(v1?.boundaries[0]?.boundary).toBe(SHIPPED);
    expect(v2?.replaces?.[0]?.previous_boundary).toBe(SHIPPED);
    // Every byte of the declaration is the file's, emitter identities and aliases included.
    expect(loaded.enforcement_boundaries).toEqual(declared.enforcement_boundaries);
    // The current configuration follows the override, so the last version's boundary is a mediated resource.
    expect(loaded.mediated_scope.resources).toEqual([MOVED]);
    const { enforcementBoundaryFindings } = await import("../src/enforcement-boundary.js");
    expect(enforcementBoundaryFindings(loaded)).toEqual([]);
  });

  it("refuses an override that the retained declaration does not name as a current boundary", async () => {
    process.env.MISSION_CONFIG_DIR = configWith(withDeclaredChange());
    process.env.MCP_PAYMENTS_RESOURCE = "https://elsewhere.example/mcp";
    vi.resetModules();
    await expect(import("@mission/demo-data")).rejects.toThrow(/retained versions are never rewritten/);
  });

  it("templates a one-version declaration with no replaces record whole, as initial configuration", async () => {
    const { templatePaymentsResource } = await import("@mission/demo-data");
    const shipped = shippedStatement();
    const templated = templatePaymentsResource(shipped, SHIPPED, MOVED) as Statement;
    const [v1] = templated.enforcement_boundaries.versions;
    expect(v1?.boundaries[0]?.boundary).toBe(MOVED);
    expect(v1?.boundaries[0]?.evidence_keys).toEqual([
      { kid: "pdp-decision-evidence", emitter: MOVED, role: "pdp" },
      { kid: "ephemeral-pep", emitter: MOVED, role: "pep" },
      { kid: "ephemeral-executor", emitter: MOVED, role: "executor" },
    ]);
    expect(templated.mediated_scope.resources).toEqual([MOVED]);
    // No override, no change.
    expect(templatePaymentsResource(shipped, SHIPPED, SHIPPED)).toBe(shipped);
  });
});
