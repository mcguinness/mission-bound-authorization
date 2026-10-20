/**
 * @spec resource-access#resource-matching (issue #1264, D446, #1276)
 *
 * Before #1264, an entry naming `resource_match: "prefix"` was admitted and
 * then rebuilt without the member by the config loaders and by derivation's
 * `intersect`, silently becoming an exact entry: narrower for a ceiling or
 * proposal, wider for a containment removal. Derivation now implements both
 * values (#1276): it refuses an unrecognized value and a `prefix` entry the
 * matcher cannot enforce, and carries `prefix` onto the derived entry. The
 * ceiling loaders admit both values and refuse the same unenforceable entries
 * (#1440); a containment removal stays `exact` only (see demo-data's
 * `rejectUnsupportedResourceMatch`). PAR intake is covered in
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
const UNSUPPORTED = /resource_match "prefix"; this deployment's containment removals are exact only/;

describe("config loaders admit or refuse resource_match at load (#1264, #1440)", () => {
  let previous: string | undefined;
  let dir: string | undefined;

  afterEach(() => {
    if (previous === undefined) delete process.env.MISSION_CONFIG_DIR;
    else process.env.MISSION_CONFIG_DIR = previous;
    if (dir) rmSync(dir, { recursive: true, force: true });
    dir = undefined;
    vi.resetModules();
  });

  /**
   * A copy of the shipped config dir with the named file rewritten by
   * `mutate`, and each file `also` names rewritten by its own function.
   */
  function configDirWith(
    file: string,
    mutate: (parsed: unknown) => void,
    also: Record<string, (parsed: unknown) => void> = {},
  ): void {
    dir = mkdtempSync(join(tmpdir(), "mission-config-1264-"));
    const configDir = join(dir, "config");
    cpSync(REAL_CONFIG_DIR, configDir, { recursive: true });
    for (const [name, rewrite] of [[file, mutate] as const, ...Object.entries(also)]) {
      const filePath = join(configDir, name);
      const parsed: unknown = JSON.parse(readFileSync(filePath, "utf8"));
      rewrite(parsed);
      writeFileSync(filePath, JSON.stringify(parsed, null, 2));
    }
    previous = process.env.MISSION_CONFIG_DIR;
    process.env.MISSION_CONFIG_DIR = configDir;
    vi.resetModules();
  }

  /** containment.json with no rule: containment pairs exactly, so prefix ceilings load only without one. */
  const NO_CONTAINMENT_RULES = {
    "containment.json": (raw: unknown) => {
      (raw as { rules: unknown[] }).rules = [];
    },
  };

  it("parseCeilingEntry (policy.json) loads a ceiling entry naming resource_match prefix and keeps the member, where no containment rule is configured (#1440)", async () => {
    configDirWith(
      "policy.json",
      (raw) => {
        (raw as { ceiling: Record<string, unknown>[] }).ceiling[0].resource_match = "prefix";
      },
      NO_CONTAINMENT_RULES,
    );
    const mod = await import("@mission/demo-data");
    expect(mod.DERIVATION_POLICY.ceiling[0]?.resource_match).toBe("prefix");
    expect(mod.DERIVATION_POLICY.ceiling[1]?.resource_match).toBeUndefined();
  });

  it("loadCeilingEntries (governed-policy.json) loads a governed ceiling entry naming resource_match prefix and keeps the member, where no containment rule is configured (#1440)", async () => {
    configDirWith(
      "governed-policy.json",
      (raw) => {
        (raw as { ceiling: Record<string, unknown>[] }[])[0].ceiling[0].resource_match = "prefix";
      },
      NO_CONTAINMENT_RULES,
    );
    const mod = await import("@mission/demo-data");
    expect(mod.GOVERNED_POLICIES[0]?.ceiling[0]?.resource_match).toBe("prefix");
  });

  it("refuses a policy.json prefix ceiling entry at load while containment rules are configured, naming the entry and the reason (#1440)", async () => {
    configDirWith("policy.json", (raw) => {
      (raw as { ceiling: Record<string, unknown>[] }).ceiling[0].resource_match = "prefix";
    });
    await expect(import("@mission/demo-data")).rejects.toThrow(
      /\[config:policy\.json\] policy\.ceiling\[0\] has resource_match "prefix", but containment\.json configures containment rules, which pair a removal with an approved entry by its exact resource/,
    );
  });

  it("refuses a governed-policy.json prefix ceiling entry at load while containment rules are configured, naming the entry (#1440)", async () => {
    configDirWith("governed-policy.json", (raw) => {
      (raw as { ceiling: Record<string, unknown>[] }[])[0].ceiling[0].resource_match = "prefix";
    });
    await expect(import("@mission/demo-data")).rejects.toThrow(
      /\[config:governed-policy\.json\] governed-policy\[0\]\.ceiling\[0\] has resource_match "prefix", but containment\.json configures containment rules/,
    );
  });

  it("a ceiling loader refuses an unrecognized resource_match, naming the entry (#1440)", async () => {
    configDirWith("policy.json", (raw) => {
      (raw as { ceiling: Record<string, unknown>[] }).ceiling[0].resource_match = "glob";
    });
    await expect(import("@mission/demo-data")).rejects.toThrow(
      /policy\.ceiling\[0\] resource_match "glob" is not a value Resource Access defines/,
    );
  });

  it("a ceiling loader refuses a prefix entry whose resource carries a query, naming the entry (#1440)", async () => {
    configDirWith("governed-policy.json", (raw) => {
      const entry = (raw as { ceiling: Record<string, unknown>[] }[])[0].ceiling[0];
      entry.resource_match = "prefix";
      entry.resource = `${String(entry.resource)}?tenant=a`;
    });
    await expect(import("@mission/demo-data")).rejects.toThrow(/\.ceiling\[0\] a prefix resource .* carries a query component/);
  });

  it("the containment loader rejects a removal entry naming resource_match prefix", async () => {
    configDirWith("containment.json", (raw) => {
      (raw as { rules: { remove: Record<string, unknown>[] }[] }).rules[0].remove[0].resource_match = "prefix";
    });
    await expect(import("@mission/demo-data")).rejects.toThrow(UNSUPPORTED);
  });

  it("an explicit resource_match exact loads (positive control for the refusals)", async () => {
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

  it("refuses an unrecognized resource_match, or a prefix entry whose resource carries a query or names no // authority, in a ceiling entry or a submitted proposal (#1276)", () => {
    const variants: Array<[string, Record<string, unknown>, RegExp]> = [
      ["glob", { resource_match: "glob" }, /resource_match "glob" is not a value Resource Access defines/],
      ["null", { resource_match: null }, /resource_match null is not a value Resource Access defines/],
      ["prefix with a query", { resource_match: "prefix", resource: `${CANONICAL_RESOURCE}?tenant=a` }, /carries a query component/],
      ["prefix with no authority", { resource_match: "prefix", resource: "urn:example:invoices" }, /has no \/\/ authority/],
    ];
    for (const [label, over, message] of variants) {
      const ceilingSide = refusal(() => deriveAuthoritySet(intent, policy([entry(over)])));
      expect(ceilingSide.code, label).toBe("invalid_authorization_details");
      expect(ceilingSide.message, label).toMatch(message);
      const proposalSide = refusal(() => deriveAuthoritySet(intent, policy([entry()]), [entry(over)]));
      expect(proposalSide.code, label).toBe("invalid_authorization_details");
      expect(proposalSide.message, label).toMatch(message);
    }
  });

  it("derives a proposal naming an explicit resource_match exact (positive control)", () => {
    const derived = deriveAuthoritySet(intent, policy([entry()]), [entry({ resource_match: "exact" })]);
    expect(derived).toHaveLength(1);
    expect(derived[0]?.actions).toEqual(["payments:invoice.read"]);
  });
});

describe("derivation under prefix entries (@spec resource-access#subset, mission#derivation-modes, #1276)", () => {
  const INVOICES = `${CANONICAL_RESOURCE}/invoices`;
  const INV1 = `${INVOICES}/inv-1`;
  const at = (resource: string, resource_match?: "exact" | "prefix"): AuthorityEntry => ({
    type: "mission_resource_access",
    resource,
    ...(resource_match ? { resource_match } : {}),
    actions: ["payments:invoice.read"],
  });
  const intentFor = (...target_resources: string[]) =>
    ({ purpose: "Read invoices for the quarterly close", target_resources }) as MissionIntent;
  const policy = (ceiling: AuthorityEntry[]) => ({ policy_version: "resource-match-1276", ceiling });
  const derive = (ceiling: AuthorityEntry[], proposal?: AuthorityEntry[], targets = [INVOICES, INV1]) =>
    deriveAuthoritySet(intentFor(...targets), policy(ceiling), proposal);
  const noAuthority = (fn: () => unknown): string => {
    try {
      fn();
    } catch (e) {
      if (e instanceof IntentError) return e.code;
      throw e;
    }
    throw new Error("expected an IntentError");
  };

  it("derives an exact proposal beneath a prefix ceiling entry as the proposal's own exact resource, never the ceiling's base, and nothing for a sibling outside the boundary", () => {
    expect(derive([at(INVOICES, "prefix")], [at(INV1)])).toEqual([at(INV1)]);
    expect(derive([at(`${INVOICES}/`, "prefix")], [at(INV1)])).toEqual([at(INV1)]);
    const sibling = `${CANONICAL_RESOURCE}/invoices-archive/inv-1`;
    expect(noAuthority(() => derive([at(INVOICES, "prefix")], [at(sibling)], [sibling]))).toBe("invalid_authorization_details");
    // An exact ceiling entry admits only its own string.
    expect(noAuthority(() => derive([at(INVOICES)], [at(INV1)]))).toBe("invalid_authorization_details");
  });

  it("carries prefix onto the derived entry: a prefix proposal within a prefix ceiling keeps its own base, and a configured mapping keeps a prefix ceiling entry unchanged", () => {
    const Y2026 = `${INVOICES}/2026`;
    expect(derive([at(INVOICES, "prefix")], [at(Y2026, "prefix")], [Y2026])).toEqual([at(Y2026, "prefix")]);
    expect(derive([at(INVOICES, "prefix")], [at(INVOICES, "prefix")])).toEqual([at(INVOICES, "prefix")]);
    expect(derive([at(INVOICES, "prefix"), at(`${CANONICAL_RESOURCE}/vendors`, "prefix")], undefined, [INVOICES])).toEqual([
      at(INVOICES, "prefix"),
    ]);
  });

  it("narrows a prefix proposal to an exact ceiling entry naming its base, and derives nothing from a prefix proposal broader than every ceiling entry under another string", () => {
    expect(derive([at(INVOICES)], [at(INVOICES, "prefix")])).toEqual([at(INVOICES)]);
    // A narrower ceiling under another string is not one the Intent's targets name.
    expect(noAuthority(() => derive([at(`${INVOICES}/2026`, "prefix")], [at(INVOICES, "prefix")]))).toBe(
      "invalid_authorization_details",
    );
    expect(noAuthority(() => derive([at(INV1)], [at(INVOICES, "prefix")]))).toBe("invalid_authorization_details");
    // A prefix proposal never widens past an exact ceiling entry.
    expect(noAuthority(() => derive([at(INV1)], [at(CANONICAL_RESOURCE, "prefix")], [CANONICAL_RESOURCE]))).toBe(
      "invalid_authorization_details",
    );
  });
});
