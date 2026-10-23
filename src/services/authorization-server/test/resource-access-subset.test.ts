/**
 * @spec resource-access#resource-contract, resource-access#subset,
 * resource-access#iana-common-constraints (#249, D553, D676): the supported-subset
 * fixture in `vectors/mission-resource-access-subset/` stays what the payments
 * resource and this engine serve.
 *
 * The fixture is frozen: one contract version and one subset, never edited in place.
 * These tests fail when it drifts from the contract the payments resource declares
 * (its reference, document and digest), from the actions that contract covers, from
 * the members and constraint keys the engine supports, from the initial Common
 * Constraints the Resource Access registry names, or from the case vocabulary it
 * selects cases with. They make no conformance claim: independent evidence is #819's
 * second consumer, running the same files.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  type JsonValue,
  type ResourceContractRef,
  resourceContractDigest,
  SUPPORTED_CONSTRAINT_KEYS,
  SUPPORTED_ENTRY_MEMBERS,
} from "@mission/core";
import { RESOURCE_CONTRACTS } from "@mission/demo-data";
import { describe, expect, it } from "vitest";
import { EXECUTABLE_CHECKS, IMPLEMENTED, knownCapability } from "./resource-access-capabilities.helper.js";

const ROOT = new URL("../../../../", import.meta.url);
const SUBSET_DIR = fileURLToPath(new URL("vectors/mission-resource-access-subset/", ROOT));
const CASES_DIR = fileURLToPath(new URL("vectors/mission-resource-access/", ROOT));
const DRAFT = fileURLToPath(new URL("draft-mcguinness-oauth-mission-resource-access.md", ROOT));
const RESOURCE_ACCESS = "draft-mcguinness-oauth-mission-resource-access";
const DISCHARGE = "draft-mcguinness-oauth-mission-discharge";

interface ContractFile {
  format: string;
  reference: ResourceContractRef;
  document: {
    resource_match: string[];
    constraints: Record<string, string>;
    operations: Record<string, { action: string }>;
  };
}
interface SubsetFile {
  format: string;
  type: string;
  contract: { file: string; reference: ResourceContractRef };
  resource_match: string[];
  actions: string[];
  members: string[];
  constraints: Record<string, { registered_by: string | null }>;
  outside_subset: {
    resource_match: string[];
    members: string[];
    constraints: Record<string, { registered_by: string | null; reason: string }>;
  };
  capabilities: string[];
  excluded_capabilities: string[];
}
interface Case {
  id: string;
  check: string;
  requires: string[];
  unless?: string[];
}

const read = <T>(path: string): T => JSON.parse(readFileSync(path, "utf8")) as T;
const subset = read<SubsetFile>(join(SUBSET_DIR, "supported-subset.json"));
const contract = read<ContractFile>(join(SUBSET_DIR, subset.contract.file));
const sorted = (values: Iterable<string>) => [...values].sort();

/** The key names in the draft's "Initial Mission Common Constraints registry" table. */
function initialRegistryKeys(): string[] {
  const text = readFileSync(DRAFT, "utf8");
  const end = text.indexOf('{: title="Initial Mission Common Constraints registry"}');
  const start = text.lastIndexOf("| Key Name | Value Syntax |", end);
  if (end < 0 || start < 0) throw new Error("the initial Common Constraints registry table is not in the draft");
  return [...text.slice(start, end).matchAll(/^\| `([A-Za-z0-9_.:-]+)` \|/gm)].map((m) => m[1] as string);
}

/** Whether a consumer implementing `implemented` runs `c` (the case README's applicability rule). */
const applies = (c: Case, implemented: ReadonlySet<string>) =>
  c.requires.every((cap) => implemented.has(cap)) && !(c.unless ?? []).some((cap) => implemented.has(cap));

describe("the supported-subset fixture freezes the payments contract and the initial subset (@spec resource-access#resource-contract, #249, D676)", () => {
  it("freezes the contract version the payments resource declares as current: the same reference and document, under a digest that commits the document", () => {
    expect(contract.format).toBe("mission-resource-contract/1");
    expect(subset.format).toBe("mission-resource-access-subset/1");
    expect(subset.type).toBe("mission_resource_access");
    expect(subset.contract.reference).toEqual(contract.reference);
    const declared = RESOURCE_CONTRACTS.versionOf(contract.reference);
    expect(declared?.version.state).toBe("current");
    expect(declared?.version.digest).toBe(contract.reference.digest);
    expect(declared?.version.document).toEqual(contract.document);
    expect(resourceContractDigest(contract.document as unknown as JsonValue)).toBe(contract.reference.digest);
  });

  it("lists exactly the actions the contract covers, each an explicit identifier: no action family", () => {
    const covered = new Set(Object.values(contract.document.operations).map((op) => op.action));
    expect(subset.actions).toEqual(sorted(covered));
    expect(subset.actions.filter((a) => a.endsWith(".*"))).toEqual([]);
  });

  it("matches exact resources only, of the modes the contract serves", () => {
    expect(subset.resource_match).toEqual(["exact"]);
    expect(subset.outside_subset.resource_match).toEqual(["prefix"]);
    expect(sorted([...subset.resource_match, ...subset.outside_subset.resource_match])).toEqual(
      sorted(contract.document.resource_match),
    );
  });

  it("divides the entry members the engine admits between the subset and outside it, the contract reference inside", () => {
    expect(subset.members).toContain("resource_contract");
    expect(subset.members.filter((m) => subset.outside_subset.members.includes(m))).toEqual([]);
    expect(sorted([...subset.members, ...subset.outside_subset.members])).toEqual(sorted(SUPPORTED_ENTRY_MEMBERS));
  });

  it("carries the nine initial Common Constraints the Resource Access registry names, and sets aside the other keys the engine supports with the specification that registers each", () => {
    const registry = initialRegistryKeys();
    expect(registry).toHaveLength(9);
    expect(sorted(Object.keys(subset.constraints))).toEqual(sorted(registry));
    for (const [key, c] of Object.entries(subset.constraints)) expect(c.registered_by, key).toBe(RESOURCE_ACCESS);
    const outside = subset.outside_subset.constraints;
    expect(sorted(Object.keys(outside))).toEqual(["terminal_when", "vendors"]);
    expect(outside.terminal_when?.registered_by).toBe(DISCHARGE);
    expect(outside.vendors?.registered_by).toBeNull();
    const named = [...Object.keys(subset.constraints), ...Object.keys(outside)];
    expect(sorted(named)).toEqual(sorted(SUPPORTED_CONSTRAINT_KEYS));
    expect(sorted(named)).toEqual(sorted(Object.keys(contract.document.constraints)));
  });

  it("declares its capabilities in the case vocabulary, one per subset constraint and member, never prefix matching or action families", () => {
    expect(subset.excluded_capabilities).toEqual(["resource-match.prefix", "action-families"]);
    for (const cap of [...subset.capabilities, ...subset.excluded_capabilities]) {
      expect(knownCapability(cap), cap).toBe(true);
    }
    expect(subset.capabilities.filter((cap) => subset.excluded_capabilities.includes(cap))).toEqual([]);
    const named = (prefix: string) =>
      sorted(subset.capabilities.filter((cap) => cap.startsWith(prefix)).map((cap) => cap.slice(prefix.length)));
    expect(named("constraint.")).toEqual(sorted(Object.keys(subset.constraints)));
    for (const member of named("member.")) expect(subset.members, member).toContain(member);
    for (const cap of subset.capabilities) expect(IMPLEMENTED.has(cap), `${cap} is implemented here`).toBe(true);
  });

  it("selects expected-outcome cases this implementation runs, except a refusal of input the subset excludes and this implementation supports", () => {
    const capabilities = new Set(subset.capabilities);
    const cases = readdirSync(CASES_DIR)
      .filter((f) => f.endsWith(".json"))
      .flatMap((f) => read<{ cases: Case[] }>(join(CASES_DIR, f)).cases);
    const selected = cases.filter((c) => applies(c, capabilities));
    expect(selected.length).toBeGreaterThan(0);
    for (const c of selected) {
      expect(EXECUTABLE_CHECKS.has(c.check), `${c.id}: an executor for ${c.check}`).toBe(true);
      if (applies(c, IMPLEMENTED)) continue;
      const inapplicable = (c.unless ?? []).filter((cap) => IMPLEMENTED.has(cap));
      expect(inapplicable.length, c.id).toBeGreaterThan(0);
      for (const cap of inapplicable) expect(subset.excluded_capabilities, c.id).toContain(cap);
    }
  });
});
