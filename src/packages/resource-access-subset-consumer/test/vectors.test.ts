// Runs every vectors/mission-resource-access case this consumer's declared
// capabilities select, under the README's applicability rule, and compares
// outcome always and error where the case gives one. A case whose outcome
// differs must be listed in disagreements.json, and a listed case must still
// differ.

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  type CaseResult,
  CONSTRAINT_RULES,
  type ConsumerConfig,
  IMPLEMENTED_CHECKS,
  runCase,
  type Selection,
  SUBSET_MEMBERS,
  SUBSET_RESOURCE_MATCH,
  selectCase,
  type VectorCase,
} from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../../..");
const casesDir = join(repoRoot, "vectors/mission-resource-access");
const subsetDir = join(repoRoot, "vectors/mission-resource-access-subset");

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}

interface SubsetFixture {
  format: string;
  contract: { file: string; reference: { id: string; version: string; digest: string } };
  resource_match: string[];
  actions: string[];
  members: string[];
  constraints: Record<string, unknown>;
  capabilities: string[];
  excluded_capabilities: string[];
}

interface ContractFile {
  format: string;
  reference: { id: string; version: string; digest: string };
  document: { operations: Record<string, { action: string }> };
}

interface Disagreement {
  id: string;
  classification: "case-bug" | "consumer-bug" | "spec-gap";
  reason: string;
}

const fixture = readJson(join(subsetDir, "supported-subset.json")) as SubsetFixture;
const contract = readJson(join(subsetDir, fixture.contract.file)) as ContractFile;

// The consumer's declared capability set is the fixture's.
const declared = new Set(fixture.capabilities);

// The consumer's trusted configuration: the frozen contract is the one
// current contract. The fixture names no resource URI for it, so it is
// configured as current for every resource.
const config: ConsumerConfig = {
  currentContracts: [
    {
      reference: contract.reference,
      actions: Object.values(contract.document.operations).map((op) => op.action),
    },
  ],
};

const caseFiles = readdirSync(casesDir)
  .filter((f) => f.endsWith(".json"))
  .sort();
const cases: VectorCase[] = caseFiles.flatMap((file) => {
  const group = readJson(join(casesDir, file)) as { format: string; cases: VectorCase[] };
  if (group.format !== "mission-resource-access-cases/1") {
    throw new Error(`${file}: unexpected format ${group.format}`);
  }
  return group.cases;
});

const disagreements = readJson(join(here, "disagreements.json")) as Disagreement[];
const listed = new Map(disagreements.map((d) => [d.id, d]));

interface Outcome {
  readonly c: VectorCase;
  readonly selection: Selection;
  readonly result?: CaseResult;
  readonly agrees?: boolean;
}

function agrees(c: VectorCase, result: CaseResult): boolean {
  if (result.outcome !== c.expected.outcome) return false;
  if (c.expected.error !== undefined && result.error !== c.expected.error) return false;
  return true;
}

const outcomes: Outcome[] = cases.map((c) => {
  const selection = selectCase(c, declared);
  if (!selection.run) return { c, selection };
  const result = runCase(c, config);
  return { c, selection, result, agrees: agrees(c, result) };
});

describe("the subset fixture as this consumer reads it", () => {
  it("declares no excluded capability", () => {
    for (const cap of fixture.excluded_capabilities) expect(declared.has(cap)).toBe(false);
  });

  it("matches the members, resource_match values and constraint keys the consumer implements", () => {
    expect([...SUBSET_MEMBERS].sort()).toEqual([...fixture.members].sort());
    expect([...SUBSET_RESOURCE_MATCH].sort()).toEqual([...fixture.resource_match].sort());
    expect([...CONSTRAINT_RULES.keys()].sort()).toEqual(Object.keys(fixture.constraints).sort());
  });

  it("names the reference its contract file carries, and the contract defines the subset actions", () => {
    expect(contract.reference).toEqual(fixture.contract.reference);
    const defined = new Set(config.currentContracts[0]?.actions);
    expect([...defined].sort()).toEqual([...fixture.actions].sort());
  });
});

describe("the case set", () => {
  it("has unique case ids", () => {
    const ids = cases.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("lists only known, run, non-consumer-bug disagreements", () => {
    for (const d of disagreements) {
      expect(["case-bug", "spec-gap"], `${d.id}: fix a consumer bug rather than list it`).toContain(
        d.classification,
      );
      expect(d.reason, `${d.id}: a disagreement states its reason`).not.toBe("");
      const o = outcomes.find((x) => x.c.id === d.id);
      expect(o, `${d.id}: listed but no such case`).toBeDefined();
      expect(o?.selection.run, `${d.id}: listed but not run`).toBe(true);
    }
  });
});

describe("cases", () => {
  for (const o of outcomes) {
    const { c, selection } = o;
    if (!selection.run) {
      it.skip(`${c.id} (${c.check}) skipped, ${selection.reason}: ${selection.detail}`, () => {});
      continue;
    }
    it(`${c.id} (${c.check})`, () => {
      const result = o.result as CaseResult;
      const actual = { outcome: result.outcome, error: result.error, reason: result.reason };
      if (listed.has(c.id)) {
        // A listed case that now agrees is a stale entry.
        expect(o.agrees, `${c.id} is listed in disagreements.json but passes`).toBe(false);
        return;
      }
      expect(actual.outcome, `${c.id}: ${result.reason}`).toBe(c.expected.outcome);
      if (c.expected.error !== undefined) expect(actual.error).toBe(c.expected.error);
    });
  }
});

describe("the run", () => {
  const run = outcomes.filter((o) => o.selection.run);

  it("runs at least one case for each implemented check", () => {
    for (const check of IMPLEMENTED_CHECKS) {
      expect(
        run.filter((o) => o.c.check === check).length,
        `no case runs for ${check}`,
      ).toBeGreaterThan(0);
    }
  });

  it("skips no case the declared capabilities select, other than derive", () => {
    const unrun = outcomes.filter(
      (o) => !o.selection.run && o.selection.reason === "check-not-implemented",
    );
    expect(unrun.map((o) => o.c.id)).toEqual([]);
  });

  it("has every run case passing or listed, and every listed case still disagreeing", () => {
    const unlisted = run
      .filter((o) => o.agrees === false && !listed.has(o.c.id))
      .map((o) => o.c.id);
    const stale = run.filter((o) => o.agrees === true && listed.has(o.c.id)).map((o) => o.c.id);
    expect(unlisted, "unlisted failures").toEqual([]);
    expect(stale, "stale disagreements").toEqual([]);

    const summary: Record<string, unknown> = {
      files: caseFiles,
      total: outcomes.length,
      run: Object.fromEntries(
        IMPLEMENTED_CHECKS.map((check) => [check, run.filter((o) => o.c.check === check).length]),
      ),
      passed: run.filter((o) => o.agrees).length,
      listedDisagreements: run.filter((o) => listed.has(o.c.id)).length,
      skipped: Object.fromEntries(
        ["missing-capability", "inapplicable", "scoped-out", "check-not-implemented"].map(
          (reason) => [
            reason,
            outcomes.filter((o) => !o.selection.run && o.selection.reason === reason).length,
          ],
        ),
      ),
    };
    console.log(`resource-access subset consumer run: ${JSON.stringify(summary)}`);
  });
});
