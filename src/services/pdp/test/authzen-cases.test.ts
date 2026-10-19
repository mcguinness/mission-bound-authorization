/**
 * @spec authzen#context-operation-target (#1276, D457): the reference implementation's reader
 * for the AuthZEN profile's expected-outcome cases in `vectors/mission-authzen/`.
 *
 * It validates every case file, then runs each case whose `requires` capabilities this
 * implementation has and none of whose `unless` capabilities it has, and reports every
 * other case as skipped, naming the missing capability or the implemented one that makes
 * the case inapplicable. The reference PDP and PEPs do not carry or match the operation
 * target yet, so `IMPLEMENTED` is empty and no executor exists: every case is skipped and
 * none is evidence. An implementation adds a capability to `IMPLEMENTED` and an executor
 * for its check only together with the behavior.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const DIR = fileURLToPath(new URL("../../../../vectors/mission-authzen/", import.meta.url));
const FORMAT = "mission-authzen-cases/1";

/** The deployment capability configuration: what this reference implementation implements. */
const IMPLEMENTED = new Set<string>([]);

/** The declared capability vocabulary (README.md). */
const KNOWN_CAPABILITIES = new Set([
  ...IMPLEMENTED,
  "pdp.operation-target",
  "pdp.resource-match.prefix",
  "pdp.enforcement-scope",
  "pep.operation-target",
  "pep.permit-target-binding",
]);

/** The role that decides each check, and the outcomes it may expect. */
const CHECKS: Record<string, { role: string; outcomes: readonly string[] }> = {
  evaluate: { role: "pdp", outcomes: ["permit", "deny", "refuse"] },
  "establish-target": { role: "pep", outcomes: ["established", "refuse"] },
  "permit-reuse": { role: "pep", outcomes: ["reuse", "re-evaluate"] },
  execute: { role: "pep", outcomes: ["release", "suppress"] },
};

/** The carrier each identifier-bearing outcome uses. */
const CARRIERS: Record<string, string> = {
  deny: "pdp-denial",
  refuse: "refusal-record",
  suppress: "execution-evidence",
};

interface Case {
  id: string;
  description: string;
  role: string;
  requires: string[];
  unless?: string[];
  check: string;
  input: Record<string, unknown>;
  expected: {
    outcome: string;
    reason: string;
    carrier?: string;
    error?: string;
    authority_bound?: string;
    target?: string;
  };
  refs: string[];
}
interface CaseFile {
  format: string;
  group: string;
  description: string;
  spec: string;
  cases: Case[];
}

const files = readdirSync(DIR)
  .filter((f) => f.endsWith(".json"))
  .sort()
  .map((f) => ({ name: f, doc: JSON.parse(readFileSync(join(DIR, f), "utf8")) as CaseFile }));

/** Checks with an executor in this implementation; none until the behavior exists. */
const EXECUTABLE_CHECKS = new Set<string>([]);

/** Why a case does not run for a consumer implementing `implemented`, or undefined when it applies. */
function skipReason(c: Case, implemented: ReadonlySet<string> = IMPLEMENTED): string | undefined {
  const missing = c.requires.filter((cap) => !implemented.has(cap));
  if (!EXECUTABLE_CHECKS.has(c.check) && missing.length === 0) missing.push(`executor:${c.check}`);
  if (missing.length > 0) return `requires ${missing.join(", ")}`;
  const excluded = (c.unless ?? []).filter((cap) => implemented.has(cap));
  if (excluded.length > 0) return `not applicable: implements ${excluded.join(", ")}`;
  return undefined;
}

describe("Mission AuthZEN expected-outcome cases (#1276, D457)", () => {
  it("validates every case file: format, group, unique ids, roles, checks, outcomes, carriers and capabilities", () => {
    expect(files.length).toBeGreaterThan(0);
    const ids = new Set<string>();
    for (const { name, doc } of files) {
      expect(doc.format, name).toBe(FORMAT);
      expect(`${doc.group}.json`, name).toBe(name);
      expect(doc.spec, name).toBe("draft-mcguinness-mission-authzen");
      expect(doc.cases.length, name).toBeGreaterThan(0);
      for (const c of doc.cases) {
        expect(ids.has(c.id), `${name}: duplicate id ${c.id}`).toBe(false);
        ids.add(c.id);
        const check = CHECKS[c.check];
        expect(check, `${c.id}: unknown check ${c.check}`).toBeDefined();
        expect(c.role, c.id).toBe(check?.role);
        expect(check?.outcomes, c.id).toContain(c.expected.outcome);
        expect(typeof c.expected.reason, c.id).toBe("string");
        expect(Array.isArray(c.requires) && c.requires.length > 0, c.id).toBe(true);
        expect(Array.isArray(c.refs) && c.refs.length > 0, c.id).toBe(true);
        for (const cap of [...c.requires, ...(c.unless ?? [])]) {
          expect(KNOWN_CAPABILITIES.has(cap), `${c.id}: unknown capability ${cap}`).toBe(true);
        }
        if (c.unless !== undefined) expect(c.unless.length, `${c.id}: empty unless`).toBeGreaterThan(0);
        const carrier = CARRIERS[c.expected.outcome];
        if (carrier === undefined) {
          expect(c.expected.carrier, `${c.id}: no carrier on ${c.expected.outcome}`).toBeUndefined();
          expect(c.expected.error, `${c.id}: no error on ${c.expected.outcome}`).toBeUndefined();
        } else {
          expect(c.expected.carrier, c.id).toBe(carrier);
          expect(typeof c.expected.error, c.id).toBe("string");
        }
        if (c.expected.outcome === "deny") expect(["credential", "mission"], c.id).toContain(c.expected.authority_bound);
        if (c.expected.outcome === "established") expect(typeof c.expected.target, c.id).toBe("string");
      }
    }
  });

  it("covers every minimum case family #1276 names", () => {
    const all = files.flatMap(({ doc }) => doc.cases);
    const byCheck = (check: string, outcome: string) =>
      all.filter((c) => c.check === check && c.expected.outcome === outcome).length;
    expect(byCheck("evaluate", "permit")).toBeGreaterThan(0);
    expect(byCheck("evaluate", "deny")).toBeGreaterThan(0);
    expect(all.filter((c) => c.expected.error === "operation_target_invalid").length).toBeGreaterThan(0);
    expect(all.filter((c) => c.expected.error === "target_unresolvable").length).toBeGreaterThan(0);
    expect(byCheck("establish-target", "established")).toBeGreaterThan(0);
    expect(byCheck("permit-reuse", "re-evaluate")).toBeGreaterThan(0);
    expect(all.filter((c) => c.expected.error === "target_drift").length).toBeGreaterThan(0);
    expect(all.some((c) => c.requires.includes("pdp.resource-match.prefix"))).toBe(true);
  });

  for (const { name, doc } of files) {
    describe(`${doc.group} (${name})`, () => {
      for (const c of doc.cases) {
        const reason = skipReason(c);
        if (reason !== undefined) {
          it.skip(`${c.id}: ${c.description} [skipped: ${reason}]`, () => {});
        } else {
          it(`${c.id}: ${c.description}`, () => {
            throw new Error(`${c.id}: no executor for check ${c.check}`);
          });
        }
      }
    });
  }
});
