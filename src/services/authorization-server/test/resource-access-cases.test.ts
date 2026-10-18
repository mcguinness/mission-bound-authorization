/**
 * @spec resource-access (#1258, D452): the reference implementation's reader for the
 * Mission Resource Access expected-outcome cases in `vectors/mission-resource-access/`.
 *
 * It validates every case file, then runs each case whose `requires` capabilities
 * this implementation has, and reports every other case as skipped with the missing
 * capability in its name. A skipped case is not evidence; a run case is helper-level
 * evidence only (it does not establish endpoint or resource-server enforcement), so
 * ledger rows cite these runs only where the row's role and surface match.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  delegatePermitted,
  deriveAuthoritySet,
  IntentError,
  isSubsetEntry,
  type MissionIntent,
} from "../src/index.js";

const DIR = fileURLToPath(new URL("../../../../vectors/mission-resource-access/", import.meta.url));
const FORMAT = "mission-resource-access-cases/1";

/** Capabilities this reference implementation runs cases for. */
const IMPLEMENTED = new Set([
  "subset.exact-resource",
  "constraint.max_amount",
  "constraint.requires_action_approval",
  "refusal.unsupported-input",
  "delegate-matcher",
]);

/** The declared capability vocabulary (README.md). */
const KNOWN_CAPABILITIES = new Set([
  ...IMPLEMENTED,
  "operation-target",
  "resource-match.exact",
  "resource-match.prefix",
  "action-families",
  "constraint.resource_issued_after",
  "constraint.resource_issued_before",
  "constraint.tenant",
  "constraint.recipient_domain",
  "constraint.time_window",
  "constraint.data_classification",
  "constraint.allowed_tools",
  "refusal.locations",
  "rs.enforcement",
  "rs.alternative-grants",
  "rs.member-roles",
  "delegation.policy",
  "delegation.inherited-eligibility",
  "transformation-capabilities",
  "scope-projection",
]);

/** The outcomes each check may expect. */
const OUTCOMES: Record<string, readonly string[]> = {
  "resource-match": ["match", "no-match"],
  "target-resolution": ["refuse-resolution", "no-match"],
  subset: ["subset", "not-subset"],
  derive: ["derived", "refuse"],
  "delegate-matcher": ["permitted", "not-permitted"],
  "delegate-eligibility": ["eligible", "not-eligible", "narrowed-out"],
  "rs-authorize": ["allow", "deny", "reject-token"],
  "capability-declaration": ["declared", "invalid-claim"],
  issuance: ["issue", "refuse-issuance", "refuse"],
  projection: ["safe", "unsafe"],
};

interface Case {
  id: string;
  description: string;
  role: string;
  requires: string[];
  check: string;
  input: Record<string, unknown>;
  expected: { outcome: string; reason: string; error?: string; entries?: AuthorityEntry[] };
  refs: string[];
}
interface CaseFile {
  format: string;
  group: string;
  description: string;
  cases: Case[];
}

const files = readdirSync(DIR)
  .filter((f) => f.endsWith(".json"))
  .sort()
  .map((f) => ({ name: f, doc: JSON.parse(readFileSync(join(DIR, f), "utf8")) as CaseFile }));

const intent = { target_resources: ["https://api.example/orders", "https://erp.example.com"] } as unknown as MissionIntent;

/** Runs one case against this implementation; called only when every required capability is implemented. */
function run(c: Case): void {
  const input = c.input;
  switch (c.check) {
    case "subset": {
      const result = isSubsetEntry(input.candidate as AuthorityEntry, input.reference as AuthorityEntry);
      expect(result, c.expected.reason).toBe(c.expected.outcome === "subset");
      return;
    }
    case "derive": {
      const derive = () =>
        deriveAuthoritySet(
          intent,
          { policy_version: "resource-access-cases", ceiling: input.ceiling as AuthorityEntry[] },
          input.proposal as AuthorityEntry[] | undefined,
        );
      if (c.expected.outcome === "refuse") {
        let error: unknown;
        try {
          derive();
        } catch (e) {
          error = e;
        }
        expect(error, c.expected.reason).toBeInstanceOf(IntentError);
        expect((error as IntentError).code).toBe(c.expected.error);
      } else {
        expect(derive(), c.expected.reason).toEqual(c.expected.entries);
      }
      return;
    }
    case "delegate-matcher": {
      const delegate = input.delegate as { sub: string; sub_profile?: string };
      const matchers = (input.allowed_delegates ?? undefined) as Parameters<typeof delegatePermitted>[1];
      // Only an AS-asserted profile reaches the matcher; a self-asserted one never does.
      const permitted = delegatePermitted({ sub: delegate.sub, assertedProfile: delegate.sub_profile }, matchers);
      expect(permitted, c.expected.reason).toBe(c.expected.outcome === "permitted");
      return;
    }
    default:
      throw new Error(`${c.id}: no executor for check ${c.check}`);
  }
}

const EXECUTABLE_CHECKS = new Set(["subset", "derive", "delegate-matcher"]);

describe("Mission Resource Access expected-outcome cases (#1258, D452)", () => {
  it("validates every case file: format, group, unique ids, roles, checks, outcomes and capabilities", () => {
    expect(files.length).toBeGreaterThan(0);
    const ids = new Set<string>();
    for (const { name, doc } of files) {
      expect(doc.format, name).toBe(FORMAT);
      expect(`${doc.group}.json`, name).toBe(name);
      expect(doc.cases.length, name).toBeGreaterThan(0);
      for (const c of doc.cases) {
        expect(ids.has(c.id), `${name}: duplicate id ${c.id}`).toBe(false);
        ids.add(c.id);
        expect(["authorization-server", "resource-server"], c.id).toContain(c.role);
        expect(Object.keys(OUTCOMES), c.id).toContain(c.check);
        expect(OUTCOMES[c.check], c.id).toContain(c.expected.outcome);
        expect(typeof c.expected.reason, c.id).toBe("string");
        expect(Array.isArray(c.requires) && Array.isArray(c.refs) && c.refs.length > 0, c.id).toBe(true);
        for (const cap of c.requires) expect(KNOWN_CAPABILITIES.has(cap), `${c.id}: unknown capability ${cap}`).toBe(true);
        if (c.expected.outcome === "refuse") expect(typeof c.expected.error, c.id).toBe("string");
      }
    }
  });

  for (const { name, doc } of files) {
    describe(`${doc.group} (${name})`, () => {
      for (const c of doc.cases) {
        const missing = c.requires.filter((cap) => !IMPLEMENTED.has(cap));
        if (!EXECUTABLE_CHECKS.has(c.check) && missing.length === 0) missing.push(`executor:${c.check}`);
        if (missing.length > 0) {
          it.skip(`${c.id}: ${c.description} [skipped: requires ${missing.join(", ")}]`, () => {});
        } else {
          it(`${c.id}: ${c.description}`, () => run(c));
        }
      }
    });
  }
});
