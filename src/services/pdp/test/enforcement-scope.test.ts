/**
 * @spec runtime#runtime-conformance — negative-conformance evidence for the
 * Enforcement Scope Statement's baseline declaration and the "MUST NOT
 * claim runtime enforcement ... outside that declared scope" rule: each
 * baseline member omitted in turn fails validation, a claimed extension
 * with no attached declaration fails validation, and a claim naming a
 * resource, action class, authority-entry type, or execution path outside
 * the declared scope is rejected. Positive fixtures (a complete baseline
 * statement, and one claiming an extension with its declaration attached)
 * cover core-only and core-plus-one-extension, so the negative cases are
 * not the only path through the validator.
 */

import { describe, expect, it } from "vitest";
import {
  claimsWithinScope,
  resourceDispositions,
  type EnforcementScopeStatement,
  validateEnforcementScopeStatement,
} from "../src/enforcement-scope.js";

const RESOURCE = "http://localhost:4403/mcp";

const baseline = (): EnforcementScopeStatement => ({
  mediated_scope: {
    resources: [RESOURCE],
    action_classes: ["irreversible_action"],
    execution_paths: ["mcp:tools/call"],
    pep_locations: ["mcp-payments-pep"],
    excluded_paths: [],
    mission_establishment_mode: "token-claim",
  },
  authority_entry_types: [{ type: "mission_resource_access", evaluator: "fga-contextual-check" }],
  pdps: ["mcp-payments-pdp"],
  state_source: {
    source: "status",
    max_staleness_seconds: 30,
    pdp_unavailability_posture: "deny",
  },
  remote_decision_channels: [{ boundary: RESOURCE, trust_mode: "signed-request-response" }],
  record_integrity_mechanism: "hash-linked-log",
});

describe("Perimeter dispositions inside mediated_scope (@spec runtime#runtime-conformance)", () => {
  const statement = (resources: unknown, excluded_paths: unknown = []) => ({
    ...baseline(), mediated_scope: { ...baseline().mediated_scope, resources, excluded_paths },
  });
  it("the draft's nested resources and excluded paths validate", () => {
    expect(validateEnforcementScopeStatement(statement([
      { resource: RESOURCE, disposition: "mediated" },
      { resource: "https://warehouse.example.com/sales", disposition: "reconstructed" },
    ], [{ path: "notebook_interpreter", disposition: "unrecorded" }]))).toEqual([]);
  });
  it("a bare resource string is the mediated shorthand and validates", () => {
    const stmt = statement([RESOURCE]);
    expect(validateEnforcementScopeStatement(stmt)).toEqual([]);
    expect(resourceDispositions(stmt).get(RESOURCE)).toBe("mediated");
  });
  it.each([
    ["missing disposition", [{ resource: RESOURCE }], []],
    ["unknown disposition", [{ resource: RESOURCE, disposition: "other" }], []],
    ["bare excluded path", [RESOURCE], ["notebook_interpreter"]],
    ["mediated excluded path", [RESOURCE], [{ path: "notebook_interpreter", disposition: "mediated" }]],
    ["conflicting resource dispositions", [RESOURCE, { resource: RESOURCE, disposition: "reconstructed" }], []],
    ["conflicting excluded dispositions", [RESOURCE], [{ path: "notebook_interpreter", disposition: "unrecorded" }, { path: "notebook_interpreter", disposition: "reconstructed" }]],
  ])("refuses %s and names the offending entry", (_label, resources, excluded) => {
    const stmt = statement(resources, excluded);
    expect(validateEnforcementScopeStatement(stmt)).toEqual(expect.arrayContaining([
      expect.objectContaining({ member: expect.stringMatching(/^mediated_scope\.(resources|excluded_paths)\[\d+\]$/) }),
    ]));
    expect(claimsWithinScope(stmt, { resource: RESOURCE })).toBe(false);
  });
  it("identical repeated keys normalize to one entry and validate", () => {
    const stmt = statement([RESOURCE, { resource: RESOURCE, disposition: "mediated" }], [
      { path: "excluded", disposition: "unrecorded" }, { path: "excluded", disposition: "unrecorded" },
    ]);
    expect(validateEnforcementScopeStatement(stmt)).toEqual([]);
    expect(resourceDispositions(stmt).size).toBe(1);
  });
  it.each(["reconstructed", "unrecorded"])("a claim naming a %s resource is rejected", (disposition) => {
    const stmt = statement([{ resource: RESOURCE, disposition }]);
    expect(validateEnforcementScopeStatement(stmt)).toEqual([]);
    expect(claimsWithinScope(stmt, { resource: RESOURCE })).toBe(false);
  });
  it("an excluded execution path refuses even when it is also declared", () => {
    const stmt = statement([RESOURCE], [{ path: "mcp:tools/call", disposition: "unrecorded" }]);
    expect(validateEnforcementScopeStatement(stmt)).toEqual([]);
    expect(claimsWithinScope(stmt, { resource: RESOURCE, execution_path: "mcp:tools/call" })).toBe(false);
  });
  it("a mediated resource on a declared nonexcluded path is accepted", () => {
    const stmt = statement([{ resource: RESOURCE, disposition: "mediated" }]);
    expect(claimsWithinScope(stmt, { resource: RESOURCE, execution_path: "mcp:tools/call" })).toBe(true);
  });
  it("conflicts and malformed duplicates refuse in either order and cannot be repaired by a third duplicate", () => {
    for (const bad of [{ resource: RESOURCE, disposition: "reconstructed" }, { resource: RESOURCE }]) {
      for (const entries of [[RESOURCE, bad], [bad, RESOURCE], [RESOURCE, bad, RESOURCE]]) {
        const stmt = statement(entries);
        expect(resourceDispositions(stmt).size).toBe(0);
        expect(claimsWithinScope(stmt, { resource: RESOURCE })).toBe(false);
      }
    }
  });
  it("malformed JSON containers and entries yield findings rather than throwing or widening claims", () => {
    for (const input of [null, [], 42, {},
      { ...baseline(), mediated_scope: null },
      statement(null), statement([null]), statement([RESOURCE], [null]),
      statement([RESOURCE], [{ disposition: "unrecorded" }]),
      { ...baseline(), state_source: null },
      { ...baseline(), authority_entry_types: [null] },
      { ...baseline(), remote_decision_channels: [null] },
    ]) {
      expect(validateEnforcementScopeStatement(input).length).toBeGreaterThan(0);
      expect(claimsWithinScope(input, { resource: RESOURCE })).toBe(false);
    }
  });
});

/** Removes one key entirely (not `undefined`-assigned) so the statement is
 * genuinely missing that baseline member, not merely holding an explicit
 * `undefined` under it. */
function omit<K extends keyof EnforcementScopeStatement>(
  stmt: EnforcementScopeStatement,
  key: K,
): Partial<EnforcementScopeStatement> {
  const clone: Partial<EnforcementScopeStatement> = { ...stmt };
  delete clone[key];
  return clone;
}

describe("Enforcement Scope Statement validation (@spec runtime#runtime-conformance)", () => {
  it("a complete baseline statement is valid", () => {
    expect(validateEnforcementScopeStatement(baseline())).toEqual([]);
  });

  it("a statement claiming one extension with its attached declaration is valid", () => {
    const stmt: EnforcementScopeStatement = {
      ...baseline(),
      claims: ["custody"],
      extensions: { custody: [{ mediated_class: "irreversible_action", custody_mode: "mediated-execution" }] },
    };
    expect(validateEnforcementScopeStatement(stmt)).toEqual([]);
  });

  it("omitting mediated_scope fails validation, naming that member", () => {
    const findings = validateEnforcementScopeStatement(omit(baseline(), "mediated_scope"));
    expect(findings.some((f) => f.member === "mediated_scope")).toBe(true);
  });

  it("omitting authority_entry_types fails validation, naming that member", () => {
    const findings = validateEnforcementScopeStatement(omit(baseline(), "authority_entry_types"));
    expect(findings.some((f) => f.member === "authority_entry_types")).toBe(true);
  });

  it("omitting pdps fails validation, naming that member", () => {
    const findings = validateEnforcementScopeStatement(omit(baseline(), "pdps"));
    expect(findings.some((f) => f.member === "pdps")).toBe(true);
  });

  it("omitting state_source fails validation, naming that member", () => {
    const findings = validateEnforcementScopeStatement(omit(baseline(), "state_source"));
    expect(findings.some((f) => f.member === "state_source")).toBe(true);
  });

  it("omitting remote_decision_channels fails validation, naming that member", () => {
    const findings = validateEnforcementScopeStatement(omit(baseline(), "remote_decision_channels"));
    expect(findings.some((f) => f.member === "remote_decision_channels")).toBe(true);
  });

  it("omitting record_integrity_mechanism fails validation, naming that member", () => {
    const findings = validateEnforcementScopeStatement(omit(baseline(), "record_integrity_mechanism"));
    expect(findings.some((f) => f.member === "record_integrity_mechanism")).toBe(true);
  });

  it("an empty remote_decision_channels array is valid (a wholly co-resident deployment)", () => {
    const stmt: EnforcementScopeStatement = { ...baseline(), remote_decision_channels: [] };
    expect(validateEnforcementScopeStatement(stmt)).toEqual([]);
  });

  it("claiming an extension with no attached declaration fails validation", () => {
    const stmt: EnforcementScopeStatement = { ...baseline(), claims: ["outcome_reconciliation"] };
    const findings = validateEnforcementScopeStatement(stmt);
    expect(findings.some((f) => f.member === "extensions.outcome_reconciliation")).toBe(true);
  });

  it("a claim within the declared scope passes claimsWithinScope", () => {
    const stmt = baseline();
    expect(
      claimsWithinScope(stmt, {
        resource: RESOURCE,
        action_class: "irreversible_action",
        authority_entry_type: "mission_resource_access",
        execution_path: "mcp:tools/call",
      }),
    ).toBe(true);
  });

  it("a claim naming a resource outside the declared scope is rejected", () => {
    const stmt = baseline();
    expect(claimsWithinScope(stmt, { resource: "http://localhost:9999/other" })).toBe(false);
  });

  it("a claim naming an action class outside the declared scope is rejected", () => {
    const stmt = baseline();
    expect(claimsWithinScope(stmt, { resource: RESOURCE, action_class: "privileged_administration" })).toBe(false);
  });

  it("a claim naming an authority-entry type outside the declared scope is rejected", () => {
    const stmt = baseline();
    expect(claimsWithinScope(stmt, { resource: RESOURCE, authority_entry_type: "unrecognized_type" })).toBe(false);
  });

  it("a claim naming an execution path outside the declared scope is rejected", () => {
    const stmt = baseline();
    expect(claimsWithinScope(stmt, { resource: RESOURCE, execution_path: "mcp:tools/unlisted" })).toBe(false);
  });
});
