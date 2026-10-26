/**
 * @spec runtime#input-authority-dependency (#830, D798): "A deployment that
 * declares an authority dependency MUST state in its Enforcement Scope
 * Statement" the dependency, its source and the state an observation
 * represents; what it governs; the invalidating changes; its maximum
 * staleness, separately from the Mission-state freshness declaration; its
 * enforcement route; and how reliance is restored and responsibility passes
 * to a successor.
 *
 * The deployment's declaration is `config/authority-dependencies.json`; a
 * composition that enforces it states it in its statement
 * (`withAuthorityDependencies`), and the statement's strict loader refuses a
 * declaration missing any element.
 */

import { AUTHORITY_DEPENDENCIES } from "@mission/demo-data";
import { describe, expect, it } from "vitest";
import { loadRuntimePosture, RUNTIME_POSTURE, withAuthorityDependencies } from "../src/runtime-posture.js";

const shipped = () => JSON.parse(JSON.stringify(AUTHORITY_DEPENDENCIES[0])) as Record<string, unknown>;

describe("the deployment's Enforcement Scope Statement declares its authority dependency (@spec runtime#input-authority-dependency, #830)", () => {
  it("states every element the Runtime requires, the staleness bound apart from the Mission-state freshness declaration", () => {
    const statement = withAuthorityDependencies(RUNTIME_POSTURE, AUTHORITY_DEPENDENCIES);
    const [declared] = (statement.extensions?.authority_dependencies ?? []) as Record<string, unknown>[];
    expect(declared).toMatchObject({
      id: "subject-delegation",
      dependency: expect.stringContaining("continuing delegation"),
      source: { id: "reference-identity-source", description: expect.stringContaining("identity source") },
      observation: expect.stringContaining("account status"),
      governs: { authority_sources: ["user_delegated"], scope: expect.stringContaining("Existing Missions") },
      invalidating_changes: ["subject_disabled", "subject_deprovisioned", "delegation_withdrawn"],
      max_staleness_seconds: 300,
      online_check: false,
      enforcement: { direct: "pdp", lifecycle: false },
      recovery: expect.stringContaining("revives no terminated Mission"),
      responsibility_transfer: expect.stringContaining("attribution is unchanged"),
    });
    // A member of its own, not one of the Mission-state freshness rows.
    expect(statement.state_source).toEqual(RUNTIME_POSTURE.state_source);
    // A composition that enforces none states none.
    expect(withAuthorityDependencies(RUNTIME_POSTURE, [])).toBe(RUNTIME_POSTURE);
  });

  it("refuses at load a declaration missing any element, or one that names no enforcement route or a non-positive staleness", () => {
    const load = (declaration: Record<string, unknown>) =>
      loadRuntimePosture({ ...RUNTIME_POSTURE, extensions: { ...RUNTIME_POSTURE.extensions, authority_dependencies: [declaration] } });
    expect(() => load(shipped())).not.toThrow();
    for (const member of [
      "id",
      "dependency",
      "source",
      "observation",
      "governs",
      "invalidating_changes",
      "max_staleness_seconds",
      "online_check",
      "enforcement",
      "recovery",
      "responsibility_transfer",
    ]) {
      const declaration = shipped();
      delete declaration[member];
      expect(() => load(declaration), member).toThrow(new RegExp(`missing ${member}`));
    }
    expect(() => load({ ...shipped(), enforcement: { lifecycle: false } })).toThrow(/names no route/);
    expect(() => load({ ...shipped(), max_staleness_seconds: 0 })).toThrow(/max_staleness_seconds must be a positive integer/);
    expect(() => load({ ...shipped(), governs: { authority_sources: [], scope: "x" } })).toThrow(/authority_sources/);
    expect(() => load({ ...shipped(), invalidating_changes: ["approver_departed"] })).toThrow(/invalidating_changes/);
    expect(() => load({ ...shipped(), extra: true })).toThrow(/unknown member extra/);
  });
});
