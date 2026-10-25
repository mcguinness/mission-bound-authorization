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
      enforcement: {
        direct: "pdp",
        lifecycle: true,
        reconciliation_max_lag_seconds: 60,
        lifecycle_operations: { subject_disabled: "suspend", delegation_withdrawn: "suspend", subject_deprovisioned: "revoke" },
      },
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
    // Lifecycle-mediated enforcement states its lag bound and its operations.
    const enforcement = shipped().enforcement as Record<string, unknown>;
    const { reconciliation_max_lag_seconds: _lag, ...noLag } = enforcement;
    expect(() => load({ ...shipped(), enforcement: noLag })).toThrow(/reconciliation_max_lag_seconds/);
    const { lifecycle_operations: _ops, ...noOps } = enforcement;
    expect(() => load({ ...shipped(), enforcement: noOps })).toThrow(/lifecycle_operations/);
    expect(() => load({ ...shipped(), enforcement: { ...enforcement, lifecycle_operations: { subject_disabled: "delete" } } })).toThrow(
      /must be suspend or revoke/,
    );
  });

  it("@spec runtime#state-freshness (#830): states its bound from an external authority change from start to end, work already started separately, and the path the claim accounts for", () => {
    const statement = withAuthorityDependencies(RUNTIME_POSTURE, AUTHORITY_DEPENDENCIES);
    const [declared] = (statement.extensions?.authority_dependencies ?? []) as { external_change_bound?: Record<string, unknown> }[];
    expect(declared?.external_change_bound).toMatchObject({
      seconds: 60,
      start: expect.stringContaining("identity source records the change"),
      end: expect.stringContaining("can begin an effect"),
      already_started: expect.stringMatching(/Permit issuance is not already-started work.*valid_until/s),
      path: expect.stringMatching(/Detection.*Evaluation.*State change.*Downstream reliance.*Permit validity.*Release/s),
      // The periods the path names, covered by the bound in sequence.
      detection_period_seconds: 30,
      reconciliation_period_seconds: 30,
    });
    // The claim states its failure behavior too: a measured success is not the bound under failure.
    expect(declared?.external_change_bound?.path).toEqual(expect.stringContaining("when the source cannot be read or a reconciliation fails"));
    const load = (bound: Record<string, unknown>) =>
      loadRuntimePosture({
        ...RUNTIME_POSTURE,
        extensions: { ...RUNTIME_POSTURE.extensions, authority_dependencies: [{ ...shipped(), external_change_bound: bound }] },
      });
    const bound = shipped().external_change_bound as Record<string, unknown>;
    for (const member of ["seconds", "start", "end", "already_started", "path", "detection_period_seconds"]) {
      const { [member]: _dropped, ...partial } = bound;
      expect(() => load(partial), member).toThrow(new RegExp(`external_change_bound is missing ${member}`));
    }
    expect(() => load({ ...bound, seconds: 0 })).toThrow(/external_change_bound.seconds must be a positive integer/);
    // A bound that does not cover one detection period and one reconciliation period in sequence is refused.
    expect(() => load({ ...bound, seconds: 59 })).toThrow(/must cover one detection period and one reconciliation period/);
    expect(() => load({ ...bound, detection_period_seconds: 31 })).toThrow(/must cover one detection period and one reconciliation period/);
    // A reconciler runs on a declared period shorter than its lag bound, and only where one runs.
    const { reconciliation_period_seconds: _period, ...noPeriod } = bound;
    expect(() => load(noPeriod)).toThrow(/reconciliation_period_seconds must be a positive integer under lifecycle-mediated enforcement/);
    expect(() => load({ ...bound, seconds: 120, reconciliation_period_seconds: 60 })).toThrow(
      /reconciliation_period_seconds must be shorter than enforcement.reconciliation_max_lag_seconds/,
    );
    expect(() =>
      loadRuntimePosture({
        ...RUNTIME_POSTURE,
        extensions: {
          ...RUNTIME_POSTURE.extensions,
          authority_dependencies: [{ ...shipped(), enforcement: { direct: "pdp", lifecycle: false }, external_change_bound: bound }],
        },
      }),
    ).toThrow(/reconciliation_period_seconds applies to lifecycle-mediated enforcement only/);
  });
});
