import { describe, expect, it } from "vitest";
import { RUNTIME_SCOPE_CONFIG, MISSION_MAX_STALE_SECONDS } from "@mission/demo-data";
import { loadRuntimePosture, PostureConfigError, postureStalenessBound, RUNTIME_CLASSES, RUNTIME_POSTURE } from "../src/runtime-posture.js";
import { stalenessBound } from "../src/policy.js";

describe("published runtime posture (@spec runtime#runtime-operational, status#status-operational)", () => {
  it("publishes the enforced per-class bounds, issuer ceiling, recovery objective and beyond-bound refusal", () => {
    const published = JSON.parse(JSON.stringify(RUNTIME_POSTURE));
    expect(published.state_source.mission_max_stale_seconds).toBe(MISSION_MAX_STALE_SECONDS);
    for (const name of RUNTIME_CLASSES) {
      const declaration = published.state_source.per_class[name];
      const resolved = stalenessBound(name);
      if (declaration.freshness_posture === "none") {
        // @spec runtime#state-freshness — the draft's Audit-only row: no
        // active freshness required, declared as a posture and never as a
        // zero-second window.
        expect(resolved).toEqual({ kind: "none" });
        expect(declaration.max_staleness_seconds).toBeUndefined();
        continue;
      }
      expect(resolved).toEqual({ kind: "bounded", seconds: declaration.max_staleness_seconds });
      expect(declaration.max_staleness_seconds).toBeLessThanOrEqual(MISSION_MAX_STALE_SECONDS as number);
      expect(declaration.recovery_objective_seconds).toBe(60);
      expect(declaration.beyond_bound).toBe("deny");
    }
    expect(published.state_source.availability_consequence).toContain("outage never restarts observation age");
    expect(published.state_source.pdp_unavailability_posture).toBe("deny");
    expect(published.remote_decision_channels).toEqual([]);
    expect(published.state_source.replication).toBe("none");
    expect(published.state_source.break_glass).toBe("absent");
    expect(published.claims).toBeUndefined();
  });

  it("resolves every declared class to a window or to no active freshness, and an undeclared label to neither", () => {
    // The deployment declares a bound for `non_consequential`; the draft
    // prescribes no numeric value for it, so the number is read from the
    // statement, not from the code.
    expect(stalenessBound("non_consequential")).toEqual({
      kind: "bounded",
      seconds: (RUNTIME_POSTURE.state_source.per_class.non_consequential as { max_staleness_seconds: number }).max_staleness_seconds,
    });
    expect(stalenessBound("audit_only")).toEqual({ kind: "none" });
    expect(stalenessBound(undefined)).toEqual(stalenessBound("consequential_read"));
    for (const label of ["unknown", "__proto__", "toString", ""]) {
      expect(stalenessBound(label), label).toEqual({ kind: "undeclared" });
    }
  });

  it("a configured class change is consumed without mutating the original declaration", () => {
    const changed = structuredClone(RUNTIME_POSTURE);
    (changed.state_source.per_class.consequential_read as { max_staleness_seconds: number }).max_staleness_seconds = 45;
    const loaded = loadRuntimePosture(changed);
    expect(postureStalenessBound(loaded, "consequential_read")).toEqual({ kind: "bounded", seconds: 45 });
    expect(stalenessBound("consequential_read")).toEqual({ kind: "bounded", seconds: 300 });
    expect(postureStalenessBound(loaded, "unknown")).toEqual({ kind: "undeclared" });
    expect(postureStalenessBound(loaded, "__proto__")).toEqual({ kind: "undeclared" });
    expect(Object.isFrozen(loaded.state_source.per_class.consequential_read)).toBe(true);
  });

  it("refuses unsupported modes, malformed or missing bounds, and bounds exceeding the issuer ceiling", () => {
    for (const bad of [undefined, null, {}, "300", 0, -1, 1.5, Infinity, NaN, 301]) {
      const changed = structuredClone(RUNTIME_POSTURE) as any;
      changed.state_source.per_class.irreversible_action.max_staleness_seconds = bad;
      expect(() => loadRuntimePosture(changed), String(bad)).toThrow("invalid runtime posture");
    }
    for (const [key, value] of [["pdp_unavailability_posture", "permit_within_bounds"], ["pdp_unavailability_posture", "allow"], ["unknown_action_class", "default"], ["replication", "replica"], ["break_glass", "enabled"], ["per_class", null], ["availability_consequence", ""], ["mission_max_stale_seconds", 29]]) {
      const changed = structuredClone(RUNTIME_POSTURE) as any;
      changed.state_source[key as string] = value;
      expect(() => loadRuntimePosture(changed), String(key)).toThrow();
    }
    expect(() => loadRuntimePosture(null)).toThrow();
    expect(loadRuntimePosture(RUNTIME_SCOPE_CONFIG)).toEqual(RUNTIME_POSTURE);
  });

  it("refuses at load: an action class the code declares no posture for, a class missing its posture, and a no-freshness class carrying a bound", () => {
    // An undeclared label in the policy config is a configuration error the
    // deployment cannot boot with, never a label the PDP first meets at
    // decision time.
    const undeclaredClass = structuredClone(RUNTIME_POSTURE) as any;
    undeclaredClass.state_source.per_class.speculative_read = { freshness_posture: "bounded", max_staleness_seconds: 30, recovery_objective_seconds: 60, beyond_bound: "deny" };
    expect(() => loadRuntimePosture(undeclaredClass)).toThrow(PostureConfigError);
    expect(() => loadRuntimePosture(undeclaredClass)).toThrow("undeclared action class: speculative_read");

    // A declared class that states no freshness posture at all, and one that
    // claims a bound without supplying it: both refuse where the deployment
    // is loaded, so no class can resolve to a zero-second window.
    for (const mutate of [
      (p: any) => { delete p.state_source.per_class.consequential_write.freshness_posture; },
      (p: any) => { p.state_source.per_class.consequential_write = { freshness_posture: "bounded", recovery_objective_seconds: 60, beyond_bound: "deny" }; },
      (p: any) => { delete p.state_source.per_class.audit_only; },
      (p: any) => { p.state_source.per_class.audit_only = { freshness_posture: "none", max_staleness_seconds: 900 }; },
    ]) {
      const changed = structuredClone(RUNTIME_POSTURE) as any;
      mutate(changed);
      expect(() => loadRuntimePosture(changed)).toThrow(PostureConfigError);
    }
  });
});
