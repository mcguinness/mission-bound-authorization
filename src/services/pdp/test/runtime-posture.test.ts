import { describe, expect, it } from "vitest";
import { RUNTIME_SCOPE_CONFIG, MISSION_MAX_STALE_SECONDS } from "@mission/demo-data";
import { loadRuntimePosture, postureStalenessBound, RUNTIME_CLASSES, RUNTIME_POSTURE } from "../src/runtime-posture.js";
import { stalenessBoundSeconds } from "../src/policy.js";

describe("published runtime posture (@spec runtime#runtime-operational, status#status-operational)", () => {
  it("publishes the enforced per-class bounds, issuer ceiling, recovery objective and beyond-bound refusal", () => {
    const published = JSON.parse(JSON.stringify(RUNTIME_POSTURE));
    expect(published.state_source.mission_max_stale_seconds).toBe(MISSION_MAX_STALE_SECONDS);
    for (const name of RUNTIME_CLASSES) {
      const declaration = published.state_source.per_class[name];
      expect(stalenessBoundSeconds(name)).toBe(declaration.max_staleness_seconds);
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

  it("a configured class change is consumed without mutating the original declaration", () => {
    const changed = structuredClone(RUNTIME_POSTURE);
    changed.state_source.per_class.consequential_read.max_staleness_seconds = 45;
    const loaded = loadRuntimePosture(changed);
    expect(postureStalenessBound(loaded, "consequential_read")).toBe(45);
    expect(stalenessBoundSeconds("consequential_read")).toBe(300);
    expect(postureStalenessBound(loaded, "unknown")).toBe(0);
    expect(postureStalenessBound(loaded, "__proto__")).toBe(0);
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
});
