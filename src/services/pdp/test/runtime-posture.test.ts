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
    // @spec authzen#context-audience-freshness: the PEP supplies state.
    expect(published.state_source.placement).toBe("pep");
    expect(published.remote_decision_channels).toEqual([]);
    expect(published.state_source.replication).toBe("none");
    expect(published.state_source.break_glass).toBe("absent");
    // @spec runtime#execution-reverification, runtime#runtime-conformance
    // (#252 C) — this deployment now CLAIMS the transaction-assurance tier,
    // because it publishes that tier's execution lease maximum and the
    // executing PEP caps its own lease by the published number. The claim was
    // previously absent, so this expectation moved with the declaration it
    // describes rather than being relaxed: the statement asserts exactly the
    // one tier whose declaration it carries.
    // The declaration exists without the capability being claimed: ten rows
    // gated on this tier are still unmet, two of them blocked, so the shipped
    // statement asserts nothing it cannot meet (#252 C1). Its one claim is
    // Evaluation-Context Binding at the verified property (#773), whose
    // declaration it carries.
    expect(published.claims).toEqual(["evaluation_context_binding"]);
    expect(published.claims).not.toContain("transaction_assurance");
    for (const declaration of published.extensions.transaction_assurance) {
      expect(published.mediated_scope.action_classes).toContain(declaration.mediated_class_or_scope);
      expect(published.mediated_scope.pep_locations).toContain(declaration.execution_lease_consumer);
      expect(declaration.execution_lease_max_seconds).toBeGreaterThan(0);
      // @spec runtime#idempotency (#917): the claim domain is named per
      // class, never per key: the PDP that owns it (a declared PDP), the
      // Exact profile and the single-writer topology it runs under.
      expect(declaration.idempotency_claim_domain).toContain("pdp-local");
      expect(published.pdps).toContain(declaration.idempotency_claim_owner);
      expect(declaration.idempotency_enforcement_profile).toBe("exact");
      expect(declaration.idempotency_claim_topology).toBe("local-single-writer");
    }
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
    // @spec runtime#classification (#956, D814): a missing class is not a
    // class. It resolves to `undeclared`, never to the consequential_read window.
    expect(stalenessBound(undefined)).toEqual({ kind: "undeclared" });
    expect(stalenessBound(undefined)).not.toEqual(stalenessBound("consequential_read"));
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
    for (const [key, value] of [["pdp_unavailability_posture", "permit_within_bounds"], ["pdp_unavailability_posture", "allow"], ["unknown_action_class", "default"], ["replication", "replica"], ["break_glass", "enabled"], ["per_class", null], ["availability_consequence", ""], ["mission_max_stale_seconds", 29], ["placement", undefined], ["placement", "both"]]) {
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

/**
 * @spec runtime#evaluation-context-binding (#773): "A claiming deployment MUST
 * publish the covered classes and operations, each operation's versioned
 * binding descriptor, and whether it reaches the verified or enforced
 * property". The loader refuses a claim that does not, a descriptor whose
 * published bytes no longer hash to its reference, and an enforced property
 * no declared capability supports. Each case mutates one member of the
 * shipped declaration and loads it under the claim.
 */
describe("the Evaluation-Context Binding declaration is refused at load unless complete (@spec runtime#evaluation-context-binding, #773)", () => {
  const claimed = (mutate: (ecb: any, s: any) => void = () => {}) => {
    const s = structuredClone(RUNTIME_SCOPE_CONFIG) as any;
    s.claims = ["evaluation_context_binding"];
    mutate(s.extensions.evaluation_context_binding, s);
    return s;
  };

  it("admits the shipped declaration, publishing each covered operation's class, descriptor reference and the verified property", () => {
    const posture = loadRuntimePosture(claimed()) as any;
    const ecb = posture.extensions.evaluation_context_binding;
    expect(ecb.covered_classes).toEqual(["irreversible_action", "external_commitment"]);
    for (const o of ecb.operations) {
      expect(ecb.covered_classes).toContain(o.action_class);
      expect(o.property).toBe("verified");
      expect(ecb.descriptors.some((d: any) => d.id === o.descriptor.id && d.version === o.descriptor.version && d.digest === o.descriptor.digest)).toBe(true);
    }
    for (const d of ecb.descriptors) {
      expect(d.document.facts.length).toBeGreaterThan(0);
      for (const f of d.document.facts) {
        expect(typeof f.resolver).toBe("string");
        expect(["revision", "effective_values"]).toContain(f.granularity);
        expect(typeof f.normalization).toBe("string");
      }
    }
  });

  it("a claiming class without an operation, a descriptor or a resolver is refused at load", () => {
    const cases: Array<[string, (ecb: any, s: any) => void, RegExp]> = [
      ["no declaration", (_e, s) => { delete s.extensions.evaluation_context_binding; }, /claimed but carries no attached declaration|claimed with no declaration/],
      ["no operation", (e) => { e.operations = []; }, /at least one covered operation/],
      ["a covered class with no operation", (e) => { e.operations = e.operations.filter((o: any) => o.action_class !== "external_commitment"); }, /covered class external_commitment declares no operation/],
      ["an operation with no descriptor", (e) => { delete e.operations[0].descriptor; }, /operations\[0\]\.descriptor must be an object/],
      ["a descriptor reference naming no declared descriptor", (e) => { e.operations[0].descriptor = { ...e.operations[0].descriptor, version: "1999-01-01" }; }, /resolves to no declared descriptor/],
      ["a fact naming no resolver", (e) => { delete e.descriptors[0].document.facts[0].resolver; }, /names no authoritative resolver|does not hash/],
      ["a fact with an undeclared granularity", (e) => { e.descriptors[0].document.facts[0].granularity = "snapshot"; }, /granularity|does not hash/],
    ];
    for (const [label, mutate, problem] of cases) {
      expect(() => loadRuntimePosture(claimed(mutate)), label).toThrow(PostureConfigError);
      expect(() => loadRuntimePosture(claimed(mutate)), label).toThrow(problem);
    }
  });

  it("a fact naming no resolver is refused even when its descriptor's digest is recomputed over the changed bytes", async () => {
    const { canonicalDigest } = await import("@mission/core");
    const s = claimed((e) => {
      const d = e.descriptors[0];
      delete d.document.facts[0].resolver;
      d.digest = canonicalDigest(d.document);
      for (const o of e.operations) if (o.descriptor.id === d.id && o.descriptor.version === d.version) o.descriptor.digest = d.digest;
    });
    expect(() => loadRuntimePosture(s)).toThrow(/names no authoritative resolver/);
  });

  it("refuses at load a descriptor whose published bytes no longer hash to its reference", () => {
    const changed = claimed((e) => {
      e.descriptors[0].document.facts[0].normalization = "string";
    });
    expect(() => loadRuntimePosture(changed)).toThrow(/does not hash to its reference's digest/);
    // The same check holds for a declaration present without the claim.
    const unclaimed = structuredClone(RUNTIME_SCOPE_CONFIG) as any;
    unclaimed.extensions.evaluation_context_binding.descriptors[0].document.targets = ["invoice"];
    expect(() => loadRuntimePosture(unclaimed)).toThrow(/does not hash to its reference's digest/);
  });

  it("refuses at load an enforced property no execution capability supports, and a covered class outside the mediated scope", () => {
    expect(() => loadRuntimePosture(claimed((e) => { e.operations[0].property = "enforced"; }))).toThrow(
      /enforced property for payments:payment.execute with no execution capability asserting evaluation_context_enforced/,
    );
    expect(() =>
      loadRuntimePosture(
        claimed((e, s) => {
          // The class leaves the mediated scope with every other declaration that names it.
          s.mediated_scope.action_classes = s.mediated_scope.action_classes.filter((c: string) => c !== "external_commitment");
          s.extensions.transaction_assurance = s.extensions.transaction_assurance.filter(
            (d: any) => d.mediated_class_or_scope !== "external_commitment",
          );
          s.extensions.execution_capabilities = s.extensions.execution_capabilities.filter(
            (d: any) => d.action_class !== "external_commitment",
          );
        }),
      ),
    ).toThrow(/covered class \W+external_commitment\W+ is outside mediated_scope.action_classes/);
  });
});
