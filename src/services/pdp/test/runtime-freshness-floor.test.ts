/** @spec runtime#state-freshness — configuration and runtime share the floor. */
import { describe, it, expect } from "vitest";
import { evaluate, type EvaluationRequest, type EvaluateOptions, type MissionView, relationForAction } from "../src/index.js";
import { loadRuntimePosture, postureStalenessBound, RUNTIME_POSTURE } from "../src/runtime-posture.js";

describe("consequential freshness floor (@spec runtime#state-freshness)", () => {
  it("rejects disabling freshness for every consequential class at configuration load", () => {
    for (const actionClass of ["consequential_read", "consequential_write", "irreversible_action", "external_commitment", "privileged_administration"] as const) {
      const candidate = structuredClone(RUNTIME_POSTURE);
      candidate.state_source.per_class[actionClass] = { freshness_posture: "none" };
      expect(() => loadRuntimePosture(candidate), actionClass).toThrow("requires a freshness bound");
    }
  });

  it("refuses an injected no-freshness posture for consequential, undeclared and default classes", async () => {
    const view: MissionView = {
      id: "review-mission", issuer: "https://as.test", state: "active", version: 1,
      authority_hash: "sha-256:test", subject: { iss: "https://as.test", sub: "alice" }, client_id: "agent",
      authority_set: [{ type: "mission_resource_access", resource: "https://resource.test", actions: ["payments:payment.execute"] }],
    };
    const request: EvaluationRequest = {
      subject: { id: "alice" }, resource: { type: "invoice", id: "inv-1", properties: { vendor_id: "v1" } },
      action: { name: "payments:payment.execute" },
      context: { audience: "https://resource.test", mission: { id: view.id, issuer: view.issuer, authority_hash: view.authority_hash }, action_class: "irreversible_action", parameter_digest: "sha-256:params" },
    };
    const options: EvaluateOptions = {
      view, modelId: "review", now: () => new Date("2026-07-22T12:00:00Z"),
      fga: { checkWithContext: async () => true } as never,
      stalenessBound: () => ({ kind: "none" }), relationForAction,
    };
    for (const actionClass of [undefined, "consequential_read", "consequential_write", "irreversible_action", "external_commitment", "privileged_administration", "unknown"]) {
      request.context.action_class = actionClass;
      for (const freshness of [undefined, { source: "status", observed_at: "2026-07-22T12:00:00Z" }]) {
        request.context.freshness = freshness;
        const result = await evaluate(request, options);
        expect(result.decision, actionClass).toBe(false);
        expect(result.context.denial_reason).toBe("out_of_authority");
      }
    }
  });

  it("keeps the explicit audit-only exemption and the configured non-consequential window", () => {
    expect(postureStalenessBound(loadRuntimePosture(RUNTIME_POSTURE), "audit_only")).toEqual({ kind: "none" });
    expect(postureStalenessBound(loadRuntimePosture(RUNTIME_POSTURE), "non_consequential")).toEqual({ kind: "bounded", seconds: 300 });
  });
});
