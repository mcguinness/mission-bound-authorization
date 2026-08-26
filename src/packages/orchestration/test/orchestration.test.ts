import { createHmac } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  type AuthorityNarrowingStepInput,
  buildAuthorityNarrowingEvidence,
  buildOrchestrationEvidence,
  classifyOutcome,
  commitUnwindPlan,
  deriveReversibility,
  type EnvelopeSigner,
  enforceReversibilityFloor,
  floorReversibility,
  isHighRiskUnknown,
  ORCHESTRATION_EVIDENCE_TYP,
  onMissionStateChange,
  reEvaluateOnAuthorityNarrowing,
  reEvaluateStepOnAuthorityNarrowing,
  requiresHumanReview,
  resolveCompensationAuthority,
  reverseDependencyOrder,
  type UnwindPlan,
  unwindPlanHash,
  unwindTerminalState,
  validateUnwindPlan,
} from "../src/index.js";

const ISS = "https://as.example.com";

// The draft's worked unwind plan (§ worked-unwind-plan). Member order is
// irrelevant: the anchor canonicalizes (JCS) before hashing.
const WORKED_PLAN: UnwindPlan = {
  step_id: "post_journal_entry",
  mission_id: "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  reversibility: "irreversible_action",
  pre_start_behavior: "human_review",
  in_flight_behavior: "wait_then_review",
  post_completion_behavior: "human_review",
  review_queue: "finance-control-review",
  evidence_policy: { link_runtime_evidence: true, retain_for: "mission_audit_horizon" },
};

const PUBLISHED_HASH = "sha-256:jKxM47ygRiTXYVfKjrVE34VZx8nsxg1I9OPPeHnO-_c";

const MISSION = {
  id: "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  issuer: ISS,
  authority_hash: "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
};

// A deterministic HS256 JWS-Compact signer, so the envelope test is pure and
// reproducible. The protected header carries kid, alg, typ as the draft MUSTs.
function makeSigner(secret: string, kid: string): EnvelopeSigner {
  return (payload: string): string => {
    const header = { alg: "HS256", kid, typ: ORCHESTRATION_EVIDENCE_TYP };
    const h = Buffer.from(JSON.stringify(header), "utf8").toString("base64url");
    const p = Buffer.from(payload, "utf8").toString("base64url");
    const signingInput = `${h}.${p}`;
    const sig = createHmac("sha256", secret).update(signingInput).digest("base64url");
    return `${signingInput}.${sig}`;
  };
}

describe("unwind plan integrity (@spec orchestration#unwind-plan-integrity, mission#test-vectors)", () => {
  it("1: reproduces the draft's published unwind_plan_hash byte-exact", () => {
    expect(unwindPlanHash(ISS, WORKED_PLAN)).toBe(PUBLISHED_HASH);
  });

  it("2: dispatch is fail-closed and the commit is strictly before dispatch", () => {
    const order: string[] = [];
    const ok = commitUnwindPlan({
      iss: ISS,
      plan: WORKED_PLAN,
      commit: (hash) => {
        expect(hash).toBe(PUBLISHED_HASH);
        order.push("commit");
        return { ok: true };
      },
    });
    if (ok.dispatch) order.push("dispatch");
    expect(order).toEqual(["commit", "dispatch"]);
    expect(ok.unwind_plan_hash).toBe(PUBLISHED_HASH);

    // A failed commit write MUST prevent dispatch (no "dispatch" recorded).
    const order2: string[] = [];
    const bad = commitUnwindPlan({
      iss: ISS,
      plan: WORKED_PLAN,
      commit: () => {
        order2.push("commit");
        return { ok: false };
      },
    });
    if (bad.dispatch) order2.push("dispatch");
    expect(bad.dispatch).toBe(false);
    expect(order2).toEqual(["commit"]);
  });

  it("validates conditional-required members (§ unwind-plan)", () => {
    expect(validateUnwindPlan(WORKED_PLAN).ok).toBe(true);

    const missingPost: UnwindPlan = {
      step_id: "s",
      mission_id: "m",
      reversibility: "external_commitment",
      pre_start_behavior: "suppress",
      in_flight_behavior: "cancel_if_possible",
    };
    expect(validateUnwindPlan(missingPost).ok).toBe(false);

    const compensateNoAction: UnwindPlan = {
      step_id: "s",
      mission_id: "m",
      reversibility: "reversible_write",
      pre_start_behavior: "suppress",
      in_flight_behavior: "cancel_if_possible",
      post_completion_behavior: "compensate",
    };
    expect(validateUnwindPlan(compensateNoAction).ok).toBe(false);
  });
});

describe("state-change behavior (@spec orchestration#state-change-behavior)", () => {
  it("3: established revoked runs the full 5-step sequence; committed step gets post-completion", () => {
    const res = onMissionStateChange({
      state: "revoked",
      stale: false,
      steps: [
        {
          step_id: "s1",
          reversibility: "reversible_write",
          outcome: "committed",
          pre_start_behavior: "suppress",
          in_flight_behavior: "cancel_if_possible",
          post_completion_behavior: "compensate",
        },
      ],
    });
    expect(res.trigger).toBe("established_non_active");
    expect(res.sequence).toEqual([
      "stop_dispatch",
      "suppress_or_pause_queued",
      "evaluate_in_flight",
      "post_completion",
      "emit_evidence",
    ]);
    expect(res.runs_post_completion).toBe(true);
    const s1 = res.steps[0];
    expect(s1?.orchestration_decision).toBe("compensate");
    expect(s1?.post_completion_deferred).toBe(false);

    const ev = buildOrchestrationEvidence({
      event_id: "orch_1",
      mission: MISSION,
      workflow_id: "wf_invoice_recon_2026q3",
      step_id: "s1",
      mission_state: "revoked",
      state_source: "status",
      orchestration_decision: "suppress",
      reason: "mission_revoked",
      occurred_at: "2026-11-02T08:16:00Z",
    });
    expect(ev.mission_state).toBe("revoked");
  });

  it("4: staleness alone runs items 1,2,3,5 and skips post-completion (item 4)", () => {
    const res = onMissionStateChange({
      state: "active",
      stale: true,
      steps: [
        {
          step_id: "s1",
          reversibility: "external_commitment",
          outcome: "committed",
          pre_start_behavior: "suppress",
          in_flight_behavior: "wait_then_review",
          post_completion_behavior: "compensate",
        },
      ],
    });
    expect(res.trigger).toBe("staleness");
    expect(res.sequence).toEqual([
      "stop_dispatch",
      "suppress_or_pause_queued",
      "evaluate_in_flight",
      "emit_evidence",
    ]);
    expect(res.sequence).not.toContain("post_completion");
    expect(res.runs_post_completion).toBe(false);
    // No post-completion decision of ANY kind runs under staleness: neither a
    // compensation nor a record_only (which would misrepresent a skipped step 4).
    expect(res.steps.every((s) => s.orchestration_decision !== "compensate")).toBe(true);
    expect(res.steps.every((s) => s.orchestration_decision !== "record_only")).toBe(true);
    expect(res.steps[0]?.orchestration_decision).toBeUndefined();
    expect(res.steps[0]?.post_completion_deferred).toBe(true);
  });

  it("established non-active takes precedence over staleness (revoked + stale => 5 steps)", () => {
    const res = onMissionStateChange({ state: "revoked", stale: true, steps: [] });
    expect(res.trigger).toBe("established_non_active");
    expect(res.sequence).toContain("post_completion");
    expect(res.sequence).toHaveLength(5);
  });

  it("any non-active state (incl. cascaded) is a trigger; active+fresh is not", () => {
    expect(onMissionStateChange({ state: "cascaded", stale: false }).trigger).toBe(
      "established_non_active",
    );
    expect(onMissionStateChange({ state: "superseded", stale: false }).triggered).toBe(true);
    expect(onMissionStateChange({ state: "active", stale: false }).triggered).toBe(false);
  });
});

describe("in-flight classification (@spec orchestration#state-change-behavior)", () => {
  it("6: maps D36 OpState fixtures onto the correct outcome class", () => {
    expect(classifyOutcome("reserved")).toBe("not_dispatched");
    expect(classifyOutcome("permit_consumed")).toBe("dispatched_not_committed");
    expect(classifyOutcome("connector_committed")).toBe("committed");
    expect(classifyOutcome("evidence_emitted")).toBe("committed");
    expect(classifyOutcome("reconciled")).toBe("committed");
    expect(classifyOutcome("abandoned")).toBe("unknown");
    expect(classifyOutcome(undefined)).toBe("unknown");
  });

  it("abandoned => unknown => human review for a high-risk class", () => {
    const outcome = classifyOutcome("abandoned");
    expect(outcome).toBe("unknown");
    expect(requiresHumanReview(outcome, "external_commitment")).toBe(true);
    expect(isHighRiskUnknown(outcome, "external_commitment")).toBe(true);
    expect(isHighRiskUnknown(outcome, "read_only")).toBe(false);
  });
});

describe("reversibility floor (@spec orchestration#reversibility)", () => {
  it("maps runtime action classes to the draft's minimum reversibility", () => {
    expect(floorReversibility("non_consequential")).toBe("read_only");
    expect(floorReversibility("consequential_read")).toBe("read_only");
    expect(floorReversibility("consequential_write")).toBe("reversible_write");
    expect(floorReversibility("irreversible_action")).toBe("irreversible_action");
    expect(floorReversibility("external_commitment")).toBe("external_commitment");
    expect(floorReversibility("privileged_administration")).toBe("privileged_administration");
  });

  it("MUST NOT lower: the floor wins over a lower proposal; a raise is allowed", () => {
    expect(enforceReversibilityFloor("read_only", "external_commitment")).toBe(
      "external_commitment",
    );
    expect(enforceReversibilityFloor("privileged_administration", "consequential_read")).toBe(
      "privileged_administration",
    );
  });

  it("model output cannot lower class; a trusted source can raise it", () => {
    const untrusted = deriveReversibility({
      runtimeActionClass: "external_commitment",
      proposed: "read_only",
      proposedSource: "model_output",
    });
    expect(untrusted.reversibility).toBe("external_commitment");
    expect(untrusted.adopted).toBe(false);

    const trusted = deriveReversibility({
      runtimeActionClass: "consequential_write",
      proposed: "external_commitment",
      proposedSource: "operation_profile",
    });
    expect(trusted.reversibility).toBe("external_commitment");
    expect(trusted.adopted).toBe(true);
  });
});

describe("compensation authority (@spec orchestration#compensation)", () => {
  it("5: refuses terminated-Mission authority; no basis => human review; separate_mission permits", () => {
    // Attempted with the terminated Mission's own authority => refused.
    expect(
      resolveCompensationAuthority({
        reversedEvaluationId: "dec_x",
        presentsTerminatedMissionAuthority: true,
      }).decision,
    ).toBe("deny");

    // No basis => human review.
    expect(resolveCompensationAuthority({ reversedEvaluationId: "dec_x" }).decision).toBe(
      "human_review",
    );

    // A separate_mission that is not active does not apply => human review.
    expect(
      resolveCompensationAuthority({ reversedEvaluationId: "dec_x", basis: "separate_mission" })
        .decision,
    ).toBe("human_review");

    // A valid active separate_mission permits, bound to the reversed evaluation_id.
    const r = resolveCompensationAuthority({
      reversedEvaluationId: "dec_8K2nP4qV9rL3tY6sB1zN0eF7jB",
      basis: "separate_mission",
      separateMissionActive: true,
    });
    expect(r.decision).toBe("permit");
    expect(r.authority_basis).toBe("separate_mission");
    expect(r.compensates_evaluation_id).toBe("dec_8K2nP4qV9rL3tY6sB1zN0eF7jB");

    // resource_policy also binds to the reversed evaluation_id.
    const rp = resolveCompensationAuthority({
      reversedEvaluationId: "dec_8K2nP4qV9rL3tY6sB1zN0eF7jB",
      basis: "resource_policy",
    });
    expect(rp.decision).toBe("permit");
    expect(rp.authority_basis).toBe("resource_policy");
    expect(rp.compensates_evaluation_id).toBe("dec_8K2nP4qV9rL3tY6sB1zN0eF7jB");
  });

  it("5b: compensate evidence for a high-risk class carries basis, binding, and a signed envelope", () => {
    const r = resolveCompensationAuthority({
      reversedEvaluationId: "dec_8K2nP4qV9rL3tY6sB1zN0eF7jB",
      basis: "separate_mission",
      separateMissionActive: true,
    });
    const signer = makeSigner("test-secret", "test-kid");
    const ev = buildOrchestrationEvidence(
      {
        event_id: "orch_9wK2nR5vXq7t",
        mission: MISSION,
        workflow_id: "wf_invoice_recon_2026q3",
        step_id: "post_journal_entry",
        mission_state: "revoked",
        state_source: "status",
        orchestration_decision: "compensate",
        reason: "committed_step_reversed_after_review",
        occurred_at: "2026-11-02T09:03:00Z",
        outcome_state: "committed",
        linked_evidence: ["orch_4r9SqLm8tY2p", "evd_9Nq3TmR6xL2vP8kY4sD1eB7jH0wC5uA"],
        authority_basis: r.authority_basis,
        compensation_action: "erp.journal_entry.reverse",
        compensation_outcome: "completed",
        compensates_evaluation_id: r.compensates_evaluation_id,
        compensated_reversibility: "irreversible_action",
      },
      { signEnvelope: signer },
    );
    expect(ev.authority_basis).toBe("separate_mission");
    expect(ev.compensates_evaluation_id).toBe("dec_8K2nP4qV9rL3tY6sB1zN0eF7jB");
    // linked_evidence carries only the supplied evidence-record identifiers;
    // the compensated evaluation_id is never folded into it.
    expect(ev.linked_evidence).toEqual([
      "orch_4r9SqLm8tY2p",
      "evd_9Nq3TmR6xL2vP8kY4sD1eB7jH0wC5uA",
    ]);
    expect(ev.linked_evidence).not.toContain("dec_8K2nP4qV9rL3tY6sB1zN0eF7jB");
    expect(ev.evidence_envelope).toBeDefined();

    const [headerB64, payloadB64] = (ev.evidence_envelope ?? "").split(".");
    const header = JSON.parse(Buffer.from(headerB64 ?? "", "base64url").toString("utf8")) as {
      alg?: string;
      kid?: string;
      typ?: string;
    };
    expect(header.alg).toBe("HS256");
    expect(header.kid).toBe("test-kid");
    expect(header.typ).toBe("mission-orchestration-evidence");

    // The signed JCS payload carries the new member and never the old name.
    const payload = Buffer.from(payloadB64 ?? "", "base64url").toString("utf8");
    expect(payload).toContain('"compensates_evaluation_id":"dec_8K2nP4qV9rL3tY6sB1zN0eF7jB"');
    expect(payload).not.toContain("compensates_decision_id");
  });

  it("5c: high-risk compensation without a signer fails closed", () => {
    expect(() =>
      buildOrchestrationEvidence({
        event_id: "orch_bad",
        mission: MISSION,
        workflow_id: "wf",
        mission_state: "revoked",
        state_source: "status",
        orchestration_decision: "compensate",
        reason: "reversed",
        occurred_at: "2026-11-02T09:03:00Z",
        linked_evidence: ["evd_1"],
        authority_basis: "resource_policy",
        compensation_action: "erp.journal_entry.reverse",
        compensation_outcome: "completed",
        compensates_evaluation_id: "dec_1",
        compensated_reversibility: "external_commitment",
      }),
    ).toThrow();
  });

  it("5d: compensate evidence missing compensates_evaluation_id fails closed", () => {
    expect(() =>
      buildOrchestrationEvidence({
        event_id: "orch_bad2",
        mission: MISSION,
        workflow_id: "wf",
        mission_state: "revoked",
        state_source: "status",
        orchestration_decision: "compensate",
        reason: "reversed",
        occurred_at: "2026-11-02T09:03:00Z",
        linked_evidence: ["evd_1"],
        authority_basis: "resource_policy",
        compensation_action: "erp.journal_entry.reverse",
        compensation_outcome: "completed",
      }),
    ).toThrow(/compensates_evaluation_id/);
  });

  it("runs compensations in reverse dependency order; partial failure => compensation_incomplete", () => {
    const order = reverseDependencyOrder([
      { step_id: "s1" },
      { step_id: "s2", depends_on: ["s1"] },
      { step_id: "s3", depends_on: ["s2"] },
    ]);
    expect(order).toEqual(["s3", "s2", "s1"]);

    expect(unwindTerminalState([{ step_id: "a", outcome: "completed" }]).terminal_state).toBe(
      "compensated",
    );
    const terminal = unwindTerminalState([
      { step_id: "a", outcome: "completed" },
      { step_id: "b", outcome: "failed" },
      { step_id: "c", outcome: "unknown" },
    ]);
    expect(terminal.terminal_state).toBe("compensation_incomplete");
    expect(terminal.incomplete_steps).toEqual(["b", "c"]);
  });
});

describe("authority-narrowing behavior (@spec orchestration#authority-narrowing)", () => {
  it("not_dispatched: still authorized proceeds untouched (no decision, no evidence, no dispatch)", () => {
    const step: AuthorityNarrowingStepInput = {
      step_id: "s1",
      outcome: "not_dispatched",
      in_flight_behavior: "cancel_if_possible",
    };
    const result = reEvaluateStepOnAuthorityNarrowing(step, () => true);
    expect(result.still_authorized).toBe(true);
    expect(result.orchestration_decision).toBeUndefined();
    expect(result.requires_evidence).toBe(false);
  });

  it("not_dispatched: denied is suppressed, never dispatched (§ in-flight's own suppress-or-pause rule, not the fuller pre_start_behavior range)", () => {
    const step: AuthorityNarrowingStepInput = {
      step_id: "s1",
      outcome: "not_dispatched",
      in_flight_behavior: "cancel_if_possible",
    };
    const result = reEvaluateStepOnAuthorityNarrowing(step, () => false);
    expect(result.still_authorized).toBe(false);
    expect(result.orchestration_decision).toBe("suppress");
    expect(result.requires_evidence).toBe(true);
    // OrchestrationDecision's own type has no "dispatch" member (see
    // evidence.ts): a denied not_dispatched step cannot be re-dispatched by
    // this trigger, a compile-time guarantee this assertion pins at runtime.
    expect(["suppress", "pause"]).toContain(result.orchestration_decision);
  });

  it("dispatched_not_committed: denied follows the step's EXISTING in_flight_behavior (re-gated, not additionally stopped)", () => {
    const behaviors: Array<[AuthorityNarrowingStepInput["in_flight_behavior"], string]> = [
      ["cancel_if_possible", "cancel"],
      ["continue_to_safe_point", "continue_to_safe_point"],
      ["wait_then_review", "human_review"],
      ["human_review", "human_review"],
    ];
    for (const [in_flight_behavior, expected] of behaviors) {
      const result = reEvaluateStepOnAuthorityNarrowing(
        { step_id: "s1", outcome: "dispatched_not_committed", in_flight_behavior },
        () => false,
      );
      expect(result.still_authorized).toBe(false);
      expect(result.orchestration_decision).toBe(expected);
      expect(result.requires_evidence).toBe(true);
    }
  });

  it("dispatched_not_committed: still authorized proceeds (this trigger does not stop already-dispatched work by itself)", () => {
    const result = reEvaluateStepOnAuthorityNarrowing(
      {
        step_id: "s1",
        outcome: "dispatched_not_committed",
        in_flight_behavior: "cancel_if_possible",
      },
      () => true,
    );
    expect(result.still_authorized).toBe(true);
    expect(result.requires_evidence).toBe(false);
  });

  it("committed: MUST NOT be compensated merely because authority narrowed (resolver never consulted, no double-commit possible)", () => {
    const resolver = vi.fn(() => false);
    const result = reEvaluateStepOnAuthorityNarrowing(
      { step_id: "s1", outcome: "committed", in_flight_behavior: "cancel_if_possible" },
      resolver,
    );
    expect(resolver).not.toHaveBeenCalled();
    expect(result.still_authorized).toBe(true);
    expect(result.orchestration_decision).toBeUndefined();
    expect(result.requires_evidence).toBe(false);
  });

  it("unknown: unaffected by this trigger (§ in-flight's own human-review rule already covers it; resolver never consulted)", () => {
    const resolver = vi.fn(() => false);
    const result = reEvaluateStepOnAuthorityNarrowing(
      { step_id: "s1", outcome: "unknown", in_flight_behavior: "cancel_if_possible" },
      resolver,
    );
    expect(resolver).not.toHaveBeenCalled();
    expect(result.still_authorized).toBe(true);
    expect(result.requires_evidence).toBe(false);
  });

  it("batch re-evaluation: each step is resolved independently, order and count preserved", () => {
    const steps: AuthorityNarrowingStepInput[] = [
      { step_id: "s1", outcome: "not_dispatched", in_flight_behavior: "cancel_if_possible" },
      {
        step_id: "s2",
        outcome: "dispatched_not_committed",
        in_flight_behavior: "wait_then_review",
      },
      { step_id: "s3", outcome: "committed", in_flight_behavior: "cancel_if_possible" },
    ];
    // Denies s1 and s2 only; s3 is never asked (committed short-circuits above).
    const results = reEvaluateOnAuthorityNarrowing(steps, (s) => s.step_id === "s3");
    expect(results.map((r) => r.step_id)).toEqual(["s1", "s2", "s3"]);
    expect(results[0]?.still_authorized).toBe(false);
    expect(results[0]?.orchestration_decision).toBe("suppress");
    expect(results[1]?.still_authorized).toBe(false);
    expect(results[1]?.orchestration_decision).toBe("human_review");
    expect(results[2]?.still_authorized).toBe(true);
    expect(results[2]?.requires_evidence).toBe(false);
  });

  it("evidence: step_id is REQUIRED on an authority-narrowing record (fail closed when absent)", () => {
    expect(() =>
      buildAuthorityNarrowingEvidence({
        event_id: "orch_an_1",
        mission: MISSION,
        workflow_id: "wf_invoice_recon_2026q3",
        step_id: "",
        mission_state: "active",
        state_source: "signal",
        orchestration_decision: "suppress",
        reason: "authority_narrowed",
        occurred_at: "2026-11-02T10:00:00Z",
      }),
    ).toThrow();
  });

  it("evidence: a valid authority-narrowing record carries step_id, state_source signal, and mission_state active", () => {
    const ev = buildAuthorityNarrowingEvidence({
      event_id: "orch_an_2",
      mission: MISSION,
      workflow_id: "wf_invoice_recon_2026q3",
      step_id: "s1",
      mission_state: "active",
      state_source: "signal",
      orchestration_decision: "suppress",
      reason: "authority_narrowed",
      occurred_at: "2026-11-02T10:01:00Z",
    });
    expect(ev.step_id).toBe("s1");
    expect(ev.state_source).toBe("signal");
    expect(ev.mission_state).toBe("active");
    expect(ev.orchestration_decision).toBe("suppress");
  });
});
