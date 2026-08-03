/**
 * @spec orchestration#unwind-plan
 * @spec orchestration#unwind-plan-integrity
 *
 * The per-step unwind plan and its integrity anchor. The `unwind_plan_hash` is
 * computed with the issuance profile's integrity-anchor envelope under a new
 * `typ` value `mission-unwind-plan` (owned in `@mission/core`), the plan object
 * as `value`. The hash MUST be durably committed STRICTLY BEFORE dispatch, and
 * dispatch MUST fail closed if that write fails (§ unwind-plan-integrity).
 */

import { computeAnchor, type JsonValue, UNWIND_PLAN_TYP } from "@mission/core";
import type { ReversibilityClass } from "./reversibility.js";

export type PreStartBehavior = "suppress" | "pause" | "cancel_workflow" | "human_review";
export type InFlightBehavior =
  | "cancel_if_possible"
  | "wait_then_review"
  | "continue_to_safe_point"
  | "human_review";
export type PostCompletionBehavior = "compensate" | "record_only" | "human_review";

/** The reversibility classes for which post-completion behavior is REQUIRED. */
const WRITE_CLASSES: ReadonlySet<ReversibilityClass> = new Set([
  "reversible_write",
  "irreversible_action",
  "external_commitment",
  "privileged_administration",
]);

/** The unwind plan (§ unwind-plan). Deployment documentation, not a wire format. */
export interface UnwindPlan {
  step_id: string;
  mission_id: string;
  reversibility: ReversibilityClass;
  pre_start_behavior: PreStartBehavior;
  in_flight_behavior: InFlightBehavior;
  post_completion_behavior?: PostCompletionBehavior;
  compensation_action?: string;
  review_queue?: string;
  safe_point?: string;
  evidence_policy?: { [k: string]: JsonValue };
}

/**
 * The `unwind_plan_hash` over the plan: the integrity-anchor envelope
 * { typ: "mission-unwind-plan", iss, value: plan }, JCS-canonicalized,
 * SHA-256, "sha-256:" + base64url. The draft's worked plan reproduces its
 * published hash under this exact call (see the test vector).
 */
export function unwindPlanHash(iss: string, plan: UnwindPlan): string {
  return computeAnchor(UNWIND_PLAN_TYP, iss, plan as unknown as JsonValue);
}

export interface UnwindPlanValidation {
  ok: boolean;
  errors: string[];
}

/**
 * Validate the conditional-required members (§ unwind-plan): post-completion
 * behavior for the write classes, a compensation action when the behavior is
 * `compensate`, and a review queue whenever any behavior is `human_review`.
 */
export function validateUnwindPlan(plan: UnwindPlan): UnwindPlanValidation {
  const errors: string[] = [];
  if (WRITE_CLASSES.has(plan.reversibility) && plan.post_completion_behavior === undefined) {
    errors.push(`post_completion_behavior is REQUIRED for reversibility '${plan.reversibility}'`);
  }
  if (plan.post_completion_behavior === "compensate" && plan.compensation_action === undefined) {
    errors.push("compensation_action is REQUIRED when post_completion_behavior is 'compensate'");
  }
  const usesReview =
    plan.pre_start_behavior === "human_review" ||
    plan.in_flight_behavior === "human_review" ||
    plan.post_completion_behavior === "human_review";
  if (usesReview && plan.review_queue === undefined) {
    errors.push("review_queue is REQUIRED when any behavior is 'human_review'");
  }
  return { ok: errors.length === 0, errors };
}

/** The result of an injected durable commit of the `unwind_plan_hash`. */
export interface CommitOutcome {
  ok: boolean;
}

export interface DispatchGateResult {
  unwind_plan_hash: string;
  /** MUST be false if the commit write did not complete durably (fail closed). */
  dispatch: boolean;
}

/**
 * The fail-closed dispatch gate (§ unwind-plan-integrity). Computes the hash,
 * then invokes the injected durable-write `commit` STRICTLY BEFORE any dispatch
 * decision. Dispatch is permitted only when the commit succeeds; a failed write
 * MUST prevent dispatch. `commit` is called before this function returns, so
 * the commit is ordered strictly before any dispatch the caller performs on a
 * `dispatch: true` result.
 */
export function commitUnwindPlan(input: {
  iss: string;
  plan: UnwindPlan;
  commit: (unwindPlanHash: string) => CommitOutcome;
}): DispatchGateResult {
  const unwind_plan_hash = unwindPlanHash(input.iss, input.plan);
  const outcome = input.commit(unwind_plan_hash);
  return { unwind_plan_hash, dispatch: outcome.ok };
}
