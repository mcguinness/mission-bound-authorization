/**
 * @spec orchestration#state-change-behavior
 *
 * Behavior when a Mission becomes non-active or its active state cannot be
 * established within the staleness bound. Two triggers, resolved with
 * established-non-active taking precedence (a signed `revoked` overrides a stale
 * `active` cache, § trigger-sources):
 *
 * - An ESTABLISHED non-active state runs the full sequence 1..5.
 * - STALENESS ALONE (an `active` state that could not be established within the
 *   bound) runs items 1, 2, 3, 5 and MUST NOT execute post-completion (item 4):
 *   compensation is itself consequential work, and unwinding work nobody
 *   stopped is not fail-closed.
 *
 * `MissionState` is imported read-only from the agent harness; per the issuance
 * profile's forward-compatibility rule, any state other than `active` is
 * non-active, so `cascaded` (and any future state) is just one more trigger.
 */

import type { MissionState } from "@mission/agent";
import type { OrchestrationDecision } from "./evidence.js";
import { type OutcomeClass, requiresHumanReview } from "./in-flight.js";
import type { ReversibilityClass } from "./reversibility.js";
import type { InFlightBehavior, PostCompletionBehavior, PreStartBehavior } from "./unwind-plan.js";

export type StateChangeStep =
  | "stop_dispatch" // 1
  | "suppress_or_pause_queued" // 2
  | "evaluate_in_flight" // 3
  | "post_completion" // 4 (established non-active only)
  | "emit_evidence"; // 5

export type StateChangeTrigger = "established_non_active" | "staleness" | "none";

export interface InFlightStepInput {
  step_id: string;
  reversibility: ReversibilityClass;
  outcome: OutcomeClass;
  pre_start_behavior: PreStartBehavior;
  in_flight_behavior: InFlightBehavior;
  post_completion_behavior?: PostCompletionBehavior;
}

export interface StepDecision {
  step_id: string;
  outcome: OutcomeClass;
  /**
   * ABSENT when `post_completion_deferred` is true: under staleness a committed
   * step is classified (item 3) but item 4 does not run, so no post-completion
   * decision is reached. Recording `record_only` here would misrepresent a
   * skipped step 4 as a deliberate no-compensation decision.
   */
  orchestration_decision?: OrchestrationDecision;
  requires_human_review: boolean;
  /** True for a `committed` step whose post-completion was skipped under staleness. */
  post_completion_deferred: boolean;
}

export interface StateChangeResult {
  triggered: boolean;
  trigger: StateChangeTrigger;
  /** The ordered items that run: [1,2,3,4,5] established, [1,2,3,5] staleness. */
  sequence: StateChangeStep[];
  runs_post_completion: boolean;
  steps: StepDecision[];
}

function fromPreStart(behavior: PreStartBehavior): OrchestrationDecision {
  switch (behavior) {
    case "cancel_workflow":
      return "cancel";
    case "suppress":
      return "suppress";
    case "pause":
      return "pause";
    case "human_review":
      return "human_review";
  }
}

function fromInFlight(behavior: InFlightBehavior): OrchestrationDecision {
  switch (behavior) {
    case "cancel_if_possible":
      return "cancel";
    case "continue_to_safe_point":
      return "continue_to_safe_point";
    case "wait_then_review":
    case "human_review":
      return "human_review";
  }
}

function fromPostCompletion(behavior: PostCompletionBehavior | undefined): OrchestrationDecision {
  switch (behavior) {
    case "compensate":
      return "compensate";
    case "record_only":
      return "record_only";
    default:
      // Missing behavior on a committed write class: fail closed to review.
      return "human_review";
  }
}

function classifyStep(step: InFlightStepInput, runsPostCompletion: boolean): StepDecision {
  const base = { step_id: step.step_id, outcome: step.outcome, post_completion_deferred: false };
  switch (step.outcome) {
    case "not_dispatched": {
      const decision = fromPreStart(step.pre_start_behavior);
      return {
        ...base,
        orchestration_decision: decision,
        requires_human_review: decision === "human_review",
      };
    }
    case "dispatched_not_committed": {
      const decision = fromInFlight(step.in_flight_behavior);
      return {
        ...base,
        orchestration_decision: decision,
        requires_human_review: decision === "human_review",
      };
    }
    case "committed": {
      if (!runsPostCompletion) {
        // Staleness: item 4 is skipped, so no post-completion decision is
        // reached. The committed step is classified in item 3 and recorded in
        // item 5, but carries NO orchestration_decision; the state-change
        // record's own stop decision (suppress/pause) stands.
        return {
          ...base,
          requires_human_review: false,
          post_completion_deferred: true,
        };
      }
      const decision = fromPostCompletion(step.post_completion_behavior);
      return {
        ...base,
        orchestration_decision: decision,
        requires_human_review: decision === "human_review",
      };
    }
    case "unknown": {
      // MUST route to human review; MUST NOT be treated as success (§ in-flight).
      return {
        ...base,
        orchestration_decision: "human_review",
        requires_human_review: requiresHumanReview("unknown", step.reversibility),
      };
    }
  }
}

/**
 * Compute the ordered state-change decision for a Mission whose state became
 * non-active or could not be established. `stale` means specifically "the active
 * state could not be established within the staleness bound"; an established
 * non-active `state` takes precedence over `stale`.
 */
export function onMissionStateChange(input: {
  state: MissionState | string;
  stale: boolean;
  steps?: InFlightStepInput[];
}): StateChangeResult {
  const isActive = input.state === "active";

  let trigger: StateChangeTrigger;
  if (!isActive) {
    // Established non-active (e.g. a signed `revoked`) runs the full sequence,
    // even if a local cache was also stale.
    trigger = "established_non_active";
  } else if (input.stale) {
    trigger = "staleness";
  } else {
    trigger = "none";
  }

  if (trigger === "none") {
    return { triggered: false, trigger, sequence: [], runs_post_completion: false, steps: [] };
  }

  const runsPostCompletion = trigger === "established_non_active";
  const sequence: StateChangeStep[] = [
    "stop_dispatch",
    "suppress_or_pause_queued",
    "evaluate_in_flight",
    ...(runsPostCompletion ? (["post_completion"] as StateChangeStep[]) : []),
    "emit_evidence",
  ];

  const steps = (input.steps ?? []).map((s) => classifyStep(s, runsPostCompletion));
  return { triggered: true, trigger, sequence, runs_post_completion: runsPostCompletion, steps };
}
