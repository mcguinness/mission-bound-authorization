/**
 * @spec orchestration#authority-narrowing
 *
 * The third, independent State-Change Behavior trigger: a
 * `mission.lifecycle-change` event carries `authority_changed` true at
 * unchanged `state` (signals#lifecycle-event). The Mission stays `active`;
 * the narrowing is scoped to the entries it affects, not to the Mission as a
 * whole, so this is never folded into `onMissionStateChange`'s non-active
 * sequence (§ state-change.ts).
 *
 * The orchestrator rematerializes its Effective Authority Set and re-evaluates
 * each pending step's concrete resource/action against it. This module takes
 * that per-step re-evaluation result as an injected `stillAuthorized`
 * predicate: the caller resolves it via a fresh PDP evaluation of the step's
 * concrete resource/action, or a comparison of the step's Decision Evidence
 * `authorizing_entry`/`entry_digest` (runtime-evidence#decision-evidence)
 * against the rematerialized set. Both are integration concerns this
 * dependency-free package does not own.
 *
 * Only `not_dispatched` and `dispatched_not_committed` are narrowable here.
 * A `committed` step is left alone (MUST NOT be compensated merely because
 * authority narrowed after it committed) and an `unknown` step is unaffected
 * (§ in-flight's own human-review rule already covers it): the resolver is
 * never even consulted for either, so this trigger cannot re-dispatch a step
 * already denied (no "dispatch" decision exists in `OrchestrationDecision`)
 * or double-act on a step already committed.
 */

import type { OrchestrationDecision } from "./evidence.js";
import type { OutcomeClass } from "./in-flight.js";
import type { InFlightBehavior } from "./unwind-plan.js";

/** The two outcome classes this trigger can deny. `committed`/`unknown` never reach the resolver. */
export type NarrowableOutcome = Extract<
  OutcomeClass,
  "not_dispatched" | "dispatched_not_committed"
>;

export interface AuthorityNarrowingStepInput {
  step_id: string;
  outcome: OutcomeClass;
  /** Read only when `outcome` is `dispatched_not_committed`. */
  in_flight_behavior: InFlightBehavior;
}

export interface AuthorityNarrowingDecision {
  step_id: string;
  outcome: OutcomeClass;
  /**
   * Whether the fresh re-evaluation (PDP evaluation, or an
   * authorizing_entry/entry_digest comparison against the rematerialized
   * Effective Authority Set) still permits this step. Always `true` for a
   * `committed` or `unknown` step: the resolver is not consulted for either.
   */
  still_authorized: boolean;
  /** Present only when `still_authorized` is false (denied). */
  orchestration_decision?: OrchestrationDecision;
  /** True exactly when an Orchestration Evidence record MUST be emitted for this step. */
  requires_evidence: boolean;
}

/** `not_dispatched` denial: § in-flight's own generic rule (suppress or pause), not the fuller pre_start_behavior range used by the non-active sequence. */
function notDispatchedDenialDecision(): OrchestrationDecision {
  return "suppress";
}

/** `dispatched_not_committed` denial: follows the step's EXISTING `in_flight_behavior`, unchanged from the non-active sequence's own mapping (§ state-change.ts `fromInFlight`). Re-gates already-dispatched work; does not additionally stop it. */
function dispatchedNotCommittedDenialDecision(behavior: InFlightBehavior): OrchestrationDecision {
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

/**
 * Re-evaluate one pending step against a rematerialized Effective Authority
 * Set. `stillAuthorized` is the caller's fresh PDP evaluation, or its
 * comparison of the step's `authorizing_entry`/`entry_digest`.
 *
 * A `committed` or `unknown` step is returned unaffected WITHOUT calling
 * `stillAuthorized`: this is what makes "never compensated on narrowing
 * alone" (committed) and "unaffected by this trigger" (unknown) structural
 * rather than incidental.
 */
export function reEvaluateStepOnAuthorityNarrowing(
  step: AuthorityNarrowingStepInput,
  stillAuthorized: (step: AuthorityNarrowingStepInput) => boolean,
): AuthorityNarrowingDecision {
  if (step.outcome !== "not_dispatched" && step.outcome !== "dispatched_not_committed") {
    return {
      step_id: step.step_id,
      outcome: step.outcome,
      still_authorized: true,
      requires_evidence: false,
    };
  }

  if (stillAuthorized(step)) {
    return {
      step_id: step.step_id,
      outcome: step.outcome,
      still_authorized: true,
      requires_evidence: false,
    };
  }

  const decision: OrchestrationDecision =
    step.outcome === "not_dispatched"
      ? notDispatchedDenialDecision()
      : dispatchedNotCommittedDenialDecision(step.in_flight_behavior);

  return {
    step_id: step.step_id,
    outcome: step.outcome,
    still_authorized: false,
    orchestration_decision: decision,
    requires_evidence: true,
  };
}

/** Re-evaluate every pending step independently; order and count are preserved. */
export function reEvaluateOnAuthorityNarrowing(
  steps: AuthorityNarrowingStepInput[],
  stillAuthorized: (step: AuthorityNarrowingStepInput) => boolean,
): AuthorityNarrowingDecision[] {
  return steps.map((s) => reEvaluateStepOnAuthorityNarrowing(s, stillAuthorized));
}
