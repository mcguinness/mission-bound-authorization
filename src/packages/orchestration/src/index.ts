/**
 * @spec orchestration
 *
 * Mission Orchestration and Unwinding: the deterministic core of the
 * saga/compensation "unwinding" profile. It classifies actions by
 * reversibility, commits an unwind plan hash before dispatch (fail closed),
 * decides state-change behavior with the staleness asymmetry, classifies
 * in-flight outcomes, resolves compensation authority, and builds Orchestration
 * Evidence. It issues no credential and modifies no service.
 */

export {
  type AuthorityBasis,
  type CompensationAuthorityResult,
  type CompensationOutcome,
  type CompensationRequest,
  type CompensationStep,
  type CompensationStepResult,
  resolveCompensationAuthority,
  reverseDependencyOrder,
  type UnwindTerminalState,
  unwindTerminalState,
} from "./compensation.js";
export {
  type BuildOrchestrationEvidenceInput,
  buildOrchestrationEvidence,
  type EnvelopeSigner,
  type MissionDescriptor,
  ORCHESTRATION_EVIDENCE_TYP,
  type OrchestrationDecision,
  type OrchestrationEvidence,
} from "./evidence.js";
export {
  classifyOutcome,
  isHighRiskUnknown,
  type OutcomeClass,
  requiresHumanReview,
} from "./in-flight.js";
export {
  type ClassSource,
  type DeriveReversibilityResult,
  deriveReversibility,
  enforceReversibilityFloor,
  floorReversibility,
  HIGH_RISK_REVERSIBILITY,
  isTrustedClassSource,
  REVERSIBILITY_FLOOR,
  type ReversibilityClass,
  type RuntimeActionClass,
} from "./reversibility.js";
export {
  type InFlightStepInput,
  onMissionStateChange,
  type StateChangeResult,
  type StateChangeStep,
  type StateChangeTrigger,
  type StepDecision,
} from "./state-change.js";
export {
  type CommitOutcome,
  commitUnwindPlan,
  type DispatchGateResult,
  type InFlightBehavior,
  type PostCompletionBehavior,
  type PreStartBehavior,
  type UnwindPlan,
  type UnwindPlanValidation,
  unwindPlanHash,
  validateUnwindPlan,
} from "./unwind-plan.js";
