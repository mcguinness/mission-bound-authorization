export { Fga, DOMAIN_MODEL, loadCa, type FgaConfig } from "./fga.js";
export {
  policyViewId,
  deriveContextualTuples,
  type MissionView,
  type AuthorityEntry,
} from "./policy-view.js";
export {
  evaluate,
  type Decision,
  type DenialReason,
  type EvaluateOptions,
  type EvaluationRequest,
} from "./evaluate.js";
export { PAYMENTS_RELATIONS, relationForAction, stalenessBoundSeconds } from "./policy.js";
