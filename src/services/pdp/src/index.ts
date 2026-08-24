export { Fga, DOMAIN_MODEL, loadCa, type FgaConfig } from "./fga.js";
export {
  policyViewId,
  deriveContextualTuples,
  MISSION_RESOURCE_ACCESS_TYPE,
  type MissionView,
  type AuthorityEntry,
} from "./policy-view.js";
export {
  evaluate,
  type Decision,
  type DenialReason,
  type EntitlementObservation,
  type EntitlementResolver,
  type EvaluateOptions,
  type EvaluationRequest,
  type ActionApproval,
  type Freshness,
  type OriginPrincipal,
  type PrincipalMappingObservation,
  type PrincipalMappingResolver,
} from "./evaluate.js";
export { PAYMENTS_RELATIONS, relationForAction, stalenessBoundSeconds } from "./policy.js";
