export { Fga, DOMAIN_MODEL, loadCa, type FgaConfig } from "./fga.js";
export {
  policyViewId,
  joinViewId,
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
export {
  createPdpHttpServer,
  type AuthorizedPep,
  type PdpHttpServerHandle,
  type PdpRemoteServerConfig,
} from "./server.js";
export { evaluateRemote, type RemotePdpClientConfig } from "./client.js";
export {
  claimsWithinScope,
  validateEnforcementScopeStatement,
  type EnforcementClaim,
  type EnforcementExtensionDeclarations,
  type EnforcementExtensionName,
  type EnforcementScopeBaseline,
  type EnforcementScopeFinding,
  type EnforcementScopeStatement,
} from "./enforcement-scope.js";
export {
  resolveBaselineJoin,
  deriveJoinDelegation,
  type BaselineJoinInput,
  type BaselineJoinResult,
  type DelegatePolicy,
  type KernelDelegationPolicy,
} from "./mas-join.js";
