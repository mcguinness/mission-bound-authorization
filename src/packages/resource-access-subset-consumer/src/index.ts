// An independently authored consumer of the Mission Resource Access vectors,
// implementing the initial interoperable subset
// (vectors/mission-resource-access-subset/) from
// draft-mcguinness-oauth-mission-resource-access alone.

export { CONSTRAINT_RULES, type ConstraintRule } from "./constraints.js";
export { compareDecimal, type DecimalValue, parseDecimal } from "./decimal.js";
export { isValidRecipientDomain, isWithinDomain } from "./dns.js";
export {
  type ConfiguredContract,
  type ConsumerConfig,
  type ContractReference,
  contractApprovalRefusal,
  ENTRY_TYPE,
  type ParsedEntry,
  type ParseResult,
  parseEntry,
  REFUSAL_ERROR,
  SUBSET_MEMBERS,
  SUBSET_RESOURCE_MATCH,
} from "./entry.js";
export { compareInstant, type Instant, parseInstant } from "./instant.js";
export {
  type MatchResult,
  matchResource,
  type ResolutionInput,
  type ResolutionResult,
  resolveTarget,
  resourceMatchCheck,
} from "./matching.js";
export {
  type CaseResult,
  entryValidationCheck,
  IMPLEMENTED_CHECKS,
  runCase,
  SCOPED_OUT_CHECKS,
  type Selection,
  selectCase,
  type VectorCase,
} from "./runner.js";
export { type SubsetResult, subsetCheck } from "./subset.js";
export { type AbsoluteUri, parseAbsoluteUri } from "./uri.js";
