/** Assembly: kernel + adapters + keys. Used by server.ts and tests. */

import {
  INTROSPECTION_PRINCIPALS,
  DESIGNABLE_CLIENTS,
  type IntrospectionPrincipal,
  ACTOR_PROFILES,
  AUTHORITY_SOURCES,
  CANONICAL_RESOURCE,
  CHILD_MISSION_CARRYOVER,
  CONTAINMENT_POLICY,
  DEMO_DISPATCH_POLICIES,
  demoReconciliationTemplate,
  DERIVATION_POLICY,
  seedAgentClient,
  seedChildClient,
  seedGovernedClient,
  seedLedgerReconcilerClient,
  seedTrustedSources,
  type SeededTrustedSource,
  SCOPE_PROJECTION,
  TOPOLOGY,
  USERS,
  APPROVAL_FLOOR,
  type ApprovalFloorPolicy,
} from "@mission/demo-data";
import { randomBytes } from "node:crypto";
import type { ScopeProjectionMapping } from "@mission/core";
import { exportJWK, generateKeyPair, importJWK, type CryptoKey, type JWK } from "jose";
import {
  generateEphemeralSigningKeys,
  loadSigningKeyRing,
  SigningKeyRingError,
  type SigningKeySource,
} from "./kernel/signing-key-ring.js";
import type Provider from "oidc-provider";
import type { ApprovalSessionStore } from "./adapters/approval-resolution.js";
import { capabilityEnabled, type ProviderCapability } from "./adapters/capabilities.js";
export { APPROVAL_SUBJECT_HEADER, ApprovalSessionStore, MISSION_APPROVAL_SCOPE, type ApprovalPrincipal } from "./adapters/approval-resolution.js";
import { ApproverLoginRelyingParty, type ApproverLoginOptions } from "./adapters/approver-login.js";
export {
  APPROVER_LOGIN_CALLBACK_PATH,
  APPROVER_LOGIN_COOKIE,
  ApproverLoginError,
  loginCookieName,
  ApproverLoginRelyingParty,
  type ApproverIdentityMapping,
  type ApproverLoginOptions,
} from "./adapters/approver-login.js";
import type { DpopProofReplay } from "./adapters/dpop-replay.js";
import {
  buildProvider,
  type ProtectedEventSource,
  type ServiceTokenPrincipal,
  type TxnArs,
} from "./adapters/provider.js";
import type { CrossOrgOptions } from "./adapters/cross-org-grant.js";
import { bindAuthoritySourceCatalog } from "./kernel/authority-source.js";
import { IssuerEvidenceStore } from "./kernel/issuer-evidence.js";
import { defaultSubjectResolver, type SubjectResolver } from "./adapters/continuation-grant.js";
import type { CarryoverConfig } from "./kernel/carryover.js";
import { revokeChildrenCreatedByAnotherClient } from "./kernel/child-delegation.js";
import {
  DEFAULT_EXPANSION_RATE_LIMIT,
  type DrawdownRemediation,
  ExpansionRateLimiter,
  revokeDrawdownSuccessorsRequestedByAnotherClient,
  revokeSuccessorsExpandedByAnotherClient,
  type SuccessorRemediation,
} from "./kernel/expansion.js";
import type { ContinuationIssuer } from "./kernel/continuation-assertion.js";
import type { DestinationClientRegistration } from "./kernel/cross-domain.js";
import { ContinuationStore, DEFAULT_CONTINUATION_HOP_LIMIT } from "./kernel/continuation-store.js";
import { DelegationFamilyStore } from "./kernel/delegation-family-store.js";
import { TokenIssuanceStore } from "./kernel/token-issuance-store.js";
import { DeferralStore, ExpansionDeferralStore } from "./kernel/deferred.js";
import type { GovernedPolicyApprovalConfig } from "./kernel/governed-policy-approval.js";
import { type ModelAdvisor, MissionApprovalDeferralStore } from "./kernel/mission-approval-deferral.js";
import {
  CreationIdempotencyStore,
  DEFAULT_CREATION_TOMBSTONE_TTL_S,
} from "./kernel/creation-idempotency.js";
import {
  DEFAULT_DISCHARGE_EVENT_TTL_S,
  DEFAULT_LIFECYCLE_NONCE_TTL_S as LIFECYCLE_NONCE_TTL_S,
} from "./kernel/lifecycle-idempotency.js";
import type { DerivationPolicy, EffectiveAuthoritySource } from "./kernel/derive.js";
import type { DelegationAuthorizationPolicy } from "./kernel/eligibility-provenance.js";
import type { ChildCreationAuthorizationPolicy } from "./kernel/child-actor-eligibility.js";
import type { DischargeAuthorityPolicy } from "./kernel/discharge.js";
import { newReplayCache } from "./kernel/instance-assertion.js";
import { MissionKernel } from "./kernel/kernel.js";
import { type ScheduleTimers, SuspensionScheduler } from "./kernel/suspension-scheduler.js";
import type { TxnAuthorizationOptions } from "./adapters/transaction-authorization.js";
import { StatusListPublisher } from "./kernel/status-list.js";
import type { ActivationPolicyRegistry } from "./kernel/activation-policy.js";
import { type ProgressiveDrawdownOptions, validateProgressiveDrawdownOptions } from "./kernel/progressive.js";
import { createTemplate, type DispatchPolicies } from "./kernel/template.js";
import { trustedCapabilityResolver } from "./adapters/capability-resolver.js";
import { TemplateStore } from "./kernel/template-store.js";
import { TERMINAL_STATES } from "./kernel/types.js";
import type { LifecycleCommit, MissionRecord } from "./kernel/types.js";

export {
  MissionKernel,
  GateError,
  LifecycleConflictError,
  MissionNotFoundError,
  ObservationWatermarkError,
  StaleVersionError,
  STATUS_SIGNING_ALG,
  type DischargeReceiptObservation,
  type ObservationWatermark,
  type ScheduleFire,
  type StatusObservation,
  type StatusObservationOptions,
} from "./kernel/kernel.js";
export {
  MAX_TIMER_DELAY_MS,
  SCHEDULE_RETRY_DELAY_MS,
  type ScheduleDelivery,
  type ScheduleTimers,
  SuspensionScheduler,
  SYSTEM_SCHEDULE_TIMERS,
} from "./kernel/suspension-scheduler.js";
export {
  DerivationReservationStore,
  type DerivationReservation,
  type DerivationReservationResult,
  type DerivationReservationState,
} from "./kernel/derivation-reservations.js";

export { MISSION_ID_ENTROPY_BYTES, newMissionId } from "./kernel/mission-id.js";
export {
  AS_SIGNING_ROLES,
  type AsSigningRole,
  initSigningKeyRing,
  kernelStoreFromEnv,
  loadSigningKeyRing,
  SIGNING_KEY_RING_FORMAT,
  SigningKeyRingError,
  type SigningKeySource,
  signingKeysFromEnv,
} from "./kernel/signing-key-ring.js";
export {
  attachCapabilitySources,
  type CapabilitySourceResolution,
  type CapabilitySourceResolver,
  inheritCapabilitySources,
} from "./kernel/capability-binding.js";
export {
  buildContainmentEvidence,
  containmentEvidenceBytes,
  CONTAINMENT_EVIDENCE_MEDIA_TYPE,
  type ContainmentEvidence,
  type ContainmentPolicy,
  UnknownProtectedEventError,
} from "./kernel/containment.js";
export {
  IssuerEvidenceStore,
  type IngestionEvidenceInput,
} from "./kernel/issuer-evidence.js";
export {
  type DeliveryDisposition,
  type DurableCommitSubscriber,
  LEGACY_LIFECYCLE_EVENT_PAYLOAD_VERSION,
  LIFECYCLE_EVENT_PAYLOAD_VERSION,
  LifecycleOutbox,
  readPersistedCommit,
} from "./kernel/lifecycle-outbox.js";
export {
  LEGACY_TERMINAL_REASONS,
  normalizeLegacyCommit,
  normalizeStoredLifecycle,
  observeExpiry,
  parentTerminatedTermination,
  parseTermination,
  UNKNOWN_TERMINATION_REASON,
} from "./kernel/termination.js";
export {
  composeTombstoneRetentionSeconds,
  DEFAULT_AUDIT_RETENTION_S,
  DEFAULT_CLOCK_SKEW_S,
  type MissionTombstone,
  MissionIdReuseError,
  MissionTombstoneStore,
  type TombstoneRetentionInputs,
} from "./kernel/tombstones.js";
export type { ProtectedEventSource } from "./adapters/provider.js";
export {
  ALL_PROVIDER_CAPABILITIES,
  capabilityEnabled,
  type ProviderCapability,
  TOKEN_EXCHANGE_CAPABILITIES,
} from "./adapters/capabilities.js";
export {
  DEFAULT_SERVICE_TOKEN_PRINCIPALS,
  MISSION_DISCHARGE_SCOPE,
  MISSION_LIFECYCLE_SCOPE,
  MISSION_RESUME_SCOPE,
  MISSION_STATUS_RESPONSE_MEDIA_TYPE,
  MISSION_STATUS_SCOPE,
  type ServiceTokenPrincipal,
} from "./adapters/provider.js";
export {
  DEFAULT_MAX_EVIDENCE_ENTRIES,
  DEFAULT_MAX_EVIDENCE_ENTRY_BYTES,
  INTENT_SUBMISSION_EVIDENCE_TYPES,
  IntentError,
  type IntentSubmissionEvidenceType,
  type IntentSubmissionEvidenceVerifyInput,
  type IntentSubmissionPresenter,
  provisionalIntentHash,
  registerIntentSubmissionEvidenceType,
  type SubmissionEvidenceBounds,
  type SubmissionIntakeOptions,
  unregisterIntentSubmissionEvidenceType,
  validateAuthorityProposal,
  validateIntentSubmissionEvidence,
  validateMissionIntent,
  validateMissionIntentSubmission,
  verifyIntentSubmissionEvidence,
} from "./kernel/intent.js";
export {
  deriveAuthoritySet,
  deriveAuthoritySetWithProvenance,
  type DerivationPolicy,
  type DerivedAuthority,
  type EffectiveAuthoritySource,
  isSubsetEntry,
  isSubsetSet,
  type OriginProjection,
  projectThroughEffective,
  projectThroughEffectiveWithOrigin,
  SourceUnavailableError,
} from "./kernel/derive.js";
export {
  assertDischargeAuthoritiesResolvable,
  conditionDigest,
  conditionsNoBroader,
  DISCHARGE_EVENT_ID_RE,
  DISCHARGE_RECEIPT_MEDIA_TYPE,
  DISCHARGE_RECEIPT_TYP,
  DISCHARGE_AUTHORITY_RE,
  type DischargeAssertion,
  type DischargeAuthorityMapping,
  type DischargeAuthorityPolicy,
  dischargeAssertionFingerprint,
  DischargeConflictError,
  DischargeNotFoundError,
  DischargeTraversalError,
  type DischargeOutcome,
  type DischargeRefusalReason,
  type DischargeRequest,
  type DischargeResult,
  type DischargeTargetForm,
  entryDigest,
  EVIDENCE_REF_MAX_CHARS,
  mappingPermits,
  resolveConditionMapping,
  targetFormOf,
  terminalWhenOf,
  unionConditions,
} from "./kernel/discharge.js";
export {
  CONDITION_SELECTOR_PREFIX,
  CONDITION_SELECTOR_RE,
  type DischargeTargetTriple,
  DischargeSelectorStore,
} from "./kernel/discharge-selector-store.js";
export {
  DEFAULT_DISCHARGE_EVENT_TTL_S,
  DEFAULT_LIFECYCLE_NONCE_TTL_S,
  type DischargeEventAudit,
  type DischargeEventKey,
  DischargeEventStore,
  LIFECYCLE_ENDPOINT_KEY,
  type LifecycleNonceKey,
  type LifecycleResponseMaterial,
  type LifecycleResponseState,
  LifecycleResponseStore,
  type RetainedLifecycleResponse,
  type StoredDischargeEvent,
  type StoredLifecycleResponse,
} from "./kernel/lifecycle-idempotency.js";
export {
  missionResourceAccessProfile,
  type OperationProfile,
  OperationProfileRegistry,
  type OperationResolution,
  type ResolvedOperation,
} from "./kernel/operation-profile.js";
export { delegatePermitted, type DelegateCandidate } from "./kernel/delegate-matcher.js";
export {
  ceilingOrigin,
  combineOrigins,
  DENY_ALL_DELEGATION_POLICY,
  type DelegationAuthorizationPolicy,
  type DelegationCandidate,
  type DelegationPolicyRequest,
  delegateEligibility,
  type EligibilityOrigin,
  type EligibilityOutcome,
  gateDelegableAuthority,
  inheritOrigins,
  type PolicyCheck,
  type RetainedOrigin,
} from "./kernel/eligibility-provenance.js";
export {
  type ChildActorParent,
  type ChildActorRefusal,
  childActorCeilingOrigin,
  childActorRefusal,
  type ChildCreationAuthorizationPolicy,
  type ChildCreationPolicyRequest,
  DENY_ALL_CHILD_CREATION_POLICY,
  inheritChildActorOrigins,
  presentedChildActorPermitted,
} from "./kernel/child-actor-eligibility.js";
export {
  authorizationDetailsTypesMetadata,
  AUTHORIZATION_DETAILS_TYPES_METADATA,
  MISSION_RESOURCE_ACCESS_SCHEMA,
  MISSION_RESOURCE_ACCESS_TYPE,
  SUPPORTED_AUTHORIZATION_DETAILS_TYPES,
  validateMissionResourceAccessSchema,
  type AuthorizationDetailsTypeMetadata,
} from "./kernel/authorization-details-metadata.js";
export * from "./kernel/types.js";
export {
  issueCrossDomainGrant,
  audienceScopedAuthority,
  RequestedAuthorityExceededError,
  AuthorityNarrowedToEmptyError,
  DestinationClientUnresolvedError,
  resolveDestinationClientId,
  type DestinationClientRegistration,
  ID_JAG_TYP,
  ID_JAG_TOKEN_TYPE,
} from "./kernel/cross-domain.js";
export {
  deriveAttenuationRoot,
  mintChildOffline,
  deriveCrossOrgRoot,
  mintCrossOrgChild,
  mapAuthorityToTools,
  mapToolsToAuthority,
  AAT_TYP,
  MAX_ROOT_LIFETIME_S,
  type DeriveRootInput,
  type MintChildOptions,
  type CrossOrgRootInput,
} from "./kernel/attenuation.js";
export {
  verifyCrossOrgChain,
  ChainVerificationError,
  WORKLOAD_ATTESTATION_TYPE,
  type FederationConfig,
  type VerifiedChain,
  type VerifiedHop,
} from "./kernel/cross-org-chain.js";
export {
  handleCrossOrgChainExchange,
  type CrossOrgOptions,
  type CrossOrgDerivationRecord,
  type PrincipalMappingEntry,
} from "./adapters/cross-org-grant.js";
export {
  CatalogProvider,
  type ServiceSeed,
  type CatalogService,
  type CatalogFilter,
  type ConnectionStatus,
} from "./kernel/catalog.js";
export {
  validateInstanceAssertion,
  newReplayCache,
  InstanceAssertionError,
  CLIENT_INSTANCE_JWT_TYP,
  CLIENT_INSTANCE_TOKEN_TYPE,
  type InstanceIssuer,
  type ValidatedInstance,
} from "./kernel/instance-assertion.js";
export {
  validateContinuationAssertion,
  checkContinuationFreshness,
  ContinuationAssertionError,
  IDENTITY_CONTINUATION_JWT_TYP,
  IDENTITY_CONTINUATION_TOKEN_TYPE,
  MAX_CONTINUATION_LIFETIME_S,
  CONTINUATION_CLOCK_SKEW_S,
  type ContinuationIssuer,
  type ContinuationActor,
  type ValidatedContinuation,
} from "./kernel/continuation-assertion.js";
export {
  ContinuationStore,
  DEFAULT_CONTINUATION_HOP_LIMIT,
  type AnchorType,
  type ContinuationState,
  type AuthEnvelope,
  type HandleLookup,
  type ResolvedAnchor,
  type ResolvedContinuation,
} from "./kernel/continuation-store.js";
export {
  DelegationFamilyStore,
  type DelegationFamilyState,
  type ResolvedFamily,
} from "./kernel/delegation-family-store.js";
export {
  constructDelegatedIssuance,
  delegatedContextActor,
  type DelegatedIssuance,
  type DelegationGate,
} from "./kernel/delegation.js";
export {
  createExpansion,
  DEFAULT_EXPANSION_RATE_LIMIT,
  ExpansionRateLimiter,
  revokeDrawdownSuccessorsRequestedByAnotherClient,
  revokeSuccessorsExpandedByAnotherClient,
  successorMissionClaim,
  successorWidensOnly,
  type ContainmentHistoryEntry,
  type DrawdownRemediation,
  type ExpansionEvidence,
  type ExpansionInput,
  type ExpansionResult,
  type SuccessorRemediation,
  type UnresolvedDrawdownProvenance,
  type UnresolvedSuccessorProvenance,
} from "./kernel/expansion.js";
export {
  createChildMission,
  childMissionClaim,
  childEvidenceBytes,
  revokeChildrenCreatedByAnotherClient,
  ChildDelegationError,
  CHILD_EVIDENCE_MEDIA_TYPE,
  MAX_CHILD_DEPTH,
  type ChildActor,
  type ChildDenialReason,
  type CreateChildInput,
  type ChildResult,
} from "./kernel/child-delegation.js";
export {
  applyCarryoverInCallerTx,
  CARRYOVER_APPROVAL_EVENT_TYP,
  CARRYOVER_CHANGE_CLASSES,
  CARRYOVER_EVIDENCE_JWS_TYP,
  CARRYOVER_EVIDENCE_MEDIA_TYPE,
  CARRYOVER_EVIDENCE_TYP,
  CARRYOVER_MANIFEST_TYP,
  carryoverApprovalEventId,
  carryoverEvidenceHash,
  CarryoverError,
  carryoverManifestHash,
  CarryoverRetrievalError,
  CarryoverStore,
  commitCarryoverManifest,
  decodeCarryoverEvidence,
  prepareCarryover,
  readCarryoverMap,
  verifyCarryoverEvidence,
  type ApplyCarryoverInput,
  type ApplyCarryoverResult,
  type CarryoverChangeClass,
  type CarryoverCommittedResult,
  type CarryoverConfig,
  type CarryoverEntry,
  type CarryoverEntryPair,
  carryoverEntryPairs,
  type CarryoverEvidence,
  type CarryoverExclusionPolicy,
  type CarryoverExternalState,
  type CarryoverExternalStateAdapter,
  type CarryoverManifest,
  type CarryoverMap,
  type CarryoverMapRow,
  type CarryoverPlan,
  type CarryoverRef,
  type CarryoverRefusalCode,
  type CarryoverReplacementProposal,
  type CarryoverReplacementRow,
} from "./kernel/carryover.js";
export {
  produceWorkProduct,
  ingestWorkProduct,
  bindWorkProduct,
  type BindWorkProductInput,
  ProvenanceCustodyError,
  type ProvenanceMediator,
  type ProvenanceCustodyDenialReason,
  type WorkProduct,
  type ProduceWorkProductInput,
  type IngestWorkProductInput,
  type IngestedWorkProduct,
} from "./kernel/work-products.js";
export {
  verifyWorkProductBinding,
  signWorkProductBinding,
  computeArtifactDigest,
  computeProvenanceDigest,
  workProductBytes,
  WORK_PRODUCT_BINDING_TYP,
  WORK_PRODUCT_PROVENANCE_TYP,
  type WorkProductBindingPayload,
  type SignWorkProductBindingOptions,
  type VerifyWorkProductBindingOptions,
  type BindingVerifyResult,
} from "@mission/mcp-payments";
export {
  mintChildGrant,
  CHILD_GRANT_TYP,
  CHILD_JWT_BEARER_GRANT_TYPE,
  MAX_CHILD_GRANT_LIFETIME_S,
  type MintChildGrantInput,
} from "./adapters/child-grant.js";
export {
  activationPolicyMatches,
  type ActivationPolicyRegistry,
  mintActivationPolicyRef,
  type RegisteredActivationPolicy,
  verifiedActivationPolicy,
} from "./kernel/activation-policy.js";
// @spec mission#standing-consent-bases: the retained activation policy
// snapshots (MissionKernel.activationPolicySnapshots) and the audit check
// MissionKernel.verifyActivationPolicyCommitment returns.
export {
  type ActivationPolicyCommitmentCheck,
  ActivationPolicyRetentionError,
  type ActivationPolicySnapshotKey,
  ActivationPolicySnapshotStore,
  committedActivationPolicy,
  type EvaluatedActivationPolicy,
  type RetainedActivationPolicySnapshot,
} from "./kernel/activation-policy-snapshots.js";
export {
  AGR_ENVELOPE_FORMAT,
  AGR_JWS_CTY,
  AGR_JWS_TYP,
  type AgrAssertion,
  type ApprovalGovernanceRecord,
  ApprovalGovernanceError,
  ApprovalGovernanceRecordStore,
  approvalGovernanceRecordDigest,
  assertAccountableApprover,
  assertAssertionAuthority,
  assertContributing,
  assertGovernedPolicyRecord,
  type HumanAuthority,
  jwsMediaTypeMatches,
  type PolicyAuthority,
  type ServiceAuthority,
  assertMissionBinding,
  signApprovalGovernanceRecord,
  type UnsignedApprovalGovernanceRecord,
  verifyApprovalGovernanceRecord,
} from "./kernel/approval-governance.js";
export {
  activateGovernedPolicy,
  classifyHighRisk,
  eligibleGovernedPolicyConsents,
  evaluateGovernedPolicyRules,
  type GovernedActivation,
  type GovernedActivationInput,
  type GovernedPolicyApprovalConfig,
  GovernedPolicyConfigError,
  type GovernedPolicyConsent,
  GovernedPolicyConsentStore,
  type GovernedPolicyDecision,
  GovernedPolicyError,
  type GovernedPolicyInputs,
  type GovernedPolicyRefusal,
  type GovernedPolicyRoot,
  type GovernedPolicyRules,
  HIGH_RISK_CLASSES,
  type HighRiskClass,
  parseGovernedPolicyRoot,
  parseGovernedPolicyRules,
  previewGovernedActivation,
  recheckGovernedActivation,
  type RecordedModelOutput,
  recordGovernedPolicyConsent,
  STANDARD_CLASS,
  unclassifiedActions,
  validateGovernedPolicyApprovalConfig,
  withdrawGovernedPolicyConsent,
} from "./kernel/governed-policy-approval.js";
export {
  DEFAULT_MAX_PENDING_PER_CLIENT,
  DELIVERY_CLAIM_STALE_S,
  type DeliveryConfirmation,
  type MissionApprovalDeferralOptions,
  MissionApprovalDeferralError,
  MissionApprovalDeferralStore,
  type MissionApprovalPoll,
  type MissionApprovalState,
  type ModelAdvisor,
  type ModelAdvisorRequest,
  type PolicyCompletionResult,
} from "./kernel/mission-approval-deferral.js";
export {
  DEFERRAL_CODE_TOKEN_TYPE,
  DEFERRED_CODE_TTL_S,
  MISSION_APPROVAL_DEFERRAL_PREFIX,
  QUEUE_FULL_RETRY_AFTER_S,
} from "./adapters/deferred-mission-approval.js";
export {
  createTemplate,
  dispatchFromTemplate,
  findDispatch,
  selectDispatchAgent,
  TemplateStore,
  TemplateError,
  DispatchError,
  DispatchMismatchError,
  type DispatchPolicies,
  type DispatchPolicy,
  type MissionTemplate,
  type TemplateCreate,
  type TemplateState,
  type DispatchReason,
  type CreateTemplateInput,
  type DispatchInput,
  type DispatchResult,
} from "./kernel/template.js";
export {
  AUTHORITY_SOURCE_TYPES,
  assertLocalPrincipal,
  bindAuthoritySourceCatalog,
  catalogAuthoritySourceResolver,
  type AuthoritySourceBinding,
  type AuthoritySourceCatalog,
  type AuthoritySourceCatalogEntry,
  type AuthoritySourceRequest,
  type AuthoritySourceResolution,
  type AuthoritySourceResolver,
  type BoundAuthoritySourceCatalog,
  type LocalPrincipal,
  authoritySourceOf,
  isAuthoritySourceType,
  parseAuthoritySource,
  validateAuthoritySourceCatalog,
} from "./kernel/authority-source.js";
export type {
  AuthoritySourceReconciliation,
  HistoricalAuthoritySourceCatalog,
} from "./kernel/source-binding-reconciliation.js";
export type { AuthoritySource, AuthoritySourceType } from "./kernel/types.js";
export {
  DeferralStore,
  DeferralError,
  DEFERRED_GRANT_TYPE,
  ExpansionDeferralStore,
  ExpansionDeferralError,
  ApprovalFloorRefusedError,
  type ApplyCarryoverOutcome,
  type ExpansionApproval,
  type ExpansionDeferredResult,
  type DeferralPending,
  type DeferralSlowDown,
  type DeferredToken,
} from "./kernel/deferred.js";
export { evaluateApprovalFloor, type ApprovalFloorOutcome, type AchievedApproverContext } from "./kernel/approval-floor.js";
export {
  ChallengeError,
  type ChallengeErrorCode,
  type ChallengeIssuerKeys,
  type ChallengeIssuers,
  validateChallenge,
  TXN_CHALLENGE_TYP,
  type TxnChallengeClaims,
} from "./kernel/txn-challenge.js";
export {
  MISSION_TXN_TOKEN_TYP,
  mintTransactionToken,
  type MintTransactionTokenInput,
} from "./kernel/transaction-token.js";
export {
  TxnWorkflowStore,
  type TxnWorkflowRecord,
  type TxnWorkflowState,
} from "./kernel/txn-workflow-store.js";
export type {
  DestinationPolicy,
  FreshDecision,
  FreshDecisionInput,
  TxnAuthorizationOptions,
} from "./adapters/transaction-authorization.js";
export {
  StatusListPublisher,
  signStatusListToken,
  verifyStatusListToken,
  readStatus,
  readStatusBit,
  stateToBit,
  statusListUri,
  STATUS_LIST_ID,
  STATUS_LIST_TYP,
  STATUS_LIST_MEDIA_TYPE,
  STATUS_LIST_BITS,
  STATUS_LIST_SIZE,
  STATUS_LIST_TTL_SECONDS,
  STATUS_VALID,
  STATUS_INVALID,
  STATUS_SUSPENDED,
  type StatusListPayload,
  type StatusListClaim,
  type StatusEntry,
  type SignStatusListOptions,
  type VerifyStatusListOptions,
} from "./kernel/status-list.js";

/**
 * @spec mission#introspection (issue #541 P1-4) — strip EVERY RFC 7517/7518
 * private-key member so a JWK is safe to publish on jwks_uri: an EC key's
 * sole private member is `d`, but an RSA key ALSO carries `p, q, dp, dq, qi`
 * (the CRT primes/exponents) — stripping only `d` from an RSA private JWK
 * (the naive EC-shaped strip) still publishes the private primes. `asToken`
 * is RS256 (config/topology.json), so this matters for the injected
 * test-signing-key path below.
 */
function publicJwkOf(jwk: JWK): Record<string, unknown> {
  const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, ...pub } = jwk as JWK & {
    p?: string;
    q?: string;
    dp?: string;
    dq?: string;
    qi?: string;
  };
  return pub;
}

/**
 * @spec status#lifecycle-authorization: a dedicated client of the Mission
 * Lifecycle endpoint ({@link buildAuthorizationServer}'s `lifecycleClients`).
 */
export interface LifecycleClientRegistration {
  client_id: string;
  client_name: string;
  /** The public half of the client's ES256 signing key; the private half stays at the client. */
  jwks: { keys: Record<string, unknown>[] };
  /** The lifecycle grants bound to this client, `mission_lifecycle` for the state operations. */
  grants: readonly string[];
}

export interface BuiltAs {
  provider: Provider;
  kernel: MissionKernel;
  /** AROP Deferred Token Response store (drive open/approve/deny headlessly). */
  deferrals: DeferralStore;
  /**
   * @spec expansion — the DTR deferred-completion store for Mission EXPANSION
   * (drive open/approve/deny headlessly, mirroring `deferrals`).
   */
  expansionDeferrals: ExpansionDeferralStore;
  /** @spec expansion#policy-probing (#1177): the expansion rate limiter this assembly applies. */
  expansionRateLimiter: ExpansionRateLimiter;
  /**
   * @spec deferred-approval#deferred-approval: the Deferred Mission Approval
   * store, present exactly where the `deferred-approval` capability is on.
   * Exposed so a test can drive the issuer side (a policy completion, a
   * denial) and observe pending approvals.
   */
  missionApprovalDeferrals?: MissionApprovalDeferralStore;
  /**
   * @spec expansion#creation-idempotency — the creation-idempotency store
   * (observe recorded operations; perturb delivery artifacts in tests).
   */
  creationIdempotency: CreationIdempotencyStore;
  issuer: string;
  /** @spec #831: whether this AS signs with a key ring's durable keys or with keys generated at this boot. */
  signingKeyMode: "ring" | "ephemeral";
  agentClientJwk: Record<string, unknown>;
  /**
   * @spec child-delegation#child-client-identity — the child-actor client's
   * private JWK, so a test can authenticate the child at /token and redeem the
   * child-bound RFC 7523 grant AS ITSELF.
   */
  childClientJwk: Record<string, unknown>;
  /**
   * @spec mission#downgrade-by-omission — the Mission-governed client's private
   * JWK, so a test can push a bare authorization_details request as the
   * governed client and observe the AS-side rejection.
   */
  governedClientJwk: Record<string, unknown>;
  /**
   * @spec mission#authority-sources: the private JWK of `ledger-reconciler`,
   * the client of the shipped `service_owned` source, so a test can drive an
   * agent acting for its own workload principal end to end.
   */
  ledgerReconcilerClientJwk: Record<string, unknown>;
  canonicalResource: string;
  /**
   * @spec id-continuation-assertion — the continuation handle store, exposed so a
   * test/exhibit can seed anchors and handles and observe terminal propagation.
   */
  continuationStore: ContinuationStore;
  /**
   * @spec async-delegation — the per-delegation FAMILY store (grant_id ->
   * mission_id), exposed so a test can observe terminal propagation (resolve
   * returns undefined once the Mission reaches a terminal lifecycle state).
   */
  delegationFamilyStore: DelegationFamilyStore;
  /**
   * @spec mission#introspection, mission#delegation-constraints (#869): the
   * token issuance index, which is also the delegation accounting, exposed so
   * a test can model a restart (a lost record) or a truncated chain.
   */
  tokenIssuanceStore: TokenIssuanceStore;
  /**
   * @spec mission-template — the Mission Template store, seeded with one demo
   * read-only reconciliation template. Exposed so the wire PR can dispatch
   * instances (dispatchFromTemplate) and a test/exhibit can inspect templates
   * and dispatch events. Holds no kernel reference (dispatch is a pure function).
   */
  templateStore: TemplateStore;
  /**
   * @spec containment#containment-plane — the issuer-side evidence store holding
   * the protected-event `ingestion` records (accepted AND rejected) and the
   * retained Containment Evidence. Exposed so the later activity-log PR can join
   * these records, and so a test can assert the fail-closed retention.
   */
  issuerEvidence: IssuerEvidenceStore;
  /**
   * @spec containment#protected-events — the config-seeded trusted sources with
   * their PER-BOOT keypairs (D25). Exposed so a test/demo sender can sign a
   * protected-event report with a source's private key.
   */
  protectedEventSources: SeededTrustedSource[];
  /**
   * @spec authority-server#mission-join (#557): whether this assembly armed
   * the dev ordinary-token route with a signer (`devOrdinaryIssuance`). The
   * route mints only when this is true and the `dev-token` capability is
   * enabled, so a deployment that must serve neither (D332) can show this
   * half is off even where the capability gate already refuses.
   */
  devOrdinaryIssuance: boolean;
  /**
   * The capability set this assembly was built with (`adapters/capabilities.ts`).
   * Absent: every capability is on, the full reference provider.
   */
  capabilities?: ReadonlySet<ProviderCapability>;
  /**
   * @spec status#mission-lifecycle-endpoint ("Operations"): the suspension
   * scheduler, present exactly where this assembly adopted schedules
   * (`suspensionSchedules`) and serves `suspend`.
   */
  suspensionScheduler?: SuspensionScheduler;
  /**
   * @spec child-delegation#request-processing step 4, expansion#verification-order
   * step 4 (#1326, #1349): what building this assembly revoked from before
   * the acting-client checks existed, and the committed expansions from
   * another client whose successor it could not identify, for the operator.
   */
  startupRemediation: {
    revokedChildren: string[];
    successors: SuccessorRemediation;
    /** #1372: the ceiling-drawdown successors another client requested. */
    drawdownSuccessors: DrawdownRemediation;
  };
}

export async function buildAuthorizationServer(opts: {
  issuer: string;
  allowHeadlessAdjudication?: boolean;
  /**
   * @spec mission-template#the-mission-template, mission#standing-consent-bases
   * — the deployment's Dispatch Policies, keyed by `dispatch_policy.id`: each
   * policy's version and the exact snapshot the issuer evaluates, whose JSON
   * `select_agent` member is the Agent selection rule for a template that
   * lists several Agents. Merged over the demo policies
   * ({@link DEMO_DISPATCH_POLICIES}); a template commits the named policy's
   * digest at consent and Dispatch verifies it before evaluating anything.
   */
  dispatchPolicies?: DispatchPolicies;
  /**
   * @spec mission#standing-consent-bases — the activation policies the kernel
   * evaluates for a policy-adjudicated child creation, keyed by policy `id`.
   * An Authority Set entry's `child_creation_policy` is verified against them
   * before each child creation. Absent, none is configured.
   */
  activationPolicies?: ActivationPolicyRegistry;
  /**
   * @spec control-plane#deployment-declaration (D27) — the kernel store. The
   * default is in-memory and single-process; a `file` selects the OPT-IN
   * file-backed SINGLE-WRITER store, which is what makes the durable lifecycle
   * outbox and the terminal tombstones survive a restart and lets the recovery
   * test exercise that path. It authorizes no second writer.
   */
  kernelStore?: { file?: string };
  /**
   * @spec child-delegation#carryover — override the deployment's Child Mission
   * Carryover configuration (the capability on-switch, the plan cap, the
   * committed exclusion policy, and the external meter/latch seam). Defaults to
   * the config-shipped {@link CHILD_MISSION_CARRYOVER} (D25). A test that
   * exercises a different exclusion policy, a smaller plan cap, or a real
   * external-transfer adapter injects it here.
   */
  childMissionCarryover?: CarryoverConfig;
  /** Independent approver login integration; OAuth interaction cookies never establish this login. */
  approvalSessions?: ApprovalSessionStore;
  /**
   * @spec mission#approval-authentication (#1320, D496): the approval
   * surface logs its Approver in as an OpenID Connect relying party to this
   * upstream provider, recording each validated login in `approvalSessions`
   * (required with it). Absent: no login route is served, and only the
   * trusted in-process integration records a login.
   */
  approverLogin?: ApproverLoginOptions;
  /**
   * @spec mission#approval-authentication (#826, D425) — override the
   * published approval-authentication floor. Defaults to the config-shipped
   * {@link APPROVAL_FLOOR}.
   */
  approvalFloor?: ApprovalFloorPolicy;
  /**
   * @spec mission#intent-submission-evidence — the deployment-GLOBAL
   * policy-required Intent Submission Evidence types (the anti-downgrade
   * hook), unioned per submission with the presenting client's registered
   * `required_intent_evidence_types`. Empty as shipped.
   */
  requiredIntentEvidenceTypes?: string[];
  /**
   * @spec txn-authorization#challenge-redemption — the
   * transaction_authorization_endpoint's deployment configuration. The
   * transaction-token signing key is this AS's own per-purpose as-txn key and
   * is filled in here, so callers supply only policy and collaborators.
   */
  transactionAuthorization?: Omit<TxnAuthorizationOptions, "tokenKey" | "tokenKid">;
  /**
   * @spec signals#lifecycle-event — an additional lifecycle-commit subscriber,
   * composed with the Status List republisher so BOTH run on every committed
   * transition. Mission Signals injects its emitter's `onCommit` here to emit a
   * `mission.lifecycle-change` SET per consumer. The AS deliberately does NOT
   * import `@mission/signals`: `@mission/signals` imports `LifecycleCommit` from
   * this package, so an import back would form a package reference cycle; the
   * subscriber is injected instead.
   */
  onLifecycleCommit?: (commit: LifecycleCommit) => void;
  /**
   * @spec id-continuation-assertion — override the trusted Continuation
   * Assertion Issuers of ICAs, each scoped to the RAS audiences it attests for
   * (ICA -02 7.3). Defaults to the AS acting as its own Continuation Assertion
   * Issuer for its own hops, under its as-continuation key only. Tests inject
   * a dedicated issuer key.
   */
  continuationAssertionIssuers?: ContinuationIssuer[];
  /**
   * @spec cross-domain#pre-established-trust (#1166, D510);
   * id-continuation-assertion (ICA -02 5.5.5) — the destination-scoped mapping
   * from each requesting client to its registration at each target Resource
   * AS, the onward grant's `client_id`. Defaults to the deployment's
   * `config/topology.json` `crossDomainClients`; a client and target it does
   * not cover is refused `invalid_target`.
   */
  crossDomainClients?: DestinationClientRegistration[];
  /**
   * @spec id-continuation-assertion — the IdP's finite hop-count limit for
   * every continuation chain (ICA -02 6.3), a positive integer. Defaults to
   * {@link DEFAULT_CONTINUATION_HOP_LIMIT}.
   */
  continuationHopLimit?: number;
  /** Resource -> authoritative AS map. Defaults to the demo cross-domain map. */
  resourceToAs?: (resource: string) => string;
  /** Deterministic audience-local subject resolver. Defaults to a stable digest. */
  subjectResolver?: SubjectResolver;
  /**
   * @spec draft-mcguinness-oauth-mission#per-entry-enforcement — override/extend
   * the AS's actor-type ASSERTION registry (delegate/child-actor client id ->
   * asserted `sub_profile`). Merged OVER the config-shipped {@link ACTOR_PROFILES}
   * (D25). Tests inject the actor identities their child/delegation flows use;
   * production leaves this undefined and relies on config.
   */
  actorProfiles?: Record<string, string>;
  /**
   * @spec resource-access#delegate-eligibility (#1275, D457): the
   * authorization server's delegation-authorization policy, consulted at every
   * delegated issuance for an approved entry whose eligibility defers to it
   * (its ceiling entry carries `delegation` without `allowed_delegates`), and
   * read at each call. Absent, the reference policy denies every delegate.
   */
  delegationPolicy?: DelegationAuthorizationPolicy;
  /**
   * @spec child-delegation#fanout (#1304, D486): the authorization server's
   * child-creation policy, consulted for the child actor at every creation
   * and carryover commit where a justifying parent entry's child-actor
   * eligibility defers to it (its `children` grant derives from one without
   * `allowed_child_actors`), and read at each call. Never asked for an entry
   * whose eligibility is its list. Absent, the reference policy denies every
   * child actor. Distinct from an entry's `child_creation_policy` reference.
   */
  childCreationPolicy?: ChildCreationAuthorizationPolicy;
  /**
   * @spec mission#authorization-derivation: override the config-shipped
   * derivation policy ({@link DERIVATION_POLICY}) the kernel derives every
   * Authority Set under. A deployment (or a test) whose ceiling differs from
   * the shipped one supplies it here, together with `authoritySources` when
   * its source ceilings must change to match.
   */
  derivationPolicy?: DerivationPolicy;
  /**
   * @spec mission#authority-sources: override the config-shipped trusted
   * authority-source catalog ({@link AUTHORITY_SOURCES}) the kernel
   * establishes every Mission's source from. Template consent keeps the
   * shipped catalog.
   */
  authoritySources?: typeof AUTHORITY_SOURCES;
  /**
   * @spec mission#introspection (issue #541 P1-4) — TEST-ONLY: inject the AT
   * signing key (a private JWK matching {@link TOPOLOGY.keys.asToken}'s alg)
   * instead of generating one per boot. Lets a test craft adversarial at+jwt
   * fixtures against the strict introspection resolver from ITS OWN retained
   * copy of the private half, without this function ever handing the
   * production signing key back through {@link BuiltAs}. Production callers
   * MUST omit this.
   */
  testTokenSigningJwk?: JWK;
  /**
   * @spec mission#mission-bound-tokens, #831: where the AS's four role keys
   * (`as-token`, `as-status`, `as-txn`, `as-continuation`) come from. A key
   * ring file (`{ ring: path }`, initialized once with `pnpm keys init`)
   * keeps the same material under the same `kid` across restarts; a missing,
   * unreadable or mismatched ring refuses startup and nothing is generated in
   * its place. Absent, or `{ ephemeral: true }`, generates the keys at this
   * boot, as tests and demos do. A deployment entry point chooses explicitly
   * ({@link signingKeysFromEnv}).
   */
  signingKeys?: SigningKeySource;
  /**
   * @spec async-delegation (issue #651) — TEST-ONLY: additional client
   * registrations composed ONTO the config-shipped registry
   * (`config/clients.json`), never replacing an entry of it. A test that needs
   * a registration the demo deliberately does not ship registers it here and
   * signs its own `private_key_jwt` assertions with the private half of the
   * `jwks` it supplies, so this function never hands a shipped client's key
   * back. The motivating cases are child actors a test names in a Child
   * Mission's `child_actor` (the async-delegation family rooted at its own
   * access token, a jwt-bearer-only registration's refusal). Production
   * callers MUST omit this.
   */
  testClients?: Record<string, unknown>[];
  /**
   * TEST-ONLY: introspection principals registered beside the shipped ones
   * (config/introspection.json), so a test can stand up a resource server
   * the demo does not ship, such as a misconfigured one whose audience
   * collides with a client identifier (@spec mission#designation, #869).
   * Production callers MUST omit this.
   */
  testIntrospectionPrincipals?: IntrospectionPrincipal[];
  /**
   * @spec mission#designation (#869, D449): the clients a designation may
   * name. Defaults to config/delegation.json; a test names its own.
   */
  designableClients?: readonly string[];
  /**
   * @spec cross-org-delegation#projection-exchange — destination Resource AS
   * configuration for Chain acceptance (federation trust, principal mapping,
   * local ceiling, evidence sink). Absent = the exchange is refused.
   */
  crossOrg?: CrossOrgOptions;
  /**
   * @spec issuance-grant#effective-set-projection (#617 review 1) — override
   * the Effective Authority Set resolution seam. Defaults to the kernel this
   * function builds. A deployment whose authority source is remote (a MAS
   * Mission Status client) injects it here and raises
   * {@link SourceUnavailableError} for the TRANSIENT class, which the token
   * endpoint refuses `temporarily_unavailable` (HTTP 503) without consuming the
   * presented grant or refresh token.
   */
  authoritySource?: EffectiveAuthoritySource;
  /** The `Retry-After` seconds stamped on a `temporarily_unavailable`. */
  stateRecoveryRetryAfter?: number;
  /**
   * @spec RFC 9449 Section 11.1 — the token endpoint's DPoP proof replay
   * cache. Defaults to a bounded in-memory one; a test of the cache's bound
   * (#1173, D375) injects a smaller one.
   */
  dpopProofReplay?: DpopProofReplay;
  /**
   * @spec authority-server#mission-join (#557) — DEV ONLY: serve
   * `POST /dev/ordinary-token`, which mints an ORDINARY DPoP-bound access
   * token (a `scope`, the payments audience, no `mission` claim) on a
   * registered service token's authority. The MAS Join acts under exactly
   * that credential class and nothing else here issues one, so the demo
   * stack turns it on to have a credential to present. Absent (the default):
   * no such route exists.
   */
  devOrdinaryIssuance?: boolean;
  /**
   * @spec discharge#discharge-authority — additional service-token principals and
   * their scopes, merged OVER the shipped dev token (which carries both
   * `mission_lifecycle` and `mission_discharge`). A test registers a
   * lifecycle-only token to prove the two grants do not imply one another.
   */
  serviceTokenPrincipals?: Record<string, ServiceTokenPrincipal>;
  /**
   * @spec authority-server#join-disclosure (#818): the PDPs enrolled for each
   * enforcement scope, keyed by service principal, each naming the Status
   * `audience` values it is enrolled for. Deployment configuration the MAS
   * holds; absent (the default), no caller is enrolled and no Status response
   * discloses the Mission's `subject` or `client_id`.
   */
  enrolledJoinPdps?: Readonly<Record<string, readonly string[]>>;
  /**
   * @spec status#lifecycle-authorization: the grants bound to a client that
   * authenticates to the Mission Lifecycle endpoint by private-key JWT, keyed by
   * `client_id`. Absent (the default), no client holds any.
   */
  lifecycleClientGrants?: Record<string, readonly string[]>;
  /**
   * @spec status#lifecycle-authorization, status#mission-status-authentication:
   * dedicated Lifecycle clients a deployment registers, each with the PUBLIC
   * half of its own signing key (the private half stays at the client) and the
   * lifecycle grants bound to it. Registered beside the shipped clients, never
   * in place of one; no other client gains a lifecycle grant. Absent (the
   * default), none is registered.
   */
  lifecycleClients?: LifecycleClientRegistration[];
  /**
   * @spec status#lifecycle-authorization: require the distinct
   * `mission_resume` grant, beside `mission_lifecycle`, for a direct `resume`
   * and for scheduling one. Absent (the default), `mission_lifecycle` alone
   * authorizes both.
   */
  distinctResumeGrant?: boolean;
  /**
   * @spec status#mission-lifecycle-endpoint ("Operations"): adopt
   * `suspend_until` and `on_expiry` and run the suspension scheduler that
   * applies them, on the given timers (the process's own by default). Absent
   * (the default), a schedule is refused `invalid_request` and no scheduler
   * runs. Ignored where `suspend` is not served (`lifecycle-extended` off).
   */
  suspensionSchedules?: { timers?: ScheduleTimers };
  /**
   * The kernel's clock. Absent, the system clock. A test drives a schedule's
   * deadline or a Mission's expiry with a controlled one.
   */
  now?: () => Date;
  /**
   * @spec discharge#discharge-authority — the issuer-held discharge-authority
   * policy handed to the kernel: which principals may assert which
   * `event_type`, resolved through a condition's `discharge_authority` value or
   * the baseline mapping. Absent (the default) FAILS CLOSED: no condition can
   * enter a record and no discharge is ever authorized.
   */
  dischargeAuthority?: DischargeAuthorityPolicy;
  /** @spec discharge#discharge-idempotency — event-dedup retention override (seconds). */
  dischargeEventRetentionSeconds?: number;
  /**
   * @spec mission#scope-projection — override the scope-projection mapping.
   * Defaults to the config-shipped {@link SCOPE_PROJECTION}. Read at every
   * Mission-bound issuance, so a test that replaces an audience's entry (or
   * bumps its `version`) observes the next issuance under the new mapping.
   */
  scopeProjection?: ScopeProjectionMapping;
  /**
   * The deployment's enabled capabilities (`adapters/capabilities.ts`).
   * Absent: every capability is on, which is the full reference assembly. A
   * disabled capability refuses with its path's standard error, and with
   * child delegation off the child client is not registered.
   */
  capabilities?: ReadonlySet<ProviderCapability>;
  /**
   * @spec progressive#in-ceiling-expansion: select the policy-adjudicated
   * drawdown path, with the bounds the Mission Deployment Profile publishes.
   * Absent (the default), no drawdown is adjudicated by policy.
   */
  progressive?: ProgressiveDrawdownOptions;
  /**
   * @spec approval-governance#governed-policy: the `governed_policy`
   * standing-consent basis: the consented roots this issuer holds and the
   * humans authorized to approve each. Trusted deployment configuration.
   * Absent (the default), no consent is recorded and nothing activates under
   * that basis.
   */
  governedPolicyApproval?: GovernedPolicyApprovalConfig;
  /**
   * @spec deferred-approval#pending-staleness, deferred-approval#queue-pressure,
   * deferred-approval#policy-completion: Deferred Mission Approval's settings,
   * read where the `deferred-approval` capability is on: the pending lifetime
   * (seconds), the per-client queue bound, the model hook a governed policy
   * consults, and what a policy evaluation that does not authorize
   * activation leaves. This assembly serves no review surface for a human
   * `direct` approval, so that outcome defaults to `deny`; `await_human`
   * leaves the approval pending until its lifetime ends.
   */
  deferredApproval?: {
    pendingLifetimeS?: number;
    maxPendingPerClient?: number;
    onPolicyRefusal?: "await_human" | "deny";
    modelAdvisor?: ModelAdvisor;
  };
  /**
   * @spec expansion#policy-probing (#1177): the per-predecessor, per-client
   * bound on expansion requests, `max` per `windowSeconds`. Default
   * {@link DEFAULT_EXPANSION_RATE_LIMIT}.
   */
  expansionRateLimit?: { max: number; windowSeconds: number };
}): Promise<BuiltAs> {
  // @spec progressive#in-ceiling-expansion, mission#approval-authentication
  // (#1255): a configuration refusal, before any key, store or recovery is
  // touched. A drawdown mapping that disagrees with the approval floor does not start.
  const progressive = opts.progressive
    ? validateProgressiveDrawdownOptions(opts.progressive, opts.approvalFloor ?? APPROVAL_FLOOR)
    : undefined;
  // Per-purpose keys on one jwks_uri (@spec mission#as-metadata; matrix D39):
  // as-token signs tokens, as-status signs Status responses, as-txn signs
  // txn-bound single-use approval tokens (AROP Transaction Challenge), and
  // as-continuation signs the continuation ID-JAG (an identity grant gets its
  // own signing key, discoverable on the AS jwks_uri AND trusted by the RAS).
  const { asToken, asStatus, asTxn, asContinuation } = TOPOLOGY.keys;
  // @spec #831: this process's boot identity, carried by single-use artifacts
  // whose consumption is recorded only in memory (AdapterOptions.processBootId).
  const processBootId = randomBytes(12).toString("base64url");
  // @spec mission#introspection (issue #541 P1-4) — the AT signing key is the
  // ONE key a test legitimately needs the private half of, to craft
  // adversarial at+jwt fixtures against the strict introspection resolver
  // (missing claims, wrong issuer, narrowed authorization_details, ...).
  // Rather than exporting the production private key from BuiltAs (handing
  // every in-process consumer the root key needed to mint arbitrary access
  // tokens), a test MAY inject its OWN key here; production callers omit
  // `testTokenSigningJwk` and get the usual per-boot generated key (D25).
  // The test keeps its own copy of what it injected; nothing signing-capable
  // is ever returned from this function.
  // @spec #831: the four role keys, from a key ring (durable across
  // restarts) or generated at this boot. A ring never falls back to
  // generation, and a test-injected token key belongs to ephemeral keys only.
  const keySource: SigningKeySource = opts.signingKeys ?? { ephemeral: true };
  const roleConfig = { asToken, asStatus, asTxn, asContinuation };
  if ("ring" in keySource && opts.testTokenSigningJwk) {
    throw new SigningKeyRingError("testTokenSigningJwk cannot be combined with a key ring");
  }
  const signing =
    "ring" in keySource
      ? await loadSigningKeyRing(keySource.ring, opts.issuer, roleConfig)
      : await generateEphemeralSigningKeys(roleConfig);
  let tokenPrivateKey: CryptoKey = signing.asToken.privateKey;
  let tokenJwk: Record<string, unknown> = signing.asToken.privateJwk;
  let tokenJwkPub: Record<string, unknown> = signing.asToken.publicJwk;
  if (opts.testTokenSigningJwk) {
    const injected = { ...opts.testTokenSigningJwk, kid: asToken.kid, alg: asToken.alg, use: "sig" };
    tokenPrivateKey = (await importJWK(injected as JWK, asToken.alg)) as CryptoKey;
    tokenJwk = injected;
    tokenJwkPub = publicJwkOf(injected as JWK);
  }
  const statusKeys = { privateKey: signing.asStatus.privateKey };
  const txnKeys = { privateKey: signing.asTxn.privateKey };
  const continuationKeys = { privateKey: signing.asContinuation.privateKey };
  const statusJwkPriv = signing.asStatus.privateJwk;
  const txnJwkPriv = signing.asTxn.privateJwk;
  const continuationJwkPriv = signing.asContinuation.privateJwk;
  const statusJwkPub = signing.asStatus.publicJwk;
  const txnJwkPub = signing.asTxn.publicJwk;
  const continuationJwkPub = signing.asContinuation.publicJwk;

  const agent = await seedAgentClient();
  const child = await seedChildClient();
  // @spec mission#downgrade-by-omission — the Mission-governed demo client:
  // registered so the AS-side anti-downgrade hook is exercisable end to end.
  const governed = await seedGovernedClient();
  // @spec mission#authority-sources: the agent acting for its own workload
  // principal, the client of the shipped `service_owned` source.
  const ledgerReconciler = await seedLedgerReconcilerClient();
  // @spec async-delegation (issue #651) — TEST-ONLY registrations compose ONTO
  // the shipped registry. A duplicate `client_id` would SHADOW a shipped
  // registration rather than add to it (silently widening what the demo
  // ships), so it is refused outright.
  const shippedClientIds = new Set([agent, child, governed, ledgerReconciler].map((c) => c.metadata.client_id));
  for (const testClient of opts.testClients ?? []) {
    const id = String(testClient.client_id);
    if (shippedClientIds.has(id)) {
      throw new Error(`testClients MUST NOT redefine the config-shipped client ${id}`);
    }
  }
  // @spec status#lifecycle-authorization: a dedicated Lifecycle client is a
  // private-key-JWT registration with no grant at /token, holding only the
  // lifecycle grants the deployment binds to it.
  const lifecycleClientMetadata = (opts.lifecycleClients ?? []).map((c) => {
    if (shippedClientIds.has(c.client_id)) {
      throw new Error(`lifecycleClients MUST NOT redefine the config-shipped client ${c.client_id}`);
    }
    if (c.jwks.keys.length === 0 || c.jwks.keys.some((k) => Object.hasOwn(k, "d"))) {
      throw new Error(`lifecycleClients: ${c.client_id} registers public keys only, at least one`);
    }
    return {
      client_id: c.client_id,
      client_name: c.client_name,
      grant_types: [],
      response_types: [],
      redirect_uris: [],
      token_endpoint_auth_method: "private_key_jwt",
      token_endpoint_auth_signing_alg: "ES256",
      jwks: c.jwks,
    } as Record<string, unknown>;
  });
  const lifecycleClientGrants: Record<string, readonly string[]> = {
    ...(opts.lifecycleClientGrants ?? {}),
    ...Object.fromEntries((opts.lifecycleClients ?? []).map((c) => [c.client_id, c.grants])),
  };
  // @spec containment#protected-events — the trusted protected-event source
  // registry: config seeds kid+alg per source (D25), the ES256 keypair is
  // generated per boot. The registry resolves the report's payload `source`
  // IDENTITY to its public verify key + trusted event types; the seeded array is
  // exposed on BuiltAs so a demo/test sender can sign with the private half.
  const seededSources = await seedTrustedSources();
  const protectedEventSources = new Map<string, ProtectedEventSource>();
  for (const s of seededSources) {
    protectedEventSources.set(s.source, {
      key: (await importJWK(s.publicJwk as JWK, s.alg)) as CryptoKey,
      eventTypes: new Set(s.event_types),
      advisory: s.advisory,
    });
  }
  // @spec containment#containment-plane — the issuer-side evidence store: holds
  // the ingestion records (accepted AND rejected) and the retained Containment
  // Evidence (previously discarded at the lifecycle contain handler).
  const issuerEvidence = new IssuerEvidenceStore();
  // The Status List republisher subscribes to the kernel's lifecycle-commit
  // hook. It is created after the kernel closes over it, but onLifecycleCommit
  // only fires at runtime (post-construction), so the forward reference is safe;
  // the publisher takes a build thunk, never the kernel, to avoid an import cycle.
  let statusListPublisher: StatusListPublisher | undefined;
  const tokenIssuanceStore = new TokenIssuanceStore();
  // @spec mission-template — the Mission Template store, seeded with one demo
  // read-only reconciliation template. Independent of the kernel (dispatch is a
  // pure function over both); the wire PR calls dispatchFromTemplate.
  const templateStore = new TemplateStore();
  const dispatchPolicies: DispatchPolicies = { ...DEMO_DISPATCH_POLICIES, ...(opts.dispatchPolicies ?? {}) };
  // @spec mission#authority-sources — template consent establishes the
  // template's authority source from the SAME trusted catalog the kernel uses,
  // so a dispatched instance inherits a source this deployment actually
  // declares.
  createTemplate(templateStore, demoReconciliationTemplate(opts.issuer) as never, {
    // @spec mission#authority-sources (#829, #827): bound to the same issuer
    // and deployment the kernel below binds its catalog to, so consent holds
    // the approver to the one namespace the kernel recognizes and resolves
    // for the one deployment it serves.
    authoritySourceCatalog: bindAuthoritySourceCatalog(AUTHORITY_SOURCES as never, opts.issuer, opts.issuer),
    capabilityResolver: trustedCapabilityResolver(),
    dispatchPolicies,
  });
  // @spec async-delegation — forward reference to the provider (assigned after
  // buildProvider, like statusListPublisher). Captured by the terminal subscriber in
  // the fan-out so it can revoke per-delegation family grants; undefined until
  // construction completes, and no lifecycle commit fires before then.
  let terminalProvider: Provider | undefined;
  // @spec discharge#discharge-idempotency, control-plane#tombstones (issue
  // #250, owner review) — the EFFECTIVE discharge retention, derived once here
  // and used both for the composed tombstone horizon below and for the
  // discharge event store the kernel builds. Composing the default constant
  // while handing the store a larger configured value would leave the detailed
  // tombstone horizon short of the retry window this deployment declared.
  const dischargeEventRetentionSeconds =
    opts.dischargeEventRetentionSeconds ?? DEFAULT_DISCHARGE_EVENT_TTL_S;
  // @spec status#mission-lifecycle-endpoint ("Operations"): the suspension
  // scheduler runs only where schedules are adopted and `suspend` is served.
  // Created after the kernel; it joins the fan-out below by forward reference,
  // like the Status List republisher.
  const schedulesAdopted =
    opts.suspensionSchedules !== undefined && capabilityEnabled(opts, "lifecycle-extended");
  let suspensionScheduler: SuspensionScheduler | undefined;
  const kernel = new MissionKernel({
    capabilityResolver: trustedCapabilityResolver(),
    issuer: opts.issuer,
    policy: (opts.derivationPolicy ?? DERIVATION_POLICY) as never,
    // @spec control-plane#deployment-declaration (D27) — in-memory by default;
    // the file-backed single-writer store is the declared opt-in.
    ...(opts.kernelStore?.file ? { store: { file: opts.kernelStore.file } } : {}),
    // @spec control-plane#tombstones — the deployment's declared retention
    // horizons, composed into the detailed tombstone horizon. Every input is a
    // number this deployment actually declares: the access-token lifetime is
    // the longest-lived artifact that can name a Mission, the creation and
    // discharge idempotency windows bound replay against a terminal record,
    // and the child-cascade horizon is zero because the cascade commits inside
    // the terminal transition's own transaction.
    tombstoneHorizons: {
      credential_artifact_lifetime_seconds: TOPOLOGY.ttls.accessTokenSeconds,
      idempotency_retry_seconds: Math.max(
        DEFAULT_CREATION_TOMBSTONE_TTL_S,
        dischargeEventRetentionSeconds,
        LIFECYCLE_NONCE_TTL_S,
      ),
      child_cascade_seconds: (opts.derivationPolicy ?? DERIVATION_POLICY).max_mission_lifetime_s ?? 0,
    },
    // @spec containment#containment-policy — the issuer-held ContainmentPolicy;
    // only containOnEvent reads it (the manual contain path is unaffected).
    containmentPolicy: CONTAINMENT_POLICY as never,
    // @spec discharge#discharge-authority — the issuer-held discharge-authority
    // policy. Absent as shipped: no deployment config declares a
    // `terminal_when` mapping, so the completion capability stays off and fails
    // closed until one does.
    ...(opts.dischargeAuthority ? { dischargeAuthority: opts.dischargeAuthority } : {}),
    dischargeEventRetentionSeconds,
    // @spec draft-mcguinness-oauth-mission#per-entry-enforcement — the AS-asserted
    // actor-type registry, config-shipped and optionally extended by the caller.
    actorProfiles: { ...ACTOR_PROFILES, ...(opts.actorProfiles ?? {}) },
    // @spec resource-access#delegate-eligibility: deny-all unless supplied.
    ...(opts.delegationPolicy ? { delegationPolicy: opts.delegationPolicy } : {}),
    // @spec child-delegation#fanout (#1304): deny-all unless supplied.
    ...(opts.childCreationPolicy ? { childCreationPolicy: opts.childCreationPolicy } : {}),
    ...(opts.activationPolicies ? { activationPolicies: opts.activationPolicies } : {}),
    ...(opts.governedPolicyApproval ? { governedPolicyApproval: opts.governedPolicyApproval } : {}),
    // @spec mission#authority-sources, mission#approval-event — the deployment's
    // TRUSTED authority-source catalog (config/authority-sources.json plus the
    // governed policies it references). The approval event establishes
    // `authority_source` from this and from nothing a client sends.
    authoritySourceCatalog: (opts.authoritySources ?? AUTHORITY_SOURCES) as never,
    statusKey: statusKeys.privateKey,
    statusKid: asStatus.kid,
    ...(opts.now ? { now: opts.now } : {}),
    // Fan the committed transition out to the Status List republisher (PULL) and
    // any injected subscriber, e.g. the Mission Signals emitter (PUSH). The
    // continuation and delegation-family projections are not subscribers: the
    // kernel writes them in the committing transaction (kernel.continuations,
    // kernel.delegationFamilies), so a commit that is never published still
    // roots or terminates them.
    onLifecycleCommit: (commit) => {
      statusListPublisher?.markDirty();
      // @spec status#mission-lifecycle-endpoint ("Operations"): arm the timer
      // of a committed schedule, cancel it when its suspension ends.
      suspensionScheduler?.onLifecycleCommit(commit);
      opts.onLifecycleCommit?.(commit);
    },
  });
  // @spec id-continuation-assertion, async-delegation, control-plane#serialization
  // (#250): the continuation and delegation-family projections live on the
  // kernel's database and are written in its committing transactions; the
  // adapters reach them through these names.
  const continuationStore = kernel.continuations;
  const delegationFamilyStore = kernel.delegationFamilies;
  if (schedulesAdopted) {
    suspensionScheduler = new SuspensionScheduler(kernel, {
      ...(opts.suspensionSchedules?.timers ? { timers: opts.suspensionSchedules.timers } : {}),
    });
  }
  // @spec status#mission-lifecycle-endpoint ("Operations"), control-plane#fanout:
  // a scheduled revocation also destroys the Mission's OAuth grant, as the
  // Lifecycle endpoint's own `revoke` does, so refresh fails structurally. The
  // effect follows the COMMITTED terminal event that names the schedule it
  // applied, so it is owed whichever path committed the transition (a read, a
  // request, or the timer), and it is a durable delivery: a failed attempt
  // stays pending with its backoff and the next drain retries it. `capture`
  // snapshots the grant identifier inside the commit transaction; destroying
  // an already-destroyed grant finds nothing and succeeds, so a redelivery is
  // harmless. Registered whatever the deployment's schedule setting, so a
  // schedule committed before a restart that turned schedules off still owes
  // it.
  kernel.registerDurableSubscriber<{ grantId: string }>({
    id: "scheduled-termination-grant-destroy",
    capture: (commit) => {
      if (!TERMINAL_STATES.has(commit.state) || !commit.applied_schedule) return undefined;
      const grantId = kernel.get(commit.id)?.grant_id;
      return grantId ? { grantId } : undefined;
    },
    deliver: async ({ grantId }) => {
      const p = terminalProvider;
      // Retryable, never accepted-by-default, as the family revocation below.
      if (!p) throw new Error("provider is not constructed yet");
      const grant = await p.Grant.find(grantId);
      await grant?.destroy();
    },
  });
  // @spec control-plane#fanout: a durable retryable subscriber. Its
  // effect leaves this process (it revokes and destroys oidc-provider grants),
  // so it cannot be acknowledged by returning: it gets a durable delivery row
  // with attempts and a next-retry time, and the promise-returning drain awaits
  // it from boot and from the request paths. This replaces the fire-and-forget
  // revocation with a swallowed rejection that the commit hook used to launch.
  //
  // `capture` runs inside the commit transaction and SNAPSHOTS the family grant
  // identifiers, so the delivery is payload-only: a retry after a restart
  // revokes exactly the grants the transition owed, not whatever the family
  // table holds when the retry runs. Cascade re-enters per descendant commit,
  // so a child's own family gets its own row.
  kernel.registerDurableSubscriber<{ grants: string[] }>({
    id: "delegation-family-grant-revoke",
    capture: (commit) => {
      if (!TERMINAL_STATES.has(commit.state)) return undefined;
      const grants = delegationFamilyStore.familiesForMission(commit.id);
      return grants.length > 0 ? { grants } : undefined;
    },
    deliver: async ({ grants }) => {
      const p = terminalProvider;
      // Retryable, never accepted-by-default: acknowledging while the provider
      // is unavailable would drop the revocation the transition owes.
      if (!p) throw new Error("provider is not constructed yet");
      for (const gid of grants) {
        await p.RefreshToken.revokeByGrantId(gid);
        const grant = await p.Grant.find(gid);
        await grant?.destroy();
      }
    },
  });
  // The publisher compares a cached token's own `exp` against the same clock
  // that signed it (@spec control-plane#fresh-observation).
  statusListPublisher = new StatusListPublisher(
    () => kernel.publishStatusList(),
    () => kernel.nowDate(),
  );
  // AROP DTR store, wired onto the real /token deferred grant (D42).
  const deferrals = new DeferralStore(kernel);
  // @spec expansion — the DTR deferred-completion store for Mission EXPANSION
  // (widening; distinct from AROP, which never widens).
  // @spec child-delegation#carryover — the deployment's carryover configuration
  // rides the same store: absent or disabled, no plan is prepared, no
  // identifier is reserved, and ordinary cascade remains the default.
  const expansionDeferrals = new ExpansionDeferralStore(
    kernel,
    () => kernel.nowDate(),
    opts.childMissionCarryover ?? CHILD_MISSION_CARRYOVER,
    opts.approvalFloor ?? APPROVAL_FLOOR,
  );
  const expansionRateLimit = opts.expansionRateLimit ?? DEFAULT_EXPANSION_RATE_LIMIT;
  const expansionRateLimiter = new ExpansionRateLimiter(
    expansionRateLimit.max,
    expansionRateLimit.windowSeconds,
    () => kernel.nowDate().getTime(),
  );
  // @spec expansion#creation-idempotency — the creation-idempotency store over
  // the kernel database (instances over the same kernel share the table; this
  // one is exposed for tests/exhibit to observe or perturb recorded operations).
  const creationIdempotency = new CreationIdempotencyStore(kernel);
  // @spec deferred-approval#deferred-approval: the Deferred Mission Approval
  // store, on the kernel database, only where the opt-in capability is on.
  // The client registrations this assembly serves (the provider's, below).
  const clientRegistrations: Record<string, unknown>[] = [
    agent.metadata,
    // The child actor is also the demo templates' selected Agent, which
    // redeems a Dispatch Handoff (@spec mission-template#dispatch-handoff),
    // and the shipped same-Mission delegate (@spec mission#delegation, #869).
    ...(capabilityEnabled(opts, "child-delegation") ||
    capabilityEnabled(opts, "templates") ||
    capabilityEnabled(opts, "delegation")
      ? [child.metadata]
      : []),
    governed.metadata,
    ledgerReconciler.metadata,
    ...(opts.testClients ?? []),
    ...lifecycleClientMetadata,
  ];
  // @spec mission#intent-submission-evidence: the deployment-global required
  // evidence types, unioned with the client's registered ones, as the
  // synchronous decision applies them (requiredEvidenceTypesFor).
  const requiredEvidenceTypes = (clientId: string): string[] => {
    const required = new Set(opts.requiredIntentEvidenceTypes ?? []);
    const registration = clientRegistrations.find((c) => c.client_id === clientId);
    const perClient = registration?.required_intent_evidence_types;
    if (Array.isArray(perClient)) for (const t of perClient) if (typeof t === "string") required.add(t);
    return [...required];
  };
  const missionApprovalDeferrals = capabilityEnabled(opts, "deferred-approval")
    ? new MissionApprovalDeferralStore(kernel, {
        requiredEvidenceTypes,
        onPolicyRefusal: opts.deferredApproval?.onPolicyRefusal ?? "deny",
        ...(opts.deferredApproval?.pendingLifetimeS !== undefined
          ? { pendingLifetimeS: opts.deferredApproval.pendingLifetimeS }
          : {}),
        ...(opts.deferredApproval?.maxPendingPerClient !== undefined
          ? { maxPendingPerClient: opts.deferredApproval.maxPendingPerClient }
          : {}),
        ...(opts.deferredApproval?.modelAdvisor ? { modelAdvisor: opts.deferredApproval.modelAdvisor } : {}),
      })
    : undefined;

  // @spec id-continuation-assertion — continuation-grant defaults. The AS is its
  // OWN Continuation Assertion Issuer in the demo, trusted only under its
  // continuation-purpose as-continuation key, not every key on its jwks_uri
  // (D39 per-purpose), and only for its own hops: the roots it accepts as their
  // RAS (ICA -02 5.5.3 rule 3, 7.3). That key also signs the continuation
  // ID-JAG; the validator's pinned ICA typ keeps the two token types apart. The
  // resource->AS map mirrors the demo cross-domain wiring (stack.ts). The
  // subject resolver is deterministic over a constant salt.
  const publicJwks = { keys: [tokenJwkPub, statusJwkPub, txnJwkPub, continuationJwkPub] };
  const continuationAssertionIssuers: ContinuationIssuer[] = opts.continuationAssertionIssuers ?? [
    { iss: opts.issuer, jwks: { keys: [continuationJwkPub] } as never, attestsFor: [] },
  ];
  const resourceToAs =
    opts.resourceToAs ??
    ((r: string) => (r === TOPOLOGY.resources.saas ? TOPOLOGY.issuers.ras : opts.issuer));
  const subjectResolver = opts.subjectResolver ?? defaultSubjectResolver(opts.issuer);
  const continuationHopLimit = opts.continuationHopLimit ?? DEFAULT_CONTINUATION_HOP_LIMIT;
  if (!Number.isSafeInteger(continuationHopLimit) || continuationHopLimit < 1) {
    throw new Error("continuationHopLimit must be a finite positive integer (ICA -02 6.3)");
  }

  if (opts.approverLogin && !opts.approvalSessions) {
    throw new Error("the approver login records its logins in approvalSessions, which is not configured");
  }
  const provider = buildProvider({
    issuer: opts.issuer,
    kernel,
    deferrals,
    expansionDeferrals,
    expansionRateLimiter,
    ...(missionApprovalDeferrals ? { missionApprovalDeferrals } : {}),
    creationIdempotency,
    statusListPublisher,
    clients: clientRegistrations,
    jwks: { keys: [tokenJwk, statusJwkPriv, txnJwkPriv, continuationJwkPriv] },
    publicJwks,
    allowHeadlessAdjudication: opts.allowHeadlessAdjudication ?? false,
    ...(opts.approvalSessions ? { approvalSessions: opts.approvalSessions } : {}),
    ...(opts.approverLogin ? { approverLogin: new ApproverLoginRelyingParty(opts.approverLogin, opts.issuer) } : {}),
    approverApprovesFor: new Map(USERS.map(u => [u.sub, new Set(u.approves_for)])),
    knownSubjects: new Set([...USERS.map(u => u.sub), ...AUTHORITY_SOURCES.entries.flatMap(e => e.principals ?? [])]),
    ...(opts.requiredIntentEvidenceTypes
      ? { requiredIntentEvidenceTypes: opts.requiredIntentEvidenceTypes }
      : {}),
    approverRoleSubs: new Set(USERS.filter((u) => u.roles.includes("approver")).map((u) => u.sub)),
    approvalFloor: opts.approvalFloor ?? APPROVAL_FLOOR,
    accessTokenTTL: TOPOLOGY.ttls.accessTokenSeconds,
    // @spec mission#caller-authorization-and-minimization — the registered
    // RFC 7662 introspection principals (config/introspection.json).
    introspectionPrincipals: [...INTROSPECTION_PRINCIPALS, ...(opts.testIntrospectionPrincipals ?? [])],
    // @spec mission#designation (#869, D449): config/delegation.json.
    designableClients: opts.designableClients ?? DESIGNABLE_CLIENTS,
    // @spec mission#delegation-constraints (#869): the issuance index, which
    // is also the delegation accounting, exposed on BuiltAs.
    tokenIssuanceStore,
    // @spec discharge#discharge-authority — service-token principals and their
    // scopes; merged over the default (the dev token holds both grants).
    ...(opts.serviceTokenPrincipals
      ? { serviceTokenPrincipals: opts.serviceTokenPrincipals }
      : {}),
    ...(opts.enrolledJoinPdps ? { enrolledJoinPdps: opts.enrolledJoinPdps } : {}),
    ...(Object.keys(lifecycleClientGrants).length > 0 ? { lifecycleClientGrants } : {}),
    ...(opts.distinctResumeGrant ? { distinctResumeGrant: true } : {}),
    ...(schedulesAdopted ? { suspensionSchedules: true } : {}),
    ...(opts.crossOrg ? { crossOrg: opts.crossOrg } : {}),
    // @spec txn-authorization#challenge-redemption — the endpoint's
    // configuration, assembled from the caller's deployment inputs plus this
    // AS's own per-purpose transaction-token signing key (D39).
    ...(opts.transactionAuthorization
      ? {
          txnAuthorization: {
            ...opts.transactionAuthorization,
            tokenKey: txnKeys.privateKey,
            tokenKid: asTxn.kid,
          },
        }
      : {}),
    // @spec child-delegation#child-client-identity — sign the child-bound RFC 7523
    // authorization grant with the AS token key (verifies on the jwks_uri).
    childGrantKey: tokenPrivateKey,
    childGrantKid: asToken.kid,
    childGrantAlg: asToken.alg,
    // @spec authority-server#mission-join (#557) — the dev-only ordinary
    // issuance route, signed with this AS's own token key so the resource
    // verifies it on the jwks_uri exactly as it verifies a Mission-bound one.
    ...(opts.devOrdinaryIssuance
      ? {
          devOrdinaryIssuance: {
            key: tokenPrivateKey,
            kid: asToken.kid,
            alg: asToken.alg,
            audience: CANONICAL_RESOURCE,
          },
        }
      : {}),
    // @spec id-continuation-assertion — the RFC 8693 token-exchange continuation
    // grant. The continuation ID-JAG is an identity grant, so it is signed with
    // its OWN dedicated ES256 as-continuation key (D39 per-purpose). That key is
    // published on the AS jwks_uri (so the ID-JAG verifies there) AND trusted by
    // the RAS (so it redeems). ES256 matches the header issueCrossDomainGrant
    // hardcodes; the RS256 AS token key could not have signed it.
    continuationStore,
    // @spec async-delegation — the per-delegation family store used by
    // extraTokenClaims (family fallback), rotateRefreshToken (mandatory family
    // rotation), and ttl.RefreshToken (absolute-lifetime clamp).
    familyStore: delegationFamilyStore,
    continuationAssertionIssuers,
    crossDomainClients: opts.crossDomainClients ?? TOPOLOGY.crossDomainClients,
    continuationReplay: newReplayCache(),
    continuationHopLimit,
    resourceToAs,
    subjectResolver,
    continuationGrantKey: continuationKeys.privateKey,
    continuationGrantKid: asContinuation.kid,
    templateStore,
    dispatchPolicies,
    protectedEventSources,
    issuerEvidence,
    // @spec issuance-grant#effective-set-projection (#617 review 1) — the
    // Effective Authority Set resolution seam. Omitted means the local kernel
    // is the source (it is the authoritative record in this deployment); a
    // consuming AS whose source is a remote MAS Mission Status client injects
    // one that raises SourceUnavailableError for the transient class.
    ...(opts.authoritySource ? { authoritySource: opts.authoritySource } : {}),
    ...(opts.stateRecoveryRetryAfter !== undefined
      ? { stateRecoveryRetryAfter: opts.stateRecoveryRetryAfter }
      : {}),
    ...(opts.dpopProofReplay ? { dpopProofReplay: opts.dpopProofReplay } : {}),
    // @spec mission#scope-projection — the trusted out-of-band mapping.
    scopeProjection: opts.scopeProjection ?? SCOPE_PROJECTION,
    processBootId,
    ...(opts.capabilities ? { capabilities: opts.capabilities } : {}),
    ...(progressive ? { progressive } : {}),
  });
  // @spec async-delegation — publish the provider to the terminal subscriber now
  // that construction is complete (no lifecycle commit could have fired earlier).
  terminalProvider = provider;
  // @spec control-plane#fanout, control-plane#tombstones — startup recovery,
  // run AFTER the provider exists so a pending durable delivery can actually
  // be attempted. It marks pending deliveries owed to subscribers that are no
  // longer registered, replays committed-but-unpublished transitions from the
  // durable outbox, awaits runnable deliveries, and prunes settled outbox rows
  // and expired tombstone detail past the composed retention horizon. A no-op
  // on the in-memory default; the `store.file` opt-in is what makes it
  // observable across a restart.
  await kernel.recoverAtBoot();
  // @spec child-delegation#request-processing step 4 (#1326): revoke any child
  // that a client other than its parent's own created before the step-4 check
  // existed, while its creation operation is retained.
  // @spec expansion#verification-order step 4 (#1349, D516): revoke any
  // successor created through another client's committed deferral, as its
  // retained deferral identifies it.
  // @spec expansion#verification-order step 4 (#1372, D528): revoke any
  // ceiling-drawdown successor another client requested, as its recorded
  // `activation_actor` identifies it. Then attempt the durable effects
  // (family grants) of every transition the sweeps committed before serving a
  // request: unconditionally, since the expiry clock each sweep runs first
  // can commit an `expired` transition that no revocation count reports. A
  // failed revocation throws, so the assembly is not served.
  const revokedChildren = revokeChildrenCreatedByAnotherClient(kernel, creationIdempotency);
  const successorRemediation = revokeSuccessorsExpandedByAnotherClient(kernel, expansionDeferrals);
  const drawdownRemediation = revokeDrawdownSuccessorsRequestedByAnotherClient(kernel);
  await kernel.drainLifecycleOutbox();
  // @spec status#mission-lifecycle-endpoint ("Operations"): re-arm every
  // persisted schedule, delivering any whose deadline passed while the
  // process was down, before this assembly serves a request.
  await suspensionScheduler?.recover();

  return {
    provider,
    kernel,
    deferrals,
    expansionDeferrals,
    expansionRateLimiter,
    ...(missionApprovalDeferrals ? { missionApprovalDeferrals } : {}),
    creationIdempotency,
    issuer: opts.issuer,
    signingKeyMode: "ring" in keySource ? "ring" : "ephemeral",
    agentClientJwk: agent.privateJwk,
    childClientJwk: child.privateJwk,
    governedClientJwk: governed.privateJwk,
    ledgerReconcilerClientJwk: ledgerReconciler.privateJwk,
    canonicalResource: CANONICAL_RESOURCE,
    continuationStore,
    delegationFamilyStore,
    tokenIssuanceStore,
    templateStore,
    issuerEvidence,
    protectedEventSources: seededSources,
    devOrdinaryIssuance: opts.devOrdinaryIssuance === true,
    ...(opts.capabilities ? { capabilities: opts.capabilities } : {}),
    ...(suspensionScheduler ? { suspensionScheduler } : {}),
    startupRemediation: {
      revokedChildren,
      successors: successorRemediation,
      drawdownSuccessors: drawdownRemediation,
    },
  };
}

/**
 * #1326, #1349, #1372: the operator notices a launcher logs for a build's
 * startup remediation (what it revoked from a kernel written before #1340,
 * the committed expansions from another client it could not resolve, and the
 * drawdown successors whose provenance it could not confirm); none when it
 * did nothing.
 */
export function startupRemediationNotices(
  remediation: BuiltAs["startupRemediation"],
): Array<{ level: "info" | "warn"; message: string; detail: Record<string, unknown> }> {
  const { revokedChildren, successors, drawdownSuccessors } = remediation;
  return [
    ...(revokedChildren.length + successors.revoked.length + drawdownSuccessors.revoked.length > 0
      ? [{
          level: "info" as const,
          message: "revoked Missions another client created before #1340",
          detail: {
            revokedChildren,
            revokedSuccessors: successors.revoked,
            revokedDrawdownSuccessors: drawdownSuccessors.revoked,
          },
        }]
      : []),
    ...(successors.unresolved.length > 0
      ? [{
          level: "warn" as const,
          message: "committed expansions from another client whose successor could not be identified",
          detail: { unresolved: successors.unresolved },
        }]
      : []),
    ...(drawdownSuccessors.unresolved.length > 0
      ? [{
          level: "warn" as const,
          message: "ceiling-drawdown successors from another client whose provenance could not be confirmed",
          detail: { unresolved: drawdownSuccessors.unresolved },
        }]
      : []),
  ];
}
