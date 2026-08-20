/** Assembly: kernel + adapters + keys. Used by server.ts and tests. */

import {
  INTROSPECTION_PRINCIPALS,
  ACTOR_PROFILES,
  CANONICAL_RESOURCE,
  CONTAINMENT_POLICY,
  demoReconciliationTemplate,
  DERIVATION_POLICY,
  seedAgentClient,
  seedChildClient,
  seedGovernedClient,
  seedTrustedSources,
  type SeededTrustedSource,
  TOPOLOGY,
  USERS,
} from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, type CryptoKey, type JWK } from "jose";
import type Provider from "oidc-provider";
import { buildProvider, type ProtectedEventSource, type TxnArs } from "./adapters/provider.js";
import type { CrossOrgOptions } from "./adapters/cross-org-grant.js";
import { IssuerEvidenceStore } from "./kernel/issuer-evidence.js";
import { defaultSubjectResolver, type SubjectResolver } from "./adapters/continuation-grant.js";
import type { ContinuationIssuer } from "./kernel/continuation-assertion.js";
import { ContinuationStore } from "./kernel/continuation-store.js";
import { DelegationFamilyStore } from "./kernel/delegation-family-store.js";
import { DeferralStore, ExpansionDeferralStore } from "./kernel/deferred.js";
import { CreationIdempotencyStore } from "./kernel/creation-idempotency.js";
import type { EffectiveAuthoritySource } from "./kernel/derive.js";
import { newReplayCache } from "./kernel/instance-assertion.js";
import { MissionKernel } from "./kernel/kernel.js";
import type { TxnAuthorizationOptions } from "./adapters/transaction-authorization.js";
import { StatusListPublisher } from "./kernel/status-list.js";
import { createTemplate } from "./kernel/template.js";
import { TemplateStore } from "./kernel/template-store.js";
import { TERMINAL_STATES } from "./kernel/types.js";
import type { LifecycleCommit, MissionRecord } from "./kernel/types.js";

export { MissionKernel, GateError, LifecycleConflictError } from "./kernel/kernel.js";
export { MISSION_ID_ENTROPY_BYTES, newMissionId } from "./kernel/mission-id.js";
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
export type { ProtectedEventSource } from "./adapters/provider.js";
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
  unregisterIntentSubmissionEvidenceType,
  validateAuthorityProposal,
  validateIntentSubmissionEvidence,
  validateMissionIntent,
  validateMissionIntentSubmission,
  verifyIntentSubmissionEvidence,
} from "./kernel/intent.js";
export {
  deriveAuthoritySet,
  type EffectiveAuthoritySource,
  isSubsetEntry,
  isSubsetSet,
  projectThroughEffective,
  SourceUnavailableError,
} from "./kernel/derive.js";
export {
  missionResourceAccessProfile,
  type OperationProfile,
  OperationProfileRegistry,
  type OperationResolution,
  type ResolvedOperation,
} from "./kernel/operation-profile.js";
export { delegatePermitted, type DelegateCandidate } from "./kernel/delegate-matcher.js";
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
  ContinuationAssertionError,
  IDENTITY_CONTINUATION_JWT_TYP,
  IDENTITY_CONTINUATION_TOKEN_TYPE,
  MAX_CONTINUATION_LIFETIME_S,
  type ContinuationIssuer,
  type ContinuationActor,
  type ValidatedContinuation,
} from "./kernel/continuation-assertion.js";
export {
  ContinuationStore,
  type AnchorType,
  type ContinuationState,
  type AuthEnvelope,
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
} from "./kernel/delegation.js";
export {
  createExpansion,
  successorMissionClaim,
  successorWidensOnly,
  type ContainmentHistoryEntry,
  type ExpansionEvidence,
  type ExpansionInput,
  type ExpansionResult,
} from "./kernel/expansion.js";
export {
  createChildMission,
  childMissionClaim,
  childEvidenceBytes,
  ChildDelegationError,
  CHILD_EVIDENCE_MEDIA_TYPE,
  MAX_CHILD_DEPTH,
  type ChildActor,
  type ChildDenialReason,
  type CreateChildInput,
  type ChildResult,
} from "./kernel/child-delegation.js";
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
  createTemplate,
  dispatchFromTemplate,
  TemplateStore,
  TemplateError,
  DispatchError,
  type MissionTemplate,
  type TemplateCreate,
  type TemplateState,
  type DispatchReason,
  type CreateTemplateInput,
  type DispatchInput,
  type DispatchResult,
} from "./kernel/template.js";
export {
  DeferralStore,
  DeferralError,
  DEFERRED_GRANT_TYPE,
  ExpansionDeferralStore,
  ExpansionDeferralError,
  type ExpansionApproval,
  type ExpansionDeferredResult,
  type DeferralPending,
  type DeferralSlowDown,
  type DeferredToken,
} from "./kernel/deferred.js";
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
 * @spec id-continuation-assertion — root a durable grant anchor and mint the
 * INITIAL continuation handle for a newly-activated Mission. Invoked from the
 * lifecycle-commit fan-out on the activating commit. Idempotency guard: a Mission
 * that already carries a handle is left untouched, so the anchor is never
 * duplicated (belt-and-suspenders with the kernel already not emitting a commit on
 * idempotent re-approval).
 *
 * Auth envelope: this is the DEMO's ROOTING-EVENT envelope. `auth_time` is the
 * approval timestamp (from `created_at`) and `acr` is `intent.controls.acr` when
 * present; `amr` is omitted. A real deployment supplies the root AUTHENTICATION
 * event's envelope instead of synthesising it from the approval.
 *
 * The initial handle binds the Mission's actor: the agent CLIENT
 * (iss = AS issuer, sub = client_id), matching the /token four-signal contract's
 * `currentActor`. No cnf is bound (no DPoP key exists at approval); the four-signal
 * check validates the PRESENTED key at /token, never this stored handle's cnf.
 */
function rootMissionContinuation(store: ContinuationStore, record: MissionRecord): void {
  if (store.handlesForMission(record.id).length > 0) return; // never double-root
  const acr = record.intent.controls?.acr;
  const anchorId = store.rootGrantAnchor({
    missionId: record.id,
    authEnvelope: {
      authTime: Math.floor(Date.parse(record.created_at) / 1000),
      ...(acr !== undefined ? { acr } : {}),
    },
  });
  store.mint({
    anchorId,
    missionId: record.id,
    actor: { iss: record.issuer, sub: record.client_id },
  });
}

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
  /**
   * @spec expansion#creation-request-id — the creation-idempotency store
   * (observe recorded operations; perturb delivery artifacts in tests).
   */
  creationIdempotency: CreationIdempotencyStore;
  issuer: string;
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
}

export async function buildAuthorizationServer(opts: {
  issuer: string;
  allowHeadlessAdjudication?: boolean;
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
   * @spec id-continuation-assertion — override the trusted Chain Authority
   * issuers of ICAs. Defaults to the AS acting as its own Chain Authority (its
   * jwks_uri keys). Tests inject a dedicated Chain Authority key.
   */
  chainAuthorityIssuers?: ContinuationIssuer[];
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
}): Promise<BuiltAs> {
  // Per-purpose keys on one jwks_uri (@spec mission#as-metadata; matrix D39):
  // as-token signs tokens, as-status signs Status responses, as-txn signs
  // txn-bound single-use approval tokens (AROP Transaction Challenge), and
  // as-continuation signs the continuation ID-JAG (an identity grant gets its
  // own signing key, discoverable on the AS jwks_uri AND trusted by the RAS).
  const { asToken, asStatus, asTxn, asContinuation } = TOPOLOGY.keys;
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
  let tokenPrivateKey: CryptoKey;
  let tokenJwk: Record<string, unknown>;
  let tokenJwkPub: Record<string, unknown>;
  if (opts.testTokenSigningJwk) {
    const injected = { ...opts.testTokenSigningJwk, kid: asToken.kid, alg: asToken.alg, use: "sig" };
    tokenPrivateKey = (await importJWK(injected as JWK, asToken.alg)) as CryptoKey;
    tokenJwk = injected;
    tokenJwkPub = publicJwkOf(injected as JWK);
  } else {
    const tokenKeys = await generateKeyPair(asToken.alg, { extractable: true });
    tokenPrivateKey = tokenKeys.privateKey;
    tokenJwk = { ...(await exportJWK(tokenKeys.privateKey)), kid: asToken.kid, alg: asToken.alg, use: "sig" };
    tokenJwkPub = { ...(await exportJWK(tokenKeys.publicKey)), kid: asToken.kid, alg: asToken.alg, use: "sig" };
  }
  const statusKeys = await generateKeyPair(asStatus.alg, { extractable: true });
  const txnKeys = await generateKeyPair(asTxn.alg, { extractable: true });
  const continuationKeys = await generateKeyPair(asContinuation.alg, { extractable: true });
  const statusJwkPriv = { ...(await exportJWK(statusKeys.privateKey)), kid: asStatus.kid, alg: asStatus.alg, use: "sig" };
  const txnJwkPriv = { ...(await exportJWK(txnKeys.privateKey)), kid: asTxn.kid, alg: asTxn.alg, use: "sig" };
  const continuationJwkPriv = { ...(await exportJWK(continuationKeys.privateKey)), kid: asContinuation.kid, alg: asContinuation.alg, use: "sig" };
  const statusJwkPub = { ...(await exportJWK(statusKeys.publicKey)), kid: asStatus.kid, alg: asStatus.alg, use: "sig" };
  const txnJwkPub = { ...(await exportJWK(txnKeys.publicKey)), kid: asTxn.kid, alg: asTxn.alg, use: "sig" };
  const continuationJwkPub = { ...(await exportJWK(continuationKeys.publicKey)), kid: asContinuation.kid, alg: asContinuation.alg, use: "sig" };

  const agent = await seedAgentClient();
  const child = await seedChildClient();
  // @spec mission#downgrade-by-omission — the Mission-governed demo client:
  // registered so the AS-side anti-downgrade hook is exercisable end to end.
  const governed = await seedGovernedClient();
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
  // @spec id-continuation-assertion — the continuation handle store. Holds no
  // kernel reference; constructed before the kernel so it can join the
  // lifecycle-commit fan-out below (a terminal Mission terminates every
  // continuation anchor/handle rooted in it, so its lineages stop resolving).
  const continuationStore = new ContinuationStore();
  // @spec async-delegation — the per-delegation FAMILY store. Holds no kernel
  // reference; constructed before the kernel so it can join the lifecycle-commit
  // fan-out below (a terminal Mission terminates every delegation family rooted in
  // it, and the provider-capturing terminal subscriber revokes each family's grant).
  const delegationFamilyStore = new DelegationFamilyStore();
  // @spec mission-template — the Mission Template store, seeded with one demo
  // read-only reconciliation template. Independent of the kernel (dispatch is a
  // pure function over both); the wire PR calls dispatchFromTemplate.
  const templateStore = new TemplateStore();
  createTemplate(templateStore, demoReconciliationTemplate(opts.issuer) as never);
  // @spec async-delegation — forward reference to the provider (assigned after
  // buildProvider, like statusListPublisher). Captured by the terminal subscriber in
  // the fan-out so it can revoke per-delegation family grants; undefined until
  // construction completes, and no lifecycle commit fires before then.
  let terminalProvider: Provider | undefined;
  const kernel = new MissionKernel({
    issuer: opts.issuer,
    policy: DERIVATION_POLICY as never,
    // @spec containment#containment-policy — the issuer-held ContainmentPolicy;
    // only containOnEvent reads it (the manual contain path is unaffected).
    containmentPolicy: CONTAINMENT_POLICY as never,
    // @spec draft-mcguinness-oauth-mission#per-entry-enforcement — the AS-asserted
    // actor-type registry, config-shipped and optionally extended by the caller.
    actorProfiles: { ...ACTOR_PROFILES, ...(opts.actorProfiles ?? {}) },
    statusKey: statusKeys.privateKey,
    statusKid: asStatus.kid,
    // Fan the committed transition out to the Status List republisher (PULL), the
    // continuation store (terminal propagation), and any injected subscriber, e.g.
    // the Mission Signals emitter (PUSH).
    onLifecycleCommit: (commit) => {
      statusListPublisher?.markDirty();
      continuationStore.onLifecycleCommit(commit);
      // @spec async-delegation — terminal propagation for delegation families. A
      // terminal Mission marks all of its family rows terminal (so resolve stops).
      delegationFamilyStore.onLifecycleCommit(commit);
      // @spec async-delegation — provider-capturing terminal subscriber. On ANY
      // terminal commit (revoke/complete AND expiry/cascade/supersede all funnel
      // through here) revoke + destroy the oidc grant of every per-delegation family
      // rooted in this Mission, so a subsequent refresh fails STRUCTURALLY rather
      // than merely by the family resolving terminal. The hook carries no Koa ctx,
      // so the request-scoped revoke helper is unavailable; revoke via the STATIC
      // RefreshToken.revokeByGrantId + Grant.destroy. Fire-and-forget with a swallowed
      // rejection (the hook is synchronous): the in-process microtask chain settles
      // before the next request macrotask, and a missing grant is a no-op. Cascade
      // re-enters this hook per descendant commit, so a child's own family is covered.
      if (terminalProvider && TERMINAL_STATES.has(commit.state)) {
        const p = terminalProvider;
        for (const gid of delegationFamilyStore.familiesForMission(commit.id)) {
          void (async () => {
            await p.RefreshToken.revokeByGrantId(gid);
            const grant = await p.Grant.find(gid);
            await grant?.destroy();
          })().catch(() => {});
        }
      }
      // @spec id-continuation-assertion — approval-time grant-anchor rooting. The
      // ACTIVATING commit (version 1, no prior_state, active) of a newly-approved
      // Mission roots the durable grant-anchored continuation root + an INITIAL
      // handle, so a continuation chain can actually begin from an approved
      // Mission. This is the single funnel that fires for kernel.approve() as well
      // as expansion successors and Child Missions (all reach insertRecord ->
      // emitCommit); every activated Mission is thus a durable root. Purely
      // additive: a Mission that never continues is unaffected (the anchor/handle
      // sit inert). Not fired on idempotent re-approval: a duplicate
      // approval_event_id throws before emitCommit, so no commit is emitted.
      if (commit.version === 1 && commit.prior_state === undefined && commit.state === "active") {
        const record = kernel.get(commit.id);
        if (record) rootMissionContinuation(continuationStore, record);
      }
      opts.onLifecycleCommit?.(commit);
    },
  });
  statusListPublisher = new StatusListPublisher(() => kernel.publishStatusList());
  // AROP DTR store, wired onto the real /token deferred grant (D42).
  const deferrals = new DeferralStore(kernel);
  // @spec expansion — the DTR deferred-completion store for Mission EXPANSION
  // (widening; distinct from AROP, which never widens).
  const expansionDeferrals = new ExpansionDeferralStore(kernel);
  // @spec expansion#creation-request-id — the creation-idempotency store over
  // the kernel database (instances over the same kernel share the table; this
  // one is exposed for tests/exhibit to observe or perturb recorded operations).
  const creationIdempotency = new CreationIdempotencyStore(kernel);

  // @spec id-continuation-assertion — continuation-grant defaults. The AS is its
  // OWN Chain Authority in the demo (ICAs trusted when signed by a key on its
  // jwks_uri). The resource->AS map mirrors the demo cross-domain wiring
  // (stack.ts). The subject resolver is deterministic over a constant salt.
  const publicJwks = { keys: [tokenJwkPub, statusJwkPub, txnJwkPub, continuationJwkPub] };
  const chainAuthorityIssuers: ContinuationIssuer[] =
    opts.chainAuthorityIssuers ?? [{ iss: opts.issuer, jwks: publicJwks as never }];
  const resourceToAs =
    opts.resourceToAs ??
    ((r: string) => (r === TOPOLOGY.resources.saas ? TOPOLOGY.issuers.ras : opts.issuer));
  const subjectResolver = opts.subjectResolver ?? defaultSubjectResolver(opts.issuer);

  const provider = buildProvider({
    issuer: opts.issuer,
    kernel,
    deferrals,
    expansionDeferrals,
    creationIdempotency,
    statusListPublisher,
    clients: [agent.metadata, child.metadata, governed.metadata],
    jwks: { keys: [tokenJwk, statusJwkPriv, txnJwkPriv, continuationJwkPriv] },
    publicJwks,
    allowHeadlessAdjudication: opts.allowHeadlessAdjudication ?? false,
    ...(opts.requiredIntentEvidenceTypes
      ? { requiredIntentEvidenceTypes: opts.requiredIntentEvidenceTypes }
      : {}),
    approverRoleSubs: new Set(USERS.filter((u) => u.roles.includes("approver")).map((u) => u.sub)),
    accessTokenTTL: TOPOLOGY.ttls.accessTokenSeconds,
    // @spec mission#caller-authorization-and-minimization — the registered
    // RFC 7662 introspection principals (config/introspection.json).
    introspectionPrincipals: INTROSPECTION_PRINCIPALS,
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
    chainAuthorityIssuers,
    continuationReplay: newReplayCache(),
    resourceToAs,
    subjectResolver,
    continuationGrantKey: continuationKeys.privateKey,
    continuationGrantKid: asContinuation.kid,
    templateStore,
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
  });
  // @spec async-delegation — publish the provider to the terminal subscriber now
  // that construction is complete (no lifecycle commit could have fired earlier).
  terminalProvider = provider;

  return {
    provider,
    kernel,
    deferrals,
    expansionDeferrals,
    creationIdempotency,
    issuer: opts.issuer,
    agentClientJwk: agent.privateJwk,
    childClientJwk: child.privateJwk,
    governedClientJwk: governed.privateJwk,
    canonicalResource: CANONICAL_RESOURCE,
    continuationStore,
    delegationFamilyStore,
    templateStore,
    issuerEvidence,
    protectedEventSources: seededSources,
  };
}
