/** Assembly: kernel + adapters + keys. Used by server.ts and tests. */

import {
  CANONICAL_RESOURCE,
  CONTAINMENT_POLICY,
  demoReconciliationTemplate,
  DERIVATION_POLICY,
  seedAgentClient,
  seedChildClient,
  seedTrustedSources,
  type SeededTrustedSource,
  TOPOLOGY,
  USERS,
} from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, type CryptoKey, type JWK } from "jose";
import type Provider from "oidc-provider";
import { buildProvider, type ProtectedEventSource, type TxnArs } from "./adapters/provider.js";
import { IssuerEvidenceStore } from "./kernel/issuer-evidence.js";
import { defaultSubjectResolver, type SubjectResolver } from "./adapters/continuation-grant.js";
import type { ContinuationIssuer } from "./kernel/continuation-assertion.js";
import { ContinuationStore } from "./kernel/continuation-store.js";
import { DelegationFamilyStore } from "./kernel/delegation-family-store.js";
import { DeferralStore } from "./kernel/deferred.js";
import { newReplayCache } from "./kernel/instance-assertion.js";
import { MissionKernel } from "./kernel/kernel.js";
import { StatusListPublisher } from "./kernel/status-list.js";
import { createTemplate } from "./kernel/template.js";
import { TemplateStore } from "./kernel/template-store.js";
import { TERMINAL_STATES } from "./kernel/types.js";
import type { LifecycleCommit, MissionRecord } from "./kernel/types.js";

export { MissionKernel, GateError, LifecycleConflictError } from "./kernel/kernel.js";
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
export { validateMissionIntent, IntentError } from "./kernel/intent.js";
export { deriveAuthoritySet, isSubsetEntry, isSubsetSet } from "./kernel/derive.js";
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
  mapAuthorityToTools,
  mapToolsToAuthority,
  AAT_TYP,
  MAX_ROOT_LIFETIME_S,
  type DeriveRootInput,
  type MintChildOptions,
} from "./kernel/attenuation.js";
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
  type WorkProduct,
  type ProduceWorkProductInput,
  type IngestWorkProductInput,
  type IngestedWorkProduct,
} from "./kernel/work-products.js";
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
  type DeferralPending,
  type DeferralSlowDown,
  type DeferredToken,
} from "./kernel/deferred.js";
export {
  signChallenge,
  validateChallenge,
  issueTxnToken,
  TxnReplayCache,
  TXN_CHALLENGE_TYP,
  TXN_TOKEN_TYP,
  type TxnChallengeClaims,
} from "./kernel/txn-challenge.js";
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

export interface BuiltAs {
  provider: Provider;
  kernel: MissionKernel;
  /** AROP Deferred Token Response store (drive open/approve/deny headlessly). */
  deferrals: DeferralStore;
  issuer: string;
  agentClientJwk: Record<string, unknown>;
  /**
   * @spec child-delegation#child-client-identity — the child-actor client's
   * private JWK, so a test can authenticate the child at /token and redeem the
   * child-bound RFC 7523 grant AS ITSELF.
   */
  childClientJwk: Record<string, unknown>;
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
  /** The resource's txn-challenge keys, for the transaction endpoint. */
  resourceTxnJwks?: { keys: JWK[] };
  /** AROP transaction task store (AS vouches; owns the txn pending id, D37). */
  ars?: TxnArs;
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
}): Promise<BuiltAs> {
  // Per-purpose keys on one jwks_uri (@spec mission#as-metadata; matrix D39):
  // as-token signs tokens, as-status signs Status responses, as-txn signs
  // txn-bound single-use approval tokens (AROP Transaction Challenge), and
  // as-continuation signs the continuation ID-JAG (an identity grant gets its
  // own signing key, discoverable on the AS jwks_uri AND trusted by the RAS).
  const { asToken, asStatus, asTxn, asContinuation } = TOPOLOGY.keys;
  const tokenKeys = await generateKeyPair(asToken.alg, { extractable: true });
  const statusKeys = await generateKeyPair(asStatus.alg, { extractable: true });
  const txnKeys = await generateKeyPair(asTxn.alg, { extractable: true });
  const continuationKeys = await generateKeyPair(asContinuation.alg, { extractable: true });
  const tokenJwk = { ...(await exportJWK(tokenKeys.privateKey)), kid: asToken.kid, alg: asToken.alg, use: "sig" };
  const statusJwkPriv = { ...(await exportJWK(statusKeys.privateKey)), kid: asStatus.kid, alg: asStatus.alg, use: "sig" };
  const txnJwkPriv = { ...(await exportJWK(txnKeys.privateKey)), kid: asTxn.kid, alg: asTxn.alg, use: "sig" };
  const continuationJwkPriv = { ...(await exportJWK(continuationKeys.privateKey)), kid: asContinuation.kid, alg: asContinuation.alg, use: "sig" };
  const tokenJwkPub = { ...(await exportJWK(tokenKeys.publicKey)), kid: asToken.kid, alg: asToken.alg, use: "sig" };
  const statusJwkPub = { ...(await exportJWK(statusKeys.publicKey)), kid: asStatus.kid, alg: asStatus.alg, use: "sig" };
  const txnJwkPub = { ...(await exportJWK(txnKeys.publicKey)), kid: asTxn.kid, alg: asTxn.alg, use: "sig" };
  const continuationJwkPub = { ...(await exportJWK(continuationKeys.publicKey)), kid: asContinuation.kid, alg: asContinuation.alg, use: "sig" };

  const agent = await seedAgentClient();
  const child = await seedChildClient();
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
    statusListPublisher,
    clients: [agent.metadata, child.metadata],
    jwks: { keys: [tokenJwk, statusJwkPriv, txnJwkPriv, continuationJwkPriv] },
    publicJwks,
    allowHeadlessAdjudication: opts.allowHeadlessAdjudication ?? false,
    approverRoleSubs: new Set(USERS.filter((u) => u.roles.includes("approver")).map((u) => u.sub)),
    accessTokenTTL: TOPOLOGY.ttls.accessTokenSeconds,
    txnKey: txnKeys.privateKey,
    txnKid: asTxn.kid,
    // @spec child-delegation#child-client-identity — sign the child-bound RFC 7523
    // authorization grant with the AS token key (verifies on the jwks_uri).
    childGrantKey: tokenKeys.privateKey,
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
    ...(opts.resourceTxnJwks ? { resourceTxnJwks: opts.resourceTxnJwks } : {}),
    ...(opts.ars ? { ars: opts.ars } : {}),
  });
  // @spec async-delegation — publish the provider to the terminal subscriber now
  // that construction is complete (no lifecycle commit could have fired earlier).
  terminalProvider = provider;

  return {
    provider,
    kernel,
    deferrals,
    issuer: opts.issuer,
    agentClientJwk: agent.privateJwk,
    childClientJwk: child.privateJwk,
    canonicalResource: CANONICAL_RESOURCE,
    continuationStore,
    delegationFamilyStore,
    templateStore,
    issuerEvidence,
    protectedEventSources: seededSources,
  };
}
