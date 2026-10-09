/**
 * Thin adapters over node-oidc-provider 9.10.0 (decision D30): the provider
 * and custom routes call the mission-kernel only through its interface.
 * Wiring facts verified by the pre-flight spike (src/spikes/SPIKE-REPORT.md).
 */

import { createHash, timingSafeEqual } from "node:crypto";
import { MISSION_MAX_STALE_SECONDS } from "@mission/demo-data";
import { APPROVAL_SUBJECT_HEADER, ApprovalSessionStore, MISSION_APPROVAL_SCOPE, validApprovalPrincipal, type ApprovalPrincipal } from "./approval-resolution.js";
import type { IncomingMessage, ServerResponse } from "node:http";
import {
  DERIVATION_POLICY,
  DEV_SERVICE_TOKEN,
  type IntrospectionPrincipal,
  DISPATCH_PROHIBITED_ACTIONS,
  USERS,
  WRITE_ACTIONS,
} from "@mission/demo-data";
import {
  calculateJwkThumbprint,
  createLocalJWKSet,
  decodeJwt,
  decodeProtectedHeader,
  jwtVerify,
  SignJWT,
  type CryptoKey,
  type JWK,
} from "jose";
import Provider, { errors, type Configuration, type KoaContextWithOIDC, type ResourceServer } from "oidc-provider";
import {
  delegatedRoutingRefusal,
  earlyScopeRefusal,
  projectScope,
  type RequestedScope,
  type ScopeProjectionMapping,
  type ScopeProjectionOutcome,
  splitScope,
  withoutCapabilitySources,
} from "@mission/core";

/**
 * @spec mission#authority-proposal, mission#scope-projection — the reserved
 * stored-interaction key marking an `authorization_details` value the AS
 * wrote itself (the Intent-only completion workaround in `decide`). It is not
 * an oidc-provider parameter, so a client can never send it: the provider's
 * parameter allow-list drops it from every PAR and authorization request.
 */
export const DERIVED_AUTHORIZATION_DETAILS_MARKER = "__mission_derived_authorization_details";
/** Interaction-result member marking an approval no End-User authenticated
 *  in the user agent (a headless approval service's, #826). */
const HEADLESS_APPROVAL_RESULT = "mission_headless_approval";

/**
 * @spec mission#authority-proposal — the client's authority proposal as the
 * stored interaction carries it: the `authorization_details` string the
 * client pushed, or undefined when it pushed none. A value the AS injected
 * for oidc-provider's completion check is never a proposal.
 */
export function clientProposalParam(params: Record<string, unknown>): string | undefined {
  if (params[DERIVED_AUTHORIZATION_DETAILS_MARKER] === true) return undefined;
  return typeof params.authorization_details === "string" ? params.authorization_details : undefined;
}

/**
 * @spec mission#error-mapping — a scope-projection refusal as the OAuth error
 * the core's error-mapping table names for it: `invalid_scope` for an
 * explicitly requested value the issuance cannot grant, `invalid_target` for
 * an unknown mapping, the delegated-routing rule, or no safe projection.
 */
export function scopeProjectionError(outcome: Extract<ScopeProjectionOutcome, { outcome: "refuse" }>) {
  return outcome.error === "invalid_scope"
    ? // No `scope` member on the error body (@types require one; the runtime does not).
      new (errors.InvalidScope as unknown as new (description: string) => errors.OIDCProviderError)(
        outcome.reason,
      )
    : new errors.InvalidTarget(outcome.reason);
}

// @types/oidc-provider (9.5) predates InvalidAuthorizationDetails, present at
// runtime in 9.10 (spec traceability: SPEC_VERSIONS O-2 note). Typed alias
// (exported for the token-exchange proposal intake in continuation-grant.ts).
export const InvalidAuthorizationDetails = (errors as unknown as {
  InvalidAuthorizationDetails: new (message?: string) => Error;
}).InvalidAuthorizationDetails;

// @spec mission#error-mapping — `access_denied` ({{RFC6749}}) for the
// configured-mapping-mode derivation refusal (no `authorization_details`
// proposal was submitted, so AS policy alone yields no Authority Set).
// Standard oidc-provider error, same @types-lag pattern as the alias above.
export const AccessDenied = (errors as unknown as {
  AccessDenied: new (message?: string) => Error;
}).AccessDenied;

/**
 * @spec mission#intent-submission-evidence — `invalid_mission_intent_evidence`,
 * the core-registered OAuth error for Intent Submission Evidence dispatch
 * failures (an entry of an unsupported `type`, an entry failing its type's
 * validation, a policy-required type absent). Envelope STRUCTURAL failures
 * (bare shape, unknown member, missing `type`, bounds) stay invalid_request.
 */
export class InvalidMissionIntentEvidence extends errors.CustomOIDCProviderError {
  constructor(description?: string) {
    super("invalid_mission_intent_evidence", description);
  }
}

/**
 * @spec mission#issuance-gating, mission#error-mapping — `invalid_grant` plus
 * the `mission_error` token-error-response extension member. oidc-provider
 * 9.10's `InvalidGrant` hardcodes `error_description` to a generic constant
 * and its renderer (`err_out.js`) copies only `error`/`error_description`/
 * `scope`/`state` from a thrown error onto the wire body, so no property added
 * to a thrown `InvalidGrant` instance reaches the client. `mission_error` is
 * therefore carried by the `grant.error` event instead (below), which fires
 * synchronously after the generic body is set but before the response is
 * flushed: this class is the marker the listener keys on, and `missionError`
 * is the value it splices in. This is the fix for the wrong wire carrier the
 * conformance manifest recorded (this member previously never reached the
 * client at all).
 */
export class MissionGrantError extends errors.InvalidGrant {
  constructor(
    message: string,
    readonly missionError?: MissionErrorValue,
  ) {
    super(message);
  }
}

/**
 * The `mission_error` values this deployment emits: the OAuth binding's own,
 * Derivation Limits' `derivations_exhausted`, and Mission Status's
 * `mission_suspended` and `mission_completed`.
 */
export type MissionErrorValue =
  | "mission_revoked"
  | "mission_expired"
  | "derivations_exhausted"
  | "mission_suspended"
  | "mission_completed";

/**
 * @spec mission#issuance-gating, status#mission-lifecycle-endpoint — map a
 * kernel {@link GateError} onto the `mission_error` diagnostic value, where
 * one applies. `reason` alone is not enough: `mission_not_active` covers
 * `revoked` and Mission Status's `suspended` and `completed`, each with its
 * own value, and the ancestor-lineage-walk refusal (also
 * `mission_not_active`) names an ancestor's state, not `missionId`'s own.
 * `currentState`, the FRESH persisted state of `missionId` itself (read
 * after the throw, since `applyExpiry` may have just committed an `expired`
 * transition), resolves both: the value names `missionId`'s own state, so a
 * lineage-refused Mission whose own state is still `active` gets no
 * `mission_error` rather than a misleading one. A child that a parent's
 * suspension projects to `suspended` holds that state as its own, so it gets
 * `mission_suspended`. `authority_contained` and `authority_exhausted` are
 * not `mission_error` values (the former rides the Containment companion's
 * own `mission_denial_reason`; the latter has no diagnostic), so both also
 * fall through to plain `invalid_grant`, which the SHOULD permits.
 */
export function gateErrorToMissionError(
  reason: GateError["reason"],
  currentState: string | undefined,
): MissionErrorValue | undefined {
  switch (reason) {
    case "mission_expired":
      return "mission_expired";
    case "mission_not_active":
      switch (currentState) {
        case "revoked":
          return "mission_revoked";
        case "suspended":
          return "mission_suspended";
        case "completed":
          return "mission_completed";
        default:
          return undefined;
      }
    case "derivation_cap_exhausted":
      return "derivations_exhausted";
    default:
      return undefined;
  }
}

/** Map an intake {@link IntentError} onto its OAuth error class. */
export function intentErrorToOidc(e: IntentError): Error {
  switch (e.code) {
    case "invalid_authorization_details":
      return new InvalidAuthorizationDetails(e.message);
    case "invalid_mission_intent_evidence":
      return new InvalidMissionIntentEvidence(e.message);
    case "access_denied":
      return new AccessDenied(e.message);
    default:
      return new errors.InvalidRequest(e.message);
  }
}

/**
 * @spec mission#intent-submission-evidence — resolve the policy-REQUIRED
 * evidence types for a submission (the anti-downgrade hook), BEFORE
 * derivation: the deployment-global set
 * ({@link AdapterOptions.requiredIntentEvidenceTypes}) unioned with the
 * presenting client's registered `required_intent_evidence_types` metadata.
 */
export function requiredEvidenceTypesFor(opts: AdapterOptions, clientMeta?: unknown): string[] {
  const set = new Set(opts.requiredIntentEvidenceTypes ?? []);
  const per = (clientMeta as { required_intent_evidence_types?: unknown } | undefined)
    ?.required_intent_evidence_types;
  if (Array.isArray(per)) {
    for (const t of per) if (typeof t === "string") set.add(t);
  }
  return [...set];
}
import {
  DEFERRED_GRANT_TYPE,
  DeferralError,
  type DeferralStore,
  type DeferredToken,
  type ExpansionDeferralStore,
} from "../kernel/deferred.js";
import {
  type ChildDenialReason,
  childMissionClaim,
} from "../kernel/child-delegation.js";
import { CreationIdempotencyStore } from "../kernel/creation-idempotency.js";
import { type DpopProofReplay, newDpopProofReplay } from "./dpop-replay.js";
import {
  handleTransactionAuthorization,
  newTxnWorkflows,
  type TxnAuthorizationOptions,
} from "./transaction-authorization.js";
export type { TxnArs } from "./transaction-authorization.js";
import { successorMissionClaim } from "../kernel/expansion.js";
import { ID_JAG_TOKEN_TYPE } from "../kernel/cross-domain.js";
import {
  authorizationDetailsTypesMetadata,
  validateMissionResourceAccessSchema,
} from "../kernel/authorization-details-metadata.js";
import { withTransaction } from "@mission/store";
import { UnknownProtectedEventError } from "../kernel/containment.js";
import {
  DIGEST_PREFIX,
  DISCHARGE_EVENT_ID_RE,
  DISCHARGE_RECEIPT_MEDIA_TYPE,
  DischargeConflictError,
  DischargeNotFoundError,
  type DischargeTargetForm,
  EVIDENCE_REF_MAX_CHARS,
} from "../kernel/discharge.js";
import { CONDITION_SELECTOR_RE } from "../kernel/discharge-selector-store.js";
import {
  LIFECYCLE_ENDPOINT_KEY,
  type LifecycleNonceKey,
  type LifecycleResponseMaterial,
  LifecycleResponseStore,
  type RetainedLifecycleResponse,
} from "../kernel/lifecycle-idempotency.js";
import {
  type EffectiveAuthoritySource,
  isSubsetSet,
  type OriginProjection,
  projectRarThroughMission,
  SourceUnavailableError,
} from "../kernel/derive.js";
import type { IssuerEvidenceStore } from "../kernel/issuer-evidence.js";
import { IntentError } from "../kernel/intent.js";
import {
  type DischargeReceiptObservation,
  GateError,
  LifecycleConflictError,
  type MissionKernel,
  STATUS_SIGNING_ALG,
  type StatusObservation,
} from "../kernel/kernel.js";
import {
  STATUS_LIST_ID,
  STATUS_LIST_MEDIA_TYPE,
  type StatusListPublisher,
} from "../kernel/status-list.js";

import type {
  AuthorityEntry,
  AuthoritySource,
  LifecycleOperation,
  MissionIntent,
  MissionRecord,
} from "../kernel/types.js";
import { CHILD_GRANT_TYP, CHILD_JWT_BEARER_GRANT_TYPE } from "./child-grant.js";
import { DISPATCH_HANDOFF_TYP, handleDispatchHandoffRedemption } from "./dispatch-handoff.js";
import type { CrossOrgOptions } from "./cross-org-grant.js";
import {
  type ContinuationReplay,
  freshProofJti,
  handleTokenExchangeGrant,
  type SubjectResolver,
  TOKEN_EXCHANGE_GRANT_TYPE,
} from "./continuation-grant.js";
import type { ContinuationIssuer } from "../kernel/continuation-assertion.js";
import type { ContinuationStore } from "../kernel/continuation-store.js";
import type { DelegationFamilyStore } from "../kernel/delegation-family-store.js";
import {
  createTemplate,
  dispatchFromTemplate,
  DispatchError,
  DispatchMismatchError,
  findDispatch,
  TemplateError,
  type CreateTemplateInput,
  type DispatchInput,
  type DispatchPolicies,
  type DispatchReason,
} from "../kernel/template.js";
import type { TemplateStore } from "../kernel/template-store.js";
import { TokenIssuanceStore } from "../kernel/token-issuance-store.js";
import {
  capabilityEnabled,
  type ProviderCapability,
  TOKEN_EXCHANGE_CAPABILITIES,
} from "./capabilities.js";

/**
 * @spec mission-template#dispatch — the impl-local grant type a dispatcher
 * redeems at /token to instantiate an ordinary Mission from a Mission
 * Template (dispatchFromTemplate). Mirrors DEFERRED_GRANT_TYPE's shape (an
 * implementation choice on top of "no new endpoints when /token carries it");
 * distinct from the child-redemption grant type.
 */
export const MISSION_DISPATCH_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:mission-dispatch";

/**
 * @spec status#mission-status-authentication — the scope the four Mission-state
 * lifecycle operations (`revoke`, `suspend`, `resume`, `complete`, and this
 * deployment's `contain`) require at the Mission Lifecycle endpoint.
 */
export const MISSION_LIFECYCLE_SCOPE = "mission_lifecycle";

/**
 * @spec discharge#discharge-authority — the DISTINCT scope `discharge` requires.
 * Possession of {@link MISSION_LIFECYCLE_SCOPE}, or being the Mission's
 * Subject, Approver, or an administrator, MUST NOT by itself imply it: a
 * `terminal_when` condition is asserted by a resource or event authority, not by
 * whoever may revoke, suspend, resume, or complete the Mission.
 */
export const MISSION_DISCHARGE_SCOPE = "mission_discharge";

/**
 * @spec status#mission-status-authentication — the explicit read authorization
 * the Mission Status operation requires of an authenticated caller. A caller
 * without it is refused with the not-found response. The same grant decides
 * whether a discharge forwarded after carryover is answered with the
 * replacement's Status envelope or with a Discharge Receipt
 * (@spec discharge#discharge-carryover, "Response").
 */
export const MISSION_STATUS_SCOPE = "mission_status";

/**
 * A registered service-token caller of the AS's operational surfaces: the
 * principal identity the AS records and checks discharge authority against, and
 * the scopes the token carries. This is the minimal stand-in for the profile's
 * mTLS / sender-constrained-token / private-key-JWT mechanism set; what matters
 * for conformance is that the two grants are DISTINCT and neither implies the
 * other.
 */
export interface ServiceTokenPrincipal {
  principal_id: string;
  scopes: string[];
  approver?: ApprovalPrincipal;
}

/**
 * The shipped dev token carries every grant (lifecycle, discharge, status
 * read), so every existing operational caller keeps working; a deployment (or a test proving non-implication)
 * registers additional tokens, which are merged OVER this default.
 */
export const DEFAULT_SERVICE_TOKEN_PRINCIPALS: Readonly<Record<string, ServiceTokenPrincipal>> = {
  [DEV_SERVICE_TOKEN]: {
    principal_id: "svc:console",
    scopes: [MISSION_LIFECYCLE_SCOPE, MISSION_DISCHARGE_SCOPE, MISSION_STATUS_SCOPE],
  },
};

export interface AdapterOptions {
  issuer: string;
  kernel: MissionKernel;
  /**
   * @spec discharge#discharge-authority — service-token principals and their
   * scopes, merged OVER {@link DEFAULT_SERVICE_TOKEN_PRINCIPALS}. A caller
   * holding `mission_lifecycle` alone is refused `discharge` with the
   * endpoint's `not_found` (an authorization failure never distinguishes
   * itself, @spec discharge#discharge-anti-oracle).
   */
  serviceTokenPrincipals?: Record<string, ServiceTokenPrincipal>;
  clients: Record<string, unknown>[];
  jwks: { keys: Record<string, unknown>[] };
  publicJwks: { keys: Record<string, unknown>[] };
  /** Accept a scoped approver service principal, never skip authentication. */
  allowHeadlessAdjudication?: boolean;
  approvalSessions?: ApprovalSessionStore;
  approverApprovesFor: Map<string, Set<string>>;
  knownSubjects: Set<string>;
  /**
   * @spec mission#intent-submission-evidence — the GLOBAL policy-required
   * Intent Submission Evidence types (the anti-downgrade hook): resolved
   * BEFORE derivation on every submission carrier, unioned with the
   * presenting client's registered `required_intent_evidence_types`. A
   * required type absent from a submission refuses it
   * (invalid_mission_intent_evidence); success without evidence never
   * satisfies a requirement. Empty as shipped (no evidence types exist).
   */
  requiredIntentEvidenceTypes?: string[];
  approverRoleSubs: Set<string>;
  /** Access-token lifetime (seconds) for issued mission tokens. Default 300. */
  accessTokenTTL?: number;
  /**
   * @spec mission#caller-authorization-and-minimization — the registered RFC
   * 7662 introspection principals (config-driven): each caller's authorized
   * audiences and disclosure privileges. Empty means no caller can introspect.
   */
  introspectionPrincipals?: IntrospectionPrincipal[];
  /**
   * @spec cross-org-delegation#projection-exchange — the destination Resource
   * AS configuration for accepting Cross-Organizational Delegation Chains.
   * Absent (the default) the chain subject_token_type is refused.
   */
  crossOrg?: CrossOrgOptions;
  /**
   * @spec txn-authorization#challenge-redemption — the
   * transaction_authorization_endpoint's configuration (accepted challenge
   * issuers and their published keys, the approval service, the token signing
   * key, the two independent lifetimes). When unset the endpoint replies 501.
   */
  txnAuthorization?: TxnAuthorizationOptions;
  /**
   * AROP Deferred Token Response store. When set, the deferred grant type is
   * wired onto the real /token endpoint (initiation + poll/redeem). Injected so
   * tests/exhibit can drive open/approve/deny headlessly.
   */
  deferrals?: DeferralStore;
  /**
   * @spec expansion — the DTR deferred-completion store for Mission EXPANSION.
   * When set, a widening expansion exchange (fresh approval required) completes via
   * the Deferred Token Response path (authorization_pending -> poll -> successor).
   * Distinct from `deferrals` (AROP, which never widens per D42). When unset a
   * widening exchange replies invalid_request.
   */
  expansionDeferrals?: ExpansionDeferralStore;
  /**
   * Mission Status List republisher. When set, GET /statuslist/{id} serves the
   * current whole-list token (@spec status-list#status-list).
   */
  statusListPublisher?: StatusListPublisher;
  /**
   * @spec child-delegation#child-client-identity — child-grant signing key + kid.
   * Signs the child-bound RFC 7523 JWT authorization grant the AS hands back on
   * child creation. Wired to the AS token key so the assertion verifies on the
   * jwks_uri under the token kid. When unset, the child-creation route replies
   * 501 (the child leg cannot be minted).
   */
  childGrantKey?: CryptoKey;
  childGrantKid?: string;
  childGrantAlg?: string;
  /**
   * @spec authority-server#mission-join (#557) — DEV ONLY. When set, this AS
   * serves `POST /dev/ordinary-token`, minting an ORDINARY DPoP-bound access
   * token: a `scope`, the configured audience, and NO `mission` claim. The
   * MAS Join's premise is an UNCHANGED authorization server issuing ordinary
   * tokens, and no other path in this deployment mints one, so a MAS-governed
   * route would have no credential to be presented with. This is not an OAuth
   * grant: it mints on a registered service token's authority, with no client
   * authentication, no user interaction, and no Mission. Unset (the default,
   * and any deployment that is not the demo): the route does not exist.
   */
  devOrdinaryIssuance?: { key: CryptoKey; kid: string; alg: string; audience: string };
  /**
   * @spec id-continuation-assertion — the RFC 8693 token-exchange continuation
   * grant wiring. All are composed in src/index.ts; when any is unset the grant
   * (registered unconditionally) refuses with invalid_request.
   */
  continuationStore?: ContinuationStore;
  /**
   * @spec async-delegation — the per-delegation FAMILY store (grant_id ->
   * mission_id). Recorded when the async-delegation continuation transport issues a
   * per-delegation grant; consulted by extraTokenClaims (family fallback), by
   * rotateRefreshToken (mandatory family rotation), and by ttl.RefreshToken
   * (absolute-lifetime clamp to Mission expiry). When unset every family branch is
   * a no-op, so no existing refresh/token path changes.
   */
  familyStore?: DelegationFamilyStore;
  /** Trusted Continuation Assertion Issuers of ICAs (iss + jwks + the RAS audiences each attests for). */
  continuationAssertionIssuers?: ContinuationIssuer[];
  /** Shared (iss, jti) ICA replay cache (from newReplayCache()). */
  continuationReplay?: ContinuationReplay;
  /**
   * @spec id-continuation-assertion — the finite per-chain hop-count limit (ICA
   * -02 6.3). Defaults to DEFAULT_CONTINUATION_HOP_LIMIT.
   */
  continuationHopLimit?: number;
  /** Resource -> authoritative AS map (reused from the demo cross-domain wiring). */
  resourceToAs?: (resource: string) => string;
  /** Deterministic audience-local subject resolver. */
  subjectResolver?: SubjectResolver;
  /**
   * ES256 signing key + kid for the continuation ID-JAG, published on the AS
   * jwks_uri and trusted by the RAS. issueCrossDomainGrant hardcodes an ES256
   * header, so the RS256 AS token key cannot sign it; index.ts wires the
   * dedicated ES256 as-continuation key here (D39 per-purpose).
   */
  continuationGrantKey?: CryptoKey;
  continuationGrantKid?: string;
  /** Template store backing mission-dispatch + the /templates admin routes. */
  templateStore?: TemplateStore;
  /**
   * @spec mission-template#the-mission-template — the deployment's Dispatch
   * Policies: the Agent selection rule of a template listing several Agents.
   */
  dispatchPolicies?: DispatchPolicies;
  /**
   * @spec containment#protected-events — the trusted protected-event source
   * registry, keyed by source IDENTITY (NOT the transport origin). An incoming
   * report's JWS is verified against the resolved source's key, and the source
   * must be trusted FOR the reported `event_type`. When unset, POST
   * /missions/:id/protected-events replies 501 (ingestion is not wired).
   */
  protectedEventSources?: ReadonlyMap<string, ProtectedEventSource>;
  /**
   * @spec containment#containment-plane — the issuer-side evidence store. Holds
   * the `ingestion` records (accepted AND rejected) and the retained Containment
   * Evidence. When unset, the ingestion endpoint replies 501.
   */
  issuerEvidence?: IssuerEvidenceStore;
  /**
   * @spec expansion#creation-request-id — the durable creation-idempotency
   * store (child creation + expansion + async-delegation). Lives over the KERNEL database so the
   * reservation commits atomically with Mission creation. Defaulted by
   * buildProvider when unset (instances over the same kernel share the table).
   */
  creationIdempotency?: CreationIdempotencyStore;
  /**
   * @spec RFC 9449 — the shared proof-jti replay cache for the token
   * endpoint's manually verified DPoP proofs (custom grants). Defaulted by
   * buildProvider when unset; a reused jti within the window refuses with
   * invalid_dpop_proof.
   */
  dpopProofReplay?: DpopProofReplay;
  /**
   * @spec mission#introspection (issue #541 P1-2) — the (iss, jti) -> grantId
   * issuance index, consulted by introspection's per-token individual-
   * revocation check (never `record.grant_id`, which is only the Mission's
   * OWN approval grant). Defaulted by buildProvider when unset, matching the
   * `creationIdempotency`/`dpopProofReplay` idiom: a caller that omits it
   * still gets a working (if throwaway, per-instance) index, rather than every
   * access token silently introspecting bare `active: false`.
   */
  tokenIssuanceStore?: TokenIssuanceStore;
  /**
   * @spec issuance-grant#effective-set-projection (#617 review 1) — the
   * Effective Authority Set resolution seam ({@link EffectiveAuthoritySource}).
   * Defaults to the local kernel, which IS the authoritative record here. A
   * consuming AS whose source is remote (a MAS Mission Status client) injects
   * it and raises {@link SourceUnavailableError} for the TRANSIENT class
   * (unreachable, unverifiable, rolled-back state `version`), which the token
   * endpoint refuses `temporarily_unavailable` with HTTP 503 instead of
   * `invalid_grant`, consuming neither the presented grant nor the refresh
   * token.
   */
  authoritySource?: EffectiveAuthoritySource;
  /**
   * @spec issuance-grant#effective-set-projection — the `Retry-After` value
   * (seconds) stamped on a `temporarily_unavailable` refusal: the deployment's
   * declared state-recovery policy. Defaults to 5.
   */
  stateRecoveryRetryAfter?: number;
  /**
   * @spec mission#scope-projection — the trusted, versioned scope-projection
   * mapping (step 2: authenticated out-of-band configuration). Read at every
   * Mission-bound issuance, never snapshotted, so a replaced mapping is seen
   * by the next issuance. Absent: no audience is known, so every
   * Mission-bound access token is refused (fail closed).
   */
  scopeProjection?: ScopeProjectionMapping;
  /**
   * The deployment's enabled capabilities (`adapters/capabilities.ts`).
   * Absent: every capability is on, which is the full reference provider. A
   * disabled capability refuses with its path's standard error.
   */
  capabilities?: ReadonlySet<ProviderCapability>;
}

/**
 * @spec containment#protected-events — a resolved trusted source: the public
 * key its reports are verified against, the protected-event types it is trusted
 * to report, and whether it is a LOW-TRUST advisory source (a harness-forwarded
 * egress reporter, whose records are marked advisory; the PEP/PDP remain the
 * backstop).
 */
export interface ProtectedEventSource {
  key: CryptoKey;
  eventTypes: ReadonlySet<string>;
  advisory: boolean;
}


interface KoaCtx {
  method: string;
  path: string;
  status: number;
  body: unknown;
  query: Record<string, string | string[] | undefined>;
  req: IncomingMessage;
  res: ServerResponse;
  set: (name: string, value: string) => void;
  get: (name: string) => string;
}

/**
 * @spec issuance-grant#effective-set-projection (#617 review 1) — the
 * token-endpoint refusal for the TRANSIENT authority-source class: the OAuth
 * `temporarily_unavailable` error code with HTTP status 503, which a client
 * reads as "retry this same credential" WITHOUT parsing `error_description`.
 *
 * Two oidc-provider mechanics are pinned here. Its own
 * `errors.TemporarilyUnavailable` is a 400 (the E() factory pins 400 for every
 * generated code), so the status is set explicitly; and
 * `OIDCProviderError` computes `expose = status < 500`, while
 * lib/helpers/err_out.js replaces every non-exposed error with a generic
 * `server_error` body, so `expose` is re-asserted or the 503 would render as
 * `server_error`. `Retry-After` cannot ride the error object (the error
 * handler renders a body, never headers); the middleware in buildProvider
 * stamps it.
 */
export function sourceUnavailableError(description: string): errors.OIDCProviderError {
  const err = new errors.TemporarilyUnavailable(description);
  err.status = 503;
  err.statusCode = 503;
  err.expose = true;
  return err;
}

/**
 * @spec mission#approval-authentication (#826): the provider's account
 * lookup. An unknown id is no account. An interactive login is always the
 * authenticated Approver, a configured user; a workload principal stays
 * resolvable only because the Mission-bound mint paths record a Mission's
 * Subject as the token account, and a workload Subject never obtains
 * `openid`, so it never reaches UserInfo.
 */
export function accountFinder(knownSubjects: ReadonlySet<string>) {
  return async (_ctx: unknown, id: string) => {
    const user = USERS.find((u) => u.sub === id);
    if (!user && !knownSubjects.has(id)) return undefined;
    return {
      accountId: id,
      claims: async () => ({
        sub: id,
        ...(user ? { name: user.name, email: user.email, preferred_username: user.sub } : {}),
      }),
    };
  };
}

export function buildProvider(opts: AdapterOptions): Provider {
  const { kernel } = opts;
  // @spec expansion#creation-request-id — idempotency is NOT optional wiring:
  // default the store over the kernel database (any instance over the same
  // kernel sees the same table, so a caller-supplied store is equivalent).
  opts.creationIdempotency ??= new CreationIdempotencyStore(kernel);
  // @spec RFC 9449 — proof-jti replay protection for the manual DPoP blocks.
  opts.dpopProofReplay ??= newDpopProofReplay();
  // @spec mission#introspection (issue #541 P1-2) — the issuance index is NOT
  // optional wiring either: default it so a caller that omits it still gets
  // correct (fail-closed) individual revocation, never a silent "every access
  // token introspects active:false" footgun.
  opts.tokenIssuanceStore ??= new TokenIssuanceStore();

  // Deployment capability controls (adapters/capabilities.ts). A custom grant
  // whose capability is off is never registered, so its URN answers
  // `unsupported_grant_type`. It is also removed from every client's
  // `grant_types`, since a registered client naming an unregistered grant type
  // fails as invalid_client_metadata at its first lookup.
  const enabled = (c: ProviderCapability): boolean => capabilityEnabled(opts, c);
  const grantEnabled = new Map<string, boolean>([
    [DEFERRED_GRANT_TYPE, enabled("deferred")],
    // The RFC 7523 grant redeems a child grant and a Dispatch Handoff grant.
    [CHILD_JWT_BEARER_GRANT_TYPE, enabled("child-delegation") || enabled("templates")],
    [MISSION_DISPATCH_GRANT_TYPE, enabled("templates")],
    [TOKEN_EXCHANGE_GRANT_TYPE, TOKEN_EXCHANGE_CAPABILITIES.some(enabled)],
  ]);
  const clients = opts.capabilities
    ? opts.clients.map((c) => {
        const grantTypes = (c as { grant_types?: unknown }).grant_types;
        return Array.isArray(grantTypes)
          ? { ...c, grant_types: grantTypes.filter((g) => grantEnabled.get(String(g)) !== false) }
          : c;
      })
    : opts.clients;

  // Effective Authority Set projection (#589): a stored oidc grant copies its
  // rar at issuance, so a refresh (or a late code redemption) could echo
  // capability the Mission's current effective set no longer carries
  // (containment's "derivation MUST NOT carry a contained capability", and,
  // structurally, any future narrowing mechanism the kernel composes into
  // effectiveAuthoritySet). Token-response rar resolution therefore ALWAYS
  // re-projects the grant's rar through {@link projectRarThroughMission} once
  // a Mission resolves; it is never skipped on an absent containment record
  // (that record's absence means the mechanism narrows nothing, not that the
  // projection itself is skipped). The Mission resolves from the grant like
  // the async path does: a Mission approval grant via kernel.findByGrant,
  // else a per-delegation family grant via the family store. A grant
  // belonging to no Mission has no narrowing mechanism to apply and passes
  // through UNCHANGED; a Mission with nothing currently narrowed reaches the
  // same unchanged result THROUGH the primitive (a computed no-op, not a
  // bypassed one). A non-empty rar collapsing to empty is full narrowing:
  // the credential's authority is now entirely contained (or otherwise gone),
  // and every path that carries the grant's rar (an initial code exchange
  // reached late, or any refresh) MUST fail closed rather than echo an empty
  // authorization_details with a 200 (@spec containment#derivation-gating,
  // issuance-grant#effective-set-projection).
  // @spec issuance-grant#effective-set-projection (#617 review 1) — the
  // authority source: the local kernel unless a deployment injects a remote
  // one. Resolution is NOT memoized per request: a remote source owns its own
  // cache and published staleness bound, so two resolutions in one token
  // response are that source's concern, not this adapter's.
  const authoritySource: EffectiveAuthoritySource = opts.authoritySource ?? kernel;
  const rarThroughEffectiveSet = (grant?: { jti?: string; rar?: unknown }): unknown => {
    const rar = grant?.rar;
    if (!Array.isArray(rar) || !grant?.jti) return rar;
    let record = kernel.findByGrant(grant.jti);
    if (!record) {
      const fam = opts.familyStore?.resolve(grant.jti);
      record = fam ? kernel.get(fam.missionId) : undefined;
    }
    if (!record) {
      // @spec issuance-grant#effective-set-projection (#617 review 3) — the
      // durable index, consulted as the LAST resolution step and then as the
      // discriminator. Index MISS: this grant was never Mission-bound, so its
      // rar carries no Mission narrowing and passes through (an ordinary OAuth
      // grant). Index HIT and the indexed Mission resolves: project through it
      // (this also covers a grant the Mission's own `grant_id` column has
      // moved on from, and a family row invalidated on a terminal Mission).
      // Index HIT and no Mission: the state integration this profile requires
      // cannot be performed, so it fails CLOSED. Returning the grant's
      // issuance-time rar here (the prior behavior) reissued a Mission-bound
      // credential's old authority with the Mission gone.
      const indexed = missionForBoundGrant(grant.jti);
      if (!indexed) return rar; // never Mission-bound: nothing narrows it
      record = indexed;
    }
    const { projected, collapsed } = projectMissionRar(record, rar as AuthorityEntry[]);
    if (collapsed) {
      throw new errors.InvalidGrant("mission-bound credential authority is fully contained");
    }
    return projected;
  };

  /**
   * @spec issuance-grant#effective-set-projection (#617 review 3) — resolve a
   * grant the ordinary lookups (kernel.findByGrant, then the delegation-family
   * store) could not place, through the durable Mission-bound grant index.
   *
   * Returns the indexed Mission where it resolves: the grant IS Mission-bound
   * and its Mission is live, which happens when the Mission's own `grant_id`
   * column has since moved to another grant, or when a family row was
   * invalidated on a terminal lifecycle commit. Both must be GATED and
   * PROJECTED, never passed through. THROWS `invalid_grant` where the index
   * knows the grant is Mission-bound and no Mission record resolves at all:
   * the state gate cannot be evaluated, so the profile fails closed. Returns
   * undefined only for an index MISS, the one case a token-plane hook may pass
   * through unchanged (an ordinary OAuth grant this AS never bound).
   */
  function missionForBoundGrant(grantId: string): MissionRecord | undefined {
    const bound = kernel.missionBoundGrants.resolve(grantId);
    if (!bound) return undefined;
    const record = kernel.get(bound.missionId);
    if (!record) {
      throw new errors.InvalidGrant("mission-bound grant's Mission no longer resolves");
    }
    return record;
  }

  /**
   * @spec mission#issuance-gating — the Mission a token minted under
   * `grantId` is gated against, and how, resolved ONCE for both the save-time
   * gate (`extraTokenClaims`) and the refresh pre-check (`rotateRefreshToken`):
   *
   * - `counted: true` — the Mission's own approval grant (`kernel.findByGrant`):
   *   each derivation counts against its `derivation_limit`;
   * - `counted: false` — a delegation-family grant, or a durable-index hit whose
   *   Mission's `grant_id` has moved on: live state only, never counted (a
   *   family's single count was spent at the exchange that created it,
   *   @spec async-delegation).
   *
   * Undefined for a grant that was never Mission-bound, or a family whose
   * Mission no longer resolves. An index hit with no Mission refuses
   * (`missionForBoundGrant`).
   */
  function missionGateTarget(grantId: string): { record: MissionRecord; counted: boolean } | undefined {
    const record = kernel.findByGrant(grantId);
    if (record) return { record, counted: true };
    const fam = opts.familyStore?.resolve(grantId);
    const famRecord = fam ? kernel.get(fam.missionId) : missionForBoundGrant(grantId);
    return famRecord ? { record: famRecord, counted: false } : undefined;
  }

  /**
   * @spec mission#issuance-gating — the Mission gate for `target`, throwing
   * the kernel's {@link GateError}. `issue` is the authoritative save-time gate
   * (`gateDerivation`, which counts, or `gateActive`); `precheck` runs the
   * same checks with nothing counted (`checkDerivation`, or the same
   * `gateActive`). Both map through {@link missionGateRefusal}, so the wire
   * refusal is identical.
   */
  function missionGate(target: { record: MissionRecord; counted: boolean }, mode: "issue" | "precheck"): MissionRecord {
    if (!target.counted) return kernel.gateActive(target.record.id);
    return mode === "issue" ? kernel.gateDerivation(target.record.id) : kernel.checkDerivation(target.record.id);
  }

  /** A {@link GateError} as the token endpoint's `invalid_grant` (with `mission_error` where a value applies). */
  function missionGateRefusal(e: unknown, missionId: string): unknown {
    return e instanceof GateError
      ? new MissionGrantError(e.message, gateErrorToMissionError(e.reason, kernel.get(missionId)?.state))
      : e;
  }

  /**
   * @spec mission#issuance-gating, status#legal-transitions (#914) — the
   * NON-CONSUMING refresh pre-check. oidc-provider consumes the presented
   * refresh token (lib/actions/grants/refresh_token.js 9.10.0 L137) and saves
   * the rotated one (L168) before `at.save()` (L216) runs the Mission gate, so a
   * refresh refused there has already spent the lineage: after a `resume`, the
   * client's token is reuse and revokes the grant. This runs the same gate,
   * without counting, inside `rotateRefreshToken`, before consumption.
   *
   * Non-consuming, not read-only: an expiry it discovers commits, as the gate's
   * does. And it is a PARTIAL fix: a suspension, or another derivation, landing
   * between this check and the save-time gate is still refused there, after
   * rotation, so only refusals detected HERE consume nothing. That window is
   * #250's cross-step atomic domain.
   */
  function preCheckRefreshMissionState(grantId: string | undefined): void {
    if (!grantId) return;
    const target = missionGateTarget(grantId);
    if (!target) return;
    try {
      missionGate(target, "precheck");
    } catch (e) {
      throw missionGateRefusal(e, target.record.id);
    }
  }

  /**
   * @spec mission#mission-bound-tokens — the Mission whose `expires_at` bounds
   * a credential saved under `grantId`, resolved the way issuance resolves it:
   * the Mission's own grant, then the delegation-family store, then the durable
   * bound-grant index (which refuses an index hit whose Mission is gone).
   * Undefined for a grant that was never Mission-bound.
   */
  function missionForGrant(grantId: string | undefined): MissionRecord | undefined {
    if (!grantId) return undefined;
    const record = kernel.findByGrant(grantId);
    if (record) return record;
    const fam = opts.familyStore?.resolve(grantId);
    if (fam) return kernel.get(fam.missionId);
    return missionForBoundGrant(grantId);
  }

  /**
   * @spec mission#mission-bound-tokens — "A credential the Mission Issuer
   * derives MUST have an `exp` that does not exceed the Mission's
   * `expires_at`." The lifetime of a credential saved under a Mission-bound
   * grant is the configured lifetime or the Mission's remaining whole seconds,
   * whichever is shorter. A non-Mission grant keeps `configured` unchanged.
   *
   * oidc-provider evaluates a token's lifetime BEFORE `extraTokenClaims` runs
   * the state gate (lib/models/formats/opaque.js 9.10.0 L28 before L39), and
   * saves a rotated refresh token before the access token is gated (the
   * refresh_token grant, L168 before L216). So this hook is reached for a
   * Mission at or past `expires_at`, and it never returns a 0 or negative
   * lifetime: it runs the state gate itself, which commits the expiry and
   * refuses exactly as the gate does, and a Mission with under one second left
   * is refused the same way rather than given a token that outlives it.
   *
   * `surface` selects the refusal's error vocabulary. A token-endpoint mint
   * refuses `invalid_grant` (with `mission_error`). The authorization code is
   * minted at the authorization endpoint's resume, whose response RFC 6749
   * Section 4.1.2.1 defines without `invalid_grant`, so it refuses
   * `access_denied` (@spec mission#error-mapping: an authorization decision
   * refused by AS policy).
   */
  function clampToMission(
    configured: number,
    grantId: string | undefined,
    surface: "token-endpoint" | "authorization-endpoint" = "token-endpoint",
  ): number {
    const authorization = surface === "authorization-endpoint";
    const expiring = (): Error =>
      authorization
        ? new errors.AccessDenied("the Mission expires before the authorization can complete")
        : new MissionGrantError("the Mission expires before a credential can be issued", "mission_expired");
    let record: MissionRecord | undefined;
    try {
      record = missionForGrant(grantId);
    } catch (e) {
      if (authorization && e instanceof errors.InvalidGrant) {
        throw new errors.AccessDenied("the Mission is not available");
      }
      throw e;
    }
    if (!record) return configured;
    const remaining = Math.floor((Date.parse(record.expires_at) - Date.now()) / 1000);
    if (remaining >= 1) return Math.min(configured, remaining);
    try {
      kernel.gateActive(record.id);
    } catch (e) {
      if (e instanceof GateError) {
        if (authorization) {
          throw e.reason === "mission_expired" ? expiring() : new errors.AccessDenied("the Mission is not active");
        }
        throw new MissionGrantError(e.message, gateErrorToMissionError(e.reason, kernel.get(record.id)?.state));
      }
      throw e;
    }
    throw expiring();
  }

  /**
   * @spec issuance-grant#effective-set-projection (#617 review 1) — project
   * through the source, mapping the TRANSIENT class to
   * `temporarily_unavailable` (HTTP 503) rather than letting it read as a
   * collapse. A source outage says nothing about the credential's authority.
   */
  function projectMissionRar(
    record: MissionRecord,
    rar: AuthorityEntry[],
  ): { projected: AuthorityEntry[]; collapsed: boolean } {
    try {
      return projectRarThroughMission(authoritySource, record, rar);
    } catch (e) {
      if (e instanceof SourceUnavailableError) throw sourceUnavailableError(e.message);
      throw e;
    }
  }

  /**
   * @spec issuance-grant#effective-set-projection (#617 review 1) — resolve
   * the authority source for a grant BEFORE oidc-provider consumes anything,
   * so a transient outage refuses without spending the presented credential.
   * The resolved set is deliberately discarded: this is the availability
   * resolution, and the value is re-resolved at projection time (the source
   * owns its own staleness bound). A grant that resolves to no Mission has no
   * source to consult.
   */
  const probeAuthoritySource = (grantId?: string): void => {
    if (!grantId) return;
    let record = kernel.findByGrant(grantId);
    if (!record) {
      const fam = opts.familyStore?.resolve(grantId);
      record = fam ? kernel.get(fam.missionId) : undefined;
    }
    if (!record) return;
    try {
      authoritySource.effectiveAuthoritySet(record);
    } catch (e) {
      if (e instanceof SourceUnavailableError) throw sourceUnavailableError(e.message);
      throw e;
    }
  };

  // The tokens whose `scope` the projection decided, so the JWT customizer
  // below applies exactly that decision (and refuses any Mission-bound token
  // that did not pass through it), with the `scope` value the token response
  // reports for each (OIDC values granted plus the projected ones).
  const projectedTokens = new WeakSet<object>();
  const responseScopes = new WeakMap<object, string | undefined>();

  /**
   * @spec mission#scope-projection — THE shared projection for every
   * Mission-bound access token oidc-provider mints (authorization code,
   * refresh, Token Exchange families, deferred, child jwt-bearer, dispatch,
   * expansion). Runs from extraTokenClaims BEFORE the state and derivation
   * gates, so a refusal consumes no derivation, and is evaluated against the
   * mapping current at this issuance (no version pin: a changed mapping is
   * not by itself stale). Resolves the token's audience (step 1) and the
   * mapping (step 2), applies the subset condition (step 3) over the token's
   * own carried `authorization_details`, omits `scope` for an
   * `authorization_details` target (step 4), narrows to the requested
   * values, and refuses per the core's error mapping: `invalid_target` for
   * an unknown mapping or no safe projection, `invalid_scope` for an
   * explicitly requested value the issuance cannot grant. The decided value
   * replaces whatever oidc-provider computed on `token.scope`, so the JWT
   * claim (the customizer) carries it, and the token response reports the
   * granted values (the response middleware below).
   */
  function projectMissionBoundScope(
    ctx: unknown,
    token: {
      rar?: unknown;
      scope?: string | undefined;
      resourceServer?: { audience?: unknown };
    },
  ): void {
    if (delegationHandles.has(token)) {
      // @spec mission#scope-projection step 4: a delegation handle's consumer
      // is this AS's own async-delegation exchange, which reads
      // `authorization_details`: no `scope` is emitted (#1157).
      token.scope = undefined;
      projectedTokens.add(token);
      responseScopes.set(token, undefined);
      return;
    }
    const aud = token.resourceServer?.audience;
    const audiences = typeof aud === "string" ? [aud] : Array.isArray(aud) ? (aud as string[]) : [];
    const { emitted, granted } = decideMissionScope(
      ctx,
      audiences,
      Array.isArray(token.rar) ? token.rar : [],
    );
    token.scope = emitted.length ? emitted.join(" ") : undefined;
    projectedTokens.add(token);
    responseScopes.set(token, granted.length ? granted.join(" ") : undefined);
  }

  /**
   * @spec mission#scope-projection — the scope decision itself, shared by the
   * save-time projection and the refresh pre-check so the two cannot differ:
   * the projected resource values (`emitted`) and everything granted
   * (`granted`: the OIDC values plus `emitted`), or a thrown refusal. A
   * refresh omitting `scope` inherits the refresh token's granted scope; when
   * the current mapping no longer grants some of it (a changed mode, or a
   * value no longer safe), the narrowed grant is issued only while it still
   * holds a scope value the response can report, and refused `invalid_scope`
   * when it would hold none (RFC 6749 Section 3.3: a changed grant is
   * reported, and there is no empty scope).
   */
  function decideMissionScope(
    ctx: unknown,
    audiences: readonly string[],
    entries: readonly unknown[],
  ): { emitted: string[]; granted: string[] } {
    const request = missionScopeRequest(ctx);
    if (!request.oidcGrantable && request.oidc.length) {
      throw new errors.InvalidScope(
        `requested scope value ${request.oidc[0]} cannot be granted on this grant`,
        request.oidc[0] as string,
      );
    }
    const outcome = projectScope({
      mapping: opts.scopeProjection,
      audiences,
      entries,
      ...(request.requested ? { requested: request.requested } : {}),
    });
    if (outcome.outcome === "refuse") throw scopeProjectionError(outcome);
    const emitted = outcome.outcome === "emit" ? outcome.values : [];
    const granted = [...request.oidcGranted, ...emitted];
    if (request.inherited.length && !granted.length) {
      throw scopeProjectionError({
        outcome: "refuse",
        error: "invalid_scope",
        reason: `the inherited scope ${request.inherited.join(" ")} can no longer be granted`,
      });
    }
    return { emitted, granted };
  }

  /**
   * @spec mission#scope-projection — what the current request names or
   * inherits as `scope`, split into OIDC values (their own semantics,
   * unaffected by the projection) and resource values (projected). A request
   * `scope` naming resource values is explicit; a code carries the resource
   * values its authorization request named (explicit). A refresh inherits the
   * refresh token's granted scope (RFC 6749 Section 6, not explicit) only when
   * it omits `scope`; a refresh naming only OIDC values explicitly asks for no
   * resource value. Only the code and refresh grants issue OIDC artifacts.
   */
  function missionScopeRequest(ctx: unknown): {
    requested?: RequestedScope;
    oidc: string[];
    oidcGranted: string[];
    oidcGrantable: boolean;
    /** The granted scope a refresh omitting `scope` inherits (empty otherwise). */
    inherited: string[];
  } {
    const oidc = (ctx as { oidc?: { params?: Record<string, unknown>; entities?: Record<string, unknown> } })
      .oidc;
    const params = oidc?.params ?? {};
    const entities = (oidc?.entities ?? {}) as {
      AuthorizationCode?: { scope?: string };
      RefreshToken?: { scope?: string };
      Grant?: { getOIDCScope(): string };
    };
    const grantType = params.grant_type;
    const oidcGrantable = grantType === "authorization_code" || grantType === "refresh_token";
    const explicit = splitScope(params.scope);
    let requested: RequestedScope | undefined;
    let oidcValues = explicit.oidc;
    let inherited: string[] = [];
    if (grantType === "refresh_token" && typeof params.scope === "string") {
      requested = { values: explicit.resource, explicit: true };
    } else if (explicit.resource.length) {
      requested = { values: explicit.resource, explicit: true };
    } else if (grantType === "authorization_code") {
      const code = splitScope(entities.AuthorizationCode?.scope);
      if (code.resource.length) requested = { values: code.resource, explicit: true };
      if (typeof params.scope !== "string") oidcValues = code.oidc;
    } else if (grantType === "refresh_token") {
      const rt = splitScope(entities.RefreshToken?.scope);
      requested = { values: rt.resource, explicit: false };
      oidcValues = rt.oidc;
      inherited = [...rt.oidc, ...rt.resource];
    }
    const held = new Set((entities.Grant?.getOIDCScope() ?? "").split(" ").filter(Boolean));
    return {
      ...(requested ? { requested } : {}),
      oidc: explicit.oidc,
      oidcGranted: oidcGrantable ? oidcValues.filter((v) => held.has(v)) : [],
      oidcGrantable,
      inherited,
    };
  }

  /**
   * @spec mission#scope-projection, mission#refresh-preservation — the
   * refresh pre-check. oidc-provider's refresh_token grant calls
   * `rotateRefreshToken` after client authentication, the refresh token's
   * own client, expiry, sender-constraint and reuse checks, and the grant
   * lookup, and BEFORE it consumes or rotates the token
   * (lib/actions/grants/refresh_token.js 9.10.0 L60-133 then L137). The
   * projection is decided here with the same inputs the access token's save
   * will use, so a refusal caused solely by the projection leaves the
   * refresh token and its grant valid. A failure to resolve the refreshed
   * authority itself is left to the ordinary path.
   */
  function preCheckRefreshProjection(ctx: unknown): void {
    const c = ctx as {
      oidc: {
        params: Record<string, unknown>;
        entities: { RefreshToken?: { grantId?: string; resource?: unknown }; Grant?: { jti?: string; rar?: unknown } };
      };
    };
    const rt = c.oidc.entities.RefreshToken;
    const grant = c.oidc.entities.Grant;
    if (!rt?.grantId || !grant) return;
    const bound =
      kernel.findByGrant(rt.grantId) !== undefined ||
      opts.familyStore?.resolve(rt.grantId) !== undefined ||
      kernel.missionBoundGrants.resolve(rt.grantId) !== undefined;
    if (!bound) return; // an ordinary OAuth grant: no projection applies
    let rar: unknown;
    try {
      rar = rarThroughEffectiveSet(grant);
    } catch {
      return;
    }
    const resource =
      typeof c.oidc.params.resource === "string" ? c.oidc.params.resource : rt.resource;
    if (typeof resource !== "string") return;
    decideMissionScope(ctx, [resource], Array.isArray(rar) ? rar : []);
  }

  const configuration: Configuration = {
    clients: clients as never,
    jwks: opts.jwks as never,
    // @spec mission#scope-projection — the OIDC vocabulary only (the prior
    // list less the synthetic "payments"): a resource `scope` value is the
    // scope projection's, never a provider scope.
    scopes: ["openid", "profile", "email"],
    // OIDC claims by scope, sourced from the identity store; put them in the
    // id_token itself (not only at userinfo) so the token carries the subject's
    // identity for the demo. `sub` is always present.
    claims: { profile: ["name", "preferred_username"], email: ["email"] },
    conformIdTokenClaims: false,
    issueRefreshToken: async (ctx, client, source) => {
      if (!client.grantTypeAllowed("refresh_token")) return false;
      // @spec mission#scope-projection — the refresh token records the scope
      // actually granted (the code's OIDC values plus the projected ones), so
      // a later refresh naming a subset is checked against it, and one
      // naming nothing inherits it (RFC 6749 Section 6).
      const at = (ctx.oidc.entities as { AccessToken?: object }).AccessToken;
      const s = source as { scope?: string | undefined };
      if (at && projectedTokens.has(at)) {
        const projected = splitScope((at as { scope?: string }).scope).resource;
        const kept = splitScope(s.scope).oidc;
        const recorded = [...kept, ...projected];
        s.scope = recorded.length ? recorded.join(" ") : undefined;
      }
      return true;
    },
    // @spec mission#approval-authentication (#826): a headless approval's
    // code has no End-User session to bind to (its resume session is torn
    // down, see the headless-resume middleware), so it and the tokens it
    // yields are not session-bound. Otherwise oidc-provider's default.
    expiresWithSession: async (ctx, code) =>
      (ctx.oidc.result as Record<string, unknown> | undefined)?.[HEADLESS_APPROVAL_RESULT] === true
        ? false
        : !code.scopes.has("offline_access"),
    pkce: { required: () => true },
    interactions: { url: (_ctx, interaction) => `/interaction/${interaction.uid}` },
    // @spec mission#downgrade-by-omission — the per-client Mission-governance
    // flag (a deployment MAY register a client as Mission-governed). Declared so
    // oidc-provider retains it on the client registration; read by the RAR
    // validate hook below to reject a governed client's bare
    // authorization_details request.
    extraClientMetadata: { properties: ["mission_governed", "required_intent_evidence_types"] },
    findAccount: accountFinder(opts.knownSubjects) as never,
    features: {
      // We serve our own approval interaction (the mission-kernel adapter).
      devInteractions: { enabled: false },
      pushedAuthorizationRequests: { enabled: true, requirePushedAuthorizationRequests: true },
      richAuthorizationRequests: {
        enabled: true,
        ack: "experimental-01",
        // Issuer-derived RAR (@spec mission#authorization-derivation): the
        // grant's rar IS the Mission's Authority Set; every surface projects it.
        // Token responses re-project through the effective set (containment).
        rarForAuthorizationCode: (ctx: { oidc: { grant?: { rar?: unknown } } }) =>
          ctx.oidc.grant?.rar as never,
        rarForCodeResponse: (ctx: { oidc: { grant?: { jti?: string; rar?: unknown } } }) =>
          rarThroughEffectiveSet(ctx.oidc.grant) as never,
        rarForRefreshTokenResponse: (ctx: { oidc: { grant?: { jti?: string; rar?: unknown } } }) =>
          rarThroughEffectiveSet(ctx.oidc.grant) as never,
        types: {
          mission_resource_access: {
            // @spec mission#authority-proposal — a client MAY submit entries of
            // this advertised type on the standard authorization_details
            // parameter alongside mission_intent, as a PROPOSAL subject to
            // derivation. The submission is never authority: ISSUED details stay
            // issuer-derived (the rarFor* projections above read grant.rar, the
            // Mission's derived Authority Set, never this input). An entry of an
            // unadvertised type is already refused by oidc-provider's own
            // checkRar (no `types` config entry -> invalid_authorization_details),
            // which is the D60 advertised-type rule.
            // @types/oidc-provider (9.5) has no richAuthorizationRequests
            // types; parameters typed to the runtime 9.10 contract
            // (checkRar: validate(ctx, detail, client)).
            validate: (ctx: unknown, detail: unknown, client: unknown) => {
              const oidc = (ctx as unknown as {
                oidc: { params: Record<string, unknown>; route?: string };
              }).oidc;
              // @spec mission#downgrade-by-omission — the AS-side anti-downgrade
              // hook: a client registered Mission-governed (mission_governed on
              // its registration) MUST NOT obtain ungoverned tokens by stripping
              // the Intent, so its bare authorization_details AUTHORIZATION
              // request (no mission_intent) is rejected. The spec deliberately
              // pins no error code for this rejection (mirroring the AAuth
              // missionless-request rule, #459); this implementation chooses
              // invalid_request. Scoped to the authorization-request routes:
              // this same hook also runs at the token endpoint, where
              // authorization_details is an RFC 9396 subset request under an
              // already-Mission-bound grant, not a bare request.
              const governed = (client as unknown as { mission_governed?: unknown })
                .mission_governed === true;
              const authorizationRoute =
                oidc.route === "pushed_authorization_request" ||
                oidc.route === "authorization" ||
                oidc.route === "resume";
              if (governed && authorizationRoute && oidc.params.mission_intent === undefined) {
                throw new errors.InvalidRequest(
                  "client is Mission-governed: authorization_details is accepted only as a proposal alongside mission_intent",
                );
              }
              // @spec mission#authority-proposal (the D60 intake rule, re-pointed
              // at the standard parameter): each submitted entry MUST validate
              // against the type's published JSON Schema; a failing entry is
              // refused invalid_authorization_details, never silently kept. The
              // resource-containment cross-check against the Intent's resources
              // runs in the mission_intent extraParams handler below (it needs
              // the parsed Intent).
              const schemaError = validateMissionResourceAccessSchema(detail);
              if (schemaError) {
                throw new InvalidAuthorizationDetails(schemaError);
              }
            },
          },
        },
      },
      dPoP: { enabled: true },
      revocation: { enabled: enabled("token-revocation") },
      // With OIDC off, no grant can carry `openid`; userinfo and RP-initiated
      // logout are removed too, so their routes answer 404.
      userinfo: { enabled: enabled("oidc") },
      rpInitiatedLogout: { enabled: enabled("oidc") },
      resourceIndicators: {
        enabled: true,
        defaultResource: () => opts.issuer,
        // @types/oidc-provider 9.5 types `scope` as required; the 9.10 runtime
        // treats an absent one as an empty vocabulary.
        getResourceServerInfo: (_ctx, resourceIndicator) =>
          resourceServerInfoFor(resourceIndicator, opts.accessTokenTTL ?? 300) as unknown as ResourceServer,
        useGrantedResource: () => true,
      },
    },
    extraParams: {
      // @spec mission#submission-via-par — PAR-only carriage. The parameter
      // VALUE is the Mission Intent Submission envelope {intent, evidence?}:
      // the bare-Intent shape is refused, presented evidence is typed and
      // bounded (unknown type refused, never silently ignored), and
      // intent_hash commits exactly the inner semantic `intent`. Concrete
      // authority is proposed via the standard authorization_details parameter
      // pushed alongside mission_intent (@spec mission#authority-proposal);
      // the Intent itself carries no authority members (an Intent with the
      // retired proposed_authority member fails the closed-top-level rule).
      async mission_intent(ctx, value) {
        const oidc = (ctx as {
          oidc: { params: Record<string, unknown>; client?: { clientId: string } };
        }).oidc;
        const params = oidc.params;
        // Deployment capability controls (adapters/capabilities.ts): with OIDC
        // off, an OIDC scope value is refused on every authorization request,
        // with or without a Mission Intent (oidc-provider runs each extraParams
        // validator on PAR and the authorization endpoint whether or not the
        // parameter is present).
        if (!enabled("oidc")) {
          const oidcValues = splitScope(params.scope).oidc;
          if (oidcValues.length > 0) {
            throw new errors.InvalidScope("OIDC is not enabled on this deployment", oidcValues.join(" "));
          }
        }
        if (value === undefined) return;
        try {
          const submission = kernel.validateSubmission(String(value));
          const { intent } = submission;
          // @spec mission#authority-proposal — the intake cross-check that needs
          // the parsed Intent: each proposed entry's resource MUST be among the
          // Intent's resources (invalid_request), the array strict-parses
          // (duplicate member names rejected before canonicalization), and each
          // entry is of an advertised type + schema-valid (the per-entry RAR
          // validate hook above also enforces the latter two).
          const proposalRaw = params.authorization_details;
          if (typeof proposalRaw === "string") {
            kernel.validateProposal(proposalRaw, intent.target_resources);
          }
          // @spec mission#scope-projection, mission#error-mapping — the early
          // requested-scope check (same error class as the issuance): under a
          // trusted mapping, a resource value for an `authorization_details`
          // target, or one a `scope`-only target's mapping does not name, can
          // never be granted. Values that depend on the derived authority are
          // checked at the decision; an unknown mapping at the token endpoint.
          const requested = splitScope(params.scope).resource;
          const resourceParam = params.resource;
          const audiences =
            typeof resourceParam === "string"
              ? [resourceParam]
              : Array.isArray(resourceParam)
                ? (resourceParam as string[])
                : [];
          const early = earlyScopeRefusal(opts.scopeProjection, audiences, requested);
          if (early) throw new errors.InvalidScope(early, requested.join(" "));
          // @spec mission#intent-submission-evidence — STAGE-2 verification at
          // submission time (required types resolved BEFORE derivation; the
          // presenter is the PAR-authenticated client, no cnf at this carrier).
          // The verified FACTS recorded at approval are re-derived at decide()
          // from the interaction's immutable pushed parameters (the same
          // TOCTOU rule as the proposal re-derivation).
          const clientId = oidc.client?.clientId ?? String(params.client_id ?? "");
          await kernel.verifySubmissionEvidence({
            intent,
            ...(submission.evidence ? { evidence: submission.evidence } : {}),
            presenter: { clientId },
            required: requiredEvidenceTypesFor(opts, oidc.client),
            requestContext: { carrier: "par" },
          });
        } catch (e) {
          if (e instanceof IntentError) {
            throw intentErrorToOidc(e);
          }
          throw e;
        }
      },
      // @spec child-delegation#child-creation — child-creation no longer uses PAR:
      // its request side is an RFC 8693 token exchange (subject_token = the parent's
      // Mission access token; possession via DPoP). The former PAR front-channel
      // params (`parent`, the back-channel `parent_token`, `child_actor`) are gone;
      // the exchange carries `parent` (cross-check) and `child_actor` as token
      // grant params (declared in the token-exchange param set), parsed by
      // handleChildCreationExchange. The refresh-token `parent_token` carrier is
      // removed entirely (#448: a reusable bearer refresh credential MUST NOT carry
      // possession).
    },
    // @spec mission#the-mission-claim + state-gated issuance (mission#lifecycle):
    // every mission-bound access token carries the projection; a non-active
    // mission refuses issuance with invalid_grant.
    extraTokenClaims(_ctx, token) {
      const grantId = (token as { grantId?: string }).grantId;
      if (!grantId) return {};
      // The same resolution and gate the refresh pre-check runs
      // (missionGateTarget, missionGate), here in its authoritative mode.
      const target = missionGateTarget(grantId);
      if (!target) return {};
      if (!target.counted) {
        // @spec async-delegation — per-delegation family fallback. The grant is NOT
        // a Mission approval grant (findByGrant missed), so it may be a
        // per-delegation family grant. resolve() returns undefined for an unknown OR
        // a terminal family; on a hit, re-gate ACTIVE state WITHOUT consuming a
        // derivation (gateActive, not gateDerivation) — the SINGLE family count was
        // spent once at issuance (handleAsyncDelegationExchange step 4). A terminal
        // family never reaches here in practice: its grant is destroyed on the
        // terminal lifecycle commit, so refresh fails structurally first. The
        // gateActive map (GateError -> InvalidGrant) is identical to the branch below.
        // @spec issuance-grant#effective-set-projection (#617 review 3) — the
        // durable index as the LAST resolution step, then the discriminator.
        // `{}` is an access token with NO `mission` claim: for an ordinary
        // OAuth grant that is correct (index miss), for a Mission-bound grant
        // it silently strips the binding at exactly the moment the state gate
        // could not be evaluated. So an index hit whose Mission resolves is
        // GATED here (a family row invalidated on a terminal Mission, or a
        // Mission whose own `grant_id` column has moved on), and an index hit
        // with no Mission at all refuses (missionForBoundGrant throws).
        const famRecord = target.record;
        projectMissionBoundScope(_ctx, token as Parameters<typeof projectMissionBoundScope>[1]);
        try {
          // gateActive, never gateDerivation: the SINGLE count of a family (or
          // of the Mission's original issuance) was spent once at issuance
          // (handleAsyncDelegationExchange step 4), so re-gating here checks
          // live state without recounting.
          missionGate(target, "issue");
          // @spec child-delegation#parent-member + expansion#predecessor-member —
          // the family fallback mirrors the gateDerivation dispatch below: a
          // family rooted at a Child or Successor Mission's own access token
          // (async-delegation `subject_token`) still projects that Mission's
          // lineage member on every token the family issues, initial mint and
          // refresh alike, not just the base claim (#651).
          const claim = famRecord.parent
            ? childMissionClaim(kernel, famRecord)
            : famRecord.predecessor
              ? successorMissionClaim(kernel, famRecord)
              : kernel.missionClaim(famRecord);
          return { mission: claim };
        } catch (e) {
          throw missionGateRefusal(e, famRecord.id);
        }
      }
      const record = target.record;
      projectMissionBoundScope(_ctx, token as Parameters<typeof projectMissionBoundScope>[1]);
      try {
        // @spec control-plane#serialization — THE UNCOUPLED COUNTER. This hook
        // is synchronous and runs inside oidc-provider's own token `save()`,
        // which offers no acceptance callback and no operation identity, so the
        // count cannot be reserved against the access token it pays for the way
        // the ID-JAG and AAT root paths do ({@link
        // MissionKernel.reserveDerivation}). The conditional write still
        // prevents cap overshoot; coupling the count to THIS artifact needs the
        // provider's issuance state recorded transactionally before delivery,
        // which this slice does not build.
        const gated = missionGate(target, "issue");
        // @spec child-delegation#parent-member + expansion#predecessor-member — a
        // Child Mission projects the `parent` lineage member; a successor Mission
        // projects the `predecessor` lineage member (its predecessor's mission_id),
        // so a resource server sees expansion lineage on the wire WITHOUT
        // introspecting; a root Mission (neither) projects the base claim. The two
        // lineage kinds are mutually exclusive on a record (a successor never carries
        // `parent`, a child never carries `predecessor`). gateDerivation already ran
        // the child active-state + ancestor-active gate and incremented
        // derivation_count EXACTLY ONCE (the child-redemption handler deliberately
        // does not gate, so there is no double-increment).
        const claim = gated.parent
          ? childMissionClaim(kernel, gated)
          : gated.predecessor
            ? successorMissionClaim(kernel, gated)
            : kernel.missionClaim(gated);
        return { mission: claim };
      } catch (e) {
        throw missionGateRefusal(e, record.id);
      }
    },
    // @spec async-delegation — MANDATORY family rotation. A per-delegation family
    // refresh token is rotated on EVERY refresh so a consumed-RT replay trips
    // oidc-provider's reuse detection, whose revoke is scoped to the RT's grantId —
    // it wipes ONLY this per-delegation grant, never the Mission approval grant. For
    // any other grant this defers to the oidc-provider default behaviour (inlined
    // below, because supplying this option replaces the default entirely).
    rotateRefreshToken(ctx) {
      const rt = (ctx.oidc.entities as {
        RefreshToken?: {
          grantId?: string;
          totalLifetime(): number;
          isSenderConstrained(): boolean;
          ttlPercentagePassed(): number;
        };
      }).RefreshToken;
      // @spec issuance-grant#effective-set-projection (#617 review 1) — the
      // PRE-CONSUMPTION authority-source resolution, and the ONLY seam where a
      // transient failure can refuse a refresh without spending the presented
      // credential. oidc-provider's refresh_token grant awaits this hook
      // (lib/actions/grants/refresh_token.js 9.10.0 L133-135) BEFORE
      // refreshToken.consume() (L137) and long before the rar hook (L212) and
      // at.save() -> extraTokenClaims (L216); a throw from either of those
      // lands after the presented token is already consumed and a rotated one
      // saved, which is exactly the "MUST NOT consume or rotate the presented
      // refresh token" the profile forbids. Resolving here makes the 503 land
      // at L135 instead, leaving the client's refresh token usable for a retry.
      probeAuthoritySource(rt?.grantId);
      // @spec mission#scope-projection — refusal before consumption.
      preCheckRefreshProjection(ctx);
      // @spec mission#issuance-gating (#914) — the Mission state, lineage,
      // effective-set and cap refusals, before consumption too. Partial: see
      // preCheckRefreshMissionState.
      preCheckRefreshMissionState(rt?.grantId);
      if (rt?.grantId && opts.familyStore?.resolve(rt.grantId)) return true;
      // Default: lib/helpers/defaults.js rotateRefreshToken (oidc-provider 9.10.0,
      // L528-546) — cap rotation at 1 year, rotate non-sender-constrained public
      // clients, else rotate once past 70% of lifetime.
      if (!rt) return false;
      const client = (ctx.oidc.entities as { Client?: { clientAuthMethod?: string } }).Client;
      if (rt.totalLifetime() >= 365.25 * 24 * 60 * 60) return false;
      if (client?.clientAuthMethod === "none" && !rt.isSenderConstrained()) return true;
      return rt.ttlPercentagePassed() >= 70;
    },
    // @spec mission#scope-projection — the JWT access-token claim follows the
    // projection's decision, never the `scope` oidc-provider computed from the
    // grant and the resource-server vocabulary. oidc-provider assembles the
    // payload (the `mission` claim included) before this hook and signs after
    // it. A Mission-bound token the projection did not decide is refused:
    // every Mission-bound mint passes through extraTokenClaims, so this is
    // the fail-closed backstop, not a path.
    formats: {
      customizers: {
        jwt: async (_ctx: unknown, token: unknown, jwt: { payload: Record<string, unknown> }) => {
          if (jwt.payload.mission === undefined) return;
          const t = token as { scope?: string; grantId?: string };
          if (!projectedTokens.has(t)) {
            throw new errors.InvalidTarget("Mission-bound token without a scope projection");
          }
          // @spec mission#mission-bound-tokens, mission#approval-authentication
          // (#826): a Mission-bound token's `sub` is the Mission's Subject.
          // oidc-provider writes `sub` from the grant's account, which is the
          // authenticated Approver; when the Approver approved for another
          // principal they differ. Resolved from the grant the `mission` claim
          // was gated on (no second count), failing closed when it no longer
          // resolves. ID Tokens never reach this hook.
          const target = t.grantId ? missionGateTarget(t.grantId) : undefined;
          if (!target) {
            throw new errors.InvalidGrant("Mission-bound token whose Mission no longer resolves");
          }
          jwt.payload.sub = target.record.subject.sub;
          if (t.scope) jwt.payload.scope = t.scope;
          else delete jwt.payload.scope;
          // @spec mission#rs-enforcement — the delegated-routing backstop. No
          // oidc-provider mint here carries `act` today (extraTokenClaims adds
          // only `mission`); should one ever, it reaches only audiences the
          // mapping classifies Mission-aware.
          if (jwt.payload.act !== undefined) {
            const aud = jwt.payload.aud;
            const audiences = typeof aud === "string" ? [aud] : Array.isArray(aud) ? (aud as string[]) : [];
            const refusal = delegatedRoutingRefusal(opts.scopeProjection, audiences);
            if (refusal) throw new errors.InvalidTarget(refusal);
          }
        },
      },
    } as never,
    // @spec mission#mission-bound-tokens — every credential oidc-provider
    // issues under a Mission-bound grant is clamped to the Mission's
    // `expires_at` (clampToMission). Each configured lifetime is oidc-provider's
    // own default (lib/helpers/defaults.js, 9.10.0), so a non-Mission token is
    // unchanged. A partial ttl override deep-merges with the defaults. Regular
    // functions (not arrows) satisfy checkTTL.
    ttl: {
      // The resource server's lifetime (resourceServerInfoFor), or 1 hour.
      AccessToken: function AccessTokenTTL(_ctx, token) {
        const t = token as { grantId?: string; resourceServer?: { accessTokenTTL?: number } };
        return clampToMission(t.resourceServer?.accessTokenTTL || 60 * 60, t.grantId);
      },
      // Minted at the authorization endpoint's resume: its refusal is an
      // authorization-response error, never invalid_grant.
      AuthorizationCode: function AuthorizationCodeTTL(_ctx, code) {
        return clampToMission(60, (code as { grantId?: string }).grantId, "authorization-endpoint");
      },
      // An ID Token is not saved, but it is issued under the grant: its
      // AccessToken entity carries the grant id on both the code exchange and
      // refresh.
      IdToken: function IdTokenTTL(ctx) {
        const at = (ctx as { oidc?: { entities?: { AccessToken?: { grantId?: string } } } } | undefined)?.oidc
          ?.entities?.AccessToken;
        return clampToMission(60 * 60, at?.grantId);
      },
      // @spec async-delegation — absolute-lifetime clamp. A per-delegation family
      // refresh token lives exactly until its Mission's expires_at (no
      // configured cap), through the same clamp and refusal as every other
      // credential: no 1 s floor, so under one second left it is refused.
      // Any other refresh token is oidc-provider's 14 days, clamped.
      RefreshToken: function RefreshTokenTTL(_ctx, token) {
        const grantId = (token as { grantId?: string }).grantId;
        const fam = grantId ? opts.familyStore?.resolve(grantId) : undefined;
        // Uncapped only when the family's Mission resolves, so the clamp always
        // bounds it; otherwise the ordinary 14-day value applies.
        const familyBound = fam !== undefined && kernel.get(fam.missionId) !== undefined;
        return clampToMission(familyBound ? Number.POSITIVE_INFINITY : 14 * 24 * 60 * 60, grantId);
      },
    },
  };

  const provider = new Provider(opts.issuer, configuration);

  // @spec mission#introspection (issue #541 P1-2) — record EVERY minted access
  // token's issuance binding: (iss, jti) -> the grantId it was ACTUALLY minted
  // under. A provider-level hook (not a per-callsite edit at each `new
  // provider.AccessToken(...)`) so it covers every mint path uniformly — the
  // standard authorization_code/refresh_token grant (oidc-provider mints these
  // internally, never through a call site this package controls), async-
  // delegation, deferred, child-redemption, and mission-dispatch/expansion —
  // and any future one, without per-callsite wiring. oidc-provider's base
  // token model emits `${kind}.saved` when the adapter persists a payload and
  // `${kind}.issued` when it does not (a signed-only JWT access token, this
  // deployment's ONLY access-token format, stores no adapter payload); both
  // are subscribed so a future opaque/encrypted-format change stays covered.
  const recordTokenIssuance = (at: { jti?: string; grantId?: string; rar?: unknown }) => {
    if (!at.jti || !at.grantId) return;
    opts.tokenIssuanceStore?.record({
      iss: opts.issuer,
      jti: at.jti,
      grantId: at.grantId,
      authorizationDetails: (Array.isArray(at.rar) ? at.rar : []) as AuthorityEntry[],
    });
  };
  provider.on("access_token.issued", recordTokenIssuance);
  provider.on("access_token.saved", recordTokenIssuance);

  // @spec mission#issuance-gating, mission#error-mapping — splice `mission_error`
  // onto the token endpoint's already-rendered `invalid_grant` body. `grant.error`
  // (oidc-provider's error-handler event for the /token route,
  // lib/helpers/initialize_app.js: `error(this, "grant.error")`) fires
  // synchronously right after `error_handler.js` sets `ctx.body` from the thrown
  // error and before the response is flushed, so mutating `ctx.body` here is the
  // only point at which a member `err_out.js` does not itself copy (it copies
  // only error/error_description/scope/state) can still reach the client.
  // @types/oidc-provider's `on()` overloads predate this event name (same
  // known drift as the InvalidAuthorizationDetails cast above); cast to the
  // generic EventEmitter shape rather than widen the typed overload set.
  (provider as unknown as { on(event: string, listener: (...args: unknown[]) => void): void }).on(
    "grant.error",
    (ctx: unknown, err: unknown) => {
      const body = (ctx as { body?: Record<string, unknown> }).body;
      if (err instanceof MissionGrantError && err.missionError && body?.error === "invalid_grant") {
        body.mission_error = err.missionError;
      }
    },
  );

  // @spec DTR (draft-gerber-oauth-deferred-token-response-00): the AROP deferred
  // grant on the REAL /token endpoint. Registered AFTER construction so the URN
  // is in configuration.grantTypes before any client is validated (clients are
  // validated lazily on first Client.find, i.e. at request time). `deferral_code`
  // (poll) and `deferred_authorization` (initiation) are declared so the token
  // endpoint does not strip them from ctx.oidc.params.
  if (opts.deferrals && grantEnabled.get(DEFERRED_GRANT_TYPE)) {
    const deferrals = opts.deferrals;
    provider.registerGrantType(
      DEFERRED_GRANT_TYPE,
      (ctx) => handleDeferredGrant(opts, deferrals, provider, ctx),
      // `scope` (@spec mission#scope-projection) is read on the redeeming request.
      new Set(["deferral_code", "deferred_authorization", "scope"]),
    );
  }

  // @spec child-delegation#child-client-identity — the RFC 7523 JWT-bearer
  // authorization grant a Child Mission's actor redeems AS ITSELF. Registered
  // whenever child delegation is on (the default; not behind a wiring option) so
  // the URN is in configuration.grantTypes
  // before the child client is validated (clients validate lazily at Client.find),
  // and so a child client that lists this grant type is not rejected as
  // invalid_client_metadata. `assertion` is declared in the params set or the
  // token endpoint strips it; client_assertion/_type are auth params and survive.
  // @spec mission-template#dispatch-handoff (#1158): the same grant type
  // redeems a Dispatch Handoff grant, selected by the assertion's own `typ`;
  // each branch verifies its own `typ`, so neither accepts the other's grant.
  if (grantEnabled.get(CHILD_JWT_BEARER_GRANT_TYPE)) {
    provider.registerGrantType(
      CHILD_JWT_BEARER_GRANT_TYPE,
      (ctx) => handleJwtBearerGrant(opts, provider, ctx),
      // `scope` (@spec mission#scope-projection) narrows the projected scope.
      new Set(["assertion", "scope"]),
    );
  }

  // @spec child-delegation#child-creation — Child Mission CREATION is now an RFC
  // 8693 token exchange (grant_type=token-exchange, requested_token_type=jwt),
  // handled by handleChildCreationExchange (adapters/continuation-grant.ts). The
  // legacy PAR + refresh-token `parent_token` creation grant is removed: the
  // parent is resolved FROM the subject_token (its Mission access token) and
  // possession is a DPoP proof over that token's cnf, never a reusable bearer
  // refresh credential (#448).

  // @spec mission-template#dispatch — instantiate an ordinary Mission from a
  // Mission Template at /token. Every param the handler reads MUST be
  // declared here or stripGrantIrrelevantParams removes it from
  // ctx.oidc.params (pinned empirically on the other custom grants).
  if (grantEnabled.get(MISSION_DISPATCH_GRANT_TYPE)) {
    provider.registerGrantType(
      MISSION_DISPATCH_GRANT_TYPE,
      (ctx) => handleMissionDispatchGrant(provider, opts, ctx),
      // `authorization_details` carries the dispatcher's authority proposal
      // (@spec mission#authority-proposal), the same standard carriage as PAR
      // and the child/expansion exchanges; it MUST be declared here or
      // stripGrantIrrelevantParams removes it.
      // `scope` (@spec mission#scope-projection) narrows the projected scope.
      new Set(["template_id", "mission_intent", "dispatch_event_id", "authorization_details", "scope"]),
    );
  }

  // @spec id-continuation-assertion — the RFC 8693 token-exchange grant: an ICA
  // subject token in, a Mission-rooted continuation ID-JAG out. Registered
  // whenever any token-exchange profile is on (the default; mirrors
  // CHILD_JWT_BEARER_GRANT_TYPE) so a client listing the URN is not rejected as
  // invalid_client_metadata; the handler validates the
  // wiring lazily. Every param the handler reads MUST be in this set or the token
  // endpoint strips it. PINNED empirically by the integration test: `resource` IS
  // stripped for this custom grant unless declared here (the resourceIndicators
  // machinery does NOT retain it), so it is declared. `scope` is not read by the
  // handler and so is not declared. client_assertion/_type are auth params and
  // survive independently. Each profile's branch is gated again inside
  // handleTokenExchangeGrant.
  if (grantEnabled.get(TOKEN_EXCHANGE_GRANT_TYPE)) {
    provider.registerGrantType(
      TOKEN_EXCHANGE_GRANT_TYPE,
      (ctx) => handleTokenExchangeGrant(opts, provider, ctx),
      new Set([
        "subject_token",
        "subject_token_type",
        "actor_token",
        "actor_token_type",
        "audience",
        "resource",
        "requested_token_type",
        "authorization_details",
        // @spec async-delegation — the async-delegation discriminator. Declared here
        // or the token endpoint strips it (the file documents `resource` was
        // empirically stripped for this custom grant); a test asserts its survival.
        "request_refresh_token",
        // @spec expansion / child-delegation — the possession-fixed delegation
        // exchanges read these; each MUST be declared here or stripGrantIrrelevantParams
        // removes it. `mission_intent` (widened/child intent), `child_actor`
        // (child-creation), `parent` (non-authoritative cross-check), `deferral_code`
        // (expansion deferred poll).
        "mission_intent",
        "child_actor",
        "parent",
        // @spec expansion#creation-request-id — the non-authoritative
        // `predecessor` cross-check (mirrors `parent`) and the REQUIRED
        // `creation_request_id`; each MUST be declared here or
        // stripGrantIrrelevantParams removes it.
        "predecessor",
        "creation_request_id",
        "deferral_code",
        // @spec child-delegation#carryover-commit — the carryover result
        // retrieval mode of the child-creation completion surface (no new
        // endpoint and no new metadata member).
        "carryover_replacement",
        // @spec mission#scope-projection — declared so an exchange's requested
        // `scope` is honored or refused, never stripped unseen.
        "scope",
        // @spec mission-template#dispatch-handoff: the handoff selector.
        "mission_dispatch_handoff",
      ]),
      // @spec id-continuation-assertion — the ICA continuation exchange takes
      // zero or more `resource` (ICA -02 5.5.3 rule 1), so it is the one
      // repeatable parameter of this grant. Every other exchange refuses a
      // repeated `resource` itself (handleTokenExchangeGrant), as before.
      new Set(["resource"]),
    );
  }

  // @spec issuance-grant#effective-set-projection (#617 review 1) — stamp
  // `Retry-After` on the transient refusal. oidc-provider's error handler
  // renders a body from the error object and never reads headers off it, so
  // the header is applied here: Provider#use splices each middleware BEFORE
  // the internal route dispatcher, so this wrapper observes the rendered
  // response body of every route, custom grant included. An explicit
  // Retry-After set by a handler wins.
  provider.use(async (ctx, next) => {
    await next();
    const body = ctx.body as { error?: unknown } | undefined;
    if (body?.error === "temporarily_unavailable" && !ctx.response.get("Retry-After")) {
      ctx.set("Retry-After", String(opts.stateRecoveryRetryAfter ?? 5));
    }
  });

  // @spec mission#scope-projection — the token response reports the scope
  // actually granted (RFC 6749 Section 5.1): the OIDC values granted plus the
  // projected ones, and no member when nothing was granted. Applied to every
  // Mission-bound issuance oidc-provider or a custom grant rendered, keyed on
  // the minted AccessToken the projection decided.
  provider.use(async (ctx, next) => {
    await next();
    if (ctx.oidc?.route !== "token" || ctx.status !== 200) return;
    const body = ctx.body as Record<string, unknown> | undefined;
    const at = (ctx.oidc.entities as { AccessToken?: object } | undefined)?.AccessToken;
    if (!body || typeof body.access_token !== "string" || !at || !responseScopes.has(at)) return;
    const granted = responseScopes.get(at);
    if (granted) body.scope = granted;
    else delete body.scope;
  });

  // @spec mission#grant-binding — `mission_expires_at` (and `mission_id`) on the
  // DIRECT-creation success response. Direct creation completes as the native
  // `authorization_code` token response, which oidc-provider renders internally,
  // so the members are stamped here: Provider#use splices this middleware BEFORE
  // the internal route dispatcher, so it observes the rendered token body (the
  // seam the Retry-After wrapper above already relies on) with
  // `ctx.oidc.entities.AccessToken` populated and its `grantId` bound.
  //
  // Gated on `authorization_code` deliberately. That single-use redemption IS
  // the creation-completing body, where the member is a MUST. Every custom grant
  // (dispatch, the token exchanges, DTR) rides the same route and stamps its own
  // body at its own handler, and a `refresh_token` redemption is an ordinary
  // Mission-bound token response, where the member is a SHOULD this deployment
  // does not take up. A grant with no Mission (an ordinary OAuth grant) is left
  // untouched.
  provider.use(async (ctx, next) => {
    await next();
    if (ctx.oidc?.route !== "token") return;
    if (ctx.oidc.params?.grant_type !== "authorization_code") return;
    const body = ctx.body as Record<string, unknown> | undefined;
    if (ctx.status !== 200 || !body || typeof body.access_token !== "string") return;
    const grantId = (ctx.oidc.entities?.AccessToken as { grantId?: string } | undefined)?.grantId;
    if (!grantId) return;
    const record = opts.kernel.findByGrant(grantId);
    if (!record) return;
    body.mission_id = record.id;
    // @spec mission#grant-binding — the COMMITTED record value, verbatim: the
    // effective expiry is read back from the record, never recomputed while
    // rendering, so a replayed or recovered completion returns the same string.
    body.mission_expires_at = record.expires_at;
  });

  // @spec control-plane#fanout — the request-path drain. Durable subscriber
  // deliveries are awaited HERE, once per request, after the handler returned
  // and before the response is flushed: the commit path is synchronous, so an
  // awaited drain launched from it would be the floating promise with a
  // swallowed rejection this replaces. One central seam rather than a call at
  // every terminal funnel, because a terminal transition can also be
  // materialized lazily by the expiry clock inside an ordinary gate. Provider#use
  // splices each middleware BEFORE the internal route dispatcher, so this
  // observes every route, custom grant included. A publication or delivery
  // failure leaves its own durable row pending for the next drain rather than
  // being discarded.
  provider.use(async (ctx, next) => {
    await next();
    await opts.kernel.drainLifecycleOutbox();
  });

  // @spec mission#approval-authentication (#826): a headless approval
  // leaves the client's user agent no End-User session. Its resume runs
  // without the session cookie this user agent holds, so that session is
  // neither read nor modified. Once the route returns, before the response is
  // flushed, the session the resume's login created is destroyed and its
  // cookie removed, on success or error, so the user agent never holds it.
  // The code it issued is not session-bound (expiresWithSession). The
  // headless marker is read from the stored interaction, written only by
  // `decide()`.
  //
  // The resume is recognized by the interaction it resumes, not by its path.
  // oidc-provider's resume action loads the interaction named by the resume
  // cookie and never by the path's `:uid`, and its router is neither strict
  // about a trailing slash nor case-sensitive, and serves HEAD on the GET
  // route. A client that owns the user agent controls all of these, so any
  // request whose resume cookie names a headless interaction gets this
  // treatment. The cookie is read exactly as the resume action reads it
  // (same name, the provider's default signing).
  provider.use(async (ctx, next) => {
    // `cookieName` is the provider's own resolver (configured names
    // included); oidc-provider's types omit it.
    const resumeCookie = (provider as unknown as { cookieName(type: "resume"): string }).cookieName("resume");
    const resumeId = ctx.cookies.get(resumeCookie);
    const interaction = resumeId ? await provider.Interaction.find(resumeId) : undefined;
    const result = interaction?.result as Record<string, unknown> | undefined;
    if (result?.[HEADLESS_APPROVAL_RESULT] !== true) return next();
    const sessionCookie = /^_session(?:\.sig)?$/;
    const kept = (ctx.req.headers.cookie ?? "")
      .split(";")
      .filter((c) => c.trim() && !sessionCookie.test(c.trim().split("=")[0] ?? ""));
    if (kept.length) ctx.req.headers.cookie = kept.join(";");
    else delete ctx.req.headers.cookie;
    try {
      await next();
    } finally {
      const set = ctx.response.get("set-cookie") as unknown as string[] | string | undefined;
      const lines = typeof set === "string" ? [set] : set ?? [];
      for (const line of lines) {
        const [name, value] = (line.split(";")[0] ?? "").split("=");
        if (name?.trim() === "_session" && value) await (await provider.Session.find(value.trim()))?.destroy();
      }
      const rest = lines.filter((l) => !sessionCookie.test((l.split("=")[0] ?? "").trim()));
      if (rest.length !== lines.length) {
        if (rest.length) ctx.set("set-cookie", rest);
        else ctx.remove("set-cookie");
      }
    }
  });

  provider.use(makeRoutes(provider, opts));
  return provider;
}

/**
 * @spec mission#scope-projection — what a custom-grant mint passes for
 * oidc-provider's typed `scope` member. Never emitted: save() replaces it with
 * the scope-projection decision (projectMissionBoundScope in buildProvider).
 */
export const SCOPE_DECIDED_AT_SAVE = "";

/**
 * @spec continuation#transport-async (#1157, D358): the delegation handles
 * this AS mints (the handle exchange and the Dispatch Handoff redemption): an
 * access token audienced to the acting client itself, which presents it back
 * to this AS's async-delegation exchange. That exchange consumes the handle's
 * `authorization_details`, so the scope projection omits `scope` for it (core
 * scope-projection step 4) instead of seeking a resource mapping for a client
 * audience. Only AS code marks a token; nothing a client sends can.
 */
const delegationHandles = new WeakSet<object>();

/** Mark `token` (an unsaved AccessToken) as a delegation handle; see {@link delegationHandles}. */
export function markDelegationHandle(token: object): void {
  delegationHandles.add(token);
}

/**
 * The resource-server info the AS attaches to every resource-bound JWT access
 * token: audience = the resource, JWT format, TTL. Shared by the
 * resourceIndicators config and the custom-grant mints so all project an
 * identical, resource-bound (not opaque) token.
 *
 * It declares no resource-server `scope` vocabulary: authority is the
 * token's `authorization_details`, and a Mission-bound token's `scope` is the
 * scope-projection decision alone (@spec mission#scope-projection,
 * projectMissionBoundScope in buildProvider).
 */
export function resourceServerInfoFor(resource: string, accessTokenTTL: number) {
  return {
    audience: resource,
    accessTokenFormat: "jwt" as const,
    accessTokenTTL,
  };
}

/**
 * Construct the runtime ResourceServer (oidc-provider 9.10 exposes it on the
 * provider instance; @types 9.5 declares ResourceServer as an interface only, so
 * this narrow cast bridges the gap — matrix SPEC_VERSIONS Notes).
 */
export function newResourceServer(
  provider: Provider,
  resource: string,
  info: ReturnType<typeof resourceServerInfoFor>,
): ResourceServer {
  const Ctor = (provider as unknown as {
    ResourceServer: new (identifier: string, data: unknown) => ResourceServer;
  }).ResourceServer;
  return new Ctor(resource, info);
}

/**
 * The AROP Deferred Token Response grant handler, on the real /token endpoint.
 * Runs AFTER client authentication, so `ctx.oidc.client` is set. Two branches:
 *
 *  - Initiation: `deferred_authorization` (JSON `{mission_id, requested}`) and no
 *    `deferral_code` -> open a deferral and return the DTR initiation body
 *    (HTTP 400 authorization_pending + deferral_code/expires_in/interval,
 *    Cache-Control: no-store). This is set directly on ctx because the OAuth
 *    error renderer (err_out) drops any member other than error/error_description.
 *  - Poll/redeem: `deferral_code` present -> `deferrals.redeem(code)`. Error
 *    states map to the RFC 8628-shaped OAuth errors (all HTTP 400); a
 *    DeferredToken mints a REAL resource-bound mission JWT (see mintDeferredToken).
 */
async function handleDeferredGrant(
  opts: AdapterOptions,
  deferrals: DeferralStore,
  provider: Provider,
  ctx: KoaContextWithOIDC,
): Promise<void> {
  const params = ctx.oidc.params as Record<string, unknown>;

  // --- Poll/redeem: the client presents the deferral_code. ---
  if (typeof params.deferral_code === "string" && params.deferral_code) {
    const r = deferrals.redeem(params.deferral_code);
    if ("error" in r) {
      switch (r.error) {
        case "authorization_pending":
          throw new errors.AuthorizationPending();
        case "slow_down":
          throw new errors.SlowDown();
        case "expired_token":
          throw new errors.ExpiredToken();
        case "access_denied":
          throw new errors.AccessDenied();
        default:
          throw new errors.InvalidGrant("unknown or already-redeemed deferral_code");
      }
    }
    await mintDeferredToken(opts, provider, ctx, r);
    return;
  }

  // --- Initiation: the client submits the mission subset it wants deferred. ---
  const raw = params.deferred_authorization;
  if (typeof raw === "string" && raw) {
    // @spec mission#scope-projection — no token is issued here, so a
    // requested `scope` is refused rather than dropped: it belongs on the
    // redeeming request, whose issuance it narrows.
    if (params.scope !== undefined) {
      throw new errors.InvalidRequest("scope is accepted on the deferral_code redemption that issues the token");
    }
    let intent: { mission_id?: unknown; requested?: unknown };
    try {
      intent = JSON.parse(raw) as { mission_id?: unknown; requested?: unknown };
    } catch {
      throw new errors.InvalidRequest("deferred_authorization must be a JSON object");
    }
    if (typeof intent.mission_id !== "string" || !Array.isArray(intent.requested)) {
      throw new errors.InvalidRequest("deferred_authorization requires mission_id and requested[]");
    }
    let pending;
    try {
      pending = deferrals.open({
        missionId: intent.mission_id,
        requested: intent.requested as AuthorityEntry[],
        clientId: ctx.oidc.client?.clientId as string,
      });
    } catch (e) {
      // Requested authority exceeds the active Mission (or it is not active):
      // AROP never widens -> not a deferrable request.
      if (e instanceof DeferralError) throw new errors.InvalidRequest(e.message);
      throw e;
    }
    // DTR initiation body (HTTP 400). Set on ctx directly: the OAuth error
    // renderer would strip deferral_code/expires_in/interval. Status BEFORE body
    // (Koa forces 200 if body is set first).
    ctx.status = 400;
    ctx.body = {
      error: pending.error,
      deferral_code: pending.deferral_code,
      expires_in: pending.expires_in,
      interval: pending.interval,
    };
    ctx.set("cache-control", "no-store");
    return;
  }

  throw new errors.InvalidRequest("deferral_code (poll) or deferred_authorization (initiation) required");
}

/**
 * Mint the REAL mission token on redemption. The token MUST be resource-bound
 * (JWT, aud = the resource), not opaque, or the RS rejects it: that requires a
 * ResourceServer. Setting grantId lets the existing extraTokenClaims hook attach
 * the `mission` claim (D42: the ACTIVE Mission, unchanged) and re-gate on active
 * state — the claim is never hand-set here. The credential never outlives the
 * recorded approval expiry (approved_until bounds the TTL).
 */
async function mintDeferredToken(
  opts: AdapterOptions,
  provider: Provider,
  ctx: KoaContextWithOIDC,
  deferred: DeferredToken,
): Promise<void> {
  const record = opts.kernel.get(deferred.mission.id);
  if (!record || !record.grant_id) {
    throw new errors.InvalidGrant("mission grant not found for deferral");
  }

  // DPoP-bind the minted token: derive the jkt from the request's DPoP proof
  // (the token endpoint does not pre-validate DPoP for custom grants), exactly
  // like the /transaction handler. Nonce handling is not required here.
  const proofJws = ctx.get("DPoP");
  if (!proofJws) throw new errors.InvalidRequest("DPoP proof JWT required");
  let jkt: string;
  let proofJti: unknown;
  try {
    const header = decodeProtectedHeader(proofJws);
    jkt = await calculateJwkThumbprint(header.jwk as JWK);
    const { payload: proof } = await jwtVerify(proofJws, header.jwk as JWK, { typ: "dpop+jwt" });
    if (proof.htu !== `${opts.issuer}/token` || proof.htm !== "POST") {
      throw new Error("DPoP htu/htm mismatch");
    }
    proofJti = proof.jti;
  } catch {
    throw new errors.InvalidRequest("invalid DPoP proof");
  }
  // @spec RFC 9449 — proof-jti single-use within the bounded replay window.
  if (!freshProofJti(opts, proofJti)) {
    ctx.status = 400;
    ctx.body = { error: "invalid_dpop_proof", error_description: "DPoP proof jti missing or replayed" };
    ctx.set("cache-control", "no-store");
    return;
  }

  // Containment: derive the resource fallback from the EFFECTIVE set (a fresh
  // mission has no containment, so this is the approved set as-is).
  const resource =
    deferred.authorization_details[0]?.resource ??
    opts.kernel.effectiveAuthoritySet(record)[0]?.resource ??
    opts.issuer;
  const info = resourceServerInfoFor(resource, opts.accessTokenTTL ?? 300);
  // TTL MUST NOT outlive approved_until (D42: the credential is bounded by the
  // recorded approval expiry).
  info.accessTokenTTL = Math.min(
    info.accessTokenTTL,
    Math.max(1, Math.floor((Date.parse(deferred.approved_until) - Date.now()) / 1000)),
  );

  const at = new provider.AccessToken({
    accountId: record.subject.sub,
    client: ctx.oidc.client as NonNullable<typeof ctx.oidc.client>,
    grantId: record.grant_id,
    gty: DEFERRED_GRANT_TYPE,
    rar: deferred.authorization_details,
    scope: SCOPE_DECIDED_AT_SAVE,
  });
  at.resourceServer = newResourceServer(provider, resource, info);
  at.jkt = jkt; // sender-constrain to the DPoP key (tokenType -> DPoP)
  ctx.oidc.entity("AccessToken", at);
  const jwt = await at.save();

  ctx.status = 200;
  ctx.body = {
    access_token: jwt,
    token_type: "DPoP",
    expires_in: at.expiration,
    // @spec mission#scope-projection — the projected value save() decided.
    ...(at.scope ? { scope: at.scope } : {}),
    authorization_details: deferred.authorization_details,
  };
  ctx.set("cache-control", "no-store");
}

/**
 * @spec child-delegation#child-client-identity — the RFC 7523 JWT-bearer
 * authorization-grant handler on the real /token endpoint. Client authentication
 * (private_key_jwt) runs BEFORE this handler, so `ctx.oidc.client` is the
 * AUTHENTICATED child actor. The child presents the child-bound assertion the AS
 * handed its parent on child creation (mintChildGrant) and redeems it AS ITSELF
 * for a DPoP-bound child access token. Mirrors mintDeferredToken for the DPoP
 * binding, the resource-server mint, and the mission re-gating (via
 * extraTokenClaims, which runs the child active-state + ancestor-active gate and
 * increments derivation_count exactly once — this handler deliberately does not
 * gate). The load-bearing control is step 3: the assertion's `client_id` MUST
 * equal the authenticated client, which is what makes conveying the assertion
 * through the parent safe (the parent, a different client, cannot redeem it).
 */
async function handleJwtBearerGrant(opts: AdapterOptions, provider: Provider, ctx: KoaContextWithOIDC): Promise<void> {
  const assertion = (ctx.oidc.params as Record<string, unknown>).assertion;
  let typ: unknown;
  try {
    typ = typeof assertion === "string" ? decodeProtectedHeader(assertion).typ : undefined;
  } catch {
    typ = undefined;
  }
  if (typ === DISPATCH_HANDOFF_TYP) {
    if (!capabilityEnabled(opts, "templates")) throw new errors.InvalidGrant("invalid dispatch handoff grant");
    await handleDispatchHandoffRedemption(opts, provider, ctx, assertion as string);
    return;
  }
  if (!capabilityEnabled(opts, "child-delegation")) throw new errors.InvalidGrant("invalid child-bound grant assertion");
  await handleChildJwtBearerGrant(opts, provider, ctx);
}

async function handleChildJwtBearerGrant(
  opts: AdapterOptions,
  provider: Provider,
  ctx: KoaContextWithOIDC,
): Promise<void> {
  const { kernel } = opts;

  // 1. The assertion is the child-bound grant. The client is already authenticated.
  const params = ctx.oidc.params as Record<string, unknown>;
  const assertion = params.assertion;
  if (typeof assertion !== "string" || !assertion) {
    throw new errors.InvalidRequest("assertion (the child-bound JWT authorization grant) required");
  }

  // 2. Verify the assertion. It is signed by the AS token key, so it verifies on
  //    the same public JWKS as tokens; iss = the AS, aud = the token endpoint,
  //    typ = the child-grant typ.
  let claims: Record<string, unknown>;
  try {
    const verified = await jwtVerify(assertion, createLocalJWKSet(opts.publicJwks as never), {
      issuer: opts.issuer,
      audience: `${opts.issuer}/token`,
      typ: CHILD_GRANT_TYP,
    });
    claims = verified.payload as Record<string, unknown>;
  } catch {
    throw new errors.InvalidGrant("invalid child-bound grant assertion");
  }
  const assertedClientId = claims.client_id;
  const missionRef = claims.mission as { id?: unknown; issuer?: unknown; authority_hash?: unknown } | undefined;
  const missionId = missionRef?.id;
  const assertedIssuer = missionRef?.issuer;
  const assertedHash = missionRef?.authority_hash;

  // 3. SECURITY GATE — the assertion names its only authorized redeemer in
  //    `client_id`; it MUST equal the authenticated client. This is the load-bearing
  //    control (it is what makes conveying the assertion through the parent safe).
  //    Set on ctx DIRECTLY (status before body): oidc-provider's invalid_grant
  //    renderer replaces any thrown error_description with the generic "grant
  //    request is invalid", but this gate MUST be distinguishable from the several
  //    other invalid_grant returns, so the DISTINCT error_description is emitted
  //    directly (same technique handleChildCreationExchange uses for mission_denial_reason).
  const client = ctx.oidc.client as NonNullable<typeof ctx.oidc.client>;
  if (typeof assertedClientId !== "string" || assertedClientId !== client.clientId) {
    ctx.status = 400;
    ctx.body = {
      error: "invalid_grant",
      error_description: "child grant redeemer does not match the authenticated client",
    };
    ctx.set("cache-control", "no-store");
    return;
  }

  // 4. Resolve the Child Mission; the record is authoritative. Cross-check its
  //    client_id and (#702: (issuer, id) is now the complete Mission identity)
  //    issuer against the assertion (defence in depth against a stale or
  //    tampered assertion); `authority_hash` (#702: not on the baseline
  //    `mission` claim `childMissionClaim` projects) is checked only when the
  //    assertion happens to carry it — present-then-check, never required,
  //    mirroring the AuthZEN/MAS wire-consistency pattern.
  if (typeof missionId !== "string") {
    throw new errors.InvalidGrant("child grant assertion missing mission.id");
  }
  const record = kernel.get(missionId);
  if (!record) {
    throw new errors.InvalidGrant("child mission not found");
  }
  if (
    record.client_id !== assertedClientId ||
    assertedIssuer !== record.issuer ||
    (assertedHash !== undefined && record.authority_hash !== assertedHash)
  ) {
    throw new errors.InvalidGrant("child grant assertion does not match the mission record");
  }

  // 5. DPoP-bind — mirror mintDeferredToken EXACTLY. This proof is the CHILD's own
  //    key; its thumbprint becomes the token's cnf.jkt.
  const proofJws = ctx.get("DPoP");
  if (!proofJws) throw new errors.InvalidRequest("DPoP proof JWT required");
  let jkt: string;
  let proofJti: unknown;
  try {
    const header = decodeProtectedHeader(proofJws);
    jkt = await calculateJwkThumbprint(header.jwk as JWK);
    const { payload: proof } = await jwtVerify(proofJws, header.jwk as JWK, { typ: "dpop+jwt" });
    if (proof.htu !== `${opts.issuer}/token` || proof.htm !== "POST") {
      throw new Error("DPoP htu/htm mismatch");
    }
    proofJti = proof.jti;
  } catch {
    throw new errors.InvalidRequest("invalid DPoP proof");
  }
  // @spec RFC 9449 — proof-jti single-use within the bounded replay window.
  if (!freshProofJti(opts, proofJti)) {
    ctx.status = 400;
    ctx.body = { error: "invalid_dpop_proof", error_description: "DPoP proof jti missing or replayed" };
    ctx.set("cache-control", "no-store");
    return;
  }

  // 6. Bind an oidc Grant to the child LAZILY (mirror the `decide` path). Do NOT
  //    call gateDerivation here: extraTokenClaims runs it during save() and a
  //    second call would double-increment derivation_count. Binding the grant is
  //    what makes findByGrant(grantId) resolve to the child inside that hook, so
  //    the child `mission` claim is attached (never hand-set). The Grant and the
  //    AccessToken name the SAME client (record.client_id == the authenticated
  //    client, guaranteed by steps 3-4), which oidc-provider requires.
  // Containment: every copy of the child's authority into rar/authorization_
  // details projects the EFFECTIVE set (approved minus containment overlay).
  const effective = kernel.effectiveAuthoritySet(record);
  const resource = effective[0]?.resource ?? opts.issuer;
  let grantId: string;
  if (record.grant_id) {
    grantId = record.grant_id;
  } else {
    const grant = new provider.Grant({ accountId: record.subject.sub, clientId: record.client_id });
    for (const entry of effective) {
      (grant as unknown as { addRar: (d: unknown) => void }).addRar(entry);
    }
    grantId = await grant.save();
    kernel.bindGrant(record.id, grantId);
  }

  // 7. Resource + TTL — mirror mintDeferredToken; clamp the TTL to the child's
  //    expires_at so the child token never outlives the Child Mission.
  const info = resourceServerInfoFor(resource, opts.accessTokenTTL ?? 300);
  info.accessTokenTTL = Math.min(
    info.accessTokenTTL,
    Math.max(1, Math.floor((Date.parse(record.expires_at) - Date.now()) / 1000)),
  );

  // 8. Mint — mirror mintDeferredToken. save() fires extraTokenClaims, which gates
  //    the derivation and attaches the child `mission` claim exactly once.
  const at = new provider.AccessToken({
    accountId: record.subject.sub,
    client,
    grantId,
    gty: CHILD_JWT_BEARER_GRANT_TYPE,
    rar: effective,
    scope: SCOPE_DECIDED_AT_SAVE,
  });
  at.resourceServer = newResourceServer(provider, resource, info);
  at.jkt = jkt; // sender-constrain to the child DPoP key (tokenType -> DPoP)
  ctx.oidc.entity("AccessToken", at);
  const jwt = await at.save();

  // 9. Response — mirror mintDeferredToken.
  ctx.status = 200;
  ctx.body = {
    access_token: jwt,
    token_type: "DPoP",
    expires_in: at.expiration,
    // @spec mission#scope-projection — the projected value save() decided.
    ...(at.scope ? { scope: at.scope } : {}),
    authorization_details: effective,
  };
  ctx.set("cache-control", "no-store");
}

/**
 * @spec mission#introspection (issue #541 P1-2) — liveness of the grant/family
 * that ACTUALLY minted a credential (never `record.grant_id`, the Mission's
 * own approval grant, which stays live independent of any per-delegation
 * family sharing the Mission). `wasEverFamily` disambiguates a recognized-but-
 * now-terminal family (liveness IS the family store's own terminal flag,
 * regardless of the underlying oidc-provider Grant's existence — an
 * `invalidate()` call never touches the Grant store) from an ordinary
 * approval-grant id (liveness is the oidc-provider Grant's own existence).
 */
async function isGrantLive(opts: AdapterOptions, provider: Provider, grantId: string): Promise<boolean> {
  if (opts.familyStore?.wasEverFamily(grantId)) {
    return opts.familyStore.resolve(grantId) !== undefined;
  }
  return !!(await provider.Grant.find(grantId).catch(() => undefined));
}

/**
 * @spec mission#caller-authorization-and-minimization (cleanup, issue #541) —
 * map each disclosed audience to the RESOURCE identifiers it authorizes
 * disclosure for, via the principal's registered `audience_resources`
 * (config/introspection.json). An OAuth `aud`/resource-indicator value is NOT
 * required to be byte-equal to an Authority Set entry's `resource` (the core
 * explicitly allows a deployment's own audience-to-resource mapping); an
 * audience absent from the map defaults to IDENTITY (itself).
 */
export function resourcesForAudiences(
  audiences: readonly string[],
  mapping: Record<string, string[]> | undefined,
): Set<string> {
  const out = new Set<string>();
  for (const aud of audiences) {
    const mapped = mapping?.[aud];
    if (mapped?.length) {
      for (const r of mapped) out.add(r);
    } else {
      out.add(aud);
    }
  }
  return out;
}

/** The capability that enables each lifecycle-endpoint operation. */
const LIFECYCLE_OPERATION_CAPABILITY: Readonly<Record<string, ProviderCapability>> = {
  revoke: "lifecycle-revoke",
  suspend: "lifecycle-extended",
  resume: "lifecycle-extended",
  complete: "lifecycle-extended",
  contain: "containment",
  discharge: "discharge",
};

function makeRoutes(provider: Provider, opts: AdapterOptions) {
  const { kernel } = opts;
  const enabled = (c: ProviderCapability): boolean => capabilityEnabled(opts, c);
  const jwksResolver = createLocalJWKSet(opts.publicJwks as never);
  // @spec txn-authorization#two-phase-expiry — the admitted pending workflows.
  const txnWorkflows = newTxnWorkflows();

  /**
   * @spec RFC 6749 Appendix B — decode HTTP Basic client credentials: the
   * scheme token is case-insensitive ("Basic"/"basic"/"BASIC" all valid), the
   * credentials are base64, split on the FIRST colon (a secret MAY itself
   * contain one), and each half is percent-DECODED per the Appendix B
   * application/x-www-form-urlencoded profile (`%20` for space; `+` is never
   * special here, unlike a query-string decoder). A malformed percent-
   * sequence fails closed (undefined), never throws.
   */
  const parseBasicAuth = (raw: string): { id: string; secret: string } | undefined => {
    const m = /^Basic\s+(.+)$/i.exec(raw);
    if (!m) return undefined;
    const decoded = Buffer.from(m[1] as string, "base64").toString("utf8");
    const sep = decoded.indexOf(":");
    const rawId = sep >= 0 ? decoded.slice(0, sep) : decoded;
    const rawSecret = sep >= 0 ? decoded.slice(sep + 1) : "";
    try {
      return { id: decodeURIComponent(rawId), secret: decodeURIComponent(rawSecret) };
    } catch {
      return undefined;
    }
  };

  /**
   * @spec mission#caller-authorization-and-minimization — authenticate the RFC
   * 7662 caller as a REGISTERED introspection principal (HTTP Basic against
   * the config-registered secret, compared timing-safely, via {@link
   * parseBasicAuth}). The principal's authorized audiences and disclosure
   * privileges come from that server-side registration, never from a
   * caller-supplied value. On failure the 401 is written and no token
   * processing occurs.
   */
  const authenticateIntrospection = (ctx: KoaCtx): IntrospectionPrincipal | undefined => {
    const creds = parseBasicAuth(ctx.get("authorization") ?? "");
    if (creds) {
      const principal = (opts.introspectionPrincipals ?? []).find(
        (p) => p.principal_id === creds.id,
      );
      if (principal) {
        const a = Buffer.from(creds.secret);
        const b = Buffer.from(principal.secret);
        if (a.length === b.length && timingSafeEqual(a, b)) return principal;
      }
    }
    ctx.status = 401;
    ctx.set("WWW-Authenticate", 'Basic realm="introspection"');
    ctx.body = { error: "invalid_client" };
    return undefined;
  };

  // Null-prototype registry + own-property lookup below: a presented token
  // must NEVER authenticate through an inherited Object.prototype name
  // (`__proto__`, `constructor`, `toString`, ...), which a plain object
  // lookup would resolve for an unregistered token.
  const serviceTokenPrincipals: Record<string, ServiceTokenPrincipal> = Object.assign(
    Object.create(null) as Record<string, ServiceTokenPrincipal>,
    DEFAULT_SERVICE_TOKEN_PRINCIPALS,
    opts.serviceTokenPrincipals ?? {},
  );

  /**
   * @spec status#mission-status-authentication, discharge#discharge-authority —
   * AUTHENTICATE the operational caller and resolve the principal its token is
   * registered for, with the scopes that token carries. AUTHENTICATION failure
   * (an absent or unregistered token) is the endpoint's only `unauthorized`
   * (401); every AUTHORIZATION failure is the caller's to discover as
   * `not_found`, decided per operation against these scopes.
   */
  const authenticateService = (ctx: KoaCtx): ServiceTokenPrincipal | undefined => {
    const presented = ctx.get("x-service-token");
    const principal =
      presented && Object.hasOwn(serviceTokenPrincipals, presented)
        ? serviceTokenPrincipals[presented]
        : undefined;
    if (!principal) {
      ctx.status = 401;
      ctx.body = { error: "unauthorized" };
      return undefined;
    }
    return principal;
  };

  const requireServiceToken = (ctx: KoaCtx): boolean => authenticateService(ctx) !== undefined;

  /**
   * @spec status#mission-status-authentication — the Mission Status operation's
   * authorization check, in ONE place: the deployment serves the operation and
   * the authenticated caller carries the `mission_status` grant. The Status
   * route and the forwarded-discharge response choice both call this, so they
   * can never disagree about who may inspect a Mission.
   */
  const mayReadStatus = (principal: ServiceTokenPrincipal): boolean =>
    enabled("status") && principal.scopes.includes(MISSION_STATUS_SCOPE);

  /**
   * @spec discharge#condition-selectors — add `discharge_selectors` to an ACTIVE
   * introspection `mission` projection, for exactly the `authorization_details`
   * this response returns to this caller, and only where this deployment
   * exposes the `discharge` operation. Absent when there is nothing to
   * disclose, so a projection without a completing entry is unchanged. The
   * issuer-only rule and the record-target mapping live in the kernel
   * ({@link MissionKernel.dischargeSelectorsFor}).
   */
  const withDischargeSelectors = (
    record: MissionRecord,
    mission: Record<string, unknown>,
    returned: ReadonlyArray<OriginProjection<AuthorityEntry>>,
  ): Record<string, unknown> => {
    if (!enabled("discharge")) return mission;
    const selectors = kernel.dischargeSelectorsFor(record, returned);
    return selectors.length > 0 ? { ...mission, discharge_selectors: selectors } : mission;
  };

  /**
   * @spec discharge#discharge-idempotency — the lifecycle endpoint's `nonce`
   * replay store, constructed once per provider on the kernel's own database.
   */
  const lifecycleResponses = new LifecycleResponseStore(kernel.db, {
    now: () => kernel.nowDate(),
  });

  return async (ctx: KoaCtx, next: () => Promise<void>) => {
    // --- Approval interaction (minimal approver surface + headless path) ---
    const interactionMatch = ctx.path.match(/^\/interaction\/([^/]+)$/);
    if (interactionMatch && ctx.method === "GET") {
      const details = await provider.interactionDetails(ctx.req, ctx.res);
      const params = details.params as Record<string, unknown>;
      // @spec mission#submission-via-par — the pushed parameter is the
      // Submission envelope; the approval renders the SEMANTIC intent (the
      // object intent_hash commits), never the envelope.
      const submission = kernel.validateSubmission(String(params.mission_intent));
      const intent = submission.intent;
      // @spec mission#authority-proposal — the proposal rides the pushed
      // authorization_details parameter; the rendering distinguishes the
      // submitted proposal (untrusted) from the derived Authority Set (what
      // approval grants).
      const proposalRaw = clientProposalParam(params);
      const proposal =
        proposalRaw !== undefined
          ? kernel.validateProposal(proposalRaw, intent.target_resources)
          : undefined;
      // @spec mission#error-mapping — a well-formed Intent this AS's policy
      // (or the client's own proposal) derives no Authority Set from is a
      // refusal at render time too, not only at decide(): surface it the same
      // way (400, the mapped error code) rather than let it propagate uncaught.
      let authority: ReturnType<typeof kernel.derive>;
      try {
        authority = kernel.derive(intent, proposal);
      } catch (e) {
        if (e instanceof IntentError) {
          ctx.status = 400;
          ctx.body = { error: e.code, error_description: e.message };
          return;
        }
        throw e;
      }
      // @spec mission#intent-submission-evidence — MATERIAL verified
      // provenance is INPUT to the approval rendering: the Approver sees the
      // normalized verified facts (never the raw artifacts), re-verified from
      // the interaction's immutable pushed parameters. Evidence whose validity
      // LAPSED since the push (freshness/status) refuses here, before render.
      let provenance: Awaited<ReturnType<typeof kernel.verifySubmissionEvidence>>;
      try {
        provenance = await kernel.verifySubmissionEvidence({
          intent,
          ...(submission.evidence ? { evidence: submission.evidence } : {}),
          presenter: { clientId: String(params.client_id ?? "") },
          required: requiredEvidenceTypesFor(
            opts,
            opts.clients.find((c) => c.client_id === params.client_id),
          ),
          requestContext: { carrier: "par" },
        });
      } catch (e) {
        if (e instanceof IntentError) {
          ctx.status = 400;
          ctx.body = { error: e.code, error_description: e.message };
          return;
        }
        throw e;
      }
      // @spec mission#approval-event (step 5) — the rendering MUST identify the
      // authority source and, for `organizational`, the governed policy it
      // draws on. Resolved from the deployment's trusted catalog at render
      // time; a catalog change before the decision re-enters `kernel.approve`
      // with the changed inputs, which re-establishes the source and refuses
      // rather than committing what was never rendered. The Subject the
      // decision binds is the one the approval session for this interaction
      // selected (#827, #826; `login_hint` concerns the Approver), so the
      // rendering resolves for it; without a session it shows only a
      // provenance every source of this client shares.
      const selectedSubject = opts.approvalSessions?.subjectFor(ctx.get("cookie"), interactionMatch[1] as string);
      let authoritySource: AuthoritySource;
      try {
        authoritySource = kernel.renderAuthoritySource({
          clientId: String(params.client_id),
          ...(selectedSubject ? { subject: { iss: opts.issuer, sub: selectedSubject } } : {}),
        });
      } catch (e) {
        if (e instanceof IntentError) {
          ctx.status = 400;
          ctx.body = { error: e.code, error_description: e.message };
          return;
        }
        throw e;
      }
      ctx.status = 200;
      ctx.set("content-type", "text/html; charset=utf-8");
      ctx.body = renderApprovalPage(
        interactionMatch[1] as string,
        intent,
        authority,
        proposal,
        provenance,
        authoritySource,
      );
      return;
    }
    const decideMatch = ctx.path.match(/^\/interaction\/([^/]+)\/decide$/);
    if (decideMatch && ctx.method === "POST") {
      const body = await readJsonBody(ctx.req);
      if (["approver", "subject", "approver_acr", "approver_auth_time"].some(k => Object.hasOwn(body, k)) ||
          (body.decision !== "approve" && body.decision !== "deny")) {
        ctx.status = 400;
        ctx.body = { error: "invalid_request", error_description: "decide accepts a decision, not resolving identity" };
        return;
      }
      const uid = decideMatch[1]!;
      const origin = ctx.get("origin");
      const browser = (!origin || origin === new URL(opts.issuer).origin)
        ? opts.approvalSessions?.resolve(ctx.get("cookie"), ctx.get("x-csrf-token"), uid)
        : undefined;
      const token = ctx.get("x-service-token");
      const service = token && Object.hasOwn(serviceTokenPrincipals, token) ? serviceTokenPrincipals[token] : undefined;
      // @spec mission#approval-event (step 2) (#826): a trusted headless
      // approval service names the Subject it resolved on its own
      // authenticated request; a browser session carries the selection its
      // trusted login recorded. Neither comes from the client.
      const headless = !browser && opts.allowHeadlessAdjudication && service?.scopes.includes(MISSION_APPROVAL_SCOPE) &&
        validApprovalPrincipal(service.approver) ? service.approver : undefined;
      const selected = ctx.get(APPROVAL_SUBJECT_HEADER);
      const principal = browser ?? (headless ? { ...headless, ...(selected ? { subject: selected } : {}) } : undefined);
      if (!principal || principal.auth_time > Math.floor(opts.kernel.nowDate().getTime() / 1000)) {
        ctx.status = 401;
        ctx.body = { error: "unauthorized" };
        return;
      }
      await decide(provider, opts, ctx, body, principal, browser !== undefined);
      return;
    }

    // --- Signed Status (@spec status#mission-status-response) ---
    // A deployment with Mission Status off serves no such route (404).
    const statusMatch = ctx.path.match(/^\/missions\/([^/]+)\/status$/);
    if (statusMatch && ctx.method === "GET" && enabled("status")) {
      const principal = authenticateService(ctx);
      if (!principal) return;
      const statusNonce = str(ctx.query.nonce);
      try {
        // A caller without the read grant gets the same not-found body as an
        // unknown reference (@spec status#mission-status-anti-oracle).
        if (!mayReadStatus(principal)) throw new Error("status read not authorized");
        const jws = await kernel.signedStatus(statusMatch[1] as string, {
          ...optional("audience", str(ctx.query.audience)),
          ...optional("nonce", statusNonce),
          requester: principal.principal_id,
        });
        ctx.status = 200;
        ctx.set("content-type", MISSION_STATUS_RESPONSE_MEDIA_TYPE);
        ctx.set("cache-control", "no-store");
        ctx.body = jws;
      } catch {
        // @spec status#mission-status-errors, status#mission-status-anti-oracle
        // — one not-found shape for the unknown and the invisible reference,
        // echoing the request's `nonce` when it carried one.
        ctx.status = 404;
        ctx.set("cache-control", "no-store");
        ctx.body = {
          error: "not_found",
          error_description: "Mission reference is not found or not visible.",
          ...(statusNonce ? { nonce: statusNonce } : {}),
        };
      }
      return;
    }

    // --- Mission Status List whole-list fetch (@spec status-list#status-list) ---
    // Deliberately unauthenticated (NOT behind requireServiceToken): the fetch
    // covers every opaque index at once and reveals no per-mission interest, so
    // it is anti-oracle-safe by design (@spec status#mission-status-anti-oracle).
    // The per-mission status_list.uri and the token's `sub` both equal this URL.
    const statusListMatch = ctx.path.match(/^\/statuslist\/([^/]+)$/);
    if (statusListMatch && ctx.method === "GET") {
      if (statusListMatch[1] !== STATUS_LIST_ID || !opts.statusListPublisher || !enabled("status-list")) {
        ctx.status = 404;
        ctx.body = { error: "not_found" };
        return;
      }
      ctx.status = 200;
      ctx.set("content-type", STATUS_LIST_MEDIA_TYPE);
      ctx.body = await opts.statusListPublisher.current();
      return;
    }

    // --- Authorization Details Types Metadata (@spec mission#other-types,
    // I-D.draft-zehavi-oauth-rar-metadata) ---
    // Public discovery, like the endpoints above: no consent or per-mission
    // state is disclosed, only the AS's published authorization_details type
    // registry (schema/version/description/examples per type).
    if (ctx.path === "/authorization-details-types" && ctx.method === "GET") {
      ctx.status = 200;
      ctx.set("content-type", "application/json");
      ctx.body = authorizationDetailsTypesMetadata();
      return;
    }

    // --- Lifecycle operations (@spec status#legal-transitions) ---
    const lifecycleMatch = ctx.path.match(/^\/missions\/([^/]+)\/lifecycle$/);
    if (lifecycleMatch && ctx.method === "POST") {
      const principal = authenticateService(ctx);
      if (!principal) return;
      const missionId = lifecycleMatch[1] as string;
      // Read the body ONCE and keep the digest of the exact bytes: the `nonce`
      // rule of @spec status#idempotency is byte-identity of the request.
      const { body, digest } = await readBodyWithDigest(ctx.req);
      const rawNonce = body.nonce;
      const nonce =
        typeof rawNonce === "string" && rawNonce.length > 0 && rawNonce.length <= 255
          ? rawNonce
          : undefined;
      const nonceKey: LifecycleNonceKey | undefined = nonce
        ? {
            endpoint: LIFECYCLE_ENDPOINT_KEY,
            principal: principal.principal_id,
            missionId,
            nonce,
          }
        : undefined;
      /**
       * @spec status#mission-status-errors — send and, when the request carried
       * a well-formed `nonce`, REMEMBER this response for that nonce. The store
       * is first-writer-wins, so a later divergent-retry refusal never
       * overwrites the response a retransmission must replay.
       */
      const send = (status: number, contentType: string, text: string): void => {
        // @spec control-plane#serialization — RETENTION PRECEDES DELIVERY: the
        // exact bytes are durable before they are handed to the network, so a
        // crash between the two replays the same response instead of
        // re-executing the operation.
        if (nonceKey) {
          lifecycleResponses.record(nonceKey, { requestDigest: digest, status, contentType, body: text });
        }
        ctx.status = status;
        ctx.set("content-type", contentType);
        ctx.set("cache-control", "no-store");
        ctx.body = text;
      };
      const sendJson = (status: number, json: Record<string, unknown>): void =>
        send(status, "application/json", JSON.stringify(json));
      /**
       * @spec status#mission-status-errors, discharge#discharge-anti-oracle — the
       * ONE not-found shape every unknown, invisible, and unauthorized reference
       * collapses to. `error_description` is diagnostic and identical across the
       * cases; `nonce` is echoed whenever the request carried a well-formed one.
       */
      const sendNotFound = (): void =>
        sendJson(404, {
          error: "not_found",
          error_description: "Mission reference is not found or not visible.",
          ...(nonce ? { nonce } : {}),
        });
      const sendInvalidRequest = (description: string, echoNonce = true): void =>
        sendJson(400, {
          error: "invalid_request",
          error_description: description,
          // A request whose `nonce` is absent or malformed echoes none.
          ...(echoNonce && nonce ? { nonce } : {}),
        });
      /**
       * @spec status#idempotency — the DIVERGENT-RETRY refusal: delivered, and
       * RETAINED NOWHERE (issue #250, owner review). This refusal exists
       * precisely because a row claimed under a DIFFERENT request digest
       * already holds this nonce, so the refusal is not that nonce's response
       * and must never be written where the retained one belongs. Every other
       * refusal goes through `send` and is retained first-writer-wins.
       */
      const sendDivergentRetry = (): void => {
        ctx.status = 400;
        ctx.set("content-type", "application/json");
        ctx.set("cache-control", "no-store");
        ctx.body = JSON.stringify({
          error: "invalid_request",
          error_description: "nonce was already used with a different request",
          ...(nonce ? { nonce } : {}),
        });
      };
      // @spec status#idempotency, control-plane#serialization — the
      // retransmission rule, evaluated FIRST and BEFORE ANY STATE-DEPENDENT
      // CHECK: it governs the HTTP exchange, so a request that already
      // succeeded replays its success even after the Mission moved on. A
      // conditional precondition this endpoint may grow (`expected_version`)
      // belongs strictly AFTER this lookup, never in front of it.
      if (nonceKey) {
        const stored = lifecycleResponses.find(nonceKey);
        // ONE clock, the nonce window: both halves of the rule run on it. A
        // divergent retry is refused for the whole window, and a byte-identical
        // retransmit replays the original response for the whole window, which
        // the profile requires and the window is sized to cover.
        if (stored?.requestDigest !== undefined && stored.requestDigest !== digest) {
          // Never answered with the unrelated original response, and never
          // retained in its place.
          sendDivergentRetry();
          return;
        }
        if (stored) {
          // @spec status#idempotency — a FINAL row replays its exact retained
          // bytes: the profile says the ORIGINAL response, and re-signing an
          // ECDSA envelope would produce different bytes every time.
          //
          // @spec control-plane#serialization — RECOVERY ACROSS THE SIGNING
          // BOUNDARY, the crash case only. A `committed` row is an operation
          // that committed and a response whose bytes were never retained. It
          // is finalized from the retained immutable material, never
          // re-executed: for a signed envelope the recorded observation is
          // signed again, carrying its ORIGINAL `iat` and `exp`, so recovery
          // reports the state at the observation point and re-dates nothing.
          const recovered =
            stored.state === "final"
              ? stored.body
              : await finalizeRetainedResponse(kernel, stored);
          if (recovered === undefined) {
            sendNotFound();
            return;
          }
          if (stored.state !== "final") {
            lifecycleResponses.record(nonceKey, {
              requestDigest: digest,
              status: stored.status,
              contentType: stored.contentType,
              body: recovered,
            });
          }
          ctx.status = stored.status;
          ctx.set("content-type", stored.contentType);
          ctx.set("cache-control", "no-store");
          ctx.body = recovered;
          return;
        }
      }
      // Deployment capability controls (adapters/capabilities.ts): an operation
      // this deployment disabled is refused `invalid_request` before any Mission
      // is looked up, so the refusal names the deployment, never the Mission.
      const operationCapability = LIFECYCLE_OPERATION_CAPABILITY[String(body.operation)];
      if (operationCapability && !enabled(operationCapability)) {
        sendInvalidRequest(`operation ${String(body.operation)} is not enabled on this deployment`);
        return;
      }
      // @spec discharge#discharge-operation, discharge#discharge-commit ("States")
      // — the fifth operation: it changes no
      // Mission state, so it is handled entirely outside the state machine
      // below, under its own DISTINCT authority.
      if (body.operation === "discharge") {
        await handleDischarge({
          kernel,
          principal,
          missionId,
          body,
          ...(nonce !== undefined ? { nonce } : {}),
          mayReadStatus,
          // @spec control-plane#serialization — the discharge latch, the nonce
          // claim and the OBSERVATION (or receipt) the response reports commit
          // together; only the signature happens after.
          claimResponse: (material, contentType, validUntilMs) => {
            if (!nonceKey) return;
            lifecycleResponses.claimInCallerTx(nonceKey, {
              requestDigest: digest,
              status: 200,
              contentType,
              material,
              responseValidUntil: validUntilMs,
            });
          },
          sendSigned: (contentType, jws) => send(200, contentType, jws),
          sendJson,
          sendNotFound,
          sendInvalidRequest,
        });
        return;
      }
      // @spec status#mission-status-errors — every other operation is a
      // Mission-state transition and requires the lifecycle grant; an
      // authenticated caller without it is refused with the endpoint's
      // not-found shape (the profile's Authorization section), never a 403.
      if (!principal.scopes.includes(MISSION_LIFECYCLE_SCOPE)) {
        sendNotFound();
        return;
      }
      try {
        // Mission Containment: a metadata-only commit (state unchanged, version
        // incremented) carrying `{ event, remove }`. Mirrors the other
        // operations' response shape plus containment_version; a terminal-state
        // contain maps to 409 through the shared LifecycleConflictError catch.
        if (body.operation === "contain") {
          const event = body.event as
            | { type?: unknown; source?: unknown; observed_at?: unknown; event_id?: unknown }
            | undefined;
          const remove = body.remove;
          if (
            !event ||
            typeof event.type !== "string" ||
            typeof event.source !== "string" ||
            typeof event.observed_at !== "string" ||
            typeof event.event_id !== "string" ||
            !Array.isArray(remove) ||
            remove.length === 0
          ) {
            sendInvalidRequest(
              "contain requires event {type, source, observed_at, event_id} and a non-empty remove[]",
            );
            return;
          }
          // @spec control-plane#serialization — the containment commit, the
          // nonce claim and the committed outcome are ONE transaction, so a
          // committed narrowing always leaves a replayable record behind.
          // The narrowed members are captured before the closure: a closure
          // does not carry the control-flow narrowing the checks above proved.
          const containEvent = {
            type: event.type,
            source: event.source,
            observed_at: event.observed_at,
            event_id: event.event_id,
          };
          // @spec control-plane#serialization — the expiry clock OUTSIDE the
          // operation's transaction, for the same reason the derivation gate
          // keeps it outside the counter's: `contain` is refused from a
          // terminal state, and a refusal must never roll back the `expired`
          // transition that discovering it committed.
          kernel.materializeExpiry(missionId);
          const contained = withTransaction(kernel.db, () => {
            const { record, evidence } = kernel.contain(missionId, {
              event: containEvent,
              remove: remove as Array<{ resource: string; actions?: string[] }>,
            });
            const outcome = {
              id: record.id,
              state: record.state,
              version: record.version,
              containment_version: record.containment?.containment_version ?? 0,
            };
            if (nonceKey) {
              lifecycleResponses.claimInCallerTx(nonceKey, {
                requestDigest: digest,
                status: 200,
                contentType: "application/json",
                material: { kind: "json", body: outcome },
              });
            }
            return { evidence, outcome };
          });
          // Retain the returned Containment Evidence issuer-side (break-glass
          // path: its evidence `policy` is "manual"). Previously discarded.
          opts.issuerEvidence?.retainContainment(contained.evidence);
          sendJson(200, contained.outcome);
          return;
        }
        // @spec control-plane#serialization — the expiry clock runs FIRST, in
        // its own transaction, and stays OUT of the transition's. The clock
        // MATERIALIZES a narrowing transition; the operation then requested may
        // be illegal from the state that commit left, and rolling the refusal
        // back would leave an expired Mission `active`, without the expiry
        // transition and without its publication. The counter path already
        // keeps the gate outside its transaction for exactly this reason.
        kernel.materializeExpiry(missionId);
        // @spec control-plane#serialization — the transition, the nonce claim
        // and the committed outcome are ONE transaction. Before this, a process
        // lost between the commit and the response answered a retry 409 for an
        // operation that had in fact succeeded. The grant destruction stays
        // OUTSIDE: it is asynchronous and reaches the provider's own store, so
        // it can neither join nor roll back with this commit.
        const transitioned = withTransaction(kernel.db, () => {
          const record = kernel.transition(missionId, body.operation as LifecycleOperation);
          const outcome = { id: record.id, state: record.state, version: record.version };
          if (nonceKey) {
            lifecycleResponses.claimInCallerTx(nonceKey, {
              requestDigest: digest,
              status: 200,
              contentType: "application/json",
              material: { kind: "json", body: outcome },
            });
          }
          return { record, outcome };
        });
        const record = transitioned.record;
        // Revocation/terminal states also revoke the OAuth grant so refresh
        // fails structurally, not just by gating.
        if (record.state !== "active" && record.state !== "suspended" && record.grant_id) {
          const grant = await provider.Grant.find(record.grant_id);
          await grant?.destroy();
        }
        sendJson(200, transitioned.outcome);
      } catch (e) {
        if (e instanceof LifecycleConflictError) {
          sendJson(409, {
            error: "conflict",
            error_description: e.message,
            ...(nonce ? { nonce } : {}),
          });
        } else {
          // @spec status#mission-status-errors — the endpoint's vocabulary is
          // `not_found` (the same body an unauthorized reference gets), never a
          // distinguishing symbol of its own.
          sendNotFound();
        }
      }
      return;
    }

    // --- Protected-event ingestion (@spec containment#protected-events) ---
    // A trusted source reports a protected event as a COMPACT JWS
    // (application/protected-event+jwt by local agreement). The source is
    // authenticated by its SIGNATURE, resolved for the payload `source` IDENTITY
    // (NOT the transport origin) from the config-seeded trusted-source registry,
    // and must be trusted FOR the reported `type`. Containment then applies
    // DETERMINISTICALLY through the issuer-held policy (kernel.containOnEvent):
    // the caller supplies only the event, never what narrows. This is
    // deliberately NOT behind requireServiceToken: the JWS is the authenticator,
    // and "unknown/untrusted source -> 403 + recorded rejection" must be
    // reachable (a transport-secret gate would 401 first). BOTH outcomes are
    // recorded issuer-side; fail closed (never silently ignored).
    const protectedEventMatch = ctx.path.match(/^\/missions\/([^/]+)\/protected-events$/);
    if (protectedEventMatch && ctx.method === "POST") {
      const missionId = protectedEventMatch[1] as string;
      const sources = opts.protectedEventSources;
      const issuerEvidence = opts.issuerEvidence;
      if (!sources || !issuerEvidence || !enabled("containment")) {
        ctx.status = 501;
        ctx.body = { error: "temporarily_unavailable" };
        return;
      }
      const emitter = { id: opts.issuer, role: "issuer" as const };
      // Record one REJECTED ingestion (fail closed) and set the response.
      const reject = (
        status: number,
        reason: string,
        f: { event_type: string; source: string; event_id: string; advisory: boolean },
      ): void => {
        issuerEvidence.recordIngestion({
          kind: "ingestion",
          event_type: f.event_type,
          source: f.source,
          outcome: "rejected",
          rejection_reason: reason,
          mission_id: missionId,
          event_id: f.event_id,
          ...(f.advisory ? { advisory: true } : {}),
          emitter,
        });
        ctx.status = status;
        ctx.body = { error: "protected_event_rejected", rejection_reason: reason };
      };

      const raw = (await readTextBody(ctx.req)).trim();
      // Peek the payload to discover the claimed source (key lookup needs it).
      // NOT trusted until jwtVerify re-reads it from the verified payload below.
      let peek: Record<string, unknown>;
      try {
        peek = decodeJwt(raw) as Record<string, unknown>;
      } catch {
        reject(403, "malformed_jws", {
          event_type: "unknown",
          source: "unknown",
          event_id: "unknown",
          advisory: false,
        });
        return;
      }
      const claimedSource = typeof peek.source === "string" ? peek.source : "unknown";
      const claimedType = typeof peek.type === "string" ? peek.type : "unknown";
      const claimedEventId = typeof peek.event_id === "string" ? peek.event_id : "unknown";
      const entry = sources.get(claimedSource);
      if (!entry) {
        reject(403, "unknown_source", {
          event_type: claimedType,
          source: claimedSource,
          event_id: claimedEventId,
          advisory: false,
        });
        return;
      }
      // Verify the SIGNATURE against the resolved source's key (ES256 only).
      let payload: Record<string, unknown>;
      try {
        ({ payload } = await jwtVerify(raw, entry.key, { algorithms: ["ES256"] }));
      } catch {
        reject(403, "bad_signature", {
          event_type: claimedType,
          source: claimedSource,
          event_id: claimedEventId,
          advisory: entry.advisory,
        });
        return;
      }
      // Read the VERIFIED payload; assert the verified source is the one we keyed
      // on (closes a source-substitution hole) and is trusted for this `type`.
      const type = typeof payload.type === "string" ? payload.type : "";
      const source = typeof payload.source === "string" ? payload.source : "";
      const observed_at = typeof payload.observed_at === "string" ? payload.observed_at : "";
      const event_id = typeof payload.event_id === "string" ? payload.event_id : "";
      const advisory = entry.advisory;
      if (source !== claimedSource || !entry.eventTypes.has(type)) {
        reject(403, "source_not_trusted_for_type", {
          event_type: type || claimedType,
          source: source || claimedSource,
          event_id: event_id || claimedEventId,
          advisory,
        });
        return;
      }
      if (payload.mission_id !== missionId) {
        reject(403, "mission_mismatch", { event_type: type, source, event_id, advisory });
        return;
      }
      try {
        const { record, evidence } = kernel.containOnEvent(missionId, {
          type,
          source,
          observed_at,
          event_id,
        });
        // Retain the returned Containment Evidence issuer-side (no longer dropped)
        // and record the ACCEPTED ingestion, carrying the rule_id that fired.
        issuerEvidence.retainContainment(evidence);
        issuerEvidence.recordIngestion({
          kind: "ingestion",
          event_type: type,
          source,
          outcome: "applied",
          ...(evidence.policy ? { rule_id: evidence.policy } : {}),
          mission_id: missionId,
          event_id,
          ...(advisory ? { advisory: true } : {}),
          emitter,
        });
        ctx.status = 200;
        ctx.body = {
          containment_version: record.containment?.containment_version ?? 0,
          removed: evidence.removed,
        };
      } catch (e) {
        // Order matters: UnknownProtectedEventError -> 422 must precede the
        // LifecycleConflictError -> 409 and the unknown-mission -> 404 arms, else
        // the headline reject-and-record behavior is shadowed by a 404.
        if (e instanceof UnknownProtectedEventError) {
          reject(422, "unknown_event_type", { event_type: type, source, event_id, advisory });
        } else if (e instanceof LifecycleConflictError) {
          reject(409, "mission_terminal", { event_type: type, source, event_id, advisory });
        } else {
          reject(404, "unknown_mission", { event_type: type, source, event_id, advisory });
        }
      }
      return;
    }

    // --- Adapter introspection (@spec mission#introspection, #composite-active,
    // #caller-authorization-and-minimization; RFC 7662; issue #526) ---
    // JWT ATs cannot use the provider's introspection endpoint (spike finding),
    // so the adapter owns the RFC 7662 surface: an AUTHENTICATED introspection
    // principal (registered audiences + disclosure privileges), STRICT token
    // resolution (signature, expected issuer, at+jwt class, time validity,
    // stored-token presence, Mission resolution), caller visibility, and only
    // then the composite-active matrix over the audience-minimized projection.
    if (ctx.path === "/introspect" && ctx.method === "POST") {
      const principal = authenticateIntrospection(ctx);
      if (!principal) return;
      const body = await readJsonBody(ctx.req);
      const token = typeof body.token === "string" ? body.token : undefined;
      if (!token) {
        ctx.status = 400;
        ctx.body = { error: "invalid_request", error_description: "token is required" };
        return;
      }
      ctx.status = 200;
      const inactive = { active: false };
      const caller = { disclose: new Set<string>(principal.disclose) };

      // A Mission-bound refresh token is an opaque value (no JWS segments) and
      // introspects under the SAME composite rule (@spec mission#composite-active).
      if (token.split(".").length !== 3) {
        const rt = (await provider.RefreshToken.find(token).catch(() => undefined)) as
          | {
              grantId?: string;
              consumed?: unknown;
              accountId?: string;
              clientId?: string;
              jti?: string;
              iat?: number;
              exp?: number;
              jkt?: string;
              resource?: unknown;
              rar?: unknown;
            }
          | undefined;
        // Unknown, expired, rotated-and-consumed, or revoked (destroyed): bare false.
        if (!rt?.grantId || rt.consumed) {
          ctx.body = inactive;
          return;
        }
        const fam = opts.familyStore?.resolve(rt.grantId);
        const record = kernel.findByGrant(rt.grantId) ?? (fam ? kernel.get(fam.missionId) : undefined);
        if (!record) {
          ctx.body = inactive;
          return;
        }
        // Caller visibility (@spec mission#caller-authorization-and-minimization
        // cleanup — issue #541): the TOKEN-VISIBLE audience is its own recorded
        // RFC 8707 `resource` when the refresh token carries one, narrowed by
        // the caller's registration — never the caller's FULL registration
        // regardless of what this particular token was scoped to. A refresh
        // token recording no resource (unscoped) falls back to the caller's
        // full registration (unchanged from the pre-#541 rule).
        const rtResource = typeof rt.resource === "string" ? rt.resource : undefined;
        const visibleAudiences = rtResource
          ? principal.audiences.includes(rtResource)
            ? [rtResource]
            : []
          : principal.audiences;
        if (visibleAudiences.length === 0) {
          ctx.body = inactive;
          return;
        }
        const mission = kernel.introspectionProjection(record, caller);
        if (mission.state !== "active") {
          ctx.body = { active: false, mission };
          return;
        }
        // Individual revocation (@spec mission#introspection — issue #541
        // P1-2): the grant/family that issued THIS refresh token. Unlike the
        // stateless access-token branch below, a refresh token is a STORED
        // object, so `rt.grantId` is already the token's own actual minting
        // grant (no issuance-index lookup needed) — but liveness itself must
        // still be family-aware: an invalidated (not merely destroyed)
        // delegation family leaves the underlying oidc-provider Grant intact.
        if (!(await isGrantLive(opts, provider, rt.grantId))) {
          ctx.body = inactive;
          return;
        }
        // Top-level authorization_details (@spec mission#introspection —
        // P1-1, RFC 9396 §9.2): intersect the refresh token's OWN recorded
        // rar with the Mission's CURRENT effective authority (approved minus
        // containment applied since issuance), then audience-minimize via
        // the caller's registered audience-to-resource mapping (cleanup: an
        // `aud`/resource-indicator value need not be byte-equal to a RAR
        // `resource`).
        const credentialAuthority = Array.isArray(rt.rar) ? (rt.rar as AuthorityEntry[]) : [];
        // The same projection as projectThroughEffective, keeping each
        // fragment's record-entry origin for discharge_selectors.
        const narrowed = kernel.projectCredentialWithOrigin(record, credentialAuthority);
        const resourceSet = resourcesForAudiences(visibleAudiences, principal.audience_resources);
        const returned = narrowed.filter((e) => resourceSet.has(e.entry.resource));
        const authorization_details = returned.map((e) => e.entry);
        const disclosedMission = withDischargeSelectors(record, mission, returned);
        ctx.body = {
          active: true,
          iss: opts.issuer,
          // @spec mission#approval-authentication (#826): the Mission's Subject,
          // never the refresh token's provider account (the Approver).
          sub: record.subject.sub,
          ...(rt.clientId ? { client_id: rt.clientId } : {}),
          ...(typeof rt.exp === "number" ? { exp: rt.exp } : {}),
          ...(typeof rt.iat === "number" ? { iat: rt.iat } : {}),
          ...(rt.jti ? { jti: rt.jti } : {}),
          ...(rt.jkt ? { cnf: { jkt: rt.jkt } } : {}),
          authorization_details,
          mission: disclosedMission,
        };
        return;
      }

      try {
        // Strict resolution: signature over the published keys, the expected
        // issuer, the at+jwt token class, and time validity.
        const { payload } = await jwtVerify(token, jwksResolver, {
          issuer: opts.issuer,
          typ: "at+jwt",
        });

        // @spec mission#introspection, RFC 9068 — the REQUIRED, TYPED claim
        // set, checked BEFORE any Mission resolution. jose validates iss/typ
        // (and exp/iat/nbf ONLY when present) but does not itself require
        // exp/iat/jti/sub/client_id to exist: an AS-signed at+jwt omitting
        // one would otherwise still resolve. Missing or mistyped -> bare
        // false; no Mission or token detail is recovered from failure.
        if (
          typeof payload.exp !== "number" ||
          typeof payload.iat !== "number" ||
          typeof payload.jti !== "string" ||
          !payload.jti ||
          typeof payload.sub !== "string" ||
          !payload.sub ||
          typeof payload.client_id !== "string" ||
          !payload.client_id
        ) {
          ctx.body = inactive;
          return;
        }
        const jti: string = payload.jti;
        const sub: string = payload.sub;
        const clientId: string = payload.client_id;
        const exp: number = payload.exp;
        const iat: number = payload.iat;

        // @spec mission#the-mission-claim (#702) — the baseline Mission
        // profile claim shape is exactly `{id, issuer}`, when a `mission`
        // member is present at all; its total ABSENCE is the pre-existing,
        // distinct "unresolvable" case handled by the Mission lookup below
        // (never Mission-bound), not a malformed shape. `authority_hash` is
        // NOT part of the baseline claim; where a companion profile carries
        // it (e.g. a child-delegation `parent` ref), it is typed but never
        // REQUIRED here, and its absence is never grounds to reject an
        // otherwise well-formed baseline claim.
        const missionClaimRaw = payload.mission;
        if (missionClaimRaw !== undefined) {
          const m = missionClaimRaw as Record<string, unknown> | null;
          if (
            typeof m !== "object" ||
            m === null ||
            typeof m.id !== "string" ||
            !m.id ||
            typeof m.issuer !== "string" ||
            !m.issuer ||
            (m.authority_hash !== undefined && (typeof m.authority_hash !== "string" || !m.authority_hash))
          ) {
            ctx.body = inactive;
            return;
          }
        }

        // @spec mission#authorization-derivation — every access token this AS
        // mints carries `authorization_details` (possibly an empty array);
        // its absence is malformed, not merely undisclosed. Each entry MUST
        // carry a non-empty string `type` + `resource` and an actions array
        // (the mission_resource_access minimum this endpoint's intersection
        // needs downstream). Malformed (e.g. an array of bare strings) ->
        // bare false.
        const rawDetails = payload.authorization_details;
        const isWellFormedEntry = (d: unknown): d is AuthorityEntry => {
          if (typeof d !== "object" || d === null) return false;
          const e = d as Record<string, unknown>;
          return (
            typeof e.type === "string" &&
            e.type !== "" &&
            typeof e.resource === "string" &&
            e.resource !== "" &&
            Array.isArray(e.actions) &&
            e.actions.every((a) => typeof a === "string")
          );
        };
        if (!Array.isArray(rawDetails) || !rawDetails.every(isWellFormedEntry)) {
          ctx.body = inactive;
          return;
        }
        const credentialAuthority = rawDetails as AuthorityEntry[];

        // Mission resolution: a token the AS cannot bind to a known Mission
        // is unresolvable; no Mission or token detail is recovered from
        // failure.
        const missionIdent = payload.mission as { id?: string; issuer?: string } | undefined;
        const missionId = missionIdent?.id;
        const record = missionId ? kernel.get(missionId) : undefined;
        if (!record) {
          ctx.body = inactive;
          return;
        }
        // @spec mission#the-mission-claim (#702): (id, issuer) is now the
        // COMPLETE Mission identity, so both members MUST resolve the same
        // record; neither is silently preferred. Resolving by `id` alone and
        // returning the record's own issuer would let a locally-signed,
        // otherwise-valid token whose `mission.issuer` names a different
        // (or no longer accurate) issuer introspect active, silently
        // normalized to the record's issuer. This adapter only ever serves
        // introspection for Missions it itself holds, so `record.issuer`
        // is also always this AS's own issuer.
        if (missionIdent?.issuer !== record.issuer) {
          ctx.body = inactive;
          return;
        }
        // Caller visibility: the caller must be an audience of the token; the
        // disclosed `aud` is the caller-visible intersection.
        const aud = Array.isArray(payload.aud) ? payload.aud : payload.aud ? [payload.aud] : [];
        const visible = aud.filter((a) => principal.audiences.includes(a));
        if (visible.length === 0) {
          ctx.body = inactive;
          return;
        }
        const mission = kernel.introspectionProjection(record, caller);
        if (mission.state !== "active") {
          // Composite non-active: the token is itself valid but the Mission is
          // not `active`; per the core's governed RFC 7662 deviation the
          // response carries ONLY the minimized `mission` projection with
          // `mission.state`, NEVER top-level token/authorization detail
          // (@spec mission#introspection — issue #541). Mission-level
          // revocation destroys the grant too, so the individual-revocation
          // check below never demotes a non-active Mission's REQUIRED state
          // report to bare false.
          ctx.body = { active: false, mission };
          return;
        }
        // Individual revocation (@spec mission#introspection — issue #541
        // P1-2): resolve the grant/family that ACTUALLY minted THIS token
        // via the issuance index — never `record.grant_id` (the Mission's
        // own approval grant), which stays live independent of a
        // per-delegation family sharing the Mission. Destroying or
        // invalidating that family must not leave its already-issued tokens
        // introspecting active. A token this AS has no issuance record for
        // is treated as NOT VERIFIED, never active (the stateless-JWT
        // forgery/rogue-mint surface this index closes).
        const issuance = opts.tokenIssuanceStore?.resolve(opts.issuer, jti);
        if (!issuance || !(await isGrantLive(opts, provider, issuance.grantId))) {
          ctx.body = inactive;
          return;
        }

        // Top-level authorization_details (@spec mission#introspection —
        // P1-1, RFC 9396 §9.2): intersect the credential's OWN authority
        // (its verified JWT claim, read above) with the Mission's CURRENT
        // effective authority (approved minus containment applied since
        // issuance), then audience-minimize via the caller's registered
        // audience-to-resource mapping. Never the Mission's full effective
        // set: a narrowed/attenuated token must never introspect as though
        // it held authority it was never issued.
        const narrowed = kernel.projectCredentialWithOrigin(record, credentialAuthority);
        const resourceSet = resourcesForAudiences(visible, principal.audience_resources);
        const returned = narrowed.filter((e) => resourceSet.has(e.entry.resource));
        const authorization_details = returned.map((e) => e.entry);
        const disclosedMission = withDischargeSelectors(record, mission, returned);

        const cnf = payload.cnf as { jkt?: string } | undefined;
        ctx.body = {
          active: true,
          iss: payload.iss,
          sub,
          aud: visible.length === 1 ? visible[0] : visible,
          client_id: clientId,
          exp,
          iat,
          jti,
          ...(typeof payload.scope === "string" ? { scope: payload.scope } : {}),
          ...(cnf ? { cnf } : {}),
          token_type: cnf?.jkt ? "DPoP" : "Bearer",
          authorization_details,
          mission: disclosedMission,
        };
      } catch {
        ctx.body = inactive;
      }
      return;
    }

    // --- @spec txn-authorization#challenge-redemption ---
    if (ctx.path === "/transaction" && ctx.method === "POST") {
      await handleTransactionAuthorization(
        {
          issuer: opts.issuer,
          kernel,
          clients: opts.clients,
          publicJwks: opts.publicJwks as { keys: JWK[] },
          dpopProofReplay: opts.dpopProofReplay as DpopProofReplay,
          // @spec txn-authorization#challenge-redemption — the SAME liveness
          // path introspection answers from: the issuance index resolves the
          // grant/family that actually minted this credential, and that
          // family's fate is what makes it live or not.
          subjectTokenLive: async (jti: string) => {
            const issuance = opts.tokenIssuanceStore?.resolve(opts.issuer, jti);
            return !!issuance && (await isGrantLive(opts, provider, issuance.grantId));
          },
          now: () => new Date(),
          ...(opts.txnAuthorization && enabled("transaction-authorization")
            ? { txn: opts.txnAuthorization }
            : {}),
          ...(opts.scopeProjection ? { scopeProjection: opts.scopeProjection } : {}),
        },
        ctx,
        txnWorkflows,
      );
      return;
    }

    // @spec child-delegation#child-creation, #request-processing — Child Mission
    // CREATION lives on the real /token endpoint as an RFC 8693 token exchange
    // (grant_type=token-exchange, requested_token_type=jwt; see
    // handleChildCreationExchange), authenticated by the parent's private_key_jwt
    // with possession proven via DPoP over the parent access token's cnf. The
    // bespoke back-channel POST /child-missions route and the earlier PAR +
    // refresh-token creation grant were both retired in favour of that surface.

    // --- Mission Template admin plane (@spec mission-template) ---
    // POST /templates -- create a Mission Template (service-token admin plane).
    // Demo/test stand-in: a real deployment runs template consent through the full
    // approval + consent-evidence surface.
    if (ctx.path === "/templates" && ctx.method === "POST") {
      if (!requireServiceToken(ctx)) return;
      if (!opts.templateStore || !enabled("templates")) {
        ctx.status = 501;
        ctx.body = { error: "temporarily_unavailable" };
        return;
      }
      const body = await readJsonBody(ctx.req);
      try {
        // @spec mission#authority-sources — the template's source is
        // established from the deployment's trusted catalog, keyed on the
        // recipients; a source member on the request body is ignored, exactly
        // as `authority_source` is never taken from client assertion.
        const template = createTemplate(opts.templateStore, body as unknown as CreateTemplateInput, {
          ...kernel.authoritySourceOptions(),
          ...(opts.dispatchPolicies ? { dispatchPolicies: opts.dispatchPolicies } : {}),
        });
        ctx.status = 201;
        ctx.body = {
          template_id: template.id,
          template_version: template.template_version,
          template_hash: template.template_hash,
        };
      } catch (e) {
        if (e instanceof IntentError) throw intentErrorToOidc(e);
        if (e instanceof TemplateError) {
          ctx.status = 400;
          ctx.body = { error: "invalid_request", error_description: e.message };
        } else {
          throw e;
        }
      }
      return;
    }
    // POST /templates/:id/lifecycle -- revoke. (No expire() accessor exists; expiry is
    // evaluated from expires_at at dispatch time. No conflict state exists yet either.)
    const templateLifecycleMatch = ctx.path.match(/^\/templates\/([^/]+)\/lifecycle$/);
    if (templateLifecycleMatch && ctx.method === "POST") {
      if (!requireServiceToken(ctx)) return;
      if (!opts.templateStore || !enabled("templates")) {
        ctx.status = 501;
        ctx.body = { error: "temporarily_unavailable" };
        return;
      }
      const id = templateLifecycleMatch[1] as string;
      const body = await readJsonBody(ctx.req);
      if (!opts.templateStore.get(id)) {
        ctx.status = 404;
        ctx.body = { error: "unknown_template" };
        return;
      }
      if (body.operation === "revoke") {
        opts.templateStore.revoke(id);
        ctx.status = 200;
        ctx.body = { template_id: id, state: opts.templateStore.get(id)?.state };
        return;
      }
      ctx.status = 400;
      ctx.body = { error: "unsupported_operation", error_description: "only revoke is supported; expiry is time-based via expires_at" };
      return;
    }

    // --- Ordinary (non-Mission) token issuance, DEV ONLY ---
    // @spec authority-server#mission-join (#557) — the credential a MAS Join
    // acts under: an ordinary DPoP-bound OAuth access token with a `scope`
    // and NO `mission` claim. The Join's whole premise is that this AS is
    // unchanged, so the token is deliberately plain; every Mission control
    // lives on the resource side, where the reference is joined.
    if (ctx.path === "/dev/ordinary-token" && ctx.method === "POST") {
      if (!requireServiceToken(ctx)) return;
      const dev = enabled("dev-token") ? opts.devOrdinaryIssuance : undefined;
      if (!dev) {
        ctx.status = 501;
        ctx.body = { error: "temporarily_unavailable" };
        return;
      }
      const body = await readJsonBody(ctx.req);
      const str = (k: string): string | undefined =>
        typeof body[k] === "string" && (body[k] as string).length > 0 ? (body[k] as string) : undefined;
      const sub = str("sub");
      const clientId = str("client_id");
      const scope = str("scope");
      const jkt = str("jkt");
      if (!sub || !clientId || !scope || !jkt) {
        ctx.status = 400;
        ctx.body = {
          error: "invalid_request",
          error_description: "sub, client_id, scope and jkt are all required",
        };
        return;
      }
      const ttl = opts.accessTokenTTL ?? 300;
      const accessToken = await new SignJWT({ client_id: clientId, scope, cnf: { jkt } })
        .setProtectedHeader({ alg: dev.alg, kid: dev.kid })
        .setIssuer(opts.issuer)
        .setAudience(dev.audience)
        .setSubject(sub)
        .setIssuedAt()
        .setExpirationTime(`${ttl}s`)
        .sign(dev.key);
      ctx.status = 200;
      ctx.set("content-type", "application/json");
      ctx.body = { access_token: accessToken, token_type: "DPoP", expires_in: ttl, scope };
      return;
    }

    await next();

    // --- AS metadata flags (@spec mission#as-metadata) ---
    if (ctx.path === "/.well-known/openid-configuration" && ctx.status === 200) {
      const meta = ctx.body as Record<string, unknown>;
      meta.mission_bound_authorization_supported = true;
      // @spec status#as-metadata, status#status-operational — issuer ceiling
      // shared with the runtime's published, enforced per-class bounds.
      meta.mission_max_stale_seconds = MISSION_MAX_STALE_SECONDS;
      // Each capability member below is advertised only where the deployment
      // enables it (adapters/capabilities.ts); the default enables all of them.
      // Not capability members: mission_attenuation_supported and
      // service_catalog_endpoint are never advertised (#897). The token
      // endpoint parses no mission_attenuation_root, and no HTTP route serves
      // the catalog, which is in-process (kernel/catalog.ts). Each member is
      // restored only alongside its working protocol surface and an
      // integration test that exercises that surface.
      // @spec child-delegation#discovery: this AS accepts the child-creation
      // request and enforces the child-delegation controls of that profile.
      if (enabled("child-delegation")) meta.mission_child_delegation_supported = true;
      // @spec id-continuation-assertion#metadata-idp: this AS runs the RFC 8693
      // token-exchange continuation grant (ICA subject token -> continuation
      // ID-JAG), signed by the dedicated as-continuation key on the jwks_uri.
      // The continuation ID-JAG is still the id-jag token type, so the AS also
      // lists it as a requested token type it issues (ICA -02 7.1).
      if (enabled("continuation")) {
        meta.identity_continuation_supported = true;
        meta.identity_chaining_requested_token_types_supported = [ID_JAG_TOKEN_TYPE];
      }
      // @spec async-delegation#discovery: this AS runs the async-delegation
      // continuation transport (RFC 8693 token exchange with request_refresh_token
      // -> a per-delegation grant with a rotated, sender-constrained refresh token).
      if (enabled("async-delegation")) meta.delegated_refresh_token_profile_supported = true;
      // @spec status#as-metadata, discharge#discharge-receipt — the response-signing
      // algorithms of the Mission Status Response shape, wherever it (or the
      // Discharge Receipt, signed the same way) can be served: the Status
      // operation, and the Lifecycle endpoint's `discharge` operation, which
      // answers with either even where the Status route itself is disabled.
      if (enabled("status") || enabled("discharge")) {
        meta.mission_status_signing_alg_values_supported = [STATUS_SIGNING_ALG];
      }
      meta.introspection_endpoint = `${opts.issuer}/introspect`;
      // @spec mission#caller-authorization-and-minimization (cleanup, issue
      // #541) — advertise the introspection endpoint's actual authentication
      // method (registered-principal HTTP Basic, authenticateIntrospection
      // above), matching RFC 8414's *_endpoint_auth_methods_supported idiom.
      meta.introspection_endpoint_auth_methods_supported = ["client_secret_basic"];
      // @spec txn-authorization#challenge-redemption — advertised only where the
      // endpoint is CONFIGURED. An AS without transaction authorization answers
      // 501 there, and advertising it would send clients to a dead endpoint.
      if (opts.txnAuthorization && enabled("transaction-authorization")) {
        meta.transaction_authorization_endpoint = `${opts.issuer}/transaction`;
      }
      // @spec mission#other-types, I-D.draft-zehavi-oauth-rar-metadata — the
      // metadata endpoint is the source of truth for "AS-supported types"; its
      // key set is authorization_details_types_supported (below, already
      // published by the richAuthorizationRequests feature from `types`).
      meta.authorization_details_types_metadata_endpoint = `${opts.issuer}/authorization-details-types`;
    }
  };
}

/**
 * @spec child-delegation#denial-reasons — map a symbolic child denial reason to
 * its layered OAuth error code: `parent_not_active`/`parent_mismatch` ride
 * `invalid_grant`; `delegation_not_permitted`/`child_actor_not_allowed`/
 * `not_strict_subset`/`fanout_exceeded` ride `invalid_request`; `policy_denied`
 * rides `access_denied`.
 */
export function childErrorCode(reason: ChildDenialReason): string {
  switch (reason) {
    case "parent_not_active":
    case "parent_mismatch":
      return "invalid_grant";
    case "policy_denied":
      return "access_denied";
    default:
      return "invalid_request";
  }
}

/**
 * @spec mission-template#dispatch-refusals — map a symbolic dispatch denial
 * reason to its layered OAuth error code: `dispatcher_not_allowed`/
 * `agent_not_selected`/`recipient_not_allowed`/`template_not_active`/
 * `review_overdue`/`dispatch_policy_changed` ride `access_denied`
 * (`agent_not_selected` and `review_overdue` are implementation-local, D205);
 * `out_of_template_ceiling`/`dispatch_prohibited_class`/`max_active_exceeded`/
 * `rate_exceeded` ride `invalid_request`.
 */
function dispatchErrorCode(reason: DispatchReason): "invalid_request" | "access_denied" {
  switch (reason) {
    case "dispatcher_not_allowed":
    case "agent_not_selected":
    case "recipient_not_allowed":
    case "template_not_active":
    case "review_overdue":
    case "dispatch_policy_changed":
      return "access_denied";
    default: // out_of_template_ceiling, dispatch_prohibited_class, max_active_exceeded, rate_exceeded
      return "invalid_request";
  }
}

/**
 * @spec mission-template#dispatch — instantiate an ordinary Mission from a
 * Mission Template and mint a DPoP-bound mission-bound access token for it,
 * in ONE /token round trip (unlike child-creation + child-redemption, which
 * are two separate grants). The dispatcher (ap-agent) is the AUTHENTICATED
 * client (private_key_jwt ran before this handler); the recipient named on
 * the template becomes the instance's client_id, but the Grant/AccessToken
 * are owned by the DISPATCHER (the entity actually redeeming here) so
 * oidc-provider's same-client invariant holds. Denials set ctx.status/body
 * DIRECTLY (status before body) so `mission_denial_reason` survives —
 * oidc-provider's err_out renderer would otherwise strip any member other
 * than error/error_description (same technique as handleChildCreationExchange).
 */
async function handleMissionDispatchGrant(
  provider: Provider,
  opts: AdapterOptions,
  ctx: KoaContextWithOIDC,
): Promise<void> {
  const { kernel } = opts;
  const store = opts.templateStore;
  if (!store) {
    ctx.status = 501;
    ctx.body = { error: "temporarily_unavailable", error_description: "template store not configured" };
    return;
  }
  const client = ctx.oidc.client as NonNullable<typeof ctx.oidc.client>;
  const params = ctx.oidc.params as Record<string, unknown>;

  const templateId = typeof params.template_id === "string" ? params.template_id : "";
  const missionIntentRaw = typeof params.mission_intent === "string" ? params.mission_intent : "";
  if (!templateId) {
    ctx.status = 400;
    ctx.body = { error: "invalid_request", error_description: "template_id required" };
    return;
  }
  if (!missionIntentRaw) {
    ctx.status = 400;
    ctx.body = { error: "invalid_request", error_description: "mission_intent required" };
    return;
  }
  // @spec mission-template#dispatch — dispatch_event_id is REQUIRED (it is the
  // dispatch grant's realization of the creation_request_id pattern: the
  // client-held idempotency handle). The former crypto.randomUUID() fallback
  // silently DEFEATED idempotency for a client that omitted it (every retry
  // minted a fresh event id, so a lost response duplicated the instance);
  // missing now refuses, aligning the code to the spec's REQUIRED.
  const dispatchEventId =
    typeof params.dispatch_event_id === "string" && params.dispatch_event_id
      ? params.dispatch_event_id
      : "";
  if (!dispatchEventId) {
    ctx.status = 400;
    ctx.body = { error: "invalid_request", error_description: "dispatch_event_id required" };
    return;
  }

  // Resolve the template FIRST: we need its approver (to establish the subject)
  // BEFORE dispatch, and to control the unknown-template reply
  // (dispatchFromTemplate throws a plain Error for unknown ids). The instance's
  // Agent is NOT chosen here: the kernel selects it under the Dispatch Policy
  // (@spec mission-template#the-mission-template), and this request names none.
  const template = store.get(templateId);
  if (!template) {
    ctx.status = 400;
    ctx.body = { error: "invalid_request", error_description: "unknown template" };
    return;
  }

  // @spec mission#submission-via-par — this carrier adopts the Submission
  // envelope: `mission_intent` carries {intent, evidence?}.
  let submission: ReturnType<typeof kernel.validateSubmission>;
  try {
    submission = kernel.validateSubmission(missionIntentRaw);
  } catch (e) {
    ctx.status = 400;
    ctx.body = {
      error: e instanceof IntentError ? e.code : "invalid_request",
      error_description: e instanceof Error ? e.message : "invalid mission_intent",
    };
    return;
  }
  const intent = submission.intent;
  // @spec mission#authority-proposal — the dispatcher's authority proposal
  // rides the standard authorization_details parameter of this grant (the
  // instance Intent carries no authority members). Optional: absent means
  // template-mode derivation under the double intersection.
  let proposedAuthority: AuthorityEntry[] | undefined;
  const proposalRaw = params.authorization_details;
  if (proposalRaw !== undefined) {
    if (typeof proposalRaw !== "string" || !proposalRaw) {
      ctx.status = 400;
      ctx.body = { error: "invalid_request", error_description: "authorization_details must be a JSON array" };
      return;
    }
    try {
      const proposal = kernel.validateProposal(proposalRaw, intent.target_resources);
      proposedAuthority = proposal.length ? proposal : undefined;
    } catch (e) {
      if (e instanceof IntentError) {
        ctx.status = 400;
        ctx.body = { error: e.code, error_description: e.message };
        return;
      }
      throw e;
    }
  }

  // @spec expansion#creation-lookup-order, mission-template#dispatch —
  // possession verification precedes the Dispatch idempotency lookup, and the
  // verified DPoP key is the fingerprint's `cnf` and the issued token's binding.
  const proofJws = ctx.get("DPoP");
  if (!proofJws) throw new errors.InvalidRequest("DPoP proof JWT required");
  let jkt: string;
  let proofJti: unknown;
  try {
    const header = decodeProtectedHeader(proofJws);
    jkt = await calculateJwkThumbprint(header.jwk as JWK);
    const { payload: proof } = await jwtVerify(proofJws, header.jwk as JWK, { typ: "dpop+jwt" });
    if (proof.htu !== `${opts.issuer}/token` || proof.htm !== "POST") {
      throw new Error("DPoP htu/htm mismatch");
    }
    proofJti = proof.jti;
  } catch {
    throw new errors.InvalidRequest("invalid DPoP proof");
  }
  // @spec RFC 9449 — proof-jti single-use within the bounded replay window.
  if (!freshProofJti(opts, proofJti)) {
    ctx.status = 400;
    ctx.body = { error: "invalid_dpop_proof", error_description: "DPoP proof jti missing or replayed" };
    ctx.set("cache-control", "no-store");
    return;
  }

  // Core-consistency: the Dispatcher does NOT name the Subject; the Issuer
  // establishes it. The template carries the consenting human (approver); the
  // subject is established from it (decide() defaults subject to approver, and
  // read-only missions may self-approve, D37). Recipient comes from the template.
  const dispatchInput: DispatchInput = {
    templateId,
    dispatchEventId,
    dispatcher: client.clientId,
    ...(opts.creationIdempotency ? { idempotency: opts.creationIdempotency } : {}),
    presenterJkt: jkt,
    ...(submission.evidence ? { presentedEvidence: submission.evidence } : {}),
    ...(opts.dispatchPolicies ? { dispatchPolicies: opts.dispatchPolicies } : {}),
    intent,
    ...(proposedAuthority ? { proposedAuthority } : {}),
    subject: { iss: template.issuer, sub: template.approver.sub },
    policyVersion: DERIVATION_POLICY.policy_version,
    dispatchProhibitedActions: DISPATCH_PROHIBITED_ACTIONS,
  };
  /** A refused Dispatch: the response, or false when `e` is not a Dispatch outcome. */
  const dispatchFailure = (e: unknown): boolean => {
    if (e instanceof DispatchMismatchError) {
      // @spec mission-template#dispatch — the expansion profile's durable
      // reservation: a different fingerprint is invalid_request, with no
      // mission_denial_reason (the profile's closed set has no member for it).
      ctx.status = 400;
      ctx.body = { error: "invalid_request", error_description: e.message };
      ctx.set("cache-control", "no-store");
      return true;
    }
    if (e instanceof DispatchError) {
      const code = dispatchErrorCode(e.reason);
      ctx.status = code === "access_denied" ? 403 : 400;
      // Set status/body DIRECTLY (status before body) so mission_denial_reason
      // survives oidc-provider's err_out renderer (same pattern as child creation).
      ctx.body = { error: code, mission_denial_reason: e.reason };
      ctx.set("cache-control", "no-store");
      return true;
    }
    return false;
  };

  // @spec expansion#creation-lookup-order, mission#intent-submission-evidence —
  // the completed-operation recovery lookup runs after possession verification
  // and BEFORE evidence re-verification and the gates.
  let record: MissionRecord | undefined;
  try {
    record = findDispatch(kernel, store, dispatchInput)?.mission;
  } catch (e) {
    if (dispatchFailure(e)) return;
    ctx.status = 400;
    ctx.body = { error: "invalid_request", error_description: e instanceof Error ? e.message : "dispatch failed" };
    return;
  }
  if (!record) {
    // @spec mission#intent-submission-evidence — STAGE-2 verification (required
    // types resolved BEFORE derivation; the presenter is the AUTHENTICATED
    // dispatcher). It runs AFTER the completed-operation recovery lookup above:
    // an artifact that expired after the first Dispatch completed MUST NOT
    // break recovery; a new Dispatch still verifies.
    let submissionEvidence: Awaited<ReturnType<typeof kernel.verifySubmissionEvidence>>;
    try {
      submissionEvidence = await kernel.verifySubmissionEvidence({
        intent,
        ...(submission.evidence ? { evidence: submission.evidence } : {}),
        presenter: { clientId: client.clientId },
        required: requiredEvidenceTypesFor(opts, client),
        requestContext: { carrier: "mission-dispatch" },
      });
    } catch (e) {
      if (e instanceof IntentError) {
        ctx.status = 400;
        ctx.body = { error: e.code, error_description: e.message };
        return;
      }
      throw e;
    }

    try {
      ({ mission: record } = dispatchFromTemplate(kernel, store, {
        ...dispatchInput,
        ...(submissionEvidence?.length ? { submissionEvidence } : {}),
      }));
    } catch (e) {
      if (e instanceof IntentError) throw intentErrorToOidc(e);
      if (dispatchFailure(e)) return;
      ctx.status = 400;
      ctx.body = { error: "invalid_request", error_description: e instanceof Error ? e.message : "dispatch failed" };
      return;
    }
  }

  // ---- mint mission-bound access token: INLINE COPY of handleChildJwtBearerGrant
  // (~806-879). DPoP-bind to the proof verified above. The Grant and the
  // AccessToken are owned by `client` (the DISPATCHER, the authenticated entity
  // here) rather than by `record.client_id` (the recipient, who is not present
  // in this exchange) — the one substitution the child-bearer code does not need,
  // because there record.client_id IS the authenticated client.
  // Containment: every copy of the instance's authority into rar/authorization_
  // details projects the EFFECTIVE set (approved minus containment overlay).
  const effective = kernel.effectiveAuthoritySet(record);
  const resource = effective[0]?.resource ?? opts.issuer;
  let grantId: string;
  if (record.grant_id) {
    grantId = record.grant_id;
  } else {
    const grant = new provider.Grant({ accountId: record.subject.sub, clientId: client.clientId });
    for (const entry of effective) {
      (grant as unknown as { addRar: (d: unknown) => void }).addRar(entry);
    }
    grantId = await grant.save();
    kernel.bindGrant(record.id, grantId);
  }

  // Resource + TTL — mirror mintDeferredToken; clamp the TTL to the instance's
  // expires_at so the mission-bound token never outlives the dispatched instance.
  const info = resourceServerInfoFor(resource, opts.accessTokenTTL ?? 300);
  info.accessTokenTTL = Math.min(
    info.accessTokenTTL,
    Math.max(1, Math.floor((Date.parse(record.expires_at) - Date.now()) / 1000)),
  );

  // Mint — mirror mintDeferredToken. save() fires extraTokenClaims, which gates
  // the derivation and attaches the mission `mission` claim exactly once.
  const at = new provider.AccessToken({
    accountId: record.subject.sub,
    client,
    grantId,
    gty: MISSION_DISPATCH_GRANT_TYPE,
    rar: effective,
    scope: SCOPE_DECIDED_AT_SAVE,
  });
  at.resourceServer = newResourceServer(provider, resource, info);
  at.jkt = jkt; // sender-constrain to the dispatcher's DPoP key (tokenType -> DPoP)
  ctx.oidc.entity("AccessToken", at);
  const jwt = await at.save();

  ctx.status = 200;
  ctx.body = {
    access_token: jwt,
    token_type: "DPoP",
    expires_in: at.expiration,
    // @spec mission#scope-projection — the projected value save() decided.
    ...(at.scope ? { scope: at.scope } : {}),
    mission_id: record.id,
    // @spec mission#grant-binding — the dispatched instance's COMMITTED
    // effective expiry, verbatim from the record, never recomputed here.
    mission_expires_at: record.expires_at,
    authorization_details: effective,
  };
  ctx.set("cache-control", "no-store");
}

/**
 * @spec mission#approval-authentication — does the Approver's ACHIEVED
 * authentication context satisfy the client's requested `acr_values`/
 * `max_age`? Approver-scoped, never Subject-scoped: this checks only the
 * principal acting as Approver for THIS approval event, never the Mission
 * Subject, who MAY be a different principal. Absence of either request
 * parameter trivially satisfies that parameter (the deployment's own
 * approval-authentication floor, enforced elsewhere, is unaffected either
 * way and is never relaxed by a narrower or absent client request).
 */
function approverAuthenticationSatisfies(
  requested: { acrValues?: string; maxAge?: string; forceFreshLogin?: boolean },
  achieved: { acr?: string; authTime?: number },
  nowEpochSeconds: number,
): boolean {
  const acrValues = requested.acrValues?.split(" ").filter(Boolean);
  if (acrValues && acrValues.length > 0) {
    if (!achieved.acr || !acrValues.includes(achieved.acr)) return false;
  }
  // `forceFreshLogin` recovers `max_age=0` after oidc-provider's own
  // check_max_age middleware clears `params.max_age` and translates it to
  // `prompt=login` (its literal max_age=0-to-prompt=login rule) before this
  // handler ever sees it: both signals demand the freshest possible
  // authentication, so both are treated as an effective max_age of 0.
  const maxAge = requested.forceFreshLogin
    ? 0
    : requested.maxAge !== undefined
      ? Number(requested.maxAge)
      : undefined;
  if (maxAge !== undefined) {
    if (!Number.isFinite(maxAge) || achieved.authTime === undefined) return false;
    if (nowEpochSeconds - achieved.authTime > maxAge) return false;
  }
  return true;
}

async function decide(
  provider: Provider,
  opts: AdapterOptions,
  ctx: KoaCtx,
  body: Record<string, unknown>,
  principal: ApprovalPrincipal,
  /** The Approver authenticated in this user agent (a trusted browser
   *  session), not through a headless approval service. */
  interactive: boolean,
) {
  const details = await provider.interactionDetails(ctx.req, ctx.res);
  if (details.uid !== ctx.path.split("/")[2]) {
    ctx.status = 400;
    ctx.body = { error: "invalid_request" };
    return;
  }
  const params = details.params as Record<string, unknown>;
  // @spec mission#submission-via-par — re-parse the pushed Submission envelope;
  // approval and intent_hash cover exactly the semantic `intent`.
  const submission = opts.kernel.validateSubmission(String(params.mission_intent));
  const intent = submission.intent;
  // @spec mission#intent-submission-evidence — STAGE-2 verification re-runs at
  // the DECISION over the interaction's immutable pushed parameters (the same
  // TOCTOU rule as the proposal/derivation re-computation below): the facts
  // recorded on the Mission are the ones verified in the approved context, and
  // evidence that expired between rendering and decision refuses here.
  let submissionEvidence: Awaited<ReturnType<typeof opts.kernel.verifySubmissionEvidence>>;
  try {
    submissionEvidence = await opts.kernel.verifySubmissionEvidence({
      intent,
      ...(submission.evidence ? { evidence: submission.evidence } : {}),
      presenter: { clientId: String(params.client_id ?? "") },
      required: requiredEvidenceTypesFor(
        opts,
        opts.clients.find((c) => c.client_id === params.client_id),
      ),
      requestContext: { carrier: "par" },
    });
  } catch (e) {
    if (e instanceof IntentError) {
      ctx.status = 400;
      ctx.body = { error: e.code, error_description: e.message };
      return;
    }
    throw e;
  }
  // @spec mission#authority-proposal, mission#integrity-anchors (TOCTOU) — the
  // task and the proposal are re-read from the interaction's pushed parameters
  // (immutable for the life of the interaction uid) and the Authority Set is
  // re-derived HERE, at the decision: kernel.approve() then computes all three
  // commitments (intent_hash, proposal_hash, authority_hash) together over
  // exactly this context, so a change to any of task, proposal, or derived set
  // between rendering and decision is a NEW interaction context and recomputes
  // every anchor.
  const proposalRaw = clientProposalParam(params);
  const proposedAuthority =
    proposalRaw !== undefined
      ? opts.kernel.validateProposal(proposalRaw, intent.target_resources)
      : undefined;
  // @spec mission#approval-event (step 2), mission#approval-authentication
  // (#826): the Subject is the one the authenticated approval surface
  // selected, or the Approver for a self-approval; never `login_hint`, which
  // concerns the Approver. An approval for another principal still needs the
  // Approver's local approve-for authorization.
  const approver = principal.sub;
  const subject = principal.subject ?? approver;
  if (!opts.knownSubjects.has(subject) || (subject !== approver && !opts.approverApprovesFor.get(approver)?.has(subject))) {
    ctx.status = 403;
    ctx.body = { error: "approval_forbidden" };
    return;
  }

  if (body.decision !== "approve") {
    await provider.interactionFinished(ctx.req, ctx.res, {
      error: "access_denied",
      error_description: "approver denied the mission",
    });
    return;
  }

  // @spec mission#approval-authentication (#826): `openid` asks for an ID
  // Token about the End-User this interaction authenticates, the Approver.
  // Refused `invalid_scope` before anything is created when the Approver is
  // not the Subject (issuer-qualified principals compared), and when no
  // End-User authenticated in this user agent at all: a headless approval
  // service's credential is not an interactive login.
  const requestedScope = splitScope(params.scope);
  if (requestedScope.oidc.includes("openid")) {
    const approverPrincipal = { iss: opts.issuer, sub: approver };
    const subjectPrincipal = { iss: opts.issuer, sub: subject };
    const samePrincipal =
      approverPrincipal.iss === subjectPrincipal.iss && approverPrincipal.sub === subjectPrincipal.sub;
    if (!samePrincipal || !interactive) {
      await provider.interactionFinished(ctx.req, ctx.res, {
        error: "invalid_scope",
        error_description: samePrincipal
          ? "openid requires an End-User authenticated in this user agent; a headless approval is not one"
          : "openid is unavailable when the Approver is not the Mission's Subject",
      });
      return;
    }
  }

  // @spec mission#approval-authentication — the client's requested
  // `acr_values`/`max_age` (standard OIDC authorization-request params;
  // oidc-provider parses them unconditionally, no extraParams registration
  // needed) describe the Approver's authentication, never the Subject's. This
  // resolution surface supplies the achieved context from its independent
  // login or scoped service-principal registration, never from decide input.
  const achievedAcr = principal.acr;
  const achievedAuthTime = principal.auth_time;
  const requestedPrompts = typeof params.prompt === "string" ? params.prompt.split(" ") : [];
  if (
    !approverAuthenticationSatisfies(
      {
        ...(typeof params.acr_values === "string" ? { acrValues: params.acr_values } : {}),
        ...(typeof params.max_age === "string" ? { maxAge: params.max_age } : {}),
        // oidc-provider's check_max_age middleware already translated a
        // literal max_age=0 to prompt=login and cleared params.max_age.
        ...(params.max_age === undefined && requestedPrompts.includes("login")
          ? { forceFreshLogin: true }
          : {}),
      },
      { ...(achievedAcr ? { acr: achievedAcr } : {}), ...(achievedAuthTime !== undefined ? { authTime: achievedAuthTime } : {}) },
      Math.floor(opts.kernel.nowDate().getTime() / 1000),
    )
  ) {
    await provider.interactionFinished(ctx.req, ctx.res, {
      error: "access_denied",
      error_description: "approver authentication did not satisfy the requested acr_values/max_age",
    });
    return;
  }

  // @spec mission#error-mapping — a derivation refusal at the approval
  // decision is an authorization-decision outcome ({{error-mapping}}'s row for
  // this surface), completed through the pending front-channel authorization
  // request exactly like the "approver declined" branch above:
  // `invalid_authorization_details` when the client submitted a proposal that
  // yields nothing, `access_denied` when configured-mapping mode (no
  // proposal) yields nothing.
  let authority: ReturnType<typeof opts.kernel.derive>;
  try {
    authority = opts.kernel.derive(intent, proposedAuthority);
  } catch (e) {
    if (e instanceof IntentError) {
      await provider.interactionFinished(ctx.req, ctx.res, {
        error: e.code,
        error_description: e.message,
      });
      return;
    }
    throw e;
  }
  // Governance (D37): write-bearing missions require subject != approver
  // with the approver role; read-only may self-approve.
  const writeBearing = authority.some((e) => e.actions.some((a) => WRITE_ACTIONS.has(a)));
  if (writeBearing && (approver === subject || !opts.approverRoleSubs.has(approver))) {
    ctx.status = 403;
    ctx.body = { error: "approval_forbidden", error_description: "write-bearing missions require a distinct approver" };
    return;
  }

  // @spec mission#scope-projection, mission#error-mapping — the requested
  // `scope` check at the authorization decision, before any Mission exists:
  // under a trusted mapping, a requested resource value the derived authority
  // cannot make a safe projection of refuses `invalid_scope` through the
  // pending authorization request. An unknown mapping or a target with no
  // safe projection is left to the token endpoint, which refuses it
  // `invalid_target` (the mapping error takes precedence).
  const audience = typeof params.resource === "string" ? params.resource : authority[0]?.resource;
  if (requestedScope.resource.length && audience) {
    const outcome = projectScope({
      mapping: opts.scopeProjection,
      audiences: [audience],
      entries: authority,
      requested: { values: requestedScope.resource, explicit: true },
    });
    if (outcome.outcome === "refuse" && outcome.error === "invalid_scope") {
      await provider.interactionFinished(ctx.req, ctx.res, {
        error: "invalid_scope",
        error_description: outcome.reason,
      });
      return;
    }
  }

  // @spec mission#approval-event (step 3), mission#error-mapping — the five
  // authority-source gates run inside `approve()`, before any anchor is
  // computed and before the record is created. Every refusal is an
  // authorization-decision outcome, so it completes through the pending
  // front-channel authorization request as `access_denied`, exactly like the
  // "approver declined" and derivation-refusal branches above.
  // @spec mission#approval-event (step 4) — the creation commit re-checks the
  // effective expiry atomically. Submission acceptance did not freeze time, so a
  // requested ceiling that passes while the approval is pending refuses HERE and
  // creates no Mission. Mapped like the derivation refusal above: the
  // interaction finishes with the error, never a 500.
  let record: MissionRecord;
  try {
    record = opts.kernel.approve({
      intent: intent as MissionIntent,
      ...(proposedAuthority ? { proposedAuthority } : {}),
      // @spec mission#intent-submission-evidence — the verified facts land on
      // the Mission Record (outside all anchors), request-derived, never
      // fabricated downstream.
      ...(submissionEvidence?.length ? { submissionEvidence } : {}),
      subject: { iss: opts.issuer, sub: subject },
      approver: { iss: opts.issuer, sub: approver },
      clientId: String(params.client_id),
      approvalEventId: `apev_${details.uid}`,
    });
  } catch (e) {
    if (e instanceof IntentError) {
      await provider.interactionFinished(ctx.req, ctx.res, {
        error: e.code,
        error_description: e.message,
      });
      return;
    }
    throw e;
  }

  // @spec mission#approval-authentication (#826): the provider account is the
  // authenticated Approver; the Mission records the Subject, and every
  // Mission-bound token projects it (the JWT customizer).
  const grant = new provider.Grant({ accountId: approver, clientId: String(params.client_id) });
  // @spec mission#scope-projection — the grant holds exactly what the
  // request named: its OIDC values (openid enables an id_token), and any
  // resource values the check above let through, so the authorization code
  // carries them to the token request. Authority itself is the grant's rar;
  // no resource scope stands in for it.
  if (requestedScope.oidc.length) grant.addOIDCScope(requestedScope.oidc.join(" "));
  if (requestedScope.resource.length && audience) {
    grant.addResourceScope(audience, requestedScope.resource.join(" "));
  }
  // Containment: the grant's rar copies the EFFECTIVE set. A freshly approved
  // Mission has no containment, so this is the approved set as-is (fast path).
  const effective = opts.kernel.effectiveAuthoritySet(record);
  for (const entry of effective) {
    (grant as unknown as { addRar: (d: unknown) => void }).addRar(entry);
  }
  const grantId = await grant.save();
  opts.kernel.bindGrant(record.id, grantId);

  // @spec mission#scope-projection — an Intent-only request (configured
  // mapping: no `authorization_details`, and no resource `scope` either,
  // since a Mission client does not request one for this authority) must
  // still complete. oidc-provider's authorization endpoint finishes a
  // request only when a scope was granted or `authorization_details` was
  // requested (lib/actions/authorization/interactions.js 9.10.0 L63-72), so
  // the pending request records the issuer-derived authority as its
  // `authorization_details`: the authority this request obtains is carried
  // through RAR, never through a synthetic scope. The grant's rar, not this
  // parameter, is what every token carries.
  // The value is marked (DERIVED_AUTHORIZATION_DETAILS_MARKER) so every
  // reader of the stored parameters as a client proposal (the approval render
  // and a repeated decision on this interaction) treats it as absent, and the
  // anchors never commit a proposal the client did not send.
  if (typeof params.authorization_details !== "string" || params[DERIVED_AUTHORIZATION_DETAILS_MARKER] === true) {
    params.authorization_details = JSON.stringify(withoutCapabilitySources(effective));
    params[DERIVED_AUTHORIZATION_DETAILS_MARKER] = true;
    await details.save(Math.max(1, (details.exp ?? 0) - Math.floor(Date.now() / 1000)));
  }

  // @spec mission#approval-authentication (#826): the login is the
  // Approver's own, with its achieved `acr` and authentication time, never a
  // time manufactured from the approval click and never an authentication of
  // a different Subject. oidc-provider finishes an interaction only through
  // a login, which on a headless approval is the code's account and nothing
  // more: this user agent is the client's, no End-User authenticated in it,
  // and the resume leaves it no session (the headless-resume middleware).
  // The resume runs on a fresh session, so the interaction no longer names
  // the one this user agent held when it began.
  if (!interactive && details.session?.uid) {
    delete (details.session as { uid?: string }).uid;
    await details.save(Math.max(1, (details.exp ?? 0) - Math.floor(Date.now() / 1000)));
  }
  await provider.interactionFinished(ctx.req, ctx.res, {
    login: { accountId: approver, acr: principal.acr, ts: principal.auth_time, remember: interactive },
    consent: { grantId },
    ...(interactive ? {} : { [HEADLESS_APPROVAL_RESULT]: true }),
  });
}

function renderApprovalPage(
  uid: string,
  intent: unknown,
  authority: unknown,
  proposal?: unknown,
  provenance?: unknown[],
  authoritySource?: AuthoritySource,
): string {
  // @spec mission#approval-event — the rendering distinguishes the submitted
  // proposal (untrusted client input) from the derived Authority Set (what
  // approval grants); the proposal section appears only when one was submitted.
  const proposalSection = proposal
    ? `<h2>Proposed authority (submitted, untrusted)</h2><pre>${escapeHtml(JSON.stringify(proposal, null, 2))}</pre>`
    : "";
  // @spec mission#intent-submission-evidence — MATERIAL verified provenance is
  // rendered to the Approver as normalized FACTS (never raw artifacts); the
  // section appears only when evidence verified.
  const provenanceSection = provenance?.length
    ? `<h2>Verified intent provenance</h2><pre>${escapeHtml(JSON.stringify(provenance, null, 2))}</pre>`
    : "";
  // @spec mission#approval-event (step 5), mission#authority-sources — the
  // rendering identifies WHOSE authority the approval draws on, and for
  // `organizational` the governed policy it draws on. The policy `digest` is
  // record detail, not consent context, so the page names `id` and `version`.
  const sourceSection = authoritySource
    ? `<h2>Authority source (whose authority this draws on)</h2><pre>${escapeHtml(
        JSON.stringify(
          authoritySource.policy
            ? {
                type: authoritySource.type,
                policy: {
                  id: authoritySource.policy.id,
                  version: authoritySource.policy.version,
                },
              }
            : { type: authoritySource.type },
          null,
          2,
        ),
      )}</pre>`
    : "";
  return `<!doctype html><title>Mission approval</title>
<h1>Approve mission?</h1>
<h2>Intent (task context, untrusted)</h2><pre>${escapeHtml(JSON.stringify(intent, null, 2))}</pre>
${sourceSection}
${proposalSection}
${provenanceSection}
<h2>Derived authority (what approval grants)</h2><pre>${escapeHtml(JSON.stringify(authority, null, 2))}</pre>
<form method="post" action="/interaction/${uid}/decide" enctype="application/json">
<button name="decision" value="approve">Approve</button>
<button name="decision" value="deny">Deny</button></form>`;
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function optional<T>(key: string, value: T | undefined): Record<string, T> {
  return value === undefined ? {} : { [key]: value };
}

function str(v: string | string[] | undefined): string | undefined {
  return typeof v === "string" ? v : undefined;
}

/** @spec status#mission-status-response — the signed Status envelope's media type. */
export const MISSION_STATUS_RESPONSE_MEDIA_TYPE = "application/mission-status-response+jwt";

/**
 * @spec discharge#discharge-operation ("observed_at") — the caller's asserted
 * observation time is validated for syntax and REASONABLE CLOCK BOUNDS only,
 * never as trusted ordering or freshness. One day either side of the AS's own
 * clock; the AS records its own commit time as `received_at` regardless.
 */
const OBSERVED_AT_SKEW_MS = 24 * 60 * 60 * 1000;

/**
 * A prefixed digest of the family's only defined algorithm: exactly 32 bytes,
 * base64url without padding (43 characters). Anything looser admits values no
 * digest computation can ever match.
 */
const FAMILY_DIGEST_RE = /^sha-256:[A-Za-z0-9_-]{43}$/;
function isFamilyDigest(value: unknown): value is string {
  return typeof value === "string" && FAMILY_DIGEST_RE.test(value);
}

/**
 * Strict RFC 3339 date-time shape, gated BEFORE `Date.parse`: the platform
 * parser accepts many non-RFC3339 forms (bare dates, RFC 2822 strings) that
 * the wire contract does not.
 */
const RFC3339_RE = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$/;

/**
 * @spec discharge#discharge-operation, discharge#discharge-anti-oracle,
 * discharge#discharge-result, discharge#discharge-carryover,
 * discharge#discharge-receipt — the `discharge` operation on the Mission Lifecycle
 * endpoint. Request-shape failures are `invalid_request` (including a request
 * naming its target in both forms, or neither); the selector, membership, and
 * target-authorization refusals are ONE `not_found`; a divergent
 * re-assertion of the same event tuple is `conflict`; success is the endpoint's
 * signed Mission Status Response envelope carrying `discharge_result` as a
 * sibling of `mission`. A discharge FORWARDED after carryover
 * (@spec discharge#discharge-carryover) answers with the replacement's envelope
 * (`forwarded_from` in the result) when the caller may read Mission Status, and
 * with a signed Discharge Receipt (@spec discharge#discharge-receipt) otherwise.
 */
/**
 * @spec control-plane#serialization, control-plane#fresh-observation — finalize
 * a COMMITTED lifecycle response from its retained immutable material.
 *
 * This is the recovery half of the signing boundary: the operation committed,
 * the response bytes did not survive, and the exact response is reproduced
 * rather than the operation re-executed. A JSON outcome re-serializes to the
 * same bytes. A signed envelope is signed again over the RECORDED observation,
 * so its `iat` and `exp` are the original observation point's and nothing is
 * re-dated. Only this crash case re-signs: a response whose bytes ARE retained
 * replays those exact bytes and never reaches here.
 */
async function finalizeRetainedResponse(
  kernel: MissionKernel,
  stored: RetainedLifecycleResponse,
): Promise<string | undefined> {
  const material = stored.material;
  if (!material) return undefined;
  if (material.kind === "json") return JSON.stringify(material.body);
  if (material.kind === "discharge-receipt") {
    return kernel.signDischargeReceipt(material.receipt as unknown as DischargeReceiptObservation);
  }
  return kernel.signObservation(material.observation as unknown as StatusObservation);
}

async function handleDischarge(input: {
  kernel: MissionKernel;
  principal: ServiceTokenPrincipal;
  missionId: string;
  body: Record<string, unknown>;
  nonce?: string;
  /**
   * @spec status#mission-status-authentication — the Mission Status operation's
   * own authorization check, deciding a forwarded discharge's response shape.
   */
  mayReadStatus: (principal: ServiceTokenPrincipal) => boolean;
  /**
   * @spec control-plane#serialization — invoked INSIDE the latch transaction
   * with the material the response will be signed from (a Status observation
   * or a Discharge Receipt), so the committed outcome and its replayable
   * material are durable before anything is signed.
   */
  claimResponse?: (material: LifecycleResponseMaterial, contentType: string, validUntilMs: number) => void;
  sendSigned: (contentType: string, jws: string) => void;
  sendJson: (status: number, json: Record<string, unknown>) => void;
  sendNotFound: () => void;
  sendInvalidRequest: (description: string, echoNonce?: boolean) => void;
}): Promise<void> {
  const { kernel, principal, missionId, body, nonce } = input;
  // @spec discharge#discharge-operation — `nonce` is REQUIRED, and a request whose
  // nonce is absent or malformed is refused with NO nonce echoed.
  if (nonce === undefined) {
    input.sendInvalidRequest("discharge requires a well-formed nonce", false);
    return;
  }
  // @spec discharge#discharge-authority — the DISTINCT grant, checked before any
  // selector work. A caller holding only `mission_lifecycle` (or acting as the
  // Subject, Approver, or an administrator) is refused with the same
  // indistinguishable not-found body every unauthorized reference gets.
  if (!principal.scopes.includes(MISSION_DISCHARGE_SCOPE)) {
    input.sendNotFound();
    return;
  }
  const entryDigestValue = body.entry_digest;
  const conditionDigestValue = body.condition_digest;
  const selectorValue = body.condition_selector;
  const eventType = body.event_type;
  const eventId = body.event_id;
  // @spec discharge#discharge-operation — the target is named in EXACTLY ONE of
  // two forms: a condition selector, or the digest pair. Both, or neither, is
  // refused `invalid_request`.
  const hasSelector = selectorValue !== undefined;
  const hasDigests = entryDigestValue !== undefined || conditionDigestValue !== undefined;
  if (hasSelector === hasDigests) {
    input.sendInvalidRequest(
      "discharge names its target by condition_selector or by entry_digest and condition_digest, exactly one",
    );
    return;
  }
  let target: DischargeTargetForm;
  if (hasSelector) {
    if (typeof selectorValue !== "string" || !CONDITION_SELECTOR_RE.test(selectorValue)) {
      input.sendInvalidRequest("condition_selector must be 1*128 ALPHA / DIGIT / '-' / '_'");
      return;
    }
    target = { condition_selector: selectorValue };
  } else {
    if (!isFamilyDigest(entryDigestValue)) {
      input.sendInvalidRequest("entry_digest must be a sha-256: prefixed digest");
      return;
    }
    if (!isFamilyDigest(conditionDigestValue)) {
      input.sendInvalidRequest("condition_digest must be a sha-256: prefixed digest");
      return;
    }
    target = { entry_digest: entryDigestValue, condition_digest: conditionDigestValue };
  }
  if (typeof eventType !== "string" || eventType.length === 0) {
    input.sendInvalidRequest("event_type must be a non-empty string");
    return;
  }
  if (typeof eventId !== "string" || !DISCHARGE_EVENT_ID_RE.test(eventId)) {
    input.sendInvalidRequest("event_id must be 1*128 ALPHA / DIGIT / '-' / '_' / ':' / '.'");
    return;
  }
  // `reason` belongs to the state-changing operations; discharge records its own
  // request members in audit, so carrying it is an invalid member combination.
  if (body.reason !== undefined) {
    input.sendInvalidRequest("reason is not used by discharge");
    return;
  }
  const evidenceRef = body.evidence_ref;
  if (evidenceRef !== undefined) {
    if (typeof evidenceRef !== "string" || evidenceRef.length > EVIDENCE_REF_MAX_CHARS) {
      input.sendInvalidRequest(`evidence_ref must be a URI of at most ${EVIDENCE_REF_MAX_CHARS} characters`);
      return;
    }
    try {
      new URL(evidenceRef);
    } catch {
      input.sendInvalidRequest("evidence_ref must be a URI");
      return;
    }
  }
  const evidenceDigest = body.evidence_digest;
  if (evidenceDigest !== undefined && !isFamilyDigest(evidenceDigest)) {
    input.sendInvalidRequest("evidence_digest must be a sha-256: prefixed digest");
    return;
  }
  const observedAt = body.observed_at;
  if (observedAt !== undefined) {
    const parsed =
      typeof observedAt === "string" && RFC3339_RE.test(observedAt) ? Date.parse(observedAt) : Number.NaN;
    if (Number.isNaN(parsed) || Math.abs(parsed - kernel.nowDate().getTime()) > OBSERVED_AT_SKEW_MS) {
      input.sendInvalidRequest("observed_at must be an RFC 3339 date-time within reasonable clock bounds");
      return;
    }
  }
  // @spec control-plane#serialization — the expiry clock OUTSIDE the operation's
  // transaction (#844), as the lifecycle and `contain` handlers keep it: a
  // refused discharge (any not-found class, or a conflict) must never roll back
  // the `expired` transition discovering it committed. Guarded on existence so
  // an unknown Mission still reaches the kernel's DischargeNotFoundError and the
  // one indistinguishable not-found body; it sits outside the `try` so a storage
  // failure here is never disguised as not-found. `kernel.discharge` keeps its
  // own expiry clock for other callers. The walk follows committed `carried_to`
  // correlations too, so a replacement a forwarded discharge may reach keeps
  // the expiry it discovers when the forwarded request is refused. (The walk
  // only materializes expiry; forwarding resolves through Carryover Evidence.)
  const walked = new Set<string>();
  for (let cur = kernel.get(missionId); cur && !walked.has(cur.id); ) {
    walked.add(cur.id);
    kernel.materializeExpiry(cur.id);
    cur = cur.carried_to ? kernel.get(cur.carried_to) : undefined;
  }
  try {
    // @spec control-plane#serialization, control-plane#fresh-observation — the
    // latch, the observation it is reported at and the nonce claim commit as
    // one unit; the signature is the only work left outside, and it adds no
    // recency of its own.
    const signable = withTransaction(kernel.db, () => {
      const { record: described, result } = kernel.discharge(missionId, {
        // The AUTHENTICATED discharge authority, never a request-supplied value.
        authority: principal.principal_id,
        ...target,
        event_type: eventType,
        event_id: eventId,
        ...(typeof evidenceRef === "string" ? { evidence_ref: evidenceRef } : {}),
        ...(typeof evidenceDigest === "string" ? { evidence_digest: evidenceDigest } : {}),
        ...(typeof observedAt === "string" ? { observed_at: observedAt } : {}),
      });
      // @spec discharge#discharge-carryover ("Response") — a forwarded discharge
      // answers a caller NOT authorized for the Mission Status operation with a
      // Discharge Receipt naming only what it targeted.
      if (result.forwarded_from && !input.mayReadStatus(principal)) {
        const receipt = kernel.dischargeReceiptObservation({
          requester: principal.principal_id,
          nonce,
          targetedMissionId: missionId,
          result,
        });
        input.claimResponse?.(
          { kind: "discharge-receipt", receipt: receipt as unknown as Record<string, unknown> },
          DISCHARGE_RECEIPT_MEDIA_TYPE,
          receipt.exp * 1000,
        );
        return { kind: "receipt" as const, receipt };
      }
      // Otherwise the signed Status envelope of the record the result DESCRIBES:
      // the targeted Mission, or the replacement a forwarded discharge changed
      // (its `discharge_result` then carries `forwarded_from`).
      const captured = kernel.observeInCallerTx(described.id, {
        requester: principal.principal_id,
        nonce,
        dischargeResult: result,
      });
      input.claimResponse?.(
        {
          kind: "status-observation",
          observation: captured as unknown as Record<string, unknown>,
        },
        MISSION_STATUS_RESPONSE_MEDIA_TYPE,
        captured.exp * 1000,
      );
      return { kind: "status" as const, observation: captured };
    });
    // @spec discharge#discharge-result — the endpoint's existing signed envelope,
    // state-only (the request carries no `audience`), echoing this request's own
    // nonce, or the receipt: the durable acknowledgement an at-least-once
    // sender stops retrying against.
    if (signable.kind === "receipt") {
      input.sendSigned(DISCHARGE_RECEIPT_MEDIA_TYPE, await kernel.signDischargeReceipt(signable.receipt));
    } else {
      input.sendSigned(MISSION_STATUS_RESPONSE_MEDIA_TYPE, await kernel.signObservation(signable.observation));
    }
  } catch (e) {
    if (e instanceof DischargeNotFoundError) {
      // Every refusal class, indistinguishable on the wire; the reason is
      // recorded issuer-side only (e.reason).
      input.sendNotFound();
      return;
    }
    if (e instanceof DischargeConflictError) {
      input.sendJson(409, { error: "conflict", error_description: e.message, nonce });
      return;
    }
    throw e;
  }
}

/**
 * @spec status#idempotency — read the body ONCE, returning both the parsed
 * members and the digest of the EXACT bytes received. The `nonce` retry rule is
 * byte-identity of the request, so the comparison must be over what arrived,
 * not over a re-serialization of the parse.
 */
async function readBodyWithDigest(
  req: IncomingMessage,
): Promise<{ body: Record<string, unknown>; digest: string }> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const bytes = Buffer.concat(chunks);
  const digest = `${DIGEST_PREFIX}${createHash("sha256").update(bytes).digest("base64url")}`;
  const text = bytes.toString("utf8");
  if (!text) return { body: {}, digest };
  try {
    const parsed: unknown = JSON.parse(text);
    // A valid-JSON body that is not an object (`null`, an array, a number, a
    // string) must land as an EMPTY member set — request-shape validation
    // then refuses it as `invalid_request` — never reach member access and
    // turn into a 500.
    const body =
      parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
        ? (parsed as Record<string, unknown>)
        : {};
    return { body, digest };
  } catch {
    return { body: Object.fromEntries(new URLSearchParams(text)), digest };
  }
}

/** Read a raw text body (e.g. a compact JWS protected-event report). */
async function readTextBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const text = Buffer.concat(chunks).toString("utf8");
  if (!text) return {};
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    return Object.fromEntries(new URLSearchParams(text));
  }
}
