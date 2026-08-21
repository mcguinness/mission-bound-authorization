/**
 * Thin adapters over node-oidc-provider 9.10.0 (decision D30): the provider
 * and custom routes call the mission-kernel only through its interface.
 * Wiring facts verified by the pre-flight spike (src/spikes/SPIKE-REPORT.md).
 */

import { createHash, timingSafeEqual } from "node:crypto";
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
  type CryptoKey,
  type JWK,
} from "jose";
import Provider, { errors, type Configuration, type KoaContextWithOIDC, type ResourceServer } from "oidc-provider";

// @types/oidc-provider (9.5) predates InvalidAuthorizationDetails, present at
// runtime in 9.10 (spec traceability: SPEC_VERSIONS O-2 note). Typed alias
// (exported for the token-exchange proposal intake in continuation-grant.ts).
export const InvalidAuthorizationDetails = (errors as unknown as {
  InvalidAuthorizationDetails: new (message?: string) => Error;
}).InvalidAuthorizationDetails;

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

/** Map an intake {@link IntentError} onto its OAuth error class. */
export function intentErrorToOidc(e: IntentError): Error {
  switch (e.code) {
    case "invalid_authorization_details":
      return new InvalidAuthorizationDetails(e.message);
    case "invalid_mission_intent_evidence":
      return new InvalidMissionIntentEvidence(e.message);
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
import {
  authorizationDetailsTypesMetadata,
  validateMissionResourceAccessSchema,
} from "../kernel/authorization-details-metadata.js";
import { UnknownProtectedEventError } from "../kernel/containment.js";
import {
  DIGEST_PREFIX,
  DISCHARGE_EVENT_ID_RE,
  DischargeConflictError,
  DischargeNotFoundError,
  EVIDENCE_REF_MAX_CHARS,
} from "../kernel/discharge.js";
import {
  LIFECYCLE_ENDPOINT_KEY,
  type LifecycleNonceKey,
  LifecycleResponseStore,
} from "../kernel/lifecycle-idempotency.js";
import {
  type EffectiveAuthoritySource,
  isSubsetSet,
  projectRarThroughMission,
  projectThroughEffective,
  SourceUnavailableError,
} from "../kernel/derive.js";
import type { IssuerEvidenceStore } from "../kernel/issuer-evidence.js";
import { IntentError } from "../kernel/intent.js";
import { GateError, LifecycleConflictError, type MissionKernel } from "../kernel/kernel.js";
import {
  STATUS_LIST_ID,
  STATUS_LIST_MEDIA_TYPE,
  type StatusListPublisher,
} from "../kernel/status-list.js";

import type { AuthorityEntry, LifecycleOperation, MissionIntent, MissionRecord } from "../kernel/types.js";
import { CHILD_GRANT_TYP, CHILD_JWT_BEARER_GRANT_TYPE } from "./child-grant.js";
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
  TemplateError,
  type CreateTemplateInput,
  type DispatchReason,
} from "../kernel/template.js";
import type { TemplateStore } from "../kernel/template-store.js";
import { TokenIssuanceStore } from "../kernel/token-issuance-store.js";

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
 * @spec status#discharge-authority — the DISTINCT scope `discharge` requires.
 * Possession of {@link MISSION_LIFECYCLE_SCOPE}, or being the Mission's
 * Subject, Approver, or an administrator, MUST NOT by itself imply it: a
 * `terminal_when` condition is asserted by a resource or event authority, not by
 * whoever may revoke, suspend, resume, or complete the Mission.
 */
export const MISSION_DISCHARGE_SCOPE = "mission_discharge";

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
}

/**
 * The shipped dev token carries BOTH grants, so every existing operational
 * caller keeps working; a deployment (or a test proving non-implication)
 * registers additional tokens, which are merged OVER this default.
 */
export const DEFAULT_SERVICE_TOKEN_PRINCIPALS: Readonly<Record<string, ServiceTokenPrincipal>> = {
  [DEV_SERVICE_TOKEN]: {
    principal_id: "svc:console",
    scopes: [MISSION_LIFECYCLE_SCOPE, MISSION_DISCHARGE_SCOPE],
  },
};

export interface AdapterOptions {
  issuer: string;
  kernel: MissionKernel;
  /**
   * @spec status#discharge-authority — service-token principals and their
   * scopes, merged OVER {@link DEFAULT_SERVICE_TOKEN_PRINCIPALS}. A caller
   * holding `mission_lifecycle` alone is refused `discharge` with the
   * endpoint's `not_found` (an authorization failure never distinguishes
   * itself, @spec status#discharge-anti-oracle).
   */
  serviceTokenPrincipals?: Record<string, ServiceTokenPrincipal>;
  clients: Record<string, unknown>[];
  jwks: { keys: Record<string, unknown>[] };
  publicJwks: { keys: Record<string, unknown>[] };
  /** Test-only headless adjudication (D40): disabled unless set. */
  allowHeadlessAdjudication?: boolean;
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
   * current whole-list token (@spec status#status-list).
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
  /** Trusted Chain Authority issuers of ICAs (iss + jwks). */
  chainAuthorityIssuers?: ContinuationIssuer[];
  /** Shared (iss, jti) ICA replay cache (from newReplayCache()). */
  continuationReplay?: ContinuationReplay;
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

  const configuration: Configuration = {
    clients: opts.clients as never,
    jwks: opts.jwks as never,
    scopes: ["openid", "profile", "email", "payments"],
    // OIDC claims by scope, sourced from the identity store; put them in the
    // id_token itself (not only at userinfo) so the token carries the subject's
    // identity for the demo. `sub` is always present.
    claims: { profile: ["name", "preferred_username"], email: ["email"] },
    conformIdTokenClaims: false,
    issueRefreshToken: async (_ctx, client) => client.grantTypeAllowed("refresh_token"),
    pkce: { required: () => true },
    interactions: { url: (_ctx, interaction) => `/interaction/${interaction.uid}` },
    // @spec mission#downgrade-by-omission — the per-client Mission-governance
    // flag (a deployment MAY register a client as Mission-governed). Declared so
    // oidc-provider retains it on the client registration; read by the RAR
    // validate hook below to reject a governed client's bare
    // authorization_details request.
    extraClientMetadata: { properties: ["mission_governed", "required_intent_evidence_types"] },
    async findAccount(_ctx, id) {
      const user = USERS.find((u) => u.sub === id);
      return {
        accountId: id,
        claims: async () => ({
          sub: id,
          ...(user ? { name: user.name, email: user.email, preferred_username: user.sub } : {}),
        }),
      };
    },
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
      revocation: { enabled: true },
      resourceIndicators: {
        enabled: true,
        defaultResource: () => opts.issuer,
        getResourceServerInfo: (_ctx, resourceIndicator) =>
          resourceServerInfoFor(resourceIndicator, opts.accessTokenTTL ?? 300),
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
        if (value === undefined) return;
        const oidc = (ctx as {
          oidc: { params: Record<string, unknown>; client?: { clientId: string } };
        }).oidc;
        const params = oidc.params;
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
            kernel.validateProposal(proposalRaw, intent.resources);
          }
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
      const record = kernel.findByGrant(grantId);
      if (!record) {
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
        const fam = opts.familyStore?.resolve(grantId);
        const famRecord = fam ? kernel.get(fam.missionId) : missionForBoundGrant(grantId);
        if (!famRecord) return {};
        try {
          // gateActive, never gateDerivation: the SINGLE count of a family (or
          // of the Mission's original issuance) was spent once at issuance
          // (handleAsyncDelegationExchange step 4), so re-gating here checks
          // live state without recounting.
          kernel.gateActive(famRecord.id);
          // The base claim, unchanged from the family fallback's existing
          // behavior: the lineage members of the approval branch below are
          // deliberately not introduced onto this path by #617 review 3, which
          // is about failing closed, not about reshaping a claim that already
          // ships.
          return { mission: kernel.missionClaim(famRecord) };
        } catch (e) {
          if (e instanceof GateError) throw new errors.InvalidGrant(e.message);
          throw e;
        }
      }
      try {
        const gated = kernel.gateDerivation(record.id);
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
        if (e instanceof GateError) throw new errors.InvalidGrant(e.message);
        throw e;
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
    ttl: {
      // @spec async-delegation — absolute-lifetime clamp. A per-delegation family
      // refresh token never outlives its Mission: its lifetime is bounded by the
      // Mission's expires_at. Any other refresh token keeps the oidc-provider
      // default (lib/helpers/defaults.js RefreshTokenTTL, 9.10.0 L397: 14 days). A
      // partial ttl override deep-merges with the defaults, so AccessToken et al.
      // are unaffected. A regular function (not arrow) satisfies checkTTL.
      RefreshToken: function RefreshTokenTTL(_ctx, token) {
        const grantId = (token as { grantId?: string }).grantId;
        const fam = grantId ? opts.familyStore?.resolve(grantId) : undefined;
        if (fam) {
          const record = kernel.get(fam.missionId);
          if (record) {
            return Math.max(1, Math.floor((Date.parse(record.expires_at) - Date.now()) / 1000));
          }
        }
        return 14 * 24 * 60 * 60;
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

  // @spec DTR (draft-gerber-oauth-deferred-token-response-00): the AROP deferred
  // grant on the REAL /token endpoint. Registered AFTER construction so the URN
  // is in configuration.grantTypes before any client is validated (clients are
  // validated lazily on first Client.find, i.e. at request time). `deferral_code`
  // (poll) and `deferred_authorization` (initiation) are declared so the token
  // endpoint does not strip them from ctx.oidc.params.
  if (opts.deferrals) {
    const deferrals = opts.deferrals;
    provider.registerGrantType(
      DEFERRED_GRANT_TYPE,
      (ctx) => handleDeferredGrant(opts, deferrals, provider, ctx),
      new Set(["deferral_code", "deferred_authorization"]),
    );
  }

  // @spec child-delegation#child-client-identity — the RFC 7523 JWT-bearer
  // authorization grant a Child Mission's actor redeems AS ITSELF. Registered
  // UNCONDITIONALLY (not behind an option) so the URN is in configuration.grantTypes
  // before the child client is validated (clients validate lazily at Client.find),
  // and so a child client that lists this grant type is not rejected as
  // invalid_client_metadata. `assertion` is declared in the params set or the
  // token endpoint strips it; client_assertion/_type are auth params and survive.
  provider.registerGrantType(
    CHILD_JWT_BEARER_GRANT_TYPE,
    (ctx) => handleChildJwtBearerGrant(opts, provider, ctx),
    new Set(["assertion"]),
  );

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
  provider.registerGrantType(
    MISSION_DISPATCH_GRANT_TYPE,
    (ctx) => handleMissionDispatchGrant(provider, opts, ctx),
    // `authorization_details` carries the dispatcher's authority proposal
    // (@spec mission#authority-proposal), the same standard carriage as PAR
    // and the child/expansion exchanges; it MUST be declared here or
    // stripGrantIrrelevantParams removes it.
    new Set(["template_id", "mission_intent", "dispatch_event_id", "authorization_details"]),
  );

  // @spec id-continuation-assertion — the RFC 8693 token-exchange grant: an ICA
  // subject token in, a Mission-rooted continuation ID-JAG out. Registered
  // UNCONDITIONALLY (mirrors CHILD_JWT_BEARER_GRANT_TYPE) so a client listing the
  // URN is not rejected as invalid_client_metadata; the handler validates the
  // wiring lazily. Every param the handler reads MUST be in this set or the token
  // endpoint strips it. PINNED empirically by the integration test: `resource` IS
  // stripped for this custom grant unless declared here (the resourceIndicators
  // machinery does NOT retain it), so it is declared. `scope` is not read by the
  // handler and so is not declared. client_assertion/_type are auth params and
  // survive independently.
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
    ]),
  );

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

  provider.use(makeRoutes(provider, opts));
  return provider;
}

/**
 * The resource-server info the AS attaches to every mission-bound JWT access
 * token: audience = the resource, JWT format, `payments` scope, TTL. Shared by
 * the resourceIndicators config and the deferred-grant mint so both project an
 * identical, resource-bound (not opaque) token.
 */
export function resourceServerInfoFor(resource: string, accessTokenTTL: number) {
  return {
    scope: "payments",
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
    scope: "payments",
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
    scope: "payments",
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
  const missionRef = claims.mission as { id?: unknown; authority_hash?: unknown } | undefined;
  const missionId = missionRef?.id;
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
  //    client_id and authority_hash against the assertion (defence in depth against
  //    a stale or tampered assertion).
  if (typeof missionId !== "string") {
    throw new errors.InvalidGrant("child grant assertion missing mission.id");
  }
  const record = kernel.get(missionId);
  if (!record) {
    throw new errors.InvalidGrant("child mission not found");
  }
  if (record.client_id !== assertedClientId || record.authority_hash !== assertedHash) {
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
    grant.addOIDCScope("payments");
    grant.addResourceScope(resource, "payments");
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
    scope: "payments",
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
    scope: "payments",
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

function makeRoutes(provider: Provider, opts: AdapterOptions) {
  const { kernel } = opts;
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

  const serviceTokenPrincipals: Record<string, ServiceTokenPrincipal> = {
    ...DEFAULT_SERVICE_TOKEN_PRINCIPALS,
    ...(opts.serviceTokenPrincipals ?? {}),
  };

  /**
   * @spec status#mission-status-authentication, status#discharge-authority —
   * AUTHENTICATE the operational caller and resolve the principal its token is
   * registered for, with the scopes that token carries. AUTHENTICATION failure
   * (an absent or unregistered token) is the endpoint's only `unauthorized`
   * (401); every AUTHORIZATION failure is the caller's to discover as
   * `not_found`, decided per operation against these scopes.
   */
  const authenticateService = (ctx: KoaCtx): ServiceTokenPrincipal | undefined => {
    const presented = ctx.get("x-service-token");
    const principal = presented ? serviceTokenPrincipals[presented] : undefined;
    if (!principal) {
      ctx.status = 401;
      ctx.body = { error: "unauthorized" };
      return undefined;
    }
    return principal;
  };

  const requireServiceToken = (ctx: KoaCtx): boolean => authenticateService(ctx) !== undefined;

  /**
   * @spec status#discharge-idempotency — the lifecycle endpoint's `nonce`
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
      const proposal =
        typeof params.authorization_details === "string"
          ? kernel.validateProposal(params.authorization_details, intent.resources)
          : undefined;
      const authority = kernel.derive(intent, proposal);
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
      ctx.status = 200;
      ctx.set("content-type", "text/html; charset=utf-8");
      ctx.body = renderApprovalPage(interactionMatch[1] as string, intent, authority, proposal, provenance);
      return;
    }
    const decideMatch = ctx.path.match(/^\/interaction\/([^/]+)\/decide$/);
    if (decideMatch && ctx.method === "POST") {
      if (!opts.allowHeadlessAdjudication && !requireServiceToken(ctx)) return;
      const body = await readJsonBody(ctx.req);
      await decide(provider, opts, ctx, body);
      return;
    }

    // --- Signed Status (@spec status#mission-status-response) ---
    const statusMatch = ctx.path.match(/^\/missions\/([^/]+)\/status$/);
    if (statusMatch && ctx.method === "GET") {
      const principal = authenticateService(ctx);
      if (!principal) return;
      const statusNonce = str(ctx.query.nonce);
      try {
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

    // --- Mission Status List whole-list fetch (@spec status#status-list) ---
    // Deliberately unauthenticated (NOT behind requireServiceToken): the fetch
    // covers every opaque index at once and reveals no per-mission interest, so
    // it is anti-oracle-safe by design (@spec status#mission-status-anti-oracle).
    // The per-mission status_list.uri and the token's `sub` both equal this URL.
    const statusListMatch = ctx.path.match(/^\/statuslist\/([^/]+)$/);
    if (statusListMatch && ctx.method === "GET") {
      if (statusListMatch[1] !== STATUS_LIST_ID || !opts.statusListPublisher) {
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
        ctx.status = status;
        ctx.set("content-type", contentType);
        ctx.set("cache-control", "no-store");
        ctx.body = text;
        if (nonceKey) {
          lifecycleResponses.record(nonceKey, { requestDigest: digest, status, contentType, body: text });
        }
      };
      const sendJson = (status: number, json: Record<string, unknown>): void =>
        send(status, "application/json", JSON.stringify(json));
      /**
       * @spec status#mission-status-errors, status#discharge-anti-oracle — the
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
      // @spec status#idempotency — the retransmission rule, evaluated FIRST:
      // it governs the HTTP exchange, before any operation is re-executed.
      if (nonceKey) {
        const stored = lifecycleResponses.find(nonceKey);
        if (stored) {
          if (stored.requestDigest !== digest) {
            // Never answered with the unrelated original response.
            sendInvalidRequest("nonce was already used with a different request");
            return;
          }
          ctx.status = stored.status;
          ctx.set("content-type", stored.contentType);
          ctx.set("cache-control", "no-store");
          ctx.body = stored.body;
          return;
        }
      }
      // @spec status#discharge-operation — the fifth operation: it changes no
      // Mission state, so it is handled entirely outside the state machine
      // below, under its own DISTINCT authority.
      if (body.operation === "discharge") {
        await handleDischarge({
          kernel,
          principal,
          missionId,
          body,
          ...(nonce !== undefined ? { nonce } : {}),
          sendJws: (jws) => send(200, MISSION_STATUS_RESPONSE_MEDIA_TYPE, jws),
          sendJson,
          sendNotFound,
          sendInvalidRequest,
        });
        return;
      }
      // @spec status#authorization — every other operation is a Mission-state
      // transition and requires the lifecycle grant; an authenticated caller
      // without it is refused with the not-found shape, never a 403.
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
          const { record, evidence } = kernel.contain(missionId, {
            event: {
              type: event.type,
              source: event.source,
              observed_at: event.observed_at,
              event_id: event.event_id,
            },
            remove: remove as Array<{ resource: string; actions?: string[] }>,
          });
          // Retain the returned Containment Evidence issuer-side (break-glass
          // path: its evidence `policy` is "manual"). Previously discarded.
          opts.issuerEvidence?.retainContainment(evidence);
          sendJson(200, {
            id: record.id,
            state: record.state,
            version: record.version,
            containment_version: record.containment?.containment_version ?? 0,
          });
          return;
        }
        const record = kernel.transition(missionId, body.operation as LifecycleOperation);
        // Revocation/terminal states also revoke the OAuth grant so refresh
        // fails structurally, not just by gating.
        if (record.state !== "active" && record.state !== "suspended" && record.grant_id) {
          const grant = await provider.Grant.find(record.grant_id);
          await grant?.destroy();
        }
        sendJson(200, { id: record.id, state: record.state, version: record.version });
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
      if (!sources || !issuerEvidence) {
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
        const effective = kernel.effectiveAuthoritySet(record);
        const narrowed = projectThroughEffective(credentialAuthority, effective);
        const resourceSet = resourcesForAudiences(visibleAudiences, principal.audience_resources);
        const authorization_details = narrowed.filter((e) => resourceSet.has(e.resource));
        ctx.body = {
          active: true,
          iss: opts.issuer,
          ...(rt.accountId ? { sub: rt.accountId } : {}),
          ...(rt.clientId ? { client_id: rt.clientId } : {}),
          ...(typeof rt.exp === "number" ? { exp: rt.exp } : {}),
          ...(typeof rt.iat === "number" ? { iat: rt.iat } : {}),
          ...(rt.jti ? { jti: rt.jti } : {}),
          ...(rt.jkt ? { cnf: { jkt: rt.jkt } } : {}),
          authorization_details,
          mission,
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

        // @spec mission#the-mission-claim — the Mission profile's claim
        // shape, when a `mission` member is present at all; its total
        // ABSENCE is the pre-existing, distinct "unresolvable" case handled
        // by the Mission lookup below (never Mission-bound), not a
        // malformed shape.
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
            typeof m.authority_hash !== "string" ||
            !m.authority_hash
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
        const missionId = (payload.mission as { id?: string } | undefined)?.id;
        const record = missionId ? kernel.get(missionId) : undefined;
        if (!record) {
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
        const effective = kernel.effectiveAuthoritySet(record);
        const narrowed = projectThroughEffective(credentialAuthority, effective);
        const resourceSet = resourcesForAudiences(visible, principal.audience_resources);
        const authorization_details = narrowed.filter((e) => resourceSet.has(e.resource));

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
          mission,
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
          ...(opts.txnAuthorization ? { txn: opts.txnAuthorization } : {}),
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
      if (!opts.templateStore) {
        ctx.status = 501;
        ctx.body = { error: "temporarily_unavailable" };
        return;
      }
      const body = await readJsonBody(ctx.req);
      try {
        const template = createTemplate(opts.templateStore, body as unknown as CreateTemplateInput);
        ctx.status = 201;
        ctx.body = {
          template_id: template.id,
          template_version: template.template_version,
          template_hash: template.template_hash,
        };
      } catch (e) {
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
      if (!opts.templateStore) {
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

    await next();

    // --- AS metadata flags (@spec mission#as-metadata) ---
    if (ctx.path === "/.well-known/openid-configuration" && ctx.status === 200) {
      const meta = ctx.body as Record<string, unknown>;
      meta.mission_bound_authorization_supported = true;
      // @spec attenuation#request-discovery: this AS issues Mission-bound
      // attenuation roots and derives their authority from the Authority Set.
      meta.mission_attenuation_supported = true;
      // @spec child-delegation#discovery: this AS accepts the child-creation
      // request and enforces the child-delegation controls of that profile.
      meta.mission_child_delegation_supported = true;
      // @spec id-continuation-assertion#discovery: this AS runs the RFC 8693
      // token-exchange continuation grant (ICA subject token -> continuation
      // ID-JAG), signed by the dedicated as-continuation key on the jwks_uri.
      meta.identity_continuation_supported = true;
      // @spec async-delegation#discovery: this AS runs the async-delegation
      // continuation transport (RFC 8693 token exchange with request_refresh_token
      // -> a per-delegation grant with a rotated, sender-constrained refresh token).
      meta.delegated_refresh_token_profile_supported = true;
      meta.service_catalog_endpoint = `${opts.issuer}/service-catalog`;
      meta.introspection_endpoint = `${opts.issuer}/introspect`;
      // @spec mission#caller-authorization-and-minimization (cleanup, issue
      // #541) — advertise the introspection endpoint's actual authentication
      // method (registered-principal HTTP Basic, authenticateIntrospection
      // above), matching RFC 8414's *_endpoint_auth_methods_supported idiom.
      meta.introspection_endpoint_auth_methods_supported = ["client_secret_basic"];
      // @spec txn-authorization#challenge-redemption — advertised only where the
      // endpoint is CONFIGURED. An AS without transaction authorization answers
      // 501 there, and advertising it would send clients to a dead endpoint.
      if (opts.txnAuthorization) meta.transaction_authorization_endpoint = `${opts.issuer}/transaction`;
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
 * `recipient_not_allowed`/`template_not_active` ride `access_denied`;
 * `out_of_template_ceiling`/`dispatch_prohibited_class`/`max_active_exceeded`/
 * `rate_exceeded` ride `invalid_request`.
 */
function dispatchErrorCode(reason: DispatchReason): "invalid_request" | "access_denied" {
  switch (reason) {
    case "dispatcher_not_allowed":
    case "recipient_not_allowed":
    case "template_not_active":
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
  // and its recipient BEFORE dispatch, and to control the unknown-template reply
  // (dispatchFromTemplate throws a plain Error for unknown ids).
  const template = store.get(templateId);
  if (!template) {
    ctx.status = 400;
    ctx.body = { error: "invalid_request", error_description: "unknown template" };
    return;
  }
  const recipient = template.recipients[0];
  if (!recipient) {
    ctx.status = 400;
    ctx.body = { error: "invalid_request", error_description: "template names no recipient" };
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
  // @spec mission#intent-submission-evidence — STAGE-2 verification (required
  // types resolved BEFORE derivation; the presenter is the AUTHENTICATED
  // dispatcher). Dispatch has its own idempotency (dispatch_event_id inside
  // dispatchFromTemplate) but no D69 creation fingerprint; verification runs
  // here on every dispatch request, and a retried dispatch of a completed
  // event recovers below regardless of these facts (same instance returned).
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
      const proposal = kernel.validateProposal(proposalRaw, intent.resources);
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

  // Core-consistency: the Dispatcher does NOT name the Subject; the Issuer
  // establishes it. The template carries the consenting human (approver); the
  // subject is established from it (decide() defaults subject to approver, and
  // read-only missions may self-approve, D37). Recipient comes from the template.
  let record: MissionRecord;
  try {
    ({ mission: record } = dispatchFromTemplate(kernel, store, {
      templateId,
      dispatchEventId,
      dispatcher: client.clientId,
      recipient,
      intent,
      ...(proposedAuthority ? { proposedAuthority } : {}),
      ...(submissionEvidence?.length ? { submissionEvidence } : {}),
      subject: { iss: template.issuer, sub: template.approver.sub },
      policyVersion: DERIVATION_POLICY.policy_version,
      dispatchProhibitedActions: DISPATCH_PROHIBITED_ACTIONS,
    }));
  } catch (e) {
    if (e instanceof DispatchError) {
      const code = dispatchErrorCode(e.reason);
      ctx.status = code === "access_denied" ? 403 : 400;
      // Set status/body DIRECTLY (status before body) so mission_denial_reason
      // survives oidc-provider's err_out renderer (same pattern as child creation).
      ctx.body = { error: code, mission_denial_reason: e.reason };
      ctx.set("cache-control", "no-store");
      return;
    }
    ctx.status = 400;
    ctx.body = { error: "invalid_request", error_description: e instanceof Error ? e.message : "dispatch failed" };
    return;
  }

  // ---- mint mission-bound access token: INLINE COPY of handleChildJwtBearerGrant
  // (~806-879). DPoP-bind from the request proof (unchanged). The Grant and the
  // AccessToken are owned by `client` (the DISPATCHER, the authenticated entity
  // here) rather than by `record.client_id` (the recipient, who is not present
  // in this exchange) — the one substitution the child-bearer code does not need,
  // because there record.client_id IS the authenticated client.
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

  // Containment: every copy of the instance's authority into rar/authorization_
  // details projects the EFFECTIVE set (approved minus containment overlay).
  const effective = kernel.effectiveAuthoritySet(record);
  const resource = effective[0]?.resource ?? opts.issuer;
  let grantId: string;
  if (record.grant_id) {
    grantId = record.grant_id;
  } else {
    const grant = new provider.Grant({ accountId: record.subject.sub, clientId: client.clientId });
    grant.addOIDCScope("payments");
    grant.addResourceScope(resource, "payments");
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
    scope: "payments",
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
    mission_id: record.id,
    authorization_details: effective,
  };
  ctx.set("cache-control", "no-store");
}

async function decide(
  provider: Provider,
  opts: AdapterOptions,
  ctx: KoaCtx,
  body: Record<string, unknown>,
) {
  const details = await provider.interactionDetails(ctx.req, ctx.res);
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
  const proposedAuthority =
    typeof params.authorization_details === "string"
      ? opts.kernel.validateProposal(params.authorization_details, intent.resources)
      : undefined;
  const approver = String(body.approver ?? "");
  const subject = String(body.subject ?? approver);

  if (body.decision !== "approve") {
    await provider.interactionFinished(ctx.req, ctx.res, {
      error: "access_denied",
      error_description: "approver denied the mission",
    });
    return;
  }

  const authority = opts.kernel.derive(intent, proposedAuthority);
  // Governance (D37): write-bearing missions require subject != approver
  // with the approver role; read-only may self-approve.
  const writeBearing = authority.some((e) => e.actions.some((a) => WRITE_ACTIONS.has(a)));
  if (writeBearing && (approver === subject || !opts.approverRoleSubs.has(approver))) {
    ctx.status = 403;
    ctx.body = { error: "approval_forbidden", error_description: "write-bearing missions require a distinct approver" };
    return;
  }

  const record = opts.kernel.approve({
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

  const grant = new provider.Grant({ accountId: subject, clientId: String(params.client_id) });
  // Grant exactly the requested scopes (openid enables an id_token when asked).
  grant.addOIDCScope(typeof params.scope === "string" ? params.scope : "payments");
  // Containment: the grant's rar copies the EFFECTIVE set. A freshly approved
  // Mission has no containment, so this is the approved set as-is (fast path).
  const effective = opts.kernel.effectiveAuthoritySet(record);
  const resource = effective[0]?.resource ?? opts.issuer;
  grant.addResourceScope(resource, "payments");
  for (const entry of effective) {
    (grant as unknown as { addRar: (d: unknown) => void }).addRar(entry);
  }
  const grantId = await grant.save();
  opts.kernel.bindGrant(record.id, grantId);

  await provider.interactionFinished(ctx.req, ctx.res, {
    login: { accountId: subject },
    consent: { grantId },
  });
}

function renderApprovalPage(
  uid: string,
  intent: unknown,
  authority: unknown,
  proposal?: unknown,
  provenance?: unknown[],
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
  return `<!doctype html><title>Mission approval</title>
<h1>Approve mission?</h1>
<h2>Intent (task context, untrusted)</h2><pre>${escapeHtml(JSON.stringify(intent, null, 2))}</pre>
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
 * @spec status#discharge-operation ("observed_at") — the caller's asserted
 * observation time is validated for syntax and REASONABLE CLOCK BOUNDS only,
 * never as trusted ordering or freshness. One day either side of the AS's own
 * clock; the AS records its own commit time as `received_at` regardless.
 */
const OBSERVED_AT_SKEW_MS = 24 * 60 * 60 * 1000;

/** A prefixed digest of the family's only defined algorithm. */
function isFamilyDigest(value: unknown): value is string {
  return typeof value === "string" && value.startsWith(DIGEST_PREFIX) && value.length > DIGEST_PREFIX.length;
}

/**
 * @spec status#discharge-operation, status#discharge-anti-oracle,
 * status#discharge-result — the `discharge` operation on the Mission Lifecycle
 * endpoint. Request-shape failures are `invalid_request`; the six selector,
 * membership, and target-authorization refusals are ONE `not_found`; a divergent
 * re-assertion of the same event tuple is `conflict`; success is the endpoint's
 * signed Mission Status Response envelope carrying `discharge_result` as a
 * sibling of `mission`.
 */
async function handleDischarge(input: {
  kernel: MissionKernel;
  principal: ServiceTokenPrincipal;
  missionId: string;
  body: Record<string, unknown>;
  nonce?: string;
  sendJws: (jws: string) => void;
  sendJson: (status: number, json: Record<string, unknown>) => void;
  sendNotFound: () => void;
  sendInvalidRequest: (description: string, echoNonce?: boolean) => void;
}): Promise<void> {
  const { kernel, principal, missionId, body, nonce } = input;
  // @spec status#discharge-operation — `nonce` is REQUIRED, and a request whose
  // nonce is absent or malformed is refused with NO nonce echoed.
  if (nonce === undefined) {
    input.sendInvalidRequest("discharge requires a well-formed nonce", false);
    return;
  }
  // @spec status#discharge-authority — the DISTINCT grant, checked before any
  // selector work. A caller holding only `mission_lifecycle` (or acting as the
  // Subject, Approver, or an administrator) is refused with the same
  // indistinguishable not-found body every unauthorized reference gets.
  if (!principal.scopes.includes(MISSION_DISCHARGE_SCOPE)) {
    input.sendNotFound();
    return;
  }
  const entryDigestValue = body.entry_digest;
  const conditionDigestValue = body.condition_digest;
  const eventType = body.event_type;
  const eventId = body.event_id;
  if (!isFamilyDigest(entryDigestValue)) {
    input.sendInvalidRequest("entry_digest must be a sha-256: prefixed digest");
    return;
  }
  if (!isFamilyDigest(conditionDigestValue)) {
    input.sendInvalidRequest("condition_digest must be a sha-256: prefixed digest");
    return;
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
    const parsed = typeof observedAt === "string" ? Date.parse(observedAt) : Number.NaN;
    if (Number.isNaN(parsed) || Math.abs(parsed - kernel.nowDate().getTime()) > OBSERVED_AT_SKEW_MS) {
      input.sendInvalidRequest("observed_at must be an RFC 3339 date-time within reasonable clock bounds");
      return;
    }
  }
  try {
    const { result } = kernel.discharge(missionId, {
      // The AUTHENTICATED discharge authority, never a request-supplied value.
      authority: principal.principal_id,
      entry_digest: entryDigestValue,
      condition_digest: conditionDigestValue,
      event_type: eventType,
      event_id: eventId,
      ...(typeof evidenceRef === "string" ? { evidence_ref: evidenceRef } : {}),
      ...(typeof evidenceDigest === "string" ? { evidence_digest: evidenceDigest } : {}),
      ...(typeof observedAt === "string" ? { observed_at: observedAt } : {}),
    });
    // @spec status#discharge-result — the endpoint's existing signed envelope,
    // state-only (the request carries no `audience`), echoing this request's own
    // nonce: the durable acknowledgement an at-least-once sender stops retrying
    // against.
    const jws = await kernel.signedStatus(missionId, {
      requester: principal.principal_id,
      nonce,
      dischargeResult: result,
    });
    input.sendJws(jws);
  } catch (e) {
    if (e instanceof DischargeNotFoundError) {
      // All six refusal classes, indistinguishable on the wire; the reason is
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
    return { body: JSON.parse(text) as Record<string, unknown>, digest };
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
