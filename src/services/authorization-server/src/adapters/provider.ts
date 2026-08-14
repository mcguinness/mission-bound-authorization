/**
 * Thin adapters over node-oidc-provider 9.10.0 (decision D30): the provider
 * and custom routes call the mission-kernel only through its interface.
 * Wiring facts verified by the pre-flight spike (src/spikes/SPIKE-REPORT.md).
 */

import { timingSafeEqual } from "node:crypto";
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
import { successorMissionClaim } from "../kernel/expansion.js";
import {
  authorizationDetailsTypesMetadata,
  validateMissionResourceAccessSchema,
} from "../kernel/authorization-details-metadata.js";
import { UnknownProtectedEventError } from "../kernel/containment.js";
import { isSubsetSet, projectThroughEffective } from "../kernel/derive.js";
import type { IssuerEvidenceStore } from "../kernel/issuer-evidence.js";
import { IntentError } from "../kernel/intent.js";
import { GateError, LifecycleConflictError, type MissionKernel } from "../kernel/kernel.js";
import {
  STATUS_LIST_ID,
  STATUS_LIST_MEDIA_TYPE,
  type StatusListPublisher,
} from "../kernel/status-list.js";
import { issueTxnToken, validateChallenge } from "../kernel/txn-challenge.js";
import type { AuthorityEntry, LifecycleOperation, MissionIntent, MissionRecord } from "../kernel/types.js";
import { CHILD_GRANT_TYP, CHILD_JWT_BEARER_GRANT_TYPE } from "./child-grant.js";
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

export interface AdapterOptions {
  issuer: string;
  kernel: MissionKernel;
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
  /** AS-txn signing key + kid: signs txn-bound, single-use approval tokens. */
  txnKey?: CryptoKey;
  txnKid?: string;
  /**
   * The resource's txn-challenge verification keys (its
   * txn_challenge_jwks_uri). Required for the transaction_authorization_endpoint;
   * phase 3 wires it from composeStack, the phase-1 test injects a generated
   * rs-txn pub.
   */
  resourceTxnJwks?: { keys: JWK[] };
  /**
   * AROP transaction task store. The AS vouches for the RS-validated challenge
   * and opens/polls a task here (D37: AS owns the txn pending id, ARS owns the
   * approval). Injected so the AS package takes no dependency on the ARS.
   */
  ars?: TxnArs;
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

/**
 * The subset of the Access Request Service the transaction endpoint uses.
 * Structural so the AS package needs no compile-time dependency on the ARS.
 */
export interface TxnArs {
  openForTxn(input: {
    txn: string;
    missionId: string;
    action: string;
    parameter_digest: string;
    subject: string;
  }): { taskId: string; state: string };
  getTask(taskId: string):
    | {
        state: string;
        approval?: { id: string; approved_at: string; approved_until: string; parameter_digest: string };
      }
    | undefined;
}

/**
 * The AS-side state a `transaction_authorization_id` resolves to. Minted at
 * initiation (the client presents the challenge ONCE), it captures everything
 * the poll needs to issue the txn-token without re-presenting the challenge
 * (openid/authzen#531). Bound to the initiating client via `cnfJkt`.
 */
interface TxnHandle {
  taskId: string;
  txn: string;
  missionId: string;
  cnfJkt: string;
  parameter_digest: string;
  authorizationDetails: AuthorityEntry[];
  subject: string;
  /** The resource the token is audienced to (the challenge's iss). */
  audience: string;
  /** Epoch seconds the challenge expires; drives expires_in on poll responses. */
  expiresAt: number;
}

/** Poll cadence advertised to the client (seconds). */
const TXN_POLL_INTERVAL = 5;

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

  // Containment refresh-path conformance: a stored oidc grant copies its rar
  // at issuance, so a refresh (or a late code redemption) could echo a
  // capability contained AFTER issuance ("derivation MUST NOT carry a
  // contained capability"). Token-response rar resolution therefore
  // re-projects the grant's rar through the Mission's EFFECTIVE authority set
  // (approved minus contained). The Mission resolves from the grant like the
  // async path does: a Mission approval grant via kernel.findByGrant, else a
  // per-delegation family grant via the family store. A grant belonging to no
  // Mission, or to a Mission with no containment, passes through UNCHANGED
  // (the same object: byte-identical fast path).
  const rarThroughContainment = (grant?: { jti?: string; rar?: unknown }): unknown => {
    const rar = grant?.rar;
    if (!Array.isArray(rar) || !grant?.jti) return rar;
    let record = kernel.findByGrant(grant.jti);
    if (!record) {
      const fam = opts.familyStore?.resolve(grant.jti);
      record = fam ? kernel.get(fam.missionId) : undefined;
    }
    if (!record?.containment) return rar;
    const effective = kernel.effectiveAuthoritySet(record);
    const filtered: unknown[] = [];
    for (const detail of rar as Array<{ resource?: string; actions?: string[] }>) {
      const eff = effective.find((e) => e.resource === detail.resource);
      if (!eff) continue; // the whole entry is contained
      if (Array.isArray(detail.actions)) {
        const actions = detail.actions.filter((a) => eff.actions.includes(a));
        if (actions.length === 0) continue; // every action contained
        if (actions.length !== detail.actions.length) {
          filtered.push({ ...detail, actions });
          continue;
        }
      }
      filtered.push(detail);
    }
    return filtered;
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
          rarThroughContainment(ctx.oidc.grant) as never,
        rarForRefreshTokenResponse: (ctx: { oidc: { grant?: { jti?: string; rar?: unknown } } }) =>
          rarThroughContainment(ctx.oidc.grant) as never,
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
        const fam = opts.familyStore?.resolve(grantId);
        if (!fam) return {};
        const famRecord = kernel.get(fam.missionId);
        if (!famRecord) return {};
        try {
          kernel.gateActive(famRecord.id);
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
  // transaction_authorization_id -> handle state. The client presents the
  // challenge ONCE (initiation) and thereafter polls this endpoint WITH the
  // opaque handle the AS minted against the validated challenge (AROP; D42).
  const txnTasks = new Map<string, TxnHandle>();

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

  const requireServiceToken = (ctx: KoaCtx): boolean => {
    if (ctx.get("x-service-token") !== DEV_SERVICE_TOKEN) {
      ctx.status = 401;
      ctx.body = { error: "unauthorized" };
      return false;
    }
    return true;
  };

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
      if (!requireServiceToken(ctx)) return;
      try {
        const jws = await kernel.signedStatus(statusMatch[1] as string, {
          ...optional("audience", str(ctx.query.audience)),
          ...optional("nonce", str(ctx.query.nonce)),
          requester: "svc:console",
        });
        ctx.status = 200;
        ctx.set("content-type", "application/mission-status-response+jwt");
        ctx.set("cache-control", "no-store");
        ctx.body = jws;
      } catch {
        ctx.status = 404;
        ctx.body = { error: "unknown_mission" };
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
      if (!requireServiceToken(ctx)) return;
      const body = await readJsonBody(ctx.req);
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
            ctx.status = 400;
            ctx.body = {
              error: "invalid_request",
              error_description: "contain requires event {type, source, observed_at, event_id} and a non-empty remove[]",
            };
            return;
          }
          const { record, evidence } = kernel.contain(lifecycleMatch[1] as string, {
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
          ctx.status = 200;
          ctx.body = {
            id: record.id,
            state: record.state,
            version: record.version,
            containment_version: record.containment?.containment_version ?? 0,
          };
          return;
        }
        const record = kernel.transition(
          lifecycleMatch[1] as string,
          body.operation as LifecycleOperation,
        );
        // Revocation/terminal states also revoke the OAuth grant so refresh
        // fails structurally, not just by gating.
        if (record.state !== "active" && record.state !== "suspended" && record.grant_id) {
          const grant = await provider.Grant.find(record.grant_id);
          await grant?.destroy();
        }
        ctx.status = 200;
        ctx.body = { id: record.id, state: record.state, version: record.version };
      } catch (e) {
        if (e instanceof LifecycleConflictError) {
          ctx.status = 409;
          ctx.body = { error: "conflict", error_description: e.message };
        } else {
          ctx.status = 404;
          ctx.body = { error: "unknown_mission" };
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

    // --- AROP Transaction Challenge (@spec txn-challenge; openid/authzen#531) ---
    // The client presents its base mission token (DPoP) + the RS-signed
    // txn-challenge; the AS validates + subset-gates against the ACTIVE Mission
    // (D42), obtains approval, and issues a txn-bound single-use token.
    if (ctx.path === "/transaction" && ctx.method === "POST") {
      await handleTransaction(opts, ctx, txnTasks);
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
      meta.transaction_authorization_endpoint = `${opts.issuer}/transaction`;
      // @spec mission#other-types, I-D.draft-zehavi-oauth-rar-metadata — the
      // metadata endpoint is the source of truth for "AS-supported types"; its
      // key set is authorization_details_types_supported (below, already
      // published by the richAuthorizationRequests feature from `types`).
      meta.authorization_details_types_metadata_endpoint = `${opts.issuer}/authorization-details-types`;
    }
  };
}

/**
 * transaction_authorization_endpoint handler. Client-authenticated by its base
 * mission token (DPoP). The body is EITHER `{ challenge }` (initiation: the
 * client presents the RS-signed txn-challenge ONCE) OR
 * `{ transaction_authorization_id }` (poll: the client presents the
 * continuation handle the AS minted at initiation). Initiation validates the
 * challenge, subset-gates against the ACTIVE Mission (D42), opens the ARS task,
 * and returns a pending response carrying the handle; the poll returns the same
 * pending response until approval, then a txn-bound, audience-restricted,
 * single-use token carrying the ACTIVE Mission unchanged plus the verified
 * approval (openid/authzen#531).
 */
async function handleTransaction(
  opts: AdapterOptions,
  ctx: KoaCtx,
  txnTasks: Map<string, TxnHandle>,
) {
  const { kernel } = opts;

  // 1. Base mission token + DPoP proof (the client authenticates with these,
  //    identically for initiation and poll).
  const auth = ctx.get("authorization");
  if (!auth || !auth.startsWith("DPoP ")) {
    ctx.status = 401;
    ctx.body = { error: "invalid_token", error_description: "DPoP-bound base mission token required" };
    return;
  }
  const baseToken = auth.slice("DPoP ".length);
  const proofJws = ctx.get("dpop");
  if (!proofJws) {
    ctx.status = 401;
    ctx.body = { error: "invalid_dpop_proof", error_description: "missing DPoP proof" };
    return;
  }
  let baseClaims: Record<string, unknown>;
  try {
    const { payload } = await jwtVerify(baseToken, createLocalJWKSet(opts.publicJwks as never), {
      issuer: opts.issuer,
    });
    baseClaims = payload as Record<string, unknown>;
  } catch {
    ctx.status = 401;
    ctx.body = { error: "invalid_token" };
    return;
  }
  const cnf = baseClaims.cnf as { jkt?: string } | undefined;
  if (!cnf?.jkt) {
    ctx.status = 401;
    ctx.body = { error: "invalid_token", error_description: "base token missing cnf.jkt" };
    return;
  }
  // Bind the DPoP proof to this endpoint (htu/htm) and to the token's cnf.jkt.
  try {
    const header = decodeProtectedHeader(proofJws);
    const proofJkt = await calculateJwkThumbprint(header.jwk as never);
    if (proofJkt !== cnf.jkt) throw new Error("DPoP key does not match token cnf.jkt");
    const { payload: proof } = await jwtVerify(proofJws, header.jwk as never, { typ: "dpop+jwt" });
    if (proof.htu !== `${opts.issuer}/transaction` || proof.htm !== "POST") {
      throw new Error("DPoP htu/htm mismatch");
    }
  } catch {
    ctx.status = 401;
    ctx.body = { error: "invalid_dpop_proof" };
    return;
  }
  const missionRef = baseClaims.mission as { id?: string } | undefined;
  const missionId = missionRef?.id;
  const subject = baseClaims.sub as string;
  if (!missionId) {
    ctx.status = 401;
    ctx.body = { error: "invalid_token", error_description: "base token missing mission claim" };
    return;
  }

  if (!opts.resourceTxnJwks || !opts.txnKey || !opts.txnKid || !opts.ars) {
    ctx.status = 501;
    ctx.body = { error: "transaction_authorization_unsupported" };
    return;
  }

  // 2. Body: EITHER { challenge } (initiation) OR { transaction_authorization_id } (poll).
  const body = await readJsonBody(ctx.req);

  // --- Poll: resolve the continuation handle minted at initiation. ---
  if (typeof body.transaction_authorization_id === "string") {
    await pollTransaction(opts, ctx, txnTasks, body.transaction_authorization_id, cnf.jkt);
    return;
  }

  // --- Initiation: the client presents the RS-signed txn-challenge ONCE. ---
  const challenge = body.challenge;
  if (typeof challenge !== "string") {
    ctx.status = 400;
    ctx.body = {
      error: "invalid_request",
      error_description: "challenge (initiation) or transaction_authorization_id (poll) required",
    };
    return;
  }

  // Validate the challenge against the resource's txn-challenge keys.
  let claims;
  try {
    claims = await validateChallenge(challenge, opts.resourceTxnJwks, opts.issuer);
  } catch {
    ctx.status = 400;
    ctx.body = { error: "invalid_challenge" };
    return;
  }
  if (!claims.parameter_digest) {
    ctx.status = 400;
    ctx.body = { error: "invalid_challenge", error_description: "parameter_digest required" };
    return;
  }
  const requested = claims.authorization_details as AuthorityEntry[];

  // D42 subset gate: the requested authority MUST be within the ACTIVE Mission.
  // Widening is not an AROP case (that is the separate Expansion flow).
  const record = kernel.get(missionId);
  if (!record) {
    ctx.status = 404;
    ctx.body = { error: "unknown_mission" };
    return;
  }
  const active = kernel.applyExpiry(record);
  if (active.state !== "active") {
    ctx.status = 403;
    ctx.body = { error: "mission_not_active" };
    return;
  }
  // Containment: the txn subset gate measures against the EFFECTIVE set, so a
  // contained capability cannot be laundered through a transaction approval.
  if (!isSubsetSet(requested, kernel.effectiveAuthoritySet(active))) {
    ctx.status = 403;
    ctx.body = { error: "out_of_authority" };
    return;
  }

  // Open the AS-vouched ARS task and mint an opaque continuation handle bound to
  // the validated challenge and to the requesting client (cnf.jkt). The client
  // never re-presents the challenge; it polls with this handle.
  const action = requested[0]?.actions?.[0] ?? claims.reason;
  const { taskId } = opts.ars.openForTxn({
    txn: claims.txn,
    missionId,
    action,
    parameter_digest: claims.parameter_digest,
    subject,
  });
  const transactionAuthorizationId = `txa_${crypto.randomUUID()}`;
  const nowSec = Math.floor(Date.now() / 1000);
  const decoded = decodeJwt(challenge);
  const expiresAt = typeof decoded.exp === "number" ? decoded.exp : nowSec + 300;
  txnTasks.set(transactionAuthorizationId, {
    taskId,
    txn: claims.txn,
    missionId,
    cnfJkt: cnf.jkt,
    parameter_digest: claims.parameter_digest,
    authorizationDetails: requested,
    subject,
    audience: claims.iss, // the resource
    expiresAt,
  });
  ctx.status = 200;
  ctx.body = {
    transaction_authorization_id: transactionAuthorizationId,
    expires_in: Math.max(1, expiresAt - nowSec),
    interval: TXN_POLL_INTERVAL,
  };
}

/**
 * Poll the transaction endpoint with a continuation handle. Unknown handle ->
 * 404; a handle bound to a different client (cnf.jkt mismatch) -> 403. Then, per
 * §5.3 (RFC 8628-shaped): an expired handle -> 400 expired_token (and the handle
 * is reaped); a denied task -> 400 access_denied; still pending -> 400
 * authorization_pending; approved -> 200 with the txn-bound single-use token
 * issued from the STORED challenge state (D42: ACTIVE Mission unchanged) plus
 * the verified approval.
 */
async function pollTransaction(
  opts: AdapterOptions,
  ctx: KoaCtx,
  txnTasks: Map<string, TxnHandle>,
  transactionAuthorizationId: string,
  requesterJkt: string,
) {
  const { kernel } = opts;
  const handle = txnTasks.get(transactionAuthorizationId);
  if (!handle) {
    ctx.status = 404;
    ctx.body = { error: "invalid_request", error_description: "unknown transaction_authorization_id" };
    return;
  }
  // The handle is bound to the client that initiated it.
  if (handle.cnfJkt !== requesterJkt) {
    ctx.status = 403;
    ctx.body = { error: "invalid_token" };
    return;
  }

  // §5.3 (RFC 8628-shaped) poll semantics. The handle expiring is terminal:
  // reap it and report expired_token. Otherwise map the ARS task state -- a
  // denied task is terminal (access_denied, handle kept so the denial is
  // idempotent); anything not yet approved is still authorization_pending.
  if (Math.floor(Date.now() / 1000) >= handle.expiresAt) {
    txnTasks.delete(transactionAuthorizationId);
    ctx.status = 400;
    ctx.body = { error: "expired_token" };
    return;
  }
  const task = opts.ars?.getTask(handle.taskId);
  if (task?.state === "denied") {
    ctx.status = 400;
    ctx.body = { error: "access_denied" };
    return;
  }
  if (!task || task.state !== "approved" || !task.approval) {
    ctx.status = 400;
    ctx.body = { error: "authorization_pending" };
    return;
  }

  // Approved: gate a derivation on the active Mission and issue the txn-bound
  // single-use token carrying the ACTIVE Mission unchanged (D42).
  let gated;
  try {
    gated = kernel.gateDerivation(handle.missionId);
  } catch (e) {
    if (e instanceof GateError) {
      ctx.status = 403;
      ctx.body = { error: "mission_not_active", error_description: e.message };
      return;
    }
    throw e;
  }
  const approval = task.approval;
  const token = await issueTxnToken({
    txn: handle.txn,
    audience: handle.audience, // the resource
    mission: kernel.missionClaim(gated),
    authorizationDetails: handle.authorizationDetails,
    approval: {
      id: approval.id,
      approved_at: approval.approved_at,
      approved_until: approval.approved_until,
      parameter_digest: approval.parameter_digest,
    },
    approvedUntil: approval.approved_until,
    cnfJkt: handle.cnfJkt,
    key: opts.txnKey as CryptoKey,
    kid: opts.txnKid as string,
    issuer: opts.issuer,
  });
  ctx.status = 200;
  ctx.body = { access_token: token, token_type: "DPoP", txn: handle.txn };
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
