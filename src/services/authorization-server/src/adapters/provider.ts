/**
 * Thin adapters over node-oidc-provider 9.10.0 (decision D30): the provider
 * and custom routes call the mission-kernel only through its interface.
 * Wiring facts verified by the pre-flight spike (src/spikes/SPIKE-REPORT.md).
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { DEV_SERVICE_TOKEN, USERS, WRITE_ACTIONS } from "@mission/demo-data";
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
// runtime in 9.10 (spec traceability: SPEC_VERSIONS O-2 note). Typed alias.
const InvalidAuthorizationDetails = (errors as unknown as {
  InvalidAuthorizationDetails: new (message?: string) => Error;
}).InvalidAuthorizationDetails;
import {
  DEFERRED_GRANT_TYPE,
  DeferralError,
  type DeferralStore,
  type DeferredToken,
} from "../kernel/deferred.js";
import {
  ChildDelegationError,
  type ChildDenialReason,
  childMissionClaim,
  createChildMission,
} from "../kernel/child-delegation.js";
import { isSubsetSet } from "../kernel/derive.js";
import { IntentError } from "../kernel/intent.js";
import { GateError, LifecycleConflictError, type MissionKernel } from "../kernel/kernel.js";
import {
  STATUS_LIST_ID,
  STATUS_LIST_MEDIA_TYPE,
  type StatusListPublisher,
} from "../kernel/status-list.js";
import { issueTxnToken, validateChallenge } from "../kernel/txn-challenge.js";
import type { AuthorityEntry, LifecycleOperation, MissionIntent, MissionRecord } from "../kernel/types.js";
import { CHILD_GRANT_TYP, CHILD_JWT_BEARER_GRANT_TYPE, mintChildGrant } from "./child-grant.js";
import {
  type ContinuationReplay,
  handleTokenExchangeGrant,
  type SubjectResolver,
  TOKEN_EXCHANGE_GRANT_TYPE,
} from "./continuation-grant.js";
import type { ContinuationIssuer } from "../kernel/continuation-assertion.js";
import type { ContinuationStore } from "../kernel/continuation-store.js";
import type { DelegationFamilyStore } from "../kernel/delegation-family-store.js";

/**
 * IMPL-LOCAL grant type for Child Mission CREATION on the real /token endpoint.
 * The child-delegation draft does NOT register a creation grant type (its IANA
 * section registers only the PAR params `parent`/`parent_token`/`child_actor`,
 * the discovery flag, and the denial reasons); the draft models creation as PAR +
 * adjudication. Relocating creation onto /token is the house rule "no new
 * endpoints when an existing surface carries it" applied on top of the draft, so
 * this URN is an implementation choice, mirroring DEFERRED_GRANT_TYPE's shape for
 * in-repo consistency. It is DISTINCT from CHILD_JWT_BEARER_GRANT_TYPE (the grant
 * the child redeems AS ITSELF).
 */
export const CHILD_CREATION_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:mission-child-creation";

export interface AdapterOptions {
  issuer: string;
  kernel: MissionKernel;
  clients: Record<string, unknown>[];
  jwks: { keys: Record<string, unknown>[] };
  publicJwks: { keys: Record<string, unknown>[] };
  /** Test-only headless adjudication (D40): disabled unless set. */
  allowHeadlessAdjudication?: boolean;
  approverRoleSubs: Set<string>;
  /** Access-token lifetime (seconds) for issued mission tokens. Default 300. */
  accessTokenTTL?: number;
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
        rarForAuthorizationCode: (ctx: { oidc: { grant?: { rar?: unknown } } }) =>
          ctx.oidc.grant?.rar as never,
        rarForCodeResponse: (ctx: { oidc: { grant?: { rar?: unknown } } }) =>
          ctx.oidc.grant?.rar as never,
        rarForRefreshTokenResponse: (ctx: { oidc: { grant?: { rar?: unknown } } }) =>
          ctx.oidc.grant?.rar as never,
        types: {
          mission_resource_access: {
            validate: () => {
              // Raw client submission of the issuer-derived type is refused;
              // authority is proposed only inside the Intent.
              // @spec mission#submission-via-par
              throw new InvalidAuthorizationDetails(
                "mission_resource_access is issuer-derived; propose authority via mission_intent",
              );
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
      // @spec mission#submission-via-par — PAR-only carriage + exclusions.
      async mission_intent(ctx, value) {
        if (value === undefined) return;
        const params = (ctx as { oidc: { params: Record<string, unknown> } }).oidc.params;
        if (params.authorization_details !== undefined) {
          throw new errors.InvalidRequest("mission_intent and authorization_details are mutually exclusive");
        }
        try {
          kernel.validateIntent(String(value));
        } catch (e) {
          if (e instanceof IntentError) {
            throw e.code === "invalid_request"
              ? new errors.InvalidRequest(e.message)
              : new InvalidAuthorizationDetails(e.message);
          }
          throw e;
        }
      },
      // @spec child-delegation#child-creation — the Parent Mission id. Cross-check
      // and audit value only; the authoritative parent is resolved from
      // parent_token in the back-channel handler. Registered (null validator) so
      // oidc-provider carries it through PAR rather than stripping it.
      parent: null,
      // @spec child-delegation#child-creation — the parent grant. It is a
      // BACK-CHANNEL credential: it MUST be pushed via PAR and MUST NOT appear on
      // a front-channel authorization request. On any route other than PAR
      // (notably a request_uri resolved at /auth, which rehydrates the pushed
      // params before this validator re-runs) reject with invalid_request.
      // @spec child-delegation#denial-reasons.
      async parent_token(ctx, value) {
        if (value === undefined) return;
        const oidc = (ctx as { oidc: { route?: string; params: Record<string, unknown> } }).oidc;
        if (oidc.route !== "pushed_authorization_request") {
          throw new errors.InvalidRequest("parent_token is a back-channel credential; submit it via PAR");
        }
        // Child creation carries mission_intent + parent + parent_token + child_actor.
        const p = oidc.params;
        if (p.mission_intent === undefined || p.parent === undefined || p.child_actor === undefined) {
          throw new errors.InvalidRequest(
            "child creation requires mission_intent, parent, parent_token, and child_actor",
          );
        }
      },
      // @spec child-delegation#child-creation — the child actor object. Shape only
      // here (the fan-out actor gating runs in the kernel); carried through PAR.
      async child_actor(ctx, value) {
        if (value === undefined) return;
        let obj: unknown;
        try {
          obj = JSON.parse(String(value));
        } catch {
          throw new errors.InvalidRequest("child_actor must be a JSON object");
        }
        if (
          obj === null ||
          typeof obj !== "object" ||
          Array.isArray(obj) ||
          typeof (obj as { sub?: unknown }).sub !== "string"
        ) {
          throw new errors.InvalidRequest("child_actor requires a string sub");
        }
      },
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
        // @spec child-delegation#parent-member — a Child Mission projects the
        // `parent` lineage member; a root Mission (no parent) projects the base
        // claim. gateDerivation already ran the child active-state + ancestor-active
        // gate and incremented derivation_count EXACTLY ONCE (the child-redemption
        // handler deliberately does not gate, so there is no double-increment).
        const claim = gated.parent ? childMissionClaim(kernel, gated) : kernel.missionClaim(gated);
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

  // @spec child-delegation#child-creation, #request-processing, #protocol-flow —
  // Child Mission CREATION on the real /token endpoint (impl-local grant, see
  // CHILD_CREATION_GRANT_TYPE). Client authentication (private_key_jwt) runs BEFORE
  // this handler, so ctx.oidc.client is the AUTHENTICATED parent — the real
  // authentication that satisfies #request-processing step 1 and replaces the
  // dev-grade x-service-token stand-in the retired POST /child-missions route used.
  // `request_uri` MUST be in the params set or stripGrantIrrelevantParams removes it.
  provider.registerGrantType(
    CHILD_CREATION_GRANT_TYPE,
    (ctx) => handleChildCreationGrant(provider, opts, ctx),
    new Set(["request_uri"]),
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
    (ctx) => handleTokenExchangeGrant(opts, ctx),
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
function resourceServerInfoFor(resource: string, accessTokenTTL: number) {
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
function newResourceServer(
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
  try {
    const header = decodeProtectedHeader(proofJws);
    jkt = await calculateJwkThumbprint(header.jwk as JWK);
    const { payload: proof } = await jwtVerify(proofJws, header.jwk as JWK, { typ: "dpop+jwt" });
    if (proof.htu !== `${opts.issuer}/token` || proof.htm !== "POST") {
      throw new Error("DPoP htu/htm mismatch");
    }
  } catch {
    throw new errors.InvalidRequest("invalid DPoP proof");
  }

  const resource =
    deferred.authorization_details[0]?.resource ?? record.authority_set[0]?.resource ?? opts.issuer;
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
  //    directly (same technique handleChildCreationGrant uses for mission_denial_reason).
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
  try {
    const header = decodeProtectedHeader(proofJws);
    jkt = await calculateJwkThumbprint(header.jwk as JWK);
    const { payload: proof } = await jwtVerify(proofJws, header.jwk as JWK, { typ: "dpop+jwt" });
    if (proof.htu !== `${opts.issuer}/token` || proof.htm !== "POST") {
      throw new Error("DPoP htu/htm mismatch");
    }
  } catch {
    throw new errors.InvalidRequest("invalid DPoP proof");
  }

  // 6. Bind an oidc Grant to the child LAZILY (mirror the `decide` path). Do NOT
  //    call gateDerivation here: extraTokenClaims runs it during save() and a
  //    second call would double-increment derivation_count. Binding the grant is
  //    what makes findByGrant(grantId) resolve to the child inside that hook, so
  //    the child `mission` claim is attached (never hand-set). The Grant and the
  //    AccessToken name the SAME client (record.client_id == the authenticated
  //    client, guaranteed by steps 3-4), which oidc-provider requires.
  const resource = record.authority_set[0]?.resource ?? opts.issuer;
  let grantId: string;
  if (record.grant_id) {
    grantId = record.grant_id;
  } else {
    const grant = new provider.Grant({ accountId: record.subject.sub, clientId: record.client_id });
    grant.addOIDCScope("payments");
    grant.addResourceScope(resource, "payments");
    for (const entry of record.authority_set) {
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
    rar: record.authority_set,
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
    authorization_details: record.authority_set,
  };
  ctx.set("cache-control", "no-store");
}

function makeRoutes(provider: Provider, opts: AdapterOptions) {
  const { kernel } = opts;
  const jwksResolver = createLocalJWKSet(opts.publicJwks as never);
  // transaction_authorization_id -> handle state. The client presents the
  // challenge ONCE (initiation) and thereafter polls this endpoint WITH the
  // opaque handle the AS minted against the validated challenge (AROP; D42).
  const txnTasks = new Map<string, TxnHandle>();

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
      const raw = (details.params as Record<string, unknown>).mission_intent;
      const intent = kernel.validateIntent(String(raw));
      const authority = kernel.derive(intent);
      ctx.status = 200;
      ctx.set("content-type", "text/html; charset=utf-8");
      ctx.body = renderApprovalPage(interactionMatch[1] as string, intent, authority);
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

    // --- Lifecycle operations (@spec status#legal-transitions) ---
    const lifecycleMatch = ctx.path.match(/^\/missions\/([^/]+)\/lifecycle$/);
    if (lifecycleMatch && ctx.method === "POST") {
      if (!requireServiceToken(ctx)) return;
      const body = await readJsonBody(ctx.req);
      try {
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

    // --- Adapter introspection (@spec mission#introspection; RFC 7662) ---
    // JWT ATs cannot use the provider's introspection endpoint (spike
    // finding); this route mirrors the JWT claim set per CIA-CORE.
    if (ctx.path === "/introspect" && ctx.method === "POST") {
      if (!requireServiceToken(ctx)) return;
      const body = await readJsonBody(ctx.req);
      ctx.status = 200;
      try {
        const { payload } = await jwtVerify(String(body.token), jwksResolver);
        const mission = payload.mission as { id?: string } | undefined;
        const record = mission?.id ? kernel.get(mission.id) : undefined;
        ctx.body = {
          active: true,
          iss: payload.iss,
          sub: payload.sub,
          aud: payload.aud,
          client_id: payload.client_id,
          exp: payload.exp,
          iat: payload.iat,
          jti: payload.jti,
          cnf: payload.cnf,
          ...(record ? { mission: kernel.introspectionMission(record) } : {}),
        };
      } catch {
        ctx.body = { active: false };
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
    // CREATION now lives on the real /token endpoint as the CHILD_CREATION_GRANT_TYPE
    // grant (registered above), authenticated by the parent's private_key_jwt. The
    // bespoke back-channel POST /child-missions route was retired in favour of that
    // existing OAuth surface; see handleChildCreationGrant.

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
      meta.transaction_authorization_endpoint = `${opts.issuer}/transaction`;
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
  if (!isSubsetSet(requested, active.authority_set)) {
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
function childErrorCode(reason: ChildDenialReason): string {
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
 * @spec child-delegation#child-creation, #request-processing, #protocol-flow — the
 * child-creation handler, now on the real /token endpoint as the impl-local
 * CHILD_CREATION_GRANT_TYPE grant. The parent has already pushed the child-creation
 * params via PAR and presents the request_uri here, authenticating with
 * private_key_jwt; oidc-provider's client-auth middleware runs BEFORE this handler,
 * so ctx.oidc.client is the AUTHENTICATED parent (#request-processing step 1). Runs
 * the ~11-step order end-to-end: bind the authenticated client, resolve the Parent
 * Mission from parent_token (RESOLVE-ONLY: find() does not consume or rotate and the
 * refresh_token grant is never invoked, so replay detection does not fire),
 * cross-check the `parent` param, then createChildMission (steps 4-11), and mint the
 * child-bound RFC 7523 JWT authorization grant the child redeems AS ITSELF
 * (redemption handled by handleChildJwtBearerGrant). Child credentials never transit
 * the parent: the returned assertion is redeemable only by the named child actor.
 * Denials set ctx.status/body DIRECTLY (status before body) so the
 * `mission_denial_reason` carrier survives -- oidc-provider's err_out renderer would
 * strip any member other than error/error_description.
 */
async function handleChildCreationGrant(provider: Provider, opts: AdapterOptions, ctx: KoaContextWithOIDC) {
  const { kernel } = opts;
  const PUSHED_REQUEST_URN = "urn:ietf:params:oauth:request_uri:";
  const params = ctx.oidc.params as Record<string, unknown>;

  // Step 1: bind the AUTHENTICATED client (private_key_jwt ran before this handler)
  // and resolve the PAR the parent pushed. The request_uri is the capability the
  // PAR (also client-authenticated) minted.
  const client = ctx.oidc.client as NonNullable<typeof ctx.oidc.client>;
  const requestUri = typeof params.request_uri === "string" ? params.request_uri : "";
  if (!requestUri.startsWith(PUSHED_REQUEST_URN)) {
    ctx.status = 400;
    ctx.body = { error: "invalid_request", error_description: "request_uri (PAR) required" };
    return;
  }
  const parId = requestUri.slice(PUSHED_REQUEST_URN.length);
  const PAR = (provider as unknown as {
    PushedAuthorizationRequest: {
      find(id: string, o?: unknown): Promise<{ request: string; isValid: boolean; destroy(): Promise<void> } | undefined>;
    };
  }).PushedAuthorizationRequest;
  const parEntity = await PAR.find(parId, { ignoreExpiration: true });
  if (!parEntity || !parEntity.isValid) {
    ctx.status = 400;
    ctx.body = { error: "invalid_request", error_description: "unknown or expired request_uri" };
    return;
  }
  // The pushed params live in an UnsecuredJWT whose iss is the client that
  // pushed the PAR. It MUST equal the client authenticated at /token: this is the
  // real authentication that replaces the retired x-service-token guard
  // (@spec #request-processing step 1). A request_uri pushed by another client is
  // not redeemable here.
  const pushed = decodeJwt(parEntity.request) as Record<string, unknown>;
  const parClientId = pushed.iss;
  // @spec "Parent Grant at Rest in PAR" — delete the pushed request (which
  // carries parent_token) once read; parent_token is never logged or echoed.
  await parEntity.destroy();

  if (parClientId !== client.clientId) {
    ctx.status = 403;
    ctx.body = { error: "invalid_client", error_description: "request_uri was not pushed by the authenticated client" };
    ctx.set("cache-control", "no-store");
    return;
  }

  const missionIntent = pushed.mission_intent;
  const parentParam = pushed.parent;
  const parentToken = pushed.parent_token;
  const childActorRaw = pushed.child_actor;
  if (
    typeof missionIntent !== "string" ||
    typeof parentParam !== "string" ||
    typeof parentToken !== "string" ||
    typeof childActorRaw !== "string"
  ) {
    ctx.status = 400;
    ctx.body = {
      error: "invalid_request",
      error_description: "child creation requires mission_intent, parent, parent_token, and child_actor",
    };
    return;
  }

  // Step 2: resolve the Parent Mission from parent_token. RESOLVE-ONLY -- find()
  // is non-consuming and ignoreSessionBinding keeps it a pure lookup; the
  // refresh_token grant is never invoked, so no rotation and no replay
  // registration (@spec #child-creation).
  const RT = (provider as unknown as {
    RefreshToken: { find(v: string, o?: unknown): Promise<{ grantId?: string } | undefined> };
  }).RefreshToken;
  const rt = await RT.find(parentToken, { ignoreExpiration: true, ignoreSessionBinding: true });
  const grantId = rt?.grantId;
  const parentRecord = grantId ? kernel.findByGrant(grantId) : undefined;
  if (!parentRecord) {
    ctx.status = 400;
    ctx.body = { error: "invalid_grant", error_description: "parent_token did not resolve to a Mission" };
    return;
  }

  // Step 3: cross-check the resolved Mission against the caller-supplied `parent`.
  if (parentRecord.id !== parentParam) {
    ctx.status = 400;
    ctx.body = { error: "invalid_grant", mission_denial_reason: "parent_mismatch" };
    return;
  }

  // Re-validated here: the pushed request is untrusted input on read (the AS must
  // not trust the PAR store as already-validated), so both parses are re-guarded.
  let intent: MissionIntent;
  try {
    intent = kernel.validateIntent(missionIntent);
  } catch (e) {
    ctx.status = 400;
    ctx.body = {
      error: "invalid_request",
      error_description: e instanceof Error ? e.message : "invalid mission_intent",
    };
    return;
  }
  let childActor: { sub: string; iss?: string; sub_profile?: string };
  try {
    childActor = JSON.parse(childActorRaw) as { sub: string; iss?: string; sub_profile?: string };
  } catch {
    ctx.status = 400;
    ctx.body = { error: "invalid_request", error_description: "child_actor must be a JSON object" };
    return;
  }

  // Steps 4-11: createChildMission runs active-check, strict-subset, fan-out, and
  // commits the Child Mission atomically. Map ChildDelegationError.reason to the
  // layered OAuth error + mission_denial_reason (set on ctx directly).
  let child: MissionRecord;
  try {
    ({ child } = createChildMission(kernel, { parentId: parentRecord.id, intent, childActor }));
  } catch (e) {
    if (e instanceof ChildDelegationError) {
      const code = childErrorCode(e.reason);
      ctx.status = code === "access_denied" ? 403 : 400;
      ctx.body = { error: code, mission_denial_reason: e.reason };
      return;
    }
    throw e;
  }

  if (!opts.childGrantKey || !opts.childGrantKid || !opts.childGrantAlg) {
    ctx.status = 501;
    ctx.body = { error: "child_delegation_unsupported" };
    return;
  }
  const { assertion } = await mintChildGrant(
    kernel,
    { key: opts.childGrantKey, kid: opts.childGrantKid, alg: opts.childGrantAlg },
    { child, tokenEndpoint: `${opts.issuer}/token` },
  );

  // @spec #child-client-identity — the grant reference: an RFC 7523 JWT-bearer
  // authorization grant redeemable only by the named child actor AS ITSELF,
  // never a child token. The parent conveys it; it cannot redeem it. `grant_type`
  // names the grant the CHILD redeems under, not this creation grant. 200 (not the
  // retired route's 201): this is the /token endpoint's success response.
  ctx.status = 200;
  ctx.set("cache-control", "no-store");
  ctx.body = {
    mission_id: child.id,
    parent: child.parent,
    grant_type: CHILD_JWT_BEARER_GRANT_TYPE,
    assertion,
  };
}

async function decide(
  provider: Provider,
  opts: AdapterOptions,
  ctx: KoaCtx,
  body: Record<string, unknown>,
) {
  const details = await provider.interactionDetails(ctx.req, ctx.res);
  const params = details.params as Record<string, unknown>;
  const intent = opts.kernel.validateIntent(String(params.mission_intent));
  const approver = String(body.approver ?? "");
  const subject = String(body.subject ?? approver);

  if (body.decision !== "approve") {
    await provider.interactionFinished(ctx.req, ctx.res, {
      error: "access_denied",
      error_description: "approver denied the mission",
    });
    return;
  }

  const authority = opts.kernel.derive(intent);
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
    subject: { iss: opts.issuer, sub: subject },
    approver: { iss: opts.issuer, sub: approver },
    clientId: String(params.client_id),
    approvalEventId: `apev_${details.uid}`,
  });

  const grant = new provider.Grant({ accountId: subject, clientId: String(params.client_id) });
  // Grant exactly the requested scopes (openid enables an id_token when asked).
  grant.addOIDCScope(typeof params.scope === "string" ? params.scope : "payments");
  const resource = record.authority_set[0]?.resource ?? opts.issuer;
  grant.addResourceScope(resource, "payments");
  for (const entry of record.authority_set) {
    (grant as unknown as { addRar: (d: unknown) => void }).addRar(entry);
  }
  const grantId = await grant.save();
  opts.kernel.bindGrant(record.id, grantId);

  await provider.interactionFinished(ctx.req, ctx.res, {
    login: { accountId: subject },
    consent: { grantId },
  });
}

function renderApprovalPage(uid: string, intent: unknown, authority: unknown): string {
  return `<!doctype html><title>Mission approval</title>
<h1>Approve mission?</h1>
<h2>Intent (proposal, untrusted)</h2><pre>${escapeHtml(JSON.stringify(intent, null, 2))}</pre>
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
