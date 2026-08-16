/**
 * @spec draft-mcguinness-oauth-id-continuation-assertion-00 (RFC 8693 token
 * exchange -> continuation ID-JAG)
 *
 * The token-exchange grant at /token: a client presents an Identity Continuation
 * Assertion (ICA) as the RFC 8693 `subject_token` and receives a Mission-rooted
 * continuation ID-JAG as the issued token. This is the end-to-end intra-domain
 * continuation hop. It layers the FOUR-SIGNAL actor agreement over the ICA
 * validator: the authenticated presenter (client auth), the `actor_token`, the
 * ICA `act`, and the DPoP proof key MUST all name the SAME actor and be bound to
 * the SAME confirmed key before a continuation is minted.
 *
 * The ID-JAG is minted through `issueCrossDomainGrant` (the single PR-B emitter),
 * which signs with a direct `SignJWT` and runs `gateDerivation` EXACTLY ONCE — it
 * is never routed through `provider.AccessToken`, so the Mission gate is not
 * double-run.
 */

import { createHash } from "node:crypto";
import { handleCrossOrgChainExchange } from "./cross-org-grant.js";
import { type ActObject, extendChainCollapsing } from "@mission/actor-chain";
import {
  calculateJwkThumbprint,
  createLocalJWKSet,
  decodeJwt,
  decodeProtectedHeader,
  type JWK,
  jwtVerify,
} from "jose";
import { errors, type KoaContextWithOIDC } from "oidc-provider";
import type Provider from "oidc-provider";
import {
  ContinuationAssertionError,
  IDENTITY_CONTINUATION_TOKEN_TYPE,
  type ValidatedContinuation,
  validateContinuationAssertion,
} from "../kernel/continuation-assertion.js";
import { ID_JAG_TOKEN_TYPE, issueCrossDomainGrant } from "../kernel/cross-domain.js";
import { isSubsetSet, projectThroughEffective } from "../kernel/derive.js";
import { UniqueViolationError } from "@mission/store";
import {
  type CreationOperation,
  type CreationReservation,
  creationFingerprint,
  isValidCreationRequestId,
} from "../kernel/creation-idempotency.js";
import { DEFERRAL_EXPIRES_IN, DEFERRAL_INTERVAL, ExpansionDeferralError } from "../kernel/deferred.js";
import { ChildDelegationError, createChildMission } from "../kernel/child-delegation.js";
import { IntentError } from "../kernel/intent.js";
import { GateError } from "../kernel/kernel.js";
import type { AuthorityEntry, MissionIntent, MissionIntentSubmission, MissionRecord } from "../kernel/types.js";
import { mintChildGrant } from "./child-grant.js";
import {
  childErrorCode,
  intentErrorToOidc,
  InvalidAuthorizationDetails,
  newResourceServer,
  requiredEvidenceTypesFor,
  resourceServerInfoFor,
} from "./provider.js";
import type { AdapterOptions } from "./provider.js";

/** @spec RFC 8693 §2.1 — the token-exchange grant type. */
export const TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";

/** @spec RFC 8693 §3 — the access-token token type (the async-delegation subject_token). */
export const ACCESS_TOKEN_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

/** @spec RFC 8693 §3 — the JWT token type. The `requested_token_type` that selects
 *  the CHILD-CREATION exchange (a child-bound RFC 7523 JWT authorization grant is
 *  issued); it also matches the response `issued_token_type`. */
export const JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";

/** @spec RFC 8693 §3 — the refresh-token token type. NEVER acceptable as
 *  `subject_token` for expansion/child-creation (#448: a reusable bearer refresh
 *  credential MUST NOT be the possession carrier). */
export const REFRESH_TOKEN_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:refresh_token";

/** The (iss, jti) replay cache shape (from `newReplayCache()`). */
export type ContinuationReplay = {
  seen: (iss: string, jti: string) => boolean;
  record: (iss: string, jti: string) => void;
};

/**
 * Deterministic, audience-local subject resolver: for a fixed (audience, global
 * subject) it MUST return the same value across hops and across AS restarts, so
 * the target RAS sees a stable `sub`. NOT random, NOT stored.
 */
export type SubjectResolver = (audience: string, subject: { iss: string; sub: string }) => string;

/**
 * Default deterministic audience-local subject: a stable digest over the AS
 * issuer (the constant local salt), the target audience, and the global subject.
 * Same (audience, subject) -> same value on every hop and every restart; never
 * the global subject; never stored.
 */
export function defaultSubjectResolver(issuer: string): SubjectResolver {
  return (audience, subject) =>
    `acct_${createHash("sha256").update(`${issuer}\n${audience}\n${subject.sub}`).digest("base64url")}`;
}

/** Set the RFC 6749 error body directly (status BEFORE body; no-store). Used for
 *  error codes oidc-provider does not model (`invalid_continuation`,
 *  `invalid_target`, `invalid_dpop_proof`) and for the four-signal `invalid_grant`
 *  returns whose distinct `error_description` the invalid_grant renderer would
 *  otherwise overwrite. */
function txError(ctx: KoaContextWithOIDC, status: number, error: string, description: string): void {
  ctx.status = status;
  ctx.body = { error, error_description: description };
  ctx.set("cache-control", "no-store");
}

/**
 * @spec RFC 9449 — record-and-check a manually verified DPoP proof's `jti` in
 * the bounded replay cache: a missing/empty jti or a reuse within the window
 * refuses (invalid_dpop_proof). Shared by every manual DPoP block at the token
 * endpoint (the custom grants); exported for the provider.ts blocks.
 */
export function freshProofJti(opts: AdapterOptions, jti: unknown): boolean {
  return typeof jti === "string" && jti !== "" && opts.dpopProofReplay?.check(jti) === true;
}

/**
 * Handle the RFC 8693 token-exchange grant. Client authentication
 * (private_key_jwt) has already run, so `ctx.oidc.client` is the authenticated
 * presenter. Returns by setting the response on `ctx` directly (the ID-JAG is
 * not a provider AccessToken).
 */
export async function handleTokenExchangeGrant(
  opts: AdapterOptions,
  provider: Provider,
  ctx: KoaContextWithOIDC,
): Promise<void> {
  const params = ctx.oidc.params as Record<string, unknown>;

  // @spec async-delegation — dispatch. `request_refresh_token` selects the
  // async-delegation transport (a base mission access token in; a per-delegation
  // grant with a rotated, sender-constrained refresh token out). Checked BEFORE the
  // ICA param hard-checks below, so the ICA continuation path is byte-for-byte
  // unchanged whenever the flag is absent. The familyStore lookup (NOT a gty string)
  // is the discriminator on every subsequent hop.
  const requestRefresh = params.request_refresh_token;
  if (requestRefresh === "true" || requestRefresh === true) {
    await handleAsyncDelegationExchange(opts, provider, ctx);
    return;
  }

  // @spec expansion / child-delegation — the possession-fixed delegation exchanges
  // (#448 supersession). `requested_token_type` selects the operation and is
  // checked BEFORE the ICA hard-checks below, so the ICA continuation path is
  // byte-for-byte unchanged whenever neither value is present:
  //   - child-creation issues a child-bound RFC 7523 JWT authorization grant (jwt);
  //   - expansion defers a Mission access token (or refuses a non-widening request).
  // The subject_token possession rule (control the subject_token's OWN cnf) is the
  // inverse of the async transport's deliberate re-binding; see verifySubjectPossession.
  // @spec cross-org-delegation#projection-exchange — a Chain Presentation
  // subject_token forks BEFORE the requested_token_type forks: the chain
  // exchange also requests an access token, and the subject_token_type is the
  // discriminator RFC 8693 provides for exactly this.
  if (params.subject_token_type === "urn:ietf:params:oauth:token-type:mission-delegation-chain") {
    await handleCrossOrgChainExchange(
      {
        issuer: opts.issuer,
        ...(opts.crossOrg ? { crossOrg: opts.crossOrg } : {}),
        tokenKey: opts.childGrantKey as CryptoKey,
        tokenKid: opts.childGrantKid as string,
        proofJtiFresh: (jti) => freshProofJti(opts, jti),
        now: () => opts.kernel.nowDate(),
      },
      ctx,
    );
    return;
  }
  if (params.requested_token_type === JWT_TOKEN_TYPE) {
    await handleChildCreationExchange(opts, provider, ctx);
    return;
  }
  if (params.requested_token_type === ACCESS_TOKEN_TOKEN_TYPE) {
    await handleExpansionExchange(opts, provider, ctx);
    return;
  }

  // Step 1: RFC 8693 param shape.
  if (params.requested_token_type !== ID_JAG_TOKEN_TYPE) {
    throw new errors.InvalidRequest("requested_token_type MUST be the id-jag token type");
  }
  if (params.subject_token_type !== IDENTITY_CONTINUATION_TOKEN_TYPE) {
    throw new errors.InvalidRequest("unsupported subject_token_type");
  }
  const subjectToken = params.subject_token;
  const audience = params.audience;
  const resource = params.resource;
  if (typeof subjectToken !== "string" || !subjectToken) {
    throw new errors.InvalidRequest("subject_token required");
  }
  if (typeof audience !== "string" || !audience) {
    throw new errors.InvalidRequest("audience required");
  }
  if (typeof resource !== "string" || !resource) {
    throw new errors.InvalidRequest("resource required");
  }

  // Wiring guard: the grant is registered unconditionally, so a request can
  // reach here even when the continuation options were not composed.
  const store = opts.continuationStore;
  const issuers = opts.chainAuthorityIssuers;
  const replay = opts.continuationReplay;
  const resourceToAs = opts.resourceToAs;
  const subjectResolver = opts.subjectResolver;
  // Sign with an ES256 key published on the AS jwks_uri. NOTE: the goal is "the
  // ID-JAG verifies on jwks_uri"; the natural means ("the AS token key") is not
  // usable here because `issueCrossDomainGrant` hardcodes an ES256 protected
  // header while the AS token key is RS256 (topology.json). index.ts therefore
  // wires the ES256 as-txn key (already on jwks_uri) as the continuation-grant
  // signer. See the PR body.
  const signKey = opts.continuationGrantKey;
  const signKid = opts.continuationGrantKid;
  if (!store || !issuers || !replay || !resourceToAs || !subjectResolver || !signKey || !signKid) {
    throw new errors.InvalidRequest("token-exchange continuation grant is not configured");
  }

  // Signal #1 (client auth): the authenticated presenter. The actor identity is
  // (AS issuer, client_id) — this IS the contract the Chain Authority MUST mint
  // the ICA `act` and the `actor_token` (iss,sub) against; all three are compared
  // raw and case-sensitive below.
  const client = ctx.oidc.client as NonNullable<typeof ctx.oidc.client>;
  const currentActor = { iss: opts.issuer, sub: client.clientId };

  // Signal #4 (DPoP): derive the presenter jkt exactly as mintDeferredToken does.
  const proofJws = ctx.get("DPoP");
  if (!proofJws) {
    txError(ctx, 400, "invalid_dpop_proof", "DPoP proof JWT required");
    return;
  }
  let jkt: string;
  let dpopJwk: JWK;
  let proofJti: unknown;
  try {
    const header = decodeProtectedHeader(proofJws);
    dpopJwk = header.jwk as JWK;
    jkt = await calculateJwkThumbprint(dpopJwk);
    const { payload: proof } = await jwtVerify(proofJws, dpopJwk, { typ: "dpop+jwt" });
    if (proof.htu !== `${opts.issuer}/token` || proof.htm !== "POST") {
      throw new Error("DPoP htu/htm mismatch");
    }
    proofJti = proof.jti;
  } catch {
    txError(ctx, 400, "invalid_dpop_proof", "invalid DPoP proof");
    return;
  }
  if (!freshProofJti(opts, proofJti)) {
    txError(ctx, 400, "invalid_dpop_proof", "DPoP proof jti missing or replayed");
    return;
  }

  // Step 4: validate the ICA. `audience` is the AS issuer identifier (NOT /token).
  // The validator records the (iss, jti) on success (continuation-assertion.ts
  // step 9), so the ICA is single-use from THIS point — do NOT re-record. A
  // request that fails a LATER step still consumes the ICA (fail-safe, not
  // retryable). Every typed validator error maps to invalid_request with its
  // specific message preserved (invalid_request, unlike invalid_grant, is not
  // re-rendered), so exp>300 / forbidden-claim / replay / presenter-key reasons
  // stay visible.
  let ica: ValidatedContinuation;
  try {
    ica = await validateContinuationAssertion(subjectToken, {
      audience: opts.issuer,
      issuers,
      presenterJkt: jkt,
      replay,
    });
  } catch (e) {
    if (e instanceof ContinuationAssertionError) {
      throw new errors.InvalidRequest(e.message);
    }
    throw e;
  }

  // Step 5: resolve the handle -> Mission. Unknown/terminal (incl. a Mission that
  // reached a terminal lifecycle state, via the onLifecycleCommit fan-out) ->
  // invalid_continuation. This description pins the STORE path (distinct from the
  // gate path in step 9).
  const resolved = store.resolve(ica.handle);
  if (!resolved) {
    txError(ctx, 400, "invalid_continuation", "unknown or terminal continuation handle");
    return;
  }

  // Step 6: invalid_target — the resource MUST be served by the named audience.
  if (resourceToAs(resource) !== audience) {
    txError(ctx, 400, "invalid_target", "resource is not served by the requested audience");
    return;
  }

  // Step 7: Signal #2 (actor_token) — REQUIRED for a chained continuation. It is
  // bound to the confirmed presenter key: it MUST be signed by that key and carry
  // cnf.jkt === jkt. (iss,sub) is extracted for the agreement check.
  const actorTokenRaw = params.actor_token;
  if (typeof actorTokenRaw !== "string" || !actorTokenRaw) {
    throw new errors.InvalidRequest("actor_token required for a chained continuation");
  }
  let actorIss: unknown;
  let actorSub: unknown;
  let actorCnfJkt: unknown;
  try {
    const { payload } = await jwtVerify(actorTokenRaw, dpopJwk, { algorithms: ["ES256"] });
    actorIss = payload.iss;
    actorSub = payload.sub;
    actorCnfJkt = (payload.cnf as { jkt?: unknown } | undefined)?.jkt;
  } catch {
    txError(ctx, 400, "invalid_grant", "actor_token verification failed");
    return;
  }

  // Step 8: FOUR-SIGNAL ACTOR AGREEMENT. All of {client-auth actor, actor_token
  // (iss,sub), ICA act (iss,sub)} MUST agree (raw ===, case-sensitive) and be
  // bound to the confirmed key: actor_token cnf.jkt === ICA cnf.jkt === presenter
  // jkt. Each mismatch returns invalid_grant with a DISTINCT description (set on
  // ctx directly so it survives the invalid_grant renderer).
  if (actorCnfJkt !== jkt) {
    txError(ctx, 400, "invalid_grant", "actor_token is not sender-constrained to the presenter key");
    return;
  }
  if (ica.cnf.jkt !== jkt) {
    // Defence in depth (the validator already enforced this).
    txError(ctx, 400, "invalid_grant", "continuation assertion cnf.jkt does not match the presenter key");
    return;
  }
  if (actorIss !== currentActor.iss || actorSub !== currentActor.sub) {
    txError(ctx, 400, "invalid_grant", "actor_token actor does not match the authenticated client");
    return;
  }
  if (ica.act.iss !== currentActor.iss || ica.act.sub !== currentActor.sub) {
    txError(ctx, 400, "invalid_grant", "continuation assertion actor does not match the authenticated client");
    return;
  }

  // Step 9: mint the continuation ID-JAG. gateDerivation runs INSIDE
  // issueCrossDomainGrant (exactly once); kernel.get here is a non-gating read
  // only for the deterministic sub, so there is no double-gate.
  const record = opts.kernel.get(resolved.missionId);
  if (!record) {
    txError(ctx, 400, "invalid_continuation", "continuation Mission not found");
    return;
  }
  // Audience-local, deterministic sub (NOT the global mission subject).
  const localSub = subjectResolver(audience, record.subject);
  // Fresh new-hop handle, bound to the SAME anchor/Mission, linked to the prior.
  const freshHandle = store.mint({
    anchorId: resolved.anchor.anchorId,
    missionId: resolved.missionId,
    actor: { iss: currentActor.iss, sub: currentActor.sub },
    cnfJkt: jkt,
    priorHandle: ica.handle,
  });
  // Collapse the current actor over the ICA hop lineage. Because the four-signal
  // check forces currentActor === ICA act and the ICA `act` is single-level, this
  // ALWAYS collapses to a depth-1 lineage (a single actor's multi-hop
  // continuation keeps one entry) — it never extends here by construction.
  const collapsedAct: ActObject = extendChainCollapsing(
    { iss: currentActor.iss, sub: currentActor.sub },
    { iss: ica.act.iss, sub: ica.act.sub },
  );
  // Root auth envelope, carried unchanged (store shape -> ID-JAG shape).
  const env = resolved.authEnvelope;
  const authEnvelope = {
    ...(env.authTime !== undefined ? { auth_time: env.authTime } : {}),
    ...(env.acr !== undefined ? { acr: env.acr } : {}),
    ...(env.amr !== undefined ? { amr: env.amr } : {}),
  };

  let grant: string;
  try {
    ({ grant } = await issueCrossDomainGrant(opts.kernel, signKey, signKid, {
      missionId: resolved.missionId,
      targetAs: audience,
      clientId: client.clientId,
      cnfJkt: jkt,
      resourceToAs,
      sub: localSub,
      identityContinuationHandle: freshHandle,
      act: collapsedAct,
      authEnvelope,
    }));
  } catch (e) {
    // A non-active / expired / cap-exhausted Mission (gate path -> distinct
    // description from the store path in step 5).
    if (e instanceof GateError) {
      txError(ctx, 400, "invalid_continuation", "continuation Mission gate refused issuance");
      return;
    }
    // issueCrossDomainGrant throws a bare Error when no authority-set entry maps
    // to the target audience (reachable even past the step-6 target check).
    if (e instanceof Error && /audience-scoped authority/.test(e.message)) {
      txError(ctx, 400, "invalid_target", e.message);
      return;
    }
    throw e;
  }

  // Step 10: RFC 8693 §2.2.1 response (token_type N_A; the ID-JAG is not a bearer
  // token). Set on ctx directly.
  const claims = decodeJwt(grant);
  const expiresIn = Math.max(0, (claims.exp as number) - Math.floor(Date.now() / 1000));
  ctx.status = 200;
  ctx.body = {
    access_token: grant,
    issued_token_type: ID_JAG_TOKEN_TYPE,
    token_type: "N_A",
    expires_in: expiresIn,
  };
  ctx.set("cache-control", "no-store");
  // Step 11: the ICA jti was already recorded by the validator (step 4); nothing
  // to record here.
}

/**
 * @spec async-delegation — the async-delegation continuation transport at /token.
 *
 * An acting client presents a base mission ACCESS token (RFC 8693 `subject_token`,
 * `subject_token_type` = access_token) and asks (`request_refresh_token=true`) for a
 * durable, disconnected delegation. The AS mints an initial DPoP-bound access token
 * AND a rotated, sender-constrained refresh token, both bound to a NEW per-delegation
 * `Grant` (one Grant per issuance), tracked in the DelegationFamilyStore
 * (grant_id -> mission_id).
 *
 * The per-delegation grant is load-bearing: it is NEVER the Mission's approval grant
 * (a consumed-async-RT reuse-wipe would otherwise destroy the Mission grant and break
 * child-delegation's parent_token). It also makes confinement STRUCTURAL — the grant's
 * `rar` IS the confined subset, so every refreshed access token re-projects exactly
 * that subset (features.richAuthorizationRequests.rarForRefreshTokenResponse reads the
 * grant's rar) and is audienced to the target (the refresh token carries resource =
 * target). Refresh redemption is ordinary native `grant_type=refresh_token`; there is
 * no custom refresh handler.
 *
 * The Mission gate is spent EXACTLY ONCE here (gateDerivation, step 5). The initial
 * access-token save fires extraTokenClaims, whose family fallback re-gates with
 * gateActive (no increment); every later refresh does likewise. So derivation_count
 * stays 1 across N refreshes.
 *
 * @spec continuation#transport-async — retry safety (#485): the exchange REQUIRES
 * `creation_request_id` (the COMMON idempotency primitives adopted from
 * expansion#creation-request-id; family delivery/recovery defined by the
 * continuation profile itself). The reservation is acquired BEFORE any side
 * effect, the family-created transition commits atomically with the single
 * gateDerivation, and a revalidated retry recovers the operation
 * ({@link recoverAsyncDelegation}) — never a second delegation family, never a
 * second derivation count, and never a sibling refresh token once the initial
 * one is consumed (consumption proves delivery).
 */
export async function handleAsyncDelegationExchange(
  opts: AdapterOptions,
  provider: Provider,
  ctx: KoaContextWithOIDC,
): Promise<void> {
  const { kernel } = opts;
  const params = ctx.oidc.params as Record<string, unknown>;

  // Wiring guard: the family store + resource->AS map must be composed.
  const familyStore = opts.familyStore;
  const resourceToAs = opts.resourceToAs;
  if (!familyStore || !resourceToAs) {
    throw new errors.InvalidRequest("async-delegation transport is not configured");
  }

  // Step 1: the authenticated acting client (client auth ran before this handler) +
  // the DPoP-derived presenter jkt (reuse the ICA handler's DPoP block). The new
  // access + refresh tokens are sender-constrained to THIS key; a disconnected client
  // presents a fresh DPoP proof per refresh, matching the refresh token's jkt.
  const client = ctx.oidc.client as NonNullable<typeof ctx.oidc.client>;
  const proofJws = ctx.get("DPoP");
  if (!proofJws) {
    txError(ctx, 400, "invalid_dpop_proof", "DPoP proof JWT required");
    return;
  }
  let jkt: string;
  let proofJti: unknown;
  try {
    const header = decodeProtectedHeader(proofJws);
    const dpopJwk = header.jwk as JWK;
    jkt = await calculateJwkThumbprint(dpopJwk);
    const { payload: proof } = await jwtVerify(proofJws, dpopJwk, { typ: "dpop+jwt" });
    if (proof.htu !== `${opts.issuer}/token` || proof.htm !== "POST") {
      throw new Error("DPoP htu/htm mismatch");
    }
    proofJti = proof.jti;
  } catch {
    txError(ctx, 400, "invalid_dpop_proof", "invalid DPoP proof");
    return;
  }
  if (!freshProofJti(opts, proofJti)) {
    txError(ctx, 400, "invalid_dpop_proof", "DPoP proof jti missing or replayed");
    return;
  }

  // Step 2: resolve the Mission from the base mission access token (mirror the
  // /transaction handler's resolution: verify on the AS jwks, read mission.id).
  if (params.subject_token_type !== ACCESS_TOKEN_TOKEN_TYPE) {
    throw new errors.InvalidRequest("subject_token_type MUST be the access_token token type");
  }
  const subjectToken = params.subject_token;
  if (typeof subjectToken !== "string" || !subjectToken) {
    throw new errors.InvalidRequest("subject_token (base mission access token) required");
  }
  let baseClaims: Record<string, unknown>;
  try {
    const { payload } = await jwtVerify(subjectToken, createLocalJWKSet(opts.publicJwks as never), {
      issuer: opts.issuer,
    });
    baseClaims = payload as Record<string, unknown>;
  } catch {
    txError(ctx, 400, "invalid_grant", "subject_token verification failed");
    return;
  }
  const missionRef = baseClaims.mission as { id?: string } | undefined;
  const missionId = missionRef?.id;
  if (typeof missionId !== "string") {
    txError(ctx, 400, "invalid_grant", "subject_token is missing the mission claim");
    return;
  }
  // @spec async-delegation: the delegation handle (the base access token) is
  // bound to the acting client. Require the base token's client_id to equal the
  // authenticated acting client, so an authenticated client cannot present a base
  // token issued to a DIFFERENT client and continue that Mission. The continuation
  // family is re-bound to the acting client's own DPoP key (which may differ from
  // the base token's key, so the base cnf is deliberately NOT required to match).
  if (baseClaims.client_id !== client.clientId) {
    txError(ctx, 400, "invalid_grant", "subject_token was not issued to the acting client");
    return;
  }
  const record = kernel.get(missionId);
  if (!record) {
    txError(ctx, 400, "invalid_grant", "subject_token mission not found");
    return;
  }

  // @spec continuation#transport-async — REQUIRED creation_request_id on the
  // delegation-family-creating exchange, adopting expansion#creation-request-id
  // by reference (missing -> invalid_request).
  const creationRequestId = readCreationRequestId(params);

  // The fingerprint inputs are parsed BEFORE the idempotency lookup: the target
  // and the requested confined subset (SHAPE only here; the subset-of-effective
  // check stays a live-state gate below).
  const resource = params.resource;
  if (typeof resource !== "string" || !resource) {
    throw new errors.InvalidRequest("resource (the delegation target) required");
  }
  const target = resource;
  let requestedSubset: AuthorityEntry[] | undefined;
  const requestedRaw = params.authorization_details;
  if (requestedRaw !== undefined) {
    let requested: unknown = requestedRaw;
    if (typeof requestedRaw === "string") {
      try {
        requested = JSON.parse(requestedRaw);
      } catch {
        throw new errors.InvalidRequest("authorization_details must be a JSON array");
      }
    }
    if (!Array.isArray(requested)) {
      throw new errors.InvalidRequest("authorization_details must be a JSON array");
    }
    requestedSubset = requested as AuthorityEntry[];
  }

  // @spec continuation#transport-async — the async-delegation operation
  // fingerprint: the RESOLVED base Mission (never the raw subject_token), the
  // ACTING client's cnf (this exchange deliberately re-binds the family to the
  // acting key), the requested confined subset, the target, and the selecting
  // request_refresh_token parameter.
  const fingerprint = creationFingerprint({
    op: "async-delegation",
    iss: opts.issuer,
    client: client.clientId,
    source: record.id,
    cnf: { jkt },
    ...(requestedSubset ? { proposal: requestedSubset } : {}),
    resource: target,
    request_refresh_token: true,
  });
  const idem = opts.creationIdempotency;
  if (!idem) {
    throw new errors.InvalidRequest("creation idempotency is not configured");
  }

  // @spec expansion#creation-lookup-order (adopted) — the lookup runs AFTER
  // client authentication and possession (the acting-key re-binding) but BEFORE
  // the Mission lifecycle gate and the derivation gate below: the retry worth
  // recovering is exactly the one whose first attempt consumed the single
  // family derivation (or whose Mission changed state) when it succeeded.
  const existing = idem.find(client.clientId, creationRequestId);
  if (existing) {
    await recoverAsyncDelegation(opts, provider, ctx, existing, fingerprint, jkt);
    return;
  }

  // Step 3: require the Mission ACTIVE, an intra-domain target, and a confined subset.
  const active = kernel.applyExpiry(record);
  if (active.state !== "active") {
    txError(ctx, 400, "invalid_grant", `mission ${missionId} is ${active.state}`);
    return;
  }
  // Intra-domain only: the target MUST be served by this issuer. A cross-domain
  // target is the ICA/cross-domain flow's job, not async-delegation.
  if (resourceToAs(target) !== opts.issuer) {
    txError(ctx, 400, "invalid_target", "target resource is not served by this issuer (async-delegation is intra-domain)");
    return;
  }
  // Confine the requested authorization_details to a subset of the ACTIVE Authority
  // Set. Absent -> the full active set (the Mission's authority is the ceiling).
  // Containment: the ceiling (and the absent-case default) is the EFFECTIVE set,
  // so a contained capability cannot ride an async-delegation family.
  const effective = kernel.effectiveAuthoritySet(active);
  let confinedSubset: AuthorityEntry[];
  if (requestedSubset === undefined) {
    confinedSubset = effective;
  } else {
    if (!isSubsetSet(requestedSubset, effective)) {
      txError(ctx, 400, "invalid_authorization_details", "requested authorization_details exceed the Mission authority");
      return;
    }
    confinedSubset = requestedSubset;
  }
  if (confinedSubset.length === 0) {
    txError(ctx, 400, "invalid_authorization_details", "confined authorization_details must be non-empty");
    return;
  }

  // Step 4 (RESERVED): acquire the durable (client, creation_request_id)
  // reservation BEFORE any side effect. The datastore uniqueness constraint is
  // the concurrency funnel: a concurrent duplicate loses the INSERT and
  // re-reads the winner (retryable in-progress, a family-created resume, or
  // the stored response) — it never creates a second family.
  const reservation: CreationReservation = {
    clientId: client.clientId,
    creationRequestId,
    op: "async-delegation",
    fingerprint,
    cnfJkt: jkt,
    sourceMissionId: record.id,
  };
  try {
    idem.reserve(reservation);
  } catch (e) {
    if (e instanceof UniqueViolationError) {
      const winner = idem.find(client.clientId, creationRequestId);
      if (winner) {
        await recoverAsyncDelegation(opts, provider, ctx, winner, fingerprint, jkt);
        return;
      }
    }
    throw e;
  }

  // Step 5 (FAMILY-CREATED): create the per-delegation Grant (its rar IS the
  // confined subset — structural confinement; addResourceScope(target) is
  // REQUIRED or the refreshed access token's scope filters empty), record the
  // family so extraTokenClaims/rotate/ttl recognise it, then record the family
  // identity on the reservation ATOMICALLY with the single gateDerivation (one
  // kernel-db transaction). Every later hop (initial mint + refreshes +
  // resumed delivery) re-gates with gateActive only, so it never recounts.
  // Crash windows: before this transaction, only the reservation exists (a
  // retry sees a retryable in-progress result until the tombstone expires; the
  // token-less grant is inert); after it, a retry finds family-created and
  // RESUMES delivery of the recorded family. A GateError rolls the count and
  // the family-created transition back together, invalidates the provisional
  // family, and records a failed tombstone (the refusal replays).
  const grant = new provider.Grant({ accountId: record.subject.sub, clientId: client.clientId });
  grant.addOIDCScope("payments");
  grant.addResourceScope(target, "payments");
  for (const entry of confinedSubset) {
    (grant as unknown as { addRar: (d: unknown) => void }).addRar(entry);
  }
  const grantId = await grant.save();
  familyStore.record({ grantId, missionId: record.id });
  try {
    idem.advanceReserved(client.clientId, creationRequestId, { grant_id: grantId, target }, () => {
      kernel.gateDerivation(record.id);
    });
  } catch (e) {
    if (e instanceof GateError) {
      familyStore.invalidate(grantId);
      await (grant as unknown as { destroy: () => Promise<void> }).destroy();
      const body = { error: "invalid_grant", error_description: e.message };
      idem.failReserved(client.clientId, creationRequestId, { status: 400, body });
      ctx.status = 400;
      ctx.body = body;
      ctx.set("cache-control", "no-store");
      return;
    }
    throw e;
  }

  // Steps 6-8 (COMPLETED = delivery): mint the family's initial access +
  // refresh tokens and complete the operation with the stored response.
  await deliverAsyncDelegationFamily(opts, provider, ctx, {
    mission: active,
    grantId,
    target,
    tokenRar: confinedSubset,
    refreshRar: confinedSubset,
    jkt,
    creationRequestId,
  });
}

/** The async-delegation response body stored as the delivery artifact. */
interface AsyncDelegationResponseBody {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
  authorization_details: AuthorityEntry[];
}

/** The inputs of one async-delegation family delivery (initial or resumed). */
interface AsyncFamilyDelivery {
  /** The ACTIVE base Mission record (accountId + absolute-lifetime clamp). */
  mission: MissionRecord;
  grantId: string;
  target: string;
  /** The authorization the initial access token carries. */
  tokenRar: AuthorityEntry[];
  /** The family's structural subset, carried on the refresh token across rotations. */
  refreshRar: AuthorityEntry[];
  /** The confirmed key the family is sender-constrained to. */
  jkt: string;
  creationRequestId: string;
}

/**
 * @spec continuation#transport-async — DELIVER one async-delegation family:
 * mint the family's initial access token (TTL clamped to the Mission
 * expires_at; save() fires extraTokenClaims -> family fallback -> gateActive,
 * no derivation recount) and its initial refresh token (resource = target
 * keeps every refreshed access token audienced to the target; the jkt MUST be
 * set MANUALLY — setRefreshTokenBindings no-ops for private_key_jwt), then
 * mark the operation COMPLETED with the response as the stored delivery
 * artifact. Shared by the first presentation and by the family-created RESUME
 * path of {@link recoverAsyncDelegation}.
 */
async function deliverAsyncDelegationFamily(
  opts: AdapterOptions,
  provider: Provider,
  ctx: KoaContextWithOIDC,
  d: AsyncFamilyDelivery,
): Promise<void> {
  const client = ctx.oidc.client as NonNullable<typeof ctx.oidc.client>;
  const ttlClamp = Math.max(1, Math.floor((Date.parse(d.mission.expires_at) - Date.now()) / 1000));
  const info = resourceServerInfoFor(d.target, Math.min(opts.accessTokenTTL ?? 300, ttlClamp));
  const at = new provider.AccessToken({
    accountId: d.mission.subject.sub,
    client,
    grantId: d.grantId,
    gty: TOKEN_EXCHANGE_GRANT_TYPE,
    rar: d.tokenRar,
    scope: "payments",
  });
  at.resourceServer = newResourceServer(provider, d.target, info);
  at.jkt = d.jkt; // sender-constrain to the confirmed key (tokenType -> DPoP)
  ctx.oidc.entity("AccessToken", at);
  const accessToken = await at.save();
  const RefreshTokenCtor = (provider as unknown as {
    RefreshToken: new (props: Record<string, unknown>) => { jkt?: string; save(): Promise<string> };
  }).RefreshToken;
  const rt = new RefreshTokenCtor({
    accountId: d.mission.subject.sub,
    client,
    grantId: d.grantId,
    gty: TOKEN_EXCHANGE_GRANT_TYPE,
    scope: "payments",
    rar: d.refreshRar,
    resource: d.target,
  });
  rt.jkt = d.jkt;
  const refreshTokenValue = await rt.save();
  // RFC 8693-shaped success (200, no-store). The refreshed access tokens are
  // obtained via ordinary native grant_type=refresh_token (no custom handler).
  const responseBody: AsyncDelegationResponseBody = {
    access_token: accessToken,
    token_type: "DPoP",
    expires_in: (at as unknown as { expiration: number }).expiration,
    refresh_token: refreshTokenValue,
    authorization_details: d.tokenRar,
  };
  opts.creationIdempotency?.completeDelivered(client.clientId, d.creationRequestId, d.mission.id, {
    grant_id: d.grantId,
    target: d.target,
    body: responseBody,
  });
  ctx.status = 200;
  ctx.body = responseBody;
  ctx.set("cache-control", "no-store");
}

/**
 * @spec continuation#transport-async (containment conformance) — project a
 * family grant's issuance-time rar through the Mission's CURRENT effective set
 * (approved minus contained) for a RESUMED delivery, exactly as the provider's
 * rarThroughContainment does for refresh responses. No containment -> the same
 * array (fast path). The narrowing itself is {@link projectThroughEffective}
 * (shared with provider.ts and the introspection credential/Mission-authority
 * intersection, @spec mission#introspection): actions-only narrowing, nothing
 * inherited from the target.
 */
function projectRarThroughEffective(
  kernel: AdapterOptions["kernel"],
  record: MissionRecord,
  rar: AuthorityEntry[],
): AuthorityEntry[] {
  if (!record.containment) return rar;
  return projectThroughEffective(rar, kernel.effectiveAuthoritySet(record));
}

/**
 * @spec continuation#transport-async — recover a repeated async-delegation
 * exchange. Fingerprint match + proof of the RECORDED confirmation key are
 * REQUIRED (a matching identifier never bypasses possession); recovery is
 * DELIVERY of the single recorded family, never a second family and never a
 * second derivation count:
 *  - failed         -> the recorded refusal is replayed verbatim;
 *  - reserved       -> retryable in-progress (no family exists yet);
 *  - family-created -> RESUME delivery: the recorded family's initial tokens
 *                      are issued and the operation completes (the crash
 *                      window between the family-created transition and the
 *                      response);
 *  - completed      -> the stored response is returned while the initial
 *                      refresh token is unissued or unconsumed. Consumption
 *                      PROVES delivery (the client held the response and
 *                      rotated on it), so once it is consumed — or gone:
 *                      expired, or wiped by reuse detection — creation
 *                      recovery is REFUSED and the caller continues on the
 *                      family's current refresh token. A rotating
 *                      refresh-token family is a single lineage; recovery
 *                      never mints an independent sibling refresh token into
 *                      it.
 */
async function recoverAsyncDelegation(
  opts: AdapterOptions,
  provider: Provider,
  ctx: KoaContextWithOIDC,
  op: CreationOperation,
  fingerprint: string,
  presenterJkt: string,
): Promise<void> {
  if (op.op !== "async-delegation" || op.fingerprint !== fingerprint) {
    txError(
      ctx,
      400,
      "invalid_request",
      "creation_request_id was already used for a different creation request",
    );
    return;
  }
  if (presenterJkt !== op.cnfJkt) {
    txError(ctx, 400, "invalid_grant", "possession proof does not match the recorded confirmation key");
    return;
  }
  if (op.state === "failed") {
    ctx.status = op.failure?.status ?? 400;
    ctx.body = op.failure?.body ?? { error: "invalid_request" };
    ctx.set("cache-control", "no-store");
    return;
  }
  const stored = op.delivery as
    | { grant_id?: string; target?: string; body?: AsyncDelegationResponseBody }
    | undefined;
  const grantId = typeof stored?.grant_id === "string" ? stored.grant_id : undefined;
  const target = typeof stored?.target === "string" ? stored.target : undefined;
  if (op.state === "reserved" && !grantId) {
    // RESERVED (no family yet): a concurrent first presentation holds the
    // reservation, or the first attempt crashed before the family-created
    // transition (nothing was created or counted; the tombstone frees the
    // identifier at the retry horizon).
    txError(ctx, 400, "invalid_request", "creation is in progress; retry with the same creation_request_id");
    return;
  }
  // family-created or completed: the recorded family must still be live.
  const missionId = op.missionId ?? op.sourceMissionId;
  const record = opts.kernel.get(missionId);
  if (!record) {
    txError(ctx, 400, "invalid_grant", "recorded mission not found");
    return;
  }
  const active = opts.kernel.applyExpiry(record);
  if (active.state !== "active") {
    txError(ctx, 400, "invalid_grant", `recorded mission is ${active.state}`);
    return;
  }
  if (!grantId || !target || !opts.familyStore?.resolve(grantId)) {
    txError(ctx, 400, "invalid_grant", "recorded delegation family not found");
    return;
  }
  if (op.state === "reserved") {
    // FAMILY-CREATED: the family and its single derivation count exist but the
    // response was never delivered (no token was ever issued). RESUME delivery
    // of the RECORDED family: issue its initial tokens and complete — never a
    // second family, never a second gateDerivation. The grant's rar is the
    // authoritative structural subset; it is projected through the CURRENT
    // effective set so a capability contained since creation cannot ride the
    // resumed delivery. A grant already destroyed fails closed.
    const GrantModel = (provider as unknown as {
      Grant: { find: (id: string) => Promise<{ rar?: unknown } | undefined> };
    }).Grant;
    const grant = await GrantModel.find(grantId);
    const grantRar = Array.isArray(grant?.rar) ? (grant.rar as AuthorityEntry[]) : undefined;
    if (!grantRar) {
      txError(ctx, 400, "invalid_grant", "recorded delegation family no longer exists");
      return;
    }
    const projected = projectRarThroughEffective(opts.kernel, active, grantRar);
    if (projected.length === 0) {
      txError(ctx, 400, "invalid_grant", "the recorded delegation's authority is fully contained");
      return;
    }
    await deliverAsyncDelegationFamily(opts, provider, ctx, {
      mission: active,
      grantId,
      target,
      tokenRar: projected,
      refreshRar: grantRar,
      jkt: op.cnfJkt,
      creationRequestId: op.creationRequestId,
    });
    return;
  }
  // COMPLETED: the stored response is returned while the initial refresh token
  // is unissued or unconsumed (find() excludes an expired token).
  const storedBody = stored?.body;
  if (storedBody?.refresh_token) {
    const RefreshTokenModel = (provider as unknown as {
      RefreshToken: { find: (v: string) => Promise<{ consumed?: number } | undefined> };
    }).RefreshToken;
    const rt = await RefreshTokenModel.find(storedBody.refresh_token);
    if (rt && !rt.consumed) {
      ctx.status = 200;
      ctx.body = storedBody;
      ctx.set("cache-control", "no-store");
      return;
    }
  }
  // Consumption of the initial refresh token PROVES delivery: the client held
  // the response and rotated on it. The rotating family is a single lineage —
  // recovery MUST NOT mint an independent sibling refresh token into it, so
  // creation recovery is refused and the caller continues on its current
  // refresh token.
  txError(
    ctx,
    400,
    "invalid_grant",
    "the delegation was already delivered; continue with the family's current refresh token",
  );
}

// ===========================================================================
// @spec expansion / child-delegation — the possession-fixed delegation exchanges.
//
// Abstract requirement (binding-independent): to expand a predecessor Mission or
// create a child Mission, the requester MUST prove possession of the
// predecessor/parent's authority via a SENDER-CONSTRAINED proof; a reusable bearer
// refresh credential MUST NOT be the carrier (#448). The AS binding of that
// requirement is an RFC 8693 token exchange whose `subject_token` is the
// predecessor/parent's Mission-bound ACCESS token; possession is control of that
// token's OWN confirmation key (RFC 9449 DPoP jkt). The predecessor/parent is
// resolved FROM `subject_token` (the token is the selector, not a `predecessor`/
// `parent` param).
// ===========================================================================

/** A resolved, possession-verified subject Mission (verification order steps 1-3). */
interface ResolvedSubject {
  record: MissionRecord;
  /** The verified presenter jkt (== the subject_token's own cnf.jkt). */
  jkt: string;
  /** The presenter DPoP public key (for verifying a carried actor_token). */
  dpopJwk: JWK;
  claims: Record<string, unknown>;
}

/**
 * @spec expansion / child-delegation — AS verification order steps 1-3, shared by
 * BOTH exchanges. (1) require an access-token `subject_token` and REJECT a refresh
 * token; verify the token on the AS jwks. (2) resolve the Mission FROM it. (3)
 * verify POSSESSION: the presenter's DPoP proof key MUST equal the subject_token's
 * OWN cnf.jkt. This is the inverse of {@link handleAsyncDelegationExchange}, which
 * deliberately re-binds to the acting client's key. The DPoP `jti` is single-use
 * per RFC 9449, enforced by the shared bounded-TTL replay cache
 * ({@link freshProofJti}) like every other manual DPoP block here.
 * Returns null after setting the ctx error body; the caller returns immediately.
 */
async function verifySubjectPossession(
  opts: AdapterOptions,
  ctx: KoaContextWithOIDC,
): Promise<ResolvedSubject | null> {
  const params = ctx.oidc.params as Record<string, unknown>;
  // Step 1: subject_token type. A refresh token MUST NOT be the carrier (#448).
  if (params.subject_token_type === REFRESH_TOKEN_TOKEN_TYPE) {
    txError(
      ctx,
      400,
      "invalid_request",
      "a refresh token MUST NOT be accepted as subject_token; present the Mission access token",
    );
    return null;
  }
  if (params.subject_token_type !== ACCESS_TOKEN_TOKEN_TYPE) {
    txError(ctx, 400, "invalid_request", "subject_token_type MUST be the access_token token type");
    return null;
  }
  const subjectToken = params.subject_token;
  if (typeof subjectToken !== "string" || !subjectToken) {
    txError(ctx, 400, "invalid_request", "subject_token (the Mission access token) required");
    return null;
  }
  // Step 1: verify subject_token on the AS jwks.
  let claims: Record<string, unknown>;
  try {
    const { payload } = await jwtVerify(subjectToken, createLocalJWKSet(opts.publicJwks as never), {
      issuer: opts.issuer,
    });
    claims = payload as Record<string, unknown>;
  } catch {
    txError(ctx, 400, "invalid_grant", "subject_token verification failed");
    return null;
  }
  // Step 2: the Mission is selected BY subject_token (replaces predecessor_token/parent_token).
  const missionRef = claims.mission as { id?: string } | undefined;
  const missionId = missionRef?.id;
  if (typeof missionId !== "string") {
    txError(ctx, 400, "invalid_grant", "subject_token is missing the mission claim");
    return null;
  }
  const cnfJkt = (claims.cnf as { jkt?: unknown } | undefined)?.jkt;
  if (typeof cnfJkt !== "string" || !cnfJkt) {
    txError(ctx, 400, "invalid_grant", "subject_token is not sender-constrained (no cnf.jkt)");
    return null;
  }
  // Step 3: POSSESSION — the presenter controls the subject_token's OWN cnf key.
  const proofJws = ctx.get("DPoP");
  if (!proofJws) {
    txError(ctx, 400, "invalid_dpop_proof", "DPoP proof JWT required");
    return null;
  }
  let jkt: string;
  let dpopJwk: JWK;
  let proofJti: unknown;
  try {
    const header = decodeProtectedHeader(proofJws);
    dpopJwk = header.jwk as JWK;
    jkt = await calculateJwkThumbprint(dpopJwk);
    const { payload: proof } = await jwtVerify(proofJws, dpopJwk, { typ: "dpop+jwt" });
    if (proof.htu !== `${opts.issuer}/token` || proof.htm !== "POST") {
      throw new Error("DPoP htu/htm mismatch");
    }
    proofJti = proof.jti;
  } catch {
    txError(ctx, 400, "invalid_dpop_proof", "invalid DPoP proof");
    return null;
  }
  if (!freshProofJti(opts, proofJti)) {
    txError(ctx, 400, "invalid_dpop_proof", "DPoP proof jti missing or replayed");
    return null;
  }
  if (jkt !== cnfJkt) {
    txError(ctx, 400, "invalid_grant", "possession proof does not match the subject_token confirmation key");
    return null;
  }
  const record = opts.kernel.get(missionId);
  if (!record) {
    txError(ctx, 400, "invalid_grant", "subject_token mission not found");
    return null;
  }
  return { record, jkt, dpopJwk, claims };
}

/**
 * @spec expansion / child-delegation — AS verification order step 4: identify the
 * acting agent. The acting agent is the authenticated client (client auth ran
 * before this handler). Phase 1 CARRIES `actor_token`; it does NOT restructure the
 * act chain (that is #433, out of scope). When an actor_token is present it MUST be
 * sender-constrained to the presenter key (cnf.jkt === jkt). Returns the acting
 * agent, or null after setting the error body.
 */
async function carryActingAgent(
  opts: AdapterOptions,
  ctx: KoaContextWithOIDC,
  dpopJwk: JWK,
  jkt: string,
): Promise<{ iss: string; sub: string } | null> {
  const client = ctx.oidc.client as NonNullable<typeof ctx.oidc.client>;
  const acting = { iss: opts.issuer, sub: client.clientId };
  const actorTokenRaw = (ctx.oidc.params as Record<string, unknown>).actor_token;
  if (actorTokenRaw === undefined) return acting; // client auth identifies the actor
  if (typeof actorTokenRaw !== "string" || !actorTokenRaw) {
    txError(ctx, 400, "invalid_request", "actor_token must be a JWT");
    return null;
  }
  try {
    const { payload } = await jwtVerify(actorTokenRaw, dpopJwk, { algorithms: ["ES256"] });
    if ((payload.cnf as { jkt?: unknown } | undefined)?.jkt !== jkt) {
      txError(ctx, 400, "invalid_grant", "actor_token is not sender-constrained to the presenter key");
      return null;
    }
  } catch {
    txError(ctx, 400, "invalid_grant", "actor_token verification failed");
    return null;
  }
  return acting; // carried, not restructured (#433).
}

/** Seconds until an ISO instant, floored at 1 (absolute-lifetime clamp). */
function secondsUntil(iso: string): number {
  return Math.max(1, Math.floor((Date.parse(iso) - Date.now()) / 1000));
}

/**
 * Mint a DPoP-bound, resource-bound Mission access token for `mission`, single-
 * gated through `extraTokenClaims`. The token is bound to the mission's OWN
 * approval grant (created + bound lazily), so `findByGrant` resolves the Mission
 * inside the hook and the `mission` claim is attached + the derivation gated
 * EXACTLY ONCE (never hand-set, never double-gated). Because oidc-provider requires
 * the AccessToken and its Grant to name the same client, the acting client MUST be
 * the mission's own client_id (a Mission derivation is performed by the Mission's
 * own agent); a mismatch refuses. `tokenRar` is the authorization the token
 * carries (the successor's full effective set at both call sites). Sets the
 * RFC 8693-shaped success body on ctx.
 */
async function mintMissionAccessToken(
  opts: AdapterOptions,
  provider: Provider,
  ctx: KoaContextWithOIDC,
  mission: MissionRecord,
  tokenRar: AuthorityEntry[],
  jkt: string,
): Promise<boolean> {
  const client = ctx.oidc.client as NonNullable<typeof ctx.oidc.client>;
  if (client.clientId !== mission.client_id) {
    txError(ctx, 400, "invalid_grant", "acting client is not the mission client");
    return false;
  }
  const effective = opts.kernel.effectiveAuthoritySet(mission);
  const resource = tokenRar[0]?.resource ?? effective[0]?.resource ?? opts.issuer;
  let grantId: string;
  if (mission.grant_id) {
    grantId = mission.grant_id;
  } else {
    const grant = new provider.Grant({ accountId: mission.subject.sub, clientId: mission.client_id });
    grant.addOIDCScope("payments");
    grant.addResourceScope(resource, "payments");
    for (const entry of effective) (grant as unknown as { addRar: (d: unknown) => void }).addRar(entry);
    grantId = await grant.save();
    opts.kernel.bindGrant(mission.id, grantId);
  }
  const info = resourceServerInfoFor(resource, opts.accessTokenTTL ?? 300);
  info.accessTokenTTL = Math.min(info.accessTokenTTL, secondsUntil(mission.expires_at));
  const at = new provider.AccessToken({
    accountId: mission.subject.sub,
    client,
    grantId,
    gty: TOKEN_EXCHANGE_GRANT_TYPE,
    rar: tokenRar,
    scope: "payments",
  });
  at.resourceServer = newResourceServer(provider, resource, info);
  at.jkt = jkt; // sender-constrain to the possession key (tokenType -> DPoP)
  ctx.oidc.entity("AccessToken", at);
  const jwt = await at.save();
  ctx.status = 200;
  ctx.body = {
    access_token: jwt,
    token_type: "DPoP",
    expires_in: (at as unknown as { expiration: number }).expiration,
    scope: "payments",
    authorization_details: tokenRar,
  };
  ctx.set("cache-control", "no-store");
  return true;
}

/**
 * @spec child-delegation#child-creation — the CHILD-CREATION exchange (request
 * side migrated from PAR + refresh-token `parent_token` to this RFC 8693 exchange).
 * The parent is resolved FROM `subject_token` (its Mission-bound ACCESS token);
 * possession is control of that token's cnf key. Child-creation stays a
 * NON-derivation subset creation (it creates a NEW Mission, not a token within the
 * parent's derivation counter): createChildMission uses the active-state check, NOT
 * gateDerivation, so it MUST NOT consume the parent's cap. The RESPONSE is already
 * RFC 8693-shaped and the two-grant flow is KEPT: a child-bound RFC 7523 JWT
 * authorization grant is returned, redeemable only by the named child actor AS
 * ITSELF (handleChildJwtBearerGrant), so conveying it through the parent is safe.
 */
/**
 * @spec mission#authority-proposal — parse and validate the OPTIONAL authority
 * proposal riding the standard `authorization_details` parameter of a
 * possession-fixed delegation exchange (child creation / expansion), the same
 * carriage the core fixes for PAR. Returns undefined when absent. The D60
 * intake rules apply (advertised type + published schema ->
 * invalid_authorization_details; resource containment / parse failures ->
 * invalid_request), mapped onto the exchange's error surface.
 */
/**
 * @spec expansion#creation-request-id (child-delegation cites it) — read the
 * REQUIRED `creation_request_id`: the client-generated identifier of ONE
 * Mission-creation operation across all completion modes. Missing or malformed
 * -> invalid_request. Syntax: bounded ASCII (max 255 octets); opaque to the AS
 * beyond equality.
 */
function readCreationRequestId(params: Record<string, unknown>): string {
  const v = params.creation_request_id;
  if (v === undefined) {
    throw new errors.InvalidRequest("creation_request_id required");
  }
  if (!isValidCreationRequestId(v)) {
    throw new errors.InvalidRequest(
      "creation_request_id must be a visible-ASCII string of at most 255 octets",
    );
  }
  return v;
}

function readProposalParam(
  opts: AdapterOptions,
  params: Record<string, unknown>,
  intent: MissionIntent,
): AuthorityEntry[] | undefined {
  const raw = params.authorization_details;
  if (raw === undefined) return undefined;
  if (typeof raw !== "string" || !raw) {
    throw new errors.InvalidRequest("authorization_details must be a JSON array");
  }
  try {
    const proposal = opts.kernel.validateProposal(raw, intent.resources);
    return proposal.length ? proposal : undefined;
  } catch (e) {
    if (e instanceof IntentError) {
      throw e.code === "invalid_request"
        ? new errors.InvalidRequest(e.message)
        : new InvalidAuthorizationDetails(e.message);
    }
    throw e;
  }
}

export async function handleChildCreationExchange(
  opts: AdapterOptions,
  _provider: Provider,
  ctx: KoaContextWithOIDC,
): Promise<void> {
  const params = ctx.oidc.params as Record<string, unknown>;
  // Steps 1-3: possession — the parent is selected by subject_token.
  const resolved = await verifySubjectPossession(opts, ctx);
  if (!resolved) return;
  const parent = resolved.record;
  // Step 4: acting agent (the authenticated parent client; carry actor_token).
  const acting = await carryActingAgent(opts, ctx, resolved.dpopJwk, resolved.jkt);
  if (!acting) return;

  // @spec child-delegation#creation-request-id — REQUIRED on every child
  // creation, in every completion mode (missing -> invalid_request).
  const creationRequestId = readCreationRequestId(params);

  // Non-authoritative `parent` cross-check (audit only): subject_token is the
  // selector, but a supplied `parent` that disagrees is refused (parent_mismatch).
  const parentParam = params.parent;
  if (typeof parentParam === "string" && parentParam && parentParam !== parent.id) {
    ctx.status = 400;
    ctx.body = { error: "invalid_grant", mission_denial_reason: "parent_mismatch" };
    ctx.set("cache-control", "no-store");
    return;
  }

  // The child Submission envelope + child actor (untrusted request input;
  // parsed + validated here). @spec mission#submission-via-par — this carrier
  // adopts the envelope: `mission_intent` carries {intent, evidence?}; the
  // bare-Intent shape and any invalid evidence entry are refused here.
  const missionIntentRaw = params.mission_intent;
  if (typeof missionIntentRaw !== "string" || !missionIntentRaw) {
    throw new errors.InvalidRequest("mission_intent (the child intent submission) required");
  }
  let submission: MissionIntentSubmission;
  try {
    submission = opts.kernel.validateSubmission(missionIntentRaw);
  } catch (e) {
    if (e instanceof IntentError) throw intentErrorToOidc(e);
    throw new errors.InvalidRequest(e instanceof Error ? e.message : "invalid mission_intent");
  }
  const intent = submission.intent;
  // @spec mission#authority-proposal — the child's concrete authority proposal
  // rides the standard authorization_details parameter of this exchange (the
  // child Intent carries no authority members).
  const proposedAuthority = readProposalParam(opts, params, intent);
  const childActorRaw = params.child_actor;
  if (typeof childActorRaw !== "string" || !childActorRaw) {
    throw new errors.InvalidRequest("child_actor required");
  }
  let childActor: { sub: string; iss?: string; sub_profile?: string };
  try {
    const parsed = JSON.parse(childActorRaw) as unknown;
    if (parsed === null || typeof parsed !== "object" || typeof (parsed as { sub?: unknown }).sub !== "string") {
      throw new Error("shape");
    }
    childActor = parsed as { sub: string; iss?: string; sub_profile?: string };
  } catch {
    throw new errors.InvalidRequest("child_actor must be a JSON object with a string sub");
  }

  // @spec expansion#creation-fingerprint (child-delegation members) — the typed
  // operation fingerprint over the PARSED, VERIFIED inputs (never the raw
  // subject_token, DPoP proof, or client-auth assertion; never
  // creation_request_id itself).
  const client = ctx.oidc.client as NonNullable<typeof ctx.oidc.client>;
  const fingerprint = creationFingerprint({
    op: "child-creation",
    iss: opts.issuer,
    client: client.clientId,
    source: parent.id,
    cnf: { jkt: resolved.jkt },
    actor: acting,
    intent,
    ...(proposedAuthority ? { proposal: proposedAuthority } : {}),
    // @spec mission#intent-submission-evidence — presented evidence is part of
    // the creation fingerprint: same creation_request_id + different evidence
    // is a mismatch, never a silent replay. (Unreachable today — no registered
    // evidence types, so any presented entry was already refused above.)
    ...(submission.evidence ? { evidence: submission.evidence } : {}),
    child_actor: childActor,
    requested_token_type: JWT_TOKEN_TYPE,
    ...(typeof parentParam === "string" && parentParam ? { cross_check: parentParam } : {}),
  });
  const reservation: CreationReservation = {
    clientId: client.clientId,
    creationRequestId,
    op: "child-creation",
    fingerprint,
    cnfJkt: resolved.jkt,
    sourceMissionId: parent.id,
  };
  const idem = opts.creationIdempotency;
  if (!idem) {
    throw new errors.InvalidRequest("creation idempotency is not configured");
  }

  // @spec expansion#creation-lookup-order — the idempotency lookup runs AFTER
  // client authentication and possession verification but BEFORE the parent
  // lifecycle gate (inside createChildMission): the recoverable retry is exactly
  // the one whose source Mission changed state when the first attempt succeeded.
  const existing = idem.find(client.clientId, creationRequestId);
  if (existing) {
    await recoverChildCreation(opts, ctx, existing, fingerprint, resolved.jkt);
    return;
  }

  // @spec mission#intent-submission-evidence — STAGE-2 evidence verification
  // runs AFTER the completed-operation recovery lookup above (an artifact
  // that expired after the first attempt completed MUST NOT break recovery)
  // and BEFORE creation/derivation. Presenter conjunction: the AUTHENTICATED
  // client + the possession key of THIS exchange; required types are resolved
  // from policy (global + client registration) before derivation.
  let submissionEvidence: Awaited<ReturnType<typeof opts.kernel.verifySubmissionEvidence>>;
  try {
    submissionEvidence = await opts.kernel.verifySubmissionEvidence({
      intent,
      ...(submission.evidence ? { evidence: submission.evidence } : {}),
      presenter: { clientId: client.clientId, cnf: { jkt: resolved.jkt } },
      required: requiredEvidenceTypesFor(opts, client),
      requestContext: { carrier: "token-exchange:child-creation" },
    });
  } catch (e) {
    if (e instanceof IntentError) throw intentErrorToOidc(e);
    throw e;
  }

  // Steps 5-6: SYNCHRONOUS, NON-derivation subset creation, ATOMIC with the
  // idempotency reservation (one kernel-db transaction: reserved -> insertRecord
  // -> completed; the datastore uniqueness constraint — never read-before-insert
  // — serializes concurrent duplicates). Denials map through the shared
  // childErrorCode + mission_denial_reason (set on ctx directly so err_out
  // does not strip the reason) and are recorded as a `failed` operation so a
  // retry replays the refusal.
  let child: MissionRecord;
  try {
    child = idem.createCompleted(reservation, () => {
      const created = createChildMission(opts.kernel, {
        parentId: parent.id,
        intent,
        ...(proposedAuthority ? { proposedAuthority } : {}),
        ...(submissionEvidence?.length ? { submissionEvidence } : {}),
        childActor,
      });
      return { missionId: created.child.id, value: created.child };
    });
  } catch (e) {
    if (e instanceof UniqueViolationError) {
      // A concurrent duplicate won the reservation: recover its outcome.
      const winner = idem.find(client.clientId, creationRequestId);
      if (winner) {
        await recoverChildCreation(opts, ctx, winner, fingerprint, resolved.jkt);
        return;
      }
      throw e;
    }
    if (e instanceof ChildDelegationError) {
      const code = childErrorCode(e.reason);
      const status = code === "access_denied" ? 403 : 400;
      const body = { error: code, mission_denial_reason: e.reason };
      idem.recordFailure(reservation, { status, body });
      ctx.status = status;
      ctx.body = body;
      ctx.set("cache-control", "no-store");
      return;
    }
    throw e;
  }

  if (!opts.childGrantKey || !opts.childGrantKid || !opts.childGrantAlg) {
    ctx.status = 501;
    ctx.body = { error: "child_delegation_unsupported" };
    return;
  }
  // Credential generation AFTER the atomic creation commit: a crash between the
  // commit and the response is recovered by the retry finding the completed
  // operation and resuming DELIVERY (recovery = delivery, never re-creation).
  const { assertion } = await mintChildGrant(
    opts.kernel,
    { key: opts.childGrantKey, kid: opts.childGrantKid, alg: opts.childGrantAlg },
    { child, tokenEndpoint: `${opts.issuer}/token` },
  );
  idem.recordDelivery(client.clientId, creationRequestId, {
    mode: "synchronous",
    assertion,
    exp: decodeJwt(assertion).exp as number,
  });
  // @spec RFC 8693 §2.2.1 — the (unchanged) child response: a grant reference, not
  // a token; token_type N_A because bearer semantics do not apply to an unredeemed grant.
  ctx.status = 200;
  ctx.set("cache-control", "no-store");
  ctx.body = {
    access_token: assertion,
    issued_token_type: JWT_TOKEN_TYPE,
    token_type: "N_A",
    mission_id: child.id,
    parent: child.parent,
  };
}

/**
 * @spec child-delegation#creation-request-id — recover a repeated child
 * creation. A matching identifier NEVER bypasses verification: the fingerprint
 * MUST match (the fingerprint binds the resolved source Mission, the acting
 * actor, and every semantic input, so any divergence refuses), and the
 * presenter MUST prove the RECORDED sender-constraint identity (no key-rotation
 * recovery path is defined). Recovery is DELIVERY, never re-creation:
 *  - reserved  -> retryable in-progress (a concurrent attempt holds the
 *                 reservation; the client retries with the SAME identifier);
 *  - failed    -> the recorded refusal is replayed verbatim;
 *  - completed -> the stored child grant is returned while it is still valid;
 *                 once expired (it is deliberately short-lived), a FRESH child
 *                 grant is minted for the SAME child, provided the child
 *                 remains active. The fresh mint is an ordinary issuance event:
 *                 creation accounting is NOT repeated (no fan-out increment, no
 *                 second lifecycle event, no second Child Evidence).
 */
async function recoverChildCreation(
  opts: AdapterOptions,
  ctx: KoaContextWithOIDC,
  op: CreationOperation,
  fingerprint: string,
  presenterJkt: string,
): Promise<void> {
  if (op.op !== "child-creation" || op.fingerprint !== fingerprint) {
    txError(
      ctx,
      400,
      "invalid_request",
      "creation_request_id was already used for a different creation request",
    );
    return;
  }
  if (presenterJkt !== op.cnfJkt) {
    txError(ctx, 400, "invalid_grant", "possession proof does not match the recorded confirmation key");
    return;
  }
  if (op.state === "reserved") {
    txError(ctx, 400, "invalid_request", "creation is in progress; retry with the same creation_request_id");
    return;
  }
  if (op.state === "failed") {
    ctx.status = op.failure?.status ?? 400;
    ctx.body = op.failure?.body ?? { error: "invalid_request" };
    ctx.set("cache-control", "no-store");
    return;
  }
  const child = op.missionId ? opts.kernel.get(op.missionId) : undefined;
  if (!child) {
    txError(ctx, 400, "invalid_grant", "recorded child mission not found");
    return;
  }
  const state = opts.kernel.applyExpiry(child).state;
  if (state !== "active") {
    txError(ctx, 400, "invalid_grant", `recorded child mission is ${state}`);
    return;
  }
  const stored = op.delivery as { assertion?: string; exp?: number } | undefined;
  const nowS = Math.floor(opts.kernel.nowDate().getTime() / 1000);
  let assertion: string;
  if (stored?.assertion && typeof stored.exp === "number" && stored.exp > nowS) {
    assertion = stored.assertion;
  } else {
    if (!opts.childGrantKey || !opts.childGrantKid || !opts.childGrantAlg) {
      ctx.status = 501;
      ctx.body = { error: "child_delegation_unsupported" };
      return;
    }
    ({ assertion } = await mintChildGrant(
      opts.kernel,
      { key: opts.childGrantKey, kid: opts.childGrantKid, alg: opts.childGrantAlg },
      { child, tokenEndpoint: `${opts.issuer}/token` },
    ));
    opts.creationIdempotency?.recordDelivery(op.clientId, op.creationRequestId, {
      mode: "synchronous",
      assertion,
      exp: decodeJwt(assertion).exp as number,
    });
  }
  ctx.status = 200;
  ctx.set("cache-control", "no-store");
  ctx.body = {
    access_token: assertion,
    issued_token_type: JWT_TOKEN_TYPE,
    token_type: "N_A",
    mission_id: child.id,
    parent: child.parent,
  };
}

/**
 * @spec expansion — the EXPANSION exchange (a real back-channel wire path; expansion
 * previously had none). The predecessor is resolved FROM `subject_token`; possession
 * is control of that token's cnf key. Expansion ALWAYS widens and ALWAYS requires a
 * fresh approval; TWO completion modes:
 *   - DEFERRED via the DTR substrate ({@link ExpansionDeferralStore}): the fresh
 *     approval is asynchronous;
 *   - INTERACTIVE (the deployment's existing front-channel approval) is RETAINED as
 *     an alternative and is untouched here.
 * A NON-WIDENING request (the derived requested authority is a subset of the
 * predecessor's own effective Authority Set) is REFUSED — nothing to expand;
 * ordinary token derivation already serves it. There is no synchronous exchange
 * completion: an expansion response must never ambiguously be a non-successor (#486).
 * A poll (deferral_code, no subject_token) completes a deferred expansion.
 */
export async function handleExpansionExchange(
  opts: AdapterOptions,
  provider: Provider,
  ctx: KoaContextWithOIDC,
): Promise<void> {
  const params = ctx.oidc.params as Record<string, unknown>;

  // Deferred completion (poll): a deferral_code, no subject_token. Possession and
  // the predecessor binding were RECORDED at request time (@spec deferred-window
  // check (b): the subject_token's expiry does NOT gate this completion).
  const deferralCode = params.deferral_code;
  if (typeof deferralCode === "string" && deferralCode) {
    await pollDeferredExpansion(opts, provider, ctx, deferralCode);
    return;
  }

  // Steps 1-3: possession — the predecessor is selected by subject_token.
  const resolved = await verifySubjectPossession(opts, ctx);
  if (!resolved) return;
  // Step 4: acting agent.
  const acting = await carryActingAgent(opts, ctx, resolved.dpopJwk, resolved.jkt);
  if (!acting) return;

  // @spec expansion#creation-request-id — REQUIRED on every expansion
  // initiation, in every completion mode: initiation is mode-agnostic (the
  // client cannot know in advance whether the request defers or goes
  // interactive; missing -> invalid_request).
  const creationRequestId = readCreationRequestId(params);

  // @spec expansion#request-binding — the non-authoritative `predecessor`
  // cross-check (audit only; subject_token is the selector, mirroring the
  // child path's `parent`): a supplied value that does not name the resolved
  // Mission is refused. Per the profile this is NOT a denial reason (no
  // mission_denial_reason): it fails with invalid_grant directly.
  const predecessorParam = params.predecessor;
  if (
    typeof predecessorParam === "string" &&
    predecessorParam &&
    predecessorParam !== resolved.record.id
  ) {
    txError(
      ctx,
      400,
      "invalid_grant",
      "predecessor cross-check does not match the subject_token-resolved mission",
    );
    return;
  }

  // The widened Submission envelope (the fresh-approval basis).
  // @spec mission#submission-via-par — this carrier adopts the envelope:
  // `mission_intent` carries {intent, evidence?}; the bare-Intent shape and
  // any invalid evidence entry are refused here.
  const missionIntentRaw = params.mission_intent;
  if (typeof missionIntentRaw !== "string" || !missionIntentRaw) {
    throw new errors.InvalidRequest("mission_intent (the widened intent submission) required for expansion");
  }
  let submission: MissionIntentSubmission;
  try {
    submission = opts.kernel.validateSubmission(missionIntentRaw);
  } catch (e) {
    if (e instanceof IntentError) throw intentErrorToOidc(e);
    throw new errors.InvalidRequest(e instanceof Error ? e.message : "invalid mission_intent");
  }
  const intent = submission.intent;
  // @spec mission#authority-proposal — the widened request's concrete authority
  // proposal rides the standard authorization_details parameter of this
  // exchange (the widened Intent carries no authority members).
  const proposedAuthority = readProposalParam(opts, params, intent);

  // @spec expansion#creation-fingerprint — the typed operation fingerprint over
  // the PARSED, VERIFIED inputs.
  const client = ctx.oidc.client as NonNullable<typeof ctx.oidc.client>;
  const fingerprint = creationFingerprint({
    op: "expansion",
    iss: opts.issuer,
    client: client.clientId,
    source: resolved.record.id,
    cnf: { jkt: resolved.jkt },
    actor: acting,
    intent,
    ...(proposedAuthority ? { proposal: proposedAuthority } : {}),
    // @spec mission#intent-submission-evidence — presented evidence is part of
    // the creation fingerprint (see the child-creation exchange above).
    ...(submission.evidence ? { evidence: submission.evidence } : {}),
    requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    ...(typeof predecessorParam === "string" && predecessorParam
      ? { cross_check: predecessorParam }
      : {}),
  });
  const idem = opts.creationIdempotency;
  if (!idem) {
    throw new errors.InvalidRequest("creation idempotency is not configured");
  }

  // @spec expansion#creation-lookup-order — the idempotency lookup runs AFTER
  // client authentication and possession verification but BEFORE the
  // predecessor lifecycle gate below: the recoverable retry is exactly the one
  // whose predecessor moved to `superseded` when the first attempt succeeded;
  // re-running "predecessor must be active" first would reject it.
  const existing = idem.find(client.clientId, creationRequestId);
  if (existing) {
    await recoverExpansion(opts, provider, ctx, existing, fingerprint, resolved.jkt);
    return;
  }

  // @spec mission#intent-submission-evidence — STAGE-2 evidence verification
  // runs AFTER the recovery lookup above (recovery of a completed or pending
  // operation never re-verifies evidence freshness) and BEFORE the lifecycle
  // gate and derivation. The verified facts persist across a deferred window
  // (store.open below) and land on the successor at redemption.
  let submissionEvidence: Awaited<ReturnType<typeof opts.kernel.verifySubmissionEvidence>>;
  try {
    submissionEvidence = await opts.kernel.verifySubmissionEvidence({
      intent,
      ...(submission.evidence ? { evidence: submission.evidence } : {}),
      presenter: { clientId: client.clientId, cnf: { jkt: resolved.jkt } },
      required: requiredEvidenceTypesFor(opts, client),
      requestContext: { carrier: "token-exchange:expansion" },
    });
  } catch (e) {
    if (e instanceof IntentError) throw intentErrorToOidc(e);
    throw e;
  }

  // The predecessor MUST be active at request time.
  const active = opts.kernel.applyExpiry(resolved.record);
  if (active.state !== "active") {
    txError(ctx, 400, "invalid_grant", `predecessor mission is ${active.state}`);
    return;
  }

  // Step 5: widening check. @spec expansion#nothing-to-expand — a NON-WIDENING
  // request (the derived requested authority is a subset of the predecessor's
  // own effective Authority Set) is REFUSED: there is nothing to expand, and
  // ordinary token derivation already serves it (an expansion response must
  // never ambiguously be a non-successor; #486). Nothing is created or
  // reserved and the predecessor is untouched. Set on ctx directly (err_out
  // would strip mission_denial_reason).
  const requested = opts.kernel.derive(intent, proposedAuthority);
  const effective = opts.kernel.effectiveAuthoritySet(active);
  if (isSubsetSet(requested, effective)) {
    ctx.status = 400;
    ctx.body = { error: "invalid_request", mission_denial_reason: "nothing_to_expand" };
    ctx.set("cache-control", "no-store");
    return;
  }

  // Widening: a FRESH approval is required. Complete via the DTR deferred path.
  const store = opts.expansionDeferrals;
  if (!store) {
    throw new errors.InvalidRequest("deferred expansion approval is not configured");
  }
  let pending: ReturnType<typeof store.open>;
  try {
    pending = store.open({
      predecessorId: active.id,
      intent,
      ...(proposedAuthority ? { proposedAuthority } : {}),
      // Facts verified at INITIATION persist across the deferred window and
      // land on the successor at redemption.
      ...(submissionEvidence?.length ? { submissionEvidence } : {}),
      clientId: acting.sub,
      jkt: resolved.jkt,
      creationRequestId,
    });
  } catch (e) {
    if (e instanceof ExpansionDeferralError) {
      txError(ctx, 400, "invalid_grant", e.message);
      return;
    }
    throw e;
  }
  // @spec expansion#creation-request-id — reserve the operation at deferred
  // INITIATION (state `reserved`; the deferral handle is the recorded delivery
  // continuation). A repetition of the same (client, creation_request_id)
  // returns the SAME deferral, never a second ceremony. A concurrent duplicate
  // serializes on the uniqueness constraint and recovers the winner.
  try {
    idem.reserve({
      clientId: client.clientId,
      creationRequestId,
      op: "expansion",
      fingerprint,
      cnfJkt: resolved.jkt,
      sourceMissionId: active.id,
      delivery: { mode: "deferred", deferral_code: pending.deferral_code },
    });
  } catch (e) {
    if (e instanceof UniqueViolationError) {
      const winner = idem.find(client.clientId, creationRequestId);
      if (winner) {
        await recoverExpansion(opts, provider, ctx, winner, fingerprint, resolved.jkt);
        return;
      }
    }
    throw e;
  }
  // Step 6 (deferred): the DTR initiation body (HTTP 400 authorization_pending). Set
  // on ctx directly (err_out would strip deferral_code/expires_in/interval).
  ctx.status = 400;
  ctx.body = {
    error: pending.error,
    deferral_code: pending.deferral_code,
    expires_in: pending.expires_in,
    interval: pending.interval,
  };
  ctx.set("cache-control", "no-store");
}

/**
 * @spec expansion — poll/complete a deferred expansion. Re-establishes KEY
 * possession at completion (the poller's DPoP key MUST equal the key recorded at
 * request time; @spec deferred-window check (b) re-verifies the KEY, never the
 * expired subject_token) and requires the poller to be the acting client that
 * opened the deferral. redeem() runs deferred-window check (a) (predecessor STATE +
 * containment-version delta) and CREATES the successor on approval; this handler
 * mints the successor's first token and supersedes the predecessor on that first
 * redemption.
 */
async function pollDeferredExpansion(
  opts: AdapterOptions,
  provider: Provider,
  ctx: KoaContextWithOIDC,
  deferralCode: string,
): Promise<void> {
  const store = opts.expansionDeferrals;
  if (!store) {
    throw new errors.InvalidRequest("deferred expansion approval is not configured");
  }
  const client = ctx.oidc.client as NonNullable<typeof ctx.oidc.client>;
  const recordedClient = store.recordedClientId(deferralCode);
  if (recordedClient !== undefined && recordedClient !== client.clientId) {
    txError(ctx, 400, "invalid_grant", "deferral was not opened by the polling client");
    return;
  }
  // KEY possession at completion (only the KEY, never the expired subject_token).
  const proofJws = ctx.get("DPoP");
  if (!proofJws) {
    txError(ctx, 400, "invalid_dpop_proof", "DPoP proof JWT required");
    return;
  }
  let jkt: string;
  let proofJti: unknown;
  try {
    const header = decodeProtectedHeader(proofJws);
    const dpopJwk = header.jwk as JWK;
    jkt = await calculateJwkThumbprint(dpopJwk);
    const { payload: proof } = await jwtVerify(proofJws, dpopJwk, { typ: "dpop+jwt" });
    if (proof.htu !== `${opts.issuer}/token` || proof.htm !== "POST") {
      throw new Error("DPoP htu/htm mismatch");
    }
    proofJti = proof.jti;
  } catch {
    txError(ctx, 400, "invalid_dpop_proof", "invalid DPoP proof");
    return;
  }
  if (!freshProofJti(opts, proofJti)) {
    txError(ctx, 400, "invalid_dpop_proof", "DPoP proof jti missing or replayed");
    return;
  }
  const recordedJkt = store.recordedJkt(deferralCode);
  if (recordedJkt !== undefined && recordedJkt !== jkt) {
    txError(ctx, 400, "invalid_grant", "possession proof does not match the recorded confirmation key");
    return;
  }

  const r = store.redeem(deferralCode);
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
  // The successor exists (check (a) passed in redeem). Mint its first token (bound
  // to the possession key) and supersede the predecessor on this first redemption.
  const minted = await mintMissionAccessToken(
    opts,
    provider,
    ctx,
    r.successor,
    opts.kernel.effectiveAuthoritySet(r.successor),
    jkt,
  );
  if (minted) {
    opts.kernel.supersedeOnRedemption(r.successor.id);
    // @spec expansion#creation-request-id — attach the delivery artifact to the
    // completed operation (redeem() already marked it completed atomically with
    // successor creation): an initiation retry returns this token while it is
    // valid, and re-mints for the SAME successor once it expires.
    if (r.creationRequestId) {
      const body = ctx.body as { access_token?: string; expires_in?: number };
      if (typeof body?.access_token === "string") {
        const nowS = Math.floor(opts.kernel.nowDate().getTime() / 1000);
        opts.creationIdempotency?.recordDelivery(client.clientId, r.creationRequestId, {
          mode: "deferred",
          access_token: body.access_token,
          exp: nowS + (typeof body.expires_in === "number" ? body.expires_in : 0),
        });
      }
    }
  }
}

/**
 * @spec expansion#creation-request-id — recover a repeated expansion
 * initiation. Same contract as {@link recoverChildCreation}: fingerprint match
 * + proof of the RECORDED confirmation key are REQUIRED (a matching identifier
 * never bypasses possession); recovery is DELIVERY, never re-creation.
 *  - reserved  -> the SAME deferral continuation body is returned (the pending
 *                 approval ceremony is the delivery artifact);
 *  - failed    -> the recorded refusal is replayed;
 *  - completed -> the stored successor token is returned while valid; once
 *                 expired, a FRESH Mission access token is minted for the SAME
 *                 successor (ordinary issuance accounting via extraTokenClaims;
 *                 no second creation, no second lifecycle event).
 * This path is reached by the retry whose predecessor moved to `superseded`
 * when the first attempt succeeded (the lookup-order rule).
 */
async function recoverExpansion(
  opts: AdapterOptions,
  provider: Provider,
  ctx: KoaContextWithOIDC,
  op: CreationOperation,
  fingerprint: string,
  presenterJkt: string,
): Promise<void> {
  if (op.op !== "expansion" || op.fingerprint !== fingerprint) {
    txError(
      ctx,
      400,
      "invalid_request",
      "creation_request_id was already used for a different creation request",
    );
    return;
  }
  if (presenterJkt !== op.cnfJkt) {
    txError(ctx, 400, "invalid_grant", "possession proof does not match the recorded confirmation key");
    return;
  }
  if (op.state === "failed") {
    ctx.status = op.failure?.status ?? 400;
    ctx.body = op.failure?.body ?? { error: "invalid_request" };
    ctx.set("cache-control", "no-store");
    return;
  }
  if (op.state === "reserved") {
    const code = typeof op.delivery?.deferral_code === "string" ? op.delivery.deferral_code : undefined;
    if (!code) {
      txError(ctx, 400, "invalid_request", "creation is in progress; retry with the same creation_request_id");
      return;
    }
    ctx.status = 400;
    ctx.body = {
      error: "authorization_pending",
      deferral_code: code,
      expires_in: DEFERRAL_EXPIRES_IN,
      interval: DEFERRAL_INTERVAL,
    };
    ctx.set("cache-control", "no-store");
    return;
  }
  // completed: deliver for the ALREADY-CREATED successor.
  const successor = op.missionId ? opts.kernel.get(op.missionId) : undefined;
  if (!successor) {
    txError(ctx, 400, "invalid_grant", "recorded successor mission not found");
    return;
  }
  const state = opts.kernel.applyExpiry(successor).state;
  if (state !== "active") {
    txError(ctx, 400, "invalid_grant", `recorded successor mission is ${state}`);
    return;
  }
  const stored = op.delivery as { access_token?: string; exp?: number } | undefined;
  const nowS = Math.floor(opts.kernel.nowDate().getTime() / 1000);
  if (stored?.access_token && typeof stored.exp === "number" && stored.exp > nowS) {
    ctx.status = 200;
    ctx.body = {
      access_token: stored.access_token,
      token_type: "DPoP",
      expires_in: stored.exp - nowS,
      scope: "payments",
      authorization_details: opts.kernel.effectiveAuthoritySet(successor),
    };
    ctx.set("cache-control", "no-store");
    return;
  }
  const minted = await mintMissionAccessToken(
    opts,
    provider,
    ctx,
    successor,
    opts.kernel.effectiveAuthoritySet(successor),
    presenterJkt,
  );
  if (minted) {
    const body = ctx.body as { access_token?: string; expires_in?: number };
    if (typeof body?.access_token === "string") {
      opts.creationIdempotency?.recordDelivery(op.clientId, op.creationRequestId, {
        mode: "deferred",
        access_token: body.access_token,
        exp: nowS + (typeof body.expires_in === "number" ? body.expires_in : 0),
      });
    }
  }
}
