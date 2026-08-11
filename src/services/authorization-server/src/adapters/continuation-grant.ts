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
import { isSubsetSet } from "../kernel/derive.js";
import { ExpansionDeferralError } from "../kernel/deferred.js";
import { ChildDelegationError, createChildMission } from "../kernel/child-delegation.js";
import { GateError } from "../kernel/kernel.js";
import type { AuthorityEntry, MissionIntent, MissionRecord } from "../kernel/types.js";
import { mintChildGrant } from "./child-grant.js";
import { childErrorCode, newResourceServer, resourceServerInfoFor } from "./provider.js";
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
  //   - expansion issues (synchronously) or defers a Mission access token.
  // The subject_token possession rule (control the subject_token's OWN cnf) is the
  // inverse of the async transport's deliberate re-binding; see verifySubjectPossession.
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
  try {
    const header = decodeProtectedHeader(proofJws);
    dpopJwk = header.jwk as JWK;
    jkt = await calculateJwkThumbprint(dpopJwk);
    const { payload: proof } = await jwtVerify(proofJws, dpopJwk, { typ: "dpop+jwt" });
    if (proof.htu !== `${opts.issuer}/token` || proof.htm !== "POST") {
      throw new Error("DPoP htu/htm mismatch");
    }
  } catch {
    txError(ctx, 400, "invalid_dpop_proof", "invalid DPoP proof");
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
 * The Mission gate is spent EXACTLY ONCE here (gateDerivation, step 4). The initial
 * access-token save fires extraTokenClaims, whose family fallback re-gates with
 * gateActive (no increment); every later refresh does likewise. So derivation_count
 * stays 1 across N refreshes.
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
  try {
    const header = decodeProtectedHeader(proofJws);
    const dpopJwk = header.jwk as JWK;
    jkt = await calculateJwkThumbprint(dpopJwk);
    const { payload: proof } = await jwtVerify(proofJws, dpopJwk, { typ: "dpop+jwt" });
    if (proof.htu !== `${opts.issuer}/token` || proof.htm !== "POST") {
      throw new Error("DPoP htu/htm mismatch");
    }
  } catch {
    txError(ctx, 400, "invalid_dpop_proof", "invalid DPoP proof");
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

  // Step 3: require the Mission ACTIVE, an intra-domain target, and a confined subset.
  const active = kernel.applyExpiry(record);
  if (active.state !== "active") {
    txError(ctx, 400, "invalid_grant", `mission ${missionId} is ${active.state}`);
    return;
  }
  const resource = params.resource;
  if (typeof resource !== "string" || !resource) {
    throw new errors.InvalidRequest("resource (the delegation target) required");
  }
  const target = resource;
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
  const requestedRaw = params.authorization_details;
  if (requestedRaw === undefined) {
    confinedSubset = effective;
  } else {
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
    if (!isSubsetSet(requested as AuthorityEntry[], effective)) {
      txError(ctx, 400, "invalid_authorization_details", "requested authorization_details exceed the Mission authority");
      return;
    }
    confinedSubset = requested as AuthorityEntry[];
  }
  if (confinedSubset.length === 0) {
    txError(ctx, 400, "invalid_authorization_details", "confined authorization_details must be non-empty");
    return;
  }

  // Step 4: THE SINGLE family count (catch GateError -> invalid_grant). Every later
  // hop (initial mint + refreshes) re-gates with gateActive only, so it never recounts.
  try {
    kernel.gateDerivation(record.id);
  } catch (e) {
    if (e instanceof GateError) {
      txError(ctx, 400, "invalid_grant", e.message);
      return;
    }
    throw e;
  }

  // Step 5: the per-delegation Grant. Its rar IS the confined subset (structural
  // confinement); addResourceScope(target) is REQUIRED or the refreshed access token's
  // scope filters empty. Record the family so extraTokenClaims/rotate/ttl recognise it.
  const grant = new provider.Grant({ accountId: record.subject.sub, clientId: client.clientId });
  grant.addOIDCScope("payments");
  grant.addResourceScope(target, "payments");
  for (const entry of confinedSubset) {
    (grant as unknown as { addRar: (d: unknown) => void }).addRar(entry);
  }
  const grantId = await grant.save();
  familyStore.record({ grantId, missionId: record.id });

  // Step 6: mint the initial access token under the family grant (mirror
  // mintDeferredToken). TTL clamped to the Mission expires_at (absolute lifetime).
  // save() fires extraTokenClaims -> family fallback -> gateActive (no double count).
  const ttlClamp = Math.max(1, Math.floor((Date.parse(active.expires_at) - Date.now()) / 1000));
  const info = resourceServerInfoFor(target, Math.min(opts.accessTokenTTL ?? 300, ttlClamp));
  const at = new provider.AccessToken({
    accountId: record.subject.sub,
    client,
    grantId,
    gty: TOKEN_EXCHANGE_GRANT_TYPE,
    rar: confinedSubset,
    scope: "payments",
  });
  at.resourceServer = newResourceServer(provider, target, info);
  at.jkt = jkt; // sender-constrain to the DPoP key (tokenType -> DPoP)
  ctx.oidc.entity("AccessToken", at);
  const accessToken = await at.save();

  // Step 7: mint the refresh token under the family grant. resource = target keeps
  // every refreshed access token audienced to the target even when the disconnected
  // client sends no resource; rar carries the confined subset across rotations. The
  // jkt MUST be set MANUALLY (setRefreshTokenBindings no-ops for private_key_jwt).
  const RefreshTokenCtor = (provider as unknown as {
    RefreshToken: new (props: Record<string, unknown>) => { jkt?: string; save(): Promise<string> };
  }).RefreshToken;
  const rt = new RefreshTokenCtor({
    accountId: record.subject.sub,
    client,
    grantId,
    gty: TOKEN_EXCHANGE_GRANT_TYPE,
    scope: "payments",
    rar: confinedSubset,
    resource: target,
  });
  rt.jkt = jkt;
  const refreshTokenValue = await rt.save();

  // Step 8: RFC 8693-shaped success (200, no-store). The refreshed access tokens are
  // obtained via ordinary native grant_type=refresh_token (no custom handler).
  ctx.status = 200;
  ctx.body = {
    access_token: accessToken,
    token_type: "DPoP",
    expires_in: (at as unknown as { expiration: number }).expiration,
    refresh_token: refreshTokenValue,
    authorization_details: confinedSubset,
  };
  ctx.set("cache-control", "no-store");
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
 * per RFC 9449; NOTE the token endpoint does not maintain a proof-jti replay cache
 * for custom grants (the same limitation as every other manual DPoP block here).
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
  try {
    const header = decodeProtectedHeader(proofJws);
    dpopJwk = header.jwk as JWK;
    jkt = await calculateJwkThumbprint(dpopJwk);
    const { payload: proof } = await jwtVerify(proofJws, dpopJwk, { typ: "dpop+jwt" });
    if (proof.htu !== `${opts.issuer}/token` || proof.htm !== "POST") {
      throw new Error("DPoP htu/htm mismatch");
    }
  } catch {
    txError(ctx, 400, "invalid_dpop_proof", "invalid DPoP proof");
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
 * carries (a confined subset for a subset-derivation, the full effective set for a
 * successor). Sets the RFC 8693-shaped success body on ctx.
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

  // Non-authoritative `parent` cross-check (audit only): subject_token is the
  // selector, but a supplied `parent` that disagrees is refused (parent_mismatch).
  const parentParam = params.parent;
  if (typeof parentParam === "string" && parentParam && parentParam !== parent.id) {
    ctx.status = 400;
    ctx.body = { error: "invalid_grant", mission_denial_reason: "parent_mismatch" };
    ctx.set("cache-control", "no-store");
    return;
  }

  // The child Intent + child actor (untrusted request input; parsed + validated here).
  const missionIntentRaw = params.mission_intent;
  if (typeof missionIntentRaw !== "string" || !missionIntentRaw) {
    throw new errors.InvalidRequest("mission_intent (the child intent) required");
  }
  let intent: MissionIntent;
  try {
    intent = opts.kernel.validateIntent(missionIntentRaw);
  } catch (e) {
    throw new errors.InvalidRequest(e instanceof Error ? e.message : "invalid mission_intent");
  }
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

  // Steps 5-6: SYNCHRONOUS, NON-derivation subset creation. Denials map through the
  // shared childErrorCode + mission_denial_reason (set on ctx directly so err_out
  // does not strip the reason).
  let child: MissionRecord;
  try {
    ({ child } = createChildMission(opts.kernel, { parentId: parent.id, intent, childActor }));
  } catch (e) {
    if (e instanceof ChildDelegationError) {
      const code = childErrorCode(e.reason);
      ctx.status = code === "access_denied" ? 403 : 400;
      ctx.body = { error: code, mission_denial_reason: e.reason };
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
  const { assertion } = await mintChildGrant(
    opts.kernel,
    { key: opts.childGrantKey, kid: opts.childGrantKid, alg: opts.childGrantAlg },
    { child, tokenEndpoint: `${opts.issuer}/token` },
  );
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
 * @spec expansion — the EXPANSION exchange (a real back-channel wire path; expansion
 * previously had none). The predecessor is resolved FROM `subject_token`; possession
 * is control of that token's cnf key. Completion modes:
 *   - SYNCHRONOUS when the requested authority is a pure subset of the predecessor's
 *     EFFECTIVE set (an ordinary confined derivation, no fresh consent, NO successor);
 *   - DEFERRED via the DTR substrate ({@link ExpansionDeferralStore}) when the
 *     request WIDENS (a fresh approval is required and is asynchronous);
 *   - INTERACTIVE (the deployment's existing front-channel approval) is RETAINED as
 *     an alternative for the widening case and is untouched here.
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

  // The widened Intent (the fresh-approval basis).
  const missionIntentRaw = params.mission_intent;
  if (typeof missionIntentRaw !== "string" || !missionIntentRaw) {
    throw new errors.InvalidRequest("mission_intent (the widened intent) required for expansion");
  }
  let intent: MissionIntent;
  try {
    intent = opts.kernel.validateIntent(missionIntentRaw);
  } catch (e) {
    throw new errors.InvalidRequest(e instanceof Error ? e.message : "invalid mission_intent");
  }

  // The predecessor MUST be active at request time.
  const active = opts.kernel.applyExpiry(resolved.record);
  if (active.state !== "active") {
    txError(ctx, 400, "invalid_grant", `predecessor mission is ${active.state}`);
    return;
  }

  // Step 5: subset-derivation vs fresh-approval-required.
  const requested = opts.kernel.derive(intent);
  const effective = opts.kernel.effectiveAuthoritySet(active);
  if (isSubsetSet(requested, effective)) {
    // Step 6 (synchronous): a pure subset is an ordinary confined derivation on the
    // predecessor (no fresh consent, no successor). gate + claim run in extraTokenClaims.
    await mintMissionAccessToken(opts, provider, ctx, active, requested, resolved.jkt);
    return;
  }

  // Widening: a FRESH approval is required. Complete via the DTR deferred path.
  const store = opts.expansionDeferrals;
  if (!store) {
    throw new errors.InvalidRequest("deferred expansion approval is not configured");
  }
  let pending: ReturnType<typeof store.open>;
  try {
    pending = store.open({ predecessorId: active.id, intent, clientId: acting.sub, jkt: resolved.jkt });
  } catch (e) {
    if (e instanceof ExpansionDeferralError) {
      txError(ctx, 400, "invalid_grant", e.message);
      return;
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
  try {
    const header = decodeProtectedHeader(proofJws);
    const dpopJwk = header.jwk as JWK;
    jkt = await calculateJwkThumbprint(dpopJwk);
    const { payload: proof } = await jwtVerify(proofJws, dpopJwk, { typ: "dpop+jwt" });
    if (proof.htu !== `${opts.issuer}/token` || proof.htm !== "POST") {
      throw new Error("DPoP htu/htm mismatch");
    }
  } catch {
    txError(ctx, 400, "invalid_dpop_proof", "invalid DPoP proof");
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
  if (minted) opts.kernel.supersedeOnRedemption(r.successor.id);
}
