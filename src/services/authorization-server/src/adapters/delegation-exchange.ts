/**
 * @spec mission#delegation, mission#designation, mission#delegation-constraints
 * (#869, #1268, D449): same-Mission delegation by designation.
 *
 * Two RFC 8693 exchanges. At a designation, the holder of a Mission-bound access
 * token (the approved agent, or the delegate the accounting records as its
 * current actor) proves possession of the token's key and names another client
 * as `audience`; the result is a designation: `aud` and `may_act` name that
 * client, no `cnf`, no `act`, a short life within its source, never usable for
 * resource access. At a delegated exchange (the redemption), the named client
 * presents the designation, authenticates, and proves its own key; the result
 * is a delegated token bound to that key, its authority narrowed per entry at
 * the accounted depth, with `act` rendered from the accounting.
 *
 * Both exchanges refuse before any side effect, then settle the same way
 * ({@link settle}): the token is built with a fixed `jti`, its accounting is
 * recorded, the derivation is counted once (the commit point), and the token is
 * saved under the grant recorded for the presented token, marked so the
 * save-time gate re-checks the Mission's state without counting again. The
 * delegated token therefore lives and dies with that grant or family.
 */

import { canonicalize, delegatedRoutingRefusal, type JsonValue } from "@mission/core";
import { createLocalJWKSet, jwtVerify } from "jose";
import type { KoaContextWithOIDC } from "oidc-provider";
import type Provider from "oidc-provider";
import { projectThroughEffective, SourceUnavailableError } from "../kernel/derive.js";
import { gateDelegableAuthority } from "../kernel/delegation.js";
import { GateError } from "../kernel/kernel.js";
import type { AccountedActor, RecordedIssuance } from "../kernel/token-issuance-store.js";
import type { AuthorityEntry, MissionRecord } from "../kernel/types.js";
import { audienceCollision, resourceAudiences, separationDeclared } from "./audience-separation.js";
import {
  ACCESS_TOKEN_TOKEN_TYPE,
  authoritySource,
  presentedTokenAuthority,
  TOKEN_EXCHANGE_GRANT_TYPE,
  txError,
  verifySubjectPossession,
  verifyTokenEndpointDpop,
} from "./continuation-grant.js";
import { refuseTokenEndpointProof } from "./dpop-replay.js";
import {
  gateErrorToMissionError,
  isGrantLive,
  lifecycleMissionError,
  markDelegationHandle,
  markDelegationMint,
  MissionExchangeError,
  newResourceServer,
  resourceServerInfoFor,
  SCOPE_DECIDED_AT_SAVE,
  tokenEndpointGateRefusal,
  type AdapterOptions,
} from "./provider.js";

/** The reference AS's designation lifetime cap (D449), within the presented token and the Mission. */
export const DESIGNATION_MAX_LIFETIME_S = 300;

/**
 * A structural cap on the rendered `act` chain, separate from any entry's
 * `max_depth` (which governs authority): a chain longer than this is refused
 * `invalid_request` before narrowing.
 */
export const MAX_DELEGATION_CHAIN = 8;

/**
 * The parameters that select Expansion on an access-token exchange: an
 * Expansion request carries `mission_intent` and `creation_request_id`, its
 * poll carries `deferral_code`, and `predecessor` is its cross-check. A
 * request carrying none of them is a delegated exchange where delegation is on.
 */
export const EXPANSION_SELECTORS = ["mission_intent", "creation_request_id", "deferral_code", "predecessor"] as const;

/** Render an accounted chain (oldest delegate first) as a nested `act`, newest outermost. */
export function renderAct(chain: readonly AccountedActor[]): Record<string, unknown> | undefined {
  let act: Record<string, unknown> | undefined;
  for (const actor of chain) act = { ...actor, ...(act ? { act } : {}) };
  return act;
}

/** Whether the token's `act` is exactly the rendering of the accounted chain (both absent at depth 0). */
function actMatchesChain(act: unknown, chain: readonly AccountedActor[]): boolean {
  const rendered = renderAct(chain);
  if (rendered === undefined) return act === undefined;
  if (act === null || typeof act !== "object") return false;
  return canonicalize(act as JsonValue) === canonicalize(rendered as JsonValue);
}

/**
 * Fix the token's `jti` before it is recorded, counted and saved. oidc-provider
 * resolves a token's format when it generates the identifier (formats/dynamic.js
 * 9.10.0), so the identifier is generated here, after the resource server is
 * set, rather than passed in.
 */
function fixTokenId(at: { jti?: string }): void {
  at.jti = (at as unknown as { generateTokenId(): string }).generateTokenId();
}

/** The current time in epoch seconds, as oidc-provider stamps `iat`. */
const nowSeconds = (): number => Math.floor(Date.now() / 1000);

/** An ISO instant in epoch seconds, rounded down so a bound never moves later. */
const epochOf = (iso: string): number => Math.floor(Date.parse(iso) / 1000);

/**
 * Pin a token's absolute expiry (#1279 review). The bound is computed after
 * every awaited check, from absolute instants, and set on the token itself,
 * so time spent in the request can never carry it past its source; a bound
 * already reached refuses before settlement. Returns the seconds remaining,
 * or undefined after setting the refusal.
 */
function pinExpiry(
  ctx: KoaContextWithOIDC,
  at: { exp?: number | undefined },
  bounds: readonly number[],
  exhausted: string,
): number | undefined {
  const now = nowSeconds();
  const exp = Math.min(...bounds);
  if (exp <= now) {
    txError(ctx, 400, "invalid_request", exhausted);
    return undefined;
  }
  at.exp = exp;
  return exp - now;
}

/** The Mission's current state, refusing a Mission that is not active (D369: `invalid_request` on Token Exchange). */
function activeMission(opts: AdapterOptions, record: MissionRecord): MissionRecord {
  const active = opts.kernel.applyExpiry(record);
  if (active.state !== "active") {
    throw new MissionExchangeError(`mission ${record.id} is ${active.state}`, lifecycleMissionError(active));
  }
  return active;
}

/**
 * The common settlement for a designation or a delegated token: record the
 * accounting under the token's fixed `jti`, count the derivation once (the
 * commit point), then save. A failed record refuses with nothing counted; a
 * refused count or save removes the record. A save refused after the count
 * leaves the count spent with no token, the uncoupled-counter residual the
 * handle and approval mints share.
 */
async function settle(
  opts: AdapterOptions,
  ctx: KoaContextWithOIDC,
  at: InstanceType<Provider["AccessToken"]>,
  accounting: Parameters<NonNullable<AdapterOptions["tokenIssuanceStore"]>["recordDelegation"]>[0],
): Promise<string | undefined> {
  const store = opts.tokenIssuanceStore;
  if (!store) {
    txError(ctx, 500, "server_error", "delegation accounting is unavailable");
    return undefined;
  }
  try {
    store.recordDelegation(accounting);
  } catch {
    txError(ctx, 500, "server_error", "the delegation accounting could not be recorded");
    return undefined;
  }
  try {
    opts.kernel.gateDerivation(accounting.missionId);
  } catch (e) {
    store.remove(accounting.iss, accounting.jti);
    if (!(e instanceof GateError)) throw e;
    throw tokenEndpointGateRefusal(
      e.reason,
      e.message,
      gateErrorToMissionError(e.reason, opts.kernel.observedRecord(accounting.missionId)),
      true,
    );
  }
  ctx.oidc.entity("AccessToken", at);
  try {
    return await at.save();
  } catch (e) {
    store.remove(accounting.iss, accounting.jti);
    throw e;
  }
}

/** The presented token's recorded accounting, or undefined where its depth cannot be established. */
function accountingFor(opts: AdapterOptions, claims: Record<string, unknown>, missionId: string): RecordedIssuance | undefined {
  const jti = claims.jti;
  if (typeof jti !== "string") return undefined;
  const issuance = opts.tokenIssuanceStore?.resolve(opts.issuer, jti);
  if (!issuance || issuance.depth === undefined || issuance.chain === undefined) return undefined;
  if (issuance.missionId !== missionId) return undefined;
  return issuance;
}

/** The Mission's effective authority, or a 503 refusal on a source outage. */
function effectiveAuthority(opts: AdapterOptions, ctx: KoaContextWithOIDC, record: MissionRecord): AuthorityEntry[] | undefined {
  try {
    return authoritySource(opts).effectiveAuthoritySet(record);
  } catch (e) {
    if (e instanceof SourceUnavailableError) {
      txError(ctx, 503, "temporarily_unavailable", e.message);
      return undefined;
    }
    throw e;
  }
}

/**
 * @spec mission#designation: the holder of a Mission-bound access token names
 * another client as `audience`. The router sends an access-token exchange here
 * only where delegation is on and `audience` names a client other than the
 * requester; the conflicting parameters were refused before routing.
 */
export async function handleDesignationExchange(
  opts: AdapterOptions,
  provider: Provider,
  ctx: KoaContextWithOIDC,
): Promise<void> {
  const params = ctx.oidc.params as Record<string, unknown>;
  const client = ctx.oidc.client as NonNullable<typeof ctx.oidc.client>;

  // 1. Parse.
  const designee = params.audience;
  if (typeof designee !== "string" || !designee) {
    txError(ctx, 400, "invalid_target", "a designation names exactly one client as audience");
    return;
  }
  if (params.scope !== undefined) {
    txError(ctx, 400, "invalid_scope", "a designation carries authority, not scope");
    return;
  }
  if (params.authorization_details !== undefined) {
    txError(ctx, 400, "invalid_request", "a designation carries the presented authority; the delegated exchange narrows it");
    return;
  }
  if (!(await provider.Client.find(designee))) {
    txError(ctx, 400, "invalid_target", "a designation's audience must name a registered client");
    return;
  }
  // Audience separation (#1274 review): the deployment must list the client,
  // its statement that no resource server accepts the identifier, and the
  // identifier must be none of the audiences the AS knows are accepted.
  if (!separationDeclared(designee, opts.designableClients)) {
    txError(ctx, 400, "invalid_target", "audience separation is not established for the designated client");
    return;
  }
  if (audienceCollision(designee, resourceAudiences(opts))) {
    txError(ctx, 400, "invalid_target", "the designated client's identifier is an audience a resource server accepts for this AS's tokens");
    return;
  }

  // 2. Possession of the presented token's own key.
  const subject = await verifySubjectPossession(opts, ctx, { subjectError: "invalid_request" });
  if (!subject) return;
  const { record, jkt, claims } = subject;

  // 3. The holder: the token's client, and its accounted current actor.
  if (claims.client_id !== client.clientId) {
    txError(ctx, 400, "invalid_request", "subject_token was not issued to the requesting client");
    return;
  }
  const issuance = accountingFor(opts, claims, record.id);
  if (!issuance?.chain || issuance.depth === undefined || !actMatchesChain(claims.act, issuance.chain)) {
    txError(ctx, 400, "invalid_target", "the presented token's delegation depth cannot be established");
    return;
  }
  const holder =
    issuance.depth === 0
      ? record.client_id === client.clientId
      : issuance.chain[issuance.chain.length - 1]?.sub === client.clientId;
  if (!holder) {
    txError(ctx, 400, "invalid_request", "only the presented token's current actor may designate");
    return;
  }

  // 4. The source grant or family is still live.
  if (!(await isGrantLive(opts, provider, issuance.grantId))) {
    txError(ctx, 400, "invalid_request", "the presented token's grant is no longer valid");
    return;
  }

  // 5. Lifecycle.
  const active = activeMission(opts, record);

  // 6. Authority: the presented authority within the Mission's current
  // effective authority, keeping only the entries whose delegation policy
  // admits the designated client at the next depth. A `delegation` member
  // holding only other policy (such as `children`) delegates nothing here.
  const presented = presentedTokenAuthority(claims);
  if (!presented) {
    txError(ctx, 400, "invalid_request", "subject_token carries no readable authorization_details");
    return;
  }
  const effective = effectiveAuthority(opts, ctx, active);
  if (!effective) return;
  const authority = gateDelegableAuthority(
    projectThroughEffective(presented, effective),
    { sub: designee, assertedProfile: opts.kernel.actorProfile(designee) },
    issuance.depth + 1,
  );
  if (authority.length === 0) {
    txError(ctx, 400, "invalid_target", "the presented authority carries no entry the designated client may be delegated");
    return;
  }
  // Audience separation, against the Mission's own resources.
  const missionResources = [...effective, ...presented].map((e) => e.resource).filter((r): r is string => typeof r === "string");
  if (missionResources.includes(designee)) {
    txError(ctx, 400, "invalid_target", "the designated client's identifier is one of the Mission's resources");
    return;
  }

  // 7. Settle and return the designation, its expiry pinned within 300 s,
  // the presented token and the Mission.
  if (typeof claims.exp !== "number") {
    txError(ctx, 400, "invalid_request", "subject_token carries no exp");
    return;
  }
  const at = new provider.AccessToken({
    accountId: active.subject.sub,
    client,
    grantId: issuance.grantId,
    gty: TOKEN_EXCHANGE_GRANT_TYPE,
    rar: authority,
    scope: SCOPE_DECIDED_AT_SAVE,
  });
  const lifetime = pinExpiry(
    ctx,
    at,
    [nowSeconds() + DESIGNATION_MAX_LIFETIME_S, claims.exp, epochOf(active.expires_at)],
    "the presented token has no lifetime left to designate",
  );
  if (lifetime === undefined) return;
  at.resourceServer = newResourceServer(provider, designee, resourceServerInfoFor(designee, lifetime));
  fixTokenId(at);
  // A client audience: scope projection omits `scope`, as for a handle.
  markDelegationHandle(at);
  markDelegationMint(at, { may_act: { sub: designee, iss: opts.issuer } });
  const jwt = await settle(opts, ctx, at, {
    iss: opts.issuer,
    jti: at.jti as string,
    grantId: issuance.grantId,
    authorizationDetails: authority,
    kind: "designation",
    missionId: active.id,
    depth: issuance.depth,
    chain: issuance.chain,
    designee,
    designatorJkt: jkt,
  });
  if (jwt === undefined) return;
  ctx.status = 200;
  ctx.body = {
    access_token: jwt,
    issued_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    // RFC 8693 Section 2.2.1: usable only at this AS's delegated exchange, never as an access token.
    token_type: "N_A",
    expires_in: lifetime,
    authorization_details: authority,
  };
  ctx.set("cache-control", "no-store");
}

/**
 * @spec mission#delegation: the delegated exchange. The designated client
 * presents the designation, authenticates, and proves its own key. The router
 * sends an access-token exchange here only where delegation is on and the
 * request carries no `audience` and none of the Expansion parameters.
 */
export async function handleDelegatedExchange(
  opts: AdapterOptions,
  provider: Provider,
  ctx: KoaContextWithOIDC,
): Promise<void> {
  const { kernel } = opts;
  const params = ctx.oidc.params as Record<string, unknown>;
  const client = ctx.oidc.client as NonNullable<typeof ctx.oidc.client>;

  // 1. Parse.
  if (params.subject_token_type !== ACCESS_TOKEN_TOKEN_TYPE) {
    txError(ctx, 400, "invalid_request", "subject_token_type MUST be the access_token token type");
    return;
  }
  if (typeof params.subject_token !== "string" || !params.subject_token) {
    txError(ctx, 400, "invalid_request", "subject_token (a designation) required");
    return;
  }
  if (params.actor_token !== undefined || params.actor_token_type !== undefined) {
    txError(ctx, 400, "invalid_request", "this delegated exchange identifies the delegate by its client authentication; actor_token is not supported");
    return;
  }
  if (params.scope !== undefined) {
    txError(ctx, 400, "invalid_scope", "a delegated token carries authority, not scope");
    return;
  }
  if (params.authorization_details !== undefined) {
    txError(ctx, 400, "invalid_request", "a delegated token's authority is the designation's, narrowed for the delegate");
    return;
  }
  const resource = params.resource;
  if (typeof resource !== "string" || !resource) {
    txError(ctx, 400, "invalid_request", "resource (the delegated token's target) required: a designation's audience is a client");
    return;
  }

  // 2. The designation, by its own verifier: never a possession check, since
  // a designation carries no key and its holder is the requesting client.
  let claims: Record<string, unknown>;
  try {
    const { payload } = await jwtVerify(params.subject_token, createLocalJWKSet(opts.publicJwks as never), {
      issuer: opts.issuer,
    });
    claims = payload as Record<string, unknown>;
  } catch {
    txError(ctx, 400, "invalid_request", "subject_token verification failed");
    return;
  }
  const missionId = (claims.mission as { id?: unknown } | undefined)?.id;
  const issuance = typeof missionId === "string" ? accountingFor(opts, claims, missionId) : undefined;
  const mayAct = claims.may_act as { sub?: unknown } | undefined;
  if (
    typeof missionId !== "string" ||
    issuance?.kind !== "designation" ||
    issuance.designee !== client.clientId ||
    claims.aud !== client.clientId ||
    mayAct?.sub !== client.clientId
  ) {
    txError(ctx, 400, "invalid_request", "subject_token is not a designation naming the requesting client");
    return;
  }
  const record = kernel.get(missionId);
  if (!record || !issuance.chain || issuance.depth === undefined) {
    txError(ctx, 400, "invalid_request", "subject_token is not a designation naming the requesting client");
    return;
  }

  // 3. The delegate's own key.
  const proofJws = ctx.get("DPoP");
  if (!proofJws) {
    txError(ctx, 400, "invalid_dpop_proof", "DPoP proof JWT required");
    return;
  }
  const verified = await verifyTokenEndpointDpop(opts, proofJws);
  if (!verified.ok) {
    refuseTokenEndpointProof(ctx, verified);
    return;
  }
  const { jkt } = verified.proof;
  if (jkt === issuance.designatorJkt) {
    txError(ctx, 400, "invalid_request", "a delegated token is bound to the delegate's own key, not the delegating party's");
    return;
  }

  // 4. Source and lifecycle, afresh at every redemption.
  if (!(await isGrantLive(opts, provider, issuance.grantId))) {
    txError(ctx, 400, "invalid_request", "the designation's source grant is no longer valid");
    return;
  }
  const active = activeMission(opts, record);

  // 5. Narrowing at the accounted depth, for this client as delegate.
  if (issuance.chain.length + 1 > MAX_DELEGATION_CHAIN) {
    txError(ctx, 400, "invalid_request", `a delegation chain longer than ${MAX_DELEGATION_CHAIN} is not supported`);
    return;
  }
  const depth = issuance.depth + 1;
  const profile = kernel.actorProfile(client.clientId);
  const actor: AccountedActor = { iss: opts.issuer, sub: client.clientId, ...(profile ? { sub_profile: profile } : {}) };
  const designated = presentedTokenAuthority(claims);
  if (!designated) {
    txError(ctx, 400, "invalid_request", "subject_token carries no readable authorization_details");
    return;
  }
  const effective = effectiveAuthority(opts, ctx, active);
  if (!effective) return;
  // Entries covering `resource`, by exact string equality (the comparison
  // model this slice uses while #1258 settles resource matching).
  const authority = gateDelegableAuthority(
    projectThroughEffective(designated, effective),
    { sub: client.clientId, assertedProfile: profile },
    depth,
  ).filter((e) => e.resource === resource);
  if (authority.length === 0) {
    txError(ctx, 400, "invalid_target", "no entry of the designation permits this delegate at this depth for this resource");
    return;
  }

  // 6. Routing: a delegated token reaches only a Mission-aware target (D166).
  const refusal = delegatedRoutingRefusal(opts.scopeProjection, [resource]);
  if (refusal) {
    txError(ctx, 400, "invalid_target", refusal);
    return;
  }

  // 7. Settle and return the delegated token. The designation is still
  // unexpired after every awaited check, and the token's expiry is pinned
  // within the access-token lifetime and the Mission.
  const chain = [...issuance.chain, actor];
  if (typeof claims.exp !== "number" || claims.exp <= nowSeconds()) {
    txError(ctx, 400, "invalid_request", "the designation has expired");
    return;
  }
  const at = new provider.AccessToken({
    accountId: active.subject.sub,
    client,
    grantId: issuance.grantId,
    gty: TOKEN_EXCHANGE_GRANT_TYPE,
    rar: authority,
    scope: SCOPE_DECIDED_AT_SAVE,
  });
  const lifetime = pinExpiry(
    ctx,
    at,
    [nowSeconds() + (opts.accessTokenTTL ?? 300), epochOf(active.expires_at)],
    "the Mission has no lifetime left to delegate",
  );
  if (lifetime === undefined) return;
  at.resourceServer = newResourceServer(provider, resource, resourceServerInfoFor(resource, lifetime));
  at.jkt = jkt; // the delegate's own key
  fixTokenId(at);
  markDelegationMint(at, { act: renderAct(chain) });
  const jwt = await settle(opts, ctx, at, {
    iss: opts.issuer,
    jti: at.jti as string,
    grantId: issuance.grantId,
    authorizationDetails: authority,
    kind: "delegated",
    missionId: active.id,
    depth,
    chain,
  });
  if (jwt === undefined) return;
  ctx.status = 200;
  ctx.body = {
    access_token: jwt,
    issued_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    token_type: "DPoP",
    expires_in: lifetime,
    ...((at as { scope?: string }).scope ? { scope: (at as { scope?: string }).scope } : {}),
    authorization_details: authority,
  };
  ctx.set("cache-control", "no-store");
}
