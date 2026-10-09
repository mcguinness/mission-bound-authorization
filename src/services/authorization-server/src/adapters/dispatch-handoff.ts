/**
 * @spec mission-template#dispatch-handoff (#1158; D357, D358, D361)
 *
 * The Dispatch Handoff conveys a dispatched instance to its selected Agent.
 * The Dispatcher holds the instance's access token, sender-constrained to its
 * own key; the instance's approved agent is the selected Agent (the Mission
 * Record's `client_id`). The Dispatcher exchanges the token (RFC 8693,
 * `mission_dispatch_handoff=true`, a DPoP proof of the token's own key) for a
 * short-lived, single-use grant naming the Agent as its only redeemer; the
 * Agent redeems it under RFC 7523, authenticating as itself with its own key,
 * for a token of its own. The grant is validated apart from the child grant:
 * its own `typ`, its own single-use store.
 */

import { randomBytes } from "node:crypto";
import { createLocalJWKSet, type CryptoKey, type JSONWebKeySet, jwtVerify, SignJWT } from "jose";
import { errors, type KoaContextWithOIDC } from "oidc-provider";
import type Provider from "oidc-provider";
import { isSubsetSetIgnoringCapabilitySources } from "@mission/core";
import { projectThroughEffective, SourceUnavailableError } from "../kernel/derive.js";
import type { AuthorityEntry, MissionRecord } from "../kernel/types.js";
import { GateError } from "../kernel/kernel.js";
import { CHILD_JWT_BEARER_GRANT_TYPE } from "./child-grant.js";
import {
  authoritySource,
  JWT_TOKEN_TYPE,
  presentedTokenAuthority,
  txError,
  verifySubjectPossession,
  verifyTokenEndpointDpop,
} from "./continuation-grant.js";
import {
  type AdapterOptions,
  gateErrorToMissionError,
  markDelegationHandle,
  MissionGrantError,
  newResourceServer,
  resourceServerInfoFor,
  SCOPE_DECIDED_AT_SAVE,
} from "./provider.js";

/** @spec mission-template#dispatch-handoff: the handoff grant's JWS `typ` (media type application/mission-dispatch-handoff+jwt). */
export const DISPATCH_HANDOFF_TYP = "mission-dispatch-handoff+jwt";

/** The handoff grant is short-lived, and never outlasts the instance. */
export const MAX_DISPATCH_HANDOFF_LIFETIME_S = 300;

/** The token request parameter that selects the handoff (registered by the Template profile). */
export const DISPATCH_HANDOFF_PARAM = "mission_dispatch_handoff";

/**
 * The parameters that select another exchange: combined with the handoff
 * selector they are refused (`invalid_request`), never routed to that
 * exchange. `request_refresh_token` selects async delegation; the rest are
 * Child Mission creation's (`actor_token` included: the handoff has no actor).
 */
export const DISPATCH_HANDOFF_CONFLICTS = [
  "request_refresh_token",
  "mission_intent",
  "child_actor",
  "parent",
  "creation_request_id",
  "carryover_replacement",
  "actor_token",
] as const;

/** The AS signing material for the handoff grant (its token key, as for the child grant). */
export interface DispatchHandoffSigner {
  key: CryptoKey;
  kid: string;
  alg: string;
}

/**
 * Mint the handoff grant: `aud` identifies the redeeming AS's token endpoint,
 * `client_id` the selected Agent (the Mission Record's `client_id`) as the
 * only redeemer. Not a derivation: the redemption is (it mints the token).
 */
export async function mintDispatchHandoffGrant(
  signer: DispatchHandoffSigner,
  input: {
    issuer: string;
    instance: MissionRecord;
    missionClaim: unknown;
    authority: AuthorityEntry[];
    now: Date;
  },
): Promise<{ grant: string; jti: string; expiresIn: number }> {
  const nowS = Math.floor(input.now.getTime() / 1000);
  const exp = Math.min(nowS + MAX_DISPATCH_HANDOFF_LIFETIME_S, Math.floor(Date.parse(input.instance.expires_at) / 1000));
  const jti = `dho_${randomBytes(16).toString("base64url")}`;
  const grant = await new SignJWT({
    mission: input.missionClaim,
    authorization_details: input.authority,
    client_id: input.instance.client_id,
  })
    .setProtectedHeader({ alg: signer.alg, kid: signer.kid, typ: DISPATCH_HANDOFF_TYP })
    .setIssuer(input.issuer)
    .setAudience(`${input.issuer}/token`)
    .setSubject(input.instance.subject.sub)
    .setIssuedAt(nowS)
    .setExpirationTime(exp)
    .setJti(jti)
    .sign(signer.key);
  return { grant, jti, expiresIn: exp - nowS };
}

/** The claims of a verified handoff grant. */
export interface DispatchHandoffClaims {
  clientId: string;
  missionId: string;
  missionIssuer: unknown;
  authority: AuthorityEntry[];
  jti: string;
  expMs: number;
}

/**
 * @spec mission-template#dispatch-handoff redemption step 1: verify the
 * grant's signature, `typ` and `exp`, and that its `aud` identifies this AS's
 * token endpoint. `undefined` for any grant that fails, a child grant
 * included: the handoff grant is validated apart from it.
 */
export async function verifyDispatchHandoffGrant(
  grant: string,
  jwks: JSONWebKeySet,
  issuer: string,
): Promise<DispatchHandoffClaims | undefined> {
  let payload: Record<string, unknown>;
  try {
    const verified = await jwtVerify(grant, createLocalJWKSet(jwks), {
      issuer,
      audience: `${issuer}/token`,
      typ: DISPATCH_HANDOFF_TYP,
    });
    payload = verified.payload as Record<string, unknown>;
  } catch {
    return undefined;
  }
  const mission = payload.mission as { id?: unknown; issuer?: unknown } | undefined;
  const authority = payload.authorization_details;
  if (
    typeof payload.client_id !== "string" ||
    typeof mission?.id !== "string" ||
    typeof payload.jti !== "string" ||
    typeof payload.exp !== "number" ||
    !Array.isArray(authority) ||
    authority.length === 0
  ) {
    return undefined;
  }
  return {
    clientId: payload.client_id,
    missionId: mission.id,
    missionIssuer: mission.issuer,
    authority: authority as AuthorityEntry[],
    jti: payload.jti,
    expMs: payload.exp * 1000,
  };
}

/**
 * @spec mission-template#dispatch-handoff: the exchange. The router has
 * already checked the selector (`true`, no conflicting selector, the jwt
 * `requested_token_type`). Steps follow the Template profile; the response is
 * the handoff grant, and nothing is counted (the redemption is the
 * derivation).
 */
export async function handleDispatchHandoffExchange(opts: AdapterOptions, ctx: KoaContextWithOIDC): Promise<void> {
  const { kernel } = opts;
  const params = ctx.oidc.params as Record<string, unknown>;
  // The grant carries authority, not scope: a requested `scope` is refused,
  // as on the child-creation exchange that also issues a grant.
  if (params.scope !== undefined) {
    throw new errors.InvalidScope("scope is not supported on this exchange", String(params.scope));
  }
  // 1. The subject token, and possession of the key it is bound to.
  const resolved = await verifySubjectPossession(opts, ctx);
  if (!resolved) return;
  // 2. The authenticated client is the client the token was issued to.
  const client = ctx.oidc.client as NonNullable<typeof ctx.oidc.client>;
  if (resolved.claims.client_id !== client.clientId) {
    txError(ctx, 400, "invalid_grant", "subject_token was not issued to the authenticated client");
    return;
  }
  // 3. A dispatched instance, active.
  const record = resolved.record;
  if (!record.template) {
    txError(ctx, 400, "invalid_grant", "subject_token's Mission is not a dispatched instance");
    return;
  }
  const active = kernel.applyExpiry(record);
  if (active.state !== "active") {
    txError(ctx, 400, "invalid_grant", `dispatched instance is ${active.state}`);
    return;
  }
  const presented = presentedTokenAuthority(resolved.claims);
  if (!presented) {
    txError(ctx, 400, "invalid_grant", "subject_token carries no readable authorization_details");
    return;
  }

  // 5. The handed-off authority: within the presented token's and the current
  //    effective set, the request (if any) a subset of both.
  let requested: AuthorityEntry[] | undefined;
  const requestedRaw = params.authorization_details;
  if (requestedRaw !== undefined) {
    let parsed: unknown = requestedRaw;
    if (typeof requestedRaw === "string") {
      try {
        parsed = JSON.parse(requestedRaw);
      } catch {
        throw new errors.InvalidRequest("authorization_details must be a JSON array");
      }
    }
    if (!Array.isArray(parsed)) throw new errors.InvalidRequest("authorization_details must be a JSON array");
    requested = parsed as AuthorityEntry[];
  }
  let effective: AuthorityEntry[];
  try {
    effective = authoritySource(opts).effectiveAuthoritySet(active);
  } catch (e) {
    if (e instanceof SourceUnavailableError) {
      txError(ctx, 503, "temporarily_unavailable", e.message);
      return;
    }
    throw e;
  }
  let authority: AuthorityEntry[];
  if (requested === undefined) {
    authority = projectThroughEffective(presented, effective);
  } else {
    if (!isSubsetSetIgnoringCapabilitySources(requested, presented)) {
      txError(ctx, 400, "invalid_authorization_details", "requested authorization_details exceed the presented token's authority");
      return;
    }
    if (!isSubsetSetIgnoringCapabilitySources(requested, effective)) {
      txError(ctx, 400, "invalid_authorization_details", "requested authorization_details exceed the Mission authority");
      return;
    }
    authority = projectThroughEffective(requested, effective);
  }
  if (authority.length === 0) {
    txError(ctx, 400, "invalid_authorization_details", "handed-off authorization_details must be non-empty");
    return;
  }

  // 4. The recipient is the instance's recorded client_id (its selected
  //    Agent), never a request parameter.
  if (!opts.childGrantKey || !opts.childGrantKid || !opts.childGrantAlg) {
    ctx.status = 501;
    ctx.body = { error: "dispatch_handoff_unsupported" };
    return;
  }
  const { grant, expiresIn } = await mintDispatchHandoffGrant(
    { key: opts.childGrantKey, kid: opts.childGrantKid, alg: opts.childGrantAlg },
    { issuer: opts.issuer, instance: active, missionClaim: resolved.claims.mission, authority, now: kernel.nowDate() },
  );
  ctx.status = 200;
  ctx.set("cache-control", "no-store");
  ctx.body = {
    access_token: grant,
    issued_token_type: JWT_TOKEN_TYPE,
    token_type: "N_A",
    expires_in: expiresIn,
  };
}

function refuse(ctx: KoaContextWithOIDC, error: string, description: string): void {
  ctx.status = 400;
  ctx.body = { error, error_description: description };
  ctx.set("cache-control", "no-store");
}

/**
 * @spec mission-template#dispatch-handoff: redemption. Client authentication
 * (private_key_jwt) has run, so `ctx.oidc.client` is the authenticated client.
 * Steps follow the Template profile's redemption rules. The token is issued to
 * the Agent under a provider Grant of its own, recorded in the Mission-bound
 * grant index (kind `dispatch-handoff`) WITHOUT moving the Mission's
 * `grant_id`, so the Dispatcher's token keeps resolving. The redemption is
 * one counted derivation (`reserveDerivation` here, keyed by the grant); the
 * save-time hook then resolves the grant through the index and re-gates with
 * `gateActive` only, as for a delegation family, so nothing is counted twice.
 */
export async function handleDispatchHandoffRedemption(
  opts: AdapterOptions,
  provider: Provider,
  ctx: KoaContextWithOIDC,
  assertion: string,
): Promise<void> {
  const { kernel } = opts;
  const client = ctx.oidc.client as NonNullable<typeof ctx.oidc.client>;

  // 1. The grant itself: signature, typ, exp, and aud = this token endpoint.
  const grant = await verifyDispatchHandoffGrant(assertion, opts.publicJwks as JSONWebKeySet, opts.issuer);
  if (!grant) {
    refuse(ctx, "invalid_grant", "invalid dispatch handoff grant");
    return;
  }

  // 2. One client: the grant's redeemer, the authenticated client, and the
  //    instance's recorded client_id (its selected Agent).
  if (grant.clientId !== client.clientId) {
    refuse(ctx, "invalid_grant", "dispatch handoff grant redeemer does not match the authenticated client");
    return;
  }
  //    The grant is AS-signed and minted only for a dispatched instance's
  //    recorded client_id, so the record comparison below is defence in depth
  //    against a grant this AS did not mint that way.
  const record = kernel.get(grant.missionId);
  if (!record || record.issuer !== grant.missionIssuer || record.client_id !== grant.clientId || !record.template) {
    refuse(ctx, "invalid_grant", "dispatch handoff grant does not match a dispatched instance's selected Agent");
    return;
  }

  // The Agent's own key: its DPoP proof binds the token it receives. Every
  // proof failure is invalid_dpop_proof (@spec RFC 9449 Section 4.3, #1163
  // review), a stale or incomplete proof included.
  const proofJws = ctx.get("DPoP");
  if (!proofJws) throw new errors.InvalidRequest("DPoP proof JWT required");
  const verified = await verifyTokenEndpointDpop(opts, proofJws);
  if (!verified.ok) {
    refuse(ctx, "invalid_dpop_proof", verified.description);
    return;
  }
  const { jkt } = verified.proof;

  // 5 (resolved first). The grant's authority narrowed by the current
  //    effective set, resolved through the authority source BEFORE the grant
  //    is taken (#1163 review): a transient outage refuses 503 and leaves the
  //    grant redeemable.
  let effective: AuthorityEntry[];
  try {
    effective = authoritySource(opts).effectiveAuthoritySet(record);
  } catch (e) {
    if (e instanceof SourceUnavailableError) {
      txError(ctx, 503, "temporarily_unavailable", e.message);
      return;
    }
    throw e;
  }
  const authority = projectThroughEffective(grant.authority, effective);
  if (authority.length === 0) {
    refuse(ctx, "invalid_grant", "the handed-off authority is no longer within the instance's effective authority");
    return;
  }

  // 4. Single use: the jti is taken atomically, then confirmed once the token
  //    exists; a redemption that issues no token releases it, so the grant
  //    stays redeemable within its lifetime.
  const taken = kernel.dispatchHandoffs.reserve({ jti: grant.jti, missionId: record.id, expMs: grant.expMs });
  if (taken === "consumed") {
    refuse(ctx, "invalid_grant", "dispatch handoff grant was already redeemed");
    return;
  }
  if (taken === "in-progress") {
    txError(ctx, 400, "invalid_request", "a redemption of this dispatch handoff grant is in progress; retry with the same grant");
    return;
  }

  // 3 and 5. The Agent's token, under a provider Grant owned by the Agent and
  //    recorded as Mission-bound. The redemption is one counted derivation,
  //    reserved against the grant's own jti as its operation identity
  //    (@spec control-plane#serialization): its gate refuses an instance that
  //    is not active (the grant is then released), and a retry after a failed
  //    attempt replays that reservation and never counts twice.
  let oidcGrant: { destroy: () => Promise<void> } | undefined;
  let derivationReservation: string | undefined;
  let jwt: string;
  let at: InstanceType<Provider["AccessToken"]>;
  try {
    // @spec mission-template#dispatch-handoff, continuation#transport-async
    // (#1157, D358) — the redeemed token is the Agent's delegation handle: its
    // audience is the Agent's own client_id (not a resource), and it is
    // sender-constrained to the Agent's key, so the Agent opens the async
    // delegation family as its approved agent.
    const handleAudience = record.client_id;
    const agentGrant = new provider.Grant({ accountId: record.subject.sub, clientId: record.client_id });
    for (const entry of authority) {
      (agentGrant as unknown as { addRar: (d: unknown) => void }).addRar(entry);
    }
    const grantId = await agentGrant.save();
    oidcGrant = agentGrant as unknown as { destroy: () => Promise<void> };
    kernel.missionBoundGrants.record({ grantId, missionId: record.id, kind: "dispatch-handoff" });
    const admitted = kernel.reserveDerivation(record.id, { operationId: `dispatch-handoff:${grant.jti}` });
    derivationReservation = admitted.reservation.reservation.reservationId;

    const info = resourceServerInfoFor(handleAudience, opts.accessTokenTTL ?? 300);
    info.accessTokenTTL = Math.min(
      info.accessTokenTTL,
      Math.max(1, Math.floor((Date.parse(record.expires_at) - Date.now()) / 1000)),
    );
    at = new provider.AccessToken({
      accountId: record.subject.sub,
      client,
      grantId,
      gty: CHILD_JWT_BEARER_GRANT_TYPE,
      rar: authority,
      scope: SCOPE_DECIDED_AT_SAVE,
    });
    at.resourceServer = newResourceServer(provider, handleAudience, info);
    at.jkt = jkt; // sender-constrained to the Agent's own key
    markDelegationHandle(at);
    ctx.oidc.entity("AccessToken", at);
    jwt = await at.save();
  } catch (e) {
    // No token was issued: release the grant and drop the Agent's provider
    // Grant. A derivation already reserved stays pending under the grant's
    // operation identity, so the retry mints against it.
    kernel.dispatchHandoffs.release(grant.jti);
    await oidcGrant?.destroy();
    if (e instanceof SourceUnavailableError) {
      txError(ctx, 503, "temporarily_unavailable", e.message);
      return;
    }
    throw gateRefusal(opts, e, record.id);
  }
  kernel.releaseDerivation(derivationReservation as string, { artifactId: at.jti });
  kernel.dispatchHandoffs.confirm(grant.jti);

  ctx.status = 200;
  ctx.body = {
    access_token: jwt,
    token_type: "DPoP",
    expires_in: at.expiration,
    ...(at.scope ? { scope: at.scope } : {}),
    authorization_details: authority,
  };
  ctx.set("cache-control", "no-store");
}

/** A kernel {@link GateError} as `invalid_grant`, with `mission_error` where a value applies. */
export function gateRefusal(opts: AdapterOptions, e: unknown, missionId: string): unknown {
  return e instanceof GateError
    ? new MissionGrantError(e.message, gateErrorToMissionError(e.reason, opts.kernel.get(missionId)?.state))
    : e;
}
