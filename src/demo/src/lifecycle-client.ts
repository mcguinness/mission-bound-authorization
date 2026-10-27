/**
 * @spec status#mission-lifecycle-endpoint, status#mission-status-authentication:
 * the reference client of the Mission Lifecycle endpoint, a dedicated lifecycle
 * console. It generates its own ES256 key and keeps the private half; the AS is
 * given only the public half, with the lifecycle grants the deployment binds to
 * this one client (`lifecycleClients`). It discovers the endpoint from the AS
 * metadata and authenticates each request by private-key JWT.
 */

import type { LifecycleClientRegistration } from "@mission/authorization-server";
import { declaredStatusKeys, MISSION_STATUS_SKEW_SECONDS, verifyMissionStatusResponse } from "@mission/pdp";
import {
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  importJWK,
  type JSONWebKeySet,
  type JWK,
  type JWTPayload,
  SignJWT,
} from "jose";

const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/** The console's own credential: its identifier and the private half of its key. */
export interface LifecycleConsoleCredentials {
  clientId: string;
  kid: string;
  privateJwk: Record<string, unknown>;
}

/**
 * A new lifecycle console: its credential, kept by the console, and the
 * registration the deployment hands its AS (public key and grants only).
 */
export async function newLifecycleConsole(
  clientId = "lifecycle-console",
  grants: readonly string[] = ["mission_lifecycle"],
): Promise<{ credentials: LifecycleConsoleCredentials; registration: LifecycleClientRegistration }> {
  const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
  const kid = `${clientId}-auth`;
  const publicJwk = { ...(await exportJWK(publicKey)), kid, alg: "ES256", use: "sig" };
  const privateJwk = { ...(await exportJWK(privateKey)), kid, alg: "ES256" };
  return {
    credentials: { clientId, kid, privateJwk: privateJwk as Record<string, unknown> },
    registration: {
      client_id: clientId,
      client_name: "Lifecycle console",
      jwks: { keys: [publicJwk as Record<string, unknown>] },
      grants,
    },
  };
}

/**
 * @spec status#mission-status-authentication: the console's client assertion.
 * `iss` and `sub` are its identifier, `aud` is the AS's issuer identifier as
 * its sole value, `exp` is a minute away, `jti` is fresh, and the JWS `typ` is
 * `client-authentication+jwt`, the explicit type the client SHOULD set.
 */
export async function lifecycleClientAssertion(
  issuer: string,
  client: LifecycleConsoleCredentials,
): Promise<string> {
  const key = await importJWK(client.privateJwk as JWK, "ES256");
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: client.kid, typ: "client-authentication+jwt" })
    .setIssuer(client.clientId)
    .setSubject(client.clientId)
    .setAudience(issuer)
    .setIssuedAt()
    .setExpirationTime("60s")
    .setJti(crypto.randomUUID())
    .sign(key);
}

/** What the client reads from the AS's validated metadata. */
export interface LifecycleIssuerMetadata {
  issuer: string;
  /** `mission_lifecycle_endpoint`. */
  endpoint: string;
  /** `jwks_uri`, the source of the keys it verifies responses with. */
  jwksUri: string;
  /** `mission_status_signing_alg_values_supported`. */
  signingAlgs: readonly string[];
}

/**
 * @spec status#mission-status (RFC 8414 Section 3.3): the metadata of
 * the issuer the client is configured with, retrieved from that identifier
 * and refused unless its `issuer` equals it, so neither the endpoint nor the
 * `jwks_uri` comes from another issuer.
 */
export async function discoverLifecycleIssuer(issuer: string): Promise<LifecycleIssuerMetadata> {
  const meta = (await (await fetch(`${issuer}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
  if (meta.issuer !== issuer) throw new Error(`${issuer} serves metadata for issuer ${String(meta.issuer)}`);
  const endpoint = meta.mission_lifecycle_endpoint;
  if (typeof endpoint !== "string") throw new Error(`${issuer} advertises no mission_lifecycle_endpoint`);
  if (typeof meta.jwks_uri !== "string") throw new Error(`${issuer} advertises no jwks_uri`);
  const algs = meta.mission_status_signing_alg_values_supported;
  return {
    issuer,
    endpoint,
    jwksUri: meta.jwks_uri,
    signingAlgs: Array.isArray(algs) ? algs.filter((a): a is string => typeof a === "string") : [],
  };
}

/** The endpoint the AS advertises as `mission_lifecycle_endpoint`. */
export async function discoverLifecycleEndpoint(issuer: string): Promise<string> {
  return (await discoverLifecycleIssuer(issuer)).endpoint;
}

/**
 * One Lifecycle request: the form members (`mission_id`, `operation`, `nonce`
 * and any others) under a fresh client assertion. Returns the status, the
 * content type and the body text (a signed Mission Status Response on success).
 */
export async function requestLifecycle(
  issuer: string,
  client: LifecycleConsoleCredentials,
  members: Record<string, string>,
): Promise<{ status: number; contentType: string; text: string }> {
  const res = await fetch(await discoverLifecycleEndpoint(issuer), {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      ...members,
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: await lifecycleClientAssertion(issuer, client),
    }).toString(),
  });
  return { status: res.status, contentType: res.headers.get("content-type") ?? "", text: await res.text() };
}

/**
 * @spec status#lifecycle-operations, status#idempotency: one operation the
 * console requested, retained so that a retry retransmits it: the Mission, the
 * operation's members and the `nonce` drawn for it. A retransmission comes only
 * from this record, so it repeats the members and the `nonce` exactly.
 */
export interface LifecycleRequestRecord {
  missionId: string;
  /** The operation's members (`operation`, `reason` and any others); never `mission_id` or `nonce`. */
  members: Readonly<Record<string, string>>;
  nonce: string;
}

/**
 * @spec status#lifecycle-operations: a NEW operation on a Mission, under a
 * fresh `nonce`. A random UUID carries 122 random bits, so the value is unique
 * among the console's nonces for that Mission within any deduplication
 * window. A retry never draws one: it retransmits the record
 * ({@link transmitLifecycle}).
 */
export function newLifecycleRequest(missionId: string, members: Record<string, string>): LifecycleRequestRecord {
  if ("mission_id" in members || "nonce" in members) {
    throw new Error("the record sets mission_id and nonce itself");
  }
  return { missionId, members: Object.freeze({ ...members }), nonce: crypto.randomUUID() };
}

/**
 * @spec status#idempotency: transmit a retained request, its first
 * transmission and every retransmission alike: the same members and the same
 * `nonce`, under a fresh client assertion, which the AS's comparison excludes.
 */
export function transmitLifecycle(
  issuer: string,
  client: LifecycleConsoleCredentials,
  request: LifecycleRequestRecord,
): Promise<{ status: number; contentType: string; text: string }> {
  return requestLifecycle(issuer, client, { ...request.members, mission_id: request.missionId, nonce: request.nonce });
}

/** What a verified Lifecycle response establishes. */
export type LifecycleVerdict =
  /** A current response: its observation may be relied on within its signed bounds. */
  | { kind: "observation"; payload: JWTPayload; mission: Record<string, unknown> }
  /**
   * @spec status#idempotency: an expired replay of the retained request. It
   * confirms that request's outcome and nothing else, so it carries no
   * Mission object to cache or rely on: it refreshes no cached state,
   * authorizes no action, and is not the Mission's current state, for which
   * the client obtains a fresh Mission Status Response.
   */
  | { kind: "confirmation"; missionId: string; nonce: string; outcome: { state: unknown; version: unknown } }
  | { kind: "refused"; reason: string };

/**
 * @spec status#mission-status-response, status#idempotency: verify the
 * response to a retained request by the consumer checks, through the shared
 * verifier (`@mission/pdp`): `alg` among those the AS advertises (check 2);
 * the signature under a key the client's configuration trusts for Status
 * responses (`trustedKids`) among those the AS's `jwks_uri` publishes NOW, read
 * afresh for every verification, so a key the AS has withdrawn as compromised
 * is never used (check 3); `iss` and `mission.issuer` the configured issuer
 * (4); `aud` and `sub` the client (5, 6); `nonce` and `mission.id` the retained
 * request's (7, 8); `iat` not in the future and `exp` not past, with the
 * profile's skew (9); `fresh_until` within `exp` (10).
 *
 * A replay whose `exp` has passed fails check 9 unless it correlates to the
 * retained request (checks 7 and 8) and passes every other check: then it is
 * accepted as a confirmation only.
 */
export async function verifyLifecycleResponse(
  jws: string,
  context: {
    issuer: string;
    client: Pick<LifecycleConsoleCredentials, "clientId">;
    request: LifecycleRequestRecord;
    trustedKids: readonly string[];
    now?: () => Date;
  },
): Promise<LifecycleVerdict> {
  const { issuer, client, request } = context;
  const now = context.now?.() ?? new Date();
  const meta = await discoverLifecycleIssuer(issuer);
  let alg: unknown;
  try {
    alg = decodeProtectedHeader(jws).alg;
  } catch {
    return { kind: "refused", reason: "not a JWS" };
  }
  if (typeof alg !== "string" || alg === "none" || !meta.signingAlgs.includes(alg)) return { kind: "refused", reason: "alg" };
  const published = (await (await fetch(meta.jwksUri)).json()) as JSONWebKeySet;
  const verified = await verifyMissionStatusResponse(
    jws,
    { missionId: request.missionId, issuer, audience: client.clientId },
    declaredStatusKeys(published, context.trustedKids),
    now,
    MISSION_STATUS_SKEW_SECONDS,
    { expired: "report" },
  );
  if (verified === undefined) return { kind: "refused", reason: "signature or claims" };
  const { payload, mission } = verified;
  if (payload.sub !== client.clientId) return { kind: "refused", reason: "sub" };
  if (payload.nonce !== request.nonce) return { kind: "refused", reason: "nonce" };
  if ((payload.iat as number) * 1000 - now.getTime() > MISSION_STATUS_SKEW_SECONDS * 1000) {
    return { kind: "refused", reason: "iat" };
  }
  if (verified.expired) {
    return {
      kind: "confirmation",
      missionId: request.missionId,
      nonce: request.nonce,
      outcome: { state: mission.state, version: mission.version },
    };
  }
  return { kind: "observation", payload, mission };
}
