/**
 * @spec status#mission-lifecycle-endpoint, status#mission-status-authentication:
 * the reference client of the Mission Lifecycle endpoint, a dedicated lifecycle
 * console. It generates its own ES256 key and keeps the private half; the AS is
 * given only the public half, with the lifecycle grants the deployment binds to
 * this one client (`lifecycleClients`). It discovers the endpoint from the AS
 * metadata and authenticates each request by private-key JWT.
 */

import type { LifecycleClientRegistration } from "@mission/authorization-server";
import { exportJWK, generateKeyPair, importJWK, type JWK, SignJWT } from "jose";

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

/** The endpoint the AS advertises as `mission_lifecycle_endpoint`. */
export async function discoverLifecycleEndpoint(issuer: string): Promise<string> {
  const meta = (await (await fetch(`${issuer}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
  const endpoint = meta.mission_lifecycle_endpoint;
  if (typeof endpoint !== "string") throw new Error(`${issuer} advertises no mission_lifecycle_endpoint`);
  return endpoint;
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
