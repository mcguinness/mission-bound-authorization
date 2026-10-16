/**
 * @spec status#mission-lifecycle-endpoint, status#mission-status-authentication
 * a test client of the advertised Mission Lifecycle endpoint: a registered
 * private-key-JWT client, its client assertion, the form request, and the
 * decoded signed response.
 */

import { decodeJwt, decodeProtectedHeader, exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import { LIFECYCLE_ENDPOINT_PATH } from "../src/adapters/lifecycle-endpoint.js";

export const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/** A registered lifecycle client: its oidc-provider metadata and its signing key. */
export interface LifecycleTestClient {
  clientId: string;
  kid: string;
  /** The JWS algorithm its key signs with. */
  alg: string;
  privateKey: CryptoKey;
  /** For `buildAuthorizationServer({ testClients })`. */
  metadata: Record<string, unknown>;
}

/** A private-key-JWT client that holds no grant at /token, only a key. */
export async function newLifecycleClient(clientId: string, alg = "ES256"): Promise<LifecycleTestClient> {
  const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true });
  const kid = `${clientId}-key`;
  const jwk = { ...((await exportJWK(publicKey)) as JWK), kid, alg, use: "sig" };
  return {
    clientId,
    kid,
    alg,
    privateKey: privateKey as CryptoKey,
    metadata: {
      client_id: clientId,
      client_name: `${clientId} (lifecycle test client)`,
      grant_types: [],
      response_types: [],
      redirect_uris: [],
      token_endpoint_auth_method: "private_key_jwt",
      token_endpoint_auth_signing_alg: alg,
      jwks: { keys: [jwk] },
    },
  };
}

export interface AssertionOptions {
  /** The `aud` claim; the issuer identifier by default. */
  aud?: string | string[];
  /** The JWS `typ`; `client-authentication+jwt` by default, `null` for none. */
  typ?: string | null;
  /** Seconds until `exp`; 60 by default, `null` for no `exp`. */
  expiresIn?: number | null;
  /** The `jti`; a fresh UUID by default, `null` for none. */
  jti?: string | null;
  /** The `iss` and `sub`; the client's identifier by default. */
  issuer?: string;
  /** Sign with this key instead of the client's. */
  key?: CryptoKey;
}

/**
 * @spec status#mission-status-authentication: the client's assertion: `iss`
 * and `sub` its identifier, `aud` the AS issuer identifier as its sole value,
 * and the JWS `typ` the client SHOULD set, `client-authentication+jwt`.
 */
export async function lifecycleClientAssertion(
  issuer: string,
  client: LifecycleTestClient,
  options: AssertionOptions = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const claims: Record<string, unknown> = {};
  if (options.jti !== null) claims.jti = options.jti ?? crypto.randomUUID();
  const jwt = new SignJWT(claims)
    .setProtectedHeader({
      alg: client.alg,
      kid: client.kid,
      ...(options.typ === null ? {} : { typ: options.typ ?? "client-authentication+jwt" }),
    })
    .setIssuer(options.issuer ?? client.clientId)
    .setSubject(options.issuer ?? client.clientId)
    .setAudience(options.aud ?? issuer)
    .setIssuedAt(now);
  if (options.expiresIn !== null) jwt.setExpirationTime(now + (options.expiresIn ?? 60));
  return jwt.sign(options.key ?? client.privateKey);
}

export interface LifecycleAnswer {
  status: number;
  contentType: string;
  cacheControl: string;
  wwwAuthenticate: string | null;
  text: string;
  /** The JSON body, or undefined for a signed response. */
  json?: Record<string, unknown>;
}

/** POST a form to the advertised endpoint, exactly as given. */
export async function postLifecycleForm(
  issuer: string,
  form: Record<string, string>,
  headers: Record<string, string> = {},
): Promise<LifecycleAnswer> {
  const res = await fetch(`${issuer}${LIFECYCLE_ENDPOINT_PATH}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
    body: new URLSearchParams(form).toString(),
  });
  return readAnswer(res);
}

/** A Lifecycle request from `client`, under a fresh assertion unless one is given. */
export async function lifecycleRequest(
  issuer: string,
  client: LifecycleTestClient,
  members: Record<string, string>,
  assertion?: string,
): Promise<LifecycleAnswer> {
  return postLifecycleForm(issuer, {
    ...members,
    client_assertion_type: CLIENT_ASSERTION_TYPE,
    client_assertion: assertion ?? (await lifecycleClientAssertion(issuer, client)),
  });
}

export async function readAnswer(res: Response): Promise<LifecycleAnswer> {
  const text = await res.text();
  const contentType = res.headers.get("content-type") ?? "";
  let json: Record<string, unknown> | undefined;
  if (contentType.startsWith("application/json")) json = JSON.parse(text) as Record<string, unknown>;
  return {
    status: res.status,
    contentType,
    cacheControl: res.headers.get("cache-control") ?? "",
    wwwAuthenticate: res.headers.get("www-authenticate"),
    text,
    ...(json ? { json } : {}),
  };
}

/** The decoded JWS header and payload of a signed Mission Status Response. */
export function decodeStatusResponse(text: string): {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  mission: Record<string, unknown>;
} {
  const payload = decodeJwt(text) as Record<string, unknown>;
  return {
    header: decodeProtectedHeader(text) as Record<string, unknown>,
    payload,
    mission: payload.mission as Record<string, unknown>,
  };
}
