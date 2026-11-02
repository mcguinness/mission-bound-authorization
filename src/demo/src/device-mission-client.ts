/**
 * @spec device-authorization#discovery, device-authorization#issuance (#1202):
 * the reference client of Mission Device Authorization, for a client with no
 * redirect. It sends a Mission Intent to the RFC 8628 device authorization
 * endpoint only when the AS's validated metadata advertises the profile, never
 * falls back to an ordinary device authorization request, and uses the tokens
 * of a success response only when the response carries the Mission members.
 */

import { dpopProofFor, type DpopKeys } from "./oauth-client.js";

const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const FORM = { "content-type": "application/x-www-form-urlencoded" };
/** RFC 8628 Section 3.2: the polling interval when the response names none. */
const DEFAULT_INTERVAL_SECONDS = 5;
/** RFC 8628 Section 3.5: `slow_down` adds 5 seconds to every later interval. */
const SLOW_DOWN_SECONDS = 5;

export interface DeviceMissionClient {
  /** The issuer identifier the client is configured with. */
  issuer: string;
  /**
   * The device authorization endpoint the client is configured to use. When
   * set, the AS's metadata must name exactly this endpoint; otherwise the
   * client uses the one the metadata names.
   */
  deviceAuthorizationEndpoint?: string;
  /** The client's authentication parameters for each request: `client_id` alone for a public client. */
  authenticate: () => Promise<Record<string, string>>;
  /** The key that sender-constrains the issued tokens (RFC 9449), proved on every poll. */
  dpopKeys?: DpopKeys;
  /** Waits between polls; a test injects one that records the wait instead. */
  sleep?: (ms: number) => Promise<void>;
  /** The clock, in milliseconds, that the session's deadline is measured on; `Date.now` by default. */
  now?: () => number;
}

export interface MissionDeviceRequest {
  /** The Submission envelope, sent only as the form-encoded `mission_intent`. */
  missionIntent: Record<string, unknown>;
  /** An optional authority proposal. */
  authorizationDetails?: unknown[];
  scope?: string;
  resource?: string;
}

/** What the client shows its user: the verification members of RFC 8628 Section 3.2. */
export interface DeviceUserInstruction {
  userCode: string;
  verificationUri: string;
  verificationUriComplete?: string;
  expiresIn: number;
}

export type DeviceMissionSupport =
  | { supported: true; deviceAuthorizationEndpoint: string; tokenEndpoint: string }
  | { supported: false; reason: string };

export type DeviceMissionResult =
  /** The AS does not advertise the profile; the client sent no device authorization request. */
  | { outcome: "unsupported"; reason: string }
  /**
   * No usable Mission: a refused request, a terminal poll error, or a success
   * response lacking a Mission member, whose tokens are discarded.
   */
  | { outcome: "no_mission"; error: string; errorDescription?: string }
  | {
      outcome: "created";
      missionId: string;
      missionExpiresAt: string;
      authorizationDetails: unknown[];
      accessToken: string;
      tokenType: string;
      expiresIn?: number;
      refreshToken?: string;
    };

const unsupported = (reason: string): DeviceMissionSupport => ({ supported: false, reason });

/**
 * Whether the AS advertises Mission Device Authorization, from metadata
 * retrieved at the OpenID-compatible location the reference AS serves
 * (RFC 8414 Section 5) and refused unless its `issuer` equals the configured
 * issuer (Section 3.3). Both support members must be `true`: device-grant
 * metadata or the OAuth binding's member alone establishes nothing.
 */
export async function discoverMissionDeviceSupport(issuer: string, configuredEndpoint?: string): Promise<DeviceMissionSupport> {
  let meta: Record<string, unknown> | undefined;
  try {
    const res = await fetch(`${issuer}/.well-known/openid-configuration`);
    if (res.status !== 200) return unsupported(`${issuer} answered its metadata request with ${res.status}`);
    meta = objectOf(await res.json());
  } catch (e) {
    return unsupported(`${issuer} serves no readable metadata: ${(e as Error).message}`);
  }
  if (meta === undefined) return unsupported(`${issuer} serves metadata that is not a JSON object`);
  if (meta.issuer !== issuer) return unsupported(`${issuer} serves metadata for issuer ${String(meta.issuer)}`);
  if (meta.mission_bound_authorization_supported !== true) {
    return unsupported(`${issuer} does not advertise mission_bound_authorization_supported`);
  }
  if (meta.mission_device_authorization_supported !== true) {
    return unsupported(`${issuer} does not advertise mission_device_authorization_supported`);
  }
  const endpoint = meta.device_authorization_endpoint;
  if (typeof endpoint !== "string") return unsupported(`${issuer} names no device_authorization_endpoint`);
  if (configuredEndpoint !== undefined && endpoint !== configuredEndpoint) {
    return unsupported(`${issuer} names the device_authorization_endpoint ${endpoint}, not ${configuredEndpoint}`);
  }
  if (typeof meta.token_endpoint !== "string") return unsupported(`${issuer} names no token_endpoint`);
  return { supported: true, deviceAuthorizationEndpoint: endpoint, tokenEndpoint: meta.token_endpoint };
}

/**
 * Create a Mission through the device flow: discovery, the device
 * authorization request, `show` with the user code, then polling until the
 * session ends. An unsupported AS receives no request at all; the client
 * reports the inability and never asks for the same authority as `scope` or as
 * `authorization_details` without `mission_intent`.
 */
export async function createMissionByDevice(
  client: DeviceMissionClient,
  request: MissionDeviceRequest,
  show: (instruction: DeviceUserInstruction) => void | Promise<void>,
): Promise<DeviceMissionResult> {
  const support = await discoverMissionDeviceSupport(client.issuer, client.deviceAuthorizationEndpoint);
  if (!support.supported) return { outcome: "unsupported", reason: support.reason };

  const form = new URLSearchParams({ ...(await client.authenticate()), mission_intent: JSON.stringify(request.missionIntent) });
  if (request.authorizationDetails) form.set("authorization_details", JSON.stringify(request.authorizationDetails));
  if (request.scope) form.set("scope", request.scope);
  if (request.resource) form.set("resource", request.resource);
  const now = client.now ?? Date.now;
  const res = await fetch(support.deviceAuthorizationEndpoint, { method: "POST", headers: FORM, body: form.toString() });
  const session = await jsonOf(res);
  if (res.status !== 200) return refused(session, res.status);
  const { device_code: deviceCode, user_code: userCode, verification_uri: verificationUri, expires_in: expiresIn } = session;
  if (typeof deviceCode !== "string" || typeof userCode !== "string" || typeof verificationUri !== "string" || typeof expiresIn !== "number") {
    return { outcome: "no_mission", error: "invalid_device_authorization_response" };
  }
  // RFC 8628 Section 3.2: `expires_in` runs from this response. Every later
  // moment, the user's time with the code, authentication and requests
  // included, is measured against this deadline.
  const deadline = now() + expiresIn * 1000;
  await show({
    userCode,
    verificationUri,
    ...(typeof session.verification_uri_complete === "string" ? { verificationUriComplete: session.verification_uri_complete } : {}),
    expiresIn,
  });

  const sleep = client.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  let interval = typeof session.interval === "number" ? session.interval : DEFAULT_INTERVAL_SECONDS;
  for (;;) {
    // A poll the interval would delay to or past the deadline is never
    // waited for, and the deadline is checked again just before sending, so a
    // wait or an authentication that ran up to it sends nothing.
    if (now() + interval * 1000 >= deadline) break;
    await sleep(interval * 1000);
    const headers: Record<string, string> = { ...FORM };
    if (client.dpopKeys) headers.dpop = await dpopProofFor(client.dpopKeys, support.tokenEndpoint, "POST");
    const body = new URLSearchParams({ ...(await client.authenticate()), grant_type: DEVICE_GRANT, device_code: deviceCode });
    if (now() >= deadline) break;
    const polled = await fetch(support.tokenEndpoint, { method: "POST", headers, body: body.toString() });
    const answer = await jsonOf(polled);
    if (polled.status === 200) return missionResponse(answer);
    if (answer.error === "authorization_pending") continue;
    if (answer.error === "slow_down") {
      interval += SLOW_DOWN_SECONDS;
      continue;
    }
    return refused(answer, polled.status);
  }
  return { outcome: "no_mission", error: "expired_token", errorDescription: "the device_code lifetime elapsed while polling" };
}

/**
 * @spec device-authorization#issuance: a success response lacking
 * `mission_id`, `mission_expires_at` or the granted `authorization_details` is
 * a failed Mission creation. Its tokens are discarded, never returned to the
 * caller, so none is presented.
 */
function missionResponse(body: Record<string, unknown>): DeviceMissionResult {
  const missing = [
    typeof body.mission_id === "string" && body.mission_id !== "" ? undefined : "mission_id",
    typeof body.mission_expires_at === "string" && body.mission_expires_at !== "" ? undefined : "mission_expires_at",
    Array.isArray(body.authorization_details) ? undefined : "authorization_details",
  ].filter((m): m is string => m !== undefined);
  if (missing.length > 0) {
    return { outcome: "no_mission", error: "mission_members_missing", errorDescription: `the token response lacks ${missing.join(", ")}` };
  }
  if (typeof body.access_token !== "string" || typeof body.token_type !== "string") {
    return { outcome: "no_mission", error: "invalid_token_response" };
  }
  return {
    outcome: "created",
    missionId: body.mission_id as string,
    missionExpiresAt: body.mission_expires_at as string,
    authorizationDetails: body.authorization_details as unknown[],
    accessToken: body.access_token,
    tokenType: body.token_type,
    ...(typeof body.expires_in === "number" ? { expiresIn: body.expires_in } : {}),
    ...(typeof body.refresh_token === "string" ? { refreshToken: body.refresh_token } : {}),
  };
}

function refused(body: Record<string, unknown>, status: number): DeviceMissionResult {
  return {
    outcome: "no_mission",
    error: typeof body.error === "string" ? body.error : `http_${status}`,
    ...(typeof body.error_description === "string" ? { errorDescription: body.error_description } : {}),
  };
}

function objectOf(body: unknown): Record<string, unknown> | undefined {
  return body !== null && typeof body === "object" && !Array.isArray(body) ? (body as Record<string, unknown>) : undefined;
}

async function jsonOf(res: Response): Promise<Record<string, unknown>> {
  try {
    return objectOf(await res.json()) ?? {};
  } catch {
    return {};
  }
}
