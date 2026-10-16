/**
 * @spec status#mission-lifecycle-endpoint, status#mission-status-authentication,
 * status#idempotency: the advertised Mission Lifecycle endpoint's request
 * surface: its form transport, its private-key-JWT client authentication, and
 * the parsing of the state-changing operations' request members.
 *
 * The operation engine (the retransmission rule, operation dispatch, the
 * signed state-only response) lives with the routes in provider.ts. It serves
 * this endpoint and the dev-only path route alike, so the two differ only in
 * how a caller authenticates and how its members arrive.
 */

import type { IncomingMessage } from "node:http";
import { createLocalJWKSet, decodeJwt, decodeProtectedHeader, type JWK, jwtVerify } from "jose";
import type { LifecycleOperation } from "../kernel/types.js";
import { DPOP_PROOF_REPLAY_WINDOW_S, type DpopProofReplay } from "./dpop-replay.js";

/** The advertised endpoint's path, published as `mission_lifecycle_endpoint`. */
export const LIFECYCLE_ENDPOINT_PATH = "/mission/lifecycle";

/**
 * @spec status#as-metadata: the methods this endpoint accepts
 * (`mission_lifecycle_endpoint_auth_methods_supported`). Private-key JWT only:
 * the profile requires at least one of its three mechanisms, and this
 * deployment accepts no access-token scheme here.
 */
export const LIFECYCLE_ENDPOINT_AUTH_METHODS: readonly string[] = ["private_key_jwt"];

/**
 * @spec status#as-metadata: the client-assertion verification set
 * (`mission_lifecycle_endpoint_auth_signing_alg_values_supported`), never
 * `none`. Distinct from the response-signing algorithms.
 */
export const LIFECYCLE_CLIENT_ASSERTION_ALGS: readonly string[] = ["ES256"];

const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/**
 * @spec status#mission-status-authentication: the explicit type a client
 * SHOULD set on its assertion (draft-ietf-oauth-rfc7523bis).
 */
export const CLIENT_AUTHENTICATION_TYP = "client-authentication+jwt";

/** @spec status#mission-lifecycle-endpoint ("Operations"): `reason`'s bound. */
export const REASON_MAX_CHARS = 1024;

/** The request body this endpoint will read at all (bytes). */
const MAX_BODY_BYTES = 64 * 1024;

export type LifecycleFormResult =
  | { ok: true; params: Record<string, string> }
  /** `nonce`: the request's well-formed nonce, for the refusal to echo. */
  | { ok: false; description: string; nonce?: string };

/**
 * @spec status#idempotency: a well-formed `nonce`: a string of 1 to 255
 * characters. Anything else is malformed and never echoed.
 */
export function wellFormedNonce(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 && value.length <= 255 ? value : undefined;
}

/**
 * @spec status#mission-lifecycle-endpoint ("Operations"): read the body as
 * `application/x-www-form-urlencoded` and nothing else. Every member of this
 * endpoint is single-valued, so a repeated parameter is refused rather than
 * resolved: whichever occurrence the server read, another participant may
 * read the other.
 */
export async function readLifecycleForm(req: IncomingMessage, contentType: string): Promise<LifecycleFormResult> {
  const mediaType = contentType.split(";")[0]?.trim().toLowerCase();
  const chunks: Buffer[] = [];
  let size = 0;
  let oversize = false;
  // Drain even past the cap: the request is refused, not left half-read.
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > MAX_BODY_BYTES) oversize = true;
    if (!oversize) chunks.push(buf);
  }
  if (mediaType !== "application/x-www-form-urlencoded") {
    return { ok: false, description: "content-type must be application/x-www-form-urlencoded" };
  }
  if (oversize) return { ok: false, description: "request body is too large" };
  const form = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
  const params: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const [name, value] of form) {
    if (Object.hasOwn(params, name)) {
      const nonces = form.getAll("nonce");
      const nonce = nonces.length === 1 ? wellFormedNonce(nonces[0]) : undefined;
      return { ok: false, description: `${name} MUST NOT appear more than once`, ...(nonce ? { nonce } : {}) };
    }
    params[name] = value;
  }
  return { ok: true, params };
}

export type LifecycleClientAuthentication =
  | { ok: true; clientId: string }
  | { ok: false; description: string; retryAfterS?: number };

export interface LifecycleClientAuthenticationDeps {
  issuer: string;
  clients: ReadonlyArray<Record<string, unknown>>;
  /** The AS's single-use `jti` cache; an assertion's jti is held under `ca:`. */
  replay: DpopProofReplay;
  now: () => Date;
}

/**
 * @spec status#mission-status-authentication, status#mission-status-auth-failures
 * authenticate the caller by private-key JWT (RFC 7523).
 *
 * The ASSERTION names the client: `iss` and `sub` are its identifier, the
 * registered record is selected from that identity, and the signature is
 * checked under that client's keys alone. A `client_id` parameter only
 * corroborates. The assertion's `aud` MUST be this AS's issuer identifier as
 * its sole value: a bare string, or an array holding exactly that one value.
 * The endpoint URL, the token endpoint, or any array adding a second value is
 * refused (draft-ietf-oauth-rfc7523bis). `exp` and `jti` are required, `exp`
 * lies within the replay cache's memory so the jti is single-use for the
 * assertion's whole life, and only the advertised algorithms verify.
 *
 * The JWS `typ` is the client's SHOULD, so an assertion without one, or with
 * the generic `JWT`, is accepted; an assertion explicitly typed as some other
 * kind of JWT is refused, since accepting it would let a token minted for one
 * purpose authenticate here.
 *
 * Plain Basic or POST client authentication, and any `Authorization` header
 * (this endpoint accepts no access-token scheme), are refused. Every failure
 * is the HTTP-layer `invalid_client` the caller maps to a 400; only a jti the
 * full replay cache could not record is retryable.
 */
export async function authenticateLifecycleClient(
  deps: LifecycleClientAuthenticationDeps,
  params: Record<string, string>,
  authorization: string,
): Promise<LifecycleClientAuthentication> {
  const fail = (description: string): LifecycleClientAuthentication => ({ ok: false, description });
  if (authorization) {
    return fail("this endpoint accepts private_key_jwt client authentication only");
  }
  if (params.client_secret !== undefined) {
    return fail("client secret authentication is not accepted at this endpoint");
  }
  const assertion = params.client_assertion;
  if (assertion === undefined && params.client_assertion_type === undefined) {
    return fail("client authentication is required");
  }
  if (params.client_assertion_type !== CLIENT_ASSERTION_TYPE || !assertion) {
    return fail(`client_assertion_type must be ${CLIENT_ASSERTION_TYPE} with a client_assertion`);
  }
  let asserted: string;
  try {
    const typ = decodeProtectedHeader(assertion).typ;
    if (typ !== undefined && !acceptedAssertionTyp(typ)) {
      return fail(`client_assertion typ ${typ} is not a client authentication type`);
    }
    const claims = decodeJwt(assertion);
    if (typeof claims.iss !== "string" || claims.iss.length === 0 || claims.iss !== claims.sub) {
      return fail("client_assertion iss and sub must both name the client");
    }
    asserted = claims.iss;
  } catch {
    return fail("client_assertion is not a JWT");
  }
  if (params.client_id !== undefined && params.client_id !== asserted) {
    return fail("client_id does not match the client_assertion");
  }
  const client = deps.clients.find((c) => c.client_id === asserted);
  const jwks = client?.jwks as { keys?: JWK[] } | undefined;
  if (!client || !jwks?.keys?.length) return fail("client is not registered for private_key_jwt");
  const now = deps.now();
  let payload: Record<string, unknown>;
  try {
    ({ payload } = await jwtVerify(assertion, createLocalJWKSet({ keys: jwks.keys }), {
      algorithms: [...LIFECYCLE_CLIENT_ASSERTION_ALGS],
      issuer: asserted,
      subject: asserted,
      currentDate: now,
      requiredClaims: ["exp", "jti"],
    }));
  } catch {
    return fail("client_assertion did not verify");
  }
  const aud = payload.aud;
  const soleAudience = Array.isArray(aud) ? (aud.length === 1 ? aud[0] : undefined) : aud;
  if (soleAudience !== deps.issuer) {
    return fail("client_assertion aud must be the issuer identifier as its sole value");
  }
  if (typeof payload.exp !== "number" || payload.exp * 1000 > now.getTime() + DPOP_PROOF_REPLAY_WINDOW_S * 1000) {
    return fail(`client_assertion exp must lie within ${DPOP_PROOF_REPLAY_WINDOW_S} seconds`);
  }
  if (typeof payload.jti !== "string" || payload.jti.length === 0) return fail("client_assertion jti is required");
  const admission = deps.replay.admit(`ca:${payload.jti}`);
  if (!admission.admitted) {
    return admission.reason === "full"
      ? { ok: false, description: "client assertion replay cache is full", retryAfterS: admission.retryAfterS }
      : fail("client_assertion jti was already used");
  }
  return { ok: true, clientId: asserted };
}

/** No `typ`, the generic `JWT`, or the client-authentication type (with or without `application/`). */
function acceptedAssertionTyp(typ: string): boolean {
  const t = typ.toLowerCase().replace(/^application\//, "");
  return t === "jwt" || t === CLIENT_AUTHENTICATION_TYP;
}

/**
 * @spec status#mission-lifecycle-endpoint ("Operations"): a `suspend`'s
 * deadline and the transition applied when it passes.
 */
export interface SuspendSchedule {
  suspendUntil: string;
  onExpiry: "resume" | "revoke";
}

/** The parsed request members of `revoke`, `suspend`, `resume` and `complete`. */
export interface TransitionMembers {
  reason?: string;
  /** @spec status#idempotency: the state version the caller last observed. */
  expectedVersion?: number;
  /** Present only on a `suspend` carrying both schedule members. */
  schedule?: SuspendSchedule;
}

export type MembersResult<T> = { ok: true; value: T } | { ok: false; description: string };

/**
 * @spec status#mission-lifecycle-endpoint ("Operations"), status#idempotency:
 * parse the request members of a state-changing operation. Request-shape
 * failures are `invalid_request`; nothing here reads the Mission.
 */
export function parseTransitionMembers(
  operation: LifecycleOperation,
  body: Record<string, unknown>,
): MembersResult<TransitionMembers> {
  const value: TransitionMembers = {};
  const reason = body.reason;
  if (reason !== undefined) {
    if (typeof reason !== "string" || reason.length > REASON_MAX_CHARS) {
      return { ok: false, description: `reason must be a string of at most ${REASON_MAX_CHARS} characters` };
    }
    value.reason = reason;
  }
  const expected = body.expected_version;
  if (expected !== undefined) {
    // The decimal form of a positive integer state version.
    const parsed = typeof expected === "string" && /^[1-9][0-9]*$/.test(expected) ? Number(expected) : Number.NaN;
    if (!Number.isSafeInteger(parsed)) {
      return { ok: false, description: "expected_version must be the decimal form of a state version" };
    }
    value.expectedVersion = parsed;
  }
  const schedule = parseSuspendSchedule(operation, body);
  if (!schedule.ok) return schedule;
  if (schedule.value) value.schedule = schedule.value;
  return { ok: true, value };
}

/** Strict RFC 3339 date-time shape, checked before `Date.parse`. */
const RFC3339_DATE_TIME = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$/;

/**
 * @spec status#mission-lifecycle-endpoint ("Operations"), status#idempotency:
 * THE ONE PLACE a `suspend` request's schedule members are parsed.
 * `suspend_until` is valid only on `suspend`; `on_expiry` is REQUIRED with it
 * and MUST NOT be sent without it, so a request carrying only one of the two
 * is invalid and changes nothing. Undefined when the request carries neither.
 */
export function parseSuspendSchedule(
  operation: LifecycleOperation,
  body: Record<string, unknown>,
): MembersResult<SuspendSchedule | undefined> {
  const until = body.suspend_until;
  const onExpiry = body.on_expiry;
  if (until === undefined && onExpiry === undefined) return { ok: true, value: undefined };
  if (operation !== "suspend") {
    return { ok: false, description: "suspend_until and on_expiry are valid only on suspend" };
  }
  if (until === undefined || onExpiry === undefined) {
    return { ok: false, description: "suspend_until and on_expiry are sent together or not at all" };
  }
  if (typeof until !== "string" || !RFC3339_DATE_TIME.test(until) || Number.isNaN(Date.parse(until))) {
    return { ok: false, description: "suspend_until must be an RFC 3339 date-time" };
  }
  if (onExpiry !== "resume" && onExpiry !== "revoke") {
    return { ok: false, description: "on_expiry must be resume or revoke" };
  }
  return { ok: true, value: { suspendUntil: until, onExpiry } };
}
