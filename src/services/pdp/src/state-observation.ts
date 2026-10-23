/**
 * @spec authzen#context-audience-freshness, authzen#mission-status-composition
 * (#1004): the PEP's Mission state observation as the AuthZEN profile carries
 * it, at `context.mission_state_observation`. It conveys the runtime
 * profile's state and freshness inputs on the wire; the trusted state source
 * and its staleness bound are the deployment's declaration, never a request
 * member.
 */

import { type JWTPayload, type JWTVerifyGetKey, jwtVerify } from "jose";

/**
 * The observation's members. Typed `string` where the profile names a closed
 * set or a timestamp: a value outside the set, or one that does not parse, is
 * refused at evaluation rather than admitted by the type system.
 */
export interface MissionStateObservation {
  /** REQUIRED. The lifecycle state the PEP established; only exactly `active` is active. */
  state: string;
  /** OPTIONAL. The Mission's state version, compared against the PDP's tracked version. */
  version?: number;
  /** REQUIRED. `fresh`, `cached`, or `event_driven`. */
  mode: string;
  /** REQUIRED in every mode. When the PEP's view of the Mission state was current. */
  freshness_at: string;
  /** REQUIRED for `cached` and `event_driven`. When the relied-on state was issued. */
  mission_status_issued_at?: string;
  /** REQUIRED for `cached` and `event_driven`. When reliance on the observed state ends. */
  mission_status_expires_at?: string;
  /** OPTIONAL. The signed Mission Status Response the PEP obtained `state` and `version` from. */
  assertion?: string;
}

/** @spec authzen#mission-status-composition: how the PEP obtained state. */
export const STATE_OBSERVATION_MODES: ReadonlySet<string> = new Set(["fresh", "cached", "event_driven"]);

const RFC3339 = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$/;

/** An RFC 3339 timestamp as epoch milliseconds, or `undefined` for anything else. */
export function rfc3339Ms(value: unknown): number | undefined {
  if (typeof value !== "string" || !RFC3339.test(value)) return undefined;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : undefined;
}

/** A well-formed observation, its timestamps as epoch milliseconds. */
export interface ParsedStateObservation {
  state: string;
  version?: number;
  mode: string;
  freshnessAtMs: number;
  issuedAtMs?: number;
  expiresAtMs?: number;
  assertion?: string;
}

/**
 * @spec authzen#context-audience-freshness: the observation with every member
 * its `mode` REQUIRES present and every member it carries well-formed, or
 * `undefined`. `state`, `mode` and `freshness_at` are REQUIRED in every mode;
 * `mission_status_issued_at` and `mission_status_expires_at` are REQUIRED for
 * `cached` and `event_driven`; `version` is an integer and `assertion` a string
 * where present. Shape only: the time comparisons against the decision
 * instant, the clock skew and the class bound are the PDP's.
 *
 * One rule for both components: the PEP refuses to send an observation this
 * rejects, and the PDP refuses to rely on one.
 */
export function parseStateObservation(value: unknown): ParsedStateObservation | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const o = value as Record<string, unknown>;
  if (typeof o.state !== "string") return undefined;
  if (typeof o.mode !== "string" || !STATE_OBSERVATION_MODES.has(o.mode)) return undefined;
  const freshnessAtMs = rfc3339Ms(o.freshness_at);
  if (freshnessAtMs === undefined) return undefined;
  if (o.version !== undefined && !(Number.isSafeInteger(o.version) && (o.version as number) >= 0)) return undefined;
  if (o.assertion !== undefined && typeof o.assertion !== "string") return undefined;
  const issuedAtMs = rfc3339Ms(o.mission_status_issued_at);
  const expiresAtMs = rfc3339Ms(o.mission_status_expires_at);
  if (o.mission_status_issued_at !== undefined && issuedAtMs === undefined) return undefined;
  if (o.mission_status_expires_at !== undefined && expiresAtMs === undefined) return undefined;
  if (o.mode !== "fresh" && (issuedAtMs === undefined || expiresAtMs === undefined)) return undefined;
  return {
    state: o.state,
    mode: o.mode,
    freshnessAtMs,
    ...(o.version !== undefined ? { version: o.version as number } : {}),
    ...(issuedAtMs !== undefined ? { issuedAtMs } : {}),
    ...(expiresAtMs !== undefined ? { expiresAtMs } : {}),
    ...(typeof o.assertion === "string" ? { assertion: o.assertion } : {}),
  };
}

/** @spec status#mission-status-response: the signed Status envelope's `typ`. */
const MISSION_STATUS_RESPONSE_TYP = "mission-status-response+jwt";

/** A Mission Status Response that verified: its claims, its `mission` object, and the signed bounds on relying on it. */
export interface VerifiedMissionStatus {
  payload: JWTPayload;
  mission: Record<string, unknown>;
  /** The signed `mission.fresh_until`, epoch milliseconds. */
  freshUntilMs: number;
  /** The signed `exp`, epoch milliseconds. */
  expMs: number;
  /** For a reported `active` state, the signed `mission.expires_at`, epoch milliseconds; absent for any other state. */
  activeUntilMs?: number;
  /**
   * The response's own reliance bound, epoch milliseconds: the earliest of
   * `mission.fresh_until`, `exp` and, for a reported `active` state,
   * `mission.expires_at`. The advertised `mission_max_stale_seconds` ceiling
   * is the caller's to add: it is issuer metadata, not a response member.
   */
  relianceBoundMs: number;
}

/**
 * @spec status#mission-status-response (consumer checks 1, 3, 4, 5, 8, 10 and
 * the `exp` half of 9), status#mission-status-caching (the reliance bound):
 * the ONE verifier of a signed Mission Status Response, shared by the
 * PEP-carried `assertion` ({@link verifyStateAssertion}) and the PDP's own
 * read of the declared state source (`mission-status-resolver.ts`), so the
 * two never disagree about what verifies or how long it is relied on.
 *
 * Verified means: a JWS of the Status media type, signed by one of `keys`,
 * issued by `expected.issuer`, audienced to `expected.audience` (the
 * enforcement scope), carrying `iat` and `exp` and not expired, its `mission` object naming
 * `expected.missionId` under that same issuer (check 4: `mission.issuer`
 * equals `iss`), and carrying a signed `mission.fresh_until` no later than
 * `exp` (check 10), and a signed `mission.expires_at` that parses.
 * `keys` are the declared state source's published status-response keys;
 * absent, nothing can be verified. Each caller adds the checks its own input
 * needs; this function adds none of theirs.
 *
 * Checks 6 (`sub` is the requesting client) and 7 (`nonce`) are the
 * requester's, so they are not here (#1407). The PDP's own read requested its
 * response and makes both (`mission-status-resolver.ts`). A PEP-carried
 * `assertion` was requested by the PEP, which makes them when it obtains it;
 * the PDP did not request it and cannot check its nonce, so it does not check
 * its `sub` either, and relies on what binds the snapshot to its decision.
 *
 * `clockToleranceSeconds` is check 9's receipt-time allowance on `exp`: it
 * decides whether the response is accepted, never how long it is relied on.
 * The returned reliance bound carries no allowance.
 */
export async function verifyMissionStatusResponse(
  jws: string,
  expected: { missionId: string; issuer: string; audience: string },
  keys: JWTVerifyGetKey | undefined,
  now: Date,
  clockToleranceSeconds: number,
): Promise<VerifiedMissionStatus | undefined> {
  if (keys === undefined) return undefined;
  try {
    const { payload } = await jwtVerify(jws, keys, {
      typ: MISSION_STATUS_RESPONSE_TYP,
      issuer: expected.issuer,
      audience: expected.audience,
      currentDate: now,
      clockTolerance: clockToleranceSeconds,
      // Consumer check 9 compares both: a response without either is not
      // one whose lifetime can be established, so it does not verify.
      requiredClaims: ["exp", "iat"],
    });
    const mission = payload.mission;
    if (mission === null || typeof mission !== "object" || Array.isArray(mission)) return undefined;
    const m = mission as Record<string, unknown>;
    if (m.id !== expected.missionId || m.issuer !== expected.issuer) return undefined;
    // The signed state ceiling. A status response with none bounds nothing
    // the PDP could rely on, so it does not verify.
    const freshUntilMs = rfc3339Ms(m.fresh_until);
    if (freshUntilMs === undefined) return undefined;
    // Consumer check 10: the signed state ceiling never outlives the signed
    // response that carries it. `exp` is present and numeric: jose required it.
    const expMs = (payload.exp as number) * 1000;
    if (freshUntilMs > expMs) return undefined;
    // @spec status#mission-status-response `expires_at` (REQUIRED),
    // status#mission-status-caching: a consumer "MUST NOT rely on a reported
    // `active` state at or after `mission.expires_at`". One that is absent or
    // does not parse leaves that bound unknowable, so it does not verify.
    const expiresAtMs = rfc3339Ms(m.expires_at);
    if (expiresAtMs === undefined) return undefined;
    const activeUntilMs = m.state === "active" ? expiresAtMs : undefined;
    const relianceBoundMs = Math.min(freshUntilMs, expMs, activeUntilMs ?? Number.POSITIVE_INFINITY);
    return { payload, mission: m, freshUntilMs, expMs, ...(activeUntilMs !== undefined ? { activeUntilMs } : {}), relianceBoundMs };
  } catch {
    return undefined;
  }
}

/**
 * @spec authzen#context-audience-freshness `assertion`: verify the signed
 * Mission Status Response "the PEP obtained `state` and `version` from", so
 * the PDP relies on the snapshot rather than on an unsigned PEP assertion.
 * `keys` are the declared state source's published status-response keys;
 * absent, nothing can be verified and the assertion is refused.
 *
 * Verified means: the response verifies ({@link verifyMissionStatusResponse})
 * and agrees with the observation it rides in: the same `state`, the same
 * `version` where the observation names one, an `iat` equal to
 * `mission_status_issued_at`, and a `fresh_until` no earlier than
 * `mission_status_expires_at` ("its `mission.fresh_until`, never its `exp`,
 * or an earlier end deployment policy sets").
 *
 * Returns the response's signed reliance bound (epoch milliseconds: the
 * earliest of its `fresh_until`, its `exp` and, for `active`, the Mission's
 * `expires_at`, @spec status#mission-status-caching) when verified, and
 * `undefined` otherwise. The caller enforces it whether or not the
 * observation repeats it (#1049 review P2-a): `mission_status_expires_at` is
 * OPTIONAL in `fresh` mode, and omitting the repeat must never discard the
 * signed ceiling.
 */
export async function verifyStateAssertion(
  observation: ParsedStateObservation & { assertion: string },
  expected: { missionId: string; issuer: string; audience: string },
  keys: JWTVerifyGetKey | undefined,
  now: Date,
  clockToleranceSeconds: number,
): Promise<number | undefined> {
  const verified = await verifyMissionStatusResponse(observation.assertion, expected, keys, now, clockToleranceSeconds);
  if (verified === undefined) return undefined;
  const { payload, mission: m, freshUntilMs, relianceBoundMs } = verified;
  if (m.state !== observation.state) return undefined;
  if (observation.version !== undefined && m.version !== observation.version) return undefined;
  if (
    observation.issuedAtMs !== undefined &&
    (typeof payload.iat !== "number" || payload.iat * 1000 !== observation.issuedAtMs)
  ) {
    return undefined;
  }
  // A repeated expiry later than the signed one is a mismatch, as for state
  // and version; an earlier one is a deployment-policy end and stands.
  if (observation.expiresAtMs !== undefined && observation.expiresAtMs > freshUntilMs) return undefined;
  return relianceBoundMs;
}
