/**
 * @spec authzen#context-audience-freshness, authzen#mission-status-composition
 * (#1004): the PEP's Mission state observation as the AuthZEN profile carries
 * it, at `context.mission_state_observation`. It conveys the runtime
 * profile's state and freshness inputs on the wire; the trusted state source
 * and its staleness bound are the deployment's declaration, never a request
 * member.
 */

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
