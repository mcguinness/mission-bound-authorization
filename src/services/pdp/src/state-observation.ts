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

const RFC3339 = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$/;

/** An RFC 3339 timestamp as epoch milliseconds, or `undefined` for anything else. */
export function rfc3339Ms(value: unknown): number | undefined {
  if (typeof value !== "string" || !RFC3339.test(value)) return undefined;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : undefined;
}
