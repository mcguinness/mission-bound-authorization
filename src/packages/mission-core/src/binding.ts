/**
 * @spec harness#mission-binding
 *
 * The Mission Binding and its status-lease shape, owned here in the shared,
 * service-dependency-free core so every profile that produces or consumes
 * Mission state speaks one vocabulary. The harness draft fixes `state_source`
 * as THE shared value space "reused by the orchestration profile rather than
 * defining its own", and Status List / Lifecycle Signals produce the very
 * `MissionStatusLease` the harness consumes. Placing these types in
 * `@mission/core` is what prevents each profile from redefining them.
 *
 * These types grant no authority. A Mission Binding is the pointer that tells
 * a harness which Mission state it must check before continuing governed work
 * (draft § mission-binding: "The Mission binding grants no authority").
 */

/**
 * The shared `state_source` value space (harness § mission-binding). String-open
 * per the draft's "or a deployment-defined source": `status` and `signal` name
 * the Mission Status and Lifecycle Signals surfaces, `runtime_decision` a
 * runtime enforcement decision, `harness` a harness stop decision, and
 * `operator` a human operator action.
 */
export type StateSource =
  | "status"
  | "signal"
  | "runtime_decision"
  | "harness"
  | "operator"
  | (string & Record<never, never>);

/**
 * The stop behavior a harness applies when a Mission is non-active or stale
 * (harness § stop-behavior). This increment realizes only `suppress` (do not
 * dispatch queued or resumable work; preserve state) in the harness; `pause`,
 * `terminate`, and `handoff` are declared here but unimplemented (Deferred).
 */
export type StopPolicy = "suppress" | "pause" | "terminate" | "handoff";

/**
 * @spec mission#termination: a Mission's `termination` as a consumer reads it
 * beside a reported `state` of `terminated` (Status, Signals, the harness
 * binding). `reason` is a Mission Termination Reasons registry value carried
 * as an open string: a reason the reader does not recognize still means
 * terminated (stop governed work, follow no absent reference, infer no
 * cause-specific action). The other members are optional here because a
 * termination recorded before its reason defined a member, or an `expired` or
 * `parent_terminated` termination observed before it is committed, omits what
 * it has no value for; a reader never invents one.
 */
export interface MissionTermination {
  /** REQUIRED. The termination reason (`revoked`, `expired`, `completed`,
   *  `superseded`, `parent_terminated`, or a reason this reader does not know). */
  reason: string;
  /** RFC 3339: the instant the termination took effect. */
  terminated_at?: string;
  /** The state version of the transition that committed the termination (Status). */
  version?: number;
  /** `superseded`: the successor Mission's `id` (same issuer). */
  successor?: string;
  /** `parent_terminated`: the immediate parent Mission's `id`. */
  parent?: string;
  /** `parent_terminated`: the ancestor whose termination started the cascade (provenance only). */
  origin?: string;
  /** `parent_terminated`: that ancestor's termination reason. */
  origin_reason?: string;
  /** `parent_terminated`: the Carryover replacement Mission's `id` (correlation, never authority). */
  carried_to?: string;
}

const TERMINATION_STRING_MEMBERS = [
  "terminated_at",
  "successor",
  "parent",
  "origin",
  "origin_reason",
  "carried_to",
] as const;

/**
 * Read a received `termination` value. Returns `undefined` when it is not an
 * object with a non-empty string `reason`; otherwise the known members that
 * are well typed, each other member dropped. Never throws and never fills a
 * member in: a malformed termination yields no termination facts, and the
 * caller still treats a `terminated` state as terminated (fail closed).
 */
export function readMissionTermination(value: unknown): MissionTermination | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const t = value as Record<string, unknown>;
  if (typeof t.reason !== "string" || t.reason === "") return undefined;
  const out: MissionTermination = { reason: t.reason };
  for (const member of TERMINATION_STRING_MEMBERS) {
    const v = t[member];
    if (typeof v === "string" && v !== "") out[member] = v;
  }
  if (typeof t.version === "number" && Number.isSafeInteger(t.version) && t.version >= 0) {
    out.version = t.version;
  }
  return out;
}

/** The terminal state values a report could carry before the termination vocabulary. */
const LEGACY_TERMINAL_STATES: ReadonlyMap<string, string> = new Map([
  ["revoked", "revoked"],
  ["expired", "expired"],
  ["completed", "completed"],
  ["superseded", "superseded"],
  ["cascaded", "parent_terminated"],
]);

/**
 * @spec mission#termination (transition-period reading): a consumer of a
 * report that still carries `revoked`, `expired`, `completed`, `superseded`
 * or `cascaded` as a Mission's `state` MAY read it as `terminated` with that
 * reason (`cascaded` as `parent_terminated`). The result is a local view:
 * only `reason` is set, because a legacy report retained no termination
 * members, and the caller never re-emits or re-signs it. A caller holding a
 * signed artifact verifies it over its original bytes BEFORE calling this.
 * Any other state value is returned unchanged (`active`, `suspended`,
 * `terminated`, or an unrecognized value, which stays non-active).
 */
export function normalizeLegacyMissionState(state: string): {
  state: string;
  termination?: MissionTermination;
} {
  const reason = LEGACY_TERMINAL_STATES.get(state);
  return reason === undefined ? { state } : { state: "terminated", termination: { reason } };
}

/**
 * A status lease: the ONE status shape the harness consumes and the Status List
 * / Lifecycle Signals surfaces produce. `status_expires_at` is the RFC 3339
 * instant after which the status MUST NOT be used for continuation
 * (harness § mission-binding, § resume-checks).
 */
export interface MissionStatusLease {
  /** The last Mission state established for this lease (e.g. `active`). */
  state: string;
  /**
   * @spec mission#termination: the Mission's `termination` as the producing
   * surface reported it, beside a `state` of `terminated`; absent for any
   * other state, and absent when the report carried none.
   */
  termination?: MissionTermination;
  /** RFC 3339 timestamp: when status was checked. */
  status_checked_at: string;
  /** RFC 3339 timestamp: after this instant the lease MUST NOT be relied upon. */
  status_expires_at: string;
  /** OPTIONAL monotonic version of the status, when the producer supplies one. */
  version?: number;
  /** Which surface established `state` (shared `state_source` value space). */
  state_source: StateSource;
}

/**
 * The Mission Binding object (harness § mission-binding). A Mission-aware
 * harness MUST bind every governed session and governed task graph node to a
 * Mission reference. `stop_policy` is REQUIRED for governed work.
 */
export interface MissionBinding {
  /** REQUIRED. The Mission identifier. */
  mission_id: string;
  /** REQUIRED. The Mission's `issuer` (the Mission Issuer's issuer URL). */
  issuer: string;
  /** REQUIRED when known. The Authority Set commitment from the Mission claim. */
  authority_hash?: string;
  /** REQUIRED when known. The last Mission state established by the harness. */
  state?: string;
  /** Present exactly when `state` is `terminated` and the surface reported it. */
  termination?: MissionTermination;
  /** REQUIRED when `state` is present. The surface that established `state`. */
  state_source?: StateSource;
  /** REQUIRED when the harness has checked status. An RFC 3339 timestamp. */
  status_checked_at?: string;
  /** REQUIRED when the harness relies on a status lease. An RFC 3339 timestamp. */
  status_expires_at?: string;
  /** OPTIONAL. Identifies the runtime enforcement scope for this session/node. */
  enforcement_scope?: string | Record<string, unknown>;
  /** REQUIRED for governed work. The stop policy on non-active or stale state. */
  stop_policy: StopPolicy;
}
