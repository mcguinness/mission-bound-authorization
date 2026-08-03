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
 * A status lease: the ONE status shape the harness consumes and the Status List
 * / Lifecycle Signals surfaces produce. `status_expires_at` is the RFC 3339
 * instant after which the status MUST NOT be used for continuation
 * (harness § mission-binding, § resume-checks).
 */
export interface MissionStatusLease {
  /** The last Mission state established for this lease (e.g. `active`). */
  state: string;
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
