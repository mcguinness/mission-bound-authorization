/**
 * @spec draft-mcguinness-mission-harness (minimal duty only, D22)
 *
 * The agent harness's one in-scope obligation: on resume, check the Mission's
 * current state before attempting any action, and stop if it is not active.
 * This is the handbook's "02:00 resume" running example -- the mission was
 * cancelled while the agent idled, and the harness must not resume the work.
 * The PEP remains the backstop; this is defense in depth, not the only gate.
 */

import {
  type MissionStatusLease,
  type MissionTermination,
  normalizeLegacyMissionState,
  readMissionTermination,
} from "@mission/core";

/**
 * @spec mission#lifecycle: the Mission lifecycle states: the OAuth binding's
 * `active` and `terminated`, and Mission Status's `suspended`. How a Mission
 * ended is its `termination.reason`, never a state.
 */
export type MissionState = "active" | "suspended" | "terminated";

export interface ResumeDecision {
  proceed: boolean;
  state: MissionState;
  /**
   * @spec mission#termination: the Mission's `termination` as the status
   * source reported it, present only beside `state` `terminated`. A synthetic
   * fail-closed decision (no state, no lease, an unrecognized state) carries
   * none: the harness never invents a termination reason.
   */
  termination?: MissionTermination;
  reason?: string;
  /**
   * @spec harness#resume-algorithm
   * Set when the refusal is a STALE status lease (now > status_expires_at)
   * rather than a non-active recorded state; see {@link checkStatusContinuity}.
   */
  stale?: boolean;
  /**
   * @spec harness#supersession-continuity: the successor Mission a harness MAY
   * continue under by rebinding. Set only on a refusal over a fresh lease whose
   * `termination.reason` is `superseded` and whose `termination.successor` is
   * a string ({@link supersessionSuccessor}); never from a `superseded` state
   * string or any other reason. It grants nothing: see
   * {@link checkSupersessionContinuity}.
   */
  successor?: string;
}

/**
 * Check mission state at resume. `readState` fetches the authoritative state
 * (signed Status in a real deployment; the kernel in-process here). A missing
 * or non-active state fails closed: the agent stops.
 */
export async function checkOnResume(
  missionId: string,
  readState: (id: string) => Promise<MissionState | undefined>,
): Promise<ResumeDecision> {
  const state = await readState(missionId);
  if (state === undefined) {
    return { proceed: false, state: "terminated", reason: "mission state unavailable (fail closed)" };
  }
  if (state !== "active") {
    return { proceed: false, state, reason: `mission is ${state}; not resuming` };
  }
  return { proceed: true, state };
}

const KNOWN_MISSION_STATES: ReadonlySet<MissionState> = new Set(["active", "suspended", "terminated"]);

function asMissionState(state: string): MissionState | undefined {
  return KNOWN_MISSION_STATES.has(state as MissionState) ? (state as MissionState) : undefined;
}

/**
 * The lease's state as the harness reads it: a legacy terminal state value is
 * read as `terminated` with that reason (the transition-period reading, a
 * local view only), and `termination` is kept only beside `terminated`. An
 * unrecognized state yields no state at all, which every caller treats as
 * non-active.
 */
function leaseState(lease: MissionStatusLease): { state?: MissionState; termination?: MissionTermination } {
  const normalized = normalizeLegacyMissionState(lease.state);
  const state = asMissionState(normalized.state);
  if (state !== "terminated") return state === undefined ? {} : { state };
  const termination = normalized.termination ?? readMissionTermination(lease.termination);
  return termination === undefined ? { state } : { state, termination };
}

/**
 * @spec harness#supersession-continuity: the successor a superseded Mission
 * names, keyed on the termination reason: `state` `terminated`,
 * `termination.reason` exactly `superseded`, and a string
 * `termination.successor`, over a lease that is not stale. Anything else
 * (another reason with a stray `successor`, `superseded` with no successor, a
 * legacy `superseded` state string, which retained no successor, a stale
 * lease) names none, and the harness suppresses per the stop matrix.
 */
export function supersessionSuccessor(
  decision: Pick<ResumeDecision, "state" | "termination" | "stale">,
): string | undefined {
  if (decision.stale === true || decision.state !== "terminated") return undefined;
  const termination = decision.termination;
  if (termination === undefined || termination.reason !== "superseded") return undefined;
  const successor = termination.successor;
  return typeof successor === "string" && successor !== "" ? successor : undefined;
}

/**
 * @spec harness#resume-algorithm (step 5: freshness valid at submission)
 *
 * The lease-aware entry point that composes IN FRONT of {@link checkOnResume}:
 * before trusting a recorded state it enforces the status lease's freshness.
 * Once `now > status_expires_at` the check fails closed EVEN IF the last state
 * was `active` -- the "22:00 checked / 22:05 expired, resume at 02:00 refused"
 * example: session continuity is not authority continuity. A fresh lease then
 * applies {@link checkOnResume}'s rule (only `active` proceeds; any other or
 * unrecognized state stops), carrying the lease's `termination` onto the
 * decision and, for a supersession, the successor it names.
 *
 * `now` is injected so a harness can re-check freshness at each submission
 * (§ resume-checks: freshness must hold at the moment each action is submitted,
 * not only at the resume boundary).
 */
export async function checkStatusContinuity(
  lease: MissionStatusLease | undefined,
  now: Date,
): Promise<ResumeDecision> {
  if (lease === undefined) {
    return { proceed: false, state: "terminated", reason: "status lease unavailable (fail closed)" };
  }
  const expiresMs = Date.parse(lease.status_expires_at);
  if (Number.isNaN(expiresMs)) {
    return { proceed: false, state: "terminated", reason: "status lease has no valid expiry (fail closed)" };
  }
  const { state, termination } = leaseState(lease);
  if (now.getTime() > expiresMs) {
    // Stale: fail closed regardless of the last-observed state.
    return {
      proceed: false,
      state: state ?? "terminated",
      ...(termination !== undefined ? { termination } : {}),
      reason: `status lease expired at ${lease.status_expires_at}; refusing to resume (fail closed)`,
      stale: true,
    };
  }
  if (state === undefined) {
    // Forward-compatibility: an unrecognized state is non-active; stop.
    return {
      proceed: false,
      state: "terminated",
      reason: `mission state '${lease.state}' is not recognized; treating as non-active (fail closed)`,
    };
  }
  // Fresh: only exactly `active` proceeds.
  if (state !== "active") {
    const successor = supersessionSuccessor({ state, ...(termination !== undefined ? { termination } : {}) });
    return {
      proceed: false,
      state,
      ...(termination !== undefined ? { termination } : {}),
      ...(successor !== undefined ? { successor } : {}),
      reason: `mission is ${state}${termination !== undefined ? ` (${termination.reason})` : ""}; not resuming`,
    };
  }
  return { proceed: true, state };
}

/** The outcome of {@link checkSupersessionContinuity}. */
export type SupersessionContinuity =
  | { rebind: true; successor: string; resume: ResumeDecision }
  | { rebind: false; reason: string; successor?: string; resume?: ResumeDecision };

/**
 * @spec harness#supersession-continuity: the harness's check before it
 * continues a superseded Mission's work item by rebinding. It runs only when
 * the predecessor's decision names a successor ({@link supersessionSuccessor},
 * keyed on `termination.reason`), and confirms the successor's own lease is
 * fresh and `active` through {@link checkStatusContinuity}. Any other outcome
 * is `rebind: false`, and the harness suppresses.
 *
 * `rebind: true` grants nothing. Rebinding itself is the caller's: it derives
 * a fresh Mission-bound credential under the successor, discards every
 * credential bound to the predecessor, binds the work item to the successor
 * (a harness over the successor's Mission identifier), and proceeds only for
 * actions the successor's Authority Set authorizes.
 */
export async function checkSupersessionContinuity(
  decision: ResumeDecision,
  readStatus: (id: string) => Promise<MissionStatusLease | undefined>,
  now: Date,
): Promise<SupersessionContinuity> {
  const successor = supersessionSuccessor(decision);
  if (successor === undefined || decision.proceed) {
    return { rebind: false, reason: "no supersession successor to continue under; suppress" };
  }
  const resume = await checkStatusContinuity(await readStatus(successor), now);
  if (!resume.proceed) {
    return {
      rebind: false,
      successor,
      resume,
      reason: `successor ${successor} is not established active (${resume.reason ?? resume.state}); suppress`,
    };
  }
  return { rebind: true, successor, resume };
}
