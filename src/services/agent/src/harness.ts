/**
 * @spec draft-mcguinness-mission-harness (minimal duty only, D22)
 *
 * The agent harness's one in-scope obligation: on resume, check the Mission's
 * current state before attempting any action, and stop if it is not active.
 * This is the handbook's "02:00 resume" running example -- the mission was
 * cancelled while the agent idled, and the harness must not resume the work.
 * The PEP remains the backstop; this is defense in depth, not the only gate.
 */

import type { MissionStatusLease } from "@mission/core";

export type MissionState = "active" | "suspended" | "revoked" | "expired" | "completed" | "superseded" | "cascaded";

export interface ResumeDecision {
  proceed: boolean;
  state: MissionState;
  reason?: string;
  /**
   * @spec harness#resume-algorithm
   * Set when the refusal is a STALE status lease (now > status_expires_at)
   * rather than a non-active recorded state; see {@link checkStatusContinuity}.
   */
  stale?: boolean;
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
    return { proceed: false, state: "revoked", reason: "mission state unavailable (fail closed)" };
  }
  if (state !== "active") {
    return { proceed: false, state, reason: `mission is ${state}; not resuming` };
  }
  return { proceed: true, state };
}

const KNOWN_MISSION_STATES: ReadonlySet<MissionState> = new Set([
  "active",
  "suspended",
  "revoked",
  "expired",
  "completed",
  "superseded",
  "cascaded",
]);

function asMissionState(state: string): MissionState | undefined {
  return KNOWN_MISSION_STATES.has(state as MissionState) ? (state as MissionState) : undefined;
}

/**
 * @spec harness#resume-algorithm (step 5: freshness valid at submission)
 *
 * The lease-aware entry point that composes IN FRONT of {@link checkOnResume}:
 * before trusting a recorded state it enforces the status lease's freshness.
 * Once `now > status_expires_at` the check fails closed EVEN IF the last state
 * was `active` -- the "22:00 checked / 22:05 expired, resume at 02:00 refused"
 * example: session continuity is not authority continuity. A fresh lease then
 * delegates the state-trust decision to {@link checkOnResume}'s rule (only
 * `active` proceeds; any other or unrecognized state stops).
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
    return { proceed: false, state: "revoked", reason: "status lease unavailable (fail closed)" };
  }
  const expiresMs = Date.parse(lease.status_expires_at);
  if (Number.isNaN(expiresMs)) {
    return { proceed: false, state: "revoked", reason: "status lease has no valid expiry (fail closed)" };
  }
  if (now.getTime() > expiresMs) {
    // Stale: fail closed regardless of the last-observed state.
    return {
      proceed: false,
      state: asMissionState(lease.state) ?? "revoked",
      reason: `status lease expired at ${lease.status_expires_at}; refusing to resume (fail closed)`,
      stale: true,
    };
  }
  // Fresh: trust the recorded state via checkOnResume's rule.
  const known = asMissionState(lease.state);
  if (known === undefined) {
    // Forward-compatibility: an unrecognized state is non-active; stop.
    return {
      proceed: false,
      state: "revoked",
      reason: `mission state '${lease.state}' is not recognized; treating as non-active (fail closed)`,
    };
  }
  return checkOnResume("", async () => known);
}
