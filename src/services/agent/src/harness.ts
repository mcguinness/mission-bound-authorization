/**
 * @spec draft-mcguinness-mission-harness (minimal duty only, D22)
 *
 * The agent harness's one in-scope obligation: on resume, check the Mission's
 * current state before attempting any action, and stop if it is not active.
 * This is the handbook's "02:00 resume" running example -- the mission was
 * cancelled while the agent idled, and the harness must not resume the work.
 * The PEP remains the backstop; this is defense in depth, not the only gate.
 */

export type MissionState = "active" | "suspended" | "revoked" | "expired" | "completed" | "superseded" | "cascaded";

export interface ResumeDecision {
  proceed: boolean;
  state: MissionState;
  reason?: string;
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
