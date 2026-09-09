/**
 * @spec runtime#state-freshness — the ONE permit-deadline calculation.
 *
 * "A state source MUST either report the Mission state with an explicit
 * expiry or lease end, or report only an observation time, in which case the
 * state remains acceptable only until that observation time plus the
 * deployment's published staleness bound for the relevant action class. A
 * permit issued from that state view MUST expire no later than this state
 * valid-through."
 *
 * Every ceiling on a permit's validity resolves here, and the result names
 * WHICH ceiling won, so a decision point never carries two competing
 * calculations. The authority, credential and policy ceilings (#594 W4-13)
 * extend this by pushing entries onto {@link PermitDeadlineInput.ceilings};
 * they do not add a second computation beside it.
 *
 * The trusted input is the state observation the Decision was actually taken
 * against: the one the freshness gate ACCEPTED (parseable, from a declared
 * source, inside the class window). Arbitrary request freshness metadata is
 * never a cap, because a request that supplies a later observation than the
 * PDP accepted would otherwise buy itself a longer permit.
 */

import type { StalenessBound } from "./runtime-posture.js";

/** One named ceiling on a permit's validity, as an absolute instant. */
export interface PermitCeiling {
  /** Stable identifier of the ceiling, reported as the winning source. */
  name: string;
  atMs: number;
}

/**
 * A permit deadline, or the refusal that no positive Decision may carry.
 *
 * `elapsed` is returned when the tightest ceiling is already at or before the
 * decision instant, or when an input is not a finite instant. The caller MUST
 * deny rather than emit a permit: an expired positive Decision and a NaN
 * deadline are both records asserting something that was never established.
 */
export type PermitDeadline =
  | { kind: "bounded"; validUntilMs: number; validUntil: string; source: string }
  | { kind: "elapsed"; source: string };

export interface PermitDeadlineInput {
  /** The decision instant. */
  nowMs: number;
  /** The class's own permit lifetime, before any ceiling applies. */
  permitTtlSeconds: number;
  /** The declared freshness posture for this action class. */
  stalenessBound: StalenessBound;
  /**
   * The ACCEPTED state observation this Decision was taken against, as epoch
   * milliseconds. Absent when the class's posture required no observation and
   * none was presented; never a value the freshness gate rejected.
   */
  stateObservedAtMs?: number;
  /** Additional named ceilings (#594 W4-13's authority/credential/policy bounds). */
  ceilings?: readonly PermitCeiling[];
}

export function permitDeadline(input: PermitDeadlineInput): PermitDeadline {
  const { nowMs, permitTtlSeconds, stalenessBound, stateObservedAtMs } = input;
  if (!Number.isFinite(nowMs)) return { kind: "elapsed", source: "decision_instant_unparseable" };
  if (!Number.isFinite(permitTtlSeconds) || permitTtlSeconds <= 0) {
    return { kind: "elapsed", source: "permit_ttl_unusable" };
  }

  const candidates: PermitCeiling[] = [{ name: "permit_ttl", atMs: nowMs + permitTtlSeconds * 1000 }];

  switch (stalenessBound.kind) {
    case "undeclared":
      // The decision point refuses an undeclared class before reaching a
      // permit; treated as elapsed here so this helper can never be the
      // component that lets one through.
      return { kind: "elapsed", source: "undeclared_action_class" };
    case "none":
      // The draft's "No active freshness required" row: there is no state
      // view valid-through to cap against, so the class's own permit lifetime
      // stands alone. This is a declared posture, not a missing bound.
      break;
    case "bounded": {
      const seconds = stalenessBound.seconds;
      if (!Number.isFinite(seconds) || seconds <= 0) {
        return { kind: "elapsed", source: "unenforceable_staleness_bound" };
      }
      if (stateObservedAtMs === undefined) {
        // A bounded class the deployment mediates with no observation to cap
        // against. Reachable today only below the high-consequence floor,
        // where the draft treats the credential's own lifetime as a
        // conforming state source and an absent `context.freshness` is not
        // itself a refusal. The class's published bound is still the longest
        // any reliance on state may run, so it caps the permit measured from
        // the decision instant: never later than the permit lifetime alone,
        // so it can only narrow. The credential's own expiry is a separate,
        // named ceiling (#594 W4-13) rather than a second calculation here.
        candidates.push({ name: "class_staleness_bound", atMs: nowMs + seconds * 1000 });
        break;
      }
      if (!Number.isFinite(stateObservedAtMs)) {
        return { kind: "elapsed", source: "state_observation_unparseable" };
      }
      // Clock skew: the freshness gate tolerates an observation dated
      // slightly in the future, but a future-dated observation MUST NOT buy a
      // longer permit than one taken now, so the observation is clamped to
      // the decision instant before the bound is added.
      const observedAtMs = Math.min(stateObservedAtMs, nowMs);
      candidates.push({ name: "state_view", atMs: observedAtMs + seconds * 1000 });
      break;
    }
  }

  for (const ceiling of input.ceilings ?? []) {
    if (!Number.isFinite(ceiling.atMs)) return { kind: "elapsed", source: `${ceiling.name}_unparseable` };
    candidates.push(ceiling);
  }

  // Tightest wins; ties resolve by name so the reported source is stable.
  const winner = candidates.reduce((a, b) => (b.atMs < a.atMs || (b.atMs === a.atMs && b.name < a.name) ? b : a));
  // A ceiling already reached by the time evaluation completes yields no
  // permit at all: the state view the Decision relied on is no longer
  // acceptable, which is a staleness-bound breach, not a permit to be issued
  // pre-expired.
  if (winner.atMs <= nowMs) return { kind: "elapsed", source: winner.name };
  return { kind: "bounded", validUntilMs: winner.atMs, validUntil: new Date(winner.atMs).toISOString(), source: winner.name };
}

/**
 * @spec runtime#execution-reverification — the executing PEP's local lease,
 * derived from the PUBLISHED maximum and capped by the permit's own validity:
 * "A permit authorizes initiation ... run-to-completion applies only within
 * that bound." A local lease never extends authorization, so its end is the
 * earlier of the published bound and the permit's `valid_until`.
 *
 * Returns milliseconds from `nowMs`, never a NaN or negative interval: an
 * unparseable or already-passed bound yields 0, which the caller's pre-effect
 * expiry check refuses on before any lease is taken.
 *
 * This is the lease covering an already-started attempt, a different question
 * from whether the permit may still INITIATE one. The pre-effect check owns
 * initiation; this bound owns what happens after it passes.
 */
export function executionLeaseMs(input: {
  nowMs: number;
  publishedMaxSeconds: number | undefined;
  permitValidUntilMs: number | undefined;
}): number {
  const { nowMs, publishedMaxSeconds, permitValidUntilMs } = input;
  if (!Number.isFinite(nowMs)) return 0;
  const bounds: number[] = [];
  if (publishedMaxSeconds !== undefined && Number.isFinite(publishedMaxSeconds) && publishedMaxSeconds > 0) {
    bounds.push(nowMs + publishedMaxSeconds * 1000);
  }
  if (permitValidUntilMs !== undefined && Number.isFinite(permitValidUntilMs)) bounds.push(permitValidUntilMs);
  // No published bound and no permit validity is not a licence to run
  // unbounded: the class that requires a lease has one published (refused at
  // config load otherwise), so this is the fail-closed remainder.
  if (bounds.length === 0) return 0;
  return Math.max(0, Math.min(...bounds) - nowMs);
}
