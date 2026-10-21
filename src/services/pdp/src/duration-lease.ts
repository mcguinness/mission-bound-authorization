/**
 * @spec metering#metering (`max_duration` rules 3 and 4), metering#lease-renewal
 * (#1440): the PDP's duration leases and their renewal.
 *
 * "For an action whose duration is not known before execution, the PDP MUST
 * either reserve a bounded maximum duration or issue a duration lease that
 * expires unless renewed." A deployment declares which actions it leases this
 * way and for how long ({@link createDurationLeaseLedger}). A permit for such
 * an action opens one metered activity: a reservation of one lease interval,
 * leased by that permit, whose `valid_until` is the lease's end.
 *
 * "A duration-lease renewal is a new re-evaluation request that carries the
 * prior permit's `evaluation_id` in `context.prior_evaluation_id`, so the PDP
 * continues the same metered activity rather than opening a new
 * reservation." and "The PDP MUST verify that the renewal's Mission, subject,
 * action, operation target and audience match the evaluation named by
 * `prior_evaluation_id`." A renewal that names no lease this PDP issued, a
 * lease that has ended, or an evaluation any of the five differs from,
 * continues nothing and is denied. A matching renewal is evaluated in full
 * like any request; its permit continues the renewed activity and moves the
 * lease's end, and no second reservation is opened.
 *
 * This is the smallest realization the renewal rule needs. The ledger holds
 * leases in memory, and nothing here accumulates `max_duration`, commits a
 * reported `measured_duration`, or settles a lease.
 *
 * The ledger is PDP-side state read as a decision input, like the idempotency
 * claim domain: bound at decision-point construction and never supplied by an
 * enforcement component (see `DecisionOptions` in ./evaluate.ts).
 */

import { randomUUID } from "node:crypto";
import type { EvaluationRequest } from "./evaluate.js";

/** The five members a renewal must share with the evaluation it renews. */
export interface LeaseContinuity {
  mission: { id: string; issuer: string };
  subject: { id: string; iss: string | null };
  action: string;
  operation_target: string;
  audience: string;
}

/** One metered activity: its one reservation, and every permit that leased it. */
export interface DurationActivity {
  activityId: string;
  /** The permits that leased this activity, the opening permit first. */
  evaluations: string[];
  /** The current lease's end: the latest leasing permit's `valid_until`. */
  leaseEndMs: number;
}

/** The PDP's duration-lease state. */
export interface DurationLeaseDomain {
  /** The lease interval, in seconds, the deployment declares for `action`; undefined where it leases none. */
  leaseSeconds(action: string): number | undefined;
  /** The activity the permit `evaluationId` leased, with that permit's continuity members, or undefined. */
  lookup(evaluationId: string): { activity: DurationActivity; continuity: LeaseContinuity } | undefined;
  /** Open a new activity, leased by this permit. */
  open(evaluationId: string, continuity: LeaseContinuity, leaseEndMs: number): DurationActivity;
  /** Lease an existing activity to this permit as well, opening no reservation. */
  extend(activityId: string, evaluationId: string, continuity: LeaseContinuity, leaseEndMs: number): DurationActivity;
  /** Every activity this ledger has opened. */
  activities(): DurationActivity[];
}

/**
 * An in-memory ledger leasing the declared actions: `declared` maps an action
 * name to its lease interval in whole seconds. A non-positive or fractional
 * interval refuses at construction.
 */
export function createDurationLeaseLedger(declared: Readonly<Record<string, number>>): DurationLeaseDomain {
  for (const [action, seconds] of Object.entries(declared)) {
    if (!Number.isSafeInteger(seconds) || seconds <= 0) {
      throw new Error(`duration lease for ${action} must be a positive whole number of seconds`);
    }
  }
  const activities = new Map<string, DurationActivity>();
  const leases = new Map<string, { activityId: string; continuity: LeaseContinuity }>();
  const snapshot = (a: DurationActivity): DurationActivity => ({ ...a, evaluations: [...a.evaluations] });
  return {
    leaseSeconds: (action) => (Object.hasOwn(declared, action) ? declared[action] : undefined),
    lookup(evaluationId) {
      const lease = leases.get(evaluationId);
      const activity = lease ? activities.get(lease.activityId) : undefined;
      return lease && activity ? { activity: snapshot(activity), continuity: lease.continuity } : undefined;
    },
    open(evaluationId, continuity, leaseEndMs) {
      const activity: DurationActivity = { activityId: `act_${randomUUID()}`, evaluations: [evaluationId], leaseEndMs };
      activities.set(activity.activityId, activity);
      leases.set(evaluationId, { activityId: activity.activityId, continuity });
      return snapshot(activity);
    },
    extend(activityId, evaluationId, continuity, leaseEndMs) {
      const activity = activities.get(activityId);
      if (!activity) throw new Error(`no duration-lease activity ${activityId}`);
      activity.evaluations.push(evaluationId);
      activity.leaseEndMs = Math.max(activity.leaseEndMs, leaseEndMs);
      leases.set(evaluationId, { activityId, continuity });
      return snapshot(activity);
    },
    activities: () => [...activities.values()].map(snapshot),
  };
}

/**
 * The continuity members of a validated request. The operation target is the
 * one the authenticated PEP established for this request, carried as spelled.
 */
function continuityOf(req: EvaluationRequest): LeaseContinuity {
  return {
    mission: { id: req.context.mission.id, issuer: req.context.mission.issuer },
    subject: { id: req.subject.id, iss: req.subject.properties?.iss ?? null },
    action: req.action.name,
    operation_target: req.resource.properties.operation_target,
    audience: req.resource.properties.audience,
  };
}

/**
 * Whether a renewal matches the evaluation it renews in all five members.
 * Every member is compared by string equality, the operation target
 * included: both targets are ones an authenticated PEP established for one
 * activity, so a renewal continues it only at the same target, never at
 * another target an entry's `prefix` would also admit.
 */
function sameContinuity(a: LeaseContinuity, b: LeaseContinuity): boolean {
  return (
    a.mission.id === b.mission.id &&
    a.mission.issuer === b.mission.issuer &&
    a.subject.id === b.subject.id &&
    a.subject.iss === b.subject.iss &&
    a.action === b.action &&
    a.operation_target === b.operation_target &&
    a.audience === b.audience
  );
}

/** What the lease step leaves for the permit. */
export type LeaseStep =
  /** The action is not duration-leased and the request renews nothing. */
  | { kind: "none" }
  /** The request claims a renewal that continues no activity. */
  | { kind: "refused" }
  /**
   * A permit for this request is leased: `ceiling` caps its `valid_until` at
   * the lease interval, and `commit` records it once it is issued.
   */
  | {
      kind: "leased";
      ceiling: { name: string; atMs: number };
      commit(evaluationId: string, validUntilMs: number): void;
    };

/**
 * The lease step for one request that has passed every authority and
 * constraint check, at the decision instant `nowMs`. A request carrying
 * `context.prior_evaluation_id` is a renewal: refused unless `domain` holds
 * that permit's activity, the activity's lease has not ended, the action is
 * still one the deployment leases, and the five continuity members match.
 */
export function durationLeaseStep(
  req: EvaluationRequest,
  domain: DurationLeaseDomain | undefined,
  nowMs: number,
): LeaseStep {
  const prior = (req.context as { prior_evaluation_id?: unknown }).prior_evaluation_id;
  const seconds = domain?.leaseSeconds(req.action.name);
  if (prior === undefined && (domain === undefined || seconds === undefined)) return { kind: "none" };
  if (domain === undefined || seconds === undefined) return { kind: "refused" };
  const continuity = continuityOf(req);
  const ceiling = { name: "duration_lease_end", atMs: nowMs + seconds * 1000 };
  if (prior === undefined) {
    return { kind: "leased", ceiling, commit: (id, end) => void domain.open(id, continuity, end) };
  }
  const renewed = typeof prior === "string" && prior.length > 0 ? domain.lookup(prior) : undefined;
  if (!renewed || renewed.activity.leaseEndMs <= nowMs || !sameContinuity(renewed.continuity, continuity)) {
    return { kind: "refused" };
  }
  const { activityId } = renewed.activity;
  return { kind: "leased", ceiling, commit: (id, end) => void domain.extend(activityId, id, continuity, end) };
}
