/**
 * @spec status#mission-lifecycle-endpoint ("Operations"), status#legal-transitions,
 * status#state-machine: the suspension scheduler, which applies a committed
 * schedule's `on_expiry` when its `suspend_until` passes, without a further
 * request.
 *
 * WHAT IS DURABLE. The schedule, not the timer. Each schedule lives in its
 * Mission's own row, committed with the `suspend` (or the replacement) that
 * armed it, so it is exactly as durable as the Mission Record: on the
 * file-backed single-writer store it survives a restart, on the in-memory
 * default nothing does. Timers are in-process and are rebuilt at boot from
 * the persisted schedules ({@link SuspensionScheduler.recover}); one whose
 * deadline passed while the process was down is delivered at once.
 *
 * GENERATION SAFETY. A timer carries the Mission and the generation of the
 * schedule it was armed for (the state version of the commit that armed it).
 * Its delivery claims that generation inside one kernel transaction
 * ({@link MissionKernel.fireSchedule}), so a stale or replaced timer, a
 * duplicate delivery, and a delivery racing a manual transition change
 * nothing. Correctness never depends on cancelling a timer; cancellation only
 * saves a wasted delivery.
 *
 * NO FIRE-TIME AUTHORITY CHECK. The schedule was authorized when it was
 * committed (status#lifecycle-authorization). A delivery executes it without
 * re-checking the committing party's grant.
 *
 * The expiry clock ({@link MissionKernel.applyExpiry}) also applies a due
 * schedule on any read of the record, so the deadline holds even between its
 * passing and the timer's delivery.
 */

import { MissionNotFoundError, type MissionKernel } from "./kernel.js";
import type { LifecycleCommit, MissionRecord } from "./types.js";

/**
 * The timer facility. The default is the process's own; a test injects a
 * controlled one. `callback` is a delivery, which never rejects; a facility
 * may await it.
 */
export interface ScheduleTimers {
  set(callback: () => Promise<unknown>, delayMs: number): unknown;
  clear(handle: unknown): void;
}

/**
 * The longest delay `setTimeout` honors: a longer one fires at once. A
 * deadline further away waits in steps of this; each early delivery finds it
 * not due and re-arms.
 */
export const MAX_TIMER_DELAY_MS = 2 ** 31 - 1;

/** The retry delay after a delivery whose commit did not land. */
export const SCHEDULE_RETRY_DELAY_MS = 1000;

/** Process timers, unreferenced so a pending schedule never holds the process open. */
export const SYSTEM_SCHEDULE_TIMERS: ScheduleTimers = {
  set: (callback, delayMs) => {
    const handle = setTimeout(() => {
      void callback();
    }, delayMs);
    handle.unref();
    return handle;
  },
  clear: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

/** One timer delivery: the Mission and the schedule generation it was armed for. */
export interface ScheduleDelivery {
  missionId: string;
  generation: number;
}

export interface SuspensionSchedulerOptions {
  timers?: ScheduleTimers;
  /**
   * Called once for each transition a delivery committed, after the commit:
   * the adapter's hook for effects outside the kernel (the provider grant a
   * terminal transition destroys). A failure here never undoes the commit.
   */
  onApplied?: (record: MissionRecord) => Promise<void>;
}

/** The scheduler's own record of the delivery a deadline or a retry is waiting on. */
interface ArmedTimer {
  generation: number;
  handle: unknown;
}

export class SuspensionScheduler {
  private readonly timers: ScheduleTimers;
  private readonly armed = new Map<string, ArmedTimer>();

  constructor(
    private readonly kernel: MissionKernel,
    private readonly opts: SuspensionSchedulerOptions = {},
  ) {
    this.timers = opts.timers ?? SYSTEM_SCHEDULE_TIMERS;
  }

  /**
   * @spec control-plane#fanout: the lifecycle-commit subscriber. A commit
   * that armed or replaced a schedule arms its timer; a commit that left
   * `suspended` cancels the Mission's timer. A commit carries its version, so
   * a replayed older commit never displaces the timer of a newer one.
   */
  onLifecycleCommit(commit: LifecycleCommit): void {
    if (commit.state === "suspended" && commit.suspend_until !== undefined) {
      const until = Date.parse(commit.suspend_until);
      this.arm({ missionId: commit.id, generation: commit.version }, Math.min(until, Date.parse(commit.expires_at)));
    } else if (commit.state !== "suspended") {
      const current = this.armed.get(commit.id);
      if (current && current.generation < commit.version) this.cancel(commit.id);
    }
  }

  /**
   * Arm (or re-arm) the timer for `delivery` at `dueAtMs`. A timer armed for a
   * newer generation of the same Mission is kept.
   */
  arm(delivery: ScheduleDelivery, dueAtMs: number): void {
    const current = this.armed.get(delivery.missionId);
    if (current && current.generation > delivery.generation) return;
    if (current) this.timers.clear(current.handle);
    const delay = Math.min(Math.max(0, dueAtMs - this.kernel.nowDate().getTime()), MAX_TIMER_DELAY_MS);
    const handle = this.timers.set(() => this.deliver(delivery), delay);
    this.armed.set(delivery.missionId, { generation: delivery.generation, handle });
  }

  /**
   * Deliver one timer: claim its generation and apply the schedule if it is
   * still current and due. Never throws; a delivery that could not commit is
   * retried.
   */
  async deliver(delivery: ScheduleDelivery): Promise<ReturnType<MissionKernel["fireSchedule"]>["outcome"]> {
    // This delivery consumes the armed timer for its own generation, if any.
    if (this.armed.get(delivery.missionId)?.generation === delivery.generation) this.cancel(delivery.missionId);
    let fired: ReturnType<MissionKernel["fireSchedule"]>;
    try {
      fired = this.kernel.fireSchedule(delivery.missionId, delivery.generation);
    } catch (e) {
      if (e instanceof MissionNotFoundError) return "superseded";
      // A storage fault: the schedule is still persisted, so retry it.
      this.arm(delivery, this.kernel.nowDate().getTime() + SCHEDULE_RETRY_DELAY_MS);
      return "retry";
    }
    if (fired.outcome === "not-due") {
      this.arm(delivery, fired.dueAtMs);
    } else if (fired.outcome === "retry") {
      this.arm(delivery, this.kernel.nowDate().getTime() + SCHEDULE_RETRY_DELAY_MS);
    } else if (fired.outcome === "applied" || fired.outcome === "ended") {
      try {
        await this.opts.onApplied?.(fired.record);
      } catch {
        // The transition committed; the state gate refuses derivation from it
        // whatever became of this effect.
      }
      try {
        // A terminal commit can owe durable deliveries (control-plane#fanout).
        await this.kernel.drainLifecycleOutbox();
      } catch {
        // Retried by the next drain, from boot or a request path.
      }
    }
    return fired.outcome;
  }

  /**
   * @spec control-plane#serialization: boot recovery. Arm every persisted
   * schedule; one already due is delivered now, before the caller serves
   * requests.
   */
  async recover(): Promise<void> {
    const now = this.kernel.nowDate().getTime();
    for (const schedule of this.kernel.currentSchedules()) {
      const delivery = { missionId: schedule.missionId, generation: schedule.generation };
      if (schedule.dueAtMs <= now) await this.deliver(delivery);
      else this.arm(delivery, schedule.dueAtMs);
    }
  }

  /** The generation each Mission's armed timer is waiting on. */
  armedGenerations(): Map<string, number> {
    return new Map([...this.armed].map(([id, t]) => [id, t.generation]));
  }

  /** Cancel every timer (a closing deployment). The schedules stay persisted. */
  stop(): void {
    for (const id of [...this.armed.keys()]) this.cancel(id);
  }

  private cancel(missionId: string): void {
    const current = this.armed.get(missionId);
    if (!current) return;
    this.timers.clear(current.handle);
    this.armed.delete(missionId);
  }
}
