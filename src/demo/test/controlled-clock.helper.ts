/**
 * A controlled clock for a test file (#249, D1091; review of #1959): `Date`
 * reports a fixed instant plus the real time elapsed since installation, at
 * the real clock's own precision, so nothing a test asserts moves with the
 * host's date while durations (a cadence a test sleeps past, events ordered
 * within a millisecond) behave as on the real clock. Install it before the
 * modules that read the time at load (`vi.hoisted`), and restore it after.
 */
export function installControlledClock(atMs: number): { restore: () => void } {
  const RealDate = globalThis.Date;
  const offset = atMs - RealDate.now();
  class ControlledDate extends RealDate {
    constructor(...args: unknown[]) {
      if (args.length === 0) super(RealDate.now() + offset);
      else super(...(args as [number]));
    }
    static override now(): number {
      return RealDate.now() + offset;
    }
  }
  globalThis.Date = ControlledDate as DateConstructor;
  return {
    restore: () => {
      globalThis.Date = RealDate;
    },
  };
}

/** The instant the payments contract's witnesses run at: after 2026-10-27 took effect, before the Missions' fixed 2027-01-01 Intent expiry, and inside every declared retention. */
export const CONTROLLED_CLOCK_MS = Date.parse("2026-11-02T12:00:00Z");
