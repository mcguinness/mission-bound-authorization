/** Milliseconds since the epoch. */
export type Clock = () => number;

/** Wait `ms` milliseconds. */
export type Sleep = (ms: number) => Promise<void>;

export const realSleep: Sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * A clock shared by every party of a test. Sleeping advances it instead of
 * waiting, so an agent that waits for the next second of `created` costs no
 * wall time, and a token can be aged past its `exp` on demand.
 */
export class ManualClock {
  constructor(private ms: number = Math.floor(Date.now() / 1000) * 1000) {}

  readonly now: Clock = () => this.ms;

  readonly sleep: Sleep = async (ms) => {
    this.ms += ms;
  };

  advance(ms: number): void {
    this.ms += ms;
  }
}
