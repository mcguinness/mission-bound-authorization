/**
 * @spec status#security-considerations ("Mission Status Denial of Service",
 * #1686): the AS MUST implement per-consumer rate limiting on the Mission
 * Status operation, answering `rate_limited` (status#mission-status-errors).
 *
 * A fixed window per authenticated client. The count is kept per consumer,
 * never per Mission, so a refusal says nothing about any Mission
 * (status#mission-status-anti-oracle), and it is taken only after
 * authentication, so an unauthenticated request is an authentication failure
 * that counts against no client. The windows live in this process, as the
 * deployment's single process does; a refused request is not counted.
 */

/** Requests a client may make to the Mission Status operation per window. */
export interface MissionStatusRateLimit {
  requests: number;
  windowSeconds: number;
}

/** This deployment's default: generous for per-request consumers, still a bound. */
export const DEFAULT_MISSION_STATUS_RATE_LIMIT: MissionStatusRateLimit = { requests: 120, windowSeconds: 60 };

export class MissionStatusRateLimiter {
  private readonly windows = new Map<string, { start: number; count: number }>();

  constructor(
    private readonly limit: MissionStatusRateLimit,
    private readonly now: () => number,
  ) {
    for (const [name, value] of Object.entries(limit)) {
      if (!Number.isInteger(value) || value < 1) {
        throw new Error(`missionStatusRateLimit.${name} must be a positive integer`);
      }
    }
  }

  /**
   * Count one request for `client`. Undefined when it is admitted; otherwise
   * the whole seconds until its window resets, for `Retry-After`.
   */
  admit(client: string): number | undefined {
    const now = this.now();
    const windowMs = this.limit.windowSeconds * 1000;
    const window = this.windows.get(client);
    if (!window || now - window.start >= windowMs) {
      this.windows.set(client, { start: now, count: 1 });
      return undefined;
    }
    if (window.count < this.limit.requests) {
      window.count += 1;
      return undefined;
    }
    return Math.max(1, Math.ceil((window.start + windowMs - now) / 1000));
  }
}
