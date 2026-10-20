/**
 * @spec expansion#policy-probing (#1177): the per-predecessor, per-client
 * expansion rate limiter, a sliding window over an injected clock.
 */
import { describe, expect, it } from "vitest";
import { ExpansionRateLimiter } from "../src/index.js";

describe("the expansion rate limiter (@spec expansion#policy-probing, #1177)", () => {
  it("admits max requests per window for one predecessor and client, refuses the next with the seconds until a slot frees, and admits again once the oldest leaves the window", () => {
    let now = 1_000_000;
    const limiter = new ExpansionRateLimiter(3, 60, () => now);
    expect(limiter.admit("msn_a", "client-1")).toEqual({ ok: true });
    now += 10_000;
    expect(limiter.admit("msn_a", "client-1")).toEqual({ ok: true });
    expect(limiter.admit("msn_a", "client-1")).toEqual({ ok: true });
    expect(limiter.admit("msn_a", "client-1")).toEqual({ ok: false, retryAfterS: 50 });
    // A refused request counts nothing: the wait is unchanged by retrying.
    expect(limiter.admit("msn_a", "client-1")).toEqual({ ok: false, retryAfterS: 50 });
    now += 50_001;
    expect(limiter.admit("msn_a", "client-1")).toEqual({ ok: true });
    expect(limiter.admit("msn_a", "client-1")).toEqual({ ok: false, retryAfterS: 10 });
  });

  it("keeps each predecessor and client pair separate", () => {
    const limiter = new ExpansionRateLimiter(1, 60, () => 0);
    expect(limiter.admit("msn_a", "client-1")).toEqual({ ok: true });
    expect(limiter.admit("msn_a", "client-1").ok).toBe(false);
    expect(limiter.admit("msn_b", "client-1")).toEqual({ ok: true });
    expect(limiter.admit("msn_a", "client-2")).toEqual({ ok: true });
  });
});
