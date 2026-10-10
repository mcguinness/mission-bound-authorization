/**
 * @spec RFC 9449 Section 11.1, Section 4.3 (#1173, D375)
 *
 * The shared DPoP proof replay cache: a `jti` is single-use through the whole
 * window, its expiry instant included; a live entry is never evicted; and at
 * the size bound a NEW `jti` is refused retryably while a seen one stays a
 * replay. The acceptance window is asymmetric (60 s ahead, 240 s behind),
 * inclusive and compared in milliseconds, so every instant a proof is
 * acceptable falls inside the cache's memory of its `jti`.
 */

import { describe, expect, it } from "vitest";
import {
  DPOP_PROOF_FUTURE_SKEW_S,
  DPOP_PROOF_REPLAY_WINDOW_S,
  dpopProofIatAcceptableAt,
  newDpopProofReplay,
} from "../src/index.js";

const WINDOW_MS = DPOP_PROOF_REPLAY_WINDOW_S * 1000;

/** A clock the test moves by hand (milliseconds). */
function clock(start = 1_700_000_000_000) {
  let t = start;
  return { now: () => t, advance: (ms: number) => (t += ms), set: (ms: number) => (t = ms) };
}

describe("DPoP proof replay cache (@spec RFC 9449 Section 11.1, #1173)", () => {
  it("admits a jti once and refuses it through the window's last instant; it is admitted again only after it", () => {
    const c = clock();
    const cache = newDpopProofReplay(DPOP_PROOF_REPLAY_WINDOW_S, c.now);
    expect(cache.admit("a")).toEqual({ admitted: true });
    expect(cache.admit("a")).toEqual({ admitted: false, reason: "replay" });
    c.advance(WINDOW_MS);
    expect(cache.admit("a")).toEqual({ admitted: false, reason: "replay" });
    c.advance(1);
    expect(cache.admit("a")).toEqual({ admitted: true });
  });

  it("at its bound refuses a new jti retryably, records nothing and evicts no live entry; a seen jti stays a replay", () => {
    const c = clock();
    const cache = newDpopProofReplay(DPOP_PROOF_REPLAY_WINDOW_S, c.now, 3);
    expect(cache.admit("a")).toEqual({ admitted: true });
    c.advance(10_000);
    expect(cache.admit("b")).toEqual({ admitted: true });
    expect(cache.admit("c")).toEqual({ admitted: true });
    // Full: the new jti is refused, retryable once the oldest entry ("a") has
    // expired: the millisecond after its expiry instant, 290.001 s away.
    expect(cache.admit("d")).toEqual({
      admitted: false,
      reason: "full",
      retryAfterS: DPOP_PROOF_REPLAY_WINDOW_S - 10 + 1,
    });
    // Nothing was evicted to make room: every live jti is still a replay.
    for (const jti of ["a", "b", "c"])
      expect(cache.admit(jti)).toEqual({ admitted: false, reason: "replay" });
    // Nothing was recorded either: "d" is still new, and still refused for capacity.
    expect(cache.admit("d")).toMatchObject({ admitted: false, reason: "full" });
  });

  it("admits the same new jti once the oldest entry has expired, and the Retry-After never rounds to zero", () => {
    const c = clock();
    const cache = newDpopProofReplay(DPOP_PROOF_REPLAY_WINDOW_S, c.now, 2);
    cache.admit("a");
    cache.admit("b");
    c.advance(WINDOW_MS - 200);
    expect(cache.admit("n")).toEqual({ admitted: false, reason: "full", retryAfterS: 1 });
    // At the oldest entry's expiry instant it is still live: still full.
    c.advance(200);
    expect(cache.admit("n")).toEqual({ admitted: false, reason: "full", retryAfterS: 1 });
    c.advance(1);
    expect(cache.admit("n")).toEqual({ admitted: true });
    expect(cache.admit("n")).toEqual({ admitted: false, reason: "replay" });
  });
});

describe("DPoP proof replay cache with a zero bound (@spec #1173)", () => {
  it("refuses every new jti for capacity with a whole window as the Retry-After, never NaN", () => {
    const cache = newDpopProofReplay(DPOP_PROOF_REPLAY_WINDOW_S, clock().now, 0);
    expect(cache.admit("a")).toEqual({
      admitted: false,
      reason: "full",
      retryAfterS: DPOP_PROOF_REPLAY_WINDOW_S,
    });
  });
});

describe("DPoP proof acceptance window (@spec RFC 9449 Section 4.3, #1173)", () => {
  const nowS = 1_700_000_000;
  it("accepts an iat up to the skew ahead and up to the window less the skew behind, inclusive, and nothing outside", () => {
    const at = nowS * 1000;
    expect(dpopProofIatAcceptableAt(nowS, at)).toBe(true);
    expect(dpopProofIatAcceptableAt(nowS + DPOP_PROOF_FUTURE_SKEW_S, at)).toBe(true);
    expect(dpopProofIatAcceptableAt(nowS + DPOP_PROOF_FUTURE_SKEW_S + 1, at)).toBe(false);
    const behind = DPOP_PROOF_REPLAY_WINDOW_S - DPOP_PROOF_FUTURE_SKEW_S;
    expect(behind).toBe(240);
    expect(dpopProofIatAcceptableAt(nowS - behind, at)).toBe(true);
    expect(dpopProofIatAcceptableAt(nowS - behind - 1, at)).toBe(false);
  });

  it("compares in milliseconds: half a second past the bound is outside it, never rounded back in", () => {
    expect(dpopProofIatAcceptableAt(nowS - 240, nowS * 1000 + 500)).toBe(false);
    expect(dpopProofIatAcceptableAt(nowS + 60, nowS * 1000 - 500)).toBe(false);
  });
});

describe("freshness and replay retention together (@spec RFC 9449 Section 11.1, #1199 review)", () => {
  it("refuses a replay at every instant its proof is still acceptable, its final instant included, whatever the sub-second of first sight", () => {
    for (const firstSeen of [1_700_000_000_000, 1_700_000_000_500, 1_700_000_000_999]) {
      const c = clock(firstSeen);
      const cache = newDpopProofReplay(DPOP_PROOF_REPLAY_WINDOW_S, c.now);
      // The latest integer iat acceptable at first sight.
      const iat = Math.floor((firstSeen + DPOP_PROOF_FUTURE_SKEW_S * 1000) / 1000);
      expect(dpopProofIatAcceptableAt(iat, firstSeen)).toBe(true);
      expect(cache.admit("j")).toEqual({ admitted: true });
      const lastAcceptable =
        iat * 1000 + (DPOP_PROOF_REPLAY_WINDOW_S - DPOP_PROOF_FUTURE_SKEW_S) * 1000;
      for (let t = firstSeen + 250; t <= lastAcceptable + 1_000; t += 250) {
        c.set(t);
        if (dpopProofIatAcceptableAt(iat, t))
          expect(cache.admit("j"), `at +${t - firstSeen} ms`).toEqual({
            admitted: false,
            reason: "replay",
          });
      }
      // The final acceptable instant itself, and the first instant past it.
      c.set(lastAcceptable);
      expect(dpopProofIatAcceptableAt(iat, lastAcceptable)).toBe(true);
      expect(cache.admit("j")).toEqual({ admitted: false, reason: "replay" });
      expect(dpopProofIatAcceptableAt(iat, lastAcceptable + 1)).toBe(false);
    }
  });
});
