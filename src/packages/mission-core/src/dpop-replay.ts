/**
 * @spec RFC 9449 §11.1 — a bounded-TTL replay cache for DPoP proof `jti`
 * values, shared by every party that verifies proofs itself.
 *
 * It lives here because the Authorization Server's custom grants and the
 * Resource Server's credential paths need the IDENTICAL discipline and cannot
 * import each other (the RS must not depend on the AS package). The cache is
 * pure: a Map and an injectable clock, no crypto and no I/O, so both sides get
 * one implementation rather than two that drift.
 *
 * Bounded in TIME (entries expire after the window) and in SIZE. At the size
 * bound a NEW `jti` is refused retryably and nothing is evicted (#1173, D375):
 * evicting a live entry would make a still-acceptable proof replayable, so the
 * cache fails closed instead. A `jti` already seen stays a replay at the bound.
 */

/** The jti acceptance window (seconds). Proof lifetimes are short; a jti is
 *  remembered at least as long as any server would accept its proof. */
export const DPOP_PROOF_REPLAY_WINDOW_S = 300;

/**
 * How far in the future a DPoP proof's `iat` may lie (clock skew). The past
 * bound is the replay window less this, so a proof's whole acceptance
 * interval, `[iat - skew, iat + window - skew]`, fits inside the replay
 * cache's memory of its `jti` (first seen plus the window): a replay is always
 * refused by either the `iat` check or the cache, never neither.
 */
export const DPOP_PROOF_FUTURE_SKEW_S = 60;

/**
 * @spec RFC 9449 §4.3 — whether a proof's `iat` (seconds) is inside the
 * acceptance window at `nowS`: at most {@link DPOP_PROOF_FUTURE_SKEW_S} ahead,
 * and at most the replay window less that skew behind.
 */
export function dpopProofIatInWindow(iat: number, nowS: number): boolean {
  return (
    iat <= nowS + DPOP_PROOF_FUTURE_SKEW_S &&
    iat >= nowS - (DPOP_PROOF_REPLAY_WINDOW_S - DPOP_PROOF_FUTURE_SKEW_S)
  );
}

/** Size bound: past this, a new `jti` is refused retryably. */
export const DPOP_PROOF_REPLAY_MAX_ENTRIES = 100_000;

/** The outcome of admitting a `jti`. */
export type DpopProofAdmission =
  | { admitted: true }
  | { admitted: false; reason: "replay" }
  /** The cache is at its bound: refuse retryably; capacity frees in `retryAfterS` seconds. */
  | { admitted: false; reason: "full"; retryAfterS: number };

export interface DpopProofReplay {
  /**
   * Record-and-check. `admitted` when the `jti` is FRESH within the window (it
   * is recorded); `replay` when it was already seen (refuse the proof); `full`
   * when it is new but the cache is at its bound (refuse retryably; nothing is
   * recorded or evicted).
   */
  admit(jti: string): DpopProofAdmission;
}

export function newDpopProofReplay(
  windowSeconds = DPOP_PROOF_REPLAY_WINDOW_S,
  now: () => number = Date.now,
  maxEntries = DPOP_PROOF_REPLAY_MAX_ENTRIES,
): DpopProofReplay {
  // jti -> expiry (ms). Insertion order == expiry order (constant window), so
  // lazy purging can stop at the first unexpired entry.
  const seen = new Map<string, number>();
  return {
    admit(jti) {
      const t = now();
      for (const [k, exp] of seen) {
        if (exp <= t) seen.delete(k);
        else break;
      }
      const existing = seen.get(jti);
      if (existing !== undefined && existing > t) return { admitted: false, reason: "replay" };
      if (seen.size >= maxEntries) {
        // Capacity frees when the oldest entry expires; with no entry at all
        // (a zero bound) it never does, so a whole window is the answer.
        const oldest = seen.values().next().value;
        const retryAfterS =
          oldest === undefined ? windowSeconds : Math.max(1, Math.ceil((oldest - t) / 1000));
        return { admitted: false, reason: "full", retryAfterS };
      }
      seen.set(jti, t + windowSeconds * 1000);
      return { admitted: true };
    },
  };
}
