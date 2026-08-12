/**
 * @spec RFC 9449 §11.1 — a bounded-TTL replay cache for DPoP proof `jti`
 * values at the token endpoint's CUSTOM grants.
 *
 * oidc-provider's native grants run the provider's own DPoP validation; the
 * custom grants (child-creation, expansion and its deferred poll, the ICA
 * continuation exchange, async delegation, the AROP deferred grant, child
 * redemption, and mission dispatch) verify their proofs MANUALLY and
 * previously kept no jti cache — the code's own comment admitted it — so a
 * captured proof was replayable for its whole validity window. This cache
 * closes that: a proof `jti` is single-use within the acceptance window.
 *
 * In-memory and AS-local (D27), bounded in TIME (entries expire after the
 * window) and in SIZE (oldest-first eviction past the cap: refusing to grow
 * without bound is preferred over unbounded state, at the cost of a
 * theoretically re-usable very-old jti under sustained flood).
 */

/** The jti acceptance window (seconds). Proof lifetimes are short; a jti is
 *  remembered at least as long as any server would accept its proof. */
export const DPOP_PROOF_REPLAY_WINDOW_S = 300;

/** Size bound: past this, the oldest entry is evicted. */
const MAX_ENTRIES = 100_000;

export interface DpopProofReplay {
  /**
   * Record-and-check: true when the `jti` is FRESH within the window (it is
   * recorded); false when it was already seen (a replay — refuse the proof).
   */
  check(jti: string): boolean;
}

export function newDpopProofReplay(
  windowSeconds = DPOP_PROOF_REPLAY_WINDOW_S,
  now: () => number = Date.now,
): DpopProofReplay {
  // jti -> expiry (ms). Insertion order == expiry order (constant window), so
  // lazy purging can stop at the first unexpired entry.
  const seen = new Map<string, number>();
  return {
    check(jti) {
      const t = now();
      for (const [k, exp] of seen) {
        if (exp <= t) seen.delete(k);
        else break;
      }
      const existing = seen.get(jti);
      if (existing !== undefined && existing > t) return false;
      seen.delete(jti);
      seen.set(jti, t + windowSeconds * 1000);
      if (seen.size > MAX_ENTRIES) {
        const oldest = seen.keys().next().value;
        if (oldest !== undefined) seen.delete(oldest);
      }
      return true;
    },
  };
}
