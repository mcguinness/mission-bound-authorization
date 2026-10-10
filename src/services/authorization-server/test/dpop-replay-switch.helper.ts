/**
 * @spec RFC 9449 Section 11.1, #1173 (D375): a DPoP replay cache a test can
 * switch to "full". Until then it is the real bounded cache. Once full, a `jti`
 * it already admitted stays a replay and a new one is refused for capacity,
 * as the real cache does at its bound (its own tests: @mission/core
 * dpop-replay.test.ts). Shared by suites whose one server serves every test,
 * so filling a real small cache would refuse their neighbours.
 */
import { type DpopProofAdmission, type DpopProofReplay, newDpopProofReplay } from "../src/adapters/dpop-replay.js";

/** The `Retry-After` the switched cache reports. */
export const SWITCHED_RETRY_AFTER_S = 7;

export function switchableDpopReplay(): DpopProofReplay & {
  full: boolean;
  /** While full, which `jti`s the bound applies to (default: every one). */
  fullWhen: (jti: string) => boolean;
} {
  const real = newDpopProofReplay();
  const admitted = new Set<string>();
  const cache = {
    full: false,
    fullWhen: (_jti: string): boolean => true,
    admit(jti: string): DpopProofAdmission {
      if (cache.full && cache.fullWhen(jti)) {
        return admitted.has(jti)
          ? { admitted: false, reason: "replay" }
          : { admitted: false, reason: "full", retryAfterS: SWITCHED_RETRY_AFTER_S };
      }
      const r = real.admit(jti);
      if (r.admitted) admitted.add(jti);
      return r;
    },
  };
  return cache;
}
