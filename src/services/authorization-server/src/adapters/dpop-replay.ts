/**
 * @spec RFC 9449 §11.1 — the DPoP proof `jti` replay cache at the token
 * endpoint's CUSTOM grants.
 *
 * oidc-provider's native grants run the provider's own DPoP validation; the
 * custom grants (child-creation, expansion and its deferred poll, the ICA
 * continuation exchange, async delegation, the AROP deferred grant, child
 * redemption, and mission dispatch) verify their proofs MANUALLY and
 * previously kept no jti cache — the code's own comment admitted it — so a
 * captured proof was replayable for its whole validity window. This cache
 * closes that: a proof `jti` is single-use within the acceptance window.
 *
 * The implementation is the family's ONE replay cache
 * ({@link @mission/core}): the Resource Server verifies proofs under the same
 * discipline and the two packages cannot import each other. In-memory and
 * AS-local (D27).
 */

import type { KoaContextWithOIDC } from "oidc-provider";

export {
  DPOP_PROOF_FUTURE_SKEW_S,
  DPOP_PROOF_REPLAY_WINDOW_S,
  type DpopProofAdmission,
  type DpopProofReplay,
  dpopProofIatAcceptableAt,
  newDpopProofReplay,
} from "@mission/core";

/** A token-endpoint proof the shared verifier did not accept. */
export interface TokenEndpointProofFailure {
  description: string;
  /** Set when the replay cache is at its bound: the refusal is retryable. */
  retryAfterS?: number;
}

/**
 * @spec RFC 9449 Section 4.3, #1173 (D375): the token endpoint's refusal for a
 * proof the shared verifier did not accept. A proof that fails a check is
 * `invalid_dpop_proof`. A new proof refused only because the replay cache is
 * at its bound is `temporarily_unavailable` (HTTP 503) with `Retry-After`: a
 * retry with a fresh proof may succeed once capacity frees.
 */
export function refuseTokenEndpointProof(ctx: KoaContextWithOIDC, failure: TokenEndpointProofFailure): void {
  const unavailable = failure.retryAfterS !== undefined;
  ctx.status = unavailable ? 503 : 400;
  ctx.body = {
    error: unavailable ? "temporarily_unavailable" : "invalid_dpop_proof",
    error_description: failure.description,
  };
  ctx.set("cache-control", "no-store");
  if (unavailable) ctx.set("Retry-After", String(failure.retryAfterS));
}
