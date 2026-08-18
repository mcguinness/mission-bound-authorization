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

export {
  DPOP_PROOF_REPLAY_WINDOW_S,
  type DpopProofReplay,
  newDpopProofReplay,
} from "@mission/core";
