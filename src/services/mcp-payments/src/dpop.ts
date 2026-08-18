/**
 * @spec RFC 9449 §4.2, §4.3 — the Resource Server's ONE DPoP proof verifier.
 *
 * Every credential class this resource accepts is held to the identical
 * discipline: an ordinary Mission-bound access token and a transaction token
 * are both sender-constrained, and a transaction credential authorizes an
 * irreversible operation, so it can afford the weaker check least of all.
 * Splitting the verification per class is how one path silently loses a check;
 * there is one function and both call it.
 *
 * The checks, in order, all REQUIRED:
 *
 *  - the proof is a `dpop+jwt` signed under an allowlisted algorithm;
 *  - its header `jwk` is a PUBLIC key (a `d` member means the presenter shipped
 *    private material, which is never a proof of anything);
 *  - that key's thumbprint is the PRESENTED credential's `cnf.jkt`;
 *  - `htu`/`htm` bind the proof to THIS request;
 *  - `jti` is a string and single-use within the acceptance window;
 *  - `iat` is a number within that window in BOTH directions (a captured proof
 *    stops being usable; a future-dated one never starts);
 *  - `ath` is the access token's hash. Without it a proof binds only to a KEY,
 *    so two credentials bound to the same key are interchangeable on the wire:
 *    the proof minted to present one would present the other. `ath` is what
 *    makes the proof name the credential it accompanies.
 */

import { createHash } from "node:crypto";
import {
  DPOP_PROOF_REPLAY_WINDOW_S,
  type DpopProofReplay,
} from "@mission/core";
import { calculateJwkThumbprint, decodeProtectedHeader, type JWK, jwtVerify } from "jose";

/** The signing algorithms this resource accepts on a DPoP proof. */
export const DPOP_PROOF_ALGS = ["ES256"] as const;

/** @spec RFC 9449 §4.2 `ath` — base64url(SHA-256(access token)), over the
 *  ASCII of the token as it was presented. */
export function accessTokenHash(accessToken: string): string {
  return createHash("sha256").update(accessToken, "ascii").digest("base64url");
}

/** The request-bound proof a presented credential travels with. */
export interface DpopPresentation {
  proof: string;
  htu: string;
  htm: string;
}

/**
 * Verify a DPoP proof against the credential it accompanies. Throws on every
 * failure (the callers map that to their own refusal vocabulary); returns the
 * proven key thumbprint on success.
 */
export async function verifyDpopProof(input: {
  proof: string;
  /** The credential presented on this request; `ath` MUST hash to it. */
  accessToken: string;
  /** The presented credential's `cnf.jkt`. */
  expectedJkt: string;
  htu: string;
  htm: string;
  replay: DpopProofReplay;
  now?: () => Date;
}): Promise<string> {
  const header = decodeProtectedHeader(input.proof);
  const jwk = header.jwk as (JWK & { d?: string }) | undefined;
  if (!jwk) throw new Error("DPoP proof header carries no jwk");
  if (jwk.d !== undefined) throw new Error("DPoP proof header jwk carries private key material");
  const jkt = await calculateJwkThumbprint(jwk as never);
  if (jkt !== input.expectedJkt) throw new Error("DPoP key does not match token cnf.jkt");
  const { payload } = await jwtVerify(input.proof, jwk as never, {
    typ: "dpop+jwt",
    algorithms: [...DPOP_PROOF_ALGS],
  });
  if (payload.htu !== input.htu || payload.htm !== input.htm) throw new Error("DPoP htu/htm mismatch");
  if (typeof payload.iat !== "number") throw new Error("DPoP proof has no iat");
  const nowS = Math.floor((input.now?.() ?? new Date()).getTime() / 1000);
  if (Math.abs(nowS - payload.iat) > DPOP_PROOF_REPLAY_WINDOW_S) {
    throw new Error("DPoP proof iat is outside the acceptance window");
  }
  if (typeof payload.ath !== "string") throw new Error("DPoP proof has no ath");
  if (payload.ath !== accessTokenHash(input.accessToken)) {
    throw new Error("DPoP ath does not hash the presented credential");
  }
  if (typeof payload.jti !== "string" || !input.replay.check(payload.jti)) {
    throw new Error("DPoP proof jti is missing or replayed");
  }
  return jkt;
}
