/**
 * @spec AROP Transaction Challenge binding (I-D.rosomakho-oauth-txn-challenge),
 * openid/authzen#531 -- resource-server (PEP) side.
 *
 * These primitives are a deliberate COPY of the leaf helpers in
 * `@mission/authorization-server` (src/kernel/txn-challenge.ts). The resource
 * server must not depend on the authorization-server package: that would drag
 * the whole AS kernel (incl. oidc-provider) into the RS closure and close a
 * workspace dependency loop (authorization-server --(dev)--> access-request -->
 * mcp-payments). Both sides depend only on `jose`, so the format-coupling cost
 * of the copy is small; keep the two in sync if the wire format changes.
 */

import { SignJWT, type CryptoKey } from "jose";

export const TXN_CHALLENGE_TYP = "txn-authz-challenge+jwt";
export const TXN_TOKEN_TYP = "txn-token+jwt";

export interface TxnChallengeClaims {
  txn: string;
  authorization_details: unknown[];
  iss: string; // the resource
  aud: string; // the AS
  reason: string;
  /** Digest of the effective operation parameters the RS gated on. */
  parameter_digest?: string;
}

/**
 * RS side: sign a challenge with the rs-txn key (txn_challenge_jwks_uri). The
 * transaction id travels as a `txn` claim in the signed body (draft §4.2.1);
 * a REQUIRED `jti` (§4.2.2) makes each challenge uniquely identifiable.
 */
export async function signChallenge(claims: TxnChallengeClaims, key: CryptoKey, kid: string): Promise<string> {
  const body: Record<string, unknown> = {
    txn: claims.txn,
    authorization_details: claims.authorization_details,
    reason: claims.reason,
  };
  if (claims.parameter_digest !== undefined) body.parameter_digest = claims.parameter_digest;
  return new SignJWT(body)
    .setProtectedHeader({ alg: "ES256", kid, typ: TXN_CHALLENGE_TYP })
    .setIssuer(claims.iss)
    .setAudience(claims.aud)
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(key);
}

/**
 * RS side: single-use re-presentation cache. Returns true the first time a
 * txn-bound token is presented for its txn, false on replay.
 */
export class TxnReplayCache {
  private readonly used = new Set<string>();
  accept(txn: string): boolean {
    if (this.used.has(txn)) return false;
    this.used.add(txn);
    return true;
  }
}
