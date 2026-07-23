/**
 * @spec AROP Transaction Challenge binding (I-D.rosomakho-oauth-txn-challenge),
 * openid/authzen#531.
 *
 * The protected resource (PEP) signs a Transaction Authorization Challenge
 * (JWS: txn, authorization_details, iss=resource, aud=AS, reason). The client
 * presents it to the AS transaction_authorization_endpoint; the AS validates
 * it against the resource's txn_challenge_jwks_uri keys, obtains approval, and
 * issues a txn-bound, audience-restricted, single-use token the client
 * re-presents to the resource.
 */

import { createLocalJWKSet, jwtVerify, SignJWT, type CryptoKey, type JWK } from "jose";

export const TXN_CHALLENGE_TYP = "txn-challenge+jwt";
export const TXN_TOKEN_TYP = "txn-token+jwt";

export interface TxnChallengeClaims {
  txn: string;
  authorization_details: unknown[];
  iss: string; // the resource
  aud: string; // the AS
  reason: string;
}

/** RS side: sign a challenge with the rs-txn key (txn_challenge_jwks_uri). */
export async function signChallenge(claims: TxnChallengeClaims, key: CryptoKey, kid: string): Promise<string> {
  return new SignJWT({ authorization_details: claims.authorization_details, reason: claims.reason })
    .setProtectedHeader({ alg: "ES256", kid, typ: TXN_CHALLENGE_TYP })
    .setIssuer(claims.iss)
    .setAudience(claims.aud)
    .setSubject(claims.txn)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(key);
}

/** AS side: validate a challenge against the resource's signing keys. */
export async function validateChallenge(
  challenge: string,
  resourceJwks: { keys: JWK[] },
  expectedAud: string,
): Promise<TxnChallengeClaims> {
  const jwks = createLocalJWKSet({ keys: resourceJwks.keys } as never);
  const { payload } = await jwtVerify(challenge, jwks, { audience: expectedAud, typ: TXN_CHALLENGE_TYP });
  return {
    txn: payload.sub as string,
    authorization_details: (payload.authorization_details as unknown[]) ?? [],
    iss: payload.iss as string,
    aud: payload.aud as string,
    reason: payload.reason as string,
  };
}

/**
 * AS side: issue a txn-bound, audience-restricted, single-use access token
 * after approval. Carries the challenge txn and the (successor) mission claim.
 */
export async function issueTxnToken(input: {
  txn: string;
  audience: string; // the resource
  mission: Record<string, unknown>;
  authorizationDetails: unknown[];
  approvedUntil: string;
  cnfJkt: string;
  key: CryptoKey;
  kid: string;
  issuer: string;
}): Promise<string> {
  const exp = Math.floor(Date.parse(input.approvedUntil) / 1000);
  return new SignJWT({
    txn: input.txn,
    mission: input.mission,
    authorization_details: input.authorizationDetails,
    single_use: true,
    cnf: { jkt: input.cnfJkt },
  })
    .setProtectedHeader({ alg: "ES256", kid: input.kid, typ: TXN_TOKEN_TYP })
    .setIssuer(input.issuer)
    .setAudience(input.audience)
    .setIssuedAt()
    .setExpirationTime(exp)
    .sign(input.key);
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
