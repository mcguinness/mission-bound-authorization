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
import type { MissionClaim } from "./types.js";

export const TXN_CHALLENGE_TYP = "txn-challenge+jwt";
export const TXN_TOKEN_TYP = "txn-token+jwt";

export interface TxnChallengeClaims {
  txn: string;
  authorization_details: unknown[];
  iss: string; // the resource
  aud: string; // the AS
  reason: string;
  /**
   * Digest of the effective operation parameters the RS gated on. Optional on
   * the shared type (the de-risk spike predates it); the shipped
   * transaction_authorization_endpoint requires it and rejects a challenge
   * without one.
   */
  parameter_digest?: string;
}

/** RS side: sign a challenge with the rs-txn key (txn_challenge_jwks_uri). */
export async function signChallenge(claims: TxnChallengeClaims, key: CryptoKey, kid: string): Promise<string> {
  const body: Record<string, unknown> = {
    authorization_details: claims.authorization_details,
    reason: claims.reason,
  };
  if (claims.parameter_digest !== undefined) body.parameter_digest = claims.parameter_digest;
  return new SignJWT(body)
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
    ...(payload.parameter_digest !== undefined
      ? { parameter_digest: payload.parameter_digest as string }
      : {}),
  };
}

/**
 * AS side: issue a txn-bound, audience-restricted, single-use access token
 * after approval. Carries the challenge txn and the ACTIVE mission claim
 * unchanged (D42: AROP never widens; widening is the separate Expansion flow),
 * plus the verified approval (incl. its parameter_digest).
 */
export async function issueTxnToken(input: {
  txn: string;
  audience: string; // the resource
  mission: MissionClaim | Record<string, unknown>;
  authorizationDetails: unknown[];
  approval: { id: string; approved_at: string; approved_until: string; parameter_digest: string };
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
    approval: input.approval,
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
