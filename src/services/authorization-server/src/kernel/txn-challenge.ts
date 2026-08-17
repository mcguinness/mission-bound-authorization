/**
 * @spec txn-authorization#resource-challenge, #two-phase-expiry (key discovery)
 * — the Transaction Authorization Server's challenge-verification side.
 *
 * The wire vocabulary lives in `@mission/core`, shared with the
 * Challenge-Issuing Resource (the two packages cannot import each other).
 * What lives here is the TAS's own trust decision: the set of acceptable
 * Challenge-Issuing Resources is deployment and federation policy, never taken
 * from an untrusted request claim, and a challenge issuer's keys are resolved
 * from THAT issuer's published `txn_challenge_jwks_uri` and nowhere else. One
 * resource's key therefore cannot verify another resource's `iss`.
 */

import {
  readTxnMissionClaim,
  TXN_CHALLENGE_TYP,
  type JsonValue,
  type TxnChallengeClaims,
} from "@mission/core";
import { decodeJwt, jwtVerify, SignJWT, type CryptoKey, type JWTVerifyGetKey } from "jose";
import type { MissionClaim } from "./types.js";

export { TXN_CHALLENGE_TYP, type TxnChallengeClaims };

/**
 * One accepted Challenge-Issuing Resource: the resolver for the keys it
 * publishes at its `txn_challenge_jwks_uri`, and the algorithms it declares in
 * `txn_challenge_signing_alg_values_supported`. Any jose key resolver fits
 * (createRemoteJWKSet over the published URI in a deployment; createLocalJWKSet
 * in a test), so the AS package holds no fetching policy of its own.
 */
export interface ChallengeIssuerKeys {
  jwks: JWTVerifyGetKey;
  algs?: string[];
}

/** The accepted challenge issuers, keyed by the resource's `iss` value. */
export type ChallengeIssuers = ReadonlyMap<string, ChallengeIssuerKeys>;

export type ChallengeErrorCode =
  | "unknown_issuer"
  | "invalid_signature"
  | "invalid_claims"
  | "expired_challenge";

export class ChallengeError extends Error {
  constructor(
    readonly code: ChallengeErrorCode,
    message: string,
  ) {
    super(message);
  }
}

/**
 * Validate a challenge against the keys of the issuer it NAMES. The issuer is
 * read from the unverified JWT only to select the key set; the signature is
 * then verified under that set alone, so a valid signature by a DIFFERENT
 * accepted resource's key fails. `expiredOk` lets a caller distinguish the
 * admission check (a late challenge is refused into a new workflow) from a
 * re-read of a challenge already admitted.
 */
export async function validateChallenge(
  challenge: string,
  issuers: ChallengeIssuers,
  expectedAud: string,
  opts: { expiredOk?: boolean } = {},
): Promise<TxnChallengeClaims> {
  let iss: string | undefined;
  try {
    iss = decodeJwt(challenge).iss;
  } catch {
    throw new ChallengeError("invalid_claims", "challenge is not a JWT");
  }
  const issuer = iss ? issuers.get(iss) : undefined;
  if (!iss || !issuer) {
    throw new ChallengeError("unknown_issuer", "challenge issuer is not an accepted resource");
  }
  let payload: Record<string, unknown>;
  try {
    ({ payload } = (await jwtVerify(challenge, issuer.jwks, {
      audience: expectedAud,
      issuer: iss,
      typ: TXN_CHALLENGE_TYP,
      ...(issuer.algs ? { algorithms: issuer.algs } : {}),
      ...(opts.expiredOk ? { clockTolerance: Number.MAX_SAFE_INTEGER } : {}),
    })) as { payload: Record<string, unknown> });
  } catch (e) {
    const code = (e as { code?: string }).code;
    if (code === "ERR_JWT_EXPIRED") {
      throw new ChallengeError("expired_challenge", "challenge has expired");
    }
    throw new ChallengeError("invalid_signature", "challenge did not verify under its issuer's keys");
  }

  // Upstream REQUIRED claims plus this profile's three additions. A challenge
  // missing any of them is rejected outright, never parsed best-effort.
  const details = payload.authorization_details;
  const cnf = payload.cnf as { jkt?: unknown } | undefined;
  const mission = readTxnMissionClaim(payload.mission);
  if (
    typeof payload.jti !== "string" ||
    typeof payload.iat !== "number" ||
    typeof payload.exp !== "number" ||
    typeof payload.txn !== "string" ||
    typeof payload.reason !== "string" ||
    !Array.isArray(details) ||
    details.length !== 1 ||
    typeof payload.parameter_digest !== "string" ||
    typeof cnf?.jkt !== "string" ||
    !mission
  ) {
    throw new ChallengeError("invalid_claims", "challenge is missing a REQUIRED claim");
  }
  return {
    iss,
    aud: expectedAud,
    iat: payload.iat,
    exp: payload.exp,
    jti: payload.jti,
    txn: payload.txn,
    authorization_details: details as JsonValue[],
    reason: payload.reason,
    mission,
    parameter_digest: payload.parameter_digest,
    cnf: { jkt: cnf.jkt },
    ...(payload.act !== undefined ? { act: payload.act as JsonValue } : {}),
    ...(typeof payload.reason_uri === "string" ? { reason_uri: payload.reason_uri } : {}),
  };
}

/** @deprecated superseded by the conforming mission-txn-token+jwt mint. */
export const TXN_TOKEN_TYP = "txn-token+jwt";

/** @deprecated superseded by the conforming mission-txn-token+jwt mint. */
export async function issueTxnToken(input: {
  txn: string;
  audience: string;
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

/** @deprecated superseded by the linearizable consumption store. */
export class TxnReplayCache {
  private readonly used = new Set<string>();
  accept(txn: string): boolean {
    if (this.used.has(txn)) return false;
    this.used.add(txn);
    return true;
  }
}
