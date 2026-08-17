/**
 * @spec txn-authorization#resource-challenge — the Challenge-Issuing Resource's
 * signing side.
 *
 * The wire vocabulary (typ constants, claim interfaces, the value-equality
 * helpers) lives in `@mission/core`; only the signing, which needs this
 * resource's own key, lives here. `mission`, `parameter_digest` and `cnf` are
 * REQUIRED and are derived by the resource from the request and the VERIFIED
 * Mission-bound access token: a client-supplied replacement for any of them is
 * never accepted, which is why this function takes them as typed inputs rather
 * than as an open claim bag.
 */

import {
  TXN_CHALLENGE_TYP,
  type JsonValue,
  type TxnChallengeClaims,
  type TxnMissionClaim,
} from "@mission/core";
import { SignJWT, type CryptoKey } from "jose";

export { TXN_CHALLENGE_TYP, type TxnChallengeClaims };

/** The resource-derived inputs to one challenge. */
export interface SignChallengeInput {
  txn: string;
  /** Exactly one operation-scoped entry. */
  authorization_details: JsonValue[];
  /** This resource (the challenge `iss`). */
  iss: string;
  /** The Transaction Authorization Server (the challenge `aud`). */
  aud: string;
  reason: string;
  /** Copied unchanged from the verified Mission-bound access token. */
  mission: TxnMissionClaim;
  /** The runtime profile's digest over the effective operation parameters. */
  parameter_digest: string;
  /** The presenter key the resulting transaction token must be bound to. */
  cnf: { jkt: string };
  /** Seconds the challenge admits a workflow; it bounds admission only. */
  lifetimeSeconds?: number;
  act?: JsonValue;
  reason_uri?: string;
}

/** The signed challenge plus the identifiers the resource retains for it. */
export interface SignedChallenge {
  challenge: string;
  txn: string;
  jti: string;
}

/**
 * Sign a transaction authorization challenge with this resource's
 * txn-challenge key (the key published at its `txn_challenge_jwks_uri`).
 */
export async function signChallenge(
  input: SignChallengeInput,
  key: CryptoKey,
  kid: string,
  alg = "ES256",
): Promise<SignedChallenge> {
  const jti = crypto.randomUUID();
  const body: Record<string, unknown> = {
    txn: input.txn,
    authorization_details: input.authorization_details,
    reason: input.reason,
    mission: input.mission,
    parameter_digest: input.parameter_digest,
    cnf: input.cnf,
    ...(input.act !== undefined ? { act: input.act } : {}),
    ...(input.reason_uri !== undefined ? { reason_uri: input.reason_uri } : {}),
  };
  const challenge = await new SignJWT(body)
    .setProtectedHeader({ alg, kid, typ: TXN_CHALLENGE_TYP })
    .setIssuer(input.iss)
    .setAudience(input.aud)
    .setJti(jti)
    .setIssuedAt()
    .setExpirationTime(`${input.lifetimeSeconds ?? 300}s`)
    .sign(key);
  return { challenge, txn: input.txn, jti };
}

/** @deprecated superseded by MISSION_TXN_TOKEN_TYP + the offline-verification path. */
export const TXN_TOKEN_TYP = "txn-token+jwt";

/** @deprecated superseded by the linearizable consumption store. */
export class TxnReplayCache {
  private readonly used = new Set<string>();
  accept(txn: string): boolean {
    if (this.used.has(txn)) return false;
    this.used.add(txn);
    return true;
  }
}
