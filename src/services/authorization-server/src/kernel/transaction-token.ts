/**
 * @spec txn-authorization#transaction-token — the `mission-txn-token+jwt` mint.
 *
 * Its own JWT access-token profile, not RFC 9068: a Resource Server that
 * recognizes only `at+jwt` correctly rejects it as unknown, and this token is
 * never acceptable as a general Mission-bound access token. `aud` is a
 * SINGLETON string, exactly the verified challenge's `iss`; `sub` is the
 * verified effective subject and never the Approver; `client_id` is the client
 * authenticated at the transaction endpoint. The claim set is CLOSED: nothing
 * outside it is written, so the approval object, `single_use`, raw parameters
 * or rendered text, roles, relationships, and evidence objects cannot ride
 * here even by accident.
 */

import {
  MISSION_TXN_TOKEN_TYP,
  type JsonValue,
  type TxnMissionClaim,
} from "@mission/core";
import { SignJWT, type CryptoKey } from "jose";

export { MISSION_TXN_TOKEN_TYP };

export interface MintTransactionTokenInput {
  issuer: string;
  /** The verified challenge's `iss`. Becomes the singleton `aud`. */
  audience: string;
  jti: string;
  /** Epoch seconds; the caller computes the min() bound. */
  expS: number;
  /** The verified effective subject: the Mission's subject or origin principal. */
  subject: string;
  /** The client authenticated at the transaction endpoint. */
  clientId: string;
  txn: string;
  /** The exact permitted entry, never wider than the challenge or the decision. */
  authorizationDetails: JsonValue[];
  /** Recomputed and verified against the challenge before it is copied. */
  parameterDigest: string;
  /** Value-equal to the verified challenge's profiled members. */
  mission: TxnMissionClaim;
  cnfJkt: string;
  /** REQUIRED where actor context existed upstream; otherwise absent. */
  act?: JsonValue;
  key: CryptoKey;
  kid: string;
  alg?: string;
}

export async function mintTransactionToken(input: MintTransactionTokenInput): Promise<string> {
  return new SignJWT({
    sub: input.subject,
    client_id: input.clientId,
    txn: input.txn,
    authorization_details: input.authorizationDetails,
    parameter_digest: input.parameterDigest,
    mission: input.mission,
    cnf: { jkt: input.cnfJkt },
    // Attribution, never authority: it names who acted, and grants nothing.
    ...(input.act !== undefined ? { act: input.act } : {}),
  })
    .setProtectedHeader({ alg: input.alg ?? "ES256", kid: input.kid, typ: MISSION_TXN_TOKEN_TYP })
    .setIssuer(input.issuer)
    .setAudience(input.audience)
    .setIssuedAt()
    .setExpirationTime(input.expS)
    .setJti(input.jti)
    .sign(input.key);
}
