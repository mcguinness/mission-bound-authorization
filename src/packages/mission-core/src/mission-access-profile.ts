/**
 * @spec runtime-oauth#token-validation, mission#introspection (#825, D402) —
 * the Mission access-token profile, read the same way by the resource and by
 * AS introspection: `typ` `at+jwt`, the RFC 9068 claim set with its types and
 * clock bounds, the `mission` claim's profiled members, the credential's own
 * authority read in full, and the structure of its sender-constraint binding.
 *
 * Each validator adds only what is its own. The resource requires the DPoP
 * key it proves possession of; introspection requires a binding where the
 * token's profile requires sender constraint, and never proves possession.
 */

import { type ActObject, validateActChain } from "@mission/actor-chain";
import { type Confirmation, parseConfirmation } from "./confirmation.js";
import { type CredentialAuthorityEntry, parseCredentialAuthority } from "./credential-authority.js";
import { readTxnMissionClaim, type TxnMissionClaim } from "./txn-authorization.js";

/** RFC 9068 Section 2.1: the JWT access token type. */
export const MISSION_ACCESS_TOKEN_TYP = "at+jwt";

/** Accepted clock skew, in seconds, for an `iat` that reads slightly ahead of the validator's clock. */
export const ISSUED_AT_SKEW_S = 60;

/** Thrown when a verified payload does not meet its credential profile. */
export class CredentialProfileError extends Error {}

/** The claims every Mission-bound credential profile requires, read and typed. */
export interface CredentialProfileClaims {
  sub: string;
  clientId: string;
  jti: string;
  iat: number;
  exp: number;
  /** The sender-constraint binding, structure only; absent for a bearer token. */
  confirmation?: Confirmation;
}

/** An ordinary Mission access token's profile (`at+jwt`). */
export interface MissionAccessProfile extends CredentialProfileClaims {
  mission: TxnMissionClaim;
  /** The authority the credential itself carries (`authorization_details`), read in full. */
  credentialAuthority: readonly CredentialAuthorityEntry[];
  /** A delegated token's actor chain, validated under the Actor Profile; absent when self-acting. */
  act?: ActObject;
}

const nonEmptyString = (v: unknown): v is string => typeof v === "string" && v.length > 0;
const numericDate = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);

/** RFC 7515 Section 4.1.9: `typ` is a media type, compared without its `application/` prefix, case-insensitively. */
export function mediaTypeOf(typ: unknown): string | undefined {
  if (typeof typ !== "string") return undefined;
  const lower = typ.toLowerCase();
  return lower.startsWith("application/") ? lower.slice("application/".length) : lower;
}

/** The claim primitives of every Mission-bound credential profile, at `nowS` (seconds). */
export function readCredentialProfileClaims(
  payload: Record<string, unknown>,
  nowS: number,
): CredentialProfileClaims {
  const { exp, iat, nbf, jti, sub, client_id: clientId } = payload;
  if (!numericDate(exp)) throw new CredentialProfileError("token exp must be a NumericDate");
  if (!numericDate(iat)) throw new CredentialProfileError("token iat must be a NumericDate");
  if (nbf !== undefined && !numericDate(nbf))
    throw new CredentialProfileError("token nbf must be a NumericDate");
  if (exp <= nowS) throw new CredentialProfileError("token is expired");
  if (iat > nowS + ISSUED_AT_SKEW_S) throw new CredentialProfileError("token iat is in the future");
  if (!nonEmptyString(jti))
    throw new CredentialProfileError("token jti must be a non-empty string");
  if (!nonEmptyString(sub))
    throw new CredentialProfileError("token sub must be a non-empty string");
  if (!nonEmptyString(clientId))
    throw new CredentialProfileError("token client_id must be a non-empty string");
  let confirmation: Confirmation | undefined;
  try {
    confirmation = parseConfirmation(payload.cnf);
  } catch (e) {
    throw new CredentialProfileError(`token ${(e as Error).message}`);
  }
  return { sub, clientId, jti, iat, exp, ...(confirmation ? { confirmation } : {}) };
}

/**
 * The ordinary Mission access-token profile. A present but unreadable
 * `mission` claim refuses; it never demotes the credential to another class.
 */
export function readMissionAccessProfile(
  typ: unknown,
  payload: Record<string, unknown>,
  nowS: number,
): MissionAccessProfile {
  if (mediaTypeOf(typ) !== MISSION_ACCESS_TOKEN_TYP) {
    throw new CredentialProfileError(`token typ must be ${MISSION_ACCESS_TOKEN_TYP}`);
  }
  const base = readCredentialProfileClaims(payload, nowS);
  const mission = readTxnMissionClaim(payload.mission);
  if (!mission?.id || !mission.issuer) {
    throw new CredentialProfileError("token mission claim is missing or malformed");
  }
  let credentialAuthority: readonly CredentialAuthorityEntry[];
  try {
    credentialAuthority = parseCredentialAuthority(payload.authorization_details);
  } catch (e) {
    throw new CredentialProfileError(`token authorization_details: ${(e as Error).message}`);
  }
  // @spec mission#delegation, RFC 8693 Section 4.1 (#904): a present `act`
  // is an object whose every hop meets the Actor Profile (`sub` and `iss`,
  // no `client_profile`, valid `sub_profile` tokens, depth within the
  // maximum), the check the resource's enforcement point applies to it.
  const act = payload.act;
  if (act !== undefined) {
    if (typeof act !== "object" || act === null || Array.isArray(act)) {
      throw new CredentialProfileError("token act must be an object");
    }
    try {
      validateActChain(act as ActObject);
    } catch (e) {
      throw new CredentialProfileError(`token act: ${(e as Error).message}`);
    }
  }
  return {
    ...base,
    mission,
    credentialAuthority,
    ...(act !== undefined ? { act: act as ActObject } : {}),
  };
}
