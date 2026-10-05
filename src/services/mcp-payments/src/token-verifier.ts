/**
 * @spec runtime-oauth#token-validation, RFC 9068 Section 2 (#825) — the claim
 * profiles of the Mission-bound credentials this resource accepts, checked on
 * an already signature-verified payload before any value becomes a decision
 * input. Each profile is its own: the ordinary Mission access token is an
 * `at+jwt`, and an attenuation root is an `aat+jwt`. They share the claim
 * primitives below and nothing else, so neither class is ever accepted as the
 * other.
 *
 * Every REQUIRED claim is checked for presence AND type: `jose` validates
 * `exp`, `nbf` and `iat` only when present (and refuses a future `nbf`
 * itself), and never requires `jti`, `sub` or `client_id`. A credential that
 * fails here yields no trusted facts.
 */

import {
  AAT_TYP,
  type AuthorityEntry,
  type CredentialAuthorityEntry,
  credentialEntriesFromAuthority,
  parseCredentialAuthority,
  readTxnMissionClaim,
  type TxnMissionClaim,
} from "@mission/core";
import type { JWTPayload } from "jose";

/**
 * Authority entries read as a credential's own authority, under the same
 * strict rules a verified token's `authorization_details` meets: for a
 * credential modeled on what an issuer would mint for a Mission (fixtures,
 * evaluations, exhibits).
 */
export function credentialAuthorityFrom(
  entries: readonly Pick<AuthorityEntry, "type" | "resource" | "actions" | "constraints">[],
): readonly CredentialAuthorityEntry[] {
  return credentialEntriesFromAuthority(entries as readonly AuthorityEntry[]);
}

/** RFC 9068 Section 2.1: the JWT access token type. */
export const MISSION_ACCESS_TOKEN_TYP = "at+jwt";

/** Accepted clock skew, in seconds, for an `iat` that reads slightly ahead of this resource's clock. */
export const ISSUED_AT_SKEW_S = 60;

/** Thrown when a verified payload does not meet its credential profile. */
export class TokenProfileError extends Error {}

/** The claims every Mission-bound credential profile requires, read and typed. */
export interface VerifiedCredentialClaims {
  sub: string;
  clientId: string;
  jti: string;
  iat: number;
  exp: number;
  /** The sender-constraint key; a proof of possession is verified separately, by transport. */
  cnfJkt: string;
}

/** An ordinary Mission access token's claims (`at+jwt`). */
export interface VerifiedMissionAccessClaims extends VerifiedCredentialClaims {
  mission: TxnMissionClaim;
  /** The authority the credential itself carries (`authorization_details`). */
  credentialAuthority: readonly CredentialAuthorityEntry[];
}

/** An attenuation root's claims (`aat+jwt`); its authority is the chain's `tools`. */
export interface VerifiedAttenuationRootClaims extends VerifiedCredentialClaims {
  mission: { id: string; issuer: string; authority_hash: string };
}

const nonEmptyString = (v: unknown): v is string => typeof v === "string" && v.length > 0;
const numericDate = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);

/** RFC 7515 Section 4.1.9: `typ` is a media type, compared without its `application/` prefix, case-insensitively. */
function typeOf(typ: unknown): string | undefined {
  if (typeof typ !== "string") return undefined;
  const lower = typ.toLowerCase();
  return lower.startsWith("application/") ? lower.slice("application/".length) : lower;
}

function requireType(typ: unknown, expected: string): void {
  if (typeOf(typ) !== expected) throw new TokenProfileError(`token typ must be ${expected}`);
}

function requireCredentialClaims(payload: JWTPayload, nowS: number): VerifiedCredentialClaims {
  if (!numericDate(payload.exp)) throw new TokenProfileError("token exp must be a NumericDate");
  if (!numericDate(payload.iat)) throw new TokenProfileError("token iat must be a NumericDate");
  if (payload.nbf !== undefined && !numericDate(payload.nbf)) throw new TokenProfileError("token nbf must be a NumericDate");
  if (payload.exp <= nowS) throw new TokenProfileError("token is expired");
  if (payload.iat > nowS + ISSUED_AT_SKEW_S) throw new TokenProfileError("token iat is in the future");
  if (!nonEmptyString(payload.jti)) throw new TokenProfileError("token jti must be a non-empty string");
  if (!nonEmptyString(payload.sub)) throw new TokenProfileError("token sub must be a non-empty string");
  if (!nonEmptyString(payload.client_id)) throw new TokenProfileError("token client_id must be a non-empty string");
  const cnf = payload.cnf as { jkt?: unknown } | undefined;
  if (typeof cnf !== "object" || cnf === null || Array.isArray(cnf) || !nonEmptyString(cnf.jkt)) {
    throw new TokenProfileError("token cnf.jkt must be a non-empty string");
  }
  return { sub: payload.sub, clientId: payload.client_id, jti: payload.jti, iat: payload.iat, exp: payload.exp, cnfJkt: cnf.jkt };
}

/**
 * The ordinary Mission access-token profile: `typ` `at+jwt`, the RFC 9068
 * claim set, a `mission` claim with non-empty `id` and `issuer`, and an
 * `authorization_details` the resource reads in full as the credential's own
 * authority. A present but unreadable `mission` claim refuses; it never
 * demotes the credential to another class.
 */
export function readMissionAccessClaims(typ: unknown, payload: JWTPayload, nowS: number): VerifiedMissionAccessClaims {
  requireType(typ, MISSION_ACCESS_TOKEN_TYP);
  const base = requireCredentialClaims(payload, nowS);
  const mission = readTxnMissionClaim(payload.mission);
  if (!mission || !mission.id || !mission.issuer) throw new TokenProfileError("token mission claim is missing or malformed");
  let credentialAuthority: readonly CredentialAuthorityEntry[];
  try {
    credentialAuthority = parseCredentialAuthority(payload.authorization_details);
  } catch (e) {
    throw new TokenProfileError(`token authorization_details: ${(e as Error).message}`);
  }
  return { ...base, mission, credentialAuthority };
}

/**
 * The attenuation-root profile: `typ` `aat+jwt`, the same claim primitives,
 * and a `mission` claim that carries `authority_hash` (the chain's lineage
 * anchor). The root's `tools` are read by the chain verifier, not here.
 */
export function readAttenuationRootClaims(typ: unknown, payload: JWTPayload, nowS: number): VerifiedAttenuationRootClaims {
  requireType(typ, AAT_TYP);
  const base = requireCredentialClaims(payload, nowS);
  const m = payload.mission as { id?: unknown; issuer?: unknown; authority_hash?: unknown } | undefined;
  if (typeof m !== "object" || m === null || !nonEmptyString(m.id) || !nonEmptyString(m.issuer) || !nonEmptyString(m.authority_hash)) {
    throw new TokenProfileError("attenuation root mission claim is missing or malformed");
  }
  return { ...base, mission: { id: m.id, issuer: m.issuer, authority_hash: m.authority_hash } };
}
