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
  type Confirmation,
  CredentialProfileError,
  credentialEntriesFromAuthority,
  mediaTypeOf,
  readCredentialProfileClaims,
  readMissionAccessProfile,
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

/** The Mission access-token profile's type and `iat` skew, shared with AS introspection. */
export { ISSUED_AT_SKEW_S, MISSION_ACCESS_TOKEN_TYP } from "@mission/core";

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

function requireType(typ: unknown, expected: string): void {
  if (mediaTypeOf(typ) !== expected) throw new TokenProfileError(`token typ must be ${expected}`);
}

/** Read through the profile reader shared with AS introspection, refusing as this resource's {@link TokenProfileError}. */
function asTokenProfile<T>(read: () => T): T {
  try {
    return read();
  } catch (e) {
    if (e instanceof CredentialProfileError) throw new TokenProfileError(e.message);
    throw e;
  }
}

/**
 * @spec runtime-oauth#token-validation (#825, D402): the binding's structure is
 * read as introspection reads it; this resource proves possession by DPoP
 * only, so its profile requires `cnf.jkt`.
 */
function requireDpopKey(confirmation: Confirmation | undefined): string {
  if (confirmation?.jkt === undefined) throw new TokenProfileError("token cnf.jkt must be a non-empty string");
  return confirmation.jkt;
}

function requireCredentialClaims(payload: JWTPayload, nowS: number): VerifiedCredentialClaims {
  const { confirmation, ...claims } = asTokenProfile(() => readCredentialProfileClaims(payload, nowS));
  return { ...claims, cnfJkt: requireDpopKey(confirmation) };
}

/**
 * The ordinary Mission access-token profile: `typ` `at+jwt`, the RFC 9068
 * claim set, a `mission` claim with non-empty `id` and `issuer`, and an
 * `authorization_details` the resource reads in full as the credential's own
 * authority. A present but unreadable `mission` claim refuses; it never
 * demotes the credential to another class.
 */
export function readMissionAccessClaims(typ: unknown, payload: JWTPayload, nowS: number): VerifiedMissionAccessClaims {
  const { confirmation, ...claims } = asTokenProfile(() => readMissionAccessProfile(typ, payload, nowS));
  return { ...claims, cnfJkt: requireDpopKey(confirmation) };
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
