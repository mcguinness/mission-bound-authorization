/**
 * @spec txn-authorization#resource-challenge, #challenge-redemption,
 * #transaction-token, #offline-verification — the wire vocabulary the
 * Challenge-Issuing Resource and the Transaction Authorization Server BOTH
 * speak.
 *
 * It lives here because the two sides cannot import each other: the RS must not
 * depend on the AS package (that would drag the whole AS kernel, incl.
 * oidc-provider, into the RS closure and close a workspace dependency loop),
 * and the AS must not depend on the RS. The previous shape duplicated the
 * constants and claim interfaces in both packages with a "keep these in sync"
 * comment; one shared, dependency-free module replaces that. Crypto stays with
 * whichever side owns the key: the resource signs the challenge, the TAS
 * verifies it and signs the transaction token.
 */

import { canonicalize, type JsonValue } from "./canonicalize.js";

/** @spec txn-authorization#resource-challenge — the challenge's protected `typ`. */
export const TXN_CHALLENGE_TYP = "txn-authz-challenge+jwt";

/** @spec txn-authorization#transaction-token — the transaction token's protected `typ`. */
export const MISSION_TXN_TOKEN_TYP = "mission-txn-token+jwt";

/** @spec txn-authorization#resource-challenge — the upstream error the resource returns. */
export const TXN_AUTHORIZATION_REQUIRED = "transaction_authorization_required";

/** @spec txn-authorization#resource-challenge — the client signal that gates the challenge. */
export const ACCEPT_TXN_CHALLENGE_HEADER = "accept-txn-challenge";

/**
 * @spec txn-authorization#resource-challenge — `Accept-Txn-Challenge` is an RFC
 * 8941 Structured Field Boolean, so ONLY `?1` signals that the client accepts a
 * challenge. `?0` is the client saying it does not; an empty, repeated or
 * malformed value is not a Boolean at all. None of those is acceptance, and a
 * resource that treated mere presence as acceptance would hand challenges to
 * clients that declined them.
 */
export function acceptsTxnChallenge(value: string | string[] | undefined): boolean {
  return typeof value === "string" && value.trim() === "?1";
}

/** @spec txn-authorization#challenge-redemption — the RFC 8693 subject token type. */
export const SUBJECT_TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";

/**
 * @spec txn-authorization#failure-semantics — the upstream pending/polling
 * vocabulary, applied unchanged. This profile defines no second vocabulary for
 * that surface.
 */
export const TXN_POLL_ERRORS = [
  "authorization_pending",
  "slow_down",
  "access_denied",
  "expired_token",
] as const;
export type TxnPollError = (typeof TXN_POLL_ERRORS)[number];

/**
 * @spec mission#the-mission-claim — the `mission` members this profile compares
 * for value equality across the challenge, the `subject_token`, and the
 * transaction token. `subject` is the invariant origin principal, present only
 * where the Origin Principal profile applies.
 */
export interface TxnMissionClaim {
  id: string;
  issuer: string;
  authority_hash: string;
  expires_at: number;
  approval_basis: { type: string };
  subject?: { iss: string; sub: string };
}

/** @spec txn-authorization#resource-challenge — the challenge's claim set. */
export interface TxnChallengeClaims {
  /** The Challenge-Issuing Resource. */
  iss: string;
  /** The Transaction Authorization Server. */
  aud: string;
  iat: number;
  /** @spec txn-authorization#two-phase-expiry — bounds ADMISSION only. */
  exp: number;
  jti: string;
  txn: string;
  /** Exactly one operation-scoped entry. */
  authorization_details: JsonValue[];
  reason: string;
  /** Copied unchanged from the verified Mission-bound access token. */
  mission: TxnMissionClaim;
  /** The runtime profile's digest; this profile defines no second canonicalization. */
  parameter_digest: string;
  /** The presenter key the resulting transaction token is bound to. */
  cnf: { jkt: string };
  act?: JsonValue;
  reason_uri?: string;
}

/** @spec txn-authorization#transaction-token — the transaction token's claim set. */
export interface MissionTxnTokenClaims {
  iss: string;
  iat: number;
  exp: number;
  jti: string;
  /** A singleton, exactly the verified challenge's `iss`. Never a list. */
  aud: string;
  /** The verified effective subject. Never the Approver. */
  sub: string;
  /** The client authenticated at the transaction endpoint. */
  client_id: string;
  txn: string;
  authorization_details: JsonValue[];
  parameter_digest: string;
  mission: TxnMissionClaim;
  cnf: { jkt: string };
  /** Present only where requester/actor context existed upstream. */
  act?: JsonValue;
}

/**
 * @spec txn-authorization#transaction-token — claims the transaction token MUST
 * NOT carry. A generic approval object or `single_use` boolean would make the
 * token a bearer approval; raw parameters and rendered text belong to the
 * resource's own retained operation; roles, relationships and evidence objects
 * belong to the governance and evidence profiles; a refresh token, delegation
 * grant, or token-exchange input would make it a general credential.
 */
export const TXN_TOKEN_PROHIBITED_CLAIMS: readonly string[] = [
  "approval",
  "single_use",
  "parameters",
  "rendered_text",
  "roles",
  "relationships",
  "evidence",
  "refresh_token",
  "delegation_grant",
  "subject_token",
  "actor_token",
];

/** The prohibited claims actually present on a payload (empty when conforming). */
export function prohibitedTxnTokenClaims(payload: Record<string, unknown>): string[] {
  return TXN_TOKEN_PROHIBITED_CLAIMS.filter((c) => payload[c] !== undefined);
}

/**
 * Read the profiled `mission` members off an untyped claim value. Returns
 * undefined when a REQUIRED member is missing or mistyped, so every caller
 * fails closed rather than comparing partial claims.
 */
export function readTxnMissionClaim(value: unknown): TxnMissionClaim | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  const m = value as Record<string, unknown>;
  const basis = m.approval_basis as { type?: unknown } | undefined;
  if (
    typeof m.id !== "string" ||
    typeof m.issuer !== "string" ||
    typeof m.authority_hash !== "string" ||
    typeof m.expires_at !== "number" ||
    typeof basis?.type !== "string"
  ) {
    return undefined;
  }
  const subject = m.subject as { iss?: unknown; sub?: unknown } | undefined;
  const claim: TxnMissionClaim = {
    id: m.id,
    issuer: m.issuer,
    authority_hash: m.authority_hash,
    expires_at: m.expires_at,
    approval_basis: { type: basis.type },
  };
  if (subject !== undefined) {
    if (typeof subject.iss !== "string" || typeof subject.sub !== "string") return undefined;
    claim.subject = { iss: subject.iss, sub: subject.sub };
  }
  return claim;
}

/**
 * @spec txn-authorization#challenge-redemption step 2, #transaction-token —
 * exact value equality of the profiled `mission` members. The transaction token
 * is a freshly signed JWT, so this is value equality, never byte preservation.
 * A claim missing a REQUIRED member is never equal to anything.
 */
export function missionInvariantsEqual(a: unknown, b: unknown): boolean {
  const left = readTxnMissionClaim(a);
  const right = readTxnMissionClaim(b);
  if (!left || !right) return false;
  return canonicalize(left as unknown as JsonValue) === canonicalize(right as unknown as JsonValue);
}

/** Exact value equality of two `authorization_details` arrays (JCS-canonical). */
export function authorizationDetailsEqual(a: unknown, b: unknown): boolean {
  if (!Array.isArray(a) || !Array.isArray(b)) return false;
  try {
    return canonicalize(a as JsonValue) === canonicalize(b as JsonValue);
  } catch {
    return false;
  }
}
