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

import { createHash } from "node:crypto";
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
 * transaction token.
 *
 * The shape is the CORE's, not a second one: `id`, `issuer` and
 * `authority_hash` are the REQUIRED invariants; `expires_at` is OPTIONAL and an
 * RFC 3339 date-time STRING (the same form the Mission Record and every other
 * family surface render it in, never epoch seconds); `approval_basis` is
 * OPTIONAL. `subject` is the issuer-qualified origin principal, present only
 * where the Origin Principal profile applies.
 *
 * A parser that REQUIRED the optional members would reject conforming claims --
 * the cross-org grant mints one carrying only the invariants and `subject` --
 * and, because this parser fails closed, would turn them into unequal
 * invariants and refusals with no visible cause.
 */
export interface TxnMissionClaim {
  id: string;
  issuer: string;
  authority_hash: string;
  /** RFC 3339 date-time. OPTIONAL. */
  expires_at?: string;
  approval_basis?: { type: string };
  subject?: { iss: string; sub: string };
}

/**
 * @spec txn-authorization#challenge-redemption step 5 — the COMPLETE
 * transaction an approval is opened against, and the only thing it is ever
 * good for.
 *
 * `parameter_digest` alone identifies the operation's PARAMETERS, not the
 * transaction: the same digest can be reached under a different Mission, a
 * different client, a different presenter key or a different principal. An
 * approval carrying only the digest would therefore satisfy a transaction it
 * was never granted for. This structure is the whole binding, and its digest
 * travels with the approval so the Transaction Authorization Server can
 * recompute it from its OWN pinned state at completion and refuse anything the
 * approval was not opened under.
 *
 * `subject` is the destination-local principal (the `subject_token`'s `sub`);
 * `origin_principal` is the issuer-qualified origin identity where the Origin
 * Principal profile applies. Both travel: the approver and the policy see the
 * identity that acts locally AND the identity it originates from, and neither
 * is ever substituted for the other.
 */
export interface TxnApprovalBinding {
  /** The Challenge-Issuing Resource (the challenge `iss`). */
  resource: string;
  txn: string;
  mission: TxnMissionClaim;
  /** The operation's `authorization_details` `type` (the Operation Profile). */
  operation_type: string;
  authorization_details: JsonValue[];
  parameter_digest: string;
  /** The destination-local subject: the `subject_token`'s own `sub`. */
  subject: string;
  /** The issuer-qualified origin principal, where the profile applies. */
  origin_principal?: { iss: string; sub: string };
  /** The client AUTHENTICATED at the transaction endpoint. */
  client_id: string;
  /** The presenter key the resulting transaction token is bound to. */
  cnf_jkt: string;
}

/**
 * The approval binding's digest: the family's anchor idiom (JCS-canonical,
 * SHA-256, `"sha-256:" + base64url`) over {@link TxnApprovalBinding}. Value
 * equality of the whole transaction reduces to equality of this one string.
 */
export function txnApprovalBindingDigest(binding: TxnApprovalBinding): string {
  const digest = createHash("sha256")
    .update(canonicalize(binding as unknown as JsonValue))
    .digest("base64url");
  return `sha-256:${digest}`;
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
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  const m = value as Record<string, unknown>;
  if (
    typeof m.id !== "string" ||
    typeof m.issuer !== "string" ||
    typeof m.authority_hash !== "string"
  ) {
    return undefined;
  }
  const claim: TxnMissionClaim = {
    id: m.id,
    issuer: m.issuer,
    authority_hash: m.authority_hash,
  };
  // Present-but-wrong-type is a REFUSAL, never a silently ignored member: a
  // claim this parser cannot read in full is not one anything should compare.
  if (m.expires_at !== undefined) {
    if (typeof m.expires_at !== "string" || !Number.isFinite(Date.parse(m.expires_at)))
      return undefined;
    claim.expires_at = m.expires_at;
  }
  if (m.approval_basis !== undefined) {
    const basis = m.approval_basis as { type?: unknown };
    if (typeof basis !== "object" || basis === null || typeof basis.type !== "string")
      return undefined;
    claim.approval_basis = { type: basis.type };
  }
  if (m.subject !== undefined) {
    const subject = m.subject as { iss?: unknown; sub?: unknown };
    if (typeof subject !== "object" || subject === null) return undefined;
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
