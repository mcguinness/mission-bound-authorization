/**
 * @spec authzen#context-approval (#2067, D1313): an action approval binds to
 * the qualified Mission identity, `issuer` and `id`, established through
 * integrity-protected approval material, never through the request's
 * `context.mission`. This module verifies that material: the Access Request
 * Service's signed approval `state` (`arap-approval+jwt`), or the
 * Transaction Authorization Server's transaction token
 * (`mission-txn-token+jwt`) the transaction profile carries its approval in.
 *
 * Every trust anchor (key set, issuer, audience) is the decision point's
 * own, bound where the point is constructed and never taken from a caller.
 * The checks step 8 applies (Mission identity, contract, parameter digest,
 * grant age, validity bound) read the members this material states, never
 * the presented object's own account of them.
 */

import { MISSION_TXN_TOKEN_TYP } from "@mission/core";
import {
  createLocalJWKSet,
  decodeProtectedHeader,
  errors,
  type JWK,
  type JWTPayload,
  type CryptoKey,
  type JWTVerifyGetKey,
  jwtVerify,
} from "jose";

/** ARAP's signed approval `state`, as the Access Request Service mints it. */
export const ARAP_APPROVAL_TYP = "arap-approval+jwt";

/** One issuer of approval material this decision point trusts. */
export interface ApprovalMaterialIssuer {
  /** The material's protected-header `typ`: it selects how the claims are read. */
  typ: typeof ARAP_APPROVAL_TYP | typeof MISSION_TXN_TOKEN_TYP;
  /** The required `iss`. */
  issuer: string;
  /** The required `aud`: the PDP for ARAP state, the resource for a transaction token. */
  audience: string;
  /**
   * The issuer's verification keys: a fixed key set, or a key resolver (a
   * local or remote JWKS, read at every verification) the decision point's
   * own configuration supplies.
   */
  keys: { keys: JWK[] } | JWTVerifyGetKey;
}

/** The decision point's approval-material trust anchors. */
export interface ApprovalVerification {
  issuers: readonly ApprovalMaterialIssuer[];
}

/** An approval as its verified material states it. */
export interface VerifiedApproval {
  id: string;
  mission: { issuer: string; id: string };
  parameter_digest: string;
  approved_at?: string;
  approved_until?: string;
  /** The approved Resource's `properties.resource_contract`; absent where it names none. */
  resource_contract?: unknown;
}

export type ApprovalBindingOutcome =
  | { kind: "verified"; approval: VerifiedApproval }
  /** The material verified, but its own `exp` has passed. */
  | { kind: "expired" }
  /** No material, material no trusted issuer verifies, or material that states no Mission. */
  | { kind: "unverifiable" };

/**
 * @spec txn-authorization#offline-verification: the approval identifier a
 * transaction token carries its approval under, derived from its `jti`.
 */
export function txnApprovalId(jti: string): string {
  return `txn:${jti}`;
}

/** A presented approval, as far as binding verification reads it. */
export interface PresentedApproval {
  id: string;
  state?: string;
}

function readMission(value: unknown): { issuer: string; id: string } | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  const m = value as Record<string, unknown>;
  if (typeof m.issuer !== "string" || m.issuer === "" || typeof m.id !== "string" || m.id === "") return undefined;
  return { issuer: m.issuer, id: m.id };
}

function readArapState(payload: JWTPayload): VerifiedApproval | undefined {
  const mission = readMission(payload.mission);
  if (!mission || typeof payload.id !== "string" || typeof payload.parameter_digest !== "string") return undefined;
  if (payload.approved_at !== undefined && typeof payload.approved_at !== "string") return undefined;
  if (payload.approved_until !== undefined && typeof payload.approved_until !== "string") return undefined;
  const resource = payload.resource as { properties?: { resource_contract?: unknown } } | undefined;
  return {
    id: payload.id,
    mission,
    parameter_digest: payload.parameter_digest,
    ...(payload.approved_at !== undefined ? { approved_at: payload.approved_at } : {}),
    ...(payload.approved_until !== undefined ? { approved_until: payload.approved_until } : {}),
    ...(resource?.properties?.resource_contract !== undefined
      ? { resource_contract: resource.properties.resource_contract }
      : {}),
  };
}

function readTxnToken(payload: JWTPayload): VerifiedApproval | undefined {
  const mission = readMission(payload.mission);
  if (
    !mission ||
    typeof payload.jti !== "string" ||
    typeof payload.parameter_digest !== "string" ||
    typeof payload.iat !== "number" ||
    typeof payload.exp !== "number"
  ) {
    return undefined;
  }
  const details = payload.authorization_details;
  const contract = Array.isArray(details)
    ? (details[0] as { resource_contract?: unknown } | undefined)?.resource_contract
    : undefined;
  return {
    id: txnApprovalId(payload.jti),
    mission,
    parameter_digest: payload.parameter_digest,
    approved_at: new Date(payload.iat * 1000).toISOString(),
    approved_until: new Date(payload.exp * 1000).toISOString(),
    ...(contract !== undefined ? { resource_contract: contract } : {}),
  };
}

type VerifyOptions = NonNullable<Parameters<typeof jwtVerify>[2]>;

/**
 * `jwtVerify` over a key set in which more than one key matches the header
 * (a rotation that keeps one `kid`): each candidate is tried in turn. An
 * expired token is final once a candidate's signature verified it.
 */
async function verifyUnderKeys(material: string, keys: JWTVerifyGetKey, options: VerifyOptions): Promise<JWTPayload> {
  try {
    return (await jwtVerify(material, keys, options)).payload;
  } catch (e) {
    if (!(e instanceof errors.JWKSMultipleMatchingKeys)) throw e;
    let last: unknown = e;
    for await (const key of e as unknown as AsyncIterable<CryptoKey>) {
      try {
        return (await jwtVerify(material, key, options)).payload;
      } catch (inner) {
        if (inner instanceof errors.JWTExpired) throw inner;
        last = inner;
      }
    }
    throw last;
  }
}

/**
 * Verify the presented approval's material against the decision point's
 * trusted issuers and read the approval it states. The material must name
 * the presented approval's `id`. Fails closed: no anchors, no material, a
 * signature, `typ`, `iss` or `aud` no trusted issuer accepts, or material
 * that states no Mission identity is unverifiable.
 */
export async function verifyApprovalBinding(
  presented: PresentedApproval,
  verification: ApprovalVerification | undefined,
  now: Date,
): Promise<ApprovalBindingOutcome> {
  const material = presented.state;
  if (verification === undefined || typeof material !== "string" || material === "") return { kind: "unverifiable" };
  let typ: unknown;
  try {
    typ = decodeProtectedHeader(material).typ;
  } catch {
    return { kind: "unverifiable" };
  }
  for (const anchor of verification.issuers) {
    if (anchor.typ !== typ) continue;
    const keys = typeof anchor.keys === "function" ? anchor.keys : createLocalJWKSet(anchor.keys as never);
    let payload: JWTPayload;
    try {
      payload = await verifyUnderKeys(material, keys, {
        typ: anchor.typ,
        issuer: anchor.issuer,
        audience: anchor.audience,
        currentDate: now,
      });
    } catch (e) {
      // jose checks `exp` after the signature, `typ`, `iss` and `aud`.
      if (e instanceof errors.JWTExpired) return { kind: "expired" };
      continue;
    }
    const approval = anchor.typ === ARAP_APPROVAL_TYP ? readArapState(payload) : readTxnToken(payload);
    if (approval === undefined || approval.id !== presented.id) return { kind: "unverifiable" };
    return { kind: "verified", approval };
  }
  return { kind: "unverifiable" };
}
