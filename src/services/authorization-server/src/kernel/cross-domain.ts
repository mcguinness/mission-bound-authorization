/**
 * @spec draft-mcguinness-oauth-mission-cross-domain (ID-JAG profile)
 *
 * Issue a Mission-bound cross-domain grant (ID-JAG): a JWT authorization
 * grant, signed by the Mission issuer, audienced to the target Resource AS,
 * <=300s, exp not exceeding the Mission's expires_at, sender-constrained by
 * cnf, one-time via jti, carrying the mission claim (id/issuer/authority_hash
 * unchanged) and the audience-scoped authorization_details. Gated as a
 * derivation (D26 lifecycle). Backs M9.
 */

import { randomBytes } from "node:crypto";
import type { ActObject } from "@mission/actor-chain";
import { SignJWT, type CryptoKey, type JWTPayload } from "jose";
import type { MissionKernel } from "./kernel.js";
import type { AuthorityEntry, MissionRecord } from "./types.js";

export const ID_JAG_TYP = "oauth-id-jag+jwt";
export const ID_JAG_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id-jag";
export const MAX_GRANT_LIFETIME_S = 300;

/**
 * @spec cross-domain#audience-scope: project only the authority-set entries
 * whose resource the target Resource AS is authoritative for.
 */
export function audienceScopedAuthority(
  authoritySet: AuthorityEntry[],
  resourceToAs: (resource: string) => string,
  targetAs: string,
): AuthorityEntry[] {
  return authoritySet.filter((e) => resourceToAs(e.resource) === targetAs);
}

export interface IssueGrantInput {
  missionId: string;
  targetAs: string;
  /**
   * @spec cross-domain / ID-JAG §3.1: the client at the requesting AS that acts
   * for the subject. Emitted as the grant's `client_id` claim.
   */
  clientId: string;
  /** Presenting client's DPoP key thumbprint (sender-constraint, cnf.jkt). */
  cnfJkt: string;
  resourceToAs: (resource: string) => string;
  /**
   * @spec id-continuation-assertion: optional, opt-in continuation extensions.
   * When every field below is omitted the emitted ID-JAG is byte-identical to
   * the legacy grant (this is the same code path, not a sibling emitter).
   */
  /**
   * Audience-local subject. When present it REPLACES `record.subject.sub` as
   * the ID-JAG's `sub`. The deterministic resolver that computes it lives in
   * the caller (a later PR); here the value is consumed verbatim.
   */
  sub?: string;
  /**
   * Fresh new-hop continuation handle, minted by the caller. Emitted as the
   * top-level `identity_continuation_handle` claim; never generated here.
   */
  identityContinuationHandle?: string;
  /**
   * Pre-built, already-collapsed `act` lineage (the caller builds/collapses it
   * with `extendChainCollapsing`). Emitted verbatim as the `act` claim.
   */
  act?: ActObject;
  /**
   * Root auth envelope, carried not refreshed. Present sub-fields are emitted
   * as top-level `auth_time`/`acr`/`amr`; absent sub-fields are omitted.
   */
  authEnvelope?: { auth_time?: number; acr?: string; amr?: string[] };
}

/**
 * Issue the ID-JAG. Gated on Mission state as a derivation; refuses when the
 * Mission is not active (this is how the issuer's lifecycle gate reaches
 * across the boundary -- after revocation the next grant request is refused).
 */
export async function issueCrossDomainGrant(
  kernel: MissionKernel,
  signKey: CryptoKey,
  kid: string,
  input: IssueGrantInput,
): Promise<{ grant: string; jti: string; audienceScoped: AuthorityEntry[] }> {
  // Derivation gate: throws GateError when non-active/expired/cap-exhausted.
  const record: MissionRecord = kernel.gateDerivation(input.missionId);

  // Containment: the audience-scoped projection draws on the EFFECTIVE set, so
  // a contained capability never crosses the domain boundary.
  const scoped = audienceScopedAuthority(
    kernel.effectiveAuthoritySet(record),
    input.resourceToAs,
    input.targetAs,
  );
  if (scoped.length === 0) throw new Error("no audience-scoped authority for the target Resource AS");

  const nowS = Math.floor(kernel.nowDate().getTime() / 1000);
  const missionExp = Math.floor(Date.parse(record.expires_at) / 1000);
  const exp = Math.min(nowS + MAX_GRANT_LIFETIME_S, missionExp);
  const jti = `jag_${randomBytes(12).toString("base64url")}`;

  // The five legacy claims, in their legacy insertion order. `sub` defaults to
  // the GLOBAL subject; an audience-local `sub` (when passed) replaces it. Any
  // continuation claims below are appended AFTER these, so a legacy call (all
  // continuation fields omitted) serializes byte-identically to before.
  const payload: JWTPayload = {
    mission: {
      id: record.id,
      issuer: record.issuer,
      authority_hash: record.authority_hash,
    },
    authorization_details: scoped,
    cnf: { jkt: input.cnfJkt },
    sub: input.sub !== undefined ? input.sub : record.subject.sub,
    // @spec ID-JAG §3.1: the acting client at the requesting AS.
    client_id: input.clientId,
  };
  // @spec id-continuation-assertion: opt-in continuation claims.
  if (input.identityContinuationHandle !== undefined) {
    payload.identity_continuation_handle = input.identityContinuationHandle;
  }
  if (input.act !== undefined) {
    payload.act = input.act;
  }
  if (input.authEnvelope !== undefined) {
    // Root envelope carried unchanged; omit any absent sub-field.
    if (input.authEnvelope.auth_time !== undefined) payload.auth_time = input.authEnvelope.auth_time;
    if (input.authEnvelope.acr !== undefined) payload.acr = input.authEnvelope.acr;
    if (input.authEnvelope.amr !== undefined) payload.amr = input.authEnvelope.amr;
  }

  const grant = await new SignJWT(payload)
    .setProtectedHeader({ alg: "ES256", kid, typ: ID_JAG_TYP })
    .setIssuer(record.issuer)
    .setAudience(input.targetAs)
    .setIssuedAt(nowS)
    .setExpirationTime(exp)
    .setJti(jti)
    .sign(signKey);

  return { grant, jti, audienceScoped: scoped };
}
