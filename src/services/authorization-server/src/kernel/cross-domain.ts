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
import { SignJWT, type CryptoKey } from "jose";
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
  /** Presenting client's DPoP key thumbprint (sender-constraint, cnf.jkt). */
  cnfJkt: string;
  resourceToAs: (resource: string) => string;
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

  const scoped = audienceScopedAuthority(record.authority_set, input.resourceToAs, input.targetAs);
  if (scoped.length === 0) throw new Error("no audience-scoped authority for the target Resource AS");

  const nowS = Math.floor(kernel.nowDate().getTime() / 1000);
  const missionExp = Math.floor(Date.parse(record.expires_at) / 1000);
  const exp = Math.min(nowS + MAX_GRANT_LIFETIME_S, missionExp);
  const jti = `jag_${randomBytes(12).toString("base64url")}`;

  const grant = await new SignJWT({
    mission: {
      id: record.id,
      issuer: record.issuer,
      authority_hash: record.authority_hash,
    },
    authorization_details: scoped,
    cnf: { jkt: input.cnfJkt },
    sub: record.subject.sub,
  })
    .setProtectedHeader({ alg: "ES256", kid, typ: ID_JAG_TYP })
    .setIssuer(record.issuer)
    .setAudience(input.targetAs)
    .setIssuedAt(nowS)
    .setExpirationTime(exp)
    .setJti(jti)
    .sign(signKey);

  return { grant, jti, audienceScoped: scoped };
}
