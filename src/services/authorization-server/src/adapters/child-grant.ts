/**
 * @spec draft-mcguinness-oauth-mission-child-delegation (#child-client-identity)
 *
 * Mint the child-bound RFC 7523 JWT authorization grant a Child Mission's actor
 * redeems AS ITSELF at the token endpoint. Mirrors the ID-JAG assertion shape
 * (kernel/cross-domain.ts): a signed JWT, audienced to the AS token endpoint,
 * naming the child actor as the authorized redeemer (`client_id`) and the
 * Mission subject as `sub`, carrying the child `mission` claim WITH the `parent`
 * lineage member (via childMissionClaim) and the child authorization_details.
 * The child's own `authority_hash` (over the CHILD set) is the authority
 * commitment; the `parent` member is lineage and audit data only.
 *
 * This is the "grant reference" the parent conveys, never a child token: it is
 * redeemable only by the child actor it names, so conveying it through the
 * parent gives the parent no ability to redeem it (@spec #child-client-identity).
 * The redemption of this assertion into a DPoP-bound child access token (the
 * child authenticating AS ITSELF at /token) shipped in PR4b
 * (handleChildJwtBearerGrant); creation was relocated onto /token in PR4c.
 */

import { randomBytes } from "node:crypto";
import { type CryptoKey, SignJWT } from "jose";
import { childMissionClaim } from "../kernel/child-delegation.js";
import type { MissionKernel } from "../kernel/kernel.js";
import type { MissionRecord } from "../kernel/types.js";

/** @spec #child-client-identity — the child-bound authorization-grant assertion typ. */
export const CHILD_GRANT_TYP = "oauth-mission-child-grant+jwt";

/**
 * @spec RFC 7523 / #child-client-identity — the JWT-bearer authorization grant
 * type the child presents the assertion under when it redeems AS ITSELF (PR4b).
 */
export const CHILD_JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/** Grant assertions are short-lived and never exceed the child Mission expiry. */
export const MAX_CHILD_GRANT_LIFETIME_S = 300;

export interface MintChildGrantInput {
  child: MissionRecord;
  /** The AS token-endpoint audience the child presents the assertion at. */
  tokenEndpoint: string;
}

/** The AS signing material for the child-bound grant (its token key + kid + alg). */
export interface ChildGrantSigner {
  key: CryptoKey;
  kid: string;
  alg: string;
}

/**
 * Mint the child-bound JWT authorization grant. NOT gated as a derivation: the
 * grant reference is not a token (no derivation_count increment); the derivation
 * gate runs when the child redeems it (PR4b). `exp` is clamped to the child
 * Mission's `expires_at`, which createChildMission already clamped no later than
 * the parent's, so the assertion transitively caps the child token's lifetime.
 */
export async function mintChildGrant(
  kernel: MissionKernel,
  signer: ChildGrantSigner,
  input: MintChildGrantInput,
): Promise<{ assertion: string; jti: string }> {
  const { child } = input;
  const nowS = Math.floor(kernel.nowDate().getTime() / 1000);
  const childExp = Math.floor(Date.parse(child.expires_at) / 1000);
  const exp = Math.min(nowS + MAX_CHILD_GRANT_LIFETIME_S, childExp);
  const jti = `chg_${randomBytes(12).toString("base64url")}`;

  const assertion = await new SignJWT({
    // @spec #parent-member — the child `mission` claim carries the parent lineage.
    // @spec #child-client-identity / #attenuation — authority_hash commits the CHILD set.
    mission: childMissionClaim(kernel, child),
    // Containment: the assertion carries the child's EFFECTIVE set (a fresh
    // child has no containment, so this is its approved set as-is).
    authorization_details: kernel.effectiveAuthoritySet(child),
    // @spec #child-client-identity — the child actor is the only authorized redeemer.
    client_id: child.client_id,
  })
    .setProtectedHeader({ alg: signer.alg, kid: signer.kid, typ: CHILD_GRANT_TYP })
    .setIssuer(child.issuer)
    // @spec #child-client-identity — aud is the AS token endpoint the child presents at.
    .setAudience(input.tokenEndpoint)
    // sub = the Mission subject, inherited from the parent (worked example: the
    // human subject), distinct from client_id (the child actor).
    .setSubject(child.subject.sub)
    .setIssuedAt(nowS)
    .setExpirationTime(exp)
    .setJti(jti)
    .sign(signer.key);

  return { assertion, jti };
}
