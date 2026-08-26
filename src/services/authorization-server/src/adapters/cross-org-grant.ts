/**
 * @spec cross-org-delegation#projection-exchange — the RFC 8693 seam where a
 * destination Resource AS accepts a Chain Presentation and mints an
 * audience-local Mission-bound token. Verification is
 * kernel/cross-org-chain.ts's; this adapter owns the wire shape, the leaf
 * proof of possession, the origin-principal mapping, the local-policy
 * intersection, the mint, and the derivation evidence.
 */
import {
  chainDigest,
  ChainPresentationError,
  type EntitlementResolver,
  type LocalMappingPolicy,
  parseChainPresentation,
  resolveLocalPrincipal,
} from "@mission/core";
import type { AuthorityEntry } from "../kernel/types.js";
import {
  calculateJwkThumbprint,
  decodeProtectedHeader,
  jwtVerify,
  SignJWT,
  type CryptoKey,
  type JWK,
} from "jose";
import { randomBytes } from "node:crypto";
import { mapToolsToAuthority } from "../kernel/attenuation.js";
import { isSubsetSet } from "../kernel/derive.js";
import {
  verifyCrossOrgChain,
  ChainVerificationError,
  type FederationConfig,
} from "../kernel/cross-org-chain.js";
import type { KoaContextWithOIDC } from "oidc-provider";

/**
 * @spec runtime#state-freshness — the same small future-skew tolerance the
 * PDP's own dual-axis check applies: absorbs ordinary clock drift without
 * meaningfully widening the entitlement freshness bound.
 */
const FRESHNESS_SKEW_TOLERANCE_MS = 5_000;

/**
 * A recorded origin-to-local principal mapping row (config-registered).
 * @spec cross-domain#origin-principal-mapping (#539) — re-export of the
 * shared reference resolver's entry shape (mission-core's
 * `LocalPrincipalMapping`), so a caller of this adapter's public API keeps
 * its existing import name.
 */
export type { LocalPrincipalMapping as PrincipalMappingEntry } from "@mission/core";

export interface CrossOrgOptions {
  federation: FederationConfig;
  stateSource: (missionId: string, issuer: string) => { state: string; observedAtS: number } | undefined;
  mappingPolicy: LocalMappingPolicy;
  /** The destination's local authority ceiling; output never exceeds it. */
  localCeiling: readonly AuthorityEntry[];
  /** Retained derivation records (@spec cross-org-delegation#projection). */
  evidence: CrossOrgDerivationRecord[];
  /** Local access-token lifetime ceiling (seconds). */
  accessTokenTTL: number;
  /**
   * @spec cross-domain#dual-axis (#539) — current entitlement of the mapped
   * local principal, the profile's second axis alongside the static
   * `localCeiling` below. The whole endpoint IS the cross-domain Origin
   * Principal profile (there is no unclaimed-profile case to fall back to),
   * so this is a REQUIRED construction-time dependency rather than an
   * optional, fail-closed-on-absence one: a deployment cannot forget to
   * wire it and still exchange chains. Audience-wide, all-or-none: a
   * positive result authorizes the complete set below (the verified
   * delegated authority intersected with localCeiling), unmodified; it does
   * not narrow individual entries by action or resource (see
   * `EntitlementResolver`'s own doc).
   */
  entitlement: EntitlementResolver;
  /** Independent freshness bound for the entitlement observation, seconds. */
  entitlementStalenessBoundSeconds: number;
}

export interface CrossOrgDerivationRecord {
  chain_digest: string;
  leaf_jti: string;
  input_authority: AuthorityEntry[];
  output_authority: AuthorityEntry[];
  lineage: Array<{ named: boolean; iss?: string; sub?: string }>;
  policy: { id: string; version: string };
  principal_mapping: {
    origin: { iss: string; sub: string };
    local: string;
    policy: { id: string; version: string };
    observed_at: string;
    valid_until: string;
  };
}

interface HandlerOpts {
  issuer: string;
  crossOrg?: CrossOrgOptions;
  tokenKey: CryptoKey;
  tokenKid: string;
  proofJtiFresh: (jti: unknown) => boolean;
  now: () => Date;
}

function fail(ctx: KoaContextWithOIDC, code: string, description: string): void {
  ctx.status = 400;
  ctx.body = { error: code, error_description: description };
  ctx.set("cache-control", "no-store");
}

/**
 * @spec cross-org-delegation#projection-exchange — parameters, leaf PoP,
 * error mapping (invalid_request for structure/bounds; invalid_grant for any
 * verification failure with no partial detail; invalid_target for an audience
 * outside the leaf), and the local mint with a restarted `act`.
 */
export async function handleCrossOrgChainExchange(
  opts: HandlerOpts,
  ctx: KoaContextWithOIDC,
): Promise<void> {
  const crossOrg = opts.crossOrg;
  if (!crossOrg) {
    fail(ctx, "invalid_request", "unsupported subject_token_type");
    return;
  }
  const params = ctx.oidc.params as Record<string, unknown>;
  const subjectToken = params.subject_token;
  if (typeof subjectToken !== "string" || !subjectToken) {
    fail(ctx, "invalid_request", "subject_token is required");
    return;
  }
  const requestedAud =
    typeof params.audience === "string" && params.audience
      ? params.audience
      : typeof params.resource === "string"
        ? params.resource
        : undefined;
  if (!requestedAud) {
    fail(ctx, "invalid_target", "audience or resource is required");
    return;
  }

  // Structure and bounds BEFORE any signature verification.
  let presentation;
  try {
    presentation = parseChainPresentation(subjectToken, crossOrg.federation.bounds);
  } catch (e) {
    if (e instanceof ChainPresentationError) {
      fail(ctx, "invalid_request", (e as Error).message);
      return;
    }
    throw e;
  }

  // Leaf proof of possession: the request's DPoP key must be the leaf cnf.jwk.
  const proofJws = ctx.get("dpop");
  if (!proofJws) {
    fail(ctx, "invalid_request", "DPoP proof of the leaf key is required");
    return;
  }
  let dpopJkt: string;
  try {
    const header = decodeProtectedHeader(proofJws);
    const dpopJwk = header.jwk as JWK;
    dpopJkt = await calculateJwkThumbprint(dpopJwk);
    const { payload: proof } = await jwtVerify(proofJws, dpopJwk, { typ: "dpop+jwt" });
    if (proof.htu !== `${opts.issuer}/token` || proof.htm !== "POST") {
      throw new Error("DPoP htu/htm mismatch");
    }
    if (!opts.proofJtiFresh(proof.jti)) throw new Error("DPoP proof jti missing or replayed");
  } catch {
    fail(ctx, "invalid_dpop_proof", "invalid DPoP proof");
    return;
  }

  const nowS = Math.floor(opts.now().getTime() / 1000);
  let verified;
  try {
    verified = await verifyCrossOrgChain({
      federation: crossOrg.federation,
      presentation,
      nowS,
      stateSource: crossOrg.stateSource,
    });
  } catch (e) {
    if (e instanceof ChainVerificationError) {
      // @spec cross-org-delegation#projection-exchange — no partial
      // verification detail crosses the boundary.
      fail(ctx, "invalid_grant", "chain verification failed");
      return;
    }
    throw e;
  }

  if (dpopJkt !== (await calculateJwkThumbprint(verified.leaf.cnfJwk))) {
    fail(ctx, "invalid_grant", "chain verification failed");
    return;
  }
  if (!verified.leaf.aud.includes(requestedAud)) {
    fail(ctx, "invalid_target", "requested audience is outside the leaf audience");
    return;
  }

  // Origin-principal mapping (@spec cross-domain#origin-principal-mapping):
  // authenticated issuer-qualified input, registered policy, refusal on a
  // missing, ambiguous, disabled, future-dated, or expired mapping; the
  // local account is a local fact, never agent-selected. `resolveLocalPrincipal`
  // (mission-core, #539) replaces the previous first-match `.find()`, which
  // could not reject a duplicate/ambiguous entry.
  const nowDate = opts.now();
  const mapping = resolveLocalPrincipal(crossOrg.mappingPolicy, verified.subject, requestedAud, nowDate);
  if (!mapping) {
    fail(ctx, "invalid_grant", "chain verification failed");
    return;
  }

  // @spec cross-domain#dual-axis (#539): current entitlement of the mapped
  // local principal — independent of the static `localCeiling` intersection
  // below and of the mapping's own validity bound. A missing resolver
  // result, `entitled !== true`, a future-dated or stale-beyond-bound
  // observation, or a throwing resolver are all a failed result here, never
  // a distinct outcome or an unclassified transport exception.
  let entitlementObservedMs: number;
  try {
    const entitlement = await crossOrg.entitlement.resolve({
      local: { iss: opts.issuer, sub: mapping.local_sub },
      audience: requestedAud,
    });
    const observedMs = entitlement ? Date.parse(entitlement.observed_at) : NaN;
    const ageMs = nowDate.getTime() - observedMs;
    const current =
      entitlement?.entitled === true &&
      Number.isFinite(observedMs) &&
      ageMs >= -FRESHNESS_SKEW_TOLERANCE_MS &&
      ageMs <= crossOrg.entitlementStalenessBoundSeconds * 1000;
    if (!current) {
      fail(ctx, "invalid_grant", "chain verification failed");
      return;
    }
    entitlementObservedMs = observedMs;
  } catch {
    fail(ctx, "invalid_grant", "chain verification failed");
    return;
  }

  // Dual-axis: the verified delegated authority intersected with the local
  // ceiling; entries the destination does not permit are narrowed out.
  const inputAuthority = mapToolsToAuthority(verified.leaf.tools);
  const outputAuthority = inputAuthority.filter((e) =>
    isSubsetSet([e], crossOrg.localCeiling as AuthorityEntry[]),
  );
  if (outputAuthority.length === 0) {
    fail(ctx, "invalid_grant", "chain verification failed");
    return;
  }

  const clientId = ctx.oidc.client?.clientId ?? "";
  const leafExp = Number(verified.leaf.payload.exp);
  // exp never outlives the leaf's own lease, the mapping's own validity
  // bound, or the entitlement observation's freshness horizon (#539).
  const mappingValidMs = Date.parse(mapping.valid_until);
  const entitlementHorizonS = Math.floor(entitlementObservedMs / 1000) + crossOrg.entitlementStalenessBoundSeconds;
  const exp = Math.min(nowS + crossOrg.accessTokenTTL, leafExp, Math.floor(mappingValidMs / 1000), entitlementHorizonS);
  // @spec cross-domain#dual-axis (#539): refuse rather than mint an
  // already-expired token when the tightest bound (mapping validity or
  // entitlement freshness horizon) has already elapsed. Mirrors the RAS's
  // exp-before-consumption fix (ras/src/index.ts); here the presenter's
  // one-time DPoP proof jti was already consumed earlier (line ~169,
  // `opts.proofJtiFresh`), a structural difference from the RAS's grant jti
  // this endpoint does not resolve: DPoP proof-of-possession validation
  // runs, by design, before the chain/mapping/entitlement checks that
  // determine exp, and reordering it was judged out of scope here. A
  // presenter that hits this refusal simply mints a fresh DPoP proof and
  // retries; no token is issued either way.
  if (exp <= nowS) {
    fail(ctx, "invalid_grant", "chain verification failed");
    return;
  }
  const jti = `xorg_${randomBytes(9).toString("base64url")}`;
  // The audience-local token: local iss/sub, restarted local act, invariant
  // mission claim including subject, bound to the presenting (leaf) key.
  const accessToken = await new SignJWT({
    sub: mapping.local_sub,
    client_id: clientId,
    act: { iss: opts.issuer, sub: clientId },
    cnf: { jkt: dpopJkt },
    mission: {
      id: verified.missionId,
      issuer: verified.missionIssuer,
      authority_hash: verified.authorityHash,
      subject: { iss: verified.subject.iss, sub: verified.subject.sub },
    },
    authorization_details: outputAuthority,
  })
    .setProtectedHeader({ alg: "RS256", kid: opts.tokenKid, typ: "at+jwt" })
    .setIssuer(opts.issuer)
    .setAudience(requestedAud)
    .setIssuedAt(nowS)
    .setExpirationTime(exp)
    .setJti(jti)
    .sign(opts.tokenKey);

  crossOrg.evidence.push({
    chain_digest: chainDigest(presentation.chain),
    leaf_jti: verified.lineage[verified.lineage.length - 1]?.jti ?? "",
    input_authority: inputAuthority,
    output_authority: outputAuthority,
    lineage: verified.lineage.map((h) => ({
      named: !!h.actor,
      ...(h.actor ? { iss: h.actor.iss, sub: h.actor.sub } : {}),
    })),
    policy: { id: crossOrg.mappingPolicy.id, version: crossOrg.mappingPolicy.version },
    principal_mapping: {
      origin: verified.subject,
      local: mapping.local_sub,
      policy: mapping.policy,
      // @spec cross-domain#origin-principal-mapping (#539) — genuine
      // mapping-source facts (the registered entry's own observed_at/
      // valid_until), never the adapter's own clock or the minted token's
      // expiry.
      observed_at: mapping.observed_at,
      valid_until: mapping.valid_until,
    },
  });

  ctx.status = 200;
  ctx.body = {
    access_token: accessToken,
    issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
    token_type: "DPoP",
    expires_in: exp - nowS,
    authorization_details: outputAuthority,
  };
  ctx.set("cache-control", "no-store");
}
