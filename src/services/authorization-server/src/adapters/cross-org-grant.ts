/**
 * @spec cross-org-delegation#projection-exchange — the RFC 8693 seam where a
 * destination Resource AS accepts a Chain Presentation and mints an
 * audience-local Mission-bound token. Verification is
 * kernel/cross-org-chain.ts's; this adapter owns the wire shape, the leaf
 * proof of possession, the origin-principal mapping, the local-policy
 * intersection, the mint, and the derivation evidence.
 */
import { refuseTokenEndpointProof, type TokenEndpointProofFailure } from "./dpop-replay.js";
import {
  aatChainAudienceProblem,
  type AttenuationOperations,
  canonicalize,
  chainDigest,
  ChainPresentationError,
  type JsonValue,
  type MissionConstraints,
  missionToolEntry,
  type ResourceContractDeclarations,
  type EntitlementAuthorityEntry,
  type EntitlementResolver,
  type LocalMappingPolicy,
  narrowToEntitledAuthority,
  narrowToCeiling,
  OIDC_SCOPE_VALUES,
  parseChainPresentation,
  projectScope,
  resolveLocalPrincipal,
  type ScopeProjectionMapping,
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
import { mapAuthorityToCeiling } from "../kernel/attenuation.js";
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
  /**
   * @spec cross-org-delegation#projection (#1759): what this destination's
   * resource servers declare about the operations a tool identifier names,
   * as the attenuation root mapping reads it. A leaf tool projects to a local
   * entry only where this declaration maps that entry to exactly the tool's
   * argument constraints ({@link projectLeafTool}); a destination that
   * declares nothing projects nothing.
   */
  operations: AttenuationOperations;
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
   * wire it and still exchange chains. An audience-scoped observation
   * authorizes the complete set below (the verified delegated authority
   * intersected with localCeiling), unmodified. An observation carrying
   * `authority` (#744) narrows that set per action to the entitled
   * `(resource, action)` pairs, and the minted token and the recorded
   * `output_authority` both carry only the surviving subset (see
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
  /**
   * @spec cross-org-delegation#projection (#1759, D941): this authorization
   * server's configured resource-contract declarations, the ones its kernel
   * reads. A leaf tool's `resource_contract` projects only where they
   * resolve it ({@link projectLeafTool}).
   */
  resourceContracts: ResourceContractDeclarations;
  tokenKey: CryptoKey;
  tokenKid: string;
  /** @spec RFC 9449 Section 4.3 (#1173): the shared token-endpoint proof verifier (iat window, jti replay). */
  verifyDpop: (
    proofJws: string,
  ) => Promise<{ ok: true; proof: { jkt: string } } | ({ ok: false } & TokenEndpointProofFailure)>;
  now: () => Date;
  /** @spec mission#scope-projection — the AS's mapping; absent, every audience is unknown. */
  scopeProjection?: ScopeProjectionMapping;
  /**
   * @spec mission-template#prohibited-classes (#813, D830 ruling 3): whether
   * the chain's root Mission, at its issuer, is in a standing-payment lineage
   * this AS admitted; such a lineage is not delegated across organizations.
   */
  standingPaymentLineage?: (missionId: string, issuer: string) => boolean;
}

/**
 * @spec cross-org-delegation#projection (#1759, D941): the local entry one
 * leaf tool projects to, or undefined when a restriction of either layer is
 * one the local token cannot represent or its consumer cannot enforce. The
 * entry is the one-action entry the tool's `mission_constraints` value
 * describes, so its `constraints` and `resource_contract` carry over
 * unchanged. The tool's argument constraints must be exactly what this
 * destination's operations map that entry to (the root mapping,
 * {@link mapAuthorityToCeiling}): every declared argument admitted, and the
 * facts of every constraint established. A local entry has no argument
 * constraints, so a narrower argument map is a restriction it cannot
 * represent, and an entry the declaration does not map (an undeclared
 * operation, or a constraint whose facts its consumer does not establish)
 * is one its consumer cannot enforce. So is a `resource_contract` this
 * destination's declarations do not resolve: an undeclared contract or
 * version, a retired one, one superseded past its retention, or one that
 * does not define the entry's action. A superseded version within its
 * retention projects, as the kernel admits a carried reference.
 */
function projectLeafTool(
  toolId: string,
  args: Record<string, unknown>,
  missionConstraints: MissionConstraints,
  operations: AttenuationOperations,
  contracts: ResourceContractDeclarations,
  now: Date,
): AuthorityEntry | undefined {
  const value = Object.hasOwn(missionConstraints, toolId) ? missionConstraints[toolId] : undefined;
  if (value === undefined) return undefined;
  const entry = missionToolEntry(toolId, value) as AuthorityEntry;
  if (contracts.carriedViolation(entry, now) !== undefined) return undefined;
  const mapped = mapAuthorityToCeiling([entry], operations);
  const mappedArgs = Object.hasOwn(mapped.tools, toolId) ? mapped.tools[toolId] : undefined;
  if (mappedArgs === undefined) return undefined;
  return canonicalize(mappedArgs as JsonValue) === canonicalize(args as JsonValue) ? entry : undefined;
}

function fail(ctx: KoaContextWithOIDC, code: string, description: string): void {
  ctx.status = 400;
  ctx.body = { error: code, error_description: description };
  ctx.set("cache-control", "no-store");
}

/**
 * @spec cross-org-delegation#projection-exchange — parameters, leaf PoP,
 * error mapping (invalid_request for structure/bounds; invalid_grant for any
 * verification failure with no partial detail, and for an empty
 * intersection; invalid_target for an audience outside a hop's `aud`, or a
 * leaf restriction of either layer the local token cannot carry or its
 * consumer cannot enforce), and the local mint with a restarted `act`.
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
  const verifiedProof = await opts.verifyDpop(proofJws);
  if (!verifiedProof.ok) {
    refuseTokenEndpointProof(ctx, verifiedProof);
    return;
  }
  const dpopJkt = verifiedProof.proof.jkt;

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
  // @spec mission-template#prohibited-classes (#813, D830 ruling 3): a
  // standing-payment lineage is not delegated across organizations until its
  // budget accounting extends there. Defense in depth: this issuer's only
  // chain-root issuance, deriveCrossOrgRoot, already refuses such a lineage,
  // so a chain rooted at one of its own standing-payment Missions cannot
  // arrive here signed by its key.
  if (opts.standingPaymentLineage?.(verified.missionId, verified.missionIssuer) === true) {
    fail(ctx, "invalid_grant", "a standing-payment lineage is not delegated across organizations (#813)");
    return;
  }
  // @spec cross-org-delegation#projection-exchange (#1759): the requested
  // audience is within the `aud` of every hop, the check the substrate makes
  // of an enforcement point (AAT -02 Section 8 step 6c). With the per-hop
  // nesting verification enforces, this is the leaf's `aud`.
  if (aatChainAudienceProblem(verified.tokens, { audiences: [requestedAud], requireChainAud: true }) !== undefined) {
    fail(ctx, "invalid_target", "requested audience is outside a hop's audience");
    return;
  }
  // @spec cross-org-delegation#projection (#1759, D941): both layers'
  // restrictions carry into the local token, or the whole exchange is
  // refused; ordinary local-policy narrowing comes after, separately.
  const inputAuthority: AuthorityEntry[] = [];
  for (const [toolId, args] of Object.entries(verified.leaf.tools)) {
    const entry = projectLeafTool(
      toolId,
      args,
      verified.leaf.missionConstraints,
      crossOrg.operations,
      opts.resourceContracts,
      opts.now(),
    );
    if (entry === undefined) {
      fail(ctx, "invalid_target", "a leaf restriction cannot be carried or enforced by the local token");
      return;
    }
    inputAuthority.push(entry);
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
  let entitledAuthority: EntitlementAuthorityEntry[] | undefined;
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
    entitledAuthority = entitlement?.authority;
  } catch {
    fail(ctx, "invalid_grant", "chain verification failed");
    return;
  }

  // Dual-axis: the verified delegated authority intersected with the local
  // ceiling; entries the destination does not permit are narrowed out.
  let outputAuthority = narrowToCeiling(inputAuthority, crossOrg.localCeiling as AuthorityEntry[]);
  // @spec cross-domain#dual-axis (#744): the third bound of the same
  // intersection, when the entitlement observation carries the action- and
  // resource-scoped grain. An audience-scoped observation leaves the
  // ceiling-intersected set untouched. Narrowing runs before the
  // empty-set refusal below, so a partial entitlement mints the surviving
  // subset and only a wholly empty intersection refuses; it also runs
  // before the derivation-evidence push, so `output_authority` records the
  // narrowed set with no schema change.
  if (entitledAuthority !== undefined) {
    outputAuthority = narrowToEntitledAuthority(outputAuthority, entitledAuthority);
  }
  if (outputAuthority.length === 0) {
    fail(ctx, "invalid_grant", "chain verification failed");
    return;
  }
  // @spec mission#scope-projection — this exchange signs its Mission-bound
  // access token directly, outside oidc-provider's save(), so it calls the
  // same projection itself: omit `scope` for an `authorization_details`
  // target, emit only proven-safe values for a `scope`-only one, refuse
  // otherwise (`invalid_target`, or `invalid_scope` for an explicitly
  // requested value it cannot grant, @spec mission#error-mapping).
  // @spec mission#rs-enforcement — this token always carries a (restarted)
  // `act`: it is a delegated Mission-bound token, minted only for an
  // audience the mapping classifies Mission-aware.
  const requested =
    typeof params.scope === "string" ? [...new Set(params.scope.split(" ").filter(Boolean))] : [];
  const oidcValue = requested.find((v) => OIDC_SCOPE_VALUES.has(v));
  if (oidcValue !== undefined) {
    fail(ctx, "invalid_scope", `requested scope value ${oidcValue} cannot be granted on this grant`);
    return;
  }
  const projection = projectScope({
    mapping: opts.scopeProjection,
    audiences: [requestedAud],
    entries: outputAuthority,
    delegated: true,
    ...(requested.length ? { requested: { values: requested, explicit: true } } : {}),
  });
  if (projection.outcome === "refuse") {
    fail(ctx, projection.error, projection.reason);
    return;
  }
  const projectedScope = projection.outcome === "emit" ? projection.scope : undefined;

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
  // one-time DPoP proof jti was already consumed earlier (the leaf proof,
  // `opts.verifyDpop`), a structural difference from the RAS's grant jti
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
    ...(projectedScope ? { scope: projectedScope } : {}),
  })
    .setProtectedHeader({ alg: "RS256", kid: opts.tokenKid, typ: "at+jwt" })
    .setIssuer(opts.issuer)
    .setAudience(requestedAud)
    .setIssuedAt(nowS)
    .setExpirationTime(exp)
    .setJti(jti)
    .sign(opts.tokenKey);

  crossOrg.evidence.push({
    chain_digest: chainDigest(presentation.aat_chain),
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
    ...(projectedScope ? { scope: projectedScope } : {}),
    authorization_details: outputAuthority,
  };
  ctx.set("cache-control", "no-store");
}
