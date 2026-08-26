/**
 * @spec cross-domain#validation-at-resource-as, MCP EMA
 *
 * The Resource Authorization Server for the SaaS trust domain. A second AS
 * (its own issuer) that redeems Mission-bound ID-JAGs via the RFC 7523
 * JWT-bearer grant and mints short-lived local access tokens preserving the
 * mission anchors. The lifetime-bounded estate: no PDP; the SaaS RS enforces
 * from the token alone.
 */

import {
  type EntitlementResolver,
  type LocalMappingPolicy,
  type OriginPrincipal,
  resolveCoResolvedLocalPrincipal,
} from "@mission/core";
import { openStore, redeemOnce, redemptionSchema, type Database } from "@mission/store";
import { createLocalJWKSet, jwtVerify, SignJWT, type CryptoKey, type JWK } from "jose";

export const ID_JAG_TYP = "oauth-id-jag+jwt";
export const JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/**
 * @spec runtime#state-freshness — the same small future-skew tolerance the
 * PDP's own dual-axis check applies (evaluate.ts,
 * DEFAULT_FRESHNESS_SKEW_TOLERANCE_SECONDS): absorbs ordinary clock drift
 * without meaningfully widening the entitlement freshness bound.
 */
const FRESHNESS_SKEW_TOLERANCE_MS = 5_000;

export interface RasConfig {
  issuer: string;
  /** Trusted originating Mission issuers -> their JWKS (issuer trust, local policy). */
  trustedIssuers: Record<string, { keys: JWK[] }>;
  signKey: CryptoKey;
  signKid: string;
  localTokenTtlSeconds?: number;
  /** Audience stamped on minted local tokens (the SaaS resource). */
  localTokenAudience?: string;
  /**
   * @spec cross-domain#validation-at-resource-as (S-12): this RAS's own
   * client registration, seeded at construction and keyed by the client's
   * DPoP public-key JWK thumbprint (`jkt`). A key-bound registration IS
   * client authentication here (the same shape as private_key_jwt or
   * DPoP-bound client credentials): redemption authenticates the
   * presenting client by looking up its proven `jkt` in this table and
   * refuses `invalid_client` on an unrecognized key, then mints the
   * matched value as `client_id`. It is never copied or derived from the
   * ID-JAG grant's own `client_id` claim, which names the acting client at
   * the ORIGINATING AS, nor from the presenter key alone without a
   * matching registration. A client whose key is generated after this RAS
   * is constructed is onboarded via {@link ResourceAuthorizationServer.registerClient}.
   */
  registeredClients?: Record<string, string>;
  /**
   * @spec cross-domain#origin-principal-mapping (#539) — the registered
   * origin-to-local mapping table for a BASE ID-JAG (no
   * `identity_continuation_handle`). Consulted for co-resolution: the
   * grant's own `(iss, sub)` and its carried `mission.subject` MUST both
   * resolve, via this table, to the SAME destination-local `sub`. A
   * continuation ID-JAG carries its own already-resolved, per-audience
   * deterministic `sub` (a distinct, separately specified mechanism,
   * {{id-continuation-assertion}}) and is not looked up here.
   */
  mapping: LocalMappingPolicy;
  /**
   * @spec cross-domain#dual-axis (#539) — current entitlement of the
   * destination-local principal, the profile's second axis. Runs on EVERY
   * redemption (base and continuation grant alike), against whichever local
   * `sub` that grant resolves to.
   */
  entitlement: EntitlementResolver;
  /** Independent freshness bound for the entitlement observation, seconds. */
  entitlementStalenessBoundSeconds: number;
  now?: () => Date;
}

export class RasError extends Error {
  constructor(readonly code: "invalid_grant" | "invalid_client", message: string) {
    super(message);
  }
}

export class ResourceAuthorizationServer {
  readonly db: Database;
  private now: () => Date;
  private readonly registeredClients: Map<string, string>;
  constructor(private readonly cfg: RasConfig) {
    this.db = openStore(redemptionSchema("jag_redemptions"));
    this.now = cfg.now ?? (() => new Date());
    this.registeredClients = new Map(Object.entries(cfg.registeredClients ?? {}));
  }

  /**
   * @spec cross-domain#validation-at-resource-as (S-12): onboard a
   * destination-local client's key after construction, for a client whose
   * key is generated later (e.g. per-session DPoP key material). This IS
   * the RAS's client-registration surface; only a `jkt` registered here
   * (at construction or by this call) authenticates at redemption.
   */
  registerClient(jkt: string, clientId: string): void {
    this.registeredClients.set(jkt, clientId);
  }

  /**
   * Redeem an ID-JAG (JWT-bearer grant). Validates typ, signature against the
   * trusted originating issuer, aud = this RAS, exp, sender-constraint (cnf.jkt
   * vs presenter), one-time jti, and iss == mission.issuer. Separately
   * authenticates the redeeming client against this RAS's own registration
   * (S-12; {{cross-domain#validation-at-resource-as}}), refusing
   * `invalid_client` on an unrecognized presenter key: the grant's
   * sender-constraint alone does NOT establish this.
   *
   * @spec cross-domain#origin-principal-mapping, #dual-axis (#539): for a
   * BASE grant, co-resolves the grant's own `(iss, sub)` and its carried
   * `mission.subject` to a single destination-local principal via the
   * registered mapping table, then confirms that principal's current
   * entitlement, before minting. Never mints `payload.sub` unverified. A
   * continuation ID-JAG (`identity_continuation_handle` present, read only
   * from the VERIFIED payload -- not request-controlled) carries its own
   * already-resolved, per-audience deterministic `sub`
   * ({{id-continuation-assertion}}), a distinct, separately specified
   * identity-resolution mechanism a static mapping table cannot represent
   * (its value is derived fresh per audience, not registered); mapping and
   * co-resolution are skipped for it, but entitlement still runs against
   * whatever local `sub` it presents, so no redemption path mints a local
   * token without an entitlement check.
   *
   * Mints a local token preserving mission.id/issuer/authority_hash/subject
   * and identifying the authenticated client as `client_id`, never the
   * grant's own `client_id`, which names the originating agent.
   */
  async redeem(idJag: string, presenterJkt: string): Promise<{ access_token: string; expires_in: number }> {
    // Peek the issuer to select the trust anchor.
    let unverified: Record<string, unknown>;
    try {
      unverified = JSON.parse(Buffer.from(idJag.split(".")[1] ?? "", "base64url").toString());
    } catch {
      throw new RasError("invalid_grant", "malformed grant");
    }
    const issuer = unverified.iss as string;
    const anchor = this.cfg.trustedIssuers[issuer];
    if (!anchor) throw new RasError("invalid_grant", "untrusted grant issuer");

    let payload: Record<string, unknown>;
    let header: Record<string, unknown>;
    try {
      const jwks = createLocalJWKSet({ keys: anchor.keys } as never);
      const res = await jwtVerify(idJag, jwks, { audience: this.cfg.issuer, issuer, typ: ID_JAG_TYP });
      payload = res.payload as Record<string, unknown>;
      header = res.protectedHeader as Record<string, unknown>;
    } catch (e) {
      throw new RasError("invalid_grant", `grant verification failed: ${(e as Error).message}`);
    }
    if (header.typ !== ID_JAG_TYP) throw new RasError("invalid_grant", "wrong grant typ");

    // @spec cross-domain#origin-principal-mapping: strictly parse the
    // complete Mission claim, including the closed {iss, sub} `subject`
    // member every grant now carries (kernel/cross-domain.ts). A missing or
    // malformed `subject` is a refusal, never a silently dropped member.
    const mission = payload.mission as
      | { id: string; issuer: string; authority_hash: string; subject?: OriginPrincipal }
      | undefined;
    if (!mission) throw new RasError("invalid_grant", "grant missing mission claim");
    // @spec: the signer MUST be the Mission issuer named by mission.issuer.
    if (mission.issuer !== issuer) throw new RasError("invalid_grant", "grant iss != mission.issuer");
    const originSubject = mission.subject;
    if (
      !originSubject ||
      typeof originSubject.iss !== "string" ||
      !originSubject.iss ||
      typeof originSubject.sub !== "string" ||
      !originSubject.sub
    ) {
      throw new RasError("invalid_grant", "grant missing or malformed mission.subject");
    }

    // Sender-constraint (cnf.jkt) verified against the presenting client:
    // proves the presenter holds the grant's OWN bound key. This is grant
    // validity, not client authentication (S-12; see the lookup below).
    const cnf = payload.cnf as { jkt?: string } | undefined;
    if (!cnf?.jkt) throw new RasError("invalid_grant", "grant not sender-constrained");
    if (cnf.jkt !== presenterJkt) throw new RasError("invalid_grant", "presenter key mismatch");

    // @spec cross-domain#validation-at-resource-as (S-12): authenticate the
    // redeeming client against THIS RAS's own registration, independent of
    // anything the origin AS asserted (the grant's client_id claim names
    // the originating agent and is never consulted here). A valid,
    // sender-constrained grant is not enough on its own: the presenter key
    // must resolve to a client this RAS recognizes, or redemption fails
    // invalid_client rather than minting a token for an unauthenticated
    // party. Checked before jti consumption so an unrecognized presenter
    // does not burn the grant's one-time use.
    const localClientId = this.registeredClients.get(presenterJkt);
    if (!localClientId) {
      throw new RasError("invalid_client", "unrecognized redeeming client");
    }

    const audience = this.cfg.localTokenAudience ?? "http://localhost:4406/mcp";
    const now = this.now();
    // @spec id-continuation-assertion: read only from the payload `jwtVerify`
    // already authenticated against the trusted originating issuer -- never
    // request-controlled, so this branch cannot be forced by a presenter.
    const isContinuation = typeof payload.identity_continuation_handle === "string";

    let localSub: string;
    // The mapping's own validity bound additionally caps the minted token's
    // lifetime for a base grant (below); a continuation grant has no mapping
    // lookup, so no such bound applies.
    let mappingValidUntilMs: number | undefined;
    if (isContinuation) {
      // The continuation profile's own already-resolved, per-audience
      // deterministic subject: not looked up in the mapping table (see the
      // method doc above).
      localSub = String(payload.sub);
    } else {
      // @spec cross-domain#origin-principal-mapping (#539): the grant's own
      // (iss, sub) and mission.subject MUST co-resolve to the SAME
      // destination-local principal. A missing, ambiguous, disabled,
      // future-dated, or expired mapping on EITHER side, or a disagreement
      // between the two, denies uniformly.
      const grantIdentity: OriginPrincipal = { iss: issuer, sub: String(payload.sub) };
      const resolved = resolveCoResolvedLocalPrincipal(this.cfg.mapping, grantIdentity, originSubject, audience, now);
      if (!resolved) throw new RasError("invalid_grant", "origin principal mapping failed");
      localSub = resolved.local_sub;
      mappingValidUntilMs = Date.parse(resolved.valid_until);
    }

    // @spec cross-domain#dual-axis (#539): current entitlement of the
    // destination-local principal, independent of Mission-state freshness
    // and (for a base grant) independent of the mapping's own validity
    // bound. Runs for EVERY redemption; a resolver exception is a failed
    // result, not a distinct outcome or an unclassified transport failure.
    let entitlementObservedMs: number | undefined;
    try {
      const entitlement = await this.cfg.entitlement.resolve({ local: { iss: this.cfg.issuer, sub: localSub }, audience });
      const observedMs = entitlement ? Date.parse(entitlement.observed_at) : NaN;
      const ageMs = now.getTime() - observedMs;
      const current =
        entitlement?.entitled === true &&
        Number.isFinite(observedMs) &&
        ageMs >= -FRESHNESS_SKEW_TOLERANCE_MS &&
        ageMs <= this.cfg.entitlementStalenessBoundSeconds * 1000;
      if (!current) throw new RasError("invalid_grant", "entitlement check failed");
      entitlementObservedMs = observedMs;
    } catch (e) {
      if (e instanceof RasError) throw e;
      throw new RasError("invalid_grant", "entitlement check failed");
    }

    // One-time use (jti). Replay -> invalid_grant. Checked only after the
    // dual-axis check succeeds, alongside the existing client-registration
    // check above (@spec cross-domain#origin-principal-mapping: run mapping
    // and entitlement before consuming the grant's one-time use).
    const jti = payload.jti as string;
    if (!jti || !redeemOnce(this.db, "jag_redemptions", jti, "ras")) {
      throw new RasError("invalid_grant", "grant replay or missing jti");
    }

    // Mint a short-lived local token preserving the mission anchors
    // (including the unchanged origin `mission.subject`). Its iss is the
    // RAS; mission.issuer remains the originating AS. exp never outlives
    // the grant lease, the mapping's own validity bound (base grant), or
    // the entitlement observation's freshness horizon.
    const nowS = Math.floor(now.getTime() / 1000);
    const ttl = this.cfg.localTokenTtlSeconds ?? 120;
    const grantExp = payload.exp as number;
    const entitlementHorizonS = Math.floor((entitlementObservedMs ?? nowS * 1000) / 1000) + this.cfg.entitlementStalenessBoundSeconds;
    const bounds = [nowS + ttl, grantExp, entitlementHorizonS];
    if (mappingValidUntilMs !== undefined) bounds.push(Math.floor(mappingValidUntilMs / 1000));
    const exp = Math.min(...bounds);
    const token = await new SignJWT({
      mission,
      authorization_details: payload.authorization_details,
      cnf: { jkt: presenterJkt },
      // @spec cross-domain#validation-at-resource-as (S-12): client_id names
      // the client identity the registration lookup above authenticated,
      // never copied or derived from the grant's own client_id
      // (payload.client_id), which names the originating agent and MUST
      // NOT appear in this slot.
      client_id: localClientId,
    })
      .setProtectedHeader({ alg: "ES256", kid: this.cfg.signKid, typ: "at+jwt" })
      .setSubject(localSub)
      .setIssuer(this.cfg.issuer)
      .setAudience(audience)
      .setIssuedAt(nowS)
      .setExpirationTime(exp)
      .sign(this.cfg.signKey);
    return { access_token: token, expires_in: exp - nowS };
  }

  /** @spec MCP EMA: the RAS declares enterprise-managed auth in its metadata. */
  metadata(): Record<string, unknown> {
    return {
      issuer: this.cfg.issuer,
      grant_types_supported: [JWT_BEARER_GRANT],
      // @spec id-continuation-assertion — the RAS redeems both the base ID-JAG
      // and the continuation ID-JAG (same JWT-bearer grant, continuation claims
      // preserved into the local token).
      authorization_grant_profiles_supported: [
        "urn:ietf:params:oauth:grant-profile:id-jag",
        "urn:ietf:params:oauth:grant-profile:id-jag-continuation",
      ],
      "io.modelcontextprotocol/enterprise-managed-authorization": { enabled: true },
    };
  }
}
