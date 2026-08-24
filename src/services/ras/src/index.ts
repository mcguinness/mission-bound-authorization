/**
 * @spec cross-domain#validation-at-resource-as, MCP EMA
 *
 * The Resource Authorization Server for the SaaS trust domain. A second AS
 * (its own issuer) that redeems Mission-bound ID-JAGs via the RFC 7523
 * JWT-bearer grant and mints short-lived local access tokens preserving the
 * mission anchors. The lifetime-bounded estate: no PDP; the SaaS RS enforces
 * from the token alone.
 */

import { openStore, redeemOnce, redemptionSchema, type Database } from "@mission/store";
import { createLocalJWKSet, jwtVerify, SignJWT, type CryptoKey, type JWK } from "jose";

export const ID_JAG_TYP = "oauth-id-jag+jwt";
export const JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";

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
   * sender-constraint alone does NOT establish this. Mints a local token
   * preserving mission.id/issuer/authority_hash and identifying the
   * authenticated client as `client_id`, never the grant's own `client_id`,
   * which names the originating agent.
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

    const mission = payload.mission as { id: string; issuer: string; authority_hash: string } | undefined;
    if (!mission) throw new RasError("invalid_grant", "grant missing mission claim");
    // @spec: the signer MUST be the Mission issuer named by mission.issuer.
    if (mission.issuer !== issuer) throw new RasError("invalid_grant", "grant iss != mission.issuer");

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

    // One-time use (jti). Replay -> invalid_grant.
    const jti = payload.jti as string;
    if (!jti || !redeemOnce(this.db, "jag_redemptions", jti, "ras")) {
      throw new RasError("invalid_grant", "grant replay or missing jti");
    }

    // Mint a short-lived local token preserving the mission anchors. Its iss
    // is the RAS; mission.issuer remains the originating AS.
    const nowS = Math.floor(this.now().getTime() / 1000);
    const ttl = this.cfg.localTokenTtlSeconds ?? 120;
    const grantExp = payload.exp as number;
    const exp = Math.min(nowS + ttl, grantExp); // never outlive the grant lease
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
      .setSubject(String(payload.sub))
      .setIssuer(this.cfg.issuer)
      .setAudience(this.cfg.localTokenAudience ?? "http://localhost:4406/mcp")
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
