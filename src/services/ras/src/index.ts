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
  now?: () => Date;
}

export class RasError extends Error {
  constructor(readonly code: "invalid_grant", message: string) {
    super(message);
  }
}

export class ResourceAuthorizationServer {
  readonly db: Database;
  private now: () => Date;
  constructor(private readonly cfg: RasConfig) {
    this.db = openStore(redemptionSchema("jag_redemptions"));
    this.now = cfg.now ?? (() => new Date());
  }

  /**
   * Redeem an ID-JAG (JWT-bearer grant). Validates typ, signature against the
   * trusted originating issuer, aud = this RAS, exp, sender-constraint (cnf.jkt
   * vs presenter), one-time jti, and iss == mission.issuer. Mints a local
   * token preserving mission.id/issuer/authority_hash.
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

    // Sender-constraint (cnf.jkt) verified against the presenting client.
    const cnf = payload.cnf as { jkt?: string } | undefined;
    if (!cnf?.jkt) throw new RasError("invalid_grant", "grant not sender-constrained");
    if (cnf.jkt !== presenterJkt) throw new RasError("invalid_grant", "presenter key mismatch");

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
    })
      .setProtectedHeader({ alg: "ES256", kid: this.cfg.signKid, typ: "at+jwt" })
      .setSubject(String(payload.sub))
      .setIssuer(this.cfg.issuer)
      .setAudience("http://localhost:4406/mcp")
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
      "io.modelcontextprotocol/enterprise-managed-authorization": { enabled: true },
    };
  }
}
