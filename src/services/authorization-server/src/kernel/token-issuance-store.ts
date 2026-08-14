/**
 * @spec mission#introspection, mission#caller-authorization-and-minimization
 * (issue #541 P1-2) — the token ISSUANCE index.
 *
 * A stateless `at+jwt` access token carries no stored per-token record (unlike
 * a refresh token, which the oidc-provider adapter persists and can be looked
 * up by its own `grantId`), so introspection has no way to recover WHICH
 * grant/family actually minted a presented access token. Checking the
 * Mission's own approval `grant_id` instead (the pre-fix behavior) is wrong
 * for a per-delegation async-delegation family: its access tokens are minted
 * under their OWN `grantId` (@spec continuation#transport-async), so
 * destroying or invalidating that family leaves its already-issued tokens
 * introspecting as `active: true` against the Mission's still-live approval
 * grant. This store closes that gap: EVERY access-token mint records (iss,
 * jti) -> the grantId it was ACTUALLY minted under, so individual revocation
 * can check the credential's own grant/family, never a different one that
 * happens to share the Mission.
 *
 * Recorded via a single provider-level hook (`access_token.issued` /
 * `access_token.saved`, buildProvider), not per mint call site: every AT mint
 * path (the standard authorization_code/refresh_token grant, async-
 * delegation, deferred, child, mission-dispatch/expansion) funnels through
 * `provider.AccessToken#save()`, which oidc-provider's base token model
 * always emits from — so this ONE subscription covers every current and
 * future mint path without per-callsite wiring.
 *
 * In-memory, built per boot (D25/D27), mirroring {@link DelegationFamilyStore}.
 */

import { type Database, openStore } from "@mission/store";
import type { AuthorityEntry } from "./types.js";

const SCHEMA = `
CREATE TABLE token_issuance (
  iss TEXT NOT NULL,
  jti TEXT NOT NULL,
  grant_id TEXT NOT NULL,
  authorization_details TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (iss, jti)
) STRICT;
`;

/** One recorded issuance: the grant/family it was minted under. */
export interface RecordedIssuance {
  grantId: string;
  /**
   * The `rar` the token was minted with (belt-and-suspenders audit copy).
   * Introspection does NOT read this as the credential's authority: an
   * access token's authority is read from its OWN verified JWT
   * `authorization_details` claim (already cryptographically bound to the
   * presented token, strictly more authoritative than a second copy here);
   * this field exists so the index shape matches what a grant/family lookup
   * would otherwise require a second store for, and is available for a
   * future audit/cross-check need.
   */
  authorizationDetails: AuthorityEntry[];
}

interface IssuanceRow {
  grant_id: string;
  authorization_details: string;
}

export class TokenIssuanceStore {
  readonly db: Database;
  constructor(private readonly now: () => Date = () => new Date()) {
    this.db = openStore(SCHEMA);
  }

  /** Record (or overwrite) the issuance binding for one minted access token. */
  record(input: {
    iss: string;
    jti: string;
    grantId: string;
    authorizationDetails: AuthorityEntry[];
  }): void {
    this.db
      .prepare(
        `INSERT INTO token_issuance (iss, jti, grant_id, authorization_details, created_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (iss, jti) DO UPDATE SET
           grant_id = excluded.grant_id,
           authorization_details = excluded.authorization_details,
           created_at = excluded.created_at`,
      )
      .run(
        input.iss,
        input.jti,
        input.grantId,
        JSON.stringify(input.authorizationDetails),
        this.now().toISOString(),
      );
  }

  /**
   * Resolve the recorded issuance for a presented (iss, jti). Undefined means
   * this AS has no record of minting that token: introspection treats that as
   * NOT VERIFIED (bare `active: false`), never active — the stateless-JWT
   * forgery/rogue-mint surface this store exists to close.
   */
  resolve(iss: string, jti: string): RecordedIssuance | undefined {
    const row = this.db
      .prepare("SELECT grant_id, authorization_details FROM token_issuance WHERE iss = ? AND jti = ?")
      .get(iss, jti) as IssuanceRow | undefined;
    if (!row) return undefined;
    return {
      grantId: row.grant_id,
      authorizationDetails: JSON.parse(row.authorization_details) as AuthorityEntry[],
    };
  }
}
