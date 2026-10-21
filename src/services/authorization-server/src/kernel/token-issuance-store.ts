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
 * @spec mission#delegation-constraints (#869, D449): the same index is the
 * AS's delegation accounting. Each record carries its delegation depth and the
 * accounted actor chain. An origin mint (every mint this hook sees that is not
 * a designation or a delegated exchange) is depth 0 with an empty chain; a
 * designation and a delegated token are pre-recorded by their exchange, keyed
 * by the token's fixed `jti`, before it is saved, and the hook's later upsert
 * never touches those columns. A token with no record has unknown depth: a
 * missing record never reads as depth 0.
 *
 * In-memory, built per boot (D25/D27), also when the kernel is file-backed: a
 * restart makes every earlier token unknown, so its depth cannot be
 * established and an earlier designation is not redeemable (#250's restart
 * inventory, src/docs/control-plane-deployment.md).
 */

import { type Database, openStore } from "@mission/store";
import type { AuthorityEntry } from "./types.js";

/** One accounted actor, as a delegated token's `act` renders it. */
export interface AccountedActor {
  iss: string;
  sub: string;
  sub_profile?: string;
}

/** The kind of mint a record accounts for. */
export type IssuanceKind = "origin" | "designation" | "delegated";

const SCHEMA = `
CREATE TABLE token_issuance (
  iss TEXT NOT NULL,
  jti TEXT NOT NULL,
  grant_id TEXT NOT NULL,
  authorization_details TEXT NOT NULL,
  created_at TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'origin' CHECK (kind IN ('origin', 'designation', 'delegated')),
  mission_id TEXT,
  depth INTEGER,
  chain TEXT,
  designee TEXT,
  designator_jkt TEXT,
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
  /** @spec mission#delegation-constraints: what the record accounts for. */
  kind: IssuanceKind;
  /** The Mission the minting grant resolved to, where the AS recorded it. */
  missionId: string | undefined;
  /** The delegation depth; undefined is unknown, never 0. */
  depth: number | undefined;
  /** The accounted actor chain, oldest delegate first; undefined is unknown. */
  chain: AccountedActor[] | undefined;
  /** A designation's named client. */
  designee: string | undefined;
  /** A designation's designator key (the presented token's `cnf.jkt`). */
  designatorJkt: string | undefined;
}

interface IssuanceRow {
  grant_id: string;
  authorization_details: string;
  kind: IssuanceKind;
  mission_id: string | null;
  depth: number | null;
  chain: string | null;
  designee: string | null;
  designator_jkt: string | null;
}

export class TokenIssuanceStore {
  readonly db: Database;
  constructor(private readonly now: () => Date = () => new Date()) {
    this.db = openStore(SCHEMA);
  }

  /**
   * Record (or overwrite) the issuance binding for one minted access token: an
   * origin mint at depth 0 with an empty chain. A record a delegation exchange
   * already wrote keeps its kind, depth, chain and designation members.
   */
  record(input: {
    iss: string;
    jti: string;
    grantId: string;
    authorizationDetails: AuthorityEntry[];
    missionId?: string | undefined;
  }): void {
    this.db
      .prepare(
        `INSERT INTO token_issuance (iss, jti, grant_id, authorization_details, created_at, kind, mission_id, depth, chain)
         VALUES (?, ?, ?, ?, ?, 'origin', ?, 0, '[]')
         ON CONFLICT (iss, jti) DO UPDATE SET
           grant_id = excluded.grant_id,
           authorization_details = excluded.authorization_details,
           created_at = excluded.created_at,
           mission_id = COALESCE(token_issuance.mission_id, excluded.mission_id)`,
      )
      .run(
        input.iss,
        input.jti,
        input.grantId,
        JSON.stringify(input.authorizationDetails),
        this.now().toISOString(),
        input.missionId ?? null,
      );
  }

  /**
   * @spec mission#designation, mission#delegation-constraints (#869, D449):
   * pre-record a designation or a delegated token before it is saved, keyed by
   * its fixed `jti`. Write-once: a second record for the same token throws.
   */
  recordDelegation(input: {
    iss: string;
    jti: string;
    grantId: string;
    authorizationDetails: AuthorityEntry[];
    kind: "designation" | "delegated";
    missionId: string;
    depth: number;
    chain: AccountedActor[];
    designee?: string;
    designatorJkt?: string;
  }): void {
    this.db
      .prepare(
        `INSERT INTO token_issuance
           (iss, jti, grant_id, authorization_details, created_at, kind, mission_id, depth, chain, designee, designator_jkt)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        input.iss,
        input.jti,
        input.grantId,
        JSON.stringify(input.authorizationDetails),
        this.now().toISOString(),
        input.kind,
        input.missionId,
        input.depth,
        JSON.stringify(input.chain),
        input.designee ?? null,
        input.designatorJkt ?? null,
      );
  }

  /** Remove a pre-record whose token was never issued (a refusal after it was written). */
  remove(iss: string, jti: string): void {
    this.db.prepare("DELETE FROM token_issuance WHERE iss = ? AND jti = ?").run(iss, jti);
  }

  /**
   * Resolve the recorded issuance for a presented (iss, jti). Undefined means
   * this AS has no record of minting that token: introspection treats that as
   * NOT VERIFIED (bare `active: false`), never active — the stateless-JWT
   * forgery/rogue-mint surface this store exists to close.
   */
  resolve(iss: string, jti: string): RecordedIssuance | undefined {
    const row = this.db
      .prepare(
        `SELECT grant_id, authorization_details, kind, mission_id, depth, chain, designee, designator_jkt
         FROM token_issuance WHERE iss = ? AND jti = ?`,
      )
      .get(iss, jti) as IssuanceRow | undefined;
    if (!row) return undefined;
    return {
      grantId: row.grant_id,
      authorizationDetails: JSON.parse(row.authorization_details) as AuthorityEntry[],
      kind: row.kind,
      missionId: row.mission_id ?? undefined,
      depth: row.depth ?? undefined,
      chain: row.chain === null ? undefined : (JSON.parse(row.chain) as AccountedActor[]),
      designee: row.designee ?? undefined,
      designatorJkt: row.designator_jkt ?? undefined,
    };
  }
}
