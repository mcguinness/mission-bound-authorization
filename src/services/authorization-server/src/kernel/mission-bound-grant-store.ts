/**
 * @spec issuance-grant#effective-set-projection, mission#the-mission-claim
 * (#617 review 3) — the MISSION-BOUND GRANT index: every provider `grantId`
 * ever minted as Mission-bound, and the Mission it was minted for.
 *
 * The gap it closes is a fail-OPEN. Both token-plane hooks resolved a grant's
 * Mission by LOOKUP (kernel.findByGrant, then the delegation-family store) and
 * treated "no Mission resolved" as "this is not a Mission-bound grant": the rar
 * projection returned the grant's stored, issuance-time `authorization_details`
 * unchanged, and extraTokenClaims returned `{}` (a token with NO `mission`
 * claim). For an ordinary OAuth grant that is correct. For a Mission-bound
 * grant whose Mission record has become unresolvable it is exactly backwards:
 * the state integration failed, so the profile says fail CLOSED, and instead
 * the AS issued the credential's old authority with its Mission binding
 * silently dropped.
 *
 * A durable discriminator is the only way to tell those two cases apart, so
 * this index is written when the binding is ESTABLISHED (kernel.bindGrant for a
 * Mission's own approval grant, {@link MissionBoundGrantStore.record} for a
 * per-delegation family grant) and is APPEND-ONLY: no delete, no invalidate,
 * and deliberately NOT cleaned up with the Mission record or with the family
 * row (DelegationFamilyStore.invalidate has no counterpart here). A record that
 * vanished with its Mission would answer "not Mission-bound" for exactly the
 * grants this exists to catch.
 *
 * Its own table over its own store handle (the {@link TokenIssuanceStore}
 * idiom), so a `DELETE FROM missions` cannot take it with it. In-memory, built
 * per boot (D25/D27).
 */

import { type Database, openStore } from "@mission/store";

const SCHEMA = `
CREATE TABLE mission_bound_grants (
  grant_id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;
`;

/** How the grant became Mission-bound (audit only; both fail closed alike). */
export type MissionBoundGrantKind = "approval" | "delegation-family";

export interface MissionBoundGrant {
  missionId: string;
  kind: MissionBoundGrantKind;
}

interface GrantRow {
  mission_id: string;
  kind: string;
}

export class MissionBoundGrantStore {
  readonly db: Database;
  constructor(private readonly now: () => Date = () => new Date()) {
    this.db = openStore(SCHEMA);
  }

  /**
   * Record that `grantId` is Mission-bound. Idempotent on the grant id: a
   * re-bind of the same grant keeps the FIRST Mission, since a provider grant
   * is bound to one Mission for its whole life and a conflicting rebind would
   * be a bug, not a legitimate move.
   */
  record(input: { grantId: string; missionId: string; kind: MissionBoundGrantKind }): void {
    this.db
      .prepare(
        `INSERT INTO mission_bound_grants (grant_id, mission_id, kind, created_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT (grant_id) DO NOTHING`,
      )
      .run(input.grantId, input.missionId, input.kind, this.now().toISOString());
  }

  /**
   * Resolve the Mission binding of a grant. `undefined` means this AS never
   * minted that grant as Mission-bound, which is the ONLY case a token-plane
   * hook may pass through unchanged.
   */
  resolve(grantId: string): MissionBoundGrant | undefined {
    const row = this.db
      .prepare("SELECT mission_id, kind FROM mission_bound_grants WHERE grant_id = ?")
      .get(grantId) as GrantRow | undefined;
    if (!row) return undefined;
    return { missionId: row.mission_id, kind: row.kind as MissionBoundGrantKind };
  }
}
