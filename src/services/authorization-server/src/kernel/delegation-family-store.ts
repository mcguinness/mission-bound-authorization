/**
 * @spec async-delegation — the delegation FAMILY store (the async-delegation
 * foundation).
 *
 * A delegation FAMILY binds a grant to the Mission whose delegation lineage it
 * belongs to. An upcoming async-delegation continuation transport records a
 * family when it issues a delegation grant, resolves it to recover the Mission
 * on a later hop, and revokes every family of a Mission that reaches a terminal
 * lifecycle state. The binding lives HERE, not on MissionRecord, so no kernel
 * schema migration is needed.
 *
 * Terminal propagation: a Mission reaching a terminal lifecycle state marks
 * all of its family rows terminal ({@link terminateMissionInCallerTx}); a
 * terminal family makes `resolve` return undefined, while `familiesForMission`
 * still lists it so a caller can drive the corresponding grant revocation.
 *
 * @spec control-plane#serialization (#250) — the table lives on the KERNEL's
 * database, which owns it and closes it with itself, and the terminal
 * propagation is a kernel-owned write in the terminal commit, beside the
 * tombstone. A file-backed kernel keeps every family across a restart; the
 * provider Grant a family names does not survive one (the provider's grants
 * are in memory), so a recovered family whose grant is gone is refused where
 * it is presented.
 */

import type { Database } from "@mission/store";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS delegation_families (
  grant_id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL,
  state TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS delegation_families_mission ON delegation_families (mission_id);
`;

export type DelegationFamilyState = "active" | "terminal";

/** The Mission binding recovered for an active (non-terminal) family. */
export interface ResolvedFamily {
  missionId: string;
  state: DelegationFamilyState;
}

interface FamilyRow {
  grant_id: string;
  mission_id: string;
  state: string;
}

export class DelegationFamilyStore {
  /** @param db the kernel's database, which owns this table. */
  constructor(
    readonly db: Database,
    private readonly now: () => Date = () => new Date(),
  ) {
    this.db.exec(SCHEMA);
  }

  /** Record an active delegation family binding a grant to its Mission. */
  record(input: { grantId: string; missionId: string }): void {
    this.db
      .prepare(
        `INSERT INTO delegation_families (grant_id, mission_id, state, created_at)
         VALUES (?, ?, 'active', ?)`,
      )
      .run(input.grantId, input.missionId, this.now().toISOString());
  }

  /**
   * Resolve a family by grant id. Returns undefined when the grant is unknown OR
   * its family is terminal, so a terminated lineage stops resolving.
   */
  resolve(grantId: string): ResolvedFamily | undefined {
    const row = this.db
      .prepare("SELECT grant_id, mission_id, state FROM delegation_families WHERE grant_id = ?")
      .get(grantId) as FamilyRow | undefined;
    if (!row || row.state === "terminal") return undefined;
    return { missionId: row.mission_id, state: row.state as DelegationFamilyState };
  }

  /**
   * Terminal propagation: mark ALL family rows for a Mission terminal, so
   * every delegation lineage rooted in it stops resolving. NO OWN
   * TRANSACTION: the kernel calls this inside the terminal commit, beside the
   * tombstone. Mirrors ContinuationStore.terminateMissionInCallerTx.
   */
  terminateMissionInCallerTx(missionId: string): void {
    if (!this.db.inTransaction) {
      throw new Error("delegation family termination must be written inside the terminal commit's transaction");
    }
    this.db.prepare("UPDATE delegation_families SET state = 'terminal' WHERE mission_id = ?").run(missionId);
  }

  /**
   * Invalidate ONE provisional family (its creation rolled back before any
   * token was issued, e.g. a derivation-gate rejection after the grant was
   * saved): the row goes terminal so the lineage never resolves.
   */
  invalidate(grantId: string): void {
    this.db
      .prepare("UPDATE delegation_families SET state = 'terminal' WHERE grant_id = ?")
      .run(grantId);
  }

  /**
   * @spec mission#introspection — whether `grantId` was EVER recorded as a
   * delegation family, in ANY state (active or terminal). {@link resolve}
   * alone cannot distinguish "never a family" (liveness is decided elsewhere,
   * e.g. the Mission approval grant) from "was a family, now terminal"
   * (liveness IS this store's terminal flag, regardless of the underlying
   * oidc-provider Grant's own existence) — both return undefined. A caller
   * that must tell those apart (introspection's per-token individual-
   * revocation check, issue #541 P1-2) checks this FIRST.
   */
  wasEverFamily(grantId: string): boolean {
    const row = this.db
      .prepare("SELECT 1 FROM delegation_families WHERE grant_id = ?")
      .get(grantId);
    return row !== undefined;
  }

  /**
   * Read accessor: the grant ids of every family for a Mission, in ANY state
   * (ordered by record time), so a caller can drive revocation of each grant
   * even after the families were marked terminal.
   */
  familiesForMission(missionId: string): string[] {
    const rows = this.db
      .prepare("SELECT grant_id FROM delegation_families WHERE mission_id = ? ORDER BY created_at")
      .all(missionId) as Array<{ grant_id: string }>;
    return rows.map((r) => r.grant_id);
  }
}
