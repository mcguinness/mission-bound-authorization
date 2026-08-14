/**
 * @spec draft-mcguinness-oauth-id-continuation-assertion-00 — the delegation
 * FAMILY store (async-delegation foundation).
 *
 * A delegation FAMILY binds a grant to the Mission whose delegation lineage it
 * belongs to. An upcoming async-delegation continuation transport records a
 * family when it issues a delegation grant, resolves it to recover the Mission
 * on a later hop, and revokes every family of a Mission that reaches a terminal
 * lifecycle state. The binding lives HERE, not on MissionRecord, so no kernel
 * schema migration is needed.
 *
 * Terminal propagation: a Mission reaching a terminal lifecycle state
 * (`onLifecycleCommit`) marks all of its family rows terminal; a terminal family
 * makes `resolve` return undefined, while `familiesForMission` still lists it so
 * a caller can drive the corresponding grant revocation.
 *
 * Structure mirrors `ContinuationStore` (SQLite via `openStore`), holding no
 * kernel reference: every operation is self-contained local state and
 * `onLifecycleCommit` receives its event by value. That method is composed into
 * the AS lifecycle-commit fan-out by a LATER PR; it is not wired here.
 */

import { type Database, openStore } from "@mission/store";
import { TERMINAL_STATES } from "./types.js";
import type { LifecycleCommit } from "./types.js";

const SCHEMA = `
CREATE TABLE delegation_families (
  grant_id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL,
  state TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;
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
  readonly db: Database;
  constructor(private readonly now: () => Date = () => new Date()) {
    this.db = openStore(SCHEMA);
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
   * Lifecycle fan-out target (wired by a later PR): when the committed Mission
   * transition is terminal, mark ALL family rows for that Mission terminal, so
   * every delegation lineage rooted in it stops resolving. Mirrors
   * ContinuationStore.onLifecycleCommit.
   */
  onLifecycleCommit(commit: LifecycleCommit): void {
    if (!TERMINAL_STATES.has(commit.state)) return;
    this.db
      .prepare("UPDATE delegation_families SET state = 'terminal' WHERE mission_id = ?")
      .run(commit.id);
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
