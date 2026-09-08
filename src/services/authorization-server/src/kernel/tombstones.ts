/**
 * @spec control-plane#tombstones — kernel-held terminal-state tombstones.
 *
 * A tombstone is written in the SAME transaction as the terminal state write,
 * carries the canonical issuer/Mission identity, the terminal state, the final
 * version and the commit reference, and is retained for the COMPOSED maximum of
 * the deployment's applicable horizons. After that detailed retention expires
 * the detail columns are pruned and the identity row remains forever as the
 * permanent nonreuse marker.
 *
 * The table deliberately declares NO foreign key to `missions`. `foreign_keys`
 * is ON, so a cascade from a pruned terminal Mission row would delete the very
 * marker that prevents identifier reuse. This is the reasoning that already
 * gave the Mission-bound grant index its own handle.
 */

import type { Database } from "@mission/store";
import type { MissionState } from "./types.js";

export const MISSION_TOMBSTONE_SCHEMA = `
CREATE TABLE IF NOT EXISTS mission_tombstones (
  issuer TEXT NOT NULL,
  mission_id TEXT NOT NULL,
  terminal_state TEXT,
  final_version INTEGER,
  transition_at TEXT,
  commit_event_id TEXT,
  detail_expires_at INTEGER NOT NULL,
  detail_pruned INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (issuer, mission_id)
) STRICT;
`;

/**
 * The horizons the detailed retention composes. Every member is a declared
 * number of seconds; a declaration that is not a finite, non-negative number is
 * refused at construction rather than silently treated as zero.
 */
export interface TombstoneRetentionInputs {
  /** Longest lifetime of a credential or artifact that can name the Mission. */
  credential_artifact_lifetime_seconds: number;
  /** The advertised state-staleness ceiling consumers may rely within. */
  state_staleness_seconds: number;
  /** Clock-skew tolerance added to the staleness ceiling. */
  clock_skew_seconds: number;
  /** Longest idempotency or retry horizon that can replay against the record. */
  idempotency_retry_seconds: number;
  /**
   * The child-cascade horizon. The reference kernel cascades inside the
   * terminal commit's own transaction, so it adds no horizon of its own; a
   * deployment whose cascade is asynchronous declares the lag here.
   */
  child_cascade_seconds: number;
  /** Required audit retention for the terminal transition. */
  audit_retention_seconds: number;
}

/** The audit-retention horizon this reference deployment declares. */
export const DEFAULT_AUDIT_RETENTION_S = 7_776_000; // 90 days
/** Clock-skew tolerance, matching the Status List consumer's iat tolerance. */
export const DEFAULT_CLOCK_SKEW_S = 30;

/**
 * The composed detailed-retention horizon: the maximum of the declared
 * horizons, with staleness and skew composed as one bound because a consumer
 * may rely on an observation for staleness plus skew.
 */
export function composeTombstoneRetentionSeconds(inputs: TombstoneRetentionInputs): number {
  for (const [key, value] of Object.entries(inputs)) {
    if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
      throw new Error(`tombstone retention horizon '${key}' must be a non-negative number`);
    }
  }
  return Math.max(
    inputs.credential_artifact_lifetime_seconds,
    inputs.state_staleness_seconds + inputs.clock_skew_seconds,
    inputs.idempotency_retry_seconds,
    inputs.child_cascade_seconds,
    inputs.audit_retention_seconds,
  );
}

export interface MissionTombstone {
  issuer: string;
  missionId: string;
  terminalState?: MissionState;
  finalVersion?: number;
  transitionAt?: string;
  commitEventId?: string;
  detailExpiresAt: number;
  detailPruned: boolean;
}

/** Raised when a Mission Identifier that already reached a terminal state is
 *  presented for creation. Deliberately NOT a UniqueViolationError: the
 *  approval funnel treats that as idempotent re-approval, and identifier reuse
 *  must never be answered with someone else's record. */
export class MissionIdReuseError extends Error {}

export class MissionTombstoneStore {
  readonly retentionSeconds: number;

  constructor(
    private readonly db: Database,
    private readonly opts: { now: () => Date; horizons: TombstoneRetentionInputs },
  ) {
    this.db.exec(MISSION_TOMBSTONE_SCHEMA);
    this.retentionSeconds = composeTombstoneRetentionSeconds(opts.horizons);
  }

  /** The declared horizons, for the deployment declaration and its tests. */
  horizons(): TombstoneRetentionInputs {
    return { ...this.opts.horizons };
  }

  /**
   * Write the tombstone inside the caller's terminal-state transaction. First
   * terminal transition wins: a Mission reaches a terminal state once, and a
   * repeated write (a replayed cascade, say) must not restamp the horizon.
   */
  recordInCallerTx(input: {
    issuer: string;
    missionId: string;
    terminalState: MissionState;
    finalVersion: number;
    transitionAt: string;
    commitEventId: string;
  }): void {
    const detailExpiresAt =
      Date.parse(input.transitionAt) + this.retentionSeconds * 1000;
    this.db
      .prepare(
        `INSERT INTO mission_tombstones
           (issuer, mission_id, terminal_state, final_version, transition_at, commit_event_id, detail_expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (issuer, mission_id) DO NOTHING`,
      )
      .run(
        input.issuer,
        input.missionId,
        input.terminalState,
        input.finalVersion,
        input.transitionAt,
        input.commitEventId,
        detailExpiresAt,
      );
  }

  /**
   * Whether this identifier ever reached a terminal state under this issuer.
   * True for a pruned row too: the identity row is the permanent marker.
   */
  exists(issuer: string, missionId: string): boolean {
    return (
      this.db
        .prepare("SELECT 1 FROM mission_tombstones WHERE issuer = ? AND mission_id = ?")
        .get(issuer, missionId) !== undefined
    );
  }

  find(issuer: string, missionId: string): MissionTombstone | undefined {
    const row = this.db
      .prepare("SELECT * FROM mission_tombstones WHERE issuer = ? AND mission_id = ?")
      .get(issuer, missionId) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    return {
      issuer: row.issuer as string,
      missionId: row.mission_id as string,
      ...(row.terminal_state ? { terminalState: row.terminal_state as MissionState } : {}),
      ...(row.final_version !== null ? { finalVersion: row.final_version as number } : {}),
      ...(row.transition_at ? { transitionAt: row.transition_at as string } : {}),
      ...(row.commit_event_id ? { commitEventId: row.commit_event_id as string } : {}),
      detailExpiresAt: row.detail_expires_at as number,
      detailPruned: (row.detail_pruned as number) === 1,
    };
  }

  /**
   * Prune the DETAIL of every tombstone past its composed horizon, keeping the
   * `(issuer, mission_id)` row. The identifier is never reused and never
   * returns to `active` after the detail is gone.
   */
  pruneDetails(): number {
    const res = this.db
      .prepare(
        `UPDATE mission_tombstones
            SET terminal_state = NULL, final_version = NULL, transition_at = NULL,
                commit_event_id = NULL, detail_pruned = 1
          WHERE detail_pruned = 0 AND detail_expires_at <= ?`,
      )
      .run(this.opts.now().getTime());
    return res.changes;
  }
}
