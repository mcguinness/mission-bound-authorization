/**
 * @spec authority-server#join-assertion-artifact (#1560): the retained join
 * evidence events. "Each minting is a join evidence event. The MAS records
 * the following, retained for the audit horizon": the Mission reference, the
 * token digest and thumbprint, the `join` result, the authenticated caller,
 * the mapping version where one is published, and the validity window. The
 * reference MAS validates no Instance Context, so none is recorded.
 *
 * - Durability: the table is on the kernel database, the transaction domain
 *   of the Mission records and the other audit records, so an event is
 *   exactly as durable as the kernel store: the file-backed opt-in
 *   (`MISSION_KERNEL_STORE`) survives a restart; the in-memory default does
 *   not. A minting writes its event before the assertion is cached or
 *   returned (`JoinAssertionService`), so no assertion leaves the MAS without
 *   its event.
 * - Retention: an event is kept until its Mission's `expires_at` plus the
 *   deployment's declared post-expiry audit retention
 *   (`audit_retention_seconds`, the declaration the terminal tombstones and
 *   the activation policy snapshots compose): the audit horizon, "at least
 *   the Mission's lifetime plus a declared post-expiry period".
 * - Deletion: {@link JoinEvidenceStore.pruneExpired} deletes an event only
 *   once its horizon has passed, at boot recovery or when an operator calls
 *   it. Nothing else deletes, and no write updates a recorded event.
 * - Order: events read back oldest first, in recording order, so two
 *   mintings in one second (`iat` is in seconds) keep their order, and a
 *   mapping change reads as the point where `mapping_version` changes.
 * - Reads are for audit: an operator surface reads them, never a minting
 *   check.
 */

import type { Database } from "@mission/store";
import type { MissionRecord } from "./types.js";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS join_assertion_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  issuer TEXT NOT NULL,
  mission_id TEXT NOT NULL,
  event TEXT NOT NULL,
  retain_until INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS join_assertion_events_by_mission
  ON join_assertion_events (issuer, mission_id, seq);
`;

/** The acting token's one confirmation: a key thumbprint or a certificate thumbprint. */
export type JoinEvidenceConfirmation = { jkt: string } | { "x5t#S256": string };

/** A join evidence event: one minting. */
export interface JoinAssertionEvent {
  /** The Mission reference. */
  mission: { issuer: string; id: string };
  /** The token digest and its one confirmation (thumbprint). */
  token: { sha256: string } & JoinEvidenceConfirmation;
  /** The `join` result. */
  join: { client_id: string; disposition: "client" | "delegate"; depth?: number };
  /** The authenticated caller. */
  caller: string;
  /** The consuming PDP the assertion was minted for. */
  audience: string;
  /** The mapping contract version the joins were evaluated under, where the deployment names one. */
  mapping_version?: string;
  /** The validity window, epoch seconds. */
  iat: number;
  exp: number;
}

/** A retained event and the instant past which boot recovery may prune it. */
export interface RetainedJoinAssertionEvent {
  event: JoinAssertionEvent;
  /** The Mission's `expires_at` plus the declared audit retention. */
  retain_until: string;
}

/** Raised when an event cannot be retained; the minting returns no assertion. */
export class JoinEvidenceRetentionError extends Error {}

export class JoinEvidenceStore {
  constructor(
    private readonly db: Database,
    private readonly opts: { now: () => Date; auditRetentionSeconds: number },
  ) {
    if (!Number.isFinite(opts.auditRetentionSeconds) || opts.auditRetentionSeconds < 0) {
      throw new Error("join evidence audit retention must be a non-negative number of seconds");
    }
    this.db.exec(SCHEMA);
  }

  /**
   * Record one minting's event, retained for the audit horizon of `mission`,
   * the Mission it was minted for. An event naming another Mission, or a
   * Mission whose expiry is not a date-time, is refused and nothing is
   * written.
   */
  record(mission: Pick<MissionRecord, "issuer" | "id" | "expires_at">, event: JoinAssertionEvent): RetainedJoinAssertionEvent {
    if (event.mission.issuer !== mission.issuer || event.mission.id !== mission.id) {
      throw new JoinEvidenceRetentionError(`a join evidence event for ${event.mission.id} is not retained under ${mission.id}`);
    }
    const retainUntil = Date.parse(mission.expires_at) + this.opts.auditRetentionSeconds * 1000;
    if (!Number.isFinite(retainUntil)) {
      throw new JoinEvidenceRetentionError(`Mission expiry ${mission.expires_at} is not a date-time`);
    }
    this.db
      .prepare("INSERT INTO join_assertion_events (issuer, mission_id, event, retain_until) VALUES (?, ?, ?, ?)")
      .run(mission.issuer, mission.id, JSON.stringify(event), retainUntil);
    return { event, retain_until: new Date(retainUntil).toISOString() };
  }

  /** Every retained event, oldest first. */
  all(): RetainedJoinAssertionEvent[] {
    return this.rows(this.db.prepare("SELECT event, retain_until FROM join_assertion_events ORDER BY seq").all());
  }

  /** The retained events of one Mission, oldest first. */
  forMission(mission: { issuer: string; id: string }): RetainedJoinAssertionEvent[] {
    return this.rows(
      this.db
        .prepare("SELECT event, retain_until FROM join_assertion_events WHERE issuer = ? AND mission_id = ? ORDER BY seq")
        .all(mission.issuer, mission.id),
    );
  }

  /** Delete every event whose horizon has passed; returns how many. Nothing else deletes. */
  pruneExpired(): number {
    return this.db.prepare("DELETE FROM join_assertion_events WHERE retain_until < ?").run(this.opts.now().getTime()).changes;
  }

  private rows(rows: unknown[]): RetainedJoinAssertionEvent[] {
    return (rows as Array<{ event: string; retain_until: number }>).map((row) => ({
      event: JSON.parse(row.event) as JoinAssertionEvent,
      retain_until: new Date(row.retain_until).toISOString(),
    }));
  }
}
