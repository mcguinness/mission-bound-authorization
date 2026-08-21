/**
 * @spec status#idempotency, status#discharge-idempotency
 *
 * The Mission Lifecycle endpoint keeps TWO identities apart, and this module
 * holds one durable store for each:
 *
 *  - `nonce` is the HTTP retry key for the WHOLE endpoint
 *    ({@link LifecycleResponseStore}): a retransmission with the same `nonce`
 *    and a byte-identical request returns the STORED SIGNED RESPONSE verbatim;
 *    the same `nonce` with a different request is refused `invalid_request`,
 *    never answered with the unrelated original response. Keyed by (endpoint,
 *    client, `mission_id`, `nonce`), so one endpoint's nonce space is its own.
 *
 *  - `event_id` deduplicates the external OCCURRENCE a `discharge` asserts
 *    ({@link DischargeEventStore}), scoped by (authenticated discharge
 *    authority, `mission_id`, `entry_digest`, `condition_digest`, `event_id`)
 *    and qualified by the event assertion FINGERPRINT. The same tuple with the
 *    same fingerprint performs no state work and replays the stored operation
 *    result (a FRESH envelope echoing the new nonce, since a response's `nonce`
 *    MUST equal the one just sent); the same tuple with a different fingerprint
 *    is refused `conflict`; the same `event_id` against another Mission, entry,
 *    or condition is a valid independent assertion, because one real-world
 *    event legitimately fans out to more than one target.
 *
 * When both rules could apply the `nonce` rule is evaluated first: it governs
 * the HTTP exchange, the `event_id` rule governs across distinct exchanges.
 *
 * Both tables live in the KERNEL's own database (the creation-idempotency
 * precedent), so the event row can share ONE SQLite transaction with the latch
 * and version increment it records (@spec status#discharge-operation,
 * "Atomicity"); nested `withTransaction` calls become savepoints.
 */

import { withTransaction, type Database } from "@mission/store";
import type { DischargeOutcome, DischargeResult } from "./discharge.js";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS lifecycle_responses (
  endpoint TEXT NOT NULL,
  principal TEXT NOT NULL,
  mission_id TEXT NOT NULL,
  nonce TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  status INTEGER NOT NULL,
  content_type TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (endpoint, principal, mission_id, nonce)
) STRICT;
CREATE TABLE IF NOT EXISTS discharge_events (
  authority TEXT NOT NULL,
  mission_id TEXT NOT NULL,
  entry_digest TEXT NOT NULL,
  condition_digest TEXT NOT NULL,
  event_id TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  outcome TEXT NOT NULL,
  prior_version INTEGER NOT NULL,
  current_version INTEGER NOT NULL,
  received_at TEXT NOT NULL,
  evidence_ref TEXT,
  evidence_digest TEXT,
  observed_at TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (authority, mission_id, entry_digest, condition_digest, event_id)
) STRICT;
`;

/**
 * @spec status#idempotency — the replay window MUST be at least the validity
 * span of the signed response the AS would replay (its `iat` to `exp`, 60s
 * here). Ten minutes is a deployment choice well above that floor.
 */
export const DEFAULT_LIFECYCLE_NONCE_TTL_S = 600;

/**
 * @spec status#discharge-idempotency ("Retention") — event-dedup state is
 * retained at least as long as the deployment's published retry horizon and the
 * replayable result's usable lifetime. One day, the same horizon the creation
 * tombstone uses. After eviction a repeated assertion is processed fresh
 * against the latch and yields `already_discharged` with no version increment,
 * which is safe because the latch is monotonic.
 */
export const DEFAULT_DISCHARGE_EVENT_TTL_S = 86400;

/** The lifecycle endpoint's own name in the nonce key space. */
export const LIFECYCLE_ENDPOINT_KEY = "mission_lifecycle_endpoint";

/** The (endpoint, client, mission, nonce) identity of one HTTP exchange. */
export interface LifecycleNonceKey {
  endpoint: string;
  principal: string;
  missionId: string;
  nonce: string;
}

/** A stored endpoint response, replayed verbatim on a matching retransmission. */
export interface StoredLifecycleResponse {
  requestDigest: string;
  status: number;
  contentType: string;
  body: string;
}

export class LifecycleResponseStore {
  private readonly retentionMs: number;

  constructor(
    private readonly db: Database,
    private readonly options: { now: () => Date; retentionSeconds?: number },
  ) {
    this.db.exec(SCHEMA);
    this.retentionMs = (options.retentionSeconds ?? DEFAULT_LIFECYCLE_NONCE_TTL_S) * 1000;
  }

  /**
   * The response stored for this nonce, or undefined when none is live. A row
   * past its window is out of contract: it is purged, so the nonce is free.
   */
  find(key: LifecycleNonceKey): StoredLifecycleResponse | undefined {
    const row = this.db
      .prepare(
        `SELECT * FROM lifecycle_responses
         WHERE endpoint = ? AND principal = ? AND mission_id = ? AND nonce = ?`,
      )
      .get(key.endpoint, key.principal, key.missionId, key.nonce) as
      | Record<string, unknown>
      | undefined;
    if (!row) return undefined;
    if (this.options.now().getTime() > (row.expires_at as number)) {
      this.db
        .prepare(
          `DELETE FROM lifecycle_responses
           WHERE endpoint = ? AND principal = ? AND mission_id = ? AND nonce = ?`,
        )
        .run(key.endpoint, key.principal, key.missionId, key.nonce);
      return undefined;
    }
    return {
      requestDigest: row.request_digest as string,
      status: row.status as number,
      contentType: row.content_type as string,
      body: row.body as string,
    };
  }

  /**
   * Store the response this exchange produced. FIRST WRITER WINS (the PK
   * conflict is ignored): a later response under the same nonce, including the
   * `invalid_request` the divergent-retry rule itself produces, must never
   * overwrite the original the retransmission rule has to replay.
   */
  record(key: LifecycleNonceKey, response: StoredLifecycleResponse): void {
    const nowMs = this.options.now().getTime();
    this.db
      .prepare(
        `DELETE FROM lifecycle_responses
         WHERE endpoint = ? AND principal = ? AND mission_id = ? AND nonce = ? AND expires_at < ?`,
      )
      .run(key.endpoint, key.principal, key.missionId, key.nonce, nowMs);
    this.db
      .prepare(
        `INSERT INTO lifecycle_responses (endpoint, principal, mission_id, nonce, request_digest,
         status, content_type, body, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT DO NOTHING`,
      )
      .run(
        key.endpoint,
        key.principal,
        key.missionId,
        key.nonce,
        response.requestDigest,
        response.status,
        response.contentType,
        response.body,
        nowMs,
        nowMs + this.retentionMs,
      );
  }
}

/**
 * @spec status#discharge-idempotency — the five-part event tuple: the
 * AUTHENTICATED discharge authority plus the three selectors and the asserted
 * occurrence's identifier.
 */
export interface DischargeEventKey {
  authority: string;
  missionId: string;
  entryDigest: string;
  conditionDigest: string;
  eventId: string;
}

/** A recorded occurrence: its fingerprint and the operation result it produced. */
export interface StoredDischargeEvent {
  fingerprint: string;
  outcome: DischargeOutcome;
  priorVersion: number;
  currentVersion: number;
}

/**
 * @spec status#discharge-operation — the audit members that ride the recorded
 * occurrence and NOTHING else: `evidence_ref` is never dereferenced, and neither
 * evidence member nor the caller-asserted `observed_at` is authorization input.
 * `received_at` is the AS's own commit time.
 */
export interface DischargeEventAudit {
  receivedAt: string;
  evidenceRef?: string;
  evidenceDigest?: string;
  observedAt?: string;
}

export class DischargeEventStore {
  private readonly retentionMs: number;

  constructor(
    private readonly db: Database,
    private readonly options: { now: () => Date; retentionSeconds?: number },
  ) {
    this.db.exec(SCHEMA);
    this.retentionMs = (options.retentionSeconds ?? DEFAULT_DISCHARGE_EVENT_TTL_S) * 1000;
  }

  /** The recorded occurrence for this tuple, purging one past its retention. */
  find(key: DischargeEventKey): StoredDischargeEvent | undefined {
    const row = this.db
      .prepare(
        `SELECT * FROM discharge_events
         WHERE authority = ? AND mission_id = ? AND entry_digest = ? AND condition_digest = ?
           AND event_id = ?`,
      )
      .get(key.authority, key.missionId, key.entryDigest, key.conditionDigest, key.eventId) as
      | Record<string, unknown>
      | undefined;
    if (!row) return undefined;
    if (this.options.now().getTime() > (row.expires_at as number)) {
      this.purge(key);
      return undefined;
    }
    return {
      fingerprint: row.fingerprint as string,
      outcome: row.outcome as DischargeOutcome,
      priorVersion: row.prior_version as number,
      currentVersion: row.current_version as number,
    };
  }

  /**
   * Record one processed occurrence. NO OWN TRANSACTION: a caller committing a
   * latch MUST run this inside that same `withTransaction`, so the event row and
   * the latch commit as one unit; a caller recording a non-committing outcome
   * wraps it itself ({@link recordStandalone}).
   */
  recordInCallerTx(
    key: DischargeEventKey,
    fingerprint: string,
    result: DischargeResult,
    audit: DischargeEventAudit,
  ): void {
    const nowMs = this.options.now().getTime();
    this.db
      .prepare(
        `DELETE FROM discharge_events
         WHERE authority = ? AND mission_id = ? AND entry_digest = ? AND condition_digest = ?
           AND event_id = ? AND expires_at < ?`,
      )
      .run(key.authority, key.missionId, key.entryDigest, key.conditionDigest, key.eventId, nowMs);
    this.db
      .prepare(
        `INSERT INTO discharge_events (authority, mission_id, entry_digest, condition_digest,
         event_id, fingerprint, outcome, prior_version, current_version, received_at,
         evidence_ref, evidence_digest, observed_at, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT DO NOTHING`,
      )
      .run(
        key.authority,
        key.missionId,
        key.entryDigest,
        key.conditionDigest,
        key.eventId,
        fingerprint,
        result.outcome,
        result.prior_version,
        result.current_version,
        audit.receivedAt,
        audit.evidenceRef ?? null,
        audit.evidenceDigest ?? null,
        audit.observedAt ?? null,
        nowMs,
        nowMs + this.retentionMs,
      );
  }

  /** Record an occurrence that commits no latch (its own transaction). */
  recordStandalone(
    key: DischargeEventKey,
    fingerprint: string,
    result: DischargeResult,
    audit: DischargeEventAudit,
  ): void {
    withTransaction(this.db, () => this.recordInCallerTx(key, fingerprint, result, audit));
  }

  private purge(key: DischargeEventKey): void {
    this.db
      .prepare(
        `DELETE FROM discharge_events
         WHERE authority = ? AND mission_id = ? AND entry_digest = ? AND condition_digest = ?
           AND event_id = ?`,
      )
      .run(key.authority, key.missionId, key.entryDigest, key.conditionDigest, key.eventId);
  }
}
