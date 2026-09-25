/**
 * @spec status#idempotency, discharge#discharge-idempotency
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
 * and version increment it records (@spec discharge#discharge-operation,
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
  state TEXT NOT NULL DEFAULT 'final',
  material_json TEXT,
  response_valid_until INTEGER,
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
 * @spec status#idempotency — the replay window. ONE clock governs the whole
 * window: a byte-identical retransmit MUST replay the original response, and
 * the same nonce with a different request MUST be refused `invalid_request`,
 * for as long as the window lasts. The window MUST be at least the validity
 * span of the signed response the AS would replay (its `iat` to `exp`, 60s
 * here) and MAY be longer; ten minutes is this deployment's choice.
 *
 * A retained response is therefore NOT cut off at its own validity (issue #250,
 * owner review). Replaying a retained acknowledgement of a completed operation
 * and making a fresh observation are separate concerns: the acknowledgement is
 * historical by construction, and the envelope's own `exp` already tells its
 * consumer it is not a fresh observation. Cutting the replay off at 60s inside
 * a 600s window would re-execute a retransmit the profile says MUST replay.
 */
export const DEFAULT_LIFECYCLE_NONCE_TTL_S = 600;

/**
 * @spec discharge#discharge-idempotency ("Retention") — event-dedup state is
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

/**
 * @spec control-plane#serialization, control-plane#fresh-observation — THE
 * SIGNING BOUNDARY.
 *
 * A response the endpoint must be able to replay cannot be written in the
 * transition transaction, because signing and serialization are asynchronous
 * and a synchronous `withTransaction` cannot span them. What CAN commit with
 * the transition is the nonce claim, the committed outcome, and enough
 * IMMUTABLE MATERIAL to reproduce the response afterwards. So the retention is
 * two-phase:
 *
 *  1. `committed` - written by {@link LifecycleResponseStore.claimInCallerTx}
 *     inside the transition transaction. The nonce is claimed, the outcome is
 *     durable, and the material is fixed. A crash here loses only the bytes.
 *  2. `final` - written by {@link LifecycleResponseStore.record} once the exact
 *     bytes exist, BEFORE they are handed to the network.
 *
 * A retransmission that finds a `final` row is served THOSE EXACT BYTES: the
 * profile says the original response, and re-signing an ECDSA envelope yields
 * different bytes every time. Only a `committed` row, the crash case where
 * finalization never happened, is reproduced from its retained material, and
 * for a signed envelope that means the recorded observation is signed again:
 * the payload, including its `iat` and `exp`, is the ORIGINAL observation's, so
 * recovery never re-dates it.
 */
export type LifecycleResponseState = "committed" | "final";

/**
 * The immutable material a committed outcome is reproducible from: either the
 * exact response members of a JSON outcome, or a signed state observation
 * captured at its observation point.
 */
export type LifecycleResponseMaterial =
  | { kind: "json"; body: Record<string, unknown> }
  | { kind: "status-observation"; observation: Record<string, unknown> };

/** A retained response: claimed and reproducible, or finalized and verbatim. */
export interface RetainedLifecycleResponse {
  state: LifecycleResponseState;
  requestDigest: string;
  status: number;
  contentType: string;
  /** The exact bytes; present only for `final`. */
  body?: string;
  /** The material a `committed` row is finalized from. */
  material?: LifecycleResponseMaterial;
}

export class LifecycleResponseStore {
  private readonly retentionMs: number;

  constructor(
    private readonly db: Database,
    private readonly options: { now: () => Date; retentionSeconds?: number },
  ) {
    this.db.exec(SCHEMA);
    migrateLifecycleResponses(this.db);
    this.retentionMs = (options.retentionSeconds ?? DEFAULT_LIFECYCLE_NONCE_TTL_S) * 1000;
  }

  /**
   * The response stored for this nonce, or undefined when none is live. A row
   * past its window is out of contract: it is purged, so the nonce is free.
   *
   * @spec status#idempotency — ONE clock, the nonce window. A retained response
   * is replayable for the whole of it, whatever validity the response itself
   * carries: the profile requires the ORIGINAL response on a byte-identical
   * retransmit, and the window is required to be at least that validity span
   * and permitted to be longer. A replayed acknowledgement is a historical
   * record of a completed operation, not a fresh observation, and a signed
   * envelope's own `exp` says so to its consumer.
   */
  find(key: LifecycleNonceKey): RetainedLifecycleResponse | undefined {
    const row = this.row(key);
    if (!row) return undefined;
    if (this.options.now().getTime() > (row.expires_at as number)) {
      this.purge(key);
      return undefined;
    }
    return toRetained(row);
  }

  /**
   * @spec control-plane#serialization — CLAIM the nonce and the committed
   * outcome INSIDE the transition transaction. NO OWN TRANSACTION: the caller
   * MUST hold the transaction that commits the operation, so the nonce claim
   * and its side effect are one atomic domain and a committed operation always
   * leaves a replayable record behind.
   *
   * FIRST WRITER WINS, decided by the datastore: a losing claim re-reads the
   * winning row and returns it, so a divergent retry still refuses on the
   * original request digest.
   */
  claimInCallerTx(
    key: LifecycleNonceKey,
    claim: {
      requestDigest: string;
      status: number;
      contentType: string;
      material: LifecycleResponseMaterial;
      /**
       * @spec status#idempotency — the response's own validity end, in epoch
       * ms; signed envelopes only. It is NOT a replay cutoff: it is the FLOOR
       * the nonce window must clear, because the profile requires a window at
       * least as long as the validity span of the response the AS would replay.
       * Recorded with the row, and honoured below.
       */
      responseValidUntil?: number;
    },
  ): RetainedLifecycleResponse {
    const nowMs = this.options.now().getTime();
    // The window is the deployment's retention, never shorter than the
    // response's own validity span: a deployment configured below that floor
    // would free the nonce while the response it must replay is still live.
    const expiresAt = Math.max(nowMs + this.retentionMs, claim.responseValidUntil ?? 0);
    this.db
      .prepare(
        `DELETE FROM lifecycle_responses
         WHERE endpoint = ? AND principal = ? AND mission_id = ? AND nonce = ? AND expires_at < ?`,
      )
      .run(key.endpoint, key.principal, key.missionId, key.nonce, nowMs);
    this.db
      .prepare(
        `INSERT INTO lifecycle_responses (endpoint, principal, mission_id, nonce, request_digest,
         status, content_type, body, created_at, expires_at, state, material_json, response_valid_until)
         VALUES (?, ?, ?, ?, ?, ?, ?, '', ?, ?, 'committed', ?, ?)
         ON CONFLICT DO NOTHING`,
      )
      .run(
        key.endpoint,
        key.principal,
        key.missionId,
        key.nonce,
        claim.requestDigest,
        claim.status,
        claim.contentType,
        nowMs,
        expiresAt,
        JSON.stringify(claim.material),
        claim.responseValidUntil ?? null,
      );
    const row = this.row(key);
    if (!row) throw new Error("lifecycle response claim vanished");
    return toRetained(row);
  }

  /**
   * Retain the exact bytes this exchange produced, BEFORE they are delivered.
   *
   * A row THIS EXCHANGE claimed is FINALIZED (the bytes fill in the committed
   * outcome). Otherwise this is an unclaimed response, typically a refusal that
   * committed nothing, and first writer wins: the PK conflict is ignored so a
   * later refusal never overwrites the response a retransmission has to replay.
   *
   * "This exchange" is what `request_digest` decides (issue #250, owner
   * review). Matching on the committed STATE alone let another exchange's
   * bytes land in this exchange's claim: while the original response was still
   * being signed, a divergent retry's `400 invalid_request` finalized the
   * committed row and became the response retained for that nonce, destroying a
   * success that had already committed. The guard names BOTH the committed
   * state and the request digest the claim was made under, so only the exchange
   * that claimed the row can finalize it.
   */
  record(key: LifecycleNonceKey, response: StoredLifecycleResponse): void {
    const finalized = this.db
      .prepare(
        `UPDATE lifecycle_responses
         SET body = ?, status = ?, content_type = ?, state = 'final'
         WHERE endpoint = ? AND principal = ? AND mission_id = ? AND nonce = ?
           AND state = 'committed' AND request_digest = ?`,
      )
      .run(
        response.body,
        response.status,
        response.contentType,
        key.endpoint,
        key.principal,
        key.missionId,
        key.nonce,
        response.requestDigest,
      );
    if (finalized.changes === 1) return;
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
         status, content_type, body, created_at, expires_at, state)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'final')
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

  private row(key: LifecycleNonceKey): Record<string, unknown> | undefined {
    return this.db
      .prepare(
        `SELECT * FROM lifecycle_responses
         WHERE endpoint = ? AND principal = ? AND mission_id = ? AND nonce = ?`,
      )
      .get(key.endpoint, key.principal, key.missionId, key.nonce) as
      | Record<string, unknown>
      | undefined;
  }

  private purge(key: LifecycleNonceKey): void {
    this.db
      .prepare(
        `DELETE FROM lifecycle_responses
         WHERE endpoint = ? AND principal = ? AND mission_id = ? AND nonce = ?`,
      )
      .run(key.endpoint, key.principal, key.missionId, key.nonce);
  }
}

function toRetained(row: Record<string, unknown>): RetainedLifecycleResponse {
  const state = (row.state as LifecycleResponseState) ?? "final";
  const material = row.material_json
    ? (JSON.parse(row.material_json as string) as LifecycleResponseMaterial)
    : undefined;
  return {
    state,
    requestDigest: row.request_digest as string,
    status: row.status as number,
    contentType: row.content_type as string,
    ...(state === "final" ? { body: row.body as string } : {}),
    ...(material ? { material } : {}),
  };
}

/**
 * The two-phase retention columns are additive, and `openStore` only ever runs
 * `CREATE TABLE IF NOT EXISTS`, so a kernel database that predates them (a
 * file-backed store opened again) is migrated here. The Mission Signals outbox
 * sets the precedent for an idempotent in-place migration.
 */
function migrateLifecycleResponses(db: Database): void {
  const columns = new Set(
    (db.prepare("PRAGMA table_info(lifecycle_responses)").all() as Array<{ name: string }>).map(
      (c) => c.name,
    ),
  );
  if (!columns.has("state")) {
    db.exec("ALTER TABLE lifecycle_responses ADD COLUMN state TEXT NOT NULL DEFAULT 'final'");
  }
  if (!columns.has("material_json")) {
    db.exec("ALTER TABLE lifecycle_responses ADD COLUMN material_json TEXT");
  }
  if (!columns.has("response_valid_until")) {
    db.exec("ALTER TABLE lifecycle_responses ADD COLUMN response_valid_until INTEGER");
  }
}

/**
 * @spec discharge#discharge-idempotency — the five-part event tuple: the
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
 * @spec discharge#discharge-operation — the audit members that ride the recorded
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
