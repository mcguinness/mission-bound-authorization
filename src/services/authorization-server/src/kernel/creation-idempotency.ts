/**
 * @spec expansion#creation-idempotency (owner), child-delegation#creation-request-id,
 * continuation#transport-async
 *
 * The durable creation-idempotency store: `creation_request_id` identifies ONE
 * creation operation (child creation / expansion / async-delegation family
 * establishment) across all completion modes. The Mission Issuer durably binds the authenticated client, the
 * identifier, the semantic operation FINGERPRINT, and the resulting Mission or
 * continuation, ATOMICALLY with the creation decision; repetition recovers that
 * operation and never repeats Mission creation or its creation-side effects
 * (fan-out accounting, lifecycle events, evidence emission).
 *
 * The table lives in the KERNEL's own database (not a sibling `openStore`
 * database) so the reservation + created-Mission-id write shares ONE SQLite
 * transaction with `kernel.insertRecord` (nested `withTransaction` calls become
 * savepoints). Every instance constructed over the same kernel sees the same
 * table (CREATE TABLE IF NOT EXISTS), so no cross-module wiring is needed.
 *
 * Uniqueness is carried by the datastore PRIMARY KEY
 * `(client_id, creation_request_id)` — never by read-before-insert: a
 * concurrent duplicate surfaces as {@link UniqueViolationError} and the caller
 * re-reads the winning row.
 *
 * State machine: reserved -> completed | failed.
 *  - Synchronous child creation reserves + creates + completes in one
 *    transaction, so `reserved` is never observable for it (the crash window is
 *    closed: either nothing committed, or the completed operation is found and
 *    delivery resumes).
 *  - Deferred expansion reserves at initiation (delivery = the deferral handle)
 *    and completes atomically with successor creation at redemption.
 *  - Async-delegation interposes a FAMILY-CREATED stage, encoded as `reserved`
 *    with the family identity recorded in `delivery_json`
 *    ({@link advanceReserved}): reserved (no side effects yet) ->
 *    family-created (family exists, the single derivation counted, atomically)
 *    -> completed with the delivered response ({@link completeDelivered}). A
 *    retry finding family-created RESUMES delivery of the recorded family.
 *
 * Retention (two tiers): the delivery ARTIFACT (the child grant / access token)
 * expires on its own short lifetime; the idempotency TOMBSTONE (this row)
 * outlives it — `retentionSeconds`, default {@link DEFAULT_CREATION_TOMBSTONE_TTL_S},
 * the deployment's published retry horizon. A reuse of the identifier after
 * tombstone expiry is out of contract: the expired row is purged and the
 * identifier admits a fresh reservation.
 */

import {
  computeAnchor,
  type JsonValue,
  MISSION_CREATION_FINGERPRINT_TYP,
} from "@mission/core";
import { UniqueViolationError, withTransaction, type Database } from "@mission/store";
import type { MissionKernel } from "./kernel.js";
import type { AuthorityEntry, IntentSubmissionEvidenceEntry, MissionIntent } from "./types.js";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS creation_idempotency (
  client_id TEXT NOT NULL,
  creation_request_id TEXT NOT NULL,
  op TEXT NOT NULL,
  state TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  cnf_jkt TEXT NOT NULL,
  source_mission_id TEXT NOT NULL,
  mission_id TEXT,
  delivery_json TEXT,
  failure_json TEXT,
  created_at INTEGER NOT NULL,
  completed_at INTEGER,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (client_id, creation_request_id)
) STRICT;
`;

/**
 * Tombstone retention default (seconds): the published retry horizon. It
 * deliberately outlives every delivery artifact (the ~300s child grant, the
 * ~300s expansion access token, the 600s deferral lifetime).
 */
export const DEFAULT_CREATION_TOMBSTONE_TTL_S = 86400;

/** @spec expansion#creation-idempotency — bounded ASCII string, max 255 octets. */
export const CREATION_REQUEST_ID_MAX_OCTETS = 255;
const CREATION_REQUEST_ID_RE = /^[\x21-\x7e]{1,255}$/;

/** Syntax gate: non-empty visible-ASCII string of at most 255 octets. */
export function isValidCreationRequestId(v: unknown): v is string {
  return typeof v === "string" && CREATION_REQUEST_ID_RE.test(v);
}

/** The Mission-creating token exchanges plus the delegation-family-creating
 *  async-delegation exchange (domain separation member `op`). */
export type CreationOp = "child-creation" | "expansion" | "async-delegation";

/**
 * @spec expansion#creation-fingerprint — the EXACT typed fingerprint object.
 * JCS-canonicalized under the family anchor idiom (envelope
 * `{ typ: "mission-creation-fingerprint", iss, value }`, SHA-256,
 * `sha-256:`+base64url). Members:
 *  - `op`: `child-creation` | `expansion` (domain separation).
 *  - `iss`: the AS issuer.
 *  - `client`: the authenticated client identifier.
 *  - `source`: the RESOLVED parent/predecessor Mission identifier (from
 *    subject_token resolution) — never the raw subject_token, never the
 *    optional cross-check parameter alone.
 *  - `cnf`: the verified presenter confirmation (`{ jkt }` for DPoP; an mTLS
 *    binding would carry `{ "x5t#S256" }`).
 *  - `actor`: the verified acting-actor identity.
 *  - `intent`: the parsed semantic Mission Intent object (the `intent` member
 *    of the Submission envelope).
 *  - `proposal`: the parsed `authorization_details` array, when present.
 *  - `evidence`: the presented Intent Submission Evidence entries (canonical
 *    form: the parsed array, JCS-canonicalized with the rest of this object),
 *    when present — evidence affecting admission, derivation, approval, or
 *    side effects MUST be included, so the same `creation_request_id` with
 *    different evidence is a fingerprint MISMATCH, never a silent replay
 *    (@spec mission#intent-submission-evidence).
 *  - `child_actor`: child-creation only.
 *  - `requested_token_type`.
 *  - `cross_check`: the supplied `parent`/`predecessor` value, when present.
 * EXCLUDED (attempt-specific): the DPoP proof serialization/jti, the client
 * authentication assertion, the raw subject_token serialization, and
 * `creation_request_id` itself.
 * Extension rule: a new parameter affecting authorization, derivation,
 * approval, output, or side effects of the creation MUST extend this object.
 */
export interface MissionCreationFingerprintInput {
  op: "child-creation" | "expansion";
  iss: string;
  client: string;
  source: string;
  cnf: { jkt: string };
  actor: { iss: string; sub: string };
  intent: MissionIntent;
  proposal?: AuthorityEntry[];
  evidence?: IntentSubmissionEvidenceEntry[];
  child_actor?: { sub: string; iss?: string; sub_profile?: string };
  requested_token_type: string;
  cross_check?: string;
}

/**
 * @spec continuation#transport-async — the async-delegation exchange's
 * fingerprint (same anchor idiom, same `typ`). Members:
 *  - `op`: `async-delegation`.
 *  - `iss` / `client`: as the expansion profile defines them.
 *  - `source`: the RESOLVED base Mission identifier (from subject_token
 *    resolution) — never the raw subject_token.
 *  - `cnf`: the ACTING client's verified confirmation — this exchange
 *    deliberately re-binds the family to the acting key rather than proving
 *    possession of the subject token's own confirmation.
 *  - `proposal`: the parsed `authorization_details` array naming the requested
 *    confined subset, when present.
 *  - `resource`: the target the family is audienced to.
 *  - `request_refresh_token`: the parameter selecting this exchange.
 */
export interface AsyncDelegationFingerprintInput {
  op: "async-delegation";
  iss: string;
  client: string;
  source: string;
  cnf: { jkt: string };
  proposal?: AuthorityEntry[];
  resource: string;
  request_refresh_token: true;
}

export type CreationFingerprintInput =
  | MissionCreationFingerprintInput
  | AsyncDelegationFingerprintInput;

export function creationFingerprint(input: CreationFingerprintInput): string {
  if (input.op === "async-delegation") {
    const value = {
      op: input.op,
      iss: input.iss,
      client: input.client,
      source: input.source,
      cnf: input.cnf,
      ...(input.proposal ? { proposal: input.proposal } : {}),
      resource: input.resource,
      request_refresh_token: true,
    };
    return computeAnchor(MISSION_CREATION_FINGERPRINT_TYP, input.iss, value as unknown as JsonValue);
  }
  const value = {
    op: input.op,
    iss: input.iss,
    client: input.client,
    source: input.source,
    cnf: input.cnf,
    actor: input.actor,
    intent: input.intent,
    ...(input.proposal ? { proposal: input.proposal } : {}),
    ...(input.evidence ? { evidence: input.evidence } : {}),
    ...(input.child_actor
      ? {
          child_actor: {
            sub: input.child_actor.sub,
            ...(input.child_actor.iss !== undefined ? { iss: input.child_actor.iss } : {}),
            ...(input.child_actor.sub_profile !== undefined
              ? { sub_profile: input.child_actor.sub_profile }
              : {}),
          },
        }
      : {}),
    requested_token_type: input.requested_token_type,
    ...(input.cross_check !== undefined ? { cross_check: input.cross_check } : {}),
  };
  return computeAnchor(MISSION_CREATION_FINGERPRINT_TYP, input.iss, value as unknown as JsonValue);
}

/** The reservation identity + recorded security context. */
export interface CreationReservation {
  clientId: string;
  creationRequestId: string;
  op: CreationOp;
  fingerprint: string;
  /** The verified presenter confirmation recorded for recovery revalidation. */
  cnfJkt: string;
  /** The RESOLVED source (parent/predecessor) Mission identifier. */
  sourceMissionId: string;
  /** Initial delivery metadata (e.g. the deferral handle), when known at reserve time. */
  delivery?: Record<string, unknown>;
}

/** A recorded failure outcome, replayed verbatim on a matching retry. */
export interface CreationFailure {
  status: number;
  body: Record<string, unknown>;
}

/** A stored creation operation (tombstone row, parsed). */
export interface CreationOperation {
  clientId: string;
  creationRequestId: string;
  op: CreationOp;
  state: "reserved" | "completed" | "failed";
  fingerprint: string;
  cnfJkt: string;
  sourceMissionId: string;
  missionId?: string;
  delivery?: Record<string, unknown>;
  failure?: CreationFailure;
  createdAt: number;
  expiresAt: number;
}

export class CreationIdempotencyStore {
  private readonly db: Database;
  private readonly now: () => Date;
  private readonly retentionMs: number;

  constructor(
    kernel: MissionKernel,
    options: { retentionSeconds?: number; now?: () => Date } = {},
  ) {
    // The KERNEL's database: reservation + Mission INSERT share one transaction.
    this.db = kernel.db;
    this.db.exec(SCHEMA);
    this.now = options.now ?? (() => kernel.nowDate());
    this.retentionMs = (options.retentionSeconds ?? DEFAULT_CREATION_TOMBSTONE_TTL_S) * 1000;
  }

  /**
   * Look up the operation bound to `(clientId, creationRequestId)`. A row past
   * its tombstone expiry is out of contract: it is treated as absent (and
   * purged), so the identifier admits a fresh reservation.
   */
  find(clientId: string, creationRequestId: string): CreationOperation | undefined {
    const row = this.db
      .prepare("SELECT * FROM creation_idempotency WHERE client_id = ? AND creation_request_id = ?")
      .get(clientId, creationRequestId) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    if (this.now().getTime() > (row.expires_at as number)) {
      this.db
        .prepare("DELETE FROM creation_idempotency WHERE client_id = ? AND creation_request_id = ?")
        .run(clientId, creationRequestId);
      return undefined;
    }
    return {
      clientId: row.client_id as string,
      creationRequestId: row.creation_request_id as string,
      op: row.op as CreationOp,
      state: row.state as CreationOperation["state"],
      fingerprint: row.fingerprint as string,
      cnfJkt: row.cnf_jkt as string,
      sourceMissionId: row.source_mission_id as string,
      ...(row.mission_id ? { missionId: row.mission_id as string } : {}),
      ...(row.delivery_json
        ? { delivery: JSON.parse(row.delivery_json as string) as Record<string, unknown> }
        : {}),
      ...(row.failure_json
        ? { failure: JSON.parse(row.failure_json as string) as CreationFailure }
        : {}),
      createdAt: row.created_at as number,
      expiresAt: row.expires_at as number,
    };
  }

  /** Bare INSERT (state as given); the caller controls the transaction. An
   *  expired tombstone under the same key is purged first (reuse after the
   *  horizon is out of contract, so the identifier is simply free again). */
  private insertRow(res: CreationReservation, state: "reserved" | "failed", failure?: CreationFailure): void {
    const nowMs = this.now().getTime();
    this.db
      .prepare("DELETE FROM creation_idempotency WHERE client_id = ? AND creation_request_id = ? AND expires_at < ?")
      .run(res.clientId, res.creationRequestId, nowMs);
    this.db
      .prepare(
        `INSERT INTO creation_idempotency (client_id, creation_request_id, op, state, fingerprint,
         cnf_jkt, source_mission_id, mission_id, delivery_json, failure_json, created_at, completed_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, NULL, ?)`,
      )
      .run(
        res.clientId,
        res.creationRequestId,
        res.op,
        state,
        res.fingerprint,
        res.cnfJkt,
        res.sourceMissionId,
        res.delivery ? JSON.stringify(res.delivery) : null,
        failure ? JSON.stringify(failure) : null,
        nowMs,
        nowMs + this.retentionMs,
      );
  }

  /**
   * The SYNCHRONOUS-creation funnel: reserve, run `create` (which inserts the
   * Mission via `kernel.insertRecord` — a savepoint inside this transaction),
   * and mark completed with the created Mission id, all in ONE transaction.
   * Credential generation happens AFTER (a crash between commit and delivery is
   * recovered by the retry finding the completed operation).
   * A concurrent duplicate reservation throws {@link UniqueViolationError};
   * the caller re-reads the winning row and recovers.
   */
  createCompleted<T>(
    res: CreationReservation,
    create: () => { missionId: string; value: T },
  ): T {
    return withTransaction(this.db, () => {
      this.insertRow(res, "reserved");
      // NOTE: insertRecord's lifecycle-commit hook fires inside this outer
      // transaction (its own withTransaction nests as a savepoint). That is
      // safe because the only statement after create() is the completion
      // UPDATE of the row inserted above, which cannot hit a constraint — the
      // transaction cannot fail after the hook has fanned out.
      const { missionId, value } = create();
      this.db
        .prepare(
          "UPDATE creation_idempotency SET state = 'completed', mission_id = ?, completed_at = ? WHERE client_id = ? AND creation_request_id = ?",
        )
        .run(missionId, this.now().getTime(), res.clientId, res.creationRequestId);
      return value;
    });
  }

  /**
   * Reserve without creating (deferred expansion initiation: the deferral
   * handle is the recorded delivery metadata; the creation completes at
   * redemption via {@link completeInCallerTx}). Throws
   * {@link UniqueViolationError} on a concurrent duplicate.
   */
  reserve(res: CreationReservation): void {
    withTransaction(this.db, () => this.insertRow(res, "reserved"));
  }

  /**
   * @spec continuation#transport-async — advance a `reserved` operation to
   * FAMILY-CREATED: record the created family's identity (`delivery`) on the
   * reservation, atomically with the caller's creation-side accounting
   * (`accompany`, e.g. the single gateDerivation, runs inside the same
   * kernel-db transaction; its throw rolls the whole transition back and the
   * reservation stays plain `reserved`).
   */
  advanceReserved(
    clientId: string,
    creationRequestId: string,
    delivery: Record<string, unknown>,
    accompany?: () => void,
  ): void {
    withTransaction(this.db, () => {
      accompany?.();
      this.db
        .prepare(
          "UPDATE creation_idempotency SET delivery_json = ? WHERE client_id = ? AND creation_request_id = ? AND state = 'reserved'",
        )
        .run(JSON.stringify(delivery), clientId, creationRequestId);
    });
  }

  /**
   * Mark a `reserved` operation FAILED in place (a definitive refusal after
   * the reservation was acquired, e.g. a derivation-gate rejection), replayed
   * verbatim on a matching retry.
   */
  failReserved(clientId: string, creationRequestId: string, failure: CreationFailure): void {
    this.db
      .prepare(
        "UPDATE creation_idempotency SET state = 'failed', failure_json = ?, completed_at = ? WHERE client_id = ? AND creation_request_id = ? AND state = 'reserved'",
      )
      .run(JSON.stringify(failure), this.now().getTime(), clientId, creationRequestId);
  }

  /**
   * @spec continuation#transport-async — mark an operation COMPLETED with its
   * delivered response (the stable outcome + the delivery artifact in one
   * UPDATE). Used at delivery time, after the family-created stage.
   */
  completeDelivered(
    clientId: string,
    creationRequestId: string,
    missionId: string,
    delivery: Record<string, unknown>,
  ): void {
    this.db
      .prepare(
        "UPDATE creation_idempotency SET state = 'completed', mission_id = ?, delivery_json = ?, completed_at = ? WHERE client_id = ? AND creation_request_id = ?",
      )
      .run(missionId, JSON.stringify(delivery), this.now().getTime(), clientId, creationRequestId);
  }

  /**
   * Mark a reserved operation completed with the created Mission id. NO OWN
   * TRANSACTION: the caller MUST run this inside the same `withTransaction`
   * (on the kernel database) that inserts the Mission, so reservation state and
   * Mission creation commit atomically.
   */
  completeInCallerTx(clientId: string, creationRequestId: string, missionId: string): void {
    this.db
      .prepare(
        "UPDATE creation_idempotency SET state = 'completed', mission_id = ?, completed_at = ? WHERE client_id = ? AND creation_request_id = ?",
      )
      .run(missionId, this.now().getTime(), clientId, creationRequestId);
  }

  /**
   * Record a definitive creation REFUSAL (state `failed`), replayed verbatim on
   * a matching retry. A concurrent duplicate is ignored (the winning row is
   * authoritative).
   */
  recordFailure(res: CreationReservation, failure: CreationFailure): void {
    try {
      withTransaction(this.db, () => this.insertRow(res, "failed", failure));
    } catch (e) {
      if (e instanceof UniqueViolationError) return;
      throw e;
    }
  }

  /**
   * Attach/refresh the delivery-artifact metadata of a completed operation
   * (tier-(a) retention: the artifact reference MAY be short-lived; the
   * tombstone row outlives it and a recovery past artifact expiry re-mints).
   */
  recordDelivery(clientId: string, creationRequestId: string, delivery: Record<string, unknown>): void {
    this.db
      .prepare(
        "UPDATE creation_idempotency SET delivery_json = ? WHERE client_id = ? AND creation_request_id = ?",
      )
      .run(JSON.stringify(delivery), clientId, creationRequestId);
  }
}
