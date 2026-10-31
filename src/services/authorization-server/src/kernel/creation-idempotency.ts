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
 * the deployment's published retry horizon.
 * @spec mission#approval-idempotency (#1915, D1056): the horizon starts when the
 * key is reserved (`created_at`) and the key is retained through `expires_at`
 * inclusive, fixed at reservation, so a later retention change never shortens
 * it. A `reserved` operation still pending at that boundary keeps its key until
 * it ends (`pending_until`, a deferral's own lifetime), so a lapsed horizon
 * never frees the key of a live operation. A reuse after both is a NEW
 * operation: the expired row is purged and the identifier admits a fresh
 * reservation, judged on current state.
 */

import {
  computeAnchor,
  type JsonValue,
  MISSION_CREATION_FINGERPRINT_TYP,
} from "@mission/core";
import { UniqueViolationError, withTransaction, type Database } from "@mission/store";
import { DEFERRAL_EXPIRES_IN } from "./deferral-lifetime.js";
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
  pending_until INTEGER,
  PRIMARY KEY (client_id, creation_request_id)
) STRICT;
`;

/**
 * A row is retained (found, and never purged) through its horizon, and while a
 * `reserved` operation it names is still pending. Both bounds are inclusive.
 */
const RETAINED = "(expires_at >= ? OR (state = 'reserved' AND pending_until IS NOT NULL AND pending_until >= ?))";

/**
 * Tombstone retention default (seconds): the published retry horizon. It
 * deliberately outlives every delivery artifact (the ~300s child grant, the
 * ~300s expansion access token, the 600s deferral lifetime).
 */
export const DEFAULT_CREATION_TOMBSTONE_TTL_S = 86400;

/** @spec expansion#submission — bounded ASCII string, max 255 octets. */
export const CREATION_REQUEST_ID_MAX_OCTETS = 255;
const CREATION_REQUEST_ID_RE = /^[\x21-\x7e]{1,255}$/;

/** Syntax gate: non-empty visible-ASCII string of at most 255 octets. */
export function isValidCreationRequestId(v: unknown): v is string {
  return typeof v === "string" && CREATION_REQUEST_ID_RE.test(v);
}

/** The Mission-creating token exchanges, the delegation-family-creating
 *  async-delegation exchange, and the template Dispatch grant (domain
 *  separation member `op`). */
export type CreationOp = "child-creation" | "expansion" | "async-delegation" | "dispatch";

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
 *  - `actor`: the verified `actor_token`'s `iss` and `sub`; absent where
 *    client authentication alone identifies the acting agent (#1177).
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
  actor?: { iss: string; sub: string };
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
 *  - `cnf`: the acting client's verified confirmation, which is the delegation
 *    handle's own key: the exchange proves possession of it (#1157).
 *  - `proposal`: the parsed `authorization_details` array naming the requested
 *    confined subset, when present.
 *  - `resource`: the target the family is audienced to.
 *  - `request_refresh_token`: the parameter selecting this exchange.
 *  - `scope` (@spec mission#scope-projection): the requested `scope`,
 *    normalized as its value set, sorted and space-separated, empty when
 *    absent. It changes the outcome (projection, narrowing, `invalid_scope`),
 *    so a retry naming a different set is a different request.
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
  scope: string;
}

/**
 * @spec mission-template#dispatch — the Dispatch grant's fingerprint (same
 * anchor idiom, same `typ`), adopting the expansion profile's apparatus under
 * its own `op`. Members:
 *  - `op`: `dispatch`.
 *  - `iss` / `client`: as the expansion profile defines them; `client` is the
 *    authenticated Dispatcher.
 *  - `source`: the Dispatch's `template_id` (a Dispatch has no source Mission).
 *  - `cnf`: the Dispatcher's verified presenter confirmation.
 *  - `intent` / `evidence`: the parsed Submission envelope's members.
 *  - `proposal`: the parsed `authorization_details` array, when present.
 * `actor`, `child_actor`, `requested_token_type` and `cross_check` are absent.
 */
export interface DispatchFingerprintInput {
  op: "dispatch";
  iss: string;
  client: string;
  source: string;
  cnf: { jkt: string };
  intent: MissionIntent;
  proposal?: AuthorityEntry[];
  evidence?: IntentSubmissionEvidenceEntry[];
}

/** A `scope` parameter as its normalized value set: deduplicated, sorted, space-separated. */
export function normalizedScope(value: unknown): string {
  if (typeof value !== "string") return "";
  return [...new Set(value.split(" ").filter(Boolean))].sort().join(" ");
}

export type CreationFingerprintInput =
  | MissionCreationFingerprintInput
  | AsyncDelegationFingerprintInput
  | DispatchFingerprintInput;

export function creationFingerprint(input: CreationFingerprintInput): string {
  if (input.op === "dispatch") {
    const value = {
      op: input.op,
      iss: input.iss,
      client: input.client,
      source: input.source,
      cnf: input.cnf,
      intent: input.intent,
      ...(input.proposal ? { proposal: input.proposal } : {}),
      ...(input.evidence ? { evidence: input.evidence } : {}),
    };
    return computeAnchor(MISSION_CREATION_FINGERPRINT_TYP, input.iss, value as unknown as JsonValue);
  }
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
      scope: input.scope,
    };
    return computeAnchor(MISSION_CREATION_FINGERPRINT_TYP, input.iss, value as unknown as JsonValue);
  }
  const value = {
    op: input.op,
    iss: input.iss,
    client: input.client,
    source: input.source,
    cnf: input.cnf,
    ...(input.actor ? { actor: input.actor } : {}),
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
  /** The RESOLVED source: the parent/predecessor Mission identifier, or a
   *  Dispatch's `template_id`. */
  sourceMissionId: string;
  /** Initial delivery metadata (e.g. the deferral handle), when known at reserve time. */
  delivery?: Record<string, unknown>;
  /**
   * The instant (ms) a reserved operation that completes later stops being
   * pending (a deferral's lifetime): the key stays bound to it until then,
   * whatever the horizon.
   */
  pendingUntil?: number;
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

/**
 * @spec expansion#creation-retention (#1915 review): a deferred Expansion
 * reserved before `pending_until` existed keeps its key while its deferral
 * lives. Its `pending_until` is filled from the deferral it names (created_at
 * plus the deferral lifetime), so an upgrade never frees the key of a live
 * operation. Idempotent: only a `reserved` row with no `pending_until` that
 * names a deferral is touched, and only where the deferral table exists.
 */
function backfillPendingUntil(db: Database): void {
  const deferrals = db
    .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'expansion_deferrals'")
    .get();
  if (!deferrals) return;
  db.prepare(
    `UPDATE creation_idempotency SET pending_until = (
       SELECT d.created_at + ? FROM expansion_deferrals d
       WHERE d.deferral_code = json_extract(creation_idempotency.delivery_json, '$.deferral_code'))
     WHERE state = 'reserved' AND pending_until IS NULL
       AND json_extract(delivery_json, '$.deferral_code') IS NOT NULL`,
  ).run(DEFERRAL_EXPIRES_IN * 1000);
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
    const columns = new Set(
      (this.db.prepare("PRAGMA table_info(creation_idempotency)").all() as Array<{ name: string }>).map((c) => c.name),
    );
    if (!columns.has("pending_until")) this.db.exec("ALTER TABLE creation_idempotency ADD COLUMN pending_until INTEGER");
    backfillPendingUntil(this.db);
    this.now = options.now ?? (() => kernel.nowDate());
    this.retentionMs = (options.retentionSeconds ?? DEFAULT_CREATION_TOMBSTONE_TTL_S) * 1000;
  }

  /**
   * Look up the operation bound to `(clientId, creationRequestId)`. A row no
   * longer retained ({@link RETAINED}) is treated as absent (and purged), so
   * the identifier admits a fresh reservation.
   */
  find(clientId: string, creationRequestId: string): CreationOperation | undefined {
    const row = this.db
      .prepare("SELECT * FROM creation_idempotency WHERE client_id = ? AND creation_request_id = ?")
      .get(clientId, creationRequestId) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    if (this.purgeLapsed(clientId, creationRequestId)) return undefined;
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

  /**
   * @spec child-delegation#request-processing step 4 (#1326): every retained,
   * completed child creation, with the client that requested it. The child
   * record names no creating client, so this is the only stored link from a
   * child to the client that created it; an operation purged here is gone.
   */
  retainedChildCreations(): Array<{ clientId: string; parentId: string; childId: string }> {
    const rows = this.db
      .prepare(
        "SELECT client_id, source_mission_id, mission_id FROM creation_idempotency WHERE op = 'child-creation' AND state = 'completed' AND mission_id IS NOT NULL",
      )
      .all() as Array<{ client_id: string; source_mission_id: string; mission_id: string }>;
    return rows.map((r) => ({ clientId: r.client_id, parentId: r.source_mission_id, childId: r.mission_id }));
  }

  /** Delete the row under the key when it is no longer retained; true when one was deleted. */
  private purgeLapsed(clientId: string, creationRequestId: string): boolean {
    const nowMs = this.now().getTime();
    return (
      this.db
        .prepare(`DELETE FROM creation_idempotency WHERE client_id = ? AND creation_request_id = ? AND NOT ${RETAINED}`)
        .run(clientId, creationRequestId, nowMs, nowMs).changes > 0
    );
  }

  /** Bare INSERT (state as given); the caller controls the transaction. A
   *  lapsed tombstone under the same key is purged first (a reuse after it is
   *  a new operation); a retained one makes the INSERT a uniqueness violation. */
  private insertRow(res: CreationReservation, state: "reserved" | "failed", failure?: CreationFailure): void {
    const nowMs = this.now().getTime();
    this.purgeLapsed(res.clientId, res.creationRequestId);
    this.db
      .prepare(
        `INSERT INTO creation_idempotency (client_id, creation_request_id, op, state, fingerprint,
         cnf_jkt, source_mission_id, mission_id, delivery_json, failure_json, created_at, completed_at, expires_at,
         pending_until)
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, NULL, ?, ?)`,
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
        res.pendingUntil ?? null,
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
      // @spec control-plane#serialization — insertRecord's lifecycle-commit
      // hook is captured inside this outer transaction (its own
      // withTransaction nests as a savepoint) and published only after the
      // OUTERMOST commit, so nothing is fanned out for a reservation this
      // transaction rolls back.
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
   * @spec mission#approval-idempotency (#1915, D1056): only the reservation the
   * completing operation made is completed, the one still `reserved` under the
   * key and, for a deferral, naming its handle. A row another operation holds
   * under the key is never bound to this Mission.
   */
  completeInCallerTx(clientId: string, creationRequestId: string, missionId: string, deferralCode?: string): void {
    this.db
      .prepare(
        `UPDATE creation_idempotency SET state = 'completed', mission_id = ?, completed_at = ?
         WHERE client_id = ? AND creation_request_id = ? AND state = 'reserved'${
           deferralCode === undefined ? "" : " AND json_extract(delivery_json, '$.deferral_code') = ?"
         }`,
      )
      .run(missionId, this.now().getTime(), clientId, creationRequestId, ...(deferralCode === undefined ? [] : [deferralCode]));
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
