/**
 * @spec draft-mcguinness-oauth-id-continuation-assertion-00 — the continuation
 * handle store.
 *
 * A continuation ANCHOR captures the root authentication envelope (auth_time,
 * acr, amr) of a Mission's delegation lineage. The envelope lives HERE, not on
 * MissionRecord, so no kernel schema migration is needed. An anchor is either
 * grant-anchored (durable, `session_id` null) or session-anchored (bound to a
 * session id, so it can be terminated when that session ends).
 *
 * A continuation HANDLE is a durable reference bound to an anchor and Mission.
 * A Chain Authority mints a handle for each intra-domain hop; the handle is
 * carried inside an ICA (see continuation-assertion.ts) and RESOLVED here to
 * recover the Mission, current actor, root auth envelope, and DPoP key. The
 * presented handle is NOT single-use: a hop record persists across
 * continuations, so `resolve` never consumes it.
 *
 * Terminal propagation: a Mission reaching a terminal lifecycle state
 * (`onLifecycleCommit`) marks all of its anchors and handles terminal; a
 * session ending (`terminateSession`) marks only its session-anchored anchors
 * and their handles terminal (grant anchors survive). A terminal handle OR
 * anchor makes `resolve` return undefined.
 *
 * Structure mirrors `DeferralStore` (SQLite via `openStore`), but holds no
 * kernel reference: every operation is self-contained local state and
 * `onLifecycleCommit` receives its event by value. That method is composed into
 * the AS lifecycle-commit fan-out by a LATER PR; it is not wired here.
 */

import { randomBytes } from "node:crypto";
import { type Database, openStore } from "@mission/store";
import { TERMINAL_STATES } from "./types.js";
import type { LifecycleCommit } from "./types.js";

const SCHEMA = `
CREATE TABLE continuation_anchors (
  anchor_id TEXT PRIMARY KEY,
  anchor_type TEXT NOT NULL,
  mission_id TEXT NOT NULL,
  session_id TEXT,
  auth_time INTEGER,
  acr TEXT,
  amr TEXT,
  state TEXT NOT NULL,
  created_at INTEGER NOT NULL
) STRICT;
CREATE TABLE continuation_handles (
  handle TEXT PRIMARY KEY,
  anchor_id TEXT NOT NULL,
  mission_id TEXT NOT NULL,
  actor_iss TEXT,
  actor_sub TEXT,
  cnf_jkt TEXT,
  prior_handle TEXT,
  state TEXT NOT NULL,
  created_at INTEGER NOT NULL
) STRICT;
`;

export type AnchorType = "grant" | "session";
export type ContinuationState = "active" | "terminal";

/** The root authentication envelope recorded on an anchor. */
export interface AuthEnvelope {
  authTime?: number;
  acr?: string;
  amr?: string[];
}

export interface ResolvedAnchor {
  anchorId: string;
  anchorType: AnchorType;
  missionId: string;
  sessionId?: string;
  state: ContinuationState;
}

export interface ResolvedContinuation {
  missionId: string;
  anchor: ResolvedAnchor;
  /** `mint` always writes both; optional only because the columns are nullable. */
  actor: { iss?: string; sub?: string };
  authEnvelope: AuthEnvelope;
  cnfJkt?: string;
}

interface AnchorRow {
  anchor_id: string;
  anchor_type: string;
  mission_id: string;
  session_id: string | null;
  auth_time: number | null;
  acr: string | null;
  amr: string | null;
  state: string;
}

interface HandleRow {
  handle: string;
  anchor_id: string;
  mission_id: string;
  actor_iss: string | null;
  actor_sub: string | null;
  cnf_jkt: string | null;
  state: string;
}

export class ContinuationStore {
  readonly db: Database;
  constructor(private readonly now: () => Date = () => new Date()) {
    this.db = openStore(SCHEMA);
  }

  /** A durable, grant-anchored root anchor (session_id null). */
  rootGrantAnchor(input: { missionId: string; authEnvelope: AuthEnvelope }): string {
    return this.insertAnchor("grant", input.missionId, null, input.authEnvelope);
  }

  /** A session-anchored root anchor, terminable when its session ends. */
  rootSessionAnchor(input: {
    missionId: string;
    sessionId: string;
    authEnvelope: AuthEnvelope;
  }): string {
    return this.insertAnchor("session", input.missionId, input.sessionId, input.authEnvelope);
  }

  private insertAnchor(
    type: AnchorType,
    missionId: string,
    sessionId: string | null,
    env: AuthEnvelope,
  ): string {
    const anchorId = `cta_${randomBytes(18).toString("base64url")}`;
    this.db
      .prepare(
        `INSERT INTO continuation_anchors
         (anchor_id, anchor_type, mission_id, session_id, auth_time, acr, amr, state, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?)`,
      )
      .run(
        anchorId,
        type,
        missionId,
        sessionId,
        env.authTime ?? null,
        env.acr ?? null,
        env.amr != null ? JSON.stringify(env.amr) : null,
        this.now().getTime(),
      );
    return anchorId;
  }

  /**
   * Mint a fresh continuation handle bound to an anchor and Mission. 144 bits
   * of entropy, base64url, within the ICA handle bounds (22-256 chars).
   */
  mint(input: {
    anchorId: string;
    missionId: string;
    actor: { iss: string; sub: string };
    /**
     * The confirmed-key thumbprint bound to this handle. OPTIONAL because the
     * INITIAL handle rooted at Mission approval has no DPoP key yet (a real
     * deployment supplies the root auth event's cnf; the demo omits it). This is
     * a type widening, not a behaviour change: every chained-hop caller still
     * passes a string and gets an identical row, and the four-signal check at
     * /token validates the PRESENTED key, never this stored value (`resolve`
     * already returns `cnfJkt` as optional).
     */
    cnfJkt?: string;
    priorHandle?: string;
  }): string {
    const handle = `ich_${randomBytes(18).toString("base64url")}`;
    this.db
      .prepare(
        `INSERT INTO continuation_handles
         (handle, anchor_id, mission_id, actor_iss, actor_sub, cnf_jkt, prior_handle, state, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?)`,
      )
      .run(
        handle,
        input.anchorId,
        input.missionId,
        input.actor.iss,
        input.actor.sub,
        input.cnfJkt ?? null,
        input.priorHandle ?? null,
        this.now().getTime(),
      );
    return handle;
  }

  /**
   * Resolve a presented handle. Returns undefined when the handle is unknown,
   * or when the handle or its anchor is terminal. Never consumes the handle.
   */
  resolve(handle: string): ResolvedContinuation | undefined {
    const h = this.db
      .prepare(
        "SELECT handle, anchor_id, mission_id, actor_iss, actor_sub, cnf_jkt, state FROM continuation_handles WHERE handle = ?",
      )
      .get(handle) as HandleRow | undefined;
    if (!h || h.state === "terminal") return undefined;
    const a = this.db
      .prepare(
        "SELECT anchor_id, anchor_type, mission_id, session_id, auth_time, acr, amr, state FROM continuation_anchors WHERE anchor_id = ?",
      )
      .get(h.anchor_id) as AnchorRow | undefined;
    if (!a || a.state === "terminal") return undefined;

    const authEnvelope: AuthEnvelope = {
      ...(a.auth_time != null ? { authTime: a.auth_time } : {}),
      ...(a.acr != null ? { acr: a.acr } : {}),
      ...(a.amr != null ? { amr: JSON.parse(a.amr) as string[] } : {}),
    };
    return {
      missionId: h.mission_id,
      anchor: {
        anchorId: a.anchor_id,
        anchorType: a.anchor_type as AnchorType,
        missionId: a.mission_id,
        ...(a.session_id != null ? { sessionId: a.session_id } : {}),
        state: a.state as ContinuationState,
      },
      actor: {
        ...(h.actor_iss != null ? { iss: h.actor_iss } : {}),
        ...(h.actor_sub != null ? { sub: h.actor_sub } : {}),
      },
      authEnvelope,
      ...(h.cnf_jkt != null ? { cnfJkt: h.cnf_jkt } : {}),
    };
  }

  /**
   * Read accessor: the handles minted for a Mission, ordered by mint time (ties
   * within the same millisecond are unordered). Additive and read-only (no state
   * change). Used by the AS assembly to (a) idempotency-guard approval-time
   * rooting (skip when a handle already exists for the Mission) and (b) let a
   * test/exhibit obtain the INITIAL handle an approval rooted (a Mission's first
   * handle, before any hop mints another, is unambiguous).
   */
  handlesForMission(missionId: string): string[] {
    const rows = this.db
      .prepare("SELECT handle FROM continuation_handles WHERE mission_id = ? ORDER BY created_at")
      .all(missionId) as Array<{ handle: string }>;
    return rows.map((r) => r.handle);
  }

  /**
   * Lifecycle fan-out target (wired by a later PR): when the committed Mission
   * transition is terminal, mark ALL anchors and handles for that Mission
   * terminal, so every continuation lineage rooted in it stops resolving.
   */
  onLifecycleCommit(commit: LifecycleCommit): void {
    if (!TERMINAL_STATES.has(commit.state)) return;
    this.db
      .prepare("UPDATE continuation_anchors SET state = 'terminal' WHERE mission_id = ?")
      .run(commit.id);
    this.db
      .prepare("UPDATE continuation_handles SET state = 'terminal' WHERE mission_id = ?")
      .run(commit.id);
  }

  /**
   * Terminate a session: mark session-anchored anchors for `sessionId` and
   * their handles terminal. Grant anchors (and their handles) are unaffected.
   */
  terminateSession(sessionId: string): void {
    this.db
      .prepare(
        `UPDATE continuation_handles SET state = 'terminal'
         WHERE anchor_id IN (
           SELECT anchor_id FROM continuation_anchors WHERE anchor_type = 'session' AND session_id = ?
         )`,
      )
      .run(sessionId);
    this.db
      .prepare(
        "UPDATE continuation_anchors SET state = 'terminal' WHERE anchor_type = 'session' AND session_id = ?",
      )
      .run(sessionId);
  }
}
