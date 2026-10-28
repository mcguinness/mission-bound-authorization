import { randomBytes } from "node:crypto";
import { type Database, openDurableStore } from "@mission/store";

/** The two native mission states (AAuth -11 Section 8.6). */
export type MissionState = "active" | "terminated";

/** A mission this PS approved, with the exact blob bytes it persisted. */
export interface MissionRecord {
  agent: string;
  s256: string;
  /** The exact bytes `s256` was computed over and `mission` encodes. */
  blob: Buffer;
  /** Seconds since the epoch. */
  approvedAt: number;
  /** Seconds since the epoch; every mission this PS approves carries one. */
  expiresAt: number;
  state: MissionState;
  terminationReason?: string;
  terminatedAt?: number;
}

/**
 * A token this PS issued. For a person token, AAuth -11 Section 7.1
 * requires the `jti`, `aud` and `exp`; one issued under a Mission
 * Reference, and every auth token issued under one, is a Tracked
 * Credential of the management companion (`iss`, `jti`, `aud`, `exp`).
 */
export interface IssuedTokenRecord {
  iss: string;
  jti: string;
  kind: "person" | "auth";
  aud: string;
  exp: number;
  sub: string;
  agent: string;
  missionS256?: string;
  issuedAt: number;
}

/** One ordered mission-log entry. No raw credential is recorded. */
export interface MissionLogEntry {
  s256: string;
  at: number;
  event: string;
  detail: Record<string, unknown>;
}

/**
 * Where one revocation of a Tracked Credential stands at one recipient.
 * `pending` is retried; `confirmed` is the recipient's `200`; the others
 * are terminal without confirmation, so the credential stays unconfirmed
 * until its `exp`: `unsupported` (no revocation endpoint advertised, or
 * `unsupported_iss`), `rejected` (a `400`), `exhausted` (the retry bound
 * reached).
 */
export type RevocationState = "pending" | "confirmed" | "unsupported" | "rejected" | "exhausted";

export interface RevocationRecord {
  iss: string;
  jti: string;
  /** The party the revocation goes to: the Resource in the token's `aud`. */
  recipient: string;
  /** The mission the credential was issued under. */
  s256: string;
  kind: "person" | "auth";
  /** The credential's own `exp`, sent as the request's `exp`. */
  exp: number;
  state: RevocationState;
  /** The recipient's `revocation_endpoint`, once discovered. */
  endpoint?: string;
  attempts: number;
  /** Seconds since the epoch: when a pending revocation is next attempted. */
  nextAt: number;
  lastOutcome?: string;
  lastStatus?: number;
  updatedAt: number;
}

/**
 * A terminate request's retained outcome, keyed by the authenticated
 * caller and its `request_id` (the management companion's idempotency
 * rule): the target, the body as a canonical parsed value, and the
 * committed receipt a replay repeats.
 */
export interface TerminateRequestRecord {
  caller: string;
  requestId: string;
  s256: string;
  body: string;
  receipt: Record<string, unknown>;
  at: number;
}

/**
 * The PS's state. A read that cannot establish state throws, and the PS
 * then fails closed: it never treats an unreadable mission as absent or
 * as missionless.
 */
export interface PsStore {
  /**
   * The mission keyed by its owning agent and `s256` together: a mission
   * of another agent is not found by the same lookup that misses an absent
   * one (ownership first).
   */
  findOwnedMission(agent: string, s256: string): MissionRecord | undefined;
  /** Insert an approved mission with its issued tokens and log, atomically. */
  approve(mission: MissionRecord, issued: readonly IssuedTokenRecord[], log: MissionLogEntry): void;
  /** Record issued tokens and their log entries, atomically. */
  recordIssued(issued: readonly IssuedTokenRecord[], log: readonly MissionLogEntry[]): void;
  /**
   * Move an active mission to terminated and log it, with `detail` added to
   * the log entry; false when it was not active, and then nothing changes.
   */
  terminate(
    agent: string,
    s256: string,
    reason: string,
    at: number,
    detail?: Record<string, unknown>,
  ): boolean;
  issuedTokens(): IssuedTokenRecord[];
  missionLog(s256: string): MissionLogEntry[];
  /** The secret the pairwise `sub` derivation is keyed with, stable for the store's life. */
  pairwiseKey(): Buffer;
  close(): void;
}

/**
 * The mission control plane's state, in the same durable store as
 * {@link PsStore} so a termination, its receipt and its revocation work
 * commit together, and every issuance path reads the state they wrote.
 */
export interface MissionControlStore {
  /** Run `fn` as one immediate transaction: it commits whole or not at all. */
  atomically<T>(fn: () => T): T;
  findOwnedMission(agent: string, s256: string): MissionRecord | undefined;
  /**
   * The mission `s256` names, when its owning agent is one of `agents`: one
   * lookup keyed by the caller's authorization and `s256` together, so a
   * mission outside it is not found by the same query that misses an
   * absent one.
   */
  findMissionAmong(agents: readonly string[], s256: string): MissionRecord | undefined;
  terminate(
    agent: string,
    s256: string,
    reason: string,
    at: number,
    detail?: Record<string, unknown>,
  ): boolean;
  appendLog(entries: readonly MissionLogEntry[]): void;
  missionLog(s256: string): MissionLogEntry[];
  findTerminateRequest(caller: string, requestId: string): TerminateRequestRecord | undefined;
  recordTerminateRequest(record: TerminateRequestRecord): void;
  /** Every Tracked Credential issued under the mission. */
  missionTokens(s256: string): IssuedTokenRecord[];
  addRevocations(rows: readonly RevocationRecord[]): void;
  revocations(s256: string): RevocationRecord[];
  /** Pending revocations due at `now` for credentials still unexpired, oldest first. */
  dueRevocations(now: number): RevocationRecord[];
  updateRevocation(row: RevocationRecord): void;
}

const MIGRATIONS = [
  `CREATE TABLE missions (
     agent TEXT NOT NULL,
     s256 TEXT NOT NULL,
     blob BLOB NOT NULL,
     approved_at INTEGER NOT NULL,
     expires_at INTEGER NOT NULL,
     state TEXT NOT NULL CHECK (state IN ('active', 'terminated')),
     termination_reason TEXT,
     terminated_at INTEGER,
     PRIMARY KEY (agent, s256)
   ) STRICT, WITHOUT ROWID;
   CREATE TABLE issued_tokens (
     iss TEXT NOT NULL,
     jti TEXT NOT NULL,
     kind TEXT NOT NULL CHECK (kind IN ('person', 'auth')),
     aud TEXT NOT NULL,
     exp INTEGER NOT NULL,
     sub TEXT NOT NULL,
     agent TEXT NOT NULL,
     mission_s256 TEXT,
     issued_at INTEGER NOT NULL,
     PRIMARY KEY (iss, jti)
   ) STRICT;
   CREATE TABLE mission_log (
     seq INTEGER PRIMARY KEY AUTOINCREMENT,
     s256 TEXT NOT NULL,
     at INTEGER NOT NULL,
     event TEXT NOT NULL,
     detail TEXT NOT NULL
   ) STRICT;
   CREATE TABLE ps_meta (k TEXT PRIMARY KEY, v BLOB NOT NULL) STRICT;`,
  // #836 slice 3: the mission control plane. A terminate request's retained
  // outcome, and each revocation of a Tracked Credential at one recipient.
  // Rows are never deleted: terminal state, receipts and revocation outcomes
  // are kept for the store's life.
  `CREATE TABLE terminate_requests (
     caller TEXT NOT NULL,
     request_id TEXT NOT NULL,
     s256 TEXT NOT NULL,
     body TEXT NOT NULL,
     receipt TEXT NOT NULL,
     at INTEGER NOT NULL,
     PRIMARY KEY (caller, request_id)
   ) STRICT;
   CREATE TABLE revocations (
     iss TEXT NOT NULL,
     jti TEXT NOT NULL,
     recipient TEXT NOT NULL,
     s256 TEXT NOT NULL,
     kind TEXT NOT NULL CHECK (kind IN ('person', 'auth')),
     exp INTEGER NOT NULL,
     state TEXT NOT NULL CHECK (state IN ('pending', 'confirmed', 'unsupported', 'rejected', 'exhausted')),
     endpoint TEXT,
     attempts INTEGER NOT NULL,
     next_at INTEGER NOT NULL,
     last_outcome TEXT,
     last_status INTEGER,
     updated_at INTEGER NOT NULL,
     PRIMARY KEY (iss, jti, recipient)
   ) STRICT;
   CREATE INDEX revocations_due ON revocations (state, next_at);
   CREATE INDEX revocations_mission ON revocations (s256);
   CREATE INDEX issued_tokens_mission ON issued_tokens (mission_s256);
   CREATE INDEX missions_s256 ON missions (s256);`,
];

interface RevocationRow {
  iss: string;
  jti: string;
  recipient: string;
  s256: string;
  kind: "person" | "auth";
  exp: number;
  state: RevocationState;
  endpoint: string | null;
  attempts: number;
  next_at: number;
  last_outcome: string | null;
  last_status: number | null;
  updated_at: number;
}

function revocationOf(row: RevocationRow): RevocationRecord {
  const record: RevocationRecord = {
    iss: row.iss,
    jti: row.jti,
    recipient: row.recipient,
    s256: row.s256,
    kind: row.kind,
    exp: row.exp,
    state: row.state,
    attempts: row.attempts,
    nextAt: row.next_at,
    updatedAt: row.updated_at,
  };
  if (row.endpoint !== null) record.endpoint = row.endpoint;
  if (row.last_outcome !== null) record.lastOutcome = row.last_outcome;
  if (row.last_status !== null) record.lastStatus = row.last_status;
  return record;
}

interface MissionRow {
  agent: string;
  s256: string;
  blob: Buffer;
  approved_at: number;
  expires_at: number;
  state: MissionState;
  termination_reason: string | null;
  terminated_at: number | null;
}

interface TokenRow {
  iss: string;
  jti: string;
  kind: "person" | "auth";
  aud: string;
  exp: number;
  sub: string;
  agent: string;
  mission_s256: string | null;
  issued_at: number;
}

function missionOf(row: MissionRow): MissionRecord {
  const record: MissionRecord = {
    agent: row.agent,
    s256: row.s256,
    blob: row.blob,
    approvedAt: row.approved_at,
    expiresAt: row.expires_at,
    state: row.state,
  };
  if (row.termination_reason !== null) record.terminationReason = row.termination_reason;
  if (row.terminated_at !== null) record.terminatedAt = row.terminated_at;
  return record;
}

function tokenOf(row: TokenRow): IssuedTokenRecord {
  const record: IssuedTokenRecord = {
    iss: row.iss,
    jti: row.jti,
    kind: row.kind,
    aud: row.aud,
    exp: row.exp,
    sub: row.sub,
    agent: row.agent,
    issuedAt: row.issued_at,
  };
  if (row.mission_s256 !== null) record.missionS256 = row.mission_s256;
  return record;
}

/**
 * Durable SQLite state through `@mission/store`'s `openDurableStore`:
 * single writer, WAL with `synchronous=FULL`, the file from configuration
 * and never defaulted. Missions, issued-token records, the mission log,
 * terminate receipts and revocation attempts survive a restart; the
 * replay cache does not (it spans one signature window).
 */
export class SqlitePsStore implements PsStore, MissionControlStore {
  private readonly db: Database;
  private readonly key: Buffer;

  constructor(file: string) {
    this.db = openDurableStore({ file, migrations: MIGRATIONS, owner: "aauth-ps" });
    const row = this.db.prepare("SELECT v FROM ps_meta WHERE k = 'pairwise_key'").get() as
      | { v: Buffer }
      | undefined;
    if (row) {
      this.key = row.v;
    } else {
      this.key = randomBytes(32);
      this.db.prepare("INSERT INTO ps_meta (k, v) VALUES ('pairwise_key', ?)").run(this.key);
    }
  }

  findOwnedMission(agent: string, s256: string): MissionRecord | undefined {
    const row = this.db
      .prepare("SELECT * FROM missions WHERE agent = ? AND s256 = ?")
      .get(agent, s256) as MissionRow | undefined;
    return row && missionOf(row);
  }

  findMissionAmong(agents: readonly string[], s256: string): MissionRecord | undefined {
    if (agents.length === 0) return undefined;
    const row = this.db
      .prepare(
        `SELECT * FROM missions WHERE s256 = ? AND agent IN (${agents.map(() => "?").join(", ")})`,
      )
      .get(s256, ...agents) as MissionRow | undefined;
    return row && missionOf(row);
  }

  atomically<T>(fn: () => T): T {
    return this.db.transaction(fn).immediate();
  }

  appendLog(entries: readonly MissionLogEntry[]): void {
    this.insertLog(entries);
  }

  findTerminateRequest(caller: string, requestId: string): TerminateRequestRecord | undefined {
    const row = this.db
      .prepare("SELECT * FROM terminate_requests WHERE caller = ? AND request_id = ?")
      .get(caller, requestId) as
      | {
          caller: string;
          request_id: string;
          s256: string;
          body: string;
          receipt: string;
          at: number;
        }
      | undefined;
    if (!row) return undefined;
    return {
      caller: row.caller,
      requestId: row.request_id,
      s256: row.s256,
      body: row.body,
      receipt: JSON.parse(row.receipt),
      at: row.at,
    };
  }

  recordTerminateRequest(record: TerminateRequestRecord): void {
    this.db
      .prepare(
        "INSERT INTO terminate_requests (caller, request_id, s256, body, receipt, at) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(
        record.caller,
        record.requestId,
        record.s256,
        record.body,
        JSON.stringify(record.receipt),
        record.at,
      );
  }

  missionTokens(s256: string): IssuedTokenRecord[] {
    const rows = this.db
      .prepare("SELECT * FROM issued_tokens WHERE mission_s256 = ? ORDER BY issued_at, jti")
      .all(s256) as TokenRow[];
    return rows.map(tokenOf);
  }

  addRevocations(rows: readonly RevocationRecord[]): void {
    const insert = this.db.prepare(
      `INSERT INTO revocations (iss, jti, recipient, s256, kind, exp, state, endpoint, attempts, next_at, last_outcome, last_status, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    for (const r of rows) {
      insert.run(
        r.iss,
        r.jti,
        r.recipient,
        r.s256,
        r.kind,
        r.exp,
        r.state,
        r.endpoint ?? null,
        r.attempts,
        r.nextAt,
        r.lastOutcome ?? null,
        r.lastStatus ?? null,
        r.updatedAt,
      );
    }
  }

  revocations(s256: string): RevocationRecord[] {
    const rows = this.db
      .prepare("SELECT * FROM revocations WHERE s256 = ? ORDER BY jti, recipient")
      .all(s256) as RevocationRow[];
    return rows.map(revocationOf);
  }

  dueRevocations(now: number): RevocationRecord[] {
    const rows = this.db
      .prepare(
        "SELECT * FROM revocations WHERE state = 'pending' AND next_at <= ? AND exp > ? ORDER BY next_at, s256, jti, recipient",
      )
      .all(now, now) as RevocationRow[];
    return rows.map(revocationOf);
  }

  updateRevocation(row: RevocationRecord): void {
    this.db
      .prepare(
        `UPDATE revocations SET state = ?, endpoint = ?, attempts = ?, next_at = ?, last_outcome = ?, last_status = ?, updated_at = ?
         WHERE iss = ? AND jti = ? AND recipient = ?`,
      )
      .run(
        row.state,
        row.endpoint ?? null,
        row.attempts,
        row.nextAt,
        row.lastOutcome ?? null,
        row.lastStatus ?? null,
        row.updatedAt,
        row.iss,
        row.jti,
        row.recipient,
      );
  }

  approve(mission: MissionRecord, issued: readonly IssuedTokenRecord[], log: MissionLogEntry) {
    this.db
      .transaction(() => {
        this.db
          .prepare(
            "INSERT INTO missions (agent, s256, blob, approved_at, expires_at, state) VALUES (?, ?, ?, ?, ?, 'active')",
          )
          .run(mission.agent, mission.s256, mission.blob, mission.approvedAt, mission.expiresAt);
        this.insertIssued(issued);
        this.insertLog([log]);
      })
      .immediate();
  }

  recordIssued(issued: readonly IssuedTokenRecord[], log: readonly MissionLogEntry[]): void {
    this.db
      .transaction(() => {
        this.insertIssued(issued);
        this.insertLog(log);
      })
      .immediate();
  }

  /**
   * The one active-to-terminated transition: the UPDATE matches only an
   * active row, so of two racing terminations exactly one changes it, and
   * the first committed reason and time stand.
   */
  terminate(
    agent: string,
    s256: string,
    reason: string,
    at: number,
    detail: Record<string, unknown> = {},
  ): boolean {
    return this.db
      .transaction(() => {
        const changed = this.db
          .prepare(
            "UPDATE missions SET state = 'terminated', termination_reason = ?, terminated_at = ? WHERE agent = ? AND s256 = ? AND state = 'active'",
          )
          .run(reason, at, agent, s256).changes;
        if (changed === 1) {
          this.insertLog([{ s256, at, event: "terminated", detail: { reason, ...detail } }]);
        }
        return changed === 1;
      })
      .immediate();
  }

  issuedTokens(): IssuedTokenRecord[] {
    const rows = this.db
      .prepare("SELECT * FROM issued_tokens ORDER BY issued_at, jti")
      .all() as TokenRow[];
    return rows.map(tokenOf);
  }

  missionLog(s256: string): MissionLogEntry[] {
    const rows = this.db
      .prepare("SELECT s256, at, event, detail FROM mission_log WHERE s256 = ? ORDER BY seq")
      .all(s256) as { s256: string; at: number; event: string; detail: string }[];
    return rows.map((row) => ({ ...row, detail: JSON.parse(row.detail) }));
  }

  pairwiseKey(): Buffer {
    return this.key;
  }

  close(): void {
    this.db.close();
  }

  private insertIssued(issued: readonly IssuedTokenRecord[]): void {
    const insert = this.db.prepare(
      "INSERT INTO issued_tokens (iss, jti, kind, aud, exp, sub, agent, mission_s256, issued_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    );
    for (const t of issued) {
      insert.run(
        t.iss,
        t.jti,
        t.kind,
        t.aud,
        t.exp,
        t.sub,
        t.agent,
        t.missionS256 ?? null,
        t.issuedAt,
      );
    }
  }

  private insertLog(entries: readonly MissionLogEntry[]): void {
    const insert = this.db.prepare(
      "INSERT INTO mission_log (s256, at, event, detail) VALUES (?, ?, ?, ?)",
    );
    for (const e of entries) insert.run(e.s256, e.at, e.event, JSON.stringify(e.detail));
  }
}
