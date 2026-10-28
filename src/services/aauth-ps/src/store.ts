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
  /** Move an active mission to terminated; false when it was not active. */
  terminate(agent: string, s256: string, reason: string, at: number): boolean;
  issuedTokens(): IssuedTokenRecord[];
  missionLog(s256: string): MissionLogEntry[];
  /** The secret the pairwise `sub` derivation is keyed with, stable for the store's life. */
  pairwiseKey(): Buffer;
  close(): void;
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
];

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

/**
 * Durable SQLite state through `@mission/store`'s `openDurableStore`:
 * single writer, WAL with `synchronous=FULL`, the file from configuration
 * and never defaulted. Missions, issued-token records and the mission log
 * survive a restart; the replay cache does not (it spans one signature
 * window).
 */
export class SqlitePsStore implements PsStore {
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
    if (!row) return undefined;
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

  terminate(agent: string, s256: string, reason: string, at: number): boolean {
    return this.db
      .transaction(() => {
        const changed = this.db
          .prepare(
            "UPDATE missions SET state = 'terminated', termination_reason = ?, terminated_at = ? WHERE agent = ? AND s256 = ? AND state = 'active'",
          )
          .run(reason, at, agent, s256).changes;
        if (changed === 1) this.insertLog([{ s256, at, event: "terminated", detail: { reason } }]);
        return changed === 1;
      })
      .immediate();
  }

  issuedTokens(): IssuedTokenRecord[] {
    const rows = this.db
      .prepare("SELECT * FROM issued_tokens ORDER BY issued_at, jti")
      .all() as TokenRow[];
    return rows.map((row) => {
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
    });
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
