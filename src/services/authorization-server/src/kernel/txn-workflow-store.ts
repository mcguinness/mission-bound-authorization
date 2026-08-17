/**
 * @spec txn-authorization#two-phase-expiry, #offline-verification — the
 * pending-workflow table behind `transaction_authorization_id`.
 *
 * Two invariants are STRUCTURAL here rather than left to handler logic:
 *
 *  - ADMISSION IDEMPOTENCY. A UNIQUE index over (challenge issuer, challenge
 *    jti, client, cnf) means a repeated initial submission of the same admitted
 *    challenge returns the EXISTING workflow; a second workflow for it cannot
 *    be created.
 *  - AT MOST ONE AUTHORIZATION RESULT PER `txn`. Issuance is guarded by a
 *    redeem-once insert keyed on `txn`, so a second token under a different
 *    `jti` for a `txn` whose workflow already produced one is impossible even
 *    across workflows, not merely unlikely.
 *
 * The workflow also PINS the challenge snapshot it was admitted on, including
 * the operation's `type`. A resource versions its Operation Profile by
 * versioning that `type`, and a TAS MUST retain and recognize a superseded
 * version for as long as a pending workflow still references it: pinning is
 * how that holds without a second registry.
 */

import { type Database, openStore, type StoreOptions } from "@mission/store";
import type { TxnChallengeClaims } from "@mission/core";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS txn_workflows (
  id TEXT PRIMARY KEY,
  challenge_iss TEXT NOT NULL,
  challenge_jti TEXT NOT NULL,
  client_id TEXT NOT NULL,
  cnf_jkt TEXT NOT NULL,
  txn TEXT NOT NULL,
  task_id TEXT NOT NULL,
  mission_id TEXT NOT NULL,
  action TEXT NOT NULL,
  operation_type TEXT NOT NULL,
  subject TEXT NOT NULL,
  parameter_digest TEXT NOT NULL,
  challenge_json TEXT NOT NULL,
  subject_token_exp INTEGER NOT NULL,
  mission_exp INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  state TEXT NOT NULL,
  issued_token TEXT,
  issued_jti TEXT,
  issued_exp INTEGER,
  created_at INTEGER NOT NULL
) STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS txn_workflows_admission
  ON txn_workflows (challenge_iss, challenge_jti, client_id, cnf_jkt);
CREATE TABLE IF NOT EXISTS txn_issuance_guard (
  txn TEXT PRIMARY KEY,
  workflow_id TEXT NOT NULL,
  issued_at INTEGER NOT NULL
) STRICT;
`;

export type TxnWorkflowState = "pending" | "denied" | "issued";

/** One admitted workflow, with the challenge it was admitted on pinned. */
export interface TxnWorkflowRecord {
  id: string;
  challenge: TxnChallengeClaims;
  clientId: string;
  taskId: string;
  missionId: string;
  action: string;
  /** The `authorization_details` entry's `type` at admission (profile version). */
  operationType: string;
  subject: string;
  /** `subject_token`'s own expiry, pinned at admission (epoch seconds). */
  subjectTokenExpS: number;
  /** The Mission's expiry at admission (epoch seconds). */
  missionExpS: number;
  /** The WORKFLOW's expiry (epoch seconds), independent of the challenge's. */
  expiresAtS: number;
  state: TxnWorkflowState;
  issuedToken?: string;
  issuedJti?: string;
  issuedExpS?: number;
}

interface Row {
  id: string;
  client_id: string;
  task_id: string;
  mission_id: string;
  action: string;
  operation_type: string;
  subject: string;
  challenge_json: string;
  subject_token_exp: number;
  mission_exp: number;
  expires_at: number;
  state: TxnWorkflowState;
  issued_token: string | null;
  issued_jti: string | null;
  issued_exp: number | null;
}

export class TxnWorkflowStore {
  readonly db: Database;
  constructor(options: StoreOptions & { db?: Database } = {}) {
    const { db, ...storeOptions } = options;
    this.db = db ?? openStore(SCHEMA, storeOptions);
    this.db.exec(SCHEMA);
  }

  /**
   * The workflow an admitted challenge already produced, if any. Keyed on the
   * exact tuple the profile names: challenge issuer, challenge jti, client,
   * presenter key.
   */
  findAdmission(input: {
    challengeIss: string;
    challengeJti: string;
    clientId: string;
    cnfJkt: string;
  }): TxnWorkflowRecord | undefined {
    const row = this.db
      .prepare(
        `SELECT * FROM txn_workflows
          WHERE challenge_iss = ? AND challenge_jti = ? AND client_id = ? AND cnf_jkt = ?`,
      )
      .get(input.challengeIss, input.challengeJti, input.clientId, input.cnfJkt) as Row | undefined;
    return row ? toRecord(row) : undefined;
  }

  get(id: string): TxnWorkflowRecord | undefined {
    const row = this.db.prepare("SELECT * FROM txn_workflows WHERE id = ?").get(id) as Row | undefined;
    return row ? toRecord(row) : undefined;
  }

  /**
   * Admit a workflow. A concurrent submission of the same admitted challenge
   * loses the UNIQUE index race and gets the winner's record back, so the
   * caller never observes two workflows for one challenge.
   */
  admit(record: TxnWorkflowRecord): TxnWorkflowRecord {
    const info = this.db
      .prepare(
        `INSERT INTO txn_workflows
           (id, challenge_iss, challenge_jti, client_id, cnf_jkt, txn, task_id, mission_id, action,
            operation_type, subject, parameter_digest, challenge_json, subject_token_exp, mission_exp,
            expires_at, state, issued_token, issued_jti, issued_exp, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, unixepoch())
         ON CONFLICT DO NOTHING`,
      )
      .run(
        record.id,
        record.challenge.iss,
        record.challenge.jti,
        record.clientId,
        record.challenge.cnf.jkt,
        record.challenge.txn,
        record.taskId,
        record.missionId,
        record.action,
        record.operationType,
        record.subject,
        record.challenge.parameter_digest,
        JSON.stringify(record.challenge),
        record.subjectTokenExpS,
        record.missionExpS,
        record.expiresAtS,
        record.state,
      );
    if (info.changes === 1) return record;
    const existing = this.findAdmission({
      challengeIss: record.challenge.iss,
      challengeJti: record.challenge.jti,
      clientId: record.clientId,
      cnfJkt: record.challenge.cnf.jkt,
    });
    if (!existing) throw new Error("workflow admission conflicted without an existing row");
    return existing;
  }

  setState(id: string, state: TxnWorkflowState): void {
    this.db.prepare("UPDATE txn_workflows SET state = ? WHERE id = ?").run(state, id);
  }

  /**
   * Take the single issuance slot for this `txn`. True exactly once per `txn`
   * across every workflow; false thereafter, including for the workflow that
   * already took it (the caller then serves its stored token).
   */
  reserveIssuance(txn: string, workflowId: string): boolean {
    return (
      this.db
        .prepare(
          "INSERT INTO txn_issuance_guard (txn, workflow_id, issued_at) VALUES (?, ?, unixepoch()) ON CONFLICT(txn) DO NOTHING",
        )
        .run(txn, workflowId).changes === 1
    );
  }

  /** The workflow that already produced the authorization result for a `txn`. */
  issuanceHolder(txn: string): string | undefined {
    const row = this.db.prepare("SELECT workflow_id FROM txn_issuance_guard WHERE txn = ?").get(txn) as
      | { workflow_id: string }
      | undefined;
    return row?.workflow_id;
  }

  recordIssued(id: string, token: string, jti: string, expS: number): void {
    this.db
      .prepare("UPDATE txn_workflows SET state = 'issued', issued_token = ?, issued_jti = ?, issued_exp = ? WHERE id = ?")
      .run(token, jti, expS, id);
  }
}

function toRecord(row: Row): TxnWorkflowRecord {
  return {
    id: row.id,
    challenge: JSON.parse(row.challenge_json) as TxnChallengeClaims,
    clientId: row.client_id,
    taskId: row.task_id,
    missionId: row.mission_id,
    action: row.action,
    operationType: row.operation_type,
    subject: row.subject,
    subjectTokenExpS: row.subject_token_exp,
    missionExpS: row.mission_exp,
    expiresAtS: row.expires_at,
    state: row.state,
    ...(row.issued_token !== null ? { issuedToken: row.issued_token } : {}),
    ...(row.issued_jti !== null ? { issuedJti: row.issued_jti } : {}),
    ...(row.issued_exp !== null ? { issuedExpS: row.issued_exp } : {}),
  };
}
