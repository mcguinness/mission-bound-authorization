/**
 * @spec txn-authorization#two-phase-expiry, #offline-verification — the
 * pending-workflow table behind `transaction_authorization_id`.
 *
 * Two invariants are STRUCTURAL here rather than left to handler logic:
 *
 *  - ADMISSION IDEMPOTENCY, AND ADMISSION AS THE RESERVATION. A UNIQUE index
 *    over (challenge issuer, challenge jti, client, cnf) means a repeated
 *    initial submission of the same admitted challenge returns the EXISTING
 *    workflow; a second workflow for it cannot be created. The insert runs
 *    BEFORE any approval is opened and reports whether THIS caller won it, so
 *    only the winner opens an approval: two concurrent submissions of one
 *    challenge cannot open two. A workflow whose `task_id` is still empty has
 *    not reached the Access Request Service yet and polls as pending.
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

import { type Database, openStore, type StoreOptions, withTransaction } from "@mission/store";
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
  subject_token_jti TEXT NOT NULL,
  act_json TEXT,
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
  challenge_iss TEXT NOT NULL,
  txn TEXT NOT NULL,
  workflow_id TEXT NOT NULL,
  issued_at INTEGER NOT NULL,
  PRIMARY KEY (challenge_iss, txn)
) STRICT;
`;

export type TxnWorkflowState = "pending" | "denied" | "issued";

/** The admission outcome: the row of record, and whether THIS caller created
 *  it (and therefore owns opening the approval for it). */
export interface TxnAdmission {
  record: TxnWorkflowRecord;
  won: boolean;
}

/** One admitted workflow, with the challenge it was admitted on pinned. */
export interface TxnWorkflowRecord {
  id: string;
  challenge: TxnChallengeClaims;
  clientId: string;
  missionId: string;
  action: string;
  /**
   * The approval task this workflow's decision waits on. EMPTY until the
   * workflow that won admission has opened it; a poll before that is pending.
   */
  taskId: string;
  /** The `authorization_details` entry's `type` at admission (profile version). */
  operationType: string;
  subject: string;
  /** `subject_token`'s own expiry, pinned at admission (epoch seconds). */
  subjectTokenExpS: number;
  /**
   * `subject_token`'s `jti`, pinned at admission. The credential's own expiry
   * is a claim it makes about itself; THIS is what the issuer's records are
   * consulted under, so an individually revoked credential stops redeeming
   * here the moment it is revoked rather than at its nominal exp.
   */
  subjectTokenJti: string;
  /** The Mission's expiry at admission (epoch seconds). */
  missionExpS: number;
  /**
   * @spec txn-authorization#transaction-token — the requester/actor context
   * that existed upstream (on `subject_token` or the challenge), pinned at
   * admission. Its presence is what makes `act` REQUIRED on the token.
   */
  act?: unknown;
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
  subject_token_jti: string;
  act_json: string | null;
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
   * Admit a workflow. THIS insert is the reservation: a concurrent submission
   * of the same admitted challenge loses the UNIQUE index race and gets the
   * winner's record back with `won: false`, so the caller never observes two
   * workflows for one challenge and only the winner opens an approval.
   */
  admit(record: TxnWorkflowRecord): TxnAdmission {
    const info = this.db
      .prepare(
        `INSERT INTO txn_workflows
           (id, challenge_iss, challenge_jti, client_id, cnf_jkt, txn, task_id, mission_id, action,
            operation_type, subject, subject_token_jti, act_json, parameter_digest, challenge_json,
            subject_token_exp, mission_exp, expires_at, state, issued_token, issued_jti, issued_exp, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, unixepoch())
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
        record.subjectTokenJti,
        record.act === undefined ? null : JSON.stringify(record.act),
        record.challenge.parameter_digest,
        JSON.stringify(record.challenge),
        record.subjectTokenExpS,
        record.missionExpS,
        record.expiresAtS,
        record.state,
      );
    if (info.changes === 1) return { record, won: true };
    const existing = this.findAdmission({
      challengeIss: record.challenge.iss,
      challengeJti: record.challenge.jti,
      clientId: record.clientId,
      cnfJkt: record.challenge.cnf.jkt,
    });
    if (!existing) throw new Error("workflow admission conflicted without an existing row");
    return { record: existing, won: false };
  }

  /**
   * Record the approval task the winner opened for an admitted workflow. Until
   * it is recorded the workflow has no decision to wait on and polls pending.
   */
  recordTask(id: string, taskId: string): void {
    this.db.prepare("UPDATE txn_workflows SET task_id = ? WHERE id = ?").run(taskId, id);
  }

  setState(id: string, state: TxnWorkflowState): void {
    this.db.prepare("UPDATE txn_workflows SET state = ? WHERE id = ?").run(state, id);
  }

  /**
   * Take the single issuance slot for this `txn` AND record the already-minted
   * token, in one transaction. `txn` is unique within the resource that issued
   * the challenge for it, never globally, so the slot is keyed by (challenge
   * issuer, txn): two accepted resources selecting the same `txn` value cannot
   * interfere. True exactly once per slot across every workflow; false
   * thereafter, including for the workflow that already took it (the caller
   * discards its own mint and serves the stored token).
   *
   * The caller mints BEFORE this runs: a signing error or crash therefore
   * leaves the slot untaken and a later poll can complete cleanly, and a taken
   * slot always has its token stored -- a reserved-but-empty workflow cannot
   * exist.
   */
  reserveAndRecordIssuance(
    challengeIss: string,
    txn: string,
    workflowId: string,
    token: string,
    jti: string,
    expS: number,
  ): boolean {
    return withTransaction(this.db, () => {
      const reserved =
        this.db
          .prepare(
            "INSERT INTO txn_issuance_guard (challenge_iss, txn, workflow_id, issued_at) VALUES (?, ?, ?, unixepoch()) ON CONFLICT(challenge_iss, txn) DO NOTHING",
          )
          .run(challengeIss, txn, workflowId).changes === 1;
      if (!reserved) return false;
      this.db
        .prepare("UPDATE txn_workflows SET state = 'issued', issued_token = ?, issued_jti = ?, issued_exp = ? WHERE id = ?")
        .run(token, jti, expS, workflowId);
      return true;
    });
  }

  /** The workflow that already produced the authorization result for a `txn`. */
  issuanceHolder(challengeIss: string, txn: string): string | undefined {
    const row = this.db
      .prepare("SELECT workflow_id FROM txn_issuance_guard WHERE challenge_iss = ? AND txn = ?")
      .get(challengeIss, txn) as { workflow_id: string } | undefined;
    return row?.workflow_id;
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
    subjectTokenJti: row.subject_token_jti,
    ...(row.act_json !== null ? { act: JSON.parse(row.act_json) as unknown } : {}),
    subjectTokenExpS: row.subject_token_exp,
    missionExpS: row.mission_exp,
    expiresAtS: row.expires_at,
    state: row.state,
    ...(row.issued_token !== null ? { issuedToken: row.issued_token } : {}),
    ...(row.issued_jti !== null ? { issuedJti: row.issued_jti } : {}),
    ...(row.issued_exp !== null ? { issuedExpS: row.issued_exp } : {}),
  };
}
