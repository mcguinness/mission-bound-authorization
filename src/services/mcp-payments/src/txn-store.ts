/**
 * @spec txn-authorization#offline-verification — the resource-side state the
 * offline check compares against.
 *
 * When it issues a challenge the resource RETAINS the pending operation, keyed
 * by `txn`: the effective parameters' digest, the Mission invariants, the
 * operation's `authorization_details` entry, and the presenter key. Offline
 * verification then matches a presented transaction token against THAT record
 * rather than trusting anything the token asserts about the operation.
 *
 * SQLite-backed and injectable so replicas capable of executing the same
 * operation can share one database (the consumption domain of
 * {@link TxnConsumptionStore} must be linearizable across all of them).
 */

import { openStore, type Database, type StoreOptions } from "@mission/store";
import type { JsonValue, TxnMissionClaim } from "@mission/core";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS txn_pending_operations (
  txn TEXT PRIMARY KEY,
  resource TEXT NOT NULL,
  challenge_jti TEXT NOT NULL,
  mission_json TEXT NOT NULL,
  action TEXT NOT NULL,
  parameter_digest TEXT NOT NULL,
  authorization_details TEXT NOT NULL,
  cnf_jkt TEXT NOT NULL,
  subject TEXT NOT NULL,
  issued_at INTEGER NOT NULL
) STRICT;
`;

/** One challenged operation the resource is holding open, keyed by `txn`. */
export interface PendingOperation {
  txn: string;
  /** The challenge `iss`: this resource. `txn` is scoped to it. */
  resource: string;
  challengeJti: string;
  mission: TxnMissionClaim;
  action: string;
  parameterDigest: string;
  authorizationDetails: JsonValue[];
  cnfJkt: string;
  /** The verified effective subject the challenge was issued for. */
  subject: string;
}

/** The retained pending operations. */
export interface TxnPendingStore {
  put(op: PendingOperation): void;
  get(resource: string, txn: string): PendingOperation | undefined;
}

class SqliteTxnPendingStore implements TxnPendingStore {
  constructor(readonly db: Database) {
    db.exec(SCHEMA);
  }

  put(op: PendingOperation): void {
    this.db
      .prepare(
        `INSERT INTO txn_pending_operations
           (txn, resource, challenge_jti, mission_json, action, parameter_digest, authorization_details, cnf_jkt, subject, issued_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, unixepoch())
         ON CONFLICT(txn) DO NOTHING`,
      )
      .run(
        op.txn,
        op.resource,
        op.challengeJti,
        JSON.stringify(op.mission),
        op.action,
        op.parameterDigest,
        JSON.stringify(op.authorizationDetails),
        op.cnfJkt,
        op.subject,
      );
  }

  get(resource: string, txn: string): PendingOperation | undefined {
    const row = this.db
      .prepare("SELECT * FROM txn_pending_operations WHERE txn = ? AND resource = ?")
      .get(txn, resource) as Record<string, string> | undefined;
    if (!row) return undefined;
    return {
      txn: row.txn as string,
      resource: row.resource as string,
      challengeJti: row.challenge_jti as string,
      mission: JSON.parse(row.mission_json as string) as TxnMissionClaim,
      action: row.action as string,
      parameterDigest: row.parameter_digest as string,
      authorizationDetails: JSON.parse(row.authorization_details as string) as JsonValue[],
      cnfJkt: row.cnf_jkt as string,
      subject: row.subject as string,
    };
  }
}

/**
 * Open the resource-side transaction stores. Pass `db` to SHARE one database
 * between replicas (the cross-replica consumption case) or `file` to share one
 * on disk; the default is this replica's own in-memory database (D27).
 */
export function openTxnPendingStore(opts: StoreOptions & { db?: Database } = {}): TxnPendingStore {
  const { db, ...storeOptions } = opts;
  return new SqliteTxnPendingStore(db ?? openStore(SCHEMA, storeOptions));
}
