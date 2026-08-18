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
  txn TEXT NOT NULL,
  resource TEXT NOT NULL,
  challenge_jti TEXT NOT NULL,
  mission_json TEXT NOT NULL,
  action TEXT NOT NULL,
  parameter_digest TEXT NOT NULL,
  authorization_details TEXT NOT NULL,
  cnf_jkt TEXT NOT NULL,
  subject TEXT NOT NULL,
  issued_at INTEGER NOT NULL,
  PRIMARY KEY (resource, txn)
) STRICT;
CREATE TABLE IF NOT EXISTS txn_consumption (
  resource TEXT NOT NULL,
  txn TEXT NOT NULL,
  op_key TEXT NOT NULL,
  state TEXT NOT NULL,
  consumed_at INTEGER NOT NULL,
  committed_at INTEGER,
  PRIMARY KEY (resource, txn)
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
         ON CONFLICT(resource, txn) DO NOTHING`,
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
 * @spec txn-authorization#offline-verification — where a consumed `txn` stands
 * relative to the IRREVERSIBLE EFFECT it authorized.
 *
 * A boolean "consumed" cannot tell the two apart, and the difference is the
 * whole question a crash asks: `consumed` means the resource took the single
 * use and the effect may or may not have landed; `effect_committed` means it
 * landed. Only the second is a completed operation, and only the first can be
 * safely resumed.
 */
export type TxnConsumptionState = "consumed" | "effect_committed";

/** The consumption record for one (resource, txn). */
export interface TxnConsumptionRecord {
  resource: string;
  txn: string;
  /** The operation key the consuming request was executing. */
  opKey: string;
  state: TxnConsumptionState;
  /** Set when the effect committed. */
  committedAt?: number;
}

/** Taking the single use: `first` when THIS call took it. */
export type TxnConsumeOutcome = { first: true } | { first: false; record: TxnConsumptionRecord };

/**
 * @spec txn-authorization#offline-verification — atomic first use of the
 * resource-scoped `txn` in the consumption domain, and the DURABLE state of the
 * effect it authorized. Consumption MUST be LINEARIZABLE across every replica
 * capable of executing the same operation, which is why this is a single-row
 * insert in a database replicas share, not per-process memory. The state lives
 * on the SAME row, so the cross-replica property covers it unchanged.
 */
export interface TxnConsumptionStore {
  /**
   * Take the single use for (resource, txn), recording the operation key of the
   * request taking it. Reports `first: true` exactly once; every later attempt
   * gets the STORED record, so the caller can tell a replay from a resumption
   * of its own interrupted request.
   */
  consume(resource: string, txn: string, opKey: string): TxnConsumeOutcome;
  /** Record that the irreversible effect committed. */
  commit(resource: string, txn: string): void;
  /** The consumption record, if this (resource, txn) was ever consumed. */
  get(resource: string, txn: string): TxnConsumptionRecord | undefined;
}

interface ConsumptionRow {
  resource: string;
  txn: string;
  op_key: string;
  state: TxnConsumptionState;
  committed_at: number | null;
}

class SqliteTxnConsumptionStore implements TxnConsumptionStore {
  constructor(readonly db: Database) {
    db.exec(SCHEMA);
  }

  consume(resource: string, txn: string, opKey: string): TxnConsumeOutcome {
    const took =
      this.db
        .prepare(
          `INSERT INTO txn_consumption (resource, txn, op_key, state, consumed_at, committed_at)
           VALUES (?, ?, ?, 'consumed', unixepoch(), NULL)
           ON CONFLICT(resource, txn) DO NOTHING`,
        )
        .run(resource, txn, opKey).changes === 1;
    if (took) return { first: true };
    const record = this.get(resource, txn);
    if (!record) throw new Error("txn consumption conflicted without an existing row");
    return { first: false, record };
  }

  commit(resource: string, txn: string): void {
    this.db
      .prepare(
        "UPDATE txn_consumption SET state = 'effect_committed', committed_at = unixepoch() WHERE resource = ? AND txn = ?",
      )
      .run(resource, txn);
  }

  get(resource: string, txn: string): TxnConsumptionRecord | undefined {
    const row = this.db
      .prepare("SELECT resource, txn, op_key, state, committed_at FROM txn_consumption WHERE resource = ? AND txn = ?")
      .get(resource, txn) as ConsumptionRow | undefined;
    if (!row) return undefined;
    return {
      resource: row.resource,
      txn: row.txn,
      opKey: row.op_key,
      state: row.state,
      ...(row.committed_at !== null ? { committedAt: row.committed_at } : {}),
    };
  }
}

/**
 * Open the resource-side transaction stores over ONE database. Pass `db` to
 * share it between replicas that can execute the same operation (consumption
 * must be linearizable across all of them) or `file` to share one on disk; the
 * default is this replica's own in-memory database (D27).
 */
export function openTxnStores(
  opts: StoreOptions & { db?: Database } = {},
): { pending: TxnPendingStore; consumption: TxnConsumptionStore } {
  const { db, ...storeOptions } = opts;
  const database = db ?? openStore(SCHEMA, storeOptions);
  return {
    pending: new SqliteTxnPendingStore(database),
    consumption: new SqliteTxnConsumptionStore(database),
  };
}

/** The retained pending operations alone (the challenge-issuing half). */
export function openTxnPendingStore(opts: StoreOptions & { db?: Database } = {}): TxnPendingStore {
  return openTxnStores(opts).pending;
}
