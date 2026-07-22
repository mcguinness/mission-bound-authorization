/**
 * @spec operation-profile-payments-v1 (idempotency keys), D36 (commit point)
 *
 * Simulated irreversible connectors: the wire-transfer ledger and the email
 * outbox. Both accept an operation idempotency key and dedupe on it, so a
 * recovery re-drive after a mid-flight crash cannot double-execute. These are
 * also the side-effect oracle (D40): every mutation records its authorizing
 * permit, giving evals ground truth for "zero unauthorized side effects".
 */

import { openStore, type Database } from "@mission/store";

const SCHEMA = `
CREATE TABLE ledger (
  op_key TEXT PRIMARY KEY,
  invoice_id TEXT NOT NULL,
  payee_account TEXT NOT NULL,
  amount TEXT NOT NULL,
  currency TEXT NOT NULL,
  permit_id TEXT NOT NULL,
  mission_id TEXT NOT NULL,
  committed_at INTEGER NOT NULL
) STRICT;
CREATE TABLE outbox (
  op_key TEXT PRIMARY KEY,
  invoice_id TEXT NOT NULL,
  to_addr TEXT NOT NULL,
  permit_id TEXT NOT NULL,
  mission_id TEXT NOT NULL,
  sent_at INTEGER NOT NULL
) STRICT;
`;

export interface WireCommit {
  opKey: string;
  invoiceId: string;
  payeeAccount: string;
  amount: string;
  currency: string;
  permitId: string;
  missionId: string;
}
export interface EmailCommit {
  opKey: string;
  invoiceId: string;
  to: string;
  permitId: string;
  missionId: string;
}

export interface CommitResult {
  committed: boolean;
  deduped: boolean;
}

export class Connectors {
  readonly db: Database;
  private nowMs: () => number;
  constructor(now: () => Date = () => new Date()) {
    this.db = openStore(SCHEMA);
    this.nowMs = () => now().getTime();
  }

  /** The commit point (D36): after this returns committed, the wire is real. */
  postWire(c: WireCommit): CommitResult {
    const existing = this.db.prepare("SELECT op_key FROM ledger WHERE op_key = ?").get(c.opKey);
    if (existing) return { committed: true, deduped: true };
    this.db
      .prepare(
        "INSERT INTO ledger (op_key, invoice_id, payee_account, amount, currency, permit_id, mission_id, committed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(c.opKey, c.invoiceId, c.payeeAccount, c.amount, c.currency, c.permitId, c.missionId, this.nowMs());
    return { committed: true, deduped: false };
  }

  sendEmail(c: EmailCommit): CommitResult {
    const existing = this.db.prepare("SELECT op_key FROM outbox WHERE op_key = ?").get(c.opKey);
    if (existing) return { committed: true, deduped: true };
    this.db
      .prepare("INSERT INTO outbox (op_key, invoice_id, to_addr, permit_id, mission_id, sent_at) VALUES (?, ?, ?, ?, ?, ?)")
      .run(c.opKey, c.invoiceId, c.to, c.permitId, c.missionId, this.nowMs());
    return { committed: true, deduped: false };
  }

  ledgerEntries(missionId?: string): Array<Record<string, unknown>> {
    return (
      missionId
        ? this.db.prepare("SELECT * FROM ledger WHERE mission_id = ?").all(missionId)
        : this.db.prepare("SELECT * FROM ledger").all()
    ) as Array<Record<string, unknown>>;
  }
}
