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

/** One committed effect, on either connector. */
export interface CommittedEffect {
  opKey: string;
  permitId: string;
  missionId: string;
  /** A wire's amount; an email has none. */
  amount?: string;
  committedAtMs: number;
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

  /**
   * The operation key a permit's effect committed under, on either connector,
   * or `undefined` when no effect committed for it. The reconciliation
   * oracle: a committed entry is an effect, whatever evidence went missing.
   */
  committedFor(permitId: string): string | undefined {
    const row = this.db
      .prepare("SELECT op_key FROM ledger WHERE permit_id = ? UNION ALL SELECT op_key FROM outbox WHERE permit_id = ? LIMIT 1")
      .get(permitId, permitId) as { op_key: string } | undefined;
    return row?.op_key;
  }

  /**
   * Every committed effect on either connector, a wire or an email, with the
   * instant it committed: the effect side of reconciliation (`reconcile.ts`).
   * An email carries no amount.
   */
  committedEffects(missionId?: string): CommittedEffect[] {
    const union = `SELECT op_key, permit_id, mission_id, amount, committed_at FROM ledger
      UNION ALL SELECT op_key, permit_id, mission_id, NULL AS amount, sent_at AS committed_at FROM outbox`;
    const rows = (
      missionId
        ? this.db.prepare(`SELECT * FROM (${union}) WHERE mission_id = ?`).all(missionId)
        : this.db.prepare(union).all()
    ) as Array<{ op_key: string; permit_id: string; mission_id: string; amount: string | null; committed_at: number }>;
    return rows.map((r) => ({
      opKey: r.op_key,
      permitId: r.permit_id,
      missionId: r.mission_id,
      ...(r.amount !== null ? { amount: r.amount } : {}),
      committedAtMs: r.committed_at,
    }));
  }

  ledgerEntries(missionId?: string): Array<Record<string, unknown>> {
    return (
      missionId
        ? this.db.prepare("SELECT * FROM ledger WHERE mission_id = ?").all(missionId)
        : this.db.prepare("SELECT * FROM ledger").all()
    ) as Array<Record<string, unknown>>;
  }
}
