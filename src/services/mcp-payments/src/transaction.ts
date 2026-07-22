/**
 * @spec runtime (transaction-assurance tier), D28 (PEP-owned redemption),
 * D36 (irreversible operation state machine)
 *
 * The transaction-assurance tier: the PEP owns single-use permit redemption
 * (redeemOnce), the execution lease, and the operation state machine
 * reserved -> permit_consumed -> connector_committed -> evidence_emitted ->
 * reconciled. The PDP declared the permit (single_use, permit_expires_at);
 * the PEP consumes it exactly once, bound to its instance epoch.
 */

import { openStore, redeemOnce, redemptionSchema, type Database } from "@mission/store";

const SCHEMA = `
${redemptionSchema("permit_redemptions")}
CREATE TABLE operations (
  op_key TEXT PRIMARY KEY,
  permit_id TEXT NOT NULL,
  mission_id TEXT NOT NULL,
  action TEXT NOT NULL,
  epoch TEXT NOT NULL,
  state TEXT NOT NULL,
  lease_expires_at INTEGER NOT NULL
) STRICT;
`;

export type OpState =
  | "reserved"
  | "permit_consumed"
  | "connector_committed"
  | "evidence_emitted"
  | "reconciled"
  | "abandoned";

export class TransactionEngine {
  readonly db: Database;
  constructor(
    readonly instanceEpoch: string,
    private readonly now: () => Date = () => new Date(),
  ) {
    this.db = openStore(SCHEMA);
  }

  /**
   * Redeem a single-use permit exactly once (D28). Redemption is keyed by the
   * stable operation key (mission+action+parameter_digest), so replaying the
   * same operation -- even with a freshly minted permit id -- is refused as
   * permit_consumed and cannot double-execute. Bound to the instance epoch
   * (D39): a prior-epoch permit is rejected after restart.
   */
  redeemPermit(input: {
    permitId: string;
    opKey: string;
    missionId: string;
    action: string;
    leaseSeconds: number;
  }): { ok: boolean; reason?: "permit_consumed" | "lease_setup_failed" } {
    const consumed = redeemOnce(this.db, "permit_redemptions", input.opKey, this.instanceEpoch);
    if (!consumed) return { ok: false, reason: "permit_consumed" };
    const leaseExpires = this.now().getTime() + input.leaseSeconds * 1000;
    this.db
      .prepare(
        "INSERT INTO operations (op_key, permit_id, mission_id, action, epoch, state, lease_expires_at) VALUES (?, ?, ?, ?, ?, 'permit_consumed', ?)",
      )
      .run(input.opKey, input.permitId, input.missionId, input.action, this.instanceEpoch, leaseExpires);
    return { ok: true };
  }

  /** The lease covers validation and pre-commit only (D36). */
  leaseValid(opKey: string): boolean {
    const row = this.db.prepare("SELECT lease_expires_at, state FROM operations WHERE op_key = ?").get(opKey) as
      | { lease_expires_at: number; state: OpState }
      | undefined;
    if (!row) return false;
    if (row.state === "connector_committed") return true; // past the commit point
    return this.now().getTime() <= row.lease_expires_at;
  }

  advance(opKey: string, to: OpState): void {
    this.db.prepare("UPDATE operations SET state = ? WHERE op_key = ?").run(to, opKey);
  }

  state(opKey: string): OpState | undefined {
    const row = this.db.prepare("SELECT state FROM operations WHERE op_key = ?").get(opKey) as
      | { state: OpState }
      | undefined;
    return row?.state;
  }
}

/** Operation idempotency key (operation-profile): op:<mission>:<action>:<digest>. */
export function operationKey(missionId: string, action: string, parameterDigest: string): string {
  return `op:${missionId}:${action}:${parameterDigest}`;
}
