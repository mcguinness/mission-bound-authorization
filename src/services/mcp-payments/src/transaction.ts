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
   * This engine's own clock, as epoch milliseconds. The lease interval and the
   * lease-expiry comparison MUST be read from one clock, so the caller that
   * derives a lease (capping the published maximum by the permit's validity)
   * measures against the same instant `redeemPermit` stamps the row with.
   * Deliberately separate from the PEP's clock, which governs whether the
   * permit may still initiate an effect.
   */
  nowMs(): number {
    return this.now().getTime();
  }

  /**
   * Redeem a single-use permit exactly once (D28). Redemption is keyed by the
   * stable operation key (mission+action+parameter_digest), so replaying the
   * same operation, even with a freshly minted permit id, cannot
   * double-execute. Bound to the instance epoch (D39): a prior-epoch permit
   * is rejected after restart.
   *
   * @spec runtime-evidence#execution-evidence-object (issue #786): the two
   * failures are DIFFERENT and are reported separately, because the draft
   * scopes `permit_consumed` to "re-presentation of an already-consumed
   * single-use evaluation identifier" and this table keys on operation
   * identity instead. The prior operation's own `permit_id` decides:
   * equal is that re-presentation (`permit_consumed`), different is a fresh
   * permit for an operation another permit already claimed
   * (`operation_already_claimed`). The lookup is scoped to THIS instance
   * epoch: `redeemOnce` keys its table on the operation key alone and merely
   * records the epoch, so a redemption taken under a different epoch must not
   * lend its `permit_id` to this comparison. A prior row this engine cannot
   * attribute reports the narrower operation-claim failure rather than
   * asserting an evaluation identifier it never saw.
   */
  redeemPermit(input: {
    permitId: string;
    opKey: string;
    missionId: string;
    action: string;
    /**
     * @spec runtime#execution-reverification — the ABSOLUTE instant this
     * attempt's lease ends, derived by the caller from the deployment's
     * PUBLISHED maximum capped by the permit's own validity
     * (`executionLeaseMs`). Absolute, not an interval: an interval re-anchored
     * to the slightly later instant this method reads its own clock at would
     * end marginally AFTER the permit's `valid_until`, which is exactly the
     * extension of authorization a local lease must never buy.
     *
     * A lease end at or before now means no usable lease could be derived, so
     * no operation row is opened and no redemption is taken.
     */
    leaseExpiresAtMs: number;
  }): { ok: boolean; reason?: "permit_consumed" | "operation_already_claimed" | "lease_setup_failed" } {
    if (!Number.isFinite(input.leaseExpiresAtMs) || input.leaseExpiresAtMs <= this.now().getTime()) {
      return { ok: false, reason: "lease_setup_failed" };
    }
    const consumed = redeemOnce(this.db, "permit_redemptions", input.opKey, this.instanceEpoch);
    if (!consumed) {
      const prior = this.db
        .prepare("SELECT permit_id FROM operations WHERE op_key = ? AND epoch = ?")
        .get(input.opKey, this.instanceEpoch) as { permit_id: string } | undefined;
      return {
        ok: false,
        reason: prior?.permit_id === input.permitId ? "permit_consumed" : "operation_already_claimed",
      };
    }
    const leaseExpires = input.leaseExpiresAtMs;
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

/**
 * Operation idempotency key (operation-profile): `op:<mission>:<action>:<digest>`,
 * or `op:<mission>:<action>:<phase>:<digest>` where the crossing is a phase of
 * a compound action.
 *
 * @spec runtime#idempotency — "Where compound-action phases share an action
 * identifier, the idempotency scope MUST include the phase". This deployment's
 * `payments:payment.execute` serves preflight, prepare and commit crossings
 * over one action identifier and one normalized parameter form, so without the
 * phase all three would claim ONE key: the prepare crossing would burn the
 * commit crossing's claim. The phase is appended only where the profile
 * declares one, so every existing single-phase key is byte-identical.
 *
 * One key per crossing flows to every consumer that keys on operation
 * identity: permit redemption and the operation state machine here, the
 * connector's own idempotency key, the single-use transaction consumption
 * lookup, and the join key on Execution Evidence.
 */
export function operationKey(
  missionId: string,
  action: string,
  parameterDigest: string,
  actionPhase?: string,
): string {
  const scope = actionPhase === undefined ? action : `${action}:${actionPhase}`;
  return `op:${missionId}:${scope}:${parameterDigest}`;
}
