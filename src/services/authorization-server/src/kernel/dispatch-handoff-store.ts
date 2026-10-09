/**
 * @spec mission-template#dispatch-handoff (#1158, D361): the consumed
 * Dispatch Handoff grants. A handoff grant is single use: its `jti` is
 * consumed ATOMICALLY (one INSERT on the primary key, so two concurrent
 * redemptions cannot both succeed) and REMEMBERED for as long as the grant
 * could otherwise be accepted, clock skew included. Nothing evicts a row
 * before that horizon: a consumed, still-valid grant never becomes redeemable
 * again because the store filled up. Rows past the horizon are pruned on
 * write. Its own table over its own store handle (the
 * {@link MissionBoundGrantStore} idiom). In-memory, built per boot like every
 * AS store (D25/D27); the AS signing keys are generated per boot too, so a
 * grant minted before a restart no longer verifies after it, and a restart
 * cannot revive a consumed grant either.
 */

import { type Database, openStore } from "@mission/store";

const SCHEMA = `
CREATE TABLE dispatch_handoff_consumed (
  jti TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL,
  remember_until_ms INTEGER NOT NULL,
  consumed_at TEXT NOT NULL
) STRICT;
`;

/** How long past a grant's `exp` a consumed `jti` is still remembered: the clock-skew allowance. */
export const DISPATCH_HANDOFF_SKEW_MS = 5 * 60 * 1000;

export class DispatchHandoffStore {
  readonly db: Database;
  constructor(private readonly now: () => Date = () => new Date()) {
    this.db = openStore(SCHEMA);
  }

  /**
   * Consume `jti`, remembering it until `expMs` plus the skew allowance.
   * Returns false when the `jti` was already consumed (a replay).
   */
  consume(input: { jti: string; missionId: string; expMs: number }): boolean {
    const nowMs = this.now().getTime();
    this.db.prepare("DELETE FROM dispatch_handoff_consumed WHERE remember_until_ms < ?").run(nowMs);
    const result = this.db
      .prepare(
        `INSERT INTO dispatch_handoff_consumed (jti, mission_id, remember_until_ms, consumed_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT (jti) DO NOTHING`,
      )
      .run(input.jti, input.missionId, input.expMs + DISPATCH_HANDOFF_SKEW_MS, new Date(nowMs).toISOString());
    return result.changes === 1;
  }
}
