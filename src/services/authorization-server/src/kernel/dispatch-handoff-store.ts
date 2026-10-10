/**
 * @spec mission-template#dispatch-handoff (#1158, D361, #1163 review): the
 * consumed Dispatch Handoff grants. A handoff grant is single use: its `jti`
 * is taken ATOMICALLY (one INSERT on the primary key, so two concurrent
 * redemptions cannot both hold it) and, once a token is issued, REMEMBERED
 * for as long as the grant could otherwise be accepted, clock skew included.
 * Nothing evicts a row before that horizon: a consumed, still-valid grant
 * never becomes redeemable again because the store filled up. Rows past the
 * horizon are pruned on write.
 *
 * Taking is two-phase so that a redemption which issues no token (a
 * transient authority-source outage, a refused gate) leaves the grant
 * redeemable: {@link DispatchHandoffStore.reserve} holds the `jti` while the
 * token is minted, {@link DispatchHandoffStore.confirm} marks it consumed
 * once the token exists, and {@link DispatchHandoffStore.release} drops a
 * reservation that issued nothing. A concurrent redemption meets the
 * reservation and is told to retry; once confirmed, it is refused.
 *
 * Its own table over its own store handle (the {@link MissionBoundGrantStore}
 * idiom). In-memory, built per boot like every AS store (D25/D27). The AS
 * signing keys are generated per boot too, so a grant minted before a restart
 * no longer verifies after it, and a restart cannot revive a consumed grant.
 * A deployment with persistent signing keys requires persistent consumption
 * records.
 */

import { type Database, openStore } from "@mission/store";

const SCHEMA = `
CREATE TABLE dispatch_handoff_consumed (
  jti TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('reserved', 'consumed')),
  remember_until_ms INTEGER NOT NULL,
  taken_at TEXT NOT NULL
) STRICT;
`;

/** How long past a grant's `exp` a consumed `jti` is still remembered: the clock-skew allowance. */
export const DISPATCH_HANDOFF_SKEW_MS = 5 * 60 * 1000;

/** The outcome of {@link DispatchHandoffStore.reserve}. */
export type DispatchHandoffReservation = "reserved" | "in-progress" | "consumed";

export class DispatchHandoffStore {
  readonly db: Database;
  constructor(private readonly now: () => Date = () => new Date()) {
    this.db = openStore(SCHEMA);
  }

  /**
   * Take `jti` for one redemption, remembering it until `expMs` plus the skew
   * allowance. `"reserved"` when this call took it; `"in-progress"` when a
   * concurrent redemption holds it; `"consumed"` when a token was already
   * issued under it (a replay).
   */
  reserve(input: { jti: string; missionId: string; expMs: number }): DispatchHandoffReservation {
    const nowMs = this.now().getTime();
    this.db.prepare("DELETE FROM dispatch_handoff_consumed WHERE remember_until_ms < ?").run(nowMs);
    const result = this.db
      .prepare(
        `INSERT INTO dispatch_handoff_consumed (jti, mission_id, state, remember_until_ms, taken_at)
         VALUES (?, ?, 'reserved', ?, ?)
         ON CONFLICT (jti) DO NOTHING`,
      )
      .run(input.jti, input.missionId, input.expMs + DISPATCH_HANDOFF_SKEW_MS, new Date(nowMs).toISOString());
    if (result.changes === 1) return "reserved";
    const row = this.db.prepare("SELECT state FROM dispatch_handoff_consumed WHERE jti = ?").get(input.jti) as
      | { state: string }
      | undefined;
    return row?.state === "consumed" ? "consumed" : "in-progress";
  }

  /** A token was issued under the reservation: the grant is consumed. */
  confirm(jti: string): void {
    this.db
      .prepare("UPDATE dispatch_handoff_consumed SET state = 'consumed' WHERE jti = ? AND state = 'reserved'")
      .run(jti);
  }

  /** The reservation issued nothing: the grant stays redeemable. A consumed grant is never released. */
  release(jti: string): void {
    this.db.prepare("DELETE FROM dispatch_handoff_consumed WHERE jti = ? AND state = 'reserved'").run(jti);
  }
}
