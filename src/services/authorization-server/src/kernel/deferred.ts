/**
 * @spec AROP DTR binding (I-D.gerber-oauth-deferred-token-response),
 * openid/authzen#531, decision D6.
 *
 * Deferred Token Response: a token request with completion_mode=deferred that
 * is requestable-denied returns a deferral_code and authorization_pending;
 * the client polls the deferred grant until approval, at which point the AS
 * records a Mission Expansion and issues a token carrying the successor
 * mission claim. Token-issuance completion (contrast M6 reevaluate mode).
 */

import { randomBytes } from "node:crypto";
import { openStore, type Database } from "@mission/store";
import type { MissionKernel } from "./kernel.js";
import { createExpansion, successorMissionClaim } from "./expansion.js";
import type { MissionIntent } from "./types.js";

export const DEFERRED_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:deferred";

const SCHEMA = `
CREATE TABLE deferrals (
  deferral_code TEXT PRIMARY KEY,
  state TEXT NOT NULL,
  predecessor_id TEXT NOT NULL,
  intent_json TEXT NOT NULL,
  client_id TEXT NOT NULL,
  approved_until TEXT,
  successor_id TEXT,
  redeemed INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
) STRICT;
`;

export type DeferralState = "authorization_pending" | "approved" | "access_denied";

export interface DeferralPending {
  error: "authorization_pending";
  deferral_code: string;
  expires_in: number;
  interval: number;
}

export class DeferralStore {
  readonly db: Database;
  constructor(
    private readonly kernel: MissionKernel,
    private readonly now: () => Date = () => new Date(),
  ) {
    this.db = openStore(SCHEMA);
  }

  /**
   * Open a deferral for a requestable-denied deferred token request.
   * Idempotent-submission (AROP): the same (predecessor, intent) returns the
   * existing pending handle rather than opening a second.
   */
  open(input: { predecessorId: string; intent: MissionIntent; clientId: string }): DeferralPending {
    const key = JSON.stringify({ p: input.predecessorId, i: input.intent });
    const existing = this.db
      .prepare("SELECT deferral_code FROM deferrals WHERE state = 'authorization_pending' AND intent_json = ? AND predecessor_id = ?")
      .get(key, input.predecessorId) as { deferral_code: string } | undefined;
    const code = existing?.deferral_code ?? `dfr_${randomBytes(18).toString("base64url")}`;
    if (!existing) {
      this.db
        .prepare(
          "INSERT INTO deferrals (deferral_code, state, predecessor_id, intent_json, client_id, created_at) VALUES (?, 'authorization_pending', ?, ?, ?, ?)",
        )
        .run(code, input.predecessorId, key, input.clientId, this.now().getTime());
    }
    return { error: "authorization_pending", deferral_code: code, expires_in: 600, interval: 5 };
  }

  /** Approver adjudication: approve records the approval expiry that bounds the credential. */
  approve(deferralCode: string, approvedUntil: string): void {
    this.db
      .prepare("UPDATE deferrals SET state = 'approved', approved_until = ? WHERE deferral_code = ? AND state = 'authorization_pending'")
      .run(approvedUntil, deferralCode);
  }

  deny(deferralCode: string): void {
    this.db.prepare("UPDATE deferrals SET state = 'access_denied' WHERE deferral_code = ?").run(deferralCode);
  }

  /**
   * Poll/redeem the deferred grant. While pending -> authorization_pending.
   * On approval, create the Mission Expansion and return the successor
   * mission claim; the handle is single-use (redeemed once).
   */
  redeem(
    deferralCode: string,
    approver: { iss: string; sub: string },
  ): DeferralPending | { error: "access_denied" } | { mission: Record<string, unknown>; successorId: string } {
    const row = this.db.prepare("SELECT * FROM deferrals WHERE deferral_code = ?").get(deferralCode) as
      | Record<string, unknown>
      | undefined;
    if (!row) return { error: "access_denied" };
    if (row.state === "authorization_pending") {
      return { error: "authorization_pending", deferral_code: deferralCode, expires_in: 600, interval: 5 };
    }
    if (row.state === "access_denied") return { error: "access_denied" };
    if (row.redeemed === 1) return { error: "access_denied" }; // single redemption

    // intent_json wraps { p, i }; the intent is the `i` member.
    const parsed = JSON.parse(row.intent_json as string) as { p: string; i: MissionIntent };
    const { successor } = createExpansion(this.kernel, {
      predecessorId: row.predecessor_id as string,
      intent: parsed.i,
      approver,
      approvalEventId: `apev_dfr_${deferralCode}`,
      approvedUntil: row.approved_until as string,
    });
    this.db.prepare("UPDATE deferrals SET redeemed = 1, successor_id = ? WHERE deferral_code = ?").run(successor.id, deferralCode);
    // First redemption supersedes the predecessor.
    this.kernel.supersedeOnRedemption(successor.id);
    return { mission: successorMissionClaim(this.kernel, successor), successorId: successor.id };
  }
}
