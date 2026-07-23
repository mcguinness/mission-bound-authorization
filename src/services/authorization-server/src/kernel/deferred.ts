/**
 * @spec AROP DTR binding (I-D.gerber-oauth-deferred-token-response),
 * openid/authzen#531, decisions D5, D42.
 *
 * Deferred Token Response for AROP. A token request with
 * completion_mode=deferred that is requestable-denied returns a deferral_code
 * and authorization_pending; the client polls the deferred grant until
 * approval, at which point the AS issues a token whose granted authority is a
 * SUBSET of the active Mission's Authority Set. Per D42, AROP never creates or
 * widens a Mission: it carries the active Mission reference unchanged. Widening
 * is the separate Expansion flow (see expansion.ts). Token-issuance completion
 * (contrast M6 reevaluate mode, which issues no token).
 */

import { randomBytes } from "node:crypto";
import { openStore, type Database } from "@mission/store";
import { isSubsetSet } from "./derive.js";
import type { MissionKernel } from "./kernel.js";
import type { AuthorityEntry, MissionClaim, MissionRecord } from "./types.js";

export const DEFERRED_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:deferred";

const SCHEMA = `
CREATE TABLE deferrals (
  deferral_code TEXT PRIMARY KEY,
  state TEXT NOT NULL,
  mission_id TEXT NOT NULL,
  requested_json TEXT NOT NULL,
  client_id TEXT NOT NULL,
  approved_until TEXT,
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

export interface DeferredToken {
  /** The active Mission claim, carried unchanged (D42: no successor). */
  mission: MissionClaim;
  /** Granted authority: a subset of the active Mission's Authority Set. */
  authorization_details: AuthorityEntry[];
  /** Credential bound never outlives the recorded approval expiry. */
  approved_until: string;
}

export class DeferralError extends Error {
  constructor(
    readonly code: "out_of_authority",
    message: string,
  ) {
    super(message);
  }
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
   * Open a deferral for a requestable-denied deferred token request. The
   * requested authority MUST be within the active Mission (D42): a request
   * that would widen the Mission is not an AROP case -- it requires Expansion
   * first, so this refuses with out_of_authority rather than deferring.
   * Idempotent submission (AROP): the same (mission, requested) returns the
   * existing pending handle.
   */
  open(input: { missionId: string; requested: AuthorityEntry[]; clientId: string }): DeferralPending {
    const mission = this.kernel.get(input.missionId);
    if (!mission || this.kernel.applyExpiry(mission).state !== "active") {
      throw new DeferralError("out_of_authority", "mission is not active");
    }
    // @spec D42: AROP grant is a subset of the active Mission; widening -> Expansion.
    if (!isSubsetSet(input.requested, mission.authority_set)) {
      throw new DeferralError(
        "out_of_authority",
        "requested authority exceeds the active Mission; use Expansion to widen",
      );
    }
    const key = JSON.stringify({ m: input.missionId, r: input.requested });
    const existing = this.db
      .prepare("SELECT deferral_code FROM deferrals WHERE state = 'authorization_pending' AND requested_json = ? AND mission_id = ?")
      .get(key, input.missionId) as { deferral_code: string } | undefined;
    const code = existing?.deferral_code ?? `dfr_${randomBytes(18).toString("base64url")}`;
    if (!existing) {
      this.db
        .prepare(
          "INSERT INTO deferrals (deferral_code, state, mission_id, requested_json, client_id, created_at) VALUES (?, 'authorization_pending', ?, ?, ?, ?)",
        )
        .run(code, input.missionId, key, input.clientId, this.now().getTime());
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
   * Poll/redeem the deferred grant. While pending -> authorization_pending. On
   * approval, gate a derivation on the active Mission and issue a token whose
   * authority is the requested subset, carrying the active Mission's claim
   * unchanged (D42). The handle is single-use.
   */
  redeem(deferralCode: string): DeferralPending | { error: "access_denied" } | DeferredToken {
    const row = this.db.prepare("SELECT * FROM deferrals WHERE deferral_code = ?").get(deferralCode) as
      | Record<string, unknown>
      | undefined;
    if (!row) return { error: "access_denied" };
    if (row.state === "authorization_pending") {
      return { error: "authorization_pending", deferral_code: deferralCode, expires_in: 600, interval: 5 };
    }
    if (row.state === "access_denied") return { error: "access_denied" };
    if (row.redeemed === 1) return { error: "access_denied" }; // single redemption

    const parsed = JSON.parse(row.requested_json as string) as { m: string; r: AuthorityEntry[] };
    // Derivation gate: refuses if the Mission is no longer active (revocation
    // reaches AROP issuance too). Throws GateError.
    const mission: MissionRecord = this.kernel.gateDerivation(row.mission_id as string);
    // Re-verify subset at redemption (the Mission may have changed).
    if (!isSubsetSet(parsed.r, mission.authority_set)) {
      this.db.prepare("UPDATE deferrals SET state = 'access_denied' WHERE deferral_code = ?").run(deferralCode);
      return { error: "access_denied" };
    }
    this.db.prepare("UPDATE deferrals SET redeemed = 1 WHERE deferral_code = ?").run(deferralCode);
    return {
      mission: this.kernel.missionClaim(mission),
      authorization_details: parsed.r,
      approved_until: row.approved_until as string,
    };
  }
}
