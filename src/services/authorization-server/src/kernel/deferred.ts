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
import type { AuthorityEntry, MissionClaim } from "./types.js";

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
  created_at INTEGER NOT NULL,
  last_polled_at INTEGER
) STRICT;
`;

/** Deferral lifetime (seconds): the advertised expires_in; a poll after this is expired_token. */
const DEFERRAL_EXPIRES_IN = 600;
/** Advertised poll cadence (seconds); RFC 8628: a poll faster than this is slow_down. */
const DEFERRAL_INTERVAL = 5;

export type DeferralState =
  | "authorization_pending"
  | "approved"
  | "access_denied"
  | "expired_token"
  | "slow_down";

export interface DeferralPending {
  error: "authorization_pending";
  deferral_code: string;
  expires_in: number;
  interval: number;
}

/** RFC 8628 slow_down: the client polled faster than `interval`; back off by +5s. */
export interface DeferralSlowDown {
  error: "slow_down";
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
    // Containment: the ceiling is the EFFECTIVE set, so a contained capability
    // is not deferrable.
    if (!isSubsetSet(input.requested, this.kernel.effectiveAuthoritySet(mission))) {
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
    return { error: "authorization_pending", deferral_code: code, expires_in: DEFERRAL_EXPIRES_IN, interval: DEFERRAL_INTERVAL };
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
   * Poll/redeem the deferred grant. A poll after the advertised lifetime ->
   * expired_token; a poll faster than the advertised interval -> slow_down
   * (RFC 8628). While pending -> authorization_pending; an approver denial ->
   * access_denied. On approval, gate a derivation on the active Mission and
   * issue a token whose authority is the requested subset, carrying the active
   * Mission's claim unchanged (D42). The handle is single-use: an unknown or
   * already-redeemed deferral_code is a malformed grant, so it returns
   * invalid_grant (draft §5.6), distinct from a denial.
   */
  redeem(
    deferralCode: string,
  ):
    | DeferralPending
    | DeferralSlowDown
    | { error: "expired_token" }
    | { error: "access_denied" }
    | { error: "invalid_grant" }
    | DeferredToken {
    const row = this.db.prepare("SELECT * FROM deferrals WHERE deferral_code = ?").get(deferralCode) as
      | Record<string, unknown>
      | undefined;
    if (!row) return { error: "invalid_grant" }; // unknown deferral_code
    const now = this.now().getTime();
    // The deferral_code outlived its advertised expires_in: expired_token.
    if (now > (row.created_at as number) + DEFERRAL_EXPIRES_IN * 1000) {
      return { error: "expired_token" };
    }
    if (row.state === "authorization_pending") {
      // RFC 8628: a poll faster than the advertised interval -> slow_down; the
      // client MUST back off by +5s. Otherwise record this poll's timestamp.
      const lastPolled = row.last_polled_at as number | null;
      if (lastPolled != null && now - lastPolled < DEFERRAL_INTERVAL * 1000) {
        return {
          error: "slow_down",
          deferral_code: deferralCode,
          expires_in: DEFERRAL_EXPIRES_IN,
          interval: DEFERRAL_INTERVAL + 5,
        };
      }
      this.db.prepare("UPDATE deferrals SET last_polled_at = ? WHERE deferral_code = ?").run(now, deferralCode);
      return { error: "authorization_pending", deferral_code: deferralCode, expires_in: DEFERRAL_EXPIRES_IN, interval: DEFERRAL_INTERVAL };
    }
    if (row.state === "access_denied") return { error: "access_denied" };
    if (row.redeemed === 1) return { error: "invalid_grant" }; // already redeemed

    const parsed = JSON.parse(row.requested_json as string) as { m: string; r: AuthorityEntry[] };
    // Read-only active check: revocation between approval and redemption reaches
    // AROP issuance, so a non-active Mission is refused here. The AUTHORITATIVE
    // derivation gate (active/cap check + derivation_count increment) runs once
    // at mint time via extraTokenClaims (keyed on grant_id). redeem() must NOT
    // gate here as well: gating in both places double-counts derivations (O-36).
    const mission = this.kernel.get(row.mission_id as string);
    if (!mission || this.kernel.applyExpiry(mission).state !== "active") {
      return { error: "access_denied" };
    }
    // Re-verify subset at redemption (the Mission may have changed) against the
    // EFFECTIVE set: containment applied between approval and redemption refuses.
    if (!isSubsetSet(parsed.r, this.kernel.effectiveAuthoritySet(mission))) {
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
