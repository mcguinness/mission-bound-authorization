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
import { openStore, withTransaction, type Database } from "@mission/store";
import { CreationIdempotencyStore } from "./creation-idempotency.js";
import { isSubsetSet } from "./derive.js";
import { createExpansion } from "./expansion.js";
import { IntentError } from "./intent.js";
import type { MissionKernel } from "./kernel.js";
import type {
  AuthorityEntry,
  IntentSubmissionEvidenceFact,
  MissionClaim,
  MissionIntent,
  MissionRecord,
} from "./types.js";

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
export const DEFERRAL_EXPIRES_IN = 600;
/** Advertised poll cadence (seconds); RFC 8628: a poll faster than this is slow_down. */
export const DEFERRAL_INTERVAL = 5;

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
    // @spec expansion#creation-request-id (deferred mode, shared rule) — the
    // dedup key is CLIENT-SCOPED: the same semantic request from two different
    // clients MUST open two deferrals (per-client scoping prevents cross-client
    // interference and replay). The previous {m, r} key omitted the client.
    const key = JSON.stringify({ m: input.missionId, r: input.requested, c: input.clientId });
    const existing = this.db
      .prepare(
        "SELECT deferral_code FROM deferrals WHERE state = 'authorization_pending' AND requested_json = ? AND mission_id = ? AND client_id = ?",
      )
      .get(key, input.missionId, input.clientId) as { deferral_code: string } | undefined;
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

    const parsed = JSON.parse(row.requested_json as string) as { m: string; r: AuthorityEntry[]; c?: string };
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

// ---------------------------------------------------------------------------
// @spec expansion (DTR deferred-completion binding) — Mission EXPANSION as an
// RFC 8693 token exchange whose fresh approval is asynchronous. Distinct from
// AROP: AROP (DeferralStore above) NEVER widens (D42), so a widening request is
// refused there. Expansion IS the widening path, so it needs its own deferral
// store with its own table; the AROP store and its D42 subset invariant stay
// untouched. On approval the deferred exchange creates the successor Mission via
// createExpansion (the async Approver DID consent, so the approval_basis is real,
// never fabricated).
// ---------------------------------------------------------------------------

const EXPANSION_SCHEMA = `
CREATE TABLE expansion_deferrals (
  deferral_code TEXT PRIMARY KEY,
  state TEXT NOT NULL,
  predecessor_id TEXT NOT NULL,
  intent_json TEXT NOT NULL,
  client_id TEXT NOT NULL,
  jkt TEXT NOT NULL,
  creation_request_id TEXT,
  pred_containment_version INTEGER NOT NULL,
  submission_evidence_json TEXT,
  approver_json TEXT,
  approval_event_id TEXT,
  approved_until TEXT,
  redeemed INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  last_polled_at INTEGER
) STRICT;
`;

/** The Approver's async adjudication payload for a deferred expansion. */
export interface ExpansionApproval {
  approver: { iss: string; sub: string };
  approvalEventId: string;
  /** Bounds the successor credential; MUST NOT be exceeded (approved_until). */
  approvedUntil: string;
}

/** The successful redemption of a deferred expansion: the created successor. */
export interface ExpansionDeferredResult {
  successor: MissionRecord;
  approvedUntil: string;
  /** The creation_request_id recorded at initiation (the handler attaches the
   *  delivery artifact to the completed idempotency operation). */
  creationRequestId?: string;
}

export class ExpansionDeferralError extends Error {
  constructor(
    readonly code: "predecessor_not_active",
    message: string,
  ) {
    super(message);
  }
}

/**
 * @spec expansion — the DTR deferred-completion store for Mission Expansion.
 * Mirrors {@link DeferralStore}'s poll/interval/expiry shape, but its redemption
 * CREATES a successor Mission (widening) rather than issuing an AROP subset. It
 * records, AT REQUEST TIME, the predecessor binding, the acting client, the
 * possession key (`jkt`), and a snapshot of the predecessor containment version.
 *
 * Deferred-window checks (@spec expansion#deferred-window):
 *  (a) predecessor STATE is re-verified AT REDEMPTION (completion): a predecessor
 *      terminated, superseded, or NEWLY CONTAINED during the deferred window fails
 *      completion (a deferred approval MUST NOT become a containment bypass). A
 *      predecessor that was ALREADY contained at request time stays expandable
 *      (containment#restoration): the check is on whether containment ADVANCED
 *      during the window (version delta), not on the presence of an overlay.
 *  (b) the `subject_token` is deliberately NOT stored and NOT re-verified here:
 *      its expiry MUST NOT gate completion. Possession was evaluated and RECORDED
 *      (the `jkt`) at request time; re-verification is of Mission STATE only.
 */
export class ExpansionDeferralStore {
  readonly db: Database;
  /** @spec expansion#creation-request-id — completion marks the reservation
   *  completed ATOMICALLY with successor creation. Instances over the same
   *  kernel share the table, so this internal instance needs no wiring. */
  private readonly creationIdempotency: CreationIdempotencyStore;
  constructor(
    private readonly kernel: MissionKernel,
    private readonly now: () => Date = () => new Date(),
  ) {
    this.db = openStore(EXPANSION_SCHEMA);
    this.creationIdempotency = new CreationIdempotencyStore(kernel);
  }

  /**
   * Open a deferred expansion. The predecessor MUST be active at request time.
   * Records the possession `jkt` and the predecessor containment-version snapshot
   * (deferred-window check (a) baseline). Idempotent for the same (predecessor,
   * intent, client): returns the existing pending handle.
   */
  open(input: {
    predecessorId: string;
    intent: MissionIntent;
    /**
     * @spec mission#authority-proposal — the authority proposal submitted on
     * the standard `authorization_details` parameter of the widening exchange
     * (already validated at intake). Part of the deferral's idempotency key: a
     * changed proposal is a changed approval context and opens a NEW deferral,
     * so all three commitments recompute together at successor creation.
     */
    proposedAuthority?: AuthorityEntry[];
    clientId: string;
    jkt: string;
    /**
     * @spec expansion#creation-request-id — the REQUIRED creation identifier
     * (the wire handler always passes it; optional here so kernel-level unit
     * use stays valid). Part of the dedup key: distinct identifiers are
     * distinct creation operations and open distinct deferrals.
     */
    creationRequestId?: string;
    /**
     * @spec mission#intent-submission-evidence — the VERIFIED evidence facts
     * of the widening submission (stage-2 output, verified at INITIATION).
     * Persisted across the deferred window and landed on the successor at
     * redemption; NOT part of the dedup key (the presented evidence is
     * already in the creation fingerprint; the same submission re-verifies
     * to the same facts modulo `verified_at`).
     */
    submissionEvidence?: IntentSubmissionEvidenceFact[];
  }): DeferralPending {
    const predecessor = this.kernel.get(input.predecessorId);
    if (!predecessor || this.kernel.applyExpiry(predecessor).state !== "active") {
      throw new ExpansionDeferralError("predecessor_not_active", "predecessor mission is not active");
    }
    const snapshotCv = predecessor.containment?.containment_version ?? 0;
    const proposal = input.proposedAuthority?.length ? input.proposedAuthority : undefined;
    // Client-scoped (the `c` member AND the explicit column predicate below):
    // the same widening request from two different clients opens two deferrals.
    // A creation_request_id, when carried, joins the key: one identifier is ONE
    // creation operation, so distinct identifiers never coalesce.
    const key = JSON.stringify({
      p: input.predecessorId,
      i: input.intent,
      c: input.clientId,
      ...(proposal ? { pr: proposal } : {}),
      ...(input.creationRequestId ? { crid: input.creationRequestId } : {}),
    });
    const existing = this.db
      .prepare(
        "SELECT deferral_code FROM expansion_deferrals WHERE state = 'authorization_pending' AND intent_json = ? AND client_id = ?",
      )
      .get(key, input.clientId) as { deferral_code: string } | undefined;
    const code = existing?.deferral_code ?? `xdfr_${randomBytes(18).toString("base64url")}`;
    if (!existing) {
      this.db
        .prepare(
          "INSERT INTO expansion_deferrals (deferral_code, state, predecessor_id, intent_json, client_id, jkt, creation_request_id, pred_containment_version, submission_evidence_json, created_at) VALUES (?, 'authorization_pending', ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .run(
          code,
          input.predecessorId,
          key,
          input.clientId,
          input.jkt,
          input.creationRequestId ?? null,
          snapshotCv,
          input.submissionEvidence?.length ? JSON.stringify(input.submissionEvidence) : null,
          this.now().getTime(),
        );
    }
    return {
      error: "authorization_pending",
      deferral_code: code,
      expires_in: DEFERRAL_EXPIRES_IN,
      interval: DEFERRAL_INTERVAL,
    };
  }

  /** Approver adjudication: records the approver, the approval event, and the expiry. */
  approve(deferralCode: string, approval: ExpansionApproval): void {
    this.db
      .prepare(
        "UPDATE expansion_deferrals SET state = 'approved', approver_json = ?, approval_event_id = ?, approved_until = ? WHERE deferral_code = ? AND state = 'authorization_pending'",
      )
      .run(
        JSON.stringify(approval.approver),
        approval.approvalEventId,
        approval.approvedUntil,
        deferralCode,
      );
  }

  deny(deferralCode: string): void {
    this.db
      .prepare("UPDATE expansion_deferrals SET state = 'access_denied' WHERE deferral_code = ?")
      .run(deferralCode);
  }

  /** The possession key recorded at request time (the handler re-binds the minted token to it). */
  recordedJkt(deferralCode: string): string | undefined {
    const row = this.db
      .prepare("SELECT jkt FROM expansion_deferrals WHERE deferral_code = ?")
      .get(deferralCode) as { jkt: string } | undefined;
    return row?.jkt;
  }

  /** The acting client recorded at request time (the handler re-checks the poller). */
  recordedClientId(deferralCode: string): string | undefined {
    const row = this.db
      .prepare("SELECT client_id FROM expansion_deferrals WHERE deferral_code = ?")
      .get(deferralCode) as { client_id: string } | undefined;
    return row?.client_id;
  }

  /**
   * Poll/redeem a deferred expansion. Mirrors {@link DeferralStore.redeem}'s
   * poll/interval/expiry states. On approval it runs the deferred-window check (a)
   * against Mission STATE (never the expired subject_token, check (b)) and then
   * CREATES the successor via createExpansion. Single-use.
   */
  redeem(
    deferralCode: string,
  ):
    | DeferralPending
    | DeferralSlowDown
    | { error: "expired_token" }
    | { error: "access_denied" }
    | { error: "invalid_grant" }
    | ExpansionDeferredResult {
    const row = this.db
      .prepare("SELECT * FROM expansion_deferrals WHERE deferral_code = ?")
      .get(deferralCode) as Record<string, unknown> | undefined;
    if (!row) return { error: "invalid_grant" };

    // Round-5 (#640 review): a COMMITTED operation is recognized BEFORE the
    // deferral-code lifetime check: a sufficiently delayed restart must
    // recover the committed successor, never report expired_token, and
    // never convert the operation to access_denied. Guarded on
    // redeemed !== 1 so the handle stays single-use.
    if (
      row.redeemed !== 1 &&
      typeof row.approval_event_id === "string" &&
      row.approval_event_id
    ) {
      const linked = this.kernel.successorByApprovalEvent(
        row.predecessor_id as string,
        row.approval_event_id,
      );
      if (linked) {
        this.kernel.drainExpansionOutbox();
        this.db
          .prepare("UPDATE expansion_deferrals SET redeemed = 1 WHERE deferral_code = ?")
          .run(deferralCode);
        const recoveredCreationRequestId =
          typeof row.creation_request_id === "string" && row.creation_request_id
            ? row.creation_request_id
            : undefined;
        return {
          successor: linked,
          approvedUntil: row.approved_until as string,
          ...(recoveredCreationRequestId ? { creationRequestId: recoveredCreationRequestId } : {}),
        };
      }
    }
    const now = this.now().getTime();
    if (now > (row.created_at as number) + DEFERRAL_EXPIRES_IN * 1000) {
      return { error: "expired_token" };
    }
    if (row.state === "authorization_pending") {
      const lastPolled = row.last_polled_at as number | null;
      if (lastPolled != null && now - lastPolled < DEFERRAL_INTERVAL * 1000) {
        return {
          error: "slow_down",
          deferral_code: deferralCode,
          expires_in: DEFERRAL_EXPIRES_IN,
          interval: DEFERRAL_INTERVAL + 5,
        };
      }
      this.db
        .prepare("UPDATE expansion_deferrals SET last_polled_at = ? WHERE deferral_code = ?")
        .run(now, deferralCode);
      return {
        error: "authorization_pending",
        deferral_code: deferralCode,
        expires_in: DEFERRAL_EXPIRES_IN,
        interval: DEFERRAL_INTERVAL,
      };
    }
    if (row.state === "access_denied") return { error: "access_denied" };
    if (row.redeemed === 1) return { error: "invalid_grant" };

    // @spec expansion#deferred-window check (a): re-verify predecessor STATE at
    // completion. A predecessor terminated/superseded during the window fails.
    const predecessor = this.kernel.get(row.predecessor_id as string);
    if (!predecessor || this.kernel.applyExpiry(predecessor).state !== "active") {
      this.db
        .prepare("UPDATE expansion_deferrals SET state = 'access_denied' WHERE deferral_code = ?")
        .run(deferralCode);
      return { error: "access_denied" };
    }
    // @spec expansion#deferred-window check (a): containment that ADVANCED during
    // the window fails completion (the deferred approval MUST NOT bypass a
    // containment applied after the request). A predecessor already contained at
    // request time still expands (containment#restoration) because the version is
    // unchanged.
    const currentCv = predecessor.containment?.containment_version ?? 0;
    if (currentCv !== (row.pred_containment_version as number)) {
      this.db
        .prepare("UPDATE expansion_deferrals SET state = 'access_denied' WHERE deferral_code = ?")
        .run(deferralCode);
      return { error: "access_denied" };
    }

    const recorded = JSON.parse(row.intent_json as string) as {
      i: MissionIntent;
      pr?: AuthorityEntry[];
    };
    const intent = recorded.i;
    const approver = JSON.parse(row.approver_json as string) as { iss: string; sub: string };
    // @spec expansion#creation-request-id — the successor INSERT and the
    // idempotency-reservation completion commit in ONE kernel-db transaction
    // (createExpansion's insertRecord nests as a savepoint), so a lost response
    // after this commit is recovered by an initiation retry finding the
    // completed operation. Credential minting happens after, in the handler.
    const creationRequestId =
      typeof row.creation_request_id === "string" && row.creation_request_id
        ? row.creation_request_id
        : undefined;
    // @spec mission#intent-submission-evidence — the facts verified at
    // INITIATION, persisted across the deferred window, land on the successor.
    const submissionEvidence = row.submission_evidence_json
      ? (JSON.parse(row.submission_evidence_json as string) as IntentSubmissionEvidenceFact[])
      : undefined;
    // @spec expansion#superseded-state + mission#lifecycle (effective-active):
    // successor creation, idempotency completion, and predecessor supersession
    // commit as ONE transaction, with the predecessor re-checked expiry-aware
    // INSIDE it, so successor authority is never issued past a predecessor
    // that stopped being effectively active between check and commit. The
    // handler mints only after this commit succeeds.
    // @spec expansion#successor-expiry — completion inherits the issuance
    // profile's atomic creation-time check. Where the submission's requested
    // ceiling (or the recorded approval expiry) has passed while the expansion
    // was pending, `insertRecord` refuses inside the creation transaction: the
    // whole transaction rolls back, no successor exists, and the exchange fails
    // with this profile's denial semantics, the same path a predecessor that
    // stopped being effectively active takes.
    let txOut: { successor: MissionRecord; predecessorId: string } | undefined;
    try {
      txOut = this.redeemInTransaction(row, intent, recorded, approver, submissionEvidence, creationRequestId);
    } catch (e) {
      if (!(e instanceof IntentError)) throw e;
      txOut = undefined;
    }
    if (!txOut) {
      this.db
        .prepare("UPDATE expansion_deferrals SET state = 'access_denied' WHERE deferral_code = ?")
        .run(deferralCode);
      return { error: "access_denied" };
    }
    this.kernel.drainExpansionOutbox();
    this.db
      .prepare("UPDATE expansion_deferrals SET redeemed = 1 WHERE deferral_code = ?")
      .run(deferralCode);
    return {
      successor: txOut.successor,
      approvedUntil: row.approved_until as string,
      ...(creationRequestId ? { creationRequestId } : {}),
    };
  }

  /** The single expansion-completion transaction (see {@link redeem}). */
  private redeemInTransaction(
    row: Record<string, unknown>,
    intent: MissionIntent,
    recorded: { pr?: AuthorityEntry[] },
    approver: { iss: string; sub: string },
    submissionEvidence: IntentSubmissionEvidenceFact[] | undefined,
    creationRequestId: string | undefined,
  ): { successor: MissionRecord; predecessorId: string } | undefined {
    return this.kernel.suppressEmits(() => withTransaction(this.kernel.db, () => {
      // Read-only effective-active re-check inside the transaction (emission
      // is suppressed here, so nothing is materialized; lazy expiry stays
      // with the ordinary gates).
      const predNow = this.kernel.get(row.predecessor_id as string);
      if (
        !predNow ||
        predNow.state !== "active" ||
        Date.parse(predNow.expires_at) <= this.kernel.nowDate().getTime()
      ) {
        return undefined;
      }
      const res = createExpansion(this.kernel, {
        predecessorId: row.predecessor_id as string,
        intent,
        ...(recorded.pr ? { proposedAuthority: recorded.pr } : {}),
        approver,
        approvalEventId: row.approval_event_id as string,
        approvedUntil: row.approved_until as string,
        ...(submissionEvidence?.length ? { submissionEvidence } : {}),
      });
      if (creationRequestId) {
        this.creationIdempotency.completeInCallerTx(
          row.client_id as string,
          creationRequestId,
          res.successor.id,
        );
      }
      const cas = this.kernel.supersedeInCallerTx(res.successor.id);
      // Single-writer SQLite makes a lost CAS unreachable after the in-tx
      // check; the throw is the invariant's tripwire, and it rolls the
      // successor back rather than ever leaving both lineages live.
      if (!cas) throw new Error("expansion predecessor supersession failed inside the redemption transaction");
      // Durable finalization: the successor's activation event and the
      // predecessor's supersession finalize are an outbox job committed WITH
      // this transaction, emitted only after it (and replayable after a
      // crash), so no event ever describes state that was rolled back.
      this.kernel.enqueueExpansionFinalize(cas.predecessorId, res.successor.id);
      return { successor: res.successor, predecessorId: cas.predecessorId };
    }));
  }
}
