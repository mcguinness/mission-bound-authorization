/**
 * @spec deferred-approval#deferred-approval, deferred-approval#state-machine,
 * deferred-approval#policy-completion: the kernel half of Deferred Mission
 * Approval for a PAR-submitted proposal. Before approval only the pending
 * request exists: no Mission, and the deferral code is pending-request state,
 * never a grant. The approval event happens later, either under the
 * `governed_policy` basis (policy completion: the issuer selects a configured
 * governed policy whose root admits the proposal, and the policy decides) or
 * as a separately authenticated, full `direct` approval by a human.
 *
 * Distinct from the AROP {@link DeferralStore} (which never creates a Mission)
 * and the {@link ExpansionDeferralStore} (which needs a predecessor): this
 * store's completion creates a top-level Mission.
 *
 * The wire half is in `adapters/deferred-mission-approval.ts`: the PAR and
 * token-endpoint carriage of `completion_mode=deferred`, the deferred-grant
 * poll that runs policy completion and delivers the credential, and
 * cancellation through the revocation endpoint. No review surface that
 * authenticates a human for {@link MissionApprovalDeferralStore.approveDirect}
 * is wired. The methods below are what the wiring calls, with the checks it
 * relies on (client and key binding, the pending lifetime, the queue bound,
 * single redemption).
 *
 * Each pending approval carries ONE `approval_event_id`, allocated when it
 * opens, so every completion path (policy, human, retry, race) resolves it to
 * at most one Mission and one record.
 */

import { randomBytes } from "node:crypto";
import { withTransaction, type Database } from "@mission/store";
import type { ApprovalGovernanceRecord } from "./approval-governance.js";
import { DEFERRAL_EXPIRES_IN, DEFERRAL_INTERVAL, type DeferralPending, type DeferralSlowDown } from "./deferred.js";
import {
  activateGovernedPolicy,
  eligibleGovernedPolicyConsents,
  GovernedPolicyError,
  previewGovernedActivation,
  type RecordedModelOutput,
} from "./governed-policy-approval.js";
import { IntentError } from "./intent.js";
import type { MissionKernel } from "./kernel.js";
import type { AuthorityEntry, MissionIntent, MissionRecord } from "./types.js";

/** @spec deferred-approval#state-machine: `approved`, `denied`, `expired`, and `cancelled` are terminal. */
export type MissionApprovalState = "pending" | "approved" | "denied" | "expired" | "cancelled";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS mission_approval_deferrals (
  deferral_code TEXT PRIMARY KEY,
  state TEXT NOT NULL,
  client_id TEXT NOT NULL,
  jkt TEXT NOT NULL,
  intent_json TEXT NOT NULL,
  proposal_json TEXT,
  approval_event_id TEXT NOT NULL UNIQUE,
  mission_id TEXT,
  basis TEXT,
  resolution_reason TEXT,
  redeemed INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  last_polled_at INTEGER
) STRICT;
`;

/** What a model is asked to evaluate for one policy completion; its outputs bind to exactly this. */
export interface ModelAdvisorRequest {
  approval_event_id: string;
  client_id: string;
  intent: MissionIntent;
  intent_hash: string;
  authority: AuthorityEntry[];
  authority_hash: string;
}

/** A deployment's model hook: its outputs are recorded inputs, never authority. */
export type ModelAdvisor = (request: ModelAdvisorRequest) => Promise<RecordedModelOutput[]>;

export interface MissionApprovalDeferralOptions {
  now?: () => Date;
  /** @spec deferred-approval#pending-staleness: the deployment-set maximum pending lifetime (seconds). */
  pendingLifetimeS?: number;
  /**
   * @spec deferred-approval#policy-completion: what a policy evaluation that
   * does not authorize activation leaves: the proposal pending for a
   * separately authenticated, full `direct` human approval (the default), or
   * resolved `denied`.
   */
  onPolicyRefusal?: "await_human" | "deny";
  modelAdvisor?: ModelAdvisor;
  /**
   * @spec deferred-approval#queue-pressure: the most pending approvals one
   * client may hold at once; {@link MissionApprovalDeferralStore.open}
   * refuses another until the queue drains. No Approver is named when a
   * proposal is submitted (a reviewer or the policy decides later), so the
   * bound is per client, which bounds every (client, Approver) pair.
   * Default {@link DEFAULT_MAX_PENDING_PER_CLIENT}.
   */
  maxPendingPerClient?: number;
}

/** @spec deferred-approval#queue-pressure: the default per-client bound on pending approvals. */
export const DEFAULT_MAX_PENDING_PER_CLIENT = 10;

export type PolicyCompletionResult =
  | { outcome: "approved"; mission: MissionRecord; record: ApprovalGovernanceRecord }
  | { outcome: "not_authorized"; reason: string; state: "pending" | "denied" }
  | { outcome: "not_pending"; state: MissionApprovalState };

export type MissionApprovalPoll =
  | DeferralPending
  | DeferralSlowDown
  | { error: "expired_token" }
  | { error: "access_denied" }
  | { error: "invalid_grant" }
  /**
   * An approved approval's Mission, claimed for delivery under `delivery`.
   * The caller delivers the credential, then settles the claim with
   * {@link MissionApprovalDeferralStore.confirmDelivery} (the credential is
   * sent only when that confirms) or, on a failure before the response,
   * {@link MissionApprovalDeferralStore.releaseDelivery}.
   */
  | { mission: MissionRecord; delivery: string; resource?: string };

/** What settling a delivery claim found. */
export type DeliveryConfirmation = "confirmed" | "cancelled" | "superseded";

/**
 * How long a delivery claim holds before another poll may claim the same
 * approval: a delivery that crashed after claiming becomes deliverable again.
 */
export const DELIVERY_CLAIM_STALE_S = 30;

/** Columns added after the table first shipped (#1185): added in place, so a database created earlier opens. */
const ADDED_COLUMNS: ReadonlyArray<[string, string]> = [
  ["delivery_claim", "TEXT"],
  ["delivery_claimed_at", "INTEGER"],
  ["resource", "TEXT"],
];

function migrate(db: Database): void {
  const columns = new Set(
    (db.prepare("PRAGMA table_info(mission_approval_deferrals)").all() as Array<{ name: string }>).map((c) => c.name),
  );
  for (const [column, type] of ADDED_COLUMNS) {
    if (!columns.has(column)) db.exec(`ALTER TABLE mission_approval_deferrals ADD COLUMN ${column} ${type}`);
  }
}

/** A completion the pending approval's state no longer admits. LOCAL code. */
export class MissionApprovalDeferralError extends Error {
  constructor(
    readonly code: "not_pending" | "unknown_deferral" | "queue_full",
    message: string,
  ) {
    super(message);
  }
}

interface Row {
  deferral_code: string;
  state: MissionApprovalState;
  client_id: string;
  jkt: string;
  intent_json: string;
  proposal_json: string | null;
  approval_event_id: string;
  mission_id: string | null;
  basis: string | null;
  resolution_reason: string | null;
  redeemed: number;
  created_at: number;
  last_polled_at: number | null;
  delivery_claim: string | null;
  delivery_claimed_at: number | null;
  resource: string | null;
}

/** A refusal the activation checks raise (as opposed to a fault of the issuer). */
const refusalReason = (e: unknown): string | undefined =>
  e instanceof GovernedPolicyError ? (e.reason ?? e.code) : e instanceof IntentError ? e.code : undefined;

export class MissionApprovalDeferralStore {
  readonly db: Database;
  private readonly now: () => Date;

  constructor(
    private readonly kernel: MissionKernel,
    private readonly opts: MissionApprovalDeferralOptions = {},
  ) {
    // Completion and the Mission's creation commit share the kernel database.
    this.db = kernel.db;
    this.db.exec(SCHEMA);
    migrate(this.db);
    this.now = opts.now ?? (() => kernel.nowDate());
  }

  private row(code: string): Row | undefined {
    return this.db.prepare("SELECT * FROM mission_approval_deferrals WHERE deferral_code = ?").get(code) as
      | Row
      | undefined;
  }

  private lifetimeMs(): number {
    return (this.opts.pendingLifetimeS ?? DEFERRAL_EXPIRES_IN) * 1000;
  }

  /** The state as of now: a `pending` approval past its lifetime is `expired` (persisted). */
  private observed(row: Row): MissionApprovalState {
    if (row.state === "pending" && this.now().getTime() > row.created_at + this.lifetimeMs()) {
      this.db
        .prepare("UPDATE mission_approval_deferrals SET state = 'expired' WHERE deferral_code = ? AND state = 'pending'")
        .run(row.deferral_code);
      return "expired";
    }
    return row.state;
  }

  private resolve(code: string, state: "denied" | "cancelled", reason?: string): void {
    this.db
      .prepare(
        "UPDATE mission_approval_deferrals SET state = ?, resolution_reason = ? WHERE deferral_code = ? AND state = 'pending'",
      )
      .run(state, reason ?? null, code);
  }

  /**
   * @spec deferred-approval#deferred-sequencing (steps 1 and 2): open a
   * pending approval for an already-validated proposal, bound to the client
   * that submitted it and to its possession key. Nothing here names an
   * approval basis or a policy: the client selects none.
   */
  open(input: {
    intent: MissionIntent;
    proposedAuthority?: AuthorityEntry[];
    clientId: string;
    jkt: string;
    /** The resource the submission selected with its resource indicator: the delivered token's audience. */
    resource?: string;
  }): DeferralPending {
    const code = `mdfr_${randomBytes(18).toString("base64url")}`;
    const proposal = input.proposedAuthority?.length ? input.proposedAuthority : undefined;
    const nowMs = this.now().getTime();
    // @spec deferred-approval#queue-pressure: the count and the insert share
    // one transaction, so concurrent submissions never overrun the bound.
    withTransaction(this.db, () => {
      if (this.pendingCount(input.clientId, nowMs) >= (this.opts.maxPendingPerClient ?? DEFAULT_MAX_PENDING_PER_CLIENT)) {
        throw new MissionApprovalDeferralError("queue_full", "this client holds the most pending approvals allowed");
      }
      this.db
        .prepare(
          `INSERT INTO mission_approval_deferrals (deferral_code, state, client_id, jkt, intent_json, proposal_json,
             approval_event_id, created_at, resource)
           VALUES (?, 'pending', ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          code,
          input.clientId,
          input.jkt,
          JSON.stringify(input.intent),
          proposal ? JSON.stringify(proposal) : null,
          `ape_${randomBytes(16).toString("base64url")}`,
          nowMs,
          input.resource ?? null,
        );
    });
    return { error: "authorization_pending", deferral_code: code, expires_in: this.lifetimeMs() / 1000, interval: DEFERRAL_INTERVAL };
  }

  /** The client's pending approvals still inside their lifetime. */
  private pendingCount(clientId: string, nowMs: number): number {
    const row = this.db
      .prepare(
        "SELECT COUNT(*) AS n FROM mission_approval_deferrals WHERE client_id = ? AND state = 'pending' AND created_at + ? >= ?",
      )
      .get(clientId, this.lifetimeMs(), nowMs) as { n: number };
    return row.n;
  }

  /** The current state, or undefined for an unknown code. */
  state(code: string): MissionApprovalState | undefined {
    const row = this.row(code);
    return row ? this.observed(row) : undefined;
  }

  /** The one approval event this pending approval resolves under. */
  approvalEventId(code: string): string | undefined {
    return this.row(code)?.approval_event_id;
  }

  /** The recorded reason a policy evaluation or a resolution did not authorize activation. */
  resolutionReason(code: string): string | undefined {
    return this.row(code)?.resolution_reason ?? undefined;
  }

  /**
   * @spec deferred-approval#deferred-sequencing: a requested ceiling that
   * passed while the approval pended fails the creation commit's
   * effective-expiry recheck; the approval resolves `denied` with no Mission.
   */
  private expiryPassed(code: string, intent: MissionIntent): boolean {
    if (Date.parse(intent.expires_at) > this.now().getTime()) return false;
    this.resolve(code, "denied", "mission_expiry_passed");
    return true;
  }

  private notAuthorized(code: string, reason: string): PolicyCompletionResult {
    if (this.opts.onPolicyRefusal === "deny") {
      this.resolve(code, "denied", reason);
      return { outcome: "not_authorized", reason, state: "denied" };
    }
    this.db
      .prepare("UPDATE mission_approval_deferrals SET resolution_reason = ? WHERE deferral_code = ? AND state = 'pending'")
      .run(reason, code);
    return { outcome: "not_authorized", reason, state: "pending" };
  }

  /**
   * @spec deferred-approval#policy-completion: complete a pending approval
   * under `governed_policy`. The issuer selects the first configured governed
   * policy whose consented root admits the pending proposal, gathers any model
   * outputs bound to this activation, and the policy decides at the atomic
   * creation commit. An evaluation that does not authorize activation creates
   * no Mission. A retried or concurrent completion resolves to the one Mission
   * and record this approval's event committed.
   */
  async completeByPolicy(code: string): Promise<PolicyCompletionResult> {
    const row = this.row(code);
    if (!row) throw new MissionApprovalDeferralError("unknown_deferral", "unknown deferral code");
    const before = this.observed(row);
    if (before !== "pending") return this.settled(code, before);
    const intent = JSON.parse(row.intent_json) as MissionIntent;
    const proposedAuthority = row.proposal_json ? (JSON.parse(row.proposal_json) as AuthorityEntry[]) : undefined;
    if (this.expiryPassed(code, intent)) {
      return { outcome: "not_authorized", reason: "mission_expiry_passed", state: "denied" };
    }
    const request = {
      approvalEventId: row.approval_event_id,
      intent,
      ...(proposedAuthority ? { proposedAuthority } : {}),
      clientId: row.client_id,
    };
    // Selection: the issuer's, from configuration and retained consent only.
    let selected: { consentId: string; view: ReturnType<typeof previewGovernedActivation> } | undefined;
    let reason = "no_eligible_policy";
    for (const consent of eligibleGovernedPolicyConsents(this.kernel, row.client_id)) {
      try {
        selected = { consentId: consent.consent_id, view: previewGovernedActivation(this.kernel, { ...request, consentId: consent.consent_id }) };
        break;
      } catch (e) {
        const why = refusalReason(e);
        if (why === undefined) throw e;
        reason = why;
      }
    }
    if (!selected) return this.notAuthorized(code, reason);
    const modelOutputs = this.opts.modelAdvisor
      ? await this.opts.modelAdvisor({ ...selected.view, client_id: row.client_id, intent })
      : [];
    const consentId = selected.consentId;
    try {
      return withTransaction(this.db, (): PolicyCompletionResult => {
        // Re-read inside the commit: a completion that raced this one, a
        // human approval, a denial, or a cancellation already settled it.
        const current = this.row(code) as Row;
        const state = this.observed(current);
        if (state !== "pending") return this.settled(code, state);
        const activation = activateGovernedPolicy(this.kernel, { ...request, consentId, modelOutputs });
        this.db
          .prepare(
            "UPDATE mission_approval_deferrals SET state = 'approved', mission_id = ?, basis = 'governed_policy', resolution_reason = NULL WHERE deferral_code = ? AND state = 'pending'",
          )
          .run(activation.mission.id, code);
        return { outcome: "approved", ...activation };
      });
    } catch (e) {
      const why = refusalReason(e);
      if (why === undefined) throw e;
      return this.notAuthorized(code, why);
    }
  }

  /** The outcome of an approval already settled: its governed Mission, or its state. */
  private settled(code: string, state: MissionApprovalState): PolicyCompletionResult {
    const row = this.row(code) as Row;
    if (state === "approved" && row.basis === "governed_policy" && row.mission_id) {
      const mission = this.kernel.get(row.mission_id);
      const record = this.kernel.governanceRecords.forMission(row.mission_id);
      if (mission && record) return { outcome: "approved", mission, record };
    }
    return { outcome: "not_pending", state };
  }

  /**
   * @spec deferred-approval#policy-completion,
   * deferred-approval#deferred-sequencing (step 3): the human path. The
   * review surface has authenticated `approver` and established `subject`;
   * this commits a full `direct` approval event under the pending approval's
   * one `approval_event_id`. It never turns a failed `governed_policy` check
   * into a `governed_policy` activation: the Mission is `direct`, with no
   * policy adjudication.
   */
  approveDirect(
    code: string,
    input: { approver: { iss: string; sub: string }; subject: { iss: string; sub: string } },
  ): MissionRecord {
    const row = this.row(code);
    if (!row) throw new MissionApprovalDeferralError("unknown_deferral", "unknown deferral code");
    const intent = JSON.parse(row.intent_json) as MissionIntent;
    const proposedAuthority = row.proposal_json ? (JSON.parse(row.proposal_json) as AuthorityEntry[]) : undefined;
    const state = this.observed(row);
    if (state === "pending" && this.expiryPassed(code, intent)) {
      throw new MissionApprovalDeferralError("not_pending", "the requested Mission expiry passed while the approval pended");
    }
    return withTransaction(this.db, () => {
      const current = this.row(code) as Row;
      if (this.observed(current) !== "pending") {
        throw new MissionApprovalDeferralError("not_pending", `the approval is ${current.state}`);
      }
      const mission = this.kernel.approve({
        intent,
        ...(proposedAuthority ? { proposedAuthority } : {}),
        subject: input.subject,
        approver: input.approver,
        clientId: current.client_id,
        approvalEventId: current.approval_event_id,
      });
      if (mission.approval_basis.type !== "direct") {
        throw new MissionApprovalDeferralError("not_pending", "this approval event already committed another basis");
      }
      this.db
        .prepare(
          "UPDATE mission_approval_deferrals SET state = 'approved', mission_id = ?, basis = 'direct', resolution_reason = NULL WHERE deferral_code = ? AND state = 'pending'",
        )
        .run(mission.id, code);
      return mission;
    });
  }

  /** @spec deferred-approval#state-machine: a reviewer's denial of a pending approval. */
  deny(code: string): boolean {
    const row = this.row(code);
    if (!row || this.observed(row) !== "pending") return false;
    this.resolve(code, "denied", "denied");
    return true;
  }

  /**
   * @spec deferred-approval#state-machine: client cancellation moves a pending
   * approval to `cancelled`; only the client it is bound to can cancel it.
   * Under the deferred substrate's cancellation rules, an approval that
   * resolved but whose credential was never delivered is redeemed and then
   * cancelled: it delivers nothing, and every later poll is `access_denied`.
   * A credential already delivered is left alone.
   */
  cancel(code: string, clientId: string): boolean {
    const row = this.row(code);
    if (!row || row.client_id !== clientId) return false;
    const state = this.observed(row);
    if (state === "pending") {
      this.resolve(code, "cancelled");
      return this.row(code)?.state === "cancelled";
    }
    if (state !== "approved") return false;
    return (
      this.db
        .prepare(
          "UPDATE mission_approval_deferrals SET redeemed = 1, resolution_reason = 'cancelled' WHERE deferral_code = ? AND state = 'approved' AND redeemed = 0",
        )
        .run(code).changes === 1
    );
  }

  /** True when a pending approval was polled less than the interval ago. */
  private tooSoon(row: Row, nowMs: number): boolean {
    return row.last_polled_at != null && nowMs - row.last_polled_at < DEFERRAL_INTERVAL * 1000;
  }

  /**
   * @spec deferred-approval#policy-completion, deferred-approval#deferred-sequencing
   * (step 5): the poll the token endpoint serves. It first checks that the
   * presenter is the client and key the approval is bound to (anything else
   * is `invalid_grant`, with no side effect) and the polling interval. A
   * pending approval that no policy evaluation has resolved then runs
   * {@link completeByPolicy}: the issuer's selection and the policy's
   * decision, never the client's. The poll that follows reports the outcome
   * and delivers an approved Mission once.
   *
   * A completion that faults (a signing or persistence failure) commits
   * nothing and leaves the approval pending; the fault propagates, and a
   * later poll, no sooner than the interval, retries it under the same
   * approval event.
   */
  async pollAndComplete(code: string, presenter: { clientId: string; jkt: string }): Promise<MissionApprovalPoll> {
    const row = this.row(code);
    if (!row || row.client_id !== presenter.clientId || row.jkt !== presenter.jkt) return { error: "invalid_grant" };
    const nowMs = this.now().getTime();
    if (this.observed(row) === "pending" && row.resolution_reason === null && !this.tooSoon(row, nowMs)) {
      try {
        await this.completeByPolicy(code);
      } catch (e) {
        this.db.prepare("UPDATE mission_approval_deferrals SET last_polled_at = ? WHERE deferral_code = ?").run(nowMs, code);
        throw e;
      }
    }
    return this.poll(code, presenter);
  }

  /**
   * @spec deferred-approval#deferred-sequencing (step 5): poll a pending
   * approval. Bound to the client and possession key that opened it; a poll
   * faster than the interval is `slow_down`; past the pending lifetime it is
   * `expired_token`; a denial or a cancellation is `access_denied`; an
   * approved approval delivers its Mission once, and only while that Mission
   * is active.
   */
  poll(code: string, presenter: { clientId: string; jkt: string }): MissionApprovalPoll {
    const row = this.row(code);
    if (!row || row.client_id !== presenter.clientId || row.jkt !== presenter.jkt) return { error: "invalid_grant" };
    const state = this.observed(row);
    const nowMs = this.now().getTime();
    switch (state) {
      case "expired":
        return { error: "expired_token" };
      case "denied":
      case "cancelled":
        return { error: "access_denied" };
      case "pending": {
        if (this.tooSoon(row, nowMs)) {
          return { error: "slow_down", deferral_code: code, expires_in: this.lifetimeMs() / 1000, interval: DEFERRAL_INTERVAL + 5 };
        }
        this.db.prepare("UPDATE mission_approval_deferrals SET last_polled_at = ? WHERE deferral_code = ?").run(nowMs, code);
        return {
          error: "authorization_pending",
          deferral_code: code,
          expires_in: Math.max(0, Math.ceil((row.created_at + this.lifetimeMs() - nowMs) / 1000)),
          interval: DEFERRAL_INTERVAL,
        };
      }
      case "approved": {
        if (row.resolution_reason === "cancelled") return { error: "access_denied" };
        const mission = row.mission_id ? this.kernel.get(row.mission_id) : undefined;
        if (!mission || this.kernel.applyExpiry(mission).state !== "active") return { error: "access_denied" };
        if (row.redeemed === 1) return { error: "invalid_grant" };
        // Claim the delivery: one live claim at a time, so concurrent polls
        // never deliver twice. The approval is redeemed only when the
        // claimant confirms after its credential exists; a delivery that
        // fails first releases the claim, and one that crashed lapses.
        const delivery = `dlv_${randomBytes(12).toString("base64url")}`;
        const claimed = this.db
          .prepare(
            `UPDATE mission_approval_deferrals SET delivery_claim = ?, delivery_claimed_at = ?
             WHERE deferral_code = ? AND state = 'approved' AND redeemed = 0
               AND (delivery_claim IS NULL OR delivery_claimed_at <= ?)`,
          )
          .run(delivery, nowMs, code, nowMs - DELIVERY_CLAIM_STALE_S * 1000).changes;
        if (claimed === 1) return { mission, delivery, ...(row.resource ? { resource: row.resource } : {}) };
        const current = this.row(code) as Row;
        // A cancellation that won the race delivers nothing either.
        if (current.resolution_reason === "cancelled") return { error: "access_denied" };
        if (current.redeemed === 1) return { error: "invalid_grant" };
        // Another poll is delivering: not delivered yet, so still pending.
        return {
          error: "authorization_pending",
          deferral_code: code,
          expires_in: Math.max(0, Math.ceil((row.created_at + this.lifetimeMs() - nowMs) / 1000)),
          interval: DEFERRAL_INTERVAL,
        };
      }
    }
  }

  /**
   * @spec deferred-approval#deferred-sequencing (step 5): settle a delivery
   * claim once the credential exists. `confirmed` redeems the approval, and
   * only then may the credential be sent. `cancelled` means the client
   * cancelled before delivery, and `superseded` that another claim delivered;
   * in either case the credential is not sent.
   */
  confirmDelivery(code: string, delivery: string): DeliveryConfirmation {
    const confirmed = this.db
      .prepare(
        `UPDATE mission_approval_deferrals SET redeemed = 1, delivery_claim = NULL
         WHERE deferral_code = ? AND delivery_claim = ? AND redeemed = 0`,
      )
      .run(code, delivery).changes;
    if (confirmed === 1) return "confirmed";
    return this.row(code)?.resolution_reason === "cancelled" ? "cancelled" : "superseded";
  }

  /** Release a delivery claim whose credential could not be produced: the approval stays deliverable. */
  releaseDelivery(code: string, delivery: string): void {
    this.db
      .prepare(
        "UPDATE mission_approval_deferrals SET delivery_claim = NULL, delivery_claimed_at = NULL WHERE deferral_code = ? AND delivery_claim = ?",
      )
      .run(code, delivery);
  }
}
