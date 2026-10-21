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
import {
  applyCarryoverInCallerTx,
  decodeCarryoverEvidence,
  type CarryoverConfig,
  type CarryoverEvidence,
  CarryoverError,
  type CarryoverManifest,
  type CarryoverMap,
  type CarryoverPlan,
  CarryoverStore,
  commitCarryoverManifest,
  prepareCarryover,
} from "./carryover.js";
import { CreationIdempotencyStore } from "./creation-idempotency.js";
import { APPROVAL_FLOOR, type ApprovalFloorPolicy } from "@mission/demo-data";
import { evaluateApprovalFloor } from "./approval-floor.js";
import { isSubsetSetIgnoringCapabilitySources } from "@mission/core";
import {
  createExpansion,
  type ReconciliationStatus,
  reconciliationStatusFor,
  restrictedSinceAdjudication,
} from "./expansion.js";
import { conditionDigest, entryDigest, terminalWhenOf } from "./discharge.js";
import { IntentError } from "./intent.js";
import {
  type CeilingConsent,
  ceilingAdjudicationLine,
  consentCeiling,
  consentedCeilingEntries,
  consentsOffer,
  type ReconsentedCeiling,
} from "./progressive.js";
import type { MissionKernel } from "./kernel.js";
import type {
  AuthorityEntry,
  IntentSubmissionEvidenceFact,
  MissionClaim,
  MissionIntent,
  MissionRecord,
  TerminalWhenCondition,
} from "./types.js";

export const DEFERRED_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:deferred";

/** The prefix of an expansion deferral code; the deferred grant routes on it. */
export const EXPANSION_DEFERRAL_PREFIX = "xdfr_";

const SCHEMA = `
CREATE TABLE deferrals (
  deferral_code TEXT PRIMARY KEY,
  state TEXT NOT NULL,
  mission_id TEXT NOT NULL,
  requested_json TEXT NOT NULL,
  client_id TEXT NOT NULL,
  jkt TEXT NOT NULL,
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
   * existing pending handle. Records the opening client and its possession key
   * (`jkt`), which the handler re-checks on every poll (#1348); whether the
   * client may open a deferral on this Mission is the handler's check.
   */
  open(input: { missionId: string; requested: AuthorityEntry[]; clientId: string; jkt: string }): DeferralPending {
    const mission = this.kernel.get(input.missionId);
    if (!mission || this.kernel.applyExpiry(mission).state !== "active") {
      throw new DeferralError("out_of_authority", "mission is not active");
    }
    // @spec D42: AROP grant is a subset of the active Mission; widening -> Expansion.
    // Containment: the ceiling is the EFFECTIVE set, so a contained capability
    // is not deferrable.
    if (!isSubsetSetIgnoringCapabilitySources(input.requested, this.kernel.effectiveAuthoritySet(mission))) {
      throw new DeferralError(
        "out_of_authority",
        "requested authority exceeds the active Mission; use Expansion to widen",
      );
    }
    // @spec expansion#creation-idempotency (deferred mode, shared rule) — the
    // dedup key is CLIENT-SCOPED: the same semantic request from two different
    // clients MUST open two deferrals (per-client scoping prevents cross-client
    // interference and replay). The previous {m, r} key omitted the client.
    // Key-scoped as well (DTR -00 Section 5.4): a code is bound to the key of
    // the request it answers, so a resubmission under another key opens a new
    // deferral rather than returning a code that key cannot poll.
    const key = JSON.stringify({ m: input.missionId, r: input.requested, c: input.clientId });
    const existing = this.db
      .prepare(
        "SELECT deferral_code FROM deferrals WHERE state = 'authorization_pending' AND requested_json = ? AND mission_id = ? AND client_id = ? AND jkt = ?",
      )
      .get(key, input.missionId, input.clientId, input.jkt) as { deferral_code: string } | undefined;
    const code = existing?.deferral_code ?? `dfr_${randomBytes(18).toString("base64url")}`;
    if (!existing) {
      this.db
        .prepare(
          "INSERT INTO deferrals (deferral_code, state, mission_id, requested_json, client_id, jkt, created_at) VALUES (?, 'authorization_pending', ?, ?, ?, ?, ?)",
        )
        .run(code, input.missionId, key, input.clientId, input.jkt, this.now().getTime());
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

  /** The Mission, client and possession key recorded at initiation (the handler re-checks the poller, #1348). */
  recorded(deferralCode: string): { missionId: string; clientId: string; jkt: string } | undefined {
    const row = this.db
      .prepare("SELECT mission_id, client_id, jkt FROM deferrals WHERE deferral_code = ?")
      .get(deferralCode) as { mission_id: string; client_id: string; jkt: string } | undefined;
    return row ? { missionId: row.mission_id, clientId: row.client_id, jkt: row.jkt } : undefined;
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
    if (!isSubsetSetIgnoringCapabilitySources(parsed.r, this.kernel.effectiveAuthoritySet(mission))) {
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
CREATE TABLE IF NOT EXISTS expansion_deferrals (
  deferral_code TEXT PRIMARY KEY,
  state TEXT NOT NULL,
  predecessor_id TEXT NOT NULL,
  intent_json TEXT NOT NULL,
  client_id TEXT NOT NULL,
  jkt TEXT NOT NULL,
  creation_request_id TEXT,
  pred_containment_version INTEGER NOT NULL,
  submission_evidence_json TEXT,
  carryover_plan_id TEXT,
  carryover_plan_json TEXT,
  carryover_manifest_json TEXT,
  carryover_manifest_hash TEXT,
  approver_json TEXT,
  approval_event_id TEXT,
  approved_until TEXT,
  redeemed INTEGER NOT NULL DEFAULT 0,
  completion_released INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  last_polled_at INTEGER
) STRICT;
CREATE TABLE IF NOT EXISTS progressive_refusals (
  mission_id TEXT NOT NULL,
  refused_at INTEGER NOT NULL
) STRICT;
`;

/**
 * The four carryover columns are additive, and this schema only ever runs
 * `CREATE TABLE IF NOT EXISTS`, so a kernel database created before them keeps
 * the older `expansion_deferrals` table and the first deferred-expansion
 * INSERT naming `carryover_plan_id` fails. They are added in place here, each
 * guarded by a `PRAGMA table_info` snapshot so a second open is a no-op rather
 * than a duplicate-column error. Same treatment as the `missions` correlation
 * columns; all four are nullable with no default, so a deferral opened before
 * carryover keeps its meaning: no plan, no manifest, ordinary cascade.
 */
function migrateExpansionDeferrals(db: Database): void {
  const columns = new Set(
    (db.prepare("PRAGMA table_info(expansion_deferrals)").all() as Array<{ name: string }>).map(
      (c) => c.name,
    ),
  );
  for (const column of [
    "carryover_plan_id",
    "carryover_plan_json",
    "carryover_manifest_json",
    "carryover_manifest_hash",
    // @spec progressive#ceiling-reconsent (#1413): the committed re-consent.
    "ceiling_reconsent_json",
    // @spec expansion#reconciliation (#1177): the reconciliation status a
    // refused completion recorded, repeated on every later poll of the deferral.
    "refusal_status",
    // @spec progressive#ceiling-review (#1017): why a drawdown request came to
    // a human, the guard exception a review disclosure lists.
    "drawdown_fallback_reason",
  ]) {
    if (!columns.has(column)) db.exec(`ALTER TABLE expansion_deferrals ADD COLUMN ${column} TEXT`);
  }
  // @spec expansion#reconciliation check 3 (#1177): the predecessor's
  // discharge-latch count at initiation, beside `pred_containment_version`.
  if (!columns.has("pred_discharge_count")) {
    db.exec("ALTER TABLE expansion_deferrals ADD COLUMN pred_discharge_count INTEGER");
  }
}

/**
 * @spec child-delegation#carryover-evidence — the committed batch outcome a
 * completion returns: the plan identity, the committed manifest commitment, the
 * complete final map, and the authenticated Carryover Evidence.
 */
export interface ApplyCarryoverOutcome {
  planId: string;
  manifestHash: string;
  map: CarryoverMap;
  evidence: CarryoverEvidence;
  evidenceJws: string;
  replacements: MissionRecord[];
}

/**
 * @spec progressive#fresh-approval, progressive#ceiling-reconsent,
 * progressive#ceiling-review (#1017): what a deferred expansion's consent
 * disclosure renders. The approval surface renders it; the store builds it
 * from the chain's records, so it shows what the Mission Issuer holds.
 */
export interface ExpansionDisclosure {
  predecessor: string;
  /** Why a drawdown request of a ceiling chain came to a human, when it did. */
  drawdown_fallback?: string;
  /** The chain's outstanding restrictions, which no approval or re-consent clears. */
  restrictions: {
    /** Each contained capability, with the event class that caused its containment. */
    contained: Array<{ resource: string; actions?: string[]; event_class: string; mission: string }>;
    /** Each discharged entry, with the condition that discharged it. */
    discharged: Array<{
      entry: AuthorityEntry;
      condition: TerminalWhenCondition | { event_type: string };
      discharged_at: string;
      mission: string;
    }>;
  };
  /** Present where the chain carries a ceiling. */
  ceiling?: {
    /** The ceiling and policy a re-consent at this approval would consent, rendered as at the initial approval. */
    reconsent_offer?: { authority_ceiling: AuthorityEntry[]; drawdown_policy?: { id: string; version: string }; adjudication: string };
    /** The chain's record since the latest ceiling consent: the initial one or the latest re-consent. */
    review: {
      since: string;
      policy_adjudicated_drawdowns: { count: number; per_hour: number };
      escalations: Array<{ at: string; reason: string }>;
      out_of_ceiling_refusals: Array<{ at: string }>;
      discharged: ExpansionDisclosure["restrictions"]["discharged"];
    };
  };
}

/** The Approver's async adjudication payload for a deferred expansion. */
export interface ExpansionApproval {
  approver: { iss: string; sub: string };
  approvalEventId: string;
  /** Bounds the successor credential; MUST NOT be exceeded (approved_until). */
  approvedUntil: string;
  /**
   * @spec mission#approval-authentication (#826, D425) — the Approver's
   * achieved authentication, as the deployment's trusted approval integration
   * recorded it when the Approver logged in on its browser approval surface:
   * the same trust boundary as `ApprovalSessionStore.establish`, never a value
   * the client or the decision supplies, and never stamped at the approval.
   * Required when the successor's authority invokes the approval-authentication
   * floor; without it such an approval refuses.
   */
  authentication?: { surface: "browser"; acr: string; auth_time: number };
  /**
   * @spec progressive#ceiling-reconsent (#1413) — a ceiling and drawdown
   * policy the Approver explicitly re-consents at this approval, separately
   * from approving the successor's authority. Absent, the chain's ceiling
   * members carry unchanged. Only a chain that carries a ceiling can
   * re-consent one.
   */
  ceiling?: CeilingConsent;
}

/**
 * @spec mission#approval-authentication (#826, D425) — an expansion approval
 * the published approval-authentication floor refuses. Nothing is recorded:
 * the deferral stays `authorization_pending`, for the integration to deny or
 * to approve again from an achieved context the floor accepts.
 */
export class ApprovalFloorRefusedError extends Error {
  constructor(readonly reason: string) {
    super(reason);
    this.name = "ApprovalFloorRefusedError";
  }
}

/** The successful redemption of a deferred expansion: the created successor. */
export interface ExpansionDeferredResult {
  successor: MissionRecord;
  approvedUntil: string;
  /** The creation_request_id recorded at initiation (the handler attaches the
   *  delivery artifact to the completed idempotency operation). */
  creationRequestId?: string;
  /**
   * @spec child-delegation#carryover-evidence — the committed batch result,
   * present only when this completion applied an approved Carryover Manifest.
   * The MAP, not `related_to`, is the normative record of replacement.
   */
  carryover?: ApplyCarryoverOutcome;
}

/**
 * A deferred-expansion refusal. `predecessor_not_active` and
 * `carryover_plan_too_large` refuse at INITIATION: an oversized widening
 * proposal is refused at INTAKE, before approval, so the approval event never
 * names a plan the kernel cannot commit in one transaction
 * (@spec child-delegation#carryover). Both are pre-decision (no Decision was
 * reached), so they are Refusal Records at the enforcement point, never
 * Execution Evidence.
 *
 * `carryover_disabled` refuses at COMPLETION, and is a DEPLOYMENT fault rather
 * than a request refusal: the deferral carries a manifest the approval
 * authenticated, and the switch that executes it is off. A committed manifest
 * either executes intact or completion refuses; silently falling back to
 * ordinary cascade would substitute one approved plan (widen and carry the
 * subtree) for another (widen and tear the subtree down) on a feature-flag
 * change, with the Approver's authenticated approval covering neither. The
 * refusal leaves the deferral approved and unredeemed, so restoring the switch
 * still completes the approved plan intact.
 *
 * LOCAL to this store's code union by design: none of these is added to any
 * draft's Execution Evidence or Refusal Record enumeration.
 */
export class ExpansionDeferralError extends Error {
  constructor(
    readonly code: "predecessor_not_active" | "carryover_plan_too_large" | "carryover_disabled",
    message: string,
  ) {
    super(message);
  }
}

/**
 * @spec expansion#reconciliation check 3 (#1177): raised inside the
 * completion transaction, rolling it back, when the successor carries
 * authority restricted since adjudication.
 */
class RestrictedSinceApprovalError extends Error {}

/**
 * @spec expansion — the DTR deferred-completion store for Mission Expansion.
 * Mirrors {@link DeferralStore}'s poll/interval/expiry shape, but its redemption
 * CREATES a successor Mission (widening) rather than issuing an AROP subset. It
 * records, AT REQUEST TIME, the predecessor binding, the acting client, the
 * possession key (`jkt`), and a snapshot of the predecessor's containment
 * version and discharge-latch count.
 *
 * Deferred-window checks (@spec expansion#deferred-window):
 *  (a) predecessor STATE is re-verified AT REDEMPTION (completion): a predecessor
 *      terminated or superseded during the deferred window fails completion, and
 *      so does a successor carrying authority the predecessor's containment or
 *      discharge restricted after the snapshot (@spec expansion#reconciliation
 *      check 3; a deferred approval MUST NOT become a containment bypass). A
 *      restriction already present at request time stays restorable
 *      (containment#restoration): the check is on what came after the
 *      snapshot, not on the presence of an overlay.
 *  (b) the `subject_token` is deliberately NOT stored and NOT re-verified here:
 *      its expiry MUST NOT gate completion. Possession was evaluated and RECORDED
 *      (the `jkt`) at request time; re-verification is of Mission STATE only.
 */
export class ExpansionDeferralStore {
  readonly db: Database;
  /** @spec expansion#creation-idempotency — completion marks the reservation
   *  completed ATOMICALLY with successor creation. Instances over the same
   *  kernel share the table, so this internal instance needs no wiring. */
  private readonly creationIdempotency: CreationIdempotencyStore;
  /**
   * @spec child-delegation#carryover — the carryover reservation, result and
   * replacement stores, over the SAME kernel database, so a prepared plan's
   * reservations and a committed batch's map share this store's transactions.
   */
  readonly carryover: CarryoverStore;
  constructor(
    private readonly kernel: MissionKernel,
    private readonly now: () => Date = () => new Date(),
    /**
     * @spec child-delegation#carryover — the deployment's carryover
     * configuration. Absent or disabled, this store behaves exactly as before:
     * no plan is prepared, no identifier is reserved and no manifest is
     * committed, and ordinary cascade remains the default.
     */
    private readonly carryoverConfig?: CarryoverConfig,
    /**
     * @spec mission#approval-authentication (#826, D425) — the published
     * approval-authentication floor every expansion approval meets.
     */
    private readonly approvalFloor: ApprovalFloorPolicy = APPROVAL_FLOOR,
    /**
     * @spec progressive#ceiling-reconsent (#1017): the ceiling and drawdown
     * policy the deployment's approval surface offers for a re-consent, the
     * same offer as at the initial approval. A re-consent consents only it.
     */
    private readonly ceilingOffer?: (request: { clientId: string; intent: MissionIntent }) => CeilingConsent | undefined,
  ) {
    // @spec control-plane#serialization — retiring this row and activating
    // its successor must share the kernel transaction, not two databases.
    this.db = kernel.db;
    this.db.exec(EXPANSION_SCHEMA);
    migrateExpansionDeferrals(this.db);
    this.creationIdempotency = new CreationIdempotencyStore(kernel);
    this.carryover = new CarryoverStore(kernel, now);
  }

  /**
   * @spec child-delegation#carryover-commit — the deployment's carryover
   * configuration, or a refusal. Called only where a committed manifest is
   * about to be executed, so a disabled switch refuses the COMPLETION instead
   * of quietly returning the deferral to ordinary cascade.
   */
  private requireCarryoverEnabled(): CarryoverConfig {
    const config = this.carryoverConfig;
    if (!config?.enabled) {
      throw new ExpansionDeferralError(
        "carryover_disabled",
        "the approved expansion carries a committed Carryover Manifest and Child Mission Carryover is disabled",
      );
    }
    return config;
  }

  /** The committed carryover batch result for a deferral, when one applied. */
  carryoverResultFor(deferralCode: string): ReturnType<CarryoverStore["result"]> {
    const row = this.db
      .prepare("SELECT carryover_plan_id FROM expansion_deferrals WHERE deferral_code = ?")
      .get(deferralCode) as { carryover_plan_id: string | null } | undefined;
    return row?.carryover_plan_id ? this.carryover.result(row.carryover_plan_id) : undefined;
  }

  /**
   * Open a deferred expansion. The predecessor MUST be active at request time.
   * Records the possession `jkt` and the predecessor's containment-version and
   * discharge-latch snapshot (deferred-window check (a) baseline). Idempotent for the same (predecessor,
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
     * @spec expansion#submission — the REQUIRED creation identifier
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
    /**
     * @spec progressive#ceiling-review (#1017): why a drawdown request of a
     * ceiling chain fell back to this fresh approval (a guard exception, or a
     * request beyond the ceiling).
     */
    drawdownFallback?: string;
  }): DeferralPending {
    const predecessor = this.kernel.get(input.predecessorId);
    if (!predecessor || this.kernel.applyExpiry(predecessor).state !== "active") {
      throw new ExpansionDeferralError("predecessor_not_active", "predecessor mission is not active");
    }
    const snapshotCv = predecessor.containment?.containment_version ?? 0;
    // @spec expansion#reconciliation check 3 (#1177): the adjudication
    // snapshot of the predecessor's discharge latches.
    const snapshotDischarges = predecessor.discharged?.length ?? 0;
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
    const code = existing?.deferral_code ?? `${EXPANSION_DEFERRAL_PREFIX}${randomBytes(18).toString("base64url")}`;
    if (!existing) {
      // @spec child-delegation#carryover-manifest — PREPARATION: render the
      // plan read-only and RESERVE the proposed successor and replacement
      // identifiers, before any approval. A reservation creates no authority.
      // An oversized plan is refused HERE, at intake, so the approval event
      // never names a plan the kernel cannot commit in one transaction. The
      // idempotent branch above returns the EXISTING deferral and therefore the
      // existing plan and reservations: nothing is re-minted on retry.
      let plan: CarryoverPlan | undefined;
      if (this.carryoverConfig?.enabled) {
        try {
          plan = prepareCarryover(this.kernel, this.carryover, {
            predecessorId: input.predecessorId,
            successorIntent: input.intent,
            ...(proposal ? { successorProposal: proposal } : {}),
            config: this.carryoverConfig,
          });
        } catch (e) {
          if (e instanceof CarryoverError && e.code === "carryover_plan_too_large") {
            throw new ExpansionDeferralError("carryover_plan_too_large", e.message);
          }
          throw e;
        }
      }
      this.db
        .prepare(
          "INSERT INTO expansion_deferrals (deferral_code, state, predecessor_id, intent_json, client_id, jkt, creation_request_id, pred_containment_version, pred_discharge_count, submission_evidence_json, carryover_plan_id, carryover_plan_json, drawdown_fallback_reason, created_at) VALUES (?, 'authorization_pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .run(
          code,
          input.predecessorId,
          key,
          input.clientId,
          input.jkt,
          input.creationRequestId ?? null,
          snapshotCv,
          snapshotDischarges,
          input.submissionEvidence?.length ? JSON.stringify(input.submissionEvidence) : null,
          plan?.plan_id ?? null,
          plan ? JSON.stringify(plan) : null,
          input.drawdownFallback ?? null,
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
    // @spec mission#approval-authentication (#826, D425): an expansion
    // approval is a direct approval of the successor's authority, so it meets
    // the same published floor as the approval interaction, at this decision.
    // The successor's authority is derived exactly as `createExpansion` derives
    // it (which only carries the predecessor's capability-source bindings
    // forward, leaving every entry's actions unchanged), and every action is
    // classified. A refusal records nothing and leaves the deferral pending.
    const pending = this.db
      .prepare(
        "SELECT intent_json, predecessor_id, client_id FROM expansion_deferrals WHERE deferral_code = ? AND state = 'authorization_pending'",
      )
      .get(deferralCode) as { intent_json: string; predecessor_id: string; client_id: string } | undefined;
    let reconsent: ReconsentedCeiling | undefined;
    if (pending) {
      const recorded = JSON.parse(pending.intent_json) as { i: MissionIntent; pr?: AuthorityEntry[] };
      const successor = this.kernel.derive(recorded.i, recorded.pr?.length ? recorded.pr : undefined);
      // @spec progressive#ceiling-reconsent (#1413): a re-consent is a
      // ceiling consent, so its entries are validated here and classified with
      // the successor's authority, as at the initial approval (#1255).
      const predecessor = this.kernel.get(pending.predecessor_id);
      const ceilingEntries = approval.ceiling ? consentedCeilingEntries(approval.ceiling) : [];
      if (approval.ceiling && !predecessor?.authority_ceiling) {
        throw new IntentError("invalid_request", "the expansion chain carries no ceiling to re-consent");
      }
      // @spec progressive#ceiling-reconsent (#1017): the disclosure renders the
      // re-consented ceiling and policy as at the initial approval, so a
      // re-consent consents only exactly the offer the disclosure rendered.
      if (
        approval.ceiling &&
        !consentsOffer(approval.ceiling, this.ceilingOffer?.({ clientId: pending.client_id, intent: recorded.i }))
      ) {
        throw new IntentError("invalid_request", "the approval re-consents a ceiling its disclosure did not render");
      }
      const authentication = approval.authentication;
      const floor = evaluateApprovalFloor(
        this.approvalFloor,
        [...successor, ...ceilingEntries],
        authentication ? { acr: authentication.acr, auth_time: authentication.auth_time } : {},
        { interactive: authentication?.surface === "browser", nowSeconds: Math.floor(this.now().getTime() / 1000) },
      );
      if (floor.outcome === "refused") throw new ApprovalFloorRefusedError(floor.reason);
      if (approval.ceiling && predecessor) {
        // Committed at this decision: the policy digest over the snapshot held
        // now, and this decision's instant as the ceiling consent instant.
        const { drawdown_count: _count, ...committed } = consentCeiling(
          predecessor.issuer,
          this.kernel.activationPolicies(),
          approval.ceiling,
          this.now().toISOString(),
          approval.approver,
        );
        reconsent = committed;
      }
    }
    // @spec child-delegation#carryover-manifest — the approval event COMMITS
    // the exact manifest: the deterministic per-child approval identifiers
    // derive from this committed expansion approval event identifier, and the
    // `manifest_hash` is taken over the finalized manifest. Approval
    // authenticates exactly what preparation rendered.
    const planRow = this.db
      .prepare("SELECT carryover_plan_json FROM expansion_deferrals WHERE deferral_code = ? AND state = 'authorization_pending'")
      .get(deferralCode) as { carryover_plan_json: string | null } | undefined;
    let manifestJson: string | null = null;
    let manifestHash: string | null = null;
    if (planRow?.carryover_plan_json) {
      const plan = JSON.parse(planRow.carryover_plan_json) as CarryoverPlan;
      const committed = commitCarryoverManifest(plan, approval.approvalEventId);
      manifestJson = JSON.stringify(committed.manifest);
      manifestHash = committed.manifestHash;
    }
    this.db
      .prepare(
        "UPDATE expansion_deferrals SET state = 'approved', approver_json = ?, approval_event_id = ?, approved_until = ?, carryover_manifest_json = ?, carryover_manifest_hash = ?, ceiling_reconsent_json = ? WHERE deferral_code = ? AND state = 'authorization_pending'",
      )
      .run(
        JSON.stringify(approval.approver),
        approval.approvalEventId,
        approval.approvedUntil,
        manifestJson,
        manifestHash,
        reconsent ? JSON.stringify(reconsent) : null,
        deferralCode,
      );
  }

  /**
   * @spec progressive#ceiling-review (#1017): record a drawdown request the
   * deployment refused `out_of_ceiling`, for the chain's review disclosure.
   */
  recordOutOfCeilingRefusal(missionId: string): void {
    this.db
      .prepare("INSERT INTO progressive_refusals (mission_id, refused_at) VALUES (?, ?)")
      .run(missionId, this.now().getTime());
  }

  /**
   * @spec progressive#fresh-approval, progressive#ceiling-reconsent,
   * progressive#ceiling-review, expansion#completion-modes (#1017): the
   * consent disclosure of a deferred expansion, or undefined for an unknown
   * code. It names every outstanding containment restriction of the chain with
   * its event class and every discharged entry with its condition, and, where
   * the chain carries a ceiling, the re-consent offer and the chain's record
   * since the latest ceiling consent.
   */
  disclosure(deferralCode: string): ExpansionDisclosure | undefined {
    const row = this.db
      .prepare(
        "SELECT predecessor_id, intent_json, client_id, drawdown_fallback_reason FROM expansion_deferrals WHERE deferral_code = ?",
      )
      .get(deferralCode) as
      | { predecessor_id: string; intent_json: string; client_id: string; drawdown_fallback_reason: string | null }
      | undefined;
    if (!row) return undefined;
    const chain: MissionRecord[] = [];
    const seen = new Set<string>();
    for (let next: string | undefined = row.predecessor_id; next && !seen.has(next); ) {
      seen.add(next);
      const m = this.kernel.get(next);
      if (!m) break;
      chain.push(m);
      next = m.predecessor;
    }
    const contained = chain.flatMap((m) =>
      (m.containment?.events ?? []).flatMap((event) =>
        event.removed.map((r) => ({ ...r, event_class: event.type, mission: m.id })),
      ),
    );
    const discharged: ExpansionDisclosure["restrictions"]["discharged"] = [];
    for (const m of chain) {
      for (const latch of m.discharged ?? []) {
        const entry = m.authority_set.find((e) => entryDigest(m.issuer, e) === latch.entry_digest);
        if (!entry) continue;
        const condition =
          terminalWhenOf(entry)?.find((c) => conditionDigest(c) === latch.condition_digest) ?? {
            event_type: latch.event_type,
          };
        discharged.push({ entry, condition, discharged_at: latch.discharged_at, mission: m.id });
      }
    }
    const disclosure: ExpansionDisclosure = {
      predecessor: row.predecessor_id,
      ...(row.drawdown_fallback_reason ? { drawdown_fallback: row.drawdown_fallback_reason } : {}),
      restrictions: { contained, discharged },
    };
    const predecessor = chain[0];
    if (predecessor?.authority_ceiling && predecessor.ceiling_consented_at) {
      const since = predecessor.ceiling_consented_at;
      const sinceMs = Date.parse(since);
      const ids = JSON.stringify(chain.map((m) => m.id));
      const drawdowns = chain.filter(
        (m) => m.approval_basis.type === "ceiling_drawdown" && Date.parse(m.created_at) > sinceMs,
      ).length;
      const hours = Math.max((this.now().getTime() - sinceMs) / 3_600_000, 1 / 3600);
      const escalations = (
        this.db
          .prepare(
            "SELECT created_at, drawdown_fallback_reason FROM expansion_deferrals WHERE predecessor_id IN (SELECT value FROM json_each(?)) AND drawdown_fallback_reason IS NOT NULL AND created_at > ? ORDER BY created_at",
          )
          .all(ids, sinceMs) as Array<{ created_at: number; drawdown_fallback_reason: string }>
      ).map((e) => ({ at: new Date(e.created_at).toISOString(), reason: e.drawdown_fallback_reason }));
      const refusals = (
        this.db
          .prepare(
            "SELECT refused_at FROM progressive_refusals WHERE mission_id IN (SELECT value FROM json_each(?)) AND refused_at > ? ORDER BY refused_at",
          )
          .all(ids, sinceMs) as Array<{ refused_at: number }>
      ).map((r) => ({ at: new Date(r.refused_at).toISOString() }));
      const recorded = JSON.parse(row.intent_json) as { i: MissionIntent };
      const offer = this.ceilingOffer?.({ clientId: row.client_id, intent: recorded.i });
      disclosure.ceiling = {
        ...(offer
          ? {
              reconsent_offer: {
                authority_ceiling: offer.authority_ceiling,
                ...(offer.drawdown_policy ? { drawdown_policy: offer.drawdown_policy } : {}),
                adjudication: ceilingAdjudicationLine(offer),
              },
            }
          : {}),
        review: {
          since,
          policy_adjudicated_drawdowns: { count: drawdowns, per_hour: Math.round((drawdowns / hours) * 1000) / 1000 },
          escalations,
          out_of_ceiling_refusals: refusals,
          discharged: discharged.filter((d) => Date.parse(d.discharged_at) > sinceMs),
        },
      };
    }
    return disclosure;
  }

  deny(deferralCode: string): void {
    this.db
      .prepare("UPDATE expansion_deferrals SET state = 'access_denied' WHERE deferral_code = ?")
      .run(deferralCode);
    // @spec child-delegation#carryover-manifest — a CANCELLED plan's reserved
    // identifiers stay HELD: never handed to another plan, never re-drawn as a
    // fresh identifier, and the cancelled plan can never complete.
    this.cancelCarryoverPlan(deferralCode);
  }

  /**
   * DTR -00 Section 7.2 (#1177): cancel a deferral at the revocation endpoint.
   * Only the client the deferral was issued to cancels it, and only within its
   * `expires_in`. A pending or approved deferral that has not completed is
   * refused, so its next poll answers `access_denied`. A completion that
   * committed but was never released to the token adapter is treated as
   * redeemed and then cancelled: no later poll delivers its token. Anything
   * else is left unchanged. Returns whether the deferral was cancelled.
   */
  cancel(deferralCode: string, clientId: string): boolean {
    const row = this.db
      .prepare("SELECT client_id, state, redeemed, completion_released, created_at FROM expansion_deferrals WHERE deferral_code = ?")
      .get(deferralCode) as
      | { client_id: string; state: string; redeemed: number; completion_released: number | null; created_at: number }
      | undefined;
    if (!row || row.client_id !== clientId) return false;
    if (this.now().getTime() > row.created_at + DEFERRAL_EXPIRES_IN * 1000) return false;
    if (row.redeemed === 0) {
      const cancelled =
        this.db
          .prepare(
            "UPDATE expansion_deferrals SET state = 'access_denied' WHERE deferral_code = ? AND redeemed = 0 AND state IN ('authorization_pending', 'approved')",
          )
          .run(deferralCode).changes === 1;
      if (cancelled) this.cancelCarryoverPlan(deferralCode);
      return cancelled;
    }
    return (
      this.db
        .prepare(
          "UPDATE expansion_deferrals SET state = 'access_denied', completion_released = 1 WHERE deferral_code = ? AND redeemed = 1 AND completion_released IS NOT 1",
        )
        .run(deferralCode).changes === 1
    );
  }

  /** Mark a denied or abandoned deferral's carryover reservations cancelled. */
  private cancelCarryoverPlan(deferralCode: string): void {
    const row = this.db
      .prepare("SELECT carryover_plan_id FROM expansion_deferrals WHERE deferral_code = ?")
      .get(deferralCode) as { carryover_plan_id: string | null } | undefined;
    if (row?.carryover_plan_id) this.carryover.cancel(row.carryover_plan_id);
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

  /** The predecessor recorded at request time (the handler re-checks the poller's authority for it, #1326). */
  recordedPredecessorId(deferralCode: string): string | undefined {
    const row = this.db
      .prepare("SELECT predecessor_id FROM expansion_deferrals WHERE deferral_code = ?")
      .get(deferralCode) as { predecessor_id: string } | undefined;
    return row?.predecessor_id;
  }

  /**
   * @spec expansion#verification-order step 4 (#1349): every retained deferral
   * whose completion committed (`redeemed`, set in the activation
   * transaction), with the client that opened it and the approval event it
   * completed under. Deferral rows are never deleted, so this is the durable
   * link from a successor to the client whose request created it. Selected by
   * that marker alone: `deny` rewrites `state` even after redemption, and a
   * late denial does not undo the committed successor.
   */
  retainedCommittedExpansions(): Array<{
    deferralCode: string;
    predecessorId: string;
    clientId: string;
    approvalEventId: string | undefined;
  }> {
    const rows = this.db
      .prepare(
        "SELECT deferral_code, predecessor_id, client_id, approval_event_id FROM expansion_deferrals WHERE redeemed = 1 ORDER BY created_at, deferral_code",
      )
      .all() as Array<{ deferral_code: string; predecessor_id: string; client_id: string; approval_event_id: string | null }>;
    return rows.map((r) => ({
      deferralCode: r.deferral_code,
      predecessorId: r.predecessor_id,
      clientId: r.client_id,
      approvalEventId: r.approval_event_id ?? undefined,
    }));
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
    | { error: "access_denied"; status?: ReconciliationStatus }
    | { error: "invalid_grant" }
    | ExpansionDeferredResult {
    const row = this.db
      .prepare("SELECT * FROM expansion_deferrals WHERE deferral_code = ?")
      .get(deferralCode) as Record<string, unknown> | undefined;
    if (!row) return { error: "invalid_grant" };

    // Round-5 (#640 review): a COMMITTED operation is recognized BEFORE the
    // deferral-code lifetime check: a sufficiently delayed restart must
    // recover the committed successor, never report expired_token, and
    // never convert the operation to access_denied. Activation retires the
    // deferral in its transaction; release to the token adapter is a separate
    // boundary. A crash before finalization can recover that committed result,
    // but a result already released stays single-use. This marker is not proof
    // of token delivery and does not claim cross-store issuance atomicity.
    if (
      row.completion_released !== 1 &&
      typeof row.approval_event_id === "string" &&
      row.approval_event_id
    ) {
      const linked = this.kernel.successorByApprovalEvent(
        row.predecessor_id as string,
        row.approval_event_id,
      );
      if (linked) {
        // @spec control-plane#fanout — recover the crash window before
        // returning the committed result: any transition committed but not yet
        // published is replayed from the durable outbox, synchronously, with
        // its original identity and timestamp.
        this.kernel.publishPendingCommits();
        this.db
          .prepare("UPDATE expansion_deferrals SET redeemed = 1, completion_released = 1 WHERE deferral_code = ?")
          .run(deferralCode);
        const recoveredCreationRequestId =
          typeof row.creation_request_id === "string" && row.creation_request_id
            ? row.creation_request_id
            : undefined;
        // @spec child-delegation#carryover-commit — an interrupted delivery
        // resumes from the DURABLY RETAINED result: the committed map and its
        // authenticated evidence are read back, never recomputed, and no
        // duplicate replacement is created.
        const retained = row.carryover_plan_id
          ? this.carryover.result(row.carryover_plan_id as string)
          : undefined;
        return {
          successor: linked,
          approvedUntil: row.approved_until as string,
          ...(recoveredCreationRequestId ? { creationRequestId: recoveredCreationRequestId } : {}),
          ...(retained
            ? {
                carryover: {
                  planId: retained.plan_id,
                  manifestHash: retained.manifest_hash,
                  map: retained.map,
                  evidence: decodeCarryoverEvidence(retained.evidence_jws),
                  evidenceJws: retained.evidence_jws,
                  replacements: retained.map.flatMap((r) =>
                    r.outcome === "carried"
                      ? [this.kernel.get(r.replacement_id)].filter(
                          (m): m is MissionRecord => m !== undefined,
                        )
                      : [],
                  ),
                },
              }
            : {}),
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
    // @spec expansion#reconciliation (#1177): a refused deferral answers
    // `access_denied` with the reconciliation status it recorded, if any, on
    // every later poll. An Approver's denial records none.
    if (row.state === "access_denied") {
      return {
        error: "access_denied",
        ...(typeof row.refusal_status === "string" && row.refusal_status
          ? { status: row.refusal_status as ReconciliationStatus }
          : {}),
      };
    }
    if (row.redeemed === 1) return { error: "invalid_grant" };
    // Record a refusal: `access_denied`, the deferred substrate's outcome for a
    // request that resolved with an error (DTR -00 Section 5.5.1 step 4), with
    // the reconciliation status when a reconciliation check failed.
    const refuse = (status?: ReconciliationStatus): { error: "access_denied"; status?: ReconciliationStatus } => {
      this.db
        .prepare("UPDATE expansion_deferrals SET state = 'access_denied', refusal_status = ? WHERE deferral_code = ?")
        .run(status ?? null, deferralCode);
      return { error: "access_denied", ...(status ? { status } : {}) };
    };

    // @spec expansion#deferred-window check (a): re-verify predecessor STATE at
    // completion. A predecessor terminated/superseded during the window fails.
    const predecessor = this.kernel.get(row.predecessor_id as string);
    const observedPredecessor = predecessor ? this.kernel.applyExpiry(predecessor) : undefined;
    if (!observedPredecessor || observedPredecessor.state !== "active") {
      return refuse(reconciliationStatusFor(observedPredecessor));
    }

    const recorded = JSON.parse(row.intent_json as string) as {
      i: MissionIntent;
      pr?: AuthorityEntry[];
    };
    const intent = recorded.i;
    const approver = JSON.parse(row.approver_json as string) as { iss: string; sub: string };
    // @spec expansion#creation-idempotency — the successor INSERT and the
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
    let txOut:
      | { successor: MissionRecord; predecessorId: string; carryover?: ApplyCarryoverOutcome }
      | undefined;
    // The in-transaction re-check refuses by returning undefined: the
    // predecessor stopped being effectively active between check and commit.
    let predecessorRefused = false;
    let restricted = false;
    try {
      txOut = this.redeemInTransaction(row, intent, recorded, approver, submissionEvidence, creationRequestId);
      predecessorRefused = txOut === undefined;
    } catch (e) {
      // @spec child-delegation#carryover-commit — a carryover refusal rolls the
      // WHOLE completion back: no partial successor, no surviving replacement
      // and no cascade. The approval is stale, so the completion fails and a
      // fresh render and approval are required.
      if (e instanceof CarryoverError) {
        this.cancelCarryoverPlan(row.deferral_code as string);
        txOut = undefined;
      } else if (e instanceof IntentError) {
        txOut = undefined;
      } else if (e instanceof RestrictedSinceApprovalError) {
        restricted = true;
        txOut = undefined;
      } else {
        throw e;
      }
    }
    if (!txOut) {
      if (restricted) return refuse("authority_restricted_since_approval");
      // An expiry or carryover refusal is not a reconciliation failure and
      // carries no status (@spec expansion#successor-expiry).
      if (!predecessorRefused) return refuse();
      const now = this.kernel.get(row.predecessor_id as string);
      return refuse(reconciliationStatusFor(now ? this.kernel.observe(now) : undefined));
    }
    this.kernel.publishPendingCommits();
    this.db.prepare("UPDATE expansion_deferrals SET completion_released = 1 WHERE deferral_code = ?").run(deferralCode);
    return {
      successor: txOut.successor,
      approvedUntil: row.approved_until as string,
      ...(creationRequestId ? { creationRequestId } : {}),
      ...(txOut.carryover ? { carryover: txOut.carryover } : {}),
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
  ): { successor: MissionRecord; predecessorId: string; carryover?: ApplyCarryoverOutcome } | undefined {
    return withTransaction(this.kernel.db, () => {
      // Read-only effective-active re-check inside the transaction (nothing is
      // materialized here; lazy expiry stays with the ordinary gates). The
      // OBSERVED state: its own expiry and any ancestor's termination apply.
      const predNow = this.kernel.get(row.predecessor_id as string);
      if (!predNow || predNow.state !== "active" || this.kernel.observe(predNow).state !== "active") {
        return undefined;
      }
      // @spec child-delegation#carryover-manifest — completion uses EXACTLY the
      // reserved successor identifier the approval authenticated; it never
      // invents an identity the approved manifest did not name.
      const manifest = row.carryover_manifest_json
        ? (JSON.parse(row.carryover_manifest_json as string) as CarryoverManifest)
        : undefined;
      // @spec child-delegation#carryover-commit — a committed manifest either
      // executes INTACT or completion REFUSES. Where the switch is off the
      // batch would be skipped and the supersession CAS's ordinary cascade
      // would terminate the whole live subtree with no replacements: a
      // different plan from the one the Approver authenticated, chosen by a
      // deployment flag. The refusal happens BEFORE any write, so there is no
      // successor, no replacement and above all no cascade, and the row stays
      // approved and unredeemed, so restoring the switch still completes the
      // approved plan as approved. Pairing the manifest with the config it runs
      // under leaves NO branch in which a manifest is present and skipped.
      const batch = manifest
        ? { manifest, config: this.requireCarryoverEnabled() }
        : undefined;
      const res = createExpansion(this.kernel, {
        predecessorId: row.predecessor_id as string,
        intent,
        ...(recorded.pr ? { proposedAuthority: recorded.pr } : {}),
        approver,
        approvalEventId: row.approval_event_id as string,
        approvedUntil: row.approved_until as string,
        ...(submissionEvidence?.length ? { submissionEvidence } : {}),
        ...(batch ? { successorId: batch.manifest.successor.mission_id } : {}),
        ...(row.ceiling_reconsent_json
          ? { ceilingReconsent: JSON.parse(row.ceiling_reconsent_json as string) as ReconsentedCeiling }
          : {}),
      });
      // @spec expansion#reconciliation check 3 (#1177), in the activation
      // transaction and before any carryover work: the successor's complete
      // Authority Set, carried authority included, overlaps no restriction of
      // the predecessor that came after adjudication, the initiation snapshot.
      // A deferral opened before this snapshot existed counts every latch.
      if (
        restrictedSinceAdjudication(predNow, res.successor.authority_set, {
          containment: row.pred_containment_version as number,
          discharge: (row.pred_discharge_count as number | null) ?? 0,
        })
      ) {
        throw new RestrictedSinceApprovalError();
      }
      if (creationRequestId) {
        this.creationIdempotency.completeInCallerTx(
          row.client_id as string,
          creationRequestId,
          res.successor.id,
        );
      }
      // @spec child-delegation#carryover-commit — the whole batch runs in THIS
      // transaction, between successor activation and predecessor supersession:
      // the descendant-set membership check, the per-row compare-and-set, every
      // replacement record, every external transfer, the terminal cascade of the
      // WHOLE old subtree (rendered carries, exclusions and unrendered
      // descendants alike), the complete final map and the authenticated
      // Carryover Evidence. Because the explicit traversal terminates every
      // descendant here, the `cascadeChildren` inside the supersession CAS below
      // is a genuine no-op rather than a second, outcome-less descent.
      // A committed manifest reaching here is always executed: the disabled
      // case refused above rather than falling through to ordinary cascade.
      let carryover: ApplyCarryoverOutcome | undefined;
      let cascadeAt: string | undefined;
      if (batch) {
        const applied = applyCarryoverInCallerTx(this.kernel, this.carryover, {
          planId: row.carryover_plan_id as string,
          manifest: batch.manifest,
          manifestHash: row.carryover_manifest_hash as string,
          successor: res.successor,
          approver,
          expansionApprovalEventId: row.approval_event_id as string,
          // @spec child-delegation#carryover — this is the AUTHENTICATED direct
          // approval completion route; there is no policy-adjudicated
          // completion path into carryover to refuse from.
          directApproval: true,
          config: batch.config,
        });
        carryover = {
          planId: row.carryover_plan_id as string,
          manifestHash: row.carryover_manifest_hash as string,
          map: applied.map,
          evidence: applied.evidence,
          evidenceJws: applied.evidenceJws,
          replacements: applied.replacements,
        };
        cascadeAt = applied.terminatedAt;
      }
      // @spec control-plane#fanout — the supersession CAS enqueues its own
      // durable event, its tombstone and the mandatory child cascade inside
      // THIS transaction, so nothing has to be suppressed and reconstructed
      // from state that has since moved. @spec child-delegation#cascade: when
      // carryover already terminated the subtree, the predecessor records the
      // same instant its rows did.
      const cas = this.kernel.supersedeInCallerTx(
        res.successor.id,
        cascadeAt ? { terminatedAt: cascadeAt } : {},
      );
      // Single-writer SQLite makes a lost CAS unreachable after the in-tx
      // check; the throw is the invariant's tripwire, and it rolls the
      // successor back rather than ever leaving both lineages live.
      if (!cas) throw new Error("expansion predecessor supersession failed inside the redemption transaction");
      const retired = this.db
        .prepare("UPDATE expansion_deferrals SET redeemed = 1 WHERE deferral_code = ? AND redeemed = 0 AND state = 'approved'")
        .run(row.deferral_code as string);
      if (retired.changes !== 1) throw new Error("expansion deferral retirement conflicted");
      return {
        successor: res.successor,
        predecessorId: cas.predecessorId,
        ...(carryover ? { carryover } : {}),
      };
    });
  }
}
