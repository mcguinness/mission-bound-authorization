/**
 * The mission-kernel (decision D30): mission records, approval events,
 * lifecycle, gating, projections, and the signed Status surface. No
 * oidc-provider types cross this boundary.
 */

import { randomBytes, randomInt } from "node:crypto";
import { authorityHash, intentHash, proposalHash } from "@mission/core";
import { openStore, UniqueViolationError, withTransaction, type Database } from "@mission/store";
import { SignJWT, type CryptoKey } from "jose";
import {
  buildContainmentEvidence,
  type ContainmentEvidence,
  type ContainmentPolicy,
  UnknownProtectedEventError,
} from "./containment.js";
import type { DerivationPolicy } from "./derive.js";
import { deriveAuthoritySet, isSubsetSet } from "./derive.js";
import {
  type SubmissionEvidenceBounds,
  validateAuthorityProposal,
  validateMissionIntent,
  validateMissionIntentSubmission,
} from "./intent.js";
import {
  signStatusListToken,
  STATUS_LIST_SIZE,
  type StatusEntry,
  stateToBit,
  statusListUri,
} from "./status-list.js";
import {
  type ApprovalBasis,
  type AuthorityEntry,
  type ContainmentEventRecord,
  type IntentSubmissionEvidenceFact,
  LEGAL_TRANSITIONS,
  type LifecycleCommit,
  type LifecycleOperation,
  type MissionClaim,
  type MissionContainment,
  type MissionIntent,
  type MissionIntentSubmission,
  type MissionRecord,
  type MissionState,
  type ParentRef,
  type TemplateRef,
  TERMINAL_STATES,
} from "./types.js";

/** Retry budget for random Status List index allocation on UNIQUE collision. */
const STATUS_INDEX_MAX_ATTEMPTS = 16;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS missions (
  id TEXT PRIMARY KEY,
  issuer TEXT NOT NULL,
  state TEXT NOT NULL,
  intent_json TEXT NOT NULL,
  proposed_authority_json TEXT,
  authority_set_json TEXT NOT NULL,
  intent_hash TEXT NOT NULL,
  proposal_hash TEXT,
  authority_hash TEXT NOT NULL,
  subject_iss TEXT NOT NULL,
  subject_sub TEXT NOT NULL,
  approver_iss TEXT NOT NULL,
  approver_sub TEXT NOT NULL,
  approval_basis_json TEXT NOT NULL,
  client_id TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  approval_event_id TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  max_derivations INTEGER,
  derivation_count INTEGER NOT NULL DEFAULT 0,
  grant_id TEXT,
  status_list_idx INTEGER UNIQUE,
  predecessor TEXT,
  successor TEXT,
  parent_id TEXT,
  parent_json TEXT,
  template_id TEXT,
  template_json TEXT,
  projected_from TEXT,
  containment_json TEXT,
  submission_evidence_json TEXT
) STRICT;
`;

export class LifecycleConflictError extends Error {}
export class GateError extends Error {
  constructor(
    readonly reason:
      | "mission_not_active"
      | "mission_expired"
      | "derivation_cap_exhausted"
      | "authority_contained",
    message: string,
  ) {
    super(message);
  }
}

export interface ApproveInput {
  intent: MissionIntent;
  /**
   * @spec mission#authority-proposal — the client-submitted
   * `authorization_details` array (already validated at intake), recorded on
   * the Mission exactly as submitted and committed by `proposal_hash`. Absent
   * (or empty) means no proposal was submitted: template-mode derivation, and
   * the record carries neither `proposed_authority` nor `proposal_hash`.
   */
  proposedAuthority?: AuthorityEntry[];
  subject: { iss: string; sub: string };
  approver: { iss: string; sub: string };
  clientId: string;
  approvalEventId: string;
  /**
   * @spec mission#intent-submission-evidence — the VERIFIED evidence facts to
   * record on the Mission (provenance metadata outside all integrity
   * anchors; see {@link MissionRecord.submission_evidence}). Absent or empty
   * means none verified — always the case today, with no registered types.
   */
  submissionEvidence?: IntentSubmissionEvidenceFact[];
}

export interface KernelOptions {
  issuer: string;
  policy: DerivationPolicy;
  statusKey: CryptoKey;
  statusKid: string;
  /**
   * @spec containment#containment-policy — the ISSUER-HELD ContainmentPolicy
   * (the map from a protected-event class to what narrows). OPTIONAL: only
   * {@link MissionKernel.containOnEvent} reads it, so a kernel constructed
   * without it behaves byte-identically to before (the manual `remove[]` path is
   * unaffected). Absent means every event fails closed at containOnEvent.
   */
  containmentPolicy?: ContainmentPolicy;
  now?: () => Date;
  /**
   * @spec status#mission-status-anti-oracle — Status List index allocator.
   * Injected so tests are deterministic; production draws a random index into a
   * list sized well above the population. The index MUST NOT be sequential and
   * MUST NOT be derivable from the Mission Identifier.
   */
  allocateStatusIndex?: () => number;
  /**
   * @spec status#status-list — the shared lifecycle-commit hook. Fired once per
   * committed transition from the four real commit funnels (`setState`,
   * `supersedeOnRedemption`, `insertRecord`, `contain`). The Status List
   * republisher subscribes today; Mission Signals subscribes next.
   */
  onLifecycleCommit?: (commit: LifecycleCommit) => void;
  /**
   * @spec draft-mcguinness-oauth-mission#per-entry-enforcement,
   * child-delegation#fanout — the AS's actor-type ASSERTION registry: a map from
   * a delegate / child-actor client identifier to the `sub_profile` the AS
   * asserts for it. Consulted ONLY by the actor-eligibility matcher
   * ({@link delegatePermitted}); a request-supplied (self-asserted) profile is
   * never matched against a `sub_profile` matcher. Absent means the AS asserts no
   * class for any actor, so only `{ "sub": ... }` matchers can admit a delegate.
   */
  actorProfiles?: Record<string, string>;
}

export class MissionKernel {
  readonly db: Database;
  private readonly now: () => Date;
  private readonly allocateStatusIndex: () => number;

  constructor(private readonly opts: KernelOptions) {
    this.db = openStore(SCHEMA);
    this.now = opts.now ?? (() => new Date());
    this.allocateStatusIndex = opts.allocateStatusIndex ?? (() => randomInt(STATUS_LIST_SIZE));
  }

  validateIntent(raw: string): MissionIntent {
    return validateMissionIntent(raw);
  }

  /**
   * @spec mission#submission-via-par — intake of the `mission_intent`
   * parameter VALUE: the Mission Intent Submission envelope
   * ({@link validateMissionIntentSubmission}). The returned `intent` is the
   * exact semantic object `intent_hash` commits; presented `evidence` is
   * typed, bounded, and never silently ignored.
   */
  validateSubmission(raw: string, bounds?: SubmissionEvidenceBounds): MissionIntentSubmission {
    return validateMissionIntentSubmission(raw, bounds);
  }

  derive(intent: MissionIntent, proposal?: readonly AuthorityEntry[]): AuthorityEntry[] {
    return deriveAuthoritySet(intent, this.opts.policy, proposal);
  }

  /** @spec mission#authority-proposal — intake of the submitted proposal. */
  validateProposal(raw: string, resources: string[]): AuthorityEntry[] {
    return validateAuthorityProposal(raw, resources);
  }

  /**
   * @spec draft-mcguinness-oauth-mission#per-entry-enforcement — the `sub_profile`
   * the AS ASSERTS for an actor (delegate / child-actor) client identifier, from
   * deployment config (D25), or undefined when the AS asserts no class. A
   * request-supplied profile is NEVER consulted here: only this AS-asserted value
   * can satisfy a `{ "sub_profile": ... }` matcher ({@link delegatePermitted}).
   */
  actorProfile(sub: string): string | undefined {
    return this.opts.actorProfiles?.[sub];
  }

  /**
   * @spec mission#integrity-anchors — the approval event creates the record
   * with both anchors; approval_event_id is the idempotency key.
   */
  approve(input: ApproveInput): MissionRecord {
    // @spec mission#authority-proposal — normalize: an empty proposal is no
    // proposal (matches the wire, where an empty authorization_details array
    // is treated as absent). Present iff submitted: template-mode Missions
    // carry neither `proposed_authority` nor `proposal_hash`.
    const proposal = input.proposedAuthority?.length ? input.proposedAuthority : undefined;
    const authoritySet = this.derive(input.intent, proposal);
    // @spec mission#mission-identifier: opaque URL-safe, >=128 bits entropy.
    const id = `msn_${randomBytes(18).toString("base64url")}`;
    // @spec mission#integrity-anchors (TOCTOU) — all three commitments
    // (intent_hash, proposal_hash, authority_hash) are computed TOGETHER here,
    // at the approval decision, over the exact context being recorded: a task,
    // proposal, or derived-set change between approval rendering and the
    // decision re-enters this method with the changed inputs and recomputes
    // every anchor, so a swapped proposal under an unchanged intent_hash
    // cannot equivocate.
    const authorityHashValue = authorityHash(this.opts.issuer, authoritySet as never);
    // @spec mission#approval-basis — direct: the human approval event itself
    // creates the record; consent_principal == activation_actor == approver,
    // and root_commitment is this Mission's own authority_hash.
    const approvalBasis: ApprovalBasis = {
      type: "direct",
      consent_principal: input.approver,
      activation: { approval_event_id: input.approvalEventId },
      activation_actor: input.approver,
      root_commitment: authorityHashValue,
    };
    const record: MissionRecord = {
      id,
      issuer: this.opts.issuer,
      state: "active",
      intent: input.intent,
      ...(proposal ? { proposed_authority: proposal } : {}),
      authority_set: authoritySet,
      intent_hash: intentHash(this.opts.issuer, input.intent as never),
      ...(proposal ? { proposal_hash: proposalHash(this.opts.issuer, proposal as never) } : {}),
      // @spec mission#intent-submission-evidence — verified facts land on the
      // record only (never in any anchor input above).
      ...(input.submissionEvidence?.length ? { submission_evidence: input.submissionEvidence } : {}),
      authority_hash: authorityHashValue,
      subject: input.subject,
      approver: input.approver,
      approval_basis: approvalBasis,
      client_id: input.clientId,
      policy_version: this.opts.policy.policy_version,
      approval_event_id: input.approvalEventId,
      created_at: this.now().toISOString(),
      expires_at: input.intent.expires_at,
      version: 1,
      max_derivations: input.intent.controls?.max_derivations ?? null,
      derivation_count: 0,
      grant_id: null,
      status_list_idx: null,
    };
    try {
      this.insertRecord(record);
    } catch (e) {
      if (e instanceof UniqueViolationError) {
        // Idempotent approval: return the record this event already created.
        const existing = this.findByApprovalEvent(input.approvalEventId);
        if (existing) return existing;
      }
      throw e;
    }
    return record;
  }

  /** Insert a full record (shared by approve and expansion). */
  insertRecord(record: MissionRecord): void {
    withTransaction(this.db, () => {
      this.db
        .prepare(
          `INSERT INTO missions (id, issuer, state, intent_json, proposed_authority_json,
           authority_set_json, intent_hash, proposal_hash,
           authority_hash, subject_iss, subject_sub, approver_iss, approver_sub,
           approval_basis_json, client_id,
           policy_version, approval_event_id, created_at, expires_at, version, max_derivations,
           derivation_count, grant_id, predecessor, parent_id, parent_json, template_id,
           template_json, projected_from, submission_evidence_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          record.id,
          record.issuer,
          record.state,
          JSON.stringify(record.intent),
          // @spec mission#mission-record — the submitted proposal exactly as
          // recorded (null when none: template mode), with its commitment.
          record.proposed_authority ? JSON.stringify(record.proposed_authority) : null,
          JSON.stringify(record.authority_set),
          record.intent_hash,
          record.proposal_hash ?? null,
          record.authority_hash,
          record.subject.iss,
          record.subject.sub,
          record.approver.iss,
          record.approver.sub,
          // @spec mission#approval-basis: fixed at creation, immutable (like
          // `parent`/`template`), so it is written only here.
          JSON.stringify(record.approval_basis),
          record.client_id,
          record.policy_version,
          record.approval_event_id,
          record.created_at,
          record.expires_at,
          record.version,
          record.max_derivations,
          record.derivation_count,
          record.grant_id,
          record.predecessor ?? null,
          // @spec child-delegation#parent-member: `parent` is immutable after
          // creation (like `predecessor`), so it is written only here.
          record.parent?.id ?? null,
          record.parent ? JSON.stringify(record.parent) : null,
          // @spec mission-template#template-lineage: `template` is immutable
          // after creation (like `parent`/`predecessor`), so it is written only
          // here. Null on every non-template Mission (fast path preserved).
          record.template?.id ?? null,
          record.template ? JSON.stringify(record.template) : null,
          // @spec child-delegation#child-state: a fresh Mission is never a
          // projected-suspended hold; the marker is written later by setState.
          record.projected_from ?? null,
          // @spec mission#intent-submission-evidence — verified facts, immutable
          // after creation (like approval_basis), written only here.
          record.submission_evidence ? JSON.stringify(record.submission_evidence) : null,
        );
    });
    // The activating event: version 1, no prior_state. Shared by approve() and
    // expansion; the commit is built from the persisted row.
    const inserted = this.get(record.id);
    if (inserted) this.emitCommit(inserted);
  }

  nowDate(): Date {
    return this.now();
  }

  /**
   * @spec expansion#superseded-state: on the successor's first grant
   * redemption, the successor stays active and the predecessor enters
   * `superseded` atomically. Returns false if already superseded.
   */
  supersedeOnRedemption(successorId: string): boolean {
    const successor = this.get(successorId);
    if (!successor?.predecessor) return false;
    // This raw UPDATE bypasses setState (the only funnel that skips it), so the
    // lifecycle-commit hook is fired here explicitly, from the persisted row.
    let predId: string | undefined;
    const superseded = withTransaction(this.db, () => {
      const pred = this.get(successor.predecessor as string);
      if (!pred || pred.state !== "active") return false;
      predId = pred.id;
      this.db
        .prepare("UPDATE missions SET state = 'superseded', successor = ?, version = version + 1 WHERE id = ? AND state = 'active'")
        .run(successorId, pred.id);
      return true;
    });
    if (superseded && predId) {
      const fresh = this.get(predId);
      if (fresh) this.emitCommit(fresh, "active", successorId);
      // @spec child-delegation#cascade — `superseded` is a TERMINAL cascade
      // trigger; the successor does NOT inherit the predecessor's children (their
      // strict-subset proof was against the predecessor's Authority Set). This
      // funnel bypasses setState, so the cascade is invoked explicitly here,
      // outside the withTransaction block above (cascadeChildren -> setState uses
      // a bare UPDATE, so there is no nested transaction).
      this.cascadeChildren(predId);
    }
    return superseded;
  }

  get(id: string): MissionRecord | undefined {
    const row = this.db.prepare("SELECT * FROM missions WHERE id = ?").get(id) as
      | Record<string, unknown>
      | undefined;
    return row ? rowToRecord(row) : undefined;
  }

  findByGrant(grantId: string): MissionRecord | undefined {
    const row = this.db.prepare("SELECT * FROM missions WHERE grant_id = ?").get(grantId) as
      | Record<string, unknown>
      | undefined;
    return row ? rowToRecord(row) : undefined;
  }

  findByApprovalEvent(approvalEventId: string): MissionRecord | undefined {
    const row = this.db
      .prepare("SELECT * FROM missions WHERE approval_event_id = ?")
      .get(approvalEventId) as Record<string, unknown> | undefined;
    return row ? rowToRecord(row) : undefined;
  }

  bindGrant(missionId: string, grantId: string): void {
    this.db.prepare("UPDATE missions SET grant_id = ? WHERE id = ?").run(grantId, missionId);
  }

  /** @spec child-delegation#parent-member — the immediate Child Missions of a parent. */
  findChildren(parentId: string): MissionRecord[] {
    const rows = this.db
      .prepare("SELECT * FROM missions WHERE parent_id = ?")
      .all(parentId) as Array<Record<string, unknown>>;
    return rows.map(rowToRecord);
  }

  /**
   * @spec child-delegation#cascade — cascade a TERMINAL parent transition to its
   * transitive descendants: each dependent Child Mission enters the terminal
   * `cascaded` state. Invoked from the terminal-commit path (the gate at the end
   * of {@link setState}, which covers `transition(revoke/complete)` and
   * `applyExpiry`) and from {@link supersedeOnRedemption} (which bypasses
   * setState). Because each child transition flows through `setState -> emitCommit`,
   * the Status List republisher and Mission Signals propagate the `cascaded`
   * commit for free (`stateToBit` already maps `cascaded` -> INVALID).
   *
   * Transitivity is carried by setState's own terminal gate: setting a child to
   * the terminal `cascaded` state re-enters this method for its children, in
   * generation order (@spec child-delegation#cascade: "in generation order").
   * This method therefore does NOT self-recurse.
   *
   * A descendant NOT in `active`/`suspended` is skipped: `setState` throws
   * {@link LifecycleConflictError} on an already-terminal source, so an
   * already-terminal descendant would otherwise abort the whole cascade. Skipping
   * it also makes a repeated cascade over the same subtree a safe no-op (e.g. an
   * expired-then-revoked parent whose stale in-memory record re-runs the cascade).
   *
   * `suspend` is deliberately NOT a cascade trigger: per @spec
   * child-delegation#cascade `suspended` is the one reversible trigger (children
   * are held non-active and restored on parent resume, NOT driven terminal). That
   * reversible projection/restore is handled separately by
   * {@link projectSuspendedChildren} / {@link restoreProjectedChildren}, gated off
   * the non-terminal `suspended`/`active` commits in {@link setState}; only
   * terminal triggers cascade here.
   */
  cascadeChildren(parentId: string): void {
    for (const child of this.findChildren(parentId)) {
      if (child.state === "active" || child.state === "suspended") {
        this.setState(child, "cascaded");
      }
    }
  }

  /**
   * @spec child-delegation#cascade (reversible trigger), #child-state — project a
   * parent SUSPEND onto its transitive descendants. Each currently-`active` child
   * is set to the reversible `suspended` hold and stamped `projected_from =
   * "active"`, recording the state to restore on parent resume. A descendant that
   * is NOT `active` (e.g. one suspended INDEPENDENTLY before the parent) is
   * skipped and gets NO marker, so it is never restored later.
   *
   * Each transition flows through `setState -> emitCommit`, so the Status List
   * republisher and Mission Signals propagate the `suspended` commit (version
   * increments; `stateToBit` maps `suspended` -> SUSPENDED). Transitivity and
   * generation order ride setState's own re-entry (see there): projecting a child
   * to `suspended` re-enters this method for ITS active children. This method
   * therefore does NOT self-recurse. It is the reversible counterpart to
   * {@link cascadeChildren}, invoked only from the non-terminal `suspended` gate.
   */
  private projectSuspendedChildren(parentId: string): void {
    for (const child of this.findChildren(parentId)) {
      if (child.state === "active") {
        this.setState(child, "suspended", "active");
      }
    }
  }

  /**
   * @spec child-delegation#cascade (reversible trigger), #child-state — restore,
   * on parent RESUME, the descendants a suspend projected. A child is restored
   * ONLY if it is still in the `suspended` hold AND carries a `projected_from`
   * marker: an independently-suspended child (no marker) and a child driven
   * terminal while suspended (no longer `suspended`) are both skipped, so neither
   * is revived. Restoring a child to `active` re-enters {@link setState}'s active
   * gate for that child's own projected children (transitive, generation order).
   *
   * @spec child-delegation#child-state (expiry precedence) — the expiry clock is
   * applied FIRST: a child whose `expires_at` passed during the suspension ends
   * `expired` (a terminal commit that itself cascades) and is NOT restored to
   * `active`. Only a still-held child is set back to its stored `projected_from`;
   * setState's `to === "active"` rule then clears the marker.
   */
  private restoreProjectedChildren(parentId: string): void {
    for (const found of this.findChildren(parentId)) {
      const held = this.get(found.id);
      if (!held || held.state !== "suspended" || held.projected_from === undefined) continue;
      const priorState = held.projected_from; // narrowed to MissionState by the guard
      // Expiry precedence: an expired-during-suspension child ends `expired`.
      const child = this.applyExpiry(held);
      if (child.state !== "suspended") continue; // expired (now terminal) -> not restored
      this.setState(child, priorState);
    }
  }

  /**
   * @spec status#status-list — opt a Mission into the Status List by assigning
   * it an index. @spec status#mission-status-anti-oracle: the index is random
   * (never sequential, never derivable from `id`), allocated into a list sized
   * well above the population and persisted UNIQUE; a collision retries.
   * Idempotent: returns the existing index if already assigned.
   *
   * Enrollment is restricted to `active` Missions. A fresh participant's bit is
   * VALID (0x00), which equals the default for unallocated indices, so a cached
   * list published before enrollment still reads that index correctly until the
   * Mission's next committed transition marks the list dirty. Enrolling a
   * non-active Mission would instead publish VALID for it until an unrelated
   * transition republished the list: a fail-open. (Enrollment persists through
   * later transitions; a re-call on an already-enrolled Mission is idempotent.)
   */
  participateInStatusList(id: string): number {
    const existing = this.mustGet(id);
    if (existing.status_list_idx !== null) return existing.status_list_idx;
    const record = this.applyExpiry(existing);
    if (record.state !== "active") {
      throw new LifecycleConflictError(
        `mission ${id} must be active to join the status list (is ${record.state})`,
      );
    }
    for (let attempt = 0; attempt < STATUS_INDEX_MAX_ATTEMPTS; attempt++) {
      const idx = this.allocateStatusIndex();
      try {
        withTransaction(this.db, () => {
          this.db.prepare("UPDATE missions SET status_list_idx = ? WHERE id = ?").run(idx, id);
        });
        return idx;
      } catch (e) {
        if (e instanceof UniqueViolationError) continue; // index taken, redraw
        throw e;
      }
    }
    throw new Error(`could not allocate a unique status list index for ${id}`);
  }

  /**
   * @spec status#status-list — the participating set as packed entries, expiry
   * applied. Latent-bug fix: enumerating raw rows would publish VALID for a
   * Mission already past its `expires_at`; applyExpiry commits the `expired`
   * transition first (and fires the commit hook), so the list reflects true
   * state. supersedeOnRedemption transitions are likewise reflected because the
   * rows are re-read here.
   */
  statusListEntries(): StatusEntry[] {
    const rows = this.db
      .prepare("SELECT * FROM missions WHERE status_list_idx IS NOT NULL")
      .all() as Array<Record<string, unknown>>;
    return rows.map(rowToRecord).map((r) => {
      const fresh = this.applyExpiry(r);
      return { idx: fresh.status_list_idx as number, bit: stateToBit(fresh.state) };
    });
  }

  /** @spec status#status-list — sign the current Status List Token. */
  publishStatusList(): Promise<string> {
    return signStatusListToken({
      issuer: this.opts.issuer,
      uri: statusListUri(this.opts.issuer),
      kid: this.opts.statusKid,
      key: this.opts.statusKey,
      now: this.now(),
      entries: this.statusListEntries(),
    });
  }

  /** @spec mission-management: enumerate the full fleet for the operator. */
  allMissions(): MissionRecord[] {
    const rows = this.db.prepare("SELECT * FROM missions ORDER BY created_at").all() as Array<
      Record<string, unknown>
    >;
    return rows.map(rowToRecord);
  }

  /** Active (non-expired) missions for a subject, for catalog status (D9). */
  activeMissionsForSubject(sub: string): MissionRecord[] {
    const rows = this.db
      .prepare("SELECT * FROM missions WHERE subject_sub = ? AND state = 'active'")
      .all(sub) as Array<Record<string, unknown>>;
    return rows.map(rowToRecord).map((r) => this.applyExpiry(r)).filter((r) => r.state === "active");
  }

  /**
   * @spec status#legal-transitions — idempotent success when the resulting
   * state equals the current state, except `resume`, which is legal only
   * from `suspended`; anything else is a conflict.
   */
  transition(id: string, op: LifecycleOperation): MissionRecord {
    const record = this.mustGet(id);
    this.applyExpiry(record);
    const rule = LEGAL_TRANSITIONS[op];
    if (record.state === rule.to && op !== "resume") return record;
    if (!rule.from.includes(record.state)) {
      throw new LifecycleConflictError(`${op} is not legal from ${record.state}`);
    }
    return this.setState(record, rule.to);
  }

  /**
   * @spec containment#containment-policy — event-driven containment: apply the
   * ISSUER-HELD ContainmentPolicy DETERMINISTICALLY when a protected event
   * fires. Look the event's `type` up in the configured policy; if NO rule
   * matches (or no policy is configured) FAIL CLOSED with {@link
   * UnknownProtectedEventError} (nothing is committed), otherwise delegate to
   * {@link contain} with the matched rule's `remove` and stamp its `rule_id` as
   * the evidence `policy`. Because a compromised caller supplies only the event
   * (never the `remove`), it cannot shape which capability narrows. Idempotency,
   * monotonicity, and the metadata-only commit are entirely {@link contain}'s.
   */
  containOnEvent(
    id: string,
    event: { type: string; source: string; observed_at: string; event_id: string },
  ): { record: MissionRecord; evidence: ContainmentEvidence } {
    const rule = this.opts.containmentPolicy?.rules.find((r) => r.event_type === event.type);
    if (!rule) {
      throw new UnknownProtectedEventError(
        `no containment rule for protected-event type '${event.type}'`,
      );
    }
    return this.contain(id, { event, remove: rule.remove, policyRule: rule.rule_id });
  }

  /**
   * Mission Containment: apply an issuer-committed, MONOTONIC narrowing of the
   * Mission's effective authority. The approved `authority_set`/`authority_hash`
   * are untouched; the new contained set is the UNION of the prior contained set
   * and `remove` (removal-only; there is no removal API, restore is the
   * Expansion successor path). Legal from `active` and `suspended`; refused from
   * a terminal state. IDEMPOTENT by `event.event_id` (mirrors approve()'s
   * approval_event_id): a repeat returns the current record with no version bump
   * and no extra event row.
   *
   * The commit is metadata-only: `containment_json` and `version = version + 1`
   * are updated atomically, then the lifecycle-commit hook fires from the
   * persisted row with `prior_state` EQUAL to `state` (the fourth commit
   * funnel), so the Status List and Mission Signals propagate the narrowing
   * with no new channels.
   */
  contain(
    id: string,
    input: {
      event: { type: string; source: string; observed_at: string; event_id: string };
      remove: Array<{ resource: string; actions?: string[] }>;
      /**
       * @spec containment#containment-policy — the ContainmentPolicy `rule_id`
       * that drove this narrowing when the event was applied via {@link
       * containOnEvent}; absent for the manual break-glass path. Recorded as the
       * evidence `policy` field (defaulting to "manual"); it does NOT affect the
       * monotonic union, idempotency, or the commit.
       */
      policyRule?: string;
    },
  ): { record: MissionRecord; evidence: ContainmentEvidence } {
    const record = this.applyExpiry(this.mustGet(id));
    if (TERMINAL_STATES.has(record.state)) {
      throw new LifecycleConflictError(`contain is not legal from ${record.state}`);
    }
    if (!Array.isArray(input.remove) || input.remove.length === 0) {
      throw new Error("contain requires a non-empty remove list");
    }
    const prior = record.containment;
    const nowIso = this.now().toISOString();
    const evidenceBase = {
      mission: { id: record.id, issuer: record.issuer, authority_hash: record.authority_hash },
      event: input.event,
      // @spec containment#containment-policy — the ContainmentPolicy rule_id that
      // fired (from containOnEvent), or "manual" for the break-glass remove[] path.
      policy: input.policyRule ?? "manual",
      created_at: nowIso,
    };

    // Idempotency by event_id: a repeat returns the current record unchanged
    // (no version bump, no extra event row) with a no-op evidence record
    // (prior_* == new_*), mirroring approve()'s idempotent re-approval.
    const applied = prior?.events.find((e) => e.event_id === input.event.event_id);
    if (applied && prior) {
      return {
        record,
        evidence: buildContainmentEvidence({
          ...evidenceBase,
          prior_version: record.version,
          new_version: record.version,
          prior_containment_version: prior.containment_version,
          new_containment_version: prior.containment_version,
          removed: applied.removed,
        }),
      };
    }

    // New contained set = UNION with the prior (monotonic). Merged by resource:
    // an entry with no `actions` contains the whole resource and absorbs any
    // per-action containment for it.
    const merged = new Map<string, Set<string> | undefined>();
    for (const e of prior?.contained ?? []) {
      merged.set(e.resource, e.actions ? new Set(e.actions) : undefined);
    }
    for (const r of input.remove) {
      if (!merged.has(r.resource)) {
        merged.set(r.resource, r.actions ? new Set(r.actions) : undefined);
        continue;
      }
      const cur = merged.get(r.resource);
      if (cur === undefined) continue; // whole resource already contained
      if (!r.actions) {
        merged.set(r.resource, undefined);
      } else {
        for (const a of r.actions) cur.add(a);
      }
    }
    const contained = [...merged.entries()].map(([resource, actions]) =>
      actions ? { resource, actions: [...actions] } : { resource },
    );
    const eventRecord: ContainmentEventRecord = {
      type: input.event.type,
      source: input.event.source,
      observed_at: input.event.observed_at,
      event_id: input.event.event_id,
      removed: input.remove.map((r) => ({
        resource: r.resource,
        ...(r.actions ? { actions: [...r.actions] } : {}),
      })),
    };
    const next: MissionContainment = {
      containment_version: (prior?.containment_version ?? 0) + 1,
      contained,
      events: [...(prior?.events ?? []), eventRecord],
    };

    // Belt-and-suspenders: the union construction above makes narrowing
    // structural, but assert it anyway — the new effective set MUST be a subset
    // of the prior effective set (containment only ever narrows).
    const priorEffective = this.effectiveAuthoritySet(record);
    const newEffective = this.effectiveAuthoritySet({ ...record, containment: next });
    if (!isSubsetSet(newEffective, priorEffective)) {
      throw new Error(`containment for ${id} would widen the effective set (monotonicity violated)`);
    }

    withTransaction(this.db, () => {
      this.db
        .prepare("UPDATE missions SET containment_json = ?, version = version + 1 WHERE id = ?")
        .run(JSON.stringify(next), record.id);
    });
    // Commit from the persisted row; prior == current state marks the commit
    // metadata-only (state unchanged, version incremented).
    const fresh = this.get(record.id);
    if (!fresh) throw new Error(`unknown mission: ${id}`);
    this.emitCommit(fresh, fresh.state);
    // @spec child-delegation#child-state — containment propagates entry-wise to
    // existing children justified by the now-contained parent entry, so a child
    // cannot keep deriving contained authority while the parent stays `active`.
    // Only the NEWLY removed items (`input.remove`), not the whole merged
    // overlay: earlier removals were already propagated when THEY were applied.
    this.propagateContainmentToChildren(fresh, input.remove, input.event, input.policyRule);
    return {
      record: fresh,
      evidence: buildContainmentEvidence({
        ...evidenceBase,
        prior_version: record.version,
        new_version: fresh.version,
        prior_containment_version: prior?.containment_version ?? 0,
        new_containment_version: next.containment_version,
        removed: eventRecord.removed,
      }),
    };
  }

  /**
   * @spec child-delegation#child-state — propagate a containment narrowing
   * entry-wise to PARENT's existing children. A removed item applies to a
   * child when the child holds an Authority Set entry for that SAME resource:
   * a Child Mission's `authority_set` is proven (at creation,
   * {@link createChildMission}) to be a strict subset of the parent's, so any
   * child entry sharing a resource with a removed item is necessarily justified
   * by the parent entry that removal narrowed (@spec
   * child-delegation#fanout-accounting). Matching on the resource key alone
   * (not a fresh subset probe) mirrors how {@link effectiveAuthoritySet} and
   * `contain`'s own merge already correlate entries, and fails CLOSED: a
   * subset re-probe here could spuriously fail on an unrelated malformed
   * constraint and silently skip propagation, which containment must not do.
   *
   * A terminal child cannot derive further and is skipped (mirrors {@link
   * cascadeChildren}'s active/suspended-only gate; `contain` itself also
   * refuses a terminal target). Recurses through {@link contain} itself, so a
   * grandchild justified transitively through the child picks up the same
   * narrowing (mirrors {@link cascadeChildren}'s re-entry pattern); the
   * recursive call's own idempotency-by-event_id is scoped to that child's own
   * containment ledger, so replaying the same `event` is safe at every level.
   * The parent's own lifecycle state is never touched here: containment only
   * ever narrows effective authority, never a Mission's state.
   */
  private propagateContainmentToChildren(
    parent: MissionRecord,
    removed: Array<{ resource: string; actions?: string[] }>,
    event: { type: string; source: string; observed_at: string; event_id: string },
    policyRule?: string,
  ): void {
    for (const child of this.findChildren(parent.id)) {
      const fresh = this.applyExpiry(child);
      if (TERMINAL_STATES.has(fresh.state)) continue;
      const applicable = removed.filter((r) =>
        fresh.authority_set.some((ce) => ce.resource === r.resource),
      );
      if (applicable.length === 0) continue;
      this.contain(fresh.id, {
        event,
        remove: applicable,
        ...(policyRule !== undefined ? { policyRule } : {}),
      });
    }
  }

  /**
   * The Mission's EFFECTIVE Authority Set: the approved set minus the
   * containment overlay. An entry whose actions are all contained (or whose
   * resource is contained with no `actions` member) is dropped; otherwise the
   * contained actions are filtered out. FAST PATH: a Mission with no
   * containment returns the approved set as-is (byte-identical behavior).
   * `authority_hash` always commits the approved set; containment is evaluated
   * state, never a new hash.
   */
  effectiveAuthoritySet(record: MissionRecord): AuthorityEntry[] {
    const containment = record.containment;
    if (!containment) return record.authority_set;
    const out: AuthorityEntry[] = [];
    for (const entry of record.authority_set) {
      const contained = containment.contained.find((c) => c.resource === entry.resource);
      if (!contained) {
        out.push(entry);
        continue;
      }
      if (!contained.actions) continue; // whole resource contained -> entry dropped
      const actions = entry.actions.filter((a) => !(contained.actions as string[]).includes(a));
      if (actions.length === 0) continue; // every action contained -> entry dropped
      out.push({ ...entry, actions });
    }
    return out;
  }

  /** @spec status#state-machine — expiry clock: active/suspended -> expired. */
  applyExpiry(record: MissionRecord): MissionRecord {
    if (
      (record.state === "active" || record.state === "suspended") &&
      Date.parse(record.expires_at) <= this.now().getTime()
    ) {
      return this.setState(record, "expired");
    }
    return record;
  }

  /**
   * @spec mission#lifecycle, child-delegation#child-state — the shared active
   * gate for BOTH {@link gateDerivation} and {@link gateActive}: apply the expiry
   * clock, require the Mission itself `active`, and walk `parent` upward refusing
   * if ANY ancestor is non-active. Returns the expiry-fresh record. It does NOT
   * touch `derivation_count` nor the `max_derivations` cap; consuming a derivation
   * is {@link gateDerivation}'s alone, layered on top of this.
   */
  private gateActiveLineage(id: string): MissionRecord {
    const record = this.applyExpiry(this.mustGet(id));
    if (record.state === "expired") throw new GateError("mission_expired", `mission ${id} is expired`);
    if (record.state !== "active") {
      throw new GateError("mission_not_active", `mission ${id} is ${record.state}`);
    }
    // @spec child-delegation#child-state — the ancestor-active gate: action
    // under a Child Mission is refused while ANY ancestor is non-active. This is
    // belt-and-suspenders with suspend-projection (which already holds the child),
    // but the profile requires the explicit lineage check: walk `parent` upward,
    // applying the expiry clock to each ancestor, and refuse if one is not active.
    for (let ancestor = record.parent; ancestor?.id; ) {
      const parent = this.get(ancestor.id);
      if (!parent) break;
      const fresh = this.applyExpiry(parent);
      if (fresh.state !== "active") {
        throw new GateError(
          "mission_not_active",
          `mission ${id} has a non-active ancestor ${fresh.id} (${fresh.state})`,
        );
      }
      ancestor = fresh.parent;
    }
    return record;
  }

  /**
   * @spec mission#lifecycle — state-gated derivation: only `active` derives,
   * bounded by expires_at and max_derivations. Increments the derivation
   * count on success.
   */
  gateDerivation(id: string): MissionRecord {
    const record = this.gateActiveLineage(id);
    // Containment gate: token derivation draws on the EFFECTIVE set; a fully
    // contained Mission (empty effective set) has nothing left to derive.
    if (record.containment && this.effectiveAuthoritySet(record).length === 0) {
      throw new GateError("authority_contained", `mission ${id} effective authority is fully contained`);
    }
    if (record.max_derivations !== null && record.derivation_count >= record.max_derivations) {
      throw new GateError("derivation_cap_exhausted", `mission ${id} derivation cap exhausted`);
    }
    this.db
      .prepare("UPDATE missions SET derivation_count = derivation_count + 1 WHERE id = ?")
      .run(id);
    return { ...record, derivation_count: record.derivation_count + 1 };
  }

  /**
   * @spec mission#lifecycle — the SAME active gate as {@link gateDerivation}
   * (expiry clock, `active`-state requirement, and ancestor-active lineage walk)
   * WITHOUT consuming a derivation: no `max_derivations` cap check and no
   * `derivation_count` increment. For an async-delegation continuation path that
   * requires the Mission (and its lineage) live but is not itself a derivation.
   * Throws {@link GateError} on refusal, with the same reasons as gateDerivation.
   */
  gateActive(id: string): MissionRecord {
    return this.gateActiveLineage(id);
  }

  /** @spec mission#the-mission-claim */
  missionClaim(record: MissionRecord): MissionClaim {
    return {
      id: record.id,
      issuer: record.issuer,
      authority_hash: record.authority_hash,
      expires_at: Math.floor(Date.parse(record.expires_at) / 1000),
      // @spec mission#approval-basis: the read-only wire signal. MUST NOT be
      // relied on to grant authority.
      approval_basis: { type: record.approval_basis.type },
    };
  }

  /** @spec mission#introspection — the mission introspection member. */
  introspectionMission(record: MissionRecord): Record<string, unknown> {
    const fresh = this.applyExpiry(record);
    return {
      ...this.missionClaim(fresh),
      state: fresh.state,
      version: fresh.version,
      // @spec mission#introspection — issuer-only, like `state`: when the
      // Mission records an authority proposal, its `proposal_hash` is surfaced
      // for audit. Approval-time provenance, never carried on the `mission`
      // token claim (missionClaim above deliberately omits it).
      ...(fresh.proposal_hash ? { proposal_hash: fresh.proposal_hash } : {}),
      // Absent means no containment was ever applied (absent-means-none).
      ...(fresh.containment ? { containment_version: fresh.containment.containment_version } : {}),
      ...this.statusListRef(fresh),
    };
  }

  /**
   * @spec status#status-list — the referenced-token status object (`idx`,
   * `uri`) for a participating Mission; empty for a non-participant so the
   * member is absent.
   */
  private statusListRef(record: MissionRecord): Record<string, unknown> {
    if (record.status_list_idx === null) return {};
    return { status_list: { idx: record.status_list_idx, uri: statusListUri(this.opts.issuer) } };
  }

  /**
   * @spec status#mission-status-response — JWS, typ
   * mission-status-response+jwt, mission object mirroring the claim plus
   * state/version/fresh_until; audience-scoped authorization_details.
   */
  async signedStatus(
    id: string,
    opts: { audience?: string; requester: string; nonce?: string; freshnessSeconds?: number },
  ): Promise<string> {
    const record = this.applyExpiry(this.mustGet(id));
    const nowS = Math.floor(this.now().getTime() / 1000);
    const freshness = opts.freshnessSeconds ?? 60;
    // Audience-scoped entries project the EFFECTIVE set (approved minus
    // containment); a contained entry never appears on the Status surface.
    const scoped = opts.audience
      ? this.effectiveAuthoritySet(record).filter((e) => e.resource === opts.audience)
      : undefined;
    const payload: Record<string, unknown> = {
      sub: record.client_id,
      mission: {
        ...this.missionClaim(record),
        state: record.state,
        version: record.version,
        expires_at: record.expires_at,
        fresh_until: new Date((nowS + freshness) * 1000).toISOString(),
        ...(record.containment
          ? { containment_version: record.containment.containment_version }
          : {}),
        ...this.statusListRef(record),
      },
    };
    if (opts.nonce) payload.nonce = opts.nonce;
    if (scoped) payload.authorization_details = scoped;
    return new SignJWT(payload)
      .setProtectedHeader({ alg: "ES256", kid: this.opts.statusKid, typ: "mission-status-response+jwt" })
      .setIssuer(this.opts.issuer)
      .setAudience(opts.audience ?? opts.requester)
      .setIssuedAt(nowS)
      .setExpirationTime(nowS + freshness)
      .sign(this.opts.statusKey);
  }

  private setState(record: MissionRecord, to: MissionState, projectedFrom?: MissionState): MissionRecord {
    if (TERMINAL_STATES.has(record.state)) {
      throw new LifecycleConflictError(`mission ${record.id} is terminal (${record.state})`);
    }
    // @spec child-delegation#child-state — the `projected_from` marker records a
    // child's pre-suspension state while it is held under a suspended parent. It
    // is SET when a suspend projection passes `projectedFrom` (always the held-from
    // `active`), and CLEARED (`NULL`) whenever a Mission returns to `active` (a
    // resume or a restore), so it is present only for the duration of the hold.
    if (projectedFrom !== undefined || to === "active") {
      this.db
        .prepare("UPDATE missions SET state = ?, version = version + 1, projected_from = ? WHERE id = ?")
        .run(to, projectedFrom ?? null, record.id);
    } else {
      this.db
        .prepare("UPDATE missions SET state = ?, version = version + 1 WHERE id = ?")
        .run(to, record.id);
    }
    // Commit from the persisted row, not the in-memory spread: transition()
    // discards applyExpiry()'s return, so the spread `version` can be off by one.
    const fresh = this.get(record.id);
    if (fresh) this.emitCommit(fresh, record.state);
    // @spec child-delegation#cascade — a terminal transition cascades to
    // dependent Child Missions. Gating here (after the commit) covers every
    // terminal funnel that flows through setState: transition(revoke/complete)
    // and applyExpiry(-> expired). It also carries cascade transitivity: setting
    // a child to `cascaded` re-enters this gate for the grandchildren.
    if (TERMINAL_STATES.has(to)) {
      this.cascadeChildren(record.id);
    } else if (to === "suspended") {
      // @spec child-delegation#cascade (reversible trigger) — a SUSPEND projects
      // active descendants to a reversible `suspended` hold. Transitivity rides
      // the same re-entry as the terminal cascade, in generation order.
      this.projectSuspendedChildren(record.id);
    } else if (to === "active") {
      // @spec child-delegation#cascade (reversible trigger) — a RESUME restores
      // the descendants this parent's suspend projected; re-entry carries the
      // restore down the tree.
      this.restoreProjectedChildren(record.id);
    }
    return { ...record, state: to, version: record.version + 1 };
  }

  /**
   * @spec status#status-list — fan the committed transition out to the
   * lifecycle-commit subscriber (no-op when none is wired). `record` MUST be the
   * post-commit persisted row so `state`/`version` are authoritative.
   *
   * @spec containment#propagation — also carries `record.containment`'s
   * current `containment_version` (absent-means-none), so a `contain` commit
   * (metadata-only: `prior_state` equals `state`) still surfaces the
   * narrowing to a subscriber comparing only `state`.
   */
  private emitCommit(record: MissionRecord, prior?: MissionState, successor?: string): void {
    const onCommit = this.opts.onLifecycleCommit;
    if (!onCommit) return;
    onCommit({
      id: record.id,
      issuer: record.issuer,
      state: record.state,
      version: record.version,
      committed_at: this.now().toISOString(),
      expires_at: record.expires_at,
      ...(prior ? { prior_state: prior } : {}),
      ...(successor ? { successor } : {}),
      ...(record.containment
        ? { containment_version: record.containment.containment_version }
        : {}),
    });
  }

  private mustGet(id: string): MissionRecord {
    const record = this.get(id);
    if (!record) throw new Error(`unknown mission: ${id}`);
    return record;
  }
}

function rowToRecord(row: Record<string, unknown>): MissionRecord {
  return {
    id: row.id as string,
    issuer: row.issuer as string,
    state: row.state as MissionState,
    intent: JSON.parse(row.intent_json as string) as MissionIntent,
    ...(row.proposed_authority_json
      ? { proposed_authority: JSON.parse(row.proposed_authority_json as string) as AuthorityEntry[] }
      : {}),
    authority_set: JSON.parse(row.authority_set_json as string) as AuthorityEntry[],
    intent_hash: row.intent_hash as string,
    ...(row.proposal_hash ? { proposal_hash: row.proposal_hash as string } : {}),
    ...(row.submission_evidence_json
      ? {
          submission_evidence: JSON.parse(
            row.submission_evidence_json as string,
          ) as IntentSubmissionEvidenceFact[],
        }
      : {}),
    authority_hash: row.authority_hash as string,
    subject: { iss: row.subject_iss as string, sub: row.subject_sub as string },
    approver: { iss: row.approver_iss as string, sub: row.approver_sub as string },
    approval_basis: JSON.parse(row.approval_basis_json as string) as ApprovalBasis,
    client_id: row.client_id as string,
    policy_version: row.policy_version as string,
    approval_event_id: row.approval_event_id as string,
    created_at: row.created_at as string,
    expires_at: row.expires_at as string,
    version: row.version as number,
    max_derivations: (row.max_derivations as number | null) ?? null,
    derivation_count: row.derivation_count as number,
    grant_id: (row.grant_id as string | null) ?? null,
    status_list_idx: (row.status_list_idx as number | null) ?? null,
    ...(row.predecessor ? { predecessor: row.predecessor as string } : {}),
    ...(row.parent_json ? { parent: JSON.parse(row.parent_json as string) as ParentRef } : {}),
    ...(row.template_json
      ? { template: JSON.parse(row.template_json as string) as TemplateRef }
      : {}),
    ...(row.projected_from ? { projected_from: row.projected_from as MissionState } : {}),
    // Absent means no containment was ever applied; written only by contain().
    ...(row.containment_json
      ? { containment: JSON.parse(row.containment_json as string) as MissionContainment }
      : {}),
  };
}
