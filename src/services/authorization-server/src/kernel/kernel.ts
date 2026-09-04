/**
 * The mission-kernel (decision D30): mission records, approval events,
 * lifecycle, gating, projections, and the signed Status surface. No
 * oidc-provider types cross this boundary.
 */

import { randomBytes, randomInt } from "node:crypto";
import {
  type ApprovalContextManifestInput,
  authorityHash,
  intentHash,
  proposalHash,
} from "@mission/core";
import { openStore, UniqueViolationError, withTransaction, type Database } from "@mission/store";
import { SignJWT, type CryptoKey } from "jose";
import {
  buildContainmentEvidence,
  type ContainmentEvidence,
  type ContainmentPolicy,
  UnknownProtectedEventError,
} from "./containment.js";
import {
  assertApproverMayActivate,
  assertPolicyDigestMatches,
  assertSubjectDiscipline,
  assertWithinSourceCeiling,
  type AuthoritySourceCatalog,
  type AuthoritySourceCatalogEntry,
  authoritySourceOf,
  parseAuthoritySource,
  resolveDeclaredSource,
  resolveSourceForClient,
  validateAuthoritySourceCatalog,
} from "./authority-source.js";
import type { DerivationPolicy } from "./derive.js";
import { deriveAuthoritySet, isSubsetSet, resolveDerivationLimit } from "./derive.js";
import {
  assertDischargePoliciesResolvable,
  conditionDigest,
  type DischargeAuthorityPolicy,
  dischargeAssertionFingerprint,
  DischargeConflictError,
  DischargeNotFoundError,
  type DischargeRequest,
  type DischargeResult,
  entryDigest,
  mappingPermits,
  resolveConditionMapping,
  terminalWhenOf,
} from "./discharge.js";
import { DischargeMappingPinStore } from "./discharge-pin-store.js";
import { DischargeEventStore, type DischargeEventKey } from "./lifecycle-idempotency.js";
import { MissionBoundGrantStore } from "./mission-bound-grant-store.js";
import { newMissionId } from "./mission-id.js";
import {
  type IntentSubmissionPresenter,
  provisionalIntentHash,
  type SubmissionEvidenceBounds,
  validateAuthorityProposal,
  validateMissionIntent,
  validateMissionIntentSubmission,
  verifyIntentSubmissionEvidence,
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
  type AuthoritySource,
  type ContainmentEventRecord,
  type DischargedEntry,
  type IntentSubmissionEvidenceEntry,
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
  authority_source_json TEXT NOT NULL,
  client_id TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  approval_event_id TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  derivation_limit INTEGER,
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
  discharged_json TEXT,
  submission_evidence_json TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS lifecycle_outbox (
  job_id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  mission_id TEXT NOT NULL,
  successor_id TEXT,
  activation_json TEXT NOT NULL,
  supersession_json TEXT NOT NULL,
  done INTEGER NOT NULL DEFAULT 0
) STRICT;
`;

export class LifecycleConflictError extends Error {}
export class GateError extends Error {
  constructor(
    readonly reason:
      | "mission_not_active"
      | "mission_expired"
      | "derivation_cap_exhausted"
      // @spec issuance-grant#effective-set-projection (#617 review 2) — an
      // empty effective set is refused BY ITS CAUSE: `authority_contained`
      // only where Containment CAUSALLY removed the authority,
      // `authority_exhausted` where the Mission has nothing to derive with the
      // overlay taken away. Both refuse `invalid_grant` at the wire; the
      // Containment denial reason rides only the former.
      | "authority_contained"
      | "authority_exhausted",
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
  /**
   * @spec discharge#discharge-authority — the ISSUER-HELD discharge-authority
   * policy (the map from a `discharge_policy` selector, or a bare `event_type`,
   * to the principals that may assert it). OPTIONAL and FAIL CLOSED: absent, no
   * condition's selector resolves, so a `terminal_when` condition cannot enter a
   * record at all and every `discharge` delivery joins the `not_found` collapse.
   */
  dischargeAuthority?: DischargeAuthorityPolicy;
  /**
   * @spec discharge#discharge-idempotency ("Retention") — override the event-dedup
   * retention window (seconds); defaults to the published retry horizon. A test
   * shortens it to prove that a repeated assertion after eviction is processed
   * fresh against the monotonic latch.
   */
  dischargeEventRetentionSeconds?: number;
  now?: () => Date;
  /**
   * @spec status#mission-status-anti-oracle — Status List index allocator.
   * Injected so tests are deterministic; production draws a random index into a
   * list sized well above the population. The index MUST NOT be sequential and
   * MUST NOT be derivable from the Mission Identifier.
   */
  allocateStatusIndex?: () => number;
  /**
   * @spec status-list#status-list — the shared lifecycle-commit hook. Fired once per
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
  /**
   * @spec mission#authority-sources, mission#approval-event — the deployment's
   * TRUSTED authority-source catalog. The approval event establishes
   * `authority_source` from this and from nothing else: never from
   * {@link ApproveInput}, a submission envelope, or any other client
   * assertion. OPTIONAL: absent, the deployment declares the single implicit
   * user-delegated source bounded by its own derivation ceiling
   * ({@link defaultAuthoritySourceEntry}), so the REQUIRED record member is
   * populated everywhere and the discriminator and ceiling rules still apply.
   */
  authoritySourceCatalog?: AuthoritySourceCatalog;
}

export class MissionKernel {
  readonly db: Database;
  /**
   * @spec issuance-grant#effective-set-projection (#617 review 3) — the durable
   * Mission-bound grant index. Its own store handle, deliberately NOT this
   * kernel's `db`: a `DELETE FROM missions` (or any future record pruning) must
   * not take the discriminator with it, or the token-plane hooks would read a
   * purged Mission-bound grant as an ordinary one and fail OPEN.
   */
  readonly missionBoundGrants: MissionBoundGrantStore;
  /**
   * @spec discharge#discharge-idempotency — the durable event-dedup store, on THIS
   * kernel's database so an event row commits in the same transaction as the
   * latch it records (@spec discharge#discharge-operation, "Atomicity").
   */
  readonly dischargeEvents: DischargeEventStore;
  /**
   * @spec discharge#discharge-authority — the pinned mapping per condition,
   * written in `insertRecord`'s transaction and the ONLY resolution discharge
   * target authorization reads (never the live policy).
   */
  readonly dischargePins: DischargeMappingPinStore;
  private readonly now: () => Date;
  private readonly allocateStatusIndex: () => number;

  constructor(private readonly opts: KernelOptions) {
    // @spec mission#authority-sources — the catalog's own invariants are
    // enforced HERE, not only over the shipped file: two declarations sharing a
    // source identity would make a drawdown's re-resolution ambiguous, and one
    // client declared twice would make establishment ambiguous. Both refuse
    // construction rather than letting a lookup silently pick a winner.
    if (opts.authoritySourceCatalog) validateAuthoritySourceCatalog(opts.authoritySourceCatalog);
    this.db = openStore(SCHEMA);
    this.missionBoundGrants = new MissionBoundGrantStore(opts.now ?? (() => new Date()));
    this.now = opts.now ?? (() => new Date());
    this.allocateStatusIndex = opts.allocateStatusIndex ?? (() => randomInt(STATUS_LIST_SIZE));
    this.dischargeEvents = new DischargeEventStore(this.db, {
      now: this.now,
      ...(opts.dischargeEventRetentionSeconds !== undefined
        ? { retentionSeconds: opts.dischargeEventRetentionSeconds }
        : {}),
    });
    this.dischargePins = new DischargeMappingPinStore(this.db);
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

  /**
   * @spec mission#intent-submission-evidence — STAGE-2 verification of a
   * parsed submission's evidence, per the processing order: the semantic
   * `intent` is already validated, so the PROVISIONAL `intent_hash` is
   * computed here and handed to each type's verifier together with this
   * issuer, the presenter the containing exchange established, and the
   * kernel clock. `required` is the policy-resolved anti-downgrade set (a
   * required type absent => refused). Returns the normalized verified facts
   * the Mission Record lands (undefined when no evidence was presented and
   * none is required). On idempotent operations the caller MUST run its
   * completed-operation recovery lookup BEFORE this.
   */
  async verifySubmissionEvidence(input: {
    intent: MissionIntent;
    evidence?: IntentSubmissionEvidenceEntry[];
    presenter: IntentSubmissionPresenter;
    required?: readonly string[];
    requestContext?: Record<string, unknown>;
  }): Promise<IntentSubmissionEvidenceFact[] | undefined> {
    return verifyIntentSubmissionEvidence(
      input.evidence,
      {
        intentHash: provisionalIntentHash(this.opts.issuer, input.intent),
        issuer: this.opts.issuer,
        presenter: input.presenter,
        now: this.now(),
        ...(input.requestContext ? { requestContext: input.requestContext } : {}),
      },
      input.required ?? [],
    );
  }

  derive(intent: MissionIntent, proposal?: readonly AuthorityEntry[]): AuthorityEntry[] {
    const derived = deriveAuthoritySet(intent, this.opts.policy, proposal);
    // @spec discharge#discharge-authority — resolve every `discharge_policy`
    // selector the derived entries carry, refusing the derivation when one maps
    // to nothing. Early and typed here (an IntentError the submission carriers
    // already map); `insertRecord` re-checks as the single record funnel, which
    // also covers child creation (a requested subset, never a fresh derivation).
    assertDischargePoliciesResolvable(derived, this.opts.dischargeAuthority);
    return derived;
  }

  /**
   * @spec mission#derivation-issuance-policy — resolve a requested
   * `requested_derivation_limit` against THIS deployment's own
   * `derivation_limit_ceiling`, for every Mission-creating surface (direct
   * approval, child creation, template dispatch, expansion): the immutable
   * effective `derivation_limit` a record commits is never the requested
   * value copied verbatim.
   */
  resolveDerivationLimit(requested: number | null | undefined): number | null {
    return resolveDerivationLimit(requested, this.opts.policy.derivation_limit_ceiling);
  }

  /** @spec mission#authority-proposal — intake of the submitted proposal. */
  validateProposal(raw: string, targetResources: string[]): AuthorityEntry[] {
    return validateAuthorityProposal(raw, targetResources);
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
   * @spec approval-governance#approval-context-manifest — the Approval Context
   * Manifest input for a Mission, taken FROM THE RECORD. `authority_source` is
   * a REQUIRED manifest input, so the manifest is computable only because the
   * record carries the member: nothing here supplies a stand-in.
   */
  approvalContextInput(record: MissionRecord): ApprovalContextManifestInput {
    const fresh = this.applyExpiry(record);
    return {
      issuer: fresh.issuer,
      id: fresh.id,
      intent_hash: fresh.intent_hash,
      ...(fresh.proposal_hash ? { proposal_hash: fresh.proposal_hash } : {}),
      authority_hash: fresh.authority_hash,
      subject: fresh.subject,
      approver: fresh.approver,
      client_id: fresh.client_id,
      created_at: fresh.created_at,
      expires_at: fresh.expires_at,
      approval_basis: fresh.approval_basis as never,
      authority_source: fresh.authority_source as never,
      policy_version: fresh.policy_version,
      approval_event_id: fresh.approval_event_id,
    };
  }

  /**
   * @spec mission#authority-sources — the trusted catalog and the deployment
   * ceiling, for the one surface that establishes a source OUTSIDE a Mission
   * Record: template consent ({@link createTemplate}). Exposed rather than
   * duplicated as an adapter option so a deployment has exactly one catalog.
   */
  authoritySourceOptions(): {
    authoritySourceCatalog?: AuthoritySourceCatalog;
    deploymentCeiling: AuthorityEntry[];
  } {
    return {
      ...(this.opts.authoritySourceCatalog
        ? { authoritySourceCatalog: this.opts.authoritySourceCatalog }
        : {}),
      deploymentCeiling: this.opts.policy.ceiling as AuthorityEntry[],
    };
  }

  /**
   * @spec mission#approval-event (step 3), mission#authority-sources — GATE 1:
   * resolve the trusted authority-source declaration for an Agent. The catalog
   * is deployment configuration; nothing a client sends reaches it.
   */
  authoritySourceEntry(clientId: string): AuthoritySourceCatalogEntry {
    return resolveSourceForClient(
      this.opts.authoritySourceCatalog,
      clientId,
      this.opts.policy.ceiling,
    );
  }

  /**
   * @spec mission#approval-event (step 3) — ESTABLISH the authority source for
   * a FRESH approval event (direct approval and Expansion). Runs gates 1, 2, 4
   * and 5; gate 3 is {@link assertAuthorityWithinSource}, kept separate so
   * activation authority is never read as possession. Every refusal is
   * `access_denied`, raised BEFORE any integrity anchor is computed and before
   * the record is created.
   */
  establishAuthoritySource(input: {
    clientId: string;
    subject: { iss: string; sub: string };
    approver: { iss: string; sub: string };
  }): AuthoritySource {
    const entry = this.authoritySourceEntry(input.clientId);
    const source = authoritySourceOf(entry);
    assertApproverMayActivate(entry, input.approver);
    assertSubjectDiscipline(this.opts.authoritySourceCatalog, entry, input.subject);
    assertPolicyDigestMatches(entry, source);
    return source;
  }

  /**
   * @spec mission#approval-event (step 3) — GATE 3: the derived Authority Set
   * lies wholly within the source's own authority. An assertion that refuses,
   * never a derivation input: intersecting the source ceiling into
   * `deriveAuthoritySet` would silently narrow where the core says the AS MUST
   * refuse.
   */
  assertAuthorityWithinSource(clientId: string, authoritySet: readonly AuthorityEntry[]): void {
    assertWithinSourceCeiling(this.authoritySourceEntry(clientId), authoritySet);
  }

  /**
   * @spec mission#authority-sources, mission#mission-record — the DRAWDOWN
   * path (template dispatch, child creation): the successor INHERITS the
   * source identity verbatim, and only the ceiling assertion re-runs against
   * catalog state current at the moment authority is drawn. A source narrowed
   * since the predecessor was approved therefore refuses `access_denied`
   * without ever rewriting provenance.
   */
  /**
   * @spec mission#authority-sources — GATE 4 against an ALREADY-ESTABLISHED
   * source. A drawdown inherits the source but binds a fresh Subject (a
   * template instance acts for its own Subject), so the subject discipline is
   * re-run at that surface while the source identity is not.
   */
  assertSubjectDisciplineForSource(
    source: AuthoritySource,
    subject: { iss: string; sub: string },
  ): void {
    assertSubjectDiscipline(
      this.opts.authoritySourceCatalog,
      resolveDeclaredSource(this.opts.authoritySourceCatalog, source, this.opts.policy.ceiling),
      subject,
    );
  }

  assertInheritedAuthoritySource(
    inherited: AuthoritySource,
    authoritySet: readonly AuthorityEntry[],
  ): void {
    const entry = resolveDeclaredSource(
      this.opts.authoritySourceCatalog,
      inherited,
      this.opts.policy.ceiling,
    );
    assertWithinSourceCeiling(entry, authoritySet);
  }

  /**
   * @spec mission#integrity-anchors, mission-substrate#approved-context: the
   * approval event creates the record with both anchors (and, where a
   * proposal was submitted, the third); approval_event_id is the idempotency
   * key.
   */
  approve(input: ApproveInput): MissionRecord {
    // @spec mission#authority-proposal — normalize: an empty proposal is no
    // proposal (matches the wire, where an empty authorization_details array
    // is treated as absent). Present iff submitted: template-mode Missions
    // carry neither `proposed_authority` nor `proposal_hash`.
    const proposal = input.proposedAuthority?.length ? input.proposedAuthority : undefined;
    const authoritySet = this.derive(input.intent, proposal);
    // @spec mission#approval-event (step 3) — establish the authority source
    // BEFORE any anchor is computed and before the record exists: gates 1, 2,
    // 4 and 5 here, then gate 3 (the source ceiling) as its own assertion.
    // `ApproveInput` carries no source member by design; establishment is
    // kernel-side from injected trusted configuration, which is what "never
    // from client assertion" requires.
    const authoritySource = this.establishAuthoritySource({
      clientId: input.clientId,
      subject: input.subject,
      approver: input.approver,
    });
    this.assertAuthorityWithinSource(input.clientId, authoritySet);
    // @spec mission#mission-identifier: opaque URL-safe, >=128 bits entropy,
    // drawn from the single mission-id.ts minting helper.
    const id = newMissionId();
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
      // @spec mission#authority-sources: whose authority this approval draws
      // on, established above from trusted configuration and immutable.
      authority_source: authoritySource,
      // @spec mission-substrate#actor-binding: the Actor handle, bound to
      // the Mission Context at approval.
      client_id: input.clientId,
      policy_version: this.opts.policy.policy_version,
      approval_event_id: input.approvalEventId,
      created_at: this.now().toISOString(),
      expires_at: input.intent.expires_at,
      version: 1,
      // @spec mission#derivation-issuance-policy — the immutable EFFECTIVE
      // ceiling: min(deployment policy, the client's requested_derivation_limit),
      // never the requested value copied verbatim.
      derivation_limit: resolveDerivationLimit(
        input.intent.requested_derivation_limit,
        this.opts.policy.derivation_limit_ceiling,
      ),
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

  /** Insert a full record (shared by approve, expansion, template dispatch, and
   *  child creation): the single Mission-record creation funnel. */
  insertRecord(record: MissionRecord): void {
    // @spec discharge#discharge-authority — the LAST point at which a
    // `terminal_when` condition can enter an immutable Mission-record entry: the
    // AS resolves and validates every selector here, whatever built the set
    // (derivation, a child's requested subset, a template's double
    // intersection), and refuses the creation when one maps to nothing.
    assertDischargePoliciesResolvable(record.authority_set, this.opts.dischargeAuthority);
    // @spec mission#approval-event (step 3), mission#authority-sources — the
    // single record-creation funnel re-asserts the source relationship for
    // EVERY creating body (direct approval, Expansion, template dispatch,
    // child creation): the declared source still agrees with the immutable
    // member the record carries, and the set being committed still lies within
    // that source's authority. A drawdown against a source narrowed since its
    // predecessor was approved refuses here.
    this.assertInheritedAuthoritySource(record.authority_source, record.authority_set);
    withTransaction(this.db, () => {
      this.db
        .prepare(
          `INSERT INTO missions (id, issuer, state, intent_json, proposed_authority_json,
           authority_set_json, intent_hash, proposal_hash,
           authority_hash, subject_iss, subject_sub, approver_iss, approver_sub,
           approval_basis_json, authority_source_json, client_id,
           policy_version, approval_event_id, created_at, expires_at, version, derivation_limit,
           derivation_count, grant_id, predecessor, parent_id, parent_json, template_id,
           template_json, projected_from, submission_evidence_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
          // @spec mission#authority-sources: established at the approval event
          // and immutable thereafter (the `approval_basis` treatment), so it is
          // written only here.
          JSON.stringify(record.authority_source),
          record.client_id,
          record.policy_version,
          record.approval_event_id,
          record.created_at,
          record.expires_at,
          record.version,
          record.derivation_limit,
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
      // @spec discharge#discharge-authority — bind the RESOLVED mapping
      // (identifier, version, and content) to this exact entry_digest +
      // condition_digest, in the SAME transaction as the record: discharge
      // target authorization reads this pin, never the live policy, so a
      // later policy edit cannot retroactively change who may discharge an
      // already-approved entry.
      for (const entry of record.authority_set) {
        const conditions = terminalWhenOf(entry);
        if (!conditions) continue;
        const eDigest = entryDigest(record.issuer, entry);
        for (const condition of conditions) {
          const mapping = resolveConditionMapping(this.opts.dischargeAuthority, condition);
          // Unreachable: assertDischargePoliciesResolvable above refused any
          // condition that maps to nothing. Guarded anyway so a future
          // reordering fails the creation, never creates an unpinned record.
          if (!mapping) {
            throw new Error(
              `no discharge-authority mapping resolvable for event_type '${condition.event_type}' at pin time`,
            );
          }
          this.dischargePins.pinInCallerTx(record.id, eDigest, conditionDigest(condition), mapping);
        }
      }
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
    let out: { predecessorId: string } | undefined;
    const superseded = withTransaction(this.db, () => {
      out = this.supersedeInCallerTx(successorId);
      return out !== undefined;
    });
    if (superseded && out) this.finalizeSupersession(out.predecessorId, successorId);
    return superseded;
  }

  /**
   * The supersession CAS alone, for a caller that already holds the
   * kernel-db transaction: expansion redemption commits successor creation,
   * idempotency completion, and predecessor supersession as ONE transaction
   * (@spec expansion#superseded-state), and the predecessor check is
   * expiry-aware (@spec mission#lifecycle, the effective-active rule), so an
   * effectively expired predecessor is never superseded and no successor
   * authority survives a predecessor that stopped being effectively active.
   * The caller MUST invoke {@link finalizeSupersession} after its
   * transaction commits (the lifecycle hook and cascade run post-commit).
   */
  supersedeInCallerTx(successorId: string): { predecessorId: string } | undefined {
    const successor = this.get(successorId);
    if (!successor?.predecessor) return undefined;
    const pred = this.get(successor.predecessor);
    // Read-only effective-active check (@spec mission#lifecycle): the caller
    // may be suppressing emission inside its transaction, so the expired
    // transition is never materialized here; lazy materialization stays with
    // the ordinary gates, and an effectively expired predecessor simply
    // refuses supersession.
    if (!pred || pred.state !== "active" || Date.parse(pred.expires_at) <= this.now().getTime()) {
      return undefined;
    }
    // This raw UPDATE bypasses setState (the only funnel that skips it); the
    // CAS on state='active' is the belt under the check above.
    const res = this.db
      .prepare("UPDATE missions SET state = 'superseded', successor = ?, version = version + 1 WHERE id = ? AND state = 'active'")
      .run(successorId, pred.id);
    return res.changes === 1 ? { predecessorId: pred.id } : undefined;
  }

  /** Post-commit half of redemption supersession: lifecycle hook + cascade. */
  finalizeSupersession(predecessorId: string, successorId: string): void {
    const fresh = this.get(predecessorId);
    if (fresh) this.emitCommit(fresh, "active", successorId);
      // @spec child-delegation#cascade — `superseded` is a TERMINAL cascade
      // trigger; the successor does NOT inherit the predecessor's children (their
      // strict-subset proof was against the predecessor's Authority Set). This
      // funnel bypasses setState, so the cascade is invoked explicitly here,
      // outside the withTransaction block above (cascadeChildren -> setState uses
      // a bare UPDATE, so there is no nested transaction).
    this.cascadeChildren(predecessorId);
  }

  /**
   * Round-4 (#639 review) recovery lookup: the committed successor created
   * for a predecessor under a specific approval event, if any. Used by
   * expansion redemption to recognize an operation whose activation
   * transaction committed but whose deferral was never marked redeemed, so
   * a committed operation is returned, never converted to access_denied.
   */
  successorByApprovalEvent(predecessorId: string, approvalEventId: string): MissionRecord | undefined {
    const row = this.db
      .prepare("SELECT * FROM missions WHERE predecessor = ? AND approval_event_id = ?")
      .get(predecessorId, approvalEventId) as Record<string, unknown> | undefined;
    return row ? rowToRecord(row) : undefined;
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

  /**
   * Bind a provider grant to a Mission. @spec
   * issuance-grant#effective-set-projection (#617 review 3) — ALSO records the
   * durable discriminator, so a later token-plane hook can tell "this grant was
   * never Mission-bound" (pass through) from "its Mission no longer resolves"
   * (fail closed), which the `missions.grant_id` column alone cannot do once the
   * row is gone.
   */
  bindGrant(missionId: string, grantId: string): void {
    this.db.prepare("UPDATE missions SET grant_id = ? WHERE id = ?").run(grantId, missionId);
    this.missionBoundGrants.record({ grantId, missionId, kind: "approval" });
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
   * @spec status-list#status-list — opt a Mission into the Status List by assigning
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
   * @spec status-list#status-list — the participating set as packed entries, expiry
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

  /** @spec status-list#status-list — sign the current Status List Token. */
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
   *
   * @spec signals#lifecycle-event — the commit's `authority_changed` is NOT
   * implied by reaching this metadata-only path: idempotency above is keyed
   * by `event.event_id`, not by effect, so a FRESH event whose `remove` is
   * already fully represented in the contained set still commits here
   * (`version`/`containment_version` still advance) with the effective set
   * UNCHANGED. `authority_changed` is computed from the effective set itself
   * (strict narrowing, not merely a new event row) and passed explicitly to
   * `emitCommit`.
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
    // @spec signals#lifecycle-event — authority_changed is true only when the
    // EFFECTIVE set actually narrowed on THIS commit. The assertion above
    // already proves newEffective <= priorEffective (monotonic); it equals
    // priorEffective (no real narrowing, e.g. a fresh event_id re-removing an
    // action another event already removed) exactly when priorEffective is
    // ALSO <= newEffective, i.e. the mutual-subset (equality) case.
    const authorityChanged = !isSubsetSet(priorEffective, newEffective);

    withTransaction(this.db, () => {
      this.db
        .prepare("UPDATE missions SET containment_json = ?, version = version + 1 WHERE id = ?")
        .run(JSON.stringify(next), record.id);
    });
    // Commit from the persisted row; prior == current state marks the commit
    // metadata-only (state unchanged, version incremented). authorityChanged
    // is passed explicitly (never inferred from prior === state).
    const fresh = this.get(record.id);
    if (!fresh) throw new Error(`unknown mission: ${id}`);
    this.emitCommit(fresh, fresh.state, undefined, authorityChanged, true);
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
   * @spec discharge#discharge-operation — the ENTRY DISCHARGE funnel: commit that a
   * `terminal_when` completion condition of one Mission-record entry has fired.
   * It changes NO Mission-level state (a deployment that also tracks all-entry
   * completion invokes `complete` separately) and produces one monotonic latch
   * on the entry's equivalence class, one version increment, one result record,
   * and one notification.
   *
   * VALIDATION ORDER IS NORMATIVE (@spec discharge#discharge-anti-oracle): selector
   * existence (`mission_id`, `entry_digest`, `condition_digest` all resolve, the
   * entry carries `terminal_when`, `event_type` matches the named condition),
   * then condition membership (the condition is looked up INSIDE the named
   * entry, so membership is the same lookup), then target authorization, and
   * only then is a terminal Mission distinguished. All six refusals raise {@link
   * DischargeNotFoundError}, which the endpoint collapses to one `not_found`, so
   * a terminal Mission is never a selector-existence oracle and an unauthorized
   * caller learns nothing about the selectors.
   *
   * The expiry clock runs FIRST (as `contain` does), so a Mission past its
   * `expires_at` reaches `terminal_noop` rather than latching.
   *
   * @spec discharge#discharge-operation ("No `expected_version`") — there is no
   * stale-version guard: a refusal would delay a safety-reducing operation. The
   * digest selectors and the idempotency rules are the guards instead.
   */
  discharge(id: string, input: DischargeRequest): { record: MissionRecord; result: DischargeResult } {
    const found = this.get(id);
    if (!found) throw new DischargeNotFoundError("unknown_mission", `unknown mission: ${id}`);
    const record = this.applyExpiry(found);
    // --- selector existence + condition membership ---
    // Every entry resolving to `entry_digest` is byte-identical (that is what
    // the digest means), so the first one carries the conditions of them all.
    const entry = record.authority_set.find(
      (e) => entryDigest(record.issuer, e) === input.entry_digest,
    );
    if (!entry) {
      throw new DischargeNotFoundError("unknown_entry", `no entry with digest ${input.entry_digest}`);
    }
    const conditions = terminalWhenOf(entry);
    if (!conditions) {
      throw new DischargeNotFoundError("no_terminal_when", "entry carries no terminal_when");
    }
    const condition = conditions.find((c) => conditionDigest(c) === input.condition_digest);
    if (!condition) {
      throw new DischargeNotFoundError(
        "unknown_condition",
        `entry has no condition with digest ${input.condition_digest}`,
      );
    }
    if (condition.event_type !== input.event_type) {
      throw new DischargeNotFoundError(
        "event_type_mismatch",
        "event_type does not match the condition condition_digest names",
      );
    }
    // --- target authorization (@spec discharge#discharge-authority) ---
    // Against the mapping PINNED when this condition entered the record
    // (identifier, version, and resolved content), never the live policy: an
    // edit to the policy after approval must not retroactively change who may
    // discharge an already-approved entry.
    const mapping = this.dischargePins.find(record.id, input.entry_digest, input.condition_digest);
    if (!mapping) {
      throw new DischargeNotFoundError(
        "unpinned_mapping",
        "no discharge-authority mapping was pinned for this condition at record creation",
      );
    }
    if (!mappingPermits(mapping, input.authority, input.event_type)) {
      throw new DischargeNotFoundError(
        "unauthorized_target",
        `${input.authority} is not a discharge authority for '${input.event_type}' on this condition`,
      );
    }
    const selectors = {
      entry_digest: input.entry_digest,
      condition_digest: input.condition_digest,
      event_id: input.event_id,
    };
    // --- event-level dedup (@spec discharge#discharge-idempotency) ---
    // Scoped by the five-part tuple and qualified by the assertion fingerprint.
    // Evaluated BEFORE the terminal check: an at-least-once sender's retry under
    // a fresh nonce must recover the ORIGINAL outcome and versions even after
    // the Mission has since gone terminal. `nonce` is the endpoint's own retry
    // key and is deliberately outside the fingerprint, so it never reaches here.
    const eventKey: DischargeEventKey = {
      authority: input.authority,
      missionId: record.id,
      entryDigest: input.entry_digest,
      conditionDigest: input.condition_digest,
      eventId: input.event_id,
    };
    const fingerprint = dischargeAssertionFingerprint({
      mission_id: record.id,
      entry_digest: input.entry_digest,
      condition_digest: input.condition_digest,
      event_type: input.event_type,
      event_id: input.event_id,
      ...(input.evidence_ref !== undefined ? { evidence_ref: input.evidence_ref } : {}),
      ...(input.evidence_digest !== undefined ? { evidence_digest: input.evidence_digest } : {}),
      ...(input.observed_at !== undefined ? { observed_at: input.observed_at } : {}),
    });
    const recorded = this.dischargeEvents.find(eventKey);
    if (recorded) {
      if (recorded.fingerprint !== fingerprint) {
        throw new DischargeConflictError(
          `event_id ${input.event_id} was already asserted against this target with a different assertion`,
        );
      }
      // No state-changing work: no re-latch, no version increment. The caller
      // signs a FRESH envelope echoing the new nonce and carrying this stored
      // outcome with the versions the original commit produced.
      return {
        record,
        result: {
          ...selectors,
          outcome: recorded.outcome,
          prior_version: recorded.priorVersion,
          current_version: recorded.currentVersion,
        },
      };
    }
    const audit = {
      receivedAt: this.now().toISOString(),
      ...(input.evidence_ref !== undefined ? { evidenceRef: input.evidence_ref } : {}),
      ...(input.evidence_digest !== undefined ? { evidenceDigest: input.evidence_digest } : {}),
      ...(input.observed_at !== undefined ? { observedAt: input.observed_at } : {}),
    };
    // --- terminal states: acknowledged, never a transition ---
    if (TERMINAL_STATES.has(record.state)) {
      const result: DischargeResult = {
        ...selectors,
        outcome: "terminal_noop",
        prior_version: record.version,
        current_version: record.version,
      };
      // Recorded like `already_discharged` below (@spec
      // discharge#discharge-idempotency): a fresh-nonce replay of THIS occurrence
      // must recover this stored outcome and these versions, and the same
      // tuple re-asserted with a DIFFERENT fingerprint must be `conflict` —
      // neither holds if the terminal acknowledgement bypasses the event
      // store.
      this.dischargeEvents.recordStandalone(eventKey, fingerprint, result, audit);
      return { record, result };
    }
    // --- the monotonic latch: `active` OR `suspended` (a suspended Mission
    // still narrows monotonically). A later delivery presenting any valid
    // condition against an already-latched entry, a sibling condition or the
    // same condition under a different event_id, is acknowledged
    // already_discharged and never re-latches or re-increments.
    if (record.discharged?.some((d) => d.entry_digest === input.entry_digest)) {
      const result: DischargeResult = {
        ...selectors,
        outcome: "already_discharged",
        prior_version: record.version,
        current_version: record.version,
      };
      // Recorded even though it commits no latch: a later replay of THIS
      // occurrence must report the versions this delivery saw, not whatever the
      // Mission's version has since become through unrelated transitions.
      this.dischargeEvents.recordStandalone(eventKey, fingerprint, result, audit);
      return { record, result };
    }
    let result!: DischargeResult;
    const fresh = this.latchDischarge(
      record,
      [
        {
          entry_digest: input.entry_digest,
          condition_digest: input.condition_digest,
          event_type: input.event_type,
          event_id: input.event_id,
        },
      ],
      (committed) => {
        result = {
          ...selectors,
          outcome: "discharged",
          prior_version: record.version,
          current_version: committed.version,
        };
        // In the SAME transaction as the latch and the version increment
        // (@spec discharge#discharge-operation, "Atomicity").
        this.dischargeEvents.recordInCallerTx(eventKey, fingerprint, result, audit);
      },
    );
    return { record: fresh, result };
  }

  /**
   * @spec discharge#discharge-operation ("Atomicity"), discharge#determining — commit
   * one or more entry latches on ONE record as a single unit: the latch rows,
   * the version increment, and the durable propagation work (the lifecycle
   * commit the Status List republisher and Mission Signals ride) share one
   * transaction, so no subscriber can observe an enqueue without the latch. The
   * commit is metadata-only (`prior_state` EQUALS `state`, `version`
   * incremented), the same shape `contain` produces.
   *
   * @spec signals#lifecycle-event — `authority_changed` is computed HERE from
   * the effective set before/after and passed explicitly, never inferred from
   * the metadata-only shape: an entry already fully contained contributes
   * nothing to the effective set, so latching it narrows nothing and the
   * discriminator stays absent.
   *
   * Several latches commit together when one propagated narrowing covers more
   * than one of a child's entries: one transition, one version increment, one
   * notification, mirroring the equivalence-class rule for duplicate entries.
   */
  private latchDischarge(
    record: MissionRecord,
    latches: ReadonlyArray<Omit<DischargedEntry, "discharged_at">>,
    /**
     * Runs INSIDE the commit transaction, after the persisted row is read and
     * before the lifecycle fan-out: how the event-dedup row (and any future
     * result record) joins this one unit.
     */
    accompany?: (committed: MissionRecord) => void,
  ): MissionRecord {
    const nowIso = this.now().toISOString();
    const next: DischargedEntry[] = [
      ...(record.discharged ?? []),
      ...latches.map((l) => ({ ...l, discharged_at: nowIso })),
    ];
    // Belt-and-suspenders (the `contain` idiom): the latch is structurally
    // removal-only, but assert the effective set really only narrowed.
    const priorEffective = this.effectiveAuthoritySet(record);
    const newEffective = this.effectiveAuthoritySet({ ...record, discharged: next });
    if (!isSubsetSet(newEffective, priorEffective)) {
      throw new Error(
        `discharge for ${record.id} would widen the effective set (monotonicity violated)`,
      );
    }
    const authorityChanged = !isSubsetSet(priorEffective, newEffective);
    const fresh = withTransaction(this.db, () => {
      this.db
        .prepare("UPDATE missions SET discharged_json = ?, version = version + 1 WHERE id = ?")
        .run(JSON.stringify(next), record.id);
      const committed = this.get(record.id);
      if (!committed) throw new Error(`unknown mission: ${record.id}`);
      accompany?.(committed);
      // Inside the unit deliberately: the signal enqueue commits with the latch
      // (@spec discharge#discharge-operation, "Atomicity"). Nothing after the
      // fan-out can fail the transaction, so the hook cannot fire on a rollback.
      this.emitCommit(committed, committed.state, undefined, authorityChanged);
      return committed;
    });
    // @spec discharge#discharge-operation ("Atomicity") — entry-wise propagation to
    // an already-justified Child Mission. Materialization is not claimed atomic
    // with the commit above; running it synchronously here closes the gap
    // entirely, so no child derivation can fall between the two.
    for (const latch of latches) {
      this.propagateDischargeToChildren(fresh, latch);
    }
    return fresh;
  }

  /**
   * @spec discharge#discharge-operation ("Atomicity"), child-delegation#child-state
   * — propagate a committed discharge entry-wise to the parent's existing
   * children, so a Child Mission already justified by the discharged parent
   * entry cannot keep deriving it while both Missions stay `active`.
   *
   * The MATCHING RULE is exact rather than resource-keyed (the containment
   * precedent's rule, which had no finer key available): a child entry is
   * justified by the discharged parent entry when it shares the resource AND
   * carries the very condition that fired, identified by `condition_digest`. The
   * subset rule guarantees the child carries every parent condition unchanged
   * (@spec discharge#subset-extension), so the condition is present exactly on the
   * child entries the parent entry justified. A child's latch is keyed by the
   * CHILD's own `entry_digest`: the child entry is narrower, so it is a
   * different immutable entry with a different commitment.
   *
   * A terminal child cannot derive and is skipped (the {@link cascadeChildren}
   * gate). Recursion rides {@link latchDischarge} itself, so a grandchild
   * justified transitively picks up the same narrowing in generation order; the
   * per-record latch is idempotent by `entry_digest`, so a replay at any level
   * is safe. The parent's and the children's lifecycle states are never touched:
   * discharge only ever narrows effective authority.
   */
  private propagateDischargeToChildren(
    parent: MissionRecord,
    latch: Omit<DischargedEntry, "discharged_at">,
  ): void {
    const parentEntry = parent.authority_set.find(
      (e) => entryDigest(parent.issuer, e) === latch.entry_digest,
    );
    if (!parentEntry) return;
    for (const child of this.findChildren(parent.id)) {
      const fresh = this.applyExpiry(child);
      if (TERMINAL_STATES.has(fresh.state)) continue;
      const already = new Set((fresh.discharged ?? []).map((d) => d.entry_digest));
      const seen = new Set<string>();
      const latches: Array<Omit<DischargedEntry, "discharged_at">> = [];
      for (const childEntry of fresh.authority_set) {
        if (childEntry.resource !== parentEntry.resource) continue;
        const conditions = terminalWhenOf(childEntry);
        if (!conditions?.some((c) => conditionDigest(c) === latch.condition_digest)) continue;
        const digest = entryDigest(fresh.issuer, childEntry);
        if (already.has(digest) || seen.has(digest)) continue;
        seen.add(digest);
        latches.push({
          entry_digest: digest,
          condition_digest: latch.condition_digest,
          event_type: latch.event_type,
          event_id: latch.event_id,
        });
      }
      if (latches.length > 0) this.latchDischarge(fresh, latches);
    }
  }

  /**
   * @spec discharge#visibility, runtime#input-authority — the committed discharge
   * latches as entry commitments, for a consumer that materializes a policy view
   * from this AS (a PDP's `discharged` input). Empty when nothing is discharged.
   */
  dischargedEntryDigests(record: MissionRecord): string[] {
    return (record.discharged ?? []).map((d) => d.entry_digest);
  }

  /**
   * The Mission's EFFECTIVE Authority Set: the approved set minus the issuer-held
   * narrowing overlays, which are TWO (#569: this method is the single
   * composition point every derivation, projection, and Status surface draws on):
   *  - DISCHARGE (@spec discharge#discharge, discharge#visibility): an entry whose
   *    `entry_digest` carries a committed latch is dropped outright. The digest
   *    is computed over the APPROVED entry, before any containment rewrite, both
   *    because `entry_digest` is defined over the immutable Mission-record entry
   *    and because a partially-contained entry's narrowed `actions` would digest
   *    to something else. This is also what makes the latch an equivalence-class
   *    latch: every byte-identical entry shares the digest and vanishes together.
   *  - CONTAINMENT: an entry whose actions are all contained (or whose resource
   *    is contained with no `actions` member) is dropped; otherwise the contained
   *    actions are filtered out.
   * FAST PATH: a Mission with NEITHER overlay returns the approved set as-is
   * (byte-identical behavior). `authority_hash` always commits the approved set;
   * both overlays are evaluated state, never a new hash.
   */
  effectiveAuthoritySet(record: MissionRecord): AuthorityEntry[] {
    const containment = record.containment;
    const discharged = record.discharged;
    if (!containment && !discharged?.length) return record.authority_set;
    const dischargedDigests = new Set((discharged ?? []).map((d) => d.entry_digest));
    const out: AuthorityEntry[] = [];
    for (const entry of record.authority_set) {
      if (dischargedDigests.size > 0 && dischargedDigests.has(entryDigest(record.issuer, entry))) {
        continue; // discharged -> no longer derivable, and omitted from every report
      }
      if (!containment) {
        out.push(entry);
        continue;
      }
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
   * @spec mission#lifecycle, child-delegation#child-state, mission-substrate#basic-gate: the shared active
   * gate for BOTH {@link gateDerivation} and {@link gateActive}: apply the expiry
   * clock, require the Mission itself `active`, and walk `parent` upward refusing
   * if ANY ancestor is non-active. Returns the expiry-fresh record. It does NOT
   * touch `derivation_count` nor the `derivation_limit` cap; consuming a derivation
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
   * bounded by expires_at and derivation_limit. Increments the derivation
   * count on success.
   */
  gateDerivation(id: string): MissionRecord {
    const record = this.gateActiveLineage(id);
    // Effective Authority Set gate (#589): token derivation draws on the
    // EFFECTIVE set, so a Mission with nothing left in its current effective
    // set has nothing left to derive. Never gated on `record.containment`
    // presence: effectiveAuthoritySet already yields the approved set unchanged
    // when nothing narrows it, and the mechanism that emptied it need not be
    // containment for the gate to apply.
    //
    // @spec issuance-grant#effective-set-projection (#617 review 2) — refuse BY
    // CAUSE. Recompute the effective set with the containment overlay REMOVED:
    // if that is empty too, containment is not what removed the authority
    // (`authority_exhausted`); only a non-empty no-overlay set collapsing under
    // the overlay is `authority_contained`, which is the condition Containment's
    // `authority_contained` denial reason may be attributed to. Today
    // containment is the only overlay effectiveAuthoritySet composes, so the
    // exhausted branch means an empty approved set; the branch is structural for
    // the next mechanism (discharge), which will not live in `containment`.
    if (this.effectiveAuthoritySet(record).length === 0) {
      const { containment: _overlay, ...withoutOverlay } = record;
      if (this.effectiveAuthoritySet(withoutOverlay).length === 0) {
        throw new GateError("authority_exhausted", `mission ${id} has no effective authority to derive`);
      }
      throw new GateError("authority_contained", `mission ${id} effective authority is fully contained`);
    }
    if (record.derivation_limit !== null && record.derivation_count >= record.derivation_limit) {
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
   * WITHOUT consuming a derivation: no `derivation_limit` cap check and no
   * `derivation_count` increment. For an async-delegation continuation path that
   * requires the Mission (and its lineage) live but is not itself a derivation.
   * Throws {@link GateError} on refusal, with the same reasons as gateDerivation.
   */
  gateActive(id: string): MissionRecord {
    return this.gateActiveLineage(id);
  }

  /**
   * @spec mission#the-mission-claim (#702) — the baseline claim is exactly
   * `{id, issuer}`. `authority_hash`, `expires_at`, and `approval_basis` are
   * NOT added here: a companion profile that needs one of them adds it as
   * its own extension member at its own call site (see
   * {@link childMissionClaim} and the attenuation/cross-domain/cross-org/
   * issuance-grant profiles), and introspection discloses `authority_hash`/
   * `approval_basis` separately under the caller's disclosure privilege
   * ({@link introspectionProjection}), never by widening this method.
   */
  missionClaim(record: MissionRecord): MissionClaim {
    return {
      id: record.id,
      issuer: record.issuer,
    };
  }

  /**
   * @spec mission#introspection — the FULL, ungated mission introspection
   * projection: every issuer-held fact, with no caller-scoped disclosure
   * privilege applied. Unlike {@link introspectionProjection} (the real,
   * caller-gated adapter surface), this is the issuer's own unrestricted
   * view and is used internally (e.g. by tests asserting record-level
   * state); it explicitly carries `authority_hash` and `approval_basis`
   * (#702 moved them off the baseline {@link missionClaim}) since an
   * ungated issuer view has no reason to withhold them.
   */
  introspectionMission(record: MissionRecord): Record<string, unknown> {
    const fresh = this.applyExpiry(record);
    return {
      ...this.missionClaim(fresh),
      authority_hash: fresh.authority_hash,
      approval_basis: { type: fresh.approval_basis.type },
      // @spec mission#authority-sources — an ungated issuer view withholds
      // nothing: the source rides beside `approval_basis`.
      authority_source: fresh.authority_source,
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
   * @spec mission#introspection + mission#caller-authorization-and-minimization
   * — the core Mission projection for an AUTHENTICATED, authorized
   * introspection caller: the claim set plus `state` and `version`;
   * `derivations_remaining` when `derivation_limit` is in force
   * (committed issuances counted); `containment_version` whenever containment
   * applies. Issuer-only audit members are authority to assert, not
   * authorization to disclose: `proposal_hash` requires the caller's
   * `provenance` privilege and the Status List reference its `status_list`
   * privilege.
   *
   * Deliberately carries NO `authorization_details`: {@link
   * MissionKernel.effectiveAuthoritySet} is the Mission's FULL effective
   * authority, never the presented credential's OWN (possibly narrower)
   * authority, so folding it in here would let a narrowed/attenuated token
   * introspect as though it held the Mission's entire authority (the P1-1
   * fix, issue #541). The top-level RFC 9396 `authorization_details` member
   * is the adapter's job: intersect the credential's own authority with
   * {@link MissionKernel.effectiveAuthoritySet} (see
   * kernel/derive.ts#projectThroughEffective) and audience-minimize that
   * result, never this method's return value.
   */
  introspectionProjection(
    record: MissionRecord,
    caller: { disclose: ReadonlySet<string> },
  ): Record<string, unknown> {
    const fresh = this.applyExpiry(record);
    return {
      ...this.missionClaim(fresh),
      state: fresh.state,
      version: fresh.version,
      ...(caller.disclose.has("budget") && fresh.derivation_limit !== null
        ? { derivations_remaining: Math.max(0, fresh.derivation_limit - fresh.derivation_count) }
        : {}),
      ...(caller.disclose.has("provenance") && fresh.proposal_hash
        ? { proposal_hash: fresh.proposal_hash }
        : {}),
      // @spec mission#caller-authorization-and-minimization (#702) —
      // `authority_hash` and `approval_basis` moved off the baseline claim;
      // introspection discloses them to a caller holding the deployment's
      // audit-and-correlation disclosure privilege, reusing the same
      // "provenance" grant `proposal_hash` above already gates on.
      ...(caller.disclose.has("provenance")
        ? {
            authority_hash: fresh.authority_hash,
            approval_basis: { type: fresh.approval_basis.type },
            // @spec mission#authority-sources, mission#introspection — the
            // source rides the SAME audit-and-correlation privilege
            // `approval_basis.type` already gates on: `type` always, plus the
            // governed policy's `id` and `version` for `organizational`. The
            // policy `digest` stays off introspection and belongs to record
            // access.
            authority_source: {
              type: fresh.authority_source.type,
              ...(fresh.authority_source.policy
                ? {
                    policy: {
                      id: fresh.authority_source.policy.id,
                      version: fresh.authority_source.policy.version,
                    },
                  }
                : {}),
            },
          }
        : {}),
      ...(fresh.containment
        ? { containment_version: fresh.containment.containment_version }
        : {}),
      ...(caller.disclose.has("status_list") ? this.statusListRef(fresh) : {}),
    };
  }

  /**
   * @spec status-list#status-list — the referenced-token status object (`idx`,
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
    opts: {
      audience?: string;
      requester: string;
      nonce?: string;
      freshnessSeconds?: number;
      /**
       * @spec discharge#discharge-result — the `discharge_result` object a
       * `discharge` delivery's response carries as a SIBLING of `mission` in
       * this same envelope. Absent on every other request, so the Status
       * response shape is unchanged for them.
       */
      dischargeResult?: DischargeResult;
    },
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
        // @spec mission-status#mission-status-response (#702) — OPTIONAL,
        // disclosed at the AS's discretion (issuance profile's introspection
        // disclosure footing); this reference AS discloses it on every
        // Status response.
        authority_hash: record.authority_hash,
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
    if (opts.dischargeResult) payload.discharge_result = opts.dischargeResult;
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
   * @spec status-list#status-list — fan the committed transition out to the
   * lifecycle-commit subscriber (no-op when none is wired). `record` MUST be the
   * post-commit persisted row so `state`/`version` are authoritative.
   *
   * @spec containment#propagation — also carries `record.containment`'s
   * current `containment_version` (absent-means-none), so a `contain` commit
   * (metadata-only: `prior_state` equals `state`) still surfaces the
   * narrowing to a subscriber comparing only `state`.
   *
   * @spec signals#lifecycle-event — `authorityChanged` is an EXPLICIT
   * argument, never inferred: the caller alone knows whether THIS commit
   * actually narrowed effective authority, and must compute that (typically
   * by comparing the effective set before/after) before calling. A
   * metadata-only commit (`prior === record.state`) does NOT by itself imply
   * a narrowing (`contain()`'s fresh-event_id/already-represented-removal
   * case is metadata-only yet narrows nothing). Defaults to `false`, so every
   * funnel that never narrows (`insertRecord`'s activating commit, `setState`,
   * `supersedeOnRedemption`) simply omits the argument. `contain` is today
   * the only caller that ever passes `true`, and only after proving the
   * effective set strictly narrowed. Rides the wire absent-means-false,
   * mirroring `containment_version`'s absent-means-none convention.
   */
  /**
   * Round-4 (#639 review): while a caller-owned activation transaction is
   * open, direct emission is suppressed; the transaction instead writes a
   * durable outbox job, and {@link drainExpansionOutbox} emits from
   * persisted rows after the commit (at-least-once; consumers dedupe on the
   * event tuple). A rolled-back transaction therefore never leaks an event
   * for state that does not exist.
   */
  private emitSuppressed = false;

  suppressEmits<T>(fn: () => T): T {
    const prior = this.emitSuppressed;
    this.emitSuppressed = true;
    try {
      return fn();
    } finally {
      this.emitSuppressed = prior;
    }
  }

  /**
   * Enqueue the expansion finalization job inside the caller's transaction.
   * The IMMUTABLE commit payloads are built and persisted here, at the
   * transaction's own time and with stable event identities, so every later
   * drain redelivers the SAME events with the ORIGINAL `committed_at`,
   * never newly asserted ones (round 5, #640 review). Call order matters:
   * the caller runs the supersession CAS first, so the predecessor row read
   * here already carries its superseded state and incremented version.
   */
  enqueueExpansionFinalize(predecessorId: string, successorId: string): void {
    const successor = this.mustGet(successorId);
    const pred = this.mustGet(predecessorId);
    const committedAt = this.now().toISOString();
    const activation: LifecycleCommit = {
      id: successor.id,
      issuer: successor.issuer,
      state: successor.state,
      version: successor.version,
      committed_at: committedAt,
      expires_at: successor.expires_at,
      event_id: `set_${randomBytes(15).toString("base64url")}`,
    };
    const supersession: LifecycleCommit = {
      id: pred.id,
      issuer: pred.issuer,
      prior_state: "active",
      state: pred.state,
      version: pred.version,
      committed_at: committedAt,
      expires_at: pred.expires_at,
      successor: successorId,
      event_id: `set_${randomBytes(15).toString("base64url")}`,
    };
    this.db
      .prepare(
        "INSERT INTO lifecycle_outbox (kind, mission_id, successor_id, activation_json, supersession_json) VALUES ('expansion-finalize', ?, ?, ?, ?)",
      )
      .run(predecessorId, successorId, JSON.stringify(activation), JSON.stringify(supersession));
  }

  /**
   * Drain committed-but-unfinalized expansion work. SCOPE (round 5, #640
   * review): this is durable LOCAL finalization, not event-plane
   * durability. Each replay delivers the PERSISTED, immutable commit
   * payloads (same `event_id`, same `committed_at`) to the lifecycle hook,
   * at-least-once, and re-runs the state-guarded mandatory child cascade;
   * jobs are marked done only after both. Durability PAST the hook is the
   * signal plane's (#641, built): @mission/signals journals one durable job
   * per (event, consumer) in the commit hook, redelivers byte-identical
   * SETs under a bounded backoff, and runs a recurring dispatcher with
   * lease-based claiming. THIS outbox's own recurring drive and
   * multi-process claiming stay scoped to the file-backed kernel store,
   * which KernelOptions does not plumb yet (D27 :memory: baseline).
   * Drains run at startup (buildAuthorizationServer) and on every
   * redemption or recovery poll.
   */
  drainExpansionOutbox(): void {
    const jobs = this.db
      .prepare(
        "SELECT job_id, mission_id, successor_id, activation_json, supersession_json FROM lifecycle_outbox WHERE done = 0 AND kind = 'expansion-finalize' ORDER BY job_id",
      )
      .all() as Array<{
      job_id: number;
      mission_id: string;
      successor_id: string;
      activation_json: string;
      supersession_json: string;
    }>;
    for (const job of jobs) {
      const onCommit = this.opts.onLifecycleCommit;
      if (onCommit) {
        onCommit(JSON.parse(job.activation_json) as LifecycleCommit);
        onCommit(JSON.parse(job.supersession_json) as LifecycleCommit);
      }
      this.cascadeChildren(job.mission_id);
      this.db.prepare("UPDATE lifecycle_outbox SET done = 1 WHERE job_id = ?").run(job.job_id);
    }
  }

  private emitCommit(
    record: MissionRecord,
    prior?: MissionState,
    successor?: string,
    authorityChanged = false,
    containmentAdvanced = false,
  ): void {
    if (this.emitSuppressed) return;
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
      ...(authorityChanged ? { authority_changed: true } : {}),
      // @spec signals#discharge-compatibility — provenance, set ONLY by the
      // one funnel that advances containment_version (`contain`); the Signals
      // gate must never have to reconstruct this from version history.
      ...(containmentAdvanced ? { containment_advanced: true } : {}),
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
    // @spec mission#mission-record, mission#lifecycle — fail closed on
    // hydration: a stored row carrying an unrecognized `authority_source.type`
    // is refused, never widened into the union.
    authority_source: parseAuthoritySource(
      JSON.parse(row.authority_source_json as string),
      `mission ${String(row.id)}`,
    ),
    client_id: row.client_id as string,
    policy_version: row.policy_version as string,
    approval_event_id: row.approval_event_id as string,
    created_at: row.created_at as string,
    expires_at: row.expires_at as string,
    version: row.version as number,
    derivation_limit: (row.derivation_limit as number | null) ?? null,
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
    // @spec discharge#discharge — absent means nothing was ever discharged;
    // written only by the discharge funnel (`latchDischarge`).
    ...(row.discharged_json
      ? { discharged: JSON.parse(row.discharged_json as string) as DischargedEntry[] }
      : {}),
  };
}
