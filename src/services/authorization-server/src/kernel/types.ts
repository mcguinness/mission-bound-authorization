import type { AuthorityEntry, JsonValue } from "@mission/core";
export type { AuthorityEntry, DelegateMatcher, ChildFanoutControls, TerminalWhenCondition } from "@mission/core";

/**
 * @spec mission#mission-intent — pure TASK context. The Intent carries no
 * authority members: the client's concrete authority proposal rides the
 * standard top-level `authorization_details` request parameter pushed
 * alongside `mission_intent` (@spec mission#authority-proposal), and an
 * Intent carrying the retired `proposed_authority` member is refused as an
 * unknown top-level member under the closed-top-level rule
 * (@spec mission#submission-via-par).
 */
export interface MissionIntent {
  goal: string;
  /** @spec mission#mission-intent — OPTIONAL BCP 47 language tag for the
   *  Intent's human-readable prose; disclosure metadata, no authority
   *  semantics, committed by intent_hash like every member. */
  goal_lang?: string;
  /** @spec mission#mission-intent — client-requested Intent ceiling on
   *  target resources; NOT RFC 8707 `resource` carriage. */
  target_resources: string[];
  expires_at: string;
  /** @spec mission#mission-intent — human-readable, non-machine-readable
   *  task bounds (renamed from `constraints` so the name cannot collide
   *  with a Resource Access entry's enforced `constraints`). */
  task_bounds?: string[];
  success_criteria?: string[];
  purpose?: string;
  /** @spec mission#derivation-issuance-policy — client-requested ceiling on
   *  derivations; the AS-established effective ceiling is
   *  `MissionRecord.derivation_limit`, never copied verbatim. */
  requested_derivation_limit?: number;
}

/**
 * @spec mission#submission-via-par, mission#intent-submission-evidence — one
 * presented Intent Submission Evidence entry: a typed artifact submitted in
 * support of claims about the Intent (inbound, client-presented — distinct
 * from the family's EMITTED Evidence objects). The REQUIRED `type` owns the
 * entry's remaining members, closed schema, and verification procedure (the
 * RAR type-dispatch discipline); an unknown type or an entry failing its
 * type's validation is refused, never silently ignored. Evidence is
 * authenticated policy input, never authority: it is never copied into the
 * Authority Set and never substitutes for the approval event.
 */
export type IntentSubmissionEvidenceEntry = {
  type: string;
} & {
  [k: string]: JsonValue | undefined;
};

/**
 * @spec mission#submission-via-par — the Mission Intent Submission envelope:
 * the VALUE of the `mission_intent` parameter. Its own closed top level:
 * `intent` (the semantic Mission Intent, the exact object `intent_hash`
 * commits) and OPTIONAL `evidence` (Intent Submission Evidence entries,
 * outside the `intent_hash` commitment, so intent-bound evidence can name the
 * hash without self-reference). The retired bare-Intent parameter shape is
 * refused.
 */
export interface MissionIntentSubmission {
  intent: MissionIntent;
  /** Present iff a non-empty `evidence` array was submitted. */
  evidence?: IntentSubmissionEvidenceEntry[];
}

/**
 * @spec mission#intent-submission-evidence — one VERIFIED evidence fact as the
 * Mission Record lands it: the entry type, the digest of the presented
 * artifact, the verification time, and the type-defined verified output facts.
 * Recorded provenance metadata OUTSIDE every integrity anchor (the
 * `approval_basis` treatment): trusted via the Mission Issuer's immutable
 * record, not an independently verifiable association. Empty in this
 * implementation today — no evidence types are registered, so every presented
 * entry is refused before verification — but the record plumbing is real.
 */
export interface IntentSubmissionEvidenceFact {
  type: string;
  artifact_hash: string;
  verified_at: string;
  facts?: Record<string, JsonValue>;
}


/** @spec status#state-machine — only `active` permits derivation. */
export type MissionState =
  | "active"
  | "suspended"
  | "revoked"
  | "expired"
  | "completed"
  | "superseded"
  | "cascaded";

export type LifecycleOperation = "revoke" | "suspend" | "resume" | "complete";

/** @spec status#legal-transitions */
export const LEGAL_TRANSITIONS: Record<LifecycleOperation, { from: MissionState[]; to: MissionState }> = {
  revoke: { from: ["active", "suspended"], to: "revoked" },
  suspend: { from: ["active"], to: "suspended" },
  resume: { from: ["suspended"], to: "active" },
  complete: { from: ["active", "suspended"], to: "completed" },
};

export const TERMINAL_STATES: ReadonlySet<MissionState> = new Set([
  "revoked",
  "expired",
  "completed",
  "superseded",
  "cascaded",
]);

/**
 * @spec child-delegation#cascade — the cascade mode recorded on a Child
 * Mission. Only `immediate` is implemented (the profile's MUST-implement,
 * issuer-committed mode). The consumer-verified modes `bounded_staleness` and
 * `status_required` are experimental and deferred.
 */
export type CascadeMode = "immediate";

/**
 * @spec child-delegation#parent-member — the Parent Mission reference carried on
 * a Child Mission record (and in the `mission` claim of child-derived tokens).
 * Lineage and audit data only: it grants no authority. Immutable after creation.
 */
export interface ParentRef {
  /** The Parent Mission identifier. */
  id: string;
  /** The Parent Mission Issuer; the child's own `issuer` MUST equal this. */
  issuer: string;
  /** The parent authority commitment the child was derived under. */
  authority_hash: string;
  /** Child-generation depth: 1 for a child of a root Mission, +1 per generation. */
  depth: number;
  /** The cascade mode from @spec child-delegation#cascade. */
  cascade_mode: CascadeMode;
  /** Mission-Issuer-defined identifier for the child delegation event. */
  delegation_id?: string;
  /** Creation time of the Child Mission. */
  created_at?: string;
}

/**
 * @spec mission-template#template-lineage — the Mission Template reference
 * carried on an instance Mission dispatched from a template (and in the
 * `mission` claim of instance-derived tokens). Lineage and audit data only: it
 * grants no authority (the instance's Authority Set is the double intersection
 * of the derivation-policy ceiling AND the template ceiling). Defined here,
 * beside {@link ParentRef}, so {@link MissionRecord} can carry it with no import
 * cycle back into `template.ts`; re-exported from `template.ts` for the public
 * surface.
 */
export interface TemplateRef {
  /** The Mission Template identifier (`tmpl_`-prefixed). */
  id: string;
  /** The template Issuer; the instance's own `issuer` equals this. */
  issuer: string;
  /** The template version the instance was dispatched under. */
  template_version: string;
  /** The template integrity anchor (@spec mission-template) the instance commits to. */
  template_hash: string;
  /** The template's dispatch policy identifier (audit only). */
  dispatch_policy: string;
}

/**
 * @spec child-delegation#child-evidence — the Child Evidence record: audit
 * material recording one child-creation decision. It grants no authority. Its
 * canonical bytes are its JCS (RFC 8785) canonicalization; its media type is
 * `application/mission-child-evidence+json`. `decision` is `created` or `denied`
 * per §child-evidence-object (the field the task calls the permit/deny outcome).
 * `child_actor`, `attenuation.result`, and `denial_reason` are typed structurally
 * here so types.ts stays free of a back-import from child-delegation.ts.
 */
export interface ChildEvidence {
  evidence_id: string;
  parent: { id: string; issuer: string; authority_hash: string };
  child: { id: string; issuer: string; authority_hash: string };
  child_actor: { sub: string; iss?: string; sub_profile?: string };
  /** Subset checks and their result (e.g. `strict_subset`, `not_strict_subset`). */
  attenuation: { result: string };
  /** Fan-out counters, present when fan-out controls apply to the justifying entry. */
  fanout?: { active_children: number; max_children?: number };
  cascade_mode: CascadeMode;
  decision: "created" | "denied";
  /** Present (and REQUIRED) when `decision` is `denied`. */
  denial_reason?: string;
  created_at: string;
}

/**
 * Mission Containment: an issuer-held, versioned, MONOTONIC narrowing overlay
 * on an active Mission's effective authority. The approved `authority_set` and
 * `authority_hash` are immutable; containment is evaluated state layered on
 * top. Removal-only in v1 (entries/actions; no constraint deltas): each contain
 * transition UNIONS into `contained`, so the effective set only ever narrows.
 * Restore exists only via the Expansion successor path.
 */
export interface MissionContainment {
  /** Increments once per applied contain transition (1-based). */
  containment_version: number;
  /**
   * The contained capabilities, merged by resource. An entry with no `actions`
   * member contains the whole resource (its Authority Set entry is dropped from
   * the effective set); with `actions`, only those actions are contained.
   */
  contained: Array<{ resource: string; actions?: string[] }>;
  /** The applied containment events, in order. `event_id` is the idempotency key. */
  events: ContainmentEventRecord[];
}

/**
 * @spec discharge#discharge-operation, discharge#determining — one committed entry
 * DISCHARGE latch: the issuer-held record that a `terminal_when` condition of
 * the named entry fired, so the entry no longer derives
 * (@spec discharge#discharge). Keyed by `entry_digest`, the Authority Set entry
 * commitment over the IMMUTABLE Mission-record entry, which makes the latch an
 * EQUIVALENCE-CLASS latch: every recorded entry resolving to that digest is
 * discharged by this one row, in one transition with one version increment
 * (@spec discharge#discharge-operation, "Duplicate entries"). MONOTONIC: a latch
 * is never removed and never re-latched, so a later delivery is acknowledged
 * `already_discharged` (@spec discharge#discharge-result). `condition_digest` /
 * `event_type` / `event_id` record WHICH condition fired and the asserted
 * occurrence, for audit and event correlation; the evidence members and
 * caller-asserted `observed_at` are audit metadata held by the event store,
 * never authorization input.
 */
export interface DischargedEntry {
  entry_digest: string;
  condition_digest: string;
  event_type: string;
  event_id: string;
  /** The AS's own commit time (`received_at` in audit), never `observed_at`. */
  discharged_at: string;
}

/** One applied containment event: the triggering signal plus what it removed. */
export interface ContainmentEventRecord {
  type: string;
  source: string;
  observed_at: string;
  event_id: string;
  removed: Array<{ resource: string; actions?: string[] }>;
}

/**
 * @spec mission#approval-basis — convergence Finding #1: the reframed
 * invariant is "every Mission is rooted in an approved authorization basis,"
 * generalizing "every Mission is created by an explicit approval event."
 * `approval_basis` is a Mission Record member, fixed at creation and
 * immutable for the life of the Mission (like `approver`/`subject`, unlike
 * containment, which is evaluated state). It separates three previously
 * collapsed facts: `consent_principal` (who consented — identical to
 * {@link MissionRecord.approver}), `activation` (which policy/event activated
 * THIS instance), and `activation_actor` (who or what dispatched it). It is
 * provenance recorded ALONGSIDE `approver`, NOT folded into `intent_hash` or
 * `authority_hash` (the core keeps its two-anchor domain separation); `type`
 * MAY ride the `mission` claim as a read-only signal (see
 * {@link MissionClaim.approval_basis}) that MUST NOT be relied on to grant
 * authority.
 */
export type ApprovalBasis = ApprovalBasisDirect | ApprovalBasisTemplate | ApprovalBasisPolicyDrawdown;

export type ApprovalBasisType = ApprovalBasis["type"];

/**
 * @spec mission#authority-sources, mission#mission-record — the three sources
 * a Mission may draw its authority from: a delegating person's own authority,
 * a workload's own provisioned authority, or explicitly governed
 * organizational policy. Subject to the forward-compatibility rule of
 * mission#lifecycle, which admits no fail-open: an unrecognized value is
 * refused at config load and at record hydration, never widened into the
 * union.
 */
export type AuthoritySourceType = "user_delegated" | "service_owned" | "organizational";

/**
 * @spec mission#authority-sources, mission#mission-record — WHOSE authority the
 * approval draws on, established at the approval event from trusted
 * configuration or authenticated governance state (never from client
 * assertion) and immutable thereafter, like `approver` and `approval_basis`.
 *
 * Provenance, exactly like `approval_basis`: folded into NEITHER `intent_hash`
 * NOR `authority_hash`, and not carried on access tokens. Resource Servers
 * enforce `authorization_details` and do not consult it.
 */
export interface AuthoritySource {
  type: AuthoritySourceType;
  /**
   * REQUIRED for `organizational`, absent otherwise: the stable reference to,
   * and commitment over, the governed organizational policy the Mission draws
   * on.
   */
  policy?: { id: string; version: string; digest: string };
}

/**
 * @spec mission#approval-basis — the default and strongest basis: a human
 * approval event created this Mission directly. `approver`/`activation_actor`
 * are the SAME approving human; this is the pre-existing, unchanged behavior
 * of {@link MissionKernel.approve}, now named.
 */
export interface ApprovalBasisDirect {
  type: "direct";
  /** The approving human. Identical to {@link MissionRecord.approver}. */
  consent_principal: { iss: string; sub: string };
  activation: { approval_event_id: string };
  /** The Approver themselves: identical to `consent_principal` for `direct`. */
  activation_actor: { iss: string; sub: string };
  /** This Mission's own `authority_hash`. */
  root_commitment: string;
}

/**
 * @spec mission-template#template-lineage — a template instance's basis:
 * standing consent to a template ceiling, activated at dispatch time with no
 * per-instance human approval. `consent_principal` is the template's
 * consenting human (identical to `approver`, unchanged from prior "copy the
 * human into approver" behavior); `activation_actor` is the Dispatcher client
 * that triggered THIS instance.
 */
export interface ApprovalBasisTemplate {
  type: "template";
  /** The template's consenting human. Identical to {@link MissionRecord.approver}. */
  consent_principal: { iss: string; sub: string };
  activation: {
    template_id: string;
    template_version: string;
    template_hash: string;
    dispatch_event_id: string;
  };
  /** The Dispatcher client that triggered this instance. */
  activation_actor: { iss: string; sub: string };
  /** The template's integrity anchor (`template_hash`). */
  root_commitment: string;
  /**
   * @spec mission#mission-record (#580) — the human approval instant of the
   * exact consented root `root_commitment` commits: the instant this
   * template version was consented, read from the issuer's RETAINED
   * template record at dispatch, never from the dispatch request.
   */
  approved_at: string;
}

/**
 * @spec child-delegation#child-creation — a policy-adjudicated child's basis:
 * the parent's own approval, drawn down by a fan-out policy with no
 * per-child human interaction (today's only child-creation path).
 * `consent_principal` is the parent's accountable human (identical to
 * `approver`, inherited from the Parent Mission); `activation_actor` is the
 * parent agent / requesting principal that triggered this child.
 */
export interface ApprovalBasisPolicyDrawdown {
  type: "policy_drawdown";
  /** The parent's accountable human. Identical to {@link MissionRecord.approver}. */
  consent_principal: { iss: string; sub: string };
  activation: {
    /** The `child_creation_policy` reference, when the justifying entry carries one. */
    policy_id?: string;
    policy_version: string;
    activation_event_id: string;
  };
  /** The parent agent / requesting principal that triggered this child. */
  activation_actor: { iss: string; sub: string };
  /**
   * The drawdown policy's committed reference: the justifying entry's
   * `child_creation_policy` when carried, else the parent's `authority_hash`
   * (the integrity anchor of the consented root that grants the drawdown).
   */
  root_commitment: string;
  /**
   * @spec mission#mission-record (#580), child-delegation#child-creation —
   * the human approval instant of the exact consented root
   * `root_commitment` commits. Both root forms here were consented at the
   * PARENT's approval event (an entry-carried `child_creation_policy`
   * reference rides the committed entry the human approved), so this is the
   * parent record's own `created_at`, read from retained state, never from
   * the child-creation request.
   */
  approved_at: string;
}

/** @spec mission#mission-record */
export interface MissionRecord {
  id: string;
  issuer: string;
  state: MissionState;
  intent: MissionIntent;
  /**
   * @spec mission#mission-record — the `authorization_details` array the
   * client submitted as its authority proposal
   * (@spec mission#authority-proposal), recorded exactly as submitted.
   * Present iff a proposal was submitted; a Mission derived in template mode
   * records none.
   */
  proposed_authority?: AuthorityEntry[];
  authority_set: AuthorityEntry[];
  intent_hash: string;
  authority_hash: string;
  /**
   * @spec mission#mission-record — the integrity commitment over the recorded
   * `proposed_authority` (@spec mission#integrity-anchors, typ
   * `mission-proposed-authority`). Present iff `proposed_authority` is
   * present. Approval-time provenance, not enforcement input: like
   * `approval_basis`, it is surfaced on the record and through introspection
   * and is NOT carried on the `mission` token claim.
   */
  proposal_hash?: string;
  /**
   * @spec mission#intent-submission-evidence — the VERIFIED Intent Submission
   * Evidence facts recorded at approval (present iff any evidence verified).
   * Provenance metadata OUTSIDE all integrity anchors — never folded into
   * `intent_hash` or `authority_hash` — trusted via this immutable record (the
   * `approval_basis` treatment), and never carried on the `mission` token
   * claim. Always absent today: no evidence types are registered, so every
   * presented entry is refused at intake before verification.
   */
  submission_evidence?: IntentSubmissionEvidenceFact[];
  subject: { iss: string; sub: string };
  approver: { iss: string; sub: string };
  /**
   * @spec mission#approval-basis — fixed at creation, immutable. `approver`
   * above IS `approval_basis.consent_principal`; see {@link ApprovalBasis}.
   */
  approval_basis: ApprovalBasis;
  /**
   * @spec mission#authority-sources — REQUIRED. Whose authority the approval
   * draws on, established at the approval event and immutable thereafter. A
   * drawdown (template dispatch, child creation) INHERITS its predecessor's
   * value verbatim; only the source ceiling is re-asserted at the moment
   * authority is drawn.
   */
  authority_source: AuthoritySource;
  client_id: string;
  policy_version: string;
  approval_event_id: string;
  created_at: string;
  expires_at: string;
  version: number;
  /** @spec mission#derivation-issuance-policy — the AS-established EFFECTIVE
   *  ceiling: min(deployment policy, `intent.requested_derivation_limit`),
   *  immutable after creation. Null when the deployment's policy imposes no
   *  ceiling on this Mission. */
  derivation_limit: number | null;
  derivation_count: number;
  grant_id: string | null;
  /**
   * @spec status-list#status-list: the opaque Status List index, assigned only when
   * a Mission participates (opt-in). Random, never derivable from `id`
   * (@spec status#mission-status-anti-oracle). Null for non-participants.
   */
  status_list_idx: number | null;
  /** @spec expansion#predecessor-member: set on a successor Mission only. */
  predecessor?: string;
  /** @spec child-delegation#parent-member: set on a Child Mission only. */
  parent?: ParentRef;
  /**
   * @spec mission-template#template-lineage: set on an instance Mission
   * dispatched from a Mission Template. Immutable after creation (like
   * `parent`), written only by `insertRecord`. Absent on every other Mission,
   * so an ordinary Mission behaves identically (fast path).
   */
  template?: TemplateRef;
  /**
   * @spec child-delegation#child-state: a Child Mission's pre-suspension state,
   * recorded when a parent SUSPEND projects it to the reversible `suspended` hold
   * (always `active`, the only projectable source). Present ONLY while so held;
   * cleared on restore at parent resume. Absent on a Mission that was never
   * projected (e.g. one suspended independently), which is exactly why an
   * independently-suspended descendant is NOT restored on parent resume.
   */
  projected_from?: MissionState;
  /**
   * The containment overlay (see {@link MissionContainment}). Absent means no
   * containment has ever been applied: the effective authority IS the approved
   * `authority_set`, byte-identical behavior. Written only by `contain()`.
   */
  containment?: MissionContainment;
  /**
   * @spec discharge#discharge, discharge#determining — the committed entry-discharge
   * latches (see {@link DischargedEntry}), the SECOND issuer-held narrowing
   * overlay beside `containment` and, like it, evaluated state:
   * `authority_set`/`authority_hash` stay immutable. Absent means nothing has
   * ever been discharged (byte-identical behavior). Written only by
   * `discharge()`; MUST NOT revert.
   */
  discharged?: DischargedEntry[];
}

/**
 * @spec status-list#status-list — the shared lifecycle-commit event. The kernel
 * fires it from its four real commit funnels (`setState`,
 * `supersedeOnRedemption`, `insertRecord`, `contain`) so subscribers observe
 * every committed transition exactly once: the Status List republisher today,
 * Mission Signals next. The activating insert carries `version: 1` and no
 * `prior_state`. A contain commit is metadata-only: `prior_state` EQUALS
 * `state` (the version still increments), so the fan-out propagates the
 * narrowed authority with no new channels.
 */
export interface LifecycleCommit {
  id: string;
  issuer: string;
  prior_state?: MissionState;
  state: MissionState;
  version: number;
  committed_at: string;
  expires_at: string;
  successor?: string;
  /**
   * @spec signals#delivery — stable event identity for replayable emission:
   * set when the commit is delivered from the durable finalization outbox,
   * so a replay is a redelivery of the SAME event (the Signals SET reuses
   * it as `jti`, per the same-`jti` redelivery rule), never a newly
   * asserted one. Absent on ordinary direct commits.
   */
  event_id?: string;
  /**
   * @spec signals#lifecycle-event — the generic effective-authority-narrowing
   * discriminator: true when this commit narrowed effective authority; absent
   * (never `false`) otherwise, mirroring `containment_version`'s
   * absent-means-none convention. {@link MissionKernel}'s private
   * `emitCommit` takes this as an EXPLICIT argument (default `false`) rather
   * than inferring it from `prior_state === state`: that equality marks a
   * commit metadata-only, but a metadata-only commit does not always narrow
   * (`contain()`'s fresh-`event_id`/already-represented-removal case is
   * metadata-only yet narrows nothing). `contain` and the discharge funnel
   * (`latchDischarge`) are the two funnels that pass `true`, each only after
   * comparing the effective set before/after and proving a strict narrowing.
   * CONSTRAINT for any future metadata-only funnel: it too MUST compute and
   * pass its own value; there is no inference to rely on.
   */
  authority_changed?: boolean;
  /**
   * @spec signals#discharge-compatibility — event PROVENANCE discriminator:
   * true exactly when THIS commit advanced `containment_version` (it came
   * through `contain()`), absent otherwise. The Signals emitter's delivery
   * gate keys on it directly: a narrowing commit with `authority_changed`
   * and NO containment advance is a discharge commit, deliverable to a
   * consumer only under the declared `authority_changed` capability. Set by
   * the kernel at commit, never inferred from emitter-side version history,
   * which does not survive an emitter restart. Internal discriminator only:
   * the SET builder does not copy it to the wire.
   */
  containment_advanced?: boolean;
  /**
   * @spec containment#propagation — the Mission's current
   * {@link MissionContainment.containment_version}, present whenever
   * containment has ever been applied (absent-means-none, mirroring
   * `introspectionMission` and `signedStatus`). A contain commit is
   * metadata-only (`state` equals `prior_state`); carrying the containment
   * version here is what makes an active-to-active authorization change
   * legible to a subscriber that only compares `state`.
   */
  containment_version?: number;
}

/**
 * @spec mission#the-mission-claim (#702) — the baseline token projection of
 * the record is exactly `{id, issuer}`; they identify the Mission and carry
 * no authority of their own. `authority_hash`, `expires_at`, and
 * `approval_basis` are NOT part of the baseline claim — they are added only
 * by a companion profile that owns them as its own extension member (e.g.
 * child-delegation's `parent` ref, the attenuation/cross-domain/cross-org
 * lineage anchor, or issuance-grant), never inherited here. A caller that
 * needs the Mission's remaining lifetime reads the token's own `exp`, or
 * introspects for the record's `expires_at` under the profile that requires
 * it.
 */
export interface MissionClaim {
  id: string;
  issuer: string;
  /**
   * @spec mission#the-mission-claim (#702) — NOT carried on the baseline
   * claim. Present only where a companion profile adds it as its own
   * extension member (see the type doc above); do not set it here.
   */
  authority_hash?: string;
  /**
   * @spec mission#the-mission-claim (#702) — an RFC 3339 date-time STRING,
   * profile-scoped: NOT carried on the baseline claim. A profile that mints a
   * further credential downstream of this one, or that verifies remaining
   * lifetime from retained state rather than a live token, MUST require it
   * and MUST treat its absence as an error, never a silent downgrade.
   */
  expires_at?: string;
  /**
   * @spec mission#approval-basis — the read-only wire signal of the basis
   * type. MUST NOT be relied on to grant authority; the full
   * {@link ApprovalBasis} lives on the Mission Record only. NOT carried on
   * the baseline claim (#702); disclosed only via introspection under the
   * caller's disclosure privilege.
   */
  approval_basis?: { type: ApprovalBasisType };
}
