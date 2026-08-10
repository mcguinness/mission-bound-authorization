import type { JsonValue } from "@mission/core";

/** @spec mission#mission-intent */
export interface MissionIntent {
  goal: string;
  resources: string[];
  expires_at: string;
  constraints?: string[];
  proposed_authority?: AuthorityEntry[];
  success_criteria?: string[];
  purpose?: string;
  controls?: { acr?: string; max_derivations?: number; [k: string]: JsonValue | undefined };
}

/**
 * @spec attenuation#root-mapping, child-delegation#fanout — a delegate matcher:
 * the actor (or actor class) a delegation right may be conferred on. Matched by
 * `sub` (exact) or `sub_profile` (class membership). Shared shape between the
 * core's `allowed_delegates` and the child-delegation companion's
 * `allowed_child_actors`.
 */
export interface DelegateMatcher {
  sub?: string;
  sub_profile?: string;
}

/**
 * @spec child-delegation#fanout — the fan-out controls carried in a delegable
 * Authority Set entry's `delegation.children` object. This strongly-types the
 * companion object WITHOUT re-typing the `delegation` member itself: `delegation`
 * keeps its open `JsonValue`-shaped index (below) so the generic carry/narrow in
 * `derive.ts` is untouched; child-delegation.ts reads `children` through a small
 * local reader that casts to this type. Expressed as an intersection (mirroring
 * `delegation`) so the named members keep precise types under the open index.
 * `max_child_depth` is a positive integer defaulting to 1 when absent.
 */
export type ChildFanoutControls = {
  /** Max concurrently non-terminal Child Missions drawing on this entry, per parent. */
  max_children?: number;
  /** Max child-generation depth at which this entry may be included (default 1). */
  max_child_depth?: number;
  /** Which actors / actor classes may receive a Child Mission from this entry. */
  allowed_child_actors?: DelegateMatcher[];
  /**
   * @spec child-delegation#fanout — a policy reference evaluated before each
   * child creation. When carried, it is the `root_commitment` of a
   * policy-adjudicated child's {@link ApprovalBasis} (see
   * `ApprovalBasisPolicyDrawdown`).
   */
  child_creation_policy?: string;
} & {
  [k: string]: JsonValue | undefined;
};

/** @spec mission#authorization-derivation (type mission_resource_access) */
export interface AuthorityEntry {
  type: "mission_resource_access";
  resource: string;
  actions: string[];
  constraints?: {
    max_amount?: { amount: string; currency: string };
    vendors?: string[];
  };
  /**
   * @spec attenuation#delegation, child-delegation#fanout — per-entry delegation
   * policy (the S-15 core extension). A GRANT, not a restriction: an entry with
   * no `delegation` is non-delegable, and derivation NEVER lets an untrusted
   * proposal introduce it (the compromised-shaper property, see derive.ts). The
   * open index carries companion members (the child-delegation `children` object)
   * unchanged; a later profile narrows them strongly. `max_depth` bounds offline
   * attenuation-chain / delegation depth; `allowed_delegates` restricts who may
   * receive the right (a restriction, narrowed like `constraints.vendors`).
   */
  delegation?: {
    max_depth: number;
    allowed_delegates?: DelegateMatcher[];
  } & {
    // Open index so companion members (the child-delegation `children` object)
    // ride unchanged. Expressed as an intersection so the named members above
    // keep their precise types under `exactOptionalPropertyTypes`.
    [k: string]: JsonValue | undefined;
  };
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
}

/** @spec mission#mission-record */
export interface MissionRecord {
  id: string;
  issuer: string;
  state: MissionState;
  intent: MissionIntent;
  authority_set: AuthorityEntry[];
  intent_hash: string;
  authority_hash: string;
  subject: { iss: string; sub: string };
  approver: { iss: string; sub: string };
  /**
   * @spec mission#approval-basis — fixed at creation, immutable. `approver`
   * above IS `approval_basis.consent_principal`; see {@link ApprovalBasis}.
   */
  approval_basis: ApprovalBasis;
  client_id: string;
  policy_version: string;
  approval_event_id: string;
  created_at: string;
  expires_at: string;
  version: number;
  max_derivations: number | null;
  derivation_count: number;
  grant_id: string | null;
  /**
   * @spec status#status-list: the opaque Status List index, assigned only when
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
}

/**
 * @spec status#status-list — the shared lifecycle-commit event. The kernel
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
}

/** @spec mission#the-mission-claim — the token projection of the record. */
export interface MissionClaim {
  id: string;
  issuer: string;
  authority_hash: string;
  expires_at: number;
  /**
   * @spec mission#approval-basis — the read-only wire signal of the basis
   * type. MUST NOT be relied on to grant authority; the full
   * {@link ApprovalBasis} lives on the Mission Record only.
   */
  approval_basis: { type: ApprovalBasisType };
  /**
   * @spec mission#approved-client, mission#delegation (delegate model, P0-2) —
   * the Mission's originally-approved agent (`record.client_id`, immutable since
   * approval). Distinct from the token's top-level `client_id`, which names the
   * OAuth client requesting THIS token (the immediate client/delegate, per
   * RFC 8693 Section 4.3 / RFC 9068 Section 2.2) and MAY therefore differ from
   * `approved_client.client_id` once a delegate acts. `iss` is OPTIONAL and
   * included only when the approving issuer differs from the token's own `iss`;
   * every issuance path in this reference impl signs with `record.issuer`, so
   * `iss` is never populated here (omitted, not disambiguation-needed).
   */
  approved_client: { client_id: string; iss?: string };
}
