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
   * @spec child-delegation#child-state: a Child Mission's pre-suspension state,
   * recorded when a parent SUSPEND projects it to the reversible `suspended` hold
   * (always `active`, the only projectable source). Present ONLY while so held;
   * cleared on restore at parent resume. Absent on a Mission that was never
   * projected (e.g. one suspended independently), which is exactly why an
   * independently-suspended descendant is NOT restored on parent resume.
   */
  projected_from?: MissionState;
}

/**
 * @spec status#status-list — the shared lifecycle-commit event. The kernel
 * fires it from its three real commit funnels (`setState`,
 * `supersedeOnRedemption`, `insertRecord`) so subscribers observe every
 * committed transition exactly once: the Status List republisher today, Mission
 * Signals next. The activating insert carries `version: 1` and no `prior_state`.
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
}
