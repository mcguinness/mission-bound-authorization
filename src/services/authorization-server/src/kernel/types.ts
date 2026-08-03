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

/** @spec mission#authorization-derivation (type mission_resource_access) */
export interface AuthorityEntry {
  type: "mission_resource_access";
  resource: string;
  actions: string[];
  constraints?: {
    max_amount?: { amount: string; currency: string };
    vendors?: string[];
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
