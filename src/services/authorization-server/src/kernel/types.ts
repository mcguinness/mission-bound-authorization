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
}

/** @spec mission#the-mission-claim — the token projection of the record. */
export interface MissionClaim {
  id: string;
  issuer: string;
  authority_hash: string;
  expires_at: number;
}
