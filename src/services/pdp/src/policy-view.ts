/**
 * @spec authzen#materialization, decision D26
 *
 * The materialized policy view is derived per check from the Mission Record;
 * no mission tuples are stored (D26). policy_view_id is the content hash of
 * (Mission Record version + FGA model id).
 */

import { createHash } from "node:crypto";
import { canonicalize } from "@mission/core";
import type { TupleKey } from "@openfga/sdk";

/**
 * @spec runtime#input-authority — the one `authorization_details` type the
 * PDP understands. Recognition is a whitelist: `evaluate()` matches an
 * entry only when `entry.type` equals this literal, so an entry of any
 * other type (a deserialization change, a new type admitted upstream)
 * never matches by `resource`/`actions` alone and falls through to the
 * same fail-closed refusal as a never-approved entry.
 */
export const MISSION_RESOURCE_ACCESS_TYPE = "mission_resource_access" as const;

export interface AuthorityEntry {
  type: typeof MISSION_RESOURCE_ACCESS_TYPE;
  resource: string;
  actions: string[];
  constraints?: {
    max_amount?: { amount: string; currency: string };
    vendors?: string[];
    /**
     * @spec txn-authorization#applicability — the matched entry requires an
     * action-bound approval. The PDP reads it beside the deployment predicate.
     */
    requires_action_approval?: boolean;
  };
}

/** The subset of the Mission Record the PDP evaluates against. */
export interface MissionView {
  id: string;
  issuer: string;
  state: string;
  version: number;
  authority_hash: string;
  authority_set: AuthorityEntry[];
  /**
   * The containment DELTA (what was removed), not a filtered authority set:
   * carrying the delta lets the PDP distinguish never-approved
   * (`out_of_authority`) from approved-then-contained (`authority_contained`).
   * A contained entry with no `actions` covers ALL the entry's actions.
   * `policyViewId` needs no containment input: it already commits
   * `mission_version`, which every contain transition bumps.
   */
  containment?: { version: number; contained: Array<{ resource: string; actions?: string[] }> };
  /**
   * @spec status#visibility, status#runtime, runtime#input-authority — the
   * DISCHARGE delta: the Authority Set entry commitments the Mission Issuer has
   * discharged (`terminal_when` fired, so the entry no longer derives). Carried
   * as a delta for the same reason containment is: it lets the PDP tell
   * never-approved (`out_of_authority`) from approved-then-completed
   * (`authority_discharged`), rather than the entry simply vanishing from the
   * authority input. Absent means nothing is discharged. `policyViewId` needs no
   * discharge input: it already commits `mission_version`, which every discharge
   * commit increments.
   */
  discharged?: { entry_digests: string[] };
}

export function policyViewId(view: MissionView, modelId: string): string {
  const commitment = canonicalize({
    mission_id: view.id,
    mission_version: view.version,
    authority_hash: view.authority_hash,
    model_id: modelId,
  });
  return `sha-256:${createHash("sha256").update(commitment, "utf8").digest("base64url")}`;
}

/**
 * Derive per-check contextual tuples granting the mission the required
 * relation on the target object, when the target's vendor is within the
 * authority entry's vendor constraint. This is the D26 join: authority +
 * constraint -> ephemeral grant, never persisted.
 */
export function deriveContextualTuples(input: {
  view: MissionView;
  entry: AuthorityEntry;
  target: { objectType: "invoice" | "vendor"; objectId: string; vendorId: string };
  relation: "payer" | "reader";
}): TupleKey[] {
  const { view, entry, target, relation } = input;
  const vendors = entry.constraints?.vendors;
  if (vendors && !vendors.includes(target.vendorId)) return []; // constraint excludes it
  return [
    { user: `mission:${view.id}`, relation, object: `${target.objectType}:${target.objectId}` },
  ];
}
