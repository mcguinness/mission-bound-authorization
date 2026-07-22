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

export interface AuthorityEntry {
  type: "mission_resource_access";
  resource: string;
  actions: string[];
  constraints?: { max_amount?: { amount: string; currency: string }; vendors?: string[] };
}

/** The subset of the Mission Record the PDP evaluates against. */
export interface MissionView {
  id: string;
  issuer: string;
  state: string;
  version: number;
  authority_hash: string;
  authority_set: AuthorityEntry[];
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
