/**
 * @spec authzen#materialization, decision D26
 *
 * The materialized policy view is derived per check from the Mission Record;
 * no mission tuples are stored (D26). policy_view_id is the content hash of
 * (Mission Record version + FGA model id).
 */

import { createHash } from "node:crypto";
import { canonicalize, type CapabilitySourceBinding, type JsonValue } from "@mission/core";
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
  /**
   * @spec capability-binding#capability-source-binding — the capability-source
   * bindings the validating server recorded at derivation, materialized into
   * the policy view exactly as the kernel committed them.
   *
   * The `join_delegation` precedent below does NOT apply: that member sits
   * outside every commitment, so a PDP-local equivalent is safe there. These
   * bindings ride INSIDE `authority_hash`, so the kernel entry and this entry
   * MUST be one byte-identical type; a PDP-local restatement could silently
   * perturb the commitment. Hence the shared `@mission/core` type.
   *
   * Recorded here, verified nowhere yet: decision-time comparison and the
   * `capability_drift` denial reason are a separate change.
   */
  capability_sources?: CapabilitySourceBinding[];
  constraints?: {
    max_amount?: { amount: string; currency: string };
    vendors?: string[];
    /**
     * @spec txn-authorization#applicability — the matched entry requires an
     * action-bound approval. The PDP reads it beside the deployment predicate.
     */
    requires_action_approval?: boolean;
  };
  /**
   * @spec authority-server#mission-join rule 5 (#557) — this entry's
   * baseline-Join delegate-narrowing rule, carried into the materialized
   * view so mas-join.ts can read it without a second Mission-Record lookup.
   * Absent means the entry is NOT delegable: rule 5 excludes it from a
   * delegate's narrowed set entirely.
   *
   * @spec observation.local — the spec cross-references "the issuance
   * profile's per-entry delegation rules" (the kernel's own
   * `AuthorityEntry.delegation`, `authorization-server/src/kernel/types.ts`,
   * matched by `DelegateMatcher {sub, sub_profile}`). This PDP package has
   * no dependency on that package, so this is a PDP-local equivalent
   * (`allowed_delegates` matched by bare `client_id` string, the identity
   * the baseline Join's rule 4 already authenticates), not a shared type.
   * Named distinctly (`join_delegation`, not `delegation`) so a MissionView
   * ever assembled by widening a kernel `AuthorityEntry` cannot silently
   * structurally satisfy or collide with this member.
   * Not a `policyViewId` input (below): entry-level fields already sit
   * outside that pinned commitment.
   */
  join_delegation?: { max_depth?: number; allowed_delegates?: string[] };
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
   * @spec authority-server#mission-join rules 3-4 — the Mission's authorized
   * party, joined against the presented credential's authenticated subject
   * and client identifier. Not a `policyViewId` input (below): the join
   * compares these against the credential outside the pinned commitment, so
   * adding them here does not perturb an existing pinned hash.
   */
  subject: { iss: string; sub: string };
  client_id: string;
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
   * @spec discharge#visibility, discharge#runtime, runtime#input-authority — the
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
 * @spec authority-server#mission-join (#557 review point 4) — a SEPARATE
 * commitment for a decision reached over a baseline-Join's resolved
 * (subject/client/delegate-narrowed) authority set, distinct from
 * `policyViewId`. `policyViewId` commits only `(mission_id, mission_version,
 * authority_hash, model_id)`: none of these change when the join's inputs
 * (the acting subject, the acting client, the delegate's narrowing) change,
 * or when the narrowed effective authority differs from the Mission's own
 * full authority_set -- so a Decision Evidence record carrying only
 * `policy_view_id` cannot distinguish a joined decision from a direct
 * Mission-bound one, nor one joined view from a differently-joined one
 * (e.g. two different delegates narrowed to two different subsets). This
 * commitment additionally binds the join disposition, the joining client,
 * and the resolved authority set itself, so it changes whenever any of
 * those does. Computed only on the baseline-Join path; `policyViewId` keeps
 * its existing meaning and is carried alongside this, never replaced by it.
 */
export function joinViewId(
  view: MissionView,
  modelId: string,
  joined: { disposition: "direct" | "delegate"; clientId: string; authoritySet: AuthorityEntry[] },
): string {
  const commitment = canonicalize({
    mission_id: view.id,
    mission_version: view.version,
    authority_hash: view.authority_hash,
    model_id: modelId,
    join_disposition: joined.disposition,
    join_client_id: joined.clientId,
    join_authority_set: joined.authoritySet as unknown as JsonValue,
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
