import type { JsonValue } from "./canonicalize.js";
import type { CapabilitySourceBinding } from "./capability-binding.js";

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

/**
 * @spec discharge#terminal-when — one entry completion condition carried in
 * `constraints.terminal_when`. `event_type` identifies the completion event
 * (deployment- or registry-defined, opaque here). `discharge_policy` is a
 * stable, opaque selector naming the AS-side discharge-authority mapping for
 * this condition (@spec discharge#discharge-authority): the AS resolves it
 * whenever the condition FIRST enters an immutable Mission-record entry and
 * refuses the derivation when it maps to nothing. Condition identity is byte
 * equality of the canonical form of THIS object, which is also what
 * `condition_digest` digests, so the member set is closed: an unrecognized
 * member would silently change identity.
 */
export interface TerminalWhenCondition {
  event_type: string;
  discharge_policy?: string;
}

/** @spec mission#authorization-derivation (type mission_resource_access) */
export interface AuthorityEntry {
  type: "mission_resource_access";
  resource: string;
  actions: string[];
  /**
   * @spec capability-binding#capability-source-binding — the capability-source
   * bindings the validating server recorded at derivation for this entry's
   * CATALOG-SOURCED actions. Part of the derived authority, so it is covered
   * by `authority_hash`: it is attached in `approve` before the anchor is
   * computed, and a proposal can never introduce or rewrite it (derive.ts
   * builds the derived entry member by member, so the member is dropped from
   * an untrusted proposal by construction).
   *
   * Applicability is PER ACTION, not per entry: a mixed entry is valid, where
   * catalog-sourced actions carry at least one binding and first-party actions
   * with stable identity carry none. One action MAY name several `tool_id`
   * values; `(action, tool_id)` is unique. Absent means no action of this
   * entry was resolved as catalog-sourced. Imported from `@mission/core`
   * rather than restated, so the kernel entry and the PDP's materialized entry
   * are one byte-identical type (this member rides inside `authority_hash`;
   * `join_delegation`, a PDP-local member, sits outside every commitment and
   * sets no precedent here).
   */
  capability_sources?: CapabilitySourceBinding[];
  constraints?: {
    max_amount?: { amount: string; currency: string };
    vendors?: string[];
    /**
     * @spec discharge#terminal-when — the OPTIONAL Common Constraint carrying one
     * or more entry completion conditions. When any condition is met the entry
     * is DISCHARGED and no longer derives (@spec discharge#discharge). MONOTONIC
     * under the subset rule: a derived entry carries every parent condition
     * unchanged and MAY add more (an added condition can only discharge
     * sooner), so dropping or altering one WIDENS and is refused
     * (@spec discharge#subset-extension). Fired status is evaluated state, never
     * part of this array and never part of `authority_hash`.
     */
    terminal_when?: TerminalWhenCondition[];
    /**
     * @spec txn-authorization#applicability — the Common Constraint that puts
     * this entry's operations under the Transaction Authorization profile: the
     * matched entry requires an action-bound approval. MONOTONIC under the
     * subset rule: `true` NARROWS (a delegated child may add it or keep it, and
     * may never drop it), and `false` is equivalent to omitting the member and
     * cannot override a `true` ancestor.
     */
    requires_action_approval?: boolean;
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
