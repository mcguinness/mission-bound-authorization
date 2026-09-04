/**
 * @spec capability-binding#capability-source-binding
 * The validating server's side of the capability-source binding: attaching the
 * trusted catalog resolution to the derived Authority Set at approval, BEFORE
 * `authority_hash` is computed, so the recorded bindings are covered by that
 * commitment by construction.
 *
 * The resolution arrives as VERIFIED FACTS on `ApproveInput` (the
 * `submissionEvidence` treatment), never from the client's proposal: a
 * client-supplied digest is never authoritative, and `approve` stays
 * synchronous and pure.
 */

import {
  type CapabilitySourceBinding,
  CapabilityBindingError,
  canonicalize,
  capabilitySourceIdentity,
  normalizeCapabilitySources,
} from "@mission/core";
import { IntentError } from "./intent.js";
import type { AuthorityEntry } from "./types.js";

/**
 * One trusted-catalog resolution outcome for a single `(resource, action)`
 * pair of the derived Authority Set.
 *
 * The pair is addressed by RESOURCE plus ACTION, never by entry index: one
 * proposal element fans across every ceiling entry sharing its resource
 * (@spec mission#authorization-derivation), so a single resolution
 * legitimately attaches to several derived entries.
 *
 * A resolution present with NO `binding` is the resolver saying "this action
 * is catalog-sourced and I could not resolve it". That refuses the
 * derivation; it is never silently dropped, and it is the only way the
 * unresolvable case is distinguishable from a first-party action, which
 * produces no resolution at all.
 */
export interface CapabilitySourceResolution {
  /** The derived entry's `resource` this resolution applies to. */
  resource: string;
  /** The action within that resource identified as catalog-sourced. */
  action: string;
  /** The resolved binding, or absent when resolution failed. */
  binding?: CapabilitySourceBinding;
}

/**
 * The resolver seam. DECLARED, NOT WIRED: no production path calls it yet.
 * The implementation resolves an action against the deployment's CONFIGURED
 * TRUSTED catalogs only (`config/catalog.json`'s per-service `trusted` flag),
 * never a client-controlled `source_uri`, retrieves the catalog's exact
 * octets, extracts the per-capability definition
 * (@spec capability-binding#capability-extraction), and returns one resolution
 * per catalog-sourced action. Presentation at the PEP and comparison at the
 * PDP are separate changes.
 */
export interface CapabilitySourceResolver {
  resolve(entries: readonly AuthorityEntry[]): CapabilitySourceResolution[];
}

/**
 * Attach the resolution to the derived Authority Set, returning entries whose
 * catalog-sourced actions carry their bindings.
 *
 * Refuses (never drops) when:
 *   - a resolution carries no `binding` (catalog-sourced, unresolvable);
 *   - a resolution's `binding.action` disagrees with its own `action`;
 *   - a resolution names a `(resource, action)` no derived entry carries, so
 *     the resolution and the derived set disagree about what was approved;
 *   - a binding is malformed, carries an unrecognized digest algorithm prefix,
 *     or repeats an `(action, tool_id)` pair within one entry
 *     ({@link normalizeCapabilitySources}).
 *
 * Entries with no resolved binding are returned unchanged, with the member
 * ABSENT rather than an empty array: JCS commits an empty array, so attaching
 * one everywhere would move every existing `authority_hash`.
 */
export function attachCapabilitySources(
  authoritySet: AuthorityEntry[],
  resolutions?: readonly CapabilitySourceResolution[],
): AuthorityEntry[] {
  if (!resolutions?.length) return authoritySet;
  for (const r of resolutions) {
    if (!r.binding) {
      throw new IntentError(
        "invalid_authorization_details",
        `capability source for catalog-sourced action '${r.action}' on '${r.resource}' could not be resolved`,
      );
    }
    if (r.binding.action !== r.action) {
      throw new IntentError(
        "invalid_authorization_details",
        `capability source binding names action '${r.binding.action}' for resolution of action '${r.action}'`,
      );
    }
    if (!authoritySet.some((e) => e.resource === r.resource && e.actions.includes(r.action))) {
      throw new IntentError(
        "invalid_authorization_details",
        `capability source resolution names action '${r.action}' on '${r.resource}', which the derived Authority Set does not carry`,
      );
    }
  }
  return authoritySet.map((entry) => {
    const bindings = resolutions
      .filter((r) => r.resource === entry.resource && entry.actions.includes(r.action))
      .map((r) => r.binding as CapabilitySourceBinding);
    if (bindings.length === 0) return entry;
    try {
      return { ...entry, capability_sources: normalizeCapabilitySources(bindings) };
    } catch (e) {
      if (e instanceof CapabilityBindingError) {
        throw new IntentError("invalid_authorization_details", e.message);
      }
      throw e;
    }
  });
}

/**
 * @spec capability-binding#capability-source-binding — the DERIVED-PATH
 * inheritance step, the counterpart of {@link attachCapabilitySources} for
 * every Mission created from an EXISTING one: child creation, template
 * dispatch, and expansion.
 *
 * Derivation never reads `capability_sources` (neither from a proposal nor
 * from a ceiling entry, see `intersect` in derive.ts), so a derived entry
 * arrives here bare. This step carries the GRANTOR's recorded bindings onto
 * it: for every action the derived entry RETAINS, every binding the grantor
 * recorded for that action, verbatim. It is the derived-path expression of the
 * monotonic rule {@link isSubsetEntry} enforces, so a retained catalog-sourced
 * action is neither emitted unbound nor made undelegable.
 *
 * The grantor is the Parent Mission's effective set, the Mission Template's
 * ceiling, or the predecessor's approved Authority Set. The derived path never
 * invents a binding, never rewrites one, and never reads one from a proposal:
 * a binding originates only in the validating server's trusted catalog
 * resolution, at the approval that first recorded it.
 *
 * Bindings are carried VERBATIM rather than through
 * {@link normalizeCapabilitySources}: normalization rebuilds a binding member
 * by member, and a rebuilt binding is no longer byte-identical to the
 * grantor's, which is exactly what the subset rule compares. The uniqueness
 * invariant normalization would have enforced is asserted here instead, since
 * expansion has no subset gate behind it.
 *
 * An action the derivation DROPPED carries no binding: bindings are selected
 * by retained action, so dropping the action drops its bindings, and an entry
 * left with none keeps the member absent rather than empty.
 */
export function inheritCapabilitySources(
  derived: AuthorityEntry[],
  grantor: readonly AuthorityEntry[],
): AuthorityEntry[] {
  if (!grantor.some((g) => g.capability_sources?.length)) return derived;
  return derived.map((entry) => {
    const retained = new Set(entry.actions);
    // Every grantor entry with the SAME type and resource contributes, since
    // isSubsetEntry gates on both. Identical bindings recorded by two such
    // entries collapse; two entries recording DIFFERENT bindings for one
    // `(action, tool_id)` are a grantor-side contradiction, refused below
    // rather than resolved by committing an arbitrary one.
    const byIdentity = new Map<string, CapabilitySourceBinding>();
    for (const g of grantor) {
      if (g.type !== entry.type || g.resource !== entry.resource) continue;
      for (const binding of g.capability_sources ?? []) {
        if (!retained.has(binding.action)) continue;
        byIdentity.set(capabilitySourceIdentity(binding), binding);
      }
    }
    if (byIdentity.size === 0) return entry;
    // Reproducible order, by the same canonical-bytes discipline
    // normalizeCapabilitySources applies: array order is inside
    // `authority_hash`, so the inherited array must not depend on grantor
    // entry order.
    const inherited = [...byIdentity.entries()]
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([, binding]) => binding);
    const pairs = new Set<string>();
    for (const binding of inherited) {
      const pair = canonicalize({ action: binding.action, tool_id: binding.tool_id });
      if (pairs.has(pair)) {
        throw new IntentError(
          "invalid_authorization_details",
          `grantor records conflicting capability sources for action ${JSON.stringify(binding.action)} and tool_id ${JSON.stringify(binding.tool_id)}`,
        );
      }
      pairs.add(pair);
    }
    return { ...entry, capability_sources: inherited };
  });
}
