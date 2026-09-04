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

import { type CapabilitySourceBinding, CapabilityBindingError, normalizeCapabilitySources } from "@mission/core";
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
