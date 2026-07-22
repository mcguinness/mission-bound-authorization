/**
 * @spec mission#authorization-derivation
 * @spec mission#subset
 * Mechanical derivation of the Authority Set from the Intent under the
 * derivation policy ceiling. The Intent is untrusted: nothing it proposes
 * can widen past the ceiling (the compromised-shaper property).
 */

import { IntentError } from "./intent.js";
import type { AuthorityEntry, MissionIntent } from "./types.js";

export interface DerivationPolicy {
  policy_version: string;
  ceiling: readonly AuthorityEntry[];
}

export function deriveAuthoritySet(intent: MissionIntent, policy: DerivationPolicy): AuthorityEntry[] {
  const proposals = intent.proposed_authority?.length
    ? intent.proposed_authority
    : // Template mode: no concrete proposal derives the full policy ceiling
      // narrowed to the Intent's resources.
      policy.ceiling.filter((c) => intent.resources.includes(c.resource));

  const derived: AuthorityEntry[] = [];
  for (const proposal of proposals) {
    const ceiling = policy.ceiling.find((c) => c.resource === proposal.resource);
    if (!ceiling) continue;
    const entry = intersect(proposal, ceiling);
    if (entry) derived.push(entry);
  }
  if (derived.length === 0) {
    // @spec mission#submission-via-par: derivation failure is distinct from syntax.
    throw new IntentError("invalid_authorization_details", "Intent yields no valid Authority Set");
  }
  return derived;
}

/** Narrow proposal by ceiling; the result is a subset of both. */
function intersect(proposal: AuthorityEntry, ceiling: AuthorityEntry): AuthorityEntry | null {
  const actions = proposal.actions.filter((a) => ceiling.actions.includes(a));
  if (actions.length === 0) return null;
  const entry: AuthorityEntry = { type: "mission_resource_access", resource: ceiling.resource, actions };
  const constraints: NonNullable<AuthorityEntry["constraints"]> = {};
  const ceilCap = ceiling.constraints?.max_amount;
  const propCap = proposal.constraints?.max_amount;
  const cap = minAmount(propCap, ceilCap);
  if (cap) constraints.max_amount = cap;
  const ceilVendors = ceiling.constraints?.vendors;
  const propVendors = proposal.constraints?.vendors;
  const vendors = ceilVendors
    ? propVendors
      ? propVendors.filter((v) => ceilVendors.includes(v))
      : [...ceilVendors]
    : propVendors;
  if (vendors) {
    if (vendors.length === 0) return null;
    constraints.vendors = vendors;
  }
  if (Object.keys(constraints).length > 0) entry.constraints = constraints;
  return entry;
}

function minAmount(
  a: { amount: string; currency: string } | undefined,
  b: { amount: string; currency: string } | undefined,
): { amount: string; currency: string } | undefined {
  if (!a) return b;
  if (!b) return a;
  if (a.currency !== b.currency) return b; // ceiling wins on currency mismatch
  return Number.parseFloat(a.amount) <= Number.parseFloat(b.amount) ? a : b;
}

/** @spec mission#subset — entry-wise subset test (resource byte-exact). */
export function isSubsetEntry(candidate: AuthorityEntry, granted: AuthorityEntry): boolean {
  if (candidate.type !== granted.type) return false;
  if (candidate.resource !== granted.resource) return false;
  if (!candidate.actions.every((a) => granted.actions.includes(a))) return false;
  const gCap = granted.constraints?.max_amount;
  const cCap = candidate.constraints?.max_amount;
  if (gCap) {
    if (!cCap) return false;
    if (cCap.currency !== gCap.currency) return false;
    if (Number.parseFloat(cCap.amount) > Number.parseFloat(gCap.amount)) return false;
  }
  const gVendors = granted.constraints?.vendors;
  const cVendors = candidate.constraints?.vendors;
  if (gVendors) {
    if (!cVendors) return false;
    if (!cVendors.every((v) => gVendors.includes(v))) return false;
  }
  return true;
}

export function isSubsetSet(candidate: AuthorityEntry[], granted: AuthorityEntry[]): boolean {
  return candidate.every((c) => granted.some((g) => isSubsetEntry(c, g)));
}
