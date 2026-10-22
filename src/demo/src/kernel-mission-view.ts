/**
 * The PDP's view of one Mission, read from the kernel's committed record: the
 * one projection both the shared demo stack and the MAS pilot load Missions
 * through, so neither drops a committed overlay the other carries (#818 review
 * P1: the pilot's own copy omitted containment, and an action a containment
 * removed was still permitted).
 */

import type { MissionKernel } from "@mission/authorization-server";
import { deriveJoinDelegation, type MissionView } from "@mission/pdp";

/** The committed view of `missionId`, with expiry applied, or `undefined` when the kernel holds no such Mission. */
export function kernelMissionView(kernel: MissionKernel, missionId: string): MissionView | undefined {
  const r = kernel.get(missionId);
  if (!r) return undefined;
  const fresh = kernel.applyExpiry(r);
  // @spec discharge#runtime, discharge#visibility (#1144, D335): the committed
  // discharge DELTA beside the committed set, so the PDP refuses a discharged
  // entry at the point of use (`authority_discharged`, step 5b) and reads a
  // credential's discharge condition through its source entries (step 5c).
  // The PDP cannot detect a missing delta, so this loader supplies it.
  const dischargedDigests = kernel.dischargedEntryDigests(fresh);
  return {
    id: fresh.id,
    issuer: fresh.issuer,
    state: fresh.state,
    version: fresh.version,
    authority_hash: fresh.authority_hash,
    // @spec authority-server#mission-join rule 5 (#557 review point 2):
    // this is the canonical Mission loader, so it is where a kernel
    // AuthorityEntry's own `delegation` policy gets mapped to the PDP's
    // `join_delegation` member via the shared deterministic adapter,
    // rather than that member existing only in hand-built test fixtures.
    authority_set: fresh.authority_set.map((e) => ({
      ...e,
      ...(e.delegation !== undefined ? { join_delegation: deriveJoinDelegation(e.delegation) } : {}),
    })),
    subject: fresh.subject,
    client_id: fresh.client_id,
    // The containment DELTA (not a filtered set), so the PDP distinguishes
    // never-approved (out_of_authority) from approved-then-contained
    // (authority_contained). @spec containment#selector-matching (#1463): the
    // PDP pairs a delta member with the approved entry it relies on by that
    // entry's `resource`, so the delta is the overlay resolved onto the
    // approved entries: a `prefix` selector, or a fine selector over a broad
    // entry, reaches the PDP exactly as it reaches the effective set.
    ...(fresh.containment
      ? {
          containment: {
            version: fresh.containment.containment_version,
            contained: kernel.containedEntryRemovals(fresh),
          },
        }
      : {}),
    ...(dischargedDigests.length > 0 ? { discharged: { entry_digests: dischargedDigests } } : {}),
  };
}
