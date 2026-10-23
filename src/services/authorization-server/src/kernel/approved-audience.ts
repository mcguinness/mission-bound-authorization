/**
 * @spec mission#transformation-capabilities, mission#token-response,
 * mission#error-mapping (#1503 finding 7, D620)
 *
 * The original approved audience. "The AS relates each entry to the audiences
 * that consume it through a trusted entry-to-audience mapping ... An entry's
 * original approved audience is the audience or audiences that mapping
 * assigned the entry when the Mission was approved. ... The AS MUST retain
 * that association with the Mission; a later change to the mapping does not
 * redefine it." Without `narrowing`, "a token request that would issue an
 * entry to another audience is refused with `invalid_target`".
 *
 * This reference's trusted mapping is the scope-projection mapping's
 * audiences (the only audiences it issues Mission-bound tokens for), related
 * to an entry by the shared matcher ({@link entryOverlapsResource}): an
 * audience serves an entry when their resource trees overlap. An entry's
 * `resource` is never taken as its audience. The record-creation funnel
 * retains each entry's audiences with the Mission
 * (`MissionRecord.approved_audiences`), and issuance reads that retained list,
 * never the mapping current at issuance.
 *
 * The reference declares no `narrowing` capability for any type
 * (src/docs/resource-access-transformation-capabilities.md), so the refusal
 * applies to every entry. An entry the token's audience does not serve still
 * rides in the token, as before; the check covers every audience that serves
 * a carried entry.
 */

import {
  entryOverlapsResource,
  isSubsetSetIgnoringCapabilitySources,
  type ScopeProjectionMapping,
} from "@mission/core";
import type { AuthorityEntry, MissionRecord } from "./types.js";

/**
 * The audiences the trusted mapping assigns `entry`: every audience the
 * mapping names whose resource tree overlaps the entry's. Read once, when the
 * record is created.
 */
export function mappedAudiences(mapping: ScopeProjectionMapping | undefined, entry: AuthorityEntry): string[] {
  return Object.keys(mapping?.audiences ?? {}).filter((aud) => entryOverlapsResource(entry, aud));
}

/**
 * The refusal reason when a token for `audiences` would carry an entry to an
 * audience that is not an original approved audience of the approved entry
 * it derives from, or undefined. For each audience, every carried entry that
 * audience serves must be a subset of an approved entry whose retained
 * audiences include it. A record whose retained audiences are absent or not
 * aligned with its Authority Set approves no audience (fail closed).
 */
export function unapprovedAudienceRefusal(
  record: Pick<MissionRecord, "authority_set" | "approved_audiences">,
  audiences: readonly string[],
  carried: readonly unknown[],
): string | undefined {
  const retained = record.approved_audiences;
  const aligned = Array.isArray(retained) && retained.length === record.authority_set.length;
  for (const aud of new Set(audiences)) {
    const approvedFor = aligned
      ? record.authority_set.filter((_, i) => retained[i]?.includes(aud) === true)
      : [];
    for (const item of carried) {
      if (item === null || typeof item !== "object" || Array.isArray(item)) continue;
      const entry = item as AuthorityEntry;
      if (!entryOverlapsResource(entry, aud)) continue;
      if (!isSubsetSetIgnoringCapabilitySources([entry], approvedFor)) {
        return `audience ${aud} is not an original approved audience of the entry for ${String(entry.resource)}`;
      }
    }
  }
  return undefined;
}
