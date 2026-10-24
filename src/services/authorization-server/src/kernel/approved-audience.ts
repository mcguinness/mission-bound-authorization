/**
 * @spec mission#transformation-capabilities, mission#token-response,
 * mission#error-mapping (#1503 finding 7, D620, D733)
 *
 * The original approved audience. "The AS relates each entry to the audiences
 * that consume it through a trusted entry-to-audience mapping ... An entry's
 * original approved audience is the audience or audiences that mapping
 * assigned the entry when the Mission was approved. ... The AS MUST retain
 * that association with the Mission; a later change to the mapping does not
 * redefine it."
 *
 * This reference's trusted mapping is the scope-projection mapping's
 * audiences (the only audiences it issues Mission-bound tokens for), related
 * to an entry by the shared matcher ({@link entryOverlapsResource}): an
 * audience serves an entry when their resource trees overlap. An entry's
 * `resource` is never taken as its audience.
 *
 * Three uses, one relation ({@link derivedAudiences}):
 *
 * - An approval event assigns each entry it approves the audiences the
 *   mapping names for it then ({@link mappedAudiences}), and the record
 *   retains them (`MissionRecord.approved_audiences`).
 * - A record derived from earlier authority (a Child Mission, a template
 *   instance, a ceiling drawdown, a governed activation, a carryover
 *   replacement, an Expansion successor's retained entries) gives each entry
 *   the association of the authority it derives from, never the mapping
 *   current at its own creation (D733 ruling 2).
 * - A Mission-bound token for an audience carries only the entries whose
 *   original approved audience includes it ({@link audienceProjection},
 *   D733 ruling 1); nothing rides because its recipient would not enforce it.
 *
 * Where the association cannot be established (a record or consent stored
 * before it was retained, or one not aligned with its entries) no audience is
 * associated, so no token carries the entry (D733 ruling 4). Nothing re-reads
 * today's mapping in its place.
 */

import {
  type AuthorityEntry as CoreAuthorityEntry,
  entryOverlapsResource,
  isSubsetSetIgnoringCapabilitySources,
  type ScopeProjectionMapping,
} from "@mission/core";
import type { AuthorityEntry } from "./types.js";

/**
 * The audiences the trusted mapping assigns `entry` now: every audience the
 * mapping names whose resource tree overlaps the entry's. Read only at an
 * approval or consent event, never at issuance.
 */
export function mappedAudiences(mapping: ScopeProjectionMapping | undefined, entry: AuthorityEntry): string[] {
  return Object.keys(mapping?.audiences ?? {}).filter((aud) => entryOverlapsResource(entry, aud));
}

/**
 * An approved (or consented) entry with its retained original approved
 * audience: `undefined` where that association cannot be established.
 */
export interface AudienceReference {
  entry: AuthorityEntry;
  audiences: readonly string[] | undefined;
}

/**
 * The references an Authority Set or a consented ceiling provides, from its
 * retained, index-aligned audiences. A list that is absent or not aligned
 * with the entries establishes no association for any of them.
 */
export function audienceReferences(
  entries: readonly AuthorityEntry[],
  retained: readonly (readonly string[])[] | undefined,
): AudienceReference[] {
  const aligned = Array.isArray(retained) && retained.length === entries.length;
  return entries.map((entry, i) => ({
    entry,
    audiences: aligned && Array.isArray(retained[i]) ? retained[i] : undefined,
  }));
}

/** The authority an entry has, for tying it to the entry it derives from (bindings and contract references set aside). */
function authorityOf(entry: AuthorityEntry): CoreAuthorityEntry {
  const { capability_sources: _bindings, resource_contract: _contract, ...authority } = entry as AuthorityEntry & {
    resource_contract?: unknown;
  };
  return authority as CoreAuthorityEntry;
}

/** Whether `entry` falls within a reference entry (the subset rule, bindings set aside). */
function within(entry: AuthorityEntry, reference: AuthorityEntry): boolean {
  return isSubsetSetIgnoringCapabilitySources([authorityOf(entry)], [authorityOf(reference)]);
}

/** Whether `entry` falls within at least one of `references`. */
export function derivesFrom(entry: AuthorityEntry, references: readonly AudienceReference[]): boolean {
  return references.some((r) => within(entry, r.entry));
}

/**
 * The original approved audience of an entry derived from `references`: the
 * audiences retained by EVERY reference it falls within, so overlapping
 * references never lend it a wider association. An entry that falls within
 * no reference, or within one whose association cannot be established, has
 * none.
 */
export function derivedAudiences(entry: unknown, references: readonly AudienceReference[]): string[] {
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) return [];
  const e = entry as AuthorityEntry;
  let kept: string[] | undefined;
  for (const r of references) {
    if (!within(e, r.entry)) continue;
    if (r.audiences === undefined) return [];
    kept = kept === undefined ? [...new Set(r.audiences)] : kept.filter((aud) => r.audiences?.includes(aud));
  }
  return kept ?? [];
}

/** {@link derivedAudiences} for each entry of a derived record, index-aligned with it. */
export function inheritedAudiences(
  entries: readonly AuthorityEntry[],
  references: readonly AudienceReference[],
): string[][] {
  return entries.map((entry) => derivedAudiences(entry, references));
}

/** The entries a token for its audiences carries, or the reason it is refused `invalid_target`. */
export type AudienceProjection = { issued: AuthorityEntry[]; refusal?: undefined } | { issued?: undefined; refusal: string };

const resourceOf = (entry: unknown): string =>
  String((entry as { resource?: unknown } | null)?.resource ?? "an entry");

/**
 * @spec mission#token-response (D733 ruling 1): the entries a Mission-bound
 * token issued for `audiences` carries, out of the `carried` entries its path
 * computed, against the Mission's retained associations (`references`).
 *
 * - An entry is carried only where every token audience is in its original
 *   approved audience; any other entry is left out, never carried along.
 * - `explicit` (the token request named `authorization_details`): an entry
 *   the request names that is not approved for every token audience refuses
 *   the request, since issuing the rest would be a narrower set than the
 *   one requested.
 * - Several audiences whose permitted entries differ refuse the request: a
 *   separate token for each audience is issued instead.
 * - A token that would carry no entry is refused.
 *
 * A token naming no audience is left to the scope projection, which refuses
 * it.
 */
export function audienceProjection(
  references: readonly AudienceReference[],
  audiences: readonly string[],
  carried: readonly unknown[],
  explicit: boolean,
): AudienceProjection {
  const auds = [...new Set(audiences)];
  if (auds.length === 0) return { issued: carried as AuthorityEntry[] };
  const allowed = carried.map((item) => derivedAudiences(item, references));
  if (explicit) {
    for (const [i, item] of carried.entries()) {
      const missing = auds.find((aud) => !allowed[i]?.includes(aud));
      if (missing !== undefined) {
        return {
          refusal: `audience ${missing} is not an original approved audience of the requested entry for ${resourceOf(item)}`,
        };
      }
    }
  }
  const [first, ...rest] = auds as [string, ...string[]];
  for (const aud of rest) {
    if (allowed.some((a) => a.includes(aud) !== a.includes(first))) {
      return {
        refusal: `audiences ${first} and ${aud} are not approved for the same entries; a separate token is issued for each audience`,
      };
    }
  }
  const issued = carried.filter((_, i) => auds.every((aud) => allowed[i]?.includes(aud))) as AuthorityEntry[];
  if (issued.length === 0) {
    return { refusal: `audience ${first} is not an original approved audience of any entry the token would carry` };
  }
  return { issued };
}

/**
 * The fail-closed issuance backstop: the reason a token for `audiences`
 * carries an entry one of them is not an original approved audience of, or
 * undefined. Every Mission-bound mint path computes its carried entries with
 * {@link audienceProjection} first, so this refuses only a path that did not.
 */
export function unapprovedCarriage(
  references: readonly AudienceReference[],
  audiences: readonly string[],
  carried: readonly unknown[],
): string | undefined {
  const auds = [...new Set(audiences)];
  for (const item of carried) {
    const allowed = derivedAudiences(item, references);
    const missing = auds.find((aud) => !allowed.includes(aud));
    if (missing !== undefined) {
      return `audience ${missing} is not an original approved audience of the carried entry for ${resourceOf(item)}`;
    }
  }
  return undefined;
}
