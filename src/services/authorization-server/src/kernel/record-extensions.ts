/**
 * @spec mission#mission-record (#1912, #1923): the record is open. A consumer
 * does not interpret a member it does not recognize, and does not remove it
 * from a record it retains or commits. The kernel store keeps each recognized
 * member in its own column; every other top-level member rides in one JSON
 * column, written at creation and never updated, and is merged back on every
 * read.
 *
 * A stored extension never stands in for a recognized member. The write side
 * stores only unrecognized names, and the read side drops any recognized name
 * it finds, so an extension cannot overwrite a recognized member, supply an
 * absent optional one, or carry authority. Nothing in the kernel reads an
 * extension's value.
 */

import type { MissionRecord } from "./types.js";

// A `Record` over `keyof MissionRecord`, so a member added to the record type
// without being listed here, or a name listed here that the type lacks, fails
// to compile.
const RECOGNIZED: Record<keyof MissionRecord, true> = {
  id: true,
  issuer: true,
  state: true,
  termination: true,
  intent: true,
  proposed_authority: true,
  authority_set: true,
  eligibility_provenance: true,
  child_actor_provenance: true,
  approved_audiences: true,
  intent_hash: true,
  authority_hash: true,
  proposal_hash: true,
  submission_evidence: true,
  subject: true,
  approval_basis: true,
  authority_source: true,
  client_id: true,
  policy_version: true,
  approval_event_id: true,
  created_at: true,
  expires_at: true,
  version: true,
  derivation_limit: true,
  derivation_count: true,
  grant_id: true,
  status_list_idx: true,
  predecessor: true,
  related_to: true,
  parent: true,
  template: true,
  projected_from: true,
  schedule: true,
  containment: true,
  discharged: true,
  authority_ceiling: true,
  ceiling_audiences: true,
  drawdown_policy: true,
  ceiling_hash: true,
  ceiling_consent_hash: true,
  ceiling_consented_at: true,
  ceiling_consent_principal: true,
  drawdown_count: true,
  resource_declaration_digest: true,
  encounter_id: true,
};

/** The top-level Mission Record members this store recognizes. */
export const RECOGNIZED_RECORD_MEMBERS: ReadonlySet<string> = new Set(Object.keys(RECOGNIZED));

/**
 * The JSON of `record`'s unrecognized top-level members, exactly as the record
 * carries them, or null when it carries none. `Object.fromEntries` defines own
 * properties, so a member named `__proto__` is kept as a member.
 */
export function recordExtensionsJson(record: MissionRecord): string | null {
  const entries = Object.entries(record).filter(
    ([name, value]) => !RECOGNIZED_RECORD_MEMBERS.has(name) && value !== undefined,
  );
  return entries.length > 0 ? JSON.stringify(Object.fromEntries(entries)) : null;
}

/**
 * The stored extension members as record members, without any recognized
 * name; none where nothing is stored or what is stored cannot be read.
 */
export function storedExtensionMembers(text: unknown): Record<string, unknown> {
  if (typeof text !== "string" || text === "") return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return {};
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return {};
  return Object.fromEntries(Object.entries(parsed).filter(([name]) => !RECOGNIZED_RECORD_MEMBERS.has(name)));
}
