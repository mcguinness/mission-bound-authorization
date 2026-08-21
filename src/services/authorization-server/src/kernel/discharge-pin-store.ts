/**
 * @spec status#discharge-authority — the issuer-held pin binding each
 * `terminal_when` condition, at the moment it entered an immutable
 * Mission-record entry, to the RESOLVED discharge-authority mapping: the
 * mapping's identifier and version plus the resolved content itself
 * (principals, event_types). Discharge target authorization is evaluated
 * against this retained resolution, never against the live policy, so a later
 * policy edit can never retroactively change who may discharge an
 * already-approved entry (rebinding policy version 1 naming principal A to
 * version 2 naming principal B would otherwise permit the premature authority
 * retirement {{completion-security}} warns against).
 *
 * Rows are written inside `insertRecord`'s transaction (the single
 * record-creation funnel), so a record never exists without its pins, and a
 * discharge finding no pin fails CLOSED into the anti-oracle `not_found`
 * collapse.
 */

import type { Database } from "@mission/store";
import type { DischargeAuthorityMapping } from "./discharge.js";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS discharge_mapping_pins (
  mission_id TEXT NOT NULL,
  entry_digest TEXT NOT NULL,
  condition_digest TEXT NOT NULL,
  mapping_id TEXT NOT NULL,
  mapping_version TEXT NOT NULL,
  event_types_json TEXT,
  principals_json TEXT NOT NULL,
  PRIMARY KEY (mission_id, entry_digest, condition_digest)
) STRICT;
`;

export class DischargeMappingPinStore {
  constructor(private readonly db: Database) {
    this.db.exec(SCHEMA);
  }

  /**
   * Pin one condition's resolved mapping. NO OWN TRANSACTION: `insertRecord`
   * runs this inside its own `withTransaction`, so the pin and the record
   * commit as one unit. Two byte-identical entries share digests and
   * therefore one pin (ON CONFLICT DO NOTHING keeps the FIRST resolution).
   */
  pinInCallerTx(
    missionId: string,
    entryDigest: string,
    conditionDigest: string,
    mapping: DischargeAuthorityMapping,
  ): void {
    this.db
      .prepare(
        `INSERT INTO discharge_mapping_pins (mission_id, entry_digest, condition_digest,
         mapping_id, mapping_version, event_types_json, principals_json)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT DO NOTHING`,
      )
      .run(
        missionId,
        entryDigest,
        conditionDigest,
        mapping.mapping_id,
        mapping.mapping_version,
        mapping.event_types !== undefined ? JSON.stringify(mapping.event_types) : null,
        JSON.stringify(mapping.principals),
      );
  }

  /** The mapping as resolved and pinned at record creation, or undefined. */
  find(
    missionId: string,
    entryDigest: string,
    conditionDigest: string,
  ): DischargeAuthorityMapping | undefined {
    const row = this.db
      .prepare(
        `SELECT mapping_id, mapping_version, event_types_json, principals_json
         FROM discharge_mapping_pins
         WHERE mission_id = ? AND entry_digest = ? AND condition_digest = ?`,
      )
      .get(missionId, entryDigest, conditionDigest) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    return {
      mapping_id: row.mapping_id as string,
      mapping_version: row.mapping_version as string,
      ...(row.event_types_json != null
        ? { event_types: JSON.parse(row.event_types_json as string) as string[] }
        : {}),
      principals: JSON.parse(row.principals_json as string) as string[],
    };
  }
}
