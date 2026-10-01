/**
 * @spec discharge#condition-selectors — the issuer-held CONDITION SELECTOR
 * table: one opaque selector per discharge target, the (`mission_id`,
 * `entry_digest`, `condition_digest`) triple of the `discharge` operation.
 *
 * - Lookup state only. Nothing here is committed: `terminal_when`, its value
 *   space, the subset rule and `authority_hash` are unchanged by a selector.
 * - ONE PER TARGET, EXACTLY ONE TARGET PER SELECTOR: `selector` is the primary
 *   key and the target triple is UNIQUE, so a target never gains a second
 *   selector and a selector never resolves to two targets. Byte-identical
 *   entries share one `entry_digest`, so they share one selector, as they share
 *   one equivalence-class latch.
 * - NON-RECONSTRUCTION: a selector is `dcs_` plus 18 random bytes (base64url),
 *   never computed from the entry's content, so its holder cannot test it
 *   against guesses of the record entry.
 * - RETENTION: rows are never deleted. A selector stays resolvable for the
 *   record's lifetime, which covers direct discharge, forwarding after
 *   carryover, and the event-deduplication replay horizon.
 *
 * Issuance is lazy get-or-create, so a selector exists only once a projection
 * has disclosed it (or a caller has asked for it).
 */

import { randomBytes } from "node:crypto";
import { withTransaction, type Database } from "@mission/store";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS discharge_selectors (
  selector TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL,
  entry_digest TEXT NOT NULL,
  condition_digest TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (mission_id, entry_digest, condition_digest)
) STRICT;
`;

/** @spec discharge#condition-selectors — `1*128( ALPHA / DIGIT / "-" / "_" )`. */
export const CONDITION_SELECTOR_RE = /^[A-Za-z0-9_-]{1,128}$/;

/** The prefix this AS gives its selectors (an opaque convention, never parsed). */
export const CONDITION_SELECTOR_PREFIX = "dcs_";

/** One discharge target: what a condition selector resolves to. */
export interface DischargeTargetTriple {
  mission_id: string;
  entry_digest: string;
  condition_digest: string;
}

/** A fresh selector: random, carrying nothing derived from the entry. */
function mintSelector(): string {
  return `${CONDITION_SELECTOR_PREFIX}${randomBytes(18).toString("base64url")}`;
}

export class DischargeSelectorStore {
  constructor(
    private readonly db: Database,
    private readonly now: () => Date = () => new Date(),
  ) {
    this.db.exec(SCHEMA);
  }

  /**
   * The selector for this target, minting it on first use. The UNIQUE target
   * constraint decides a race: the losing insert is ignored and the winner's
   * selector is read back, so a target never has two.
   */
  selectorFor(target: DischargeTargetTriple): string {
    return withTransaction(this.db, () => {
      const existing = this.find(target);
      if (existing) return existing;
      this.db
        .prepare(
          `INSERT INTO discharge_selectors (selector, mission_id, entry_digest, condition_digest, created_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT DO NOTHING`,
        )
        .run(
          mintSelector(),
          target.mission_id,
          target.entry_digest,
          target.condition_digest,
          this.now().getTime(),
        );
      const stored = this.find(target);
      if (!stored) throw new Error("condition selector insert vanished");
      return stored;
    });
  }

  /** The target a selector resolves to, or undefined when it resolves to none. */
  resolve(selector: string): DischargeTargetTriple | undefined {
    const row = this.db
      .prepare(
        "SELECT mission_id, entry_digest, condition_digest FROM discharge_selectors WHERE selector = ?",
      )
      .get(selector) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    return {
      mission_id: row.mission_id as string,
      entry_digest: row.entry_digest as string,
      condition_digest: row.condition_digest as string,
    };
  }

  private find(target: DischargeTargetTriple): string | undefined {
    const row = this.db
      .prepare(
        `SELECT selector FROM discharge_selectors
         WHERE mission_id = ? AND entry_digest = ? AND condition_digest = ?`,
      )
      .get(target.mission_id, target.entry_digest, target.condition_digest) as
      | { selector: string }
      | undefined;
    return row?.selector;
  }
}
