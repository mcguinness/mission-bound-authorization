/**
 * @spec draft-mcguinness-oauth-mission-template — the Mission Template store.
 *
 * A Mission Template is a HUMAN-CONSENTED ceiling + dispatch policy + bounds. A
 * dispatcher instantiates ORDINARY Missions from it at machine speed
 * ({@link dispatchFromTemplate} in template.ts); each instance's Authority Set
 * is a subset of BOTH the derivation-policy ceiling AND the template ceiling
 * (the double intersection). The template body lives HERE, not on
 * MissionRecord, so no kernel schema migration is needed beyond the instance
 * lineage columns.
 *
 * Structure mirrors {@link DelegationFamilyStore} / {@link ContinuationStore}
 * (SQLite via `openStore`, injected `now()`, holds no kernel reference). The
 * `templates` table is the consented ceiling; the `dispatch_events` table is
 * the per-dispatch audit trail that also backs the rate and max-active bounds.
 *
 * max-active is NOT a pure store concern: whether an instance is still
 * non-terminal is kernel lifecycle state. So the store counts its OWN
 * dispatch_events rows and delegates the terminal decision to a predicate the
 * dispatcher supplies (from `kernel.get`); see {@link activeInstanceCount}.
 */

import { openStore, UniqueViolationError, withTransaction, type Database } from "@mission/store";
import type { AuthorityEntry } from "./types.js";

const SCHEMA = `
CREATE TABLE templates (
  id TEXT PRIMARY KEY,
  template_version TEXT NOT NULL,
  issuer TEXT NOT NULL,
  approver_iss TEXT NOT NULL,
  approver_sub TEXT NOT NULL,
  ceiling_json TEXT NOT NULL,
  dispatch_policy TEXT NOT NULL,
  dispatchers_json TEXT NOT NULL,
  recipients_json TEXT NOT NULL,
  per_instance_lifetime_s INTEGER NOT NULL,
  max_active INTEGER NOT NULL,
  rate_per_min INTEGER NOT NULL,
  template_hash TEXT NOT NULL,
  approval_event_id TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  state TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;
CREATE TABLE dispatch_events (
  dispatch_event_id TEXT PRIMARY KEY,
  template_id TEXT NOT NULL,
  mission_id TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;
`;

/** @spec mission-template#lifecycle — a template is `active` until revoked
 *  (human withdraws consent). Expiry is evaluated from `expires_at`, not stored
 *  as a state, so both a revoked and an expired template refuse dispatch. */
export type TemplateState = "active" | "revoked";

/**
 * A Mission Template: the consented ceiling and the bounds within which
 * instances may be dispatched. `template_hash` is the integrity anchor over the
 * consented body (@spec mission-template, {@link MISSION_TEMPLATE_TYP}).
 */
export interface MissionTemplate {
  id: string;
  template_version: string;
  issuer: string;
  /** The HUMAN of record: every instance carries this approver, not the dispatcher. */
  approver: { iss: string; sub: string };
  /** The template ceiling: one side of the double intersection at dispatch. */
  ceiling: AuthorityEntry[];
  /** Opaque dispatch policy identifier (audit / lineage only). */
  dispatch_policy: string;
  /** Actors permitted to dispatch instances from this template. */
  dispatchers: string[];
  /** Actors an instance may be dispatched TO; the recipient becomes `client_id`. */
  recipients: string[];
  /** Per-instance lifetime cap (seconds); clamps each instance's `expires_at`. */
  per_instance_lifetime_s: number;
  /** Max concurrently non-terminal instances dispatched from this template. */
  max_active: number;
  /** Max dispatches per rolling 60s window. */
  rate_per_min: number;
  template_hash: string;
  approval_event_id: string;
  expires_at: string;
  state: TemplateState;
  created_at: string;
}

/** The fields {@link createTemplate} computes and persists; the store stamps
 *  `state` (`active`) and `created_at`. */
export interface TemplateCreate {
  id: string;
  template_version: string;
  issuer: string;
  approver: { iss: string; sub: string };
  ceiling: AuthorityEntry[];
  dispatch_policy: string;
  dispatchers: string[];
  recipients: string[];
  per_instance_lifetime_s: number;
  max_active: number;
  rate_per_min: number;
  template_hash: string;
  approval_event_id: string;
  expires_at: string;
}

interface TemplateRow {
  id: string;
  template_version: string;
  issuer: string;
  approver_iss: string;
  approver_sub: string;
  ceiling_json: string;
  dispatch_policy: string;
  dispatchers_json: string;
  recipients_json: string;
  per_instance_lifetime_s: number;
  max_active: number;
  rate_per_min: number;
  template_hash: string;
  approval_event_id: string;
  expires_at: string;
  state: string;
  created_at: string;
}

function rowToTemplate(row: TemplateRow): MissionTemplate {
  return {
    id: row.id,
    template_version: row.template_version,
    issuer: row.issuer,
    approver: { iss: row.approver_iss, sub: row.approver_sub },
    ceiling: JSON.parse(row.ceiling_json) as AuthorityEntry[],
    dispatch_policy: row.dispatch_policy,
    dispatchers: JSON.parse(row.dispatchers_json) as string[],
    recipients: JSON.parse(row.recipients_json) as string[],
    per_instance_lifetime_s: row.per_instance_lifetime_s,
    max_active: row.max_active,
    rate_per_min: row.rate_per_min,
    template_hash: row.template_hash,
    approval_event_id: row.approval_event_id,
    expires_at: row.expires_at,
    state: row.state as TemplateState,
    created_at: row.created_at,
  };
}

export class TemplateStore {
  readonly db: Database;
  constructor(private readonly now: () => Date = () => new Date()) {
    this.db = openStore(SCHEMA);
  }

  /**
   * Persist a template. IDEMPOTENT by `approval_event_id` (mirrors
   * `kernel.approve()`): a repeat with the same approval event returns the
   * template that event already created, discarding the freshly-computed
   * id/hash. The store stamps `state = 'active'` and `created_at`.
   */
  create(input: TemplateCreate): MissionTemplate {
    try {
      withTransaction(this.db, () => {
        this.db
          .prepare(
            `INSERT INTO templates (id, template_version, issuer, approver_iss, approver_sub,
             ceiling_json, dispatch_policy, dispatchers_json, recipients_json,
             per_instance_lifetime_s, max_active, rate_per_min, template_hash,
             approval_event_id, expires_at, state, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)`,
          )
          .run(
            input.id,
            input.template_version,
            input.issuer,
            input.approver.iss,
            input.approver.sub,
            JSON.stringify(input.ceiling),
            input.dispatch_policy,
            JSON.stringify(input.dispatchers),
            JSON.stringify(input.recipients),
            input.per_instance_lifetime_s,
            input.max_active,
            input.rate_per_min,
            input.template_hash,
            input.approval_event_id,
            input.expires_at,
            this.now().toISOString(),
          );
      });
    } catch (e) {
      if (e instanceof UniqueViolationError) {
        const existing = this.getByApprovalEvent(input.approval_event_id);
        if (existing) return existing;
      }
      throw e;
    }
    const created = this.get(input.id);
    if (!created) throw new Error(`template ${input.id} vanished after insert`);
    return created;
  }

  get(id: string): MissionTemplate | undefined {
    const row = this.db.prepare("SELECT * FROM templates WHERE id = ?").get(id) as
      | TemplateRow
      | undefined;
    return row ? rowToTemplate(row) : undefined;
  }

  /** Idempotency lookup by the consenting approval event. */
  getByApprovalEvent(approvalEventId: string): MissionTemplate | undefined {
    const row = this.db
      .prepare("SELECT * FROM templates WHERE approval_event_id = ?")
      .get(approvalEventId) as TemplateRow | undefined;
    return row ? rowToTemplate(row) : undefined;
  }

  /** Withdraw consent: a revoked template refuses every subsequent dispatch. */
  revoke(id: string): void {
    this.db.prepare("UPDATE templates SET state = 'revoked' WHERE id = ?").run(id);
  }

  /** Record one dispatch for the rate / max-active bounds and the audit trail. */
  recordDispatch(input: { dispatchEventId: string; templateId: string; missionId: string }): void {
    this.db
      .prepare(
        `INSERT INTO dispatch_events (dispatch_event_id, template_id, mission_id, created_at)
         VALUES (?, ?, ?, ?)`,
      )
      .run(input.dispatchEventId, input.templateId, input.missionId, this.now().toISOString());
  }

  /**
   * Count concurrently NON-TERMINAL instances of a template. The store owns its
   * own dispatch_events rows but cannot know instance lifecycle state, so the
   * caller supplies `isTerminal` (from `kernel.get` + TERMINAL_STATES). An
   * instance the kernel no longer knows is treated as not-active (the predicate
   * returns true), so it never counts against `max_active`.
   */
  activeInstanceCount(templateId: string, isTerminal: (missionId: string) => boolean): number {
    const rows = this.db
      .prepare("SELECT mission_id FROM dispatch_events WHERE template_id = ?")
      .all(templateId) as Array<{ mission_id: string }>;
    return rows.filter((r) => !isTerminal(r.mission_id)).length;
  }

  /** Dispatches for a template at or after `sinceIso`, for the rate bound. ISO
   *  UTC strings compare lexicographically == chronologically. */
  dispatchesSince(templateId: string, sinceIso: string): number {
    const row = this.db
      .prepare(
        "SELECT COUNT(*) AS n FROM dispatch_events WHERE template_id = ? AND created_at >= ?",
      )
      .get(templateId, sinceIso) as { n: number };
    return row.n;
  }
}
