/**
 * The mission-kernel (decision D30): mission records, approval events,
 * lifecycle, gating, projections, and the signed Status surface. No
 * oidc-provider types cross this boundary.
 */

import { randomBytes } from "node:crypto";
import { authorityHash, intentHash } from "@mission/core";
import { openStore, UniqueViolationError, withTransaction, type Database } from "@mission/store";
import { SignJWT, type CryptoKey } from "jose";
import type { DerivationPolicy } from "./derive.js";
import { deriveAuthoritySet } from "./derive.js";
import { validateMissionIntent } from "./intent.js";
import {
  type AuthorityEntry,
  LEGAL_TRANSITIONS,
  type LifecycleOperation,
  type MissionClaim,
  type MissionIntent,
  type MissionRecord,
  type MissionState,
  TERMINAL_STATES,
} from "./types.js";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS missions (
  id TEXT PRIMARY KEY,
  issuer TEXT NOT NULL,
  state TEXT NOT NULL,
  intent_json TEXT NOT NULL,
  authority_set_json TEXT NOT NULL,
  intent_hash TEXT NOT NULL,
  authority_hash TEXT NOT NULL,
  subject_iss TEXT NOT NULL,
  subject_sub TEXT NOT NULL,
  approver_iss TEXT NOT NULL,
  approver_sub TEXT NOT NULL,
  client_id TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  approval_event_id TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  max_derivations INTEGER,
  derivation_count INTEGER NOT NULL DEFAULT 0,
  grant_id TEXT,
  predecessor TEXT,
  successor TEXT
) STRICT;
`;

export class LifecycleConflictError extends Error {}
export class GateError extends Error {
  constructor(
    readonly reason: "mission_not_active" | "mission_expired" | "derivation_cap_exhausted",
    message: string,
  ) {
    super(message);
  }
}

export interface ApproveInput {
  intent: MissionIntent;
  subject: { iss: string; sub: string };
  approver: { iss: string; sub: string };
  clientId: string;
  approvalEventId: string;
}

export interface KernelOptions {
  issuer: string;
  policy: DerivationPolicy;
  statusKey: CryptoKey;
  statusKid: string;
  now?: () => Date;
}

export class MissionKernel {
  readonly db: Database;
  private readonly now: () => Date;

  constructor(private readonly opts: KernelOptions) {
    this.db = openStore(SCHEMA);
    this.now = opts.now ?? (() => new Date());
  }

  validateIntent(raw: string): MissionIntent {
    return validateMissionIntent(raw);
  }

  derive(intent: MissionIntent): AuthorityEntry[] {
    return deriveAuthoritySet(intent, this.opts.policy);
  }

  /**
   * @spec mission#integrity-anchors — the approval event creates the record
   * with both anchors; approval_event_id is the idempotency key.
   */
  approve(input: ApproveInput): MissionRecord {
    const authoritySet = this.derive(input.intent);
    // @spec mission#mission-identifier: opaque URL-safe, >=128 bits entropy.
    const id = `msn_${randomBytes(18).toString("base64url")}`;
    const record: MissionRecord = {
      id,
      issuer: this.opts.issuer,
      state: "active",
      intent: input.intent,
      authority_set: authoritySet,
      intent_hash: intentHash(this.opts.issuer, input.intent as never),
      authority_hash: authorityHash(this.opts.issuer, authoritySet as never),
      subject: input.subject,
      approver: input.approver,
      client_id: input.clientId,
      policy_version: this.opts.policy.policy_version,
      approval_event_id: input.approvalEventId,
      created_at: this.now().toISOString(),
      expires_at: input.intent.expires_at,
      version: 1,
      max_derivations: input.intent.controls?.max_derivations ?? null,
      derivation_count: 0,
      grant_id: null,
    };
    try {
      this.insertRecord(record);
    } catch (e) {
      if (e instanceof UniqueViolationError) {
        // Idempotent approval: return the record this event already created.
        const existing = this.findByApprovalEvent(input.approvalEventId);
        if (existing) return existing;
      }
      throw e;
    }
    return record;
  }

  /** Insert a full record (shared by approve and expansion). */
  insertRecord(record: MissionRecord): void {
    withTransaction(this.db, () => {
      this.db
        .prepare(
          `INSERT INTO missions (id, issuer, state, intent_json, authority_set_json, intent_hash,
           authority_hash, subject_iss, subject_sub, approver_iss, approver_sub, client_id,
           policy_version, approval_event_id, created_at, expires_at, version, max_derivations,
           derivation_count, grant_id, predecessor)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          record.id,
          record.issuer,
          record.state,
          JSON.stringify(record.intent),
          JSON.stringify(record.authority_set),
          record.intent_hash,
          record.authority_hash,
          record.subject.iss,
          record.subject.sub,
          record.approver.iss,
          record.approver.sub,
          record.client_id,
          record.policy_version,
          record.approval_event_id,
          record.created_at,
          record.expires_at,
          record.version,
          record.max_derivations,
          record.derivation_count,
          record.grant_id,
          record.predecessor ?? null,
        );
    });
  }

  nowDate(): Date {
    return this.now();
  }

  /**
   * @spec expansion#superseded-state: on the successor's first grant
   * redemption, the successor stays active and the predecessor enters
   * `superseded` atomically. Returns false if already superseded.
   */
  supersedeOnRedemption(successorId: string): boolean {
    const successor = this.get(successorId);
    if (!successor?.predecessor) return false;
    return withTransaction(this.db, () => {
      const pred = this.get(successor.predecessor as string);
      if (!pred || pred.state !== "active") return false;
      this.db
        .prepare("UPDATE missions SET state = 'superseded', successor = ?, version = version + 1 WHERE id = ? AND state = 'active'")
        .run(successorId, pred.id);
      return true;
    });
  }

  get(id: string): MissionRecord | undefined {
    const row = this.db.prepare("SELECT * FROM missions WHERE id = ?").get(id) as
      | Record<string, unknown>
      | undefined;
    return row ? rowToRecord(row) : undefined;
  }

  findByGrant(grantId: string): MissionRecord | undefined {
    const row = this.db.prepare("SELECT * FROM missions WHERE grant_id = ?").get(grantId) as
      | Record<string, unknown>
      | undefined;
    return row ? rowToRecord(row) : undefined;
  }

  findByApprovalEvent(approvalEventId: string): MissionRecord | undefined {
    const row = this.db
      .prepare("SELECT * FROM missions WHERE approval_event_id = ?")
      .get(approvalEventId) as Record<string, unknown> | undefined;
    return row ? rowToRecord(row) : undefined;
  }

  bindGrant(missionId: string, grantId: string): void {
    this.db.prepare("UPDATE missions SET grant_id = ? WHERE id = ?").run(grantId, missionId);
  }

  /** @spec mission-management: enumerate the full fleet for the operator. */
  allMissions(): MissionRecord[] {
    const rows = this.db.prepare("SELECT * FROM missions ORDER BY created_at").all() as Array<
      Record<string, unknown>
    >;
    return rows.map(rowToRecord);
  }

  /** Active (non-expired) missions for a subject, for catalog status (D9). */
  activeMissionsForSubject(sub: string): MissionRecord[] {
    const rows = this.db
      .prepare("SELECT * FROM missions WHERE subject_sub = ? AND state = 'active'")
      .all(sub) as Array<Record<string, unknown>>;
    return rows.map(rowToRecord).map((r) => this.applyExpiry(r)).filter((r) => r.state === "active");
  }

  /**
   * @spec status#legal-transitions — idempotent success when the resulting
   * state equals the current state, except `resume`, which is legal only
   * from `suspended`; anything else is a conflict.
   */
  transition(id: string, op: LifecycleOperation): MissionRecord {
    const record = this.mustGet(id);
    this.applyExpiry(record);
    const rule = LEGAL_TRANSITIONS[op];
    if (record.state === rule.to && op !== "resume") return record;
    if (!rule.from.includes(record.state)) {
      throw new LifecycleConflictError(`${op} is not legal from ${record.state}`);
    }
    return this.setState(record, rule.to);
  }

  /** @spec status#state-machine — expiry clock: active/suspended -> expired. */
  applyExpiry(record: MissionRecord): MissionRecord {
    if (
      (record.state === "active" || record.state === "suspended") &&
      Date.parse(record.expires_at) <= this.now().getTime()
    ) {
      return this.setState(record, "expired");
    }
    return record;
  }

  /**
   * @spec mission#lifecycle — state-gated derivation: only `active` derives,
   * bounded by expires_at and max_derivations. Increments the derivation
   * count on success.
   */
  gateDerivation(id: string): MissionRecord {
    const record = this.applyExpiry(this.mustGet(id));
    if (record.state === "expired") throw new GateError("mission_expired", `mission ${id} is expired`);
    if (record.state !== "active") {
      throw new GateError("mission_not_active", `mission ${id} is ${record.state}`);
    }
    if (record.max_derivations !== null && record.derivation_count >= record.max_derivations) {
      throw new GateError("derivation_cap_exhausted", `mission ${id} derivation cap exhausted`);
    }
    this.db
      .prepare("UPDATE missions SET derivation_count = derivation_count + 1 WHERE id = ?")
      .run(id);
    return { ...record, derivation_count: record.derivation_count + 1 };
  }

  /** @spec mission#the-mission-claim */
  missionClaim(record: MissionRecord): MissionClaim {
    return {
      id: record.id,
      issuer: record.issuer,
      authority_hash: record.authority_hash,
      expires_at: Math.floor(Date.parse(record.expires_at) / 1000),
    };
  }

  /** @spec mission#introspection — the mission introspection member. */
  introspectionMission(record: MissionRecord): Record<string, unknown> {
    const fresh = this.applyExpiry(record);
    return {
      ...this.missionClaim(fresh),
      state: fresh.state,
      version: fresh.version,
    };
  }

  /**
   * @spec status#mission-status-response — JWS, typ
   * mission-status-response+jwt, mission object mirroring the claim plus
   * state/version/fresh_until; audience-scoped authorization_details.
   */
  async signedStatus(
    id: string,
    opts: { audience?: string; requester: string; nonce?: string; freshnessSeconds?: number },
  ): Promise<string> {
    const record = this.applyExpiry(this.mustGet(id));
    const nowS = Math.floor(this.now().getTime() / 1000);
    const freshness = opts.freshnessSeconds ?? 60;
    const scoped = opts.audience
      ? record.authority_set.filter((e) => e.resource === opts.audience)
      : undefined;
    const payload: Record<string, unknown> = {
      sub: record.client_id,
      mission: {
        ...this.missionClaim(record),
        state: record.state,
        version: record.version,
        expires_at: record.expires_at,
        fresh_until: new Date((nowS + freshness) * 1000).toISOString(),
      },
    };
    if (opts.nonce) payload.nonce = opts.nonce;
    if (scoped) payload.authorization_details = scoped;
    return new SignJWT(payload)
      .setProtectedHeader({ alg: "ES256", kid: this.opts.statusKid, typ: "mission-status-response+jwt" })
      .setIssuer(this.opts.issuer)
      .setAudience(opts.audience ?? opts.requester)
      .setIssuedAt(nowS)
      .setExpirationTime(nowS + freshness)
      .sign(this.opts.statusKey);
  }

  private setState(record: MissionRecord, to: MissionState): MissionRecord {
    if (TERMINAL_STATES.has(record.state)) {
      throw new LifecycleConflictError(`mission ${record.id} is terminal (${record.state})`);
    }
    this.db
      .prepare("UPDATE missions SET state = ?, version = version + 1 WHERE id = ?")
      .run(to, record.id);
    return { ...record, state: to, version: record.version + 1 };
  }

  private mustGet(id: string): MissionRecord {
    const record = this.get(id);
    if (!record) throw new Error(`unknown mission: ${id}`);
    return record;
  }
}

function rowToRecord(row: Record<string, unknown>): MissionRecord {
  return {
    id: row.id as string,
    issuer: row.issuer as string,
    state: row.state as MissionState,
    intent: JSON.parse(row.intent_json as string) as MissionIntent,
    authority_set: JSON.parse(row.authority_set_json as string) as AuthorityEntry[],
    intent_hash: row.intent_hash as string,
    authority_hash: row.authority_hash as string,
    subject: { iss: row.subject_iss as string, sub: row.subject_sub as string },
    approver: { iss: row.approver_iss as string, sub: row.approver_sub as string },
    client_id: row.client_id as string,
    policy_version: row.policy_version as string,
    approval_event_id: row.approval_event_id as string,
    created_at: row.created_at as string,
    expires_at: row.expires_at as string,
    version: row.version as number,
    max_derivations: (row.max_derivations as number | null) ?? null,
    derivation_count: row.derivation_count as number,
    grant_id: (row.grant_id as string | null) ?? null,
    ...(row.predecessor ? { predecessor: row.predecessor as string } : {}),
  };
}
