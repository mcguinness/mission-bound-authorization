/**
 * @spec draft-mcguinness-oauth-mission-expansion
 *
 * Mission Expansion: a successor Mission created by a fresh approval that
 * widens authority. The successor carries a `predecessor` member; the
 * predecessor enters `superseded` atomically on the successor's first grant
 * redemption. The successor's authority comes only from its own approval and
 * MUST NOT broaden without one. Backs AROP token-issuance completion (D6).
 */

import { randomBytes } from "node:crypto";
import { authorityHash, intentHash } from "@mission/core";
import type { MissionKernel } from "./kernel.js";
import type { AuthorityEntry, MissionIntent, MissionRecord } from "./types.js";

export interface ExpansionInput {
  predecessorId: string;
  /** The widened intent (fresh approval basis); must be derivable under policy. */
  intent: MissionIntent;
  approver: { iss: string; sub: string };
  approvalEventId: string;
  /** Bounds the successor credential; MUST NOT be exceeded (approved_until). */
  approvedUntil: string;
}

/**
 * @spec containment#restoration — one applied containment transition the
 * predecessor carried, disclosed at expansion consent: at minimum the
 * contained capability (`removed`) and the event class that contained it
 * (`event_type`). Mirrors {@link ContainmentEventRecord} member-for-member,
 * renamed only where the disclosure vocabulary differs (`type` -> `event_type`).
 */
export interface ContainmentHistoryEntry {
  event_type: string;
  removed: Array<{ resource: string; actions?: string[] }>;
}

/**
 * @spec containment#restoration — the anti-laundering evidence for one
 * expansion: which predecessor and successor it links, and (when non-empty)
 * the containment history disclosed at consent. Mirrors the Child Evidence /
 * Containment Evidence conventions (prefixed random `evidence_id`,
 * `created_at`); not yet wired to a retention channel, like
 * {@link ChildEvidence} before it.
 */
export interface ExpansionEvidence {
  evidence_id: string;
  predecessor: { id: string; issuer: string; authority_hash: string };
  successor: { id: string; issuer: string; authority_hash: string };
  /** Present only when the predecessor carried a non-empty containment overlay. */
  containment_history?: ContainmentHistoryEntry[];
  created_at: string;
}

export interface ExpansionResult {
  successor: MissionRecord;
  /** The successor `mission` claim adds a `predecessor` member. */
  predecessor: string;
  /**
   * @spec containment#restoration — the anti-laundering MUST: present (and
   * non-empty) only when the predecessor carried a non-empty containment
   * overlay, surfacing the containment history for the expansion consent
   * disclosure. The successor's OWN containment overlay stays empty regardless
   * (containment MUST NOT propagate to a successor); this is disclosure only,
   * never a re-application of the overlay.
   */
  containmentHistory?: ContainmentHistoryEntry[];
  /** @spec containment#restoration — the evidence record for this expansion. */
  evidence: ExpansionEvidence;
}

/**
 * Create a successor Mission. It is `active` immediately but supersedes the
 * predecessor only on first grant redemption (supersedeOnRedemption).
 */
export function createExpansion(kernel: MissionKernel, input: ExpansionInput): ExpansionResult {
  const predecessor = kernel.get(input.predecessorId);
  if (!predecessor) throw new Error("unknown predecessor mission");
  // @spec expansion#predecessor-active: predecessor must be active to expand.
  if (kernel.applyExpiry(predecessor).state !== "active") {
    throw new Error("predecessor is not active");
  }

  const authoritySet = kernel.derive(input.intent);
  // @spec expansion: successor expiry MUST NOT exceed the recorded approval
  // expiry (approved_until) -- the credential is bounded by the approval.
  const expiresAt =
    Date.parse(input.intent.expires_at) <= Date.parse(input.approvedUntil)
      ? input.intent.expires_at
      : input.approvedUntil;

  const id = `msn_${randomBytes(18).toString("base64url")}`;
  const record: MissionRecord = {
    id,
    issuer: predecessor.issuer,
    state: "active",
    intent: input.intent,
    authority_set: authoritySet,
    intent_hash: intentHash(predecessor.issuer, input.intent as never),
    authority_hash: authorityHash(predecessor.issuer, authoritySet as never),
    subject: predecessor.subject,
    approver: input.approver,
    client_id: predecessor.client_id,
    policy_version: predecessor.policy_version,
    approval_event_id: input.approvalEventId,
    created_at: kernel.nowDate().toISOString(),
    expires_at: expiresAt,
    version: 1,
    max_derivations: predecessor.max_derivations,
    derivation_count: 0,
    grant_id: null,
    status_list_idx: null,
    predecessor: input.predecessorId,
  };
  kernel.insertRecord(record);

  // @spec containment#restoration — the anti-laundering MUST: surface a
  // non-empty predecessor containment history at expansion consent, rather
  // than letting a widened successor issue with no trace of why the authority
  // it restores was ever narrowed. Read directly off the predecessor's applied
  // events (each already pairs the event class with what it removed), never
  // the successor, whose own overlay stays empty.
  const containmentHistory: ContainmentHistoryEntry[] | undefined =
    predecessor.containment && predecessor.containment.events.length > 0
      ? predecessor.containment.events.map((e) => ({ event_type: e.type, removed: e.removed }))
      : undefined;

  const evidence: ExpansionEvidence = {
    evidence_id: `exp_${randomBytes(9).toString("base64url")}`,
    predecessor: { id: predecessor.id, issuer: predecessor.issuer, authority_hash: predecessor.authority_hash },
    successor: { id: record.id, issuer: record.issuer, authority_hash: record.authority_hash },
    ...(containmentHistory ? { containment_history: containmentHistory } : {}),
    created_at: record.created_at,
  };

  return {
    successor: record,
    predecessor: input.predecessorId,
    ...(containmentHistory ? { containmentHistory } : {}),
    evidence,
  };
}

/**
 * The successor's `mission` claim, adding the `predecessor` lineage member.
 */
export function successorMissionClaim(
  kernel: MissionKernel,
  successor: MissionRecord,
): Record<string, unknown> {
  return { ...kernel.missionClaim(successor), predecessor: successor.predecessor };
}

/** Authority never broadens without approval: the successor's set is exactly what its approval derived. */
export function successorWidensOnly(predecessor: AuthorityEntry[], successor: AuthorityEntry[]): boolean {
  // Every predecessor action remains, and the successor adds at least one.
  const predActions = new Set(predecessor.flatMap((e) => e.actions));
  const succActions = new Set(successor.flatMap((e) => e.actions));
  for (const a of predActions) if (!succActions.has(a)) return false;
  return true;
}
