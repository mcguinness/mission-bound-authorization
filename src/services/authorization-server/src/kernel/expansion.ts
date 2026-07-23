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

export interface ExpansionResult {
  successor: MissionRecord;
  /** The successor `mission` claim adds a `predecessor` member. */
  predecessor: string;
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
    predecessor: input.predecessorId,
  };
  kernel.insertRecord(record);
  return { successor: record, predecessor: input.predecessorId };
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
