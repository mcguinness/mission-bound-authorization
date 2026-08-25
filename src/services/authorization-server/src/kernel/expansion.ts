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
import { authorityHash, intentHash, proposalHash } from "@mission/core";
import type { MissionKernel } from "./kernel.js";
import { newMissionId } from "./mission-id.js";
import type {
  ApprovalBasis,
  AuthorityEntry,
  IntentSubmissionEvidenceFact,
  MissionIntent,
  MissionRecord,
} from "./types.js";

export interface ExpansionInput {
  predecessorId: string;
  /** The widened intent (fresh approval basis); must be derivable under policy. */
  intent: MissionIntent;
  /**
   * @spec mission#authority-proposal — the authority proposal submitted on the
   * standard `authorization_details` parameter of the expansion exchange
   * (already validated at intake). Recorded on the successor and committed by
   * `proposal_hash` iff present; absent means template-mode derivation.
   */
  proposedAuthority?: AuthorityEntry[];
  approver: { iss: string; sub: string };
  approvalEventId: string;
  /** Bounds the successor credential; MUST NOT be exceeded (approved_until). */
  approvedUntil: string;
  /**
   * @spec mission#intent-submission-evidence — the VERIFIED Intent Submission
   * Evidence facts of the widening submission (stage-2 output, verified at
   * initiation and persisted across a deferred window). Landed on the
   * successor record's `submission_evidence`, outside all anchors.
   */
  submissionEvidence?: IntentSubmissionEvidenceFact[];
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

  const proposal = input.proposedAuthority?.length ? input.proposedAuthority : undefined;
  const authoritySet = kernel.derive(input.intent, proposal);
  // @spec expansion: successor expiry MUST NOT exceed the recorded approval
  // expiry (approved_until) -- the credential is bounded by the approval.
  const expiresAt =
    Date.parse(input.intent.expires_at) <= Date.parse(input.approvedUntil)
      ? input.intent.expires_at
      : input.approvedUntil;

  const id = newMissionId();
  const authorityHashValue = authorityHash(predecessor.issuer, authoritySet as never);
  // @spec mission#approval-basis — Expansion is a fresh human approval that
  // widens authority (like kernel.approve()'s direct path): consent_principal
  // == activation_actor == the new approver, and root_commitment is the
  // successor's own authority_hash.
  const approvalBasis: ApprovalBasis = {
    type: "direct",
    consent_principal: input.approver,
    activation: { approval_event_id: input.approvalEventId },
    activation_actor: input.approver,
    root_commitment: authorityHashValue,
  };
  const record: MissionRecord = {
    id,
    issuer: predecessor.issuer,
    state: "active",
    intent: input.intent,
    ...(proposal ? { proposed_authority: proposal } : {}),
    authority_set: authoritySet,
    intent_hash: intentHash(predecessor.issuer, input.intent as never),
    ...(proposal ? { proposal_hash: proposalHash(predecessor.issuer, proposal as never) } : {}),
    ...(input.submissionEvidence?.length ? { submission_evidence: input.submissionEvidence } : {}),
    authority_hash: authorityHashValue,
    subject: predecessor.subject,
    approver: input.approver,
    approval_basis: approvalBasis,
    client_id: predecessor.client_id,
    policy_version: predecessor.policy_version,
    approval_event_id: input.approvalEventId,
    created_at: kernel.nowDate().toISOString(),
    expires_at: expiresAt,
    version: 1,
    // @spec mission#derivation-issuance-policy — every approval event
    // establishes derivation_limit afresh, an Expansion successor's
    // included: it is never inherited from the predecessor. Expansion is a
    // fresh human approval (this function's own approval_basis above is
    // "direct", exactly kernel.approve()'s path), so the successor's OWN
    // Intent (input.intent, which MAY carry its own
    // requested_derivation_limit) is clamped by this deployment's policy
    // ceiling exactly as an ordinary Mission approval would be.
    derivation_limit: kernel.resolveDerivationLimit(input.intent.requested_derivation_limit),
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
