/**
 * @spec draft-mcguinness-oauth-mission-expansion
 *
 * Mission Expansion: a successor Mission created by a fresh approval that
 * widens authority. The successor carries a `predecessor` member; the
 * predecessor is terminated `superseded` atomically on the successor's first grant
 * redemption. The successor's authority comes only from its own approval and
 * MUST NOT broaden without one. Backs AROP token-issuance completion (D6).
 */

import { randomBytes } from "node:crypto";
import { authorityHash, intentHash, proposalHash } from "@mission/core";
import { inheritCapabilitySources } from "./capability-binding.js";
import type { ExpansionDeferralStore } from "./deferred.js";
import type { MissionKernel } from "./kernel.js";
import { newMissionId } from "./mission-id.js";
import {
  type ApprovalBasis,
  type AuthorityEntry,
  type IntentSubmissionEvidenceFact,
  type MissionIntent,
  type MissionRecord,
  TERMINAL_STATES,
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
   * @spec expansion#successor-expiry — the EXACT extension ceiling recorded at
   * the expansion consent event. Supplied ONLY where the Mission Issuer's
   * policy explicitly permits extension AND the extension was disclosed to the
   * Approver; supplying it is what lets a successor outlive its predecessor,
   * and only up to this recorded value. Absent (the reference deployment's
   * policy permits no extension) the predecessor's own `expires_at` binds.
   */
  approvedExtensionUntil?: string;
  /**
   * @spec mission#intent-submission-evidence — the VERIFIED Intent Submission
   * Evidence facts of the widening submission (stage-2 output, verified at
   * initiation and persisted across a deferred window). Landed on the
   * successor record's `submission_evidence`, outside all anchors.
   */
  submissionEvidence?: IntentSubmissionEvidenceFact[];
  /**
   * @spec child-delegation#carryover-manifest — the RESERVED successor
   * identifier. A Carryover Manifest commits proposed identifiers at
   * preparation, so completion MUST use exactly the identifier the approval
   * authenticated and MUST NOT invent one. Absent (every non-carryover
   * expansion) the identifier is minted here as before. A reservation creates
   * no authority: this member only fixes which identifier the record takes.
   */
  successorId?: string;
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
  // @spec capability-binding#capability-source-binding — carry the
  // predecessor's recorded bindings for every retained catalog-sourced action,
  // before `authorityHashValue` below. The grantor is the predecessor's
  // APPROVED Authority Set, not its effective set: containment MUST NOT
  // propagate to a successor (see the containment history disclosure below),
  // and an expansion that restores a contained action restores the recorded
  // fact about that action with it rather than emitting the action unbound.
  // Actions the successor's own approval ADDS are not inherited: a binding
  // originates only in a trusted resolution at the approval that records it.
  // @spec resource-access#delegate-eligibility: a fresh derivation, so the
  // successor's origins are its own derivation's, index-aligned through the
  // per-entry capability transforms.
  const derived = kernel.deriveWithProvenance(input.intent, proposal);
  const authoritySet = kernel.resolveFreshCapabilities(inheritCapabilitySources(
    derived.entries,
    predecessor.authority_set,
  ));
  // @spec mission#approval-event (step 3), mission#authority-sources —
  // Expansion is a FRESH approval event with its own Approver (the
  // `approval_basis` built below is `direct`, exactly kernel.approve()'s
  // path), so step 3 applies verbatim: establish the source from trusted
  // configuration and assert the successor's derived set against it, both
  // before any anchor is computed.
  // One resolution (#827) for the predecessor's Subject through its client
  // feeds every gate, so the ceiling asserted is the one the source resolved.
  const resolvedSource = kernel.establishAuthoritySource({
    clientId: predecessor.client_id,
    subject: predecessor.subject,
    approver: input.approver,
  });
  kernel.assertAuthorityWithinSource(resolvedSource, authoritySet);
  const authoritySource = resolvedSource.provenance;
  // @spec expansion#successor-expiry — ONE creation instant for the successor:
  // the record's `created_at` and the instant every lifetime ceiling is
  // measured from are the same read.
  const createdAt = kernel.nowDate().toISOString();
  // @spec expansion#successor-expiry — the successor is bounded by the
  // submission's requested ceiling, by the recorded approval expiry
  // (`approved_until`), and by the PREDECESSOR's own `expires_at` unless a
  // recorded, disclosed, policy-permitted extension supplies the exact approved
  // extension ceiling in its place. Expansion adds authority; it is not a
  // lifetime-extension mechanism, so a successor never silently outlives the
  // Mission it replaces.
  const expiresAt = kernel.resolveEffectiveExpiry({
    requested: input.intent.expires_at,
    createdAt,
    ceilings: {
      predecessor: predecessor.expires_at,
      ...(input.approvedExtensionUntil
        ? { approvedExtensionUntil: input.approvedExtensionUntil }
        : {}),
      approvedUntil: input.approvedUntil,
    },
  });

  const id = input.successorId ?? newMissionId();
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
    eligibility_provenance: derived.provenance,
    // @spec child-delegation#fanout (#1304): the successor's own child-actor
    // origins, from the same fresh derivation.
    child_actor_provenance: derived.childActorProvenance,
    intent_hash: intentHash(predecessor.issuer, input.intent as never),
    ...(proposal ? { proposal_hash: proposalHash(predecessor.issuer, proposal as never) } : {}),
    ...(input.submissionEvidence?.length ? { submission_evidence: input.submissionEvidence } : {}),
    authority_hash: authorityHashValue,
    subject: predecessor.subject,
    approval_basis: approvalBasis,
    authority_source: authoritySource,
    client_id: predecessor.client_id,
    policy_version: predecessor.policy_version,
    approval_event_id: input.approvalEventId,
    created_at: createdAt,
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
  kernel.insertRecord(record, undefined, { source: resolvedSource });

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

/** A committed expansion deferral whose successor the remediation could not identify. */
export interface UnresolvedSuccessorProvenance {
  deferralCode: string;
  predecessorId: string;
  /** The client the deferral recorded as opening it. */
  clientId: string;
  reason: string;
}

/** What {@link revokeSuccessorsExpandedByAnotherClient} did. */
export interface SuccessorRemediation {
  /** The successors it revoked. */
  revoked: string[];
  /** Committed deferrals from another client that it did not act on. */
  unresolved: UnresolvedSuccessorProvenance[];
}

/**
 * @spec expansion#verification-order step 4 (#1349, D516): revoke every
 * non-terminal successor that a client other than its predecessor's own
 * created by polling a deferral before the poll check existed (#1326). Such a
 * successor carries the predecessor's client, so its own record cannot show
 * the defect; the retained committed deferral is the link. A successor is
 * identified only when the links agree: exactly one Mission carries the
 * deferral's predecessor and approval event, the predecessor's supersession
 * names it, it carries the predecessor's client, and no deferral the
 * predecessor's own client opened claims the same approval event. Anything
 * else is reported, never resolved to another Mission.
 *
 * Revocation is the ordinary lifecycle transition, after the expiry clock: the
 * predecessor stays superseded, a terminal successor keeps its recorded
 * termination, and the cascade reaches the successor's children. A later
 * successor its own client approved is not a target: only a deferral from
 * another client names one. Repeatable: a revoked successor is terminal, so a
 * later run commits nothing. A failed transition throws, so the caller does
 * not serve with a known live successor.
 */
export function revokeSuccessorsExpandedByAnotherClient(
  kernel: MissionKernel,
  deferrals: Pick<ExpansionDeferralStore, "retainedCommittedExpansions">,
): SuccessorRemediation {
  const committed = deferrals.retainedCommittedExpansions();
  const revoked: string[] = [];
  const unresolved: UnresolvedSuccessorProvenance[] = [];
  for (const op of committed) {
    const report = (reason: string): void => {
      unresolved.push({ deferralCode: op.deferralCode, predecessorId: op.predecessorId, clientId: op.clientId, reason });
    };
    const predecessor = kernel.get(op.predecessorId);
    if (!predecessor) {
      report("the predecessor record is missing");
      continue;
    }
    if (op.clientId === predecessor.client_id) continue;
    if (!op.approvalEventId) {
      report("the deferral records no approval event");
      continue;
    }
    const linked = kernel.successorsByApprovalEvent(predecessor.id, op.approvalEventId);
    const successor = linked[0];
    if (!successor || linked.length > 1) {
      report(successor ? "several successors carry the deferral's approval event" : "no successor carries the deferral's approval event");
      continue;
    }
    const termination = predecessor.termination;
    if (predecessor.state !== "terminated" || termination?.reason !== "superseded" || termination.successor !== successor.id) {
      report("the predecessor's supersession does not name the successor");
      continue;
    }
    if (successor.client_id !== predecessor.client_id) {
      report("the successor does not carry the predecessor's client");
      continue;
    }
    const ownClaim = committed.some(
      (other) =>
        other.predecessorId === predecessor.id &&
        other.approvalEventId === op.approvalEventId &&
        other.clientId === predecessor.client_id,
    );
    if (ownClaim) {
      report("a deferral the predecessor's own client opened claims the same approval event");
      continue;
    }
    if (TERMINAL_STATES.has(kernel.applyExpiry(successor).state)) continue;
    kernel.transition(successor.id, "revoke");
    revoked.push(successor.id);
  }
  return { revoked, unresolved };
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
