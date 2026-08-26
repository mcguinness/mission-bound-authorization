/**
 * @spec approval-governance#approval-context-manifest, approval-governance#approval-context-construction, approval-governance#approval-context-computation
 * The Approval Context Manifest (`mission-approval-context-v1`): a closed,
 * enumerated commitment over a Mission's immutable creation facts. Computed
 * on demand from Mission Record members; never persisted as a record member,
 * never cached authoritatively (approval-governance § approval-context-computation).
 */

import { computeAnchor } from "./anchors.js";
import type { JsonValue } from "./canonicalize.js";

export const APPROVAL_CONTEXT_TYP = "mission-approval-context-v1";
export const SUBMISSION_EVIDENCE_TYP = "mission-submission-evidence-v1";

export interface ApprovalContextManifestInput {
  issuer: string;
  id: string;
  intent_hash: string;
  proposal_hash?: string;
  authority_hash: string;
  ceiling_hash?: string;
  subject: JsonValue;
  approver: JsonValue;
  client_id: string;
  created_at: string;
  expires_at: string;
  approval_basis: JsonValue;
  authority_source: JsonValue;
  policy_version: string;
  approval_event_id: string;
  submission_evidence_commitment?: string;
}

/**
 * Builds the closed v1 manifest object (approval-governance § approval-context-manifest).
 * A conditional member is present iff the corresponding input field is
 * present; the result is a pure function of `input` alone, never of which
 * companion profiles the caller happens to have loaded
 * (approval-governance § approval-context-manifest, deterministic-presence).
 */
export function approvalContextManifest(
  input: ApprovalContextManifestInput,
): Record<string, JsonValue> {
  const manifest: Record<string, JsonValue> = {
    issuer: input.issuer,
    id: input.id,
    intent_hash: input.intent_hash,
    authority_hash: input.authority_hash,
    subject: input.subject,
    approver: input.approver,
    client_id: input.client_id,
    created_at: input.created_at,
    expires_at: input.expires_at,
    approval_basis: input.approval_basis,
    authority_source: input.authority_source,
    policy_version: input.policy_version,
    approval_event_id: input.approval_event_id,
  };
  if (input.proposal_hash !== undefined) manifest.proposal_hash = input.proposal_hash;
  if (input.ceiling_hash !== undefined) manifest.ceiling_hash = input.ceiling_hash;
  if (input.submission_evidence_commitment !== undefined) {
    manifest.submission_evidence_commitment = input.submission_evidence_commitment;
  }
  return manifest;
}

/** `approval_context_commitment`: the envelope anchor over the manifest (approval-governance § approval-context-construction). */
export function approvalContextCommitment(
  issuer: string,
  manifest: Record<string, JsonValue>,
): string {
  return computeAnchor(APPROVAL_CONTEXT_TYP, issuer, manifest);
}

/** `submission_evidence_commitment`: the envelope anchor over the retained `submission_evidence` array, exactly as recorded (approval-governance § approval-context-construction). */
export function submissionEvidenceCommitment(
  issuer: string,
  submissionEvidence: JsonValue[],
): string {
  return computeAnchor(SUBMISSION_EVIDENCE_TYP, issuer, submissionEvidence);
}

/**
 * Verifier rule (approval-governance § approval-context-computation): a
 * verifier recomputes `approval_context_commitment` from the Mission's
 * immutable creation facts, always under the fixed `typ`
 * `mission-approval-context-v1`, and rejects the artifact's reference on any
 * mismatch — including a value some other party committed under a
 * different `typ`, which recomputes to a different digest under this same
 * fixed-`typ` rule.
 */
export function verifyApprovalContextCommitment(
  disclosed: string,
  issuer: string,
  manifest: Record<string, JsonValue>,
): boolean {
  return approvalContextCommitment(issuer, manifest) === disclosed;
}
