/**
 * @spec authzen#pdp-request consistency check 11, runtime-evidence#pre-decision-refusal
 * (#1276, D457): the PDP's own Refusal Record emission path, for a decision
 * request it refuses before evaluation (`operation_target_invalid`).
 *
 * Signed on the PDP's side of the emission boundary, under a key published
 * for the PDP's role, exactly as Decision Evidence is
 * (runtime#agent-isolated-evidence-emission, #741): an enforcement
 * component's evidence store cannot sign a `pdp`-role record. The signed
 * record goes to the deployment's retention sink; the refused request gets
 * no decision.
 */

import type { JsonValue } from "@mission/core";
import { evaluationRequestDigest, newRecordId } from "./decision-evidence.js";
import type { PdpRefusal, PdpRefusalRecorder } from "./evaluate.js";
import {
  type EvidenceEnvelope,
  type EvidenceSigningKey,
  REFUSAL_RECORD_MEDIA_TYPE,
  signEvidenceEnvelope,
} from "./runtime-evidence-integrity.js";

/** A signed PDP Refusal Record (@spec runtime-evidence#pre-decision-refusal). */
export interface PdpRefusalRecord {
  refusal_id: string;
  audience: string;
  action: { name: string };
  resource?: { type: string; id: string };
  decision: "deny";
  denial_reason: PdpRefusal["denial_reason"];
  evaluated_at: string;
  /** The refused request as submitted (@spec runtime-evidence#request-digest-worked). */
  evaluation_request_digest: string;
  request_digest_input: "decision_request";
  subject?: { id: string; properties?: { iss: string } };
  emitter: { id: string; role: "pdp" };
  evidence_envelope: EvidenceEnvelope;
}

export interface PdpRefusalRecorderConfig {
  /** The PDP's evidence signing key, published for `emitterId` in the `pdp` role and for `scope`. */
  signer: EvidenceSigningKey;
  emitterId: string;
  /**
   * The enforcement scope this PDP serves and its key is published for: the
   * record's `audience`, whatever audience string the refused request carried
   * (a request this PDP refuses may name none). @spec runtime#boundary-identifier,
   * runtime-evidence#pre-decision-refusal (#853, D487): a function receives
   * the refused request's `resource.properties.audience`, when it carried a
   * string, and returns the boundary identifier the PDP establishes from the
   * request of a PEP authorized for that boundary, so this producer follows
   * the version in force. `undefined` is a boundary the PDP cannot
   * establish: no record is made rather than one with an invented `audience`.
   */
  scope: string | ((requestAudience: string | undefined) => string | undefined);
  /** The deployment's retention sink for the signed record. */
  retain: (record: PdpRefusalRecord) => unknown;
  now?: () => Date;
}

/**
 * The {@link PdpRefusalRecorder} a decision point or the remote decision
 * channel is bound to. It names only what the PDP can attest (no Mission: a
 * refusal before evaluation establishes none), digests the request as
 * submitted, signs, and retains.
 */
export function createPdpRefusalRecorder(config: PdpRefusalRecorderConfig): PdpRefusalRecorder {
  return async (refusal) => {
    const audience = typeof config.scope === "function" ? config.scope(refusal.audience) : config.scope;
    if (audience === undefined) return;
    const unsigned = {
      refusal_id: newRecordId("ref"),
      audience,
      action: refusal.action ?? { name: "" },
      ...(refusal.resource !== undefined ? { resource: refusal.resource } : {}),
      decision: "deny" as const,
      denial_reason: refusal.denial_reason,
      evaluated_at: (config.now?.() ?? new Date()).toISOString(),
      evaluation_request_digest: evaluationRequestDigest(refusal.evaluation_request),
      request_digest_input: "decision_request" as const,
      ...(refusal.subject !== undefined ? { subject: refusal.subject } : {}),
      emitter: { id: config.emitterId, role: "pdp" as const },
    };
    const evidence_envelope = await signEvidenceEnvelope(
      unsigned as unknown as JsonValue,
      REFUSAL_RECORD_MEDIA_TYPE,
      config.signer,
    );
    await config.retain(Object.freeze({ ...unsigned, evidence_envelope }));
  };
}
