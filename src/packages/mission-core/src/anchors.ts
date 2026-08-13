/**
 * @spec mission#integrity-anchors
 * Integrity anchors per core § integrity-anchors: a domain-separated,
 * issuer-bound envelope { typ, iss, value }, JCS-canonicalized, SHA-256
 * hashed, encoded as "sha-256:" + base64url (no padding).
 */

import { createHash } from "node:crypto";
import { canonicalize, type JsonValue } from "./canonicalize.js";

export const INTENT_TYP = "mission-intent";
export const AUTHORITY_SET_TYP = "mission-authority-set";
/**
 * @spec mission#authority-proposal, mission#integrity-anchors
 * The integrity-anchor `typ` for the client-submitted authority proposal: the
 * `authorization_details` array pushed alongside `mission_intent`
 * (@spec mission#authority-proposal), committed exactly as recorded. The
 * resulting `proposal_hash` exists iff a proposal was submitted; a
 * template-mode Mission has none.
 */
export const PROPOSED_AUTHORITY_TYP = "mission-proposed-authority";
/**
 * @spec authzen#decision-evidence-object (`entry_digest`)
 * The integrity-anchor `typ` for a single Authority Set entry, so a decision
 * record can cite the entry it was evaluated against by digest via
 * {@link computeAnchor} (no change to `computeAnchor` is needed).
 */
export const AUTHORITY_ENTRY_TYP = "mission-authority-entry";
/**
 * @spec orchestration#unwind-plan-integrity
 * The integrity-anchor `typ` for a Mission unwind plan. The orchestration
 * profile hashes the unwind plan under this domain separator via
 * {@link computeAnchor}; the worked plan's published hash reproduces exactly
 * under the existing envelope (no change to `computeAnchor` is needed).
 */
export const UNWIND_PLAN_TYP = "mission-unwind-plan";
/**
 * @spec draft-mcguinness-oauth-mission-template
 * The integrity-anchor `typ` for a Mission Template: a human-consented ceiling +
 * dispatch policy + bounds. The template body is hashed under this domain
 * separator via {@link computeAnchor} (no change to `computeAnchor` is needed);
 * the resulting `template_hash` is carried on each dispatched instance's lineage.
 */
export const MISSION_TEMPLATE_TYP = "mission-template";
/**
 * @spec expansion#creation-request-id (shared by child-delegation)
 * The integrity-anchor `typ` for the creation-operation FINGERPRINT: the typed
 * object a Mission Issuer binds to a `creation_request_id` so a repetition of
 * the same Mission-creating operation (child creation / expansion) is
 * recognized and recovered rather than re-created. Hashed under this domain
 * separator via {@link computeAnchor} (no change to `computeAnchor` is needed).
 */
export const MISSION_CREATION_FINGERPRINT_TYP = "mission-creation-fingerprint";

export function computeAnchor(typ: string, iss: string, value: JsonValue): string {
  const envelope: JsonValue = { typ, iss, value };
  const canonical = canonicalize(envelope);
  const digest = createHash("sha256").update(canonical, "utf8").digest();
  return `sha-256:${digest.toString("base64url")}`;
}

/** Commits exactly the SEMANTIC Mission Intent: the `intent` member of the
 *  Mission Intent Submission envelope, never the envelope or its `evidence`
 *  array (so intent-bound evidence can name this hash without self-reference). */
export function intentHash(iss: string, intent: JsonValue): string {
  return computeAnchor(INTENT_TYP, iss, intent);
}

export function authorityHash(iss: string, authoritySet: JsonValue[]): string {
  return computeAnchor(AUTHORITY_SET_TYP, iss, authoritySet);
}

/**
 * @spec mission#authority-proposal — `proposal_hash`: the commitment over the
 * submitted `authorization_details` array exactly as recorded on the Mission.
 */
export function proposalHash(iss: string, proposedAuthority: JsonValue[]): string {
  return computeAnchor(PROPOSED_AUTHORITY_TYP, iss, proposedAuthority);
}

/**
 * Verifier rule (core § integrity-anchors): reject unrecognized algorithm
 * prefixes; never treat an unknown prefix as sha-256.
 */
export function verifyAnchor(anchor: string, typ: string, iss: string, value: JsonValue): boolean {
  if (!anchor.startsWith("sha-256:")) {
    throw new Error(`unrecognized anchor algorithm prefix: ${anchor.split(":")[0]}`);
  }
  return computeAnchor(typ, iss, value) === anchor;
}
