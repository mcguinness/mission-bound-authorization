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

export function computeAnchor(typ: string, iss: string, value: JsonValue): string {
  const envelope: JsonValue = { typ, iss, value };
  const canonical = canonicalize(envelope);
  const digest = createHash("sha256").update(canonical, "utf8").digest();
  return `sha-256:${digest.toString("base64url")}`;
}

export function intentHash(iss: string, intent: JsonValue): string {
  return computeAnchor(INTENT_TYP, iss, intent);
}

export function authorityHash(iss: string, authoritySet: JsonValue[]): string {
  return computeAnchor(AUTHORITY_SET_TYP, iss, authoritySet);
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
