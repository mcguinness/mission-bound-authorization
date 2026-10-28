/**
 * @spec draft-mcguinness-oauth-mission-attenuation#mission-binding-check
 * @spec attenuation#attenuation
 *
 * Shared helpers for Mission-bound Attenuating Agent Token (AAT) chains: the
 * tool-identifier encoding, `par_hash`, and the per-hop `aud` nesting rule.
 * A Mission-bound chain is verified by the -02 substrate
 * verifier (`aat-verify.ts`) with the Mission layer of `mission-aat.ts` on
 * top, and so is the cross-organization chain (`kernel/cross-org-chain.ts`,
 * #1759).
 */

import { createHash } from "node:crypto";

/** JWS media type this profile uses for a Mission-bound AAT (root and child). */
export const AAT_TYP = "aat+jwt";
/** RFC 9396 authorization detail type carrying the AAT `tools` capability map. */
export const AAT_DETAIL_TYPE = "attenuating_agent_token";

/**
 * @spec attenuation#root-mapping — the tool-id encoding shared by the kernel
 * mapping (which builds roots) and the consumer (which reads leaf authority):
 * a tool identifier is the (resource, action) pair joined by `#`. Resources
 * and actions in this deployment carry no `#`, so the split is unambiguous.
 */
export function aatToolId(resource: string, action: string): string {
  if (!resource || !action) throw new Error("aatToolId requires non-empty resource and action");
  return `${resource}#${action}`;
}

/** Inverse of {@link aatToolId}. Total: throws on anything it cannot split. */
export function parseAatToolId(toolId: string): { resource: string; action: string } {
  const i = toolId.lastIndexOf("#");
  if (i <= 0 || i >= toolId.length - 1) throw new Error(`unparseable AAT tool id: ${toolId}`);
  return { resource: toolId.slice(0, i), action: toolId.slice(i + 1) };
}

function audSet(aud: string | string[]): Set<string> {
  return new Set(Array.isArray(aud) ? aud : [aud]);
}

/** @spec attenuation#attenuation — child `aud` equals or is a subset of parent. */
export function audNesting(childAud: string | string[], parentAud: string | string[]): boolean {
  const p = audSet(parentAud);
  return [...audSet(childAud)].every((a) => p.has(a));
}

/**
 * @spec attenuation#attenuation — `par_hash` value: base64url (no padding) of
 * the SHA-256 digest of the parent token's JWS Signing Input. The Signing Input
 * is sliced from the wire bytes (`header.payload`), never re-serialized from
 * decoded claims.
 */
export function parHash(parentCompact: string): string {
  const signingInput = parentCompact.split(".").slice(0, 2).join(".");
  return createHash("sha256").update(signingInput, "ascii").digest("base64url");
}
