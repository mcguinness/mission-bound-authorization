/**
 * @spec draft-mcguinness-oauth-mission-attenuation#mission-binding-check
 * @spec attenuation#attenuation
 *
 * Shared helpers for Mission-bound Attenuating Agent Token (AAT) chains: the
 * tool-identifier encoding, `par_hash`, and the per-hop `aud` and `exp`
 * nesting rules. A Mission-bound chain is verified by the -02 substrate
 * verifier (`aat-verify.ts`) with the Mission layer of `mission-aat.ts` on
 * top. The cross-organization chain (`kernel/cross-org-chain.ts`, #1759) still
 * verifies its hops with {@link toolsSubset} until it moves to -02.
 */

import { createHash } from "node:crypto";

/** JWS media type this profile uses for a Mission-bound AAT (root and child). */
export const AAT_TYP = "aat+jwt";
/** RFC 9396 authorization detail type carrying the AAT `tools` capability map. */
export const AAT_DETAIL_TYPE = "attenuating_agent_token";

export interface AATRangeConstraint {
  constraint_type: "range";
  min?: number;
  max?: number;
}
/** @spec AAT -02 Section 3.4: `one_of`. No revision of the substrate defines `enum` (#1756). */
export interface AATOneOfConstraint {
  constraint_type: "one_of";
  values: string[];
}
export interface AATExactConstraint {
  constraint_type: "exact";
  value: string | number;
}
export type AATConstraint = AATRangeConstraint | AATOneOfConstraint | AATExactConstraint;

/** A tool's argument constraints, keyed by argument name. */
export type AATToolArgs = Record<string, AATConstraint>;
/** The AAT capability map: tool identifier -> argument constraints. */
export type AATTools = Record<string, AATToolArgs>;

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

/** One AAT constraint is a (narrowing) subset of another of the same kind. */
function constraintSubset(child: AATConstraint, parent: AATConstraint): boolean {
  if (child.constraint_type !== parent.constraint_type) return false;
  if (parent.constraint_type === "range" && child.constraint_type === "range") {
    if (parent.max !== undefined && (child.max === undefined || child.max > parent.max))
      return false;
    if (parent.min !== undefined && (child.min === undefined || child.min < parent.min))
      return false;
    return true;
  }
  if (parent.constraint_type === "one_of" && child.constraint_type === "one_of") {
    return child.values.every((v) => parent.values.includes(v));
  }
  if (parent.constraint_type === "exact" && child.constraint_type === "exact") {
    return child.value === parent.value;
  }
  return false; // fail-closed: unrecognized constraint kind
}

/**
 * @spec cross-org-delegation#derivation — capability monotonicity as the
 * cross-organization chain checks it today (#1759 moves it to -02): `child`
 * is a subset of `parent` when every child tool exists in the parent, every
 * constraint the parent placed on that tool is present on the child and at
 * least as tight, and the child adds no tool the parent lacks.
 */
export function toolsSubset(child: AATTools, parent: AATTools): boolean {
  for (const [toolId, childArgs] of Object.entries(child)) {
    const parentArgs = parent[toolId];
    if (parentArgs === undefined) return false; // widen: tool not in parent
    for (const [arg, parentC] of Object.entries(parentArgs)) {
      const childC = childArgs[arg];
      if (childC === undefined) return false; // dropped a parent constraint => broader
      if (!constraintSubset(childC, parentC)) return false;
    }
  }
  return true;
}

function audSet(aud: string | string[]): Set<string> {
  return new Set(Array.isArray(aud) ? aud : [aud]);
}

/** @spec attenuation#attenuation — child `aud` equals or is a subset of parent. */
export function audNesting(childAud: string | string[], parentAud: string | string[]): boolean {
  const p = audSet(parentAud);
  return [...audSet(childAud)].every((a) => p.has(a));
}

/** @spec attenuation#attenuation — child `exp` does not exceed parent `exp`. */
export function expNesting(childExp: number, parentExp: number): boolean {
  return childExp <= parentExp;
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
