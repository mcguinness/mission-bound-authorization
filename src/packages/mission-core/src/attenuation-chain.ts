/**
 * @spec draft-mcguinness-oauth-mission-attenuation#mission-binding-check
 * @spec attenuation#attenuation
 *
 * Pure, keyless verifier for a Mission-bound Attenuating Agent Token (AAT)
 * chain. It checks the facts a consumer can establish from the presented
 * chain WITHOUT keys: capability monotonicity (child tools are a subset of
 * the parent's), the single unchanged `mission` binding across the chain,
 * audience and expiry nesting, the depth cap, and the `par_hash` linkage.
 *
 * Signature verification and proof-of-possession are the CONSUMER's job and
 * are keyed: the root is verified under the Mission Issuer's JWKS, each child
 * under the key its parent's `cnf` commits to (see services/mcp-payments).
 * Keeping this module keyless keeps its tests deterministic. It has no runtime
 * dependencies beyond node:crypto (used, as elsewhere in this package, for the
 * SHA-256 `par_hash` digest).
 */

import { createHash } from "node:crypto";
import { parseStrictJson } from "./strict-json.js";

/** JWS media type this profile uses for a Mission-bound AAT (root and child). */
export const AAT_TYP = "aat+jwt";
/** RFC 9396 authorization detail type carrying the AAT `tools` capability map. */
export const AAT_DETAIL_TYPE = "attenuating_agent_token";

export interface AATRangeConstraint {
  constraint_type: "range";
  min?: number;
  max?: number;
}
export interface AATEnumConstraint {
  constraint_type: "enum";
  values: string[];
}
export interface AATExactConstraint {
  constraint_type: "exact";
  value: string | number;
}
export type AATConstraint = AATRangeConstraint | AATEnumConstraint | AATExactConstraint;

/** A tool's argument constraints, keyed by argument name. */
export type AATToolArgs = Record<string, AATConstraint>;
/** The AAT capability map: tool identifier -> argument constraints. */
export type AATTools = Record<string, AATToolArgs>;

export interface AATMissionClaim {
  id: string;
  issuer: string;
  authority_hash: string;
}

export interface AATClaims {
  iss: string;
  sub?: string;
  aud: string | string[];
  exp: number;
  iat?: number;
  jti?: string;
  cnf: { jkt: string };
  del_depth: number;
  del_max_depth: number;
  par_hash?: string;
  mission?: AATMissionClaim;
  authorization_details: Array<{ type: string; tools?: AATTools }>;
}

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

/**
 * The AAT `tools` map of a token. Fail-closed: a token MUST carry exactly one
 * `attenuating_agent_token` authorization detail.
 */
export function toolsOf(claims: AATClaims): AATTools {
  const details = claims.authorization_details?.filter((d) => d.type === AAT_DETAIL_TYPE) ?? [];
  if (details.length !== 1) {
    throw new Error("expected exactly one attenuating_agent_token authorization detail");
  }
  return details[0]?.tools ?? {};
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
  if (parent.constraint_type === "enum" && child.constraint_type === "enum") {
    return child.values.every((v) => parent.values.includes(v));
  }
  if (parent.constraint_type === "exact" && child.constraint_type === "exact") {
    return child.value === parent.value;
  }
  return false; // fail-closed: unrecognized constraint kind
}

/**
 * @spec attenuation#attenuation — capability monotonicity. `child` is a subset
 * of `parent` when every child tool exists in the parent, every constraint the
 * parent placed on that tool is present on the child and at least as tight, and
 * the child adds no tool the parent lacks. A child MAY add further constraints
 * (further narrowing); it MUST NOT drop or loosen one, nor add a tool.
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

/**
 * @spec attenuation#mission-binding-check — every link carries the same
 * `mission` (`id`, `issuer`, `authority_hash`) as the root; a link that omits
 * it or differs refuses the whole chain.
 */
export function missionClaimInvariant(chain: readonly AATClaims[]): boolean {
  const root = chain[0]?.mission;
  if (!root) return false;
  return chain.every(
    (c) =>
      c.mission !== undefined &&
      c.mission.id === root.id &&
      c.mission.issuer === root.issuer &&
      c.mission.authority_hash === root.authority_hash,
  );
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

function decodeClaims(compact: string): AATClaims {
  const parts = compact.split(".");
  if (parts.length < 2 || !parts[1]) throw new Error("malformed JWS");
  const json = Buffer.from(parts[1], "base64url").toString("utf8");
  return parseStrictJson(json) as unknown as AATClaims;
}

export interface ChainVerifyOptions {
  /**
   * Maximum number of children (chain length minus the root) a consumer will
   * verify, independent of the `del_max_depth` the chain carries
   * (@spec attenuation#mission-binding-check). Default 8.
   */
  maxDepth?: number;
}

export type ChainVerifyResult =
  | { ok: true; leaf: AATClaims; chain: AATClaims[] }
  | { ok: false; reason: string };

/**
 * @spec attenuation#mission-binding-check — the keyless chain checks. Returns
 * the decoded leaf claims (its narrowed tools are the effective authority) on
 * success, or a machine-readable reason on refusal. Fails safe: any structural,
 * monotonicity, binding, nesting, depth, or linkage failure refuses the whole
 * chain rather than treating it as a narrower grant.
 */
export function verifyAttenuationChain(
  compactChain: readonly string[],
  opts: ChainVerifyOptions = {},
): ChainVerifyResult {
  if (compactChain.length === 0) return { ok: false, reason: "empty_chain" };
  const maxDepth = opts.maxDepth ?? 8;
  if (compactChain.length > maxDepth + 1) return { ok: false, reason: "chain_too_long" };

  let chain: AATClaims[];
  try {
    chain = compactChain.map(decodeClaims);
  } catch {
    return { ok: false, reason: "malformed_token" };
  }

  const root = chain[0];
  if (!root) return { ok: false, reason: "empty_chain" };
  // This profile only governs Mission-bound chains: a root with no `mission`
  // is an ordinary attenuation chain, outside this profile (kill switch N/A).
  if (!root.mission) return { ok: false, reason: "root_not_mission_bound" };
  if (root.del_depth !== 0) return { ok: false, reason: "root_depth_nonzero" };
  if (root.del_max_depth < 0) return { ok: false, reason: "invalid_max_depth" };
  if (!missionClaimInvariant(chain)) return { ok: false, reason: "mission_claim_mismatch" };

  for (let i = 1; i < chain.length; i++) {
    const parent = chain[i - 1] as AATClaims;
    const child = chain[i] as AATClaims;
    if (child.del_depth !== parent.del_depth + 1)
      return { ok: false, reason: "del_depth_not_incremented" };
    if (child.del_max_depth > parent.del_max_depth)
      return { ok: false, reason: "del_max_depth_raised" };
    if (child.del_depth > child.del_max_depth)
      return { ok: false, reason: "del_max_depth_exceeded" };
    if (child.par_hash !== parHash(compactChain[i - 1] as string)) {
      return { ok: false, reason: "par_hash_mismatch" };
    }
    let childTools: AATTools;
    let parentTools: AATTools;
    try {
      childTools = toolsOf(child);
      parentTools = toolsOf(parent);
    } catch {
      return { ok: false, reason: "malformed_authorization_details" };
    }
    if (!toolsSubset(childTools, parentTools)) return { ok: false, reason: "capability_widened" };
    if (!audNesting(child.aud, parent.aud)) return { ok: false, reason: "aud_widened" };
    if (!expNesting(child.exp, parent.exp)) return { ok: false, reason: "exp_exceeds_parent" };
  }

  return { ok: true, leaf: chain[chain.length - 1] as AATClaims, chain };
}
