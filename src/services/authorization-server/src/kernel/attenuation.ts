/**
 * @spec draft-mcguinness-oauth-mission-attenuation
 *
 * Mission-bound Attenuating Agent Token (AAT) roots and offline children.
 *
 * A root is AS-minted: gated on Mission state at issuance (like
 * {@link issueCrossDomainGrant}), it carries the `mission` claim, the holder's
 * confirmation key, `aud`, `del_depth: 0`, an explicit `del_max_depth`, and an
 * `attenuating_agent_token` authorization detail whose `tools` are DERIVED from
 * the Mission Authority Set by the §root-mapping. Children are minted holder-
 * side, offline, under the parent's `cnf` key: no Authorization Server contact.
 *
 * This is a standalone kernel module (mirrors kernel/cross-domain.ts); it is
 * not wired to an endpoint. It imports {@link isSubsetSet} read-only.
 */

import { randomBytes } from "node:crypto";
import {
  AAT_DETAIL_TYPE,
  AAT_TYP,
  type AATToolArgs,
  type AATTools,
  aatToolId,
  parHash,
  parseAatToolId,
} from "@mission/core";
import { calculateJwkThumbprint, type CryptoKey, decodeJwt, exportJWK, type JWK, SignJWT } from "jose";
import { isSubsetSet } from "./derive.js";
import type { MissionKernel } from "./kernel.js";
import type { AuthorityEntry, MissionRecord } from "./types.js";

export { AAT_TYP };
export const MAX_ROOT_LIFETIME_S = 300;

/**
 * @spec attenuation#root-mapping — forward map: Authority Set -> AAT `tools`.
 * Each (resource, action) becomes one tool; the entry's Common Constraints
 * become the tool's argument constraints (`max_amount` -> `amount_<ccy>` as a
 * range, `vendors` -> `vendor` as an enum). TOTAL and FAIL-CLOSED: an
 * unrecognized constraint name is rejected, never silently dropped.
 */
export function mapAuthorityToTools(entries: readonly AuthorityEntry[]): AATTools {
  const tools: AATTools = {};
  for (const entry of entries) {
    const args = argsFromConstraints(entry.constraints);
    for (const action of entry.actions) {
      tools[aatToolId(entry.resource, action)] = { ...args };
    }
  }
  return tools;
}

function argsFromConstraints(constraints: AuthorityEntry["constraints"]): AATToolArgs {
  const args: AATToolArgs = {};
  if (!constraints) return args;
  for (const key of Object.keys(constraints)) {
    if (key !== "max_amount" && key !== "vendors") {
      throw new Error(`attenuation root-mapping: unknown constraint '${key}'`);
    }
  }
  if (constraints.max_amount) {
    const { amount, currency } = constraints.max_amount;
    args[`amount_${currency.toLowerCase()}`] = {
      constraint_type: "range",
      max: Number.parseFloat(amount),
    };
  }
  if (constraints.vendors) {
    args.vendor = { constraint_type: "enum", values: [...constraints.vendors] };
  }
  return args;
}

/**
 * @spec attenuation#root-mapping — reverse map: AAT `tools` -> Authority Set,
 * one single-action entry per tool. The currency is synthesized from the
 * argument name (`amount_usd` -> `USD`) so that {@link isSubsetEntry}'s
 * currency hard-fail is meaningful when the reverse-mapped entry is checked
 * against the Mission's (USD) entry. TOTAL and FAIL-CLOSED: an unrecognized
 * argument name is rejected, never dropped.
 */
export function mapToolsToAuthority(tools: AATTools): AuthorityEntry[] {
  const entries: AuthorityEntry[] = [];
  for (const [toolId, args] of Object.entries(tools)) {
    const { resource, action } = parseAatToolId(toolId);
    const entry: AuthorityEntry = { type: "mission_resource_access", resource, actions: [action] };
    const constraints = constraintsFromArgs(args);
    if (constraints) entry.constraints = constraints;
    entries.push(entry);
  }
  return entries;
}

function constraintsFromArgs(args: AATToolArgs): AuthorityEntry["constraints"] | undefined {
  const constraints: NonNullable<AuthorityEntry["constraints"]> = {};
  for (const [name, c] of Object.entries(args)) {
    if (name === "vendor") {
      if (c.constraint_type !== "enum") throw new Error("attenuation: 'vendor' must be an enum constraint");
      constraints.vendors = [...c.values];
    } else if (name.startsWith("amount_")) {
      if (c.constraint_type !== "range" || c.max === undefined) {
        throw new Error("attenuation: amount_* must be a range constraint carrying max");
      }
      const currency = name.slice("amount_".length).toUpperCase();
      if (!currency) throw new Error("attenuation: amount_* argument missing a currency suffix");
      constraints.max_amount = { amount: String(c.max), currency };
    } else {
      throw new Error(`attenuation root-mapping: unknown tool argument '${name}'`);
    }
  }
  return Object.keys(constraints).length > 0 ? constraints : undefined;
}

export interface DeriveRootInput {
  missionId: string;
  /** The Resource Server(s) the root's authority is consumed at. */
  aud: string | string[];
  /** The acting client at the Mission Issuer. Emitted as `client_id`. */
  clientId: string;
  /** The holder's confirmation-key thumbprint (cnf.jkt). */
  cnfJkt: string;
  /**
   * @spec attenuation#root-mapping (S-15, closed): OPTIONAL override for
   * `del_max_depth`. When omitted, {@link deriveAttenuationRoot} DERIVES it from
   * the Authority Set's `delegation` policy (the non-delegable-by-default rule):
   * the minimum `max_depth` across the delegable entries, or 0 when none is
   * delegable. Kept as an override for back-compat with callers that set it
   * explicitly.
   */
  delMaxDepth?: number;
  /**
   * Optional client-requested narrowing, as an AAT `tools` map (the RFC 9396
   * `attenuating_agent_token` detail). When present it MUST be within the mapped
   * Authority Set; when absent the full mapped Authority Set is carried.
   */
  requestedTools?: AATTools;
  lifetimeSeconds?: number;
}

/**
 * @spec attenuation#root-mapping (S-15) — derive `del_max_depth` from the
 * Authority Set's `delegation` policy. A root's `del_max_depth` MUST NOT exceed
 * the minimum `max_depth` across the delegable entries (those carrying a
 * `delegation` member); entries carrying NO `delegation` are non-delegable by
 * default. When no entry is delegable the root is non-delegating (0).
 */
function deriveDelMaxDepth(entries: readonly AuthorityEntry[]): number {
  const depths = entries.flatMap((e) => (e.delegation ? [e.delegation.max_depth] : []));
  return depths.length === 0 ? 0 : Math.min(...depths);
}

/**
 * @spec attenuation#root — mint a Mission-bound attenuation root.
 * @spec attenuation#kill-switch — gated on Mission state at issuance via
 * {@link MissionKernel.gateDerivation}: after revocation the next root request
 * is refused (offline children still require the runtime state check on every
 * presentation; that is enforced by the consumer, not here).
 */
export async function deriveAttenuationRoot(
  kernel: MissionKernel,
  signKey: CryptoKey,
  kid: string,
  input: DeriveRootInput,
): Promise<{ root: string; jti: string; tools: AATTools }> {
  if (input.delMaxDepth !== undefined && input.delMaxDepth < 0) {
    throw new Error("attenuation: del_max_depth MUST be >= 0");
  }

  // Derivation gate (D26 lifecycle): throws GateError when non-active/expired.
  const record: MissionRecord = kernel.gateDerivation(input.missionId);

  // @spec attenuation#root-mapping (S-15, closed): derive del_max_depth from the
  // Authority Set's delegation policy unless the caller supplies an override. A
  // client-requested narrowing (requestedTools) is minted NON-delegating
  // (del_max_depth 0): deriving a depth over such a root would need the entries
  // the requested tools actually justify, which is fan-out accounting (deferred
  // to the kernel fan-out PR); a non-delegating root is fail-closed and can
  // never let a non-delegable requested tool ride a root whose depth exceeds 0.
  const delMaxDepth =
    input.delMaxDepth ?? (input.requestedTools ? 0 : deriveDelMaxDepth(record.authority_set));

  let tools: AATTools;
  if (input.requestedTools) {
    // Validate the requested narrowing is within the Mission Authority Set by
    // reverse-mapping to entries and reusing the issuance-profile subset rule.
    const requestedEntries = mapToolsToAuthority(input.requestedTools);
    if (!isSubsetSet(requestedEntries, record.authority_set)) {
      throw new Error("attenuation: requested root exceeds the Mission Authority Set");
    }
    tools = input.requestedTools;
  } else {
    // Non-delegable entries MUST NOT ride a root whose del_max_depth exceeds 0.
    // On the DERIVED path, drop them so only delegable entries map (at depth 0
    // every entry may ride, so nothing is dropped). An explicit override never
    // drops: this profile's existing caller supplies a depth over a
    // delegation-free Authority Set and expects the full mapped tool set.
    const mappable =
      input.delMaxDepth === undefined && delMaxDepth > 0
        ? record.authority_set.filter((e) => e.delegation)
        : record.authority_set;
    tools = mapAuthorityToTools(mappable);
  }

  const nowS = Math.floor(kernel.nowDate().getTime() / 1000);
  const missionExp = Math.floor(Date.parse(record.expires_at) / 1000);
  const exp = Math.min(nowS + (input.lifetimeSeconds ?? MAX_ROOT_LIFETIME_S), missionExp);
  const jti = `aat_root_${randomBytes(12).toString("base64url")}`;

  const root = await new SignJWT({
    mission: { id: record.id, issuer: record.issuer, authority_hash: record.authority_hash },
    cnf: { jkt: input.cnfJkt },
    sub: record.subject.sub,
    client_id: input.clientId,
    del_depth: 0,
    del_max_depth: delMaxDepth,
    authorization_details: [{ type: AAT_DETAIL_TYPE, tools }],
  })
    .setProtectedHeader({ alg: "ES256", kid, typ: AAT_TYP })
    .setIssuer(record.issuer)
    .setAudience(input.aud)
    .setIssuedAt(nowS)
    .setExpirationTime(exp)
    .setJti(jti)
    .sign(signKey);

  return { root, jti, tools };
}

export interface MintChildOptions {
  /**
   * The child holder's confirmation-key thumbprint (the minted child's
   * `cnf.jkt`). Defaults to the parent's, i.e. the same holder narrows for
   * itself; pass a delegate's thumbprint to hand the child to another key.
   */
  cnfJkt?: string;
  /** Narrower audience (a subset of the parent's). Defaults to the parent's. */
  aud?: string | string[];
  /** Child `exp` (MUST NOT exceed the parent's). Defaults to the parent's. */
  exp?: number;
}

/**
 * @spec attenuation#attenuation — holder-side, offline child mint. This is a
 * convenience helper, NOT the security boundary: a compromised holder never
 * calls it, so the consumer's verifier ({@link verifyAttenuationChain} plus the
 * keyed checks) is what actually bounds a child. It signs under the PARENT
 * `cnf` key (`parentKey`), embedding the parent public key as the JWS header
 * `jwk` whose thumbprint the consumer checks against the parent's `cnf.jkt`.
 * The `mission` claim rides through unchanged.
 */
export async function mintChildOffline(
  parentToken: string,
  parentKey: CryptoKey,
  narrowedTools: AATTools,
  opts: MintChildOptions = {},
): Promise<string> {
  const parent = decodeJwt(parentToken) as Record<string, unknown>;
  // Public JWK of the parent cnf key (strip any private component), embedded as
  // the child's JWS header `jwk`; the consumer checks its thumbprint == parent
  // cnf.jkt and verifies the child under it.
  const { d: _d, ...pubJwk } = await exportJWK(parentKey);
  const parentJkt = await calculateJwkThumbprint(pubJwk as JWK);
  const iss = `urn:ietf:params:oauth:jwk-thumbprint:sha-256:${parentJkt}`;

  const parentCnf = parent.cnf as { jkt?: string } | undefined;
  const cnfJkt = opts.cnfJkt ?? parentCnf?.jkt;
  if (!cnfJkt) throw new Error("attenuation: parent token missing cnf.jkt");
  const nowS = Math.floor(Date.now() / 1000);
  const exp = opts.exp ?? Number(parent.exp);

  return new SignJWT({
    mission: parent.mission as Record<string, unknown>,
    cnf: { jkt: cnfJkt },
    del_depth: Number(parent.del_depth) + 1,
    del_max_depth: Number(parent.del_max_depth),
    par_hash: parHash(parentToken),
    authorization_details: [{ type: AAT_DETAIL_TYPE, tools: narrowedTools }],
    ...(typeof parent.sub === "string" ? { sub: parent.sub } : {}),
    ...(typeof parent.client_id === "string" ? { client_id: parent.client_id } : {}),
  })
    .setProtectedHeader({ alg: "ES256", typ: AAT_TYP, jwk: pubJwk as JWK })
    .setIssuer(iss)
    .setAudience(opts.aud ?? (parent.aud as string | string[]))
    .setIssuedAt(nowS)
    .setExpirationTime(exp)
    .setJti(`aat_child_${randomBytes(9).toString("base64url")}`)
    .sign(parentKey);
}
