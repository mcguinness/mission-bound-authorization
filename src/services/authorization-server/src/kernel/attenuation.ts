/**
 * @spec draft-mcguinness-oauth-mission-attenuation
 *
 * Mission-bound Attenuating Agent Token (AAT) roots and offline children, on
 * the -02 substrate wire (#1756, D882, D902, D904).
 *
 * A root is AS-minted: gated on Mission state at issuance (like
 * {@link issueCrossDomainGrant}), it carries the `mission` claim, the holder's
 * PUBLIC key as `cnf.jwk`, `aud`, `del_depth: 0`, an explicit `del_max_depth`,
 * and one `attenuating_agent_token` authorization detail whose `tools` and
 * `mission_constraints` are DERIVED from the Mission Authority Set by the
 * §root-mapping. Children are minted holder-side, offline, under the key the
 * parent's `cnf.jwk` binds: no Authorization Server contact.
 *
 * This is a standalone kernel module (mirrors kernel/cross-domain.ts); it is
 * not wired to an endpoint. The cross-organization root and child keep their
 * current wire ({@link mapAuthorityToTools}) until #1759 moves them to -02.
 */

import { randomBytes } from "node:crypto";
import {
  AAT_DEFAULT_PARAMS,
  AAT_DETAIL_TYPE,
  AAT_TYP,
  type AATToolArgs,
  type AATTools,
  type AatObject,
  type AttenuationOperations,
  aatConstraintMapAttenuationProblem,
  aatConstraintMapProblem,
  aatEntryOf,
  aatIsObject,
  aatJwkThumbprintUri,
  aatPublicJwkProblem,
  aatToolId,
  aatUuidV7,
  audNesting,
  canonicalize,
  credentialEntriesFromMissionAat,
  isCurrencyCode,
  isSubsetEntry,
  isValidAmount,
  type JsonValue,
  MISSION_CONSTRAINTS_MEMBER,
  type MissionConstraints,
  missionConstraintsNarrowingProblem,
  type MissionToolConstraints,
  missionToolEntry,
  parHash,
  parseAatJson,
  parseAatToolId,
  readMissionConstraints,
} from "@mission/core";
import { calculateJwkThumbprint, type CryptoKey, decodeJwt, exportJWK, type JWK, SignJWT } from "jose";
import { isSubsetSetIgnoringCapabilitySources } from "@mission/core";
import type { DerivationReservationResult } from "./derivation-reservations.js";
import type { MissionKernel } from "./kernel.js";
import { assertNotStandingPaymentLineage } from "./standing-payment.js";
import type { AuthorityEntry, MissionRecord } from "./types.js";

export { AAT_TYP };
export const MAX_ROOT_LIFETIME_S = 300;

/** An AAT `tools` map as the -02 wire carries it: tool identifier -> argument constraint map. */
export type AatToolMap = Record<string, Record<string, unknown>>;

/** The authority one Mission-bound token carries: its `tools` and their `mission_constraints`. */
export interface AttenuatedAuthority {
  tools: AatToolMap;
  missionConstraints: MissionConstraints;
}

/**
 * @spec attenuation#root-mapping (#1756, D902, D904): one tool the mapping
 * reaches, with the restrictions of each entry that maps to it. The argument
 * map comes from the operations alone, so it is the same for every entry;
 * the restrictions are kept per entry and never merged.
 */
interface CeilingTool {
  args: Record<string, unknown>;
  values: MissionToolConstraints[];
}

/**
 * @spec attenuation#root-mapping (#1276, D457): the tool identifier for one
 * action of `entry`, which carries the entry's whole target restriction, or
 * undefined. The identifier is `<resource>#<action>`, read back as an `exact`
 * entry naming that `resource`, so it carries an entry whose
 * `resource_match` is absent or `exact`. It cannot carry any other
 * `resource_match` (`prefix` included), nor a `resource` and action whose
 * identifier does not read back as that same pair (an action carrying `#`
 * moves the split).
 */
function carriedToolId(entry: AuthorityEntry, action: string): string | undefined {
  const match = (entry as { resource_match?: unknown }).resource_match;
  if (match !== undefined && match !== "exact") return undefined;
  const toolId = aatToolId(entry.resource, action);
  const carried = parseAatToolId(toolId);
  return carried.resource === entry.resource && carried.action === action ? toolId : undefined;
}

/**
 * @spec attenuation#root-mapping — a tool's argument constraint map: every
 * argument the operations declare, each admitted explicitly by a wildcard,
 * and no `"*"` entry. An argument is required only when every operation
 * declares it required; otherwise it is `optional`, which leaves its
 * requiredness to each operation's own definition.
 */
function argumentMap(operations: readonly { arguments: Readonly<Record<string, { required: boolean }>> }[]) {
  const names = new Set(operations.flatMap((op) => Object.keys(op.arguments)));
  const map: Record<string, unknown> = {};
  for (const name of [...names].sort()) {
    const required = operations.every((op) => Object.hasOwn(op.arguments, name) && op.arguments[name]?.required === true);
    map[name] = required ? { constraint_type: "wildcard" } : { constraint_type: "wildcard", optional: true };
  }
  return map;
}

/**
 * @spec attenuation#root-mapping (#1756, D902, D904): every tool the mapping
 * reaches and each mapping entry's restrictions for it. An entry maps to a
 * tool only where the resource server establishes what the mapping relies
 * on; otherwise that tool is omitted for that entry, never mapped with a
 * restriction removed:
 *
 * - the tool identifier carries the entry's whole target restriction
 *   ({@link carriedToolId});
 * - the resource server declares the operations the identifier names; and
 * - for every one of them it establishes each fact the entry's
 *   `constraints` restrict.
 */
function ceilingTools(
  entries: readonly AuthorityEntry[],
  operations: AttenuationOperations,
): Map<string, CeilingTool> {
  const out = new Map<string, CeilingTool>();
  for (const entry of entries) {
    const keys = Object.keys(entry.constraints ?? {});
    for (const action of entry.actions) {
      const toolId = carriedToolId(entry, action);
      if (toolId === undefined) continue;
      const ops = operations(entry.resource, action);
      if (ops === undefined || ops.length === 0) continue;
      if (!ops.every((op) => keys.every((k) => op.establishes.includes(k)))) continue;
      const value: MissionToolConstraints = {
        constraints: structuredClone((entry.constraints ?? {}) as Record<string, unknown>),
        ...(entry.resource_contract !== undefined
          ? { resource_contract: structuredClone(entry.resource_contract) as unknown as Record<string, unknown> }
          : {}),
      };
      const known = out.get(toolId);
      if (known === undefined) {
        out.set(toolId, { args: argumentMap(ops), values: [value] });
      } else if (!known.values.some((v) => canonicalize(v as unknown as JsonValue) === canonicalize(value as unknown as JsonValue))) {
        known.values.push(value);
      }
    }
  }
  return out;
}

/**
 * @spec attenuation#root-mapping (#1756, D902, D904) — the mapped ceiling: the
 * most a root derived from `entries` can carry. Each tool's argument
 * constraints name every argument its operations declare, each an explicit
 * wildcard; its `mission_constraints` value is the mapping entry's
 * `constraints` and `resource_contract`, unchanged. A tool takes its
 * restrictions from exactly one entry: a tool that two entries with
 * different restrictions map to is left out of the ceiling, never merged
 * (a request may still name it within one entry's restrictions,
 * {@link deriveAttenuationRoot}).
 */
export function mapAuthorityToCeiling(
  entries: readonly AuthorityEntry[],
  operations: AttenuationOperations,
): AttenuatedAuthority {
  const tools: AatToolMap = {};
  const missionConstraints: MissionConstraints = {};
  for (const [toolId, tool] of ceilingTools(entries, operations)) {
    const only = tool.values.length === 1 ? tool.values[0] : undefined;
    if (only === undefined) continue;
    tools[toolId] = tool.args;
    missionConstraints[toolId] = only;
  }
  return { tools, missionConstraints };
}

/**
 * @spec attenuation#request-discovery (#1756, D904): the issued root's
 * authority for a client-requested narrowing, which is exactly the request.
 * Every requested tool is in the mapped ceiling; its argument constraints
 * attenuate the ceiling's under the substrate's capability monotonicity; and
 * its `mission_constraints` value is within one mapping entry's restrictions
 * under the Resource Access subset rule (step 3, `resource_contract`
 * unchanged under step 4). A request with no value for a tool asks for the
 * ceiling's. Anything beyond the ceiling refuses the whole request, never
 * issues a root for the rest.
 */
function requestedWithinCeiling(
  ceiling: ReadonlyMap<string, CeilingTool>,
  requested: RequestedAuthority,
): AttenuatedAuthority {
  const beyond = (why: string): Error =>
    new Error(`attenuation: requested root exceeds the Mission Authority Set: ${why}`);
  const requestedMc = requested.missionConstraints ?? {};
  for (const toolId of Object.keys(requestedMc)) {
    if (!Object.hasOwn(requested.tools, toolId)) {
      throw beyond(`mission_constraints names ${JSON.stringify(toolId)}, which the requested tools do not`);
    }
  }
  const tools: AatToolMap = {};
  const missionConstraints: MissionConstraints = {};
  for (const [toolId, args] of Object.entries(requested.tools)) {
    const tool = ceiling.get(toolId);
    if (tool === undefined) throw beyond(`${JSON.stringify(toolId)} is not in the mapped ceiling`);
    const childMap = parseAatJson(JSON.stringify(args));
    if (!aatIsObject(childMap)) throw beyond(`the argument constraints for ${JSON.stringify(toolId)} are not an object`);
    const wellFormed = aatConstraintMapProblem(childMap, AAT_DEFAULT_PARAMS.maxConstraintDepth);
    if (wellFormed) throw beyond(`${JSON.stringify(toolId)}: ${wellFormed}`);
    const attenuates = aatConstraintMapAttenuationProblem(parseAatJson(JSON.stringify(tool.args)) as AatObject, childMap);
    if (attenuates) throw beyond(`${JSON.stringify(toolId)}: ${attenuates}`);
    const asked = Object.hasOwn(requestedMc, toolId) ? requestedMc[toolId] : undefined;
    let value: MissionToolConstraints;
    if (asked === undefined) {
      if (tool.values.length !== 1) {
        throw beyond(`${JSON.stringify(toolId)} maps from more than one entry; the request names no mission_constraints value`);
      }
      value = tool.values[0] as MissionToolConstraints;
    } else {
      // Shape-checked as a token's member is, then held within one entry's
      // restrictions: the tool takes them from that entry alone.
      value = readMissionConstraints({ tools: { [toolId]: args }, [MISSION_CONSTRAINTS_MEMBER]: { [toolId]: asked } })[
        toolId
      ] as MissionToolConstraints;
      const within = tool.values.some((v) => isSubsetEntry(missionToolEntry(toolId, value), missionToolEntry(toolId, v)));
      if (!within) throw beyond(`mission_constraints for ${JSON.stringify(toolId)} is not within the mapping entry's`);
    }
    Object.defineProperty(tools, toolId, { value: args, enumerable: true, writable: true, configurable: true });
    Object.defineProperty(missionConstraints, toolId, { value, enumerable: true, writable: true, configurable: true });
  }
  return { tools, missionConstraints };
}

/**
 * The checks a consumer applies to the authority a token carries (AAT -02
 * steps 3n and 4o, and `mission_constraints`), applied before signing so a
 * mint never emits a token its consumer refuses.
 */
function assertCarriable(authority: AttenuatedAuthority): void {
  for (const [toolId, args] of Object.entries(authority.tools)) {
    const map = parseAatJson(JSON.stringify(args));
    const problem = aatIsObject(map)
      ? aatConstraintMapProblem(map, AAT_DEFAULT_PARAMS.maxConstraintDepth)
      : "is not an object";
    if (problem) throw new Error(`attenuation: the argument constraints for ${JSON.stringify(toolId)}: ${problem}`);
  }
  const entry = { tools: authority.tools, [MISSION_CONSTRAINTS_MEMBER]: authority.missionConstraints };
  credentialEntriesFromMissionAat(authority.tools, readMissionConstraints(entry));
}

/**
 * @spec attenuation#root-mapping — forward map on the cross-organization
 * wire (#1759 moves it to -02): Authority Set -> AAT `tools`. Each (resource,
 * action) becomes one tool; the entry's Common Constraints become the tool's
 * argument constraints (`max_amount` -> `amount_<ccy>` as a range, `vendors`
 * -> `vendor` as a `one_of`). TOTAL and FAIL-CLOSED: an unrecognized
 * constraint name is rejected, never silently dropped.
 *
 * @spec attenuation#root-mapping, resource-access#resource-matching (#1276,
 * D457): the mapping preserves each entry's whole target restriction, for
 * every tool and every audience. The root carries no resource member, so
 * the restriction travels in the tool identifier: each tool names the
 * entry's `resource`, and the consumer matches the operation target against
 * that `resource` exactly, whatever the root's `aud`. An `aud` equal to the
 * entry's `resource` is never relied on. Where a tool identifier cannot
 * carry the restriction, the root is refused rather than minted without it
 * ({@link toolIdCarryingTarget}).
 */
export function mapAuthorityToTools(entries: readonly AuthorityEntry[]): AATTools {
  const tools: AATTools = {};
  for (const entry of entries) {
    const args = argsFromConstraints(entry.constraints);
    for (const action of entry.actions) {
      tools[toolIdCarryingTarget(entry, action)] = { ...args };
    }
  }
  return tools;
}

/**
 * @spec attenuation#root-mapping (#1276, D457): {@link carriedToolId} as a
 * refusal, for the cross-organization mapping: any other `resource_match`,
 * or a `resource` and action whose identifier does not read back as that
 * same pair, refuses the mapping.
 */
function toolIdCarryingTarget(entry: AuthorityEntry, action: string): string {
  const match = (entry as { resource_match?: unknown }).resource_match;
  if (match !== undefined && match !== "exact") {
    throw new Error(
      `attenuation root-mapping: resource_match ${JSON.stringify(match)} cannot be carried by a tool identifier; the entry is not mapped`,
    );
  }
  const toolId = carriedToolId(entry, action);
  if (toolId === undefined) {
    throw new Error(
      `attenuation root-mapping: the tool identifier for ${JSON.stringify(action)} at ${JSON.stringify(entry.resource)} does not carry that target; the entry is not mapped`,
    );
  }
  return toolId;
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
    // @spec mission#max-amount — reject a malformed cap rather than minting a
    // root whose `range.max` silently becomes NaN or an absurd magnitude: the
    // AAT `range` constraint's `max` is a JSON number by wire contract (a
    // separate concern from the decimal-string comparisons elsewhere on this
    // path), so the fix here is validating before the one-time numeric
    // conversion, not replacing it. A malformed max here would otherwise
    // become an effectively-unbounded ceiling downstream: NaN < NaN and
    // NaN > NaN are both false, so `constraintSubset`'s child.max > parent.max
    // check never fires.
    if (!isValidAmount(amount)) {
      throw new Error(`attenuation root-mapping: malformed max_amount value ${JSON.stringify(amount)}`);
    }
    // @spec resource-access#initial-common-constraints (#1595, D727): the
    // argument name carries the code in lower case, so only a well-formed
    // code is named.
    if (!isCurrencyCode(currency)) {
      throw new Error(`attenuation root-mapping: malformed max_amount currency ${JSON.stringify(currency)}`);
    }
    args[`amount_${currency.toLowerCase()}`] = {
      constraint_type: "range",
      max: Number.parseFloat(amount),
    };
  }
  if (constraints.vendors) {
    args.vendor = { constraint_type: "one_of", values: [...constraints.vendors] };
  }
  return args;
}

/**
 * @spec attenuation#root-mapping — reverse map on the cross-organization
 * wire: AAT `tools` -> Authority Set, one single-action entry per tool. The
 * currency is synthesized from the argument name (`amount_usd` -> `USD`) so
 * that {@link isSubsetEntry}'s currency hard-fail is meaningful when the
 * reverse-mapped entry is checked against the Mission's (USD) entry. TOTAL
 * and FAIL-CLOSED: an unrecognized argument name is rejected, never dropped.
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
      if (c.constraint_type !== "one_of") throw new Error("attenuation: 'vendor' must be a one_of constraint");
      constraints.vendors = [...c.values];
    } else if (name.startsWith("amount_")) {
      if (c.constraint_type !== "range" || c.max === undefined) {
        throw new Error("attenuation: amount_* must be a range constraint carrying max");
      }
      // The suffix is exactly three lower-case ASCII letters, mapped to the
      // upper-case code; any other suffix is refused, never folded (#1595, D727).
      const suffix = name.slice("amount_".length);
      const currency = /^[a-z]{3}$/.test(suffix) ? suffix.toUpperCase() : "";
      if (!isCurrencyCode(currency)) {
        throw new Error(`attenuation: amount_* argument ${JSON.stringify(name)} does not name a currency code`);
      }
      constraints.max_amount = { amount: String(c.max), currency };
    } else {
      throw new Error(`attenuation root-mapping: unknown tool argument '${name}'`);
    }
  }
  return Object.keys(constraints).length > 0 ? constraints : undefined;
}

/**
 * @spec attenuation#request-discovery — a client-requested root authority:
 * the `tools` and `mission_constraints` of the request's
 * `attenuating_agent_token` detail. A tool with no `mission_constraints`
 * value asks for the ceiling's.
 */
export interface RequestedAuthority {
  tools: AatToolMap;
  missionConstraints?: Record<string, MissionToolConstraints>;
}

export interface DeriveRootInput {
  missionId: string;
  /** The Resource Server(s) the root's authority is consumed at. */
  aud: string | string[];
  /** The acting client at the Mission Issuer. Emitted as `client_id`. */
  clientId: string;
  /**
   * @spec attenuation#root, attenuation#request-discovery: the holder's
   * PUBLIC key (Ed25519 OKP or P-256 EC), bound as the root's `cnf.jwk`. The
   * caller has verified the client possesses its private key (`req_cnf`). A
   * key carrying a private member is refused.
   */
  cnfJwk: JWK;
  /**
   * @spec attenuation#root-mapping: what each audience's resource server
   * declares about the operations a tool identifier names, and the facts it
   * establishes for them. A tool whose operations are not declared is not
   * mapped.
   */
  operations: AttenuationOperations;
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
   * Optional client-requested narrowing. When present it MUST be within the
   * mapped ceiling and the root carries exactly it; when absent the mapped
   * ceiling is carried.
   */
  requested?: RequestedAuthority;
  lifetimeSeconds?: number;
  /**
   * @spec control-plane#serialization — OPTIONAL durable operation identity.
   * When supplied, the counted derivation is reserved against it and a repeat
   * of the same identity REPLAYS the recorded artifact instead of counting a
   * second derivation. When omitted, the reservation is keyed by the artifact
   * identity alone, so the operation is reconcilable but not replayable.
   */
  operationId?: string;
}

/** A minted root: the compact token, its `jti`, and the authority it carries. */
export interface MintedRoot extends AttenuatedAuthority {
  root: string;
  jti: string;
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
): Promise<MintedRoot> {
  if (input.delMaxDepth !== undefined && input.delMaxDepth < 0) {
    throw new Error("attenuation: del_max_depth MUST be >= 0");
  }
  // @spec AAT -02 Section 8 step 3i: a consumer refuses a root whose
  // del_max_depth exceeds MAX_DELEGATION_DEPTH.
  if (input.delMaxDepth !== undefined && input.delMaxDepth > AAT_DEFAULT_PARAMS.maxDelegationDepth) {
    throw new Error(`attenuation: del_max_depth exceeds ${AAT_DEFAULT_PARAMS.maxDelegationDepth}`);
  }
  // @spec attenuation#root: the holder's key travels as a public `cnf.jwk`.
  // Refused before any count, as a request carrying it is refused.
  const keyProblem = aatPublicJwkProblem(input.cnfJwk);
  if (keyProblem) throw new Error(`attenuation: the holder key is not a supported public key: ${keyProblem}`);
  // @spec mission-template#prohibited-classes (#813, D830 ruling 3): an
  // attenuation root carries authority onward for offline delegation, which
  // a standing-payment lineage's budget accounting does not follow. Refused
  // before any count.
  const mission = kernel.get(input.missionId);
  if (mission) assertNotStandingPaymentLineage(kernel, mission, "an attenuation root");

  // @spec control-plane#serialization — the artifact identity is minted BEFORE
  // the count, so the counted derivation and the artifact it pays for share
  // one durable reservation. @spec AAT -02 Section 3.2: a UUIDv7 `jti`.
  const jti = aatUuidV7(kernel.nowDate().getTime());
  const operationId = input.operationId ?? jti;
  // A PENDING RESERVATION IS EXCLUSIVE: signing is asynchronous, so two callers
  // presenting one operation identity would otherwise both be admitted and mint
  // two distinct roots against one counted derivation. One owner runs; the
  // other awaits its outcome or recovers the recorded artifact.
  return kernel.exclusiveDerivation(input.missionId, operationId, () =>
    mintAttenuationRoot(kernel, signKey, kid, input, jti, operationId),
  );
}

async function mintAttenuationRoot(
  kernel: MissionKernel,
  signKey: CryptoKey,
  kid: string,
  input: DeriveRootInput,
  jti: string,
  operationId: string,
): Promise<MintedRoot> {
  // Derivation gate (D26 lifecycle): throws GateError when non-active/expired.
  // A recorded operation identity replays instead of counting again, and the
  // reservation is released on acceptance below.
  const admitted = kernel.reserveDerivation(input.missionId, {
    operationId,
    artifactId: jti,
  });
  const replayed = replayRoot(admitted.reservation);
  if (replayed) return replayed;
  const record: MissionRecord = admitted.record;

  // Containment: the root maps from the EFFECTIVE set (approved minus the
  // containment overlay); a contained capability never becomes an AAT tool.
  const effective = kernel.effectiveAuthoritySet(record);

  // @spec attenuation#root-mapping (S-15, closed): derive del_max_depth from the
  // Authority Set's delegation policy unless the caller supplies an override. A
  // client-requested narrowing is minted NON-delegating (del_max_depth 0):
  // deriving a depth over such a root would need the entries the requested
  // tools actually justify, which is fan-out accounting (deferred to the
  // kernel fan-out PR); a non-delegating root is fail-closed and can never let
  // a non-delegable requested tool ride a root whose depth exceeds 0. A
  // derived depth beyond MAX_DELEGATION_DEPTH is capped there, a narrowing.
  const delMaxDepth =
    input.delMaxDepth ??
    (input.requested ? 0 : Math.min(deriveDelMaxDepth(effective), AAT_DEFAULT_PARAMS.maxDelegationDepth));

  let authority: AttenuatedAuthority;
  if (input.requested) {
    authority = requestedWithinCeiling(ceilingTools(effective, input.operations), input.requested);
  } else {
    // Non-delegable entries MUST NOT ride a root whose del_max_depth exceeds 0.
    // On the DERIVED path, drop them so only delegable entries map (at depth 0
    // every entry may ride, so nothing is dropped). An explicit override never
    // drops: this profile's existing caller supplies a depth over a
    // delegation-free Authority Set and expects the full mapped tool set.
    const mappable =
      input.delMaxDepth === undefined && delMaxDepth > 0
        ? effective.filter((e) => e.delegation)
        : effective;
    authority = mapAuthorityToCeiling(mappable, input.operations);
  }
  assertCarriable(authority);

  const nowS = Math.floor(kernel.nowDate().getTime() / 1000);
  const missionExp = Math.floor(Date.parse(record.expires_at) / 1000);
  const exp = Math.min(nowS + (input.lifetimeSeconds ?? MAX_ROOT_LIFETIME_S), missionExp);
  if (!(exp > nowS)) throw new Error("attenuation: the Mission expires before a root could be used");

  const root = await new SignJWT({
    mission: { id: record.id, issuer: record.issuer, authority_hash: record.authority_hash },
    cnf: { jwk: input.cnfJwk },
    sub: record.subject.sub,
    client_id: input.clientId,
    del_depth: 0,
    del_max_depth: delMaxDepth,
    authorization_details: [
      { type: AAT_DETAIL_TYPE, tools: authority.tools, [MISSION_CONSTRAINTS_MEMBER]: authority.missionConstraints },
    ],
  })
    .setProtectedHeader({ alg: "ES256", kid, typ: AAT_TYP })
    .setIssuer(record.issuer)
    .setAudience(input.aud)
    .setIssuedAt(nowS)
    .setExpirationTime(exp)
    .setJti(jti)
    .sign(signKey);

  // @spec control-plane#serialization — artifact acceptance settles the
  // reservation. The completion material is retained only for a caller that
  // supplied its own operation identity, i.e. one that asked to be replayable.
  const minted: MintedRoot = { root, jti, tools: authority.tools, missionConstraints: authority.missionConstraints };
  kernel.releaseDerivation(admitted.reservation.reservation.reservationId, {
    artifactId: jti,
    ...(input.operationId ? { completion: JSON.stringify(minted) } : {}),
  });
  return minted;
}

/**
 * @spec control-plane#serialization — the REPLAY half of the counter's recovery
 * states: a recorded operation whose artifact was accepted returns that exact
 * artifact. A reservation with no retained completion is reconcilable but not
 * replayable, so the operation runs on (its count was already spent and is
 * never spent twice).
 */
function replayRoot(reservation: DerivationReservationResult): MintedRoot | undefined {
  if (reservation.kind !== "replay" || !reservation.reservation.completion) return undefined;
  return JSON.parse(reservation.reservation.completion) as MintedRoot;
}

export interface MintChildOptions {
  /**
   * The child holder's PUBLIC key (the minted child's `cnf.jwk`). Defaults to
   * the parent's, i.e. the same holder narrows for itself; pass a delegate's
   * key to hand the child to another holder.
   */
  cnfJwk?: JWK;
  /** Narrower audience (a subset of the parent's). Defaults to the parent's. */
  aud?: string | string[];
  /** Child `exp` (MUST NOT exceed the parent's). Defaults to the parent's. */
  exp?: number;
}

/** @spec AAT -02 Section 3.5: the JWS `alg` a holder key signs with. */
function holderAlg(jwk: JWK): "Ed25519" | "ES256" {
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519") return "Ed25519";
  if (jwk.kty === "EC" && jwk.crv === "P-256") return "ES256";
  throw new Error(`attenuation: unsupported holder key ${JSON.stringify(jwk.kty)}/${JSON.stringify(jwk.crv)}`);
}

/**
 * @spec attenuation#attenuation — holder-side, offline child mint. This is a
 * convenience helper, NOT the security boundary: a compromised holder never
 * calls it, so the consumer's verifier (`verifyAatPresentation` and the
 * Mission layer) is what actually bounds a child. It signs under the key
 * the PARENT's `cnf.jwk` binds (`parentKey`), with `alg` chosen by that
 * key's type and no header `jwk`: the consumer verifies the child under the
 * parent's `cnf.jwk`. `iss` is that key's JWK Thumbprint URI. The `mission`
 * claim rides through unchanged, and the child carries no `sub` or
 * `client_id`. It refuses a child its consumer would refuse as broader than
 * its parent.
 */
export async function mintChildOffline(
  parentToken: string,
  parentKey: CryptoKey,
  narrowed: AttenuatedAuthority,
  opts: MintChildOptions = {},
): Promise<string> {
  const parent = decodeJwt(parentToken) as Record<string, unknown>;
  const parentCnf = (parent.cnf as { jwk?: JWK } | undefined)?.jwk;
  const parentProblem = aatPublicJwkProblem(parentCnf);
  if (parentProblem) throw new Error(`attenuation: parent cnf.jwk: ${parentProblem}`);
  const { d: _d, ...signingPublic } = await exportJWK(parentKey);
  const alg = holderAlg(signingPublic as JWK);
  const iss = aatJwkThumbprintUri(parentCnf as JWK as Record<string, unknown>);
  if (aatJwkThumbprintUri(signingPublic as Record<string, unknown>) !== iss) {
    throw new Error("attenuation: the signing key is not the key the parent's cnf.jwk binds");
  }
  const cnfJwk = opts.cnfJwk ?? (parentCnf as JWK);
  const childProblem = aatPublicJwkProblem(cnfJwk);
  if (childProblem) throw new Error(`attenuation: child cnf.jwk: ${childProblem}`);

  // @spec attenuation#attenuation, attenuation#mission-constraints: the
  // child's tools attenuate its parent's, and its mission_constraints narrow
  // its parent's for every tool it keeps.
  const parentEntry = aatEntryOf(parent);
  const parentTools = parentEntry.tools as Record<string, unknown>;
  for (const [toolId, args] of Object.entries(narrowed.tools)) {
    if (!Object.hasOwn(parentTools, toolId)) {
      throw new Error(`attenuation: the child names ${JSON.stringify(toolId)}, which its parent does not`);
    }
    const problem = aatConstraintMapAttenuationProblem(
      parseAatJson(JSON.stringify(parentTools[toolId])) as AatObject,
      parseAatJson(JSON.stringify(args)) as AatObject,
    );
    if (problem) throw new Error(`attenuation: the child's ${JSON.stringify(toolId)} is broader than its parent's: ${problem}`);
  }
  assertCarriable(narrowed);
  const childMc = readMissionConstraints({
    tools: narrowed.tools,
    [MISSION_CONSTRAINTS_MEMBER]: narrowed.missionConstraints,
  });
  const narrowing = missionConstraintsNarrowingProblem(readMissionConstraints(parentEntry), childMc);
  if (narrowing) throw new Error(`attenuation: ${narrowing}`);

  const aud = opts.aud ?? (parent.aud as string | string[]);
  if (!audNesting(aud, parent.aud as string | string[])) {
    throw new Error("attenuation: the child aud is not within its parent's");
  }
  const exp = opts.exp ?? Number(parent.exp);
  if (exp > Number(parent.exp)) throw new Error("attenuation: the child exp is after its parent's");
  const delDepth = Number(parent.del_depth) + 1;
  if (delDepth > Number(parent.del_max_depth)) {
    throw new Error("attenuation: the parent's del_max_depth permits no further derivation");
  }
  const nowS = Math.floor(Date.now() / 1000);

  return new SignJWT({
    mission: parent.mission as Record<string, unknown>,
    cnf: { jwk: cnfJwk },
    del_depth: delDepth,
    del_max_depth: Number(parent.del_max_depth),
    par_hash: parHash(parentToken),
    authorization_details: [
      { type: AAT_DETAIL_TYPE, tools: narrowed.tools, [MISSION_CONSTRAINTS_MEMBER]: narrowed.missionConstraints },
    ],
    // @spec attenuation#mission-binding-check (#1758): no `sub` or
    // `client_id`. A holder-set identity claim carries no authority in a
    // derived token (AAT -02 Section 3.3); the consumer reads both from the root.
  })
    .setProtectedHeader({ alg, typ: AAT_TYP })
    .setIssuer(iss)
    .setAudience(aud)
    .setIssuedAt(nowS)
    .setExpirationTime(exp)
    .setJti(aatUuidV7())
    .sign(parentKey);
}


/**
 * @spec cross-org-delegation#root-issuance — mint a cross-organizational
 * attenuation root, on the cross-organization wire until #1759 moves it to
 * -02 (its tools come from {@link mapAuthorityToTools}, and it carries no
 * `mission_constraints`). Differences from {@link deriveAttenuationRoot}: the
 * presenter key travels as the full public `cnf.jwk` (a disconnected verifier
 * verifies the first child under it); the root carries the issuer-asserted
 * `act` naming the approved agent under the caller-resolved canonical actor
 * mapping (@spec cross-org-delegation#actor-identity: the Mission Record's
 * client_id is not itself an actor identity); and the `mission` claim carries
 * the origin principal `subject`. The mapping and its version are returned
 * for the caller to record in the issuance derivation record.
 */
export interface CrossOrgRootInput {
  missionId: string;
  aud: string | string[];
  clientId: string;
  /** The presenter's PUBLIC key, carried as cnf.jwk. */
  cnfJwk: JWK;
  /** The caller-resolved canonical actor for the approved client. */
  actor: { iss: string; sub: string; sub_profile?: string };
  /** The actor-mapping registry version, recorded in issuance evidence. */
  mappingVersion: string;
  requestedTools?: AATTools;
  lifetimeSeconds?: number;
  delMaxDepth?: number;
  /**
   * @spec control-plane#serialization — OPTIONAL durable operation identity.
   * When supplied, the counted derivation is reserved against it and a repeat
   * of the same identity REPLAYS the recorded artifact instead of counting a
   * second derivation. When omitted, the reservation is keyed by the artifact
   * identity alone, so the operation is reconcilable but not replayable.
   */
  operationId?: string;
}

export async function deriveCrossOrgRoot(
  kernel: MissionKernel,
  signKey: CryptoKey,
  kid: string,
  input: CrossOrgRootInput,
): Promise<{ root: string; jti: string; tools: AATTools; actorMapping: { client_id: string; actor: CrossOrgRootInput["actor"]; version: string } }> {
  // @spec mission-template#prohibited-classes (#813, D830 ruling 3): the
  // Mission Issuer refuses any cross-organization derivation from a
  // standing-payment lineage. Refused before any count.
  const mission = kernel.get(input.missionId);
  if (mission) assertNotStandingPaymentLineage(kernel, mission, "a cross-organization delegation root");
  // @spec control-plane#serialization — same reservation boundary as the
  // in-org root: artifact identity first, count and reservation together,
  // release on acceptance, and ONE in-flight owner per operation identity.
  const jti = `aat_root_${randomBytes(12).toString("base64url")}`;
  const operationId = input.operationId ?? jti;
  return kernel.exclusiveDerivation(input.missionId, operationId, () =>
    mintCrossOrgRoot(kernel, signKey, kid, input, jti, operationId),
  );
}

async function mintCrossOrgRoot(
  kernel: MissionKernel,
  signKey: CryptoKey,
  kid: string,
  input: CrossOrgRootInput,
  jti: string,
  operationId: string,
): Promise<{ root: string; jti: string; tools: AATTools; actorMapping: { client_id: string; actor: CrossOrgRootInput["actor"]; version: string } }> {
  const admitted = kernel.reserveDerivation(input.missionId, {
    operationId,
    artifactId: jti,
  });
  if (admitted.reservation.kind === "replay" && admitted.reservation.reservation.completion) {
    return JSON.parse(admitted.reservation.reservation.completion) as Awaited<
      ReturnType<typeof deriveCrossOrgRoot>
    >;
  }
  const record: MissionRecord = admitted.record;
  const effective = kernel.effectiveAuthoritySet(record);
  const delMaxDepth =
    input.delMaxDepth ?? (input.requestedTools ? 0 : deriveDelMaxDepth(effective));
  let tools: AATTools;
  if (input.requestedTools) {
    const requestedEntries = mapToolsToAuthority(input.requestedTools);
    if (!isSubsetSetIgnoringCapabilitySources(requestedEntries, effective)) {
      throw new Error("attenuation: requested root exceeds the Mission Authority Set");
    }
    tools = input.requestedTools;
  } else {
    const mappable = delMaxDepth > 0 ? effective.filter((e) => e.delegation) : effective;
    tools = mapAuthorityToTools(mappable);
  }
  const nowS = Math.floor(kernel.nowDate().getTime() / 1000);
  const missionExp = Math.floor(Date.parse(record.expires_at) / 1000);
  const exp = Math.min(nowS + (input.lifetimeSeconds ?? MAX_ROOT_LIFETIME_S), missionExp);
  const root = await new SignJWT({
    mission: {
      id: record.id,
      issuer: record.issuer,
      authority_hash: record.authority_hash,
      subject: { iss: record.subject.iss, sub: record.subject.sub },
    },
    cnf: { jwk: input.cnfJwk },
    act: { iss: input.actor.iss, sub: input.actor.sub, ...(input.actor.sub_profile ? { sub_profile: input.actor.sub_profile } : {}) },
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
  const actorMapping = {
    client_id: input.clientId,
    actor: input.actor,
    version: input.mappingVersion,
  };
  kernel.releaseDerivation(admitted.reservation.reservation.reservationId, {
    artifactId: jti,
    ...(input.operationId ? { completion: JSON.stringify({ root, jti, tools, actorMapping }) } : {}),
  });
  return { root, jti, tools, actorMapping };
}

/**
 * @spec cross-org-delegation#derivation — holder-side cross-organizational
 * child mint: signs under the PARENT cnf key, binds via par_hash, carries the
 * recipient's PUBLIC key as cnf.jwk, keeps the mission claim (including
 * subject) value-invariant, and names this hop's actor only when `actor` is
 * supplied (a named hop needs an aligned actor-binding credential in the
 * Presentation; a key-only hop omits act entirely).
 */
export async function mintCrossOrgChild(
  parentToken: string,
  parentKey: CryptoKey,
  narrowedTools: AATTools,
  opts: {
    cnfJwk: JWK;
    actor?: { iss: string; sub: string; sub_profile?: string };
    aud?: string | string[];
    exp?: number;
  },
): Promise<string> {
  const parent = decodeJwt(parentToken) as Record<string, unknown>;
  const { d: _d, ...parentPub } = await exportJWK(parentKey);
  const parentJkt = await calculateJwkThumbprint(parentPub as JWK);
  const nowS = Math.floor(Date.now() / 1000);
  const exp = opts.exp ?? Number(parent.exp);
  return new SignJWT({
    mission: parent.mission as Record<string, unknown>,
    cnf: { jwk: opts.cnfJwk },
    del_depth: Number(parent.del_depth) + 1,
    del_max_depth: Number(parent.del_max_depth),
    par_hash: parHash(parentToken),
    authorization_details: [{ type: AAT_DETAIL_TYPE, tools: narrowedTools }],
    ...(opts.actor ? { act: { iss: opts.actor.iss, sub: opts.actor.sub, ...(opts.actor.sub_profile ? { sub_profile: opts.actor.sub_profile } : {}) } } : {}),
    ...(typeof parent.sub === "string" ? { sub: parent.sub } : {}),
  })
    .setProtectedHeader({ alg: "ES256", typ: AAT_TYP })
    .setIssuer(`urn:ietf:params:oauth:jwk-thumbprint:sha-256:${parentJkt}`)
    .setAudience(opts.aud ?? (parent.aud as string | string[]))
    .setIssuedAt(nowS)
    .setExpirationTime(exp)
    .setJti(`aat_child_${randomBytes(9).toString("base64url")}`)
    .sign(parentKey);
}
