/**
 * @spec attenuation#mission-constraints, attenuation#mission-binding-check
 * (#1756, D902, D904)
 *
 * The Mission layer of a Mission-bound Attenuating Agent Token chain, applied
 * on top of the -02 substrate verifier ({@link verifyAatPresentation}). The
 * substrate permits a presentation; that alone never authorizes an
 * invocation. This layer checks what the substrate gives no authority:
 *
 * - the `mission` claim, carried unchanged by every token, on a root the
 *   Mission Issuer minted (`iss` equal to `mission.issuer` and to the trust
 *   anchor that verified it);
 * - the profile's per-hop `aud` nesting;
 * - the `mission_constraints` member of every token's `attenuating_agent_token`
 *   entry: required, exactly one value per tool, each value
 *   `{ constraints, resource_contract? }`, narrowed per hop under the Resource
 *   Access subset rule's steps 3 and 4. A missing member, value or
 *   restriction refuses the whole chain, and a key this enforcement point does
 *   not understand or cannot enforce refuses it too.
 *
 * The leaf's tools and `mission_constraints` become the credential authority
 * the PEP enforces against the facts it establishes ({@link parseCredentialAuthority}).
 */

import { randomBytes } from "node:crypto";
import type { AatVerifiedToken } from "./aat-verify.js";
import { AAT_DETAIL_TYPE, audNesting, parseAatToolId } from "./attenuation-chain.js";
import type { AuthorityEntry } from "./authority-entry.js";
import { isSubsetEntry } from "./authority-subset.js";
import {
  type CredentialAuthorityEntry,
  CredentialAuthorityError,
  parseCredentialAuthority,
} from "./credential-authority.js";

/** @spec attenuation#mission-constraints — the profile-defined member of the `attenuating_agent_token` entry. */
export const MISSION_CONSTRAINTS_MEMBER = "mission_constraints";

/** One tool's value in `mission_constraints`: the mapped entry's restrictions, unchanged or narrowed. */
export interface MissionToolConstraints {
  constraints: Record<string, unknown>;
  resource_contract?: Record<string, unknown>;
}

/** `mission_constraints`: one value per tool identifier of the entry's `tools`. */
export type MissionConstraints = Record<string, MissionToolConstraints>;

/** A Mission-layer refusal: the chain is refused whole, never read as a narrower grant. */
export class MissionAatError extends Error {}

/**
 * @spec attenuation#root-mapping (#1756, D902): what the resource server
 * declares about one operation a tool identifier (`resource#action`) names.
 * `arguments` are the operation's declared arguments, each required or not by
 * the operation's own definition; `establishes` lists the constraint keys
 * whose facts the resource server establishes for the operation.
 */
export interface AttenuationOperation {
  name: string;
  arguments: Readonly<Record<string, { required: boolean }>>;
  establishes: readonly string[];
}

/** The operations a tool identifier names, or undefined when the resource server declares none. */
export type AttenuationOperations = (
  resource: string,
  action: string,
) => readonly AttenuationOperation[] | undefined;

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/** The token's one `attenuating_agent_token` entry. */
export function aatEntryOf(claims: Record<string, unknown>): Record<string, unknown> {
  const details = Array.isArray(claims.authorization_details) ? claims.authorization_details : [];
  const entries = details.filter((d) => isObject(d) && d.type === AAT_DETAIL_TYPE);
  if (entries.length !== 1 || !isObject(entries[0])) {
    throw new MissionAatError("the token carries no single attenuating_agent_token entry");
  }
  return entries[0];
}

/**
 * @spec attenuation#mission-constraints — the entry's `mission_constraints`,
 * shape-checked against its `tools`: exactly one value per tool and no other
 * member, each value an object with a REQUIRED `constraints` object and an
 * optional `resource_contract` object, and nothing else.
 */
export function readMissionConstraints(entry: Record<string, unknown>): MissionConstraints {
  const tools = entry.tools;
  if (!isObject(tools))
    throw new MissionAatError("the attenuating_agent_token entry carries no tools");
  const member = entry[MISSION_CONSTRAINTS_MEMBER];
  if (!isObject(member))
    throw new MissionAatError("mission_constraints is missing or not an object");
  for (const toolId of Object.keys(tools)) {
    if (!Object.hasOwn(member, toolId)) {
      throw new MissionAatError(
        `mission_constraints carries no value for tool ${JSON.stringify(toolId)}`,
      );
    }
  }
  const out: MissionConstraints = {};
  for (const [toolId, value] of Object.entries(member)) {
    if (!Object.hasOwn(tools, toolId)) {
      throw new MissionAatError(
        `mission_constraints names ${JSON.stringify(toolId)}, which the entry's tools do not`,
      );
    }
    if (!isObject(value))
      throw new MissionAatError(`mission_constraints[${JSON.stringify(toolId)}] is not an object`);
    for (const k of Object.keys(value)) {
      if (k !== "constraints" && k !== "resource_contract") {
        throw new MissionAatError(
          `mission_constraints[${JSON.stringify(toolId)}].${k} is not understood`,
        );
      }
    }
    if (!isObject(value.constraints)) {
      throw new MissionAatError(
        `mission_constraints[${JSON.stringify(toolId)}].constraints is missing or not an object`,
      );
    }
    if (value.resource_contract !== undefined && !isObject(value.resource_contract)) {
      throw new MissionAatError(
        `mission_constraints[${JSON.stringify(toolId)}].resource_contract is not an object`,
      );
    }
    // defineProperty, so a tool identifier named __proto__ stays a member.
    Object.defineProperty(out, toolId, {
      value: {
        constraints: value.constraints,
        ...(value.resource_contract !== undefined
          ? { resource_contract: value.resource_contract }
          : {}),
      },
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return out;
}

/** The one-action Mission entry a tool's `mission_constraints` value describes. */
export function missionToolEntry(toolId: string, value: MissionToolConstraints): AuthorityEntry {
  const { resource, action } = parseAatToolId(toolId);
  return {
    type: "mission_resource_access",
    resource,
    actions: [action],
    ...(value.resource_contract !== undefined
      ? { resource_contract: value.resource_contract }
      : {}),
    ...(Object.keys(value.constraints).length > 0 ? { constraints: value.constraints } : {}),
  } as unknown as AuthorityEntry;
}

/**
 * @spec attenuation#mission-binding-check — the authority a token's tools and
 * `mission_constraints` grant, as credential entries the PEP enforces against
 * the facts it establishes. A constraint key this enforcement point does not
 * understand or cannot enforce, or a malformed value, throws: it is never
 * dropped.
 */
export function credentialEntriesFromMissionAat(
  tools: Record<string, unknown>,
  missionConstraints: MissionConstraints,
): readonly CredentialAuthorityEntry[] {
  const entries = Object.keys(tools).map((toolId) => {
    const value = missionConstraints[toolId];
    if (value === undefined)
      throw new MissionAatError(`no mission_constraints value for tool ${JSON.stringify(toolId)}`);
    return missionToolEntry(toolId, value);
  });
  try {
    return parseCredentialAuthority(entries);
  } catch (e) {
    if (e instanceof CredentialAuthorityError)
      throw new MissionAatError(`mission_constraints: ${e.message}`);
    throw e;
  }
}

/**
 * @spec attenuation#mission-constraints — why `child` does not narrow
 * `parent`, or undefined. For every tool the child keeps, its one-action
 * entry is a subset of the parent's under the Resource Access subset rule:
 * every parent constraint kept and no broader (step 3), the contract
 * unchanged (step 4).
 */
export function missionConstraintsNarrowingProblem(
  parent: MissionConstraints,
  child: MissionConstraints,
): string | undefined {
  for (const [toolId, value] of Object.entries(child)) {
    const p = Object.hasOwn(parent, toolId) ? parent[toolId] : undefined;
    if (p === undefined)
      return `mission_constraints names ${JSON.stringify(toolId)}, which its parent does not`;
    if (!isSubsetEntry(missionToolEntry(toolId, value), missionToolEntry(toolId, p))) {
      return `mission_constraints for ${JSON.stringify(toolId)} is not within its parent's`;
    }
  }
  return undefined;
}

/** The verified Mission layer of a chain: the binding and the leaf's authority. */
export interface MissionAatChain {
  mission: { id: string; issuer: string; authority_hash: string };
  credentialAuthority: readonly CredentialAuthorityEntry[];
}

/**
 * @spec attenuation#mission-binding-check (#1756, D902): the Mission layer
 * over a chain the substrate already verified, root first. Throws
 * {@link MissionAatError} for any failure, which refuses the whole chain.
 */
export function verifyMissionAatChain(
  chain: readonly AatVerifiedToken[],
  anchorIssuer: string,
): MissionAatChain {
  const root = chain[0];
  if (root === undefined) throw new MissionAatError("the chain is empty");
  const mission = root.claims.mission;
  if (
    !isObject(mission) ||
    typeof mission.id !== "string" ||
    mission.id.length === 0 ||
    typeof mission.issuer !== "string" ||
    mission.issuer.length === 0 ||
    typeof mission.authority_hash !== "string" ||
    mission.authority_hash.length === 0
  ) {
    throw new MissionAatError("the root carries no well-formed mission claim");
  }
  if (root.claims.iss !== mission.issuer || mission.issuer !== anchorIssuer) {
    throw new MissionAatError(
      "the root's iss is not its mission.issuer and the trust anchor's issuer",
    );
  }
  let parentMc = readMissionConstraints(aatEntryOf(root.claims));
  credentialEntriesFromMissionAat(
    aatEntryOf(root.claims).tools as Record<string, unknown>,
    parentMc,
  );
  if (!Object.hasOwn(root.claims, "aud")) throw new MissionAatError("the root carries no aud");
  let leafMc = parentMc;
  for (let i = 1; i < chain.length; i++) {
    const parent = chain[i - 1] as AatVerifiedToken;
    const child = chain[i] as AatVerifiedToken;
    const m = child.claims.mission;
    if (
      !isObject(m) ||
      m.id !== mission.id ||
      m.issuer !== mission.issuer ||
      m.authority_hash !== mission.authority_hash
    ) {
      throw new MissionAatError(`token ${i} does not carry the root's mission claim unchanged`);
    }
    // @spec attenuation#attenuation: the profile's per-hop rule; the
    // substrate checks every `aud` against the enforcement point (step 6c).
    if (
      !Object.hasOwn(child.claims, "aud") ||
      !audNesting(child.claims.aud as string | string[], parent.claims.aud as string | string[])
    ) {
      throw new MissionAatError(`token ${i} aud is not within its parent's`);
    }
    const entry = aatEntryOf(child.claims);
    const mc = readMissionConstraints(entry);
    credentialEntriesFromMissionAat(entry.tools as Record<string, unknown>, mc);
    const narrowing = missionConstraintsNarrowingProblem(parentMc, mc);
    if (narrowing !== undefined) throw new MissionAatError(`token ${i}: ${narrowing}`);
    parentMc = mc;
    leafMc = mc;
  }
  const leaf = chain[chain.length - 1] as AatVerifiedToken;
  return {
    mission: { id: mission.id, issuer: mission.issuer, authority_hash: mission.authority_hash },
    credentialAuthority: credentialEntriesFromMissionAat(leaf.tools, leafMc),
  };
}

/** @spec AAT -02 Section 3.2: a lowercase hyphenated UUIDv7 for a token `jti` (RFC 9562). */
export function aatUuidV7(nowMs: number = Date.now()): string {
  const b = randomBytes(16);
  const ms = BigInt(Math.floor(nowMs));
  for (let i = 0; i < 6; i++) b[i] = Number((ms >> BigInt(8 * (5 - i))) & 0xffn);
  b[6] = ((b[6] as number) & 0x0f) | 0x70;
  b[8] = ((b[8] as number) & 0x3f) | 0x80;
  const h = b.toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
