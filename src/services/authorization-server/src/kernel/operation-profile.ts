/**
 * @spec txn-authorization#resource-challenge — the Operation Profile registry.
 *
 * A challenge's single `authorization_details` entry IS the operation. What it
 * means -- which action it names, which members are allowed to appear, what a
 * conforming entry looks like at all -- is the Challenge-Issuing Resource's
 * Operation Profile, identified by the entry's `type`. The Transaction
 * Authorization Server is not entitled to guess: reading `actions[0]` off an
 * unrecognized shape, or falling back to the human-readable `reason`, turns
 * DISPLAY text and unvalidated structure into authorization input.
 *
 * So a profile is registered per (Challenge-Issuing Resource, Operation
 * Profile version); it validates the COMPLETE entry and returns a typed
 * operation or a refusal, and an entry no registered profile reads is refused
 * at admission.
 *
 * @spec txn-authorization#resource-challenge (#249, D553): "A
 * `mission_resource_access` entry's `type` member is fixed and does not
 * version the Operation Profile: where the entry carries a
 * `resource_contract` reference, that reference names the version, and the
 * runtime profile's resolution of it decides admission and completion ...;
 * otherwise the version is the resource's current one at admission, which
 * the workflow records." The registry is keyed on the version, never on the
 * entry's `type`.
 *
 * VERSIONS ARE RETAINED: "a TAS MUST retain and recognize a superseded
 * Operation Profile version for as long as a pending workflow still
 * references it." {@link OperationProfileRegistry.supersede} removes a
 * resource's current version from ADMISSION eligibility while leaving it
 * resolvable for workflows already admitted under it: a pending workflow
 * completes on the version it recorded, and only NEW challenges are admitted
 * under the current one. Retention is what makes that hold without a second
 * registry.
 */

import { type JsonValue, type ResourceContractDeclarations, resourceContractViolation } from "@mission/core";
import { RESOURCE_CONTRACTS } from "@mission/demo-data";
import type { AuthorityEntry } from "./types.js";

/** The typed operation a profile resolves a conforming entry to. */
export interface ResolvedOperation {
  /** The single concrete action this operation authorizes. */
  action: string;
  /** The entry as the profile canonicalizes it. */
  canonicalDetails: AuthorityEntry;
}

export type OperationResolution =
  | { ok: true; operation: ResolvedOperation }
  | { ok: false; reason: string };

/** One Challenge-Issuing Resource's profile, at one Operation Profile version. */
export interface OperationProfile {
  /** The `authorization_details` `type` this profile reads; it does not version the profile. */
  type: string;
  /** The Operation Profile version this profile implements (#249). */
  version: string;
  /** Validate the COMPLETE entry against the challenge it arrived on. */
  resolve(entry: JsonValue, ctx: { resource: string }): OperationResolution;
}

/** The version an entry is admitted or completed under, and the operation it resolves to. */
export type ProfileResolution =
  | { ok: true; version: string; operation: ResolvedOperation }
  | { ok: false; reason: string; unknownProfile?: true };

function key(iss: string, version: string): string {
  return `${iss}|${version}`;
}

export class OperationProfileRegistry {
  /** The version each resource admits NEW challenges under. */
  private readonly current = new Map<string, OperationProfile>();
  /** Every version ever registered, including superseded ones. */
  private readonly retained = new Map<string, OperationProfile>();
  /**
   * The version a workflow admitted before versions were recorded resolves
   * under, keyed by the earlier pin (the challenge's `iss` and the entry's
   * `type`). Declared by the deployment; never inferred.
   */
  private readonly legacy = new Map<string, string>();

  /**
   * @param contracts the contract versions resources declare, whose
   * resolution decides admission and completion for an entry carrying a
   * `resource_contract` reference (#249). Defaults to the deployment's
   * statement (`RESOURCE_CONTRACTS`).
   */
  constructor(private readonly contracts: ResourceContractDeclarations = RESOURCE_CONTRACTS) {}

  /** Register `profile` as `iss`'s current version, retained from now on. */
  register(iss: string, profile: OperationProfile): this {
    this.current.set(iss, profile);
    this.retained.set(key(iss, profile.version), profile);
    return this;
  }

  /**
   * Retain `profile` for `iss` without making it the current version: a
   * version pending workflows may still reference, which no new challenge
   * is admitted under.
   */
  retain(iss: string, profile: OperationProfile): this {
    this.retained.set(key(iss, profile.version), profile);
    return this;
  }

  /**
   * @spec txn-authorization#resource-challenge (#249): the store upgrade's
   * binding. A workflow admitted before the store recorded Operation Profile
   * versions was pinned on the challenge's `iss` and the entry's `type`, the
   * key the earlier registry resolved to its then-current profile. This
   * declares the retained `version` that profile was, so such a workflow
   * completes under the profile it was admitted under, as the TAS retention
   * rule requires. It is declared, never inferred: without it the workflow's
   * completion is refused, and it is never read under today's version.
   */
  bindLegacyType(iss: string, type: string, version: string): this {
    this.legacy.set(key(iss, type), version);
    return this;
  }

  /**
   * Supersede a profile version: when it is `iss`'s current one, new
   * challenges are no longer admitted under it, while workflows already
   * admitted under it still resolve.
   */
  supersede(iss: string, version: string): void {
    if (this.current.get(iss)?.version === version) this.current.delete(iss);
  }

  /**
   * @spec txn-authorization#resource-challenge (#249): the version a NEW
   * challenge's entry is admitted under. A carried `resource_contract`
   * reference names it, and resolves under the resource's declarations or
   * is refused; otherwise the resource's current version, which the workflow
   * records.
   */
  admit(iss: string, entry: JsonValue, now: Date): ProfileResolution {
    const ref = (entry as { resource_contract?: unknown } | null)?.resource_contract;
    if (ref !== undefined) return this.underContract(iss, entry, ref, now);
    const profile = this.current.get(iss);
    if (!profile || profile.type !== (entry as { type?: unknown } | null)?.type) {
      return { ok: false, reason: "no Operation Profile governs this operation type", unknownProfile: true };
    }
    const resolved = profile.resolve(entry, { resource: iss });
    if (!resolved.ok) return { ok: false, reason: `operation rejected by its Operation Profile (${resolved.reason})` };
    return { ok: true, version: profile.version, operation: resolved.operation };
  }

  /**
   * The operation a workflow resolves to at completion, under the version it
   * recorded at admission, superseded or not. A carried reference is
   * resolved again: one that no longer resolves refuses completion.
   */
  complete(iss: string, version: string, entry: JsonValue, now: Date): ProfileResolution {
    const ref = (entry as { resource_contract?: unknown } | null)?.resource_contract;
    if (ref !== undefined) {
      const resolved = this.underContract(iss, entry, ref, now);
      if (resolved.ok && resolved.version !== version) {
        return { ok: false, reason: "the contract reference names another Operation Profile version than the one admitted" };
      }
      return resolved;
    }
    const profile = this.retained.get(key(iss, version));
    if (!profile) return { ok: false, reason: "the Operation Profile version this workflow was admitted under is not retained" };
    const resolved = profile.resolve(entry, { resource: iss });
    if (!resolved.ok) return { ok: false, reason: `operation rejected by its Operation Profile (${resolved.reason})` };
    return { ok: true, version, operation: resolved.operation };
  }

  /**
   * The operation a workflow admitted before versions were recorded resolves
   * to at completion: under the version {@link bindLegacyType} declares for
   * its `(iss, type)`, which must be retained and of that type. No binding,
   * an unretained version, or an entry carrying a `resource_contract` (the
   * earlier registry never admitted one) refuses with `terminal`: the
   * workflow's original binding cannot be established, so it is not read
   * under any other version.
   */
  completeLegacy(iss: string, type: string, entry: JsonValue): ProfileResolution & { terminal?: true } {
    const version = this.legacy.get(key(iss, type));
    const profile = version === undefined ? undefined : this.retained.get(key(iss, version));
    if (version === undefined || !profile || profile.type !== type) {
      return {
        ok: false,
        terminal: true,
        reason: "this workflow was admitted before Operation Profile versions were recorded, and no retained version is declared for its resource and type",
      };
    }
    if ((entry as { resource_contract?: unknown } | null)?.resource_contract !== undefined) {
      return { ok: false, terminal: true, reason: "a workflow admitted before versions were recorded never carried a resource_contract" };
    }
    const resolved = profile.resolve(entry, { resource: iss });
    if (!resolved.ok) return { ok: false, reason: `operation rejected by its Operation Profile (${resolved.reason})` };
    return { ok: true, version, operation: resolved.operation };
  }

  /**
   * @spec runtime#resource-contract: the version a reference names is the
   * profile its contract document names (`operation_profile`), read only
   * once the reference resolves for the operation at the challenging
   * resource: an unknown, retired, changed or out-of-retention reference,
   * or one naming a profile this TAS does not retain, refuses.
   */
  private underContract(iss: string, entry: JsonValue, ref: unknown, now: Date): ProfileResolution {
    const violation = resourceContractViolation(ref);
    if (violation !== undefined) return { ok: false, reason: violation };
    const declared = this.contracts.versionOf(ref);
    const version = declared?.version.operation_profile;
    const profile = version === undefined ? undefined : this.retained.get(key(iss, version));
    if (!profile || version === undefined) {
      return { ok: false, reason: "the resource_contract reference names no Operation Profile version this TAS retains" };
    }
    const resolvedOp = profile.resolve(entry, { resource: iss });
    if (!resolvedOp.ok) return { ok: false, reason: `operation rejected by its Operation Profile (${resolvedOp.reason})` };
    const resolution = this.contracts.resolve(ref, { target: iss, action: resolvedOp.operation.action, now });
    if (!resolution.ok) {
      return { ok: false, reason: `the resource_contract reference does not resolve (${resolution.reason})` };
    }
    return { ok: true, version, operation: resolvedOp.operation };
  }
}

/**
 * The members `mission_resource_access` defines. The check is CLOSED: an entry
 * carrying anything else is not this profile's operation, so an unrecognized
 * member can never ride into an approval as unread structure.
 */
const MISSION_RESOURCE_ACCESS_MEMBERS = new Set([
  "type",
  "resource",
  "actions",
  "constraints",
  // @spec resource-access#resource-contract (#249): the operation's contract
  // reference, which the registry resolves to the version before this
  // profile reads the entry; its shape is checked below.
  "resource_contract",
  // @spec attenuation#delegation — per-entry delegation policy travels with the
  // entry the challenge copied out of the Authority Set. It is a grant about
  // FURTHER delegation, not about this operation; the profile recognizes it so
  // a conforming entry is not rejected, and reads nothing from it.
  "delegation",
]);

/**
 * @spec mission#authority-set — the built-in profile for the family's own
 * `mission_resource_access` entry, read as an OPERATION: exactly one concrete
 * action, applying to the resource that issued the challenge, and no members
 * beyond the ones the type defines.
 *
 * One action, because the entry describes ONE challenged operation: an entry
 * naming several is not a narrower authority, it is an ambiguous operation, and
 * taking the first would authorize an action the approver never saw named.
 */
export function missionResourceAccessProfile(version = "mission-resource-access-1"): OperationProfile {
  return {
    type: "mission_resource_access",
    version,
    resolve(entry, ctx) {
      if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
        return { ok: false, reason: "entry is not an object" };
      }
      const e = entry as Record<string, JsonValue>;
      for (const member of Object.keys(e)) {
        if (!MISSION_RESOURCE_ACCESS_MEMBERS.has(member)) {
          return { ok: false, reason: `entry carries an unknown member ${member}` };
        }
      }
      if (e.type !== "mission_resource_access") return { ok: false, reason: "entry type mismatch" };
      if (typeof e.resource !== "string" || e.resource !== ctx.resource) {
        return { ok: false, reason: "entry does not apply to the challenging resource" };
      }
      const actions = e.actions;
      if (!Array.isArray(actions) || actions.length !== 1) {
        return { ok: false, reason: "an operation names exactly one action" };
      }
      const action = actions[0];
      if (typeof action !== "string" || action.trim() === "") {
        return { ok: false, reason: "action is not a concrete identifier" };
      }
      if (e.constraints !== undefined && (typeof e.constraints !== "object" || e.constraints === null)) {
        return { ok: false, reason: "constraints is not an object" };
      }
      if (e.resource_contract !== undefined) {
        const violation = resourceContractViolation(e.resource_contract);
        if (violation !== undefined) return { ok: false, reason: violation };
      }
      return {
        ok: true,
        operation: { action, canonicalDetails: e as unknown as AuthorityEntry },
      };
    },
  };
}
