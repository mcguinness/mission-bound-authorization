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
 * So a profile is registered per (Challenge-Issuing Resource, `type`); it
 * validates the COMPLETE entry and returns a typed operation or a refusal, and
 * an unknown pair is refused at admission.
 *
 * VERSIONS ARE RETAINED. A resource versions its profile by versioning the
 * `type`. When it does, {@link OperationProfileRegistry.supersede} removes that
 * type from ADMISSION eligibility while leaving it resolvable for workflows
 * already admitted under it: a pending workflow completes on the version it was
 * admitted under, and only NEW challenges must speak the current one. Retention
 * is what makes that hold without a second registry.
 */

import type { JsonValue } from "@mission/core";
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

/** One Challenge-Issuing Resource's profile for one `authorization_details` type. */
export interface OperationProfile {
  /** The `authorization_details` `type` this profile governs. */
  type: string;
  /** Validate the COMPLETE entry against the challenge it arrived on. */
  resolve(entry: JsonValue, ctx: { resource: string }): OperationResolution;
}

function key(iss: string, type: string): string {
  return `${iss}|${type}`;
}

export class OperationProfileRegistry {
  /** Eligible for NEW admissions. */
  private readonly current = new Map<string, OperationProfile>();
  /** Every version ever registered, including superseded ones. */
  private readonly retained = new Map<string, OperationProfile>();

  register(iss: string, profile: OperationProfile): this {
    this.current.set(key(iss, profile.type), profile);
    this.retained.set(key(iss, profile.type), profile);
    return this;
  }

  /**
   * Retire a profile version: new challenges naming this type are refused,
   * while workflows already admitted under it still resolve.
   */
  supersede(iss: string, type: string): void {
    this.current.delete(key(iss, type));
  }

  /** The profile a NEW challenge's entry may be admitted under. */
  forAdmission(iss: string, type: string): OperationProfile | undefined {
    return this.current.get(key(iss, type));
  }

  /** The profile a workflow PINNED at admission, superseded or not. */
  forPinned(iss: string, type: string): OperationProfile | undefined {
    return this.retained.get(key(iss, type));
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
export function missionResourceAccessProfile(): OperationProfile {
  return {
    type: "mission_resource_access",
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
      return {
        ok: true,
        operation: { action, canonicalDetails: e as unknown as AuthorityEntry },
      };
    },
  };
}
