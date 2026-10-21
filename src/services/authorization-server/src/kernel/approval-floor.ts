/**
 * @spec mission#approval-authentication (#826, D425) — the published
 * approval-authentication floor, evaluated over the complete derived
 * Authority Set at the approval decision.
 *
 * Every action of every derived entry is classified through the AS-owned
 * classification ({@link ApprovalFloorPolicy}), keyed by authority type,
 * resource and action; nothing the client sends (its goal, a proposal's
 * labels, the token projection) classifies authority. An admitted action the
 * classification does not name refuses: unclassified authority fails closed.
 * A class a floor `applies_to` invokes that floor, and every invoked floor
 * must hold (they are conjunctive).
 *
 * A floor is satisfied only by the achieved context of an Approver who
 * authenticated on the trusted browser approval surface: an `acr` the floor
 * accepts by exact match (no ordering among values) and an authentication
 * time that is not in the future and no older than the floor allows. A
 * headless approval service's registration is not an authentication of the
 * Approver, so a headless approval of floor-invoking authority refuses.
 *
 * Consumption bounds: this AS admits none. `derive()` refuses every
 * constraint key outside `SUPPORTED_CONSTRAINT_KEYS`, none of which is a
 * consumption bound, so no derived entry can carry one to classify.
 */

import { entryOverlapsResource, resourceWithin } from "@mission/core";
import type { ApprovalFloorClassification, ApprovalFloorPolicy } from "@mission/demo-data";
import type { AuthorityEntry } from "./types.js";

/**
 * @spec resource-access#subset, resource-access#resource-matching (#1440): the
 * classifications that apply to one derived entry, through the shared
 * matcher. A classification names a service identifier and classifies the
 * resource tree rooted there. An entry is classified only when one
 * classification contains its whole resource set: the entry is within the
 * classification's resource read as a `prefix` base, or, for an identifier
 * that is not a `//` base, names it exactly ({@link resourceWithin}). Every
 * classification whose tree overlaps the entry ({@link entryOverlapsResource})
 * then applies, so a `prefix` entry that reaches a finer classified resource
 * meets that classification as well. Undefined when no classification
 * contains the entry: its authority is unclassified.
 */
function classificationsFor(
  policy: ApprovalFloorPolicy,
  entry: AuthorityEntry,
): ApprovalFloorClassification[] | undefined {
  const sameType = policy.classification.filter((c) => c.type === entry.type);
  const contains = (c: ApprovalFloorClassification) =>
    resourceWithin(entry, { resource: c.resource, resource_match: "prefix" }) ||
    resourceWithin(entry, { resource: c.resource });
  if (!sameType.some(contains)) return undefined;
  return sameType.filter((c) => entryOverlapsResource(entry, c.resource));
}

/** The achieved authentication context the approval surface supplied. */
export interface AchievedApproverContext {
  acr?: unknown;
  auth_time?: unknown;
}

export type ApprovalFloorOutcome =
  /** No derived action invokes a floor. */
  | { outcome: "not_applicable" }
  /** Every invoked floor holds. */
  | { outcome: "satisfied"; floors: string[] }
  /** Refused before any Mission, Grant or code exists. */
  | { outcome: "refused"; reason: string };

/**
 * Classify every action of the derived entries, then evaluate each floor the
 * classes invoke against the Approver's achieved context.
 */
export function evaluateApprovalFloor(
  policy: ApprovalFloorPolicy,
  derived: readonly AuthorityEntry[],
  achieved: AchievedApproverContext,
  ctx: { interactive: boolean; nowSeconds: number },
): ApprovalFloorOutcome {
  const invoked = new Set<string>();
  for (const entry of derived) {
    const applicable = classificationsFor(policy, entry) ?? [];
    for (const action of entry.actions) {
      // Every applicable classification must name the action, and each class
      // it names invokes its floors: two classes for one action both bind
      // (the floors are conjunctive), and a classification silent on it
      // leaves that part of the entry's authority unclassified.
      const classes = applicable.map((c) => (Object.hasOwn(c.actions, action) ? c.actions[action] : undefined));
      if (classes.length === 0 || classes.includes(undefined)) {
        return {
          outcome: "refused",
          reason: `the approval-authentication floor's classification does not name ${action} at ${entry.resource}; unclassified authority is refused`,
        };
      }
      for (const cls of classes) {
        for (const floor of policy.floors) {
          if (cls !== undefined && floor.applies_to.includes(cls)) invoked.add(floor.id);
        }
      }
    }
  }
  if (invoked.size === 0) return { outcome: "not_applicable" };
  if (!ctx.interactive) {
    return {
      outcome: "refused",
      reason: "this authority invokes the approval-authentication floor, which only an Approver authenticated on the browser approval surface can satisfy; a headless approval service's registration is not that authentication",
    };
  }
  const acr = achieved.acr;
  const authTime = achieved.auth_time;
  if (typeof acr !== "string" || acr.length === 0 || typeof authTime !== "number" || !Number.isSafeInteger(authTime)) {
    return { outcome: "refused", reason: "the Approver's achieved authentication context is missing or malformed" };
  }
  if (authTime > ctx.nowSeconds) {
    return { outcome: "refused", reason: "the Approver's authentication time is in the future" };
  }
  const floors = policy.floors.filter((f) => invoked.has(f.id));
  for (const floor of floors) {
    if (!floor.accepted_acr.includes(acr)) {
      return { outcome: "refused", reason: `the Approver's achieved acr does not satisfy the ${floor.id} floor` };
    }
    if (ctx.nowSeconds - authTime > floor.max_authentication_age_seconds) {
      return { outcome: "refused", reason: `the Approver's authentication is older than the ${floor.id} floor allows` };
    }
  }
  return { outcome: "satisfied", floors: floors.map((f) => f.id) };
}
