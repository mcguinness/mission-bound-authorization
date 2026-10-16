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

import type { ApprovalFloorPolicy } from "@mission/demo-data";
import type { AuthorityEntry } from "./types.js";

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
    const classes = policy.classification.find((c) => c.type === entry.type && c.resource === entry.resource);
    for (const action of entry.actions) {
      const cls = classes && Object.hasOwn(classes.actions, action) ? classes.actions[action] : undefined;
      if (cls === undefined) {
        return {
          outcome: "refused",
          reason: `the approval-authentication floor's classification does not name ${action} at ${entry.resource}; unclassified authority is refused`,
        };
      }
      for (const floor of policy.floors) {
        if (floor.applies_to.includes(cls)) invoked.add(floor.id);
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
