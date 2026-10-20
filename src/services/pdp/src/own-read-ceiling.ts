/**
 * @spec runtime#state-freshness, authority-server#mission-join rule 2,
 * status#mission-status-caching (#818)
 *
 * Under `pdp` placement, the signed valid-through of the PDP's own read of
 * its declared state source: a Mission Status Response's `mission.fresh_until`.
 * "A permit issued from that state view MUST expire no later than this state
 * valid-through", so the decision feeds it into the same named ceiling a
 * PEP-carried signed assertion feeds (`signed_state_fresh_until`): a short
 * signed window never becomes a longer permit.
 */

import { rfc3339Ms } from "./state-observation.js";

/**
 * The own read's signed ceiling as epoch milliseconds; `"passed"` when it is
 * malformed or already at or before `nowMs` (no state is established from a
 * read that is no longer relied on); `undefined` when none was supplied.
 */
export function ownReadCeiling(stateFreshUntil: string | undefined, nowMs: number): number | "passed" | undefined {
  if (stateFreshUntil === undefined) return undefined;
  const atMs = rfc3339Ms(stateFreshUntil);
  if (atMs === undefined || atMs <= nowMs) return "passed";
  return atMs;
}
