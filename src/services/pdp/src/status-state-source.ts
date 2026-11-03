/**
 * @spec runtime#state-freshness, authzen#pdp-request rule 1,
 * status#mission-status-caching (#818 slice 4b, D560; #1101, D293)
 *
 * A decision point that reads Mission state itself, over signed Mission
 * Status, where the deployment places its state source with the PDP
 * (`state_source.placement: "pdp"`). Each decision reads within its action
 * class's staleness window; a commit-phase decision reads the source now.
 * The observation point is the response's signed `iat`, never the time of
 * the fetch or of a cache hit, and the read's reliance bound (its signed
 * `fresh_until`, `exp`, the advertised `mission_max_stale_seconds` and, for
 * `active`, the Mission's `expires_at`) caps the permit (`stateFreshUntil`).
 * A read that establishes nothing leaves the decision no state, so it
 * denies `stale_state`: nothing the PEP forwarded stands in for it.
 */

import type { DecisionFn } from "./evaluate.js";
import type { MissionStatusResolver } from "./mission-status-resolver.js";
import type { MissionView } from "./policy-view.js";

const iso = (ms: number) => new Date(ms).toISOString();

/**
 * The decision point's own read of the Mission's issuer for every decision:
 * the view, the signed observation point and the signed valid-through it
 * decides on, replacing whatever the PEP forwarded. With no read, no state
 * option is given, so the decision denies `stale_state`.
 */
export function ownReadDecide(resolver: Pick<MissionStatusResolver, "resolve">): (inner: DecisionFn) => DecisionFn {
  return (inner) => async (request, options) => {
    const { stateObservedAt: _forwarded, stateFreshUntil: _signed, ...rest } = options;
    const ref = request.context.mission;
    if (ref === undefined) return inner(request, { ...rest, stateSourcePlacement: "pdp" });
    const bound = options.stalenessBound(request.context.action_class);
    const read = await resolver.resolve(
      { id: ref.id, issuer: ref.issuer },
      {
        fresh: request.context.action_phase === "commit",
        ...(bound.kind === "bounded" ? { maxAgeSeconds: bound.seconds } : {}),
      },
    );
    return inner(request, {
      ...rest,
      stateSourcePlacement: "pdp",
      ...(read.ok
        ? { view: read.view as MissionView, stateObservedAt: iso(read.observedAtMs), stateFreshUntil: iso(read.relianceBoundMs) }
        : {}),
    });
  };
}
