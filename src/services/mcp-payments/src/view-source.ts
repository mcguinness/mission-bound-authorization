/**
 * @spec authority-server#mission-join rule 2, authzen#failure-condition-coverage
 * (#818, D560)
 *
 * A remote Mission view source: the read a PEP makes, once and asynchronously,
 * when its Mission state source is reached over a network (a separated
 * MAS's signed Mission Status) rather than held in process. The PEP awaits
 * {@link MissionViewSource.prepare} at the start of each enforcement; every
 * synchronous view read after it (`loadView` in the enforcement itself, at
 * re-verification, when observing the effective digest, and when listing
 * tools) answers from what that read established, within its reliance
 * bounds, and fails closed once they lapse. A deployment that holds its
 * Mission records in process configures no source, and nothing here runs.
 */

import type { PropagatedMissionReference } from "@mission/core";
import { type MissionStatusResolver, type MissionView, type ResolvedMission, viewHoldsCommittedSet } from "@mission/pdp";
import type { LoadedView } from "./pep.js";

/**
 * Why the read established no view, in the PEP's refusal diagnostics.
 * `unknown_mission`: the source answered that it holds no such Mission, or
 * none this caller may see. `state_unavailable`: the source gave no answer
 * this PEP can rely on (unreachable, too slow, refused this deployment's
 * credential, a response that did not verify, or one past a reliance bound):
 * "Mission state not establishable at the PEP". Both carry the signed
 * Refusal Record's `state_unavailable`.
 */
export type ViewSourceRefusal = "unknown_mission" | "state_unavailable";

export type ViewPreparation = { ok: true } | { ok: false; refusal: ViewSourceRefusal };

export interface MissionViewSource {
  /** Read the referenced Mission from its remote source, so the synchronous `loadView` answers from this read. */
  prepare(ref: { id: string; issuer: string }): Promise<ViewPreparation>;
}

/**
 * The one remote read for this enforcement, or `undefined` when no source is
 * configured or the request names no usable reference: the credential's own
 * `mission` claim, else a well-formed propagated reference. Never refuses by
 * itself: the enforcement's existing checks run in their order, and only a
 * view miss reads {@link viewMissRefusal}.
 */
export async function prepareRequestView(
  source: MissionViewSource | undefined,
  credentialMission: { id: string; issuer: string } | undefined,
  propagated: PropagatedMissionReference | undefined,
): Promise<ViewPreparation | undefined> {
  if (source === undefined) return undefined;
  const ref = credentialMission ?? (propagated !== undefined && !("malformed" in propagated) ? propagated : undefined);
  if (ref === undefined) return undefined;
  return source.prepare({ id: ref.id, issuer: ref.issuer });
}

/**
 * Whether an action's absence from `view.authority_set` means it was never
 * granted, so that a hint to request it is honest (#818 slice 4b review).
 * An in-process loader supplies the committed set, with containment and
 * discharge carried as deltas, so absence is never-granted there. A remote
 * source's view is the effective projection (a Mission Status response
 * omits a contained or discharged entry, and another audience's entries):
 * absence there may be a deliberate narrowing, which is restored only through
 * Expansion. Such a view counts only where it proves it holds the full
 * committed set (`viewHoldsCommittedSet`, D335), the proof the PDP applies
 * to the credential bound.
 */
export function absenceMeansNeverGranted(source: MissionViewSource | undefined, view: MissionView): boolean {
  return source === undefined || viewHoldsCommittedSet(view);
}

/** The refusal for a view miss: the remote read's reason where it failed, else the in-process `unknown_mission`. */
export function viewMissRefusal(prepared: ViewPreparation | undefined): ViewSourceRefusal {
  return prepared !== undefined && !prepared.ok ? prepared.refusal : "unknown_mission";
}

const iso = (ms: number) => new Date(ms).toISOString();

/**
 * @spec status#mission-status-caching (#818 slice 4b; #1101): the PEP's
 * loaded view from a signed Mission Status read: the resolver's answer, with
 * the observation of the read that produced it (its signed `iat` and its
 * reliance bound), in `cached` mode.
 */
export function statusLoadedView(read: ResolvedMission): LoadedView {
  return {
    view: read.view as MissionView,
    observation: {
      state: read.view.state,
      version: read.view.version,
      mode: "cached",
      freshness_at: iso(read.observedAtMs),
      mission_status_issued_at: iso(read.observedAtMs),
      mission_status_expires_at: iso(read.relianceBoundMs),
    },
  };
}

/**
 * @spec authzen#failure-condition-coverage (#818 slice 4b; #1101): the PEP's
 * one read per enforcement, through a signed Mission Status resolver. A
 * Mission the issuer does not hold, or will not show this client, is
 * `unknown_mission`; every other failure leaves "Mission state not
 * establishable at the PEP", `state_unavailable`, including the issuer
 * refusing this client's own credential, for which no code of its own is
 * named.
 */
export function statusViewSource(resolver: Pick<MissionStatusResolver, "resolve">): MissionViewSource {
  return {
    prepare: async (ref) => {
      const read = await resolver.resolve(ref);
      if (read.ok) return { ok: true };
      return { ok: false, refusal: read.reason === "not_found" ? "unknown_mission" : "state_unavailable" };
    },
  };
}
