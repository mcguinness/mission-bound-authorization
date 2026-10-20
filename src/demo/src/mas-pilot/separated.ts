/**
 * @spec authority-server#mission-join rules 2 and 7, authority-server#join-disclosure,
 * runtime#state-freshness, status#mission-status-caching (#818 slice 4b, D560)
 *
 * The separated MAS pilot: the same estate, gateway, mapping contract,
 * Resource policy, PEP and decision point as `composeMasPilot`, with no
 * Mission kernel at all. The MAS runs elsewhere (its own process,
 * `mas-process.ts`), and the pilot knows it only by its URL and the
 * credential its PDP presents.
 *
 * - The PDP resolves each referenced Mission through the MAS's signed
 *   Mission Status (`MissionStatusResolver`), configured from what the MAS
 *   publishes: its metadata (`issuer`, `jwks_uri`,
 *   `mission_max_stale_seconds`) and its status-response key. The state
 *   source is placed with the PDP (`separated_mas.state_source.placement`).
 * - Each decision reads within its action class's staleness window
 *   (`maxAgeSeconds`); a commit-phase decision reads the source now
 *   (`fresh: true`). The observation point is the response's signed `iat`,
 *   never the time of the fetch or of a cache hit, and the signed
 *   `fresh_until` caps the permit (`stateFreshUntil`).
 * - A read that establishes nothing leaves the PDP no state: it denies
 *   `stale_state` under `pdp` placement (authzen#pdp-request rule 1).
 * - The PEP awaits one read at the start of each enforcement
 *   (`viewSource`), from the same resolver; its synchronous reads then
 *   answer from that resolver's cache within its bounds (`peek`). The PDP's
 *   non-commit read answers from the same cache under its own window.
 * - The Authority Set is the audience-scoped Status response's effective set
 *   (rule 7), so an entry contained or discharged at the MAS is absent: the
 *   action it covered denies `out_of_authority`, where the in-process pilot,
 *   which reads the containment and discharge deltas, denies
 *   `authority_contained` or `authority_discharged`.
 */

import { TOPOLOGY } from "@mission/demo-data";
import { CANONICAL_RESOURCE, type LoadedView, type MissionReference, type MissionViewSource } from "@mission/mcp-payments";
import { declaredStatusKeys, type MissionView, MissionStatusResolver, type ResolvedMission } from "@mission/pdp";
import { assembleMasPilot, type MasPilotOptions, type MasPilotParts, type PdpDecide } from "./compose.js";
import { loadMasPilotConfig, type MasPilotConfig } from "./config.js";

export interface SeparatedMasPilotOptions extends MasPilotOptions {
  /** Where the MAS serves, and the credential this PDP presents to its Mission Status. */
  mas: { url: string; pdpToken: string };
  /** The resolver's clock. Defaults to `now`. */
  resolverNow?: () => Date;
  /** Override the Status URL (a test points it at a proxy or a double). */
  statusUrl?: (encodedMissionId: string) => string;
}

/** The separated pilot: everything `composeMasPilot` assembles, and no kernel. */
export interface SeparatedMasPilot extends MasPilotParts {
  resolver: MissionStatusResolver;
}

const iso = (ms: number) => new Date(ms).toISOString();

/** The PEP's loaded view: the resolver's answer, with the observation of the read that produced it. */
function loadedFrom(read: ResolvedMission): LoadedView {
  return {
    view: read.view as MissionView,
    observation: {
      state: read.view.state,
      version: read.view.version,
      mode: "cached",
      freshness_at: iso(read.observedAtMs),
      mission_status_issued_at: iso(read.observedAtMs),
      mission_status_expires_at: iso(read.freshUntilMs),
    },
  };
}

/**
 * The decision point's own read of the MAS for every decision: the view, the
 * signed observation point and the signed valid-through it decides on,
 * replacing whatever the PEP forwarded. With no read, no state option is
 * given, so the decision denies `stale_state`.
 */
function ownReadDecide(resolver: MissionStatusResolver): (inner: PdpDecide) => PdpDecide {
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
        ? { view: read.view as MissionView, stateObservedAt: iso(read.observedAtMs), stateFreshUntil: iso(read.freshUntilMs) }
        : {}),
    });
  };
}

/** Assemble the separated pilot against a running MAS. `close()` releases what it opened; the MAS is the caller's. */
export async function composeSeparatedMasPilot(opts: SeparatedMasPilotOptions): Promise<SeparatedMasPilot> {
  const config: MasPilotConfig = opts.config ?? loadMasPilotConfig();
  const source = config.separated_mas.state_source;
  const base = opts.mas.url.replace(/\/$/, "");
  // Configured from what the MAS publishes, over HTTP.
  const metadata = (await (await fetch(`${base}/.well-known/openid-configuration`)).json()) as {
    issuer: string;
    jwks_uri: string;
    mission_max_stale_seconds: number;
  };
  if (metadata.issuer !== config.mission_issuer) {
    throw new Error(`the MAS at ${base} is issuer ${metadata.issuer}, not the configured Mission issuer ${config.mission_issuer}`);
  }
  const jwks = (await (await fetch(metadata.jwks_uri)).json()) as { keys: Record<string, unknown>[] };
  const resolverNow = opts.resolverNow ?? opts.now;
  const resolver = new MissionStatusResolver({
    issuer: metadata.issuer,
    statusUrl: opts.statusUrl ?? ((id) => `${base}/missions/${id}/status`),
    audience: CANONICAL_RESOURCE,
    keys: declaredStatusKeys(jwks as never, [TOPOLOGY.keys.asStatus.kid]),
    serviceToken: opts.mas.pdpToken,
    maxStaleSeconds: metadata.mission_max_stale_seconds,
    timeoutMs: source.timeout_ms,
    maxResponseBytes: source.max_response_bytes,
    ...(resolverNow ? { now: resolverNow } : {}),
  });
  const viewSource: MissionViewSource = {
    prepare: async (ref) => {
      const read = await resolver.resolve(ref);
      if (read.ok) return { ok: true };
      return { ok: false, refusal: read.reason === "not_found" ? "unknown_mission" : "state_unavailable" };
    },
  };
  const parts = await assembleMasPilot(opts, config, {
    missionIssuer: metadata.issuer,
    loadView: (ref: MissionReference) => {
      const read = resolver.peek(ref);
      return read ? loadedFrom(read) : undefined;
    },
    viewSource,
    stateSourcePlacement: source.placement,
    decide: ownReadDecide(resolver),
  });
  return { ...parts, resolver };
}
