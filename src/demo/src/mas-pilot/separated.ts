/**
 * @spec authority-server#mission-join rules 2 and 7, authority-server#join-disclosure,
 * runtime#state-freshness, status#mission-status-caching (#818 slice 4b, D560)
 *
 * The separated MAS pilot: the same estate, gateway, mapping contract,
 * Resource policy, PEP and decision point as `composeMasPilot`, with no
 * Mission kernel at all. The MAS runs elsewhere (its own process,
 * `mas-process.ts`), and the pilot knows it only by its URL and the key its
 * PDP authenticates with.
 *
 * - The PDP resolves each referenced Mission through the MAS's signed
 *   Mission Status (`MissionStatusResolver`), configured from what the MAS
 *   publishes: its metadata (`issuer`, `jwks_uri`, `mission_status_endpoint`,
 *   `mission_max_stale_seconds`) and its status-response key. It is the
 *   client `separated_mas.pdp_client_id` at that endpoint, authenticating by
 *   private-key JWT (#1407). The state source is placed with the PDP
 *   (`separated_mas.state_source.placement`).
 * - Each decision reads within its action class's staleness window
 *   (`maxAgeSeconds`); a commit-phase decision reads the source now
 *   (`fresh: true`). The observation point is the response's signed `iat`,
 *   never the time of the fetch or of a cache hit, and the read's reliance
 *   bound (its signed `fresh_until`, `exp`, the advertised ceiling and, for
 *   `active`, the Mission's `expires_at`) caps the permit (`stateFreshUntil`).
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
import { declaredStatusKeys, type MissionView, MissionStatusResolver, privateKeyJwtClient, type ResolvedMission } from "@mission/pdp";
import { importJWK, type JWK } from "jose";
import { assembleMasPilot, type MasPilotOptions, type MasPilotParts, type PdpDecide, requireDeclaredMappingContract } from "./compose.js";
import { loadMasPilotConfig, type MasPilotConfig } from "./config.js";

export interface SeparatedMasPilotOptions extends MasPilotOptions {
  /**
   * Where the MAS serves, and the private key (a JWK with its `kid`) this PDP
   * authenticates with at its Mission Status endpoint, as the client
   * `separated_mas.pdp_client_id`; the MAS holds the public half.
   */
  mas: { url: string; pdpKey: JWK };
  /** The resolver's clock. Defaults to `now`. */
  resolverNow?: () => Date;
  /** Override the advertised Status endpoint (a test points it at a proxy or a double). */
  statusEndpoint?: string;
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
      mission_status_expires_at: iso(read.relianceBoundMs),
    },
  };
}

/**
 * The decision point's own read of the MAS for every decision: the view, the
 * signed observation point and the signed valid-through it decides on,
 * replacing whatever the PEP forwarded. With no read, no state option is
 * given, so the decision denies `stale_state`.
 */
export function ownReadDecide(resolver: Pick<MissionStatusResolver, "resolve">): (inner: PdpDecide) => PdpDecide {
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

/**
 * The PEP's one read per enforcement, through the resolver. A Mission the MAS
 * does not hold, or will not show this PDP, is `unknown_mission`; every
 * other failure leaves "Mission state not establishable at the PEP"
 * (authzen#failure-condition-coverage), `state_unavailable`, including the
 * MAS refusing this PDP's own credential, for which the join rules name no
 * code of their own.
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

/** Assemble the separated pilot against a running MAS. `close()` releases what it opened; the MAS is the caller's. */
export async function composeSeparatedMasPilot(opts: SeparatedMasPilotOptions): Promise<SeparatedMasPilot> {
  const config: MasPilotConfig = opts.config ?? loadMasPilotConfig();
  requireDeclaredMappingContract(config);
  const source = config.separated_mas.state_source;
  const base = opts.mas.url.replace(/\/$/, "");
  // A launch's cancellation abandons these reads (#818 slice 5B review).
  const startup = opts.startup;
  const read = (url: string): Promise<unknown> => {
    const answer = fetch(url, startup ? { signal: startup.signal } : {}).then((r) => r.json());
    return startup ? startup.step(answer) : answer;
  };
  // Configured from what the MAS publishes, over HTTP.
  const metadata = (await read(`${base}/.well-known/openid-configuration`)) as {
    issuer: string;
    jwks_uri: string;
    mission_max_stale_seconds: number;
    mission_status_endpoint?: unknown;
  };
  if (metadata.issuer !== config.mission_issuer) {
    throw new Error(`the MAS at ${base} is issuer ${metadata.issuer}, not the configured Mission issuer ${config.mission_issuer}`);
  }
  // @spec status#mission-status, status#as-metadata (#1407): the endpoint the
  // MAS advertises, never a path guessed from its URL.
  if (typeof metadata.mission_status_endpoint !== "string") {
    throw new Error(`the MAS at ${base} advertises no mission_status_endpoint`);
  }
  const pdpKey = opts.mas.pdpKey;
  if (typeof pdpKey.kid !== "string" || pdpKey.d === undefined) throw new Error("the PDP's key is not a private JWK with a kid");
  const client = privateKeyJwtClient({
    clientId: config.separated_mas.pdp_client_id,
    issuer: metadata.issuer,
    privateKey: (await importJWK(pdpKey, pdpKey.alg ?? "ES256")) as CryptoKey,
    kid: pdpKey.kid,
    ...(pdpKey.alg ? { alg: pdpKey.alg } : {}),
    ...((opts.resolverNow ?? opts.now) ? { now: (opts.resolverNow ?? opts.now) as () => Date } : {}),
  });
  const jwks = (await read(metadata.jwks_uri)) as { keys: Record<string, unknown>[] };
  const resolverNow = opts.resolverNow ?? opts.now;
  const resolver = new MissionStatusResolver({
    issuer: metadata.issuer,
    statusEndpoint: opts.statusEndpoint ?? metadata.mission_status_endpoint,
    audience: CANONICAL_RESOURCE,
    keys: declaredStatusKeys(jwks as never, [TOPOLOGY.keys.asStatus.kid]),
    client,
    maxStaleSeconds: metadata.mission_max_stale_seconds,
    timeoutMs: source.timeout_ms,
    maxResponseBytes: source.max_response_bytes,
    ...(resolverNow ? { now: resolverNow } : {}),
  });
  const parts = await assembleMasPilot(opts, config, {
    missionIssuer: metadata.issuer,
    loadView: (ref: MissionReference) => {
      const read = resolver.peek(ref);
      return read ? loadedFrom(read) : undefined;
    },
    viewSource: statusViewSource(resolver),
    stateSourcePlacement: source.placement,
    decide: ownReadDecide(resolver),
  });
  return { ...parts, resolver };
}
