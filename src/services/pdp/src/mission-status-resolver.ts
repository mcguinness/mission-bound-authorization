/**
 * @spec authority-server#mission-join rule 2, authority-server#join-disclosure,
 * status#mission-status-response, status#mission-status-caching (#818)
 *
 * The PDP's own read of a remote Mission state source: the signed Mission
 * Status operation of the Mission's issuer, over HTTP, with no handle on the
 * issuer's store. "The PDP MUST resolve the referenced Mission through the
 * MAS's Mission Status operation" and treat the MAS as the Mission state
 * source, failing closed when state cannot be established.
 *
 * - One verifier. A response is verified by
 *   {@link verifyMissionStatusResponse}, the same function the PEP-carried
 *   `assertion` is verified by: the Status media type, a declared key, `iss`,
 *   `aud` equal to this PDP's enforcement scope, `exp`, the requested Mission
 *   under that issuer, and a signed `fresh_until`. This module adds only what
 *   its own read needs: the request's `nonce` echoed, an `iat` not in the
 *   future and a `fresh_until` not already passed, a recognized `state`, and
 *   the members the view is built from.
 * - Not checked: the envelope `sub`. Status consumer check 6 has it name the
 *   requesting client, but the reference authorization server signs the
 *   Mission's own client there; requiring check 6 would refuse every response
 *   that server serves, so the resolver relies on `aud`, `nonce` and the
 *   authenticated request instead, and the divergence is reported for a ruling.
 * - Authenticated. The request carries this PDP's service credential with the
 *   `mission_status` grant, as the reference authorization server's Status
 *   route requires (`x-service-token`); that route is a `GET` with the
 *   Mission in the path and `audience` and `nonce` as query parameters.
 * - Bounded. One deadline covers connecting, the headers and the body; the
 *   body is read through a byte cap, and a redirect is never followed, so the
 *   credential never leaves for another origin.
 * - Fail closed. Every failure is a typed result, never a throw, and never
 *   cached: no negative entry outlives the request that met it.
 * - Cached within the signed bounds. An answer is reused, keyed on the
 *   Mission under this resolver's one issuer and enforcement scope, only
 *   while every bound holds: before its signed `fresh_until` (no skew
 *   allowance, for any state), within `iat` plus the issuer's advertised
 *   `mission_max_stale_seconds`, and within the caller's own `maxAgeSeconds`
 *   (its action class's staleness window). `fresh: true` bypasses the cache
 *   and reads the source now. An older observation never replaces a newer one.
 *
 * The view: `authorization_details` is the audience-scoped EFFECTIVE set the
 * issuer projects, so it carries no containment or discharge delta; an entry
 * contained or discharged at the issuer is simply absent, and an action it
 * covered is outside the Authority Set. Each entry's recorded `delegation` is
 * mapped to `join_delegation` by {@link deriveJoinDelegation}, the same
 * adapter the in-process loader uses. `subject` and `client_id` are present
 * exactly when the issuer disclosed them (Join Disclosure): to a caller it has
 * not enrolled for this enforcement scope it discloses neither, and the view
 * then carries neither.
 */

import { randomUUID } from "node:crypto";
import { createLocalJWKSet, type JSONWebKeySet, type JWTVerifyGetKey } from "jose";
import { deriveJoinDelegation, type KernelDelegationPolicy } from "./mas-join.js";
import type { AuthorityEntry, MissionView } from "./policy-view.js";
import { verifyMissionStatusResponse } from "./state-observation.js";

/** @spec status#mission-status-errors: the states a Mission Status Response reports. */
export const MISSION_STATUS_STATES: ReadonlySet<string> = new Set(["active", "suspended", "terminated"]);

/** @spec status#mission-status-caching: the consumer's clock-skew allowance, seconds. */
export const MISSION_STATUS_SKEW_SECONDS = 30;

/**
 * The Mission as this PDP's Status read established it: the members a
 * Mission Status Response carries, with `subject` and `client_id` only where
 * the issuer disclosed them, and no containment or discharge delta.
 */
export type StatusMissionView = Omit<MissionView, "subject" | "client_id" | "containment" | "discharged"> & {
  subject?: { iss: string; sub: string };
  client_id?: string;
};

export interface ResolvedMission {
  ok: true;
  view: StatusMissionView;
  /** The signed observation point (`iat`), epoch milliseconds: when the issuer observed this state. */
  observedAtMs: number;
  /** The signed `mission.fresh_until`, epoch milliseconds. */
  freshUntilMs: number;
  /** Whether this answer was read from the source for this call, or reused from the cache. */
  source: "fetched" | "cached";
}

/**
 * Why no state was established. `unavailable`: no usable answer arrived (a
 * transport failure, the deadline, a body over the cap, a redirect, or a
 * status other than 200, 401, 403 and 404). `unauthorized`: the issuer
 * refused this PDP's credential (401 or 403). `not_found`: the issuer's
 * anti-oracle not-found, or a reference naming another issuer.
 * `unverifiable`: a response arrived and did not verify or did not carry a
 * usable view.
 */
export type MissionStatusFailure = "unavailable" | "unauthorized" | "not_found" | "unverifiable";

export interface UnresolvedMission {
  ok: false;
  reason: MissionStatusFailure;
  /** A diagnostic naming the check that failed; never parsed. */
  detail: string;
}

export type MissionStatusResolution = ResolvedMission | UnresolvedMission;

export interface MissionStatusResolverOptions {
  /** The Mission issuer this resolver reads: the only `issuer` a reference resolves under, and the expected `iss`. */
  issuer: string;
  /** The Status operation's URL for one Mission. */
  statusUrl: (missionId: string) => string;
  /** This PDP's enforcement scope: the request's `audience` and the response's expected `aud`. */
  audience: string;
  /** The issuer's published status-response keys, restricted to the declared ones ({@link declaredStatusKeys}). */
  keys: JWTVerifyGetKey;
  /** This PDP's credential at the Status operation, holding the `mission_status` grant. */
  serviceToken: string;
  /** The issuer's advertised `mission_max_stale_seconds`. */
  maxStaleSeconds: number;
  /** The deadline for one read, connection to last body byte, milliseconds. */
  timeoutMs: number;
  /** The largest response body read, bytes. */
  maxResponseBytes: number;
  /** The resolver's clock. Defaults to the system clock. */
  now?: () => Date;
  /** The HTTP client. Defaults to the global `fetch`. */
  fetch?: typeof fetch;
}

export interface ResolveOptions {
  /** Read the source now, whatever the cache holds (a commit-phase decision). */
  fresh?: boolean;
  /** The longest the caller relies on an observation, seconds (its class's staleness window). */
  maxAgeSeconds?: number;
}

/**
 * The status-response keys an issuer publishes at its `jwks_uri`, restricted
 * to the declared key identifiers: a key the issuer publishes for another
 * purpose (its access-token key, say) never verifies a Status response.
 */
export function declaredStatusKeys(jwks: JSONWebKeySet, kids: readonly string[]): JWTVerifyGetKey {
  return createLocalJWKSet({ keys: jwks.keys.filter((k) => typeof k.kid === "string" && kids.includes(k.kid)) });
}

const fail = (reason: MissionStatusFailure, detail: string): UnresolvedMission => ({ ok: false, reason, detail });

const isRecord = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

/** A recorded `delegation` member the join adapter can map, or `undefined` for anything else. */
function delegationOf(value: unknown): KernelDelegationPolicy | undefined {
  if (!isRecord(value)) return undefined;
  if (!Number.isSafeInteger(value.max_depth) || (value.max_depth as number) < 0) return undefined;
  if (value.allowed_delegates === undefined) return { max_depth: value.max_depth as number };
  if (!Array.isArray(value.allowed_delegates)) return undefined;
  const matchers: Array<{ sub?: string; sub_profile?: string }> = [];
  for (const m of value.allowed_delegates) {
    if (!isRecord(m)) return undefined;
    if (m.sub !== undefined && typeof m.sub !== "string") return undefined;
    if (m.sub_profile !== undefined && typeof m.sub_profile !== "string") return undefined;
    matchers.push({
      ...(typeof m.sub === "string" ? { sub: m.sub } : {}),
      ...(typeof m.sub_profile === "string" ? { sub_profile: m.sub_profile } : {}),
    });
  }
  return { max_depth: value.max_depth as number, allowed_delegates: matchers };
}

/** One `authorization_details` entry as a view entry, or `undefined` when its keyed members are unusable. */
function entryOf(value: unknown): AuthorityEntry | undefined {
  if (!isRecord(value)) return undefined;
  if (typeof value.type !== "string" || typeof value.resource !== "string") return undefined;
  if (!Array.isArray(value.actions) || !value.actions.every((a) => typeof a === "string")) return undefined;
  if (value.delegation === undefined) return value as unknown as AuthorityEntry;
  const delegation = delegationOf(value.delegation);
  if (delegation === undefined) return undefined;
  return { ...(value as unknown as AuthorityEntry), join_delegation: deriveJoinDelegation(delegation) };
}

/** The view a verified response's members build, or a diagnostic naming the unusable member. */
function viewOf(
  missionId: string,
  issuer: string,
  mission: Record<string, unknown>,
  details: unknown,
): StatusMissionView | string {
  if (typeof mission.state !== "string" || !MISSION_STATUS_STATES.has(mission.state)) return "state";
  if (!Number.isSafeInteger(mission.version) || (mission.version as number) < 1) return "version";
  // OPTIONAL on the wire, REQUIRED here: the PDP's `policy_view_id` commits it.
  if (typeof mission.authority_hash !== "string" || mission.authority_hash === "") return "authority_hash";
  const subject = mission.subject;
  if (subject !== undefined && !(isRecord(subject) && typeof subject.iss === "string" && typeof subject.sub === "string")) {
    return "subject";
  }
  if (mission.client_id !== undefined && (typeof mission.client_id !== "string" || mission.client_id === "")) return "client_id";
  if (details !== undefined && !Array.isArray(details)) return "authorization_details";
  const authoritySet: AuthorityEntry[] = [];
  for (const raw of (details as unknown[] | undefined) ?? []) {
    const entry = entryOf(raw);
    if (entry === undefined) return "authorization_details entry";
    authoritySet.push(entry);
  }
  return {
    id: missionId,
    issuer,
    state: mission.state,
    version: mission.version as number,
    authority_hash: mission.authority_hash,
    authority_set: authoritySet,
    ...(isRecord(subject) ? { subject: { iss: subject.iss as string, sub: subject.sub as string } } : {}),
    ...(typeof mission.client_id === "string" ? { client_id: mission.client_id } : {}),
  };
}

/**
 * The body, decoded, or `undefined` once it passes `max` bytes. Counted as
 * it arrives, whatever length the response declares, and abandoned at the cap.
 */
async function readCapped(res: Response, max: number): Promise<string | undefined> {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      return undefined;
    }
    chunks.push(value);
  }
  return new TextDecoder().decode(Buffer.concat(chunks));
}

type CachedMission = Omit<ResolvedMission, "source">;

/**
 * A resolver for one Mission issuer and one enforcement scope. Construct one
 * per (issuer, scope) pair; its cache never answers for another.
 */
export class MissionStatusResolver {
  private readonly cache = new Map<string, CachedMission>();
  private readonly now: () => Date;
  private readonly http: typeof fetch;
  private readonly toleranceSeconds: number;

  constructor(private readonly opts: MissionStatusResolverOptions) {
    for (const [name, value] of [
      ["maxStaleSeconds", opts.maxStaleSeconds],
      ["timeoutMs", opts.timeoutMs],
      ["maxResponseBytes", opts.maxResponseBytes],
    ] as const) {
      if (!Number.isFinite(value) || value <= 0) throw new Error(`MissionStatusResolver: ${name} must be a positive number`);
    }
    if (!opts.serviceToken) throw new Error("MissionStatusResolver: a service credential is required");
    this.now = opts.now ?? (() => new Date());
    this.http = opts.fetch ?? fetch;
    // @spec status#mission-status-caching: the tolerance "MUST NOT exceed the
    // AS's advertised `mission_max_stale_seconds`".
    this.toleranceSeconds = Math.min(MISSION_STATUS_SKEW_SECONDS, opts.maxStaleSeconds);
  }

  /**
   * The referenced Mission's state and view, from the cache within its
   * bounds or from the issuer now. Never throws.
   */
  async resolve(ref: { id: string; issuer: string }, options: ResolveOptions = {}): Promise<MissionStatusResolution> {
    if (ref.issuer !== this.opts.issuer) return fail("not_found", "reference names another issuer");
    if (options.fresh !== true) {
      const cached = this.cache.get(ref.id);
      if (cached !== undefined && this.reusable(cached, options.maxAgeSeconds)) return { ...cached, source: "cached" };
    }
    const read = await this.read(ref.id);
    if (!read.ok) return read;
    const held = this.cache.get(ref.id);
    // An older observation never replaces a newer one: a slow read that
    // completes after a later one does not roll the cached state back.
    if (
      held === undefined ||
      read.observedAtMs > held.observedAtMs ||
      (read.observedAtMs === held.observedAtMs && read.view.version >= held.view.version)
    ) {
      this.cache.set(ref.id, read);
    }
    return { ...read, source: "fetched" };
  }

  /** Whether a cached answer is still within every bound on reliance. */
  private reusable(entry: CachedMission, maxAgeSeconds: number | undefined): boolean {
    const nowMs = this.now().getTime();
    if (nowMs >= entry.freshUntilMs) return false;
    if (nowMs > entry.observedAtMs + this.opts.maxStaleSeconds * 1000) return false;
    if (maxAgeSeconds !== undefined && !(nowMs <= entry.observedAtMs + maxAgeSeconds * 1000)) return false;
    return true;
  }

  /** One authenticated, bounded read of the Status operation, verified. */
  private async read(missionId: string): Promise<CachedMission | UnresolvedMission> {
    const nonce = randomUUID();
    const url = new URL(this.opts.statusUrl(missionId));
    url.searchParams.set("audience", this.opts.audience);
    url.searchParams.set("nonce", nonce);
    const signal = AbortSignal.timeout(this.opts.timeoutMs);
    let jws: string | undefined;
    try {
      const res = await this.http(url, {
        method: "GET",
        headers: { "x-service-token": this.opts.serviceToken, accept: "application/mission-status-response+jwt" },
        redirect: "manual",
        signal,
      });
      if (res.status !== 200) {
        await res.body?.cancel();
        if (res.status === 401 || res.status === 403) return fail("unauthorized", `status ${res.status}`);
        if (res.status === 404) return fail("not_found", "status 404");
        return fail("unavailable", `status ${res.status}`);
      }
      jws = await readCapped(res, this.opts.maxResponseBytes);
    } catch {
      return fail("unavailable", signal.aborted ? "timeout" : "transport");
    }
    if (jws === undefined) return fail("unavailable", "oversized");

    const now = this.now();
    const verified = await verifyMissionStatusResponse(
      jws,
      { missionId, issuer: this.opts.issuer, audience: this.opts.audience },
      this.opts.keys,
      now,
      this.toleranceSeconds,
    );
    if (verified === undefined) return fail("unverifiable", "signature or claims");
    const { payload, mission, freshUntilMs } = verified;
    // @spec status#mission-status-response consumer check 7: the response
    // answers THIS request, never a replayed earlier one.
    if (payload.nonce !== nonce) return fail("unverifiable", "nonce");
    // Check 9's other half: an observation dated in the future is not one the
    // issuer has made yet.
    if (typeof payload.iat !== "number" || payload.iat * 1000 - now.getTime() > this.toleranceSeconds * 1000) {
      return fail("unverifiable", "iat");
    }
    // @spec status#mission-status-caching "Hard stop": a response whose
    // signed `fresh_until` has passed is relied on for nothing.
    if (freshUntilMs <= now.getTime()) return fail("unverifiable", "fresh_until passed");
    const view = viewOf(missionId, this.opts.issuer, mission, payload.authorization_details);
    if (typeof view === "string") return fail("unverifiable", view);
    return { ok: true, view, observedAtMs: payload.iat * 1000, freshUntilMs };
  }
}
