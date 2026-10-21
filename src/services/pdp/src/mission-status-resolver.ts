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
 * - The envelope `sub` is this PDP's own client identifier (consumer check
 *   6): a response signed for another caller is refused (#1407).
 * - The profile's request. An HTTPS POST to the issuer's advertised
 *   `mission_status_endpoint` with an `application/x-www-form-urlencoded`
 *   body carrying `mission_id`, `audience` (this PDP's enforcement scope) and
 *   a fresh `nonce`, the PDP authenticated by private-key JWT (RFC 7523) as a
 *   client holding the `mission_status` grant: a fresh client assertion per
 *   read, `aud` the issuer identifier ({@link privateKeyJwtClient}). The
 *   Mission identifier travels in the body, never in the URL.
 * - Bounded. One deadline covers connecting, the headers and the body; the
 *   body is read through a byte cap, and a redirect is never followed, so the
 *   client assertion never leaves for another origin.
 * - Fail closed. Every failure is a typed result, never a throw, and never
 *   cached: no negative entry outlives the request that met it.
 * - Relied on only within the signed bounds. Every observation `resolve`
 *   returns, read now or reused from the cache, is within each bound at that
 *   instant: before its signed `fresh_until`, within `iat` plus the issuer's
 *   advertised `mission_max_stale_seconds`, and within the caller's own
 *   `maxAgeSeconds` (its action class's staleness window), with no skew
 *   allowance on the old side ({@link MissionStatusResolver.boundPassed}).
 *   An observation read now that is already past one is refused `stale` and
 *   not cached. The cache is keyed on the Mission under this resolver's one
 *   issuer and enforcement scope; `fresh: true` bypasses it and reads the
 *   source now. An older observation never replaces a newer one.
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

import { type KeyObject, randomUUID } from "node:crypto";
import { createLocalJWKSet, type JSONWebKeySet, type JWTVerifyGetKey, SignJWT } from "jose";
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
 * transport failure, the deadline, a body over the cap, a redirect, a status
 * other than 200, 400, 401, 403 and 404, or a 400 other than
 * `invalid_client`). `unauthorized`: the issuer refused this PDP's client
 * authentication (400 `invalid_client`, or 401 or 403). `not_found`: the issuer's
 * anti-oracle not-found, or a reference naming another issuer.
 * `unverifiable`: a response arrived and did not verify or did not carry a
 * usable view. `stale`: a response verified, but the observation it carries
 * is already past a reliance bound (its signed `fresh_until`,
 * `mission_max_stale_seconds`, or the caller's `maxAgeSeconds`).
 */
export type MissionStatusFailure = "unavailable" | "unauthorized" | "not_found" | "unverifiable" | "stale";

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
  /** The issuer's advertised `mission_status_endpoint`. */
  statusEndpoint: string;
  /** This PDP's enforcement scope: the request's `audience` and the response's expected `aud`. */
  audience: string;
  /** The issuer's published status-response keys, restricted to the declared ones ({@link declaredStatusKeys}). */
  keys: JWTVerifyGetKey;
  /** This PDP's client authentication at the Status endpoint, as a client holding the `mission_status` grant. */
  client: StatusClientCredential;
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

/**
 * @spec status#mission-status-authentication: a client of the Mission Status
 * endpoint that authenticates by private-key JWT (RFC 7523).
 */
export interface StatusClientCredential {
  /** The client identifier: the assertion's `iss` and `sub`, and the `sub` a response to it carries. */
  clientId: string;
  /** A fresh client assertion for one request. */
  assertion: () => Promise<string>;
}

const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/**
 * @spec status#mission-status-authentication: a private-key-JWT client: each
 * assertion has `iss` and `sub` the client identifier, `aud` the issuer
 * identifier as its sole value, a fresh `jti`, an `exp` a minute away, and
 * the JWS `typ` `client-authentication+jwt`, the explicit type the client
 * SHOULD set.
 */
export function privateKeyJwtClient(opts: {
  clientId: string;
  issuer: string;
  privateKey: CryptoKey | KeyObject | Uint8Array;
  kid: string;
  alg?: string;
  now?: () => Date;
}): StatusClientCredential {
  return {
    clientId: opts.clientId,
    assertion: async () => {
      const iat = Math.floor((opts.now?.() ?? new Date()).getTime() / 1000);
      return new SignJWT({ jti: randomUUID() })
        .setProtectedHeader({ alg: opts.alg ?? "ES256", kid: opts.kid, typ: "client-authentication+jwt" })
        .setIssuer(opts.clientId)
        .setSubject(opts.clientId)
        .setAudience(opts.issuer)
        .setIssuedAt(iat)
        .setExpirationTime(iat + 60)
        .sign(opts.privateKey);
    },
  };
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
  // Absent is the empty set; present, it is an array.
  const listed: unknown[] | undefined = Array.isArray(details) ? details : details === undefined ? [] : undefined;
  if (listed === undefined) return "authorization_details";
  const authoritySet: AuthorityEntry[] = [];
  for (const raw of listed) {
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
    if (!opts.client?.clientId) throw new Error("MissionStatusResolver: a client credential is required");
    if (!URL.canParse(opts.statusEndpoint)) throw new Error("MissionStatusResolver: statusEndpoint must be a URL");
    this.now = opts.now ?? (() => new Date());
    this.http = opts.fetch ?? fetch;
    // @spec status#mission-status-caching: the tolerance "MUST NOT exceed the
    // AS's advertised `mission_max_stale_seconds`".
    this.toleranceSeconds = Math.min(MISSION_STATUS_SKEW_SECONDS, opts.maxStaleSeconds);
  }

  /**
   * The cached answer for the referenced Mission, only while it is within
   * every reliance bound at this instant ({@link boundPassed}); `undefined`
   * otherwise. Synchronous and never reads the source: a caller that must
   * answer without awaiting (#818, D560) relies on what an earlier
   * {@link resolve} established, and on nothing once that has lapsed.
   */
  peek(ref: { id: string; issuer: string }, maxAgeSeconds?: number): ResolvedMission | undefined {
    if (ref.issuer !== this.opts.issuer) return undefined;
    const cached = this.cache.get(ref.id);
    if (cached === undefined || this.boundPassed(cached, maxAgeSeconds) !== undefined) return undefined;
    return { ...cached, source: "cached" };
  }

  /**
   * The referenced Mission's state and view, from the cache within its
   * bounds or from the issuer now. Never throws.
   */
  async resolve(ref: { id: string; issuer: string }, options: ResolveOptions = {}): Promise<MissionStatusResolution> {
    if (ref.issuer !== this.opts.issuer) return fail("not_found", "reference names another issuer");
    if (ref.id === "") return fail("not_found", "reference names no Mission");
    if (options.fresh !== true) {
      const cached = this.cache.get(ref.id);
      if (cached !== undefined && this.boundPassed(cached, options.maxAgeSeconds) === undefined) {
        return { ...cached, source: "cached" };
      }
    }
    const read = await this.read(ref.id);
    if (!read.ok) return read;
    // An answer read now is held to the same bounds as one reused from the
    // cache: a verified but already-old observation is relied on for nothing,
    // and is not cached.
    const passed = this.boundPassed(read, options.maxAgeSeconds);
    if (passed !== undefined) return fail("stale", passed);
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

  /**
   * The ONE place the reliance bounds live, for an observation read now and
   * one reused from the cache alike: the first bound it has passed at this
   * instant, or `undefined` while it is within all of them. Before its
   * signed `fresh_until` (@spec status#mission-status-caching "Hard stop",
   * no skew allowance for any state); no older than `iat` plus the issuer's
   * `mission_max_stale_seconds`; and no older than the caller's
   * `maxAgeSeconds` where it gives one. No skew allowance on the old side,
   * as the decision point's own window check (`ageMs > enforceableWindowMs`)
   * allows none; an `iat` slightly in the future, accepted at verification,
   * is younger than every bound.
   */
  private boundPassed(entry: CachedMission, maxAgeSeconds: number | undefined): string | undefined {
    const nowMs = this.now().getTime();
    if (nowMs >= entry.freshUntilMs) return "fresh_until passed";
    if (nowMs > entry.observedAtMs + this.opts.maxStaleSeconds * 1000) return "older than mission_max_stale_seconds";
    if (maxAgeSeconds !== undefined && !(nowMs <= entry.observedAtMs + maxAgeSeconds * 1000)) {
      return "older than maxAgeSeconds";
    }
    return undefined;
  }

  /** One authenticated, bounded read of the Status operation, verified. */
  private async read(missionId: string): Promise<CachedMission | UnresolvedMission> {
    const nonce = randomUUID();
    const signal = AbortSignal.timeout(this.opts.timeoutMs);
    let jws: string | undefined;
    try {
      // @spec status#mission-status-request: the form body; the identifier a
      // PEP carried is a member value, so it cannot steer the request to
      // another path at the issuer.
      const body = new URLSearchParams({
        mission_id: missionId,
        audience: this.opts.audience,
        nonce,
        client_assertion_type: CLIENT_ASSERTION_TYPE,
        client_assertion: await this.opts.client.assertion(),
      });
      const res = await this.http(this.opts.statusEndpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/mission-status-response+jwt" },
        body: body.toString(),
        redirect: "manual",
        signal,
      });
      if (res.status === 400) {
        // @spec status#mission-status-auth-failures: a refused client
        // authentication is a 400 `invalid_client`; any other 400 is no answer.
        const text = await readCapped(res, 4096);
        let error: unknown;
        try {
          error = text === undefined ? undefined : (JSON.parse(text) as { error?: unknown }).error;
        } catch {
          error = undefined;
        }
        if (error === "invalid_client") return fail("unauthorized", "invalid_client");
        return fail("unavailable", `status 400 ${String(error)}`);
      }
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
    // @spec status#mission-status-response consumer check 6 (#1407): the
    // response was signed for this client, not for another caller.
    if (payload.sub !== this.opts.client.clientId) return fail("unverifiable", "sub");
    // Consumer check 7: the response answers THIS request, never a replayed
    // earlier one.
    if (payload.nonce !== nonce) return fail("unverifiable", "nonce");
    // Check 9's other half: an observation dated in the future is not one the
    // issuer has made yet. `iat` is present and numeric: the verifier
    // requires it. Its age is the reliance bounds' question (`boundPassed`).
    const iatMs = (payload.iat as number) * 1000;
    if (iatMs - now.getTime() > this.toleranceSeconds * 1000) return fail("unverifiable", "iat");
    const view = viewOf(missionId, this.opts.issuer, mission, payload.authorization_details);
    if (typeof view === "string") return fail("unverifiable", view);
    return { ok: true, view, observedAtMs: iatMs, freshUntilMs };
  }
}
