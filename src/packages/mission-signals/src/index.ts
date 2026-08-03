/**
 * @spec draft-mcguinness-oauth-mission-signals
 *
 * Mission Lifecycle Signals: the PUSH complement to the Status List's PULL. A
 * Mission Issuer emits a `mission.lifecycle-change` Security Event Token (SET)
 * when it commits a lifecycle transition, so consumers stop honoring a Mission
 * promptly rather than waiting out token lifetimes. This module is the pure
 * event core: the SET builder/signer ({@link signLifecycleEvent}), the consumer
 * receiver ({@link MissionSignalReceiver}), and the async emitter glue that
 * subscribes to the kernel's synchronous lifecycle-commit hook
 * ({@link MissionSignalEmitter}).
 *
 * Deferred (named, not built): the SSF Transmitter/stream-config/add-subject
 * endpoints and `mission_event_stream_endpoint` metadata; the RFC 8935 push and
 * RFC 8936 poll HTTP transports (this module hands SETs to registered receivers
 * in-process); stream verification / heartbeat liveness and its staleness
 * fallback; automatic Mission Status refetch on a detected version gap (this PR
 * detects the gap only); and the `suspend_until` / `on_expiry` / `tenant`
 * members (no model exists in the kernel). The demo stack signal wiring is also
 * deferred; the emitter is injectable at the authorization-server construction
 * site (its `onLifecycleCommit` option).
 */

import { randomBytes } from "node:crypto";
import type { LifecycleCommit } from "@mission/authorization-server";
import type { MissionStatusLease, StateSource } from "@mission/core";
import { createLocalJWKSet, type JWK, type JWTPayload, jwtVerify, SignJWT } from "jose";

/**
 * @spec signals#lifecycle-event — the registered event-type identifier for the
 * Mission lifecycle-change event. Matched by the exact URI, so the namespace can
 * migrate without a semantic change (draft §consumer-behavior).
 */
export const LIFECYCLE_CHANGE_EVENT_URI =
  "https://schemas.karlmcguinness.com/mission/lifecycle-change";

/** @spec signals#set-protection — the SET `typ` header (RFC 8417 secevent+jwt). */
export const SET_TYP = "secevent+jwt";

/**
 * The `state_source` a consumer records for state established over this stream
 * (harness § mission-binding shared value space, `@mission/core`).
 */
export const SIGNAL_STATE_SOURCE: StateSource = "signal";

/** Options for signing a Mission lifecycle-change SET. */
export interface SignLifecycleOptions {
  /** The receiving consumer's registered audience identifier (SET `aud`). */
  audience: string;
  /** The Mission Issuer's SET signing key (the as-status key). */
  key: Parameters<SignJWT["sign"]>[0];
  /** The `kid` identifying the signing key in the issuer's `jwks_uri`. */
  kid: string;
}

/**
 * @spec signals#lifecycle-event @spec signals#set-protection
 *
 * Build and sign one Mission lifecycle-change SET for a single consumer
 * audience, from a kernel lifecycle commit. The SET is a JWS Compact
 * Serialization with `typ` secevent+jwt: envelope `iss` (the Mission Issuer),
 * `aud` (the consumer), `iat`, `jti`, and a `sub_id` opaque Subject Identifier
 * whose `id` is the Mission Identifier; body carries the event under the
 * event-type URI with the Mission identity, `state`, optional `prior_state`,
 * `version`, `committed_at`, `expires_at`, and optional `successor`.
 */
export async function signLifecycleEvent(
  commit: LifecycleCommit,
  opts: SignLifecycleOptions,
): Promise<string> {
  const event: Record<string, unknown> = {
    mission: { id: commit.id, issuer: commit.issuer },
    state: commit.state,
    ...(commit.prior_state ? { prior_state: commit.prior_state } : {}),
    version: commit.version,
    committed_at: commit.committed_at,
    expires_at: commit.expires_at,
    ...(commit.successor ? { successor: commit.successor } : {}),
  };
  return new SignJWT({
    sub_id: { format: "opaque", id: commit.id },
    events: { [LIFECYCLE_CHANGE_EVENT_URI]: event },
  })
    .setProtectedHeader({ alg: "ES256", kid: opts.kid, typ: SET_TYP })
    .setIssuer(commit.issuer)
    .setAudience(opts.audience)
    .setIssuedAt()
    .setJti(`set_${randomBytes(15).toString("base64url")}`)
    .sign(opts.key);
}

/** The last Mission state a receiver established over the stream, per Mission. */
export interface CachedState {
  /** Received `state` typed as an open string: any non-active value, including
   *  an unrecognized one, is treated as non-deriving (draft §consumer-behavior). */
  state: string;
  version: number;
  expires_at: string;
}

/** The outcome of applying a received SET (asserted on, so each rule is proven). */
export type ApplyResult =
  | { status: "applied"; state: string; version: number }
  | { status: "duplicate" }
  | { status: "stale"; version: number }
  | { status: "gap"; expected: number; received: number; state: string; version: number }
  | { status: "refused"; reason: "signature" | "issuer" | "audience" | "malformed" };

export interface ReceiverOptions {
  /** The Mission Issuer's published verification keys (its `jwks_uri`). */
  jwks: { keys: JWK[] };
  /** The Mission Issuer this receiver registered with; SET `iss` MUST equal it. */
  issuer: string;
  /** This receiver's own registered audience; SET `aud` MUST equal it. */
  audience: string;
}

/**
 * @spec signals#set-protection @spec signals#consumer-behavior
 *
 * A consumer's Shared Signals receiver: it verifies each SET, dedups by `jti`,
 * and applies the transition idempotently by `version` into a per-Mission cache.
 * The apply is anti-revive: a lower-or-equal `version` NEVER regresses the
 * recorded state (an old `active` can never override a newer `revoked`, whether
 * a forgery, a replay, or an at-least-once duplicate). `viewState` reads the
 * cache for a consumer's `loadView`.
 */
export class MissionSignalReceiver {
  /** @spec status/harness — the ONE status shape a consumer relies on, keyed by Mission. */
  private readonly cache = new Map<string, CachedState>();
  /** Recently seen `jti` values for duplicate suppression (unbounded in-process;
   *  a bounded iat-relative window is deferred). */
  private readonly seen = new Set<string>();
  /** Missions with a detected `version` gap: not safe to honor until refetched
   *  (detect only this increment; automatic Status refetch is deferred). */
  private readonly gapped = new Set<string>();
  private readonly jwkSet: ReturnType<typeof createLocalJWKSet>;
  /** This receiver's registered audience (the emitter delivers by audience). */
  readonly audience: string;

  constructor(private readonly opts: ReceiverOptions) {
    this.jwkSet = createLocalJWKSet({ keys: opts.jwks.keys } as never);
    this.audience = opts.audience;
  }

  /**
   * @spec signals#set-protection @spec signals#consumer-behavior
   *
   * Verify a SET and apply it. Protection checks (in order): signature against
   * the issuer's keys with the secevent+jwt `typ`; explicit `iss` == the
   * registered Mission Issuer; explicit `aud` == this receiver's own audience;
   * `jti` duplicate suppression. Then version-idempotent apply: a `version` not
   * greater than the last applied never regresses state (anti-revive); a
   * first-seen `version` > 1 or a `version` more than one past the last is a
   * gap (marked not-honored for a later refetch).
   */
  async verifyAndApply(setJwt: string): Promise<ApplyResult> {
    // 1. Signature (draft §set-protection step 1).
    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(setJwt, this.jwkSet, { typ: SET_TYP }));
    } catch {
      return { status: "refused", reason: "signature" };
    }
    // 2. Issuer (step 2): single-issuer, so SET `iss` equals `mission.issuer`.
    if (payload.iss !== this.opts.issuer) return { status: "refused", reason: "issuer" };
    // 3. Audience (step 3): the consumer refuses a SET that is not its own.
    if (!audienceMatches(payload.aud, this.audience))
      return { status: "refused", reason: "audience" };
    // 4. Redelivery (step 4): a duplicate `jti` is not an error and is not reprocessed.
    const jti = payload.jti;
    if (typeof jti !== "string") return { status: "refused", reason: "malformed" };
    if (this.seen.has(jti)) return { status: "duplicate" };

    const parsed = parseEvent(payload);
    if (!parsed) return { status: "refused", reason: "malformed" };
    this.seen.add(jti);

    const { missionId, state, version, expires_at } = parsed;
    const current = this.cache.get(missionId);
    // Anti-revive: a version at or below the last applied never regresses state.
    if (current !== undefined && version <= current.version) {
      return { status: "stale", version: current.version };
    }
    // Gap: first-seen version > 1 (no activating event ever anchored the
    // sequence), or a jump of more than one past the last applied.
    const expected = (current?.version ?? 0) + 1;
    const isGap = version > expected;
    this.cache.set(missionId, { state, version, expires_at });
    if (isGap) {
      this.gapped.add(missionId);
      return { status: "gap", expected, received: version, state, version };
    }
    this.gapped.delete(missionId);
    return { status: "applied", state, version };
  }

  /** The last state established for a Mission, for a consumer's `loadView`. */
  viewState(missionId: string): CachedState | undefined {
    return this.cache.get(missionId);
  }

  /**
   * @spec harness#mission-binding — the last signal-established state as the
   * shared `MissionStatusLease` shape (`@mission/core`) the harness consumes,
   * tagged `state_source: "signal"`. Absent until a signal has established state
   * for the Mission. `status_checked_at` is the instant the consumer read it.
   */
  lease(missionId: string, checkedAt: string): MissionStatusLease | undefined {
    const s = this.cache.get(missionId);
    if (!s) return undefined;
    return {
      state: s.state,
      version: s.version,
      status_checked_at: checkedAt,
      status_expires_at: s.expires_at,
      state_source: SIGNAL_STATE_SOURCE,
    };
  }

  /** Whether a Mission has an unresolved `version` gap (refetch before reliance). */
  hasGap(missionId: string): boolean {
    return this.gapped.has(missionId);
  }
}

/** True if `aud` (string or array) contains the receiver's own audience. */
function audienceMatches(aud: JWTPayload["aud"], self: string): boolean {
  if (typeof aud === "string") return aud === self;
  if (Array.isArray(aud)) return aud.includes(self);
  return false;
}

interface ParsedEvent {
  missionId: string;
  state: string;
  version: number;
  expires_at: string;
}

/** Pull and shape-check the required members of the lifecycle-change event. */
function parseEvent(payload: JWTPayload): ParsedEvent | undefined {
  const events = payload.events as Record<string, unknown> | undefined;
  const raw = events?.[LIFECYCLE_CHANGE_EVENT_URI];
  if (raw === null || typeof raw !== "object") return undefined;
  const ev = raw as Record<string, unknown>;
  const mission = ev.mission as { id?: unknown } | undefined;
  const missionId = typeof mission?.id === "string" ? mission.id : undefined;
  const state = typeof ev.state === "string" ? ev.state : undefined;
  const version = typeof ev.version === "number" ? ev.version : undefined;
  const expires_at = typeof ev.expires_at === "string" ? ev.expires_at : undefined;
  if (
    missionId === undefined ||
    state === undefined ||
    version === undefined ||
    expires_at === undefined
  ) {
    return undefined;
  }
  return { missionId, state, version, expires_at };
}

/** A consumer this issuer emits to, identified by its registered audience. */
export interface SignalConsumer {
  audience: string;
}

export interface EmitterOptions {
  /** The Mission Issuer's SET signing key (the as-status key). */
  key: Parameters<SignJWT["sign"]>[0];
  /** The `kid` identifying that key in the issuer's `jwks_uri`. */
  kid: string;
  /** The consumer audiences to emit one SET each per committed transition. */
  consumers: SignalConsumer[];
}

/**
 * @spec signals#lifecycle-event @spec signals#event-driven
 *
 * The emitter glue that runs OUTSIDE the kernel: the kernel's lifecycle-commit
 * hook is synchronous, but signing a SET is async. `onCommit` (the subscriber
 * handed to the kernel construction site) returns immediately, scheduling one
 * async signing per consumer audience off the commit path; each signed SET is
 * handed to the delivery sinks registered for that audience. `drain` awaits all
 * in-flight emissions for a deterministic barrier (tests, graceful shutdown);
 * it is never on the commit path.
 */
export class MissionSignalEmitter {
  private readonly deliveries: Array<{ audience: string; deliver: (set: string) => unknown }> = [];
  private inflight: Array<Promise<void>> = [];

  constructor(private readonly opts: EmitterOptions) {}

  /** Register a receiver to be handed every SET for its own audience. */
  register(receiver: MissionSignalReceiver): void {
    this.onDeliver(receiver.audience, (set) => receiver.verifyAndApply(set));
  }

  /** Register a raw delivery sink for an audience (e.g. an HTTP push, deferred). */
  onDeliver(audience: string, deliver: (set: string) => unknown): void {
    this.deliveries.push({ audience, deliver });
  }

  /**
   * The kernel `onLifecycleCommit` subscriber. Synchronous: it schedules signing
   * and returns, keeping the async SET production off the kernel's commit path.
   */
  readonly onCommit = (commit: LifecycleCommit): void => {
    for (const consumer of this.opts.consumers) {
      this.inflight.push(this.emitOne(commit, consumer.audience));
    }
  };

  private async emitOne(commit: LifecycleCommit, audience: string): Promise<void> {
    try {
      const set = await signLifecycleEvent(commit, {
        audience,
        key: this.opts.key,
        kid: this.opts.kid,
      });
      for (const d of this.deliveries) {
        if (d.audience === audience) await d.deliver(set);
      }
    } catch {
      // Delivery is best-effort and off the synchronous commit path; a consumer
      // that misses an event falls back to Mission Status (draft
      // §consumer-behavior, §missed-events-are-not-fail-open). Retry/backoff and
      // dead-lettering are deferred to the SSF transport.
    }
  }

  /** Await all in-flight emissions. A test/shutdown barrier, never on the commit path. */
  async drain(): Promise<void> {
    const pending = this.inflight;
    this.inflight = [];
    await Promise.allSettled(pending);
  }
}
