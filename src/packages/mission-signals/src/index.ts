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
 * fallback; automatic Mission Status refetch on a detected version gap or a
 * detected rematerialization need (this module detects each condition only;
 * the refetch itself is the consumer's job); and the
 * `suspend_until` / `on_expiry` / `tenant` members (no model exists in the
 * kernel). The `mission_capabilities_supported` delivery gate
 * ({@link MissionSignalEmitter}) is implemented: a stream that has not
 * declared `authority_changed` is not delivered a discharge commit's event. The demo stack signal wiring is also deferred; the emitter is
 * injectable at the authorization-server construction site (its
 * `onLifecycleCommit` option).
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
 * `version`, `committed_at`, `expires_at`, optional `successor`, and optional
 * `containment_version` and `authority_changed`.
 *
 * @spec containment#propagation — `containment_version` rides the same
 * event (no dedicated containment event type): when the kernel commit carries
 * it (containment has ever been applied to the Mission), it is copied
 * through unchanged, so an active-to-active commit whose `state` equals
 * `prior_state` is still legible as an authorization change to a consumer
 * that inspects this field.
 *
 * @spec signals#lifecycle-event — `authority_changed` is copied through the
 * same way, from the kernel commit's own computed value ({@link
 * LifecycleCommit.authority_changed}): true only on a metadata-only commit
 * that narrowed effective authority (containment today; entry discharge is
 * the other named case, {{I-D.draft-mcguinness-oauth-mission-status}}),
 * absent on every other transition. The builder relays the kernel's
 * determination unchanged; it does not itself decide what narrows.
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
    ...(commit.containment_version !== undefined
      ? { containment_version: commit.containment_version }
      : {}),
    ...(commit.authority_changed ? { authority_changed: true } : {}),
  };
  return new SignJWT({
    sub_id: { format: "opaque", id: commit.id },
    events: { [LIFECYCLE_CHANGE_EVENT_URI]: event },
  })
    .setProtectedHeader({ alg: "ES256", kid: opts.kid, typ: SET_TYP })
    .setIssuer(commit.issuer)
    .setAudience(opts.audience)
    .setIssuedAt()
    // A replay from the kernel's durable finalization outbox carries a
    // stable event identity; reusing it as `jti` makes redelivery the SAME
    // event (@spec signals same-`jti` redelivery), never a new assertion.
    .setJti(commit.event_id ?? `set_${randomBytes(15).toString("base64url")}`)
    .sign(opts.key);
}

/** The last Mission state a receiver established over the stream, per Mission. */
export interface CachedState {
  /** Received `state` typed as an open string: any non-active value, including
   *  an unrecognized one, is treated as non-deriving (draft §consumer-behavior). */
  state: string;
  version: number;
  expires_at: string;
  /** @spec containment#propagation — the last `containment_version` this
   *  receiver has observed for the Mission (absent means containment has
   *  never been observed on the stream). The cursor the containment-aware
   *  rematerialization rule (@spec signals#consumer-behavior) advances
   *  against: a newly received `containment_version` greater than this value
   *  triggers rematerialization independently of `authority_changed`. */
  containment_version?: number;
}

/**
 * @spec signals#consumer-behavior — the version state a consumer's Mission
 * Status refresh returned for a Mission, as {@link
 * MissionSignalReceiver.markRematerialized}'s `observedBaseline` argument.
 * Mirrors the two fields {@link CachedState} tracks for the rematerialization
 * rule: `containment_version` is absent when the Mission has never been
 * contained, the same absent-means-none convention as the wire event and
 * `CachedState` itself.
 */
export interface RematerializationBaseline {
  /** The Mission `version` this Status refresh observed. */
  version: number;
  /** The Mission `containment_version` this Status refresh observed, when
   *  the Mission has ever been contained (absent otherwise). */
  containment_version?: number;
}

/** The outcome of applying a received SET (asserted on, so each rule is proven). */
export type ApplyResult =
  | { status: "applied"; state: string; version: number; rematerialize: boolean }
  | { status: "duplicate" }
  | { status: "stale"; version: number }
  | {
      status: "gap";
      expected: number;
      received: number;
      state: string;
      version: number;
      rematerialize: boolean;
    }
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
 * cache for a consumer's `loadView`. It also detects, per applied event,
 * whether the Mission's effective authority view needs rematerializing
 * through Mission Status before further consequential reliance: on
 * `authority_changed` true, or on a `containment_version` advance past the
 * value this receiver last observed for the Mission
 * (@spec signals#consumer-behavior). Detection only, mirroring the gap
 * rule: the refetch itself is the consumer's job; {@link
 * MissionSignalReceiver.markRematerialized} is how the consumer, having
 * performed it, clears the latch.
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
  /**
   * @spec signals#consumer-behavior — Missions whose effective authority view
   * needs rematerializing through Mission Status before further consequential
   * reliance (detect only; the refetch itself is the consumer's job): set by
   * an applied or gapped event carrying `authority_changed` true, or by a
   * containment-aware `containment_version` advance past the value this
   * receiver last observed for the Mission (@spec containment#propagation).
   * The map value is the {@link RematerializationBaseline} of the LATEST
   * event that (re-)raised the need: the version state a consumer's Status
   * refresh must reach or exceed before {@link markRematerialized} will
   * clear it. UNLIKE `gapped`, this does not auto-clear on a later event
   * that does not itself require rematerialization, because such an event
   * proves nothing about whether the consumer actually rematerialized after
   * the EARLIER narrowing (a gap's continuity is re-established by the next
   * in-order event; a stale authority view is not). It clears only through
   * {@link markRematerialized}, and only when the acknowledged baseline
   * covers the tracked marker; a narrowing that arrives after a successful
   * acknowledgement moves the marker forward and re-raises the latch.
   */
  private readonly rematerializeNeeded = new Map<string, RematerializationBaseline>();
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
   * gap (marked not-honored for a later refetch). An applied or gapped event
   * additionally carries `rematerialize`: true when `authority_changed` is
   * true, or when `containment_version` advanced past the value last observed
   * for the Mission, either of which requires rematerializing the effective
   * authority view through Mission Status before further consequential
   * reliance, even though `state` did not change.
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

    const { missionId, state, version, expires_at, authority_changed, containment_version } =
      parsed;
    const current = this.cache.get(missionId);
    // Anti-revive: a version at or below the last applied never regresses state.
    if (current !== undefined && version <= current.version) {
      return { status: "stale", version: current.version };
    }
    // Gap: first-seen version > 1 (no activating event ever anchored the
    // sequence), or a jump of more than one past the last applied.
    const expected = (current?.version ?? 0) + 1;
    const isGap = version > expected;

    // @spec signals#consumer-behavior — rematerialize the effective authority
    // view when the generic `authority_changed` discriminator is true, or,
    // independently, when a containment-aware consumer observes
    // `containment_version` advance past a value it PREVIOUSLY OBSERVED for
    // this Mission (@spec containment#propagation). Either signal alone
    // suffices; a consumer reading only `authority_changed` and one tracking
    // `containment_version` directly reach the same result. Requiring a
    // DEFINED prior value is deliberate: with no earlier observation to
    // compare against, this receiver cannot assert an advance (a first-ever
    // event carrying a `containment_version` is not necessarily a narrowing
    // relative to whatever baseline the consumer holds from elsewhere, e.g.
    // a Mission Status bootstrap this pure event-core module does not model).
    // This independent path is NOT redundant with `authority_changed`: this
    // KERNEL's contain() only sets `authority_changed` true when the
    // EFFECTIVE set actually narrowed (@spec MissionKernel#emitCommit), but
    // `containment_version` still advances on a contain commit that narrows
    // nothing (a fresh event whose removal the contained set already
    // represents), so `containmentAdvanced` below deliberately fires on that
    // case too (any new containment activity, not only a real narrowing,
    // is conservative grounds for a refresh). A containment-aware consumer
    // that wants that broader coverage MUST track `containment_version`
    // itself rather than assume the discriminator always accompanies it. A
    // stale/duplicate event never reaches here, so "ignore stale/equal
    // `containment_version`" also falls out of the anti-revive check above
    // and the strict `>` comparison below.
    const priorContainmentVersion = current?.containment_version;
    const containmentAdvanced =
      priorContainmentVersion !== undefined &&
      containment_version !== undefined &&
      containment_version > priorContainmentVersion;
    const rematerialize = authority_changed === true || containmentAdvanced;

    // Carry the last-observed `containment_version` forward when this event
    // does not itself repeat it (defensive: the wire invariant is that it
    // rides every commit once ever present, but the cache must not forget it
    // on an event that happens not to carry it).
    const nextContainmentVersion = containment_version ?? priorContainmentVersion;
    this.cache.set(missionId, {
      state,
      version,
      expires_at,
      ...(nextContainmentVersion !== undefined
        ? { containment_version: nextContainmentVersion }
        : {}),
    });
    // Latch: an event that does not itself require rematerialization says
    // nothing about whether the consumer already rematerialized after an
    // EARLIER narrowing (see the field doc comment), so it never clears the
    // marker on its own. An event that DOES require it (re-)raises the
    // marker to THIS event's own version/containment_version: the new
    // high-water mark a markRematerialized baseline must cover to clear it.
    if (rematerialize) {
      this.rematerializeNeeded.set(missionId, {
        version,
        ...(nextContainmentVersion !== undefined
          ? { containment_version: nextContainmentVersion }
          : {}),
      });
    }
    if (isGap) {
      this.gapped.add(missionId);
      return { status: "gap", expected, received: version, state, version, rematerialize };
    }
    this.gapped.delete(missionId);
    return { status: "applied", state, version, rematerialize };
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

  /**
   * @spec signals#consumer-behavior — whether the Mission's effective
   * authority view needs rematerializing through Mission Status before
   * further consequential reliance (set on `authority_changed` true, or a
   * `containment_version` advance). LATCHED: once true, stays true across
   * later events that do not themselves require it (no auto-clear, unlike
   * `hasGap`); clears only via {@link markRematerialized}.
   */
  needsRematerialization(missionId: string): boolean {
    return this.rematerializeNeeded.has(missionId);
  }

  /**
   * @spec signals#consumer-behavior — acknowledge that the consumer has
   * rematerialized a Mission's effective authority view through Mission
   * Status, clearing {@link needsRematerialization}'s latch.
   * `observedBaseline` is the version state (this receiver's own {@link
   * RematerializationBaseline} shape) the consumer's Status refresh just
   * returned for the Mission.
   *
   * The latch clears ONLY when `observedBaseline` covers the marker of the
   * latest narrowing this receiver has observed for the Mission (the
   * `version` that narrowing advanced to, and its `containment_version` when
   * it carried one): a baseline whose `version` falls short of that marker,
   * or whose `containment_version` is absent or short of the marker's when
   * the marker has one, is STALE relative to the outstanding narrowing and
   * does NOT clear it. A narrowing event that arrives after a successful
   * acknowledgement moves the marker forward again and re-raises the latch,
   * exactly like any other first-time narrowing.
   *
   * Returns whether the latch is clear immediately after this call: `true`
   * when nothing was outstanding or the baseline covered it, `false` when a
   * stale baseline left it latched.
   */
  markRematerialized(missionId: string, observedBaseline: RematerializationBaseline): boolean {
    const marker = this.rematerializeNeeded.get(missionId);
    if (!marker) return true; // nothing outstanding
    const coversVersion = observedBaseline.version >= marker.version;
    const coversContainment =
      marker.containment_version === undefined ||
      (observedBaseline.containment_version !== undefined &&
        observedBaseline.containment_version >= marker.containment_version);
    if (coversVersion && coversContainment) {
      this.rematerializeNeeded.delete(missionId);
      return true;
    }
    return false;
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
  /** @spec signals#lifecycle-event — the generic narrowing discriminator,
   *  when the event carries it. */
  authority_changed?: boolean;
  /** @spec containment#propagation — the containment generation counter,
   *  when the event carries it. */
  containment_version?: number;
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
  return {
    missionId,
    state,
    version,
    expires_at,
    // `authority_changed` is a MUST-ignore-if-unrecognized member; a consumer
    // that does not understand it simply never sets these, so it is optional
    // here too (draft §consumer-behavior forward-compatibility).
    ...(typeof ev.authority_changed === "boolean"
      ? { authority_changed: ev.authority_changed }
      : {}),
    ...(typeof ev.containment_version === "number"
      ? { containment_version: ev.containment_version }
      : {}),
  };
}

/**
 * @spec signals#discharge-compatibility — the one value this document defines
 * for the receiver-supplied `mission_capabilities_supported` member of the SSF
 * Stream Configuration object: support for the `authority_changed`
 * rematerialization rule.
 */
export const AUTHORITY_CHANGED_CAPABILITY = "authority_changed";

/**
 * A consumer this issuer emits to, identified by its registered audience.
 *
 * @spec signals#discharge-compatibility — `mission_capabilities_supported` is
 * the receiver's declared capability list from its Stream Configuration. A
 * consumer that has NOT declared {@link AUTHORITY_CHANGED_CAPABILITY} is not
 * delivered an event whose effective-authority change is represented by
 * `authority_changed` ALONE (a discharge commit): such a consumer ignores the
 * unknown member, accepts an in-order active-to-active version increment, and
 * keeps a stale Authority Set, exactly the failure the member exists to
 * prevent. Absent means it declared nothing.
 */
export interface SignalConsumer {
  audience: string;
  mission_capabilities_supported?: string[];
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

  /**
   * @spec signals#discharge-compatibility — the delivery GATE. The bound events
   * are exactly those whose effective-authority change is represented by
   * `authority_changed` alone: a commit that set the discriminator WITHOUT
   * advancing `containment_version` (a discharge commit). An event whose
   * narrowing is also represented by a `containment_version` ADVANCE follows the
   * containment profile's existing delivery rules unchanged, and every event
   * that narrows nothing is unaffected.
   *
   * Provenance comes from the kernel's own commit-time discriminator
   * ({@link LifecycleCommit.containment_advanced}), never from emitter-side
   * version history: an in-memory cursor does not survive restart, and a
   * fresh emitter would either mistake a discharge on a previously contained
   * Mission (unchanged `containment_version`) for the first containment
   * advance — delivering an `authority_changed`-only narrowing to a consumer
   * that never declared the capability — or withhold a real containment
   * event first observed above version 1.
   */
  private deliverable(commit: LifecycleCommit, consumer: SignalConsumer): boolean {
    if (commit.authority_changed !== true) return true;
    if (commit.containment_advanced === true) return true;
    return (consumer.mission_capabilities_supported ?? []).includes(AUTHORITY_CHANGED_CAPABILITY);
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
      // @spec signals#discharge-compatibility — an undeclared stream is not
      // delivered an event whose narrowing rides `authority_changed` alone.
      if (!this.deliverable(commit, consumer)) continue;
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
