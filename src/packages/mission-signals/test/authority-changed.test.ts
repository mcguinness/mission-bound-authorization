/**
 * @spec draft-mcguinness-oauth-mission-signals #562
 *
 * The generic `authority_changed` discriminator (signals.md:408-422) and the
 * receiver's rematerialization rule for it and for `containment_version`
 * (signals.md:589-600 / status.md:1725-1729 Discharge Visibility). Before this
 * PR the builder emitted `containment_version` but never `authority_changed`,
 * and the receiver parsed neither. This file proves, positively and
 * negatively:
 *
 * - the builder emits `authority_changed: true` on a metadata-only commit
 *   that narrows effective authority (containment today, the only such
 *   funnel the kernel implements; entry discharge is named by the spec as
 *   the other case but has no kernel funnel yet, so its emission is proven
 *   here with a hand-built commit shaped the way a discharge commit would
 *   be: `state` unchanged, `authority_changed` computed true upstream) and
 *   leaves it absent on every other transition (activating insert, a plain
 *   state-changing transition);
 * - the builder only RELAYS the upstream commit's own `authority_changed`
 *   value, never recomputes it;
 * - the receiver rematerializes (flags `needsRematerialization`, and returns
 *   `rematerialize: true` on the applied event) on `authority_changed` true,
 *   and does NOT on false or absent;
 * - the receiver independently rematerializes on a `containment_version`
 *   advance past the value it last observed, and does NOT on a stale/equal
 *   `containment_version`.
 *
 * #572 (review of #562) added two corrections, also proven here:
 * - `authority_changed` is true only when a contain commit's EFFECTIVE set
 *   actually narrowed, never merely because a fresh `event_id` reached the
 *   metadata-only commit path (a removal already fully represented in the
 *   contained set still bumps `version`/`containment_version` but must leave
 *   `authority_changed` absent);
 * - the receiver's `needsRematerialization` latch is no longer permanent:
 *   `markRematerialized(missionId, observedBaseline)` clears it when the
 *   baseline covers the tracked narrowing, leaves it latched on a stale
 *   baseline, and a later narrowing re-raises it even after a successful
 *   acknowledgement.
 */

import {
  type LifecycleCommit,
  MissionKernel,
  validateMissionIntent,
} from "@mission/authorization-server";
import { exportJWK, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import {
  type ApplyResult,
  MissionSignalEmitter,
  MissionSignalReceiver,
  signLifecycleEvent,
} from "../src/index.js";

const ISS = "https://as.test";
const CONSUMER_AUD = "https://erp.consumer.test";
const RESOURCE = "https://payments.test/mcp";
const NOW = new Date("2026-08-17T12:00:00Z");
const EXPIRES_AT = "2027-01-01T00:00:00Z";

const POLICY = {
  policy_version: "authority-changed-v1",
  ceiling: [
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: ["payments:invoice.read", "payments:payment.execute"],
    },
  ],
};

const intent = () =>
  validateMissionIntent(
    JSON.stringify({
      goal: "Read approved invoices",
      target_resources: [RESOURCE],
      expires_at: EXPIRES_AT,
    }),
  );

describe("authority_changed — builder emission (@spec signals#lifecycle-event)", () => {
  it("leaves authority_changed absent on the activating commit (version 1, no prior_state)", async () => {
    const statusKeys = await generateKeyPair("ES256", { extractable: true });
    const commits: LifecycleCommit[] = [];
    const kernel = new MissionKernel({
      issuer: ISS,
      policy: POLICY as never,
      statusKey: statusKeys.privateKey,
      statusKid: "as-status",
      now: () => NOW,
      onLifecycleCommit: (c) => commits.push(c),
    });

    kernel.approve({
      intent: intent(),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: "apev-ac-1",
    });

    expect(commits[0]?.authority_changed).toBeUndefined();
    const set = await signLifecycleEvent(commits[0] as LifecycleCommit, {
      audience: CONSUMER_AUD,
      key: statusKeys.privateKey,
      kid: "as-status",
    });
    const event = eventOf(set);
    expect(event.authority_changed).toBeUndefined();
  });

  it("leaves authority_changed absent on a plain state-changing transition (revoke)", async () => {
    const statusKeys = await generateKeyPair("ES256", { extractable: true });
    const commits: LifecycleCommit[] = [];
    const kernel = new MissionKernel({
      issuer: ISS,
      policy: POLICY as never,
      statusKey: statusKeys.privateKey,
      statusKid: "as-status",
      now: () => NOW,
      onLifecycleCommit: (c) => commits.push(c),
    });

    const mission = kernel.approve({
      intent: intent(),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: "apev-ac-2",
    });
    kernel.transition(mission.id, "revoke");

    const revokeCommit = commits.find((c) => c.state === "revoked");
    expect(revokeCommit?.prior_state).toBe("active"); // state DID change: not metadata-only
    expect(revokeCommit?.authority_changed).toBeUndefined();

    const set = await signLifecycleEvent(revokeCommit as LifecycleCommit, {
      audience: CONSUMER_AUD,
      key: statusKeys.privateKey,
      kid: "as-status",
    });
    expect(eventOf(set).authority_changed).toBeUndefined();
  });

  it("emits authority_changed true on a contain commit (metadata-only, narrows effective authority)", async () => {
    const statusKeys = await generateKeyPair("ES256", { extractable: true });
    const commits: LifecycleCommit[] = [];
    const kernel = new MissionKernel({
      issuer: ISS,
      policy: POLICY as never,
      statusKey: statusKeys.privateKey,
      statusKid: "as-status",
      now: () => NOW,
      onLifecycleCommit: (c) => commits.push(c),
    });

    const mission = kernel.approve({
      intent: intent(),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: "apev-ac-3",
    });
    kernel.contain(mission.id, {
      event: {
        type: "anomaly.detected",
        source: "svc:soc",
        observed_at: NOW.toISOString(),
        event_id: "evt-ac-3",
      },
      remove: [{ resource: RESOURCE, actions: ["payments:payment.execute"] }],
    });

    const containCommit = commits[1] as LifecycleCommit;
    expect(containCommit.state).toBe("active");
    expect(containCommit.prior_state).toBe("active"); // metadata-only
    expect(containCommit.authority_changed).toBe(true);

    const set = await signLifecycleEvent(containCommit, {
      audience: CONSUMER_AUD,
      key: statusKeys.privateKey,
      kid: "as-status",
    });
    expect(eventOf(set)).toMatchObject({
      state: "active",
      prior_state: "active",
      authority_changed: true,
      containment_version: 1,
    });
  });

  it("omits authority_changed on a FRESH contain event whose removal is already fully represented (no real narrowing), even though version/containment_version still advance", async () => {
    // #572 regression: contain()'s idempotency is keyed by event_id, not by
    // effect. A DIFFERENT event whose remove[] the contained set already
    // fully covers still reaches the metadata-only commit (a real version
    // and containment_version bump), but the EFFECTIVE set is unchanged, so
    // the emitted signal must not claim a narrowing that did not happen.
    const statusKeys = await generateKeyPair("ES256", { extractable: true });
    const commits: LifecycleCommit[] = [];
    const kernel = new MissionKernel({
      issuer: ISS,
      policy: POLICY as never,
      statusKey: statusKeys.privateKey,
      statusKid: "as-status",
      now: () => NOW,
      onLifecycleCommit: (c) => commits.push(c),
    });

    const mission = kernel.approve({
      intent: intent(),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: "apev-ac-4",
    });
    kernel.contain(mission.id, {
      event: {
        type: "anomaly.detected",
        source: "svc:soc",
        observed_at: NOW.toISOString(),
        event_id: "evt-ac-4a",
      },
      remove: [{ resource: RESOURCE, actions: ["payments:payment.execute"] }],
    });
    expect(commits[1]?.authority_changed).toBe(true); // the genuine narrowing

    // A fresh event_id (NOT a repeat of evt-ac-4a) whose removal the
    // contained set already fully represents.
    kernel.contain(mission.id, {
      event: {
        type: "anomaly.detected",
        source: "svc:soc",
        observed_at: NOW.toISOString(),
        event_id: "evt-ac-4b",
      },
      remove: [{ resource: RESOURCE, actions: ["payments:payment.execute"] }],
    });
    const dupCommit = commits[2] as LifecycleCommit;
    // The commit is real, not a no-op: idempotency is by event_id, and
    // evt-ac-4b is a fresh id.
    expect(dupCommit.version).toBe(3);
    expect(dupCommit.containment_version).toBe(2);
    expect(dupCommit.authority_changed).toBeUndefined();

    const set = await signLifecycleEvent(dupCommit, {
      audience: CONSUMER_AUD,
      key: statusKeys.privateKey,
      kid: "as-status",
    });
    expect(eventOf(set)).toMatchObject({ containment_version: 2 });
    expect(eventOf(set).authority_changed).toBeUndefined();
  });

  it("relays (never recomputes) a hand-built commit shaped like a future entry-discharge commit", async () => {
    // No kernel funnel commits an entry discharge yet (#562's scope is the
    // already-specified `authority_changed`/`containment_version` wire
    // members, not the discharge operation itself). This proves the builder
    // is a pure relay: it copies whatever the upstream commit computed,
    // regardless of which narrowing overlay produced it.
    const statusKeys = await generateKeyPair("ES256", { extractable: true });
    const dischargeShapedCommit: LifecycleCommit = {
      id: "msn_discharge_shape",
      issuer: ISS,
      state: "active",
      prior_state: "active",
      version: 4,
      committed_at: NOW.toISOString(),
      expires_at: EXPIRES_AT,
      authority_changed: true, // computed upstream by a hypothetical discharge funnel
    };
    const set = await signLifecycleEvent(dischargeShapedCommit, {
      audience: CONSUMER_AUD,
      key: statusKeys.privateKey,
      kid: "as-status",
    });
    expect(eventOf(set)).toMatchObject({
      state: "active",
      prior_state: "active",
      authority_changed: true,
    });
    expect(eventOf(set).containment_version).toBeUndefined(); // unrelated overlay, absent
  });

  it("relays authority_changed false/absent as absent on the wire (no re-derivation)", async () => {
    const statusKeys = await generateKeyPair("ES256", { extractable: true });
    const commitFalse: LifecycleCommit = {
      id: "msn_relay_false",
      issuer: ISS,
      state: "active",
      prior_state: "active",
      version: 2,
      committed_at: NOW.toISOString(),
      expires_at: EXPIRES_AT,
      authority_changed: false,
    };
    const set = await signLifecycleEvent(commitFalse, {
      audience: CONSUMER_AUD,
      key: statusKeys.privateKey,
      kid: "as-status",
    });
    expect(eventOf(set).authority_changed).toBeUndefined();
  });
});

describe("authority_changed / containment_version — receiver rematerialization (@spec signals#consumer-behavior)", () => {
  async function wired() {
    const statusKeys = await generateKeyPair("ES256", { extractable: true });
    const statusPub = {
      ...(await exportJWK(statusKeys.publicKey)),
      kid: "as-status",
      alg: "ES256",
      use: "sig",
    };
    const emitter = new MissionSignalEmitter({
      key: statusKeys.privateKey,
      kid: "as-status",
      consumers: [{ audience: CONSUMER_AUD }],
    });
    const receiver = new MissionSignalReceiver({
      jwks: { keys: [statusPub] },
      issuer: ISS,
      audience: CONSUMER_AUD,
    });
    return { statusKeys, emitter, receiver };
  }

  it("does NOT rematerialize on an in-order event with authority_changed absent", async () => {
    const { statusKeys, receiver } = await wired();
    const commit: LifecycleCommit = {
      id: "msn_neg_absent",
      issuer: ISS,
      state: "active",
      version: 1,
      committed_at: NOW.toISOString(),
      expires_at: EXPIRES_AT,
    };
    const set = await signLifecycleEvent(commit, {
      audience: CONSUMER_AUD,
      key: statusKeys.privateKey,
      kid: "as-status",
    });
    const result = (await receiver.verifyAndApply(set)) as ApplyResult;
    expect(result).toMatchObject({ status: "applied", rematerialize: false });
    expect(receiver.needsRematerialization("msn_neg_absent")).toBe(false);
  });

  it("does NOT rematerialize on an in-order event with authority_changed false", async () => {
    const { statusKeys, receiver } = await wired();
    const activating: LifecycleCommit = {
      id: "msn_neg_false",
      issuer: ISS,
      state: "active",
      version: 1,
      committed_at: NOW.toISOString(),
      expires_at: EXPIRES_AT,
    };
    await receiver.verifyAndApply(
      await signLifecycleEvent(activating, {
        audience: CONSUMER_AUD,
        key: statusKeys.privateKey,
        kid: "as-status",
      }),
    );
    const commit: LifecycleCommit = {
      id: "msn_neg_false",
      issuer: ISS,
      state: "active",
      prior_state: "active",
      version: 2,
      committed_at: NOW.toISOString(),
      expires_at: EXPIRES_AT,
      authority_changed: false,
    };
    const set = await signLifecycleEvent(commit, {
      audience: CONSUMER_AUD,
      key: statusKeys.privateKey,
      kid: "as-status",
    });
    const result = (await receiver.verifyAndApply(set)) as ApplyResult;
    expect(result).toMatchObject({ status: "applied", rematerialize: false });
    expect(receiver.needsRematerialization("msn_neg_false")).toBe(false);
  });

  it("rematerializes on an in-order event with authority_changed true, state unchanged", async () => {
    const { statusKeys, receiver } = await wired();
    const activating: LifecycleCommit = {
      id: "msn_pos_true",
      issuer: ISS,
      state: "active",
      version: 1,
      committed_at: NOW.toISOString(),
      expires_at: EXPIRES_AT,
    };
    await receiver.verifyAndApply(
      await signLifecycleEvent(activating, {
        audience: CONSUMER_AUD,
        key: statusKeys.privateKey,
        kid: "as-status",
      }),
    );
    const dischargeShaped: LifecycleCommit = {
      id: "msn_pos_true",
      issuer: ISS,
      state: "active",
      prior_state: "active",
      version: 2,
      committed_at: NOW.toISOString(),
      expires_at: EXPIRES_AT,
      authority_changed: true,
    };
    const result = (await receiver.verifyAndApply(
      await signLifecycleEvent(dischargeShaped, {
        audience: CONSUMER_AUD,
        key: statusKeys.privateKey,
        kid: "as-status",
      }),
    )) as ApplyResult;
    expect(result).toMatchObject({
      status: "applied",
      state: "active",
      version: 2,
      rematerialize: true,
    });
    expect(receiver.needsRematerialization("msn_pos_true")).toBe(true);
  });

  it("latches: needsRematerialization stays true across a later event that does not itself require it", async () => {
    // A later event's own `rematerialize: false` proves nothing about
    // whether the consumer already rematerialized after the EARLIER
    // narrowing, so the flag must not auto-clear (unlike `hasGap`, whose gap
    // condition IS re-established by the very next in-order event).
    const { statusKeys, receiver } = await wired();
    const activating: LifecycleCommit = {
      id: "msn_latch",
      issuer: ISS,
      state: "active",
      version: 1,
      committed_at: NOW.toISOString(),
      expires_at: EXPIRES_AT,
    };
    await receiver.verifyAndApply(
      await signLifecycleEvent(activating, {
        audience: CONSUMER_AUD,
        key: statusKeys.privateKey,
        kid: "as-status",
      }),
    );
    const narrowing: LifecycleCommit = {
      id: "msn_latch",
      issuer: ISS,
      state: "active",
      prior_state: "active",
      version: 2,
      committed_at: NOW.toISOString(),
      expires_at: EXPIRES_AT,
      authority_changed: true,
    };
    const narrowResult = (await receiver.verifyAndApply(
      await signLifecycleEvent(narrowing, {
        audience: CONSUMER_AUD,
        key: statusKeys.privateKey,
        kid: "as-status",
      }),
    )) as ApplyResult;
    expect(narrowResult).toMatchObject({ rematerialize: true });
    expect(receiver.needsRematerialization("msn_latch")).toBe(true);

    // A plain, unrelated state-changing transition: authority_changed absent,
    // no containment_version at all. Its own outcome is rematerialize: false...
    const suspend: LifecycleCommit = {
      id: "msn_latch",
      issuer: ISS,
      state: "suspended",
      prior_state: "active",
      version: 3,
      committed_at: NOW.toISOString(),
      expires_at: EXPIRES_AT,
    };
    const suspendResult = (await receiver.verifyAndApply(
      await signLifecycleEvent(suspend, {
        audience: CONSUMER_AUD,
        key: statusKeys.privateKey,
        kid: "as-status",
      }),
    )) as ApplyResult;
    expect(suspendResult).toMatchObject({ status: "applied", rematerialize: false });
    // ...but the LATCHED flag must still read true: the consumer has not
    // been told it may stop treating the authority view as stale.
    expect(receiver.needsRematerialization("msn_latch")).toBe(true);
  });

  it("rematerializes independently on a containment_version advance with authority_changed absent from the event", async () => {
    // Proves the containment-aware consumer's OWN independent trigger
    // (signals.md:598-600): a containment_version advance rematerializes
    // even when this particular event does not itself carry
    // `authority_changed` (a generic consumer would still catch the real
    // wire event via the discriminator; this isolates the second path).
    const { statusKeys, receiver } = await wired();
    const activating: LifecycleCommit = {
      id: "msn_cv_advance",
      issuer: ISS,
      state: "active",
      version: 1,
      committed_at: NOW.toISOString(),
      expires_at: EXPIRES_AT,
      containment_version: 1,
    };
    await receiver.verifyAndApply(
      await signLifecycleEvent(activating, {
        audience: CONSUMER_AUD,
        key: statusKeys.privateKey,
        kid: "as-status",
      }),
    );
    expect(receiver.viewState("msn_cv_advance")).toMatchObject({ containment_version: 1 });

    const advanced: LifecycleCommit = {
      id: "msn_cv_advance",
      issuer: ISS,
      state: "active",
      prior_state: "active",
      version: 2,
      committed_at: NOW.toISOString(),
      expires_at: EXPIRES_AT,
      containment_version: 2, // advanced past 1, authority_changed NOT set on this commit
    };
    const result = (await receiver.verifyAndApply(
      await signLifecycleEvent(advanced, {
        audience: CONSUMER_AUD,
        key: statusKeys.privateKey,
        kid: "as-status",
      }),
    )) as ApplyResult;
    expect(result).toMatchObject({ status: "applied", rematerialize: true });
    expect(receiver.needsRematerialization("msn_cv_advance")).toBe(true);
  });

  it("ignores a stale or equal containment_version (does not rematerialize)", async () => {
    const { statusKeys, receiver } = await wired();
    const activating: LifecycleCommit = {
      id: "msn_cv_stale",
      issuer: ISS,
      state: "active",
      version: 1,
      committed_at: NOW.toISOString(),
      expires_at: EXPIRES_AT,
      containment_version: 3,
    };
    await receiver.verifyAndApply(
      await signLifecycleEvent(activating, {
        audience: CONSUMER_AUD,
        key: statusKeys.privateKey,
        kid: "as-status",
      }),
    );

    // A later, in-order (version advances) event that repeats the SAME
    // containment_version (no new narrowing on this commit, e.g. a plain
    // suspend after containment was applied once): must NOT rematerialize.
    const equalCv: LifecycleCommit = {
      id: "msn_cv_stale",
      issuer: ISS,
      state: "suspended",
      prior_state: "active",
      version: 2,
      committed_at: NOW.toISOString(),
      expires_at: EXPIRES_AT,
      containment_version: 3, // equal, not an advance
    };
    const result = (await receiver.verifyAndApply(
      await signLifecycleEvent(equalCv, {
        audience: CONSUMER_AUD,
        key: statusKeys.privateKey,
        kid: "as-status",
      }),
    )) as ApplyResult;
    expect(result).toMatchObject({ status: "applied", rematerialize: false });
    expect(receiver.needsRematerialization("msn_cv_stale")).toBe(false);

    // A stale (lower-version) redelivery carrying a NEWER containment_version
    // than materialized is rejected by the anti-revive version check before
    // containment_version is even considered: still no rematerialization.
    const staleVersionNewCv: LifecycleCommit = {
      id: "msn_cv_stale",
      issuer: ISS,
      state: "active",
      version: 1, // <= last applied (2): stale by version
      committed_at: NOW.toISOString(),
      expires_at: EXPIRES_AT,
      containment_version: 99,
    };
    const staleResult = await receiver.verifyAndApply(
      await signLifecycleEvent(staleVersionNewCv, {
        audience: CONSUMER_AUD,
        key: statusKeys.privateKey,
        kid: "as-status",
      }),
    );
    expect(staleResult.status).toBe("stale");
    expect(receiver.needsRematerialization("msn_cv_stale")).toBe(false);
  });

  it("wired end-to-end: a real kernel contain() commit drives the receiver to rematerialize", async () => {
    const statusKeys = await generateKeyPair("ES256", { extractable: true });
    const statusPub = {
      ...(await exportJWK(statusKeys.publicKey)),
      kid: "as-status",
      alg: "ES256",
      use: "sig",
    };
    const emitter = new MissionSignalEmitter({
      key: statusKeys.privateKey,
      kid: "as-status",
      consumers: [{ audience: CONSUMER_AUD }],
    });
    const receiver = new MissionSignalReceiver({
      jwks: { keys: [statusPub] },
      issuer: ISS,
      audience: CONSUMER_AUD,
    });
    emitter.register(receiver);

    const kernel = new MissionKernel({
      issuer: ISS,
      policy: POLICY as never,
      statusKey: statusKeys.privateKey,
      statusKid: "as-status",
      now: () => NOW,
      onLifecycleCommit: (c) => emitter.onCommit(c),
    });

    const mission = kernel.approve({
      intent: intent(),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: "apev-ac-e2e",
    });
    await emitter.drain();
    expect(receiver.needsRematerialization(mission.id)).toBe(false);

    kernel.contain(mission.id, {
      event: {
        type: "anomaly.detected",
        source: "svc:soc",
        observed_at: NOW.toISOString(),
        event_id: "evt-ac-e2e",
      },
      remove: [{ resource: RESOURCE, actions: ["payments:payment.execute"] }],
    });
    await emitter.drain();

    expect(receiver.viewState(mission.id)).toMatchObject({ state: "active", version: 2 });
    expect(receiver.needsRematerialization(mission.id)).toBe(true);
  });

  describe("markRematerialized(): version-bound acknowledgement (#572)", () => {
    it("clears the latch when the acknowledged baseline covers the narrowing", async () => {
      const { statusKeys, receiver } = await wired();
      const activating: LifecycleCommit = {
        id: "msn_ack_clear",
        issuer: ISS,
        state: "active",
        version: 1,
        committed_at: NOW.toISOString(),
        expires_at: EXPIRES_AT,
      };
      await receiver.verifyAndApply(
        await signLifecycleEvent(activating, {
          audience: CONSUMER_AUD,
          key: statusKeys.privateKey,
          kid: "as-status",
        }),
      );
      const narrowing: LifecycleCommit = {
        id: "msn_ack_clear",
        issuer: ISS,
        state: "active",
        prior_state: "active",
        version: 2,
        committed_at: NOW.toISOString(),
        expires_at: EXPIRES_AT,
        authority_changed: true,
      };
      await receiver.verifyAndApply(
        await signLifecycleEvent(narrowing, {
          audience: CONSUMER_AUD,
          key: statusKeys.privateKey,
          kid: "as-status",
        }),
      );
      expect(receiver.needsRematerialization("msn_ack_clear")).toBe(true);

      // The consumer's Status refresh returned version 2 (at or past the
      // narrowing): the acknowledgement clears the latch.
      expect(receiver.markRematerialized("msn_ack_clear", { version: 2 })).toBe(true);
      expect(receiver.needsRematerialization("msn_ack_clear")).toBe(false);

      // Acknowledging again with nothing outstanding is a no-op success.
      expect(receiver.markRematerialized("msn_ack_clear", { version: 2 })).toBe(true);
    });

    it("does not clear the latch when the acknowledged baseline is stale (older than the narrowing)", async () => {
      const { statusKeys, receiver } = await wired();
      const activating: LifecycleCommit = {
        id: "msn_ack_stale",
        issuer: ISS,
        state: "active",
        version: 1,
        committed_at: NOW.toISOString(),
        expires_at: EXPIRES_AT,
      };
      await receiver.verifyAndApply(
        await signLifecycleEvent(activating, {
          audience: CONSUMER_AUD,
          key: statusKeys.privateKey,
          kid: "as-status",
        }),
      );
      const narrowing: LifecycleCommit = {
        id: "msn_ack_stale",
        issuer: ISS,
        state: "active",
        prior_state: "active",
        version: 2,
        committed_at: NOW.toISOString(),
        expires_at: EXPIRES_AT,
        authority_changed: true,
      };
      await receiver.verifyAndApply(
        await signLifecycleEvent(narrowing, {
          audience: CONSUMER_AUD,
          key: statusKeys.privateKey,
          kid: "as-status",
        }),
      );
      expect(receiver.needsRematerialization("msn_ack_stale")).toBe(true);

      // A baseline from BEFORE the narrowing (version 1): stale, must not clear.
      expect(receiver.markRematerialized("msn_ack_stale", { version: 1 })).toBe(false);
      expect(receiver.needsRematerialization("msn_ack_stale")).toBe(true);
    });

    it("a narrowing that arrives after a successful acknowledgement re-raises the latch", async () => {
      const { statusKeys, receiver } = await wired();
      const activating: LifecycleCommit = {
        id: "msn_ack_reraise",
        issuer: ISS,
        state: "active",
        version: 1,
        committed_at: NOW.toISOString(),
        expires_at: EXPIRES_AT,
      };
      await receiver.verifyAndApply(
        await signLifecycleEvent(activating, {
          audience: CONSUMER_AUD,
          key: statusKeys.privateKey,
          kid: "as-status",
        }),
      );
      const narrowing1: LifecycleCommit = {
        id: "msn_ack_reraise",
        issuer: ISS,
        state: "active",
        prior_state: "active",
        version: 2,
        committed_at: NOW.toISOString(),
        expires_at: EXPIRES_AT,
        authority_changed: true,
      };
      await receiver.verifyAndApply(
        await signLifecycleEvent(narrowing1, {
          audience: CONSUMER_AUD,
          key: statusKeys.privateKey,
          kid: "as-status",
        }),
      );
      expect(receiver.markRematerialized("msn_ack_reraise", { version: 2 })).toBe(true);
      expect(receiver.needsRematerialization("msn_ack_reraise")).toBe(false);

      // A LATER narrowing (version 3) after the acknowledged baseline.
      const narrowing2: LifecycleCommit = {
        id: "msn_ack_reraise",
        issuer: ISS,
        state: "active",
        prior_state: "active",
        version: 3,
        committed_at: NOW.toISOString(),
        expires_at: EXPIRES_AT,
        authority_changed: true,
      };
      await receiver.verifyAndApply(
        await signLifecycleEvent(narrowing2, {
          audience: CONSUMER_AUD,
          key: statusKeys.privateKey,
          kid: "as-status",
        }),
      );
      expect(receiver.needsRematerialization("msn_ack_reraise")).toBe(true);

      // The OLD acknowledged baseline (version 2) no longer covers the new marker.
      expect(receiver.markRematerialized("msn_ack_reraise", { version: 2 })).toBe(false);
      expect(receiver.needsRematerialization("msn_ack_reraise")).toBe(true);
      // Only a baseline covering the NEW narrowing clears it.
      expect(receiver.markRematerialized("msn_ack_reraise", { version: 3 })).toBe(true);
      expect(receiver.needsRematerialization("msn_ack_reraise")).toBe(false);
    });

    it("a baseline omitting containment_version does not clear a containment-driven latch (fail-closed)", async () => {
      const { statusKeys, receiver } = await wired();
      const activating: LifecycleCommit = {
        id: "msn_ack_cv",
        issuer: ISS,
        state: "active",
        version: 1,
        committed_at: NOW.toISOString(),
        expires_at: EXPIRES_AT,
        containment_version: 1,
      };
      await receiver.verifyAndApply(
        await signLifecycleEvent(activating, {
          audience: CONSUMER_AUD,
          key: statusKeys.privateKey,
          kid: "as-status",
        }),
      );
      // A pure containment_version advance (authority_changed absent from
      // this event): the OTHER independent rematerialize trigger.
      const advanced: LifecycleCommit = {
        id: "msn_ack_cv",
        issuer: ISS,
        state: "active",
        prior_state: "active",
        version: 2,
        committed_at: NOW.toISOString(),
        expires_at: EXPIRES_AT,
        containment_version: 2,
      };
      await receiver.verifyAndApply(
        await signLifecycleEvent(advanced, {
          audience: CONSUMER_AUD,
          key: statusKeys.privateKey,
          kid: "as-status",
        }),
      );
      expect(receiver.needsRematerialization("msn_ack_cv")).toBe(true);

      // version covers it, but containment_version is MISSING from the
      // baseline: fails closed, does not clear.
      expect(receiver.markRematerialized("msn_ack_cv", { version: 2 })).toBe(false);
      expect(receiver.needsRematerialization("msn_ack_cv")).toBe(true);

      // version covers it, but containment_version is BEHIND the marker: also
      // does not clear.
      expect(
        receiver.markRematerialized("msn_ack_cv", { version: 2, containment_version: 1 }),
      ).toBe(false);
      expect(receiver.needsRematerialization("msn_ack_cv")).toBe(true);

      // Both fields cover the marker: clears.
      expect(
        receiver.markRematerialized("msn_ack_cv", { version: 2, containment_version: 2 }),
      ).toBe(true);
      expect(receiver.needsRematerialization("msn_ack_cv")).toBe(false);
    });
  });
});

/** Decode a signed SET's lifecycle-change event body (test-only helper). */
function eventOf(setJwt: string): Record<string, unknown> {
  const [, payloadB64] = setJwt.split(".");
  const json = Buffer.from(payloadB64 as string, "base64url").toString("utf8");
  const payload = JSON.parse(json) as { events: Record<string, Record<string, unknown>> };
  return payload.events["https://schemas.karlmcguinness.com/mission/lifecycle-change"] as Record<
    string,
    unknown
  >;
}
