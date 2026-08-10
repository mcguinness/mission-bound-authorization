/**
 * @spec draft-mcguinness-oauth-mission-signals
 *
 * A contain transition is a committed METADATA-ONLY change: the version
 * increments while `prior_state` equals `state`. It fires the same
 * lifecycle-commit fan-out as every other funnel, so Mission Signals propagate
 * it with no new channels. This proves a wired MissionSignalReceiver APPLIES
 * the metadata-only commit (version moves forward, state unchanged; never
 * `duplicate` or `stale`) and the Status List republishes with the bit
 * unchanged for an active Mission. In-process, deterministic (no HTTP, no
 * OpenFGA), mirroring the suspend-lift test's harness.
 */

import {
  type LifecycleCommit,
  MissionKernel,
  readStatusBit,
  STATUS_VALID,
  statusListUri,
  validateMissionIntent,
  verifyStatusListToken,
} from "@mission/authorization-server";
import { decodeJwt, exportJWK, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import {
  type ApplyResult,
  LIFECYCLE_CHANGE_EVENT_URI,
  MissionSignalEmitter,
  MissionSignalReceiver,
  signLifecycleEvent,
} from "../src/index.js";

const ISS = "https://as.test";
const CONSUMER_AUD = "https://erp.consumer.test";
const RESOURCE = "https://payments.test/mcp";
const NOW = new Date("2026-08-06T12:00:00Z");
const EXPIRES_AT = "2027-01-01T00:00:00Z";
const URI = statusListUri(ISS);

const POLICY = {
  policy_version: "containment-signal-v1",
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
      resources: [RESOURCE],
      expires_at: EXPIRES_AT,
    }),
  );

describe("contain commit propagated by Mission Signals (metadata-only)", () => {
  it("applies the same-state, version-incremented commit and the Status List bit stays VALID", async () => {
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
    emitter.register(receiver); // the wired path: exactly one delivery per SET

    const commits: LifecycleCommit[] = [];
    const kernel = new MissionKernel({
      issuer: ISS,
      policy: POLICY as never,
      statusKey: statusKeys.privateKey,
      statusKid: "as-status",
      now: () => NOW,
      onLifecycleCommit: (c) => {
        commits.push(c);
        emitter.onCommit(c);
      },
    });

    const mission = kernel.approve({
      intent: intent(),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: "apev-contain-signal-1",
    });
    const idx = kernel.participateInStatusList(mission.id);
    // Drain the activating commit's SET before containing: onCommit dispatches
    // an async sign-then-deliver per commit with no cross-commit ordering
    // guarantee, so two in-flight SETs can arrive inverted under load (the
    // suspend-lift test drains between transitions for the same reason).
    await emitter.drain();

    // The contain transition: version 2, state unchanged (metadata-only).
    kernel.contain(mission.id, {
      event: {
        type: "anomaly.detected",
        source: "svc:soc",
        observed_at: NOW.toISOString(),
        event_id: "evt-signal-1",
      },
      remove: [{ resource: RESOURCE, actions: ["payments:payment.execute"] }],
    });
    await emitter.drain();

    // The wired receiver APPLIED the metadata-only commit: its view moved to
    // version 2 with the state unchanged, and no gap was recorded.
    expect(receiver.viewState(mission.id)).toMatchObject({ state: "active", version: 2 });
    expect(receiver.hasGap(mission.id)).toBe(false);

    // The commit sequence: the activating v1, then the contain commit with
    // prior_state EQUAL to state (the metadata-only marker).
    const missionCommits = commits.filter((c) => c.id === mission.id);
    expect(missionCommits.map((c) => [c.state, c.version])).toEqual([
      ["active", 1],
      ["active", 2],
    ]);
    expect(missionCommits[0]?.prior_state).toBeUndefined();
    expect(missionCommits[1]?.prior_state).toBe("active");

    // The Status List republishes; the bit is unchanged for an active Mission.
    const tok = await verifyStatusListToken(
      await kernel.publishStatusList(),
      statusKeys.publicKey,
      {
        uri: URI,
        now: NOW,
      },
    );
    expect(readStatusBit(tok, idx)).toBe(STATUS_VALID);

    // Explicit ordered-apply proof on a FRESH receiver: both commits apply --
    // the metadata-only commit is not `duplicate` (same state) nor `stale`,
    // because acceptance is version-based forward progress.
    const fresh = new MissionSignalReceiver({
      jwks: { keys: [statusPub] },
      issuer: ISS,
      audience: CONSUMER_AUD,
    });
    const results: ApplyResult[] = [];
    for (const c of missionCommits) {
      const set = await signLifecycleEvent(c, {
        audience: CONSUMER_AUD,
        key: statusKeys.privateKey,
        kid: "as-status",
      });
      results.push(await fresh.verifyAndApply(set));
    }
    expect(results[0]).toMatchObject({ status: "applied", state: "active", version: 1 });
    expect(results[1]).toMatchObject({ status: "applied", state: "active", version: 2 });
  });

  it("carries the changed containment_version on the emitted SET across a contained-then-still-active sequence", async () => {
    // @spec containment#propagation, signals#lifecycle-event — a contain
    // commit is metadata-only (state === prior_state), so a consumer that
    // only compares `state` sees nothing move. containment_version on the
    // emitted event is what makes the narrowing legible without a state
    // change or a version gap.
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
      approvalEventId: "apev-contain-signal-2",
    });

    // First contain: active -> active, containment_version 0 -> 1.
    kernel.contain(mission.id, {
      event: {
        type: "anomaly.detected",
        source: "svc:soc",
        observed_at: NOW.toISOString(),
        event_id: "evt-signal-2a",
      },
      remove: [{ resource: RESOURCE, actions: ["payments:payment.execute"] }],
    });
    // Second contain: STILL active -> active (same as the first transition's
    // state pair), containment_version 1 -> 2.
    kernel.contain(mission.id, {
      event: {
        type: "anomaly.detected",
        source: "svc:soc",
        observed_at: NOW.toISOString(),
        event_id: "evt-signal-2b",
      },
      remove: [{ resource: RESOURCE, actions: ["payments:invoice.read"] }],
    });

    const missionCommits = commits.filter((c) => c.id === mission.id);
    // Activating commit: containment never applied yet, so the field is
    // absent (absent-means-none), not 0.
    expect(missionCommits[0]?.containment_version).toBeUndefined();

    const sets = await Promise.all(
      missionCommits.map((c) =>
        signLifecycleEvent(c, {
          audience: CONSUMER_AUD,
          key: statusKeys.privateKey,
          kid: "as-status",
        }),
      ),
    );
    const events = sets.map(
      (set) =>
        (decodeJwt(set).events as Record<string, Record<string, unknown>>)[
          LIFECYCLE_CHANGE_EVENT_URI
        ],
    );

    // The activating event carries no containment_version.
    expect(events[0]?.containment_version).toBeUndefined();
    // Both contain events keep `state` unchanged (active -> active)...
    expect(events[1]).toMatchObject({ state: "active", prior_state: "active" });
    expect(events[2]).toMatchObject({ state: "active", prior_state: "active" });
    // ...but containment_version on the emitted event moves forward each
    // time, which is exactly the authorization-change signal a consumer
    // watching only `state` (or only the version-gap rule) would miss.
    expect(events[1]?.containment_version).toBe(1);
    expect(events[2]?.containment_version).toBe(2);
    expect(events[2]?.containment_version).not.toBe(events[1]?.containment_version);
  });
});
