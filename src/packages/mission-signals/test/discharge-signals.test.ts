/**
 * @spec draft-mcguinness-oauth-mission-signals (#discharge-compatibility,
 * #consumer-behavior, #lifecycle-event)
 *
 * The PRODUCER half of discharge compatibility, which #562 left todo because no
 * kernel funnel committed a discharge (issue #287 residual):
 *
 *  - a real `kernel.discharge()` commit emits `authority_changed` true on the
 *    `mission.lifecycle-change` event it produces, with `state` equal to
 *    `prior_state`, and drives a declared receiver to rematerialize
 *    end-to-end;
 *  - the delivery GATE: a stream whose consumer has not declared
 *    `authority_changed` in `mission_capabilities_supported` never receives
 *    that event, while a declared stream does;
 *  - the COMPOSITE case: a discharge on a PREVIOUSLY CONTAINED Mission carries
 *    `containment_version` and is still gated;
 *  - the gate covers containment too (#1001, D1002): a contain commit that
 *    narrows effective authority carries `authority_changed` true and is
 *    withheld from an undeclared stream, while a declared stream receives it
 *    and its receiver rematerializes;
 *  - withholding renumbers nothing: the undeclared stream's next delivered
 *    event carries the Mission's own `version`, so its receiver detects the
 *    gap the withheld event left.
 *
 * A withholding also pauses the undeclared stream (#1877): it receives a
 * Stream Updated notice, and its later events are held until the staleness
 * window passes. The pause itself is proven in `stream-pause.test.ts`; here
 * each sink sorts the SETs it receives by event type, so the gate's
 * assertions read the lifecycle events alone.
 */

import {
  type AuthorityEntry,
  conditionDigest,
  type DischargeAuthorityPolicy,
  entryDigest,
  type LifecycleCommit,
  MissionKernel,
  type MissionRecord,
  validateMissionIntent,
} from "@mission/authorization-server";
import { testAuthoritySourceCatalog } from "@mission/authorization-server/test-support";
import { decodeJwt, exportJWK, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import {
  type ApplyResult,
  AUTHORITY_CHANGED_CAPABILITY,
  LIFECYCLE_CHANGE_EVENT_URI,
  MissionSignalEmitter,
  MissionSignalReceiver,
  SSF_STREAM_UPDATED_EVENT_URI,
} from "../src/index.js";

const ISS = "https://as.test";
const DECLARED_AUD = "https://declared.consumer.test";
const UNDECLARED_AUD = "https://undeclared.consumer.test";
const RESOURCE = "https://payments.test/mcp";
const NOW = new Date("2026-08-20T12:00:00Z");
const EXPIRES_AT = "2027-01-01T00:00:00Z";
const CLOSE_EVENT = "accounting-period-closed";
const CLOSE_POLICY = "close-management-2026-q3";
/** The issuer's advertised `mission_max_stale_seconds` in these tests. */
const MAX_STALE_SECONDS = 60;
/** The stream's agreed heartbeat interval, shorter than `MAX_STALE_SECONDS`. */
const HEARTBEAT_INTERVAL_SECONDS = 10;

/** True for a `mission.lifecycle-change` SET; false for an SSF stream-control SET. */
const isLifecycle = (set: string): boolean =>
  LIFECYCLE_CHANGE_EVENT_URI in (decodeJwt(set).events as Record<string, unknown>);

/** The `status` of a Stream Updated SET. */
const streamUpdatedStatus = (set: string): unknown =>
  (decodeJwt(set).events as Record<string, Record<string, unknown>>)[SSF_STREAM_UPDATED_EVENT_URI]
    ?.status;

const POLICY = {
  policy_version: "discharge-signals-v1",
  ceiling: [
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: ["payments:invoice.read", "payments:payment.execute"],
    },
  ],
};

const DISCHARGE_AUTHORITY: DischargeAuthorityPolicy = {
  policies: {
    [CLOSE_POLICY]: {
      mapping_id: "close-management",
      mapping_version: "1",
      event_types: [CLOSE_EVENT],
      principals: ["svc:close-management"],
    },
  },
};

const intent = () =>
  validateMissionIntent(
    JSON.stringify({
      goal: "Read invoices and execute approved payments",
      target_resources: [RESOURCE],
      expires_at: EXPIRES_AT,
    }),
  );

/** A live read entry plus an execute entry that discharges on the Q3 close. */
const proposal = (): AuthorityEntry[] => [
  { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] },
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions: ["payments:payment.execute"],
    constraints: {
      terminal_when: [{ event_type: CLOSE_EVENT, discharge_authority: CLOSE_POLICY }],
    },
  },
];

interface Wired {
  kernel: MissionKernel;
  emitter: MissionSignalEmitter;
  declared: MissionSignalReceiver;
  undeclared: MissionSignalReceiver;
  declaredSets: string[];
  undeclaredSets: string[];
  /** The SSF stream-control SETs the undeclared stream received, in order. */
  undeclaredControl: string[];
  /** What the undeclared receiver reported for each delivered SET, in order. */
  undeclaredResults: ApplyResult[];
  /** Advance the emitter's clock. */
  advance: (ms: number) => void;
}

/** One issuer, two streams: one that declared `authority_changed`, one that did not. */
async function wire(): Promise<Wired> {
  const statusKeys = await generateKeyPair("ES256", { extractable: true });
  const statusPub = {
    ...(await exportJWK(statusKeys.publicKey)),
    kid: "as-status",
    alg: "ES256",
    use: "sig",
  };
  let clock = NOW.getTime();
  const emitter = new MissionSignalEmitter({
    key: statusKeys.privateKey,
    kid: "as-status",
    consumers: [
      { audience: DECLARED_AUD, mission_capabilities_supported: [AUTHORITY_CHANGED_CAPABILITY] },
      { audience: UNDECLARED_AUD },
    ],
    maxStaleSeconds: MAX_STALE_SECONDS,
    // The agreed heartbeat interval: without one, a paused stream is never
    // re-enabled automatically (D1023 ruling 3).
    heartbeatIntervalSeconds: HEARTBEAT_INTERVAL_SECONDS,
    now: () => new Date(clock),
  });
  const declared = new MissionSignalReceiver({
    jwks: { keys: [statusPub] },
    issuer: ISS,
    audience: DECLARED_AUD,
  });
  const undeclared = new MissionSignalReceiver({
    jwks: { keys: [statusPub] },
    issuer: ISS,
    audience: UNDECLARED_AUD,
  });
  const declaredSets: string[] = [];
  const undeclaredSets: string[] = [];
  const undeclaredControl: string[] = [];
  const undeclaredResults: ApplyResult[] = [];
  emitter.onDeliver(DECLARED_AUD, (set) => {
    declaredSets.push(set);
    return declared.verifyAndApply(set);
  });
  emitter.onDeliver(UNDECLARED_AUD, async (set) => {
    if (!isLifecycle(set)) {
      undeclaredControl.push(set);
      return undefined;
    }
    undeclaredSets.push(set);
    const result = await undeclared.verifyAndApply(set);
    undeclaredResults.push(result);
    return result;
  });
  const kernel = new MissionKernel({
    issuer: ISS,
    policy: POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(POLICY.ceiling, ["ap-agent"], ["bob"]),
    dischargeAuthority: DISCHARGE_AUTHORITY,
    statusKey: statusKeys.privateKey,
    statusKid: "as-status",
    now: () => NOW,
    onLifecycleCommit: (c) => emitter.onCommit(c),
  });
  return {
    kernel,
    emitter,
    declared,
    undeclared,
    declaredSets,
    undeclaredSets,
    undeclaredControl,
    undeclaredResults,
    advance: (ms) => {
      clock += ms;
    },
  };
}

let approvals = 0;
function approve(kernel: MissionKernel): MissionRecord {
  approvals += 1;
  return kernel.approve({
    intent: intent(),
    proposedAuthority: proposal(),
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-dis-sig-${approvals}`,
  });
}

function selectors(record: MissionRecord) {
  const entry = record.authority_set.find((e) =>
    e.actions.includes("payments:payment.execute"),
  ) as AuthorityEntry;
  const condition = entry.constraints?.terminal_when?.[0];
  return {
    authority: "svc:close-management",
    entry_digest: entryDigest(record.issuer, entry),
    condition_digest: conditionDigest(condition as never),
    event_type: CLOSE_EVENT,
  };
}

describe("discharge compatibility: authority_changed emission and the delivery gate", () => {
  it("wired end-to-end: a real kernel discharge() commit drives a declared receiver to rematerialize", async () => {
    const w = await wire();
    const mission = approve(w.kernel);
    await w.emitter.drain();
    expect(w.declared.needsRematerialization(mission.id)).toBe(false);

    w.kernel.discharge(mission.id, { ...selectors(mission), event_id: "close-e2e-1" });
    await w.emitter.drain();

    // state unchanged, version advanced, authority_changed true on the event.
    expect(w.declared.viewState(mission.id)).toMatchObject({ state: "active", version: 2 });
    expect(w.declared.needsRematerialization(mission.id)).toBe(true);
  });

  it("does not deliver the discharge event to a stream that has not declared authority_changed", async () => {
    const w = await wire();
    const mission = approve(w.kernel);
    await w.emitter.drain();
    // The activating event reaches BOTH streams (it narrows nothing).
    expect(w.declaredSets).toHaveLength(1);
    expect(w.undeclaredSets).toHaveLength(1);

    w.kernel.discharge(mission.id, { ...selectors(mission), event_id: "close-gate-1" });
    await w.emitter.drain();

    expect(w.declaredSets).toHaveLength(2);
    expect(w.undeclaredSets).toHaveLength(1); // gated: no second event
    // The withholding paused the stream (#1877).
    expect(w.undeclaredControl.map(streamUpdatedStatus)).toEqual(["paused"]);
    expect(w.undeclared.viewState(mission.id)).toMatchObject({ version: 1 });
    expect(w.undeclared.needsRematerialization(mission.id)).toBe(false);
  });

  it("gates a discharge on a PREVIOUSLY CONTAINED Mission too: a containment_version on the event does not open the gate", async () => {
    const w = await wire();
    const mission = approve(w.kernel);
    // The activating event reaches both streams before the withholding
    // pauses the undeclared one (#1877), which would hold it.
    await w.emitter.drain();
    // A contain commit first. It narrows effective authority, so it carries
    // authority_changed true and only the declared stream receives it.
    w.kernel.contain(mission.id, {
      event: {
        type: "anomaly.detected",
        source: "svc:soc",
        observed_at: NOW.toISOString(),
        event_id: "evt-contain-1",
      },
      remove: [{ resource: RESOURCE, actions: ["payments:invoice.read"] }],
    });
    await w.emitter.drain();
    expect(w.declaredSets).toHaveLength(2);
    expect(w.undeclaredSets).toHaveLength(1);

    // Now discharge the OTHER entry. The commit carries containment_version 1
    // beside authority_changed true; the gate reads authority_changed alone.
    w.kernel.discharge(mission.id, { ...selectors(mission), event_id: "close-composite-1" });
    await w.emitter.drain();
    expect(w.declaredSets).toHaveLength(3);
    expect(w.undeclaredSets).toHaveLength(1); // still gated
    expect(w.declared.needsRematerialization(mission.id)).toBe(true);
  });
});

/** The `mission.lifecycle-change` event body a delivered SET carries. */
const eventOf = (set: string | undefined): Record<string, unknown> =>
  (decodeJwt(set as string).events as Record<string, Record<string, unknown>>)[
    LIFECYCLE_CHANGE_EVENT_URI
  ] as Record<string, unknown>;

/** A contain commit that narrows effective authority: the read entry loses its only action. */
function containRead(kernel: MissionKernel, missionId: string, eventId: string): void {
  kernel.contain(missionId, {
    event: {
      type: "anomaly.detected",
      source: "svc:soc",
      observed_at: NOW.toISOString(),
      event_id: eventId,
    },
    remove: [{ resource: RESOURCE, actions: ["payments:invoice.read"] }],
  });
}

describe("the delivery gate covers containment (@spec signals#discharge-compatibility, #1001)", () => {
  it("withholds a real kernel contain() commit from an undeclared stream and delivers it to a declared one, whose receiver rematerializes", async () => {
    const w = await wire();
    const mission = approve(w.kernel);
    await w.emitter.drain();
    expect(w.declaredSets).toHaveLength(1);
    expect(w.undeclaredSets).toHaveLength(1);

    containRead(w.kernel, mission.id, "evt-gate-contain-1");
    await w.emitter.drain();

    // The declared stream receives the contain event: same state, the next
    // version, containment_version 1 and authority_changed true. Its receiver
    // applies it in order and latches rematerialization.
    expect(w.declaredSets).toHaveLength(2);
    expect(eventOf(w.declaredSets[1])).toMatchObject({
      state: "active",
      prior_state: "active",
      version: 2,
      containment_version: 1,
      authority_changed: true,
    });
    expect(w.declared.viewState(mission.id)).toMatchObject({
      state: "active",
      version: 2,
      containment_version: 1,
    });
    expect(w.declared.needsRematerialization(mission.id)).toBe(true);

    // The undeclared stream receives nothing: its view stays at the
    // activating event, with no narrowing it would misread as current.
    expect(w.undeclaredSets).toHaveLength(1);
    expect(w.undeclared.viewState(mission.id)).toMatchObject({ state: "active", version: 1 });
    expect(w.undeclared.needsRematerialization(mission.id)).toBe(false);
  });

  it("keeps the Mission's own version on the undeclared stream's next event, so its receiver detects the gap a withheld contain commit left", async () => {
    const w = await wire();
    const mission = approve(w.kernel);
    await w.emitter.drain();

    containRead(w.kernel, mission.id, "evt-gap-contain-1"); // version 2: withheld
    await w.emitter.drain();
    expect(w.undeclaredSets).toHaveLength(1);

    // A suspend narrows nothing beyond `state`, so both streams receive it;
    // the undeclared stream, paused by the withholding (#1877), receives it
    // once the staleness window has passed and the stream is re-enabled.
    w.kernel.transition(mission.id, "suspend"); // version 3
    await w.emitter.drain();
    expect(w.undeclaredSets).toHaveLength(1);
    w.advance(MAX_STALE_SECONDS * 1000 + 1);
    await w.emitter.drain();
    expect(w.undeclaredControl.map(streamUpdatedStatus)).toEqual(["paused", "enabled"]);

    // No renumbering per stream: the undeclared stream's event carries the
    // Mission's version 3, not a stream-local 2.
    expect(w.declaredSets.map((s) => eventOf(s).version)).toEqual([1, 2, 3]);
    expect(w.undeclaredSets.map((s) => eventOf(s).version)).toEqual([1, 3]);

    // The undeclared receiver detects the gap rather than applying the event
    // as an in-order successor of its cached state; the declared receiver saw
    // a contiguous sequence.
    expect(w.undeclaredResults.map((r) => r.status)).toEqual(["applied", "gap"]);
    expect(w.undeclaredResults[1]).toMatchObject({ status: "gap", expected: 2, received: 3 });
    expect(w.undeclared.hasGap(mission.id)).toBe(true);
    expect(w.declared.hasGap(mission.id)).toBe(false);

    // The Mission Status read the gap calls for reports what the stream
    // withheld: version 3 with containment_version 1, and the contained read
    // action absent from the audience-scoped authority.
    const status = w.kernel.statusObservation(mission.id, {
      requester: "svc:reader",
      audience: RESOURCE,
    }).payload;
    expect(status.mission).toMatchObject({
      state: "suspended",
      version: 3,
      containment_version: 1,
    });
    expect(JSON.stringify(status.authorization_details)).not.toContain("payments:invoice.read");
    expect(JSON.stringify(status.authorization_details)).toContain("payments:payment.execute");

    // Later events keep applying on the undeclared stream, in order.
    w.kernel.transition(mission.id, "resume"); // version 4
    await w.emitter.drain();
    expect(w.undeclaredSets.map((s) => eventOf(s).version)).toEqual([1, 3, 4]);
    expect(w.undeclaredResults[2]).toMatchObject({
      status: "applied",
      state: "active",
      version: 4,
    });
  });
});

describe("the delivery gate survives an emitter restart: it reads the commit's authority_changed, never emitter history", () => {
  const baseCommit = (over: Partial<LifecycleCommit>): LifecycleCommit => ({
    id: "msn_restart_1",
    issuer: ISS,
    state: "active",
    prior_state: "active",
    version: 3,
    committed_at: NOW.toISOString(),
    expires_at: EXPIRES_AT,
    ...over,
  });

  /** An emitter with NO delivery history, as after a process restart. */
  async function freshEmitter() {
    const keys = await generateKeyPair("ES256", { extractable: true });
    const emitter = new MissionSignalEmitter({
      key: keys.privateKey,
      kid: "as-status",
      consumers: [
        { audience: DECLARED_AUD, mission_capabilities_supported: [AUTHORITY_CHANGED_CAPABILITY] },
        { audience: UNDECLARED_AUD },
      ],
    });
    const declared: string[] = [];
    const undeclared: string[] = [];
    const undeclaredControl: string[] = [];
    emitter.onDeliver(DECLARED_AUD, (set) => declared.push(set));
    emitter.onDeliver(UNDECLARED_AUD, (set) =>
      (isLifecycle(set) ? undeclared : undeclaredControl).push(set),
    );
    return { emitter, declared, undeclared, undeclaredControl };
  }

  it("a discharge on a previously contained Mission stays gated on a fresh emitter (containment_version 1, no advance)", async () => {
    const { emitter, declared, undeclared } = await freshEmitter();
    // First commit this emitter ever sees: an authority_changed narrowing
    // carrying containment_version 1 UNCHANGED (the Mission was contained
    // before the restart; this commit is a discharge). A cursor-inferring
    // gate mistook this for the first containment advance and delivered it
    // to the undeclared consumer, which ignores authority_changed and keeps
    // using stale authority.
    emitter.onCommit(baseCommit({ authority_changed: true, containment_version: 1 }));
    await emitter.drain();
    expect(declared).toHaveLength(1);
    expect(undeclared).toHaveLength(0);
  });

  it("withholds a containment commit first observed above version 1 from an undeclared stream and delivers it to a declared one", async () => {
    const { emitter, declared, undeclared } = await freshEmitter();
    // A contain commit narrows effective authority, so it carries
    // authority_changed true and the gate binds it like a discharge (#1001,
    // D1002): an undeclared consumer would accept the in-order increment and
    // keep the contained authority. The decision needs no history, so a fresh
    // emitter seeing the Mission first at containment_version 5 decides alike.
    emitter.onCommit(baseCommit({ authority_changed: true, containment_version: 5 }));
    await emitter.drain();
    expect(declared).toHaveLength(1);
    expect(undeclared).toHaveLength(0);
  });
});
