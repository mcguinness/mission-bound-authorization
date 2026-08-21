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
 *    `containment_version` (present, unchanged) and is still gated, because
 *    only an ADVANCE represents the narrowing to an undeclared consumer;
 *  - containment's own delivery rules are unchanged: a contain commit, whose
 *    narrowing IS represented by a `containment_version` advance, still reaches
 *    an undeclared stream.
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
import { exportJWK, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import {
  AUTHORITY_CHANGED_CAPABILITY,
  MissionSignalEmitter,
  MissionSignalReceiver,
} from "../src/index.js";

const ISS = "https://as.test";
const DECLARED_AUD = "https://declared.consumer.test";
const UNDECLARED_AUD = "https://undeclared.consumer.test";
const RESOURCE = "https://payments.test/mcp";
const NOW = new Date("2026-08-20T12:00:00Z");
const EXPIRES_AT = "2027-01-01T00:00:00Z";
const CLOSE_EVENT = "accounting-period-closed";
const CLOSE_POLICY = "close-management-2026-q3";

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
      resources: [RESOURCE],
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
    constraints: { terminal_when: [{ event_type: CLOSE_EVENT, discharge_policy: CLOSE_POLICY }] },
  },
];

interface Wired {
  kernel: MissionKernel;
  emitter: MissionSignalEmitter;
  declared: MissionSignalReceiver;
  undeclared: MissionSignalReceiver;
  declaredSets: string[];
  undeclaredSets: string[];
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
  const emitter = new MissionSignalEmitter({
    key: statusKeys.privateKey,
    kid: "as-status",
    consumers: [
      { audience: DECLARED_AUD, mission_capabilities_supported: [AUTHORITY_CHANGED_CAPABILITY] },
      { audience: UNDECLARED_AUD },
    ],
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
  emitter.onDeliver(DECLARED_AUD, (set) => {
    declaredSets.push(set);
    return declared.verifyAndApply(set);
  });
  emitter.onDeliver(UNDECLARED_AUD, (set) => {
    undeclaredSets.push(set);
    return undeclared.verifyAndApply(set);
  });
  const kernel = new MissionKernel({
    issuer: ISS,
    policy: POLICY as never,
    dischargeAuthority: DISCHARGE_AUTHORITY,
    statusKey: statusKeys.privateKey,
    statusKid: "as-status",
    now: () => NOW,
    onLifecycleCommit: (c) => emitter.onCommit(c),
  });
  return { kernel, emitter, declared, undeclared, declaredSets, undeclaredSets };
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
    expect(w.undeclared.viewState(mission.id)).toMatchObject({ version: 1 });
    expect(w.undeclared.needsRematerialization(mission.id)).toBe(false);
  });

  it("gates a discharge on a PREVIOUSLY CONTAINED Mission too: presence of containment_version is not an advance", async () => {
    const w = await wire();
    const mission = approve(w.kernel);
    // A contain commit first: its narrowing IS represented by a
    // containment_version advance, so containment's rules apply unchanged and
    // BOTH streams receive it.
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
    expect(w.undeclaredSets).toHaveLength(2);

    // Now discharge the OTHER entry. The commit carries containment_version 1
    // (unchanged), so the narrowing is represented by authority_changed alone.
    w.kernel.discharge(mission.id, { ...selectors(mission), event_id: "close-composite-1" });
    await w.emitter.drain();
    expect(w.declaredSets).toHaveLength(3);
    expect(w.undeclaredSets).toHaveLength(2); // still gated
    expect(w.declared.needsRematerialization(mission.id)).toBe(true);
  });
});

describe("the delivery gate survives an emitter restart: provenance is commit-carried, never cursor-inferred", () => {
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
    emitter.onDeliver(DECLARED_AUD, (set) => declared.push(set));
    emitter.onDeliver(UNDECLARED_AUD, (set) => undeclared.push(set));
    return { emitter, declared, undeclared };
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

  it("a real containment advance first observed above version 1 still reaches an undeclared stream on a fresh emitter", async () => {
    const { emitter, declared, undeclared } = await freshEmitter();
    // The converse failure: a cursor-inferring gate WITHHELD a genuine
    // containment event whose first observed version exceeds 1. The kernel's
    // commit-carried discriminator makes it deliverable regardless of what
    // this emitter has seen before.
    emitter.onCommit(
      baseCommit({ authority_changed: true, containment_version: 5, containment_advanced: true }),
    );
    await emitter.drain();
    expect(declared).toHaveLength(1);
    expect(undeclared).toHaveLength(1);
  });
});
