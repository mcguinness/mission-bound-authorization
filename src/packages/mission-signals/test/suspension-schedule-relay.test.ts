/**
 * @spec draft-mcguinness-oauth-mission-signals (#lifecycle-event),
 * draft-mcguinness-oauth-mission-status (#idempotency), #1002
 *
 * A suspension schedule's `suspend_until` and `on_expiry` ride the
 * `mission.lifecycle-change` event of the commit that arms the schedule (a
 * transition to `suspended` under a deadline) or replaces it (a
 * suspend-metadata update, `prior_state` and `state` both `suspended`). This
 * drives a real kernel wired to the emitter, captures the DELIVERED SET bytes
 * from the emission path, and asserts the pair is on those events alone, with
 * the committed values, and that the schedule's committing party and the
 * applied schedule a deadline's transition names never reach the wire.
 *
 * In-process and deterministic: the kernel's clock is controlled, and a
 * deadline is applied through the kernel's own timer delivery
 * (`fireSchedule`), with no scheduler, HTTP or OpenFGA.
 */

import {
  type AuthorityEntry,
  type LifecycleCommit,
  MissionKernel,
  validateMissionIntent,
} from "@mission/authorization-server";
import { testAuthoritySourceCatalog } from "@mission/authorization-server/test-support";
import { decodeJwt, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import {
  LIFECYCLE_CHANGE_EVENT_URI,
  MissionSignalEmitter,
  signLifecycleEvent,
} from "../src/index.js";

const ISS = "https://as.test";
const CONSUMER_AUD = "https://erp.consumer.test";
const RESOURCE = "https://payments.test/mcp";
const NOW = new Date("2026-08-02T12:00:00Z");
const EXPIRES_AT = "2027-01-01T00:00:00Z";

const POLICY = {
  policy_version: "schedule-relay-v1",
  ceiling: [
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: ["payments:invoice.read"],
    },
  ],
};

const PROPOSED_AUTHORITY: AuthorityEntry[] = [
  { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] },
];

/** The schedule members a kernel commit carries off the wire. */
const INTERNAL_SCHEDULE_MEMBERS = [
  "schedule_committing_party",
  "applied_schedule",
  "committing_party",
  "generation",
];

/** The lifecycle-change event body of one SET. */
const eventOf = (set: string): Record<string, unknown> =>
  (decodeJwt(set).events as Record<string, Record<string, unknown>>)[
    LIFECYCLE_CHANGE_EVENT_URI
  ] as Record<string, unknown>;

/** A deadline `seconds` after the start of the test clock. */
const at = (seconds: number) => new Date(NOW.getTime() + seconds * 1000).toISOString();

/** A real kernel on a controlled clock, its commits signed for one consumer and captured as delivered. */
async function wire() {
  const statusKeys = await generateKeyPair("ES256", { extractable: true });
  const emitter = new MissionSignalEmitter({
    key: statusKeys.privateKey,
    kid: "as-status",
    consumers: [{ audience: CONSUMER_AUD }],
  });
  const delivered: string[] = [];
  emitter.onDeliver(CONSUMER_AUD, (set) => delivered.push(set));
  let clock = NOW.getTime();
  const kernel = new MissionKernel({
    issuer: ISS,
    policy: POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(POLICY.ceiling, ["ap-agent"], ["bob"]),
    statusKey: statusKeys.privateKey,
    statusKid: "as-status",
    now: () => new Date(clock),
    onLifecycleCommit: emitter.onCommit,
  });
  let n = 0;
  const approve = () =>
    kernel.approve({
      intent: validateMissionIntent(
        JSON.stringify({
          goal: "Read approved invoices",
          target_resources: [RESOURCE],
          expires_at: EXPIRES_AT,
        }),
      ),
      proposedAuthority: PROPOSED_AUTHORITY,
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: `apev-schedule-relay-${++n}`,
    }).id;
  /** The events delivered since the last call. Signing is concurrent, so
   *  delivery order across several pending commits is not commit order. */
  const take = async () => {
    await emitter.drain();
    const events = delivered.map(eventOf);
    delivered.length = 0;
    return events;
  };
  /** The one event the preceding commit delivered. */
  const one = async () => {
    const events = await take();
    expect(events).toHaveLength(1);
    return events[0] as Record<string, unknown>;
  };
  const advance = (seconds: number) => {
    clock += seconds * 1000;
  };
  return { kernel, approve, take, one, advance, statusKeys };
}

describe("suspension schedule relayed by Mission Signals (@spec signals#lifecycle-event, #1002)", () => {
  it("delivers suspend_until and on_expiry on a suspend under a deadline, with the committed values", async () => {
    const { kernel, approve, take, one } = await wire();
    const id = approve();
    await take();

    const until = at(3600);
    kernel.transition(id, "suspend", {
      schedule: { suspend_until: until, on_expiry: "resume", committing_party: "svc:ops" },
    });
    const event = await one();
    expect(event).toMatchObject({
      state: "suspended",
      prior_state: "active",
      version: 2,
      suspend_until: until,
      on_expiry: "resume",
    });
    // The values the Status profile reports: the recorded schedule's own.
    const recorded = kernel.get(id)?.schedule;
    expect(event.suspend_until).toBe(recorded?.suspend_until);
    expect(event.on_expiry).toBe(recorded?.on_expiry);
    for (const member of INTERNAL_SCHEDULE_MEMBERS)
      expect(event, member).not.toHaveProperty(member);
  });

  it("delivers neither member on a suspend without a deadline, a resume, or the transition a deadline applies, and never the committing party or the applied schedule", async () => {
    const { kernel, approve, take, one, advance } = await wire();
    const hasSchedule = (event: Record<string, unknown>) =>
      Object.hasOwn(event, "suspend_until") || Object.hasOwn(event, "on_expiry");
    const shape = (event: Record<string, unknown>) => [
      (event.mission as { id: string }).id,
      event.prior_state,
      event.state,
    ];

    // A suspend without a deadline, and the resume that ends it.
    const plain = approve();
    await take();
    kernel.transition(plain, "suspend");
    const plainSuspend = await one();
    kernel.transition(plain, "resume");
    const plainResume = await one();
    expect(shape(plainSuspend)).toEqual([plain, "active", "suspended"]);
    expect(shape(plainResume)).toEqual([plain, "suspended", "active"]);

    // A scheduled suspension ended by a direct resume, and one ended by each
    // `on_expiry` when its deadline passes. Only the arming event carries the pair.
    const resumed = approve();
    const timedResume = approve();
    const timedRevoke = approve();
    await take();
    const armed: Record<string, unknown>[] = [];
    for (const [id, onExpiry] of [
      [resumed, "resume"],
      [timedResume, "resume"],
      [timedRevoke, "revoke"],
    ] as const) {
      kernel.transition(id, "suspend", {
        schedule: { suspend_until: at(60), on_expiry: onExpiry, committing_party: "svc:ops" },
      });
      armed.push(await one());
    }
    for (const event of armed) expect(hasSchedule(event)).toBe(true);

    kernel.transition(resumed, "resume");
    const directResume = await one();
    advance(120);
    const applied: Record<string, unknown>[] = [];
    for (const id of [timedResume, timedRevoke]) {
      const generation = kernel.get(id)?.schedule?.generation;
      expect(generation).toBeTypeOf("number");
      expect(kernel.fireSchedule(id, generation as number).outcome).toBe("applied");
      applied.push(await one());
    }
    expect(shape(directResume)).toEqual([resumed, "suspended", "active"]);
    expect(applied.map(shape)).toEqual([
      [timedResume, "suspended", "active"],
      [timedRevoke, "suspended", "terminated"],
    ]);
    for (const event of [plainSuspend, plainResume, directResume, ...applied]) {
      expect(hasSchedule(event), String(event.state)).toBe(false);
    }
    for (const event of [plainSuspend, plainResume, ...armed, directResume, ...applied]) {
      for (const member of INTERNAL_SCHEDULE_MEMBERS) {
        expect(event, `${String(event.state)} ${member}`).not.toHaveProperty(member);
      }
    }
  });

  it("delivers a schedule replacement on a suspended Mission with prior_state and state both suspended, the updated values and the next version", async () => {
    const { kernel, approve, take, one } = await wire();
    const id = approve();
    await take();

    kernel.transition(id, "suspend", {
      schedule: { suspend_until: at(3600), on_expiry: "resume", committing_party: "svc:ops" },
    });
    const arming = await one();
    expect(arming).toMatchObject({ state: "suspended", prior_state: "active", version: 2 });
    const until = at(7200);
    kernel.transition(id, "suspend", {
      schedule: { suspend_until: until, on_expiry: "revoke", committing_party: "svc:deputy" },
    });
    const replacement = await one();
    expect(replacement).toMatchObject({
      state: "suspended",
      prior_state: "suspended",
      suspend_until: until,
      on_expiry: "revoke",
      version: 3,
    });
    for (const member of INTERNAL_SCHEDULE_MEMBERS)
      expect(replacement, member).not.toHaveProperty(member);
  });

  it("the SET builder relays suspend_until and on_expiry only as a complete pair", async () => {
    const { statusKeys } = await wire();
    const build = async (members: Record<string, unknown>) =>
      eventOf(
        await signLifecycleEvent(
          {
            id: "msn_schedule_relay_0000000000001",
            issuer: ISS,
            state: "suspended",
            prior_state: "active",
            version: 2,
            committed_at: NOW.toISOString(),
            expires_at: EXPIRES_AT,
            ...members,
          } as LifecycleCommit,
          { audience: CONSUMER_AUD, key: statusKeys.privateKey, kid: "as-status" },
        ),
      );
    const until = at(60);
    expect(await build({ suspend_until: until, on_expiry: "revoke" })).toMatchObject({
      suspend_until: until,
      on_expiry: "revoke",
    });
    for (const half of [{ suspend_until: until }, { on_expiry: "revoke" }]) {
      const event = await build(half);
      expect(event, JSON.stringify(half)).not.toHaveProperty("suspend_until");
      expect(event, JSON.stringify(half)).not.toHaveProperty("on_expiry");
    }
  });
});
