/**
 * @spec status#lifecycle-authorization, status#mission-lifecycle-endpoint,
 * status#idempotency, status#legal-transitions, status#state-machine,
 * status#mission-status-response (#1002, D285, D331, D416): the suspension
 * schedule (`suspend_until`, `on_expiry`) on the advertised Mission Lifecycle
 * endpoint, and the scheduler that applies it.
 *
 * Every deadline runs on a controlled clock: the kernel's clock and the
 * scheduler's timers are one {@link ControlledClock}, so a test moves time and
 * delivers each timer whose time comes, in deadline order, or moves time
 * without delivering any.
 *
 * Covered:
 *  - authorization at commit: a suspend-only caller cannot arm or replace a
 *    resume schedule, including on another party's suspended Mission, and the
 *    refusal changes nothing; a revoke schedule needs only suspend; the
 *    deployment's direct-resume authorization is the scheduling bar, under
 *    either deployment choice;
 *  - the committing party, replacement, omission, the incomplete pair, and the
 *    members the Status response reports;
 *  - deadlines: applied without a further request, after the committing
 *    party's grant is withdrawn, never from a superseded schedule, never on a
 *    terminated Mission, and never at or after `expires_at`;
 *  - one transition under duplicate delivery, and a deadline serialized with a
 *    manual transition;
 *  - restart recovery on the file-backed store;
 *  - the scheduler is off where schedules are not adopted or `suspend` is not
 *    served.
 */

import { mkdtempSync, rmSync } from "node:fs";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CANONICAL_RESOURCE, DERIVATION_POLICY, DEV_SERVICE_TOKEN } from "@mission/demo-data";
import { decodeJwt, generateKeyPair } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  type BuiltAs,
  buildAuthorizationServer,
  createChildMission,
  type LifecycleCommit,
  MISSION_LIFECYCLE_SCOPE,
  MISSION_RESUME_SCOPE,
  MissionKernel,
  type MissionRecord,
  type ScheduleTimers,
  SuspensionScheduler,
  validateMissionIntent,
} from "../src/index.js";
import { aiAgents } from "./actor-profiles.helper.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";
import {
  decodeStatusResponse,
  type LifecycleAnswer,
  type LifecycleTestClient,
  lifecycleClientAssertion,
  lifecycleRequest,
  newLifecycleClient,
} from "./lifecycle-endpoint.helper.js";

const PORT = 14836;
const ISSUER = `http://localhost:${PORT}`;
const PLAIN_PORT = 14837;
const PLAIN_ISSUER = `http://localhost:${PLAIN_PORT}`;
const RESTART_ISSUER = "http://localhost:14838";
const UNKNOWN = "msn_unknown_0000000000000000000000";

/**
 * The kernel's clock and the scheduler's timers in one: `advance` moves time
 * and awaits each timer delivery whose time comes, in deadline order; `skip`
 * moves time and delivers nothing, as when a deadline passes before its
 * timer runs. With `ignoreClears`, a cancelled timer still fires, as one whose
 * cancellation never reached it would.
 */
class ControlledClock implements ScheduleTimers {
  at: Date;
  ignoreClears = false;
  private seq = 0;
  private readonly pending = new Map<number, { dueMs: number; callback: () => Promise<unknown> }>();

  constructor(start: Date) {
    this.at = start;
  }

  readonly now = (): Date => this.at;

  set(callback: () => Promise<unknown>, delayMs: number): unknown {
    this.seq += 1;
    this.pending.set(this.seq, { dueMs: this.at.getTime() + delayMs, callback });
    return this.seq;
  }

  clear(handle: unknown): void {
    if (!this.ignoreClears) this.pending.delete(handle as number);
  }

  skip(ms: number): void {
    this.at = new Date(this.at.getTime() + ms);
  }

  async advance(ms: number): Promise<void> {
    const target = this.at.getTime() + ms;
    for (;;) {
      let next: [number, { dueMs: number; callback: () => Promise<unknown> }] | undefined;
      for (const entry of this.pending) {
        if (entry[1].dueMs <= target && (!next || entry[1].dueMs < next[1].dueMs)) next = entry;
      }
      if (!next) break;
      this.pending.delete(next[0]);
      if (next[1].dueMs > this.at.getTime()) this.at = new Date(next[1].dueMs);
      await next[1].callback();
    }
    this.at = new Date(target);
  }
}

const clock = new ControlledClock(new Date(Math.floor(Date.now() / 1000) * 1000));
/** An RFC 3339 instant `seconds` from the controlled clock's now. */
const at = (seconds: number, c: ControlledClock = clock): string =>
  new Date(c.at.getTime() + seconds * 1000).toISOString();

let as: BuiltAs;
let server: Server;
let plain: BuiltAs;
let plainServer: Server;
/** Holds `mission_lifecycle` alone: on a deployment requiring `mission_resume`, a suspend-only caller. */
let suspender: LifecycleTestClient;
/** Holds `mission_lifecycle` and `mission_resume`. */
let operator: LifecycleTestClient;
/** Holds both too, and is a different acting party; its grants can be withdrawn. */
let deputy: LifecycleTestClient;
const deputyGrants: string[] = [MISSION_LIFECYCLE_SCOPE, MISSION_RESUME_SCOPE];
/** On the deployment where `mission_lifecycle` alone authorizes `resume`. */
let plainOperator: LifecycleTestClient;
let approvals = 0;

const proposal = (): AuthorityEntry[] => [
  { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] },
];

function approveOn(kernel: MissionKernel, issuer: string, expiresAt: string): MissionRecord {
  approvals += 1;
  return kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Reconcile the ledger", target_resources: [CANONICAL_RESOURCE], expires_at: expiresAt }),
      { now: kernel.nowDate() },
    ),
    proposedAuthority: proposal(),
    subject: { iss: issuer, sub: "alice" },
    approver: { iss: issuer, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-sched-${approvals}`,
  });
}

const approve = (expiresAt = at(30 * 86400)): MissionRecord => approveOn(as.kernel, ISSUER, expiresAt);

const nonce = (): string => `nonce-sched-${crypto.randomUUID()}`;

/** A Lifecycle request under an assertion dated by the controlled clock. */
async function op(
  client: LifecycleTestClient,
  members: Record<string, string>,
  issuer = ISSUER,
): Promise<LifecycleAnswer> {
  const assertion = await lifecycleClientAssertion(issuer, client, { now: Math.floor(clock.at.getTime() / 1000) });
  return lifecycleRequest(issuer, client, { nonce: nonce(), ...members }, assertion);
}

/** The `mission` member of a signed Mission Status response, read through the Status operation. */
async function status(id: string): Promise<Record<string, unknown>> {
  const res = await fetch(`${ISSUER}/missions/${id}/status`, { headers: { "x-service-token": DEV_SERVICE_TOKEN } });
  expect(res.status, await res.clone().text()).toBe(200);
  return (decodeJwt(await res.text()) as Record<string, unknown>).mission as Record<string, unknown>;
}

/** The stored row, read without the expiry clock: what committed, and nothing a read applied. */
function stored(kernel: MissionKernel, id: string): { state: string; version: number; termination?: string } {
  const row = kernel.db.prepare("SELECT state, version, termination_json FROM missions WHERE id = ?").get(id) as {
    state: string;
    version: number;
    termination_json: string | null;
  };
  return {
    state: row.state,
    version: row.version,
    ...(row.termination_json ? { termination: (JSON.parse(row.termination_json) as { reason: string }).reason } : {}),
  };
}

/** Every lifecycle commit the kernel emitted for `id`, in commit order. */
function events(kernel: MissionKernel, id: string): LifecycleCommit[] {
  return (
    kernel.db.prepare("SELECT commit_json FROM lifecycle_events WHERE mission_id = ? ORDER BY seq").all(id) as Array<{
      commit_json: string;
    }>
  ).map((r) => JSON.parse(r.commit_json) as LifecycleCommit);
}

function scheduler(): NonNullable<BuiltAs["suspensionScheduler"]> {
  const s = as.suspensionScheduler;
  if (!s) throw new Error("the suspension scheduler is not running");
  return s;
}

beforeAll(async () => {
  suspender = await newLifecycleClient("sched-suspender");
  operator = await newLifecycleClient("sched-operator");
  deputy = await newLifecycleClient("sched-deputy");
  plainOperator = await newLifecycleClient("sched-plain-operator");
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    testClients: [suspender.metadata, operator.metadata, deputy.metadata],
    lifecycleClientGrants: {
      [suspender.clientId]: [MISSION_LIFECYCLE_SCOPE],
      [operator.clientId]: [MISSION_LIFECYCLE_SCOPE, MISSION_RESUME_SCOPE],
      [deputy.clientId]: deputyGrants,
    },
    distinctResumeGrant: true,
    suspensionSchedules: { timers: clock },
    now: clock.now,
  });
  server = as.provider.listen(PORT);
  await new Promise<void>((r) => server.once("listening", () => r()));
  // The deployment that departs from the distinct-resume SHOULD: `mission_lifecycle` authorizes `resume`.
  plain = await buildAuthorizationServer({
    issuer: PLAIN_ISSUER,
    testClients: [plainOperator.metadata],
    lifecycleClientGrants: { [plainOperator.clientId]: [MISSION_LIFECYCLE_SCOPE] },
    suspensionSchedules: { timers: clock },
    now: clock.now,
  });
  plainServer = plain.provider.listen(PLAIN_PORT);
  await new Promise<void>((r) => plainServer.once("listening", () => r()));
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
  await new Promise<void>((r) => plainServer.close(() => r()));
});

describe("suspension schedule authorization at commit (@spec status#lifecycle-authorization, #1002)", () => {
  it("refuses a suspend-only caller a resume schedule, armed on an active Mission or set or replaced on a Mission another party suspended, as an unknown Mission, leaving state, version, schedule and committing party unchanged", async () => {
    const resumeSchedule = { operation: "suspend", suspend_until: at(60), on_expiry: "resume" };
    // On an active Mission.
    const active = approve();
    const activeBefore = as.kernel.get(active.id);
    const armed = await op(suspender, { mission_id: active.id, ...resumeSchedule });
    expect(armed.status, armed.text).toBe(404);
    // On a Mission the operator suspended without a schedule.
    const unscheduled = approve();
    expect((await op(operator, { mission_id: unscheduled.id, operation: "suspend" })).status).toBe(200);
    const unscheduledBefore = as.kernel.get(unscheduled.id);
    const set = await op(suspender, { mission_id: unscheduled.id, ...resumeSchedule });
    expect(set.status, set.text).toBe(404);
    // Replacing the operator's revoke schedule with a near-term resume.
    const scheduled = approve();
    const committed = await op(operator, {
      mission_id: scheduled.id,
      operation: "suspend",
      suspend_until: at(600),
      on_expiry: "revoke",
    });
    expect(committed.status, committed.text).toBe(200);
    const scheduledBefore = as.kernel.get(scheduled.id);
    expect(scheduledBefore?.schedule?.committing_party).toBe(operator.clientId);
    const eventsBefore = events(as.kernel, scheduled.id).length;
    const replaced = await op(suspender, { mission_id: scheduled.id, ...resumeSchedule });
    expect(replaced.status, replaced.text).toBe(404);

    expect(as.kernel.get(active.id)).toEqual(activeBefore);
    expect(as.kernel.get(unscheduled.id)).toEqual(unscheduledBefore);
    expect(as.kernel.get(unscheduled.id)?.schedule).toBeUndefined();
    expect(as.kernel.get(scheduled.id)).toEqual(scheduledBefore);
    expect(events(as.kernel, scheduled.id)).toHaveLength(eventsBefore);
    // The not-found shape of an unauthorized lifecycle request: the unknown Mission's answer.
    const unknown = await op(suspender, { mission_id: UNKNOWN, ...resumeSchedule });
    expect(unknown.status).toBe(404);
    const shape = (a: LifecycleAnswer) => ({ ...a.json, nonce: undefined });
    for (const refused of [armed, set, replaced]) {
      expect(refused.json?.error).toBe("not_found");
      expect(shape(refused)).toEqual(shape(unknown));
    }
  });

  it("commits a resume schedule for a caller holding the deployment's direct-resume authorization, also on another party's suspension, and a revoke schedule on the suspend authorization alone", async () => {
    const m = approve();
    const res = await op(operator, { mission_id: m.id, operation: "suspend", suspend_until: at(60), on_expiry: "resume" });
    expect(res.status, res.text).toBe(200);
    expect(decodeStatusResponse(res.text).mission).toMatchObject({ state: "suspended", on_expiry: "resume" });
    const record = as.kernel.get(m.id) as MissionRecord;
    expect(record.schedule).toEqual({
      suspend_until: expect.any(String),
      on_expiry: "resume",
      committing_party: operator.clientId,
      generation: record.version,
    });
    const other = approve();
    expect((await op(suspender, { mission_id: other.id, operation: "suspend" })).status).toBe(200);
    const onOther = await op(operator, { mission_id: other.id, operation: "suspend", suspend_until: at(60), on_expiry: "resume" });
    expect(onOther.status, onOther.text).toBe(200);
    expect(as.kernel.get(other.id)?.schedule).toMatchObject({ on_expiry: "resume", committing_party: operator.clientId });
    const revoke = approve();
    const revokeRes = await op(suspender, {
      mission_id: revoke.id,
      operation: "suspend",
      suspend_until: at(60),
      on_expiry: "revoke",
    });
    expect(revokeRes.status, revokeRes.text).toBe(200);
    expect(as.kernel.get(revoke.id)?.schedule).toMatchObject({ on_expiry: "revoke", committing_party: suspender.clientId });
  });

  it("holds scheduling to the deployment's direct-resume authorization: where resume needs mission_resume, a suspend-only caller can neither resume nor schedule a resume; where mission_lifecycle authorizes resume, it authorizes the schedule", async () => {
    const m = approve();
    expect((await op(operator, { mission_id: m.id, operation: "suspend" })).status).toBe(200);
    const direct = await op(suspender, { mission_id: m.id, operation: "resume" });
    expect(direct.status, direct.text).toBe(404);
    expect(stored(as.kernel, m.id).state).toBe("suspended");
    expect((await op(operator, { mission_id: m.id, operation: "resume" })).status).toBe(200);
    expect(stored(as.kernel, m.id).state).toBe("active");

    const p = approveOn(plain.kernel, PLAIN_ISSUER, at(30 * 86400));
    const scheduled = await op(
      plainOperator,
      { mission_id: p.id, operation: "suspend", suspend_until: at(60), on_expiry: "resume" },
      PLAIN_ISSUER,
    );
    expect(scheduled.status, scheduled.text).toBe(200);
    expect(plain.kernel.get(p.id)?.schedule).toMatchObject({ on_expiry: "resume", committing_party: plainOperator.clientId });
    expect((await op(plainOperator, { mission_id: p.id, operation: "resume" }, PLAIN_ISSUER)).status).toBe(200);
    expect(stored(plain.kernel, p.id).state).toBe("active");
  });
});

describe("suspension schedule record (@spec status#lifecycle-authorization, status#idempotency, status#mission-status-response, #1002)", () => {
  it("records each committed schedule's committing party, and an authorized replacement updates the pair and its committing party, emits the change and reports the new values", async () => {
    const m = approve();
    const first = await op(operator, { mission_id: m.id, operation: "suspend", suspend_until: at(60), on_expiry: "resume" });
    expect(first.status, first.text).toBe(200);
    const armed = as.kernel.get(m.id) as MissionRecord;
    expect(armed.schedule).toMatchObject({ on_expiry: "resume", committing_party: operator.clientId, generation: armed.version });
    const until = at(120);
    const second = await op(deputy, { mission_id: m.id, operation: "suspend", suspend_until: until, on_expiry: "revoke" });
    expect(second.status, second.text).toBe(200);
    const reported = decodeStatusResponse(second.text).mission;
    expect(reported).toMatchObject({ state: "suspended", suspend_until: until, on_expiry: "revoke", version: armed.version + 1 });
    expect(as.kernel.get(m.id)?.schedule).toEqual({
      suspend_until: until,
      on_expiry: "revoke",
      committing_party: deputy.clientId,
      generation: armed.version + 1,
    });
    const emitted = events(as.kernel, m.id);
    expect(emitted.at(-2)).toMatchObject({
      prior_state: "active",
      state: "suspended",
      on_expiry: "resume",
      schedule_committing_party: operator.clientId,
    });
    expect(emitted.at(-1)).toMatchObject({
      prior_state: "suspended",
      state: "suspended",
      version: armed.version + 1,
      suspend_until: until,
      on_expiry: "revoke",
      schedule_committing_party: deputy.clientId,
    });
    // Arming where none is recorded is a replacement too.
    const bare = approve();
    expect((await op(suspender, { mission_id: bare.id, operation: "suspend" })).status).toBe(200);
    const bareVersion = stored(as.kernel, bare.id).version;
    const set = await op(deputy, { mission_id: bare.id, operation: "suspend", suspend_until: until, on_expiry: "revoke" });
    expect(set.status, set.text).toBe(200);
    expect(as.kernel.get(bare.id)?.schedule).toMatchObject({ committing_party: deputy.clientId, generation: bareVersion + 1 });
    expect(events(as.kernel, bare.id).at(-1)).toMatchObject({ prior_state: "suspended", state: "suspended", on_expiry: "revoke" });
  });

  it("leaves the recorded schedule and its committing party unchanged on a suspend omitting both members, whoever sends it, and on the recorded pair sent again; the deadline still applies", async () => {
    const m = approve();
    const until = at(60);
    expect(
      (await op(operator, { mission_id: m.id, operation: "suspend", suspend_until: until, on_expiry: "revoke" })).status,
    ).toBe(200);
    const armed = as.kernel.get(m.id);
    const emitted = events(as.kernel, m.id).length;
    const omitted = await op(suspender, { mission_id: m.id, operation: "suspend" });
    expect(omitted.status, omitted.text).toBe(200);
    expect(decodeStatusResponse(omitted.text).mission).toMatchObject({ suspend_until: until, on_expiry: "revoke" });
    // The same deadline in another RFC 3339 spelling is the recorded pair.
    const same = await op(deputy, {
      mission_id: m.id,
      operation: "suspend",
      suspend_until: until.replace(".000Z", "+00:00"),
      on_expiry: "revoke",
    });
    expect(same.status, same.text).toBe(200);
    expect(as.kernel.get(m.id)).toEqual(armed);
    expect(events(as.kernel, m.id)).toHaveLength(emitted);
    await clock.advance(60_000);
    expect(stored(as.kernel, m.id)).toMatchObject({ state: "terminated", termination: "revoked" });
  });

  it("refuses either schedule member alone against a suspended Mission with a recorded schedule invalid_request, changing neither its state nor its schedule", async () => {
    const m = approve();
    expect(
      (await op(operator, { mission_id: m.id, operation: "suspend", suspend_until: at(600), on_expiry: "resume" })).status,
    ).toBe(200);
    const before = as.kernel.get(m.id);
    for (const members of [{ suspend_until: at(900) }, { on_expiry: "revoke" }]) {
      const refused = await op(operator, { mission_id: m.id, operation: "suspend", ...members });
      expect(refused.status, `${JSON.stringify(members)}: ${refused.text}`).toBe(400);
      expect(refused.json?.error).toBe("invalid_request");
    }
    expect(as.kernel.get(m.id)).toEqual(before);
  });

  it("reports suspend_until and on_expiry in the signed Mission Status Response exactly while the Mission is suspended under a deadline", async () => {
    const m = approve();
    const hasSchedule = (mission: Record<string, unknown>) =>
      Object.hasOwn(mission, "suspend_until") || Object.hasOwn(mission, "on_expiry");
    expect(hasSchedule(await status(m.id))).toBe(false);
    expect((await op(operator, { mission_id: m.id, operation: "suspend" })).status).toBe(200);
    expect(hasSchedule(await status(m.id))).toBe(false);
    const until = at(600);
    expect(
      (await op(operator, { mission_id: m.id, operation: "suspend", suspend_until: until, on_expiry: "revoke" })).status,
    ).toBe(200);
    expect(await status(m.id)).toMatchObject({ state: "suspended", suspend_until: until, on_expiry: "revoke" });
    expect((await op(operator, { mission_id: m.id, operation: "resume" })).status).toBe(200);
    const resumed = await status(m.id);
    expect(resumed.state).toBe("active");
    expect(hasSchedule(resumed)).toBe(false);
  });

  it("refuses a suspend_until already passed invalid_request, before any change", async () => {
    const m = approve();
    const before = as.kernel.get(m.id);
    for (const until of [at(0), at(-1)]) {
      const refused = await op(operator, { mission_id: m.id, operation: "suspend", suspend_until: until, on_expiry: "resume" });
      expect(refused.status, refused.text).toBe(400);
      expect(refused.json?.error).toBe("invalid_request");
    }
    expect(as.kernel.get(m.id)).toEqual(before);
  });
});

describe("suspension schedule deadlines (@spec status#mission-lifecycle-endpoint, status#legal-transitions, status#state-machine, #1002)", () => {
  it("applies on_expiry when suspend_until passes, without a further request: resume returns the Mission to active and revoke terminates it revoked, each transition emitted once", async () => {
    const r = approve();
    const v = approve();
    expect((await op(operator, { mission_id: r.id, operation: "suspend", suspend_until: at(30), on_expiry: "resume" })).status).toBe(200);
    expect((await op(operator, { mission_id: v.id, operation: "suspend", suspend_until: at(30), on_expiry: "revoke" })).status).toBe(200);
    const rSuspended = stored(as.kernel, r.id);
    const vSuspended = stored(as.kernel, v.id);
    await clock.advance(29_000);
    expect(stored(as.kernel, r.id)).toEqual(rSuspended);
    expect(stored(as.kernel, v.id)).toEqual(vSuspended);
    await clock.advance(1_000);
    // No request in between: the stored rows are what the timers committed.
    expect(stored(as.kernel, r.id)).toEqual({ state: "active", version: rSuspended.version + 1 });
    expect(stored(as.kernel, v.id)).toEqual({ state: "terminated", version: vSuspended.version + 1, termination: "revoked" });
    expect(as.kernel.get(r.id)?.schedule).toBeUndefined();
    expect(events(as.kernel, r.id).filter((e) => e.prior_state === "suspended" && e.state === "active")).toHaveLength(1);
    expect(events(as.kernel, r.id).at(-1)).toMatchObject({ prior_state: "suspended", state: "active", version: rSuspended.version + 1 });
    expect(events(as.kernel, v.id).filter((e) => e.state === "terminated")).toHaveLength(1);
    expect(events(as.kernel, v.id).at(-1)).toMatchObject({
      prior_state: "suspended",
      state: "terminated",
      termination: { reason: "revoked" },
    });
    expect((await status(r.id)).state).toBe("active");
    expect(await status(v.id)).toMatchObject({ state: "terminated", termination: { reason: "revoked" } });
  });

  it("applies a resume schedule at its deadline after the committing party's lifecycle grants are withdrawn", async () => {
    const m = approve();
    const committed = await op(deputy, { mission_id: m.id, operation: "suspend", suspend_until: at(30), on_expiry: "resume" });
    expect(committed.status, committed.text).toBe(200);
    const withdrawn = deputyGrants.splice(0);
    try {
      // The withdrawal is in force: the deputy can no longer resume directly.
      const refused = await op(deputy, { mission_id: m.id, operation: "resume" });
      expect(refused.status, refused.text).toBe(404);
      expect(stored(as.kernel, m.id).state).toBe("suspended");
      await clock.advance(30_000);
      expect(stored(as.kernel, m.id).state).toBe("active");
    } finally {
      deputyGrants.push(...withdrawn);
    }
  });

  it("never applies a superseded schedule: after a direct resume and a new suspend, or an authorized replacement, the original deadline leaves the Mission suspended with its current schedule and committing party", async () => {
    // Cancellation is never what protects a later suspension: every superseded timer still fires.
    clock.ignoreClears = true;
    try {
      const arm = async (id: string, client: LifecycleTestClient, seconds: number, onExpiry: string) => {
        const res = await op(client, { mission_id: id, operation: "suspend", suspend_until: at(seconds), on_expiry: onExpiry });
        expect(res.status, res.text).toBe(200);
        return as.kernel.get(id)?.schedule?.generation as number;
      };
      // Resumed, then suspended again with no schedule.
      const a = approve();
      const aOld = await arm(a.id, operator, 30, "resume");
      expect((await op(operator, { mission_id: a.id, operation: "resume" })).status).toBe(200);
      expect((await op(deputy, { mission_id: a.id, operation: "suspend" })).status).toBe(200);
      // Resumed, then suspended again under a later schedule.
      const b = approve();
      const bOld = await arm(b.id, operator, 30, "resume");
      expect((await op(operator, { mission_id: b.id, operation: "resume" })).status).toBe(200);
      await arm(b.id, deputy, 600, "revoke");
      // Replaced by an authorized caller.
      const c = approve();
      const cOld = await arm(c.id, operator, 30, "resume");
      await arm(c.id, deputy, 600, "revoke");
      const before = [a, b, c].map((m) => as.kernel.get(m.id));
      await clock.advance(31_000);
      for (const [i, m] of [a, b, c].entries()) {
        expect(stored(as.kernel, m.id).state, m.id).toBe("suspended");
        expect(as.kernel.get(m.id), m.id).toEqual(before[i]);
      }
      expect(as.kernel.get(a.id)?.schedule).toBeUndefined();
      expect(as.kernel.get(b.id)?.schedule).toMatchObject({ on_expiry: "revoke", committing_party: deputy.clientId });
      expect(as.kernel.get(c.id)?.schedule).toMatchObject({ on_expiry: "revoke", committing_party: deputy.clientId });
      // A late duplicate of each superseded timer changes nothing either.
      for (const [m, generation] of [
        [a, aOld],
        [b, bOld],
        [c, cOld],
      ] as const) {
        expect(await scheduler().deliver({ missionId: m.id, generation })).toBe("superseded");
      }
      expect([a, b, c].map((m) => as.kernel.get(m.id))).toEqual(before);
      // A stale delivery acts on nothing even while the current schedule is
      // due: only the current generation's own delivery applies it.
      const d = approve();
      const dOld = await arm(d.id, operator, 40, "resume");
      const dCurrent = await arm(d.id, deputy, 45, "revoke");
      clock.skip(46_000);
      expect(await scheduler().deliver({ missionId: d.id, generation: dOld })).toBe("superseded");
      expect(stored(as.kernel, d.id).state).toBe("suspended");
      expect(await scheduler().deliver({ missionId: d.id, generation: dCurrent })).toBe("applied");
      expect(stored(as.kernel, d.id)).toMatchObject({ state: "terminated", termination: "revoked" });
    } finally {
      clock.ignoreClears = false;
    }
  });

  it("changes nothing when the deadline passes for a Mission revoked or completed since its schedule was armed", async () => {
    clock.ignoreClears = true;
    try {
      const terminal: Array<[MissionRecord, string]> = [
        [approve(), "revoke"],
        [approve(), "complete"],
      ];
      const generations: number[] = [];
      for (const [m, operation] of terminal) {
        expect((await op(operator, { mission_id: m.id, operation: "suspend", suspend_until: at(30), on_expiry: "resume" })).status).toBe(200);
        generations.push(as.kernel.get(m.id)?.schedule?.generation as number);
        expect((await op(operator, { mission_id: m.id, operation })).status).toBe(200);
      }
      const before = terminal.map(([m]) => ({ record: as.kernel.get(m.id), emitted: events(as.kernel, m.id).length }));
      await clock.advance(31_000);
      for (const [i, [m]] of terminal.entries()) {
        expect(await scheduler().deliver({ missionId: m.id, generation: generations[i] as number })).toBe("superseded");
        expect(as.kernel.get(m.id)).toEqual(before[i]?.record);
        expect(events(as.kernel, m.id)).toHaveLength(before[i]?.emitted as number);
      }
      expect(stored(as.kernel, terminal[0]?.[0].id as string)).toMatchObject({ state: "terminated", termination: "revoked" });
      expect(stored(as.kernel, terminal[1]?.[0].id as string)).toMatchObject({ state: "terminated", termination: "completed" });
    } finally {
      clock.ignoreClears = false;
    }
  });

  it("changes nothing when the deadline passes for a Child Mission terminated parent_terminated by its parent's revocation", async () => {
    const childClock = new ControlledClock(new Date(clock.at.getTime()));
    childClock.ignoreClears = true;
    const resource = DERIVATION_POLICY.ceiling[0].resource as string;
    const entry = (actions: string[]): AuthorityEntry[] => [
      {
        type: "mission_resource_access",
        resource,
        actions,
        constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
      },
    ];
    let childScheduler: SuspensionScheduler | undefined;
    const kernel = new MissionKernel({
      issuer: "https://as.test",
      policy: DERIVATION_POLICY as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["parent-agent"], ["bob"]),
      statusKey: (await generateKeyPair("ES256")).privateKey,
      statusKid: "as-status",
      now: childClock.now,
      actorProfiles: aiAgents("child-agent"),
      onLifecycleCommit: (c) => childScheduler?.onLifecycleCommit(c),
    });
    childScheduler = new SuspensionScheduler(kernel, { timers: childClock });
    const expiresAt = at(30 * 86400, childClock);
    const parent = kernel.approve({
      intent: kernel.validateIntent(JSON.stringify({ goal: "Pay Acme", target_resources: [resource], expires_at: expiresAt })),
      proposedAuthority: entry(["payments:invoice.read", "payments:payment.execute"]),
      subject: { iss: "https://as.test", sub: "alice" },
      approver: { iss: "https://as.test", sub: "bob" },
      clientId: "parent-agent",
      approvalEventId: "apev-sched-parent",
    });
    const child = createChildMission(kernel, {
      parentId: parent.id,
      intent: kernel.validateIntent(
        JSON.stringify({ goal: "Read Acme invoices", target_resources: [resource], expires_at: expiresAt }),
      ),
      proposedAuthority: entry(["payments:invoice.read"]),
      childActor: { sub: "child-agent", sub_profile: "ai_agent" },
    }).child;
    kernel.transition(child.id, "suspend", {
      schedule: { suspend_until: at(30, childClock), on_expiry: "resume", committing_party: "svc:ops" },
    });
    const generation = kernel.get(child.id)?.schedule?.generation as number;
    kernel.transition(parent.id, "revoke");
    const terminated = kernel.get(child.id);
    expect(terminated).toMatchObject({ state: "terminated", termination: { reason: "parent_terminated" } });
    await childClock.advance(31_000);
    expect(await childScheduler.deliver({ missionId: child.id, generation })).toBe("superseded");
    expect(kernel.get(child.id)).toEqual(terminated);
    kernel.db.close();
  });

  it("lets expiry govern a deadline at or after expires_at: the Mission is terminated expired at expires_at and never observed active or revoked from its schedule", async () => {
    const missions: MissionRecord[] = [];
    for (const [later, onExpiry] of [
      [false, "resume"],
      [false, "revoke"],
      [true, "resume"],
      [true, "revoke"],
    ] as const) {
      const m = approve(at(120));
      const until = later ? at(180) : m.expires_at;
      const res = await op(operator, { mission_id: m.id, operation: "suspend", suspend_until: until, on_expiry: onExpiry });
      expect(res.status, res.text).toBe(200);
      missions.push(m);
    }
    const expiresAt = Date.parse(missions[0]?.expires_at as string);
    const observed = new Map<string, string[]>(missions.map((m) => [m.id, []]));
    const observe = async () => {
      for (const m of missions) {
        const s = await status(m.id);
        const reason = (s.termination as { reason?: string } | undefined)?.reason;
        observed.get(m.id)?.push(reason ? `${s.state}:${reason}` : String(s.state));
      }
    };
    // Across the boundary: before it, at it, at the later deadline, and after.
    for (const stepTo of [expiresAt - 1000, expiresAt, expiresAt + 60_000, expiresAt + 61_000]) {
      await clock.advance(stepTo - clock.at.getTime());
      await observe();
    }
    for (const m of missions) {
      expect(observed.get(m.id), m.id).toEqual(["suspended", "terminated:expired", "terminated:expired", "terminated:expired"]);
      expect(stored(as.kernel, m.id)).toMatchObject({ state: "terminated", termination: "expired" });
      const emitted = events(as.kernel, m.id);
      expect(emitted.some((e) => e.state === "active" && e.prior_state === "suspended")).toBe(false);
      expect(emitted.filter((e) => e.state === "terminated").map((e) => e.termination?.reason)).toEqual(["expired"]);
      expect(emitted.at(-1)?.termination?.terminated_at).toBe(m.expires_at);
    }
  });

  it("lets expiry govern a deadline before expires_at whose delivery comes only after expires_at: the Mission is terminated expired, never resumed", async () => {
    const m = approve(at(120));
    expect((await op(operator, { mission_id: m.id, operation: "suspend", suspend_until: at(60), on_expiry: "resume" })).status).toBe(200);
    const generation = as.kernel.get(m.id)?.schedule?.generation as number;
    // No delivery and no read until both instants have passed, as across a process outage.
    clock.skip(121_000);
    expect(await scheduler().deliver({ missionId: m.id, generation })).toBe("ended");
    expect(stored(as.kernel, m.id)).toMatchObject({ state: "terminated", termination: "expired" });
    expect(events(as.kernel, m.id).some((e) => e.state === "active" && e.prior_state === "suspended")).toBe(false);
  });

  it("commits one transition under duplicate deliveries of the same timer", async () => {
    const m = approve();
    expect((await op(operator, { mission_id: m.id, operation: "suspend", suspend_until: at(30), on_expiry: "resume" })).status).toBe(200);
    const generation = as.kernel.get(m.id)?.schedule?.generation as number;
    const suspendedAt = stored(as.kernel, m.id).version;
    clock.skip(30_000);
    const delivery = { missionId: m.id, generation };
    const outcomes = await Promise.all([scheduler().deliver(delivery), scheduler().deliver(delivery)]);
    expect([...outcomes].sort()).toEqual(["applied", "superseded"]);
    expect(await scheduler().deliver(delivery)).toBe("superseded");
    await clock.advance(0);
    expect(stored(as.kernel, m.id)).toEqual({ state: "active", version: suspendedAt + 1 });
    expect(events(as.kernel, m.id).filter((e) => e.version > suspendedAt)).toHaveLength(1);
  });

  it("serializes a deadline with a manual transition: whichever commits first decides, and the other acts on the state it left", async () => {
    // The manual revoke lands first; the deadline then finds no current schedule.
    const first = approve();
    expect((await op(operator, { mission_id: first.id, operation: "suspend", suspend_until: at(30), on_expiry: "resume" })).status).toBe(200);
    expect((await op(operator, { mission_id: first.id, operation: "revoke" })).status).toBe(200);
    const revoked = stored(as.kernel, first.id);
    // The deadline passes before its timer runs; a manual resume then reads the
    // record through the expiry clock, which applies the due revoke first.
    const raced = approve();
    expect((await op(operator, { mission_id: raced.id, operation: "suspend", suspend_until: at(30), on_expiry: "revoke" })).status).toBe(200);
    const racedGeneration = as.kernel.get(raced.id)?.schedule?.generation as number;
    // The timer applies the resume first; a manual resume is then a conflict,
    // and a new suspension is its own.
    const timed = approve();
    expect((await op(operator, { mission_id: timed.id, operation: "suspend", suspend_until: at(30), on_expiry: "resume" })).status).toBe(200);
    const timedGeneration = as.kernel.get(timed.id)?.schedule?.generation as number;
    clock.skip(30_000);
    expect(await scheduler().deliver({ missionId: timed.id, generation: timedGeneration })).toBe("applied");
    const late = await op(operator, { mission_id: raced.id, operation: "resume" });
    expect(late.status, late.text).toBe(409);
    expect(late.json?.error).toBe("conflict");
    expect(stored(as.kernel, raced.id)).toMatchObject({ state: "terminated", termination: "revoked" });
    expect(await scheduler().deliver({ missionId: raced.id, generation: racedGeneration })).toBe("superseded");
    expect((await op(operator, { mission_id: timed.id, operation: "resume" })).status).toBe(409);
    expect((await op(deputy, { mission_id: timed.id, operation: "suspend" })).status).toBe(200);
    await clock.advance(0);
    expect(await scheduler().deliver({ missionId: timed.id, generation: timedGeneration })).toBe("superseded");
    expect(stored(as.kernel, timed.id).state).toBe("suspended");
    expect(stored(as.kernel, first.id)).toEqual(revoked);
  });

  it("applies a due schedule on the next read of the record, before its timer is delivered, and the Status operation reports the committed transition", async () => {
    const m = approve();
    expect((await op(operator, { mission_id: m.id, operation: "suspend", suspend_until: at(30), on_expiry: "resume" })).status).toBe(200);
    const suspendedAt = stored(as.kernel, m.id).version;
    clock.skip(30_000);
    expect(stored(as.kernel, m.id).state).toBe("suspended");
    expect(await status(m.id)).toMatchObject({ state: "active", version: suspendedAt + 1 });
    expect(stored(as.kernel, m.id)).toEqual({ state: "active", version: suspendedAt + 1 });
    await clock.advance(0);
    expect(stored(as.kernel, m.id).version).toBe(suspendedAt + 1);
  });
});

describe("suspension scheduler deployment (@spec status#mission-lifecycle-endpoint, control-plane#serialization, #1002)", () => {
  const dirs: string[] = [];
  afterAll(() => {
    for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
  });

  it("re-arms each persisted schedule at boot on the file-backed store: one whose deadline passed while the process was down applies before the assembly serves, a later one at its deadline", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mission-schedule-"));
    dirs.push(dir);
    const file = join(dir, "kernel.db");
    const down = new ControlledClock(new Date(clock.at.getTime()));
    const first = await buildAuthorizationServer({
      issuer: RESTART_ISSUER,
      kernelStore: { file },
      suspensionSchedules: { timers: down },
      now: down.now,
    });
    const passed = approveOn(first.kernel, RESTART_ISSUER, at(30 * 86400, down));
    const later = approveOn(first.kernel, RESTART_ISSUER, at(30 * 86400, down));
    first.kernel.transition(passed.id, "suspend", {
      schedule: { suspend_until: at(60, down), on_expiry: "resume", committing_party: "svc:ops" },
    });
    first.kernel.transition(later.id, "suspend", {
      schedule: { suspend_until: at(600, down), on_expiry: "revoke", committing_party: "svc:ops" },
    });
    const laterGeneration = first.kernel.get(later.id)?.schedule?.generation;
    first.suspensionScheduler?.stop();
    first.kernel.db.close();

    // Down for two minutes: the first deadline passes with no process to apply it.
    const up = new ControlledClock(new Date(down.at.getTime() + 120_000));
    const second = await buildAuthorizationServer({
      issuer: RESTART_ISSUER,
      kernelStore: { file },
      suspensionSchedules: { timers: up },
      now: up.now,
    });
    try {
      expect(stored(second.kernel, passed.id).state).toBe("active");
      expect(events(second.kernel, passed.id).at(-1)).toMatchObject({ prior_state: "suspended", state: "active" });
      expect(second.suspensionScheduler?.armedGenerations().get(later.id)).toBe(laterGeneration);
      expect(stored(second.kernel, later.id).state).toBe("suspended");
      await up.advance(480_000);
      expect(stored(second.kernel, later.id)).toMatchObject({ state: "terminated", termination: "revoked" });
    } finally {
      second.suspensionScheduler?.stop();
      second.kernel.db.close();
    }
  });

  it("runs no scheduler where schedules are not adopted or suspend is not served", async () => {
    const off = await buildAuthorizationServer({ issuer: "http://localhost:14839" });
    expect(off.suspensionScheduler).toBeUndefined();
    const revokeOnly = await buildAuthorizationServer({
      issuer: "http://localhost:14839",
      suspensionSchedules: { timers: new ControlledClock(new Date()) },
      capabilities: new Set(["oidc", "lifecycle-revoke"]),
    });
    expect(revokeOnly.suspensionScheduler).toBeUndefined();
    expect(as.suspensionScheduler).toBeDefined();
  });
});
