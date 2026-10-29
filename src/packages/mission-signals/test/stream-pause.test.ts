/**
 * @spec draft-mcguinness-oauth-mission-signals (#discharge-compatibility,
 * #consumer-behavior)
 *
 * A withheld narrowing pauses the undeclared stream (#1877, D1017). The gate
 * withholds an event carrying `authority_changed` true from a stream whose
 * consumer has not declared `authority_changed`. The Mission Issuer then
 * pauses that stream through SSF stream status: a Stream Updated event with
 * `status` `paused` before anything else on it, its later events held with
 * their versions, and no re-enable until more than `mission_max_stale_seconds`
 * have passed since the last verification event it delivered there. While
 * paused the stream carries no liveness attestation, so the consumer's
 * existing staleness rule ends its reliance within that bound of its last
 * liveness event.
 *
 * The undeclared consumer is modeled by Signals' own rule, taken literally:
 * the model knows nothing of the pause or of `authority_changed`.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type AuthorityEntry,
  MissionKernel,
  type MissionRecord,
  validateMissionIntent,
} from "@mission/authorization-server";
import { testAuthoritySourceCatalog } from "@mission/authorization-server/test-support";
import { decodeJwt, exportJWK, generateKeyPair, type JWK } from "jose";
import { afterAll, describe, expect, it } from "vitest";
import {
  type ApplyResult,
  AUTHORITY_CHANGED_CAPABILITY,
  LIFECYCLE_CHANGE_EVENT_URI,
  MissionSignalEmitter,
  MissionSignalReceiver,
  SSF_STREAM_UPDATED_EVENT_URI,
  SSF_VERIFICATION_EVENT_URI,
} from "../src/index.js";

const ISS = "https://as.test";
const DECLARED_AUD = "https://declared.consumer.test";
const UNDECLARED_AUD = "https://undeclared.consumer.test";
const UNDECLARED_STREAM = "stream-undeclared-1";
const RESOURCE = "https://payments.test/mcp";
const T0 = Date.parse("2026-08-20T12:00:00Z");
const EXPIRES_AT = "2027-01-01T00:00:00Z";
/** The issuer's advertised `mission_max_stale_seconds`. */
const MAX_STALE_SECONDS = 60;
const MAX_STALE_MS = MAX_STALE_SECONDS * 1000;
/** The liveness schedule: well under `mission_max_stale_seconds`. */
const HEARTBEAT_MS = 10_000;

const POLICY = {
  policy_version: "stream-pause-v1",
  ceiling: [
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: ["payments:invoice.read", "payments:payment.execute"],
    },
  ],
};

const proposal = (): AuthorityEntry[] => [
  { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] },
  { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:payment.execute"] },
];

type Kind = "lifecycle" | "verification" | "stream-updated";

interface Received {
  at: number;
  kind: Kind;
  set: string;
}

function kindOf(set: string): Kind {
  const events = decodeJwt(set).events as Record<string, unknown>;
  if (LIFECYCLE_CHANGE_EVENT_URI in events) return "lifecycle";
  if (SSF_VERIFICATION_EVENT_URI in events) return "verification";
  if (SSF_STREAM_UPDATED_EVENT_URI in events) return "stream-updated";
  throw new Error("unexpected event type");
}

const eventBody = (r: Received): Record<string, unknown> =>
  (decodeJwt(r.set).events as Record<string, Record<string, unknown>>)[
    r.kind === "lifecycle"
      ? LIFECYCLE_CHANGE_EVENT_URI
      : r.kind === "verification"
        ? SSF_VERIFICATION_EVENT_URI
        : SSF_STREAM_UPDATED_EVENT_URI
  ] as Record<string, unknown>;

/** A compact trace of what a stream received: `v<version>`, `verify`, or the Stream Updated status. */
const trace = (log: Received[]): string[] =>
  log.map((r) =>
    r.kind === "lifecycle"
      ? `v${eventBody(r).version}`
      : r.kind === "verification"
        ? "verify"
        : String(eventBody(r).status),
  );

/**
 * Signals' consumer rule, taken literally (@spec signals#consumer-behavior):
 * a verification or heartbeat event attests liveness; cached Mission state is
 * stale once the stream has gone longer than `mission_max_stale_seconds`
 * without one, and once stale it stays stale until the consumer
 * re-establishes state through Mission Status. A Stream Updated event is not
 * a liveness event.
 */
class StalenessRule {
  private lastLiveness: number | undefined;
  private stale = false;
  constructor(private readonly maxStaleMs: number) {}

  receive(r: Received): void {
    if (r.kind !== "verification") return;
    this.check(r.at);
    this.lastLiveness = r.at;
  }

  private check(at: number): void {
    if (this.lastLiveness !== undefined && at - this.lastLiveness > this.maxStaleMs)
      this.stale = true;
  }

  /** Whether the consumer may still rely on its cached Mission state at `at`. */
  mayRely(at: number): boolean {
    this.check(at);
    return this.lastLiveness !== undefined && !this.stale;
  }

  get lastLivenessAt(): number | undefined {
    return this.lastLiveness;
  }
}

const tmpDirs: string[] = [];
afterAll(() => {
  for (const d of tmpDirs) rmSync(d, { recursive: true, force: true });
});

interface Wired {
  kernel: MissionKernel;
  emitter: MissionSignalEmitter;
  declaredLog: Received[];
  undeclaredLog: Received[];
  undeclaredResults: ApplyResult[];
  undeclared: MissionSignalReceiver;
  rule: StalenessRule;
  now: () => number;
  advance: (ms: number) => void;
  /** One heartbeat: advance the clock, attest liveness, dispatch. */
  tick: () => Promise<void>;
  /** Wire a fresh emitter over the same store, as after a restart. */
  reopen: () => MissionSignalEmitter;
}

async function wire(store?: { file: string }): Promise<Wired> {
  const statusKeys = await generateKeyPair("ES256", { extractable: true });
  const statusPub: JWK = {
    ...(await exportJWK(statusKeys.publicKey)),
    kid: "as-status",
    alg: "ES256",
    use: "sig",
  };
  let clock = T0;
  const now = () => clock;
  const consumers = [
    { audience: DECLARED_AUD, mission_capabilities_supported: [AUTHORITY_CHANGED_CAPABILITY] },
    { audience: UNDECLARED_AUD, stream_id: UNDECLARED_STREAM },
  ];
  const makeEmitter = () =>
    new MissionSignalEmitter({
      key: statusKeys.privateKey,
      kid: "as-status",
      issuer: ISS,
      consumers,
      maxStaleSeconds: MAX_STALE_SECONDS,
      now: () => new Date(clock),
      ...(store ? { store } : {}),
    });
  const undeclared = new MissionSignalReceiver({
    jwks: { keys: [statusPub] },
    issuer: ISS,
    audience: UNDECLARED_AUD,
  });
  const declaredLog: Received[] = [];
  const undeclaredLog: Received[] = [];
  const undeclaredResults: ApplyResult[] = [];
  const rule = new StalenessRule(MAX_STALE_MS);
  const sinks = (emitter: MissionSignalEmitter) => {
    emitter.onDeliver(DECLARED_AUD, (set) => {
      declaredLog.push({ at: clock, kind: kindOf(set), set });
    });
    emitter.onDeliver(UNDECLARED_AUD, async (set) => {
      const r: Received = { at: clock, kind: kindOf(set), set };
      undeclaredLog.push(r);
      rule.receive(r);
      if (r.kind === "lifecycle") undeclaredResults.push(await undeclared.verifyAndApply(set));
    });
  };
  let emitter = makeEmitter();
  sinks(emitter);
  const kernel = new MissionKernel({
    issuer: ISS,
    policy: POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(POLICY.ceiling, ["ap-agent"], ["bob"]),
    statusKey: statusKeys.privateKey,
    statusKid: "as-status",
    now: () => new Date(clock),
    onLifecycleCommit: (c) => emitter.onCommit(c),
  });
  const advance = (ms: number) => {
    clock += ms;
  };
  return {
    kernel,
    get emitter() {
      return emitter;
    },
    declaredLog,
    undeclaredLog,
    undeclaredResults,
    undeclared,
    rule,
    now,
    advance,
    tick: async () => {
      advance(HEARTBEAT_MS);
      await emitter.attestLiveness();
      await emitter.drain();
    },
    reopen: () => {
      emitter.close();
      emitter = makeEmitter();
      sinks(emitter);
      return emitter;
    },
  };
}

let approvals = 0;
function approve(kernel: MissionKernel): MissionRecord {
  approvals += 1;
  return kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({
        goal: "Read invoices and execute approved payments",
        target_resources: [RESOURCE],
        expires_at: EXPIRES_AT,
      }),
    ),
    proposedAuthority: proposal(),
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-stream-pause-${approvals}`,
  });
}

/** A contain commit that narrows effective authority: the read entry loses its only action. */
function containRead(w: Wired, missionId: string, eventId: string): void {
  w.kernel.contain(missionId, {
    event: {
      type: "anomaly.detected",
      source: "svc:soc",
      observed_at: new Date(w.now()).toISOString(),
      event_id: eventId,
    },
    remove: [{ resource: RESOURCE, actions: ["payments:invoice.read"] }],
  });
}

/** What the stream received at or after `from`. */
const since = (log: Received[], from: number): Received[] => log.filter((r) => r.at >= from);

describe("a withheld narrowing pauses the undeclared stream (@spec signals#discharge-compatibility, #1877)", () => {
  it("pauses the stream with Stream Updated first; with liveness attested on schedule, the consumer's staleness rule ends reliance within mission_max_stale_seconds of its last liveness event, before the stream is re-enabled", async () => {
    const w = await wire();
    const mission = approve(w.kernel);
    await w.emitter.drain();
    // Heartbeats flow on both streams until the withholding.
    for (let i = 0; i < 3; i++) await w.tick();
    expect(trace(w.undeclaredLog)).toEqual(["v1", "verify", "verify", "verify"]);
    const lastLiveness = w.rule.lastLivenessAt as number;
    expect(lastLiveness).toBe(T0 + 3 * HEARTBEAT_MS);
    expect(w.rule.mayRely(w.now())).toBe(true);

    // A real contain commit, withheld from the undeclared stream.
    w.advance(5_000);
    const withheldAt = w.now();
    containRead(w, mission.id, "evt-pause-contain-1");
    await w.emitter.drain();

    // The declared stream receives the narrowing; the undeclared stream
    // receives the Stream Updated event, status paused, before anything else.
    expect(trace(since(w.declaredLog, withheldAt))).toEqual(["v2"]);
    const afterWithholding = since(w.undeclaredLog, withheldAt);
    expect(trace(afterWithholding)).toEqual(["paused"]);
    expect(decodeJwt(afterWithholding[0]?.set as string)).toMatchObject({
      iss: ISS,
      aud: UNDECLARED_AUD,
      sub_id: { format: "opaque", id: UNDECLARED_STREAM },
    });
    expect(eventBody(afterWithholding[0] as Received)).toMatchObject({ status: "paused" });
    expect(typeof eventBody(afterWithholding[0] as Received).reason).toBe("string");
    expect(w.emitter.streamStatus(UNDECLARED_AUD)).toMatchObject({
      status: "paused",
      reenable_after: new Date(lastLiveness + MAX_STALE_MS),
    });

    // Liveness keeps being attested on schedule up to the bound: the declared
    // stream keeps receiving verification events, the undeclared one none.
    w.advance(HEARTBEAT_MS - 5_000);
    await w.emitter.attestLiveness();
    await w.emitter.drain();
    while (w.now() + HEARTBEAT_MS <= lastLiveness + MAX_STALE_MS) await w.tick();
    expect(w.now()).toBe(lastLiveness + MAX_STALE_MS);
    expect(trace(since(w.declaredLog, withheldAt + 1))).toEqual(Array(6).fill("verify"));
    expect(trace(since(w.undeclaredLog, withheldAt))).toEqual(["paused"]);

    // At exactly mission_max_stale_seconds the stream has not gone LONGER
    // than the bound: the consumer may still rely, and the stream is not
    // re-enabled.
    expect(w.rule.mayRely(w.now())).toBe(true);
    expect(w.emitter.streamStatus(UNDECLARED_AUD).status).toBe("paused");

    // One millisecond later the consumer's reliance has ended, with the
    // stream still paused: no liveness event, no Stream Updated enabled, no
    // lifecycle event reached it first.
    w.advance(1);
    expect(w.rule.mayRely(w.now())).toBe(false);
    expect(trace(since(w.undeclaredLog, withheldAt))).toEqual(["paused"]);

    // The narrowing never reached the undeclared receiver's cache; Mission
    // Status, where the stale consumer re-establishes state, reports it.
    expect(w.undeclared.viewState(mission.id)).toMatchObject({ state: "active", version: 1 });
    const status = w.kernel.statusObservation(mission.id, {
      requester: "svc:reader",
      audience: RESOURCE,
    }).payload;
    expect(status.mission).toMatchObject({ version: 2, containment_version: 1 });

    // Only now is the stream re-enabled; liveness resumes after the bound,
    // and does not restore reliance on the state cached across the gap.
    await w.emitter.drain();
    await w.tick();
    expect(trace(since(w.undeclaredLog, withheldAt))).toEqual(["paused", "enabled", "verify"]);
    const resumed = since(w.undeclaredLog, withheldAt).find((r) => r.kind === "verification");
    expect((resumed as Received).at).toBeGreaterThan(lastLiveness + MAX_STALE_MS);
    expect(w.rule.mayRely(w.now())).toBe(false);
  });

  it("re-enables after the window: Stream Updated enabled, then the held events in order with their original versions; the withheld Mission's next event shows the gap", async () => {
    const w = await wire();
    const mission = approve(w.kernel);
    await w.emitter.drain();
    await w.tick();
    const lastLiveness = w.now();

    w.advance(1_000);
    containRead(w, mission.id, "evt-pause-contain-2"); // version 2: withheld
    w.kernel.transition(mission.id, "suspend"); // version 3: held
    w.kernel.transition(mission.id, "resume"); // version 4: held
    await w.emitter.drain();
    // The declared stream receives every event (concurrent dispatch passes
    // may reorder it, #576); the undeclared stream receives none of them.
    expect(trace(w.declaredLog.filter((r) => r.kind === "lifecycle")).sort()).toEqual([
      "v1",
      "v2",
      "v3",
      "v4",
    ]);
    expect(trace(w.undeclaredLog)).toEqual(["v1", "verify", "paused"]);

    // Dispatcher passes up to the bound leave everything held.
    w.advance(lastLiveness + MAX_STALE_MS - w.now());
    await w.emitter.drain();
    expect(trace(w.undeclaredLog)).toEqual(["v1", "verify", "paused"]);
    expect(w.emitter.pending()).toBe(2);

    w.advance(1);
    await w.emitter.drain();
    expect(trace(w.undeclaredLog)).toEqual(["v1", "verify", "paused", "enabled", "v3", "v4"]);
    expect(w.emitter.streamStatus(UNDECLARED_AUD)).toMatchObject({
      status: "enabled",
      notice_pending: false,
    });
    expect(w.emitter.pending()).toBe(0);

    // The held events carry the Mission's own versions: the receiver detects
    // the gap the withheld contain commit left, then applies in order.
    expect(w.undeclaredResults.map((r) => r.status)).toEqual(["applied", "gap", "applied"]);
    expect(w.undeclaredResults[1]).toMatchObject({ status: "gap", expected: 2, received: 3 });
  });

  it("holds another Mission's lifecycle event committed during the pause, and a verification its receiver requested, and delivers both after re-enable, never dropping either", async () => {
    const w = await wire();
    const narrowed = approve(w.kernel);
    const other = approve(w.kernel);
    await w.emitter.drain();
    await w.tick();
    const lastLiveness = w.now();

    w.advance(1_000);
    containRead(w, narrowed.id, "evt-pause-contain-3");
    await w.emitter.drain();
    w.advance(1_000);
    w.kernel.transition(other.id, "revoke"); // the other Mission: held
    w.emitter.requestVerification(UNDECLARED_AUD, "state-held-1");
    await w.emitter.drain();
    expect(trace(w.undeclaredLog)).toEqual(["v1", "v1", "verify", "paused"]);
    expect(w.emitter.pending()).toBe(1);

    // Repeated passes inside the window drop nothing and transmit nothing.
    for (let t = w.now(); t + 10_000 <= lastLiveness + MAX_STALE_MS; t += 10_000) {
      w.advance(10_000);
      await w.emitter.drain();
    }
    expect(trace(w.undeclaredLog)).toEqual(["v1", "v1", "verify", "paused"]);
    expect(w.emitter.pending()).toBe(1);

    w.advance(lastLiveness + MAX_STALE_MS + 1 - w.now());
    await w.emitter.drain();
    await w.emitter.drain();
    const after = w.undeclaredLog.slice(4);
    expect(after[0]?.kind).toBe("stream-updated");
    expect(eventBody(after[0] as Received)).toMatchObject({ status: "enabled" });
    expect(trace(after).sort()).toEqual(["enabled", "v2", "verify"].sort());
    const revoked = after.find((r) => r.kind === "lifecycle") as Received;
    expect(eventBody(revoked)).toMatchObject({
      mission: { id: other.id },
      state: "terminated",
      version: 2,
    });
    const verification = after.find((r) => r.kind === "verification") as Received;
    expect(eventBody(verification)).toEqual({ state: "state-held-1" });
    expect(w.undeclared.viewState(other.id)).toMatchObject({ state: "terminated", version: 2 });
    expect(w.emitter.pending()).toBe(0);
  });

  it("keeps the pause across a restart: a fresh emitter over the same store stays paused, holds the event and attests no liveness until the window has passed", async () => {
    const dir = mkdtempSync(join(tmpdir(), "signals-stream-pause-"));
    tmpDirs.push(dir);
    const w = await wire({ file: join(dir, "outbox.db") });
    const mission = approve(w.kernel);
    await w.emitter.drain();
    await w.tick();
    const lastLiveness = w.now();
    w.advance(1_000);
    containRead(w, mission.id, "evt-pause-contain-4");
    w.kernel.transition(mission.id, "suspend"); // held
    await w.emitter.drain();
    expect(trace(w.undeclaredLog)).toEqual(["v1", "verify", "paused"]);

    // Restart mid-pause.
    w.advance(10_000);
    const reopened = w.reopen();
    expect(reopened.streamStatus(UNDECLARED_AUD)).toMatchObject({
      status: "paused",
      reenable_after: new Date(lastLiveness + MAX_STALE_MS),
    });
    await reopened.drain();
    await reopened.attestLiveness();
    expect(trace(w.undeclaredLog)).toEqual(["v1", "verify", "paused"]);
    expect(reopened.pending()).toBe(1);

    // Up to the bound: still paused, still held.
    w.advance(lastLiveness + MAX_STALE_MS - w.now());
    await reopened.attestLiveness();
    await reopened.drain();
    expect(trace(w.undeclaredLog)).toEqual(["v1", "verify", "paused"]);

    w.advance(1);
    await reopened.drain();
    expect(trace(w.undeclaredLog)).toEqual(["v1", "verify", "paused", "enabled", "v3"]);
    reopened.close();
  });

  it("never shortens a pause on a second withholding: it extends it to that withholding plus mission_max_stale_seconds", async () => {
    const w = await wire();
    const first = approve(w.kernel);
    const second = approve(w.kernel);
    await w.emitter.drain();
    await w.tick();
    const lastLiveness = w.now();

    w.advance(1_000);
    containRead(w, first.id, "evt-pause-contain-5a");
    await w.emitter.drain();
    expect(w.emitter.streamStatus(UNDECLARED_AUD).reenable_after).toEqual(
      new Date(lastLiveness + MAX_STALE_MS),
    );

    // A second narrowing withheld during the pause: one Stream Updated
    // notice only, and the window now runs from this withholding.
    w.advance(30_000);
    const secondWithheld = w.now();
    containRead(w, second.id, "evt-pause-contain-5b");
    await w.emitter.drain();
    expect(trace(w.undeclaredLog)).toEqual(["v1", "v1", "verify", "paused"]);
    expect(w.emitter.streamStatus(UNDECLARED_AUD).reenable_after).toEqual(
      new Date(secondWithheld + MAX_STALE_MS),
    );

    // Past the first window, the stream stays paused.
    w.advance(lastLiveness + MAX_STALE_MS + 1 - w.now());
    await w.emitter.drain();
    expect(w.emitter.streamStatus(UNDECLARED_AUD).status).toBe("paused");
    expect(trace(w.undeclaredLog)).toEqual(["v1", "v1", "verify", "paused"]);

    w.advance(secondWithheld + MAX_STALE_MS + 1 - w.now());
    await w.emitter.drain();
    expect(trace(w.undeclaredLog)).toEqual(["v1", "v1", "verify", "paused", "enabled"]);
  });
});
