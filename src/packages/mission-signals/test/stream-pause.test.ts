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
 * a verification or heartbeat event attests liveness, and the stream stays
 * verified live for the heartbeat interval after one. The staleness rule
 * applies to a stream not verified live: cached Mission state is stale once
 * the stream has gone longer than `mission_max_stale_seconds` without a
 * liveness event. So it goes stale after the longer of the two, and once
 * stale it stays stale until the consumer re-establishes state through
 * Mission Status: neither a Stream Updated event nor a later verification
 * or heartbeat event ends it (D1023 ruling 4). A Stream Updated event is not
 * a liveness event.
 */
class StalenessRule {
  private lastLiveness: number | undefined;
  private stale = false;
  constructor(
    private readonly maxStaleMs: number,
    private readonly heartbeatIntervalMs: number,
  ) {}

  receive(r: Received): void {
    if (r.kind !== "verification") return;
    this.check(r.at);
    this.lastLiveness = r.at;
  }

  /** The consumer re-established current state through Mission Status at `at`. */
  reestablish(at: number): void {
    this.stale = false;
    this.lastLiveness = at;
  }

  private check(at: number): void {
    if (this.lastLiveness === undefined) return;
    const silence = at - this.lastLiveness;
    const verifiedLive = silence <= this.heartbeatIntervalMs;
    if (!verifiedLive && silence > this.maxStaleMs) this.stale = true;
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

/**
 * A fault on the undeclared stream's transport. `before` runs before the
 * receiver sees the SET: throwing there is a delivery that never arrived.
 * `after` runs once the receiver has processed it: throwing there is an
 * acknowledgement lost on the way back, and a promise that has not settled
 * is a hand-off still in flight after receipt.
 */
interface Fault {
  before?: (r: Received) => unknown;
  after?: (r: Received) => unknown;
}

interface Wired {
  kernel: MissionKernel;
  emitter: MissionSignalEmitter;
  declaredLog: Received[];
  undeclaredLog: Received[];
  undeclaredResults: ApplyResult[];
  undeclared: MissionSignalReceiver;
  rule: StalenessRule;
  /** The undeclared stream's transport fault, if any. */
  fault: Fault;
  now: () => number;
  advance: (ms: number) => void;
  /** One heartbeat: advance the clock, attest liveness, dispatch. */
  tick: () => Promise<void>;
  /**
   * Wire a fresh emitter over the same store, as after a restart, optionally
   * with a heartbeat interval configured where none was.
   */
  reopen: (heartbeatIntervalSeconds?: number) => MissionSignalEmitter;
}

async function wire(
  store?: { file: string },
  opts: {
    undeclaredFirst?: boolean;
    /** The agreed heartbeat interval; `null` configures none. */
    heartbeatIntervalSeconds?: number | null;
    clockToleranceSeconds?: number;
  } = {},
): Promise<Wired> {
  const statusKeys = await generateKeyPair("ES256", { extractable: true });
  const statusPub: JWK = {
    ...(await exportJWK(statusKeys.publicKey)),
    kid: "as-status",
    alg: "ES256",
    use: "sig",
  };
  let clock = T0;
  const now = () => clock;
  const declaredConsumer = {
    audience: DECLARED_AUD,
    mission_capabilities_supported: [AUTHORITY_CHANGED_CAPABILITY],
  };
  const undeclaredConsumer = { audience: UNDECLARED_AUD, stream_id: UNDECLARED_STREAM };
  // Consumer order is journal order: the first consumer's job is claimed first.
  const consumers = opts.undeclaredFirst
    ? [undeclaredConsumer, declaredConsumer]
    : [declaredConsumer, undeclaredConsumer];
  // The agreed heartbeat interval: the liveness schedule unless a test sets
  // another, or none at all.
  let heartbeatIntervalSeconds =
    opts.heartbeatIntervalSeconds === undefined
      ? HEARTBEAT_MS / 1000
      : opts.heartbeatIntervalSeconds;
  const makeEmitter = () =>
    new MissionSignalEmitter({
      key: statusKeys.privateKey,
      kid: "as-status",
      issuer: ISS,
      consumers,
      maxStaleSeconds: MAX_STALE_SECONDS,
      ...(heartbeatIntervalSeconds !== null ? { heartbeatIntervalSeconds } : {}),
      ...(opts.clockToleranceSeconds !== undefined
        ? { clockToleranceSeconds: opts.clockToleranceSeconds }
        : {}),
      now: () => new Date(clock),
      ...(store ? { store } : {}),
    });
  const undeclared = new MissionSignalReceiver({
    jwks: { keys: [statusPub] },
    issuer: ISS,
    audience: UNDECLARED_AUD,
    maxStaleSeconds: MAX_STALE_SECONDS,
  });
  const declaredLog: Received[] = [];
  const undeclaredLog: Received[] = [];
  const undeclaredResults: ApplyResult[] = [];
  const rule = new StalenessRule(
    MAX_STALE_MS,
    heartbeatIntervalSeconds !== null ? heartbeatIntervalSeconds * 1000 : HEARTBEAT_MS,
  );
  const fault: Fault = {};
  const sinks = (emitter: MissionSignalEmitter) => {
    emitter.onDeliver(DECLARED_AUD, (set) => {
      declaredLog.push({ at: clock, kind: kindOf(set), set });
    });
    emitter.onDeliver(UNDECLARED_AUD, async (set) => {
      const r: Received = { at: clock, kind: kindOf(set), set };
      if (fault.before) await fault.before(r);
      undeclaredLog.push(r);
      rule.receive(r);
      if (r.kind === "lifecycle") undeclaredResults.push(await undeclared.verifyAndApply(set));
      if (fault.after) await fault.after(r);
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
    fault,
    now,
    advance,
    tick: async () => {
      advance(HEARTBEAT_MS);
      await emitter.attestLiveness();
      await emitter.drain();
    },
    reopen: (interval?: number) => {
      emitter.close();
      if (interval !== undefined) heartbeatIntervalSeconds = interval;
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
    const after = w.undeclaredLog.slice(4);
    expect(after[0]?.kind).toBe("stream-updated");
    expect(eventBody(after[0] as Received)).toMatchObject({ status: "enabled" });
    // The enabled notice, the held lifecycle event, then the requested
    // verification, which waits behind it (#1877 review, D1023).
    expect(trace(after)).toEqual(["enabled", "v2", "verify"]);
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

  it("holds an event committed before the withholding and not yet delivered: the stream receives Stream Updated paused, then nothing until it is re-enabled", async () => {
    // The undeclared stream's job is journaled first, so its dispatch claims
    // it and starts signing before the withholding.
    const w = await wire(undefined, { undeclaredFirst: true });
    await w.tick();
    const lastLiveness = w.now();
    w.advance(1_000);
    // No drain between the commits: the activating event (version 1) is
    // journaled, and its dispatch started, before the withholding pauses
    // the undeclared stream.
    const mission = approve(w.kernel);
    containRead(w, mission.id, "evt-pause-contain-early");
    await w.emitter.drain();
    expect(trace(w.declaredLog.filter((r) => r.kind === "lifecycle")).sort()).toEqual(["v1", "v2"]);
    expect(trace(w.undeclaredLog)).toEqual(["verify", "paused"]);
    expect(w.emitter.pending()).toBe(1);

    w.advance(lastLiveness + MAX_STALE_MS + 1 - w.now());
    await w.emitter.drain();
    expect(trace(w.undeclaredLog)).toEqual(["verify", "paused", "enabled", "v1"]);
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

  it("waits out a heartbeat interval longer than mission_max_stale_seconds: no re-enable before the last liveness plus the interval, while the consumer is still verified live", async () => {
    const HEARTBEAT_INTERVAL_SECONDS = 90;
    const intervalMs = HEARTBEAT_INTERVAL_SECONDS * 1000;
    const w = await wire(undefined, { heartbeatIntervalSeconds: HEARTBEAT_INTERVAL_SECONDS });
    const mission = approve(w.kernel);
    await w.emitter.drain();
    // Heartbeats at the stream's interval, longer than the staleness bound.
    w.advance(intervalMs);
    await w.emitter.attestLiveness();
    await w.emitter.drain();
    const lastLiveness = w.rule.lastLivenessAt as number;
    expect(lastLiveness).toBe(w.now());

    w.advance(1_000);
    containRead(w, mission.id, "evt-pause-contain-interval");
    await w.emitter.drain();
    expect(trace(w.undeclaredLog)).toEqual(["v1", "verify", "paused"]);
    expect(w.emitter.streamStatus(UNDECLARED_AUD).reenable_after).toEqual(
      new Date(lastLiveness + intervalMs),
    );

    // Past mission_max_stale_seconds the consumer is still verified live, so
    // its staleness rule has not fired; the stream stays paused.
    w.advance(lastLiveness + MAX_STALE_MS + 1 - w.now());
    expect(w.rule.mayRely(w.now())).toBe(true);
    await w.emitter.drain();
    expect(w.emitter.streamStatus(UNDECLARED_AUD).status).toBe("paused");
    expect(trace(w.undeclaredLog)).toEqual(["v1", "verify", "paused"]);

    // At exactly the interval: still verified live, still paused.
    w.advance(lastLiveness + intervalMs - w.now());
    expect(w.rule.mayRely(w.now())).toBe(true);
    await w.emitter.drain();
    expect(trace(w.undeclaredLog)).toEqual(["v1", "verify", "paused"]);

    // Past the interval the consumer's reliance has ended, and only then is
    // the stream re-enabled.
    w.advance(1);
    expect(w.rule.mayRely(w.now())).toBe(false);
    await w.emitter.drain();
    expect(trace(w.undeclaredLog)).toEqual(["v1", "verify", "paused", "enabled"]);
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

/** The undeclared stream's private sink, as the owner's review probes reach it. */
type Sinks = Array<{ audience: string; deliver: (set: string) => unknown }>;
const undeclaredSink = (emitter: MissionSignalEmitter) =>
  (emitter as unknown as { deliveries: Sinks }).deliveries.find(
    (s) => s.audience === UNDECLARED_AUD,
  ) as Sinks[number];

/** A promise and the means to settle it, for a hand-off a test holds in flight. */
function deferred(): {
  promise: Promise<void>;
  resolve: () => void;
  reject: (e: Error) => void;
} {
  let resolve!: () => void;
  let reject!: (e: Error) => void;
  const promise = new Promise<void>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe("delivery uncertainty and liveness ordering (@spec signals#discharge-compatibility, signals#delivery, #1877 review, D1023)", () => {
  it("does not re-enable before a verification received but not acknowledged has aged past the window: the window runs from the end of that delivery attempt (review probe 1)", async () => {
    const w = await wire();
    const mission = approve(w.kernel);
    await w.emitter.drain();
    await w.tick(); // acknowledged at t10
    const sink = undeclaredSink(w.emitter);
    const deliver = sink.deliver;
    let loseAck = true;
    sink.deliver = async (set) => {
      const result = await deliver(set);
      if (loseAck && kindOf(set) === "verification") {
        loseAck = false;
        throw new Error("response lost after receiver accepted verification");
      }
      return result;
    };
    await w.tick(); // received at t20, ack lost: emitter still records t10
    expect(w.rule.lastLivenessAt).toBe(T0 + 20_000);
    expect(w.emitter.streamStatus(UNDECLARED_AUD).last_liveness_at?.getTime()).toBe(T0 + 10_000);
    // The failed attempt still ended at t20, and the window runs from there.
    expect(w.emitter.streamStatus(UNDECLARED_AUD)).toMatchObject({
      liveness_resolved_at: new Date(T0 + 20_000),
      liveness_unresolved: 0,
    });
    w.advance(1_000);
    containRead(w, mission.id, "review-lost-ack");
    await w.emitter.drain();
    expect(w.emitter.streamStatus(UNDECLARED_AUD).reenable_after).toEqual(
      new Date(T0 + 20_000 + MAX_STALE_MS),
    );
    w.advance(T0 + 70_001 - w.now());
    await w.emitter.drain();
    expect(w.rule.mayRely(w.now())).toBe(true);
    const prematurelyEnabled = w.emitter.streamStatus(UNDECLARED_AUD).status;
    await w.emitter.attestLiveness();
    for (let i = 0; i < 6; i++) await w.tick();
    expect({
      statusAt70Seconds: prematurelyEnabled,
      mayRelyAt130Seconds: w.rule.mayRely(w.now()),
      cachedVersion: w.undeclared.viewState(mission.id)?.version,
    }).toEqual({ statusAt70Seconds: "paused", mayRelyAt130Seconds: false, cachedVersion: 1 });
  });

  it("does not attest liveness while an ordinary lifecycle event awaits delivery: a verification never overtakes a failed suspension delivery (review probe 2)", async () => {
    const w = await wire();
    const mission = approve(w.kernel);
    await w.emitter.drain();
    await w.tick();
    const sink = undeclaredSink(w.emitter);
    const deliver = sink.deliver;
    sink.deliver = async (set) => {
      if (kindOf(set) === "lifecycle") throw new Error("lifecycle delivery unavailable");
      return deliver(set);
    };
    w.kernel.transition(mission.id, "suspend");
    await w.emitter.drain();
    expect(w.emitter.pending()).toBeGreaterThan(0);
    expect(w.undeclared.viewState(mission.id)?.state).toBe("active");
    const count = w.undeclaredLog.filter((r) => r.kind === "verification").length;
    w.advance(10_000);
    await w.emitter.attestLiveness();
    expect(w.undeclaredLog.filter((r) => r.kind === "verification")).toHaveLength(count);
    // The declared stream, with nothing undelivered, keeps receiving liveness.
    expect(since(w.declaredLog, w.now()).map((r) => r.kind)).toEqual(["verification"]);

    // Once the suspension is delivered, liveness follows it.
    sink.deliver = deliver;
    w.advance(30_000);
    await w.emitter.drain();
    await w.emitter.attestLiveness();
    const from = T0 + HEARTBEAT_MS + 1;
    expect(trace(since(w.undeclaredLog, from))).toEqual(["v2", "verify"]);
    expect(w.undeclared.viewState(mission.id)?.state).toBe("suspended");
  });

  it("does not re-enable before a requested verification whose acknowledgement was lost has aged past the window", async () => {
    const w = await wire();
    const mission = approve(w.kernel);
    await w.emitter.drain();
    await w.tick(); // acknowledged at 10 s
    w.fault.after = (r) => {
      if (r.kind !== "verification") return undefined;
      w.fault.after = undefined;
      throw new Error("response lost after the receiver accepted the verification");
    };
    w.advance(HEARTBEAT_MS);
    const receivedAt = w.now();
    w.emitter.requestVerification(UNDECLARED_AUD, "state-lost-ack");
    await w.emitter.drain();
    expect(w.rule.lastLivenessAt).toBe(receivedAt);
    expect(w.emitter.streamStatus(UNDECLARED_AUD)).toMatchObject({
      last_liveness_at: new Date(T0 + HEARTBEAT_MS),
      liveness_resolved_at: new Date(receivedAt),
    });

    w.advance(1_000);
    containRead(w, mission.id, "evt-requested-lost-ack");
    await w.emitter.drain();
    expect(w.emitter.streamStatus(UNDECLARED_AUD).reenable_after).toEqual(
      new Date(receivedAt + MAX_STALE_MS),
    );

    // Past the window from the last acknowledged verification, the consumer
    // that received the requested one may still rely: the stream stays paused.
    w.advance(T0 + HEARTBEAT_MS + MAX_STALE_MS + 1 - w.now());
    await w.emitter.drain();
    expect(w.rule.mayRely(w.now())).toBe(true);
    expect(w.emitter.streamStatus(UNDECLARED_AUD).status).toBe("paused");

    w.advance(receivedAt + MAX_STALE_MS + 1 - w.now());
    expect(w.rule.mayRely(w.now())).toBe(false);
    await w.emitter.drain();
    // Re-enabled; the requested verification is redelivered after the
    // enabled notice, byte for byte.
    const after = since(w.undeclaredLog, receivedAt);
    expect(trace(after)).toEqual(["verify", "paused", "enabled", "verify"]);
    expect(after[3]?.set).toBe(after[0]?.set);
    expect(w.rule.mayRely(w.now())).toBe(false);
  });

  it("keeps the stream paused past the window while a verification hand-off is in flight, then runs the window from when it ends, failed", async () => {
    const w = await wire();
    const mission = approve(w.kernel);
    await w.emitter.drain();
    await w.tick(); // acknowledged at 10 s
    const received = deferred();
    const outcome = deferred();
    w.fault.after = (r) => {
      if (r.kind !== "verification") return undefined;
      w.fault.after = undefined;
      received.resolve();
      return outcome.promise;
    };
    w.advance(HEARTBEAT_MS);
    const attested = w.emitter.attestLiveness();
    await received.promise;
    const receivedAt = w.now();
    expect(w.emitter.streamStatus(UNDECLARED_AUD).liveness_unresolved).toBe(1);

    w.advance(1_000);
    containRead(w, mission.id, "evt-in-flight");
    await w.emitter.drain();
    expect(w.emitter.streamStatus(UNDECLARED_AUD).reenable_after).toEqual(
      new Date(T0 + HEARTBEAT_MS + MAX_STALE_MS),
    );

    // Past that instant the attempt is still unresolved: the stream stays paused.
    w.advance(T0 + HEARTBEAT_MS + MAX_STALE_MS + 5_000 - w.now());
    await w.emitter.drain();
    expect(w.emitter.streamStatus(UNDECLARED_AUD)).toMatchObject({
      status: "paused",
      liveness_unresolved: 1,
    });
    expect(trace(since(w.undeclaredLog, receivedAt))).toEqual(["verify", "paused"]);

    // The transport reports a failure at 90 s: the attempt ends then.
    w.advance(15_000);
    const endedAt = w.now();
    outcome.reject(new Error("connection reset after the receiver processed the event"));
    await attested;
    expect(w.emitter.streamStatus(UNDECLARED_AUD)).toMatchObject({
      status: "paused",
      liveness_unresolved: 0,
      last_liveness_at: new Date(T0 + HEARTBEAT_MS),
      liveness_resolved_at: new Date(endedAt),
      reenable_after: new Date(endedAt + MAX_STALE_MS),
    });
    await w.emitter.drain();
    w.advance(endedAt + MAX_STALE_MS - w.now());
    await w.emitter.drain();
    expect(w.emitter.streamStatus(UNDECLARED_AUD).status).toBe("paused");
    w.advance(1);
    await w.emitter.drain();
    expect(trace(since(w.undeclaredLog, receivedAt))).toEqual(["verify", "paused", "enabled"]);
    expect(w.rule.mayRely(w.now())).toBe(false);
  });

  it("ends a verification attempt left unresolved by an earlier process at the reopening instant, and keeps the stream paused until the window from then has passed", async () => {
    const dir = mkdtempSync(join(tmpdir(), "signals-stream-attempt-"));
    tmpDirs.push(dir);
    const w = await wire({ file: join(dir, "outbox.db") });
    const mission = approve(w.kernel);
    await w.emitter.drain();
    await w.tick(); // acknowledged at 10 s
    const received = deferred();
    w.fault.after = (r) => {
      if (r.kind !== "verification") return undefined;
      w.fault.after = undefined;
      received.resolve();
      // The process stops before the acknowledgement comes back.
      return new Promise(() => {});
    };
    w.advance(HEARTBEAT_MS);
    void w.emitter.attestLiveness();
    await received.promise;
    const receivedAt = w.now();
    expect(w.rule.lastLivenessAt).toBe(receivedAt);

    w.advance(1_000);
    containRead(w, mission.id, "evt-unresolved-restart");
    await w.emitter.drain();
    expect(w.emitter.streamStatus(UNDECLARED_AUD)).toMatchObject({
      status: "paused",
      liveness_unresolved: 1,
      reenable_after: new Date(T0 + HEARTBEAT_MS + MAX_STALE_MS),
    });

    // Restart past that instant, with the attempt still unresolved.
    w.advance(T0 + HEARTBEAT_MS + MAX_STALE_MS + 10_000 - w.now());
    const reopenedAt = w.now();
    const reopened = w.reopen();
    expect(reopened.streamStatus(UNDECLARED_AUD)).toMatchObject({
      status: "paused",
      liveness_unresolved: 0,
      liveness_resolved_at: new Date(reopenedAt),
      reenable_after: new Date(reopenedAt + MAX_STALE_MS),
    });
    await reopened.drain();
    await reopened.attestLiveness();
    w.advance(reopenedAt + MAX_STALE_MS - w.now());
    await reopened.drain();
    expect(reopened.streamStatus(UNDECLARED_AUD).status).toBe("paused");
    expect(trace(since(w.undeclaredLog, receivedAt))).toEqual(["verify", "paused"]);
    w.advance(1);
    await reopened.drain();
    expect(trace(since(w.undeclaredLog, receivedAt))).toEqual(["verify", "paused", "enabled"]);
    expect(w.rule.mayRely(w.now())).toBe(false);
    reopened.close();
  });

  it("holds a requested verification behind a lifecycle event whose delivery failed, and sends it only after that event is acknowledged", async () => {
    const w = await wire();
    const mission = approve(w.kernel);
    await w.emitter.drain();
    await w.tick();
    const from = w.now() + 1;
    w.fault.before = (r) => {
      if (r.kind === "lifecycle") throw new Error("lifecycle delivery unavailable");
      return undefined;
    };
    w.advance(1);
    w.kernel.transition(mission.id, "suspend");
    await w.emitter.drain();
    w.emitter.requestVerification(UNDECLARED_AUD, "state-behind-suspend");
    await w.emitter.drain();
    w.advance(5_000);
    await w.emitter.drain();
    expect(w.emitter.pending()).toBe(1);
    expect(trace(since(w.undeclaredLog, from))).toEqual([]);
    expect(w.undeclared.viewState(mission.id)?.state).toBe("active");

    w.fault.before = undefined;
    w.advance(30_000);
    await w.emitter.drain();
    const after = since(w.undeclaredLog, from);
    expect(trace(after)).toEqual(["v2", "verify"]);
    expect(eventBody(after[1] as Received)).toEqual({ state: "state-behind-suspend" });
    expect(w.undeclared.viewState(mission.id)?.state).toBe("suspended");
  });

  it("on re-enabling sends Stream Updated enabled, then the held events, and liveness only once every held event is acknowledged", async () => {
    const w = await wire();
    const mission = approve(w.kernel);
    await w.emitter.drain();
    await w.tick();
    const lastLiveness = w.now();
    w.advance(1_000);
    const withheldAt = w.now();
    containRead(w, mission.id, "evt-resume-order"); // version 2: withheld
    w.kernel.transition(mission.id, "suspend"); // version 3: held
    w.kernel.transition(mission.id, "resume"); // version 4: held
    w.emitter.requestVerification(UNDECLARED_AUD, "state-resume-order");
    await w.emitter.drain();
    expect(trace(since(w.undeclaredLog, withheldAt))).toEqual(["paused"]);

    // The last held event's first delivery after re-enabling fails.
    let failures = 1;
    w.fault.before = (r) => {
      if (r.kind === "lifecycle" && eventBody(r).version === 4 && failures-- > 0)
        throw new Error("delivery of version 4 failed");
      return undefined;
    };
    w.advance(lastLiveness + MAX_STALE_MS + 1 - w.now());
    await w.emitter.drain();
    await w.emitter.attestLiveness();
    expect(trace(since(w.undeclaredLog, withheldAt))).toEqual(["paused", "enabled", "v3"]);

    // Once version 4 is acknowledged, the requested verification follows it,
    // and attested liveness after that.
    w.advance(1_000);
    await w.emitter.drain();
    expect(trace(since(w.undeclaredLog, withheldAt))).toEqual([
      "paused",
      "enabled",
      "v3",
      "v4",
      "verify",
    ]);
    await w.emitter.attestLiveness();
    expect(trace(since(w.undeclaredLog, withheldAt))).toEqual([
      "paused",
      "enabled",
      "v3",
      "v4",
      "verify",
      "verify",
    ]);
  });

  it("never re-enables a paused stream automatically when no heartbeat interval is configured; once one is, the window runs from the reopening instant", async () => {
    const dir = mkdtempSync(join(tmpdir(), "signals-stream-interval-"));
    tmpDirs.push(dir);
    const w = await wire({ file: join(dir, "outbox.db") }, { heartbeatIntervalSeconds: null });
    const mission = approve(w.kernel);
    await w.emitter.drain();
    await w.tick();
    w.advance(1_000);
    containRead(w, mission.id, "evt-no-interval");
    w.kernel.transition(mission.id, "suspend"); // held
    await w.emitter.drain();
    const status = w.emitter.streamStatus(UNDECLARED_AUD);
    expect(status.status).toBe("paused");
    expect(status.reenable_after).toBeUndefined();

    // A day of dispatcher passes and liveness attestations later: still paused.
    for (let hour = 0; hour < 24; hour++) {
      w.advance(3_600_000);
      await w.emitter.attestLiveness();
      await w.emitter.drain();
    }
    expect(w.emitter.streamStatus(UNDECLARED_AUD).status).toBe("paused");
    expect(trace(w.undeclaredLog)).toEqual(["v1", "verify", "paused"]);
    expect(w.emitter.pending()).toBe(1);

    // Restarted with the agreed interval configured: the window runs from now.
    const reopenedAt = w.now();
    const reopened = w.reopen(HEARTBEAT_MS / 1000);
    expect(reopened.streamStatus(UNDECLARED_AUD).reenable_after).toEqual(
      new Date(reopenedAt + MAX_STALE_MS),
    );
    w.advance(MAX_STALE_MS);
    await reopened.drain();
    expect(trace(w.undeclaredLog)).toEqual(["v1", "verify", "paused"]);
    w.advance(1);
    await reopened.drain();
    expect(trace(w.undeclaredLog)).toEqual(["v1", "verify", "paused", "enabled", "v3"]);
    reopened.close();
  });

  it("adds the clock tolerance it allows its consumers to the window: a consumer whose clock runs behind by that tolerance has ended its reliance before the stream re-enables", async () => {
    const TOLERANCE_SECONDS = 5;
    const toleranceMs = TOLERANCE_SECONDS * 1000;
    const w = await wire(undefined, { clockToleranceSeconds: TOLERANCE_SECONDS });
    const mission = approve(w.kernel);
    await w.emitter.drain();
    await w.tick();
    const lastLiveness = w.now();
    w.advance(1_000);
    containRead(w, mission.id, "evt-tolerance");
    await w.emitter.drain();
    expect(w.emitter.streamStatus(UNDECLARED_AUD).reenable_after).toEqual(
      new Date(lastLiveness + MAX_STALE_MS + toleranceMs),
    );
    // A consumer that measures from the event against a clock running behind
    // the issuer's by the tolerance.
    const slow = new StalenessRule(MAX_STALE_MS, HEARTBEAT_MS);
    for (const r of w.undeclaredLog) slow.receive(r);
    const slowNow = () => w.now() - toleranceMs;

    w.advance(lastLiveness + MAX_STALE_MS + 1 - w.now());
    await w.emitter.drain();
    expect(w.rule.mayRely(w.now())).toBe(false);
    expect(slow.mayRely(slowNow())).toBe(true);
    expect(w.emitter.streamStatus(UNDECLARED_AUD).status).toBe("paused");

    w.advance(lastLiveness + MAX_STALE_MS + toleranceMs - w.now());
    await w.emitter.drain();
    expect(slow.mayRely(slowNow())).toBe(true);
    expect(w.emitter.streamStatus(UNDECLARED_AUD).status).toBe("paused");

    w.advance(1);
    expect(slow.mayRely(slowNow())).toBe(false);
    await w.emitter.drain();
    expect(trace(w.undeclaredLog)).toEqual(["v1", "verify", "paused", "enabled"]);
  });

  it("keeps reliance ended after the stream re-enables: neither Stream Updated enabled nor resumed liveness restores it, only re-established state does", async () => {
    const w = await wire();
    const mission = approve(w.kernel);
    await w.emitter.drain();
    await w.tick();
    const lastLiveness = w.now();
    w.advance(1_000);
    containRead(w, mission.id, "evt-latch");
    await w.emitter.drain();
    w.advance(lastLiveness + MAX_STALE_MS + 1 - w.now());
    expect(w.rule.mayRely(w.now())).toBe(false);
    await w.emitter.drain();
    await w.tick();
    const resumed = since(w.undeclaredLog, lastLiveness + 1);
    expect(trace(resumed)).toEqual(["paused", "enabled", "verify"]);
    // The spec-rule model: still stale after the enabled notice and liveness.
    expect(w.rule.mayRely(w.now())).toBe(false);

    // The reference receiver: no lease past its bound, and neither the
    // Stream Updated event nor the verification event restores one.
    const at = () => new Date(w.now()).toISOString();
    expect(w.undeclared.lease(mission.id, at())).toBeUndefined();
    for (const r of resumed.filter((e) => e.kind !== "lifecycle"))
      expect(await w.undeclared.verifyAndApply(r.set)).toMatchObject({ status: "refused" });
    expect(w.undeclared.lease(mission.id, at())).toBeUndefined();

    // Only re-established current state ends the staleness.
    w.rule.reestablish(w.now());
    expect(w.rule.mayRely(w.now())).toBe(true);
  });

  it("holds a verification behind an earlier verification still being retried or in flight", async () => {
    const w = await wire();
    approve(w.kernel);
    await w.emitter.drain();
    await w.tick();
    const from = w.now() + 1;

    // A requested verification whose delivery fails and is retried.
    w.fault.before = (r) => {
      if (r.kind === "verification" && eventBody(r).state === "state-retried")
        throw new Error("verification delivery failed");
      return undefined;
    };
    w.advance(1);
    w.emitter.requestVerification(UNDECLARED_AUD, "state-retried");
    w.emitter.requestVerification(UNDECLARED_AUD, "state-later");
    await w.emitter.drain();
    w.advance(5_000);
    await w.emitter.attestLiveness();
    await w.emitter.drain();
    expect(trace(since(w.undeclaredLog, from))).toEqual([]);
    expect(since(w.declaredLog, w.now()).map((r) => r.kind)).toEqual(["verification"]);

    // Once it is delivered, the later ones follow in order.
    w.fault.before = undefined;
    w.advance(30_000);
    await w.emitter.drain();
    await w.emitter.attestLiveness();
    const delivered = since(w.undeclaredLog, from);
    expect(delivered.map((r) => eventBody(r).state)).toEqual([
      "state-retried",
      "state-later",
      undefined,
    ]);

    // A hand-off in flight holds the next attestation on that stream.
    const received = deferred();
    const outcome = deferred();
    w.fault.after = (r) => {
      if (r.kind !== "verification") return undefined;
      w.fault.after = undefined;
      received.resolve();
      return outcome.promise;
    };
    w.advance(HEARTBEAT_MS);
    const first = w.emitter.attestLiveness();
    await received.promise;
    await w.emitter.attestLiveness();
    expect(since(w.undeclaredLog, w.now())).toHaveLength(1);
    outcome.resolve();
    await first;
    await w.emitter.attestLiveness();
    expect(since(w.undeclaredLog, w.now())).toHaveLength(2);
  });
});
