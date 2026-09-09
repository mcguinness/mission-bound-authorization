/**
 * @spec signals#delivery — durable per-consumer delivery (#641). The emitter
 * journals one job per (event, consumer audience) synchronously in the commit
 * hook; a failed hand-off stays pending under a bounded backoff and every
 * redelivery is the identical SET (same `jti`, same bytes). The file-backed
 * store proves the ledger survives a process restart (a fresh emitter with no
 * in-memory state delivers what its predecessor journaled); the lease keeps
 * concurrent dispatchers from double-delivering while lapsing on a crashed
 * claim holder.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type LifecycleCommit,
  MissionKernel,
  validateMissionIntent,
} from "@mission/authorization-server";
import { testAuthoritySourceCatalog } from "@mission/authorization-server/test-support";
import type { Database } from "@mission/store";
import { decodeJwt, exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterAll, describe, expect, it, vi } from "vitest";
import {
  LIFECYCLE_CHANGE_EVENT_URI,
  MissionSignalEmitter,
  MissionSignalReceiver,
  SET_TYP,
} from "../src/index.js";

const ISS = "https://as.test";
const AUD = "https://erp.consumer.test";

const T0 = Date.parse("2026-08-02T12:00:00Z");

function commitFixture(over: Partial<LifecycleCommit> = {}): LifecycleCommit {
  return {
    id: "msn_durable_0000000000000001",
    issuer: ISS,
    prior_state: "active",
    state: "revoked",
    version: 2,
    committed_at: "2026-08-02T12:00:00Z",
    expires_at: "2027-01-01T00:00:00Z",
    ...over,
  };
}

async function statusKeyPair() {
  const keys = await generateKeyPair("ES256", { extractable: true });
  const pub = {
    ...(await exportJWK(keys.publicKey)),
    kid: "as-status",
    alg: "ES256",
    use: "sig",
  };
  return { privateKey: keys.privateKey, jwks: { keys: [pub] } };
}

type ReceiverJwks = ConstructorParameters<typeof MissionSignalReceiver>[0]["jwks"];

function makeReceiver(jwks: ReceiverJwks) {
  return new MissionSignalReceiver({ jwks, issuer: ISS, audience: AUD });
}

const tmpDirs: string[] = [];
afterAll(() => {
  for (const d of tmpDirs) rmSync(d, { recursive: true, force: true });
});

describe("durable per-consumer delivery (@spec signals#delivery, #641)", () => {
  it("equal Mission ids and event ids from distinct issuers keep separate delivery jobs and state", async () => {
    const { privateKey, jwks } = await statusKeyPair();
    const secondIssuer = "https://second-issuer.test";
    const first = makeReceiver(jwks);
    const second = new MissionSignalReceiver({ jwks, issuer: secondIssuer, audience: AUD });
    const emitter = new MissionSignalEmitter({
      key: privateKey,
      kid: "as-status",
      consumers: [{ audience: AUD }],
    });
    const delivered: string[] = [];
    emitter.onDeliver(AUD, async (set) => {
      delivered.push(set);
      await (decodeJwt(set).iss === ISS ? first : second).verifyAndApply(set);
    });
    try {
      const a = commitFixture({ state: "active", version: 1, event_id: "same-event" });
      const b = { ...a, issuer: secondIssuer, state: "revoked" as const };
      emitter.onCommit(a);
      emitter.onCommit(b);
      await emitter.drain();
      expect(delivered).toHaveLength(2);
      expect(delivered.map((set) => decodeJwt(set).jti)).toEqual(["same-event", "same-event"]);
      expect(first.viewState(a.id)?.state).toBe("active");
      expect(second.viewState(a.id)?.state).toBe("revoked");
      emitter.onCommit(a);
      emitter.onCommit(b);
      await emitter.drain();
      expect(delivered).toHaveLength(2);
    } finally {
      emitter.close();
    }
  });
  it("refuses a SET whose embedded mission issuer is not the receiver's own", async () => {
    // @spec control-plane#isolation — the SET `iss` and the event's
    // `mission.issuer` are one identity. A signer trusted for this issuer
    // cannot move another issuer's Mission through this receiver's state.
    const { privateKey, jwks } = await statusKeyPair();
    const receiver = makeReceiver(jwks);
    const missionId = "msn_durable_0000000000000001";
    const set = await new SignJWT({
      sub_id: { format: "opaque", id: missionId },
      events: {
        [LIFECYCLE_CHANGE_EVENT_URI]: {
          mission: { id: missionId, issuer: "https://second-issuer.test" },
          state: "revoked",
          prior_state: "active",
          version: 2,
          committed_at: "2026-08-02T12:00:00Z",
          expires_at: "2027-01-01T00:00:00Z",
        },
      },
    })
      .setProtectedHeader({ alg: "ES256", kid: "as-status", typ: SET_TYP })
      .setIssuer(ISS)
      .setAudience(AUD)
      .setIssuedAt()
      .setJti("cross-issuer-event")
      .sign(privateKey);
    expect(await receiver.verifyAndApply(set)).toEqual({ status: "refused", reason: "issuer" });
    expect(receiver.viewState(missionId)).toBeUndefined();
    expect(receiver.hasGap(missionId)).toBe(false);
  });
  it("journals a failed hand-off and redelivers the identical SET (same jti, same bytes)", async () => {
    const { privateKey, jwks } = await statusKeyPair();
    let clock = T0;
    const emitter = new MissionSignalEmitter({
      key: privateKey,
      kid: "as-status",
      consumers: [{ audience: AUD }],
      now: () => new Date(clock),
      retry: { baseMs: 100, capMs: 400 },
    });
    const receiver = makeReceiver(jwks);
    const seen: string[] = [];
    let failOnce = true;
    emitter.onDeliver(AUD, async (set) => {
      seen.push(set);
      if (failOnce) {
        failOnce = false;
        throw new Error("transport down");
      }
      await receiver.verifyAndApply(set);
    });

    emitter.onCommit(commitFixture());
    await emitter.drain();
    // first attempt failed: not swallowed, still pending
    expect(seen).toHaveLength(1);
    expect(emitter.pending()).toBe(1);
    expect(receiver.viewState(commitFixture().id)).toBeUndefined();

    clock += 100; // past the first backoff
    await emitter.drain();
    expect(seen).toHaveLength(2);
    expect(emitter.pending()).toBe(0);
    // byte-identical redelivery, same jti
    expect(seen[1]).toBe(seen[0]);
    expect(decodeJwt(seen[1] ?? "").jti).toBe(decodeJwt(seen[0] ?? "").jti);
    expect(receiver.viewState(commitFixture().id)?.state).toBe("revoked");
    emitter.close();
  });

  it("survives a restart: a fresh emitter over the same file store delivers what its predecessor journaled", async () => {
    const dir = mkdtempSync(join(tmpdir(), "signal-outbox-"));
    tmpDirs.push(dir);
    const file = join(dir, "outbox.db");
    const { privateKey, jwks } = await statusKeyPair();
    let clock = T0;

    const before = new MissionSignalEmitter({
      key: privateKey,
      kid: "as-status",
      consumers: [{ audience: AUD }],
      store: { file },
      now: () => new Date(clock),
      retry: { baseMs: 100, capMs: 400 },
    });
    const attempted: string[] = [];
    before.onDeliver(AUD, (set) => {
      attempted.push(set);
      throw new Error("crash window: transport never came up");
    });
    before.onCommit(commitFixture());
    await before.drain();
    expect(attempted).toHaveLength(1);
    expect(before.pending()).toBe(1);
    // Simulate the pre-#250 storage-key format. Reopening must qualify the
    // key without re-signing the already persisted event or resetting retry.
    const legacyDb = (before as unknown as { db: Database }).db;
    const legacy = legacyDb.prepare("SELECT commit_json FROM signal_outbox").get() as {
      commit_json: string;
    };
    const identity = JSON.parse(legacy.commit_json) as LifecycleCommit;
    legacyDb.prepare("UPDATE signal_outbox SET event_id = ?").run(identity.event_id);
    before.close(); // the process dies with the job pending

    const after = new MissionSignalEmitter({
      key: privateKey,
      kid: "as-status",
      consumers: [{ audience: AUD }],
      store: { file },
      now: () => new Date(clock),
      retry: { baseMs: 100, capMs: 400 },
    });
    const receiver = makeReceiver(jwks);
    const redelivered: string[] = [];
    expect(
      (after as unknown as { db: Database }).db.prepare("SELECT event_id FROM signal_outbox").get(),
    ).toEqual({ event_id: JSON.stringify([identity.issuer, identity.event_id]) });
    after.onDeliver(AUD, async (set) => {
      redelivered.push(set);
      await receiver.verifyAndApply(set);
    });
    clock += 400; // past any backoff the failed attempt scheduled
    await after.drain();
    expect(after.pending()).toBe(0);
    // the persisted bytes, not a re-signed sibling: identical SET, same jti
    expect(redelivered).toEqual([attempted[0]]);
    expect(receiver.viewState(commitFixture().id)?.state).toBe("revoked");
    after.close();
  });

  it("re-enqueues nothing on a kernel-outbox replay of the same commit (UNIQUE event identity)", async () => {
    const { privateKey, jwks } = await statusKeyPair();
    const emitter = new MissionSignalEmitter({
      key: privateKey,
      kid: "as-status",
      consumers: [{ audience: AUD }],
    });
    const receiver = makeReceiver(jwks);
    const seen: string[] = [];
    emitter.onDeliver(AUD, async (set) => {
      seen.push(set);
      await receiver.verifyAndApply(set);
    });

    const replayed = commitFixture({ event_id: "set_replayed_stable_identity" });
    emitter.onCommit(replayed);
    emitter.onCommit(replayed); // the kernel finalization outbox replays the commit
    await emitter.drain();
    emitter.onCommit(replayed); // and once more after delivery completed
    await emitter.drain();

    expect(seen).toHaveLength(1);
    expect(decodeJwt(seen[0] ?? "").jti).toBe("set_replayed_stable_identity");
    expect(emitter.pending()).toBe(0);
    emitter.close();
  });

  it("bounds the retry schedule at the cap (the draft's transmitter DoS rule)", async () => {
    const { privateKey } = await statusKeyPair();
    let clock = T0;
    const emitter = new MissionSignalEmitter({
      key: privateKey,
      kid: "as-status",
      consumers: [{ audience: AUD }],
      now: () => new Date(clock),
      retry: { baseMs: 100, capMs: 400 },
    });
    let calls = 0;
    emitter.onDeliver(AUD, () => {
      calls += 1;
      throw new Error("receiver unavailable");
    });

    emitter.onCommit(commitFixture());
    await emitter.drain(); // attempt 1 at t0 -> next at +100
    expect(calls).toBe(1);
    clock += 100;
    await emitter.drain(); // attempt 2 -> +200
    clock += 200;
    await emitter.drain(); // attempt 3 -> +400 (cap)
    clock += 400;
    await emitter.drain(); // attempt 4 -> +400 (held at cap, not 800)
    expect(calls).toBe(4);
    clock += 399; // just inside the capped interval: not runnable yet
    await emitter.drain();
    expect(calls).toBe(4);
    clock += 1; // the cap boundary: runnable again
    await emitter.drain();
    expect(calls).toBe(5);
    expect(emitter.pending()).toBe(1); // never dropped, only backed off
    emitter.close();
  });

  it("keeps a job pending for an audience with no wired sink, and delivers on late registration", async () => {
    const { privateKey, jwks } = await statusKeyPair();
    let clock = T0;
    const emitter = new MissionSignalEmitter({
      key: privateKey,
      kid: "as-status",
      consumers: [{ audience: AUD }],
      now: () => new Date(clock),
      retry: { baseMs: 100, capMs: 400 },
    });

    emitter.onCommit(commitFixture());
    await emitter.drain();
    expect(emitter.pending()).toBe(1); // zero sinks is not a vacuous success

    const receiver = makeReceiver(jwks);
    emitter.register(receiver);
    clock += 100;
    await emitter.drain();
    expect(emitter.pending()).toBe(0);
    expect(receiver.viewState(commitFixture().id)?.state).toBe("revoked");
    emitter.close();
  });

  it("respects a live claim and recovers the job when the lease lapses", async () => {
    const { privateKey, jwks } = await statusKeyPair();
    let clock = T0;
    const emitter = new MissionSignalEmitter({
      key: privateKey,
      kid: "as-status",
      consumers: [{ audience: AUD }],
      now: () => new Date(clock),
      leaseMs: 1000,
    });
    // Journal with no sink wired: the commit-path dispatch fails, the job
    // stays pending, and nothing races the failpoint below.
    emitter.onCommit(commitFixture());
    await emitter.drain();

    const receiver = makeReceiver(jwks);
    const seen: string[] = [];
    emitter.onDeliver(AUD, async (set) => {
      seen.push(set);
      await receiver.verifyAndApply(set);
    });

    // Failpoint (the expansion-outbox test pattern): another dispatcher holds
    // the claim, as after a crash mid-delivery that never reached the catch.
    const db = (emitter as unknown as { db: Database }).db;
    db.prepare(
      "UPDATE signal_outbox SET claimed_until = ?, next_attempt_at = 0 WHERE done = 0",
    ).run(clock + 1000);

    await emitter.drain();
    expect(seen).toHaveLength(0); // live claim respected
    expect(emitter.pending()).toBe(1);

    clock += 1000; // lease lapses: the crashed holder's claim expires
    await emitter.drain();
    expect(seen).toHaveLength(1);
    expect(emitter.pending()).toBe(0);
    emitter.close();
  });

  it("redelivers autonomously via the recurring dispatcher, without a drain call", async () => {
    const { privateKey, jwks } = await statusKeyPair();
    const emitter = new MissionSignalEmitter({
      key: privateKey,
      kid: "as-status",
      consumers: [{ audience: AUD }],
      retry: { baseMs: 1, capMs: 5 },
    });
    const receiver = makeReceiver(jwks);
    let failOnce = true;
    emitter.onDeliver(AUD, async (set) => {
      if (failOnce) {
        failOnce = false;
        throw new Error("transport down");
      }
      await receiver.verifyAndApply(set);
    });

    emitter.startDispatcher(5);
    emitter.onCommit(commitFixture());
    await vi.waitFor(() => {
      expect(receiver.viewState(commitFixture().id)?.state).toBe("revoked");
    });
    expect(emitter.pending()).toBe(0);
    emitter.close();
  });
  it("carries ONE jti across a kernel redelivery of an ordinary lifecycle commit", async () => {
    // @spec control-plane#fanout — the kernel assigns the event identity inside
    // the state write's transaction for EVERY commit kind, not only the
    // expansion finalization outbox. Without it, a redelivered ordinary commit
    // reached this emitter with no identity, got a fresh one, and became a NEW
    // SET with a new `jti`, defeating both the same-event redelivery rule and
    // the UNIQUE(event_id, audience) no-op.
    const { privateKey, jwks } = await statusKeyPair();
    const emitter = new MissionSignalEmitter({
      key: privateKey,
      kid: "as-status",
      consumers: [{ audience: AUD }],
    });
    const receiver = makeReceiver(jwks);
    const seen: string[] = [];
    emitter.onDeliver(AUD, async (set) => {
      seen.push(set);
      await receiver.verifyAndApply(set);
    });

    const resource = "https://payments.test/mcp";
    const policy = {
      policy_version: "redelivery-test-v1",
      ceiling: [{ type: "mission_resource_access", resource, actions: ["payments:invoice.read"] }],
    };
    const drop = { publish: true };
    const kernel = new MissionKernel({
      issuer: ISS,
      policy: policy as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(policy.ceiling, ["ap-agent"], ["bob"]),
      statusKey: privateKey,
      statusKid: "as-status",
      now: () => new Date(T0),
      onLifecycleCommit: (commit) => {
        if (drop.publish) throw new Error("failpoint: publication lost");
        emitter.onCommit(commit);
      },
    });
    // Process loss between the state commit and its publication.
    expect(() =>
      kernel.approve({
        intent: validateMissionIntent(
          JSON.stringify({
            goal: "Read approved invoices",
            target_resources: [resource],
            expires_at: "2027-01-01T00:00:00Z",
          }),
        ),
        subject: { iss: ISS, sub: "alice" },
        approver: { iss: ISS, sub: "bob" },
        clientId: "ap-agent",
        approvalEventId: "apev-redelivery-1",
      }),
    ).toThrow("publication lost");
    const persistedEventId = (
      kernel.db.prepare("SELECT event_id FROM lifecycle_events WHERE published = 0").get() as {
        event_id: string;
      }
    ).event_id;
    const missionId = (kernel.db.prepare("SELECT id FROM missions").get() as { id: string }).id;

    drop.publish = false;
    kernel.publishPendingCommits();
    await emitter.drain();
    // Force a second redelivery of the same committed event.
    kernel.db.prepare("UPDATE lifecycle_events SET published = 0").run();
    kernel.publishPendingCommits();
    await emitter.drain();

    expect(seen).toHaveLength(1);
    expect(decodeJwt(seen[0] ?? "").jti).toBe(persistedEventId);
    expect(receiver.viewState(missionId)?.state).toBe("active");
    expect(emitter.pending()).toBe(0);
    emitter.close();
    kernel.db.close();
  });
});
