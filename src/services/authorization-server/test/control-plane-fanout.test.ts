/**
 * @spec control-plane#fanout, control-plane#tombstones, control-plane#rollback
 *
 * The durable lifecycle fan-out and the terminal tombstones, exercised at the
 * boundaries that actually exist here: one process, in-memory by default, with
 * the file-backed single-writer store as the declared opt-in that makes restart
 * recovery observable. Multi-process claiming and fencing are #641's and are
 * not exercised or claimed.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { type Database, openStore, withTransaction } from "@mission/store";
import { generateKeyPair } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  buildAuthorizationServer,
  composeTombstoneRetentionSeconds,
  DEFAULT_AUDIT_RETENTION_S,
  DEFAULT_CLOCK_SKEW_S,
  type DurableCommitSubscriber,
  type LifecycleCommit,
  LifecycleOutbox,
  MissionIdReuseError,
  MissionKernel,
  type PersistedLifecycleCommit,
  type TombstoneRetentionInputs,
  validateMissionIntent,
} from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISSUER = "https://issuer-fanout.test";
const EXPIRES_AT = "2027-01-01T00:00:00Z";
const T0 = "2026-09-01T00:00:00Z";

let statusKey: CryptoKey;
beforeAll(async () => {
  statusKey = (await generateKeyPair("ES256")).privateKey;
});

const tempDirs: string[] = [];
function tempStoreFile(name: string): string {
  const dir = mkdtempSync(join(tmpdir(), "mission-fanout-"));
  tempDirs.push(dir);
  return join(dir, name);
}
afterAll(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

interface Harness {
  kernel: MissionKernel;
  commits: PersistedLifecycleCommit[];
  clock: { at: Date };
  fail: { publish: boolean };
  approve: (over?: { id?: string; approvalEventId?: string }) => ReturnType<MissionKernel["approve"]>;
}

function setup(
  opts: {
    issuer?: string;
    file?: string;
    horizons?: Partial<TombstoneRetentionInputs>;
    retry?: { baseMs?: number; capMs?: number; maxAttempts?: number };
    dischargeEventRetentionSeconds?: number;
  } = {},
): Harness {
  const issuer = opts.issuer ?? ISSUER;
  const commits: PersistedLifecycleCommit[] = [];
  const clock = { at: new Date(T0) };
  const fail = { publish: false };
  const kernel = new MissionKernel({
    issuer,
    policy: DERIVATION_POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(
      DERIVATION_POLICY.ceiling,
      ["agent"],
      ["bob"],
    ),
    statusKey,
    statusKid: "status",
    now: () => clock.at,
    ...(opts.file ? { store: { file: opts.file } } : {}),
    ...(opts.horizons ? { tombstoneHorizons: opts.horizons } : {}),
    ...(opts.retry ? { outboxRetry: opts.retry } : {}),
    ...(opts.dischargeEventRetentionSeconds !== undefined
      ? { dischargeEventRetentionSeconds: opts.dischargeEventRetentionSeconds }
      : {}),
    onLifecycleCommit: (commit) => {
      if (fail.publish) throw new Error("failpoint: publication lost");
      commits.push(commit as PersistedLifecycleCommit);
    },
  });
  const approve = (over: { id?: string; approvalEventId?: string } = {}) =>
    kernel.approve({
      intent: validateMissionIntent(
        JSON.stringify({
          goal: "Read an invoice",
          target_resources: [DERIVATION_POLICY.ceiling[0].resource],
          expires_at: EXPIRES_AT,
          requested_derivation_limit: 1,
        }),
      ),
      subject: { iss: issuer, sub: "alice" },
      approver: { iss: issuer, sub: "bob" },
      clientId: "agent",
      approvalEventId: over.approvalEventId ?? "approval",
    });
  return { kernel, commits, clock, fail, approve };
}

/**
 * A durable subscriber whose every delivery returns a promise this test
 * resolves or rejects by hand, so a delivery can be held open exactly as a slow
 * external call holds one open while another drain starts.
 */
function controlled(id = "external"): {
  calls: Array<{ resolve: () => void; reject: (e: Error) => void }>;
  subscriber: DurableCommitSubscriber<{ id: string }>;
} {
  const calls: Array<{ resolve: () => void; reject: (e: Error) => void }> = [];
  return {
    calls,
    subscriber: {
      id,
      capture: (commit) => ({ id: commit.id }),
      deliver: () =>
        new Promise<void>((resolve, reject) => {
          calls.push({ resolve: () => resolve(), reject: (e) => reject(e) });
        }),
    },
  };
}

/** The newest committed event's identity. */
function lastEventId(kernel: MissionKernel): string {
  return (
    kernel.db.prepare("SELECT event_id FROM lifecycle_events ORDER BY seq DESC LIMIT 1").get() as {
      event_id: string;
    }
  ).event_id;
}

/** Every stored column of the one delivery row, for a byte-for-byte compare. */
function rawDelivery(db: Database): Record<string, unknown> {
  return db.prepare("SELECT * FROM lifecycle_deliveries").get() as Record<string, unknown>;
}

describe("durable lifecycle fan-out", () => {
  it("assigns one event identity per commit, for every commit kind", () => {
    const { kernel, commits, approve } = setup();
    try {
      const record = approve();
      kernel.transition(record.id, "suspend");
      kernel.transition(record.id, "resume");
      kernel.contain(record.id, {
        event: {
          type: "vendor.compromise",
          source: "https://feed.test",
          observed_at: T0,
          event_id: "pe-1",
        },
        remove: [{ resource: DERIVATION_POLICY.ceiling[0].resource }],
      });
      kernel.transition(record.id, "revoke");
      // Activation, suspend, resume, contain, revoke: five commits, five
      // distinct identities, none of them minted downstream.
      expect(commits).toHaveLength(5);
      for (const commit of commits) expect(commit.event_id).toMatch(/^set_/);
      expect(new Set(commits.map((c) => c.event_id)).size).toBe(5);
      const stored = kernel.db
        .prepare("SELECT event_id FROM lifecycle_events ORDER BY seq")
        .all() as Array<{ event_id: string }>;
      expect(stored.map((r) => r.event_id)).toEqual(commits.map((c) => c.event_id));
    } finally {
      kernel.db.close();
    }
  });

  it("a rolled-back transaction leaves no event, no delivery row and no tombstone", () => {
    const { kernel, commits, approve } = setup();
    try {
      const record = approve();
      const before = kernel.db
        .prepare("SELECT COUNT(*) AS n FROM lifecycle_events")
        .get() as { n: number };
      const seen: string[] = [];
      kernel.registerDurableSubscriber<{ id: string }>({
        id: "external-effect",
        capture: (commit) => ({ id: commit.id }),
        deliver: (payload) => {
          seen.push(payload.id);
        },
      });
      expect(() =>
        withTransaction(kernel.db, () => {
          kernel.transition(record.id, "revoke");
          throw new Error("outer fault");
        }),
      ).toThrow("outer fault");
      expect(kernel.get(record.id)?.state).toBe("active");
      expect(
        (kernel.db.prepare("SELECT COUNT(*) AS n FROM lifecycle_events").get() as { n: number }).n,
      ).toBe(before.n);
      expect(
        (
          kernel.db.prepare("SELECT COUNT(*) AS n FROM lifecycle_deliveries").get() as {
            n: number;
          }
        ).n,
      ).toBe(0);
      expect(kernel.tombstones.find(ISSUER, record.id)).toBeUndefined();
      expect(commits.filter((c) => c.state === "revoked")).toHaveLength(0);
      expect(seen).toEqual([]);
    } finally {
      kernel.db.close();
    }
  });

  it("redelivers a commit lost before publication under its original identity and timestamp", () => {
    const { kernel, commits, approve, fail } = setup();
    try {
      const record = approve();
      commits.length = 0;
      fail.publish = true;
      // Publication throws AFTER the state transaction commits: the crash
      // window this table exists to close.
      expect(() => kernel.transition(record.id, "revoke")).toThrow("publication lost");
      expect(kernel.get(record.id)?.state).toBe("revoked");
      expect(commits).toHaveLength(0);
      expect(kernel.outbox.pendingEventCount()).toBe(1);
      const persisted = JSON.parse(
        (
          kernel.db.prepare("SELECT commit_json FROM lifecycle_events WHERE published = 0").get() as {
            commit_json: string;
          }
        ).commit_json,
      ) as PersistedLifecycleCommit;

      fail.publish = false;
      expect(kernel.publishPendingCommits()).toBe(1);
      expect(commits).toHaveLength(1);
      expect(commits[0]?.event_id).toBe(persisted.event_id);
      expect(commits[0]?.committed_at).toBe(persisted.committed_at);
      expect(commits[0]?.version).toBe(persisted.version);
      expect(Object.isFrozen(commits[0])).toBe(true);
      // Idempotent: a second replay publishes nothing new.
      expect(kernel.publishPendingCommits()).toBe(0);
      expect(commits).toHaveLength(1);
    } finally {
      kernel.db.close();
    }
  });

  it("keeps an unpublishable event pending on the recovery path instead of failing an unrelated drain", async () => {
    const { kernel, commits, approve, fail } = setup();
    try {
      const record = approve();
      commits.length = 0;
      fail.publish = true;
      expect(() => kernel.transition(record.id, "suspend")).toThrow("publication lost");
      // The committing caller learned that publication did not complete, and the
      // transition is committed with its event pending.
      expect(kernel.get(record.id)?.state).toBe("suspended");
      expect(kernel.outbox.pendingEventCount()).toBe(1);

      // The RECOVERY path is isolated: a still-failing subscriber records the
      // attempt and leaves the row pending rather than turning a request that
      // committed nothing into a failure.
      await expect(kernel.drainLifecycleOutbox()).resolves.toBeUndefined();
      expect(kernel.publishPendingCommits()).toBe(0);
      const pending = kernel.outbox.pendingPublications();
      expect(pending).toHaveLength(1);
      expect(pending[0]?.publish_attempts).toBe(2); // the two isolated recovery attempts
      expect(pending[0]?.last_publish_error).toBe("failpoint: publication lost");

      // Nothing was discarded: once the subscriber recovers, the same event
      // publishes under its own identity.
      fail.publish = false;
      expect(kernel.publishPendingCommits()).toBe(1);
      expect(commits.map((c) => c.event_id)).toEqual([pending[0]?.event_id]);
      expect(kernel.outbox.pendingEventCount()).toBe(0);
    } finally {
      kernel.db.close();
    }
  });

  it("roots the activating commit from the payload, so a redelivery after the record advanced still resolves", () => {
    const { kernel, commits, approve, fail } = setup();
    try {
      fail.publish = true;
      let record: { id: string } | undefined;
      expect(() => {
        record = approve();
      }).toThrow("publication lost");
      const missionId = (kernel.db.prepare("SELECT id FROM missions").get() as { id: string }).id;
      expect(record).toBeUndefined();
      // The record advances past the activating commit, and is then purged
      // entirely: a subscriber that re-read live state would get a newer
      // version, then nothing at all.
      fail.publish = false;
      kernel.publishPendingCommits();
      commits.length = 0;
      kernel.db.prepare("UPDATE lifecycle_events SET published = 0").run();
      kernel.transition(missionId, "revoke");
      kernel.db.prepare("DELETE FROM missions").run();
      commits.length = 0;

      kernel.publishPendingCommits();
      const activating = commits.find((c) => c.version === 1);
      expect(activating).toBeDefined();
      expect(activating?.state).toBe("active");
      expect(activating?.prior_state).toBeUndefined();
      // The creation facts a rooting subscriber needs ride the event, so the
      // subscriber never has to reach for a record that has moved or gone.
      expect(activating?.created_at).toBe(new Date(T0).toISOString());
      expect(activating?.client_id).toBe("agent");
      expect(kernel.get(missionId)).toBeUndefined();
    } finally {
      kernel.db.close();
    }
  });

  it("acknowledges durable subscribers independently: one accepts while another retries with the same payload", async () => {
    const { kernel, approve } = setup({ retry: { baseMs: 0, capMs: 0, maxAttempts: 4 } });
    try {
      const accepted: string[] = [];
      const attempts: string[] = [];
      kernel.registerDurableSubscriber<{ id: string }>({
        id: "accepts",
        capture: (commit) => ({ id: commit.id }),
        deliver: (payload) => {
          accepted.push(payload.id);
        },
      });
      let failuresLeft = 1;
      kernel.registerDurableSubscriber<{ id: string }>({
        id: "fails-once",
        capture: (commit) => ({ id: commit.id }),
        deliver: (payload) => {
          attempts.push(payload.id);
          if (failuresLeft-- > 0) throw new Error("downstream refused");
        },
      });
      const record = approve();
      const eventId = (
        kernel.db
          .prepare("SELECT event_id FROM lifecycle_events ORDER BY seq DESC LIMIT 1")
          .get() as { event_id: string }
      ).event_id;

      await kernel.drainLifecycleOutbox();
      expect(accepted).toEqual([record.id]);
      expect(attempts).toEqual([record.id]);
      let rows = kernel.outbox.deliveries(eventId);
      expect(rows.find((r) => r.subscriber === "accepts")?.disposition).toBe("accepted");
      const failing = rows.find((r) => r.subscriber === "fails-once");
      expect(failing?.disposition).toBe("pending");
      expect(failing?.attempts).toBe(1);
      expect(failing?.last_error).toBe("downstream refused");

      await kernel.drainLifecycleOutbox();
      // The accepted subscriber is not re-delivered; the failing one retries
      // with the identical payload and then accepts.
      expect(accepted).toEqual([record.id]);
      expect(attempts).toEqual([record.id, record.id]);
      rows = kernel.outbox.deliveries(eventId);
      expect(rows.find((r) => r.subscriber === "fails-once")?.disposition).toBe("accepted");
    } finally {
      kernel.db.close();
    }
  });

  it("abandons a delivery only after its bounded retry budget, keeping the row for audit", async () => {
    const { kernel, approve } = setup({ retry: { baseMs: 0, capMs: 0, maxAttempts: 2 } });
    try {
      kernel.registerDurableSubscriber<{ id: string }>({
        id: "always-fails",
        capture: (commit) => ({ id: commit.id }),
        deliver: () => {
          throw new Error("permanently unavailable");
        },
      });
      approve();
      const eventId = (
        kernel.db.prepare("SELECT event_id FROM lifecycle_events LIMIT 1").get() as {
          event_id: string;
        }
      ).event_id;
      await kernel.drainLifecycleOutbox();
      expect(kernel.outbox.deliveries(eventId)[0]?.disposition).toBe("pending");
      await kernel.drainLifecycleOutbox();
      const row = kernel.outbox.deliveries(eventId)[0];
      expect(row?.disposition).toBe("abandoned");
      expect(row?.attempts).toBe(2);
      expect(row?.last_error).toBe("permanently unavailable");
      expect(row?.disposed_at).toBeGreaterThan(0);
    } finally {
      kernel.db.close();
    }
  });

  it("marks a removed subscriber's pending delivery terminal without blocking or resurrecting it", async () => {
    const file = tempStoreFile("removed-subscriber.db");
    const first = setup({ file, retry: { baseMs: 0, capMs: 0, maxAttempts: 4 } });
    let eventId: string;
    try {
      first.kernel.registerDurableSubscriber<{ id: string }>({
        id: "departing",
        capture: (commit) => ({ id: commit.id }),
        deliver: () => {
          throw new Error("never accepted");
        },
      });
      first.kernel.registerDurableSubscriber<{ id: string }>({
        id: "staying",
        capture: (commit) => ({ id: commit.id }),
        deliver: () => {
          throw new Error("not yet");
        },
      });
      first.approve();
      eventId = (
        first.kernel.db.prepare("SELECT event_id FROM lifecycle_events LIMIT 1").get() as {
          event_id: string;
        }
      ).event_id;
      await first.kernel.drainLifecycleOutbox();
      expect(first.kernel.outbox.deliveries(eventId).map((r) => r.disposition)).toEqual([
        "pending",
        "pending",
      ]);
    } finally {
      first.kernel.db.close();
    }

    // A new process registers only the surviving subscriber.
    const second = setup({ file, retry: { baseMs: 0, capMs: 0, maxAttempts: 4 } });
    try {
      const delivered: string[] = [];
      second.kernel.registerDurableSubscriber<{ id: string }>({
        id: "staying",
        capture: (commit) => ({ id: commit.id }),
        deliver: (payload) => {
          delivered.push(payload.id);
        },
      });
      await second.kernel.recoverAtBoot();
      const rows = second.kernel.outbox.deliveries(eventId);
      const departed = rows.find((r) => r.subscriber === "departing");
      expect(departed?.disposition).toBe("subscriber_removed");
      expect(departed?.disposed_at).toBe(new Date(T0).getTime());
      // Retained, never dropped: an audit still sees the delivery was owed.
      expect(rows).toHaveLength(2);
      // And it blocked nothing: the surviving subscriber was delivered.
      expect(rows.find((r) => r.subscriber === "staying")?.disposition).toBe("accepted");
      expect(delivered).toHaveLength(1);

      // Re-registration does not resurrect the marked row.
      second.kernel.registerDurableSubscriber<{ id: string }>({
        id: "departing",
        capture: () => undefined,
        deliver: () => {
          throw new Error("must never be called");
        },
      });
      await second.kernel.drainLifecycleOutbox();
      expect(
        second.kernel.outbox.deliveries(eventId).find((r) => r.subscriber === "departing")
          ?.disposition,
      ).toBe("subscriber_removed");
    } finally {
      second.kernel.db.close();
    }
  });

  it("migrates a legacy expansion outbox onto the generalized table without losing an event", () => {
    const file = tempStoreFile("legacy-outbox.db");
    const seed = setup({ file });
    const record = seed.approve();
    const legacyActivation = {
      id: record.id,
      issuer: ISSUER,
      state: "active",
      version: 1,
      committed_at: T0,
      expires_at: EXPIRES_AT,
      event_id: "set_legacy_activation",
    };
    const legacySupersession = {
      ...legacyActivation,
      state: "superseded",
      prior_state: "active",
      version: 2,
      event_id: "set_legacy_supersession",
    };
    // Recreate the retired expansion-specific table and one pending job.
    seed.kernel.db.exec(`CREATE TABLE IF NOT EXISTS lifecycle_outbox (
      job_id INTEGER PRIMARY KEY AUTOINCREMENT,
      kind TEXT NOT NULL,
      mission_id TEXT NOT NULL,
      successor_id TEXT,
      activation_json TEXT NOT NULL,
      supersession_json TEXT NOT NULL,
      done INTEGER NOT NULL DEFAULT 0
    ) STRICT;`);
    seed.kernel.db
      .prepare(
        "INSERT INTO lifecycle_outbox (kind, mission_id, successor_id, activation_json, supersession_json) VALUES ('expansion-finalize', ?, ?, ?, ?)",
      )
      .run(
        record.id,
        record.id,
        JSON.stringify(legacyActivation),
        JSON.stringify(legacySupersession),
      );
    seed.kernel.db.close();

    const reopened = setup({ file });
    try {
      // The legacy table is gone and both pending events survived with their
      // original identities.
      expect(
        reopened.kernel.db
          .prepare("SELECT name FROM sqlite_master WHERE name = 'lifecycle_outbox'")
          .get(),
      ).toBeUndefined();
      reopened.commits.length = 0;
      reopened.kernel.publishPendingCommits();
      expect(reopened.commits.map((c) => c.event_id)).toEqual([
        "set_legacy_activation",
        "set_legacy_supersession",
      ]);
      expect(reopened.commits[0]?.committed_at).toBe(T0);
    } finally {
      reopened.kernel.db.close();
    }
  });
});

describe("terminal tombstones and identifier nonreuse", () => {
  it("composes every declared retention horizon into the detailed horizon", () => {
    const horizons: TombstoneRetentionInputs = {
      credential_artifact_lifetime_seconds: 300,
      state_staleness_seconds: 300,
      clock_skew_seconds: DEFAULT_CLOCK_SKEW_S,
      idempotency_retry_seconds: 86_400,
      child_cascade_seconds: 0,
      audit_retention_seconds: DEFAULT_AUDIT_RETENTION_S,
    };
    const composed = composeTombstoneRetentionSeconds(horizons);
    expect(composed).toBe(DEFAULT_AUDIT_RETENTION_S);
    // Every input is actually composed, not merely accepted.
    expect(composeTombstoneRetentionSeconds({ ...horizons, audit_retention_seconds: 0 })).toBe(
      86_400,
    );
    expect(
      composeTombstoneRetentionSeconds({
        ...horizons,
        audit_retention_seconds: 0,
        idempotency_retry_seconds: 0,
      }),
    ).toBe(300 + DEFAULT_CLOCK_SKEW_S);
    expect(
      composeTombstoneRetentionSeconds({
        ...horizons,
        audit_retention_seconds: 0,
        idempotency_retry_seconds: 0,
        state_staleness_seconds: 0,
        clock_skew_seconds: 0,
        child_cascade_seconds: 900,
      }),
    ).toBe(900);
    // A declaration that is not a non-negative number is refused, never
    // silently read as zero.
    expect(() =>
      composeTombstoneRetentionSeconds({ ...horizons, audit_retention_seconds: -1 }),
    ).toThrow("audit_retention_seconds");
    expect(() =>
      composeTombstoneRetentionSeconds({
        ...horizons,
        idempotency_retry_seconds: Number.NaN,
      }),
    ).toThrow("idempotency_retry_seconds");
  });

  it("records the terminal tombstone in the terminal transition's own transaction", () => {
    const { kernel, commits, approve } = setup();
    try {
      const record = approve();
      expect(kernel.tombstones.find(ISSUER, record.id)).toBeUndefined();
      kernel.transition(record.id, "revoke");
      const terminal = commits.find((c) => c.state === "revoked");
      const tombstone = kernel.tombstones.find(ISSUER, record.id);
      expect(tombstone).toMatchObject({
        issuer: ISSUER,
        missionId: record.id,
        terminalState: "revoked",
        finalVersion: record.version + 1,
        commitEventId: terminal?.event_id,
        detailPruned: false,
      });
      expect(tombstone?.transitionAt).toBe(terminal?.committed_at);
      expect(tombstone?.detailExpiresAt).toBe(
        new Date(T0).getTime() + kernel.tombstones.retentionSeconds * 1000,
      );
    } finally {
      kernel.db.close();
    }
  });

  it("refuses a reused identifier after the record is purged and after the detail is pruned", () => {
    // Every declared horizon is 60 seconds here, the discharge retry window
    // included: the effective discharge retention floors the idempotency
    // horizon, so a deployment cannot declare a detail horizon shorter than the
    // window in which a discharge assertion may still replay.
    const { kernel, clock, approve } = setup({
      horizons: { audit_retention_seconds: 60, state_staleness_seconds: 0, clock_skew_seconds: 0 },
      dischargeEventRetentionSeconds: 60,
    });
    try {
      const record = approve();
      kernel.transition(record.id, "revoke");
      // Consumer 1: identifier nonreuse. The `missions` primary key stops reuse
      // only while the terminal row is there; purge it and the tombstone is
      // what refuses.
      kernel.db.prepare("DELETE FROM missions").run();
      expect(kernel.get(record.id)).toBeUndefined();
      expect(() =>
        kernel.insertRecord({ ...record, approval_event_id: "second-approval" }),
      ).toThrow(MissionIdReuseError);

      // Consumer 2: past the composed detailed horizon the DETAIL is pruned and
      // the identity row remains as the permanent nonreuse marker.
      clock.at = new Date(new Date(T0).getTime() + 61_000);
      expect(kernel.tombstones.pruneDetails()).toBe(1);
      const pruned = kernel.tombstones.find(ISSUER, record.id);
      expect(pruned?.detailPruned).toBe(true);
      expect(pruned?.terminalState).toBeUndefined();
      expect(pruned?.finalVersion).toBeUndefined();
      expect(kernel.tombstones.exists(ISSUER, record.id)).toBe(true);
      expect(() =>
        kernel.insertRecord({ ...record, approval_event_id: "third-approval" }),
      ).toThrow(MissionIdReuseError);
      // Pruning is idempotent and never resurrects the identifier.
      expect(kernel.tombstones.pruneDetails()).toBe(0);
    } finally {
      kernel.db.close();
    }
  });

  it("keeps the composed horizon at or above the creation-idempotency purge window", () => {
    const { kernel } = setup({ horizons: { idempotency_retry_seconds: 86_400 } });
    try {
      // Creation idempotency purges an expired reservation to admit a fresh
      // one; the tombstone must outlive that window, or a purge could admit a
      // reservation naming an identifier whose refusal record had expired.
      expect(kernel.tombstones.retentionSeconds).toBeGreaterThanOrEqual(86_400);
      expect(kernel.tombstones.horizons().idempotency_retry_seconds).toBe(86_400);
    } finally {
      kernel.db.close();
    }
  });

  it("composes a configured discharge retention that outlives the audit horizon", () => {
    // The discharge event store's retention IS an idempotency and retry
    // horizon (issue #250, owner review): a replayed assertion inside it must
    // meet a record whose terminal state, version and commit reference are
    // still readable. A year of discharge retention therefore governs over the
    // 90-day audit horizon, and the value reaches the composition even when
    // KernelOptions is built directly rather than through the AS assembly.
    const year = 365 * 24 * 60 * 60;
    const { kernel, clock, approve } = setup({ dischargeEventRetentionSeconds: year });
    try {
      expect(year).toBeGreaterThan(DEFAULT_AUDIT_RETENTION_S);
      expect(kernel.tombstones.retentionSeconds).toBe(year);
      expect(kernel.tombstones.horizons().idempotency_retry_seconds).toBe(year);
      const record = approve();
      kernel.transition(record.id, "revoke");
      // One second inside the discharge horizon: the detail is untouched.
      clock.at = new Date(new Date(T0).getTime() + (year - 1) * 1000);
      expect(kernel.tombstones.pruneDetails()).toBe(0);
      expect(kernel.tombstones.find(ISSUER, record.id)).toMatchObject({
        terminalState: "revoked",
        finalVersion: record.version + 1,
        detailPruned: false,
      });
      // Past it the detail goes and the identity row stays as the permanent
      // nonreuse marker, which still refuses the identifier.
      clock.at = new Date(new Date(T0).getTime() + (year + 1) * 1000);
      expect(kernel.tombstones.pruneDetails()).toBe(1);
      expect(kernel.tombstones.find(ISSUER, record.id)?.terminalState).toBeUndefined();
      expect(kernel.tombstones.exists(ISSUER, record.id)).toBe(true);
      expect(() => kernel.insertRecord({ ...record, approval_event_id: "after-prune" })).toThrow(
        MissionIdReuseError,
      );
    } finally {
      kernel.db.close();
    }
  });

  it("derives one effective discharge retention for the store and the horizon", async () => {
    // The AS assembly composed the DEFAULT discharge constant while handing the
    // discharge store a larger configured value, so a supported setting never
    // reached the composed maximum (issue #250, owner review). One derivation
    // now feeds both.
    const year = 365 * 24 * 60 * 60;
    const as = await buildAuthorizationServer({
      issuer: "https://composed-retention.test",
      dischargeEventRetentionSeconds: year,
    });
    try {
      expect(as.kernel.tombstones.retentionSeconds).toBeGreaterThanOrEqual(year);
      expect(as.kernel.tombstones.horizons().idempotency_retry_seconds).toBe(year);
    } finally {
      as.kernel.db.close();
    }
    // With nothing configured the shipped declaration is unchanged: 86400
    // seconds of creation and discharge idempotency, and the audit horizon
    // still governs.
    const shipped = await buildAuthorizationServer({ issuer: "https://shipped-retention.test" });
    try {
      expect(shipped.kernel.tombstones.horizons().idempotency_retry_seconds).toBe(86_400);
      expect(shipped.kernel.tombstones.retentionSeconds).toBe(DEFAULT_AUDIT_RETENTION_S);
    } finally {
      shipped.kernel.db.close();
    }
  });

  it("isolates tombstones per issuer, so one issuer's terminal id does not refuse another's", () => {
    const a = setup({ issuer: "https://issuer-a.test" });
    const b = setup({ issuer: "https://issuer-b.test" });
    try {
      const record = a.approve();
      a.kernel.transition(record.id, "revoke");
      expect(a.kernel.tombstones.exists("https://issuer-a.test", record.id)).toBe(true);
      expect(b.kernel.tombstones.exists("https://issuer-b.test", record.id)).toBe(false);
      b.kernel.insertRecord({
        ...b.approve({ approvalEventId: "b-approval" }),
        id: record.id,
        approval_event_id: "b-second",
        status_list_idx: null,
      });
      expect(b.kernel.get(record.id)?.issuer).toBe("https://issuer-b.test");
    } finally {
      a.kernel.db.close();
      b.kernel.db.close();
    }
  });
});

describe("restart recovery on the declared file-backed store", () => {
  it("recovers the unpublished commit, the version high-water and the tombstone across a restart", async () => {
    const file = tempStoreFile("restart.db");
    const before = setup({ file });
    let missionId: string;
    let persistedEventId: string;
    let finalVersion: number;
    try {
      const record = before.approve();
      missionId = record.id;
      before.kernel.transition(record.id, "suspend");
      before.fail.publish = true;
      expect(() => before.kernel.transition(record.id, "revoke")).toThrow("publication lost");
      finalVersion = before.kernel.get(record.id)?.version as number;
      expect(finalVersion).toBe(3);
      persistedEventId = (
        before.kernel.db
          .prepare("SELECT event_id FROM lifecycle_events WHERE published = 0")
          .get() as { event_id: string }
      ).event_id;
    } finally {
      // Process loss with the event committed and unpublished.
      before.kernel.db.close();
    }

    const after = setup({ file });
    try {
      // No lower version is served after recovery: the durable row is the
      // high-water mark, and the terminal tombstone survived with it.
      expect(after.kernel.get(missionId)?.version).toBe(finalVersion);
      expect(after.kernel.get(missionId)?.state).toBe("revoked");
      expect(after.kernel.tombstones.find(ISSUER, missionId)).toMatchObject({
        terminalState: "revoked",
        finalVersion,
      });
      await after.kernel.recoverAtBoot();
      // The exact payload bytes, identity and timestamp the predecessor
      // committed, delivered once by the boot recovery.
      expect(after.commits.map((c) => c.event_id)).toEqual([persistedEventId]);
      expect(after.commits[0]?.version).toBe(finalVersion);
      expect(after.kernel.outbox.pendingEventCount()).toBe(0);
    } finally {
      after.kernel.db.close();
    }
  });
});

/**
 * @spec control-plane#fanout — overlapping drains (issue #250, owner review).
 *
 * The request middleware awaits one drain per request, so two drains are in
 * flight together with ONE process and ONE writer. That is not #641: there is
 * no lease, no claim and no second process here. The controlled promises hold a
 * delivery open exactly as a slow external call would, so a second drain starts
 * while the first is still awaiting acceptance.
 */
describe("serialized drains on one outbox instance", () => {
  it("attempts one delivery for two overlapping drains and keeps the acknowledgement", async () => {
    const { kernel, approve } = setup({ retry: { baseMs: 0, capMs: 0, maxAttempts: 1 } });
    try {
      const ctl = controlled();
      kernel.registerDurableSubscriber(ctl.subscriber);
      approve();
      const eventId = lastEventId(kernel);
      const a = kernel.drainLifecycleOutbox();
      const b = kernel.drainLifecycleOutbox();
      // The second drain did not select the row the first is delivering.
      expect(ctl.calls).toHaveLength(1);
      ctl.calls[0]?.resolve();
      await Promise.all([a, b]);
      expect(ctl.calls).toHaveLength(1);
      const row = kernel.outbox.deliveries(eventId)[0];
      expect(row?.disposition).toBe("accepted");
      expect(row?.attempts).toBe(1);
      expect(row?.last_error).toBeNull();
    } finally {
      kernel.db.close();
    }
  });

  it("records one attempt when the delivery under two overlapping drains fails", async () => {
    // A backoff the follow-up pass cannot have reached, so the one recorded
    // attempt is the one delivery that ran, not a second pass retrying early.
    const { kernel, approve } = setup({
      retry: { baseMs: 60_000, capMs: 60_000, maxAttempts: 4 },
    });
    try {
      const ctl = controlled();
      kernel.registerDurableSubscriber(ctl.subscriber);
      approve();
      const eventId = lastEventId(kernel);
      const a = kernel.drainLifecycleOutbox();
      const b = kernel.drainLifecycleOutbox();
      expect(ctl.calls).toHaveLength(1);
      ctl.calls[0]?.reject(new Error("downstream refused"));
      await Promise.all([a, b]);
      expect(ctl.calls).toHaveLength(1);
      const row = kernel.outbox.deliveries(eventId)[0];
      expect(row?.disposition).toBe("pending");
      expect(row?.attempts).toBe(1);
      expect(row?.last_error).toBe("downstream refused");
    } finally {
      kernel.db.close();
    }
  });

  it("abandons the final attempt once, and a later drain does not reverse it", async () => {
    const { kernel, approve } = setup({ retry: { baseMs: 0, capMs: 0, maxAttempts: 1 } });
    try {
      const ctl = controlled();
      kernel.registerDurableSubscriber(ctl.subscriber);
      approve();
      const eventId = lastEventId(kernel);
      const a = kernel.drainLifecycleOutbox();
      const b = kernel.drainLifecycleOutbox();
      expect(ctl.calls).toHaveLength(1);
      ctl.calls[0]?.reject(new Error("permanently unavailable"));
      await Promise.all([a, b]);
      const abandoned = kernel.outbox.deliveries(eventId)[0];
      expect(abandoned?.disposition).toBe("abandoned");
      expect(abandoned?.attempts).toBe(1);
      // The terminal row is not re-selected and not re-attempted.
      await kernel.drainLifecycleOutbox();
      expect(ctl.calls).toHaveLength(1);
      expect(kernel.outbox.deliveries(eventId)[0]).toEqual(abandoned);
    } finally {
      kernel.db.close();
    }
  });

  it("attempts each delivery once across four concurrent request-path drains", async () => {
    // The provider middleware's seam is one awaited `drainLifecycleOutbox` per
    // request. Four concurrent calls stand in for four in-flight requests; the
    // HTTP layer adds nothing to this seam.
    const { kernel, approve } = setup({ retry: { baseMs: 0, capMs: 0, maxAttempts: 1 } });
    try {
      const ctl = controlled();
      kernel.registerDurableSubscriber(ctl.subscriber);
      approve();
      const eventId = lastEventId(kernel);
      const drains = [0, 1, 2, 3].map(() => kernel.drainLifecycleOutbox());
      expect(ctl.calls).toHaveLength(1);
      ctl.calls[0]?.resolve();
      await Promise.all(drains);
      expect(ctl.calls).toHaveLength(1);
      const row = kernel.outbox.deliveries(eventId)[0];
      expect(row?.disposition).toBe("accepted");
      expect(row?.attempts).toBe(1);
    } finally {
      kernel.db.close();
    }
  });

  it("delivers a row enqueued during a pass in the queued follow-up pass", async () => {
    // Why one queued follow-up rather than a bare join: a caller whose own
    // commit enqueued a row while a pass was running would otherwise wait for
    // the next request or for boot, because that pass had already selected its
    // rows.
    const { kernel, approve } = setup({ retry: { baseMs: 0, capMs: 0, maxAttempts: 1 } });
    try {
      const ctl = controlled();
      kernel.registerDurableSubscriber(ctl.subscriber);
      const record = approve();
      const first = lastEventId(kernel);
      const a = kernel.drainLifecycleOutbox();
      expect(ctl.calls).toHaveLength(1);
      // A second transition commits its own delivery row while the first pass
      // is still awaiting acceptance.
      kernel.transition(record.id, "suspend");
      const second = lastEventId(kernel);
      const b = kernel.drainLifecycleOutbox();
      expect(ctl.calls).toHaveLength(1);
      ctl.calls[0]?.resolve();
      await a;
      await vi.waitFor(() => expect(ctl.calls).toHaveLength(2));
      ctl.calls[1]?.resolve();
      await b;
      expect(kernel.outbox.deliveries(first)[0]?.disposition).toBe("accepted");
      expect(kernel.outbox.deliveries(second)[0]?.disposition).toBe("accepted");
    } finally {
      kernel.db.close();
    }
  });

  /**
   * Two outbox instances over ONE database handle in ONE process: the closest
   * single-process stand-in for the interleaving the serialization above
   * removes. It is not multi-process claiming (#641) and needs no lease. The
   * guard is what keeps a row honest if any future caller reintroduces overlap.
   */
  const handCommit = (id: string): LifecycleCommit => ({
    id,
    issuer: ISSUER,
    state: "active",
    version: 1,
    committed_at: T0,
    expires_at: EXPIRES_AT,
  });

  it("keeps an acknowledged row acknowledged when a stale attempt fails later", async () => {
    const db = openStore("");
    try {
      const now = () => new Date(T0);
      const retry = { baseMs: 60_000, capMs: 60_000, maxAttempts: 4 };
      const a = new LifecycleOutbox(db, { now, publish: () => undefined, retry });
      const b = new LifecycleOutbox(db, { now, publish: () => undefined, retry });
      const ctlA = controlled();
      const ctlB = controlled();
      a.register(ctlA.subscriber);
      b.register(ctlB.subscriber);
      const commit = withTransaction(db, () => a.enqueueInCallerTx(handCommit("m-stale-fail")));

      const drainA = a.drain();
      const drainB = b.drain();
      // Both instances selected the same pending row: the interleaving.
      expect(ctlA.calls).toHaveLength(1);
      expect(ctlB.calls).toHaveLength(1);
      ctlA.calls[0]?.resolve();
      await drainA;
      const accepted = rawDelivery(db);
      expect(accepted).toMatchObject({ disposition: "accepted", attempts: 1, last_error: null });

      ctlB.calls[0]?.reject(new Error("stale downstream failure"));
      await drainB;
      // Byte for byte: the stale failure moved neither the disposition nor the
      // attempt count, the error or the backoff.
      expect(rawDelivery(db)).toEqual(accepted);
      expect(a.deliveries(commit.event_id)[0]?.disposition).toBe("accepted");
    } finally {
      db.close();
    }
  });

  it("keeps an abandoned row abandoned when a stale attempt succeeds later", async () => {
    const db = openStore("");
    try {
      const now = () => new Date(T0);
      const retry = { baseMs: 0, capMs: 0, maxAttempts: 1 };
      const a = new LifecycleOutbox(db, { now, publish: () => undefined, retry });
      const b = new LifecycleOutbox(db, { now, publish: () => undefined, retry });
      const ctlA = controlled();
      const ctlB = controlled();
      a.register(ctlA.subscriber);
      b.register(ctlB.subscriber);
      withTransaction(db, () => a.enqueueInCallerTx(handCommit("m-stale-ok")));

      const drainA = a.drain();
      const drainB = b.drain();
      ctlA.calls[0]?.reject(new Error("budget exhausted"));
      await drainA;
      const abandoned = rawDelivery(db);
      expect(abandoned).toMatchObject({
        disposition: "abandoned",
        attempts: 1,
        last_error: "budget exhausted",
      });

      // A duplicate that later succeeded does not un-abandon the row. The
      // record keeps what the attempt it tracks did: at-least-once already
      // permits the duplicate delivery, and no update moves a row out of a
      // terminal disposition.
      ctlB.calls[0]?.resolve();
      await drainB;
      expect(rawDelivery(db)).toEqual(abandoned);
    } finally {
      db.close();
    }
  });
});
