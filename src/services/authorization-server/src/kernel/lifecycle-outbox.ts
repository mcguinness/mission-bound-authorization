/**
 * @spec control-plane#fanout — the kernel's durable lifecycle fan-out.
 *
 * Every committed transition writes one immutable event row in the SAME kernel
 * transaction as the state write, so no committed transition can be lost and no
 * rolled-back transition can be published. Publication happens after that
 * commit, at least once, and consumers dedupe on the event identity minted
 * inside the transaction.
 *
 * SUBSCRIBER CLASSES (issue #250, sketch review finding 1). There is no
 * synchronous/asynchronous boundary on the commit path: `onLifecycleCommit`,
 * `afterCommit` and every registered projection are synchronous. Subscribers
 * are therefore classified rather than each given retry rows:
 *
 *  - Durable on return. Mission Signals' subscriber performs a synchronous
 *    `signal_outbox` INSERT with `UNIQUE(event_id, audience)`; that insert IS
 *    the durable acceptance, and a redelivery of the same event is a no-op.
 *  - Unacknowledged projections. The Status List republisher rebuilds from the
 *    authoritative record set. The continuation store and the delegation-family
 *    store are in-memory projections that start EMPTY at each boot: recovery
 *    replays only committed-but-unpublished events, so an activation already
 *    published does not repopulate them. Both are idempotent per Mission, both
 *    fail closed on an unknown row, and neither is acknowledged.
 *  Both classes ride {@link LifecycleOutbox.publishPending}, which is
 *  synchronous, so nothing launches a floating promise from a commit chain.
 *  - Durable retryable. A subscriber whose effect reaches outside this process
 *    (the provider revocation of per-delegation family grants) registers with
 *    {@link LifecycleOutbox.register} and gets one `lifecycle_deliveries` row
 *    per event, carrying attempts and a next-retry time. Those rows are drained
 *    by the promise-returning {@link LifecycleOutbox.drain}, invoked from boot
 *    and from request paths, never from `afterCommit`.
 *
 * Delivery is at-least-once with idempotent acceptance. Exactly-once external
 * delivery is not achievable across the crash and acknowledgement boundaries
 * here and is not claimed.
 */

import { randomBytes } from "node:crypto";
import { afterCommit, type Database, withTransaction } from "@mission/store";
import type { LifecycleCommit, PersistedLifecycleCommit } from "./types.js";

/**
 * The guard every delivery disposition carries (issue #250, owner review). A
 * disposition applies only while the row is still the PENDING row this attempt
 * read: `disposition = 'pending'` makes every terminal disposition monotone, so
 * no update moves a row out of `accepted`, `abandoned` or `subscriber_removed`,
 * and `attempts = ?` binds the write to the attempt that produced it, so a
 * stale attempt cannot rewrite the attempt count, the error or the backoff.
 */
const PENDING_ATTEMPT_GUARD =
  "WHERE seq = ? AND subscriber = ? AND disposition = 'pending' AND attempts = ?";

/**
 * The payload schema version an event row carries. The drain refuses an
 * unrecognized version rather than reinterpreting stored bytes: a payload it
 * cannot read is pending work, never work it may silently discard.
 */
export const LIFECYCLE_EVENT_PAYLOAD_VERSION = 1;

/** Terminal dispositions a durable delivery row can reach. */
export type DeliveryDisposition =
  | "pending"
  | "accepted"
  /**
   * The subscriber that owed this delivery is no longer registered (issue #250,
   * owner recommendation 1). Marked at boot with the removal time, retained to
   * the same horizon as an accepted row so an audit can still see that a
   * delivery was owed and to whom, never blocking another subscriber's rows,
   * and never resurrected by re-registering the subscriber.
   */
  | "subscriber_removed"
  /** The bounded retry budget was exhausted; retained for the same horizon. */
  | "abandoned";

export const LIFECYCLE_OUTBOX_SCHEMA = `
CREATE TABLE IF NOT EXISTS lifecycle_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  issuer TEXT NOT NULL,
  mission_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  payload_version INTEGER NOT NULL,
  committed_at TEXT NOT NULL,
  commit_json TEXT NOT NULL,
  cascade_mission_id TEXT,
  published INTEGER NOT NULL DEFAULT 0,
  publish_attempts INTEGER NOT NULL DEFAULT 0,
  last_publish_error TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS lifecycle_deliveries (
  seq INTEGER NOT NULL,
  subscriber TEXT NOT NULL,
  disposition TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL DEFAULT 0,
  payload_json TEXT NOT NULL,
  last_error TEXT,
  disposed_at INTEGER,
  PRIMARY KEY (seq, subscriber)
) STRICT;
`;

/**
 * A subscriber whose effect leaves this process and therefore needs a durable
 * delivery row. `capture` runs INSIDE the commit transaction and returns the
 * immutable payload the delivery will use, so a later configuration change can
 * neither complete pending work nor orphan it; returning undefined means this
 * subscriber owes nothing for this commit and no row is written. `deliver` runs
 * off the commit path and is awaited by the drain.
 */
export interface DurableCommitSubscriber<P = unknown> {
  id: string;
  capture: (commit: PersistedLifecycleCommit) => P | undefined;
  deliver: (payload: P, commit: PersistedLifecycleCommit) => void | Promise<void>;
}

export interface LifecycleOutboxOptions {
  now: () => Date;
  /**
   * The synchronous subscriber chain (durable-on-return plus rebuilt
   * projections). Invoked once per publication attempt with the persisted,
   * frozen payload.
   */
  publish: (commit: PersistedLifecycleCommit) => void;
  /**
   * Re-run the state-guarded child cascade for a migrated legacy job. Only the
   * legacy `lifecycle_outbox` migration marks an event with cascade work; the
   * live funnels cascade inside their own transaction.
   */
  recoverCascade?: (missionId: string) => void;
  retry?: { baseMs?: number; capMs?: number; maxAttempts?: number };
}

interface EventRow {
  seq: number;
  event_id: string;
  payload_version: number;
  commit_json: string;
  cascade_mission_id: string | null;
}

interface DeliveryRow {
  seq: number;
  subscriber: string;
  attempts: number;
  payload_json: string;
  commit_json: string;
  payload_version: number;
}

/** The registry's payload-erased view of a registered subscriber. */
type ErasedSubscriber = {
  id: string;
  capture: (commit: PersistedLifecycleCommit) => unknown;
  deliver: (payload: unknown, commit: PersistedLifecycleCommit) => void | Promise<void>;
};

export class LifecycleOutbox {
  private readonly subscribers = new Map<string, ErasedSubscriber>();
  private readonly retryBaseMs: number;
  private readonly retryCapMs: number;
  private readonly maxAttempts: number;
  /** The drain pass running or queued on this instance ({@link drain}). */
  private scheduledPass: Promise<void> | undefined;
  /** The one not-yet-started follow-up pass mid-pass callers join. */
  private queuedPass: Promise<void> | undefined;

  constructor(
    private readonly db: Database,
    private readonly opts: LifecycleOutboxOptions,
  ) {
    this.db.exec(LIFECYCLE_OUTBOX_SCHEMA);
    this.retryBaseMs = opts.retry?.baseMs ?? 250;
    this.retryCapMs = opts.retry?.capMs ?? 30_000;
    this.maxAttempts = opts.retry?.maxAttempts ?? 8;
    this.migrateLegacyOutbox();
  }

  /**
   * `openStore` applies a schema with `CREATE TABLE IF NOT EXISTS` only, so the
   * PR that makes a file-backed kernel store possible owns the migration off
   * the expansion-specific `lifecycle_outbox` (whose `activation_json` and
   * `supersession_json` are NOT NULL). Precedent: the Signals outbox key
   * migration. Pending legacy jobs move to `lifecycle_events` with their
   * ORIGINAL event identity and `committed_at` preserved, carrying the
   * state-guarded cascade re-run the legacy drain owed, and the legacy table is
   * dropped. Invalid identities stop startup rather than dropping deliveries.
   */
  private migrateLegacyOutbox(): void {
    const legacy = this.db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'lifecycle_outbox'")
      .get();
    if (!legacy) return;
    withTransaction(this.db, () => {
      const rows = this.db
        .prepare(
          "SELECT job_id, mission_id, activation_json, supersession_json FROM lifecycle_outbox WHERE done = 0 ORDER BY job_id",
        )
        .all() as Array<{
        job_id: number;
        mission_id: string;
        activation_json: string;
        supersession_json: string;
      }>;
      for (const row of rows) {
        const payloads = [row.activation_json, row.supersession_json];
        for (const [index, json] of payloads.entries()) {
          const commit = JSON.parse(json) as LifecycleCommit;
          if (typeof commit.event_id !== "string" || !commit.event_id) {
            throw new Error(
              `legacy lifecycle_outbox job ${row.job_id} has no durable event identity to migrate`,
            );
          }
          this.insertEvent(commit as PersistedLifecycleCommit, {
            // The legacy drain re-ran the cascade once per job; carry it on the
            // first migrated event so the recovery is not lost.
            ...(index === 0 ? { cascadeMissionId: row.mission_id } : {}),
          });
        }
      }
      this.db.exec("DROP TABLE lifecycle_outbox");
    });
  }

  /** Register a durable retryable subscriber. Must happen before any commit. */
  register<P>(subscriber: DurableCommitSubscriber<P>): void {
    if (this.subscribers.has(subscriber.id)) {
      throw new Error(`durable lifecycle subscriber '${subscriber.id}' is already registered`);
    }
    this.subscribers.set(subscriber.id, subscriber as unknown as ErasedSubscriber);
  }

  /**
   * Write the durable event and its durable delivery rows inside the CALLER's
   * transaction, and schedule the synchronous publication for after the
   * outermost commit. Requires a managed transaction: an event that did not
   * commit with its state write would be exactly the loss this table exists to
   * prevent.
   */
  enqueueInCallerTx(commit: LifecycleCommit): PersistedLifecycleCommit {
    if (!this.db.inTransaction) {
      throw new Error("lifecycle commits must be enqueued inside the state write's transaction");
    }
    const persisted = Object.freeze({
      ...commit,
      event_id: commit.event_id ?? `set_${randomBytes(15).toString("base64url")}`,
    }) as PersistedLifecycleCommit;
    const seq = this.insertEvent(persisted);
    for (const subscriber of this.subscribers.values()) {
      const payload = subscriber.capture(persisted);
      if (payload === undefined) continue;
      this.db
        .prepare(
          `INSERT INTO lifecycle_deliveries (seq, subscriber, disposition, next_attempt_at, payload_json)
           VALUES (?, ?, 'pending', 0, ?)`,
        )
        .run(seq, subscriber.id, JSON.stringify(payload));
    }
    afterCommit(this.db, () => this.publishOne(seq));
    return persisted;
  }

  private insertEvent(
    commit: PersistedLifecycleCommit,
    extra: { cascadeMissionId?: string } = {},
  ): number {
    const res = this.db
      .prepare(
        `INSERT INTO lifecycle_events
           (event_id, issuer, mission_id, version, payload_version, committed_at, commit_json, cascade_mission_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        commit.event_id,
        commit.issuer,
        commit.id,
        commit.version,
        LIFECYCLE_EVENT_PAYLOAD_VERSION,
        commit.committed_at,
        JSON.stringify(commit),
        extra.cascadeMissionId ?? null,
      );
    return Number(res.lastInsertRowid);
  }

  /**
   * Publish one event row and mark it published, on the COMMITTING path. A
   * subscriber failure propagates to the caller that committed the transition,
   * which is the behavior that existed before this table: the transition stays
   * committed, its event stays pending, and the caller learns publication did
   * not complete.
   */
  private publishOne(seq: number): void {
    const row = this.db
      .prepare(
        "SELECT seq, event_id, payload_version, commit_json, cascade_mission_id FROM lifecycle_events WHERE seq = ? AND published = 0",
      )
      .get(seq) as EventRow | undefined;
    if (!row) return;
    this.deliverEventRow(row, { isolate: false });
  }

  /**
   * `isolate` marks the RECOVERY path (boot and the request-path drain). There a
   * publication failure must not become the failure of a request that committed
   * nothing: the attempt count and the error are recorded, the row stays
   * pending, and the replay moves to the next event. Nothing is discarded, so
   * the failure is still owed and still visible; it simply cannot let one
   * unpublishable event turn every later request into an error.
   */
  private deliverEventRow(row: EventRow, opts: { isolate: boolean }): boolean {
    try {
      if (row.payload_version !== LIFECYCLE_EVENT_PAYLOAD_VERSION) {
        throw new Error(
          `lifecycle event ${row.event_id} carries unrecognized payload version ${row.payload_version}`,
        );
      }
      // Frozen exactly as a directly emitted commit is: a replayed payload and
      // a first delivery are the same immutable event.
      const commit = Object.freeze(JSON.parse(row.commit_json) as PersistedLifecycleCommit);
      if (row.cascade_mission_id) this.opts.recoverCascade?.(row.cascade_mission_id);
      this.opts.publish(commit);
    } catch (e) {
      if (!opts.isolate) throw e;
      this.db
        .prepare(
          "UPDATE lifecycle_events SET publish_attempts = publish_attempts + 1, last_publish_error = ? WHERE seq = ?",
        )
        .run(e instanceof Error ? e.message : String(e), row.seq);
      return false;
    }
    this.db.prepare("UPDATE lifecycle_events SET published = 1 WHERE seq = ?").run(row.seq);
    return true;
  }

  /**
   * Replay every committed-but-unpublished event, in commit order, from its
   * persisted payload. This is the crash-window recovery: a process lost
   * between the state commit and its publication redelivers the SAME event,
   * with the same identity and the same `committed_at`, so the Signals SET
   * carries one `jti` across redelivery and the projections converge.
   */
  publishPending(): number {
    const rows = this.db
      .prepare(
        "SELECT seq, event_id, payload_version, commit_json, cascade_mission_id FROM lifecycle_events WHERE published = 0 ORDER BY seq",
      )
      .all() as EventRow[];
    let published = 0;
    for (const row of rows) {
      if (this.deliverEventRow(row, { isolate: true })) published += 1;
    }
    return published;
  }

  /**
   * The promise-returning drain: replay unpublished events, then attempt every
   * runnable durable delivery. Invoked from boot and from request paths, NEVER
   * from `afterCommit`. One subscriber can succeed while another fails: rows
   * are acknowledged independently, a failure keeps its own row pending with a
   * bounded backoff, and a retry redelivers the same payload.
   *
   * SERIALIZED ON THIS INSTANCE (issue #250, owner review). The request
   * middleware calls this once per request, so two drains could otherwise
   * select the same pending row, await delivery, and let the loser's stale
   * update reverse the winner's acknowledgement. At most one pass runs here,
   * and every caller that arrives while a pass runs joins ONE queued follow-up
   * pass that starts after it. The follow-up rather than a bare join is what
   * keeps liveness: a caller whose own commit enqueued a row would otherwise
   * wait for the next request or for boot, because the running pass had already
   * selected its rows. Bounded at one running plus one queued pass, so a slow
   * external delivery cannot pile requests up behind each other.
   *
   * A subscriber's `deliver` MUST NOT call this: it would join the pass that is
   * awaiting its own delivery. The one durable subscriber here reaches the
   * provider through the model API, never back through the request path.
   *
   * This is instance-level serialization for the declared one-process,
   * one-writer topology. It is no distributed lease: multi-process claiming and
   * fencing stay behind #641's deployment trigger.
   */
  async drain(): Promise<void> {
    // A follow-up is already scheduled. It has not selected its rows yet, so
    // it covers this caller's work too.
    if (this.queuedPass) {
      await this.queuedPass;
      return;
    }
    const ahead = this.scheduledPass;
    const pass = ahead === undefined ? this.deliverRunnable() : this.passAfter(ahead);
    if (ahead !== undefined) this.queuedPass = pass;
    this.scheduledPass = pass;
    try {
      await pass;
    } finally {
      if (this.scheduledPass === pass) this.scheduledPass = undefined;
    }
  }

  /** The queued follow-up: run one pass once the pass ahead has finished. */
  private async passAfter(ahead: Promise<void>): Promise<void> {
    // The pass ahead reports its own outcome to its own callers.
    await ahead.catch(() => undefined);
    // From here this IS the running pass, so the next caller queues behind it.
    this.queuedPass = undefined;
    await this.deliverRunnable();
  }

  /** One drain pass. Only {@link drain} may start one. */
  private async deliverRunnable(): Promise<void> {
    this.publishPending();
    const now = this.opts.now().getTime();
    const rows = this.db
      .prepare(
        `SELECT d.seq AS seq, d.subscriber AS subscriber, d.attempts AS attempts,
                d.payload_json AS payload_json, e.commit_json AS commit_json,
                e.payload_version AS payload_version
           FROM lifecycle_deliveries d JOIN lifecycle_events e ON e.seq = d.seq
          WHERE d.disposition = 'pending' AND d.next_attempt_at <= ?
          ORDER BY d.seq, d.subscriber`,
      )
      .all(now) as DeliveryRow[];
    for (const row of rows) {
      const subscriber = this.subscribers.get(row.subscriber);
      if (!subscriber) {
        // A removed subscriber's pending row is not delivered and not dropped;
        // reconciliation marks it terminal.
        this.markRemoved(row.seq, row.subscriber);
        continue;
      }
      if (row.payload_version !== LIFECYCLE_EVENT_PAYLOAD_VERSION) {
        throw new Error(
          `lifecycle delivery ${row.seq}/${row.subscriber} carries unrecognized payload version ${row.payload_version}`,
        );
      }
      const commit = Object.freeze(JSON.parse(row.commit_json) as PersistedLifecycleCommit);
      try {
        await subscriber.deliver(JSON.parse(row.payload_json) as unknown, commit);
        // A guarded write that changes nothing means another pass already
        // disposed of this row. The delivery still reached the subscriber, and
        // at-least-once already permits that duplicate; what the guard refuses
        // is rewriting the disposition that pass recorded.
        this.db
          .prepare(
            `UPDATE lifecycle_deliveries SET disposition = 'accepted', attempts = attempts + 1, disposed_at = ?, last_error = NULL ${PENDING_ATTEMPT_GUARD}`,
          )
          .run(this.opts.now().getTime(), row.seq, row.subscriber, row.attempts);
      } catch (e) {
        const attempts = row.attempts + 1;
        const message = e instanceof Error ? e.message : String(e);
        // Guarded the same way: a stale failure neither reverses an
        // acknowledgement nor overwrites the attempt, error and backoff the
        // attempt that actually ran recorded.
        if (attempts >= this.maxAttempts) {
          this.db
            .prepare(
              `UPDATE lifecycle_deliveries SET disposition = 'abandoned', attempts = ?, disposed_at = ?, last_error = ? ${PENDING_ATTEMPT_GUARD}`,
            )
            .run(
              attempts,
              this.opts.now().getTime(),
              message,
              row.seq,
              row.subscriber,
              row.attempts,
            );
          continue;
        }
        const backoff = Math.min(this.retryCapMs, this.retryBaseMs * 2 ** (attempts - 1));
        this.db
          .prepare(
            `UPDATE lifecycle_deliveries SET attempts = ?, next_attempt_at = ?, last_error = ? ${PENDING_ATTEMPT_GUARD}`,
          )
          .run(
            attempts,
            this.opts.now().getTime() + backoff,
            message,
            row.seq,
            row.subscriber,
            row.attempts,
          );
      }
    }
  }

  /**
   * Boot reconciliation: every pending delivery whose subscriber is no longer
   * registered reaches the terminal `subscriber_removed` disposition, stamped
   * with the removal time. It blocks no other subscriber's row and is never
   * silently dropped. Re-registering the subscriber does not resurrect it.
   */
  reconcileRemovedSubscribers(): number {
    const rows = this.db
      .prepare("SELECT DISTINCT subscriber FROM lifecycle_deliveries WHERE disposition = 'pending'")
      .all() as Array<{ subscriber: string }>;
    let marked = 0;
    for (const row of rows) {
      if (this.subscribers.has(row.subscriber)) continue;
      marked += this.markRemoved(undefined, row.subscriber);
    }
    return marked;
  }

  /**
   * Terminal too, and reached only from a pending row: a pass that selected a
   * row before reconciliation marked it removed cannot flip it back, and a
   * removed row cannot be re-marked.
   */
  private markRemoved(seq: number | undefined, subscriber: string): number {
    const at = this.opts.now().getTime();
    const res =
      seq === undefined
        ? this.db
            .prepare(
              "UPDATE lifecycle_deliveries SET disposition = 'subscriber_removed', disposed_at = ? WHERE subscriber = ? AND disposition = 'pending'",
            )
            .run(at, subscriber)
        : this.db
            .prepare(
              "UPDATE lifecycle_deliveries SET disposition = 'subscriber_removed', disposed_at = ? WHERE seq = ? AND subscriber = ? AND disposition = 'pending'",
            )
            .run(at, seq, subscriber);
    return res.changes;
  }

  /**
   * Prune published events older than `retentionSeconds` whose deliveries have
   * all reached a terminal disposition. Terminal rows (accepted, removed,
   * abandoned) share one horizon, so an audit sees every delivery that was
   * owed for as long as it sees the ones that completed.
   */
  pruneSettled(retentionSeconds: number): number {
    const cutoff = new Date(this.opts.now().getTime() - retentionSeconds * 1000).toISOString();
    return withTransaction(this.db, () => {
      const stale = this.db
        .prepare(
          `SELECT seq FROM lifecycle_events
            WHERE published = 1 AND committed_at < ?
              AND seq NOT IN (SELECT seq FROM lifecycle_deliveries WHERE disposition = 'pending')`,
        )
        .all(cutoff) as Array<{ seq: number }>;
      for (const row of stale) {
        this.db.prepare("DELETE FROM lifecycle_deliveries WHERE seq = ?").run(row.seq);
        this.db.prepare("DELETE FROM lifecycle_events WHERE seq = ?").run(row.seq);
      }
      return stale.length;
    });
  }

  /** Test and operator observation: the durable delivery rows for one event. */
  deliveries(eventId: string): Array<{
    subscriber: string;
    disposition: DeliveryDisposition;
    attempts: number;
    last_error: string | null;
    disposed_at: number | null;
  }> {
    return this.db
      .prepare(
        `SELECT d.subscriber AS subscriber, d.disposition AS disposition, d.attempts AS attempts,
                d.last_error AS last_error, d.disposed_at AS disposed_at
           FROM lifecycle_deliveries d JOIN lifecycle_events e ON e.seq = d.seq
          WHERE e.event_id = ? ORDER BY d.subscriber`,
      )
      .all(eventId) as Array<{
      subscriber: string;
      disposition: DeliveryDisposition;
      attempts: number;
      last_error: string | null;
      disposed_at: number | null;
    }>;
  }

  /** Test and operator observation: committed events not yet published. */
  pendingEventCount(): number {
    return (
      this.db.prepare("SELECT COUNT(*) AS n FROM lifecycle_events WHERE published = 0").get() as {
        n: number;
      }
    ).n;
  }

  /** Test and operator observation: an unpublished event's recorded attempts. */
  pendingPublications(): Array<{
    event_id: string;
    publish_attempts: number;
    last_publish_error: string | null;
  }> {
    return this.db
      .prepare(
        "SELECT event_id, publish_attempts, last_publish_error FROM lifecycle_events WHERE published = 0 ORDER BY seq",
      )
      .all() as Array<{
      event_id: string;
      publish_attempts: number;
      last_publish_error: string | null;
    }>;
  }
}
