/**
 * @spec status#lifecycle-processing (#1684, D826): a lifecycle transition is
 * durably committed before any response acknowledges it, witnessed across an
 * abrupt process exit. The AS runs in a child process on a file-backed kernel
 * store (lifecycle-crash-restart.child.ts); the parent kills it with SIGKILL
 * at a deterministic barrier, reopens the same files in a new child, and
 * retransmits the request with the same nonce.
 *
 *  - After acknowledgement: the barrier is the parent holding the complete 200.
 *    The terminal state, its version and the retained response survive; the
 *    retransmit replays the same bytes, and no second transition commits.
 *  - Between commit and retention: the barrier is the child's own, in the
 *    endpoint's retention of the response, after the transition's transaction
 *    has committed and before the bytes are retained. The retransmit is
 *    finalized from the retained observation, with its original timestamps,
 *    and the operation is not executed again.
 *
 * The WAL is preserved: the parent inspects the files only through a
 * read-only connection, which never checkpoints, and checks the `-wal` file
 * is still there before the store is reopened. This is process-crash
 * evidence; the store's synchronous=FULL, asserted here on each writer
 * connection, supports power-loss durability where the storage stack honors
 * synchronization, which a SIGKILL test does not prove.
 */

import { type ChildProcess, spawn } from "node:child_process";
import { once } from "node:events";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { openStoreReadOnly } from "@mission/store";
import { decodeJwt } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { LIFECYCLE_ENDPOINT_KEY } from "../src/index.js";
import { type LifecycleTestClient, lifecycleRequest, newLifecycleClient } from "./lifecycle-endpoint.helper.js";

const TSX_LOADER = pathToFileURL(createRequire(import.meta.url).resolve("tsx")).href;
const CHILD = fileURLToPath(new URL("./lifecycle-crash-restart.child.ts", import.meta.url));
const TIMEOUT_MS = 90_000;

let client: LifecycleTestClient;
const dirs: string[] = [];
const children: ChildProcess[] = [];

beforeAll(async () => {
  client = await newLifecycleClient("crash-console");
});

afterAll(() => {
  for (const child of children) if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

interface Ready {
  missionId?: string;
  journal: string;
  synchronous: number;
  locking: string;
}

/** Start a child AS on `store`, resolving once it listens. */
async function start(opts: {
  issuer: string;
  port: number;
  store: string;
  approve?: boolean;
  barrier?: { nonce: string; file: string };
}): Promise<{ child: ChildProcess; ready: Ready }> {
  const child = spawn(process.execPath, ["--import", TSX_LOADER, CHILD], {
    env: {
      ...process.env,
      CRASH_ISSUER: opts.issuer,
      CRASH_PORT: String(opts.port),
      CRASH_STORE: opts.store,
      CRASH_CLIENT: JSON.stringify(client.metadata),
      ...(opts.approve ? { CRASH_APPROVE: "1" } : {}),
      ...(opts.barrier ? { CRASH_BARRIER_NONCE: opts.barrier.nonce, CRASH_BARRIER_FILE: opts.barrier.file } : {}),
    },
    stdio: ["ignore", "ignore", "pipe", "ipc"],
  });
  children.push(child);
  let stderr = "";
  child.stderr?.on("data", (chunk) => {
    stderr += String(chunk);
  });
  const ready = await new Promise<Ready>((resolve, reject) => {
    child.once("message", (message) => resolve(message as Ready));
    child.once("exit", (code, signal) => reject(new Error(`child exited (${code ?? signal}) before ready: ${stderr}`)));
  });
  return { child, ready };
}

/** SIGKILL: no handler runs, nothing is flushed or closed by the child. */
async function kill(child: ChildProcess): Promise<void> {
  const exited = once(child, "exit");
  child.kill("SIGKILL");
  await exited;
}

async function waitForFile(file: string, deadlineMs: number): Promise<void> {
  const until = Date.now() + deadlineMs;
  while (!existsSync(file)) {
    if (Date.now() > until) throw new Error(`barrier ${file} not reached`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

interface StoreView {
  mission: { state: string; version: number };
  events: number;
  claim?: { state: string; body: string; material_json: string | null };
}

/** Read the store through a read-only connection, which cannot checkpoint the WAL. */
function inspect(store: string, missionId: string, nonce: string): StoreView {
  const db = openStoreReadOnly(store);
  try {
    return {
      mission: db.prepare("SELECT state, version FROM missions WHERE id = ?").get(missionId) as StoreView["mission"],
      events: (db.prepare("SELECT COUNT(*) AS n FROM lifecycle_events WHERE mission_id = ?").get(missionId) as { n: number }).n,
      claim: db
        .prepare(
          "SELECT state, body, material_json FROM lifecycle_responses WHERE endpoint = ? AND principal = ? AND mission_id = ? AND nonce = ?",
        )
        .get(LIFECYCLE_ENDPOINT_KEY, client.clientId, missionId, nonce) as StoreView["claim"],
    };
  } finally {
    db.close();
  }
}

function newStore(): string {
  const dir = mkdtempSync(join(tmpdir(), "lifecycle-crash-"));
  dirs.push(dir);
  return join(dir, "kernel.db");
}

describe("a lifecycle transition survives an abrupt process exit (@spec status#lifecycle-processing, #1684, D826)", () => {
  it(
    "after an acknowledged revocation, an abrupt kill leaves the terminal state, its version and the retained response: the retransmit replays the same bytes, with no second transition",
    async () => {
      const port = 14976;
      const issuer = `http://localhost:${port}`;
      const store = newStore();
      const first = await start({ issuer, port, store, approve: true });
      expect(first.ready).toMatchObject({ journal: "wal", synchronous: 2, locking: "normal" });
      const missionId = first.ready.missionId as string;
      const nonce = `nonce-crash-a-${crypto.randomUUID()}`;
      const eventsBefore = inspect(store, missionId, nonce).events;

      const members = { mission_id: missionId, operation: "revoke", nonce };
      const ack = await lifecycleRequest(issuer, client, members);
      expect(ack.status, ack.text).toBe(200);
      const acknowledged = decodeJwt(ack.text).mission as { state: string; version: number };
      expect(acknowledged.state).toBe("terminated");
      // The barrier: the parent holds the complete acknowledgement.
      await kill(first.child);

      expect(existsSync(`${store}-wal`)).toBe(true);
      const afterCrash = inspect(store, missionId, nonce);
      expect(afterCrash.mission).toEqual({ state: "terminated", version: acknowledged.version });
      expect(afterCrash.events).toBe(eventsBefore + 1);
      expect(afterCrash.claim).toMatchObject({ state: "final", body: ack.text });

      const second = await start({ issuer, port, store });
      expect(second.ready).toMatchObject({ journal: "wal", synchronous: 2, locking: "normal" });
      const replay = await lifecycleRequest(issuer, client, members);
      expect(replay.status).toBe(200);
      expect(replay.text).toBe(ack.text);
      await kill(second.child);

      const afterReplay = inspect(store, missionId, nonce);
      expect(afterReplay.mission).toEqual({ state: "terminated", version: acknowledged.version });
      expect(afterReplay.events).toBe(eventsBefore + 1);
    },
    TIMEOUT_MS,
  );

  it(
    "a kill between the commit and the response's retention is recovered by finalizing the committed revocation from its retained observation, with its original timestamps, never executing it again",
    async () => {
      const port = 14977;
      const issuer = `http://localhost:${port}`;
      const store = newStore();
      const barrierFile = `${store}.barrier`;
      const nonce = `nonce-crash-b-${crypto.randomUUID()}`;
      const first = await start({ issuer, port, store, approve: true, barrier: { nonce, file: barrierFile } });
      expect(first.ready).toMatchObject({ journal: "wal", synchronous: 2, locking: "normal" });
      const missionId = first.ready.missionId as string;
      const eventsBefore = inspect(store, missionId, nonce).events;

      const members = { mission_id: missionId, operation: "revoke", nonce };
      const inFlight = lifecycleRequest(issuer, client, members).then(
        (answer) => ({ answered: true as const, answer }),
        () => ({ answered: false as const }),
      );
      await waitForFile(barrierFile, 30_000);
      await kill(first.child);
      // The child blocked before retaining or sending anything.
      expect((await inFlight).answered).toBe(false);

      expect(existsSync(`${store}-wal`)).toBe(true);
      const afterCrash = inspect(store, missionId, nonce);
      expect(afterCrash.mission.state).toBe("terminated");
      expect(afterCrash.events).toBe(eventsBefore + 1);
      expect(afterCrash.claim?.state).toBe("committed");
      const material = JSON.parse(afterCrash.claim?.material_json as string) as {
        kind: string;
        observation: { iat: number; exp: number; payload: { mission: { version: number; fresh_until: string } } };
      };
      expect(material.kind).toBe("status-observation");
      const observation = material.observation;
      expect(observation.payload.mission.version).toBe(afterCrash.mission.version);

      const second = await start({ issuer, port, store });
      expect(second.ready).toMatchObject({ journal: "wal", synchronous: 2, locking: "normal" });
      const recovered = await lifecycleRequest(issuer, client, members);
      expect(recovered.status, recovered.text).toBe(200);
      const payload = decodeJwt(recovered.text) as { iat: number; exp: number; mission: Record<string, unknown> };
      expect(payload.iat).toBe(observation.iat);
      expect(payload.exp).toBe(observation.exp);
      expect(payload.mission).toMatchObject({
        state: "terminated",
        version: afterCrash.mission.version,
        fresh_until: observation.payload.mission.fresh_until,
      });
      const again = await lifecycleRequest(issuer, client, members);
      expect(again.text).toBe(recovered.text);
      await kill(second.child);

      const afterRecovery = inspect(store, missionId, nonce);
      expect(afterRecovery.claim?.state).toBe("final");
      expect(afterRecovery.mission).toEqual(afterCrash.mission);
      expect(afterRecovery.events).toBe(eventsBefore + 1);
    },
    TIMEOUT_MS,
  );
});
