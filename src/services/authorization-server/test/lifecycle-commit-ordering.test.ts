/**
 * @spec status#lifecycle-processing (#1535 finding 9; #1659, D771): a lifecycle
 * transition is committed, with its state version and its nonce claim, before
 * the response that acknowledges it is released, on the file-backed store.
 *
 * The ordering witness reads at response release, the point where the
 * endpoint retains the bytes it is about to deliver, through a SECOND
 * connection to the store file, never the writing one (which can see its own
 * uncommitted writes): the writing connection has no open transaction, and the
 * second connection already sees the transition, its version and the claimed
 * nonce. The kernel's file store is WAL with `synchronous=FULL` (#1684,
 * D826), under normal locking, which this witness's second connection needs:
 * FULL adds a WAL synchronization at each commit, which supports power-loss
 * durability where the storage stack honors synchronization. The
 * configuration assertion states the setting; it proves no hardware failure
 * case. The crash/restart witnesses are lifecycle-crash-restart.test.ts.
 */
import { mkdtempSync, rmSync } from "node:fs";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { openStore } from "@mission/store";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
  type BuiltAs,
  buildAuthorizationServer,
  LIFECYCLE_ENDPOINT_KEY,
  LifecycleResponseStore,
  MISSION_LIFECYCLE_SCOPE,
  type MissionRecord,
  validateMissionIntent,
} from "../src/index.js";
import { type LifecycleTestClient, lifecycleRequest, newLifecycleClient } from "./lifecycle-endpoint.helper.js";

const PORT = 14575;
const ISSUER = `http://localhost:${PORT}`;

let dir: string;
let file: string;
let as: BuiltAs;
let server: Server;
let consoleClient: LifecycleTestClient;
let approvals = 0;

function approve(): MissionRecord {
  approvals += 1;
  return as.kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Read Acme invoices", target_resources: [CANONICAL_RESOURCE], expires_at: "2027-01-01T00:00:00Z" }),
    ),
    proposedAuthority: [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] }],
    subject: { iss: ISSUER, sub: "alice" },
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-commit-ordering-${approvals}`,
  });
}

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "lifecycle-commit-ordering-"));
  file = join(dir, "kernel.db");
  consoleClient = await newLifecycleClient("ordering-console");
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    kernelStore: { file },
    testClients: [consoleClient.metadata],
    lifecycleClientGrants: { [consoleClient.clientId]: [MISSION_LIFECYCLE_SCOPE] },
  });
  server = as.provider.listen(PORT);
  await new Promise<void>((r) => server.once("listening", () => r()));
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
  as.kernel.db.close();
  rmSync(dir, { recursive: true, force: true });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("a lifecycle transition is committed before its acknowledgement is released (@spec status#lifecycle-processing, #1659 D771)", () => {
  it("runs on a WAL store with synchronous FULL under normal locking", () => {
    expect(String(as.kernel.db.pragma("journal_mode", { simple: true })).toLowerCase()).toBe("wal");
    // 2 is FULL (#1684, D826): a WAL synchronization at each commit.
    expect(as.kernel.db.pragma("synchronous", { simple: true })).toBe(2);
    expect(String(as.kernel.db.pragma("locking_mode", { simple: true })).toLowerCase()).toBe("normal");
  });

  it("holds no open transaction at response release, and the committed rows already carry the transition, its version and the claimed nonce; the retransmit replays with no second transition", async () => {
    const m = approve();
    const n = `nonce-ordering-${crypto.randomUUID()}`;
    const before = as.kernel.get(m.id) as MissionRecord;
    type AtRelease = {
      inTransaction: boolean;
      mission: { state: string; version: number };
      claim: { state: string; request_digest: string | null } | undefined;
    };
    let atRelease: AtRelease | undefined;
    const original = LifecycleResponseStore.prototype.record;
    vi.spyOn(LifecycleResponseStore.prototype, "record").mockImplementation(function (
      this: LifecycleResponseStore,
      ...args: Parameters<LifecycleResponseStore["record"]>
    ) {
      // Retention precedes delivery: this runs as the endpoint releases the
      // response, before its bytes leave. A second connection sees only what
      // the writing connection has committed.
      if (!atRelease) {
        const second = openStore("", { file });
        try {
          atRelease = {
            inTransaction: as.kernel.db.inTransaction,
            mission: second.prepare("SELECT state, version FROM missions WHERE id = ?").get(m.id) as AtRelease["mission"],
            claim: second
              .prepare(
                "SELECT state, request_digest FROM lifecycle_responses WHERE endpoint = ? AND principal = ? AND mission_id = ? AND nonce = ?",
              )
              .get(LIFECYCLE_ENDPOINT_KEY, consoleClient.clientId, m.id, n) as AtRelease["claim"],
          };
        } finally {
          second.close();
        }
      }
      return original.apply(this, args);
    });
    const res = await lifecycleRequest(ISSUER, consoleClient, { mission_id: m.id, operation: "suspend", nonce: n });
    expect(res.status, res.text).toBe(200);
    expect(atRelease?.inTransaction).toBe(false);
    expect(atRelease?.mission).toEqual({ state: "suspended", version: before.version + 1 });
    expect(atRelease?.claim?.state).toBe("committed");
    expect(typeof atRelease?.claim?.request_digest).toBe("string");
    vi.restoreAllMocks();
    const replay = await lifecycleRequest(ISSUER, consoleClient, { mission_id: m.id, operation: "suspend", nonce: n });
    expect(replay.status).toBe(200);
    expect(replay.text).toBe(res.text);
    expect(as.kernel.get(m.id)?.version).toBe(before.version + 1);
  });
});
