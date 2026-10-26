/**
 * The child process of lifecycle-crash-restart.test.ts (#1684, D826): an AS on
 * a file-backed kernel store, which its parent kills abruptly. Not a test file.
 *
 * Environment:
 *  - CRASH_ISSUER, CRASH_PORT, CRASH_STORE: the issuer, its port, the store file;
 *  - CRASH_CLIENT: the lifecycle test client's registration metadata (JSON);
 *  - CRASH_APPROVE=1: approve a Mission and report its identifier;
 *  - CRASH_CLOCK_OFFSET_MS: run the AS's clock this far ahead of wall time, so
 *    a restarted child's clock is explicitly later than the one it recovers;
 *  - CRASH_BARRIER_NONCE, CRASH_BARRIER_FILE: the deterministic crash barrier.
 *    When the endpoint retains the response for that nonce, after the
 *    transition's transaction has committed and before the bytes are
 *    retained, the child writes the barrier file synchronously and blocks its
 *    thread, so nothing further happens until the parent kills it.
 *
 * Once listening it sends its parent `ready` with the Mission identifier and
 * its kernel writer connection's journal, synchronous and locking settings.
 */

import { writeFileSync } from "node:fs";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import {
  buildAuthorizationServer,
  type LifecycleNonceKey,
  LifecycleResponseStore,
  MISSION_LIFECYCLE_SCOPE,
  validateMissionIntent,
} from "../src/index.js";

const env = process.env;
const issuer = env.CRASH_ISSUER as string;
const port = Number(env.CRASH_PORT);
const store = env.CRASH_STORE as string;
const client = JSON.parse(env.CRASH_CLIENT as string) as Record<string, unknown> & { client_id: string };
const barrierNonce = env.CRASH_BARRIER_NONCE;
const barrierFile = env.CRASH_BARRIER_FILE;
const clockOffsetMs = Number(env.CRASH_CLOCK_OFFSET_MS ?? 0);

if (barrierNonce && barrierFile) {
  const record = LifecycleResponseStore.prototype.record;
  LifecycleResponseStore.prototype.record = function (this: LifecycleResponseStore, key: LifecycleNonceKey, ...rest) {
    if (key.nonce === barrierNonce) {
      writeFileSync(barrierFile, "reached");
      // Block the thread: no retention, no response, until SIGKILL.
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
    }
    return record.call(this, key, ...rest);
  } as typeof record;
}

const as = await buildAuthorizationServer({
  issuer,
  ...(clockOffsetMs ? { now: () => new Date(Date.now() + clockOffsetMs) } : {}),
  kernelStore: { file: store },
  testClients: [client],
  lifecycleClientGrants: { [client.client_id]: [MISSION_LIFECYCLE_SCOPE] },
});
let missionId: string | undefined;
if (env.CRASH_APPROVE === "1") {
  missionId = as.kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Read Acme invoices", target_resources: [CANONICAL_RESOURCE], expires_at: "2027-01-01T00:00:00Z" }),
    ),
    proposedAuthority: [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] }],
    subject: { iss: issuer, sub: "alice" },
    approver: { iss: issuer, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-crash-${crypto.randomUUID()}`,
  }).id;
}
const server = as.provider.listen(port);
await new Promise<void>((resolve) => server.once("listening", () => resolve()));
process.send?.({
  ready: true,
  missionId,
  journal: String(as.kernel.db.pragma("journal_mode", { simple: true })).toLowerCase(),
  synchronous: as.kernel.db.pragma("synchronous", { simple: true }),
  locking: String(as.kernel.db.pragma("locking_mode", { simple: true })).toLowerCase(),
});
