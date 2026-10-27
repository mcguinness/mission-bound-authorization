/**
 * The child process of pre-effect-crash.test.ts (#821 review P2-2): one
 * executing PEP and its PDP on durable files (`crash-harness.ts`), which runs
 * one wire and is killed by its parent at a deterministic barrier. Not a test
 * file.
 *
 * Environment:
 *  - CRASH_CLAIMS, CRASH_RESERVATIONS, CRASH_RETENTION: the three store files;
 *  - CRASH_KEY: the wire's idempotency key. Before the wire, the child
 *    refuses one request for an invoice the resource does not hold, so the
 *    PEP has signed a record of its own under the Mission;
 *  - CRASH_BARRIER: `after-attempt` (the attempt record is committed, before
 *    the effect) or `after-effect` (the connector committed, before any
 *    outcome is retained);
 *  - CRASH_BARRIER_FILE: where the child reports reaching the barrier. It
 *    writes what it holds there (the attempt record, the connector ledger),
 *    atomically, then blocks its thread, so nothing further happens until the
 *    parent kills it with SIGKILL.
 */

import { renameSync, writeFileSync } from "node:fs";
import { Connectors, WriteReservationStore } from "../src/index.js";
import { CRASH_BASE_MS, CRASH_TOKEN, crashProcess } from "./crash-harness.js";

const env = process.env;
const barrier = env.CRASH_BARRIER as "after-attempt" | "after-effect";
const barrierFile = env.CRASH_BARRIER_FILE as string;

const proc = await crashProcess(
  { claims: env.CRASH_CLAIMS as string, reservations: env.CRASH_RESERVATIONS as string, retention: env.CRASH_RETENTION as string },
  () => new Date(CRASH_BASE_MS),
);

/** Report the barrier, then block: no further statement runs until SIGKILL. */
function stopHere(): never {
  const report = JSON.stringify({
    barrier,
    attempts: proc.writeReservations.attempts(),
    ledger: proc.connectors.ledgerEntries(),
    executions: proc.evidence.all().filter((e) => e.kind === "execution").length,
    records: proc.evidence.all().flatMap((e) =>
      e.kind === "decision" || e.kind === "refusal" || e.kind === "execution"
        ? [{ kind: e.kind, sequence: e.content.sequence, role: e.content.emitter.role }]
        : [],
    ),
  });
  writeFileSync(`${barrierFile}.tmp`, report);
  renameSync(`${barrierFile}.tmp`, barrierFile);
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
  throw new Error("unreachable");
}

if (barrier === "after-attempt") {
  const recordAttempt = WriteReservationStore.prototype.recordAttempt;
  WriteReservationStore.prototype.recordAttempt = function (this: WriteReservationStore, input) {
    recordAttempt.call(this, input);
    return stopHere();
  } as typeof recordAttempt;
} else {
  const postWire = Connectors.prototype.postWire;
  Connectors.prototype.postWire = function (this: Connectors, input) {
    postWire.call(this, input);
    return stopHere();
  } as typeof postWire;
}

await proc.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-404", idempotency_key: `${env.CRASH_KEY}-x` }, CRASH_TOKEN);
await proc.wire(env.CRASH_KEY as string);
// Reaching here means the barrier was never hit.
process.exit(3);
