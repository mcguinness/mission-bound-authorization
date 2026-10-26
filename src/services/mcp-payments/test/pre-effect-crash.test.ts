/**
 * @spec runtime#evidence (pre-effect durability, outcome reconciliation),
 * runtime#execution-capabilities (#821 review P2-2): the crash boundary
 * around a transaction-tier effect, witnessed across an abrupt process exit.
 *
 * The executing PEP and its PDP run in a child process on three durable files
 * (pre-effect-crash.child.ts, over crash-harness.ts). The parent kills it with
 * SIGKILL at a deterministic barrier the child reaches and reports, never at a
 * time, then reopens the same files in this process and reconciles:
 *
 *  - after pre-effect persistence and before the effect: the attempt record
 *    is committed, the connector has not been called;
 *  - after the effect and before outcome retention: the connector committed
 *    the wire in the child's memory, and no Execution Evidence was retained.
 *
 * In both, the identifiers the attempt record preserved (`execution_id`,
 * `op_key`, `evaluation_id`, and the retained Decision Evidence it names)
 * survive; no outcome is recorded for the attempt, before or after its claim
 * closes indeterminate; and neither reconciliation nor a retry under the same
 * key executes the effect again; and neither the PDP nor the PEP reissues a
 * sequence value its records signed before the kill. The connector ledger is the in-memory
 * simulated external resource, so after the second crash no process can see
 * the wire the child made: the outcome stays undetermined rather than being
 * decided from an empty ledger. This is process-crash evidence, not
 * power-loss evidence.
 */

import { type ChildProcess, spawn } from "node:child_process";
import { once } from "node:events";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import type { ExecutionAttemptRecord } from "../src/index.js";
import { CRASH_BASE_MS, CRASH_TOKEN, CRASH_WINDOW_CLOSE_MS, type CrashFiles, crashProcess } from "./crash-harness.js";

const TSX_LOADER = pathToFileURL(createRequire(import.meta.url).resolve("tsx")).href;
const CHILD = fileURLToPath(new URL("./pre-effect-crash.child.ts", import.meta.url));
const TIMEOUT_MS = 90_000;

const dirs: string[] = [];
const children: ChildProcess[] = [];

afterAll(() => {
  for (const child of children) if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

interface BarrierReport {
  barrier: string;
  attempts: ExecutionAttemptRecord[];
  ledger: Array<{ op_key: string; permit_id: string; invoice_id: string }>;
  executions: number;
  records: Array<{ kind: string; sequence?: number; role: string }>;
}

function newFiles(): CrashFiles & { dir: string } {
  const dir = mkdtempSync(join(tmpdir(), "pre-effect-crash-"));
  dirs.push(dir);
  return {
    dir,
    claims: join(dir, "claims.sqlite"),
    reservations: join(dir, "write-reservations.sqlite"),
    retention: join(dir, "evidence-retention.sqlite"),
  };
}

/**
 * Run one wire in a child on `files` until it reports `barrier`, then SIGKILL
 * it: no handler runs, and nothing is flushed or closed by the child.
 */
async function crashAt(barrier: "after-attempt" | "after-effect", files: CrashFiles & { dir: string }, key: string): Promise<BarrierReport> {
  const barrierFile = join(files.dir, `${barrier}.json`);
  const child = spawn(process.execPath, ["--import", TSX_LOADER, CHILD], {
    env: {
      ...process.env,
      CRASH_CLAIMS: files.claims,
      CRASH_RESERVATIONS: files.reservations,
      CRASH_RETENTION: files.retention,
      CRASH_KEY: key,
      CRASH_BARRIER: barrier,
      CRASH_BARRIER_FILE: barrierFile,
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  children.push(child);
  let stderr = "";
  child.stderr?.on("data", (chunk) => {
    stderr += String(chunk);
  });
  const exited = once(child, "exit");
  // The barrier is an event the child reports, not a delay: wait for its
  // file, and fail at once if the child exits without reaching it.
  const until = Date.now() + TIMEOUT_MS;
  while (!existsSync(barrierFile)) {
    if (child.exitCode !== null || child.signalCode !== null) throw new Error(`child exited before ${barrier}: ${stderr}`);
    if (Date.now() > until) throw new Error(`barrier ${barrier} not reached: ${stderr}`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  child.kill("SIGKILL");
  const [, signal] = await exited;
  expect(signal).toBe("SIGKILL");
  return JSON.parse(readFileSync(barrierFile, "utf8")) as BarrierReport;
}

/**
 * Reopen the killed child's files in this process and check what a crash at
 * this boundary must leave: the preserved identifiers, no invented outcome,
 * and no repeated effect, on a retry under the same key included.
 */
async function recoverAndCheck(files: CrashFiles, key: string, report: BarrierReport): Promise<void> {
  const [attempt] = report.attempts;
  if (!attempt) throw new Error("no attempt record at the barrier");
  let at = CRASH_BASE_MS + 1_000;
  const fresh = await crashProcess(files, () => new Date(at));
  try {
    // The identifiers the attempt record preserved survive the kill.
    expect(fresh.writeReservations.attempts()).toEqual(report.attempts);
    const decision = fresh.retention.get("decision", attempt.decisionEvidence.evidenceId);
    expect(decision?.digest).toBe(attempt.decisionEvidence.digest);
    expect((decision?.row as { content: { evaluation_id: string } }).content.evaluation_id).toBe(attempt.evaluationId);
    const outcomes = () =>
      fresh.evidence.all().filter((e) => e.kind === "execution" && e.content.evaluation_id === attempt.evaluationId);
    expect(outcomes()).toEqual([]);
    // Reconciliation decides nothing it cannot establish.
    expect((await fresh.reconciler.runOnce()).claims).toEqual({ settled: [], unredeemed: [], open: [], states: {}, errors: [] });
    expect(outcomes()).toEqual([]);
    // A retry under the same key is refused; nothing executes again.
    expect((await fresh.wire(key)).denial_reason).toBe("duplicate_suppressed");
    expect(fresh.connectors.ledgerEntries()).toEqual([]);
    // The claim closes indeterminate with the declared alert; no outcome is invented.
    at = CRASH_WINDOW_CLOSE_MS;
    await fresh.reconciler.runOnce();
    expect(fresh.alerts.alerts.map((a) => [a.kind, a.evaluation_id])).toEqual([["claim_indeterminate", attempt.evaluationId]]);
    expect(outcomes()).toEqual([]);
    expect(fresh.connectors.ledgerEntries()).toEqual([]);
    expect(fresh.writeReservations.attempts()).toEqual(report.attempts);
    // No emitter reissues a value its records signed before the kill: the
    // PDP's next decision (the refused retry) and the PEP's next record take
    // values past every one the killed child signed.
    const signedBefore = (kind: string) =>
      Math.max(...report.records.filter((r) => r.kind === kind).map((r) => r.sequence as number));
    const decisions = fresh.evidence
      .all()
      .flatMap((e) => (e.kind === "decision" ? [e.content.sequence] : []));
    expect(new Set(decisions).size).toBe(decisions.length);
    expect(Math.max(...decisions)).toBeGreaterThan(signedBefore("decision"));
    await fresh.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-404", idempotency_key: `${key}-y` }, CRASH_TOKEN);
    const refusals = fresh.evidence.all().flatMap((e) => (e.kind === "refusal" ? [e.content.sequence as number] : []));
    expect(new Set(refusals).size).toBe(refusals.length);
    expect(Math.max(...refusals)).toBeGreaterThan(signedBefore("refusal"));
  } finally {
    await fresh.close();
  }
}

describe("the crash boundary around a transaction-tier effect, across SIGKILL (@spec runtime#evidence, #821)", () => {
  it(
    "killed after pre-effect persistence and before the effect: the attempt's identifiers and Decision Evidence survive, no outcome is invented, and nothing executes on reconciliation or a retry",
    async () => {
      const files = newFiles();
      const key = `idem_${crypto.randomUUID()}`;
      const report = await crashAt("after-attempt", files, key);
      // At the barrier the record is committed and the connector was never called.
      expect(report.attempts).toHaveLength(1);
      expect(report.ledger).toEqual([]);
      expect(report.executions).toBe(0);
      await recoverAndCheck(files, key, report);
    },
    TIMEOUT_MS,
  );

  it(
    "killed after the effect and before outcome retention: the attempt's identifiers survive, the outcome stays undetermined rather than decided from an empty ledger, and nothing executes again",
    async () => {
      const files = newFiles();
      const key = `idem_${crypto.randomUUID()}`;
      const report = await crashAt("after-effect", files, key);
      // At the barrier the child's connector holds the wire, named by the
      // attempt record, and no outcome was retained.
      const [attempt] = report.attempts;
      expect(report.ledger.map((e) => [e.op_key, e.permit_id])).toEqual([[attempt?.opKey, attempt?.evaluationId]]);
      expect(report.executions).toBe(0);
      await recoverAndCheck(files, key, report);
    },
    TIMEOUT_MS,
  );
});
