/**
 * @spec control-plane#rollback (#250 step 3, comment 14): restore admission for
 * the file-backed single-writer kernel with an external recovery witness.
 *
 * Each case drives a real file-backed kernel. A "backup" is the closed store's
 * files copied aside, and a "restore" copies them back, exactly as an operator
 * restoring the database restore unit would. The witness lives in its own
 * directory, outside that unit.
 */

import { copyFileSync, existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { generateKeyPair } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  type LifecycleCommit,
  MissionKernel,
  readRecoveryWitness,
  reconcileKernelRecovery,
  RecoveryReconciliationError,
  RecoveryUncertainError,
  type RecoveryWitnessRecord,
  validateMissionIntent,
} from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISSUER = "https://issuer-recovery.test";
const EXPIRES_AT = "2027-01-01T00:00:00Z";
const T0 = "2026-09-01T00:00:00Z";

let statusKey: CryptoKey;
beforeAll(async () => {
  statusKey = (await generateKeyPair("ES256")).privateKey;
});

const tempDirs: string[] = [];
afterAll(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

/** A store file in one directory and its witness in another, outside the store's restore unit. */
function paths(): { store: string; witness: string; backup: string } {
  const storeDir = mkdtempSync(join(tmpdir(), "mission-recovery-store-"));
  const witnessDir = mkdtempSync(join(tmpdir(), "mission-recovery-witness-"));
  const backupDir = mkdtempSync(join(tmpdir(), "mission-recovery-backup-"));
  tempDirs.push(storeDir, witnessDir, backupDir);
  return { store: join(storeDir, "kernel.db"), witness: join(witnessDir, "kernel.witness"), backup: join(backupDir, "kernel.db") };
}

const SIDE_FILES = ["-wal", "-shm"];

/** Copy a CLOSED store's files aside. */
function backUp(store: string, backup: string): void {
  copyFileSync(store, backup);
  for (const side of SIDE_FILES) if (existsSync(store + side)) copyFileSync(store + side, backup + side);
}

/** Put a backup back in the store's place, as a restore of the database restore unit would. */
function restore(backup: string, store: string): void {
  for (const side of SIDE_FILES) rmSync(store + side, { force: true });
  copyFileSync(backup, store);
  for (const side of SIDE_FILES) if (existsSync(backup + side)) copyFileSync(backup + side, store + side);
}

function open(p: { store: string; witness: string }, commits: LifecycleCommit[] = []): MissionKernel {
  return new MissionKernel({
    issuer: ISSUER,
    policy: DERIVATION_POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["agent"], ["bob"]),
    statusKey,
    statusKid: "status",
    now: () => new Date(T0),
    store: { file: p.store },
    recoveryWitness: { file: p.witness },
    onLifecycleCommit: (commit) => {
      commits.push(commit);
    },
  });
}

let seq = 0;
function approve(kernel: MissionKernel) {
  return kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({
        goal: "Read an invoice",
        target_resources: [DERIVATION_POLICY.ceiling[0].resource],
        expires_at: EXPIRES_AT,
      }),
    ),
    subject: { iss: ISSUER, sub: "alice" },
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "agent",
    approvalEventId: `approval-${seq++}`,
  });
}

const markerSequence = (kernel: MissionKernel): number =>
  (kernel.db.prepare("SELECT sequence FROM recovery_marker").get() as { sequence: number }).sequence;

/** A started store: initialized, then one Mission approved, and closed. */
function started(): { p: ReturnType<typeof paths>; missionId: string; witness: RecoveryWitnessRecord } {
  const p = paths();
  reconcileKernelRecovery({ storeFile: p.store, witnessFile: p.witness, action: "init" });
  const kernel = open(p);
  const missionId = approve(kernel).id;
  kernel.close();
  return { p, missionId, witness: readRecoveryWitness(p.witness) as RecoveryWitnessRecord };
}

/** The uncertainty a constructor refusal carries, failing the test when the kernel opens. */
function refusal(p: { store: string; witness: string }): RecoveryUncertainError {
  try {
    open(p).close();
  } catch (e) {
    expect(e).toBeInstanceOf(RecoveryUncertainError);
    return e as RecoveryUncertainError;
  }
  throw new Error("the kernel opened");
}

describe("recovery witness: admission at boot (@spec control-plane#rollback, #250 step 3)", () => {
  it("an uninitialized store does not open, and opens once init creates the marker and the witness", () => {
    const p = paths();
    expect(refusal(p).reason).toBe("uninitialized");
    const record = reconcileKernelRecovery({ storeFile: p.store, witnessFile: p.witness, action: "init" });
    expect(record).toMatchObject({ generation: 1, committed: 0, intent: null });
    expect(readRecoveryWitness(p.witness)).toEqual(record);
    const kernel = open(p);
    expect(markerSequence(kernel)).toBe(0);
    kernel.close();
  });

  it("a normal restart on the same files opens, with the witness and the marker advanced together by every write transaction", () => {
    const p = paths();
    reconcileKernelRecovery({ storeFile: p.store, witnessFile: p.witness, action: "init" });
    const kernel = open(p);
    const record = approve(kernel);
    kernel.transition(record.id, "suspend");
    const sequence = markerSequence(kernel);
    expect(sequence).toBeGreaterThan(1);
    expect(readRecoveryWitness(p.witness)).toMatchObject({ committed: sequence, intent: null });
    expect(kernel.recoveryUncertainty()).toBeUndefined();
    kernel.close();

    const again = open(p);
    expect(again.get(record.id)?.state).toBe("suspended");
    expect(markerSequence(again)).toBe(sequence);
    again.close();
  });

  it("an older backup restored under the witness is refused, and the witness is never lowered to match it", () => {
    const { p, missionId } = started();
    backUp(p.store, p.backup);
    const kernel = open(p);
    kernel.transition(missionId, "revoke");
    const witnessed = readRecoveryWitness(p.witness) as RecoveryWitnessRecord;
    kernel.close();

    restore(p.backup, p.store);
    const e = refusal(p);
    expect(e.reason).toBe("rollback");
    expect(readRecoveryWitness(p.witness)).toEqual(witnessed);
    // No reconciliation resumes it: neither applies without a pending intent.
    for (const action of ["acknowledge", "abandon"] as const) {
      expect(() => reconcileKernelRecovery({ storeFile: p.store, witnessFile: p.witness, action })).toThrow(RecoveryReconciliationError);
    }
    expect(refusal(p).reason).toBe("rollback");
  });

  it("an older backup is refused the same way after a consumer observed the newer state", () => {
    const { p, missionId } = started();
    backUp(p.store, p.backup);
    const observed: LifecycleCommit[] = [];
    const kernel = open(p, observed);
    kernel.transition(missionId, "suspend");
    kernel.close();
    // A consumer received the suspension's version; the backup predates it.
    const seen = observed.find((c) => c.id === missionId && c.state === "suspended");
    expect(seen).toBeDefined();

    restore(p.backup, p.store);
    expect(refusal(p).reason).toBe("rollback");
  });

  it("a lost witness is refused, and init does not recreate one over a store that has a marker", () => {
    const { p } = started();
    rmSync(p.witness);
    expect(refusal(p).reason).toBe("witness_missing");
    expect(() => reconcileKernelRecovery({ storeFile: p.store, witnessFile: p.witness, action: "init" })).toThrow(
      RecoveryReconciliationError,
    );
    expect(refusal(p).reason).toBe("witness_missing");
  });

  it("a witness behind its store, another store's witness and an unreadable witness are each refused", () => {
    const { p, witness } = started();
    writeFileSync(p.witness, JSON.stringify({ ...witness, committed: witness.committed - 1 }));
    expect(refusal(p).reason).toBe("store_ahead");
    writeFileSync(p.witness, JSON.stringify({ ...witness, store_id: "kst_another" }));
    expect(refusal(p).reason).toBe("identity_mismatch");
    writeFileSync(p.witness, "{ not a witness");
    expect(refusal(p).reason).toBe("witness_unreadable");
    writeFileSync(p.witness, JSON.stringify(witness));
    open(p).close();
  });
});

describe("recovery witness: an intent left pending (@spec control-plane#rollback, #250 step 3)", () => {
  it("an intent written before a commit that never happened: the kernel stops, the restart refuses, and abandon (not acknowledge) resumes the store as it was", () => {
    const { p, missionId } = started();
    const kernel = open(p);
    const before = readRecoveryWitness(p.witness) as RecoveryWitnessRecord;
    const guard = kernel.recovery as unknown as { persist(record: RecoveryWitnessRecord): void };
    const persist = guard.persist.bind(guard);
    // The intent reaches the witness, then the transaction fails before its commit.
    vi.spyOn(guard, "persist").mockImplementationOnce((record) => {
      persist(record);
      throw new Error("injected: the process stops after the witness intent");
    });
    expect(() => kernel.transition(missionId, "suspend")).toThrow(RecoveryUncertainError);
    expect(kernel.recoveryUncertainty()?.reason).toBe("witness_write_failed");
    expect(kernel.get(missionId)?.state).toBe("active");
    // Fail-stop: no later write is accepted.
    expect(() => kernel.transition(missionId, "revoke")).toThrow(RecoveryUncertainError);
    kernel.close();

    expect(readRecoveryWitness(p.witness)).toEqual({ ...before, intent: before.committed + 1 });
    expect(refusal(p).reason).toBe("intent_pending");
    expect(() => reconcileKernelRecovery({ storeFile: p.store, witnessFile: p.witness, action: "acknowledge" })).toThrow(
      RecoveryReconciliationError,
    );
    expect(reconcileKernelRecovery({ storeFile: p.store, witnessFile: p.witness, action: "abandon" })).toEqual(before);
    const resumed = open(p);
    expect(resumed.get(missionId)?.state).toBe("active");
    resumed.transition(missionId, "suspend");
    const after = readRecoveryWitness(p.witness) as RecoveryWitnessRecord;
    expect(after.intent).toBeNull();
    expect(after.committed).toBeGreaterThan(before.committed);
    expect(after.committed).toBe(markerSequence(resumed));
    resumed.close();
  });

  it("a commit whose witness was never finalized: the kernel stops, the restart refuses, and acknowledge (not abandon) resumes the committed state", () => {
    const { p, missionId } = started();
    const kernel = open(p);
    const before = readRecoveryWitness(p.witness) as RecoveryWitnessRecord;
    const guard = kernel.recovery as unknown as { persist(record: RecoveryWitnessRecord): void };
    const persist = guard.persist.bind(guard);
    // The intent is written and the transaction commits; finalizing it fails.
    vi.spyOn(guard, "persist")
      .mockImplementationOnce((record) => persist(record))
      .mockImplementationOnce(() => {
        throw new Error("injected: the witness cannot be finalized");
      });
    expect(() => kernel.transition(missionId, "suspend")).toThrow(RecoveryUncertainError);
    expect(kernel.recoveryUncertainty()?.reason).toBe("witness_write_failed");
    expect(markerSequence(kernel)).toBe(before.committed + 1);
    expect(() => kernel.transition(missionId, "revoke")).toThrow(RecoveryUncertainError);
    kernel.close();

    expect(refusal(p).reason).toBe("intent_pending");
    expect(() => reconcileKernelRecovery({ storeFile: p.store, witnessFile: p.witness, action: "abandon" })).toThrow(
      RecoveryReconciliationError,
    );
    expect(reconcileKernelRecovery({ storeFile: p.store, witnessFile: p.witness, action: "acknowledge" })).toEqual({
      ...before,
      committed: before.committed + 1,
    });
    const resumed = open(p);
    expect(resumed.get(missionId)?.state).toBe("suspended");
    resumed.close();
  });

  it("a commit's lifecycle publication is not delivered when its witness cannot be finalized, and is delivered after reconciliation", async () => {
    const { p, missionId } = started();
    const commits: LifecycleCommit[] = [];
    const kernel = open(p, commits);
    const guard = kernel.recovery as unknown as { persist(record: RecoveryWitnessRecord): void };
    const persist = guard.persist.bind(guard);
    vi.spyOn(guard, "persist")
      .mockImplementationOnce((record) => persist(record))
      .mockImplementationOnce(() => {
        throw new Error("injected: the witness cannot be finalized");
      });
    expect(() => kernel.transition(missionId, "suspend")).toThrow(RecoveryUncertainError);
    expect(commits.filter((c) => c.state === "suspended")).toHaveLength(0);
    kernel.close();

    reconcileKernelRecovery({ storeFile: p.store, witnessFile: p.witness, action: "acknowledge" });
    const resumed = open(p, commits);
    await resumed.recoverAtBoot();
    expect(commits.filter((c) => c.id === missionId && c.state === "suspended")).toHaveLength(1);
    resumed.close();
  });
});

describe("recovery witness: one writer and every write guarded (@spec control-plane#rollback, #250 step 3)", () => {
  it("a second kernel cannot open the store while one holds it, and reconciliation refuses while it is held", () => {
    const { p } = started();
    const first = open(p);
    expect(() => open(p)).toThrow();
    expect(() => reconcileKernelRecovery({ storeFile: p.store, witnessFile: p.witness, action: "abandon" })).toThrow(
      /another writer may hold it/,
    );
    first.close();
    open(p).close();
  });

  it("a bare statement runs as a guarded transaction, and a read-only transaction advances nothing", () => {
    const { p, missionId } = started();
    const kernel = open(p);
    const before = markerSequence(kernel);
    kernel.gateDerivation(missionId); // a bare UPDATE outside any transaction
    expect(markerSequence(kernel)).toBe(before + 1);
    expect(readRecoveryWitness(p.witness)).toMatchObject({ committed: before + 1, intent: null });
    kernel.get(missionId);
    kernel.effectiveAuthoritySet(kernel.get(missionId) as never);
    expect(markerSequence(kernel)).toBe(before + 1);
    expect(kernel.recoveryUncertainty()).toBeUndefined();
    kernel.close();
  });

  it("a write that bypasses the guard stops the kernel at the next guarded transaction", () => {
    const { p, missionId } = started();
    const kernel = open(p);
    // An unwrapped statement, straight from the driver.
    const rawPrepare = Object.getPrototypeOf(kernel.db).prepare as typeof kernel.db.prepare;
    rawPrepare.call(kernel.db, "UPDATE missions SET derivation_count = derivation_count + 1 WHERE id = ?").run(missionId);
    expect(() => kernel.transition(missionId, "suspend")).toThrow(RecoveryUncertainError);
    expect(kernel.recoveryUncertainty()?.reason).toBe("escaped_write");
    kernel.close();
  });

  it("a recovery witness needs a file-backed store", () => {
    expect(
      () =>
        new MissionKernel({
          issuer: ISSUER,
          policy: DERIVATION_POLICY as never,
          authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["agent"], ["bob"]),
          statusKey,
          statusKid: "status",
          recoveryWitness: { file: join(tmpdir(), "unused.witness") },
        }),
    ).toThrow(/needs a file-backed kernel store/);
  });

  it("init refuses a store that already has a marker, and a witness that has advanced", () => {
    const { p, witness } = started();
    expect(() => reconcileKernelRecovery({ storeFile: p.store, witnessFile: p.witness, action: "init" })).toThrow(
      /already has a recovery marker/,
    );
    const fresh = paths();
    writeFileSync(fresh.witness, JSON.stringify(witness));
    expect(() => reconcileKernelRecovery({ storeFile: fresh.store, witnessFile: fresh.witness, action: "init" })).toThrow(
      /witness has advanced/,
    );
  });
});
