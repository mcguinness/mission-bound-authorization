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

    // The intent may have reached the witness, so the failure is recorded over it.
    expect(readRecoveryWitness(p.witness)).toMatchObject({
      ...before,
      intent: before.committed + 1,
      uncertain: { reason: "witness_write_failed" },
    });
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

  it("a witnessed store does not open without its witness, so nothing writes to it unwitnessed; a store that never had a witness still opens", () => {
    const { p, missionId } = started();
    const unwitnessed = (file: string) =>
      new MissionKernel({
        issuer: ISSUER,
        policy: DERIVATION_POLICY as never,
        authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["agent"], ["bob"]),
        statusKey,
        statusKid: "status",
        now: () => new Date(T0),
        store: { file },
      });
    let refused: unknown;
    try {
      unwitnessed(p.store).close();
    } catch (e) {
      refused = e;
    }
    expect(refused).toBeInstanceOf(RecoveryUncertainError);
    expect((refused as RecoveryUncertainError).reason).toBe("witness_missing");
    // The refused open wrote nothing and released the store: it opens with its witness, unchanged.
    const kernel = open(p);
    expect(kernel.get(missionId)?.state).toBe("active");
    kernel.close();
    unwitnessed(paths().store).close();
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

describe("recovery witness: review fixes (@spec control-plane#rollback, #250 step 3)", () => {
  it("review: a copied store cannot share the witness: the witness is fenced across store paths, and the copy is refused afterwards rather than lowering it", () => {
    const { p, missionId } = started();
    backUp(p.store, p.backup);
    const first = open(p);
    let second: unknown;
    try {
      open({ store: p.backup, witness: p.witness }).close();
    } catch (e) {
      second = e;
    }
    expect(second).toBeInstanceOf(RecoveryUncertainError);
    expect((second as RecoveryUncertainError).reason).toBe("witness_locked");
    first.transition(missionId, "revoke");
    const revoked = (readRecoveryWitness(p.witness) as RecoveryWitnessRecord).committed;
    first.close();
    // The copy, opened once the original released the witness, is older than it.
    expect(refusal({ store: p.backup, witness: p.witness }).reason).toBe("rollback");
    expect((readRecoveryWitness(p.witness) as RecoveryWitnessRecord).committed).toBe(revoked);
    const kept = open(p);
    expect(kept.get(missionId)?.state).toBe("terminated");
    kept.close();
  });

  it("review: a mutating statement run through get, all, iterate, a chained builder or exec is guarded: the witness advances and nothing escapes", () => {
    const { p, missionId } = started();
    const kernel = open(p);
    const sequence = () => markerSequence(kernel);
    const steps: Array<() => unknown> = [
      () => kernel.db.prepare("UPDATE missions SET derivation_count = derivation_count + 1 WHERE id = ? RETURNING derivation_count").get(missionId),
      () => kernel.db.prepare("UPDATE missions SET derivation_count = derivation_count + 1 WHERE id = ? RETURNING id").all(missionId),
      () => [...kernel.db.prepare("UPDATE missions SET derivation_count = derivation_count + 1 WHERE id = ? RETURNING id").iterate(missionId)],
      () => kernel.db.prepare("UPDATE missions SET derivation_count = derivation_count + 1 WHERE id = ? RETURNING derivation_count").pluck().get(missionId),
      () => kernel.db.exec("UPDATE missions SET derivation_count = derivation_count + 1"),
    ];
    for (const [i, step] of steps.entries()) {
      const before = sequence();
      step();
      expect(sequence(), String(i)).toBe(before + 1);
      expect(readRecoveryWitness(p.witness), String(i)).toMatchObject({ committed: before + 1, intent: null });
    }
    kernel.transition(missionId, "suspend");
    expect(kernel.recoveryUncertainty()).toBeUndefined();
    kernel.close();
    open(p).close();
  });

  it("review: an escaped write is recorded in the witness, so a restart refuses until accept takes the store under a new generation", () => {
    const { p, missionId } = started();
    const kernel = open(p);
    const rawPrepare = Object.getPrototypeOf(kernel.db).prepare as typeof kernel.db.prepare;
    rawPrepare.call(kernel.db, "UPDATE missions SET derivation_count = derivation_count + 1 WHERE id = ?").run(missionId);
    expect(() => kernel.transition(missionId, "suspend")).toThrow(RecoveryUncertainError);
    expect(kernel.recoveryUncertainty()?.reason).toBe("escaped_write");
    kernel.close();

    expect(readRecoveryWitness(p.witness)?.uncertain?.reason).toBe("escaped_write");
    expect(refusal(p).reason).toBe("escaped_write");
    for (const action of ["acknowledge", "abandon"] as const) {
      expect(() => reconcileKernelRecovery({ storeFile: p.store, witnessFile: p.witness, action })).toThrow(/no intent is pending/);
    }
    const accepted = reconcileKernelRecovery({ storeFile: p.store, witnessFile: p.witness, action: "accept" });
    expect(accepted).toMatchObject({ generation: 2, intent: null });
    expect(accepted.uncertain).toBeUndefined();
    const resumed = open(p);
    expect(resumed.get(missionId)?.state).toBe("active");
    resumed.transition(missionId, "suspend");
    resumed.close();
  });

  it("a witness rewritten underneath a running kernel stops it, the change is recorded over what is on disk, and accept never lowers the witness", () => {
    const { p, missionId, witness } = started();
    const kernel = open(p);
    // Another writer, as if the lock were defeated, advanced the witness.
    writeFileSync(p.witness, JSON.stringify({ ...witness, committed: witness.committed + 5 }));
    expect(() => kernel.transition(missionId, "suspend")).toThrow(RecoveryUncertainError);
    expect(kernel.recoveryUncertainty()?.reason).toBe("witness_moved");
    kernel.close();
    expect(readRecoveryWitness(p.witness)).toMatchObject({ committed: witness.committed + 5, uncertain: { reason: "witness_moved" } });
    expect(refusal(p).reason).toBe("witness_moved");
    // The store is older than the witness it would be accepted under.
    expect(() => reconcileKernelRecovery({ storeFile: p.store, witnessFile: p.witness, action: "accept" })).toThrow(/older than the witnessed/);
  });

  it("accept refuses with nothing recorded, and with an intent pending", () => {
    const { p, witness } = started();
    expect(() => reconcileKernelRecovery({ storeFile: p.store, witnessFile: p.witness, action: "accept" })).toThrow(/no uncertainty is recorded/);
    writeFileSync(
      p.witness,
      JSON.stringify({ ...witness, intent: witness.committed + 1, uncertain: { reason: "commit_failed", detail: "test" } }),
    );
    expect(() => reconcileKernelRecovery({ storeFile: p.store, witnessFile: p.witness, action: "accept" })).toThrow(/acknowledge or abandon/);
  });

  it("reconciliation of another store is refused while a kernel holds the witness", () => {
    const { p } = started();
    const kernel = open(p);
    try {
      expect(() =>
        reconcileKernelRecovery({ storeFile: paths().store, witnessFile: p.witness, action: "init" }),
      ).toThrow(/the witness is held/);
    } finally {
      kernel.close();
    }
  });

  it("review: a witness inside the store's directory tree, or a store inside the witness's, is refused by the kernel and by reconciliation", () => {
    const root = mkdtempSync(join(tmpdir(), "mission-recovery-tree-"));
    tempDirs.push(root);
    const store = join(root, "state", "kernel.db");
    for (const witness of [join(root, "state", "recovery", "kernel.witness"), join(root, "state", "kernel.witness")]) {
      expect(() => reconcileKernelRecovery({ storeFile: store, witnessFile: witness, action: "init" })).toThrow(
        /outside the store's directory/,
      );
      expect(() => open({ store, witness })).toThrow(/outside the store's directory/);
    }
    expect(() =>
      reconcileKernelRecovery({ storeFile: join(root, "w", "state", "kernel.db"), witnessFile: join(root, "w", "kernel.witness"), action: "init" }),
    ).toThrow(/outside the store's directory/);
  });
});
