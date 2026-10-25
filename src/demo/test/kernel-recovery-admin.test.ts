/**
 * @spec control-plane#rollback (#250 step 3): `pnpm kernel-recovery`, the
 * offline reconciliation of a kernel store with its recovery witness, driven
 * through `kernelRecoveryAdmin`.
 */
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readRecoveryWitness } from "@mission/authorization-server";
import { afterAll, describe, expect, it } from "vitest";
import { kernelRecoveryAdmin } from "../src/kernel-recovery-admin.js";

const dirs: string[] = [];
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});
function root(): string {
  const dir = mkdtempSync(join(tmpdir(), "kernel-recovery-admin-"));
  dirs.push(dir);
  return dir;
}

describe("pnpm kernel-recovery (@spec control-plane#rollback, #250 step 3)", () => {
  it("init creates the store's marker and its witness, resolving relative paths against the directory pnpm started in, and names both for the AS", () => {
    const dir = root();
    const out = kernelRecoveryAdmin(["init", "--store", "state/kernel.db", "--witness", "witness/kernel.witness"], { INIT_CWD: dir });
    const store = join(dir, "state", "kernel.db");
    const witness = join(dir, "witness", "kernel.witness");
    expect(existsSync(store)).toBe(true);
    expect(readRecoveryWitness(witness)).toMatchObject({ generation: 1, committed: 0, intent: null });
    expect(out).toContain(`start the AS with MISSION_KERNEL_STORE=${store} MISSION_KERNEL_WITNESS=${witness}`);
    // A second init refuses: the store already has its marker.
    expect(() => kernelRecoveryAdmin(["init", "--store", store, "--witness", witness], {})).toThrow(/already has a recovery marker/);
  });

  it("acknowledge, abandon and accept refuse when nothing is pending or recorded", () => {
    const dir = root();
    const store = join(dir, "state", "kernel.db");
    const witness = join(dir, "witness", "kernel.witness");
    kernelRecoveryAdmin(["init", "--store", store, "--witness", witness], {});
    for (const action of ["acknowledge", "abandon"]) {
      expect(() => kernelRecoveryAdmin([action, "--store", store, "--witness", witness], {})).toThrow(/no intent is pending/);
    }
    expect(() => kernelRecoveryAdmin(["accept", "--store", store, "--witness", witness], {})).toThrow(/no uncertainty is recorded/);
  });

  it("refuses a witness in the store's own directory, and an unknown command or flag", () => {
    const dir = root();
    expect(() =>
      kernelRecoveryAdmin(["init", "--store", join(dir, "kernel.db"), "--witness", join(dir, "kernel.witness")], {}),
    ).toThrow(/outside the store's directory/);
    // review: a witness nested inside the store's directory tree, or a store inside the witness's.
    for (const [store, witness] of [
      [join(dir, "state", "kernel.db"), join(dir, "state", "recovery", "kernel.witness")],
      [join(dir, "w", "state", "kernel.db"), join(dir, "w", "kernel.witness")],
    ]) {
      expect(() => kernelRecoveryAdmin(["init", "--store", store, "--witness", witness], {}), witness).toThrow(
        /outside the store's directory/,
      );
    }
    for (const argv of [[], ["restore"], ["init", "--store", join(dir, "a.db")], ["init", "--store", join(dir, "a.db"), "--ring", "x"]]) {
      expect(() => kernelRecoveryAdmin(argv, {}), JSON.stringify(argv)).toThrow(/^usage: pnpm kernel-recovery/);
    }
  });
});
