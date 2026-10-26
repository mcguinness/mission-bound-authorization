/**
 * @spec status#lifecycle-processing (#1684, D826): every file-backed kernel
 * writer connection runs WAL with synchronous=FULL (2), on its first open and
 * after reopening, with locking unchanged: normal for the ordinary store, so a
 * second connection can still read it, and exclusive for a witnessed one.
 * These are configuration assertions; FULL supports power-loss durability
 * where the storage stack honors synchronization, which no test here proves.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { openStoreReadOnly } from "@mission/store";
import { generateKeyPair } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MissionKernel, reconcileKernelRecovery } from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISSUER = "https://issuer-durability.test";

let statusKey: CryptoKey;
beforeAll(async () => {
  statusKey = (await generateKeyPair("ES256")).privateKey;
});

const dirs: string[] = [];
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});
const dir = (): string => {
  const d = mkdtempSync(join(tmpdir(), "kernel-durability-"));
  dirs.push(d);
  return d;
};

function open(store: string, witness?: string): MissionKernel {
  return new MissionKernel({
    issuer: ISSUER,
    policy: DERIVATION_POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["agent"], ["bob"]),
    statusKey,
    statusKid: "status",
    store: { file: store },
    ...(witness ? { recoveryWitness: { file: witness } } : {}),
  });
}

const pragma = (kernel: MissionKernel, name: string): unknown => kernel.db.pragma(name, { simple: true });

describe("the kernel store's durability, independent of its locking (@spec status#lifecycle-processing, #1684, D826)", () => {
  it("runs an ordinary file-backed kernel at WAL with synchronous=FULL and normal locking, on its first open and after reopening", () => {
    const store = join(dir(), "kernel.db");
    for (let opened = 0; opened < 2; opened++) {
      const kernel = open(store);
      expect(String(pragma(kernel, "journal_mode")).toLowerCase()).toBe("wal");
      expect(pragma(kernel, "synchronous"), `open ${opened}`).toBe(2);
      expect(String(pragma(kernel, "locking_mode")).toLowerCase()).toBe("normal");
      // Normal locking: a second connection reads the file while the kernel holds it.
      const reader = openStoreReadOnly(store);
      reader.close();
      kernel.close();
    }
  });

  it("runs a witnessed kernel at synchronous=FULL with the exclusive locking it requires, on its first open and after reopening", () => {
    const store = join(dir(), "kernel.db");
    const witness = join(dir(), "kernel.witness");
    reconcileKernelRecovery({ storeFile: store, witnessFile: witness, action: "init" });
    for (let opened = 0; opened < 2; opened++) {
      const kernel = open(store, witness);
      expect(pragma(kernel, "synchronous"), `open ${opened}`).toBe(2);
      expect(String(pragma(kernel, "locking_mode")).toLowerCase()).toBe("exclusive");
      kernel.close();
    }
  });
});
