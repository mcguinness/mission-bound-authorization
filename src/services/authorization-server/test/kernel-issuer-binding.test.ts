/**
 * @spec control-plane#isolation (#1748): one issuer owns a kernel database.
 * The first open records the issuer; an open under another issuer is refused
 * before it writes anything, so a file-backed store never serves a second
 * issuer's namespace. The store's owner still reopens it, with or without a
 * recovery witness, and a refused witnessed open releases the witness's lock.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { generateKeyPair } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  KernelIssuerMismatchError,
  MissionKernel,
  readRecoveryWitness,
  reconcileKernelRecovery,
  validateMissionIntent,
} from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISSUER_A = "https://issuer-a.isolation.test";
const ISSUER_B = "https://issuer-b.isolation.test";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;

let statusKey: CryptoKey;
beforeAll(async () => {
  statusKey = (await generateKeyPair("ES256")).privateKey;
});

const dirs: string[] = [];
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});
const dir = (): string => {
  const d = mkdtempSync(join(tmpdir(), "kernel-issuer-"));
  dirs.push(d);
  return d;
};

function open(issuer: string, store: string, witness?: string): MissionKernel {
  return new MissionKernel({
    issuer,
    policy: DERIVATION_POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["ap-agent"], ["bob"]),
    statusKey,
    statusKid: "status",
    store: { file: store },
    ...(witness ? { recoveryWitness: { file: witness } } : {}),
  });
}

const approve = (kernel: MissionKernel, issuer: string) =>
  kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Pay Acme invoices for Q3", target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" }),
    ),
    subject: { iss: issuer, sub: "alice" },
    approver: { iss: issuer, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: "apev-kernel-issuer-1748",
  });

describe("a kernel store belongs to one issuer (@spec control-plane#isolation, #1748)", () => {
  it("refuses to reopen an ordinary file-backed store under another issuer, and its owner reopens it with its Mission intact", () => {
    const store = join(dir(), "kernel.db");
    const first = open(ISSUER_A, store);
    const { id } = approve(first, ISSUER_A);
    first.close();

    expect(() => open(ISSUER_B, store)).toThrow(KernelIssuerMismatchError);
    expect(() => open(ISSUER_B, store)).toThrow(`the kernel store belongs to ${ISSUER_A}, not ${ISSUER_B}`);

    const again = open(ISSUER_A, store);
    expect(again.get(id)?.issuer).toBe(ISSUER_A);
    again.close();
  });

  it("refuses a witnessed store under another issuer without advancing its witness, and releases the witness's lock so its owner reopens it", () => {
    const store = join(dir(), "kernel.db");
    const witness = join(dir(), "kernel.witness");
    reconcileKernelRecovery({ storeFile: store, witnessFile: witness, action: "init" });
    const first = open(ISSUER_A, store, witness);
    const { id } = approve(first, ISSUER_A);
    first.close();
    const before = readRecoveryWitness(witness);

    expect(() => open(ISSUER_B, store, witness)).toThrow(KernelIssuerMismatchError);
    expect(readRecoveryWitness(witness)).toEqual(before);

    const again = open(ISSUER_A, store, witness);
    expect(again.get(id)?.issuer).toBe(ISSUER_A);
    again.close();
  });
});
