/**
 * @spec control-plane#isolation (#1748): one issuer owns a kernel database.
 * The first open records the issuer; an open under another issuer is refused
 * before it writes anything, so a file-backed store never serves a second
 * issuer's namespace. The store's owner still reopens it, with or without a
 * recovery witness, and a refused witnessed open releases the witness's lock.
 *
 * A store written before the issuer record existed (simulated by deleting the
 * record) is bound only as its own state allows: an empty one to whichever
 * issuer opens it, a populated one only to the one issuer its state names.
 * State naming another issuer, several or none is refused, and the refused
 * open writes nothing.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { openStoreReadOnly } from "@mission/store";
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

/** A store written before the issuer record existed: the record is deleted before the kernel closes. */
function forgetIssuer(kernel: MissionKernel): void {
  kernel.db.prepare("DELETE FROM kernel_issuer").run();
}

/** The issuer the store records, read from the file after every kernel released it. */
function recordedIssuer(store: string): string | undefined {
  const db = openStoreReadOnly(store);
  try {
    return (db.prepare("SELECT issuer FROM kernel_issuer WHERE k = 1").get() as { issuer: string } | undefined)?.issuer;
  } finally {
    db.close();
  }
}

/** A terminal tombstone for another issuer's Mission, written straight into the store. */
function foreignTombstone(kernel: MissionKernel, issuer: string): void {
  kernel.db
    .prepare("INSERT INTO mission_tombstones (issuer, mission_id, detail_expires_at) VALUES (?, ?, ?)")
    .run(issuer, "msn_foreign_tombstone", 4_102_444_800);
}

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

describe("a kernel store written before the issuer record binds only as its own state allows (@spec control-plane#isolation, #1748)", () => {
  it("refuses another issuer over a populated store without recording anything, then binds it to the issuer its Missions name", () => {
    const store = join(dir(), "kernel.db");
    const first = open(ISSUER_A, store);
    const { id } = approve(first, ISSUER_A);
    forgetIssuer(first);
    first.close();
    expect(recordedIssuer(store)).toBeUndefined();

    expect(() => open(ISSUER_B, store)).toThrow(KernelIssuerMismatchError);
    expect(() => open(ISSUER_B, store)).toThrow(`holds state naming ${ISSUER_A}, so it cannot be bound to ${ISSUER_B}`);
    expect(recordedIssuer(store)).toBeUndefined();

    const owner = open(ISSUER_A, store);
    expect(owner.get(id)?.issuer).toBe(ISSUER_A);
    owner.close();
    expect(recordedIssuer(store)).toBe(ISSUER_A);
    expect(() => open(ISSUER_B, store)).toThrow(`the kernel store belongs to ${ISSUER_A}, not ${ISSUER_B}`);
  });

  it("refuses another issuer over a populated witnessed store without advancing the witness or recording anything, then its owner reopens it", () => {
    const store = join(dir(), "kernel.db");
    const witness = join(dir(), "kernel.witness");
    reconcileKernelRecovery({ storeFile: store, witnessFile: witness, action: "init" });
    const first = open(ISSUER_A, store, witness);
    const { id } = approve(first, ISSUER_A);
    forgetIssuer(first);
    first.close();
    const before = readRecoveryWitness(witness);

    expect(() => open(ISSUER_B, store, witness)).toThrow(KernelIssuerMismatchError);
    expect(readRecoveryWitness(witness)).toEqual(before);
    expect(recordedIssuer(store)).toBeUndefined();

    const owner = open(ISSUER_A, store, witness);
    expect(owner.get(id)?.issuer).toBe(ISSUER_A);
    owner.close();
    expect(recordedIssuer(store)).toBe(ISSUER_A);
  });

  it("binds an empty store to the issuer that opens it", () => {
    const store = join(dir(), "kernel.db");
    const first = open(ISSUER_A, store);
    forgetIssuer(first);
    first.close();

    open(ISSUER_B, store).close();
    expect(recordedIssuer(store)).toBe(ISSUER_B);
  });

  it("binds a store whose only state is a tombstone to that tombstone's issuer, and refuses any other", () => {
    const store = join(dir(), "kernel.db");
    const first = open(ISSUER_A, store);
    foreignTombstone(first, ISSUER_B);
    forgetIssuer(first);
    first.close();

    expect(() => open(ISSUER_A, store)).toThrow(`holds state naming ${ISSUER_B}, so it cannot be bound to ${ISSUER_A}`);
    expect(recordedIssuer(store)).toBeUndefined();
    open(ISSUER_B, store).close();
    expect(recordedIssuer(store)).toBe(ISSUER_B);
  });

  it("refuses every issuer over state naming two issuers, though one of them holds every Mission", () => {
    const store = join(dir(), "kernel.db");
    const first = open(ISSUER_A, store);
    approve(first, ISSUER_A);
    foreignTombstone(first, ISSUER_B);
    forgetIssuer(first);
    first.close();

    for (const issuer of [ISSUER_A, ISSUER_B]) {
      expect(() => open(issuer, store)).toThrow(`holds state naming ${ISSUER_A}, ${ISSUER_B}, so it cannot be bound to ${issuer}`);
    }
    expect(recordedIssuer(store)).toBeUndefined();
  });

  it("refuses every issuer over state that names no issuer", () => {
    const store = join(dir(), "kernel.db");
    const first = open(ISSUER_A, store);
    first.db
      .prepare(
        "INSERT INTO approval_reservations (approval_event_id, approver_iss, approver_sub, subject_iss, subject_sub, client_id, grant_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run("apev-unowned-1748", ISSUER_A, "bob", ISSUER_A, "alice", "ap-agent", "grant-1", "2026-10-28T00:00:00Z");
    forgetIssuer(first);
    first.close();

    for (const issuer of [ISSUER_A, ISSUER_B]) {
      expect(() => open(issuer, store)).toThrow(`holds state naming no issuer, so it opens under no issuer, ${issuer} included`);
    }
    expect(recordedIssuer(store)).toBeUndefined();
  });
});
