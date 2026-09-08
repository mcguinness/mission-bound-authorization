import { generateKeyPair } from "jose";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { withTransaction } from "@mission/store";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { LifecycleConflictError, MissionKernel, type MissionRecord, validateMissionIntent } from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

let statusKey: CryptoKey;
beforeAll(async () => { statusKey = (await generateKeyPair("ES256")).privateKey; });
function setup(issuer = "https://issuer-one.test") {
  const expiresAt = "2027-01-01T00:00:00Z";
  const commits = vi.fn();
  const clock = { at: new Date("2026-09-01T00:00:00Z") };
  const kernel = new MissionKernel({ issuer, policy: DERIVATION_POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["agent"], ["bob"]),
    statusKey, statusKid: "status", now: () => clock.at, onLifecycleCommit: commits });
  const record = kernel.approve({ intent: validateMissionIntent(JSON.stringify({ goal: "Read an invoice", target_resources: [DERIVATION_POLICY.ceiling[0].resource], expires_at: expiresAt, requested_derivation_limit: 1 })),
    subject: { iss: issuer, sub: "alice" }, approver: { iss: issuer, sub: "bob" }, clientId: "agent", approvalEventId: "approval" });
  commits.mockClear();
  return { kernel, record, commits, clock };
}

describe("single-process control-plane fault boundaries", () => {
  it("a stale lifecycle snapshot cannot overwrite a committed version", () => {
    const { kernel, record, commits } = setup();
    try {
      kernel.transition(record.id, "suspend");
      const before = kernel.get(record.id);
      const seam = kernel as unknown as { setState: (record: MissionRecord, state: "revoked") => MissionRecord };
      expect(() => seam.setState(record, "revoked")).toThrow(LifecycleConflictError);
      expect(kernel.get(record.id)).toEqual(before);
      expect(commits).toHaveBeenCalledTimes(1);
    } finally { kernel.db.close(); }
  });
  it("an outer rollback restores lifecycle state and emits no transition", () => {
    const { kernel, record, commits } = setup();
    try {
      expect(() => withTransaction(kernel.db, () => {
        kernel.transition(record.id, "revoke");
        expect(commits).not.toHaveBeenCalled();
        expect(kernel.get(record.id)?.state).toBe("revoked");
        throw new Error("outer fault");
      })).toThrow("outer fault");
      expect(kernel.get(record.id)).toEqual(record);
      expect(commits).not.toHaveBeenCalled();
      kernel.transition(record.id, "revoke");
      expect(commits).toHaveBeenCalledTimes(1);
      expect(commits.mock.calls[0]![0]).toMatchObject({ state: "revoked", version: record.version + 1 });
      expect(Object.isFrozen(commits.mock.calls[0]![0])).toBe(true);
    } finally { kernel.db.close(); }
  });
  it("a counter reservation rolls back with its caller transaction and never exceeds its cap", () => {
    const { kernel, record } = setup();
    try {
      expect(() => withTransaction(kernel.db, () => {
        kernel.gateDerivation(record.id);
        throw new Error("artifact construction failed");
      })).toThrow("artifact construction failed");
      expect(kernel.get(record.id)?.derivation_count).toBe(0);
      expect(kernel.gateDerivation(record.id).derivation_count).toBe(1);
      expect(() => kernel.gateDerivation(record.id)).toThrow("derivation cap exhausted");
      expect(kernel.get(record.id)?.derivation_count).toBe(1);
    } finally { kernel.db.close(); }
  });
  it("a derivation admitted from a stale snapshot cannot overshoot the cap", () => {
    const { kernel, record } = setup();
    const readRecord = kernel.applyExpiry.bind(kernel);
    // The failpoint: the last derivation commits between this caller's read of
    // the record and its own admission write, so the caller holds a snapshot
    // that still shows the cap free. Admission is decided by the stored count
    // in the write, not by that snapshot.
    const gate = vi.spyOn(kernel, "applyExpiry").mockImplementationOnce((r) => {
      const fresh = readRecord(r);
      kernel.db
        .prepare("UPDATE missions SET derivation_count = derivation_count + 1 WHERE id = ?")
        .run(record.id);
      return fresh;
    });
    try {
      expect(() => kernel.gateDerivation(record.id)).toThrow("derivation cap exhausted");
      expect(kernel.get(record.id)?.derivation_count).toBe(1);
    } finally { gate.mockRestore(); kernel.db.close(); }
  });
  it("an expiry materialized under a transition refuses the operation once, at one version", () => {
    const { kernel, record, commits, clock } = setup();
    try {
      clock.at = new Date("2027-02-01T00:00:00Z");
      // The expiry clock materializes `expired` inside this call. The revoke is
      // then illegal from the state that commit left, and the refusal names it.
      expect(() => kernel.transition(record.id, "revoke")).toThrow(LifecycleConflictError);
      expect(() => kernel.transition(record.id, "revoke")).toThrow("expired");
      const after = kernel.get(record.id);
      expect(after?.state).toBe("expired");
      expect(after?.version).toBe(record.version + 1);
      expect(commits).toHaveBeenCalledTimes(1);
      expect(commits.mock.calls[0]![0]).toMatchObject({ state: "expired" });
    } finally { kernel.db.close(); }
  });
  it("one-issuer stores refuse foreign records and independent issuers can retain the same local id", () => {
    const a = setup();
    const b = setup("https://issuer-two.test");
    try {
      expect(() => b.kernel.insertRecord(a.record)).toThrow("record issuer does not own this kernel");
      b.kernel.insertRecord({ ...b.record, id: a.record.id, approval_event_id: "second-approval", status_list_idx: null });
      b.kernel.transition(a.record.id, "revoke");
      expect(b.kernel.get(a.record.id)?.state).toBe("revoked");
      expect(a.kernel.get(a.record.id)?.state).toBe("active");
      expect(a.kernel.get(a.record.id)?.issuer).not.toBe(b.kernel.get(a.record.id)?.issuer);
    } finally { a.kernel.db.close(); b.kernel.db.close(); }
  });
});
