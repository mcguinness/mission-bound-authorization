import { decodeJwt, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { withTransaction } from "@mission/store";
import { DERIVATION_POLICY } from "@mission/demo-data";
import {
  LifecycleConflictError,
  MissionKernel,
  type MissionRecord,
  ObservationWatermarkError,
  validateMissionIntent,
} from "../src/index.js";
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

/**
 * @spec control-plane#fresh-observation — the observation point.
 *
 * The property under test is NOT that a commit during the signature is a
 * defect: an authenticated authoritative observation may be delivered inside
 * its own validity, and a later commit makes the delivered snapshot OLDER
 * without re-dating it. What must hold is that the timestamps belong to the
 * observation, that a retained observation is never re-stamped, that expired
 * signed output is never served as fresh, and that the serving path reads
 * authoritative state.
 */
describe("control-plane state observations", () => {
  it("stamps an observation with its own observation point, not the clock at signature time", async () => {
    const { kernel, record, clock } = setup();
    try {
      const observed = kernel.statusObservation(record.id, { requester: "svc:reader" });
      const observedAt = Math.floor(clock.at.getTime() / 1000);
      expect(observed.iat).toBe(observedAt);
      expect(observed.exp).toBeGreaterThan(observedAt);
      // Two minutes pass before the signature is produced and delivered.
      clock.at = new Date(clock.at.getTime() + 120_000);
      const payload = decodeJwt(await kernel.signObservation(observed));
      expect(payload.iat).toBe(observedAt);
      expect(payload.exp).toBe(observed.exp);
      expect((payload.mission as { fresh_until: string }).fresh_until).toBe(
        new Date(observed.exp * 1000).toISOString(),
      );
      expect(payload.iat).not.toBe(Math.floor(clock.at.getTime() / 1000));
    } finally {
      kernel.db.close();
    }
  });

  it("leaves a snapshot older when state commits during the signature, and re-dates nothing", async () => {
    const { kernel, record, clock } = setup();
    try {
      const observed = kernel.statusObservation(record.id, { requester: "svc:reader" });
      const at = kernel.observationWatermark(record.id);
      expect(observed.watermark).toEqual(at);
      // A narrowing transition commits while the signature is in flight.
      kernel.transition(record.id, "suspend");
      const now = kernel.observationWatermark(record.id);
      expect(now.version).toBeGreaterThan(observed.watermark.version);
      expect(now.commit).toBeGreaterThan(observed.watermark.commit);
      clock.at = new Date(clock.at.getTime() + 5_000);
      const payload = decodeJwt(await kernel.signObservation(observed));
      // The delivered envelope reports the state it observed, at the instant it
      // observed it. It is older than the current state; it is not re-dated,
      // and it carries no freshness it did not have at the observation point.
      expect(payload.iat).toBe(observed.iat);
      expect(payload.exp).toBe(observed.exp);
      expect(payload.mission).toMatchObject({ state: "active", version: observed.watermark.version });
    } finally {
      kernel.db.close();
    }
  });

  it("observes authoritative state, committing an expiry the observation itself materialized", async () => {
    const { kernel, record, commits, clock } = setup();
    try {
      clock.at = new Date("2027-02-01T00:00:00Z");
      const observed = kernel.statusObservation(record.id, { requester: "svc:reader" });
      // The observation read the stored row inside one transaction and the
      // expiry clock materialized there, so the reported state is the one that
      // committed, at the version that commit produced.
      expect(observed.payload.mission).toMatchObject({
        state: "expired",
        version: record.version + 1,
      });
      const stored = kernel.get(record.id);
      expect(stored?.state).toBe("expired");
      expect(stored?.version).toBe(record.version + 1);
      expect(observed.watermark.version).toBe(stored?.version);
      expect(commits).toHaveBeenCalledTimes(1);
      const payload = decodeJwt(await kernel.signObservation(observed));
      expect(payload.mission).toMatchObject({ state: "expired" });
    } finally {
      kernel.db.close();
    }
  });

  it("refuses an advanced observation only under the optional strict watermark policy", async () => {
    const permissive = setup();
    const strict = new MissionKernel({
      issuer: "https://issuer-strict.test",
      policy: DERIVATION_POLICY as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["agent"], ["bob"]),
      statusKey,
      statusKid: "status",
      strictObservationWatermark: true,
    });
    try {
      // Default policy: a commit during the signature does not refuse. The
      // invariant permits delivering the authoritative observation that was
      // taken, inside its own validity.
      const observed = permissive.kernel.statusObservation(permissive.record.id, {
        requester: "svc:reader",
      });
      permissive.kernel.transition(permissive.record.id, "suspend");
      await expect(permissive.kernel.signObservation(observed)).resolves.toContain(".");

      // Opt in, and the same sequence refuses instead. This is a deployment
      // choice that trades churn and reader starvation for a narrower window.
      const record = strict.approve({
        intent: validateMissionIntent(
          JSON.stringify({
            goal: "Read an invoice",
            target_resources: [DERIVATION_POLICY.ceiling[0].resource],
            expires_at: "2027-01-01T00:00:00Z",
          }),
        ),
        subject: { iss: "https://issuer-strict.test", sub: "alice" },
        approver: { iss: "https://issuer-strict.test", sub: "bob" },
        clientId: "agent",
        approvalEventId: "approval-strict",
      });
      const strictObserved = strict.statusObservation(record.id, { requester: "svc:reader" });
      strict.transition(record.id, "suspend");
      await expect(strict.signObservation(strictObserved)).rejects.toThrow(ObservationWatermarkError);
    } finally {
      permissive.kernel.db.close();
      strict.db.close();
    }
  });
});

/**
 * @spec control-plane#serialization — the counter and its artifact.
 *
 * A conditional counter write stops cap overshoot; it does not couple the count
 * to the artifact it paid for. These exercise the reservation ledger's durable
 * operation and artifact identity and its recovery states. The rule under test
 * is that "unreleased" is AMBIGUOUS, so a count is never returned merely
 * because a local acknowledgement is missing.
 */
describe("control-plane derivation reservations", () => {
  const op = (n: number) => ({ operationId: `op-${n}`, artifactId: `art-${n}` });

  it("commits the count and its reservation as one unit", () => {
    const { kernel, record } = setup();
    try {
      expect(() =>
        withTransaction(kernel.db, () => {
          kernel.reserveDerivation(record.id, op(1));
          expect(kernel.get(record.id)?.derivation_count).toBe(1);
          throw new Error("artifact construction failed");
        }),
      ).toThrow("artifact construction failed");
      expect(kernel.get(record.id)?.derivation_count).toBe(0);
      expect(kernel.derivationReservations.find(record.issuer, record.id, "op-1")).toBeUndefined();
    } finally {
      kernel.db.close();
    }
  });

  it("never refunds a reservation that lost only its acknowledgement", async () => {
    const { kernel, record } = setup();
    try {
      const admitted = kernel.reserveDerivation(record.id, op(2));
      expect(admitted.reservation.kind).toBe("reserved");
      expect(kernel.get(record.id)?.derivation_count).toBe(1);
      // The process is lost before the artifact is acknowledged. Recovery
      // records the ambiguity and KEEPS the count: no local acknowledgement is
      // not evidence that no artifact was accepted.
      await kernel.recoverAtBoot();
      const recovered = kernel.derivationReservations.get(
        admitted.reservation.reservation.reservationId,
      );
      expect(recovered?.state).toBe("unacknowledged");
      expect(kernel.get(record.id)?.derivation_count).toBe(1);
      expect(kernel.derivationReservations.unacknowledged()).toHaveLength(1);
    } finally {
      kernel.db.close();
    }
  });

  it("replays a recorded artifact instead of counting a second derivation", () => {
    const { kernel, record } = setup();
    try {
      const first = kernel.reserveDerivation(record.id, op(3));
      kernel.releaseDerivation(first.reservation.reservation.reservationId, {
        artifactId: "art-3",
        completion: JSON.stringify({ grant: "the.signed.artifact" }),
      });
      expect(kernel.get(record.id)?.derivation_count).toBe(1);
      // The same operation identity returns the recorded artifact, so a retry
      // of a committed operation neither counts again nor mints a second
      // artifact. The cap is 1 here, so a second count would refuse outright.
      const retry = kernel.reserveDerivation(record.id, op(3));
      expect(retry.reservation.kind).toBe("replay");
      expect(retry.reservation.reservation.state).toBe("released");
      expect(JSON.parse(retry.reservation.reservation.completion as string)).toEqual({
        grant: "the.signed.artifact",
      });
      expect(kernel.get(record.id)?.derivation_count).toBe(1);
    } finally {
      kernel.db.close();
    }
  });

  it("returns a counted derivation only on an authoritative non-acceptance", async () => {
    const { kernel, record } = setup();
    try {
      const admitted = kernel.reserveDerivation(record.id, op(4));
      const reservationId = admitted.reservation.reservation.reservationId;
      await kernel.recoverAtBoot();
      expect(kernel.get(record.id)?.derivation_count).toBe(1);
      // An authoritative acceptance settles the row and leaves the count spent.
      const other = setup();
      const accepted = other.kernel.reserveDerivation(other.record.id, op(5));
      expect(
        other.kernel.reconcileDerivation(accepted.reservation.reservation.reservationId, {
          accepted: true,
          authority: "svc:issuance-log",
        }),
      ).toBe(true);
      expect(other.kernel.get(other.record.id)?.derivation_count).toBe(1);
      other.kernel.db.close();
      // An authoritative NON-acceptance is the only refund, and it is
      // attributable to the source that asserted it.
      expect(
        kernel.reconcileDerivation(reservationId, {
          accepted: false,
          authority: "svc:issuance-log",
        }),
      ).toBe(true);
      expect(kernel.get(record.id)?.derivation_count).toBe(0);
      const settled = kernel.derivationReservations.get(reservationId);
      expect(settled?.state).toBe("refunded");
      expect(settled?.settledBy).toBe("svc:issuance-log");
      // Settled once: a repeat neither refunds again nor moves the row.
      expect(
        kernel.reconcileDerivation(reservationId, { accepted: false, authority: "svc:issuance-log" }),
      ).toBe(false);
      expect(kernel.get(record.id)?.derivation_count).toBe(0);
    } finally {
      kernel.db.close();
    }
  });
});
