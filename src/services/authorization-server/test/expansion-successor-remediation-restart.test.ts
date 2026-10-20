/**
 * @spec expansion#verification-order step 4 (#1349, D516): a successor that a
 * client other than its predecessor's own created by polling a deferral before
 * the poll check existed (#1326) is revoked when the AS is built, as its
 * retained committed deferral identifies it. The successor carries the
 * predecessor's client, so the deferral is the link. A file-backed kernel
 * keeps the deferrals and Missions across each rebuild.
 *
 * Every fixture is seeded through the stores: `redeem` called directly is the
 * completion a pre-#1340 poll ran, without the handler's acting-client check.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { afterAll, describe, expect, it } from "vitest";
import { FIXTURE_BROWSER_LOGIN } from "./approval-fixture.js";
import {
  buildAuthorizationServer,
  type BuiltAs,
  createChildMission,
  startupRemediationNotices,
  validateMissionIntent,
} from "../src/index.js";
import type { MissionRecord } from "../src/kernel/types.js";

const ISSUER = "http://localhost:14849";
const FAR_EXP = "2099-01-01T00:00:00Z";
const OWN = "ap-agent";
const OTHER = "test-carryover-child";
const dirs: string[] = [];

afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

const intent = (goal: string, expiresAt = FAR_EXP) =>
  validateMissionIntent(JSON.stringify({ goal, target_resources: [CANONICAL_RESOURCE], expires_at: expiresAt }));

const authority = (actions: string[]) => [
  {
    type: "mission_resource_access",
    resource: CANONICAL_RESOURCE,
    actions,
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];
const WIDE = ["payments:invoice.read", "payments:remittance.send"];

const build = (file: string, now?: () => Date): Promise<BuiltAs> =>
  buildAuthorizationServer({ issuer: ISSUER, allowHeadlessAdjudication: true, kernelStore: { file }, ...(now ? { now } : {}) });

/** Seeding over one assembly, as a deployment before #1340 could leave it. */
function seeding(as: BuiltAs) {
  const predecessor = (): MissionRecord =>
    as.kernel.approve({
      intent: intent("Pay Acme invoices"),
      proposedAuthority: authority(["payments:invoice.read"]) as never,
      subject: { iss: ISSUER, sub: "alice" },
      approver: { iss: ISSUER, sub: "bob" },
      clientId: OWN,
      approvalEventId: `pred-${crypto.randomUUID()}`,
    });
  /** A widening deferral `clientId` opened on `predecessorId`. */
  const open = (predecessorId: string, clientId: string, expiresAt?: string): string =>
    as.expansionDeferrals.open({
      predecessorId,
      intent: intent(`Widen ${crypto.randomUUID()}`, expiresAt),
      proposedAuthority: authority(WIDE) as never,
      clientId,
      jkt: "seeded",
      creationRequestId: crypto.randomUUID(),
    }).deferral_code;
  const approve = (code: string, approvalEventId = `apev-${crypto.randomUUID()}`): void =>
    as.expansionDeferrals.approve(code, {
      approver: { iss: ISSUER, sub: "bob" },
      authentication: FIXTURE_BROWSER_LOGIN,
      approvalEventId,
      approvedUntil: FAR_EXP,
    });
  /** The committed completion: the successor it created. */
  const redeem = (code: string): string => {
    const r = as.expansionDeferrals.redeem(code);
    if ("error" in r) throw new Error(`redeem refused: ${r.error}`);
    return r.successor.id;
  };
  /** A deferral `clientId` opened, approved and completed: the successor. */
  const expand = (predecessorId: string, clientId: string, expiresAt?: string): { code: string; successor: string } => {
    const code = open(predecessorId, clientId, expiresAt);
    approve(code);
    return { code, successor: redeem(code) };
  };
  return { predecessor, open, approve, redeem, expand };
}

const lifecycleEvents = (as: BuiltAs): number =>
  (as.kernel.db.prepare("SELECT count(*) AS n FROM lifecycle_events").get() as { n: number }).n;
const versions = (as: BuiltAs): Record<string, number> =>
  Object.fromEntries(as.kernel.allMissions().map((m) => [m.id, m.version]));

describe("successor remediation at build (@spec expansion#verification-order step 4, #1349)", () => {
  it("revokes the active, suspended, committed-but-unreleased and late-denied successors another client's deferral created; leaves own-client, terminal, later and unrelated Missions; repeats with no further commit", async () => {
    const dir = mkdtempSync(join(tmpdir(), "successor-remediation-"));
    dirs.push(dir);
    const file = join(dir, "kernel.db");
    const startedAt = Date.now();
    const first = await build(file);
    const seed = seeding(first);

    // Targets: active (with a child), suspended, committed but not released.
    const pActive = seed.predecessor();
    const active = seed.expand(pActive.id, OTHER);
    const { child } = createChildMission(first.kernel, {
      parentId: active.successor,
      intent: intent("Extract Acme invoices"),
      proposedAuthority: authority(["payments:invoice.read"]) as never,
      childActor: { sub: "subagent-invoice-extractor", sub_profile: "ai_agent" },
    });
    const pSuspended = seed.predecessor();
    const suspended = seed.expand(pSuspended.id, OTHER);
    first.kernel.transition(suspended.successor, "suspend");
    const pUnreleased = seed.predecessor();
    const unreleased = seed.expand(pUnreleased.id, OTHER);
    first.expansionDeferrals.db
      .prepare("UPDATE expansion_deferrals SET completion_released = 0 WHERE deferral_code = ?")
      .run(unreleased.code);
    // Denied after its completion committed: `deny` rewrites the deferral's
    // state, not its completion marker or links.
    const pLateDenied = seed.predecessor();
    const lateDenied = seed.expand(pLateDenied.id, OTHER);
    first.expansionDeferrals.deny(lateDenied.code);

    // Terminal before the remediation: completed, and expired by the next boot.
    const pCompleted = seed.predecessor();
    const completed = seed.expand(pCompleted.id, OTHER);
    first.kernel.transition(completed.successor, "complete");
    const pExpiring = seed.predecessor();
    const expiring = seed.expand(pExpiring.id, OTHER, new Date(startedAt + 10 * 60_000).toISOString());

    // Controls: the predecessor's own client; a later successor its own client
    // approved from a remediated one; wrong-client pending and denied deferrals
    // on a predecessor its own client then expanded.
    const pOwn = seed.predecessor();
    const own = seed.expand(pOwn.id, OWN);
    const pChain = seed.predecessor();
    const chainFirst = seed.expand(pChain.id, OTHER);
    const chainLater = seed.expand(chainFirst.successor, OWN);
    const pUnrelated = seed.predecessor();
    seed.open(pUnrelated.id, OTHER);
    const denied = seed.open(pUnrelated.id, OTHER);
    seed.approve(denied);
    first.expansionDeferrals.deny(denied);
    const unrelatedOwn = seed.expand(pUnrelated.id, OWN);

    // Incomplete provenance: retired, but no successor carries its approval event.
    const pIncomplete = seed.predecessor();
    const incomplete = seed.open(pIncomplete.id, OTHER);
    seed.approve(incomplete);
    first.expansionDeferrals.db.prepare("UPDATE expansion_deferrals SET redeemed = 1 WHERE deferral_code = ?").run(incomplete);
    // Contradictory provenance: another client's deferral, completed through
    // the recovery path, claims the successor the predecessor's own deferral
    // created under the same approval event.
    const pShared = seed.predecessor();
    const sharedOther = seed.open(pShared.id, OTHER);
    const sharedOwn = seed.open(pShared.id, OWN);
    seed.approve(sharedOwn, "apev-shared");
    const sharedSuccessor = seed.redeem(sharedOwn);
    seed.approve(sharedOther, "apev-shared");
    expect(seed.redeem(sharedOther)).toBe(sharedSuccessor);

    const before = new Map(first.kernel.allMissions().map((m) => [m.id, m]));
    first.kernel.close();

    // Boot 2, an hour on: the expiring successor's own expiry has passed.
    const later = () => new Date(startedAt + 60 * 60_000);
    const second = await build(file, later);
    let afterSecond: { versions: Record<string, number>; events: number };
    try {
      const report = second.startupRemediation.successors;
      expect([...report.revoked].sort()).toEqual(
        [active.successor, suspended.successor, unreleased.successor, lateDenied.successor].sort(),
      );
      for (const id of report.revoked) {
        const m = second.kernel.get(id);
        expect(m?.state).toBe("terminated");
        expect(m?.termination?.reason).toBe("revoked");
        expect(m?.version).toBe((before.get(id)?.version ?? 0) + 1);
      }
      // The cascade reaches the active successor's child.
      expect(second.kernel.get(child.id)?.termination?.reason).toBe("parent_terminated");
      // Each predecessor stays superseded, byte-identical, naming its successor.
      for (const p of [pActive, pSuspended, pUnreleased, pLateDenied]) {
        expect(second.kernel.get(p.id)).toEqual(before.get(p.id));
        expect(second.kernel.get(p.id)?.termination?.reason).toBe("superseded");
      }
      // Terminal successors keep their recorded cause: completed, and expired
      // ahead of revocation.
      expect(second.kernel.get(completed.successor)).toEqual(before.get(completed.successor));
      expect(second.kernel.get(expiring.successor)?.termination?.reason).toBe("expired");
      // Controls stay active, and the chain's first successor stays superseded.
      for (const id of [own.successor, chainLater.successor, unrelatedOwn.successor, sharedSuccessor, pIncomplete.id]) {
        expect(second.kernel.get(id)?.state, id).toBe("active");
        expect(second.kernel.get(id)?.version, id).toBe(before.get(id)?.version);
      }
      expect(second.kernel.get(chainFirst.successor)).toEqual(before.get(chainFirst.successor));
      // The two inconsistent deferrals are reported, not acted on.
      expect(report.unresolved).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ deferralCode: incomplete, predecessorId: pIncomplete.id, clientId: OTHER, reason: "no successor carries the deferral's approval event" }),
          expect.objectContaining({ deferralCode: sharedOther, predecessorId: pShared.id, clientId: OTHER, reason: "a deferral the predecessor's own client opened claims the same approval event" }),
        ]),
      );
      expect(report.unresolved).toHaveLength(2);
      // The launchers log both: the revocations, and a warning for the rest.
      expect(startupRemediationNotices(second.startupRemediation).map((n) => n.level)).toEqual(["info", "warn"]);
      // The retained provenance is untouched.
      expect(
        second.expansionDeferrals.db
          .prepare("SELECT redeemed, completion_released FROM expansion_deferrals WHERE deferral_code = ?")
          .get(unreleased.code),
      ).toEqual({ redeemed: 1, completion_released: 0 });
      afterSecond = { versions: versions(second), events: lifecycleEvents(second) };
    } finally {
      second.kernel.close();
    }

    // Boot 3: nothing left to revoke, no version bump, no lifecycle event.
    const third = await build(file, later);
    try {
      expect(third.startupRemediation.successors.revoked).toEqual([]);
      expect(third.startupRemediation.successors.unresolved).toHaveLength(2);
      expect(startupRemediationNotices(third.startupRemediation).map((n) => n.level)).toEqual(["warn"]);
      expect(versions(third)).toEqual(afterSecond.versions);
      expect(lifecycleEvents(third)).toBe(afterSecond.events);
    } finally {
      third.kernel.close();
    }
  });

  it("attempts the family-grant revocation of a successor the expiry clock terminates before the AS is returned, when the sweep revokes nothing", async () => {
    const dir = mkdtempSync(join(tmpdir(), "successor-remediation-expiry-"));
    dirs.push(dir);
    const file = join(dir, "kernel.db");
    const startedAt = Date.now();
    const first = await build(file);
    const pExpiring = seeding(first).predecessor();
    const expiring = seeding(first).expand(pExpiring.id, OTHER, new Date(startedAt + 10 * 60_000).toISOString());
    first.delegationFamilyStore.record({ grantId: `grant-${crypto.randomUUID()}`, missionId: expiring.successor });
    first.kernel.close();

    const second = await build(file, () => new Date(startedAt + 60 * 60_000));
    try {
      expect(second.startupRemediation.successors.revoked).toEqual([]);
      expect(second.kernel.get(expiring.successor)?.termination?.reason).toBe("expired");
      expect(
        second.kernel.db
          .prepare(
            `SELECT d.disposition AS disposition, d.attempts AS attempts
               FROM lifecycle_deliveries d JOIN lifecycle_events e ON e.seq = d.seq
              WHERE e.mission_id = ? AND d.subscriber = 'delegation-family-grant-revoke'`,
          )
          .all(expiring.successor),
      ).toEqual([{ disposition: "accepted", attempts: 1 }]);
    } finally {
      second.kernel.close();
    }
  });

  it("reports, and neither revokes nor expires, a committed deferral whose predecessor or successor is another issuer's, or whose predecessor, approval event, supersession or client disagrees (#1392)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "successor-remediation-provenance-"));
    dirs.push(dir);
    const file = join(dir, "kernel.db");
    const startedAt = Date.now();
    const first = await build(file);
    const seed = seeding(first);
    const FOREIGN = "https://foreign.example";
    // Inconsistent storage, not what the exchange writes: each successor is
    // created as a pre-#1340 poll created it, then one provenance field is altered.
    const sql = (statement: string, ...values: unknown[]) => first.kernel.db.prepare(statement).run(...values);
    const setIssuer = (id: string) => sql("UPDATE missions SET issuer = ? WHERE id = ?", FOREIGN, id);

    // The predecessor is another issuer's.
    const pForeign = seed.predecessor();
    const foreignPredecessor = seed.expand(pForeign.id, OTHER);
    setIssuer(pForeign.id);
    // The successor is another issuer's. Its own expiry has passed by the
    // next boot, and the sweep does not apply it.
    const pForeignSuccessor = seed.predecessor();
    const foreignSuccessor = seed.expand(pForeignSuccessor.id, OTHER, new Date(startedAt + 10 * 60_000).toISOString());
    setIssuer(foreignSuccessor.successor);
    // Both are another issuer's, agreeing with each other.
    const pForeignPair = seed.predecessor();
    const foreignPair = seed.expand(pForeignPair.id, OTHER);
    setIssuer(pForeignPair.id);
    setIssuer(foreignPair.successor);
    // The deferral's predecessor names no record.
    const pUnlinked = seed.predecessor();
    const unlinked = seed.expand(pUnlinked.id, OTHER);
    sql("UPDATE expansion_deferrals SET predecessor_id = ? WHERE deferral_code = ?", "msn_missing", unlinked.code);
    // The deferral records no approval event.
    const pNoEvent = seed.predecessor();
    const noEvent = seed.expand(pNoEvent.id, OTHER);
    sql("UPDATE expansion_deferrals SET approval_event_id = NULL WHERE deferral_code = ?", noEvent.code);
    // (Two Missions under one approval event cannot be stored:
    // `missions.approval_event_id` is UNIQUE.)
    // The predecessor's supersession names another Mission.
    const pMisnamed = seed.predecessor();
    const misnamed = seed.expand(pMisnamed.id, OTHER);
    sql(
      "UPDATE missions SET termination_json = ? WHERE id = ?",
      JSON.stringify({ ...(first.kernel.get(pMisnamed.id) as MissionRecord).termination, successor: "msn_other" }),
      pMisnamed.id,
    );
    // The successor does not carry its predecessor's client.
    const pReassigned = seed.predecessor();
    const reassigned = seed.expand(pReassigned.id, OTHER);
    sql("UPDATE missions SET client_id = ? WHERE id = ?", "another-client", reassigned.successor);
    // A consistent target beside them, so the sweep demonstrably ran.
    const pTarget = seed.predecessor();
    const target = seed.expand(pTarget.id, OTHER);

    const before = new Map(first.kernel.allMissions().map((m) => [m.id, m]));
    first.kernel.close();

    const second = await build(file, () => new Date(startedAt + 60 * 60_000));
    try {
      const report = second.startupRemediation.successors;
      expect(report.revoked).toEqual([target.successor]);
      const untouched = [foreignPredecessor, foreignSuccessor, foreignPair, unlinked, noEvent, misnamed, reassigned];
      for (const { successor } of untouched) {
        expect(second.kernel.get(successor), successor).toEqual(before.get(successor));
      }
      const entry = (op: { code: string }, predecessorId: string, reason: string) => ({
        deferralCode: op.code,
        predecessorId,
        clientId: OTHER,
        reason,
      });
      expect(report.unresolved).toEqual(
        expect.arrayContaining([
          entry(foreignPredecessor, pForeign.id, "the predecessor is not this issuer's"),
          entry(foreignSuccessor, pForeignSuccessor.id, "the successor is not this issuer's"),
          entry(foreignPair, pForeignPair.id, "the predecessor is not this issuer's"),
          entry(unlinked, "msn_missing", "the predecessor record is missing"),
          entry(noEvent, pNoEvent.id, "the deferral records no approval event"),
          entry(misnamed, pMisnamed.id, "the predecessor's supersession does not name the successor"),
          entry(reassigned, pReassigned.id, "the successor does not carry the predecessor's client"),
        ]),
      );
      expect(report.unresolved).toHaveLength(7);
    } finally {
      second.kernel.close();
    }
  });
});
