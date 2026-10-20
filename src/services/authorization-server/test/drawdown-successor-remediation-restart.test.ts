/**
 * @spec expansion#verification-order step 4 (#1372, D528): a ceiling-drawdown
 * successor that a client other than its predecessor's own requested before
 * the step-4 check existed (#1326) is revoked when the AS is built. A drawdown
 * opens no deferral; its basis records the requesting client as
 * `activation_actor`, while `client_id` is copied from the predecessor, so the
 * successor's own record is the link. A file-backed kernel keeps it across
 * each rebuild.
 *
 * Every drawdown is created by `createCeilingDrawdownInCallerTx` in one
 * transaction, as the exchange's in-ceiling path creates it, without the
 * handler's acting-client check.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CANONICAL_RESOURCE, DERIVATION_POLICY } from "@mission/demo-data";
import { withTransaction } from "@mission/store";
import { afterAll, describe, expect, it } from "vitest";
import {
  buildAuthorizationServer,
  type BuiltAs,
  createChildMission,
  type RegisteredActivationPolicy,
  startupRemediationNotices,
  validateMissionIntent,
} from "../src/index.js";
import { createCeilingDrawdownInCallerTx } from "../src/kernel/progressive.js";
import type { AuthorityEntry, MissionRecord } from "../src/kernel/types.js";

const ISSUER = "http://localhost:14851";
const FAR_EXP = "2099-01-01T00:00:00Z";
const OWN = "ap-agent";
const OTHER = "test-carryover-child";
const dirs: string[] = [];

afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

const POLICY: RegisteredActivationPolicy = {
  version: "1",
  content_type: "application/json",
  content: JSON.stringify({ max_added_actions: 1, ceiling_review_cadence_s: 2_592_000 }),
};
/** The payments ceiling exactly as the derivation policy states it. */
const CEILING = DERIVATION_POLICY.ceiling.filter((e) => e.resource === CANONICAL_RESOURCE) as unknown as AuthorityEntry[];
const reads = (actions: string[]) =>
  [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions, constraints: { vendors: ["acme"] } }] as unknown as AuthorityEntry[];
const intent = (goal: string, expiresAt = FAR_EXP) =>
  validateMissionIntent(JSON.stringify({ goal, target_resources: [CANONICAL_RESOURCE], expires_at: expiresAt }));

const build = (file: string, now?: () => Date): Promise<BuiltAs> =>
  buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    activationPolicies: { "drawdown-std": POLICY },
    kernelStore: { file },
    ...(now ? { now } : {}),
  });

/** Seeding over one assembly, as a deployment before #1340 could leave it. */
function seeding(as: BuiltAs) {
  /** An active Mission whose Approver consented the payments ceiling and the drawdown policy. */
  const predecessor = (): MissionRecord =>
    as.kernel.approve({
      intent: intent("Read Acme invoices"),
      proposedAuthority: reads(["payments:invoice.read"]) as never,
      subject: { iss: ISSUER, sub: "alice" },
      approver: { iss: ISSUER, sub: "bob" },
      clientId: OWN,
      approvalEventId: `pred-${crypto.randomUUID()}`,
      ceiling: { authority_ceiling: CEILING, drawdown_policy: { id: "drawdown-std", version: "1" } },
    });
  /** The in-ceiling successor `requester` requested of `predecessorId`. */
  const drawdown = (predecessorId: string, requester: { iss: string; sub: string }, expiresAt?: string): string => {
    const pred = as.kernel.get(predecessorId) as MissionRecord;
    return withTransaction(as.kernel.db, () =>
      createCeilingDrawdownInCallerTx(as.kernel, {
        predecessorId,
        intent: intent(`Widen ${crypto.randomUUID()}`, expiresAt),
        proposedAuthority: reads(["payments:invoice.read", "payments:invoice.list"]),
        activationActor: requester,
        policy: { ref: pred.drawdown_policy as never, snapshot: POLICY },
      }),
    ).id;
  };
  return { predecessor, drawdown };
}

const lifecycleEvents = (as: BuiltAs): number =>
  (as.kernel.db.prepare("SELECT count(*) AS n FROM lifecycle_events").get() as { n: number }).n;
const versions = (as: BuiltAs): Record<string, number> =>
  Object.fromEntries(as.kernel.allMissions().map((m) => [m.id, m.version]));

describe("drawdown successor remediation at build (@spec expansion#verification-order step 4, #1372)", () => {
  it("revokes the active and suspended drawdown successors another client requested; leaves own-client, terminal and later Missions; reports a foreign activation actor; repeats with no further commit", async () => {
    const dir = mkdtempSync(join(tmpdir(), "drawdown-remediation-"));
    dirs.push(dir);
    const file = join(dir, "kernel.db");
    const startedAt = Date.now();
    const first = await build(file);
    const seed = seeding(first);
    const other = { iss: ISSUER, sub: OTHER };
    const own = { iss: ISSUER, sub: OWN };

    // Targets: active (with a child) and suspended.
    const pActive = seed.predecessor();
    const active = seed.drawdown(pActive.id, other);
    const { child } = createChildMission(first.kernel, {
      parentId: active,
      intent: intent("Extract Acme invoices"),
      proposedAuthority: reads(["payments:invoice.read"]) as never,
      childActor: { sub: "subagent-invoice-extractor", sub_profile: "ai_agent" },
    });
    const pSuspended = seed.predecessor();
    const suspended = seed.drawdown(pSuspended.id, other);
    first.kernel.transition(suspended, "suspend");

    // Terminal before the remediation: completed, and expired by the next boot.
    const pCompleted = seed.predecessor();
    const completed = seed.drawdown(pCompleted.id, other);
    first.kernel.transition(completed, "complete");
    const pExpiring = seed.predecessor();
    const expiring = seed.drawdown(pExpiring.id, other, new Date(startedAt + 10 * 60_000).toISOString());

    // Controls: the predecessor's own client, and a later successor its own
    // client requested from a remediated one.
    const pOwn = seed.predecessor();
    const ownSuccessor = seed.drawdown(pOwn.id, own);
    const pChain = seed.predecessor();
    const chainFirst = seed.drawdown(pChain.id, other);
    const chainLater = seed.drawdown(chainFirst, own);

    // Inconsistent provenance: an activation actor of another issuer.
    const pForeign = seed.predecessor();
    const foreign = seed.drawdown(pForeign.id, { iss: "https://other-issuer.example", sub: OTHER });

    const before = new Map(first.kernel.allMissions().map((m) => [m.id, m]));
    first.kernel.close();

    // Boot 2, an hour on: the expiring successor's own expiry has passed.
    const later = () => new Date(startedAt + 60 * 60_000);
    const second = await build(file, later);
    let afterSecond: { versions: Record<string, number>; events: number };
    try {
      const report = second.startupRemediation.drawdownSuccessors;
      expect([...report.revoked].sort()).toEqual([active, suspended].sort());
      for (const id of report.revoked) {
        expect(second.kernel.get(id)).toMatchObject({
          state: "terminated",
          termination: { reason: "revoked" },
          version: (before.get(id)?.version ?? 0) + 1,
        });
      }
      // The cascade reaches the active successor's child.
      expect(second.kernel.get(child.id)?.termination?.reason).toBe("parent_terminated");
      // Each predecessor stays superseded, byte-identical, naming its successor.
      for (const p of [pActive, pSuspended]) {
        expect(second.kernel.get(p.id)).toEqual(before.get(p.id));
        expect(second.kernel.get(p.id)?.termination?.reason).toBe("superseded");
      }
      // Terminal successors keep their recorded cause: completed, and expired
      // ahead of revocation.
      expect(second.kernel.get(completed)).toEqual(before.get(completed));
      expect(second.kernel.get(expiring)?.termination?.reason).toBe("expired");
      // Controls stay active at their prior versions; the chain's first
      // successor stays superseded.
      for (const id of [ownSuccessor, chainLater, foreign]) {
        expect(second.kernel.get(id)?.state, id).toBe("active");
        expect(second.kernel.get(id)?.version, id).toBe(before.get(id)?.version);
      }
      expect(second.kernel.get(chainFirst)).toEqual(before.get(chainFirst));
      // The foreign activation actor is reported, not acted on.
      expect(report.unresolved).toEqual([
        { successorId: foreign, clientId: OTHER, reason: "the activation actor is not this issuer's" },
      ]);
      expect(startupRemediationNotices(second.startupRemediation).map((n) => n.level)).toEqual(["info", "warn"]);
      afterSecond = { versions: versions(second), events: lifecycleEvents(second) };
    } finally {
      second.kernel.close();
    }

    // Boot 3: nothing left to revoke, no version bump, no lifecycle event.
    const third = await build(file, later);
    try {
      expect(third.startupRemediation.drawdownSuccessors.revoked).toEqual([]);
      expect(third.startupRemediation.drawdownSuccessors.unresolved).toHaveLength(1);
      expect(startupRemediationNotices(third.startupRemediation).map((n) => n.level)).toEqual(["warn"]);
      expect(versions(third)).toEqual(afterSecond.versions);
      expect(lifecycleEvents(third)).toBe(afterSecond.events);
    } finally {
      third.kernel.close();
    }
  });
});
