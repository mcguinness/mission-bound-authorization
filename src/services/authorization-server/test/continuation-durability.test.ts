/**
 * @spec control-plane#serialization, id-continuation-assertion, async-delegation
 * (#250 step 2): the continuation and delegation-family projections live on the
 * kernel's database and are written in its committing transactions.
 *
 * Covered here:
 *  - the approval-time root commits with the activating transition: a refused
 *    root refuses the Mission with it;
 *  - terminal propagation commits with the terminal transition, beside the
 *    tombstone, so a commit whose publication fails still leaves no live
 *    lineage; a suspension terminates nothing;
 *  - a retried publication of an activation, replayed after the Mission
 *    terminated, roots nothing: each commit is published on its own, so a
 *    failed activation never holds back a later revoke;
 *  - on a file-backed kernel, anchors, handles and families survive a restart
 *    and nothing is rooted again at boot; a lineage terminated before the
 *    restart stays terminal after it;
 *  - a durable delivery still pending at shutdown is attempted at boot.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CANONICAL_RESOURCE, DERIVATION_POLICY } from "@mission/demo-data";
import { type CryptoKey, generateKeyPair } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  type BuiltAs,
  buildAuthorizationServer,
  type LifecycleCommit,
  MissionKernel,
  type MissionRecord,
  validateMissionIntent,
} from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const KERNEL_ISSUER = "https://issuer-durability.test";
const EXPIRES_AT = "2027-01-01T00:00:00Z";

let statusKey: CryptoKey;
let approvals = 0;

beforeAll(async () => {
  statusKey = (await generateKeyPair("ES256")).privateKey;
});

/** A kernel on its own in-memory database, publishing through `publish`. */
function kernelWith(publish: (commit: LifecycleCommit) => void): MissionKernel {
  return new MissionKernel({
    issuer: KERNEL_ISSUER,
    policy: DERIVATION_POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["agent"], ["bob"]),
    statusKey,
    statusKid: "status",
    now: () => new Date("2026-09-01T00:00:00Z"),
    onLifecycleCommit: publish,
  });
}

function approveOnKernel(kernel: MissionKernel, approvalEventId: string): MissionRecord {
  return kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Read an invoice", target_resources: [DERIVATION_POLICY.ceiling[0].resource], expires_at: EXPIRES_AT }),
      { now: kernel.nowDate() },
    ),
    subject: { iss: KERNEL_ISSUER, sub: "alice" },
    approver: { iss: KERNEL_ISSUER, sub: "bob" },
    clientId: "agent",
    approvalEventId,
  });
}

const count = (kernel: MissionKernel, table: string, missionId: string): number =>
  (kernel.db.prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE mission_id = ?`).get(missionId) as { n: number }).n;

const missionIdFor = (kernel: MissionKernel, approvalEventId: string): string | undefined =>
  (kernel.db.prepare("SELECT id FROM missions WHERE approval_event_id = ?").get(approvalEventId) as
    | { id: string }
    | undefined)?.id;

const isActivating = (commit: LifecycleCommit): boolean =>
  commit.version === 1 && commit.prior_state === undefined && commit.state === "active";

describe("continuation and delegation-family projections in the committing transaction (#250)", () => {
  it("roots an activated Mission in its activating commit: a refused root refuses the Mission with it", () => {
    const kernel = kernelWith(() => {});
    try {
      kernel.db.exec(
        `CREATE TRIGGER fail_root BEFORE INSERT ON continuation_handles
         BEGIN SELECT RAISE(ABORT, 'injected root failure'); END;`,
      );
      expect(() => approveOnKernel(kernel, "apev-dur-atomic")).toThrow("injected root failure");
      expect(missionIdFor(kernel, "apev-dur-atomic")).toBeUndefined();
      expect((kernel.db.prepare("SELECT COUNT(*) AS n FROM continuation_anchors").get() as { n: number }).n).toBe(0);
      kernel.db.exec("DROP TRIGGER fail_root");

      // Without the fault, the Mission, one anchor and one handle commit together.
      const record = approveOnKernel(kernel, "apev-dur-atomic");
      expect(count(kernel, "continuation_anchors", record.id)).toBe(1);
      expect(count(kernel, "continuation_handles", record.id)).toBe(1);
      const [handle] = kernel.continuations.handlesForMission(record.id);
      expect(kernel.continuations.lookup(handle as string)).toMatchObject({
        status: "active",
        continuation: { missionId: record.id, audience: KERNEL_ISSUER, actor: { iss: KERNEL_ISSUER, sub: "agent" } },
      });
    } finally { kernel.close(); }
  });

  it("terminates every lineage in the terminal commit, so a failed publication still leaves none live; a suspension terminates nothing", () => {
    let failTerminal = false;
    const kernel = kernelWith((commit) => {
      if (failTerminal && commit.state === "terminated") throw new Error("injected publication failure");
    });
    try {
      const record = approveOnKernel(kernel, "apev-dur-terminal");
      const [handle] = kernel.continuations.handlesForMission(record.id);
      kernel.delegationFamilies.record({ grantId: "grant-dur-terminal", missionId: record.id });

      kernel.transition(record.id, "suspend");
      expect(kernel.continuations.lookup(handle as string).status).toBe("active");
      expect(kernel.delegationFamilies.resolve("grant-dur-terminal")).toEqual({ missionId: record.id, state: "active" });
      kernel.transition(record.id, "resume");

      failTerminal = true;
      // The revoke commits; its publication then fails.
      expect(() => kernel.transition(record.id, "revoke")).toThrow("injected publication failure");
      expect(kernel.get(record.id)?.termination?.reason).toBe("revoked");
      expect(kernel.continuations.lookup(handle as string).status).toBe("terminal");
      expect(kernel.delegationFamilies.resolve("grant-dur-terminal")).toBeUndefined();
      expect(kernel.delegationFamilies.familiesForMission(record.id)).toEqual(["grant-dur-terminal"]);
    } finally { kernel.close(); }
  });

  it("roots nothing when an activation whose publication failed is replayed after the Mission terminated", () => {
    let failActivation = true;
    const kernel = kernelWith((commit) => {
      if (failActivation && isActivating(commit)) throw new Error("injected publication failure");
    });
    try {
      // The approval commits; its publication fails and stays owed.
      expect(() => approveOnKernel(kernel, "apev-dur-replay")).toThrow("injected publication failure");
      const id = missionIdFor(kernel, "apev-dur-replay") as string;
      expect(id).toBeDefined();
      failActivation = false;
      // The revoke is published on its own, ahead of the owed activation.
      kernel.transition(id, "revoke");
      expect(kernel.publishPendingCommits()).toBe(1);

      expect(count(kernel, "continuation_anchors", id)).toBe(1);
      expect(count(kernel, "continuation_handles", id)).toBe(1);
      for (const handle of kernel.continuations.handlesForMission(id)) {
        expect(kernel.continuations.lookup(handle).status).toBe("terminal");
      }
    } finally { kernel.close(); }
  });
});

describe("continuation and delegation-family projections across a restart (#250)", () => {
  const RESTART_ISSUER = "http://localhost:14853";
  const dirs: string[] = [];
  afterAll(() => {
    for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
  });

  const proposal = (): AuthorityEntry[] => [
    { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] },
  ];

  function approveOnAs(as: BuiltAs): MissionRecord {
    approvals += 1;
    return as.kernel.approve({
      intent: validateMissionIntent(
        JSON.stringify({ goal: "Read invoices for the close", target_resources: [CANONICAL_RESOURCE], expires_at: EXPIRES_AT }),
        { now: as.kernel.nowDate() },
      ),
      proposedAuthority: proposal(),
      subject: { iss: RESTART_ISSUER, sub: "alice" },
      approver: { iss: RESTART_ISSUER, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: `apev-dur-restart-${approvals}`,
    });
  }

  const boot = (file: string): Promise<BuiltAs> =>
    buildAuthorizationServer({ issuer: RESTART_ISSUER, kernelStore: { file } });

  const deliveries = (as: BuiltAs, subscriber: string, missionId: string): string[] =>
    (
      as.kernel.db
        .prepare(
          `SELECT d.disposition FROM lifecycle_deliveries d JOIN lifecycle_events e ON e.seq = d.seq
           WHERE d.subscriber = ? AND json_extract(e.commit_json, '$.id') = ? ORDER BY d.seq`,
        )
        .all(subscriber, missionId) as Array<{ disposition: string }>
    ).map((r) => r.disposition);

  it("keeps anchors, handles and families across a restart, roots nothing again at boot, and keeps a terminated lineage terminal", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mission-continuation-"));
    dirs.push(dir);
    const file = join(dir, "kernel.db");

    const first = await boot(file);
    const live = approveOnAs(first);
    const revoked = approveOnAs(first);
    const [liveHandle] = first.continuationStore.handlesForMission(live.id);
    const [revokedHandle] = first.continuationStore.handlesForMission(revoked.id);
    first.delegationFamilyStore.record({ grantId: "grant-dur-live", missionId: live.id });
    first.delegationFamilyStore.record({ grantId: "grant-dur-revoked", missionId: revoked.id });
    first.kernel.transition(revoked.id, "revoke");
    first.suspensionScheduler?.stop();
    first.kernel.close();

    const second = await boot(file);
    try {
      // The lineage rooted before the restart resolves after it, and boot
      // recovery rooted nothing again.
      expect(count(second.kernel, "continuation_anchors", live.id)).toBe(1);
      expect(count(second.kernel, "continuation_handles", live.id)).toBe(1);
      expect(second.continuationStore.lookup(liveHandle as string)).toMatchObject({
        status: "active",
        continuation: { missionId: live.id, audience: RESTART_ISSUER, actor: { iss: RESTART_ISSUER, sub: "ap-agent" } },
      });
      expect(second.delegationFamilyStore.resolve("grant-dur-live")).toEqual({ missionId: live.id, state: "active" });

      // The lineage terminated before the restart stays terminal after it.
      expect(second.continuationStore.lookup(revokedHandle as string).status).toBe("terminal");
      expect(second.delegationFamilyStore.resolve("grant-dur-revoked")).toBeUndefined();
      expect(second.delegationFamilyStore.familiesForMission(revoked.id)).toEqual(["grant-dur-revoked"]);
      // The provider's grants are not part of this: oidc-provider's memory
      // adapter is process-global, so an in-process rebuild still holds them,
      // while a process restart does not. async-delegation.test.ts drops them
      // to witness a recovered family whose grant is gone.
    } finally {
      second.suspensionScheduler?.stop();
      second.kernel.close();
    }
  });

  it("attempts at boot a family revocation still pending at shutdown, and acknowledges it once nothing is left to revoke", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mission-continuation-"));
    dirs.push(dir);
    const file = join(dir, "kernel.db");

    const first = await boot(file);
    const record = approveOnAs(first);
    first.delegationFamilyStore.record({ grantId: "grant-dur-pending", missionId: record.id });
    // A direct transition drains nothing: the delivery it owes stays pending.
    first.kernel.transition(record.id, "revoke");
    expect(deliveries(first, "delegation-family-grant-revoke", record.id)).toEqual(["pending"]);
    first.suspensionScheduler?.stop();
    first.kernel.close();

    const second = await boot(file);
    try {
      expect(deliveries(second, "delegation-family-grant-revoke", record.id)).toEqual(["accepted"]);
    } finally {
      second.suspensionScheduler?.stop();
      second.kernel.close();
    }
  });
});
