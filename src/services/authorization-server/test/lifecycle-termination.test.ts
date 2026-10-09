/**
 * @spec mission#lifecycle, mission#termination, status#mission-status-response,
 * status#legal-transitions, child-delegation#cascade (#705)
 *
 * The termination vocabulary end to end at the kernel: a Mission is `active`,
 * `suspended` or `terminated`, and a terminated Mission carries a
 * `termination` whose `reason` says why. These are the #705 witness tests:
 * every emitter speaks only the three states; `termination` is present exactly
 * when terminated and carries the members its reason requires; a legacy row
 * reads fail closed without invented members; expiry and the ancestor
 * projection are observations that hold whether or not (and even when) the
 * write materializing them fails; an earlier recorded cause is never replaced;
 * a child's own expiry outranks its parent's termination; idempotency compares
 * the reason; and the Approval Context Manifest's `approver` digest stands.
 */

import { approvalContextCommitment, approvalContextManifest } from "@mission/core";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { type CryptoKey, generateKeyPair } from "jose";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { gateErrorToMissionError } from "../src/adapters/provider.js";
import {
  type AuthorityEntry,
  createChildMission,
  createExpansion,
  GateError,
  LifecycleConflictError,
  type LifecycleCommit,
  MissionKernel,
  type MissionRecord,
  STATUS_INVALID,
  STATUS_SUSPENDED,
  STATUS_VALID,
  stateToBit,
} from "../src/index.js";
import { aiAgents } from "./actor-profiles.helper.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISS = "https://as.test";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const T0 = "2026-07-01T00:00:00Z";
const PARENT_EXP = "2027-01-01T00:00:00Z";
const STATES = new Set(["active", "suspended", "terminated"]);

const proposed = (actions: string[]): AuthorityEntry[] => [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions,
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];

let key: CryptoKey;
let kernel: MissionKernel;
let clock: Date;
let commits: LifecycleCommit[];
let seq = 0;

beforeAll(async () => {
  key = (await generateKeyPair("ES256")).privateKey;
});

beforeEach(() => {
  clock = new Date(T0);
  commits = [];
  kernel = new MissionKernel({
    issuer: ISS,
    policy: DERIVATION_POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["parent-agent"], ["bob"]),
    statusKey: key,
    statusKid: "as-status",
    now: () => clock,
    actorProfiles: aiAgents("child-agent", "grandchild-agent"),
    onLifecycleCommit: (c) => commits.push(c),
  });
});

// Validated against the kernel's own (injected) clock, not wall time.
const intentOf = (expiresAt: string, goal = "Pay Acme invoices for Q3") =>
  kernel.validateIntent(JSON.stringify({ goal, target_resources: [RESOURCE], expires_at: expiresAt }));

const approve = (expiresAt = PARENT_EXP): MissionRecord =>
  kernel.approve({
    intent: intentOf(expiresAt),
    proposedAuthority: proposed(["payments:invoice.read", "payments:payment.execute"]),
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "parent-agent",
    approvalEventId: `apev-term-${seq++}`,
  });

const childOf = (parentId: string, sub = "child-agent", expiresAt = PARENT_EXP): MissionRecord =>
  createChildMission(kernel, {
    parentId,
    intent: intentOf(expiresAt, "Read Acme invoices"),
    proposedAuthority: proposed(["payments:invoice.read"]),
    childActor: { sub, sub_profile: "ai_agent" },
  }).child;

const supersede = (predecessorId: string): MissionRecord => {
  const { successor } = createExpansion(kernel, {
    predecessorId,
    intent: intentOf(PARENT_EXP, "Pay Acme invoices for Q3 (widened)"),
    proposedAuthority: proposed(["payments:invoice.read", "payments:payment.execute"]),
    approver: { iss: ISS, sub: "bob" },
    approvalEventId: `apev-succ-${seq++}`,
    approvedUntil: PARENT_EXP,
  });
  expect(kernel.supersedeOnRedemption(successor.id)).toBe(true);
  return successor;
};

const statusMission = (id: string) =>
  kernel.statusObservation(id, { requester: "svc:reader" }).payload.mission as Record<string, unknown>;

/** A SQLite trigger that makes every write to `terminated` fail: the injected materialization fault. */
const failTerminationWrites = () =>
  kernel.db.exec(
    `CREATE TRIGGER fail_termination BEFORE UPDATE OF state ON missions WHEN NEW.state = 'terminated'
     BEGIN SELECT RAISE(ABORT, 'injected materialization failure'); END;`,
  );
const restoreTerminationWrites = () => kernel.db.exec("DROP TRIGGER fail_termination");

const gateReason = (fn: () => unknown): string => {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(GateError);
    return (e as GateError).reason;
  }
  throw new Error("expected a gate refusal");
};

describe("termination on every emitter (#705 witnesses 1 and 2)", () => {
  it("reports only active, suspended or terminated, with termination present exactly when terminated and carrying every member its reason requires", () => {
    const revoked = approve();
    const completed = approve();
    const expiring = approve("2026-07-01T01:00:00Z");
    const predecessor = approve();
    const parent = approve();
    const child = childOf(parent.id);
    const live = approve();
    const held = approve();

    kernel.transition(revoked.id, "revoke");
    kernel.transition(completed.id, "complete");
    const successor = supersede(predecessor.id);
    const parentRevoked = kernel.transition(parent.id, "revoke");
    kernel.transition(held.id, "suspend");
    clock = new Date("2026-07-01T02:00:00Z");
    kernel.materializeExpiry(expiring.id);

    // The members each reason requires, beyond reason / terminated_at / version.
    const expected: Array<[MissionRecord, Record<string, unknown>]> = [
      [revoked, { reason: "revoked" }],
      [completed, { reason: "completed" }],
      [expiring, { reason: "expired", terminated_at: expiring.expires_at }],
      [predecessor, { reason: "superseded", successor: successor.id }],
      [
        child,
        {
          reason: "parent_terminated",
          parent: parent.id,
          terminated_at: parentRevoked.termination?.terminated_at,
          origin: parent.id,
          origin_reason: "revoked",
        },
      ],
    ];
    for (const [record, members] of expected) {
      const stored = kernel.get(record.id) as MissionRecord;
      expect(stored.state, record.id).toBe("terminated");
      expect(stored.termination).toMatchObject(members);
      expect(typeof stored.termination?.terminated_at).toBe("string");
      // Committed by this kernel: `version` is the committing transition's.
      expect(stored.termination?.version).toBe(stored.version);
      // Status response, introspection (ungated and caller-gated), the
      // lifecycle operation result: `termination` beside `state`.
      const status = statusMission(record.id);
      expect(status.state).toBe("terminated");
      expect(status.termination).toEqual(stored.termination);
      expect(kernel.introspectionMission(stored)).toMatchObject({ state: "terminated", termination: stored.termination });
      const projected = kernel.introspectionProjection(stored, { disclose: new Set() });
      expect(projected).toMatchObject({ state: "terminated", termination: stored.termination });
      for (const surface of [status, projected]) {
        expect(surface).not.toHaveProperty("successor");
        expect(surface).not.toHaveProperty("carried_to");
      }
      // Status List input: every termination reason is INVALID.
      expect(stateToBit(kernel.observe(stored).state)).toBe(STATUS_INVALID);
    }
    // A Mission that is not terminated carries no termination anywhere.
    for (const record of [live, held, successor]) {
      const stored = kernel.get(record.id) as MissionRecord;
      expect(stored).not.toHaveProperty("termination");
      expect(statusMission(record.id)).not.toHaveProperty("termination");
      expect(kernel.introspectionProjection(stored, { disclose: new Set() })).not.toHaveProperty("termination");
    }
    expect(stateToBit(kernel.observe(kernel.get(live.id) as MissionRecord).state)).toBe(STATUS_VALID);
    expect(stateToBit(kernel.observe(kernel.get(held.id) as MissionRecord).state)).toBe(STATUS_SUSPENDED);
    // The lifecycle commit (the Signals SET's source): only the three states,
    // `prior_state` never terminal, `termination` present exactly when
    // terminated with its `version` equal to the commit's, and no top-level
    // reference member.
    expect(commits.length).toBeGreaterThan(0);
    for (const commit of commits) {
      expect(STATES.has(commit.state), commit.state).toBe(true);
      if (commit.prior_state !== undefined) expect(["active", "suspended"]).toContain(commit.prior_state);
      expect(commit).not.toHaveProperty("successor");
      expect(commit).not.toHaveProperty("carried_to");
      if (commit.state === "terminated") {
        expect(commit.termination?.version).toBe(commit.version);
        expect(typeof commit.termination?.terminated_at).toBe("string");
      } else {
        expect(commit).not.toHaveProperty("termination");
      }
    }
    const supersession = commits.find((c) => c.id === predecessor.id && c.state === "terminated");
    expect(supersession?.termination).toMatchObject({ reason: "superseded", successor: successor.id });
  });
});

describe("legacy rows read fail closed and normalized (#705 witness 3)", () => {
  const raw = (id: string, sets: string, ...args: unknown[]) =>
    kernel.db.prepare(`UPDATE missions SET ${sets} WHERE id = ?`).run(...args, id);
  const storedState = (id: string) =>
    (kernel.db.prepare("SELECT state FROM missions WHERE id = ?").get(id) as { state: string }).state;

  it("reads each legacy terminal state as terminated with that reason, folding retained references and inventing no member", () => {
    const revoked = approve();
    const expired = approve();
    const completed = approve();
    const superseded = approve();
    const parent = approve();
    const cascaded = childOf(parent.id);
    // A legacy terminal transition bumped the state version, as a real one did.
    raw(revoked.id, "state = 'revoked', version = 2");
    raw(expired.id, "state = 'expired', version = 2");
    raw(completed.id, "state = 'completed', version = 2");
    raw(superseded.id, "state = 'superseded', successor = ?, version = 2", "msn_legacy_successor");
    raw(cascaded.id, "state = 'cascaded', carried_to = ?, version = 2", "msn_legacy_replacement");

    // Retained facts only (#705 owner rulings): the committing transition's
    // `version`, and for `expired` the record's own `expires_at`. A row
    // retains no commit time, so no other `terminated_at` is filled in.
    expect(kernel.get(revoked.id)?.termination).toEqual({ reason: "revoked", version: 2 });
    expect(kernel.get(expired.id)?.termination).toEqual({
      reason: "expired",
      terminated_at: expired.expires_at,
      version: 2,
    });
    expect(kernel.get(completed.id)?.termination).toEqual({ reason: "completed", version: 2 });
    expect(kernel.get(superseded.id)?.termination).toEqual({
      reason: "superseded",
      successor: "msn_legacy_successor",
      version: 2,
    });
    // `cascaded` reads as `parent_terminated`, its parent from the lineage.
    expect(kernel.get(cascaded.id)?.termination).toEqual({
      reason: "parent_terminated",
      parent: parent.id,
      carried_to: "msn_legacy_replacement",
      version: 2,
    });
    for (const record of [revoked, expired, completed, superseded, cascaded]) {
      const read = kernel.get(record.id) as MissionRecord;
      expect(read.state).toBe("terminated");
      expect(read).not.toHaveProperty("successor");
      expect(read).not.toHaveProperty("carried_to");
      // Fail closed at the gate, and every surface reports the normalized view.
      expect(() => kernel.gateActive(record.id)).toThrow(GateError);
      expect(statusMission(record.id)).toMatchObject({ state: "terminated", termination: read.termination });
    }
    for (const record of [revoked, completed, superseded, cascaded]) {
      expect(kernel.get(record.id)?.termination).not.toHaveProperty("terminated_at");
    }
    // A read-side view: the stored rows are never rewritten.
    expect(storedState(revoked.id)).toBe("revoked");
    expect(storedState(cascaded.id)).toBe("cascaded");
  });

  it("reads an unrecognized state, a malformed termination and a stray termination fail closed, never active", () => {
    const unknown = approve();
    const malformed = approve();
    const reasonless = approve();
    const stray = approve();
    raw(unknown.id, "state = 'quantum_supervened'");
    raw(malformed.id, "state = 'terminated', termination_json = ?", "{not json");
    raw(reasonless.id, "state = 'terminated', termination_json = ?", JSON.stringify({ terminated_at: T0 }));
    raw(stray.id, "termination_json = ?", JSON.stringify({ reason: "revoked", terminated_at: T0, version: 2 }));

    expect(kernel.get(unknown.id)).toMatchObject({ state: "terminated", termination: { reason: "quantum_supervened" } });
    expect(kernel.get(malformed.id)?.termination).toEqual({ reason: "unknown" });
    expect(kernel.get(reasonless.id)?.termination).toEqual({ reason: "unknown" });
    // A termination stored beside a non-terminal state is inconsistent: terminated.
    expect(kernel.get(stray.id)?.state).toBe("terminated");
    for (const record of [unknown, malformed, reasonless, stray]) {
      expect(gateReason(() => kernel.gateActive(record.id))).toBe("mission_not_active");
      expect(kernel.observedRecord(record.id)?.state).toBe("terminated");
    }
    // An unrecognized or unreadable reason carries no mission_error.
    expect(gateErrorToMissionError("mission_not_active", kernel.observedRecord(unknown.id))).toBeUndefined();
    expect(gateErrorToMissionError("mission_not_active", kernel.observedRecord(malformed.id))).toBeUndefined();
  });

  it("reads a legacy tombstone's terminal state as terminated with that reason", () => {
    kernel.db
      .prepare(
        `INSERT INTO mission_tombstones (issuer, mission_id, terminal_state, final_version, transition_at,
           commit_event_id, detail_expires_at) VALUES (?, ?, 'cascaded', 3, ?, 'set_legacy', ?)`,
      )
      .run(ISS, "msn_legacy_tombstone", T0, Date.parse(PARENT_EXP));
    expect(kernel.tombstones.find(ISS, "msn_legacy_tombstone")).toMatchObject({
      terminalState: "terminated",
      terminationReason: "parent_terminated",
      finalVersion: 3,
    });
  });
});

describe("computed expiry (#705 witness 4)", () => {
  for (const start of ["active", "suspended"] as const) {
    it(`${start === "active" ? "an" : "a"} ${start} Mission at its expires_at is terminated expired at every gate before materialization, and when the materializing write throws`, () => {
      const record = approve("2026-07-01T01:00:00Z");
      if (start === "suspended") kernel.transition(record.id, "suspend");
      const before = kernel.get(record.id) as MissionRecord;
      commits.length = 0;
      // Exactly at expires_at: the boundary is inclusive.
      clock = new Date(record.expires_at);
      const expired = { reason: "expired", terminated_at: record.expires_at };

      // Before any write: the pure observation.
      const observed = kernel.observe(before);
      expect(observed).toMatchObject({ state: "terminated", termination: expired });
      expect(observed.termination).not.toHaveProperty("version");
      expect(kernel.get(record.id)?.state).toBe(start);

      // Every gate and emitter, with the materializing write failing.
      failTerminationWrites();
      expect(gateReason(() => kernel.gateActive(record.id))).toBe("mission_expired");
      expect(gateReason(() => kernel.gateDerivation(record.id))).toBe("mission_expired");
      expect(gateErrorToMissionError("mission_expired", kernel.observedRecord(record.id))).toBe("expired");
      const status = statusMission(record.id);
      expect(status).toMatchObject({ state: "terminated", termination: expired, version: before.version });
      expect(status.termination).not.toHaveProperty("version");
      expect(kernel.introspectionProjection(before, { disclose: new Set() })).toMatchObject({
        state: "terminated",
        termination: expired,
      });
      expect(() => kernel.transition(record.id, "revoke")).toThrow(LifecycleConflictError);
      expect(() => kernel.transition(record.id, "revoke")).toThrow("terminated (expired)");
      expect(kernel.applyExpiry(before)).toMatchObject({ state: "terminated", termination: expired });
      // Nothing persisted and nothing published while the write fails.
      expect(kernel.get(record.id)).toMatchObject({ state: start, version: before.version });
      expect(kernel.get(record.id)).not.toHaveProperty("termination");
      expect(commits).toHaveLength(0);

      // Once the write can land, the first observer persists it, keeping the
      // observed cause and instant and adding the committing version.
      restoreTerminationWrites();
      expect(gateReason(() => kernel.gateActive(record.id))).toBe("mission_expired");
      expect(kernel.get(record.id)).toMatchObject({
        state: "terminated",
        termination: { ...expired, version: before.version + 1 },
        version: before.version + 1,
      });
      expect(commits).toHaveLength(1);
      expect(commits[0]).toMatchObject({
        state: "terminated",
        prior_state: start,
        termination: { ...expired, version: before.version + 1 },
      });
    });
  }

  it("maps an expired participant INVALID on the Status List while its expiry write fails", () => {
    const record = approve("2026-07-01T01:00:00Z");
    const idx = kernel.participateInStatusList(record.id);
    clock = new Date(record.expires_at);
    failTerminationWrites();
    expect(kernel.statusListEntries().find((e) => e.idx === idx)?.bit).toBe(STATUS_INVALID);
    expect(kernel.get(record.id)?.state).toBe("active");
  });
});

describe("an earlier recorded cause is preserved (#705 witness 5)", () => {
  for (const [op, reason] of [
    ["revoke", "revoked"],
    ["complete", "completed"],
  ] as const) {
    it(`a Mission terminated ${reason} keeps its reason after expires_at passes, at every gate`, () => {
      const record = approve("2026-07-01T01:00:00Z");
      const terminated = kernel.transition(record.id, op);
      commits.length = 0;
      clock = new Date("2026-07-01T02:00:00Z");
      const stored = kernel.get(record.id) as MissionRecord;
      expect(stored.termination).toEqual(terminated.termination);
      expect(kernel.observe(stored).termination).toEqual(terminated.termination);
      // The gate refuses on the recorded cause, never on expiry.
      expect(gateReason(() => kernel.gateActive(record.id))).toBe("mission_not_active");
      expect(gateErrorToMissionError("mission_not_active", kernel.observedRecord(record.id))).toBe(reason);
      expect(statusMission(record.id).termination).toEqual(terminated.termination);
      // Idempotent on the recorded cause; nothing new committed.
      expect(kernel.transition(record.id, op).termination).toEqual(terminated.termination);
      expect(kernel.get(record.id)?.version).toBe(terminated.version);
      expect(commits).toHaveLength(0);
    });
  }

  it("a terminated child keeps its own reason when its parent later terminates", () => {
    const parent = approve();
    const child = childOf(parent.id);
    const revoked = kernel.transition(child.id, "revoke");
    kernel.transition(parent.id, "revoke");
    expect(kernel.get(child.id)?.termination).toEqual(revoked.termination);
  });
});

describe("a child's own expiry outranks its parent's termination (#705 witness 6, ordinary cascade)", () => {
  it("a child whose expires_at coincides with its parent's revocation terminates expired, not parent_terminated", () => {
    const parent = approve();
    const child = childOf(parent.id, "child-agent", "2026-07-01T01:00:00Z");
    // A distinct, earlier instant, so the grandchild's own `terminated_at` is
    // told apart from the child's.
    const grandchild = childOf(child.id, "grandchild-agent", "2026-07-01T00:59:00Z");
    // The parent is revoked at the very instant the child's expiry takes effect.
    clock = new Date(child.expires_at);
    kernel.transition(parent.id, "revoke");
    expect(kernel.get(child.id)?.termination).toEqual({
      reason: "expired",
      terminated_at: child.expires_at,
      version: child.version + 1,
    });
    expect(kernel.get(grandchild.id)?.termination).toMatchObject({
      reason: "expired",
      terminated_at: grandchild.expires_at,
    });
    expect(grandchild.expires_at).not.toBe(child.expires_at);
  });

  it("a child whose expires_at equals its parent's terminates expired when the parent's expiry materializes", () => {
    const parent = approve("2026-07-01T01:00:00Z");
    const child = childOf(parent.id, "child-agent", "2026-07-01T01:00:00Z");
    expect(child.expires_at).toBe(parent.expires_at);
    clock = new Date(parent.expires_at);
    kernel.materializeExpiry(parent.id);
    expect(kernel.get(parent.id)?.termination?.reason).toBe("expired");
    expect(kernel.get(child.id)?.termination).toMatchObject({ reason: "expired", terminated_at: child.expires_at });
  });
});

describe("the ancestor-termination projection (#705 witness 7)", () => {
  it("a child reads terminated parent_terminated before its cascade commits and while that write fails, and materializing keeps the cause", () => {
    const parent = approve();
    const child = childOf(parent.id);
    const grandchild = childOf(child.id, "grandchild-agent");
    // The parent terminates WITHOUT its cascade (a raw write), so the children
    // are still stored `active`.
    const parentTermination = { reason: "revoked", terminated_at: "2026-07-01T00:30:00Z", version: 2 };
    kernel.db
      .prepare("UPDATE missions SET state = 'terminated', termination_json = ?, version = 2 WHERE id = ?")
      .run(JSON.stringify(parentTermination), parent.id);
    clock = new Date("2026-07-01T00:45:00Z");
    const projected = {
      reason: "parent_terminated",
      parent: parent.id,
      terminated_at: parentTermination.terminated_at,
      origin: parent.id,
      origin_reason: "revoked",
    };
    expect(kernel.get(child.id)?.state).toBe("active");
    expect(kernel.observe(kernel.get(child.id) as MissionRecord)).toMatchObject({
      state: "terminated",
      termination: projected,
    });
    // Transitively: the grandchild names its immediate parent, the same instant
    // and the same origin.
    expect(kernel.observe(kernel.get(grandchild.id) as MissionRecord).termination).toEqual({
      ...projected,
      parent: child.id,
    });

    failTerminationWrites();
    expect(gateReason(() => kernel.gateActive(child.id))).toBe("mission_not_active");
    expect(gateErrorToMissionError("mission_not_active", kernel.observedRecord(child.id))).toBe("parent_terminated");
    expect(statusMission(child.id)).toMatchObject({ state: "terminated", termination: projected });
    expect(statusMission(child.id).termination).not.toHaveProperty("version");
    expect(kernel.get(child.id)?.state).toBe("active");

    restoreTerminationWrites();
    expect(gateReason(() => kernel.gateActive(child.id))).toBe("mission_not_active");
    expect(kernel.get(child.id)?.termination).toEqual({ ...projected, version: child.version + 1 });
    // The materialized child's own cascade carries the same instant and origin.
    expect(kernel.get(grandchild.id)?.termination).toEqual({
      ...projected,
      parent: child.id,
      version: grandchild.version + 1,
    });
  });
});

describe("a cascade under a legacy parent invents no effective time (#705 review P2)", () => {
  const legacyRevoked = (id: string) =>
    kernel.db.prepare("UPDATE missions SET state = 'revoked', version = 2 WHERE id = ?").run(id);

  it("materializing a cascade under a legacy parent with no retained instant keeps terminated_at unknown and records its commit time on the commit", () => {
    const parent = approve();
    const cascaded = childOf(parent.id);
    const readPath = childOf(parent.id);
    legacyRevoked(parent.id);
    commits = [];

    // Observed before materialization: the parent's instant is unknown, so the child's is too.
    const observed = kernel.observe(kernel.get(cascaded.id) as MissionRecord);
    expect(observed).toMatchObject({ state: "terminated", termination: { reason: "parent_terminated", parent: parent.id } });
    expect(observed.termination).not.toHaveProperty("terminated_at");

    // Materialized by the cascade and, for the other child, by a read path.
    kernel.cascadeChildren(parent.id);
    kernel.applyExpiry(kernel.get(readPath.id) as MissionRecord);
    for (const child of [cascaded, readPath]) {
      const stored = kernel.get(child.id) as MissionRecord;
      expect(stored.state).toBe("terminated");
      expect(stored.termination).toMatchObject({
        reason: "parent_terminated",
        parent: parent.id,
        origin: parent.id,
        origin_reason: "revoked",
        version: stored.version,
      });
      expect(stored.termination).not.toHaveProperty("terminated_at");
      // The materialization time is recorded separately, on the commit.
      const commit = commits.find((c) => c.id === child.id && c.state === "terminated");
      expect(typeof commit?.committed_at).toBe("string");
      expect(commit?.termination).toEqual(stored.termination);
    }
  });

  it("a direct revoke still records its commit as the effective instant", () => {
    const record = approve();
    const revoked = kernel.transition(record.id, "revoke");
    const commit = commits.find((c) => c.id === record.id && c.state === "terminated");
    expect(revoked.termination?.terminated_at).toBe(commit?.committed_at);
  });
});

describe("idempotency compares the termination reason (#705 witness 8)", () => {
  it("same state and reason is idempotent success; revoke on a completed termination and complete on a revoked one are conflicts", () => {
    const a = approve();
    const b = approve();
    const revoked = kernel.transition(a.id, "revoke");
    const completed = kernel.transition(b.id, "complete");
    commits.length = 0;
    // Same resulting state AND reason: idempotent, no new version or commit.
    expect(kernel.transition(a.id, "revoke")).toMatchObject({ version: revoked.version, termination: revoked.termination });
    expect(kernel.transition(b.id, "complete")).toMatchObject({
      version: completed.version,
      termination: completed.termination,
    });
    // Same state, different reason: a conflict, and the recorded cause stands.
    expect(() => kernel.transition(b.id, "revoke")).toThrow(LifecycleConflictError);
    expect(() => kernel.transition(b.id, "revoke")).toThrow("revoke is not legal from terminated (completed)");
    expect(() => kernel.transition(a.id, "complete")).toThrow(LifecycleConflictError);
    expect(() => kernel.transition(a.id, "complete")).toThrow("complete is not legal from terminated (revoked)");
    expect(kernel.get(a.id)?.termination).toEqual(revoked.termination);
    expect(kernel.get(b.id)?.termination).toEqual(completed.termination);
    expect(commits).toHaveLength(0);
  });

  it("revoke on an expired Mission is a conflict, whether or not the expiry was persisted", () => {
    const record = approve("2026-07-01T01:00:00Z");
    clock = new Date("2026-07-01T02:00:00Z");
    failTerminationWrites();
    expect(() => kernel.transition(record.id, "revoke")).toThrow("revoke is not legal from terminated (expired)");
    restoreTerminationWrites();
    expect(() => kernel.transition(record.id, "revoke")).toThrow("revoke is not legal from terminated (expired)");
    expect(kernel.get(record.id)?.termination?.reason).toBe("expired");
  });
});

describe("the Approval Context Manifest keeps its digest (#705 witness 10)", () => {
  it("sources the manifest's approver from approval_basis.consent_principal, byte-identical to the retired record alias", () => {
    const principal = { iss: ISS, sub: "bob" };
    // The same hand-built record the pre-migration commitment was computed
    // over (record.approver == consent_principal), now without the alias.
    const record = {
      id: "msn_digest_fixture",
      issuer: ISS,
      state: "active",
      intent: { goal: "Pay Acme invoices for Q3", target_resources: ["https://rs.test"], expires_at: "2099-01-01T00:00:00Z" },
      authority_set: [],
      intent_hash: "sha-256:intent-fixture",
      authority_hash: "sha-256:authority-fixture",
      proposal_hash: "sha-256:proposal-fixture",
      subject: { iss: ISS, sub: "alice" },
      approval_basis: {
        type: "direct",
        consent_principal: principal,
        activation: { approval_event_id: "apev-digest" },
        activation_actor: { iss: ISS, sub: "bob" },
        root_commitment: "sha-256:authority-fixture",
      },
      authority_source: { type: "user_delegated" },
      client_id: "ap-agent",
      policy_version: "p-1",
      approval_event_id: "apev-digest",
      created_at: "2026-09-30T00:00:00Z",
      expires_at: "2099-01-01T00:00:00Z",
      version: 1,
      derivation_limit: null,
      derivation_count: 0,
      grant_id: null,
      status_list_idx: null,
    } as unknown as MissionRecord;
    const manifest = approvalContextManifest(kernel.approvalContextInput(record));
    expect(manifest.approver).toEqual(principal);
    // Computed at bc6287cc, before the alias was removed, over the same record
    // carrying `approver` == consent_principal.
    expect(approvalContextCommitment(ISS, manifest)).toBe("sha-256:3Z35U6yX7gpeQadv34CVadHIYUGgWFW-rvhFfXNk6j8");
    // And for a real record: the manifest's approver IS the consent principal.
    const real = approve();
    expect(real).not.toHaveProperty("approver");
    expect(approvalContextManifest(kernel.approvalContextInput(real)).approver).toEqual(
      real.approval_basis.consent_principal,
    );
  });
});
