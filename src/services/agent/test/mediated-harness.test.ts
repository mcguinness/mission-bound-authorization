/**
 * Increment 1 -- harness duty 1 (fail-closed resume) at the mediated boundary.
 *
 * Proves resumeGuard refuses to issue ANY tool call when the mission is not
 * active, before the request reaches the channel. Key-free and OpenFGA-free:
 * the channel is a spy, so "no tool call was issued" is directly observable
 * (the spy is never touched). Duty 2 / no-bypass is proven over the real MCP
 * transport in services/mcp-payments/test/mcp-channel.test.ts; this file lives
 * in the agent package because resumeGuard composes the agent-side
 * checkOnResume, which mcp-payments cannot import without a dependency cycle.
 */

import { randomUUID } from "node:crypto";
import type { MissionStatusLease } from "@mission/core";
import { describe, expect, it } from "vitest";
import {
  checkOnResume,
  checkStatusContinuity,
  checkSupersessionContinuity,
  type MissionState,
  supersessionSuccessor,
} from "../src/harness.js";
import { MediatedHarness, type MediatedToolChannel, resumeGuard } from "../src/mediated-harness.js";

/** @spec runtime#idempotency (#917): one fresh `idempotency_key` per intended execution. */
const idem = (): string => `idem_${randomUUID()}`;

function spyChannel(): { channel: MediatedToolChannel; calls: string[] } {
  const calls: string[] = [];
  const channel: MediatedToolChannel = {
    async listTools() {
      calls.push("listTools");
      return ["get_invoice"];
    },
    async callTool(name) {
      calls.push(`callTool:${name}`);
      return { ok: true, result: { executed: true } };
    },
  };
  return { channel, calls };
}

const active = async (): Promise<MissionState> => "active";
const terminated = async (): Promise<MissionState> => "terminated";
const missing = async (): Promise<MissionState | undefined> => undefined;

describe("harness duty 1: fail-closed resume guard", () => {
  it("resumeGuard proceeds only for an active mission (missing/non-active fail closed)", async () => {
    expect((await resumeGuard("msn", active)).proceed).toBe(true);
    expect((await resumeGuard("msn", terminated)).proceed).toBe(false);
    expect((await resumeGuard("msn", missing)).proceed).toBe(false);
  });

  it("callTool refuses BEFORE issuing any tool call when the mission is not active", async () => {
    const { channel, calls } = spyChannel();
    const harness = new MediatedHarness(channel, "msn", terminated);
    const res = await harness.callTool("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: idem() }, "jwt");
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("mission_not_active:terminated");
    expect(res.resume?.proceed).toBe(false);
    // The channel was never reached -- no tool call was issued (fail closed).
    expect(calls).toEqual([]);
  });

  it("listTools is suppressed when the mission state is unavailable", async () => {
    const { channel, calls } = spyChannel();
    const harness = new MediatedHarness(channel, "msn", missing);
    expect(await harness.listTools("jwt")).toEqual([]);
    expect(calls).toEqual([]);
  });

  it("when active, the harness proceeds to the mediated channel", async () => {
    const { channel, calls } = spyChannel();
    const harness = new MediatedHarness(channel, "msn", active);
    const res = await harness.callTool("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: idem() }, "jwt");
    expect(res.ok).toBe(true);
    expect(calls).toEqual(["callTool:execute_wire_transfer"]);
  });
});

/**
 * Additive: the status-lease path (@spec harness#resume-algorithm, step 5).
 * Reuses the same spy channel. Freshness is re-checked at each submission: a
 * lease that has expired fails closed even when the last-observed state is
 * `active`, and a within-window active lease proceeds. The duty-1 describe
 * above is unmodified -- that it stays green is the proof this path is additive.
 */
describe("harness status-continuity: fresh-at-submission fail-closed", () => {
  const activeLease = (expires: string): MissionStatusLease => ({
    state: "active",
    status_checked_at: "2026-01-01T22:00:00Z",
    status_expires_at: expires,
    state_source: "status",
  });
  const readStatus = (lease?: MissionStatusLease) => async () => lease;
  const at = (iso: string) => () => new Date(iso);
  const unusedReadState = async (): Promise<MissionState | undefined> => undefined;

  it("refuses the channel when the lease is stale, even though last state is active", async () => {
    const { channel, calls } = spyChannel();
    // Checked 22:00, expires 22:05; the agent wakes at 02:00 -> the lease is stale.
    const harness = new MediatedHarness(channel, "msn", unusedReadState, {
      readStatus: readStatus(activeLease("2026-01-01T22:05:00Z")),
      now: at("2026-01-02T02:00:00Z"),
    });
    const res = await harness.callTool("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: idem() }, "jwt");
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("mission_status_stale:active");
    expect(res.resume?.stale).toBe(true);
    expect(res.resume?.state).toBe("active"); // last-observed state WAS active
    // Fail closed: the channel was never reached despite the recorded active state.
    expect(calls).toEqual([]);
  });

  it("proceeds to the channel when the lease is within its window and active", async () => {
    const { channel, calls } = spyChannel();
    const harness = new MediatedHarness(channel, "msn", unusedReadState, {
      readStatus: readStatus(activeLease("2026-01-02T03:00:00Z")),
      now: at("2026-01-02T02:00:00Z"), // before expiry
    });
    const res = await harness.callTool("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: idem() }, "jwt");
    expect(res.ok).toBe(true);
    expect(calls).toEqual(["callTool:execute_wire_transfer"]);
  });

  it("suppresses listTools when no status lease is available (fail closed)", async () => {
    const { channel, calls } = spyChannel();
    const harness = new MediatedHarness(channel, "msn", unusedReadState, {
      readStatus: readStatus(undefined),
      now: at("2026-01-02T02:00:00Z"),
    });
    expect(await harness.listTools("jwt")).toEqual([]);
    expect(calls).toEqual([]);
  });
});

/** A lease reporting `terminated` (by default), fresh at {@link LEASE_NOW}. */
const LEASE_NOW = () => new Date("2026-01-02T02:00:00Z");
const terminatedLease = (over: Record<string, unknown> = {}): MissionStatusLease =>
  ({
    state: "terminated",
    status_checked_at: "2026-01-02T01:59:00Z",
    status_expires_at: "2026-01-02T03:00:00Z",
    state_source: "status",
    ...over,
  }) as MissionStatusLease;

/**
 * @spec mission#lifecycle, mission#termination: the harness reads a Mission's
 * lifecycle as `active`, `suspended` or `terminated`, with how it ended in
 * `termination.reason`. Only exactly `active` proceeds; every termination,
 * whatever its reason (one the harness does not recognize included), and a
 * malformed or absent termination, is non-active. A synthetic fail-closed
 * decision is `terminated` with no termination: no cause is fabricated.
 */
describe("harness termination: terminated with any reason is non-active (@spec mission#termination)", () => {
  const unusedReadState = async (): Promise<MissionState | undefined> => undefined;

  it("refuses mission_not_active:terminated for every termination reason, an unknown one, a malformed one and none, before the channel", async () => {
    const terminations: Array<[string, Record<string, unknown>]> = [
      ["revoked", { termination: { reason: "revoked", terminated_at: "2026-01-01T23:00:00Z", version: 4 } }],
      ["expired", { termination: { reason: "expired", terminated_at: "2026-01-01T00:00:00Z", version: 3 } }],
      ["completed", { termination: { reason: "completed", terminated_at: "2026-01-01T23:00:00Z", version: 5 } }],
      ["superseded without a successor", { termination: { reason: "superseded", terminated_at: "2026-01-01T23:00:00Z" } }],
      ["parent_terminated", { termination: { reason: "parent_terminated", terminated_at: "2026-01-01T23:00:00Z", parent: "msn_p" } }],
      ["an unknown reason", { termination: { reason: "future_termination_reason" } }],
      ["a malformed termination", { termination: { reason: 7 } }],
      ["no termination", {}],
    ];
    for (const [label, over] of terminations) {
      const decision = await checkStatusContinuity(terminatedLease(over), LEASE_NOW());
      expect(decision.proceed, label).toBe(false);
      expect(decision.state, label).toBe("terminated");
      expect(decision.stale, label).toBeUndefined();
      const { channel, calls } = spyChannel();
      const harness = new MediatedHarness(channel, "msn", unusedReadState, {
        readStatus: async () => terminatedLease(over),
        now: LEASE_NOW,
      });
      const res = await harness.callTool("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: idem() }, "jwt");
      expect(res.ok, label).toBe(false);
      expect(res.refusal_reason, label).toBe("mission_not_active:terminated");
      expect(await harness.listTools("jwt"), label).toEqual([]);
      expect(calls, label).toEqual([]);
    }
    // The reported termination rides the decision as read; a malformed one is dropped, never repaired.
    const unknown = await checkStatusContinuity(
      terminatedLease({ termination: { reason: "future_termination_reason" } }),
      LEASE_NOW(),
    );
    expect(unknown.termination).toEqual({ reason: "future_termination_reason" });
    const malformed = await checkStatusContinuity(terminatedLease({ termination: { reason: 7 } }), LEASE_NOW());
    expect(malformed.termination).toBeUndefined();
  });

  it("fails closed to terminated with no termination, never a fabricated revoked, when state or lease is unavailable or unrecognized", async () => {
    const decisions = [
      await checkOnResume("msn", missing),
      await checkStatusContinuity(undefined, LEASE_NOW()),
      await checkStatusContinuity(terminatedLease({ state: "active", status_expires_at: "not-a-date" }), LEASE_NOW()),
      await checkStatusContinuity(terminatedLease({ state: "paused" }), LEASE_NOW()),
    ];
    for (const decision of decisions) {
      expect(decision.proceed).toBe(false);
      expect(decision.state).toBe("terminated");
      expect(decision.termination).toBeUndefined();
      expect(decision.successor).toBeUndefined();
    }
    const { channel, calls } = spyChannel();
    const harness = new MediatedHarness(channel, "msn", missing);
    const res = await harness.callTool("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: idem() }, "jwt");
    expect(res.refusal_reason).toBe("mission_not_active:terminated");
    expect(calls).toEqual([]);
  });

  it("reads a legacy terminal state on a lease as terminated with that reason (cascaded as parent_terminated), with no invented members", async () => {
    const cases: Array<[string, string]> = [
      ["revoked", "revoked"],
      ["expired", "expired"],
      ["completed", "completed"],
      ["superseded", "superseded"],
      ["cascaded", "parent_terminated"],
    ];
    for (const [legacy, reason] of cases) {
      const decision = await checkStatusContinuity(terminatedLease({ state: legacy }), LEASE_NOW());
      expect(decision.proceed, legacy).toBe(false);
      expect(decision.state, legacy).toBe("terminated");
      expect(decision.termination, legacy).toEqual({ reason });
      expect(decision.successor, legacy).toBeUndefined();
    }
  });
});

/**
 * @spec harness#supersession-continuity: a harness MAY continue a superseded
 * Mission's work item by rebinding to the successor. The successor is read
 * from the Status-reported `termination`, keyed on `termination.reason`
 * exactly `superseded` with a string `termination.successor`, and the
 * successor must itself be established fresh and `active` first.
 */
describe("harness supersession continuity keys on termination.reason (@spec harness#supersession-continuity)", () => {
  const superseded = (successor: unknown = "msn_successor") =>
    terminatedLease({
      termination: { reason: "superseded", terminated_at: "2026-01-02T01:00:00Z", version: 6, successor },
    });

  it("names the successor only for a terminated Mission whose termination.reason is superseded with a string successor", async () => {
    const named = await checkStatusContinuity(superseded(), LEASE_NOW());
    expect(named.proceed).toBe(false);
    expect(named.termination?.reason).toBe("superseded");
    expect(named.successor).toBe("msn_successor");
    expect(supersessionSuccessor(named)).toBe("msn_successor");

    const stray = { reason: "superseded", successor: "msn_successor" };
    const none: Array<[string, MissionStatusLease]> = [
      ["revoked with a stray successor", terminatedLease({ termination: { reason: "revoked", successor: "msn_successor" } })],
      [
        "parent_terminated with a stray successor",
        terminatedLease({ termination: { reason: "parent_terminated", parent: "msn_p", successor: "msn_successor" } }),
      ],
      ["superseded without a successor", terminatedLease({ termination: { reason: "superseded" } })],
      ["superseded with a non-string successor", superseded(42)],
      ["superseded with an empty successor", superseded("")],
      ["a legacy superseded state string", terminatedLease({ state: "superseded", termination: stray })],
      ["a suspended Mission carrying a stray termination", terminatedLease({ state: "suspended", termination: stray })],
      ["a stale lease", terminatedLease({ status_expires_at: "2026-01-02T01:00:00Z", termination: stray })],
    ];
    for (const [label, lease] of none) {
      const decision = await checkStatusContinuity(lease, LEASE_NOW());
      expect(decision.proceed, label).toBe(false);
      expect(decision.successor, label).toBeUndefined();
      expect(supersessionSuccessor(decision), label).toBeUndefined();
    }
  });

  it("continues by rebinding only when the successor's own fresh lease is active, and reads no successor for another reason", async () => {
    const reads: string[] = [];
    const statusOf =
      (successorLease: MissionStatusLease | undefined) =>
      async (id: string): Promise<MissionStatusLease | undefined> => {
        reads.push(id);
        return successorLease;
      };
    const predecessor = await checkStatusContinuity(superseded(), LEASE_NOW());

    const ok = await checkSupersessionContinuity(predecessor, statusOf(terminatedLease({ state: "active" })), LEASE_NOW());
    expect(ok.rebind).toBe(true);
    expect(ok.successor).toBe("msn_successor");
    expect(ok.resume?.proceed).toBe(true);
    expect(reads).toEqual(["msn_successor"]);

    const notEstablished: Array<[string, MissionStatusLease | undefined]> = [
      ["suspended successor", terminatedLease({ state: "suspended" })],
      ["terminated successor", terminatedLease({ termination: { reason: "revoked" } })],
      ["stale successor lease", terminatedLease({ state: "active", status_expires_at: "2026-01-02T01:00:00Z" })],
      ["no successor lease", undefined],
    ];
    for (const [label, successorLease] of notEstablished) {
      const out = await checkSupersessionContinuity(predecessor, statusOf(successorLease), LEASE_NOW());
      expect(out.rebind, label).toBe(false);
    }

    reads.length = 0;
    const revoked = await checkStatusContinuity(
      terminatedLease({ termination: { reason: "revoked", successor: "msn_successor" } }),
      LEASE_NOW(),
    );
    const refused = await checkSupersessionContinuity(revoked, statusOf(terminatedLease({ state: "active" })), LEASE_NOW());
    expect(refused.rebind).toBe(false);
    expect(reads).toEqual([]); // keyed on the reason: no successor is even read
  });

  it("refuses the superseded predecessor at the mediated boundary and hands the caller the successor to rebind to", async () => {
    const { channel, calls } = spyChannel();
    const harness = new MediatedHarness(channel, "msn", missing, {
      readStatus: async () => superseded(),
      now: LEASE_NOW,
    });
    const res = await harness.callTool("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: idem() }, "jwt");
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("mission_not_active:terminated");
    expect(res.resume?.successor).toBe("msn_successor");
    expect(calls).toEqual([]); // the predecessor's credential never reaches the channel
  });
});
