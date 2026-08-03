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

import type { MissionStatusLease } from "@mission/core";
import { describe, expect, it } from "vitest";
import type { MissionState } from "../src/harness.js";
import { MediatedHarness, type MediatedToolChannel, resumeGuard } from "../src/mediated-harness.js";

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
const revoked = async (): Promise<MissionState> => "revoked";
const missing = async (): Promise<MissionState | undefined> => undefined;

describe("harness duty 1: fail-closed resume guard", () => {
  it("resumeGuard proceeds only for an active mission (missing/non-active fail closed)", async () => {
    expect((await resumeGuard("msn", active)).proceed).toBe(true);
    expect((await resumeGuard("msn", revoked)).proceed).toBe(false);
    expect((await resumeGuard("msn", missing)).proceed).toBe(false);
  });

  it("callTool refuses BEFORE issuing any tool call when the mission is not active", async () => {
    const { channel, calls } = spyChannel();
    const harness = new MediatedHarness(channel, "msn", revoked);
    const res = await harness.callTool("execute_wire_transfer", { invoice_id: "inv-1" }, "jwt");
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("mission_not_active:revoked");
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
    const res = await harness.callTool("execute_wire_transfer", { invoice_id: "inv-1" }, "jwt");
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
    const res = await harness.callTool("execute_wire_transfer", { invoice_id: "inv-1" }, "jwt");
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
    const res = await harness.callTool("execute_wire_transfer", { invoice_id: "inv-1" }, "jwt");
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
