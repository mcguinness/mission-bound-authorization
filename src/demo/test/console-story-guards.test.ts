/**
 * The console story's guards (the review of PR #2035): an agent action names
 * the Mission it runs under or runs under the active one, never a substitute
 * for an unknown one; a parked Mission approval is decided once, however many
 * requests arrive, and a failed attempt never overwrites an issued Mission;
 * and the revocation proof is done only when the run showed its contrast.
 *
 * Pure: every collaborator is a controlled stand-in, so this file never skips.
 */

import { describe, expect, it, vi } from "vitest";
import { adjudicateMissionApproval, challengedBinding, handleAgentAct, type ParkedApproval, selectBinding } from "../src/server.js";
import { proveRevocation } from "../public/console-story.js";

type Binding = { missionId: string };
const payments: Binding = { missionId: "msn_payments" };
const reconciliation: Binding = { missionId: "msn_reconciliation" };
const bindings = new Map<string, Binding>([
  [payments.missionId, payments],
  [reconciliation.missionId, reconciliation],
]);

describe("an agent action's Mission selection", () => {
  it("selects the active Mission only when none is named, and a held Mission when it is named", () => {
    expect(selectBinding(undefined, bindings, payments)).toEqual({ binding: payments });
    expect(selectBinding("msn_reconciliation", bindings, payments)).toEqual({ binding: reconciliation });
  });

  it("refuses an unknown or malformed explicit Mission rather than substituting the active one", () => {
    expect(selectBinding("msn_unknown", bindings, payments)).toMatchObject({ status: 404 });
    for (const malformed of [null, "", 7, {}, ["msn_payments"]]) {
      expect(selectBinding(malformed, bindings, payments)).toMatchObject({ status: 400 });
    }
  });

  const actDeps = () => ({
    bindings,
    active: payments,
    renew: vi.fn(async () => undefined),
    invoke: vi.fn(async () => ({ ok: true })),
    report: vi.fn(async (_tool: string, _args: Record<string, unknown>, r: { ok: boolean }, b: Binding) => ({ ...r, missionId: b.missionId })),
  });

  it("POST /agent/act never renews or calls the tool for an unknown or malformed Mission", async () => {
    for (const [missionId, status] of [["msn_unknown", 404], [null, 400], ["", 400], [42, 400]] as const) {
      const deps = actDeps();
      const res = await handleAgentAct({ tool: "get_invoice", args: { invoice_id: "inv-1" }, missionId }, deps);
      expect(res.status).toBe(status);
      expect(res.body).toMatchObject({ ok: false });
      expect(deps.renew).not.toHaveBeenCalled();
      expect(deps.invoke).not.toHaveBeenCalled();
      expect(deps.report).not.toHaveBeenCalled();
    }
  });

  it("POST /agent/act runs under the active Mission when none is named, and under the named one otherwise", async () => {
    const omitted = actDeps();
    expect(await handleAgentAct({ tool: "get_invoice", args: { invoice_id: "inv-1" } }, omitted)).toMatchObject({
      status: 200,
      body: { missionId: "msn_payments" },
    });
    expect(omitted.invoke).toHaveBeenCalledWith("get_invoice", { invoice_id: "inv-1" }, payments);

    const named = actDeps();
    expect(await handleAgentAct({ tool: "get_invoice", args: { invoice_id: "inv-1" }, missionId: "msn_reconciliation" }, named)).toMatchObject({
      status: 200,
      body: { missionId: "msn_reconciliation" },
    });
    expect(named.renew).toHaveBeenCalledWith(reconciliation);
    expect(named.invoke).toHaveBeenCalledWith("get_invoice", { invoice_id: "inv-1" }, reconciliation);
  });

  it("an approval retry runs under the Mission its challenge was opened under, and none when none is recorded", () => {
    const challenged = new Map([["task-1", "msn_reconciliation"], ["task-2", "msn_released"]]);
    expect(challengedBinding("task-1", challenged, bindings)).toBe(reconciliation);
    expect(challengedBinding("task-2", challenged, bindings)).toBeUndefined();
    expect(challengedBinding("task-3", challenged, bindings)).toBeUndefined();
  });
});

describe("a parked Mission approval is decided once", () => {
  const deferred = <T>() => {
    let resolve!: (v: T) => void;
    let reject!: (e: Error) => void;
    const promise = new Promise<T>((res, rej) => {
      resolve = res;
      reject = rej;
    });
    return { promise, resolve, reject };
  };
  const satisfied = () => ({ outcome: "satisfied" });
  const deps = (over: Partial<Parameters<typeof adjudicateMissionApproval<string>>[2]> = {}) => ({
    floor: vi.fn(satisfied),
    complete: vi.fn(async () => "issued-token"),
    adopt: vi.fn(async () => ({ missionId: "msn_issued", authority: [] })),
    deny: vi.fn(async () => undefined),
    ...over,
  });

  it("two concurrent approvals complete the interaction once and both observe the issued Mission", async () => {
    const rec: ParkedApproval = { state: "pending" };
    const completion = deferred<string>();
    const d = deps({ complete: vi.fn(() => completion.promise) });
    const one = adjudicateMissionApproval(rec, "approve", d);
    const two = adjudicateMissionApproval(rec, "approve", d);
    completion.resolve("issued-token");
    const [a, b] = await Promise.all([one, two]);
    expect(d.complete).toHaveBeenCalledTimes(1);
    expect(d.adopt).toHaveBeenCalledTimes(1);
    expect(a).toEqual(b);
    expect(a).toMatchObject({ status: 200, body: { approved: true, missionId: "msn_issued" } });
    expect(rec).toMatchObject({ state: "active", missionId: "msn_issued" });
  });

  it("a deny arriving while an approval is in flight observes the approval and decides nothing", async () => {
    const rec: ParkedApproval = { state: "pending" };
    const completion = deferred<string>();
    const d = deps({ complete: vi.fn(() => completion.promise) });
    const approve = adjudicateMissionApproval(rec, "approve", d);
    const deny = adjudicateMissionApproval(rec, "deny", d);
    completion.resolve("issued-token");
    expect(await deny).toMatchObject({ status: 200, body: { approved: true, missionId: "msn_issued" } });
    expect(await approve).toMatchObject({ body: { approved: true } });
    expect(d.deny).not.toHaveBeenCalled();
    expect(rec.state).toBe("active");
  });

  it("a completion that fails records the approval failed, not denied, and a later request does not retry it", async () => {
    const rec: ParkedApproval = { state: "pending" };
    const d = deps({ complete: vi.fn(async () => Promise.reject(new Error("approval resolution refused: 400"))) });
    const [one, two] = await Promise.all([adjudicateMissionApproval(rec, "approve", d), adjudicateMissionApproval(rec, "approve", d)]);
    expect(one).toMatchObject({ status: 400, body: { approved: false, state: "failed", error: "approval resolution refused: 400" } });
    expect(two).toEqual(one);
    expect(rec).toMatchObject({ state: "failed", error: "approval resolution refused: 400" });
    const later = await adjudicateMissionApproval(rec, "approve", d);
    expect(later).toMatchObject({ status: 200, body: { approved: false, state: "failed" } });
    expect(d.complete).toHaveBeenCalledTimes(1);
    expect(d.adopt).not.toHaveBeenCalled();
  });

  it("a Mission issued but not bound is reported failed with that cause", async () => {
    const rec: ParkedApproval = { state: "pending" };
    const d = deps({ adopt: vi.fn(async () => Promise.reject(new Error("token validation failed"))) });
    expect(await adjudicateMissionApproval(rec, "approve", d)).toMatchObject({
      status: 400,
      body: { state: "failed", error: "the Mission was issued, but the console could not bind it: token validation failed" },
    });
    expect(rec.state).toBe("failed");
  });

  it("a settled approval is never overwritten by a later request", async () => {
    const rec: ParkedApproval = { state: "pending" };
    const d = deps();
    await adjudicateMissionApproval(rec, "approve", d);
    const failing = deps({ complete: vi.fn(async () => Promise.reject(new Error("settled"))), deny: vi.fn(async () => Promise.reject(new Error("settled"))) });
    expect(await adjudicateMissionApproval(rec, "approve", failing)).toMatchObject({ body: { approved: true, state: "active", missionId: "msn_issued" } });
    expect(await adjudicateMissionApproval(rec, "deny", failing)).toMatchObject({ body: { approved: true, state: "active" } });
    expect(failing.complete).not.toHaveBeenCalled();
    expect(failing.deny).not.toHaveBeenCalled();
    expect(rec).toMatchObject({ state: "active", missionId: "msn_issued" });
  });

  it("a login the floor refuses is refused before the interaction is touched, and the approval stays approvable", async () => {
    const rec: ParkedApproval = { state: "pending" };
    const stale = deps({ floor: vi.fn(() => ({ outcome: "refused", reason: "the login is too old" })) });
    expect(await adjudicateMissionApproval(rec, "approve", stale)).toMatchObject({ status: 409, body: { state: "pending" } });
    expect(stale.complete).not.toHaveBeenCalled();
    expect(rec.state).toBe("pending");
    const fresh = deps();
    expect(await adjudicateMissionApproval(rec, "approve", fresh)).toMatchObject({ status: 200, body: { approved: true } });
  });

  it("a deny settles the approval denied, and a deny that fails records it failed", async () => {
    const denied: ParkedApproval = { state: "pending" };
    const d = deps();
    expect(await adjudicateMissionApproval(denied, "deny", d)).toMatchObject({ status: 200, body: { approved: false, state: "denied" } });
    expect(d.deny).toHaveBeenCalledTimes(1);
    expect(d.complete).not.toHaveBeenCalled();

    const broken: ParkedApproval = { state: "pending" };
    expect(await adjudicateMissionApproval(broken, "deny", deps({ deny: vi.fn(async () => Promise.reject(new Error("deny failed"))) }))).toMatchObject({
      status: 400,
      body: { state: "failed" },
    });
  });
});

describe("the revocation proof is done only when the run showed its contrast", () => {
  const revoked = { id: "msn_story", state: "terminated", termination: { reason: "revoked" } };
  const missions = [
    { id: "msn_story", state: "terminated" },
    { id: "msn_payments", state: "active", effective: [{ actions: ["payments:invoice.read", "payments:payment.execute"] }] },
    { id: "msn_reconciliation", state: "active", effective: [{ actions: ["payments:invoice.read"] }] },
  ];
  const reads = (byMission: Record<string, unknown>) =>
    vi.fn(async (id: string) => byMission[id] as { ok?: boolean; reason?: string } | undefined);

  it("is done when the revoked read is refused and the other Mission's read is permitted, contrasting with a read-only Mission", async () => {
    const read = reads({ msn_story: { ok: false, reason: "mission_inactive" }, msn_reconciliation: { ok: true } });
    expect(await proveRevocation({ revoke: revoked, missions, missionId: "msn_story", read })).toEqual({ done: true, otherId: "msn_reconciliation" });
    expect(read.mock.calls.map((c) => c[0])).toEqual(["msn_story", "msn_reconciliation"]);
  });

  it("accepts a refusal from a lapsed, unrenewable token as the revoked read's refusal", async () => {
    const read = reads({ msn_story: { ok: false, reason: "credential_invalid" }, msn_reconciliation: { ok: true } });
    expect(await proveRevocation({ revoke: revoked, missions, missionId: "msn_story", read })).toMatchObject({ done: true });
  });

  it("is not done, and reads nothing, when the operator session has expired and the revoke is refused", async () => {
    const read = reads({ msn_story: { ok: true }, msn_reconciliation: { ok: true } });
    const verdict = await proveRevocation({ revoke: { error: "unauthorized" }, missions, missionId: "msn_story", read });
    expect(verdict).toMatchObject({ done: false });
    expect(read).not.toHaveBeenCalled();
  });

  it("is not done when the response does not record this Mission as revoked", async () => {
    const read = reads({});
    for (const revoke of [{ id: "msn_story", state: "active" }, { id: "msn_other", state: "terminated", termination: { reason: "revoked" } }, undefined]) {
      expect(await proveRevocation({ revoke, missions, missionId: "msn_story", read })).toMatchObject({ done: false });
    }
    expect(read).not.toHaveBeenCalled();
  });

  it("is not done when the agent holds no other active Mission", async () => {
    const read = reads({ msn_story: { ok: false, reason: "mission_inactive" } });
    const alone = [{ id: "msn_story", state: "terminated" }, { id: "msn_suspended", state: "suspended" }];
    expect(await proveRevocation({ revoke: revoked, missions: alone, missionId: "msn_story", read })).toMatchObject({
      done: false,
      problem: "the agent holds no other active Mission to contrast with",
    });
  });

  it("is not done on an unexpected verdict", async () => {
    const cases: Array<Record<string, unknown>> = [
      { msn_story: { ok: true }, msn_reconciliation: { ok: true } },
      { msn_story: { ok: false, reason: "unknown_invoice" }, msn_reconciliation: { ok: true } },
      { msn_story: { ok: false, error: "the agent holds no Mission msn_story" }, msn_reconciliation: { ok: true } },
      { msn_story: { ok: false, reason: "mission_inactive" }, msn_reconciliation: { ok: false, reason: "credential_invalid" } },
      { msn_story: { ok: false, reason: "mission_inactive" }, msn_reconciliation: undefined },
    ];
    for (const byMission of cases) {
      expect(await proveRevocation({ revoke: revoked, missions, missionId: "msn_story", read: reads(byMission) })).toMatchObject({ done: false });
    }
  });
});
