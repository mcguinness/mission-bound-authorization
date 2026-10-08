/**
 * @spec runtime#permit-binding, runtime#single-use-identifiers,
 * authzen#response-context `use_limit` (#1080, D317): single-use permits on
 * the unkeyed write path, end to end through this resource's real PEP, the real
 * PDP, its evidence store, and a real store file.
 *
 * `hold_transfer`, the prepare phase of `payments:payment.execute`, is a
 * `consequential_write` that elects no key control, so its permit carries
 * `use_limit: 1`. The unkeyed write path redeems the permit's `evaluation_id`
 * once, as its last step before release, in the PEP's durable store; a second
 * presentation of the same Decision is suppressed `permit_consumed` and
 * releases nothing, also after a restart on the same file. The keyed writes
 * keep their idempotency-key control and carry no use limit; a `use_limit`
 * injected onto a keyed write's permit (#1136 review) is metered in the same
 * store, inside the reservation's transaction, never ignored. Releasing a
 * retained result is a use too (D342): the retrieval consumes the permit
 * before it discloses anything.
 *
 * A re-presentation is built by replaying a captured Decision in place of a
 * fresh one, the way a PEP that re-presents a Decision would. Every store is
 * a real file in a fresh temporary directory on a clock the test drives; the
 * FGA layer is a stub that always permits, so this file never skips.
 */

import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { Decision, Fga, MissionView } from "@mission/pdp";
import {
  CANONICAL_RESOURCE,
  CONSUMED_PERMIT_RETENTION_MARGIN_MS,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  type ExecutionEvidence,
  McpPaymentsServer,
  openWriteReservationStore,
  PaymentsStore,
  Pep,
  type TokenFacts,
  type WriteReservationStore,
} from "../src/index.js";
import { ALL_ACTIONS_CREDENTIAL } from "./credential-fixtures.js";

const KEYS = createEphemeralEvidenceKeys();
const BASE_MS = Date.parse("2026-10-05T12:00:00.000Z");
const ISSUER = "https://as.test";
const OWNER = "mcp-payments-pep";
const MISSION = "msn_1080";
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
const tempFile = (): string => join(mkdtempSync(join(tmpdir(), "single-use-unkeyed-write-")), "write-reservations.sqlite");

const TOKEN: TokenFacts = {
  sub: "alice",
  clientId: "ap-agent",
  mission: { id: MISSION, issuer: ISSUER, authority_hash: `sha-256:${MISSION}` },
  cnfJkt: "jkt-1080",
  credentialAuthority: ALL_ACTIONS_CREDENTIAL,
};

const VIEW: MissionView = {
  id: MISSION,
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: `sha-256:${MISSION}`,
  authority_set: [
    {
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:payment.execute", "payments:payment.schedule", "payments:payment.schedule.cancel"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    },
  ],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
};

function harness(o: { file?: string; store?: "none" } = {}) {
  let nowMs = BASE_MS;
  const now = () => new Date(nowMs);
  let replayed: Decision | undefined;
  let mutate: ((d: Decision) => Decision) | undefined;
  let captured: Decision | undefined;
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
  );
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === MISSION && ref.issuer === ISSUER
      ? { view: VIEW, observation: { state: VIEW.state, version: VIEW.version, mode: "fresh", freshness_at: now().toISOString() } }
      : undefined;
  const evidence = new EvidenceStore(KEYS.signing, KEYS.resolver);
  const file = o.file ?? tempFile();
  const store: WriteReservationStore | undefined =
    o.store === "none" ? undefined : openWriteReservationStore({ file, owner: OWNER, now });
  const pep = new Pep({
    // A replayed Decision stands in for a fresh one: the SAME evaluation
    // identifier, conditions and signed Decision Evidence, presented again.
    decide: async (req, options) => {
      const decision = replayed ?? (await KEYS.decide(req, options));
      return mutate ? mutate(decision) : decision;
    },
    observe: ({ decision }) => {
      captured = decision;
    },
    payments,
    evidence,
    fga: alwaysAllowFga,
    modelId: "model-1080",
    loadView,
    instanceEpoch: "epoch-1080",
    now,
  });
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
    jwks: { keys: [] },
    keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] },
    issuer: ISSUER,
    ...(store ? { writeReservations: store } : {}),
  });
  return {
    server,
    evidence,
    store,
    file,
    lastDecision: () => captured,
    replay: (d: Decision | undefined) => {
      replayed = d;
    },
    mutateDecision: (m: ((d: Decision) => Decision) | undefined) => {
      mutate = m;
    },
    advance: (ms: number) => {
      nowMs += ms;
    },
    executions: () => evidence.forMission(MISSION).filter((e): e is ExecutionEvidence => e.kind === "execution"),
  };
}
type Harness = ReturnType<typeof harness>;

const hold = (h: Harness) => h.server.callWriteTool("hold_transfer", { invoice_id: "inv-1" }, TOKEN);
const conditionsOf = (d: Decision | undefined) =>
  d?.context.conditions as { valid_until?: string; use_limit?: number } | undefined;
const HELD = { held: true, invoice_id: "inv-1" };

describe("single-use permits on the unkeyed write path (@spec runtime#single-use-identifiers, #1080)", () => {
  it("at the resource operation, the hold_transfer permit carries use_limit: 1, and the keyed writes keep the key control with no use_limit", async () => {
    const h = harness();
    const held = await hold(h);
    expect(held, JSON.stringify(held)).toEqual({ ok: true, result: HELD });
    const holdPermit = h.lastDecision();
    expect(holdPermit?.decision).toBe(true);
    expect(conditionsOf(holdPermit)?.use_limit).toBe(1);

    // The keyed writes: a request without a key is refused by the PDP, and a
    // keyed one is permitted under the short validity window and no use limit.
    for (const tool of ["schedule_payment", "cancel_scheduled_payment"]) {
      const keyless = await h.server.callWriteTool(tool, { invoice_id: "inv-1" }, TOKEN);
      expect(keyless.ok, tool).toBe(false);
      expect(keyless.denial_reason, tool).toBe("parameter_violation");
    }
    for (const tool of ["schedule_payment", "cancel_scheduled_payment"]) {
      const res = await h.server.callWriteTool(tool, { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` }, TOKEN);
      expect(res.ok, `${tool}: ${JSON.stringify(res)}`).toBe(true);
      const permit = h.lastDecision();
      expect(permit?.decision, tool).toBe(true);
      expect(conditionsOf(permit)?.use_limit, tool).toBeUndefined();
      const windowMs = Date.parse(conditionsOf(permit)?.valid_until ?? "") - BASE_MS;
      expect(windowMs, tool).toBeGreaterThan(0);
      expect(windowMs, tool).toBeLessThanOrEqual(300_000);
    }
    // Only the single-use permit took a consumed-identifier record.
    expect(h.store?.consumedPermits().map((c) => c.evaluationId)).toEqual([holdPermit?.context.decision_id]);
    h.store?.close();
  });

  it("a second presentation of one hold_transfer Decision is refused permit_consumed, releases no second hold, and records the suppression against the same evaluation_id", async () => {
    const h = harness();
    expect(await hold(h)).toEqual({ ok: true, result: HELD });
    const permit = h.lastDecision();
    const evaluationId = permit?.context.decision_id as string;

    h.replay(permit);
    const again = await hold(h);
    expect(again).toEqual({ ok: false, refusal_reason: "permit_consumed" });
    expect(h.executions().map((e) => [e.content.outcome, e.content.error, e.content.evaluation_id, e.content.emitter.role])).toEqual([
      ["suppressed", "permit_consumed", evaluationId, "pep"],
    ]);
    expect(h.store?.consumedPermits().map((c) => c.evaluationId)).toEqual([evaluationId]);
    h.store?.close();
  });

  it("a presentation refused before redemption burns nothing, and two concurrent presentations of that Decision release at most one hold", async () => {
    const h = harness();
    // Refused at the final permit-use check (the permit expired during the
    // awaited reads), which runs before redemption.
    const refused = await h.server.callWriteTool("hold_transfer", { invoice_id: "inv-1" }, TOKEN, () => h.advance(301_000));
    expect(refused).toEqual({ ok: false, refusal_reason: "permit_expired" });
    expect(h.store?.consumedPermits()).toEqual([]);
    const permit = h.lastDecision();
    expect(conditionsOf(permit)?.use_limit).toBe(1);

    // Back inside the window, the same unconsumed Decision presented twice at
    // once: both are admitted and wait at the awaited reverification until
    // both are there, so neither has redeemed when the other proceeds.
    h.advance(-301_000);
    h.replay(permit);
    let arrived = 0;
    let release: () => void = () => {};
    const barrier = new Promise<void>((resolve) => {
      release = resolve;
    });
    const atReverification = async () => {
      arrived += 1;
      if (arrived === 2) release();
      await barrier;
    };
    const present = () =>
      h.server.callWriteTool("hold_transfer", { invoice_id: "inv-1" }, TOKEN, undefined, undefined, { atReverification });
    const results = await Promise.all([present(), present()]);
    expect(arrived).toBe(2);
    expect(results.filter((r) => r.ok)).toEqual([{ ok: true, result: HELD }]);
    expect(results.filter((r) => !r.ok)).toEqual([{ ok: false, refusal_reason: "permit_consumed" }]);
    expect(h.executions().map((e) => e.content.error)).toEqual(["permit_expired", "permit_consumed"]);
    expect(h.store?.consumedPermits()).toHaveLength(1);
    h.store?.close();
  });

  it("the consumed record survives a store reopen: a new server on the same file refuses the replay permit_consumed with no hold", async () => {
    const file = tempFile();
    const before = harness({ file });
    expect(await hold(before)).toEqual({ ok: true, result: HELD });
    const permit = before.lastDecision();
    before.store?.close();

    const after = harness({ file });
    after.replay(permit);
    const replayed = await hold(after);
    expect(replayed).toEqual({ ok: false, refusal_reason: "permit_consumed" });
    expect(after.executions().map((e) => [e.content.outcome, e.content.error])).toEqual([["suppressed", "permit_consumed"]]);
    after.store?.close();
  });

  it("a consumed-identifier store that cannot be written refuses consumption_unavailable with no hold, and a server with no store configured does not start", async () => {
    const broken = harness();
    broken.store?.close();
    const failed = await hold(broken);
    expect(failed).toEqual({ ok: false, refusal_reason: "consumption_unavailable" });
    expect(broken.executions().map((e) => [e.content.outcome, e.content.error])).toEqual([["suppressed", "consumption_unavailable"]]);

    // @spec runtime#permit-binding (D333): no served consequential_write runs
    // without its control's enforcing store.
    expect(() => harness({ store: "none" })).toThrow(/has no configured enforcing store/);
  });

  it("a use_limit other than 1, which this PEP cannot meter, is refused condition_unrecognized with no hold and no consumed record", async () => {
    const h = harness();
    h.mutateDecision((d) => ({
      ...d,
      context: { ...d.context, conditions: { ...(d.context.conditions as Record<string, unknown>), use_limit: 2 } },
    }));
    const res = await hold(h);
    expect(res).toEqual({ ok: false, refusal_reason: "unrecognized_condition" });
    expect(h.executions().map((e) => e.content.error)).toEqual(["condition_unrecognized"]);
    expect(h.store?.consumedPermits()).toEqual([]);
    h.store?.close();
  });

  it("a hold_transfer sent down the read path is served by the write path, so its replay is refused permit_consumed", async () => {
    const h = harness();
    const first = await h.server.callReadTool("hold_transfer", { invoice_id: "inv-1" }, TOKEN);
    expect(first).toEqual({ ok: true, result: HELD });
    h.replay(h.lastDecision());
    const again = await h.server.callReadTool("hold_transfer", { invoice_id: "inv-1" }, TOKEN);
    expect(again).toEqual({ ok: false, refusal_reason: "permit_consumed" });
    h.store?.close();
  });

  it("retains each consumed identifier through the permit's whole acceptance window: until valid_until plus the margin, and a sweep at valid_until keeps it", async () => {
    const h = harness();
    expect(await hold(h)).toEqual({ ok: true, result: HELD });
    const permit = h.lastDecision();
    const validUntilMs = Date.parse(conditionsOf(permit)?.valid_until ?? "");
    expect(h.store?.consumedPermits().map((c) => c.retainUntilMs)).toEqual([validUntilMs + CONSUMED_PERMIT_RETENTION_MARGIN_MS]);

    // The last instant this PEP still accepts the permit: the record stands.
    h.advance(validUntilMs - BASE_MS);
    expect(h.store?.sweepConsumedPermits()).toBe(0);
    h.replay(permit);
    expect(await hold(h)).toEqual({ ok: false, refusal_reason: "permit_consumed" });

    // Past the retention the sweep removes it, and the permit itself is long expired.
    h.advance(CONSUMED_PERMIT_RETENTION_MARGIN_MS + 1);
    expect(h.store?.sweepConsumedPermits()).toBe(1);
    expect(await hold(h)).toEqual({ ok: false, refusal_reason: "permit_expired" });
    h.store?.close();
  });
});

/** Every Decision the harness's PDP issues carries `use_limit: n`, as the #1136 review's probe injected it. */
const withUseLimit =
  (n: number) =>
  (d: Decision): Decision => ({
    ...d,
    context: { ...d.context, conditions: { ...(d.context.conditions as Record<string, unknown>), use_limit: n } },
  });
const keyed = (h: Harness, tool: "schedule_payment" | "cancel_scheduled_payment", idempotencyKey: string) =>
  h.server.callWriteTool(tool, { invoice_id: "inv-1", idempotency_key: idempotencyKey }, TOKEN);

describe("a use_limit a keyed write's permit carries is metered, never ignored (@spec runtime#single-use-identifiers, #1136 review, D317)", () => {
  it("the review's probe: scheduled under a use_limit: 1 permit, cancelled under a fresh Decision, the original permit replayed under another key is refused permit_consumed and schedules nothing", async () => {
    const h = harness();
    // The PDP issues no use_limit on a keyed write; the probe injects one.
    h.mutateDecision(withUseLimit(1));
    const scheduled = await keyed(h, "schedule_payment", `idem_${randomUUID()}`);
    expect(scheduled.ok, JSON.stringify(scheduled)).toBe(true);
    const permit = h.lastDecision();
    expect(conditionsOf(permit)?.use_limit).toBe(1);
    const evaluationId = permit?.context.decision_id as string;
    expect(h.store?.consumedPermits().map((c) => c.evaluationId)).toEqual([evaluationId]);

    // A separately authorized cancellation, under its own fresh Decision.
    h.mutateDecision(undefined);
    const cancelled = await keyed(h, "cancel_scheduled_payment", `idem_${randomUUID()}`);
    expect(cancelled.ok, JSON.stringify(cancelled)).toBe(true);
    expect(conditionsOf(h.lastDecision())?.use_limit).toBeUndefined();

    // The original permit, presented again under a key no reservation holds.
    h.replay(permit);
    const replayed = await keyed(h, "schedule_payment", `idem_${randomUUID()}`);
    expect(replayed).toEqual({ ok: false, refusal_reason: "permit_consumed" });
    expect(h.store?.schedules().map((s) => s.state)).toEqual(["cancelled"]);
    expect(h.store?.reservations()).toHaveLength(2);
    expect(h.store?.consumedPermits().map((c) => c.evaluationId)).toEqual([evaluationId]);
    const last = h.executions().at(-1);
    expect([last?.content.outcome, last?.content.error, last?.content.evaluation_id]).toEqual([
      "suppressed",
      "permit_consumed",
      evaluationId,
    ]);
    h.store?.close();
  });

  it("the consumed permit replayed under its own key is refused permit_consumed before the retained result is disclosed; a keyed effect that refuses consumes nothing; a use_limit other than 1 is refused condition_unrecognized", async () => {
    const h = harness();
    h.mutateDecision(withUseLimit(1));
    const k = `idem_${randomUUID()}`;
    const first = await keyed(h, "schedule_payment", k);
    expect(first.ok, JSON.stringify(first)).toBe(true);
    const permit = h.lastDecision();
    h.replay(permit);
    const retrieved = await keyed(h, "schedule_payment", k);
    expect(retrieved).toEqual({ ok: false, refusal_reason: "permit_consumed" });
    expect(h.executions().at(-1)?.content.error).toBe("permit_consumed");

    // A fresh single-use permit whose effect refuses (the invoice is already
    // scheduled) is not consumed: the refusal is the effect's, and it ran nothing.
    h.replay(undefined);
    const refused = await keyed(h, "schedule_payment", `idem_${randomUUID()}`);
    expect(refused).toEqual({ ok: false, refusal_reason: "schedule_exists", next_action: "none" });
    const refusedId = h.lastDecision()?.context.decision_id;
    expect(refusedId).not.toBe(permit?.context.decision_id);
    expect(h.store?.consumedPermits().map((c) => c.evaluationId)).toEqual([permit?.context.decision_id]);

    h.mutateDecision(withUseLimit(2));
    const unmeterable = await keyed(h, "cancel_scheduled_payment", `idem_${randomUUID()}`);
    expect(unmeterable).toEqual({ ok: false, refusal_reason: "unrecognized_condition" });
    expect(h.executions().at(-1)?.content.error).toBe("condition_unrecognized");
    expect(h.store?.schedules().map((s) => s.state)).toEqual(["scheduled"]);
    expect(h.store?.reservations()).toHaveLength(1);
    h.store?.close();
  });

  it("a keyed presentation refused before admission's transaction burns nothing, and two concurrent presentations of that use_limit: 1 Decision under different keys schedule once", async () => {
    const h = harness();
    h.mutateDecision(withUseLimit(1));
    // Refused at the final permit-use check (the permit expired during the
    // awaited reads), which runs before the reservation's transaction.
    const refused = await h.server.callWriteTool(
      "schedule_payment",
      { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` },
      TOKEN,
      () => h.advance(301_000),
    );
    expect(refused).toEqual({ ok: false, refusal_reason: "permit_expired" });
    expect(h.store?.consumedPermits()).toEqual([]);
    const permit = h.lastDecision();
    expect(conditionsOf(permit)?.use_limit).toBe(1);

    // Back inside the window, the same unconsumed Decision presented twice at
    // once under two keys, both held at the reverification barrier.
    h.advance(-301_000);
    h.mutateDecision(undefined);
    h.replay(permit);
    const atReverification = barrier(2);
    const present = (key: string) =>
      h.server.callWriteTool("schedule_payment", { invoice_id: "inv-1", idempotency_key: key }, TOKEN, undefined, undefined, {
        atReverification: atReverification.wait,
      });
    const results = await Promise.all([present(`idem_${randomUUID()}`), present(`idem_${randomUUID()}`)]);
    expect(atReverification.arrived()).toBe(2);
    expect(results.filter((r) => r.ok)).toHaveLength(1);
    expect(results.filter((r) => !r.ok)).toEqual([{ ok: false, refusal_reason: "permit_consumed" }]);
    expect(h.store?.schedules().map((s) => s.state)).toEqual(["scheduled"]);
    expect(h.store?.consumedPermits().map((c) => c.evaluationId)).toEqual([permit?.context.decision_id]);
    h.store?.close();
  });
});

/** A barrier that releases every waiter once `n` have arrived. */
function barrier(n: number): { wait: () => Promise<void>; arrived: () => number } {
  let count = 0;
  let release: () => void = () => {};
  const open = new Promise<void>((resolve) => {
    release = resolve;
  });
  return {
    wait: async () => {
      count += 1;
      if (count === n) release();
      await open;
    },
    arrived: () => count,
  };
}

/**
 * A harness whose PDP issues one schedule under a key with no use limit, the
 * retained record later retrievals resolve against: the original result and
 * the key it is retained under.
 */
async function scheduledUnderKey(h: Harness): Promise<{ key: string; result: unknown }> {
  const key = `idem_${randomUUID()}`;
  const original = await keyed(h, "schedule_payment", key);
  expect(original.ok, JSON.stringify(original)).toBe(true);
  expect(conditionsOf(h.lastDecision())?.use_limit).toBeUndefined();
  return { key, result: original.result };
}

/** A fresh `use_limit: 1` Decision for `schedule_payment`, taken unconsumed: refused at admission before its transaction. */
async function unconsumedSingleUsePermit(h: Harness): Promise<Decision | undefined> {
  h.mutateDecision(withUseLimit(1));
  const refused = await h.server.callWriteTool(
    "schedule_payment",
    { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` },
    TOKEN,
    () => h.advance(301_000),
  );
  expect(refused).toEqual({ ok: false, refusal_reason: "permit_expired" });
  h.advance(-301_000);
  h.mutateDecision(undefined);
  const permit = h.lastDecision();
  expect(conditionsOf(permit)?.use_limit).toBe(1);
  expect(h.store?.consumedPermits()).toEqual([]);
  return permit;
}

/** The dispositions recorded against one evaluation identifier, in order. */
const dispositionsOf = (h: Harness, d: Decision | undefined) =>
  h
    .executions()
    .filter((e) => e.content.evaluation_id === d?.context.decision_id)
    .map((e) => [e.content.outcome, e.content.error]);

describe("retrieval is a use of a single-use permit (@spec runtime#single-use-identifiers, #1080, D342)", () => {
  it("two retrievals under one identifier: the first releases the retained result and consumes the permit, the second is refused permit_consumed and discloses nothing", async () => {
    const h = harness();
    const original = await scheduledUnderKey(h);
    h.mutateDecision(withUseLimit(1));
    const first = await keyed(h, "schedule_payment", original.key);
    expect(first).toEqual({ ok: true, deduped: true, result: original.result });
    const permit = h.lastDecision();
    expect(h.store?.consumedPermits().map((c) => c.evaluationId)).toEqual([permit?.context.decision_id]);

    h.mutateDecision(undefined);
    h.replay(permit);
    const second = await keyed(h, "schedule_payment", original.key);
    expect(second).toEqual({ ok: false, refusal_reason: "permit_consumed" });
    expect(dispositionsOf(h, permit)).toEqual([
      ["suppressed", "operation_already_claimed"],
      ["suppressed", "permit_consumed"],
    ]);
    expect(h.store?.schedules()).toHaveLength(1);
    h.store?.close();
  });

  it("a retrieval followed by admission under another key: the permit the retrieval consumed is refused permit_consumed and schedules nothing, even after a separately authorized cancellation", async () => {
    const h = harness();
    const original = await scheduledUnderKey(h);
    h.mutateDecision(withUseLimit(1));
    expect(await keyed(h, "schedule_payment", original.key)).toEqual({ ok: true, deduped: true, result: original.result });
    const permit = h.lastDecision();

    h.mutateDecision(undefined);
    const cancelKey = `idem_${randomUUID()}`;
    expect((await keyed(h, "cancel_scheduled_payment", cancelKey)).ok).toBe(true);
    h.replay(permit);
    const admitted = await keyed(h, "schedule_payment", `idem_${randomUUID()}`);
    expect(admitted).toEqual({ ok: false, refusal_reason: "permit_consumed" });
    expect(h.store?.schedules().map((s) => s.state)).toEqual(["cancelled"]);
    expect(h.store?.reservations().map((r) => r.idempotencyKey)).toEqual([original.key, cancelKey]);
    h.store?.close();
  });

  it("two concurrent retrievals of one unconsumed single-use Decision, held after their permit-use checks, release the retained result once", async () => {
    const h = harness();
    const original = await scheduledUnderKey(h);
    const permit = await unconsumedSingleUsePermit(h);
    h.replay(permit);
    const atRetrieval = barrier(2);
    const retrieve = () =>
      h.server.callWriteTool(
        "schedule_payment",
        { invoice_id: "inv-1", idempotency_key: original.key },
        TOKEN,
        undefined,
        undefined,
        { atRetrieval: atRetrieval.wait },
      );
    const results = await Promise.all([retrieve(), retrieve()]);
    expect(atRetrieval.arrived()).toBe(2);
    expect(results.filter((r) => r.ok)).toEqual([{ ok: true, deduped: true, result: original.result }]);
    expect(results.filter((r) => !r.ok)).toEqual([{ ok: false, refusal_reason: "permit_consumed" }]);
    expect(h.store?.consumedPermits().map((c) => c.evaluationId)).toEqual([permit?.context.decision_id]);
    expect(h.store?.schedules()).toHaveLength(1);
    h.store?.close();
  });

  it("the concurrent-existing fallback consumes the losing permit: two single-use Decisions under one new key, both admitted, schedule once, and the loser's permit, though it only retrieved, is refused permit_consumed under another key", async () => {
    const h = harness();
    const issued: Decision[] = [];
    h.mutateDecision((d) => {
      const single = withUseLimit(1)(d);
      issued.push(single);
      return single;
    });
    const key = `idem_${randomUUID()}`;
    const atReverification = barrier(2);
    const present = () =>
      h.server.callWriteTool("schedule_payment", { invoice_id: "inv-1", idempotency_key: key }, TOKEN, undefined, undefined, {
        atReverification: atReverification.wait,
      });
    const results = await Promise.all([present(), present()]);
    expect(atReverification.arrived()).toBe(2);
    const winner = results.find((r) => r.ok && !r.deduped);
    expect(winner?.ok).toBe(true);
    expect(results.filter((r) => r.deduped)).toEqual([{ ok: true, deduped: true, result: winner?.result }]);
    expect(issued).toHaveLength(2);
    const ids = issued.map((d) => d.context.decision_id);
    expect(h.store?.consumedPermits().map((c) => c.evaluationId).sort()).toEqual([...ids].sort());

    // The loser retrieved through the fallback; its permit is spent.
    const loser = issued.find((d) => dispositionsOf(h, d).some(([, e]) => e === "operation_already_claimed"));
    expect(loser).toBeDefined();
    h.mutateDecision(undefined);
    expect((await keyed(h, "cancel_scheduled_payment", `idem_${randomUUID()}`)).ok).toBe(true);
    h.replay(loser);
    expect(await keyed(h, "schedule_payment", `idem_${randomUUID()}`)).toEqual({ ok: false, refusal_reason: "permit_consumed" });
    expect(h.store?.schedules().map((s) => s.state)).toEqual(["cancelled"]);
    h.store?.close();
  });

  it("replay after a store reopen: a permit a retrieval consumed is refused permit_consumed by a new server on the same file, under its own key and under another", async () => {
    const file = tempFile();
    const before = harness({ file });
    const original = await scheduledUnderKey(before);
    before.mutateDecision(withUseLimit(1));
    expect(await keyed(before, "schedule_payment", original.key)).toEqual({ ok: true, deduped: true, result: original.result });
    const permit = before.lastDecision();
    before.store?.close();

    const after = harness({ file });
    after.replay(permit);
    expect(await keyed(after, "schedule_payment", original.key)).toEqual({ ok: false, refusal_reason: "permit_consumed" });
    expect(await keyed(after, "schedule_payment", `idem_${randomUUID()}`)).toEqual({ ok: false, refusal_reason: "permit_consumed" });
    expect(dispositionsOf(after, permit)).toEqual([
      ["suppressed", "permit_consumed"],
      ["suppressed", "permit_consumed"],
    ]);
    after.store?.close();
  });

  it("a fresh Decision still retrieves the original result and repeats no effect: a fresh single-use one after the first is consumed, and one with no use limit keeps the key control and consumes nothing", async () => {
    const h = harness();
    const original = await scheduledUnderKey(h);
    h.mutateDecision(withUseLimit(1));
    const spent = await keyed(h, "schedule_payment", original.key);
    const spentPermit = h.lastDecision();
    const fresh = await keyed(h, "schedule_payment", original.key);
    const freshPermit = h.lastDecision();
    expect(freshPermit?.context.decision_id).not.toBe(spentPermit?.context.decision_id);
    expect([spent, fresh]).toEqual([
      { ok: true, deduped: true, result: original.result },
      { ok: true, deduped: true, result: original.result },
    ]);
    expect(h.store?.consumedPermits().map((c) => c.evaluationId)).toEqual([
      spentPermit?.context.decision_id,
      freshPermit?.context.decision_id,
    ]);

    // No use limit: the same Decision retrieves again, and nothing is consumed.
    h.mutateDecision(undefined);
    const unlimited = await keyed(h, "schedule_payment", original.key);
    expect(unlimited).toEqual({ ok: true, deduped: true, result: original.result });
    h.replay(h.lastDecision());
    expect(await keyed(h, "schedule_payment", original.key)).toEqual({ ok: true, deduped: true, result: original.result });
    expect(h.store?.consumedPermits()).toHaveLength(2);
    expect(h.store?.schedules()).toHaveLength(1);
    h.store?.close();
  });

  it("a consumed-identifier store that cannot be written refuses the retrieval consumption_unavailable and discloses nothing: no retained result and no retained-record disposition", async () => {
    const h = harness();
    const original = await scheduledUnderKey(h);
    const store = h.store as WriteReservationStore;
    store.consumePermit = () => {
      throw new Error("the consumed-identifier table cannot be written");
    };
    h.mutateDecision(withUseLimit(1));
    const refused = await keyed(h, "schedule_payment", original.key);
    expect(refused).toEqual({ ok: false, refusal_reason: "consumption_unavailable" });
    expect(dispositionsOf(h, h.lastDecision())).toEqual([["suppressed", "consumption_unavailable"]]);
    expect(store.consumedPermits()).toEqual([]);
    store.close();
  });
});
