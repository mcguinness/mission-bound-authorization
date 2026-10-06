/**
 * @spec runtime#idempotency, runtime#permit-binding (#918, D223): the
 * enforcing PEP's reservation and retention store for keyed reversible
 * writes, end to end through this resource's real PEP, the real PDP, its
 * evidence store, and a real store file.
 *
 * `schedule_payment` and `cancel_scheduled_payment` elect the "short
 * validity window combined with an idempotency key" control. The PDP makes
 * no claim for the key; this PEP reserves the (idempotency scope, key) pair,
 * commits the schedule effect with its completed reservation and result in
 * one local transaction, and retains the record for the published P7D
 * horizon, so a duplicate after the permit's 300 s window resolves against
 * the record. Retrieval of a retained result is separate from admission:
 * it is authorized by the retry's own fresh Decision, held to the at-use
 * check immediately before release, and never by the permit the result was
 * first produced under.
 *
 * Every store here is a real file in a fresh temporary directory on a clock
 * the test drives; the FGA layer is a stub that always permits, so this file
 * never skips.
 */

import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { DurableStoreError, openDurableStore } from "@mission/store";
import { type Fga, type MissionView, RUNTIME_POSTURE, reversibleWritePermitMaxSeconds, type RuntimePosture } from "@mission/pdp";
import {
  CANONICAL_RESOURCE,
  Connectors,
  createEphemeralEvidenceKeys,
  type DecisionEvidenceObject,
  dispatchPathFor,
  EvidenceStore,
  type ExecutionEvidence,
  type ExecutionEvidenceInput,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  openWriteReservationStore,
  PaymentsStore,
  Pep,
  REVERSIBLE_WRITE_REFUSAL_ERRORS,
  type TokenFacts,
  TOOL_ACTIONS,
  TransactionEngine,
  type WriteToolResult,
} from "../src/index.js";
import { ALL_ACTIONS_CREDENTIAL } from "./credential-fixtures.js";

const KEYS = createEphemeralEvidenceKeys();
const BASE_MS = Date.parse("2026-10-02T12:00:00.000Z");
/** The PDP's consequential-write permit window, and one second past it. */
const PAST_PERMIT_MS = 301_000;
/** The published P7D retention horizon, and one second past it. */
const PAST_HORIZON_MS = 7 * 86_400_000 + 1_000;
const ISSUER = "https://as.test";
const OWNER = "mcp-payments-pep";
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
const key = (): string => `idem_${randomUUID()}`;
const tempFile = (): string => join(mkdtempSync(join(tmpdir(), "write-reservation-test-")), "write-reservations.sqlite");

const tokenFor = (missionId: string): TokenFacts => ({
  sub: "alice",
  clientId: "ap-agent",
  mission: { id: missionId, issuer: ISSUER, authority_hash: `sha-256:${missionId}` },
  cnfJkt: "jkt-918",
  credentialAuthority: ALL_ACTIONS_CREDENTIAL,
});
const TOKEN_A = tokenFor("msn_918a");
const TOKEN_B = tokenFor("msn_918b");

const viewFor = (missionId: string): MissionView => ({
  id: missionId,
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: `sha-256:${missionId}`,
  authority_set: [
    {
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:payment.schedule", "payments:payment.schedule.cancel", "payments:payment.execute"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    },
  ],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
});

/**
 * The evidence store, with two holds a test can arm: one on the retention of
 * the PDP's Decision Evidence (the Decision has been reached, nothing is
 * released yet), and one on a post-permit disposition write.
 */
class HeldEvidenceStore extends EvidenceStore {
  holdDecision?: () => Promise<void>;
  holdExecution?: (input: ExecutionEvidenceInput) => Promise<void>;
  override async retainDecision(record: DecisionEvidenceObject) {
    const hold = this.holdDecision;
    this.holdDecision = undefined;
    await hold?.();
    return super.retainDecision(record);
  }
  override async recordExecution(emitterId: string, role: "pep" | "executor", input: ExecutionEvidenceInput) {
    await this.holdExecution?.(input);
    return super.recordExecution(emitterId, role, input);
  }
}

/**
 * The shipped statement with a 30 s permit maximum and a 60 s retention for
 * both keyed writes: a valid configuration (retention longer than the
 * permit), the one the #1028 review reproduced against.
 */
function shortWindowStatement(): RuntimePosture {
  const statement = structuredClone(RUNTIME_POSTURE) as unknown as {
    extensions: { reversible_write_idempotency: Array<Record<string, unknown>> };
  };
  for (const d of statement.extensions.reversible_write_idempotency) {
    d.permit_validity_max_seconds = 30;
    d.retention_horizon = "PT60S";
  }
  return statement as unknown as RuntimePosture;
}

function harness(o: { file?: string; statement?: RuntimePosture } = {}) {
  let nowMs = BASE_MS;
  const now = () => new Date(nowMs);
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [
      { id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
      { id: "inv-2", vendor_id: "acme", amount: "75.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
    ],
  );
  const views: Record<string, MissionView> = { msn_918a: viewFor("msn_918a"), msn_918b: viewFor("msn_918b") };
  const loadView = (ref: { id: string; issuer: string }) => {
    const view = ref.issuer === ISSUER ? views[ref.id] : undefined;
    return view ? { view, observation: { state: view.state, version: view.version, mode: "fresh", freshness_at: now().toISOString() } } : undefined;
  };
  const evidence = new HeldEvidenceStore(KEYS.signing, KEYS.resolver);
  const connectors = new Connectors(now);
  const engine = new TransactionEngine("epoch-918", now);
  const file = o.file ?? tempFile();
  const store = openWriteReservationStore({ file, owner: OWNER, now });
  const statement = o.statement;
  const pep = new Pep({
    // A non-shipped statement reaches the PDP the way the shipped one does:
    // as its declared permit maximum per keyed operation.
    decide: statement
      ? (req, options) =>
          KEYS.decide(req, {
            ...options,
            reversibleWritePermitMaxSeconds: (c, a) => reversibleWritePermitMaxSeconds(statement, c, a),
          } as typeof options)
      : KEYS.decide,
    payments,
    evidence,
    fga: alwaysAllowFga,
    modelId: "model-918",
    loadView,
    instanceEpoch: "epoch-918",
    now,
  });
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
    jwks: { keys: [] },
    keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] },
    issuer: ISSUER,
    transaction: { engine, connectors, evidence },
    writeReservations: store,
    ...(statement ? { enforcementScopeStatement: statement } : {}),
  });
  const executions = (missionId = "msn_918a") =>
    evidence.forMission(missionId).filter((e): e is ExecutionEvidence => e.kind === "execution");
  return {
    server,
    pep,
    payments,
    evidence,
    connectors,
    engine,
    store,
    file,
    executions,
    advance: (ms: number) => {
      nowMs += ms;
    },
  };
}
type Harness = ReturnType<typeof harness>;

const schedule = (h: Harness, idempotencyKey: string, token = TOKEN_A, invoiceId = "inv-1") =>
  h.server.callWriteTool("schedule_payment", { invoice_id: invoiceId, idempotency_key: idempotencyKey }, token);
const cancel = (h: Harness, idempotencyKey: string, token = TOKEN_A, invoiceId = "inv-1") =>
  h.server.callWriteTool("cancel_scheduled_payment", { invoice_id: invoiceId, idempotency_key: idempotencyKey }, token);
const scheduleId = (r: WriteToolResult) => (r.result as { schedule_id?: string } | undefined)?.schedule_id;

describe("the PEP's reservation and retention for keyed reversible writes (@spec runtime#idempotency, #918)", () => {
  describe("a changed operation under the same key is a conflict", () => {
    it("a retry under the same key after the invoice changed is refused operation_identity_conflict, with one schedule and the conflict recorded through the post-permit writer", async () => {
      const h = harness();
      const k = key();
      const first = await schedule(h, k);
      expect(first.ok, JSON.stringify(first)).toBe(true);
      h.payments.bumpInvoiceAmount("inv-1", "130.00");

      const changed = await schedule(h, k);
      expect(changed.ok).toBe(false);
      expect(changed.refusal_reason).toBe("operation_identity_conflict");
      expect(changed.next_action).toBe("none");
      expect(changed).not.toHaveProperty("result");
      expect(h.store.schedules().map((s) => [s.amount, s.state])).toEqual([["125.00", "scheduled"]]);
      // A post-permit disposition of the fresh permit, never a PDP denial.
      const records = h.executions();
      expect(records.map((r) => [r.content.outcome, r.content.error, r.content.emitter.role])).toEqual([
        ["suppressed", "operation_identity_conflict", "pep"],
      ]);
      expect(h.evidence.forMission("msn_918a").filter((e) => e.kind === "refusal")).toHaveLength(0);
      h.store.close();
    });
  });

  describe("concurrent duplicates execute once", () => {
    it("eight concurrent schedules under one key: one schedule and one reservation; seven get the winner's result, deduped, and record operation_already_claimed", async () => {
      const h = harness();
      const k = key();
      // Every attempt finds the pair free and then waits at the awaited
      // reverification until all eight are there, so the winner is decided by
      // the in-transaction re-read alone.
      let arrived = 0;
      let release: () => void = () => {};
      const barrier = new Promise<void>((resolve) => {
        release = resolve;
      });
      const atReverification = async () => {
        arrived += 1;
        if (arrived === 8) release();
        await barrier;
      };
      const results = await Promise.all(
        Array.from({ length: 8 }, () =>
          h.server.callWriteTool(
            "schedule_payment",
            { invoice_id: "inv-1", idempotency_key: k },
            TOKEN_A,
            undefined,
            undefined,
            { atReverification },
          ),
        ),
      );
      expect(arrived).toBe(8);
      const winners = results.filter((r) => r.ok && !r.deduped);
      const deduped = results.filter((r) => r.ok && r.deduped);
      expect(winners, JSON.stringify(results)).toHaveLength(1);
      expect(deduped).toHaveLength(7);
      for (const r of deduped) expect(r.result).toEqual(winners[0]?.result);
      expect(h.store.schedules().map((s) => s.schedule_id)).toEqual([scheduleId(winners[0] as WriteToolResult)]);
      expect(h.store.reservations()).toHaveLength(1);
      expect(h.executions().filter((r) => r.content.error === "operation_already_claimed")).toHaveLength(7);
      h.store.close();
    });
  });

  describe("the persisted store reopens with the record", () => {
    it("a key scheduled before the store closed resolves against its record from a new server on the same file", async () => {
      const file = tempFile();
      const before = harness({ file });
      const k = key();
      const first = await schedule(before, k);
      expect(first.ok, JSON.stringify(first)).toBe(true);
      before.store.close();

      const after = harness({ file });
      const retry = await schedule(after, k);
      expect(retry.ok, JSON.stringify(retry)).toBe(true);
      expect(retry.deduped).toBe(true);
      expect(retry.result).toEqual(first.result);
      expect(after.store.schedules().map((s) => s.schedule_id)).toEqual([scheduleId(first)]);
      after.store.close();
    });

    it("refuses a second handle on a held file, an absent or in-memory file, another owner's file, a newer schema, and a store the statement does not name as the domain", () => {
      const file = tempFile();
      const held = openWriteReservationStore({ file, owner: OWNER });
      expect(() => openWriteReservationStore({ file, owner: OWNER })).toThrow(DurableStoreError);
      held.close();
      expect(() => openWriteReservationStore({ file: undefined, owner: OWNER })).toThrow(/no store file is configured/);
      expect(() => openWriteReservationStore({ file: ":memory:", owner: OWNER })).toThrow(/in-memory store is not durable/);
      expect(() => openWriteReservationStore({ file, owner: "mcp-payments-pdp" })).toThrow(/owned by mcp-payments-pep/);
      // A build that migrated this file one version further than this
      // build's two (the reservations, then the consumed identifiers, #1080).
      const newer = tempFile();
      openWriteReservationStore({ file: newer, owner: OWNER }).close();
      openDurableStore({ file: newer, owner: OWNER, migrations: ["SELECT 1", "SELECT 1", "SELECT 1"] }).close();
      expect(() => openWriteReservationStore({ file: newer, owner: OWNER })).toThrow(/newer than this build/);
      // The statement names mcp-payments-pep as the reservation owner.
      const foreign = openEphemeralWriteReservationStore({ owner: "another-pep" });
      expect(
        () =>
          new McpPaymentsServer({
            pep: {} as Pep,
            payments: new PaymentsStore(),
            loadView: () => undefined,
            jwks: { keys: [] },
            keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] },
            issuer: ISSUER,
            writeReservations: foreign,
          }),
      ).toThrow(/owned by mcp-payments-pep, not another-pep/);
      foreign.close();
    });
  });

  describe("retrieval is separate from admission and is authorized by the retry's own Decision", () => {
    it("after the original permit expired, a retry with a valid new Decision retrieves the retained result without reaching admission; the expired original attempt replayed into the effect step is refused permit_expired; past the horizon the key is new", async () => {
      const h = harness();
      const k = key();
      const original = await h.pep.enforce("schedule_payment", { invoice_id: "inv-1", idempotency_key: k }, TOKEN_A);
      // A second Decision taken at the same time and never used.
      const unused = await h.pep.enforce("schedule_payment", { invoice_id: "inv-2", idempotency_key: key() }, TOKEN_A);
      const first = await h.server.admitReversibleWrite("schedule_payment", TOKEN_A, original);
      expect(first.ok, JSON.stringify(first)).toBe(true);

      h.advance(PAST_PERMIT_MS);
      let admissionReached = false;
      const retry = await h.server.callWriteTool(
        "schedule_payment",
        { invoice_id: "inv-1", idempotency_key: k },
        TOKEN_A,
        () => {
          admissionReached = true;
        },
      );
      expect(retry.ok, JSON.stringify(retry)).toBe(true);
      expect(retry.deduped).toBe(true);
      expect(retry.result).toEqual(first.result);
      expect(admissionReached).toBe(false);

      // The expired permits, presented again at the effect step, admit nothing.
      const replayed = await h.server.admitReversibleWrite("schedule_payment", TOKEN_A, original);
      expect(replayed).toEqual({ ok: false, refusal_reason: "permit_expired" });
      const stale = await h.server.admitReversibleWrite("schedule_payment", TOKEN_A, unused);
      expect(stale).toEqual({ ok: false, refusal_reason: "permit_expired" });
      expect(h.store.schedules().map((s) => s.invoice_id)).toEqual(["inv-1"]);
      expect(h.store.reservations()).toHaveLength(1);
      expect(
        h.executions().filter((r) => r.content.error === "permit_expired").map((r) => r.content.evaluation_id).sort(),
      ).toEqual([original.attempt?.evaluationId, unused.attempt?.evaluationId].sort());

      // Past the published horizon the record is outside the guarantee: once
      // the schedule is cancelled, the same key is a new execution.
      expect((await cancel(h, key())).ok).toBe(true);
      h.advance(PAST_HORIZON_MS);
      const renewed = await schedule(h, k);
      expect(renewed.ok, JSON.stringify(renewed)).toBe(true);
      expect(renewed.deduped).toBeUndefined();
      expect(scheduleId(renewed)).not.toBe(scheduleId(first));
      expect(h.store.schedules().map((s) => s.state)).toEqual(["cancelled", "scheduled"]);
      h.store.close();
    });

    it("a new Decision that expires before release discloses nothing: held after the Decision, the at-use check suppresses permit_expired; held at the disposition write, the release-time check refuses", async () => {
      const h = harness();
      const k = key();
      expect((await schedule(h, k)).ok).toBe(true);

      // The Decision is reached, then its evidence write is held past the
      // permit's valid_until before anything is looked up or released.
      h.evidence.holdDecision = async () => h.advance(PAST_PERMIT_MS);
      const heldAtDecision = await schedule(h, k);
      expect(heldAtDecision).toEqual({ ok: false, refusal_reason: "permit_expired" });
      const suppressed = h.executions().at(-1);
      expect([suppressed?.content.outcome, suppressed?.content.error]).toEqual(["suppressed", "permit_expired"]);

      // The disposition write itself is held past the permit's valid_until.
      h.evidence.holdExecution = async (input) => {
        if (input.error === "operation_already_claimed") {
          h.evidence.holdExecution = undefined;
          h.advance(PAST_PERMIT_MS);
        }
      };
      const heldAtRelease = await schedule(h, k);
      expect(heldAtRelease).toEqual({ ok: false, refusal_reason: "permit_expired" });

      // Nor does it disclose which kind of record the key holds: a changed
      // operation whose conflict record is held past valid_until is refused
      // permit_expired, not operation_identity_conflict.
      h.payments.bumpInvoiceAmount("inv-1", "130.00");
      h.evidence.holdExecution = async (input) => {
        if (input.error === "operation_identity_conflict") {
          h.evidence.holdExecution = undefined;
          h.advance(PAST_PERMIT_MS);
        }
      };
      const heldConflict = await schedule(h, k);
      expect(heldConflict).toEqual({ ok: false, refusal_reason: "permit_expired" });
      expect(h.store.schedules()).toHaveLength(1);
      h.store.close();
    });
  });

  describe("the permit never outlives its reservation's retention (@spec runtime#permit-binding, #1028 review)", () => {
    it("with a 30 s permit maximum and a 60 s retention, the original permit replayed after the record expired is refused permit_expired and nothing executes", async () => {
      const h = harness({ statement: shortWindowStatement() });
      const issuedAtMs = BASE_MS;
      const original = await h.pep.enforce("schedule_payment", { invoice_id: "inv-1", idempotency_key: key() }, TOKEN_A);
      const validUntil = (original.decision?.context.conditions as { valid_until: string }).valid_until;
      const first = await h.server.admitReversibleWrite("schedule_payment", TOKEN_A, original);
      expect(first.ok, JSON.stringify(first)).toBe(true);
      expect((await cancel(h, key())).ok).toBe(true);

      // Past the 60 s retention, the schedule's record is outside the
      // guarantee; the permit it was made under expired at 30 s.
      h.advance(61_000);
      const replayed = await h.server.admitReversibleWrite("schedule_payment", TOKEN_A, original);
      expect(replayed).toEqual({ ok: false, refusal_reason: "permit_expired" });
      expect(h.store.schedules().map((s) => s.state)).toEqual(["cancelled"]);
      expect(h.connectors.ledgerEntries()).toHaveLength(0);
      // Because the PDP issued it under the published 30 s maximum.
      expect(Date.parse(validUntil) - issuedAtMs).toBeLessThanOrEqual(30_000);
      h.store.close();
    });
  });

  describe("an unresolved outcome is never executed again", () => {
    it("a fault inside the transaction leaves neither the schedule nor the reservation, and the retry executes once", async () => {
      const h = harness();
      const k = key();
      const crashed = await h.server.callWriteTool(
        "schedule_payment",
        { invoice_id: "inv-1", idempotency_key: k },
        TOKEN_A,
        undefined,
        undefined,
        {
          insideTransaction: () => {
            throw new Error("crash inside the transaction");
          },
        },
      );
      expect(crashed).toEqual({ ok: false, refusal_reason: "consumption_unavailable" });
      expect(h.store.schedules()).toHaveLength(0);
      expect(h.store.reservations()).toHaveLength(0);
      const retry = await schedule(h, k);
      expect(retry.ok, JSON.stringify(retry)).toBe(true);
      expect(retry.deduped).toBeUndefined();
      expect(h.store.schedules()).toHaveLength(1);
      h.store.close();
    });

    it("a fault after the commit, before the response, resolves the retry against the retained result", async () => {
      const h = harness();
      const k = key();
      await expect(
        h.server.callWriteTool("schedule_payment", { invoice_id: "inv-1", idempotency_key: k }, TOKEN_A, undefined, undefined, {
          afterCommit: () => {
            throw new Error("response lost");
          },
        }),
      ).rejects.toThrow("response lost");
      const retry = await schedule(h, k);
      expect(retry.ok, JSON.stringify(retry)).toBe(true);
      expect(retry.deduped).toBe(true);
      expect(h.store.schedules()).toHaveLength(1);
      expect(scheduleId(retry)).toBe(h.store.schedules()[0]?.schedule_id);
      h.store.close();
    });

    it("a reserved record is refused duplicate_suppressed and never executed, and time never purges it", async () => {
      const h = harness();
      const k = key();
      expect((await schedule(h, k)).ok).toBe(true);
      // A reservation whose effect is not known to have committed.
      h.store.db
        .prepare("UPDATE write_reservations SET state = 'reserved', result_json = NULL, completed_at_ms = NULL, retain_until_ms = NULL")
        .run();
      h.store.db.prepare("DELETE FROM payment_schedules").run();

      const refused = await schedule(h, k);
      expect(refused).toEqual({ ok: false, refusal_reason: "duplicate_suppressed", next_action: "retry" });
      expect(h.store.schedules()).toHaveLength(0);
      h.advance(PAST_HORIZON_MS);
      expect(h.store.sweep()).toBe(0);
      const later = await schedule(h, k);
      expect(later.refusal_reason).toBe("duplicate_suppressed");
      expect(h.store.schedules()).toHaveLength(0);
      expect(h.store.reservations().map((r) => r.state)).toEqual(["reserved"]);
      expect(h.executions().filter((r) => r.content.error === "operation_already_claimed")).toHaveLength(2);
    });

    it("an unreachable store refuses consumption_unavailable and executes nothing", async () => {
      const h = harness();
      h.store.close();
      const refused = await schedule(h, key());
      expect(refused).toEqual({ ok: false, refusal_reason: "consumption_unavailable" });
      expect(h.executions().map((r) => [r.content.outcome, r.content.error])).toEqual([
        ["suppressed", "consumption_unavailable"],
      ]);
    });
  });

  describe("the reservation scope keys on a stable actor (@spec runtime#idempotency, #1016 review)", () => {
    const instanceLeaf = (sub: string) => ({ iss: ISSUER, sub, sub_profile: "client_instance" });

    it("another instance of the same client, carried as an instance-profiled leaf, retries into the same scope and executes nothing new", async () => {
      const h = harness();
      const k = key();
      const first = await schedule(h, k, { ...TOKEN_A, act: instanceLeaf("instance-1") } as TokenFacts);
      expect(first.ok, JSON.stringify(first)).toBe(true);
      const other = await schedule(h, k, { ...TOKEN_A, act: instanceLeaf("instance-2") } as TokenFacts);
      expect(other).toEqual({ ok: true, deduped: true, result: first.result });
      expect(h.store.schedules()).toHaveLength(1);
      expect(h.store.reservations()).toHaveLength(1);
      h.store.close();
    });

    it("an instance-profiled leaf with no client to key it on has no stable actor: the write is refused after its permit, executes nothing, and leaves no reservation", async () => {
      const h = harness();
      const { clientId: _client, ...noClient } = TOKEN_A;
      const token = { ...noClient, act: instanceLeaf("instance-1") } as TokenFacts;
      const refused = await schedule(h, key(), token);
      expect(refused).toEqual({ ok: false, refusal_reason: "actor_unkeyable", next_action: "none" });
      expect(h.store.schedules()).toHaveLength(0);
      expect(h.store.reservations()).toHaveLength(0);
      // A post-permit disposition through the one writer: the PDP permitted
      // (it makes no claim for this key), and the PEP suppressed.
      const permits = h.evidence
        .forMission("msn_918a")
        .filter((e) => e.kind === "decision" && (e.content as { decision?: string }).decision === "permit");
      expect(permits).toHaveLength(1);
      expect(h.executions().map((r) => [r.content.outcome, r.content.error])).toEqual([
        ["suppressed", REVERSIBLE_WRITE_REFUSAL_ERRORS.actor_unkeyable],
      ]);
      h.store.close();
    });
  });

  describe("the schedule is a real, cancellable state that cannot pay", () => {
    it("cancel moves the Mission's active schedule to cancelled, idempotently per key, and the connector ledger stays empty", async () => {
      const h = harness();
      const scheduled = await schedule(h, key());
      expect(scheduled.ok, JSON.stringify(scheduled)).toBe(true);
      expect(scheduled.result).toEqual({
        scheduled: true,
        schedule_id: scheduleId(scheduled),
        invoice_id: "inv-1",
        amount: { amount: "125.00", currency: "USD" },
      });
      const c = key();
      const cancelled = await cancel(h, c);
      expect(cancelled.ok, JSON.stringify(cancelled)).toBe(true);
      expect(cancelled.result).toEqual({ cancelled: true, schedule_id: scheduleId(scheduled), invoice_id: "inv-1" });
      const again = await cancel(h, c);
      expect(again).toEqual({ ok: true, deduped: true, result: cancelled.result });
      const [row] = h.store.schedules();
      expect(row?.state).toBe("cancelled");
      expect(row?.cancelled_evaluation_id).toMatch(/^dec_/);

      // A new cancel key finds no active schedule: refused, no reservation.
      const nothing = await cancel(h, key());
      expect(nothing).toEqual({ ok: false, refusal_reason: "schedule_not_found", next_action: "none" });
      expect(h.store.reservations()).toHaveLength(2);
      expect(h.executions().at(-1)?.content.error).toBe(REVERSIBLE_WRITE_REFUSAL_ERRORS.schedule_not_found);

      // Nothing here moved money or opened a transaction-tier operation.
      expect(h.connectors.ledgerEntries()).toHaveLength(0);
      expect(h.engine.db.prepare("SELECT COUNT(*) AS n FROM operations").get()).toEqual({ n: 0 });
      h.store.close();
    });

    it("another Mission's cancel finds no schedule and changes nothing", async () => {
      const h = harness();
      expect((await schedule(h, key(), TOKEN_A)).ok).toBe(true);
      const foreign = await cancel(h, key(), TOKEN_B);
      expect(foreign).toEqual({ ok: false, refusal_reason: "schedule_not_found", next_action: "none" });
      expect(h.store.schedules().map((s) => [s.mission_id, s.state])).toEqual([["msn_918a", "scheduled"]]);
      expect(h.store.reservations()).toHaveLength(1);
      h.store.close();
    });

    it("a new key on an invoice the Mission already scheduled is refused schedule_exists and rewrites nothing", async () => {
      const h = harness();
      const first = await schedule(h, key());
      expect(first.ok).toBe(true);
      const second = await schedule(h, key());
      expect(second).toEqual({ ok: false, refusal_reason: "schedule_exists", next_action: "none" });
      expect(h.store.schedules().map((s) => s.schedule_id)).toEqual([scheduleId(first)]);
      expect(h.store.reservations()).toHaveLength(1);
      expect(h.executions().at(-1)?.content.error).toBe(REVERSIBLE_WRITE_REFUSAL_ERRORS.schedule_exists);
      h.store.close();
    });

    it("a keyed write sent down the read path is served by the write path and its reservation", async () => {
      const h = harness();
      const viaRead = await h.server.callReadTool("schedule_payment", { invoice_id: "inv-1", idempotency_key: key() }, TOKEN_A);
      expect(viaRead.ok, JSON.stringify(viaRead)).toBe(true);
      expect(h.store.schedules()).toHaveLength(1);
      expect(h.store.reservations()).toHaveLength(1);
      h.store.close();
    });

    it("every consequential write takes the write path, and only the transaction-assurance tier reaches callTransactionTool", () => {
      for (const [tool, mapping] of Object.entries(TOOL_ACTIONS)) {
        const expected = mapping.tier ? "transaction" : mapping.actionClass === "consequential_write" ? "write" : "read";
        expect(dispatchPathFor(mapping, true), tool).toBe(expected);
        expect(dispatchPathFor(mapping, false), tool).toBe(expected === "transaction" ? "write" : expected);
      }
      for (const tool of ["schedule_payment", "cancel_scheduled_payment", "hold_transfer"]) {
        expect(dispatchPathFor(TOOL_ACTIONS[tool], true), tool).toBe("write");
      }
    });
  });
});
