/**
 * @spec runtime#failure-modes, runtime-evidence#execution-evidence-object
 * (#1715): on the read and reversible-write paths, a refusal after the
 * permit whose `suppressed` Execution Evidence cannot be written is surfaced,
 * never dropped. The refusal stands with its own reason and nothing executes;
 * beside it the caller reads `gap: "emission_failed"`, and the operator gets
 * one `evidence_emission_failed` alert. The transaction tier's exits are
 * witnessed in pre-effect-attempt.test.ts (#821).
 *
 * Every case acts as the enforcing PEP: its real evidence store, its durable
 * write-reservation file, and the real PDP. Each makes the suppressed write
 * fail on both tries (the one retry included), then restores it and makes the
 * same refusal again as the control: no gap and no alert. The FGA layer is a
 * stub that always permits, so this file never skips.
 */

import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Decision, Fga, MissionView } from "@mission/pdp";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import { describe, expect, it, vi } from "vitest";
import {
  CANONICAL_RESOURCE,
  CollectingAlertSink,
  createEphemeralEvidenceKeys,
  EVIDENCE_UNAVAILABLE_ERROR,
  EvidenceStore,
  type ExecutionEvidence,
  McpPaymentsServer,
  openWriteReservationStore,
  PaymentsStore,
  Pep,
  REVERSIBLE_WRITE_REFUSAL_ERRORS,
  type TokenFacts,
  type WriteReservationStore,
} from "../src/index.js";
import { ALL_ACTIONS_CREDENTIAL } from "./credential-fixtures.js";

const KEYS = createEphemeralEvidenceKeys({ resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE });
const BASE_MS = Date.parse("2026-10-27T12:00:00.000Z");
const ISSUER = "https://as.test";
const OWNER = "mcp-payments-pep";
const MISSION = "msn_1715";
/** Past every permit window this resource's PDP issues. */
const PAST_PERMIT_MS = 3_600_000;
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
const key = (): string => `idem_${randomUUID()}`;
const tempFile = (): string => join(mkdtempSync(join(tmpdir(), "suppression-gap-")), "write-reservations.sqlite");

const TOKEN: TokenFacts = {
  sub: "alice",
  clientId: "ap-agent",
  mission: { id: MISSION, issuer: ISSUER, authority_hash: `sha-256:${MISSION}` },
  cnfJkt: "jkt-1715",
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
      actions: ["payments:invoice.read", "payments:invoice.list"],
      constraints: { vendors: ["acme"] },
    },
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

/**
 * One enforcing PEP over a real PDP, evidence store and reservation file, on
 * a clock the test drives. A Decision can be replayed in place of a fresh one
 * (a re-presentation) or rewritten before the PEP reads it, and a hook runs
 * after each decision.
 */
function harness(o: { store?: "closed" } = {}) {
  let nowMs = BASE_MS;
  const now = () => new Date(nowMs);
  let view: MissionView = VIEW;
  let replayed: Decision | undefined;
  let mutate: ((d: Decision) => Decision) | undefined;
  let afterDecide: (() => void) | undefined;
  let captured: Decision | undefined;
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [
      { id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
      { id: "inv-2", vendor_id: "acme", amount: "75.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
      { id: "inv-g1", vendor_id: "globex", amount: "40.00", currency: "USD", payee_account: "acct-globex", status: "payable" },
    ],
  );
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === MISSION && ref.issuer === ISSUER
      ? { view, observation: { state: view.state, version: view.version, mode: "fresh", freshness_at: now().toISOString() } }
      : undefined;
  const evidence = new EvidenceStore(KEYS.signing, KEYS.resolver);
  const store: WriteReservationStore = openWriteReservationStore({ file: tempFile(), owner: OWNER, now });
  if (o.store === "closed") store.close();
  const alerts = new CollectingAlertSink();
  const pep = new Pep({
    decide: async (req, options) => {
      const decision = replayed ?? (await KEYS.decide(req, options));
      afterDecide?.();
      return mutate ? mutate(decision) : decision;
    },
    observe: ({ decision }) => {
      captured = decision;
    },
    payments,
    evidence,
    fga: alwaysAllowFga,
    modelId: "model-1715",
    loadView,
    instanceEpoch: "epoch-1715",
    now,
  });
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
    jwks: { keys: [] },
    keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] },
    issuer: ISSUER,
    writeReservations: store,
    alerts,
  });
  return {
    server,
    payments,
    evidence,
    store,
    alerts,
    lastDecision: () => captured,
    replay: (d: Decision | undefined) => {
      replayed = d;
    },
    mutateDecision: (m: ((d: Decision) => Decision) | undefined) => {
      mutate = m;
    },
    afterDecide: (hook: (() => void) | undefined) => {
      afterDecide = hook;
    },
    setView: (next: MissionView) => {
      view = next;
    },
    advance: (ms: number) => {
      nowMs += ms;
    },
    executions: () =>
      evidence.forMission(MISSION).flatMap((e) => (e.kind === "execution" ? [(e as ExecutionEvidence).content] : [])),
    close: () => {
      try {
        store.close();
      } catch {
        /* already closed */
      }
    },
  };
}
type Harness = ReturnType<typeof harness>;

/**
 * Fail the PEP's `suppressed` record writes (or, with `all`, every record it
 * writes) until restored. `tries` counts the suppressed writes attempted.
 */
function failWrites(h: Harness, which: "suppressed" | "all" = "suppressed") {
  const original = h.evidence.recordExecution.bind(h.evidence);
  let tries = 0;
  const spy = vi.spyOn(h.evidence, "recordExecution").mockImplementation(async (emitterId, role, input) => {
    if (input.outcome === "suppressed") tries += 1;
    if (which === "all" || input.outcome === "suppressed") throw new Error("evidence store unavailable");
    return original(emitterId, role, input);
  });
  return {
    tries: () => tries,
    restore: () => spy.mockRestore(),
  };
}

/** Run `act` with the suppressed write failing on both tries; return its result. */
async function withFailedSuppression<T>(h: Harness, act: () => Promise<T>, which: "suppressed" | "all" = "suppressed") {
  const failing = failWrites(h, which);
  try {
    const result = await act();
    expect(failing.tries(), `the suppressed write is tried twice, once and its one retry: ${JSON.stringify(result)}`).toBe(2);
    return result;
  } finally {
    failing.restore();
  }
}

/** The one alert a refusal whose suppressed record was not written raises, for the permit last decided. */
function expectOneAlert(h: Harness, count = 1): void {
  expect(h.alerts.alerts).toHaveLength(count);
  expect(h.alerts.alerts.at(-1)).toEqual({
    kind: "evidence_emission_failed",
    evaluation_id: h.lastDecision()?.context.decision_id,
    mission_id: MISSION,
    cause: "suppressed_disposition_unrecorded",
    at: expect.any(String),
  });
}

const read = (h: Harness, beforeReverify?: () => void) =>
  h.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN, beforeReverify);
const list = (h: Harness, beforeReverify?: () => void) => h.server.callReadTool("list_invoices", {}, TOKEN, beforeReverify);
const hold = (h: Harness, beforeReverify?: () => void) =>
  h.server.callWriteTool("hold_transfer", { invoice_id: "inv-1" }, TOKEN, beforeReverify);
const schedule = (h: Harness, idempotencyKey: string, token = TOKEN, beforeReverify?: () => void) =>
  h.server.callWriteTool("schedule_payment", { invoice_id: "inv-1", idempotency_key: idempotencyKey }, token, beforeReverify);
const cancel = (h: Harness, idempotencyKey: string) =>
  h.server.callWriteTool("cancel_scheduled_payment", { invoice_id: "inv-1", idempotency_key: idempotencyKey }, TOKEN);
const withConditions = (extra: Record<string, unknown>) => (d: Decision): Decision => ({
  ...d,
  context: { ...d.context, conditions: { ...(d.context.conditions as Record<string, unknown>), ...extra } },
});

describe("a read or reversible-write refusal whose suppressed record cannot be written is surfaced, never dropped (@spec runtime-evidence#execution-evidence-object, #1715)", () => {
  it("read reverification: a refusal at admission, at the bound list's parameters, or at release still refuses with its own reason, carries gap emission_failed and one alert each, and discloses nothing; written, the same refusals carry neither", async () => {
    const h = harness();
    try {
      const expireAtDecision = () => h.afterDecide(() => h.advance(PAST_PERMIT_MS));
      const expireDuringReads = () => h.advance(PAST_PERMIT_MS);
      const widenScope = () =>
        h.setView({
          ...VIEW,
          // The list entry admits a second vendor after the decision.
          authority_set: VIEW.authority_set.map((e, i) =>
            i === 0 ? { ...e, constraints: { ...e.constraints, vendors: ["acme", "globex"] } } : e,
          ),
        });
      const cases: Array<[string, () => Promise<unknown>, string]> = [
        [
          "admission",
          async () => {
            expireAtDecision();
            try {
              return await read(h);
            } finally {
              h.afterDecide(undefined);
            }
          },
          "permit_expired",
        ],
        [
          "bound list parameters",
          async () => {
            try {
              return await list(h, widenScope);
            } finally {
              h.setView(VIEW);
            }
          },
          "parameter_mismatch",
        ],
        [
          "bound list with no digest condition",
          async () => {
            h.mutateDecision((d) => {
              const { parameter_digest: _digest, ...conditions } = d.context.conditions as Record<string, unknown>;
              return { ...d, context: { ...d.context, conditions } };
            });
            try {
              return await list(h);
            } finally {
              h.mutateDecision(undefined);
            }
          },
          "parameter_mismatch",
        ],
        ["release", () => read(h, expireDuringReads), "permit_expired"],
      ];
      let alerts = 0;
      for (const [label, act, reason] of cases) {
        const refused = await withFailedSuppression(h, act);
        alerts += 1;
        expect(refused, label).toEqual({ ok: false, refusal_reason: reason, gap: "emission_failed" });
        expectOneAlert(h, alerts);
        const written = await act();
        expect(written, label).toEqual({ ok: false, refusal_reason: reason });
        expect(h.alerts.alerts, label).toHaveLength(alerts);
        expect(h.executions().at(-1), label).toMatchObject({ outcome: "suppressed", error: reason });
      }
      // Only the controls' suppressed records exist; no read completed.
      expect(h.executions().map((r) => r.outcome)).toEqual(cases.map(() => "suppressed"));
    } finally {
      h.close();
    }
  });

  it("write reverification: an unkeyed hold and a keyed schedule whose invoice moved after the permit keep their reverification refusals with gap emission_failed and one alert each; nothing is held or scheduled; written, neither carries a gap", async () => {
    const h = harness();
    try {
      const drift = () => h.payments.bumpInvoiceAmount("inv-1", "150.00");
      const restore = () => h.payments.bumpInvoiceAmount("inv-1", "125.00");
      const cases: Array<[string, () => Promise<unknown>, string]> = [
        ["unkeyed hold", () => hold(h, drift), "target_drift"],
        ["keyed schedule", () => schedule(h, key(), TOKEN, drift), "parameter_mismatch"],
      ];
      let alerts = 0;
      for (const [label, act, reason] of cases) {
        const refused = await withFailedSuppression(h, act);
        restore();
        alerts += 1;
        expect(refused, label).toEqual({ ok: false, refusal_reason: reason, gap: "emission_failed" });
        expectOneAlert(h, alerts);
        const written = await act();
        restore();
        expect(written, label).toEqual({ ok: false, refusal_reason: reason });
        expect(h.alerts.alerts, label).toHaveLength(alerts);
        expect(h.executions().at(-1), label).toMatchObject({ outcome: "suppressed", error: reason });
      }
      expect(h.store.consumedPermits()).toEqual([]);
      expect(h.store.schedules()).toEqual([]);
      expect(h.store.reservations()).toEqual([]);
    } finally {
      h.close();
    }
  });

  it("single use: a re-presented hold Decision refused permit_consumed, and a keyed write whose use_limit this PEP cannot meter refused unrecognized_condition, carry gap emission_failed and one alert each; nothing further is held or consumed; written, neither carries a gap", async () => {
    const h = harness();
    try {
      expect(await hold(h)).toEqual({ ok: true, result: { held: true, invoice_id: "inv-1" } });
      const permit = h.lastDecision();
      const consumed = h.store.consumedPermits();
      h.replay(permit);
      const replayed = await withFailedSuppression(h, () => hold(h));
      expect(replayed).toEqual({ ok: false, refusal_reason: "permit_consumed", gap: "emission_failed" });
      expectOneAlert(h, 1);
      expect(await hold(h)).toEqual({ ok: false, refusal_reason: "permit_consumed" });
      h.replay(undefined);
      expect(h.store.consumedPermits()).toEqual(consumed);

      h.mutateDecision(withConditions({ use_limit: 2 }));
      const unmetered = await withFailedSuppression(h, () => schedule(h, key()));
      expect(unmetered).toEqual({ ok: false, refusal_reason: "unrecognized_condition", gap: "emission_failed" });
      expectOneAlert(h, 2);
      expect(await schedule(h, key())).toEqual({ ok: false, refusal_reason: "unrecognized_condition" });
      h.mutateDecision(undefined);
      expect(h.alerts.alerts).toHaveLength(2);
      expect(h.store.schedules()).toEqual([]);
      expect(h.store.reservations()).toEqual([]);
      expect(h.executions().map((r) => [r.outcome, r.error])).toEqual([
        ["completed", undefined],
        ["suppressed", "permit_consumed"],
        ["suppressed", "condition_unrecognized"],
      ]);
    } finally {
      h.close();
    }
  });

  it("reservation unavailable: a keyed write whose reservation store cannot be reached is refused consumption_unavailable with gap emission_failed and one alert, and schedules nothing; written, the refusal carries no gap", async () => {
    const failed = harness({ store: "closed" });
    try {
      const refused = await withFailedSuppression(failed, () => schedule(failed, key()));
      expect(refused).toEqual({ ok: false, refusal_reason: "consumption_unavailable", gap: "emission_failed" });
      expectOneAlert(failed);
      expect(failed.executions()).toEqual([]);
      expect(failed.payments.getInvoice("inv-1")?.status).toBe("payable");
    } finally {
      failed.close();
    }
    const written = harness({ store: "closed" });
    try {
      expect(await schedule(written, key())).toEqual({ ok: false, refusal_reason: "consumption_unavailable" });
      expect(written.alerts.alerts).toEqual([]);
      expect(written.executions().map((r) => [r.outcome, r.error])).toEqual([["suppressed", "consumption_unavailable"]]);
    } finally {
      written.close();
    }
  });

  it("actor unkeyable: a keyed write from an instance-profiled leaf with no client is refused actor_unkeyable with gap emission_failed and one alert, and leaves no reservation; written, the refusal carries no gap", async () => {
    const h = harness();
    try {
      const { clientId: _client, ...noClient } = TOKEN;
      const token = { ...noClient, act: { iss: ISSUER, sub: "instance-1", sub_profile: "client_instance" } } as TokenFacts;
      const refused = await withFailedSuppression(h, () => schedule(h, key(), token));
      expect(refused).toEqual({ ok: false, refusal_reason: "actor_unkeyable", next_action: "none", gap: "emission_failed" });
      expectOneAlert(h);
      expect(await schedule(h, key(), token)).toEqual({ ok: false, refusal_reason: "actor_unkeyable", next_action: "none" });
      expect(h.alerts.alerts).toHaveLength(1);
      expect(h.store.schedules()).toEqual([]);
      expect(h.store.reservations()).toEqual([]);
      expect(h.executions().map((r) => r.error)).toEqual([REVERSIBLE_WRITE_REFUSAL_ERRORS.actor_unkeyable]);
    } finally {
      h.close();
    }
  });

  it("retained release: a conflict and a reserved record keep their refusals with gap emission_failed and one alert each; a completed record is not disclosed without the retrieval's own record, and a later retrieval under its own permit discloses it; nothing executes again", async () => {
    const h = harness();
    try {
      // A completed record under k: its retrieval is withheld while the
      // retrieval's record cannot be written, and released once it can.
      const k = key();
      const first = await schedule(h, k);
      expect(first.ok, JSON.stringify(first)).toBe(true);
      const withheld = await withFailedSuppression(h, () => schedule(h, k));
      expect(withheld).toEqual({ ok: false, refusal_reason: "evidence_unavailable", next_action: "retry", gap: "emission_failed" });
      expectOneAlert(h, 1);
      expect(await schedule(h, k)).toEqual({ ok: true, deduped: true, result: first.result });
      expect(h.alerts.alerts).toHaveLength(1);

      // The same key over a changed invoice: a different operation identity.
      h.payments.bumpInvoiceAmount("inv-1", "130.00");
      const conflict = await withFailedSuppression(h, () => schedule(h, k));
      expect(conflict).toEqual({
        ok: false,
        refusal_reason: "operation_identity_conflict",
        next_action: "none",
        gap: "emission_failed",
      });
      expectOneAlert(h, 2);
      expect(await schedule(h, k)).toEqual({ ok: false, refusal_reason: "operation_identity_conflict", next_action: "none" });
      h.payments.bumpInvoiceAmount("inv-1", "125.00");

      // A reservation whose effect is not known to have committed.
      const r = key();
      expect((await h.server.callWriteTool("schedule_payment", { invoice_id: "inv-2", idempotency_key: r }, TOKEN)).ok).toBe(true);
      h.store.db.prepare("UPDATE write_reservations SET state = 'reserved', result_json = NULL, completed_at_ms = NULL, retain_until_ms = NULL WHERE idempotency_key = ?").run(r);
      const again = () => h.server.callWriteTool("schedule_payment", { invoice_id: "inv-2", idempotency_key: r }, TOKEN);
      const reserved = await withFailedSuppression(h, again);
      expect(reserved).toEqual({ ok: false, refusal_reason: "duplicate_suppressed", next_action: "retry", gap: "emission_failed" });
      expectOneAlert(h, 3);
      expect(await again()).toEqual({ ok: false, refusal_reason: "duplicate_suppressed", next_action: "retry" });
      expect(h.alerts.alerts).toHaveLength(3);

      // Nothing executed again: one schedule per invoice, one reservation per key.
      expect(h.store.schedules().map((s) => s.invoice_id).sort()).toEqual(["inv-1", "inv-2"]);
      expect(h.store.reservations()).toHaveLength(2);
    } finally {
      h.close();
    }
  });

  it("keyed effect refusal: a cancel with no schedule to cancel is refused schedule_not_found with gap emission_failed and one alert, and changes nothing; written, the refusal carries no gap", async () => {
    const h = harness();
    try {
      const refused = await withFailedSuppression(h, () => cancel(h, key()));
      expect(refused).toEqual({ ok: false, refusal_reason: "schedule_not_found", next_action: "none", gap: "emission_failed" });
      expectOneAlert(h);
      expect(await cancel(h, key())).toEqual({ ok: false, refusal_reason: "schedule_not_found", next_action: "none" });
      expect(h.alerts.alerts).toHaveLength(1);
      expect(h.store.schedules()).toEqual([]);
      expect(h.executions().map((r) => r.error)).toEqual([REVERSIBLE_WRITE_REFUSAL_ERRORS.schedule_not_found]);
    } finally {
      h.close();
    }
  });

  it("unevidenced withhold: a read and an unkeyed hold whose completed record and then suppressed record cannot be written are refused evidence_unavailable with gap emission_failed and one alert each, and disclose nothing; with the suppression written, neither carries a gap", async () => {
    const h = harness();
    try {
      const cases: Array<[string, () => Promise<unknown>]> = [
        ["read", () => read(h)],
        ["unkeyed hold", () => hold(h)],
      ];
      let alerts = 0;
      for (const [label, act] of cases) {
        const refused = await withFailedSuppression(h, act, "all");
        alerts += 1;
        expect(refused, label).toEqual({ ok: false, refusal_reason: "evidence_unavailable", gap: "emission_failed" });
        expectOneAlert(h, alerts);
        expect(h.executions(), label).toEqual([]);
      }
      // The control: the completed record still fails, the suppression is written.
      const original = h.evidence.recordExecution.bind(h.evidence);
      const completedFails = vi.spyOn(h.evidence, "recordExecution").mockImplementation(async (emitterId, role, input) => {
        if (input.outcome === "completed") throw new Error("evidence store unavailable");
        return original(emitterId, role, input);
      });
      try {
        for (const [label, act] of cases) {
          expect(await act(), label).toEqual({ ok: false, refusal_reason: "evidence_unavailable" });
        }
      } finally {
        completedFails.mockRestore();
      }
      expect(h.alerts.alerts).toHaveLength(alerts);
      expect(h.executions().map((r) => [r.outcome, r.error])).toEqual([
        ["suppressed", EVIDENCE_UNAVAILABLE_ERROR],
        ["suppressed", EVIDENCE_UNAVAILABLE_ERROR],
      ]);
    } finally {
      h.close();
    }
  });

  it("enforcement's own refusals after the permit: an unrecognized condition on a read and a keyed write, and an unfulfillable obligation on a read, keep their refusals with gap emission_failed and one alert each; nothing is disclosed or scheduled; written, none carries a gap", async () => {
    const h = harness();
    try {
      const withObligation = (d: Decision): Decision => ({
        ...d,
        context: { ...d.context, obligations: [{ id: "obl_1715", type: "step_up" }] },
      });
      const cases: Array<[string, (d: Decision) => Decision, () => Promise<unknown>, string, string]> = [
        ["condition on a read", withConditions({ require_step_up: true }), () => read(h), "unrecognized_condition", "condition_unrecognized"],
        ["condition on a keyed write", withConditions({ require_step_up: true }), () => schedule(h, key()), "unrecognized_condition", "condition_unrecognized"],
        ["obligation on a read", withObligation, () => read(h), "unfulfillable_obligation", "obligation_unfulfilled"],
      ];
      let alerts = 0;
      for (const [label, mutate, act, reason, error] of cases) {
        h.mutateDecision(mutate);
        try {
          const refused = await withFailedSuppression(h, act);
          alerts += 1;
          expect(refused, label).toEqual({ ok: false, refusal_reason: reason, gap: "emission_failed" });
          expectOneAlert(h, alerts);
          expect(await act(), label).toEqual({ ok: false, refusal_reason: reason });
          expect(h.alerts.alerts, label).toHaveLength(alerts);
          expect(h.executions().at(-1), label).toMatchObject({ outcome: "suppressed", error });
        } finally {
          h.mutateDecision(undefined);
        }
      }
      expect(h.store.schedules()).toEqual([]);
      expect(h.store.reservations()).toEqual([]);
    } finally {
      h.close();
    }
  });
});
