/**
 * @spec runtime#evidence (outcome reconciliation), runtime#runtime-conformance,
 * runtime#idempotency (#1103): the declared reconciler, run by its own loop
 * rather than called by a test.
 *
 * "The declared component MUST actively reconcile each unresolved outcome
 * before the window closes ... Evidence, never the deadline, determines the
 * result: an outcome the component cannot establish stays
 * undetermined-outcome, is escalated under the declared alerting obligation,
 * and is never synthesized into a terminal result."
 *
 * The harness is the executing PEP end to end (its real redemption store,
 * connectors, evidence store and write reservations) against a real PDP
 * claim domain on a real file, on one clock the test drives, with the claim
 * domain's `onIndeterminate` hook wired to the same collecting alert sink the
 * reconciler raises on, exactly as `composeStack` wires them to stderr. The
 * FGA layer is a stub that always permits, so this file never skips.
 *
 * Two cases are kept apart throughout: a refusal before any effect (no
 * effect, and a Refusal Record or suppressed Execution Evidence, or a permit
 * never redeemed), and missing evidence after an effect (the effect stands,
 * the claim is never settled as if nothing happened). Every case counts
 * CONNECTOR LEDGER entries, not evidence records, to show that no retry and
 * no reconciliation repeats an effect: the ledger recovery path records a
 * new completed record under a fresh execution id by design.
 */

import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  type ClaimChannel,
  createDecisionChannel,
  createEphemeralDecisionPoint,
  type EnforcementScopeStatement,
  type EvidenceKeyResolver,
  type Fga,
  type MissionView,
  newRecordId,
  openIdempotencyClaimDomain,
  relationForAction,
  RUNTIME_POSTURE,
  stalenessBound,
} from "@mission/pdp";
import {
  CANONICAL_RESOURCE,
  CollectingAlertSink,
  Connectors,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  indeterminateClaimAlert,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  operationKey,
  OutcomeReconciler,
  OutcomeReconcilerConfigError,
  type OutcomeReconcilerOptions,
  PaymentsStore,
  Pep,
  redemptionStatusFor,
  type TokenFacts,
  TransactionEngine,
  type WriteReservationStore,
} from "../src/index.js";
import { ALL_ACTIONS_CREDENTIAL } from "./credential-fixtures.js";

const BASE_MS = Date.parse("2026-10-08T12:00:00.000Z");
/** irreversible_action: the 30 s staleness bound caps the permit; the published lease is 30 s more. */
const PAST_LEASE_MS = 61_000;
/** The declared PT15M window. */
const WINDOW_MS = 15 * 60_000;
/** A permit issued at BASE_MS closes at its `valid_until` (30 s), plus the lease (30 s), plus the window. */
const WINDOW_CLOSE_MS = BASE_MS + 30_000 + 30_000 + WINDOW_MS;
const MISSION = "msn_1103";
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
const key = (): string => `idem_${randomUUID()}`;
const tempClaimsFile = (): string => join(mkdtempSync(join(tmpdir(), "claims-1103-")), "claims.sqlite");

const TOKEN: TokenFacts = {
  sub: "alice",
  clientId: "ap-agent",
  mission: { id: MISSION, issuer: "https://as.test", authority_hash: "sha-256:m1103" },
  cnfJkt: "jkt-1103",
  credentialAuthority: ALL_ACTIONS_CREDENTIAL,
};

const view = (): MissionView => ({
  id: MISSION,
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:m1103",
  authority_set: [
    {
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:payment.execute"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    },
  ],
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
});

interface Clock {
  now: () => Date;
  ms: () => number;
  advance: (ms: number) => void;
  set: (ms: number) => void;
}
function clock(start = BASE_MS): Clock {
  let current = start;
  return {
    now: () => new Date(current),
    ms: () => current,
    advance: (ms) => {
      current += ms;
    },
    set: (ms) => {
      current = ms;
    },
  };
}

interface HarnessOptions {
  mode?: "co-resident" | "remote";
  /** The PDP's claim file; a second harness on the same file is a restarted process. */
  claimsFile?: string;
  clock?: Clock;
  /** Hold the PEP's live settlements, as a lost acknowledgement does; the reconciler's channel is unaffected. */
  holdSettlement?: boolean;
}

/** One process: the PDP claim domain and decision point, and the executing PEP with its reconciler. */
async function harness(o: HarnessOptions = {}) {
  const c = o.clock ?? clock();
  const now = c.now;
  const alerts = new CollectingAlertSink();
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
  );
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === MISSION && ref.issuer === "https://as.test"
      ? { view: view(), observation: { state: view().state, version: view().version, mode: "fresh", freshness_at: now().toISOString() } }
      : undefined;

  let pepKeys: EvidenceKeyResolver | undefined;
  const claims = openIdempotencyClaimDomain({
    file: o.claimsFile ?? tempClaimsFile(),
    owner: RUNTIME_POSTURE.pdps[0] as string,
    statement: RUNTIME_POSTURE,
    now,
    settlementKeys: (params) => pepKeys?.(params),
    // As composeStack wires it: the declared alert where the transition happens.
    onIndeterminate: (claim) => alerts.alert(indeterminateClaimAlert(claim)),
  });
  const point = createEphemeralDecisionPoint({ emitterId: CANONICAL_RESOURCE, audience: CANONICAL_RESOURCE, claims });
  const keys = createEphemeralEvidenceKeys({ decisionPoint: point });
  pepKeys = keys.resolver;

  const engine = new TransactionEngine("epoch-1103", now);
  const redemption = redemptionStatusFor(engine);
  const channel = await createDecisionChannel(point, {
    mode: o.mode ?? "co-resident",
    pepId: "mcp-payments-pep",
    audience: CANONICAL_RESOURCE,
    pepEpoch: redemption.epoch,
    consumptionStatus: redemption.status,
    redeemingExecution: redemption.redeemer,
    getOptions: () => ({
      view: view(),
      fga: alwaysAllowFga,
      modelId: "model-1103",
      now,
      stalenessBound,
      relationForAction,
      stateSourcePlacement: "pep" as const,
    }),
  });
  const pepClaims: ClaimChannel = {
    settle: async (record) => (o.holdSettlement ? { accepted: false, reason: "held" } : channel.claims.settle(record)),
    listUnresolved: () => channel.claims.listUnresolved(),
    reconcile: (id, resolution) => channel.claims.reconcile(id, resolution),
  };
  const evidence = new EvidenceStore(keys.signing, keys.resolver);
  const connectors = new Connectors(now);
  const writeReservations = openEphemeralWriteReservationStore({ owner: "mcp-payments-pep", now });
  let lastDecision: Record<string, unknown> | undefined;
  const pep = new Pep({
    decide: channel.decide,
    claims: pepClaims,
    observe: ({ decision }) => {
      lastDecision = decision.context;
    },
    payments,
    evidence,
    fga: alwaysAllowFga,
    modelId: "model-1103",
    loadView,
    instanceEpoch: "epoch-1103",
    now,
  });
  const server = new McpPaymentsServer({
    writeReservations,
    pep,
    payments,
    loadView,
    jwks: { keys: [] },
    keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] },
    issuer: "https://as.test",
    transaction: { engine, connectors, evidence },
  });
  // The reconciler reads the decision channel itself, never the PEP's
  // settlement wrapper: over the remote channel that is the PDP's reconcile route.
  const reconciler = new OutcomeReconciler({
    statement: RUNTIME_POSTURE,
    component: "mcp-payments-pep",
    claims: channel.claims,
    evidence,
    redemption,
    connectors,
    writeReservations,
    alerts,
    now,
  });
  return {
    clock: c,
    alerts,
    payments,
    engine,
    connectors,
    evidence,
    writeReservations,
    pep,
    server,
    reconciler,
    lastDecision: () => lastDecision,
    close: async () => {
      await reconciler.stop();
      await channel.close();
      claims.close();
      writeReservations.close();
    },
  };
}
type Harness = Awaited<ReturnType<typeof harness>>;

const wire = (h: Harness, idempotencyKey: string) =>
  h.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: idempotencyKey }, TOKEN);

/** Retained Execution Evidence with this outcome. */
const executions = (h: Harness, outcome: string) =>
  h.evidence.all().filter((e) => e.kind === "execution" && e.content.outcome === outcome);

/**
 * Fail every `completed` write the executor attempts until restored: the
 * effect commits and its evidence is never recorded. The PEP's own
 * `suppressed` writes, and the reconciler's ledger recovery after restore,
 * pass through.
 */
function failCompletedWrites(h: Harness): { restore: () => void } {
  const original = h.evidence.recordExecution.bind(h.evidence);
  let failing = true;
  const spy = vi.spyOn(h.evidence, "recordExecution").mockImplementation(async (emitterId, role, input) => {
    if (failing && role === "executor") throw new Error("completed write failed");
    return original(emitterId, role, input);
  });
  return {
    restore: () => {
      failing = false;
      spy.mockRestore();
    },
  };
}

/** A completed wire whose evidence was lost: the effect stands, nothing recorded it. */
async function wireWithLostEvidence(h: Harness, idempotencyKey: string): Promise<void> {
  const failing = failCompletedWrites(h);
  // The call reports the failure however this server reports it; what stands
  // after it is what the reconciler must establish.
  await wire(h, idempotencyKey).catch(() => undefined);
  failing.restore();
  expect(h.connectors.ledgerEntries()).toHaveLength(1);
  expect(executions(h, "completed")).toHaveLength(0);
}

describe("the declared outcome reconciler runs the reconciliation (@spec runtime#evidence outcome reconciliation, #1103)", () => {
  for (const mode of ["co-resident", "remote"] as const) {
    it(`missing evidence after an effect, over the ${mode} channel: the wire stands once, and a run inside the window settles the claim completed from the ledger, with exactly one ledger entry`, async () => {
      const h = await harness({ mode });
      try {
        const k = key();
        await wireWithLostEvidence(h, k);
        // Inside the permit and its lease the claim is not the reconciler's yet.
        expect((await h.reconciler.runOnce()).claims).toEqual({ settled: [], unredeemed: [], open: [], states: {} });
        h.clock.advance(PAST_LEASE_MS);
        expect(h.clock.ms()).toBeLessThan(WINDOW_CLOSE_MS);
        const run = await h.reconciler.runOnce();
        expect(run.failed).toEqual([]);
        expect(Object.values(run.claims?.states ?? {})).toEqual(["completed"]);
        expect(run.claims?.open).toEqual([]);
        // Settled completed, never as if nothing happened: the evidence was
        // recorded for the effect that stands, and no second effect exists.
        expect(executions(h, "completed")).toHaveLength(1);
        expect(h.connectors.ledgerEntries()).toHaveLength(1);
        // A retry under the same key is refused as completed and executes nothing.
        expect((await wire(h, k)).denial_reason).toBe("duplicate_suppressed");
        expect(h.lastDecision()?.next_action).toBe("none");
        expect(h.connectors.ledgerEntries()).toHaveLength(1);
        // The window then closes on a settled claim: nothing to alert, nothing orphaned.
        h.clock.set(WINDOW_CLOSE_MS);
        const late = await h.reconciler.runOnce();
        expect(late.orphaned).toEqual({ effects: [], evidence: [] });
        expect(h.alerts.alerts).toEqual([]);
        expect(h.connectors.ledgerEntries()).toHaveLength(1);
      } finally {
        await h.close();
      }
    });
  }

  it("a refusal before any effect: a permit proven unredeemed in this epoch settles failed, and a retry under its key executes nothing", async () => {
    const h = await harness();
    try {
      const k = key();
      const permit = await h.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: k }, TOKEN);
      expect(permit.permitted).toBe(true);
      h.clock.advance(PAST_LEASE_MS);
      const run = await h.reconciler.runOnce();
      expect(run.claims?.unredeemed).toEqual([permit.decision?.context.evaluation_id]);
      expect(Object.values(run.claims?.states ?? {})).toEqual(["failed"]);
      expect((await wire(h, k)).denial_reason).toBe("duplicate_suppressed");
      expect(h.lastDecision()?.next_action).toBe("none");
      expect(h.connectors.ledgerEntries()).toHaveLength(0);
      expect(h.alerts.alerts).toEqual([]);
    } finally {
      await h.close();
    }
  });

  it("a refusal before any effect: the redeeming attempt's own suppressed Execution Evidence settles failed when its settlement never arrived, and nothing executes", async () => {
    const h = await harness({ holdSettlement: true });
    try {
      const k = key();
      // The parameters move after the permit and before the commit: the
      // redeeming attempt refuses itself, with no effect.
      const refused = await h.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: k }, TOKEN, () =>
        h.payments.bumpInvoiceAmount("inv-1", "150.00"),
      );
      expect(refused.refusal_reason).toBe("parameter_mismatch");
      expect(executions(h, "suppressed")).toHaveLength(1);
      h.clock.advance(PAST_LEASE_MS);
      const run = await h.reconciler.runOnce();
      expect(run.claims?.settled).toHaveLength(1);
      expect(Object.values(run.claims?.states ?? {})).toEqual(["failed"]);
      expect(run.orphaned).toEqual({ effects: [], evidence: [] });
      expect(h.connectors.ledgerEntries()).toHaveLength(0);
      expect(h.alerts.alerts).toEqual([]);
    } finally {
      await h.close();
    }
  });

  it("an outcome nothing establishes stays open, closes indeterminate when its window closes, and raises the declared alert exactly once, never from a run's open list", async () => {
    const h = await harness();
    try {
      const k = key();
      const permit = await h.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: k }, TOKEN);
      const evaluationId = String(permit.decision?.context.evaluation_id);
      const digest = String((permit.decision?.context.conditions as { parameter_digest: string }).parameter_digest);
      // The permit was redeemed and the process lost what followed: no link
      // to the redeeming attempt, no ledger entry, no evidence. Nothing here
      // can say whether an effect happened.
      const opKey = operationKey(MISSION, "payments:payment.execute", digest, "commit");
      expect(h.engine.redeemPermit({ permitId: evaluationId, opKey, missionId: MISSION, action: "payments:payment.execute", leaseExpiresAtMs: BASE_MS + 30_000 }).ok).toBe(true);
      h.clock.advance(PAST_LEASE_MS);
      const open = await h.reconciler.runOnce();
      expect(open.claims?.open).toEqual([evaluationId]);
      expect(h.alerts.alerts).toEqual([]);
      // Runs before the window closes never decide it by time.
      h.clock.set(WINDOW_CLOSE_MS - 1_000);
      expect((await h.reconciler.runOnce()).claims?.open).toEqual([evaluationId]);
      expect(h.alerts.alerts).toEqual([]);
      h.clock.set(WINDOW_CLOSE_MS);
      const closed = await h.reconciler.runOnce();
      expect(closed.claims?.open).toEqual([]);
      expect(h.alerts.alerts).toEqual([
        { kind: "claim_indeterminate", evaluation_id: evaluationId, mission_id: MISSION, cause: "window_closed", at: new Date(WINDOW_CLOSE_MS).toISOString() },
      ]);
      await h.reconciler.runOnce();
      expect(h.alerts.alerts).toHaveLength(1);
      // Indeterminate is terminal: the key stays refused and nothing executes.
      expect((await wire(h, k)).denial_reason).toBe("duplicate_suppressed");
      expect(h.lastDecision()?.next_action).toBe("none");
      expect(h.connectors.ledgerEntries()).toHaveLength(0);
      expect(h.alerts.alerts).toHaveLength(1);
    } finally {
      await h.close();
    }
  });

  it("missing evidence after an effect across a restart: the prior epoch's claim is never listed, closes indeterminate when its window closes with the declared alert, and the retry executes nothing", async () => {
    const c = clock();
    const claimsFile = tempClaimsFile();
    const before = await harness({ claimsFile, clock: c });
    const k = key();
    await wireWithLostEvidence(before, k);
    await before.close();
    // A new process on the same claim file: a new PDP boot and a new PEP
    // epoch, with empty in-memory connectors, redemption records and evidence.
    c.advance(1_000);
    const after = await harness({ claimsFile, clock: c });
    try {
      const first = await after.reconciler.runOnce();
      expect(first.claims).toEqual({ settled: [], unredeemed: [], open: [], states: {} });
      c.set(WINDOW_CLOSE_MS - 1_000);
      expect((await after.reconciler.runOnce()).claims?.open).toEqual([]);
      expect(after.alerts.alerts).toEqual([]);
      c.set(WINDOW_CLOSE_MS);
      await after.reconciler.runOnce();
      expect(after.alerts.alerts.map((a) => [a.kind, a.mission_id, a.cause])).toEqual([["claim_indeterminate", MISSION, "window_closed"]]);
      await after.reconciler.runOnce();
      expect(after.alerts.alerts).toHaveLength(1);
      // The key stays refused; the new process executes nothing, so the one
      // effect is the prior process's.
      expect((await wire(after, k)).denial_reason).toBe("duplicate_suppressed");
      expect(after.lastDecision()?.next_action).toBe("none");
      expect(after.connectors.ledgerEntries()).toHaveLength(0);
    } finally {
      await after.close();
    }
  });

  it("alerts what stays unmatched after claim settlement: evidence of an effect that never committed at once, an effect without evidence once older than the window, and never a suppressed record or an email's effect", async () => {
    const h = await harness();
    try {
      const op = (name: string) => `op:${MISSION}:${name}`;
      const record = (evaluationId: string, opKey: string, outcome: "completed" | "suppressed") =>
        h.evidence.recordExecution(CANONICAL_RESOURCE, outcome === "completed" ? "executor" : "pep", {
          permitId: evaluationId,
          opKey,
          execution_id: newRecordId("exe"),
          evaluation_id: evaluationId,
          mission_id: MISSION,
          audience: CANONICAL_RESOURCE,
          outcome,
          ...(outcome === "suppressed" ? { error: "permit_expired" } : {}),
        });
      // Matched: an email's effect, which lives in the outbox, with its evidence.
      h.connectors.sendEmail({ opKey: op("email"), invoiceId: "inv-1", to: "acme@vendor.example", permitId: "eval-email", missionId: MISSION });
      await record("eval-email", op("email"), "completed");
      // No effect asserted: a suppression.
      await record("eval-suppressed", op("suppressed"), "suppressed");
      // An effect whose evidence never arrived.
      h.connectors.postWire({ opKey: op("lost"), invoiceId: "inv-1", payeeAccount: "acct-acme", amount: "125.00", currency: "USD", permitId: "eval-lost", missionId: MISSION });
      // Evidence of an effect no connector committed.
      await record("eval-phantom", op("phantom"), "completed");

      const first = await h.reconciler.runOnce();
      expect(first.failed).toEqual([]);
      expect(first.orphaned).toEqual({ effects: [], evidence: [op("phantom")] });
      expect(h.alerts.alerts).toEqual([
        { kind: "orphaned_evidence", evaluation_id: "eval-phantom", mission_id: MISSION, cause: "execution_evidence_without_effect", at: new Date(BASE_MS).toISOString() },
      ]);
      // Just inside the window the effect may still find its evidence.
      h.clock.advance(WINDOW_MS - 1);
      expect((await h.reconciler.runOnce()).orphaned).toEqual({ effects: [], evidence: [] });
      h.clock.advance(1);
      expect((await h.reconciler.runOnce()).orphaned).toEqual({ effects: [op("lost")], evidence: [] });
      // Each anomaly alerts once.
      expect((await h.reconciler.runOnce()).orphaned).toEqual({ effects: [], evidence: [] });
      expect(h.alerts.alerts.map((a) => [a.kind, a.evaluation_id])).toEqual([
        ["orphaned_evidence", "eval-phantom"],
        ["orphaned_effect", "eval-lost"],
      ]);
      // Reconciliation only reads: still one effect each.
      expect(h.connectors.committedEffects().map((e) => e.opKey).sort()).toEqual([op("email"), op("lost")]);
    } finally {
      await h.close();
    }
  });
});

describe("the declared outcome reconciler's loop (@spec runtime#runtime-conformance, #1103)", () => {
  const stubClaims = (over: Partial<ClaimChannel> = {}): ClaimChannel => ({
    settle: async () => ({ accepted: false, reason: "unused" }),
    listUnresolved: async () => [],
    reconcile: async () => ({ accepted: false, reason: "unused" }),
    ...over,
  });

  /** A reconciler over empty stores and a stub claim channel. */
  function bare(over: Partial<OutcomeReconcilerOptions> = {}) {
    const c = clock();
    const writeReservations = openEphemeralWriteReservationStore({ owner: "mcp-payments-pep", now: c.now });
    const alerts = new CollectingAlertSink();
    const options: OutcomeReconcilerOptions = {
      statement: RUNTIME_POSTURE,
      component: "mcp-payments-pep",
      claims: stubClaims(),
      evidence: new EvidenceStore(),
      redemption: redemptionStatusFor(new TransactionEngine("epoch-bare", c.now)),
      connectors: new Connectors(c.now),
      writeReservations,
      alerts,
      now: c.now,
      ...over,
    };
    return { reconciler: new OutcomeReconciler(options), options, alerts, clock: c, writeReservations };
  }

  /** A statement whose `outcome_reconciliation` is edited by `edit`. */
  const statementWith = (edit: (declared: Record<string, unknown>, extensions: Record<string, unknown>) => void) => {
    const statement = structuredClone(RUNTIME_POSTURE) as unknown as EnforcementScopeStatement & { extensions: Record<string, unknown> };
    edit(statement.extensions.outcome_reconciliation as Record<string, unknown>, statement.extensions);
    return statement as EnforcementScopeStatement;
  };

  /** A `reserved` row: a reservation whose effect is not known to have committed. */
  function insertReservedRow(store: WriteReservationStore, evaluationId: string): void {
    store.db
      .prepare(
        `INSERT INTO write_reservations (scope_digest, idempotency_key, scope_json, action, operation_identity, state, evaluation_id, execution_id)
         VALUES (?, ?, '{}', 'payments:payment.schedule', 'sha-256:operation', 'reserved', ?, ?)`,
      )
      .run(`sha-256:${randomUUID()}`, key(), evaluationId, newRecordId("exe"));
  }

  const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

  it("refuses construction without an outcome_reconciliation declaration, or with one naming another component", () => {
    expect(() => bare({ statement: statementWith((_d, extensions) => { delete extensions.outcome_reconciliation; }) })).toThrow(
      /declares no outcome_reconciliation/,
    );
    expect(() => bare({ component: "another-pep" })).toThrow(/names mcp-payments-pep, not this component \(another-pep\)/);
    expect(() => bare({ statement: statementWith((d) => { d.responsible_component = "mcp-payments-pdp"; }) })).toThrow(
      OutcomeReconcilerConfigError,
    );
    expect(() => bare()).not.toThrow();
  });

  it("derives its interval from the declared window, a third of it, so an unresolved claim gets at least two runs before its window closes", () => {
    const shipped = bare().reconciler;
    expect(shipped.windowMs).toBe(WINDOW_MS);
    expect(shipped.intervalMs).toBe(WINDOW_MS / 3);
    const shorter = bare({ statement: statementWith((d) => { d.window = "PT3M"; }) }).reconciler;
    expect(shorter.intervalMs).toBe(60_000);
    expect(() => bare({ intervalMs: 0 })).toThrow(OutcomeReconcilerConfigError);
  });

  it("skips a run while another is in flight, so a slow run never overlaps the next tick", async () => {
    let listings = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const { reconciler } = bare({
      claims: stubClaims({
        listUnresolved: async () => {
          listings += 1;
          await gate;
          return [];
        },
      }),
    });
    const first = reconciler.runOnce();
    const second = reconciler.runOnce();
    expect(listings).toBe(1);
    release();
    expect((await second).skipped).toBe(true);
    expect((await first).skipped).toBe(false);
    expect((await reconciler.runOnce()).skipped).toBe(false);
    expect(listings).toBe(2);
  });

  it("a step that throws raises reconciliation_failed with no error text, and the other steps still run", async () => {
    const { reconciler, alerts, writeReservations } = bare({
      claims: stubClaims({
        listUnresolved: async () => {
          throw new Error("claim domain unavailable at /var/secret-path");
        },
      }),
    });
    insertReservedRow(writeReservations, "eval-reserved");
    const sweep = vi.spyOn(writeReservations, "sweep");
    const sweepPermits = vi.spyOn(writeReservations, "sweepConsumedPermits");
    const run = await reconciler.runOnce();
    expect(run.failed).toEqual(["claims"]);
    expect(sweep).toHaveBeenCalledTimes(1);
    expect(sweepPermits).toHaveBeenCalledTimes(1);
    expect(run.reserved).toEqual(["eval-reserved"]);
    expect(alerts.alerts.map((a) => [a.kind, a.cause])).toEqual([
      ["reconciliation_failed", "claims: Error"],
      ["reservation_unresolved", "reserved_without_outcome"],
    ]);
    expect(JSON.stringify(alerts.alerts)).not.toContain("secret-path");
    // A failing sweep is its own step: the other sweep and the escalation still run.
    sweep.mockImplementation(() => {
      throw new TypeError("disk full");
    });
    const again = await reconciler.runOnce();
    expect(again.failed).toEqual(["claims", "reservation_sweep"]);
    expect(sweepPermits).toHaveBeenCalledTimes(2);
    expect(again.reserved).toEqual(["eval-reserved"]);
  });

  it("each run sweeps the completed reservations and consumed permits past their retention", async () => {
    const { reconciler, writeReservations, clock: c } = bare();
    writeReservations.db
      .prepare(
        `INSERT INTO write_reservations (scope_digest, idempotency_key, scope_json, action, operation_identity, state, result_json,
           evaluation_id, execution_id, completed_at_ms, retain_until_ms)
         VALUES ('sha-256:s', ?, '{}', 'payments:payment.schedule', 'sha-256:operation', 'completed', '{}', 'eval-done', 'exe-done', ?, ?)`,
      )
      .run(key(), c.ms(), c.ms() + 1_000);
    expect(writeReservations.consumePermit({ evaluationId: "eval-used", action: "payments:payment.schedule", executionId: "exe-used", retainUntilMs: c.ms() + 1_000 })).toBe(true);
    expect((await reconciler.runOnce()).swept).toEqual({ reservations: 0, consumedPermits: 0 });
    c.advance(2_000);
    expect((await reconciler.runOnce()).swept).toEqual({ reservations: 1, consumedPermits: 1 });
    expect(writeReservations.reservations()).toEqual([]);
    expect(writeReservations.consumedPermits()).toEqual([]);
  });

  it("a reserved write reservation is escalated once and never resolved by executing: no schedule, no ledger entry, and the row stays reserved", async () => {
    const { reconciler, alerts, writeReservations, options } = bare();
    insertReservedRow(writeReservations, "eval-reserved");
    for (let i = 0; i < 3; i += 1) expect((await reconciler.runOnce()).reserved).toEqual(["eval-reserved"]);
    expect(alerts.alerts.map((a) => [a.kind, a.evaluation_id, a.cause])).toEqual([["reservation_unresolved", "eval-reserved", "reserved_without_outcome"]]);
    expect(writeReservations.reservations().map((r) => r.state)).toEqual(["reserved"]);
    expect(writeReservations.schedules()).toEqual([]);
    expect(options.connectors.committedEffects()).toEqual([]);
  });

  it("start() runs once at once and then on its interval, on a timer that holds no process open; stop() clears it and waits for a run in flight", async () => {
    let listings = 0;
    const { reconciler } = bare({
      intervalMs: 20,
      claims: stubClaims({
        listUnresolved: async () => {
          listings += 1;
          return [];
        },
      }),
    });
    expect(reconciler.started).toBe(false);
    reconciler.start();
    expect(reconciler.started).toBe(true);
    expect(listings).toBe(1);
    expect((reconciler as unknown as { timer: NodeJS.Timeout }).timer.hasRef()).toBe(false);
    for (let i = 0; i < 100 && listings < 3; i += 1) await sleep(10);
    expect(listings).toBeGreaterThanOrEqual(3);
    await reconciler.stop();
    expect(reconciler.started).toBe(false);
    const stoppedAt = listings;
    await sleep(60);
    expect(listings).toBe(stoppedAt);

    // stop() waits for the run in flight.
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const slow = bare({ intervalMs: 20, claims: stubClaims({ listUnresolved: async () => (await gate, []) }) }).reconciler;
    slow.start();
    let stopped = false;
    const stopping = slow.stop().then(() => {
      stopped = true;
    });
    await sleep(20);
    expect(stopped).toBe(false);
    release();
    await stopping;
    expect(stopped).toBe(true);
  });
});
