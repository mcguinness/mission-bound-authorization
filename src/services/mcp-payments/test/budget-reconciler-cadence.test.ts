/**
 * @spec metering#settlement-states (reconciliation cadence),
 * runtime#evidence (outcome reconciliation) (#816, D877 ruling 3): the
 * declared reconciler, running at its real cadence, is what processes budget
 * reservations whose outcome nothing reported.
 *
 * The reconciler runs at start and then every third of the declared window,
 * five minutes for PT15M. Each run lists this epoch's unresolved claims over
 * the claim channel, and the listing sweeps the PDP's claim domain: a permit
 * past its validity and lease becomes unresolved and its reservation held,
 * raising `budget_reservation_held`; an outcome nothing establishes closes
 * `indeterminate` at the window's end, raising the declared alert. The held
 * reservation stays charged indefinitely (D830 ruling 7): no run releases it.
 *
 * The harness is the executing PEP end to end against a co-resident decision
 * point whose claim domain meters a budget, on one fake clock that drives both
 * the reconciler's timer and every component's time, with the claim domain's
 * hooks wired to the same collecting sink the reconciler raises on, as
 * `composeStack` wires them to stderr. Nothing here enables the capability in
 * a shipped configuration.
 */

import { generateKeyPairSync, randomUUID } from "node:crypto";
import { canonicalDigest } from "@mission/core";
import {
  budgetCounterId,
  CLAIM_SETTLEMENT_INTAKE,
  createDecisionChannel,
  createDecisionPoint,
  type EnforcementScopeStatement,
  type EvidenceKeyResolver,
  type Fga,
  type MissionBudgetBinding,
  type MissionView,
  openEphemeralClaimDomain,
  RUNTIME_POSTURE,
  relationForAction,
  stalenessBound,
} from "@mission/pdp";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  budgetOverspendAlert,
  CANONICAL_RESOURCE,
  CollectingAlertSink,
  Connectors,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  heldReservationAlert,
  indeterminateClaimAlert,
  openEphemeralWriteReservationStore,
  OutcomeReconciler,
  PaymentsStore,
  Pep,
  redemptionStatusFor,
  releasedReservationNotice,
  type TokenFacts,
  TransactionEngine,
} from "../src/index.js";
import { ALL_ACTIONS_CREDENTIAL } from "./credential-fixtures.js";
import { pinnedToCurrentContract } from "@mission/demo-data";

const BASE_MS = Date.parse("2026-10-26T12:00:00.000Z");
const MINUTE = 60_000;
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
const MISSION = "msn_816_cadence";

const TOKEN: TokenFacts = {
  sub: "alice",
  clientId: "ap-agent",
  mission: { id: MISSION, issuer: "https://as.test", authority_hash: "sha-256:m816c" },
  cnfJkt: "jkt-816c",
  credentialAuthority: ALL_ACTIONS_CREDENTIAL,
};

const DISPATCH_POLICY = { id: "dp_vendor_payments", version: "1", digest: canonicalDigest({ dispatch_policy: "v1" }) };
const SHARED = budgetCounterId("standing_consent", { owner: "acme-treasury", budget_id: "vendor-payments-2026" });

/** The shipped statement (PT15M, this PEP responsible), claiming `budget_metering` for a 1000.00 budget. */
function meteringStatement(): EnforcementScopeStatement {
  const statement = structuredClone(RUNTIME_POSTURE) as unknown as EnforcementScopeStatement & {
    claims: string[];
    extensions: Record<string, unknown>;
  };
  statement.claims = [...(statement.claims ?? []), "budget_metering"];
  statement.extensions.budget_metering = {
    unit: { currency: "USD", exponent: 2 },
    enforcement_profile: "exact",
    topology: "local-single-writer",
    reserve_posture: "reserve_then_commit",
    settlement_intake: CLAIM_SETTLEMENT_INTAKE,
    metered_actions: [{ action: "payments:payment.execute", phase: "commit" }],
    budgets: [
      {
        owner: "acme-treasury",
        budget_id: "vendor-payments-2026",
        counter_scope: "standing_consent",
        currency: "USD",
        limit: "1000.00",
        policies: [DISPATCH_POLICY],
      },
    ],
  };
  return statement;
}

const BINDING: MissionBudgetBinding = {
  owner: "acme-treasury",
  budget_id: "vendor-payments-2026",
  currency: "USD",
  limit: "1000.00",
  policy: DISPATCH_POLICY,
  destinations: { acme: "acct-acme" },
  instance: { max_budget: { amount: "1000.00", currency: "USD" }, root_mission_id: MISSION },
};

const view = (): MissionView => ({
  id: MISSION,
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:m816c",
  authority_set: [
    pinnedToCurrentContract({
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:payment.execute"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    }),
  ],
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
  budget: BINDING,
});

afterEach(() => {
  vi.useRealTimers();
});

/**
 * The harness on one fake clock: the claim domain with its hooks on the
 * collecting sink, a co-resident decision point, and two PEP processes over
 * it (the running one, and a prior one whose redemption store is gone), each
 * holding one permit that is never redeemed and never settled.
 */
async function cadenceHarness() {
  vi.useFakeTimers({ now: BASE_MS, toFake: ["setInterval", "clearInterval", "setTimeout", "clearTimeout", "Date"] });
  const now = () => new Date();
  const alerts = new CollectingAlertSink();
  const statement = meteringStatement();
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [
      { id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
      { id: "inv-2", vendor_id: "acme", amount: "200.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
    ],
  );
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === MISSION && ref.issuer === "https://as.test"
      ? { view: view(), observation: { state: "active", version: 1, mode: "fresh", freshness_at: now().toISOString() } }
      : undefined;
  let pepKeys: EvidenceKeyResolver | undefined;
  const claims = openEphemeralClaimDomain({
    owner: RUNTIME_POSTURE.pdps[0] as string,
    statement,
    now,
    settlementKeys: (params) => pepKeys?.(params),
    // As composeStack wires them, to the alert path the reconciler raises on.
    onIndeterminate: (claim) => alerts.alert(indeterminateClaimAlert(claim)),
    onReservationHeld: (reservation) => alerts.alert(heldReservationAlert(reservation)),
    onReservationReleased: (released) => alerts.alert(releasedReservationNotice(released)),
    onBudgetOverspend: (overspend) => alerts.alert(budgetOverspendAlert(overspend)),
  });
  const pdpKey = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const point = createDecisionPoint({
    evidence: { signer: { kid: "pdp-816c", key: pdpKey.privateKey }, verificationKey: pdpKey.publicKey, emitterId: CANONICAL_RESOURCE, audience: CANONICAL_RESOURCE },
    claims,
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
    budgetBindings: (m) => (m.id === MISSION && m.issuer === "https://as.test" ? BINDING : undefined),
  });
  const keys = createEphemeralEvidenceKeys({ decisionPoint: point });
  pepKeys = keys.resolver;
  const evidence = new EvidenceStore(keys.signing, keys.resolver);
  const connectors = new Connectors(now);
  const pepIn = async (epoch: string) => {
    const engine = new TransactionEngine(epoch, now);
    const redemption = redemptionStatusFor(engine);
    const channel = await createDecisionChannel(point, {
      mode: "co-resident",
      pepId: "mcp-payments-pep",
      audience: CANONICAL_RESOURCE,
      pepEpoch: redemption.epoch,
      consumptionStatus: redemption.status,
      redeemingExecution: redemption.redeemer,
      getOptions: () => ({ view: view(), fga: alwaysAllowFga, modelId: "model-816c", now, stalenessBound, relationForAction, stateSourcePlacement: "pep" as const }),
    });
    const pep = new Pep({ decide: channel.decide, claims: channel.claims, payments, evidence, fga: alwaysAllowFga, modelId: "model-816c", loadView, instanceEpoch: epoch, now });
    return { pep, channel, redemption };
  };
  const prior = await pepIn("epoch-prior");
  const running = await pepIn("epoch-running");
  const writeReservations = openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" });
  const close = async () => {
    await prior.channel.close();
    await running.channel.close();
    writeReservations.close();
    claims.close();
  };
  try {
    const mine = await running.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` }, TOKEN);
    const theirs = await prior.pep.enforce("execute_wire_transfer", { invoice_id: "inv-2", idempotency_key: `idem_${randomUUID()}` }, TOKEN);
    expect(mine.permitted, JSON.stringify(mine)).toBe(true);
    expect(theirs.permitted, JSON.stringify(theirs)).toBe(true);
    const reconciler = new OutcomeReconciler({
      statement,
      component: "mcp-payments-pep",
      claims: running.channel.claims,
      evidence,
      redemption: running.redemption,
      connectors,
      writeReservations,
      alerts,
      now,
    });
    return {
      claims,
      alerts,
      reconciler,
      mineId: String(mine.decision?.context.evaluation_id),
      theirsId: String(theirs.decision?.context.evaluation_id),
      close,
    };
  } catch (err) {
    await close();
    throw err;
  }
}

describe("the declared reconciler processes budget reservations at its real cadence (@spec metering#settlement-states, runtime#evidence, #816, D877 ruling 3)", () => {
  it("runs at start and then every five minutes for PT15M: the run after a permit's lease elapses holds its reservation and raises budget_reservation_held once, the run after the window closes raises claim_indeterminate for an outcome it cannot establish, and the reservations stay held and charged indefinitely (@spec metering#settlement-states, runtime#evidence, #816, D830 ruling 7, D877 ruling 3)", async () => {
    const { claims, alerts, reconciler, mineId, theirsId, close } = await cadenceHarness();
    try {
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "325.00" }, held: { amount: "0.00" } });
      // The real cadence: a third of PT15M.
      expect(reconciler.intervalMs).toBe(5 * MINUTE);
      const budgetAlerts = () => alerts.alerts;
      reconciler.start();
      await vi.advanceTimersByTimeAsync(0);
      // The run at start: both permits are still valid; nothing is held or alerted.
      expect(budgetAlerts()).toEqual([]);
      expect(claims.reservationsFor(mineId).map((r) => r.state)).toEqual(["reserved", "reserved"]);

      // The run five minutes later: both permits and their leases have elapsed.
      await vi.advanceTimersByTimeAsync(5 * MINUTE);
      expect(budgetAlerts()).toHaveLength(2);
      expect(budgetAlerts()).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ kind: "budget_reservation_held", evaluation_id: mineId, mission_id: MISSION, cause: "lease_elapsed" }),
          expect.objectContaining({ kind: "budget_reservation_held", evaluation_id: theirsId, mission_id: MISSION, cause: "lease_elapsed" }),
        ]),
      );
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "325.00" } });

      // The runs at 10, 15 and 20 minutes: the prior process's outcome, which
      // this process cannot list, closes indeterminate once its window does.
      await vi.advanceTimersByTimeAsync(15 * MINUTE);
      expect(budgetAlerts()).toHaveLength(3);
      expect(budgetAlerts()[2]).toEqual(expect.objectContaining({ kind: "claim_indeterminate", evaluation_id: theirsId, mission_id: MISSION, cause: "window_closed" }));

      // An hour on, nothing releases either reservation and nothing alerts again.
      await vi.advanceTimersByTimeAsync(40 * MINUTE);
      expect(budgetAlerts()).toHaveLength(3);
      expect(claims.reservationsFor(mineId).map((r) => r.state)).toEqual(["held", "held"]);
      expect(claims.reservationsFor(theirsId).map((r) => r.state)).toEqual(["held", "held"]);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "325.00" }, committed: { amount: "0.00" } });
      await reconciler.stop();
    } finally {
      await close();
    }
  });

  it("runs once at start, before its first interval elapses: permits whose leases elapsed before the reconciler started are held, each raising budget_reservation_held, at start (@spec metering#settlement-states, runtime#evidence, #816, D877 ruling 3)", async () => {
    const { claims, alerts, reconciler, mineId, theirsId, close } = await cadenceHarness();
    try {
      // The clock moves past both permits and their leases without firing any timer.
      vi.setSystemTime(BASE_MS + 4 * MINUTE);
      expect(alerts.alerts).toEqual([]);
      expect(claims.reservationsFor(mineId).map((r) => r.state)).toEqual(["reserved", "reserved"]);
      reconciler.start();
      await vi.advanceTimersByTimeAsync(0);
      expect(alerts.alerts).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ kind: "budget_reservation_held", evaluation_id: mineId, cause: "lease_elapsed" }),
          expect.objectContaining({ kind: "budget_reservation_held", evaluation_id: theirsId, cause: "lease_elapsed" }),
        ]),
      );
      expect(alerts.alerts).toHaveLength(2);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "325.00" } });
      await reconciler.stop();
    } finally {
      await close();
    }
  });
});
