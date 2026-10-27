/**
 * @spec mission-template#standing-payment-exception, metering#metering,
 * metering#aggregate-bounds, metering#capacity-across-missions,
 * metering#settlement-states (#813, #816, D814, D830): the standing-payment
 * dispatch workflow metered end to end through the composed stack.
 *
 * Each case composes the shared stack with the AS (`withAuthServer`), a
 * human consents to a standing-payment template on the approval surface, the
 * Dispatcher dispatches instances unattended at the token endpoint, and each
 * payment runs through the payments resource's real PEP, the co-resident PDP
 * and its claim domain, and the wire connector. The PDP derives each
 * instance's budget binding from the kernel's committed Dispatch Policy
 * snapshot, never from the PEP's view.
 *
 * The opt-in `standing-payment-dispatch` capability (composeStack's test
 * fixture) and the `budget_metering` declaration (the statement built here)
 * are enabled in this file only; the shipped configuration enables neither.
 * Only the OpenFGA client is stubbed, so this file never skips.
 */

import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair } from "jose";
import { afterAll, beforeAll, describe, expect, it, type MockInstance, vi } from "vitest";
import { createExpansion, mintActivationPolicyRef } from "@mission/authorization-server";
import { DEV_SERVICE_TOKEN } from "@mission/demo-data";
import {
  CANONICAL_RESOURCE,
  credentialAuthorityFrom,
  type DecisionEvidence,
  type TokenFacts,
} from "@mission/mcp-payments";
import {
  type BudgetCounterState,
  budgetCounterId,
  CLAIM_SETTLEMENT_INTAKE,
  type ClaimChannel,
  Fga,
  RUNTIME_POSTURE,
  type RuntimePosture,
  UNDERIVABLE_BUDGET,
} from "@mission/pdp";
import { APPROVAL_RENDER_REVISION_HEADER, type ApprovalConsole } from "../src/approval-console.js";
import { kernelBudgetBinding } from "../src/kernel-mission-view.js";
import { tokenGrantRequest } from "../src/oauth-client.js";
import { composeStack, type DemoStack } from "../src/stack.js";

const MISSION_DISPATCH_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:mission-dispatch";
const FAR_FUTURE = "2099-01-01T00:00:00Z";
const POLICY_ID = "sp-e2e";
const OWNER = "payments-operator";
const BUDGET_ID = "ap-standing-e2e";
/** The payee account the approved policy commits for Acme, the account the seeded invoices pay. */
const ACME_ACCOUNT = "acct-acme-001";

/**
 * The committed standing-payment terms: Acme's account as the one
 * destination, 500.00 per payment, and a shared budget of 200.00 of which
 * each instance may carry at most 150.00.
 */
const TERMS = {
  operation: "payments:payment.execute",
  resource: CANONICAL_RESOURCE,
  destinations: { acme: ACME_ACCOUNT },
  max_amount: { amount: "500.00", currency: "USD" },
  budget: { owner: OWNER, id: BUDGET_ID, currency: "USD", limit: "200.00", per_instance_max: "150.00" },
  approval_governance: {
    recency: {
      ceilings: { default: 86400 },
      clock_skew_s: 60,
      exceptions: { irreversible_action: { max_age_s: 3600 }, consumption_bound: { max_age_s: 3600 } },
    },
  },
};
const DISPATCH_POLICIES = {
  [POLICY_ID]: {
    version: "1",
    content_type: "application/json",
    content: JSON.stringify({ id: POLICY_ID, derivation_limit_ceiling: 3, standing_payment: TERMS }),
  },
};

/**
 * The shipped statement, claiming `budget_metering` for the policy's budget
 * under the Exact profile with the policy's committed `{id, version, digest}`
 * as `issuer` computes it.
 */
function meteringStatement(issuer: string): RuntimePosture {
  const policy = mintActivationPolicyRef(issuer, DISPATCH_POLICIES, POLICY_ID, "1");
  if (!policy) throw new Error("the Dispatch Policy is not held");
  const statement = structuredClone(RUNTIME_POSTURE) as RuntimePosture & {
    claims: string[];
    extensions: Record<string, unknown>;
  };
  statement.claims = [...(statement.claims ?? []), "budget_metering"];
  statement.extensions = {
    ...statement.extensions,
    budget_metering: {
      unit: { currency: "USD", exponent: 2 },
      enforcement_profile: "exact",
      topology: "local-single-writer",
      reserve_posture: "reserve_then_commit",
      settlement_intake: CLAIM_SETTLEMENT_INTAKE,
      metered_actions: [{ action: "payments:payment.execute", phase: "commit" }],
      budgets: [
        {
          owner: OWNER,
          budget_id: BUDGET_ID,
          counter_scope: "standing_consent",
          currency: "USD",
          limit: TERMS.budget.limit,
          policies: [policy],
        },
      ],
    },
  };
  return statement;
}

const tempFile = (prefix: string, name: string): string => join(mkdtempSync(join(tmpdir(), prefix)), name);

interface StackFiles {
  claimsFile: string;
  writeReservationsFile: string;
  kernelFile?: string;
}

function newFiles(withKernel = false): StackFiles {
  return {
    claimsFile: tempFile("sp-claims-", "claims.sqlite"),
    writeReservationsFile: tempFile("sp-reservations-", "write-reservations.sqlite"),
    ...(withKernel ? { kernelFile: tempFile("sp-kernel-", "kernel.db") } : {}),
  };
}

function compose(asPort: number, files: StackFiles): Promise<DemoStack> {
  return composeStack({
    openfgaUrl: "http://unused.test",
    presharedKey: "unused",
    withAuthServer: true,
    asPort,
    claimsFile: files.claimsFile,
    writeReservationsFile: files.writeReservationsFile,
    resourcePolicyStore: { bootstrap: "development" },
    statement: meteringStatement(`http://localhost:${asPort}`),
    testStandingPaymentDispatch: { dispatchPolicies: DISPATCH_POLICIES },
    ...(files.kernelFile ? { kernelStore: { file: files.kernelFile } } : {}),
  });
}

/** Release everything the composed stack holds, the AS listener and every single-writer file included. */
async function closeStack(stack: DemoStack): Promise<void> {
  await stack.reconciler.stop();
  await stack.authServer?.closeAuthServer();
  await stack.decisionChannel.close();
  await stack.masGovernedChannel?.close();
  stack.pdpClaims.close();
  stack.writeReservations.close();
  stack.evidenceRetention.close();
  stack.payments.db.close();
  stack.kernel.close();
}

function authServer(stack: DemoStack) {
  const as = stack.authServer;
  if (!as) throw new Error("the stack runs no AS");
  return as;
}

/** Bob consents, once, to the standing-payment template on the approval surface; returns its id. */
async function consentTemplate(stack: DemoStack): Promise<string> {
  const as = authServer(stack);
  const proposed = await fetch(`${as.asUrl}/templates/proposals`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
    body: JSON.stringify({
      template_version: `sp-e2e-${randomUUID()}`,
      ceiling: [
        {
          type: "mission_resource_access",
          resource: CANONICAL_RESOURCE,
          actions: ["payments:payment.execute"],
          constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
        },
      ],
      dispatch_policy: { id: POLICY_ID, version: "1" },
      dispatchers: ["ap-agent"],
      recipients: { subjects: [{ iss: as.asUrl, sub: "bob" }], agents: ["subagent-invoice-extractor"] },
      per_instance_lifetime_s: 900,
      max_active: 3,
      rate_per_min: 30,
      review_cadence_s: 86400,
      expires_at: FAR_FUTURE,
    }),
  });
  const { proposal_id } = (await proposed.json()) as { proposal_id: string };
  expect(proposed.status).toBe(201);
  const { sessions } = as.approverConsole as ApprovalConsole;
  const { cookie, csrf } = sessions.establish(proposal_id, { sub: "bob", acr: "mfa", auth_time: Math.floor(Date.now() / 1000) });
  const page = await fetch(`${as.asUrl}/templates/proposals/${proposal_id}`, { headers: { cookie } });
  expect(page.status).toBe(200);
  const decided = await fetch(`${as.asUrl}/templates/proposals/${proposal_id}/decide`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie, "x-csrf-token": csrf },
    body: JSON.stringify({ decision: "approve", render_revision: page.headers.get(APPROVAL_RENDER_REVISION_HEADER) }),
  });
  const out = (await decided.json()) as { template_id: string };
  expect(decided.status, JSON.stringify(out)).toBe(201);
  return out.template_id;
}

/** The Dispatcher dispatches one instance, unattended, at the token endpoint; returns the instance's Mission id. */
async function dispatchInstance(stack: DemoStack, templateId: string): Promise<string> {
  const as = authServer(stack);
  const before = new Set(stack.kernel.standingPayments.dispatchedInstances(templateId));
  const dpop = await generateKeyPair("ES256", { extractable: true });
  const { status, body } = await tokenGrantRequest(as.asUrl, as.agentClientJwk, dpop, {
    grant_type: MISSION_DISPATCH_GRANT_TYPE,
    template_id: templateId,
    mission_intent: JSON.stringify({
      intent: {
        goal: "pay approved Acme invoices",
        target_resources: [CANONICAL_RESOURCE],
        expires_at: FAR_FUTURE,
        max_budget: { amount: "150.00", currency: "USD" },
      },
    }),
    dispatch_event_id: `sp-dispatch-${randomUUID()}`,
  });
  expect(status, JSON.stringify(body)).toBe(200);
  const dispatched = stack.kernel.standingPayments.dispatchedInstances(templateId).filter((id) => !before.has(id));
  expect(dispatched).toHaveLength(1);
  return dispatched[0] as string;
}

/** The acting credential's verified facts for `missionId`, as the resource's token validation establishes them. */
function tokenFor(stack: DemoStack, missionId: string): TokenFacts {
  const view = stack.viewFor(missionId);
  if (!view?.subject || !view.client_id) throw new Error(`no view of ${missionId}`);
  return {
    sub: view.subject.sub,
    iss: stack.issuer,
    clientId: view.client_id,
    cnfJkt: "jkt-standing-payment",
    mission: { id: view.id, issuer: view.issuer, authority_hash: view.authority_hash },
    credentialAuthority: credentialAuthorityFrom(view.authority_set),
  };
}

const wire = (stack: DemoStack, missionId: string, invoiceId: string) =>
  stack.server.callTransactionTool(
    "execute_wire_transfer",
    { invoice_id: invoiceId, idempotency_key: `idem_${randomUUID()}` },
    tokenFor(stack, missionId),
  );

/** Acme invoices beyond the seeded ones, each paying Acme's committed account. */
function seedAcmeInvoices(stack: DemoStack, invoices: Array<[string, string]>): void {
  stack.payments.seed(
    [],
    invoices.map(([id, amount]) => ({ id, vendor_id: "acme", amount, currency: "USD", payee_account: ACME_ACCOUNT, status: "payable" })),
  );
}

const SHARED = budgetCounterId("standing_consent", { owner: OWNER, budget_id: BUDGET_ID });
const instanceCounter = (stack: DemoStack, root: string) => budgetCounterId("mission", { issuer: stack.issuer, mission_id: root });

/** A counter's totals as decimal strings, or `undefined` for a counter never charged. */
function totals(state: BudgetCounterState | undefined) {
  return state && { reserved: state.reserved.amount, held: state.held.amount, committed: state.committed.amount };
}

/** The wires the ledger connector committed, as `[invoice, payee, amount]`. */
const wires = (stack: DemoStack) =>
  stack.connectors.ledgerEntries().map((e) => [e.invoice_id, e.payee_account, e.amount]);

/** The commit-phase Decision Evidence the PDP signed for `missionId`, in order. */
/** The executing PEP's claim channel; the stack's public type narrows its decision channel to `close`. */
const claimChannel = (stack: DemoStack): ClaimChannel => (stack.decisionChannel as unknown as { claims: ClaimChannel }).claims;

const commitDecisions = (stack: DemoStack, missionId: string) =>
  stack.evidence
    .forMission(missionId)
    .filter((e): e is DecisionEvidence => e.kind === "decision" && e.content.action_phase === "commit")
    .map((e) => e.content);

describe("standing-payment dispatch metered end to end through the composed stack (@spec mission-template#standing-payment-exception, metering#aggregate-bounds, #813, #816)", () => {
  let fgaBootstrap: MockInstance;
  beforeAll(() => {
    fgaBootstrap = vi.spyOn(Fga, "bootstrap").mockResolvedValue({
      fga: { checkWithContext: async () => true, checkStored: async () => true, client: { write: async () => ({}) }, modelId: "test" } as unknown as Fga,
      storeId: "test",
      modelId: "test",
    });
  });
  afterAll(() => fgaBootstrap.mockRestore());

  it("dispatches a standing payment unattended and executes it, committing the wire's amount on the instance counter and the shared standing_consent counter (@spec mission-template#standing-payment-exception, metering#metering, #813, #816)", async () => {
    const stack = await compose(15021, newFiles());
    try {
      const templateId = await consentTemplate(stack);
      const instance = await dispatchInstance(stack, templateId);
      const paid = await wire(stack, instance, "inv-1");
      expect(paid.ok, JSON.stringify(paid)).toBe(true);
      expect(wires(stack)).toEqual([["inv-1", ACME_ACCOUNT, "125.00"]]);
      expect(totals(stack.pdpClaims.budgetCounter(instanceCounter(stack, instance)))).toEqual({ reserved: "0.00", held: "0.00", committed: "125.00" });
      expect(totals(stack.pdpClaims.budgetCounter(SHARED))).toEqual({ reserved: "0.00", held: "0.00", committed: "125.00" });
      const [permit] = commitDecisions(stack, instance);
      expect(permit?.decision).toBe("permit");
      expect(permit?.metering?.map((m) => [m.counter_scope, m.counter_id, m.remaining.amount])).toEqual([
        ["mission", instanceCounter(stack, instance), "25.00"],
        ["standing_consent", SHARED, "75.00"],
      ]);
    } finally {
      await closeStack(stack);
    }
  });

  it("refuses a payment to a changed bank account with nothing wired: parameter_violation when the account changed before the decision, and target_drift suppression at admission when it changed after the permit, whose reservation stays charged, held with the alert once the lease elapses, so a second instance's payment against the budget is quota_exceeded (@spec mission-template#standing-payment-exception, runtime#execution-reverification, metering#settlement-states, #813, D830 ruling 4, owner ruling)", async () => {
    const stack = await compose(15022, newFiles());
    try {
      const templateId = await consentTemplate(stack);
      const instance = await dispatchInstance(stack, templateId);
      const second = await dispatchInstance(stack, templateId);
      // Before the decision: the PDP compares the payee the PEP established
      // from the payments store with the committed destination.
      stack.payments.setInvoicePayeeAccount("inv-1", "acct-acme-999");
      const refused = await wire(stack, instance, "inv-1");
      expect(refused).toMatchObject({ ok: false, denial_reason: "parameter_violation" });
      expect(commitDecisions(stack, instance).map((d) => [d.decision, d.denial_reason])).toEqual([["deny", "parameter_violation"]]);
      expect(stack.pdpClaims.budgetCounter(SHARED)).toBeUndefined();
      expect(stack.pdpClaims.budgetCounter(instanceCounter(stack, instance))).toBeUndefined();
      // After the permit: the account changes between the decision and the
      // permit's use, without even a record version change, and execution
      // reverification suppresses the permit before it is redeemed. This
      // PEP's redemption store cannot durably cancel the permit, so it sends
      // nothing and the reservation stays charged.
      seedAcmeInvoices(stack, [["inv-4", "125.00"], ["inv-5", "125.00"]]);
      stack.onEnforce(({ tool, decision }) => {
        if (tool === "execute_wire_transfer" && decision.decision) {
          stack.payments.db.prepare("UPDATE invoices SET payee_account = ? WHERE id = ?").run("acct-acme-999", "inv-4");
        }
      });
      const suppressed = await wire(stack, instance, "inv-4");
      expect(suppressed).toEqual({ ok: false, refusal_reason: "target_drift" });
      const permit = commitDecisions(stack, instance).find((d) => d.decision === "permit");
      const evaluationId = String(permit?.evaluation_id);
      expect(stack.pdpClaims.reservationsFor(evaluationId).map((r) => r.state)).toEqual(["reserved", "reserved"]);
      expect(totals(stack.pdpClaims.budgetCounter(SHARED))).toEqual({ reserved: "125.00", held: "0.00", committed: "0.00" });
      // Past the permit and its lease, the declared reconciler resolves the
      // claim unredeemed; the reservation is held, with the alert, for an
      // operator's reconciliation. The second instance's 125.00 does not fit
      // the 75.00 left of the 200.00 budget.
      const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
      vi.useFakeTimers({ toFake: ["Date"] });
      try {
        vi.setSystemTime(Date.now() + 120_000);
        expect((await stack.reconciler.runOnce()).claims?.unredeemed).toContain(evaluationId);
        const alerts = stderr.mock.calls
          .map(([chunk]) => String(chunk))
          .filter((line) => line.startsWith('{"type":"operator_alert"'))
          .map((line) => JSON.parse(line) as Record<string, unknown>);
        expect(alerts).toEqual([
          expect.objectContaining({ kind: "budget_reservation_held", evaluation_id: evaluationId, mission_id: instance, cause: "lease_elapsed" }),
        ]);
        expect(stack.pdpClaims.reservationsFor(evaluationId).map((r) => r.state)).toEqual(["held", "held"]);
        expect(await wire(stack, second, "inv-5")).toMatchObject({ ok: false, denial_reason: "quota_exceeded" });
      } finally {
        vi.useRealTimers();
        stderr.mockRestore();
      }
      expect(wires(stack)).toEqual([]);
      expect(totals(stack.pdpClaims.budgetCounter(SHARED))).toEqual({ reserved: "0.00", held: "125.00", committed: "0.00" });
      expect(totals(stack.pdpClaims.budgetCounter(instanceCounter(stack, instance)))).toEqual({ reserved: "0.00", held: "125.00", committed: "0.00" });
      expect(stack.pdpClaims.budgetCounter(instanceCounter(stack, second))).toBeUndefined();
    } finally {
      await closeStack(stack);
    }
  });

  it("refuses a payment whose invoice amount was altered above the per-payment bound out_of_authority at the PEP's credential bound, before any decision, with nothing wired and neither counter charged (@spec mission-template#standing-payment-exception, runtime#input-authority, #813)", async () => {
    const stack = await compose(15023, newFiles());
    try {
      const templateId = await consentTemplate(stack);
      const instance = await dispatchInstance(stack, templateId);
      stack.payments.bumpInvoiceAmount("inv-1", "500.01");
      const refused = await wire(stack, instance, "inv-1");
      expect(refused).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
      expect(commitDecisions(stack, instance)).toEqual([]);
      // Control: an unaltered invoice at exactly the per-payment bound is not refused for it.
      seedAcmeInvoices(stack, [["inv-4", "500.00"]]);
      expect(await wire(stack, instance, "inv-4")).toMatchObject({ ok: false, denial_reason: "quota_exceeded" });
      expect(wires(stack)).toEqual([]);
      expect(stack.pdpClaims.budgetCounter(SHARED)).toBeUndefined();
      expect(stack.pdpClaims.budgetCounter(instanceCounter(stack, instance))).toBeUndefined();
    } finally {
      await closeStack(stack);
    }
  });

  it("refuses quota_exceeded the second instance's payment that would exhaust the shared budget, naming the standing_consent counter, with nothing wired for it (@spec metering#aggregate-bounds, #813, #816)", async () => {
    const stack = await compose(15024, newFiles());
    try {
      const templateId = await consentTemplate(stack);
      const first = await dispatchInstance(stack, templateId);
      const second = await dispatchInstance(stack, templateId);
      seedAcmeInvoices(stack, [["inv-4", "125.00"]]);
      expect((await wire(stack, first, "inv-1")).ok).toBe(true);
      const refused = await wire(stack, second, "inv-4");
      expect(refused).toMatchObject({ ok: false, denial_reason: "quota_exceeded" });
      const [denied] = commitDecisions(stack, second);
      expect(denied?.metering?.map((m) => [m.counter_scope, m.counter_id, m.remaining.amount])).toEqual([
        ["mission", instanceCounter(stack, second), "150.00"],
        ["standing_consent", SHARED, "75.00"],
      ]);
      expect(wires(stack)).toEqual([["inv-1", ACME_ACCOUNT, "125.00"]]);
      expect(totals(stack.pdpClaims.budgetCounter(SHARED))).toEqual({ reserved: "0.00", held: "0.00", committed: "125.00" });
      expect(totals(stack.pdpClaims.budgetCounter(instanceCounter(stack, first)))).toEqual({ reserved: "0.00", held: "0.00", committed: "125.00" });
      expect(stack.pdpClaims.budgetCounter(instanceCounter(stack, second))).toBeUndefined();
    } finally {
      await closeStack(stack);
    }
  });

  it("holds the reservation of a permit issued before a restart, raises the operator alert, and the next instance's headroom is reduced by it (@spec metering#settlement-states, metering#aggregate-bounds, #813, #816, D830 ruling 7)", async () => {
    const files = newFiles(true);
    // The first process dispatches two instances, issues the first a permit
    // for 125.00, and stops before redeeming it.
    const before = await compose(15025, files);
    let first: string;
    let second: string;
    let evaluationId: string;
    try {
      const templateId = await consentTemplate(before);
      first = await dispatchInstance(before, templateId);
      second = await dispatchInstance(before, templateId);
      const permit = await before.pep.enforce(
        "execute_wire_transfer",
        { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` },
        tokenFor(before, first),
      );
      expect(permit.permitted, JSON.stringify(permit.denial_reason)).toBe(true);
      evaluationId = String(permit.decision?.context.evaluation_id);
      expect(before.connectors.ledgerEntries()).toEqual([]);
    } finally {
      await closeStack(before);
    }
    const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    let after: DemoStack | undefined;
    try {
      after = await compose(15025, files);
      const alerts = stderr.mock.calls
        .map(([chunk]) => String(chunk))
        .filter((line) => line.startsWith('{"type":"operator_alert"'))
        .map((line) => JSON.parse(line) as Record<string, unknown>);
      expect(alerts).toEqual([
        expect.objectContaining({ kind: "budget_reservation_held", evaluation_id: evaluationId, mission_id: first, cause: "restart_unknown" }),
      ]);
      expect(after.pdpClaims.reservationsFor(evaluationId).map((r) => r.state)).toEqual(["held", "held"]);
      expect(totals(after.pdpClaims.budgetCounter(SHARED))).toEqual({ reserved: "0.00", held: "125.00", committed: "0.00" });
      // The second instance has 75.00 of headroom left, not 200.00.
      seedAcmeInvoices(after, [["inv-4", "125.00"]]);
      expect(await wire(after, second, "inv-4")).toMatchObject({ ok: false, denial_reason: "quota_exceeded" });
      const paid = await wire(after, second, "inv-seed");
      expect(paid.ok, JSON.stringify(paid)).toBe(true);
      expect(wires(after)).toEqual([["inv-seed", ACME_ACCOUNT, "75.00"]]);
      expect(totals(after.pdpClaims.budgetCounter(SHARED))).toEqual({ reserved: "0.00", held: "125.00", committed: "75.00" });
      expect(totals(after.pdpClaims.budgetCounter(instanceCounter(after, first)))).toEqual({ reserved: "0.00", held: "125.00", committed: "0.00" });
      expect(totals(after.pdpClaims.budgetCounter(instanceCounter(after, second)))).toEqual({ reserved: "0.00", held: "0.00", committed: "75.00" });
    } finally {
      stderr.mockRestore();
      if (after) await closeStack(after);
    }
  });

  it("raises the operator alert when a wired payment's lost settlement leaves its reservation held, a resolution notice when an operator releases it, and the overspend alert when its late completed settlement commits the released reservation and pushes the shared counter past its limit (@spec metering#settlement-states, #813, #816, D830 rulings 7 and 10)", async () => {
    const stack = await compose(15028, newFiles());
    const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const alerts = () =>
      stderr.mock.calls
        .map(([chunk]) => String(chunk))
        .filter((line) => line.startsWith('{"type":"operator_alert"'))
        .map((line) => JSON.parse(line) as Record<string, unknown>);
    try {
      const templateId = await consentTemplate(stack);
      const first = await dispatchInstance(stack, templateId);
      const second = await dispatchInstance(stack, templateId);
      seedAcmeInvoices(stack, [["inv-4", "125.00"]]);
      // The first wire commits, and its settlement never reaches the PDP.
      const lost = vi.spyOn(stack.pdpClaims, "settle").mockRejectedValue(new Error("settlement lost"));
      const paid = await wire(stack, first, "inv-1");
      lost.mockRestore();
      expect(paid.ok, JSON.stringify(paid)).toBe(true);
      const [permit] = commitDecisions(stack, first);
      const evaluationId = String(permit?.evaluation_id);
      expect(totals(stack.pdpClaims.budgetCounter(SHARED))).toEqual({ reserved: "125.00", held: "0.00", committed: "0.00" });
      vi.useFakeTimers({ toFake: ["Date"] });
      vi.setSystemTime(Date.now() + 120_000);
      // Past the permit and its lease, unsettled: held, with the alert.
      stack.pdpClaims.sweep();
      expect(alerts()).toEqual([
        expect.objectContaining({ kind: "budget_reservation_held", evaluation_id: evaluationId, mission_id: first, cause: "lease_elapsed" }),
      ]);
      expect(totals(stack.pdpClaims.budgetCounter(SHARED))).toEqual({ reserved: "0.00", held: "125.00", committed: "0.00" });
      // An operator wrongly answers that it never executed, and the second
      // instance spends the headroom that frees.
      expect(stack.pdpClaims.reconcileHeldReservation(evaluationId, { kind: "not_executed", reference: "operator-ticket-813" })).toEqual({
        accepted: true,
        state: "released",
      });
      expect((await wire(stack, second, "inv-4")).ok).toBe(true);
      // The declared reconciler settles the first wire from its retained
      // Execution Evidence: the spend commits anyway, past the limit.
      expect((await stack.reconciler.runOnce()).claims?.settled).toContain(evaluationId);
      expect(alerts()).toEqual([
        expect.objectContaining({ kind: "budget_reservation_held", evaluation_id: evaluationId, mission_id: first, cause: "lease_elapsed" }),
        expect.objectContaining({
          kind: "budget_reservation_released",
          evaluation_id: evaluationId,
          mission_id: first,
          cause: "operator_reconciled:not_executed:operator-ticket-813",
        }),
        expect.objectContaining({ kind: "budget_overspend", evaluation_id: evaluationId, mission_id: first, cause: "standing_consent_limit_exceeded" }),
      ]);
      expect(wires(stack)).toEqual([
        ["inv-1", ACME_ACCOUNT, "125.00"],
        ["inv-4", ACME_ACCOUNT, "125.00"],
      ]);
      expect(totals(stack.pdpClaims.budgetCounter(SHARED))).toEqual({ reserved: "0.00", held: "0.00", committed: "250.00" });
      expect(totals(stack.pdpClaims.budgetCounter(instanceCounter(stack, first)))).toEqual({ reserved: "0.00", held: "0.00", committed: "125.00" });
    } finally {
      vi.useRealTimers();
      stderr.mockRestore();
      await closeStack(stack);
    }
  });

  it("surfaces a conflicting settlement on the composed stack's alarm path: a second completed record for a settled wire raises one settlement_conflict operator alert, and the applied settlement and the committed amount are unchanged (@spec metering#settlement-contract, #816, D877)", async () => {
    const stack = await compose(15029, newFiles());
    const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const alerts = () =>
      stderr.mock.calls
        .map(([chunk]) => String(chunk))
        .filter((line) => line.startsWith('{"type":"operator_alert"'))
        .map((line) => JSON.parse(line) as Record<string, unknown>);
    try {
      const templateId = await consentTemplate(stack);
      const instance = await dispatchInstance(stack, templateId);
      const paid = await wire(stack, instance, "inv-1");
      expect(paid.ok, JSON.stringify(paid)).toBe(true);
      const applied = stack.evidence
        .forMission(instance)
        .find((e) => e.kind === "execution" && e.content.outcome === "completed");
      if (applied?.kind !== "execution") throw new Error("no completed Execution Evidence for the wire");
      expect(totals(stack.pdpClaims.budgetCounter(SHARED))).toEqual({ reserved: "0.00", held: "0.00", committed: "125.00" });
      // A second attempt's completed record for the same permit, signed under the executor's key.
      const conflicting = await stack.evidence.recordExecution(CANONICAL_RESOURCE, "executor", {
        permitId: applied.permit_id,
        opKey: applied.op_key,
        evaluation_id: applied.content.evaluation_id,
        mission_id: instance,
        audience: applied.content.audience,
        outcome: "completed",
      });
      expect(await claimChannel(stack).settle(conflicting.content)).toEqual({ accepted: false, reason: "already_settled" });
      expect(alerts()).toEqual([
        expect.objectContaining({ kind: "settlement_conflict", evaluation_id: applied.content.evaluation_id, mission_id: instance, cause: "completed_then_completed" }),
      ]);
      expect(stack.pdpClaims.settlementConflicts(applied.content.evaluation_id)).toEqual([
        expect.objectContaining({ execution_id: conflicting.content.execution_id, outcome: "completed", applied_execution_id: applied.content.execution_id }),
      ]);
      // The applied settlement is unchanged: its own record, redelivered, is
      // acknowledged as the duplicate, and the conflicting one is still refused,
      // with no second alert.
      expect(await claimChannel(stack).settle(applied.content)).toEqual({ accepted: true, state: "completed", duplicate: true });
      expect(await claimChannel(stack).settle(conflicting.content)).toEqual({ accepted: false, reason: "already_settled" });
      expect(alerts()).toHaveLength(1);
      expect(totals(stack.pdpClaims.budgetCounter(SHARED))).toEqual({ reserved: "0.00", held: "0.00", committed: "125.00" });
    } finally {
      stderr.mockRestore();
      await closeStack(stack);
    }
  });

  it("continues both counters in an expansion successor: its payment is metered on the dispatched instance's mission counter and on the shared counter (@spec metering#capacity-across-missions, mission-template#instance-composition, #813, #816)", async () => {
    const stack = await compose(15026, newFiles());
    try {
      const templateId = await consentTemplate(stack);
      const instance = await dispatchInstance(stack, templateId);
      expect((await wire(stack, instance, "inv-1")).ok).toBe(true);
      const { successor } = createExpansion(stack.kernel, {
        predecessorId: instance,
        intent: stack.kernel.validateIntent(
          JSON.stringify({
            goal: "pay approved Acme invoices",
            target_resources: [CANONICAL_RESOURCE],
            expires_at: FAR_FUTURE,
            max_budget: { amount: "150.00", currency: "USD" },
          }),
          { admitMaxBudget: true },
        ),
        approver: { iss: stack.issuer, sub: "bob" },
        approvalEventId: `sp-expansion-${randomUUID()}`,
        approvedUntil: FAR_FUTURE,
      });
      seedAcmeInvoices(stack, [["inv-5", "50.00"], ["inv-6", "25.00"]]);
      // The instance counter already holds 125.00 of 150.00.
      expect(await wire(stack, successor.id, "inv-5")).toMatchObject({ ok: false, denial_reason: "quota_exceeded" });
      const [refused] = commitDecisions(stack, successor.id);
      expect(refused?.metering?.map((m) => [m.counter_scope, m.counter_id, m.remaining.amount])).toEqual([
        ["mission", instanceCounter(stack, instance), "25.00"],
        ["standing_consent", SHARED, "75.00"],
      ]);
      const paid = await wire(stack, successor.id, "inv-6");
      expect(paid.ok, JSON.stringify(paid)).toBe(true);
      const permit = commitDecisions(stack, successor.id).find((d) => d.decision === "permit");
      expect(permit?.metering?.map((m) => [m.counter_scope, m.counter_id, m.remaining.amount])).toEqual([
        ["mission", instanceCounter(stack, instance), "0.00"],
        ["standing_consent", SHARED, "50.00"],
      ]);
      expect(wires(stack)).toEqual([
        ["inv-1", ACME_ACCOUNT, "125.00"],
        ["inv-6", ACME_ACCOUNT, "25.00"],
      ]);
      expect(totals(stack.pdpClaims.budgetCounter(instanceCounter(stack, instance)))).toEqual({ reserved: "0.00", held: "0.00", committed: "150.00" });
      expect(totals(stack.pdpClaims.budgetCounter(SHARED))).toEqual({ reserved: "0.00", held: "0.00", committed: "150.00" });
      expect(stack.pdpClaims.budgetCounter(instanceCounter(stack, successor.id))).toBeUndefined();
    } finally {
      await closeStack(stack);
    }
  });

  it("refuses an expansion successor's re-presentation of a paid invoice under the instance's key with nothing wired twice: the successor's claim is its own, so a fresh permit reserves on both counters, the ledger refuses the wire already_settled, and that suppression releases the reservation, leaving the amount committed once (@spec metering#retry, metering#settlement-states, metering#capacity-across-missions, #816, D877)", async () => {
    const stack = await compose(15030, newFiles());
    try {
      const templateId = await consentTemplate(stack);
      const instance = await dispatchInstance(stack, templateId);
      seedAcmeInvoices(stack, [["inv-6", "25.00"]]);
      const key = `idem_${randomUUID()}`;
      const pay = (missionId: string) =>
        stack.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-6", idempotency_key: key }, tokenFor(stack, missionId));
      const first = await pay(instance);
      expect(first.ok, JSON.stringify(first)).toBe(true);
      const { successor } = createExpansion(stack.kernel, {
        predecessorId: instance,
        intent: stack.kernel.validateIntent(
          JSON.stringify({
            goal: "pay approved Acme invoices",
            target_resources: [CANONICAL_RESOURCE],
            expires_at: FAR_FUTURE,
            max_budget: { amount: "150.00", currency: "USD" },
          }),
          { admitMaxBudget: true },
        ),
        approver: { iss: stack.issuer, sub: "bob" },
        approvalEventId: `sp-expansion-${randomUUID()}`,
        approvedUntil: FAR_FUTURE,
      });
      // The idempotency scope names the Mission, so the successor's key meets no claim and its permit is fresh.
      expect(await pay(successor.id)).toMatchObject({ ok: false, refusal_reason: "already_settled" });
      const permits = commitDecisions(stack, successor.id).filter((d) => d.decision === "permit");
      expect(permits).toHaveLength(1);
      const evaluationId = String(permits[0]?.evaluation_id);
      expect(stack.pdpClaims.reservationsFor(evaluationId).map((r) => [r.counter_scope, r.state, r.cause])).toEqual(
        expect.arrayContaining([
          ["mission", "released", "settled_suppressed"],
          ["standing_consent", "released", "settled_suppressed"],
        ]),
      );
      expect(
        stack.evidence
          .forMission(successor.id)
          .filter((e) => e.kind === "execution")
          .map((e) => [e.content.outcome, (e.content as { error?: string }).error]),
      ).toEqual([["suppressed", expect.stringContaining("already_settled")]]);
      expect(wires(stack)).toEqual([["inv-6", ACME_ACCOUNT, "25.00"]]);
      expect(totals(stack.pdpClaims.budgetCounter(instanceCounter(stack, instance)))).toEqual({ reserved: "0.00", held: "0.00", committed: "25.00" });
      expect(totals(stack.pdpClaims.budgetCounter(SHARED))).toEqual({ reserved: "0.00", held: "0.00", committed: "25.00" });
    } finally {
      await closeStack(stack);
    }
  });

  it("denies constraint_unsupported every payment of a standing-payment instance whose committed policy snapshot is no longer retained, with nothing wired or charged, and the kernel-backed source answers underivable for a Mission it does not hold or holds under another issuer (@spec metering#metering, mission-template#standing-payment-exception, #813, decision d)", async () => {
    const stack = await compose(15027, newFiles());
    try {
      const templateId = await consentTemplate(stack);
      const instance = await dispatchInstance(stack, templateId);
      // The snapshot the instance's activation retained is gone (pruned past
      // its horizon): the kernel still records the standing payment, but no
      // binding derives from it.
      const derived = kernelBudgetBinding(stack.kernel, { id: instance, issuer: stack.issuer });
      expect(derived).toMatchObject({ owner: OWNER, budget_id: BUDGET_ID, destinations: { acme: ACME_ACCOUNT } });
      // The source cannot vouch for a Mission this kernel does not hold, or
      // holds under another issuer: underivable, never unbound.
      expect(kernelBudgetBinding(stack.kernel, { id: "msn_not_held", issuer: stack.issuer })).toBe(UNDERIVABLE_BUDGET);
      expect(kernelBudgetBinding(stack.kernel, { id: instance, issuer: "https://another-issuer.test" })).toBe(UNDERIVABLE_BUDGET);
      stack.kernel.db.prepare("DELETE FROM activation_policy_snapshots").run();
      expect(stack.kernel.standingPayments.admission(instance)).toBeDefined();
      expect(kernelBudgetBinding(stack.kernel, { id: instance, issuer: stack.issuer })).toBe(UNDERIVABLE_BUDGET);
      expect(await wire(stack, instance, "inv-1")).toMatchObject({ ok: false, denial_reason: "constraint_unsupported" });
      expect(wires(stack)).toEqual([]);
      expect(stack.pdpClaims.budgetCounter(SHARED)).toBeUndefined();
      expect(stack.pdpClaims.budgetCounter(instanceCounter(stack, instance))).toBeUndefined();
    } finally {
      await closeStack(stack);
    }
  });
});
