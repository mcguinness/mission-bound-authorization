/**
 * @spec mission-template#standing-payment-exception, metering#aggregate-bounds,
 * metering#retry, approval-governance#recency-evaluation,
 * approval-governance#activation-policy-commitment (#813, #816, D1143 ruling 5):
 * the shared demo composition (`composeStack({ withAuthServer: true })`, as
 * `pnpm demo:serve`, `pnpm exhibit` and `pnpm agent` compose it) running the
 * SHIPPED `config/standing-payment.json`: no fixture Dispatch Policy and no
 * supplied statement.
 *
 * `@mission/demo-data` is wrapped only to record each configuration the
 * composition loads (the real loader runs and its result is used unchanged),
 * so a test can see that the enabled composition read the file and, for the
 * snapshot case, edit the snapshot the AS holds in place as an operator edit
 * under the same version would. Only the OpenFGA client is stubbed.
 */

import { randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPair } from "jose";
import { afterAll, beforeAll, beforeEach, describe, expect, it, type MockInstance, vi } from "vitest";
import { ALL_PROVIDER_CAPABILITIES, mintActivationPolicyRef } from "@mission/authorization-server";
import { DEV_SERVICE_TOKEN, type StandingPaymentDeployment } from "@mission/demo-data";
import { CANONICAL_RESOURCE, credentialAuthorityFrom, type DecisionEvidence, type TokenFacts } from "@mission/mcp-payments";
import { type BudgetCounterState, budgetCounterId, Fga, RUNTIME_POSTURE, type RuntimePosture } from "@mission/pdp";
import { APPROVAL_RENDER_REVISION_HEADER, type ApprovalConsole } from "../src/approval-console.js";
import { tokenGrantRequest } from "../src/oauth-client.js";
import { composeStack, type DemoStack } from "../src/stack.js";

const loaded = vi.hoisted(() => [] as StandingPaymentDeployment[]);
vi.mock("@mission/demo-data", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@mission/demo-data")>();
  return {
    ...actual,
    loadStandingPaymentDeployment: () => {
      const deployment = actual.loadStandingPaymentDeployment();
      loaded.push(deployment);
      return deployment;
    },
  };
});

const MISSION_DISPATCH_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:mission-dispatch";
const FAR_FUTURE = "2099-01-01T00:00:00Z";
const SHIPPED_FILE = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "config", "standing-payment.json");
/** The shipped configuration's names, read from the file so a test never restates a fixture of its own. */
const SHIPPED = JSON.parse(readFileSync(SHIPPED_FILE, "utf8")) as {
  dispatch_policies: Record<string, { version: string; content_type: string; content: Record<string, unknown> }>;
  budget_metering: Record<string, unknown>;
};
const POLICY_ID = "ap-standing-payment";
const OWNER = "payments-operator";
const BUDGET_ID = "ap-standing-payments";
const ACME_ACCOUNT = "acct-acme-001";
const SHARED = budgetCounterId("standing_consent", { owner: OWNER, budget_id: BUDGET_ID });
/** The shipped snapshot's digest at the shipped issuer, the value the reviewed configuration was approved with (D1143). */
const SHIPPED_DIGEST_AT_4400 = "sha-256:oPOh2t72gnR7Z55KZMy34aaWVfmk7QFuQL52Fe51fPc";

const tempFile = (prefix: string, name: string): string => join(mkdtempSync(join(tmpdir(), prefix)), name);

interface StackFiles {
  claimsFile: string;
  writeReservationsFile: string;
  kernelFile?: string;
}

function newFiles(withKernel = false): StackFiles {
  return {
    claimsFile: tempFile("sp-shipped-claims-", "claims.sqlite"),
    writeReservationsFile: tempFile("sp-shipped-reservations-", "write-reservations.sqlite"),
    ...(withKernel ? { kernelFile: tempFile("sp-shipped-kernel-", "kernel.db") } : {}),
  };
}

/** The shared demo composition with the AS, as its launchers compose it: no statement and no standing-payment fixture. */
function compose(asPort: number, files: StackFiles): Promise<DemoStack> {
  return composeStack({
    openfgaUrl: "http://unused.test",
    presharedKey: "unused",
    withAuthServer: true,
    asPort,
    claimsFile: files.claimsFile,
    writeReservationsFile: files.writeReservationsFile,
    resourcePolicyStore: { bootstrap: "development" },
    ...(files.kernelFile ? { kernelStore: { file: files.kernelFile } } : {}),
  });
}

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

interface ProposalTerms {
  maxAmount?: string;
  vendors?: string[];
  maxActive?: number;
  perInstanceLifetimeS?: number;
  reviewCadenceS?: number;
}

/** Propose a template under the shipped Dispatch Policy and render its consent page for Bob; returns the page and how to decide it. */
async function propose(stack: DemoStack, t: ProposalTerms = {}) {
  const as = authServer(stack);
  const proposed = await fetch(`${as.asUrl}/templates/proposals`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
    body: JSON.stringify({
      template_version: `sp-shipped-${randomUUID()}`,
      ceiling: [
        {
          type: "mission_resource_access",
          resource: CANONICAL_RESOURCE,
          actions: ["payments:payment.execute"],
          constraints: { max_amount: { amount: t.maxAmount ?? "500.00", currency: "USD" }, vendors: t.vendors ?? ["acme"] },
        },
      ],
      dispatch_policy: { id: POLICY_ID, version: "1" },
      dispatchers: ["ap-agent"],
      recipients: { subjects: [{ iss: as.asUrl, sub: "bob" }], agents: ["subagent-invoice-extractor"] },
      per_instance_lifetime_s: t.perInstanceLifetimeS ?? 900,
      max_active: t.maxActive ?? 3,
      rate_per_min: 30,
      review_cadence_s: t.reviewCadenceS ?? 86400,
      expires_at: FAR_FUTURE,
    }),
  });
  const proposedBody = (await proposed.json()) as { proposal_id?: string };
  expect(proposed.status, JSON.stringify(proposedBody)).toBe(201);
  const proposalId = proposedBody.proposal_id as string;
  const { sessions } = as.approverConsole as ApprovalConsole;
  const { cookie, csrf } = sessions.establish(proposalId, { sub: "bob", acr: "mfa", auth_time: Math.floor(Date.now() / 1000) });
  const page = await fetch(`${as.asUrl}/templates/proposals/${proposalId}`, { headers: { cookie } });
  const html = await page.text();
  const decide = async (): Promise<{ status: number; body: Record<string, unknown> }> => {
    const decided = await fetch(`${as.asUrl}/templates/proposals/${proposalId}/decide`, {
      method: "POST",
      headers: { "content-type": "application/json", cookie, "x-csrf-token": csrf },
      body: JSON.stringify({ decision: "approve", render_revision: page.headers.get(APPROVAL_RENDER_REVISION_HEADER) }),
    });
    return { status: decided.status, body: (await decided.json()) as Record<string, unknown> };
  };
  return { status: page.status, html, decide };
}

/** Bob consents, on the approval surface, to a template under the shipped Dispatch Policy; returns its id. */
async function consentTemplate(stack: DemoStack, t: ProposalTerms = {}): Promise<string> {
  const { status, html, decide } = await propose(stack, t);
  expect(status, html).toBe(200);
  const decided = await decide();
  expect(decided.status, JSON.stringify(decided.body)).toBe(201);
  return decided.body.template_id as string;
}

/** The Dispatcher asks, unattended, at the token endpoint, for one instance carrying `maxBudget`. */
async function requestDispatch(stack: DemoStack, templateId: string, maxBudget = "500.00") {
  const as = authServer(stack);
  return tokenGrantRequest(as.asUrl, as.agentClientJwk, await generateKeyPair("ES256", { extractable: true }), {
    grant_type: MISSION_DISPATCH_GRANT_TYPE,
    template_id: templateId,
    mission_intent: JSON.stringify({
      intent: {
        goal: "pay approved Acme invoices",
        target_resources: [CANONICAL_RESOURCE],
        expires_at: FAR_FUTURE,
        max_budget: { amount: maxBudget, currency: "USD" },
      },
    }),
    dispatch_event_id: `sp-shipped-dispatch-${randomUUID()}`,
  });
}

/** Dispatch one instance and return its Mission id. */
async function dispatchInstance(stack: DemoStack, templateId: string, maxBudget = "500.00"): Promise<string> {
  const before = new Set(stack.kernel.standingPayments.dispatchedInstances(templateId));
  const { status, body } = await requestDispatch(stack, templateId, maxBudget);
  expect(status, JSON.stringify(body)).toBe(200);
  const dispatched = stack.kernel.standingPayments.dispatchedInstances(templateId).filter((id) => !before.has(id));
  expect(dispatched).toHaveLength(1);
  return dispatched[0] as string;
}

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

const wire = (stack: DemoStack, missionId: string, invoiceId: string, key = `idem_${randomUUID()}`) =>
  stack.server.callTransactionTool("execute_wire_transfer", { invoice_id: invoiceId, idempotency_key: key }, tokenFor(stack, missionId));

/** Acme invoices beyond the seeded ones; each pays `account` (Acme's committed account unless named). */
function seedInvoices(stack: DemoStack, invoices: Array<[string, string, string?, string?]>): void {
  stack.payments.seed(
    [],
    invoices.map(([id, amount, vendor = "acme", account = ACME_ACCOUNT]) => ({
      id,
      vendor_id: vendor,
      amount,
      currency: "USD",
      payee_account: account,
      status: "payable",
    })),
  );
}

const instanceCounter = (stack: DemoStack, root: string) => budgetCounterId("mission", { issuer: stack.issuer, mission_id: root });

function totals(state: BudgetCounterState | undefined) {
  return state && { reserved: state.reserved.amount, held: state.held.amount, committed: state.committed.amount };
}

const wires = (stack: DemoStack) => stack.connectors.ledgerEntries().map((e) => [e.invoice_id, e.payee_account, e.amount]);

const commitDecisions = (stack: DemoStack, missionId: string) =>
  stack.evidence
    .forMission(missionId)
    .filter((e): e is DecisionEvidence => e.kind === "decision" && e.content.action_phase === "commit")
    .map((e) => e.content);

/** The template's approval instant, as every instance records it in `approval_basis.approved_at`. */
function approvedAtMs(stack: DemoStack, instance: string): number {
  const basis = stack.kernel.get(instance)?.approval_basis as { approved_at?: string } | undefined;
  if (!basis?.approved_at) throw new Error(`instance ${instance} records no approval instant`);
  return Date.parse(basis.approved_at);
}

describe("the shared demo composition on the shipped config/standing-payment.json (@spec mission-template#standing-payment-exception, metering#aggregate-bounds, #813, #816, D1143 ruling 5)", () => {
  let fgaBootstrap: MockInstance;
  beforeAll(() => {
    fgaBootstrap = vi.spyOn(Fga, "bootstrap").mockResolvedValue({
      fga: { checkWithContext: async () => true, checkStored: async () => true, client: { write: async () => ({}) }, modelId: "test" } as unknown as Fga,
      storeId: "test",
      modelId: "test",
    });
  });
  afterAll(() => fgaBootstrap.mockRestore());
  beforeEach(() => {
    loaded.length = 0;
  });

  it("reads the shipped file once at composition, enables standing-payment-dispatch on its AS beside the full reference set, and publishes budget_metering for the shipped budget naming the shipped Dispatch Policy with the digest this issuer computes (@spec metering#aggregate-bounds, D1143 rulings 1, 2 and 5)", async () => {
    const stack = await compose(15131, newFiles());
    try {
      expect(loaded).toHaveLength(1);
      expect(authServer(stack).capabilities).toEqual(new Set([...ALL_PROVIDER_CAPABILITIES, "standing-payment-dispatch"]));
      const statement = stack.server.protectedResourceMetadata().enforcement_scope_statement as RuntimePosture & {
        claims: string[];
        extensions: { budget_metering: { budgets: Array<Record<string, unknown>> } };
      };
      expect(statement.claims).toEqual([...((RUNTIME_POSTURE as { claims?: string[] }).claims ?? []), "budget_metering"]);
      const policy = SHIPPED.dispatch_policies[POLICY_ID];
      if (!policy) throw new Error("the shipped file holds no ap-standing-payment");
      const snapshot = { [POLICY_ID]: { version: policy.version, content_type: policy.content_type, content: JSON.stringify(policy.content) } };
      const ref = mintActivationPolicyRef(stack.issuer, snapshot, POLICY_ID, "1");
      expect(mintActivationPolicyRef("http://localhost:4400", snapshot, POLICY_ID, "1")?.digest).toBe(SHIPPED_DIGEST_AT_4400);
      expect(statement.extensions.budget_metering).toEqual({
        ...SHIPPED.budget_metering,
        budgets: [
          {
            owner: OWNER,
            budget_id: BUDGET_ID,
            counter_scope: "standing_consent",
            currency: "USD",
            limit: "1000.00",
            policies: [ref],
          },
        ],
      });
    } finally {
      await closeStack(stack);
    }
  });

  it("renders the shipped terms on the human consent page and consents; dispatches unattended an instance at the shipped per_instance_max of 500.00 and refuses one at 500.01 dispatch_prohibited_class; refuses at consent a ceiling bounding each payment above the shipped 500.00 and a vendor the shipped destinations do not commit (@spec mission-template#standing-payment-exception, mission-template#template-consent, #813)", async () => {
    const stack = await compose(15132, newFiles());
    try {
      const { status, html, decide } = await propose(stack);
      expect(status, html).toBe(200);
      expect(html).toContain(
        `Standing payment: payments:payment.execute at ${CANONICAL_RESOURCE}, at most 500.00 USD per payment, only to these committed destinations: acme to account ${ACME_ACCOUNT}. A changed payee account is not approved.`,
      );
      expect(html).toContain(
        `Budget ${OWNER}/${BUDGET_ID}: at most 1000.00 USD in total across every dispatched instance and its successors, retries and replacement credentials included; each instance's own max_budget is at most 500.00 USD.`,
      );
      expect(html).toContain(
        "Approval Governance exceptions committed by this consent: irreversible_action (at most 86400 seconds after this approval), consumption_bound (at most 86400 seconds after this approval); recency ceiling 86400 seconds, clock-skew allowance 60 seconds.",
      );
      const decided = await decide();
      expect(decided.status, JSON.stringify(decided.body)).toBe(201);
      const templateId = decided.body.template_id as string;
      const before = stack.kernel.allMissions().length;
      expect(await requestDispatch(stack, templateId, "500.01")).toMatchObject({
        status: 400,
        body: { error: "invalid_request", mission_denial_reason: "dispatch_prohibited_class" },
      });
      expect(stack.kernel.allMissions()).toHaveLength(before);
      await dispatchInstance(stack, templateId, "500.00");
      expect(stack.kernel.standingPayments.dispatchedInstances(templateId)).toHaveLength(1);

      const above = await (await propose(stack, { maxAmount: "500.01" })).decide();
      expect(above.status).toBe(400);
      expect(JSON.stringify(above.body)).toContain("bounds each payment above the Dispatch Policy's max_amount of 500.00");
      const globex = await (await propose(stack, { vendors: ["globex"] })).decide();
      expect(globex.status).toBe(400);
      expect(JSON.stringify(globex.body)).toContain("names vendor globex, which the Dispatch Policy commits no destination for");
      expect(stack.kernel.standingPayments.dispatchedInstances(templateId)).toHaveLength(1);
    } finally {
      await closeStack(stack);
    }
  });

  it("pays Acme's committed account within the shipped bounds, a payment at exactly the 500.00 per-payment bound included, and commits each wire on its instance's counter and on the shared standing_consent counter (@spec mission-template#standing-payment-exception, metering#metering, #813, #816)", async () => {
    const stack = await compose(15133, newFiles());
    try {
      const templateId = await consentTemplate(stack);
      const first = await dispatchInstance(stack, templateId);
      const second = await dispatchInstance(stack, templateId);
      seedInvoices(stack, [["inv-cap", "500.00"]]);
      const atCap = await wire(stack, first, "inv-cap");
      expect(atCap.ok, JSON.stringify(atCap)).toBe(true);
      const paid = await wire(stack, second, "inv-1");
      expect(paid.ok, JSON.stringify(paid)).toBe(true);
      expect(wires(stack)).toEqual([
        ["inv-cap", ACME_ACCOUNT, "500.00"],
        ["inv-1", ACME_ACCOUNT, "125.00"],
      ]);
      expect(totals(stack.pdpClaims.budgetCounter(instanceCounter(stack, first)))).toEqual({ reserved: "0.00", held: "0.00", committed: "500.00" });
      expect(totals(stack.pdpClaims.budgetCounter(instanceCounter(stack, second)))).toEqual({ reserved: "0.00", held: "0.00", committed: "125.00" });
      expect(totals(stack.pdpClaims.budgetCounter(SHARED))).toEqual({ reserved: "0.00", held: "0.00", committed: "625.00" });
      const [permit] = commitDecisions(stack, second);
      expect(permit?.metering?.map((m) => [m.counter_scope, m.counter_id, m.remaining.amount])).toEqual([
        ["mission", instanceCounter(stack, second), "375.00"],
        ["standing_consent", SHARED, "375.00"],
      ]);
    } finally {
      await closeStack(stack);
    }
  });

  it("refuses with nothing wired and neither counter charged: a payment to a changed Acme account parameter_violation against the shipped destination, a Globex invoice and payments above the shipped 500.00 per-payment bound out_of_authority (@spec mission-template#standing-payment-exception, runtime#input-authority, #813)", async () => {
    const stack = await compose(15134, newFiles());
    try {
      const templateId = await consentTemplate(stack);
      const instance = await dispatchInstance(stack, templateId);
      seedInvoices(stack, [
        ["inv-moved", "100.00", "acme", "acct-acme-999"],
        ["inv-over", "500.01"],
      ]);
      expect(await wire(stack, instance, "inv-moved")).toMatchObject({ ok: false, denial_reason: "parameter_violation" });
      expect(commitDecisions(stack, instance).map((d) => [d.decision, d.denial_reason])).toEqual([["deny", "parameter_violation"]]);
      expect(await wire(stack, instance, "inv-3")).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
      expect(await wire(stack, instance, "inv-over")).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
      expect(await wire(stack, instance, "inv-2")).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
      expect(wires(stack)).toEqual([]);
      expect(stack.pdpClaims.budgetCounter(SHARED)).toBeUndefined();
      expect(stack.pdpClaims.budgetCounter(instanceCounter(stack, instance))).toBeUndefined();
    } finally {
      await closeStack(stack);
    }
  });

  it("draws the shared 1000.00 budget across three dispatched instances until it is exhausted: the next payment is refused quota_exceeded on the standing_consent counter with headroom left on its own instance, and the counters show the shared total (@spec metering#aggregate-bounds, #813, #816)", async () => {
    const stack = await compose(15135, newFiles());
    try {
      const templateId = await consentTemplate(stack, { maxActive: 3 });
      const a = await dispatchInstance(stack, templateId);
      const b = await dispatchInstance(stack, templateId);
      const c = await dispatchInstance(stack, templateId);
      seedInvoices(stack, [
        ["inv-a", "500.00"],
        ["inv-b", "400.00"],
        ["inv-c", "100.00"],
        ["inv-d", "10.00"],
      ]);
      for (const [missionId, invoice] of [
        [a, "inv-a"],
        [b, "inv-b"],
        [c, "inv-c"],
      ] as const) {
        const paid = await wire(stack, missionId, invoice);
        expect(paid.ok, `${invoice}: ${JSON.stringify(paid)}`).toBe(true);
      }
      expect(totals(stack.pdpClaims.budgetCounter(SHARED))).toEqual({ reserved: "0.00", held: "0.00", committed: "1000.00" });
      expect(await wire(stack, c, "inv-d")).toMatchObject({ ok: false, denial_reason: "quota_exceeded" });
      const denied = commitDecisions(stack, c).find((d) => d.decision === "deny");
      expect(denied?.metering?.map((m) => [m.counter_scope, m.counter_id, m.remaining.amount])).toEqual([
        ["mission", instanceCounter(stack, c), "400.00"],
        ["standing_consent", SHARED, "0.00"],
      ]);
      expect(wires(stack)).toEqual([
        ["inv-a", ACME_ACCOUNT, "500.00"],
        ["inv-b", ACME_ACCOUNT, "400.00"],
        ["inv-c", ACME_ACCOUNT, "100.00"],
      ]);
      expect(totals(stack.pdpClaims.budgetCounter(SHARED))).toEqual({ reserved: "0.00", held: "0.00", committed: "1000.00" });
      expect(totals(stack.pdpClaims.budgetCounter(instanceCounter(stack, a)))).toEqual({ reserved: "0.00", held: "0.00", committed: "500.00" });
      expect(totals(stack.pdpClaims.budgetCounter(instanceCounter(stack, b)))).toEqual({ reserved: "0.00", held: "0.00", committed: "400.00" });
      expect(totals(stack.pdpClaims.budgetCounter(instanceCounter(stack, c)))).toEqual({ reserved: "0.00", held: "0.00", committed: "100.00" });
    } finally {
      await closeStack(stack);
    }
  });

  it("holds the consent to the shipped 86400 s recency ceiling and 60 s clock skew: a Dispatch exactly 86400 s after the consent is admitted and its payment executes, one 1 s later is refused dispatch_prohibited_class; a Dispatch whose clock reads 60 s before the consent is admitted, 61 s before is refused; a refusal creates no instance (@spec approval-governance#recency-evaluation, mission-template#standing-payment-exception, #813)", async () => {
    const stack = await compose(15136, newFiles());
    try {
      // A review cadence longer than the ceiling, so the recency terms alone decide.
      const ceilingTemplate = await consentTemplate(stack, { reviewCadenceS: 172_800 });
      const skewTemplate = await consentTemplate(stack, { reviewCadenceS: 172_800 });
      // Each template's approval instant, as its first instance records it.
      const probe = await dispatchInstance(stack, ceilingTemplate);
      const approved = approvedAtMs(stack, probe);
      const skewProbe = await dispatchInstance(stack, skewTemplate);
      const skewApproved = approvedAtMs(stack, skewProbe);
      vi.useFakeTimers({ toFake: ["Date"] });
      try {
        vi.setSystemTime(approved + 86_400_000);
        const atCeiling = await dispatchInstance(stack, ceilingTemplate);
        const paid = await wire(stack, atCeiling, "inv-1");
        expect(paid.ok, JSON.stringify(paid)).toBe(true);
        vi.setSystemTime(approved + 86_401_000);
        const missions = stack.kernel.allMissions().length;
        expect(await requestDispatch(stack, ceilingTemplate)).toMatchObject({
          status: 400,
          body: { error: "invalid_request", mission_denial_reason: "dispatch_prohibited_class" },
        });
        expect(stack.kernel.allMissions()).toHaveLength(missions);

        vi.setSystemTime(skewApproved - 60_000);
        await dispatchInstance(stack, skewTemplate);
        vi.setSystemTime(skewApproved - 61_000);
        expect(await requestDispatch(stack, skewTemplate)).toMatchObject({
          status: 400,
          body: { error: "invalid_request", mission_denial_reason: "dispatch_prohibited_class" },
        });
        expect(stack.kernel.allMissions()).toHaveLength(missions + 1);
      } finally {
        vi.useRealTimers();
      }
      expect(stack.kernel.standingPayments.dispatchedInstances(ceilingTemplate)).toHaveLength(2);
      expect(stack.kernel.standingPayments.dispatchedInstances(skewTemplate)).toHaveLength(2);
      expect(wires(stack)).toEqual([["inv-1", ACME_ACCOUNT, "125.00"]]);
    } finally {
      await closeStack(stack);
    }
  });

  it("retains a same-Mission idempotency claim across a restart of the shared composition on the same claim, reservation and kernel files: the restart empties the in-memory payments ledger, so the paid invoice is payable again, yet the instance's duplicate under the same key is refused duplicate_suppressed against the retained claim, and again one second before the instance's expires_at, past the published 604800 s idempotency horizon, with nothing wired and both counters unchanged (@spec metering#retry, #816, D907, D1143 ruling 3)", async () => {
    const files = newFiles(true);
    const key = `idem_${randomUUID()}`;
    let instance = "";
    const before = await compose(15138, files);
    try {
      // Eight days per instance, longer than the published horizon.
      const templateId = await consentTemplate(before, { perInstanceLifetimeS: 691_200 });
      instance = await dispatchInstance(before, templateId);
      const paid = await wire(before, instance, "inv-1", key);
      expect(paid.ok, JSON.stringify(paid)).toBe(true);
      expect(wires(before)).toEqual([["inv-1", ACME_ACCOUNT, "125.00"]]);
    } finally {
      await closeStack(before);
    }
    const after = await compose(15138, files);
    const committedOnce = { reserved: "0.00", held: "0.00", committed: "125.00" };
    const duplicateDenials = () =>
      commitDecisions(after, instance).filter((d) => d.decision === "deny").map((d) => d.denial_reason);
    try {
      // The separate invoice duplicate guard did not survive the restart.
      expect(after.payments.db.prepare("SELECT status FROM invoices WHERE id = 'inv-1'").get()).toEqual({ status: "payable" });
      expect(wires(after)).toEqual([]);
      expect(await wire(after, instance, "inv-1", key)).toEqual({ ok: false, denial_reason: "duplicate_suppressed" });
      expect(duplicateDenials()).toEqual(["duplicate_suppressed"]);
      const expiresAt = Date.parse(after.kernel.get(instance)?.expires_at as string);
      expect(expiresAt - approvedAtMs(after, instance)).toBeGreaterThan(604_800_000);
      vi.useFakeTimers({ toFake: ["Date"] });
      try {
        vi.setSystemTime(expiresAt - 1000);
        after.pdpClaims.sweep();
        expect(await wire(after, instance, "inv-1", key)).toEqual({ ok: false, denial_reason: "duplicate_suppressed" });
      } finally {
        vi.useRealTimers();
      }
      expect(duplicateDenials()).toEqual(["duplicate_suppressed", "duplicate_suppressed"]);
      expect(wires(after)).toEqual([]);
      expect(totals(after.pdpClaims.budgetCounter(SHARED))).toEqual(committedOnce);
      expect(totals(after.pdpClaims.budgetCounter(instanceCounter(after, instance)))).toEqual(committedOnce);
    } finally {
      await closeStack(after);
    }
  });

  it("never carries an existing template's consent over to a changed snapshot: with the shipped Dispatch Policy edited in place under its version, the template consented under the shipped snapshot is refused dispatch_policy_changed and creates nothing, its instance's payments stay under the consented terms, and only a fresh consent admits the edited snapshot (@spec approval-governance#activation-policy-commitment, mission-template#dispatch, #813, D1143 ruling 2)", async () => {
    const stack = await compose(15137, newFiles());
    try {
      const templateId = await consentTemplate(stack);
      const instance = await dispatchInstance(stack, templateId);
      expect(loaded).toHaveLength(1);
      const held = loaded[0]?.dispatch_policies[POLICY_ID] as { content: string };
      const consented = held.content;
      const edited = JSON.parse(consented) as { standing_payment: { destinations: Record<string, string> } };
      edited.standing_payment.destinations = { acme: "acct-acme-999" };
      held.content = JSON.stringify(edited);
      const missions = stack.kernel.allMissions().length;
      expect(await requestDispatch(stack, templateId)).toMatchObject({
        status: 403,
        body: { error: "access_denied", mission_denial_reason: "dispatch_policy_changed" },
      });
      expect(stack.kernel.allMissions()).toHaveLength(missions);
      // The instance dispatched under the consent keeps its retained snapshot:
      // it pays the consented account and nothing the edit names.
      seedInvoices(stack, [["inv-moved", "100.00", "acme", "acct-acme-999"]]);
      expect(await wire(stack, instance, "inv-moved")).toMatchObject({ ok: false, denial_reason: "parameter_violation" });
      const paid = await wire(stack, instance, "inv-1");
      expect(paid.ok, JSON.stringify(paid)).toBe(true);
      expect(wires(stack)).toEqual([["inv-1", ACME_ACCOUNT, "125.00"]]);
      // A fresh consent renders and commits the edited snapshot.
      const fresh = await propose(stack);
      expect(fresh.html).toContain("only to these committed destinations: acme to account acct-acme-999.");
      const decided = await fresh.decide();
      expect(decided.status, JSON.stringify(decided.body)).toBe(201);
      await dispatchInstance(stack, decided.body.template_id as string);
    } finally {
      await closeStack(stack);
    }
  });
});
