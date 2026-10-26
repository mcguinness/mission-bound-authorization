/**
 * @spec metering#aggregate-bounds, metering#settlement-states,
 * metering#metering-evidence (#816): exact budget exhaustion end to end
 * through this resource's real PEP, its D28 redemption store, its connectors
 * and its evidence store, over a co-resident decision point
 * (`createDecisionPoint`) whose claim domain claims `budget_metering`.
 *
 * The Mission view the PEP loads carries a budget binding, and the decision
 * point derives the same binding from its own source, as the composed stack
 * derives it from the authorization server's kernel; nothing in this file
 * enables the capability in any shipped configuration. The claim domain is a
 * real file in a fresh temporary directory, and the FGA layer is a stub that
 * always permits, so this file never skips.
 */

import { generateKeyPairSync, randomUUID } from "node:crypto";
import { canonicalDigest } from "@mission/core";
import {
  budgetCounterId,
  CLAIM_SETTLEMENT_INTAKE,
  createDecisionChannel,
  createDecisionPoint,
  type DecisionEvidenceObject,
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
import { describe, expect, it, vi } from "vitest";
import {
  CANONICAL_RESOURCE,
  Connectors,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  PaymentsStore,
  Pep,
  redemptionStatusFor,
  type PepDeps,
  type TokenFacts,
  TransactionEngine,
} from "../src/index.js";
import { ALL_ACTIONS_CREDENTIAL } from "./credential-fixtures.js";

const BASE_MS = Date.parse("2026-10-25T12:00:00.000Z");
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
const key = (): string => `idem_${randomUUID()}`;

const TOKEN: TokenFacts = {
  sub: "alice",
  clientId: "ap-agent",
  mission: { id: "msn_816", issuer: "https://as.test", authority_hash: "sha-256:m816" },
  cnfJkt: "jkt-816",
  credentialAuthority: ALL_ACTIONS_CREDENTIAL,
};

/** The shared standing_consent counter of the declared budget. */
const SHARED = budgetCounterId("standing_consent", { owner: "acme-treasury", budget_id: "vendor-payments-2026" });

/** The committed Dispatch Policy the budget was approved under. */
const DISPATCH_POLICY = { id: "dp_vendor_payments", version: "1", digest: canonicalDigest({ dispatch_policy: "v1" }) };

/** The shipped statement, claiming `budget_metering` for one standing-consent budget of 200.00 USD. */
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
        limit: "200.00",
        policies: [DISPATCH_POLICY],
      },
    ],
  };
  return statement;
}

/**
 * The binding the authorization server's kernel derives for `msn_816` (#813):
 * the PEP's loaded view carries it, and the decision point takes it from its
 * own source, never from the view the PEP supplies.
 */
const BINDING: MissionBudgetBinding = {
  owner: "acme-treasury",
  budget_id: "vendor-payments-2026",
  currency: "USD",
  limit: "200.00",
  policy: DISPATCH_POLICY,
  destinations: { acme: "acct-acme" },
  instance: { max_budget: { amount: "1000.00", currency: "USD" }, root_mission_id: "msn_816" },
};

const view = (bound = true): MissionView => ({
  id: "msn_816",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:m816",
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
  ...(bound ? { budget: BINDING } : {}),
});

async function harness(o: { bound?: boolean; observe?: PepDeps["observe"] } = {}) {
  const bound = o.bound ?? true;
  let nowMs = BASE_MS;
  const now = () => new Date(nowMs);
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [
      { id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
      { id: "inv-2", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
    ],
  );
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === "msn_816" && ref.issuer === "https://as.test"
      ? { view: view(bound), observation: { state: "active", version: 1, mode: "fresh", freshness_at: now().toISOString() } }
      : undefined;
  let pepKeys: EvidenceKeyResolver | undefined;
  const claims = openEphemeralClaimDomain({
    owner: RUNTIME_POSTURE.pdps[0] as string,
    statement: meteringStatement(),
    now,
    settlementKeys: (params) => pepKeys?.(params),
  });
  const pdpKey = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const point = createDecisionPoint({
    evidence: {
      signer: { kid: "pdp-816-e2e", key: pdpKey.privateKey },
      verificationKey: pdpKey.publicKey,
      emitterId: CANONICAL_RESOURCE,
      audience: CANONICAL_RESOURCE,
    },
    claims,
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
    budgetBindings: (m) => (bound && m.id === "msn_816" && m.issuer === "https://as.test" ? BINDING : undefined),
  });
  const keys = createEphemeralEvidenceKeys({ decisionPoint: point });
  pepKeys = keys.resolver;
  const engine = new TransactionEngine("epoch-816", now);
  const redemption = redemptionStatusFor(engine);
  const channel = await createDecisionChannel(point, {
    mode: "co-resident",
    pepId: "mcp-payments-pep",
    audience: CANONICAL_RESOURCE,
    pepEpoch: redemption.epoch,
    consumptionStatus: redemption.status,
    redeemingExecution: redemption.redeemer,
    getOptions: () => ({ view: view(bound), fga: alwaysAllowFga, modelId: "model-816", now, stalenessBound, relationForAction, stateSourcePlacement: "pep" as const }),
  });
  const evidence = new EvidenceStore(keys.signing, keys.resolver);
  const connectors = new Connectors(now);
  const pep = new Pep({
    decide: channel.decide,
    claims: channel.claims,
    payments,
    evidence,
    fga: alwaysAllowFga,
    modelId: "model-816",
    loadView,
    instanceEpoch: "epoch-816",
    now,
    ...(o.observe ? { observe: o.observe } : {}),
  });
  const server = new McpPaymentsServer({
    writeReservations: openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" }),
    pep,
    payments,
    loadView,
    jwks: { keys: [] },
    keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] },
    issuer: "https://as.test",
    transaction: { engine, connectors, evidence },
  });
  return {
    server,
    payments,
    claims,
    connectors,
    evidence,
    close: async () => {
      await channel.close();
      claims.close();
    },
  };
}

describe("exact budget exhaustion through the executing PEP (@spec metering#aggregate-bounds, #816)", () => {
  it("a completed wire commits its 125.00 against a 200.00 standing-consent budget, and the next 125.00 wire is denied quota_exceeded with nothing executed (@spec metering#aggregate-bounds, metering#metering-evidence, #816)", async () => {
    const h = await harness();
    const wire = (invoice: string) =>
      h.server.callTransactionTool("execute_wire_transfer", { invoice_id: invoice, idempotency_key: key() }, TOKEN);
    const first = await wire("inv-1");
    expect(first.ok, JSON.stringify(first)).toBe(true);
    const decisions = () =>
      h.evidence.all().flatMap((e) => (e.kind === "decision" ? [e.content as DecisionEvidenceObject] : []));
    const permitted = decisions().find((d) => d.decision === "permit");
    const permitEvaluation = String(permitted?.evaluation_id);
    // The redeeming attempt's Execution Evidence settled the reservation committed.
    expect(h.claims.reservationsFor(permitEvaluation).map((r) => r.state)).toEqual(["committed", "committed"]);
    const second = await wire("inv-2");
    expect(second.ok).toBe(false);
    expect(second.denial_reason).toBe("quota_exceeded");
    expect(h.connectors.ledgerEntries()).toHaveLength(1);
    const refused = decisions().find((d) => d.denial_reason === "quota_exceeded");
    expect(refused?.metering?.find((m) => m.counter_scope === "standing_consent")).toMatchObject({
      requested: { amount: "125.00", currency: "USD" },
      remaining: { amount: "75.00", currency: "USD" },
    });
    await h.close();
  });
});

describe("a budget-bound permit suppressed before redemption (@spec metering#settlement-states, #813, #816, decision e)", () => {
  it("the PEP sends its signed suppression of a budget-bound permit it refused before redeeming it, the reservation is released and nothing executes, while a suppressed permit with no budget binding sends nothing new (@spec metering#settlement-states, runtime#execution-reverification, #813, #816, decision e)", async () => {
    for (const bound of [true, false]) {
      // The invoice's payee changes between the decision and the permit's use.
      let payments: PaymentsStore | undefined;
      const h = await harness({
        bound,
        observe: ({ tool, decision }) => {
          if (tool === "execute_wire_transfer" && decision.decision) {
            payments?.db.prepare("UPDATE invoices SET payee_account = ? WHERE id = ?").run("acct-other", "inv-1");
          }
        },
      });
      payments = h.payments;
      const release = vi.spyOn(h.claims, "releaseUnredeemed");
      const settle = vi.spyOn(h.claims, "settle");
      const res = await h.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: key() }, TOKEN);
      expect(res, String(bound)).toEqual({ ok: false, refusal_reason: "target_drift" });
      expect(h.connectors.ledgerEntries()).toEqual([]);
      expect(settle).not.toHaveBeenCalled();
      const permit = h.evidence
        .all()
        .flatMap((e) => (e.kind === "decision" ? [e.content as DecisionEvidenceObject] : []))
        .find((d) => d.decision === "permit");
      const evaluationId = String(permit?.evaluation_id);
      if (bound) {
        expect(release).toHaveBeenCalledTimes(1);
        expect(await release.mock.results[0]?.value).toEqual({ accepted: true, released: 2 });
        expect(h.claims.reservationsFor(evaluationId).map((r) => r.state)).toEqual(["released", "released"]);
        expect(h.claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "0.00" }, committed: { amount: "0.00" } });
      } else {
        expect(release).not.toHaveBeenCalled();
        expect(h.claims.reservationsFor(evaluationId)).toEqual([]);
      }
      await h.close();
    }
  });
});
