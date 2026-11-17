/**
 * @spec authzen#speculative-evaluations (#2067, D1313): a speculative
 * evaluation is not an attempt, and its guarantees hold through every
 * component downstream of the PDP. Each store is read at the component that
 * owns it, before and after a speculation: the PEP's consumed-identifier
 * stores (the write path's `WriteReservationStore` and the wire path's
 * `TransactionEngine`), the claim domain's budget counters and reservations,
 * the PDP's durable Decision Evidence sequence (the next real decision's
 * `sequence` shows it), and the evidence the PEP retains, which history
 * reads. A speculative result presented to the PEP for execution is refused
 * before any attempt and consumes nothing.
 *
 * The stack is this resource's real PEP over a co-resident decision point
 * whose claim domain meters a standing-consent budget (as in
 * budget-exhaustion.test.ts) and whose Decision Evidence sequence is the
 * claim domain's durable one. Every store is ephemeral, the FGA layer is a
 * stub that always permits, and the clock is controlled, so this file never
 * skips.
 */

import { generateKeyPairSync, randomUUID } from "node:crypto";
import { canonicalDigest } from "@mission/core";
import {
  budgetCounterId,
  CLAIM_SETTLEMENT_INTAKE,
  createDecisionChannel,
  createDecisionPoint,
  type Decision,
  type DecisionEvidenceObject,
  type DecisionOptions,
  type EnforcementScopeStatement,
  type EvaluationRequest,
  type EvidenceKeyResolver,
  type Fga,
  type MissionBudgetBinding,
  type MissionView,
  openEphemeralClaimDomain,
  RUNTIME_POSTURE,
  relationForAction,
  type SpeculativeEvaluationItem,
  stalenessBound,
} from "@mission/pdp";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
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
  type TokenFacts,
  TransactionEngine,
} from "../src/index.js";
import { ALL_ACTIONS_CREDENTIAL } from "./credential-fixtures.js";
import { pinnedToCurrentContract } from "@mission/demo-data";

// date-literal: controlled-clock
const CLOCK_MS = Date.parse("2026-11-16T12:00:00.000Z");
const MISSION = "msn_2067_spec";
const ISSUER = "https://as.test";
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
const key = (): string => `idem_${randomUUID()}`;

const TOKEN: TokenFacts = {
  sub: "alice",
  clientId: "ap-agent",
  mission: { id: MISSION, issuer: ISSUER, authority_hash: "sha-256:m2067" },
  cnfJkt: "jkt-2067",
  credentialAuthority: ALL_ACTIONS_CREDENTIAL,
};

const DISPATCH_POLICY = { id: "dp_vendor_payments", version: "1", digest: canonicalDigest({ dispatch_policy: "v1" }) };
const SHARED = budgetCounterId("standing_consent", { owner: "acme-treasury", budget_id: "vendor-payments-2026" });
const INSTANCE = budgetCounterId("mission", { issuer: ISSUER, mission_id: MISSION });

/** The shipped statement, claiming `budget_metering` for one standing-consent budget of 1000.00 USD. */
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

const VIEW: MissionView = {
  id: MISSION,
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:m2067",
  authority_set: [
    pinnedToCurrentContract({
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:payment.execute"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    }),
  ],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
  budget: BINDING,
};

async function harness() {
  const now = () => new Date();
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    ["inv-1", "inv-2", "inv-3"].map((id) => ({
      id,
      vendor_id: "acme",
      amount: "125.00",
      currency: "USD",
      payee_account: "acct-acme",
      status: "payable",
    })),
  );
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === MISSION && ref.issuer === ISSUER
      ? { view: VIEW, observation: { state: "active", version: 1, mode: "fresh", freshness_at: now().toISOString() } }
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
      signer: { kid: "pdp-2067-spec", key: pdpKey.privateKey },
      verificationKey: pdpKey.publicKey,
      emitterId: CANONICAL_RESOURCE,
      audience: CANONICAL_RESOURCE,
      // The durable, producer-owned sequence: a gap in it makes history fail closed.
      sequences: claims.evidenceSequences(),
    },
    claims,
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
    budgetBindings: (m) => (m.id === MISSION && m.issuer === ISSUER ? BINDING : undefined),
    speculativeEvaluations: true,
  });
  const speculate = point.speculate;
  if (!speculate) throw new Error("the decision point was built with the feature");
  const keys = createEphemeralEvidenceKeys({ decisionPoint: point });
  pepKeys = keys.resolver;
  const engine = new TransactionEngine("epoch-2067", now);
  const redemption = redemptionStatusFor(engine);
  const decisionOptions = (): DecisionOptions => ({
    view: VIEW,
    fga: alwaysAllowFga,
    modelId: "model-2067",
    now,
    stalenessBound,
    relationForAction,
    stateSourcePlacement: "pep" as const,
  });
  const channel = await createDecisionChannel(point, {
    mode: "co-resident",
    pepId: "mcp-payments-pep",
    audience: CANONICAL_RESOURCE,
    pepEpoch: redemption.epoch,
    consumptionStatus: redemption.status,
    redeemingExecution: redemption.redeemer,
    getOptions: decisionOptions,
  });
  const evidence = new EvidenceStore(keys.signing, keys.resolver);
  const connectors = new Connectors(now);
  const writeStore = openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" });
  const envelopes = new Map<string, EvaluationRequest>();
  /** When set, the PEP is handed this speculative preview in place of a decision. */
  let presentSpeculative = false;
  const pep = new Pep({
    decide: async (req, opts) => {
      if (!presentSpeculative) return channel.decide(req, opts);
      const { mission, ...context } = req.context;
      const previews = await speculate(
        { context: { mission }, items: [{ id: "presented", subject: req.subject, resource: req.resource, action: req.action, context }] },
        opts,
      );
      return previews.items[0] as unknown as Decision;
    },
    claims: channel.claims,
    payments,
    evidence,
    fga: alwaysAllowFga,
    modelId: "model-2067",
    loadView,
    instanceEpoch: "epoch-2067",
    now,
    observe: ({ tool, envelope }) => {
      envelopes.set(tool, envelope);
    },
  });
  const server = new McpPaymentsServer({
    writeReservations: writeStore,
    pep,
    payments,
    loadView,
    jwks: { keys: [] },
    keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] },
    issuer: ISSUER,
    transaction: { engine, connectors, evidence },
  });

  const decisions = () =>
    evidence.forMission(MISSION).flatMap((e) => (e.kind === "decision" ? [e.content as DecisionEvidenceObject] : []));
  /** Every store a speculation must leave unchanged, read at the component that owns it. */
  const stores = () => ({
    consumedWrites: writeStore.consumedPermits(),
    redeemedWires: engine.db.prepare("SELECT * FROM permit_redemptions ORDER BY 1").all(),
    wireOperations: engine.db.prepare("SELECT * FROM operations ORDER BY op_key").all(),
    sharedCounter: claims.budgetCounter(SHARED),
    instanceCounter: claims.budgetCounter(INSTANCE),
    heldReservations: claims.listHeldReservations(),
    reservations: decisions().flatMap((d) => claims.reservationsFor(String(d.evaluation_id))),
    retained: evidence.forMission(MISSION).map((e) => [e.kind, (e.content as { sequence?: number }).sequence]),
    ledger: connectors.ledgerEntries(),
  });
  /** A captured request as a speculative item: the shared context carries the Mission, the item the rest. */
  const itemOf = (id: string, envelope: EvaluationRequest | undefined, over: Partial<EvaluationRequest["action"]["properties"]> = {}) => {
    if (!envelope) throw new Error(`no captured envelope for ${id}`);
    const { mission: _mission, ...context } = envelope.context;
    return {
      id,
      subject: envelope.subject,
      resource: envelope.resource,
      action: { ...envelope.action, properties: { ...envelope.action.properties, ...over } },
      context,
    } as SpeculativeEvaluationItem;
  };

  return {
    server,
    claims,
    evidence,
    writeStore,
    stores,
    decisions,
    envelopes,
    itemOf,
    speculate: (items: SpeculativeEvaluationItem[]) =>
      speculate({ context: { mission: { id: MISSION, issuer: ISSUER, authority_hash: "sha-256:m2067" } }, items }, decisionOptions()),
    presentSpeculative: (on: boolean) => {
      presentSpeculative = on;
    },
    hold: (invoice: string) => server.callWriteTool("hold_transfer", { invoice_id: invoice }, TOKEN),
    wire: (invoice: string) => server.callTransactionTool("execute_wire_transfer", { invoice_id: invoice, idempotency_key: key() }, TOKEN),
    close: async () => {
      await channel.close();
      claims.close();
      writeStore.close();
    },
  };
}

beforeAll(() => {
  vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
  vi.setSystemTime(CLOCK_MS);
});

afterAll(() => {
  vi.useRealTimers();
});

describe("a speculative evaluation is not an attempt, through every downstream component (@spec authzen#speculative-evaluations, #2067)", () => {
  it("a speculation over a metered wire and a single-use hold leaves the consumed-identifier stores, the budget counters and reservations, the Decision Evidence sequence and the retained evidence unchanged", async () => {
    const h = await harness();
    // Real attempts first: a single-use hold consumed at the PEP, and a wire
    // that reserves and commits 125.00 on both counters.
    expect(await h.hold("inv-1"), "hold").toMatchObject({ ok: true });
    expect(await h.wire("inv-1"), "wire").toMatchObject({ ok: true });
    const before = h.stores();
    expect(before.consumedWrites).toHaveLength(1);
    expect(before.sharedCounter).toMatchObject({ committed: { amount: "125.00" } });
    const sequences = h.decisions().map((d) => d.sequence);
    expect(sequences).toEqual(sequences.map((_, i) => i));

    // The speculation: the same wire under a fresh key, which an evaluation
    // would claim and charge, and the same single-use hold.
    const { items } = await h.speculate([
      h.itemOf("wire", h.envelopes.get("execute_wire_transfer"), { idempotency_key: key() }),
      h.itemOf("hold", h.envelopes.get("hold_transfer")),
    ]);
    expect(items.map((i) => [i.id, i.decision]), JSON.stringify(items)).toEqual([
      ["wire", true],
      ["hold", true],
    ]);
    for (const item of items) {
      expect(Object.keys(item.context), item.id).toEqual(["prospective_conditions"]);
      expect((item.context.prospective_conditions as { use_limit?: number }).use_limit, item.id).toBe(1);
    }

    // Every store reads exactly as before, at the component that owns it.
    expect(h.stores()).toEqual(before);

    // The next real decision continues the Mission's Decision Evidence
    // stream with no gap, and an evaluation of the same wire does charge.
    expect(await h.wire("inv-2"), "next wire").toMatchObject({ ok: true });
    const after = h.decisions().map((d) => d.sequence);
    expect(after.slice(0, sequences.length)).toEqual(sequences);
    expect(after.slice(sequences.length)).toEqual([sequences.length]);
    expect(h.claims.budgetCounter(SHARED)).toMatchObject({ committed: { amount: "250.00" } });
    await h.close();
  });

  it("a speculative result presented to the PEP for execution is refused decision_evidence_unverifiable before any attempt, and consumes nothing", async () => {
    const h = await harness();
    expect(await h.hold("inv-1"), "hold").toMatchObject({ ok: true });
    const before = h.stores();

    h.presentSpeculative(true);
    const hold = await h.hold("inv-2");
    const wire = await h.wire("inv-2");
    h.presentSpeculative(false);
    expect(hold, JSON.stringify(hold)).toEqual({ ok: false, refusal_reason: "decision_evidence_unverifiable" });
    expect(wire, JSON.stringify(wire)).toMatchObject({ ok: false, refusal_reason: "decision_evidence_unverifiable" });

    // Nothing consumed, charged or executed; the PEP recorded only its two
    // refusals, and no attempt (no Execution Evidence).
    const after = h.stores();
    expect(after.consumedWrites).toEqual(before.consumedWrites);
    expect(after.redeemedWires).toEqual(before.redeemedWires);
    expect(after.wireOperations).toEqual(before.wireOperations);
    expect(after.sharedCounter).toEqual(before.sharedCounter);
    expect(after.ledger).toEqual(before.ledger);
    const added = h.evidence.forMission(MISSION).slice(before.retained.length);
    expect(added.map((e) => [e.kind, (e.content as { denial_reason?: string }).denial_reason])).toEqual([
      ["refusal", "decision_evidence_unverifiable"],
      ["refusal", "decision_evidence_unverifiable"],
    ]);
    await h.close();
  });
});
