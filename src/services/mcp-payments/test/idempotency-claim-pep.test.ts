/**
 * @spec runtime#idempotency (#917, owner ruling 2026-10-02) — the PDP's
 * Exact idempotency claim seen from the executing side, end to end through
 * this resource's real PEP, its real D28 redemption store, its connectors and
 * its evidence store.
 *
 * The PEP keeps redemption, the lease and the effect. The PDP is told: the
 * redeeming attempt's signed Execution Evidence settles the claim over the
 * decision channel, the declared reconciler resolves what never settled, and
 * a retransmission needs the redemption store's explicit `unconsumed`.
 *
 * Every claim domain here is a real file in a fresh temporary directory on a
 * clock the test drives; the FGA layer is a stub that always permits, so this
 * file never skips.
 */

import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { IDEMPOTENCY_KEY_PATTERN } from "@mission/core";
import { TRUSTED_TOOL_CATALOGS } from "@mission/demo-data";
import {
  type ClaimChannel,
  type ConsumptionStatusFn,
  createDecisionChannel,
  createEphemeralDecisionPoint,
  type DecisionFn,
  type EvidenceKeyResolver,
  type Fga,
  type MissionView,
  openEphemeralClaimDomain,
  relationForAction,
  RUNTIME_POSTURE,
  stalenessBound,
} from "@mission/pdp";
import {
  CANONICAL_RESOURCE,
  Connectors,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  McpPaymentsServer,
  operationKey,
  PaymentsStore,
  Pep,
  reconcileClaims,
  redemptionStatusFor,
  type TokenFacts,
  TOOL_ACTIONS,
  TransactionEngine,
} from "../src/index.js";

const BASE_MS = Date.parse("2026-10-02T12:00:00.000Z");
/** irreversible_action: the 30 s staleness bound caps the permit; the published lease is 30 s more. */
const PAST_LEASE_MS = 61_000;
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
const key = (): string => `idem_${randomUUID()}`;

const TOKEN: TokenFacts = {
  sub: "alice",
  clientId: "ap-agent",
  mission: { id: "msn_917", issuer: "https://as.test", authority_hash: "sha-256:m917" },
  cnfJkt: "jkt-917",
};

const view = (): MissionView => ({
  id: "msn_917",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:m917",
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

interface HarnessOptions {
  mode?: "co-resident" | "remote";
  /** Hold every settlement, as a lost or delayed acknowledgement does. */
  holdSettlement?: boolean;
  /** Replace the redemption store's answer (condition 6). */
  consumptionStatus?: (engineStatus: ConsumptionStatusFn) => ConsumptionStatusFn;
}

async function harness(o: HarnessOptions = {}) {
  let nowMs = BASE_MS;
  const now = () => new Date(nowMs);
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
  );
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === "msn_917" && ref.issuer === "https://as.test"
      ? { view: view(), freshness: { observed_at: now().toISOString(), source: "load_view" } }
      : undefined;

  // The PDP side: its own claim domain on its own file, verifying settlement
  // against the enforcement keys the bundle below generates.
  let pepKeys: EvidenceKeyResolver | undefined;
  const claims = openEphemeralClaimDomain({
    owner: RUNTIME_POSTURE.pdps[0] as string,
    statement: RUNTIME_POSTURE,
    now,
    settlementKeys: (params) => pepKeys?.(params),
  });
  const point = createEphemeralDecisionPoint({ emitterId: CANONICAL_RESOURCE, audience: CANONICAL_RESOURCE, claims });
  const keys = createEphemeralEvidenceKeys({ decisionPoint: point });
  pepKeys = keys.resolver;

  // The PEP side: D28 redemption, and its read-only status for condition 6.
  const engine = new TransactionEngine("epoch-917", now);
  const redemption = redemptionStatusFor(engine);
  const status = o.consumptionStatus ? o.consumptionStatus(redemption.status) : redemption.status;
  const channel = await createDecisionChannel(point, {
    mode: o.mode ?? "co-resident",
    pepId: "mcp-payments-pep",
    audience: CANONICAL_RESOURCE,
    pepEpoch: redemption.epoch,
    consumptionStatus: status,
    getOptions: () => ({
      view: view(),
      fga: alwaysAllowFga,
      modelId: "model-917",
      now,
      stalenessBound,
      relationForAction,
      allowedFreshnessSources: new Set(["load_view"]),
    }),
  });
  const settlements: unknown[] = [];
  const claimChannel: ClaimChannel = {
    settle: async (record) => {
      settlements.push(record);
      return o.holdSettlement ? { accepted: false, reason: "held" } : channel.claims.settle(record);
    },
    listUnresolved: () => channel.claims.listUnresolved(),
    reconcile: (id, resolution) => channel.claims.reconcile(id, resolution),
  };
  const evidence = new EvidenceStore(keys.signing, keys.resolver);
  const connectors = new Connectors(now);
  const decide: DecisionFn = channel.decide;
  let lastDecision: Record<string, unknown> | undefined;
  const pep = new Pep({
    decide,
    claims: claimChannel,
    observe: ({ decision }) => {
      lastDecision = decision.context;
    },
    payments,
    evidence,
    fga: alwaysAllowFga,
    modelId: "model-917",
    loadView,
    instanceEpoch: "epoch-917",
    allowedFreshnessSources: new Set(["load_view"]),
    now,
  });
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
    jwks: { keys: [] },
    issuer: "https://as.test",
    transaction: { engine, connectors, evidence },
  });
  return {
    server,
    pep,
    engine,
    connectors,
    evidence,
    claims,
    channel: claimChannel,
    redemption,
    settlements,
    /** The raw decision context the PEP last received (`next_action` and `retry_after` included). */
    lastDecision: () => lastDecision,
    advance: (ms: number) => {
      nowMs += ms;
    },
    close: async () => {
      await channel.close();
      claims.close();
    },
  };
}

const wire = (h: Awaited<ReturnType<typeof harness>>, idempotencyKey: string) =>
  h.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: idempotencyKey }, TOKEN);

describe("the PDP idempotency claim through the executing PEP (@spec runtime#idempotency, #917)", () => {
  it("returns the prior permit while the redemption store answers unconsumed, and refuses it once the permit is redeemed and its settlement is held", async () => {
    const h = await harness({ holdSettlement: true });
    const k = key();
    // A permit whose response the agent never acted on: obtained, not redeemed.
    const first = await h.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: k }, TOKEN);
    expect(first.permitted, JSON.stringify(first)).toBe(true);
    const evaluationId = first.decision?.context.evaluation_id;
    // The retry gets the SAME permit back: the store answers unconsumed.
    const retried = await h.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: k }, TOKEN);
    expect(retried.permitted, JSON.stringify(retried)).toBe(true);
    expect(retried.decision?.context.evaluation_id).toBe(evaluationId);
    // The wire now runs under that permit: redeemed and committed, with the
    // settlement held back.
    const executed = await wire(h, k);
    expect(executed.ok, JSON.stringify(executed)).toBe(true);
    expect(h.settlements).toHaveLength(1);
    // Retried again before settlement arrives: conditions 1 to 5 still hold,
    // and only the store's `consumed` keeps the copy from being returned.
    const afterRedemption = await wire(h, k);
    expect(afterRedemption.ok).toBe(false);
    expect(afterRedemption.denial_reason).toBe("duplicate_suppressed");
    expect(h.connectors.ledgerEntries()).toHaveLength(1);
    await h.close();
  });

  it("refuses the retry when the redemption store cannot answer, or answers for another epoch", async () => {
    for (const [label, replace] of [
      ["a failing status query", () => () => { throw new Error("redemption store unreachable"); }],
      ["another epoch", (engineStatus: ConsumptionStatusFn) => (id: string) => engineStatus(id, "an-earlier-epoch")],
    ] as Array<[string, (s: ConsumptionStatusFn) => ConsumptionStatusFn]>) {
      const h = await harness({ consumptionStatus: replace });
      const k = key();
      const first = await h.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: k }, TOKEN);
      expect(first.permitted, label).toBe(true);
      const retried = await h.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: k }, TOKEN);
      expect(retried.permitted, label).toBe(false);
      expect(retried.denial_reason, label).toBe("duplicate_suppressed");
      await h.close();
    }
  });

  for (const mode of ["co-resident", "remote"] as const) {
    it(`a completed wire settles its claim over the ${mode} channel: the same key is refused as completed and executes once`, async () => {
      const h = await harness({ mode });
      const k = key();
      const executed = await wire(h, k);
      expect(executed.ok, JSON.stringify(executed)).toBe(true);
      const again = await wire(h, k);
      expect(again.ok).toBe(false);
      expect(again.denial_reason).toBe("duplicate_suppressed");
      // Terminal, because the settlement arrived: completed, not unresolved.
      expect(h.lastDecision()?.next_action).toBe("none");
      const decision = h.evidence.all().filter((e) => e.kind === "decision").pop();
      expect(decision?.kind === "decision" ? decision.content.denial_reason : undefined).toBe("duplicate_suppressed");
      expect(h.connectors.ledgerEntries()).toHaveLength(1);
      expect(await h.channel.listUnresolved()).toEqual([]);
      await h.close();
    });
  }

  for (const mode of ["co-resident", "remote"] as const) {
    it(`an unreachable claim domain over the ${mode} channel: the PEP records pdp_unreachable and nothing executes`, async () => {
      const h = await harness({ mode });
      h.claims.close();
      const refused = await wire(h, key());
      expect(refused.ok).toBe(false);
      expect(refused.refusal_reason).toBe("pdp_unreachable");
      expect(h.connectors.ledgerEntries()).toHaveLength(0);
      expect(h.evidence.all().filter((e) => e.kind === "decision")).toHaveLength(0);
      expect(h.evidence.all().filter((e) => e.kind === "refusal")).toHaveLength(1);
      await h.close();
    });
  }

  it("reconciliation settles a claim whose settlement never arrived, from the attempt's retained evidence", async () => {
    const h = await harness({ holdSettlement: true });
    const k = key();
    expect((await wire(h, k)).ok).toBe(true);
    h.advance(PAST_LEASE_MS);
    const report = await reconcileClaims({ claims: h.channel, evidence: h.evidence, redemption: h.redemption, connectors: h.connectors });
    expect(report.settled).toHaveLength(1);
    expect(report.open).toEqual([]);
    // Settled from the record the attempt already signed: nothing new was emitted.
    expect(h.evidence.all().filter((e) => e.kind === "execution")).toHaveLength(1);
    const again = await wire(h, k);
    expect(again.denial_reason).toBe("duplicate_suppressed");
    expect(h.lastDecision()?.next_action).toBe("none");
    expect(h.connectors.ledgerEntries()).toHaveLength(1);
    await h.close();
  });

  it("reconciliation proves a permit that was never redeemed failed, within its epoch", async () => {
    const h = await harness();
    const k = key();
    const permit = await h.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: k }, TOKEN);
    expect(permit.permitted).toBe(true);
    h.advance(PAST_LEASE_MS);
    const report = await reconcileClaims({ claims: h.channel, evidence: h.evidence, redemption: h.redemption, connectors: h.connectors });
    expect(report.unredeemed).toEqual([permit.decision?.context.evaluation_id]);
    // Failed is terminal for the key: a retry needs a new key.
    const retry = await wire(h, k);
    expect(retry.denial_reason).toBe("duplicate_suppressed");
    expect(h.connectors.ledgerEntries()).toHaveLength(0);
    expect((await wire(h, key())).ok).toBe(true);
    await h.close();
  });

  it("reconciliation settles a committed effect whose evidence never arrived, from the connector ledger", async () => {
    const h = await harness();
    const k = key();
    const permit = await h.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: k }, TOKEN);
    const evaluationId = String(permit.decision?.context.evaluation_id);
    const digest = String((permit.decision?.context.conditions as { parameter_digest: string }).parameter_digest);
    // The redemption and the connector commit happened; the process lost the
    // Execution Evidence before it was recorded.
    const opKey = operationKey("msn_917", "payments:payment.execute", digest, "commit");
    expect(h.engine.redeemPermit({ permitId: evaluationId, opKey, missionId: "msn_917", action: "payments:payment.execute", leaseExpiresAtMs: BASE_MS + 30_000 }).ok).toBe(true);
    h.connectors.postWire({ opKey, invoiceId: "inv-1", payeeAccount: "acct-acme", amount: "125.00", currency: "USD", permitId: evaluationId, missionId: "msn_917" });
    h.advance(PAST_LEASE_MS);
    const report = await reconcileClaims({ claims: h.channel, evidence: h.evidence, redemption: h.redemption, connectors: h.connectors });
    expect(report.settled).toEqual([evaluationId]);
    expect(h.evidence.all().filter((e) => e.kind === "execution" && e.content.evaluation_id === evaluationId)).toHaveLength(1);
    expect((await wire(h, k)).denial_reason).toBe("duplicate_suppressed");
    expect(h.connectors.ledgerEntries()).toHaveLength(1);
    await h.close();
  });
});

describe("the Operation Profile defines an idempotency key for every non-idempotent high-consequence operation (@spec runtime#idempotency)", () => {
  it("every high-consequence tool's Operation Profile defines a key, and its served schema requires one in the published format", () => {
    const catalog = TRUSTED_TOOL_CATALOGS.find((c) => c.service_id === "payments");
    const tools = (JSON.parse(catalog?.text ?? "{}") as { tools: Array<{ name: string; inputSchema: { required?: string[]; properties: Record<string, unknown> } }> }).tools;
    const highConsequence = Object.entries(TOOL_ACTIONS).filter(([, mapping]) => mapping.actionClass !== undefined);
    expect(highConsequence.map(([tool]) => tool).sort()).toEqual(["execute_wire_transfer", "send_remittance_email"]);
    for (const [tool, mapping] of highConsequence) {
      expect(mapping.idempotencyKey, tool).toBe(true);
      const definition = tools.find((t) => t.name === tool);
      expect(definition?.inputSchema.required, tool).toContain("idempotency_key");
      expect(definition?.inputSchema.properties.idempotency_key, tool).toEqual({ type: "string", pattern: IDEMPOTENCY_KEY_PATTERN.source });
    }
    // The key belongs to these operations only: no other tool asks for one.
    for (const [tool, mapping] of Object.entries(TOOL_ACTIONS).filter(([, m]) => m.actionClass === undefined)) {
      expect(mapping.idempotencyKey, tool).toBeUndefined();
    }
  });

  it("a keyed tool called without a key is refused by the PDP and executes nothing", async () => {
    const h = await harness();
    const keyless = await h.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1" }, TOKEN);
    expect(keyless.ok).toBe(false);
    expect(keyless.denial_reason).toBe("parameter_violation");
    expect(h.connectors.ledgerEntries()).toHaveLength(0);
    await h.close();
  });
});
