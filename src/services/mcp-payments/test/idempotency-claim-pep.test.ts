/**
 * @spec runtime#idempotency (#917, owner ruling 2026-10-02): the PDP's
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
import { describe, expect, it, vi } from "vitest";
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
  newRecordId,
  openEphemeralClaimDomain,
  relationForAction,
  reversibleWriteKeyControl,
  RUNTIME_POSTURE,
  type SettlementResult,
  stalenessBound,
} from "@mission/pdp";
import {
  CANONICAL_RESOURCE,
  Connectors,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  operationKey,
  PaymentsStore,
  Pep,
  reconcile,
  reconcileClaims,
  recordRedeemingAttempt,
  redemptionStatusFor,
  type TokenFacts,
  TOOL_ACTIONS,
  TransactionEngine,
} from "../src/index.js";
import { ALL_ACTIONS_CREDENTIAL } from "./credential-fixtures.js";

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
  credentialAuthority: ALL_ACTIONS_CREDENTIAL,
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
      ? { view: view(), observation: { state: view().state, version: view().version, mode: "fresh", freshness_at: now().toISOString() } }
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
    redeemingExecution: redemption.redeemer,
    getOptions: () => ({
      view: view(),
      fga: alwaysAllowFga,
      modelId: "model-917",
      now,
      stalenessBound,
      relationForAction,
      stateSourcePlacement: "pep" as const,
    }),
  });
  const settlements: unknown[] = [];
  const settlementResults: SettlementResult[] = [];
  const claimChannel: ClaimChannel = {
    settle: async (record) => {
      settlements.push(record);
      const result: SettlementResult = o.holdSettlement ? { accepted: false, reason: "held" } : await channel.claims.settle(record);
      settlementResults.push(result);
      return result;
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
    now,
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
    pep,
    point,
    payments,
    engine,
    connectors,
    evidence,
    claims,
    channel: claimChannel,
    redemption,
    settlements,
    /** What the PDP answered to each live settlement. */
    settlementResults,
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

/**
 * #1016 review round 2: a committed wire whose completion evidence was lost,
 * and a replay of the same permit refused at admission after it expired. The
 * replay never redeemed the permit, so its `permit_expired` suppression says
 * nothing about the effect.
 */
async function committedWithLostEvidenceAndAReplay(h: Awaited<ReturnType<typeof harness>>, idempotencyKey: string) {
  const permit = await h.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: idempotencyKey }, TOKEN);
  const attempt = permit.attempt;
  if (!attempt) throw new Error("no permit");
  const evaluationId = String(permit.decision?.context.evaluation_id);
  const digest = String((permit.decision?.context.conditions as { parameter_digest: string }).parameter_digest);
  const opKey = operationKey("msn_917", "payments:payment.execute", digest, "commit");
  // The redeeming attempt: it took the single use (and the redemption store
  // recorded which attempt did) and the wire committed.
  expect(h.engine.redeemPermit({ permitId: evaluationId, opKey, missionId: "msn_917", action: "payments:payment.execute", leaseExpiresAtMs: BASE_MS + 30_000 }).ok).toBe(true);
  recordRedeemingAttempt(h.engine, evaluationId, attempt.executionId);
  h.connectors.postWire({ opKey, invoiceId: "inv-1", payeeAccount: "acct-acme", amount: "125.00", currency: "USD", permitId: evaluationId, missionId: "msn_917" });
  h.advance(PAST_LEASE_MS);
  // The replay: same permit, its own attempt, refused before any redemption.
  const replayExecutionId = newRecordId("exe");
  expect(await h.pep.suppressExecution({ ...attempt, executionId: replayExecutionId, redeemed: false }, "permit_expired")).toEqual({ recorded: true });
  return { evaluationId, replayExecutionId };
}

describe("reconciliation settles a failure only from the attempt that redeemed the permit (#1016)", () => {
  it("a committed wire with its completion evidence missing, beside a replay's permit_expired suppression, settles completed from the ledger, never failed", async () => {
    const h = await harness();
    const k = key();
    const { evaluationId } = await committedWithLostEvidenceAndAReplay(h, k);
    const report = await reconcileClaims({ claims: h.channel, evidence: h.evidence, redemption: h.redemption, connectors: h.connectors });
    expect(report.states).toEqual({ [evaluationId]: "completed" });
    expect(report.open).toEqual([]);
    expect((await wire(h, k)).denial_reason).toBe("duplicate_suppressed");
    expect(h.lastDecision()?.next_action).toBe("none");
    expect(h.connectors.ledgerEntries()).toHaveLength(1);
    await h.close();
  });

  it("offers the PDP no failed or suppressed record the redemption store does not link to the redeeming attempt, and consults the ledger first", async () => {
    const h = await harness();
    const { evaluationId, replayExecutionId } = await committedWithLostEvidenceAndAReplay(h, key());
    // A channel that would accept anything: what the reconciler offers is
    // then the only thing standing between the replay and a `failed` claim.
    const offered: Array<{ outcome: unknown; execution_id: unknown }> = [];
    const permissive: ClaimChannel = {
      settle: async () => ({ accepted: false, reason: "unused" }),
      listUnresolved: async () => [
        { evaluation_id: evaluationId, action_class: "irreversible_action", valid_until: "", window_closes_at: "" },
      ],
      reconcile: async (_id, resolution) => {
        const record = resolution.kind === "execution_evidence" ? (resolution.record as Record<string, unknown>) : {};
        offered.push({ outcome: record.outcome, execution_id: record.execution_id });
        return { accepted: true, state: record.outcome === "completed" ? "completed" : "failed", duplicate: false };
      },
    };
    const withoutLedger = await reconcileClaims({ claims: permissive, evidence: h.evidence, redemption: h.redemption });
    expect(withoutLedger.open).toEqual([evaluationId]);
    const withLedger = await reconcileClaims({ claims: permissive, evidence: h.evidence, redemption: h.redemption, connectors: h.connectors });
    expect(withLedger.states).toEqual({ [evaluationId]: "completed" });
    expect(offered.filter((o) => o.execution_id === replayExecutionId)).toEqual([]);
    expect(offered.every((o) => o.outcome === "completed")).toBe(true);
    await h.close();
  });

  it("a committed effect in the ledger takes precedence over the redeeming attempt's own failed or suppressed record", async () => {
    const h = await harness();
    const permit = await h.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: key() }, TOKEN);
    const attempt = permit.attempt;
    if (!attempt) throw new Error("no permit");
    const evaluationId = String(permit.decision?.context.evaluation_id);
    const digest = String((permit.decision?.context.conditions as { parameter_digest: string }).parameter_digest);
    const opKey = operationKey("msn_917", "payments:payment.execute", digest, "commit");
    expect(h.engine.redeemPermit({ permitId: evaluationId, opKey, missionId: "msn_917", action: "payments:payment.execute", leaseExpiresAtMs: BASE_MS + 30_000 }).ok).toBe(true);
    recordRedeemingAttempt(h.engine, evaluationId, attempt.executionId);
    // The redeeming attempt recorded a refusal, yet the connector holds the
    // effect (a commit that landed after the attempt gave up on it).
    expect(await h.pep.suppressExecution({ ...attempt, redeemed: false }, "permit_expired")).toEqual({ recorded: true });
    h.connectors.postWire({ opKey, invoiceId: "inv-1", payeeAccount: "acct-acme", amount: "125.00", currency: "USD", permitId: evaluationId, missionId: "msn_917" });
    h.advance(PAST_LEASE_MS);
    const offered: unknown[] = [];
    const permissive: ClaimChannel = {
      settle: async () => ({ accepted: false, reason: "unused" }),
      listUnresolved: async () => [
        { evaluation_id: evaluationId, action_class: "irreversible_action", valid_until: "", window_closes_at: "" },
      ],
      reconcile: async (_id, resolution) => {
        const record = resolution.kind === "execution_evidence" ? (resolution.record as Record<string, unknown>) : {};
        offered.push(record.outcome);
        return { accepted: true, state: record.outcome === "completed" ? "completed" : "failed", duplicate: false };
      },
    };
    const report = await reconcileClaims({ claims: permissive, evidence: h.evidence, redemption: h.redemption, connectors: h.connectors });
    expect(report.states).toEqual({ [evaluationId]: "completed" });
    expect(offered).toEqual(["completed"]);
    await h.close();
  });

  it("without ledger knowledge the claim stays unresolved, closes indeterminate at the window, and is never purged", async () => {
    const h = await harness();
    const k = key();
    const { evaluationId } = await committedWithLostEvidenceAndAReplay(h, k);
    const report = await reconcileClaims({ claims: h.channel, evidence: h.evidence, redemption: h.redemption });
    expect(report.open).toEqual([evaluationId]);
    expect(report.states).toEqual({});
    expect((await h.channel.listUnresolved()).map((u) => u.evaluation_id)).toEqual([evaluationId]);
    // Past the reconciliation window: indeterminate, terminal.
    h.advance(15 * 60_000);
    expect((await wire(h, k)).denial_reason).toBe("duplicate_suppressed");
    expect(h.lastDecision()?.next_action).toBe("none");
    expect(await h.channel.listUnresolved()).toEqual([]);
    // Far past the horizon: still refused, never fresh.
    h.advance(3 * 604_800_000);
    const late = await wire(h, k);
    expect(late.denial_reason).toBe("duplicate_suppressed");
    expect(h.lastDecision()?.next_action).toBe("none");
    expect(h.connectors.ledgerEntries()).toHaveLength(1);
    await h.close();
  });

  it("a genuine failure from the redeeming attempt still settles failed, live and through reconciliation", async () => {
    for (const holdSettlement of [false, true]) {
      const h = await harness({ holdSettlement });
      const k = key();
      // The parameters move after the permit and before the commit: the
      // redeeming attempt refuses itself, parameter_mismatch, with no effect.
      const refused = await h.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: k }, TOKEN, () =>
        h.payments.bumpInvoiceAmount("inv-1", "150.00"),
      );
      expect(refused.refusal_reason, String(holdSettlement)).toBe("parameter_mismatch");
      h.advance(PAST_LEASE_MS);
      if (holdSettlement) {
        const report = await reconcileClaims({ claims: h.channel, evidence: h.evidence, redemption: h.redemption, connectors: h.connectors });
        expect(Object.values(report.states)).toEqual(["failed"]);
      } else {
        expect(h.settlementResults).toEqual([{ accepted: true, state: "failed", duplicate: false }]);
      }
      // Settled, so not left unresolved once the permit and its lease elapsed.
      expect(await h.channel.listUnresolved()).toEqual([]);
      expect(h.connectors.ledgerEntries()).toHaveLength(0);
      await h.close();
    }
  });
});

describe("the Operation Profile defines an idempotency key for every non-idempotent high-consequence operation (@spec runtime#idempotency)", () => {
  it("every high-consequence tool's Operation Profile defines a key, and its served schema requires one in the published format", () => {
    const catalog = TRUSTED_TOOL_CATALOGS.find((c) => c.service_id === "payments");
    const tools = (JSON.parse(catalog?.text ?? "{}") as { tools: Array<{ name: string; inputSchema: { required?: string[]; properties: Record<string, unknown> } }> }).tools;
    // Every entry carries its class (#1015); the high-consequence ones are the keyed ones.
    const isHighConsequence = (actionClass: string) =>
      ["irreversible_action", "external_commitment", "privileged_administration"].includes(actionClass);
    const highConsequence = Object.entries(TOOL_ACTIONS).filter(([, mapping]) => isHighConsequence(mapping.actionClass));
    expect(highConsequence.map(([tool]) => tool).sort()).toEqual(["execute_wire_transfer", "send_remittance_email"]);
    for (const [tool, mapping] of highConsequence) {
      expect(mapping.idempotencyKey, tool).toBe(true);
      const definition = tools.find((t) => t.name === tool);
      expect(definition?.inputSchema.required, tool).toContain("idempotency_key");
      expect(definition?.inputSchema.properties.idempotency_key, tool).toEqual({ type: "string", pattern: IDEMPOTENCY_KEY_PATTERN.source });
    }
    // The key belongs to these operations, and to the reversible writes the
    // statement declares the idempotency-key control for (#918), whose key
    // the PEP reserves rather than the PDP claims: no other tool asks for one.
    for (const [tool, mapping] of Object.entries(TOOL_ACTIONS).filter(([, m]) => !isHighConsequence(m.actionClass))) {
      const elects = reversibleWriteKeyControl(RUNTIME_POSTURE, mapping.actionClass, mapping.action);
      expect(mapping.idempotencyKey, tool).toBe(elects ? true : undefined);
    }
  });

  // @spec operation-profile-payments-v1 (D316): the served schema requires
  // the key in the published format, so intake refuses a missing or malformed
  // one before any decision work.
  it("a keyed tool called without a key, or with a malformed one, is refused invalid_request at intake before any PDP call, and executes nothing", async () => {
    const h = await harness();
    for (const args of [{ invoice_id: "inv-1" }, { invoice_id: "inv-1", idempotency_key: "too-short" }]) {
      const refused = await h.server.callTransactionTool("execute_wire_transfer", args, TOKEN);
      expect(refused, JSON.stringify(args)).toEqual({ ok: false, refusal_reason: "invalid_request" });
    }
    expect(h.lastDecision()).toBeUndefined();
    expect(h.evidence.all().map((e) => [e.kind, (e.content as { denial_reason?: string }).denial_reason])).toEqual([
      ["refusal", "request_invalid"],
      ["refusal", "request_invalid"],
    ]);
    expect(h.connectors.ledgerEntries()).toHaveLength(0);
    await h.close();
  });

  // The PDP keeps its own key check (D316): a malformed key that reaches it
  // past the tool boundary is still refused.
  it("a malformed key handed to the PEP past intake is still refused parameter_violation by the PDP", async () => {
    const h = await harness();
    const res = await h.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: "too-short" }, TOKEN);
    expect(res.permitted).toBe(false);
    expect(res.denial_reason).toBe("parameter_violation");
    expect(h.lastDecision()?.denial_reason).toBe("parameter_violation");
    expect(h.connectors.ledgerEntries()).toHaveLength(0);
    await h.close();
  });
});

type Harness = Awaited<ReturnType<typeof harness>>;

/** The Execution Evidence the PEP's store retained, in order. */
const executions = (h: Harness) => h.evidence.all().flatMap((e) => (e.kind === "execution" ? [e.content] : []));

/** How many records of each signed kind the PEP's store retained. */
const retainedKinds = (h: Harness) => ({
  decision: h.evidence.all().filter((e) => e.kind === "decision").length,
  refusal: h.evidence.all().filter((e) => e.kind === "refusal").length,
  execution: executions(h).length,
});

/**
 * Fail the executor's `completed` write `times` times: either before anything
 * is retained, or after the record is retained (the write landed and its
 * acknowledgement was lost). The PEP's own `suppressed` writes pass through.
 */
function failCompletedWrite(h: Harness, mode: "before_retention" | "after_retention", times: number) {
  const original = h.evidence.recordExecution.bind(h.evidence);
  let left = times;
  return vi.spyOn(h.evidence, "recordExecution").mockImplementation(async (emitterId, role, input) => {
    if (role === "executor" && left > 0) {
      left -= 1;
      if (mode === "after_retention") await original(emitterId, role, input);
      throw new Error("completed write failed");
    }
    return original(emitterId, role, input);
  });
}

/**
 * @spec runtime-evidence#execution-evidence-object, runtime#idempotency
 * (#1104): every evidence emission failure on the transaction tier is one of
 * two cases, and each test keeps them apart. A refusal before any effect
 * leaves no effect, and its evidence is a Refusal Record, a suppressed
 * Execution Evidence, or a reported gap in either. Missing evidence after an
 * effect leaves the effect standing exactly once, reports the gap, and never
 * settles the claim as if nothing happened. No retry and no reconciliation
 * repeats the effect.
 */
describe("evidence emission failures: a refusal before any effect, or a reported gap after one (#1104)", () => {
  it("the PDP's Decision Evidence emitter throws: the claim is released, the PEP refuses pdp_unreachable, and nothing executes", async () => {
    for (const mode of ["co-resident", "remote"] as const) {
      const h = await harness({ mode });
      try {
        const k = key();
        const emit = vi.spyOn(h.point.emitter, "emit").mockRejectedValue(new Error("emitter unavailable"));
        const refused = await wire(h, k);
        expect(refused, mode).toEqual({ ok: false, refusal_reason: "pdp_unreachable" });
        expect(emit, mode).toHaveBeenCalled();
        // A refusal before any effect: no PDP record, the PEP's own Refusal Record.
        expect(h.connectors.ledgerEntries(), mode).toHaveLength(0);
        expect(retainedKinds(h), mode).toEqual({ decision: 0, refusal: 1, execution: 0 });
        expect(h.settlements, mode).toHaveLength(0);
        // Released: once the emitter recovers, the SAME key is adopted rather
        // than suppressed as an evaluation still in flight, and executes once.
        emit.mockRestore();
        const retried = await wire(h, k);
        expect(retried.ok, `${mode}: ${JSON.stringify(retried)}`).toBe(true);
        expect(h.connectors.ledgerEntries(), mode).toHaveLength(1);
        expect(
          executions(h).map((e) => e.outcome),
          mode,
        ).toEqual(["completed"]);
      } finally {
        await h.close();
      }
    }
  });

  it("a Refusal Record emission throws: the call rejects, nothing is recorded, and nothing executes", async () => {
    const h = await harness();
    try {
      const refusal = vi.spyOn(h.evidence, "recordRefusal").mockRejectedValue(new Error("refusal emission failed"));
      // Refused before any decision: the invoice does not resolve.
      await expect(
        h.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-missing", idempotency_key: key() }, TOKEN),
      ).rejects.toThrow(/refusal emission failed/);
      // Refused after the decision call failed: the emitter is down as well.
      const emit = vi.spyOn(h.point.emitter, "emit").mockRejectedValue(new Error("emitter unavailable"));
      await expect(
        h.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: key() }, TOKEN),
      ).rejects.toThrow(/refusal emission failed/);
      expect(refusal).toHaveBeenCalledTimes(2);
      expect(emit).toHaveBeenCalled();
      expect(h.connectors.ledgerEntries()).toHaveLength(0);
      expect(retainedKinds(h)).toEqual({ decision: 0, refusal: 0, execution: 0 });
    } finally {
      await h.close();
    }
  });

  it("suppressExecution returns effective_parameter_digest_unobservable when the permit's target no longer resolves, and retains nothing", async () => {
    const h = await harness();
    try {
      const permit = await h.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: key() }, TOKEN);
      const attempt = permit.attempt;
      if (!attempt) throw new Error("no permit");
      const record = vi.spyOn(h.evidence, "recordExecution");
      // Through the server: the invoice disappears between the permit and the
      // commit. Refused before any effect, with no record to retain.
      const refused = await h.server.callTransactionTool(
        "execute_wire_transfer",
        { invoice_id: "inv-1", idempotency_key: key() },
        TOKEN,
        () => h.payments.db.prepare("DELETE FROM invoices WHERE id = ?").run("inv-1"),
      );
      expect(refused).toEqual({ ok: false, refusal_reason: "parameter_mismatch" });
      expect(h.connectors.ledgerEntries()).toHaveLength(0);
      // The earlier permit's disposition, now that its target is gone.
      expect(await h.pep.suppressExecution(attempt, "parameter_mismatch")).toEqual({
        recorded: false,
        gap: "effective_parameter_digest_unobservable",
      });
      expect(record).not.toHaveBeenCalled();
      expect(executions(h)).toEqual([]);
      expect(h.settlements).toHaveLength(0);
    } finally {
      await h.close();
    }
  });

  it("suppressExecution retries once on the same execution identity, returns emission_failed after a second failure, and never retains a disposition twice", async () => {
    const h = await harness();
    try {
      const permit = await h.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: key() }, TOKEN);
      const attempt = permit.attempt;
      if (!attempt) throw new Error("no permit");
      const original = h.evidence.recordExecution.bind(h.evidence);
      const record = vi.spyOn(h.evidence, "recordExecution");
      const identities = () => record.mock.calls.map((call) => call[2].execution_id);

      // Both tries fail before retention: the gap, and nothing retained.
      record.mockRejectedValueOnce(new Error("emission failed")).mockRejectedValueOnce(new Error("emission failed"));
      expect(await h.pep.suppressExecution(attempt, "permit_expired")).toEqual({ recorded: false, gap: "emission_failed" });
      expect(identities()).toEqual([attempt.executionId, attempt.executionId]);
      expect(executions(h)).toEqual([]);

      // The write lands and its acknowledgement is lost: the retry returns
      // the retained record instead of retaining a second one.
      record.mockClear();
      record.mockImplementationOnce(async (emitterId, role, input) => {
        await original(emitterId, role, input);
        throw new Error("acknowledgement lost");
      });
      expect(await h.pep.suppressExecution(attempt, "permit_expired")).toEqual({ recorded: true });
      expect(identities()).toEqual([attempt.executionId, attempt.executionId]);
      expect(executions(h).map((e) => [e.execution_id, e.outcome, e.error])).toEqual([
        [attempt.executionId, "suppressed", "permit_expired"],
      ]);

      // A later delivery of the same disposition is still the one record.
      expect(await h.pep.suppressExecution(attempt, "permit_expired")).toEqual({ recorded: true });
      expect(executions(h)).toHaveLength(1);
      expect(h.connectors.ledgerEntries()).toHaveLength(0);
    } finally {
      await h.close();
    }
  });

  it("a completed write that fails once is retried on the same execution identity: one record, the claim settles completed, one effect", async () => {
    for (const mode of ["before_retention", "after_retention"] as const) {
      const h = await harness();
      try {
        const record = failCompletedWrite(h, mode, 1);
        const executed = await wire(h, key());
        expect(executed, mode).toMatchObject({ ok: true, deduped: false, result: { executed: true, invoice_id: "inv-1" } });
        expect(executed.gap, mode).toBeUndefined();
        const completedCalls = record.mock.calls.filter((call) => call[1] === "executor");
        expect(completedCalls, mode).toHaveLength(2);
        expect(completedCalls[0]?.[2].execution_id, mode).toBe(completedCalls[1]?.[2].execution_id);
        expect(
          executions(h).map((e) => [e.execution_id, e.outcome]),
          mode,
        ).toEqual([[completedCalls[0]?.[2].execution_id, "completed"]]);
        expect(h.settlementResults, mode).toEqual([{ accepted: true, state: "completed", duplicate: false }]);
        expect(h.connectors.ledgerEntries(), mode).toHaveLength(1);
        const opKey = (executed.result as { op_key: string }).op_key;
        expect(h.engine.state(opKey), mode).toBe("reconciled");
      } finally {
        await h.close();
      }
    }
  });

  it("a completed write that fails twice reports the gap: the effect stands once, the claim is not settled completed, and neither a retry nor reconciliation repeats the effect", async () => {
    const h = await harness();
    try {
      const k = key();
      const record = failCompletedWrite(h, "before_retention", 2);
      const first = await wire(h, k);
      // Missing evidence after an effect: not a refusal, and the effect is reported.
      expect(first).toMatchObject({
        ok: false,
        gap: "emission_failed",
        deduped: false,
        result: { executed: true, invoice_id: "inv-1" },
      });
      expect(first.refusal_reason).toBeUndefined();
      expect(first.denial_reason).toBeUndefined();
      const opKey = (first.result as { op_key: string }).op_key;
      const ledger = h.connectors.ledgerEntries();
      expect(ledger).toHaveLength(1);
      const evaluationId = String(ledger[0]?.permit_id);
      const completedCalls = record.mock.calls.filter((call) => call[1] === "executor");
      expect(completedCalls).toHaveLength(2);
      expect(completedCalls[0]?.[2].execution_id).toBe(completedCalls[1]?.[2].execution_id);
      // No record, no settlement, the operation left for reconciliation.
      expect(executions(h)).toEqual([]);
      expect(h.settlements).toHaveLength(0);
      expect(h.engine.state(opKey)).toBe("connector_committed");
      expect(reconcile("msn_917", h.evidence, h.connectors).ledgerWithoutEvidence).toEqual([opKey]);
      record.mockRestore();

      // The same request again: the claim is still held, so it is refused and executes nothing.
      const again = await wire(h, k);
      expect(again).toMatchObject({ ok: false, denial_reason: "duplicate_suppressed" });
      expect(h.connectors.ledgerEntries()).toHaveLength(1);
      // A new key for the same operation: refused at redemption, before any effect.
      const rekeyed = await wire(h, key());
      expect(rekeyed).toEqual({ ok: false, refusal_reason: "permit_consumed" });
      expect(h.connectors.ledgerEntries()).toHaveLength(1);
      expect(h.settlements).toHaveLength(0);

      // Past the lease the claim is unresolved, never completed, until
      // reconciliation settles it from the connector ledger: one completed
      // record, and still one effect.
      h.advance(PAST_LEASE_MS);
      expect((await h.channel.listUnresolved()).map((u) => u.evaluation_id)).toContain(evaluationId);
      const report = await reconcileClaims({
        claims: h.channel,
        evidence: h.evidence,
        redemption: h.redemption,
        connectors: h.connectors,
      });
      expect(report.states[evaluationId]).toBe("completed");
      expect(executions(h).filter((e) => e.evaluation_id === evaluationId).map((e) => e.outcome)).toEqual(["completed"]);
      expect(reconcile("msn_917", h.evidence, h.connectors).ledgerWithoutEvidence).toEqual([]);
      expect((await wire(h, k)).denial_reason).toBe("duplicate_suppressed");
      expect(h.lastDecision()?.next_action).toBe("none");
      expect(h.connectors.ledgerEntries()).toHaveLength(1);
    } finally {
      await h.close();
    }
  });
});
