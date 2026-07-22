/**
 * M5 transaction-assurance tier, scenario 4 end to end: single-use permit,
 * execution lease, Execution Evidence, outcome reconciliation. Plus permit
 * replay refusal and the TOCTOU-in-the-commit-window refusal. In-process,
 * live OpenFGA, auto-skip when down.
 */

import { beforeAll, describe, expect, it } from "vitest";
import { Fga, type MissionView } from "@mission/pdp";
import {
  CANONICAL_RESOURCE,
  Connectors,
  EvidenceStore,
  McpPaymentsServer,
  PaymentsStore,
  Pep,
  reconcile,
  sourceDigestOf,
  type TokenFacts,
  TransactionEngine,
} from "../src/index.js";

const API_URL = process.env.OPENFGA_HTTP_URL ?? "https://localhost:8080";
const KEY = process.env.OPENFGA_PRESHARED_KEY ?? "dev-preshared-key-change-me";
const CA = process.env.OPENFGA_CA_CERT;

async function reachable(): Promise<boolean> {
  try {
    if (CA) process.env.NODE_EXTRA_CA_CERTS = CA;
    return (await fetch(`${API_URL}/healthz`, { headers: { authorization: `Bearer ${KEY}` } })).ok;
  } catch {
    return false;
  }
}
const up = await reachable();
const d = up ? describe : describe.skip;
if (!up) console.warn("OpenFGA unreachable; skipping M5 transaction tests");

const VIEW: MissionView = {
  id: "msn_m5",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:m5hash",
  authority_set: [
    {
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:payment.execute", "payments:remittance.send"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    },
  ],
};
const TOKEN: TokenFacts = {
  sub: "alice",
  clientId: "ap-agent",
  clientInstanceId: "inst-1",
  mission: { id: "msn_m5", authority_hash: "sha-256:m5hash" },
  cnfJkt: "jkt-1",
};

let fga: Fga;
let modelId: string;

function build() {
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
  );
  const evidence = new EvidenceStore();
  const connectors = new Connectors();
  const engine = new TransactionEngine("epoch-1");
  const card = { name: "payments" };
  const pep = new Pep({
    payments,
    evidence,
    fga,
    modelId,
    loadView: (id) => (id === VIEW.id ? VIEW : undefined),
    instanceEpoch: "epoch-1",
    sourceDigest: sourceDigestOf(card),
  });
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView: (id) => (id === VIEW.id ? VIEW : undefined),
    jwks: { keys: [] },
    issuer: "https://as.test",
    serverCard: card,
    transaction: { engine, connectors, evidence },
  });
  return { payments, evidence, connectors, engine, server };
}

d("M5 transaction-assurance tier", () => {
  beforeAll(async () => {
    const conn = await Fga.connect({ apiUrl: API_URL, presharedKey: KEY, caCertPath: CA });
    fga = conn.fga;
    modelId = conn.modelId;
  });

  it("scenario 4: wire transfer executes once with permit, evidence, and reconciliation", async () => {
    const { server, evidence, connectors, engine } = build();
    const res = await server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1" }, TOKEN);
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect((res.result as { executed: boolean }).executed).toBe(true);

    // Operation reached the terminal reconciled state.
    const opKey = (res.result as { op_key: string }).op_key;
    expect(engine.state(opKey)).toBe("reconciled");

    // Execution Evidence + ledger entry both exist.
    const ev = evidence.forMission("msn_m5");
    expect(ev.some((e) => e.kind === "decision" && e.decision === true)).toBe(true);
    expect(ev.some((e) => e.kind === "execution" && e.outcome === "committed")).toBe(true);
    expect(connectors.ledgerEntries("msn_m5")).toHaveLength(1);

    // Reconciliation joins evidence to the ledger with no anomalies.
    const report = reconcile("msn_m5", evidence, connectors);
    expect(report.ok).toBe(true);
    expect(report.matched).toHaveLength(1);
    expect(report.ledgerWithoutEvidence).toEqual([]);
    expect(report.evidenceWithoutLedger).toEqual([]);
  });

  it("replayed permit is refused as permit_consumed and does not double-execute", async () => {
    const { server, connectors } = build();
    const first = await server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1" }, TOKEN);
    expect(first.ok).toBe(true);
    // Same effective params -> same permit id/op key -> single-use redemption fails.
    const replay = await server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1" }, TOKEN);
    expect(replay.ok).toBe(false);
    expect(replay.refusal_reason).toBe("permit_consumed");
    // Exactly one ledger entry: no double spend.
    expect(connectors.ledgerEntries("msn_m5")).toHaveLength(1);
  });

  it("TOCTOU in the decision->commit window refuses before the connector commits", async () => {
    const { server, payments, connectors } = build();
    const res = await server.callTransactionTool(
      "execute_wire_transfer",
      { invoice_id: "inv-1" },
      TOKEN,
      () => payments.bumpInvoiceAmount("inv-1", "480.00"),
    );
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("parameter_mismatch");
    // No wire committed.
    expect(connectors.ledgerEntries("msn_m5")).toHaveLength(0);
  });

  it("send_remittance_email executes and reconciles (external commitment)", async () => {
    const { server, evidence } = build();
    const res = await server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1" }, TOKEN);
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect(evidence.forMission("msn_m5").some((e) => e.kind === "execution")).toBe(true);
  });
});
