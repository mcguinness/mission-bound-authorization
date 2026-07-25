/**
 * M5 transaction-assurance tier, scenario 4 end to end: single-use permit,
 * execution lease, Execution Evidence, outcome reconciliation. Plus permit
 * replay refusal and the TOCTOU-in-the-commit-window refusal. In-process,
 * live OpenFGA, auto-skip when down.
 */

import { beforeAll, describe, expect, it } from "vitest";
import { Fga, type MissionView } from "@mission/pdp";
import {
  buildEffectiveParams,
  CANONICAL_RESOURCE,
  Connectors,
  EvidenceStore,
  McpPaymentsServer,
  parameterDigest,
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

function build(
  opts: {
    jit?: { sign: import("jose").CryptoKey; kid: string; endpoint: string };
    /** AROP: RS-side challenge signer (rs-txn key). */
    challengeSigner?: { sign: import("jose").CryptoKey; kid: string; txnEndpoint: string; asIssuer: string };
    /** AROP: AS txn public JWKS + issuer for validating a presented txn-token. */
    txnTokenJwks?: { keys: Record<string, unknown>[] };
    asIssuer?: string;
    /** Gate remittance on a per-action approval without wiring the ARAP signer. */
    gateRemittance?: boolean;
  } = {},
) {
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
  );
  const evidence = new EvidenceStore();
  const connectors = new Connectors();
  const engine = new TransactionEngine("epoch-1");
  const card = { name: "payments" };
  const gated = Boolean(opts.jit || opts.challengeSigner || opts.gateRemittance);
  const pep = new Pep({
    payments,
    evidence,
    fga,
    modelId,
    loadView: (id) => (id === VIEW.id ? VIEW : undefined),
    instanceEpoch: "epoch-1",
    sourceDigest: sourceDigestOf(card),
    ...(gated
      ? { requiresActionApproval: (action: string) => action === "payments:remittance.send", maxApprovalAgeSeconds: 300 }
      : {}),
    ...(opts.jit ? { requestable: opts.jit } : {}),
    ...(opts.challengeSigner ? { challengeSigner: opts.challengeSigner } : {}),
  });
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView: (id) => (id === VIEW.id ? VIEW : undefined),
    jwks: { keys: [] },
    issuer: "https://as.test",
    serverCard: card,
    transaction: { engine, connectors, evidence },
    ...(opts.txnTokenJwks ? { txnTokenJwks: opts.txnTokenJwks } : {}),
    ...(opts.asIssuer ? { asIssuer: opts.asIssuer } : {}),
  });
  return { payments, evidence, connectors, engine, server };
}

// AROP Transaction Challenge (phase 2) test helpers.
const AS_ISSUER = "https://as.test";
const TXN_ENDPOINT = "https://as.test/transaction";

/** parameter_digest for the seeded remittance operation (inv-1/acme), the way
 * the PEP computes it -- so a derived approval matches at step 8. */
function digestFor(payments: PaymentsStore): string {
  const invoice = payments.getInvoice("inv-1");
  const vendor = invoice ? payments.getVendor(invoice.vendor_id) : undefined;
  if (!invoice || !vendor) throw new Error("seed missing inv-1/acme");
  return parameterDigest(
    buildEffectiveParams({ action: "payments:remittance.send", invoice, vendor, resource: CANONICAL_RESOURCE }),
  );
}

/** Sign an AS-shaped txn-token inline (mirrors the shape in txn-endpoint.test.ts). */
async function signTxnToken(input: {
  key: import("jose").CryptoKey;
  txn: string;
  cnfJkt: string;
  approval: { id: string; approved_at: string; approved_until: string; parameter_digest: string };
}): Promise<string> {
  const { SignJWT } = await import("jose");
  return new SignJWT({ txn: input.txn, single_use: true, cnf: { jkt: input.cnfJkt }, approval: input.approval })
    .setProtectedHeader({ alg: "ES256", kid: "as-txn", typ: "txn-token+jwt" })
    .setIssuer(AS_ISSUER)
    .setAudience(CANONICAL_RESOURCE)
    .setIssuedAt()
    .setExpirationTime(Math.floor(Date.parse(input.approval.approved_until) / 1000))
    .sign(input.key);
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

  it("AROP: a gated action with challengeSigner and no txn-token yields a signed txn-challenge", async () => {
    const { generateKeyPair, exportJWK, createLocalJWKSet, jwtVerify } = await import("jose");
    const rsTxn = await generateKeyPair("ES256", { extractable: true });
    const rsTxnPub = { ...(await exportJWK(rsTxn.publicKey)), kid: "rs-txn", alg: "ES256" };
    const { server, payments } = build({
      challengeSigner: { sign: rsTxn.privateKey, kid: "rs-txn", txnEndpoint: TXN_ENDPOINT, asIssuer: AS_ISSUER },
    });

    const res = await server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1" }, TOKEN);
    expect(res.ok).toBe(false);
    expect(res.denial_reason).toBe("action_approval_required");
    expect(res.access_challenge?.txn_endpoint).toBe(TXN_ENDPOINT);

    // The challenge is a real rs-txn-signed txn-challenge, aud=AS, bound to the
    // exact operation parameter_digest the PEP gated on.
    const challenge = res.access_challenge?.challenge as string;
    expect(challenge).toBeTruthy();
    const { payload, protectedHeader } = await jwtVerify(challenge, createLocalJWKSet({ keys: [rsTxnPub] } as never), {
      audience: AS_ISSUER,
      typ: "txn-challenge+jwt",
    });
    expect(protectedHeader.typ).toBe("txn-challenge+jwt");
    expect(payload.iss).toBe(CANONICAL_RESOURCE);
    expect(payload.parameter_digest).toBe(digestFor(payments));
    // The challenge carries the active Mission's authority_set entry for this
    // resource+action (what the AS subset-gate consumes) -- not an empty set.
    const details = payload.authorization_details as { resource: string; actions: string[] }[];
    expect(details).toHaveLength(1);
    expect(details[0]?.resource).toBe(CANONICAL_RESOURCE);
    expect(details[0]?.actions).toContain("payments:remittance.send");
  });

  it("AROP: a valid presented txn-token derives the approval and commits (hybrid)", async () => {
    const { generateKeyPair, exportJWK } = await import("jose");
    const asTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxnPub = { ...(await exportJWK(asTxn.publicKey)), kid: "as-txn", alg: "ES256" };
    const { server, payments } = build({ gateRemittance: true, txnTokenJwks: { keys: [asTxnPub] }, asIssuer: AS_ISSUER });

    const approvedUntil = new Date(Date.now() + 300_000).toISOString();
    const txnToken = await signTxnToken({
      key: asTxn.privateKey,
      txn: "txn_unit_ok",
      cnfJkt: TOKEN.cnfJkt,
      approval: { id: "apr_unit", approved_at: new Date().toISOString(), approved_until: approvedUntil, parameter_digest: digestFor(payments) },
    });

    // No agent-supplied actionApproval; the approval is derived from the token.
    const res = await server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1" }, TOKEN, undefined, txnToken);
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect(res.result).toMatchObject({ executed: true, invoice_id: "inv-1" });
  });

  it("AROP: a txn-token bound to a different key is rejected (cnf mismatch)", async () => {
    const { generateKeyPair, exportJWK } = await import("jose");
    const asTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxnPub = { ...(await exportJWK(asTxn.publicKey)), kid: "as-txn", alg: "ES256" };
    const { server, payments } = build({ gateRemittance: true, txnTokenJwks: { keys: [asTxnPub] }, asIssuer: AS_ISSUER });

    const approvedUntil = new Date(Date.now() + 300_000).toISOString();
    const txnToken = await signTxnToken({
      key: asTxn.privateKey,
      txn: "txn_unit_cnf",
      cnfJkt: "jkt-someone-else", // not TOKEN.cnfJkt
      approval: { id: "apr_unit", approved_at: new Date().toISOString(), approved_until: approvedUntil, parameter_digest: digestFor(payments) },
    });

    const res = await server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1" }, TOKEN, undefined, txnToken);
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("txn_cnf_mismatch");
  });

  it("AROP: replaying the same txn is rejected (txn_replayed) and does not double-execute", async () => {
    const { generateKeyPair, exportJWK } = await import("jose");
    const asTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxnPub = { ...(await exportJWK(asTxn.publicKey)), kid: "as-txn", alg: "ES256" };
    const { server, evidence, payments } = build({ gateRemittance: true, txnTokenJwks: { keys: [asTxnPub] }, asIssuer: AS_ISSUER });

    const approvedUntil = new Date(Date.now() + 300_000).toISOString();
    const txnToken = await signTxnToken({
      key: asTxn.privateKey,
      txn: "txn_unit_replay",
      cnfJkt: TOKEN.cnfJkt,
      approval: { id: "apr_unit", approved_at: new Date().toISOString(), approved_until: approvedUntil, parameter_digest: digestFor(payments) },
    });

    const first = await server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1" }, TOKEN, undefined, txnToken);
    expect(first.ok, JSON.stringify(first)).toBe(true);
    // Replay is refused before enforce/redeem/commit, so nothing executes twice.
    const second = await server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1" }, TOKEN, undefined, txnToken);
    expect(second.ok).toBe(false);
    expect(second.refusal_reason).toBe("txn_replayed");
    expect(evidence.forMission("msn_m5").filter((e) => e.kind === "execution")).toHaveLength(1);
  });
});
