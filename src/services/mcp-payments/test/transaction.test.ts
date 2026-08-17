/**
 * M5 transaction-assurance tier, scenario 4 end to end: single-use permit,
 * execution lease, Execution Evidence, outcome reconciliation. Plus permit
 * replay refusal and the TOCTOU-in-the-commit-window refusal. In-process,
 * live OpenFGA, auto-skip when down.
 */

import { decodeJwt } from "jose";
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
  // @spec txn-authorization#resource-challenge — the VERIFIED token's whole
  // mission claim, which a challenge copies unchanged.
  missionClaim: {
    id: "msn_m5",
    issuer: "https://as.test",
    authority_hash: "sha-256:m5hash",
    expires_at: 4102444800,
    approval_basis: { type: "direct" },
  },
  cnfJkt: "jkt-1",
};

/** @spec txn-authorization#resource-challenge — the client signal that gates a challenge. */
const ACCEPT_CHALLENGE = { acceptTxnChallenge: true } as const;

let fga: Fga;
let modelId: string;

function build(
  opts: {
    jit?: { sign: import("jose").CryptoKey; kid: string; endpoint: string };
    /** AROP: RS-side challenge signer (rs-txn key). */
    challengeSigner?: { sign: import("jose").CryptoKey; kid: string; asIssuer: string };
    /** AROP: AS txn public JWKS + issuer for validating a presented txn-token. */
    txnTokenJwks?: { keys: Record<string, unknown>[] };
    asIssuer?: string;
    /** The ORDINARY access-token JWKS this resource verifies credentials under. */
    jwks?: { keys: Record<string, unknown>[] };
    /** Gate remittance on a per-action approval without wiring the ARAP signer. */
    gateRemittance?: boolean;
    /** @spec txn-authorization#offline-verification — share a consumption domain. */
    txnStores?: {
      pending: import("../src/index.js").TxnPendingStore;
      consumption: import("../src/index.js").TxnConsumptionStore;
    };
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
    jwks: opts.jwks ?? { keys: [] },
    issuer: "https://as.test",
    serverCard: card,
    transaction: { engine, connectors, evidence },
    ...(opts.txnTokenJwks ? { txnTokenJwks: opts.txnTokenJwks } : {}),
    ...(opts.asIssuer ? { asIssuer: opts.asIssuer } : {}),
    ...(opts.txnStores ? { txnStores: opts.txnStores } : {}),
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

/**
 * Stand in for the Transaction Authorization Server: mint a conforming
 * `mission-txn-token+jwt` (@spec txn-authorization#transaction-token).
 */
async function signTxnToken(input: {
  key: import("jose").CryptoKey;
  txn: string;
  cnfJkt: string;
  parameterDigest: string;
  authorizationDetails: unknown[];
  mission?: Record<string, unknown>;
  subject?: string;
  jti?: string;
  typ?: string;
  audience?: string | string[];
  expS?: number;
}): Promise<string> {
  const { SignJWT } = await import("jose");
  return new SignJWT({
    sub: input.subject ?? "alice",
    client_id: "ap-agent",
    txn: input.txn,
    authorization_details: input.authorizationDetails,
    parameter_digest: input.parameterDigest,
    mission: input.mission ?? (TOKEN.missionClaim as unknown as Record<string, unknown>),
    cnf: { jkt: input.cnfJkt },
  })
    .setProtectedHeader({ alg: "ES256", kid: "as-txn", typ: input.typ ?? "mission-txn-token+jwt" })
    .setIssuer(AS_ISSUER)
    .setAudience(input.audience ?? CANONICAL_RESOURCE)
    .setIssuedAt()
    .setExpirationTime(input.expS ?? Math.floor(Date.now() / 1000) + 300)
    .setJti(input.jti ?? `mtt_${Math.random().toString(36).slice(2)}`)
    .sign(input.key);
}

/** The single `authorization_details` entry the RS challenges the remittance with. */
function remittanceEntry(): unknown[] {
  return VIEW.authority_set
    .filter((e) => e.resource === CANONICAL_RESOURCE && e.actions.includes("payments:remittance.send"))
    .map((e) => ({ ...e, actions: ["payments:remittance.send"] }));
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

    // Every record on the shared base identifies its emitting PEP.
    const exec = ev.find((e) => e.kind === "execution");
    expect(exec?.emitter).toEqual({ id: CANONICAL_RESOURCE, role: "pep" });
    const dec = ev.find((e) => e.kind === "decision");
    expect(dec?.emitter).toEqual({ id: CANONICAL_RESOURCE, role: "pep" });

    // Reconciliation joins evidence to the ledger with no anomalies.
    const report = reconcile("msn_m5", evidence, connectors);
    expect(report.ok).toBe(true);
    expect(report.matched).toHaveLength(1);
    expect(report.ledgerWithoutEvidence).toEqual([]);
    expect(report.evidenceWithoutLedger).toEqual([]);
  });

  it("execution under a continued credential records the hop_reference", async () => {
    // A Mission credential carrying a jti and an identity-continuation handle.
    const HANDLE = "ich_0123456789abcdefABCD";
    const JTI = "jag_hopref_unit";
    const continued: TokenFacts = { ...TOKEN, jti: JTI, identityContinuationHandle: HANDLE };
    const { server, evidence } = build();

    const res = await server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1" }, continued);
    expect(res.ok, JSON.stringify(res)).toBe(true);

    const exec = evidence.forMission("msn_m5").find((e) => e.kind === "execution");
    expect(exec?.hop_reference).toEqual({ jti: JTI, mission_id: "msn_m5", continuation_handle: HANDLE });
  });

  it("execution under a jti-bearing credential with no continuation handle omits continuation_handle", async () => {
    const JTI = "jag_hopref_no_handle";
    const continued: TokenFacts = { ...TOKEN, jti: JTI };
    const { server, evidence } = build();

    const res = await server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1" }, continued);
    expect(res.ok, JSON.stringify(res)).toBe(true);

    const exec = evidence.forMission("msn_m5").find((e) => e.kind === "execution");
    expect(exec?.hop_reference).toEqual({ jti: JTI, mission_id: "msn_m5" });
  });

  it("execution under a non-JWT credential (no jti) omits hop_reference entirely", async () => {
    // The existing TOKEN carries no jti: the field is guarded, so unaffected.
    const { server, evidence } = build();

    const res = await server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1" }, TOKEN);
    expect(res.ok, JSON.stringify(res)).toBe(true);

    const exec = evidence.forMission("msn_m5").find((e) => e.kind === "execution");
    expect(exec?.hop_reference).toBeUndefined();
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

  it("returns a signed challenge, and retains the pending operation, when the client signals it accepts one (@spec txn-authorization#resource-challenge)", async () => {
    const { generateKeyPair, exportJWK, createLocalJWKSet, jwtVerify } = await import("jose");
    const rsTxn = await generateKeyPair("ES256", { extractable: true });
    const rsTxnPub = { ...(await exportJWK(rsTxn.publicKey)), kid: "rs-txn", alg: "ES256" };
    const { server, payments } = build({
      challengeSigner: { sign: rsTxn.privateKey, kid: "rs-txn", asIssuer: AS_ISSUER },
    });

    // Without the signal the client just sees the denial.
    const unsignalled = await server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1" }, TOKEN);
    expect(unsignalled.ok).toBe(false);
    expect(unsignalled.denial_reason).toBe("action_approval_required");
    expect(unsignalled.transaction_challenge).toBeUndefined();

    const res = await server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-1" },
      TOKEN,
      undefined,
      undefined,
      ACCEPT_CHALLENGE,
    );
    expect(res.ok).toBe(false);
    expect(res.denial_reason).toBe("action_approval_required");
    // The upstream wire members, verbatim: no bespoke envelope, no endpoint hint.
    expect(res.error).toBe("transaction_authorization_required");
    const challenge = res.transaction_challenge as string;
    expect(challenge).toBeTruthy();

    const { payload, protectedHeader } = await jwtVerify(challenge, createLocalJWKSet({ keys: [rsTxnPub] } as never), {
      audience: AS_ISSUER,
      typ: "txn-authz-challenge+jwt",
    });
    expect(protectedHeader.typ).toBe("txn-authz-challenge+jwt");
    expect(payload.iss).toBe(CANONICAL_RESOURCE);
    expect(typeof payload.txn).toBe("string");
    expect(typeof payload.jti).toBe("string");
    expect(payload.sub).toBeUndefined();
    expect(payload.parameter_digest).toBe(digestFor(payments));
    // This profile's REQUIRED additions, derived from the verified token.
    expect((payload.mission as { id: string }).id).toBe("msn_m5");
    expect((payload.cnf as { jkt: string }).jkt).toBe(TOKEN.cnfJkt);
    // Exactly one operation-scoped entry.
    const details = payload.authorization_details as { resource: string; actions: string[] }[];
    expect(details).toHaveLength(1);
    expect(details[0]?.resource).toBe(CANONICAL_RESOURCE);
    expect(details[0]?.actions).toEqual(["payments:remittance.send"]);
  });

  it("derives the challenge's mission, parameter_digest and cnf itself, never from the client's arguments (@spec txn-authorization#resource-challenge)", async () => {
    const { generateKeyPair } = await import("jose");
    const rsTxn = await generateKeyPair("ES256", { extractable: true });
    const { server, payments } = build({
      challengeSigner: { sign: rsTxn.privateKey, kid: "rs-txn", asIssuer: AS_ISSUER },
    });

    // The client supplies its own `mission`, `parameter_digest` and `cnf`
    // alongside the operation's real argument. All three are the resource's to
    // derive from the request and the VERIFIED token, so none is reflected.
    const res = await server.callTransactionTool(
      "send_remittance_email",
      {
        invoice_id: "inv-1",
        mission: {
          id: "msn_supplied",
          issuer: "https://elsewhere.test",
          authority_hash: "sha-256:supplied",
          expires_at: 4102444800,
          approval_basis: { type: "direct" },
        },
        parameter_digest: "sha-256:client-supplied",
        cnf: { jkt: "jkt-client-supplied" },
      },
      TOKEN,
      undefined,
      undefined,
      ACCEPT_CHALLENGE,
    );
    const claims = decodeJwt(res.transaction_challenge as string);
    expect((claims.mission as { id: string }).id).toBe("msn_m5");
    expect((claims.mission as { issuer: string }).issuer).toBe("https://as.test");
    expect(claims.parameter_digest).toBe(digestFor(payments));
    expect((claims.cnf as { jkt: string }).jkt).toBe(TOKEN.cnfJkt);
  });

  it("executes exactly once for a verified transaction token that matches the retained operation (@spec txn-authorization#offline-verification)", async () => {
    const { generateKeyPair, exportJWK } = await import("jose");
    const rsTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxnPub = { ...(await exportJWK(asTxn.publicKey)), kid: "as-txn", alg: "ES256" };
    const { server, evidence, payments } = build({
      challengeSigner: { sign: rsTxn.privateKey, kid: "rs-txn", asIssuer: AS_ISSUER },
      txnTokenJwks: { keys: [asTxnPub] },
      asIssuer: AS_ISSUER,
    });

    const challengeRes = await server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-1" },
      TOKEN,
      undefined,
      undefined,
      ACCEPT_CHALLENGE,
    );
    const txn = decodeJwt(challengeRes.transaction_challenge as string).txn as string;
    const txnToken = await signTxnToken({
      key: asTxn.privateKey,
      txn,
      cnfJkt: TOKEN.cnfJkt,
      parameterDigest: digestFor(payments),
      authorizationDetails: remittanceEntry(),
    });

    const res = await server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-1" },
      TOKEN,
      undefined,
      txnToken,
    );
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect(evidence.forMission("msn_m5").filter((e) => e.kind === "execution")).toHaveLength(1);
  });

  it("refuses a transaction token whose txn this resource never challenged", async () => {
    const { generateKeyPair, exportJWK } = await import("jose");
    const asTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxnPub = { ...(await exportJWK(asTxn.publicKey)), kid: "as-txn", alg: "ES256" };
    const { server, payments } = build({
      gateRemittance: true,
      txnTokenJwks: { keys: [asTxnPub] },
      asIssuer: AS_ISSUER,
    });
    const txnToken = await signTxnToken({
      key: asTxn.privateKey,
      txn: "txn_never_challenged",
      cnfJkt: TOKEN.cnfJkt,
      parameterDigest: digestFor(payments),
      authorizationDetails: remittanceEntry(),
    });
    const res = await server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-1" },
      TOKEN,
      undefined,
      txnToken,
    );
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("txn_unknown");
  });

  it("refuses a transaction token bound to a key the current presenter does not hold", async () => {
    const { generateKeyPair, exportJWK } = await import("jose");
    const asTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxnPub = { ...(await exportJWK(asTxn.publicKey)), kid: "as-txn", alg: "ES256" };
    const { server, payments } = build({
      gateRemittance: true,
      txnTokenJwks: { keys: [asTxnPub] },
      asIssuer: AS_ISSUER,
    });
    const txnToken = await signTxnToken({
      key: asTxn.privateKey,
      txn: "txn_wrong_key",
      cnfJkt: "jkt-someone-else",
      parameterDigest: digestFor(payments),
      authorizationDetails: remittanceEntry(),
    });
    const res = await server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-1" },
      TOKEN,
      undefined,
      txnToken,
    );
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("txn_cnf_mismatch");
  });

  it("refuses a transaction token whose mission, authority or recomputed parameter_digest differs from the retained operation (@spec txn-authorization#offline-verification)", async () => {
    const { generateKeyPair, exportJWK } = await import("jose");
    const rsTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxnPub = { ...(await exportJWK(asTxn.publicKey)), kid: "as-txn", alg: "ES256" };
    const { server, payments, evidence } = build({
      challengeSigner: { sign: rsTxn.privateKey, kid: "rs-txn", asIssuer: AS_ISSUER },
      txnTokenJwks: { keys: [asTxnPub] },
      asIssuer: AS_ISSUER,
    });
    const challengeRes = await server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-1" },
      TOKEN,
      undefined,
      undefined,
      ACCEPT_CHALLENGE,
    );
    const txn = decodeJwt(challengeRes.transaction_challenge as string).txn as string;
    const digest = digestFor(payments);
    const present = (txnToken: string) =>
      server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1" }, TOKEN, undefined, txnToken);

    // The Mission invariants must be value-equal to the retained operation's.
    const otherMission = await signTxnToken({
      key: asTxn.privateKey,
      txn,
      cnfJkt: TOKEN.cnfJkt,
      parameterDigest: digest,
      authorizationDetails: remittanceEntry(),
      mission: { ...(TOKEN.missionClaim as unknown as Record<string, unknown>), id: "msn_other" },
    });
    expect((await present(otherMission)).refusal_reason).toBe("txn_mission_mismatch");

    // As must the operation's `authorization_details` entry.
    const otherAuthority = await signTxnToken({
      key: asTxn.privateKey,
      txn,
      cnfJkt: TOKEN.cnfJkt,
      parameterDigest: digest,
      authorizationDetails: (remittanceEntry() as { actions: string[] }[]).map((e) => ({
        ...e,
        actions: ["payments:payment.execute"],
      })),
    });
    expect((await present(otherAuthority)).refusal_reason).toBe("txn_authority_mismatch");

    // And `parameter_digest` is RECOMPUTED from authoritative store state: a
    // record that moved under the operation refuses, whatever the token says.
    const matching = await signTxnToken({
      key: asTxn.privateKey,
      txn,
      cnfJkt: TOKEN.cnfJkt,
      parameterDigest: digest,
      authorizationDetails: remittanceEntry(),
    });
    payments.bumpInvoiceAmount("inv-1", "480.00");
    expect((await present(matching)).refusal_reason).toBe("txn_parameter_mismatch");
    expect(evidence.forMission("msn_m5").filter((e) => e.kind === "execution")).toHaveLength(0);
  });

  it("rejects an ordinary Mission-bound token, and any other typ, outright", async () => {
    const { generateKeyPair, exportJWK, SignJWT } = await import("jose");
    const asTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxnPub = { ...(await exportJWK(asTxn.publicKey)), kid: "as-txn", alg: "ES256" };
    const { server, payments } = build({
      gateRemittance: true,
      txnTokenJwks: { keys: [asTxnPub] },
      asIssuer: AS_ISSUER,
    });

    // An ordinary access token: right issuer, right audience, wrong class.
    const ordinary = await new SignJWT({ sub: "alice", cnf: { jkt: TOKEN.cnfJkt }, mission: TOKEN.missionClaim })
      .setProtectedHeader({ alg: "ES256", kid: "as-txn", typ: "at+jwt" })
      .setIssuer(AS_ISSUER)
      .setAudience(CANONICAL_RESOURCE)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(asTxn.privateKey);
    const asOrdinary = await server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-1" },
      TOKEN,
      undefined,
      ordinary,
    );
    expect(asOrdinary.ok).toBe(false);
    expect(asOrdinary.refusal_reason).toBe("txn_invalid");

    // An otherwise well-formed transaction token under an unknown typ.
    const wrongTyp = await signTxnToken({
      key: asTxn.privateKey,
      txn: "txn_wrong_typ",
      cnfJkt: TOKEN.cnfJkt,
      parameterDigest: digestFor(payments),
      authorizationDetails: remittanceEntry(),
      typ: "txn-token+jwt",
    });
    const res = await server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-1" },
      TOKEN,
      undefined,
      wrongTyp,
    );
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("txn_invalid");
  });

  it("refuses a transaction token presented as an ordinary Mission-bound access token (@spec txn-authorization#transaction-token)", async () => {
    const { generateKeyPair, exportJWK, SignJWT } = await import("jose");
    const asTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxnPub = { ...(await exportJWK(asTxn.publicKey)), kid: "as-txn", alg: "ES256" };
    // The resource's ORDINARY credential JWKS is this AS's: a transaction
    // token's issuer, audience, `cnf` and `mission` claim would all satisfy
    // ordinary token validation, so its `typ` is the only thing keeping it out.
    const { server, payments } = build({
      jwks: { keys: [asTxnPub] },
      txnTokenJwks: { keys: [asTxnPub] },
      asIssuer: AS_ISSUER,
      gateRemittance: true,
    });
    const txnToken = await signTxnToken({
      key: asTxn.privateKey,
      txn: "txn_as_credential",
      cnfJkt: TOKEN.cnfJkt,
      parameterDigest: digestFor(payments),
      authorizationDetails: remittanceEntry(),
    });

    // It authorizes the challenged operation and nothing else: it never
    // becomes the credential a tool call runs under, so no TokenFacts and no
    // general tool call can be derived from it at all.
    await expect(server.validateMissionToken(txnToken)).rejects.toThrow(/not a Mission-bound access token/);

    // The same claims under an ordinary access token's typ do validate, so the
    // refusal above is the token's class and nothing incidental.
    const ordinary = await new SignJWT({
      sub: "alice",
      client_id: "ap-agent",
      cnf: { jkt: TOKEN.cnfJkt },
      mission: TOKEN.missionClaim,
    })
      .setProtectedHeader({ alg: "ES256", kid: "as-txn", typ: "at+jwt" })
      .setIssuer(AS_ISSUER)
      .setAudience(CANONICAL_RESOURCE)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(asTxn.privateKey);
    expect((await server.validateMissionToken(ordinary)).mission.id).toBe("msn_m5");
  });

  it("executes once across two replicas sharing a consumption domain, whatever token jti carries the txn", async () => {
    const { generateKeyPair, exportJWK } = await import("jose");
    const { openStore } = await import("@mission/store");
    const { openTxnStores } = await import("../src/index.js");
    const rsTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxnPub = { ...(await exportJWK(asTxn.publicKey)), kid: "as-txn", alg: "ES256" };

    // ONE database behind two servers: consumption of a txn must be
    // linearizable across every replica that can execute the operation.
    const shared = openStore("");
    const stores = openTxnStores({ db: shared });
    const a = build({
      challengeSigner: { sign: rsTxn.privateKey, kid: "rs-txn", asIssuer: AS_ISSUER },
      txnTokenJwks: { keys: [asTxnPub] },
      asIssuer: AS_ISSUER,
      txnStores: stores,
    });
    const b = build({
      txnTokenJwks: { keys: [asTxnPub] },
      asIssuer: AS_ISSUER,
      gateRemittance: true,
      txnStores: stores,
    });

    const challengeRes = await a.server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-1" },
      TOKEN,
      undefined,
      undefined,
      ACCEPT_CHALLENGE,
    );
    const txn = decodeJwt(challengeRes.transaction_challenge as string).txn as string;
    const mint = (jti: string) =>
      signTxnToken({
        key: asTxn.privateKey,
        txn,
        jti,
        cnfJkt: TOKEN.cnfJkt,
        parameterDigest: digestFor(a.payments),
        authorizationDetails: remittanceEntry(),
      });

    const first = await a.server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-1" },
      TOKEN,
      undefined,
      await mint("mtt_one"),
    );
    expect(first.ok, JSON.stringify(first)).toBe(true);

    // A DISTINCT token jti for the same txn, presented at the OTHER replica, is
    // the same replay: refused, never executed as a new attempt.
    const second = await b.server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-1" },
      TOKEN,
      undefined,
      await mint("mtt_two"),
    );
    expect(second.ok).toBe(false);
    expect(second.refusal_reason).toBe("duplicate_suppressed");
    expect(a.evidence.forMission("msn_m5").filter((e) => e.kind === "execution")).toHaveLength(1);
    expect(b.evidence.forMission("msn_m5").filter((e) => e.kind === "execution")).toHaveLength(0);
  });

  it("consumes a txn exactly once when two replicas are presented distinct token jtis simultaneously", async () => {
    const { generateKeyPair, exportJWK } = await import("jose");
    const { openStore } = await import("@mission/store");
    const { openTxnStores } = await import("../src/index.js");
    const rsTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxnPub = { ...(await exportJWK(asTxn.publicKey)), kid: "as-txn", alg: "ES256" };

    // Both replicas can execute this operation, so they share ONE consumption
    // domain; the two presentations are in flight at the same time.
    const stores = openTxnStores({ db: openStore("") });
    const a = build({
      challengeSigner: { sign: rsTxn.privateKey, kid: "rs-txn", asIssuer: AS_ISSUER },
      txnTokenJwks: { keys: [asTxnPub] },
      asIssuer: AS_ISSUER,
      txnStores: stores,
    });
    const b = build({
      txnTokenJwks: { keys: [asTxnPub] },
      asIssuer: AS_ISSUER,
      gateRemittance: true,
      txnStores: stores,
    });

    const challengeRes = await a.server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-1" },
      TOKEN,
      undefined,
      undefined,
      ACCEPT_CHALLENGE,
    );
    const txn = decodeJwt(challengeRes.transaction_challenge as string).txn as string;
    const mint = (jti: string) =>
      signTxnToken({
        key: asTxn.privateKey,
        txn,
        jti,
        cnfJkt: TOKEN.cnfJkt,
        parameterDigest: digestFor(a.payments),
        authorizationDetails: remittanceEntry(),
      });

    const [first, second] = await Promise.all([
      a.server.callTransactionTool(
        "send_remittance_email",
        { invoice_id: "inv-1" },
        TOKEN,
        undefined,
        await mint("mtt_race_a"),
      ),
      b.server.callTransactionTool(
        "send_remittance_email",
        { invoice_id: "inv-1" },
        TOKEN,
        undefined,
        await mint("mtt_race_b"),
      ),
    ]);

    // Exactly one execution, whichever replica won; the loser is the same
    // replay, never a second attempt under its own jti.
    expect([first?.ok, second?.ok].filter(Boolean)).toHaveLength(1);
    const refused = first?.ok ? second : first;
    expect(refused?.refusal_reason).toBe("duplicate_suppressed");
    const executions = [...a.evidence.forMission("msn_m5"), ...b.evidence.forMission("msn_m5")].filter(
      (e) => e.kind === "execution",
    );
    expect(executions).toHaveLength(1);
  });

  it("fails closed when the consumption store is unavailable", async () => {
    const { generateKeyPair, exportJWK } = await import("jose");
    const { openStore } = await import("@mission/store");
    const { openTxnStores } = await import("../src/index.js");
    const rsTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxnPub = { ...(await exportJWK(asTxn.publicKey)), kid: "as-txn", alg: "ES256" };
    const stores = openTxnStores({ db: openStore("") });
    const unavailable = {
      pending: stores.pending,
      consumption: {
        consume(): boolean {
          throw new Error("consumption store unavailable");
        },
        consumed(): boolean {
          return false;
        },
      },
    };
    const { server, connectors, payments } = build({
      challengeSigner: { sign: rsTxn.privateKey, kid: "rs-txn", asIssuer: AS_ISSUER },
      txnTokenJwks: { keys: [asTxnPub] },
      asIssuer: AS_ISSUER,
      txnStores: unavailable,
    });
    const challengeRes = await server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-1" },
      TOKEN,
      undefined,
      undefined,
      ACCEPT_CHALLENGE,
    );
    const txn = decodeJwt(challengeRes.transaction_challenge as string).txn as string;
    const txnToken = await signTxnToken({
      key: asTxn.privateKey,
      txn,
      cnfJkt: TOKEN.cnfJkt,
      parameterDigest: digestFor(payments),
      authorizationDetails: remittanceEntry(),
    });
    const res = await server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-1" },
      TOKEN,
      undefined,
      txnToken,
    );
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("consumption_unavailable");
    expect(connectors.ledgerEntries("msn_m5")).toHaveLength(0);
  });
});

describe("txn consumption domain (@spec txn-authorization#offline-verification)", () => {
  it("admits the first use of a resource-scoped txn exactly once across replicas sharing the domain", async () => {
    const { openStore } = await import("@mission/store");
    const { openTxnStores } = await import("../src/index.js");
    // Two replicas' handles over ONE database: consumption must be
    // linearizable across every replica that can execute the same operation.
    const shared = openStore("");
    const a = openTxnStores({ db: shared, instanceEpoch: "replica-a" });
    const b = openTxnStores({ db: shared, instanceEpoch: "replica-b" });

    expect(a.consumption.consume(CANONICAL_RESOURCE, "txn_shared")).toBe(true);
    expect(b.consumption.consume(CANONICAL_RESOURCE, "txn_shared")).toBe(false);
    expect(a.consumption.consume(CANONICAL_RESOURCE, "txn_shared")).toBe(false);
    expect(b.consumption.consumed(CANONICAL_RESOURCE, "txn_shared")).toBe(true);

    // `txn` is scoped to the resource that challenged for it: the same value at
    // a different resource is a different transaction.
    expect(b.consumption.consume("https://other.test/mcp", "txn_shared")).toBe(true);
    expect(a.consumption.consumed("https://other.test/mcp", "txn_shared")).toBe(true);
    expect(a.consumption.consumed(CANONICAL_RESOURCE, "txn_never_seen")).toBe(false);
  });
});
