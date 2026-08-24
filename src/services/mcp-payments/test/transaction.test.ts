/**
 * M5 transaction-assurance tier, scenario 4 end to end: single-use permit,
 * execution lease, Execution Evidence, outcome reconciliation. Plus permit
 * replay refusal and the TOCTOU-in-the-commit-window refusal. In-process,
 * live OpenFGA, auto-skip when down.
 */

import { createHash } from "node:crypto";
import { calculateJwkThumbprint, decodeJwt, exportJWK, generateKeyPair, SignJWT } from "jose";
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
  type TxnConsumptionStore,
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
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
};

/** @spec runtime#state-freshness: a synchronous live read, freshness-stamped
 *  at this read (Finding 1); `allowedFreshnessSources` below declares "load_view" as trusted. */
const loadView = (ref: { id: string; issuer: string }) =>
  ref.id === VIEW.id && ref.issuer === VIEW.issuer
    ? { view: VIEW, freshness: { observed_at: new Date().toISOString(), source: "load_view" } }
    : undefined;
/**
 * @spec RFC 9449 — the presenter's REAL key. A transaction credential is only
 * ever accepted with a proof of possession bound to this request, so the
 * fixtures hold live key material rather than a placeholder thumbprint.
 */
const holderKeys = await generateKeyPair("ES256", { extractable: true });
const HOLDER_JKT = await calculateJwkThumbprint(await exportJWK(holderKeys.publicKey));
/** The request a presented credential is bound to (RFC 9449 htu/htm). */
const RS_HTU = CANONICAL_RESOURCE;
const RS_HTM = "POST";

/**
 * @spec RFC 9449 §4.2 — a proof of possession for THIS credential on THIS
 * request: `htu`/`htm`, a fresh `jti`, `iat`, and `ath` naming the credential.
 */
async function popFor(
  credential: string,
  opts: { keys?: typeof holderKeys; omitAth?: boolean; ath?: string; iat?: number; jti?: string } = {},
): Promise<{ proof: string; htu: string; htm: string }> {
  const keys = opts.keys ?? holderKeys;
  const jwt = new SignJWT({
    htu: RS_HTU,
    htm: RS_HTM,
    ...(opts.omitAth
      ? {}
      : { ath: opts.ath ?? createHash("sha256").update(credential, "ascii").digest("base64url") }),
  })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .setJti(opts.jti ?? crypto.randomUUID());
  return {
    proof: await (opts.iat !== undefined ? jwt.setIssuedAt(opts.iat) : jwt.setIssuedAt()).sign(keys.privateKey),
    htu: RS_HTU,
    htm: RS_HTM,
  };
}

const TOKEN: TokenFacts = {
  sub: "alice",
  clientId: "ap-agent",
  clientInstanceId: "inst-1",
  mission: { id: "msn_m5", issuer: "https://as.test", authority_hash: "sha-256:m5hash" },
  // @spec txn-authorization#resource-challenge — the VERIFIED token's whole
  // mission claim, which a challenge copies unchanged.
  missionClaim: {
    id: "msn_m5",
    issuer: "https://as.test",
    authority_hash: "sha-256:m5hash",
    expires_at: "2100-01-01T00:00:00Z",
    approval_basis: { type: "direct" },
  },
  cnfJkt: HOLDER_JKT,
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
    loadView,
    instanceEpoch: "epoch-1",
    sourceDigest: sourceDigestOf(card),
    allowedFreshnessSources: new Set(["load_view"]),
    ...(gated
      ? { requiresActionApproval: (action: string) => action === "payments:remittance.send", maxApprovalAgeSeconds: 300 }
      : {}),
    ...(opts.jit ? { requestable: opts.jit } : {}),
    ...(opts.challengeSigner ? { challengeSigner: opts.challengeSigner } : {}),
  });
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
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

/**
 * @spec txn-authorization#transaction-token — present a transaction token as
 * the request's SOLE OAuth credential: the RS derives the request's TokenFacts
 * from THAT token, so the challenged operation runs under it alone.
 */
async function credentialFor(server: McpPaymentsServer, txnToken: string): Promise<TokenFacts> {
  const verified = await server.verifyTransactionCredential(txnToken, await popFor(txnToken));
  if (!verified.ok) throw new Error(`transaction credential refused: ${verified.refusal_reason}`);
  return verified.facts;
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
          expires_at: "2100-01-01T00:00:00Z",
          approval_basis: { type: "direct" },
        },
        parameter_digest: "sha-256:client-supplied",
        cnf: { jkt: "jkt-client-supplied" },
      },
      TOKEN,
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

    // The transaction token is the request's ONLY credential: subject, client,
    // Mission and presenter key all come from it.
    const credential = await credentialFor(server, txnToken);
    expect(credential.txn?.txn).toBe(txn);
    expect(credential.mission.id).toBe("msn_m5");
    const res = await server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1" }, credential);
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect(evidence.forMission("msn_m5").filter((e) => e.kind === "execution")).toHaveLength(1);
  });

  it("refuses a transaction credential on the transport that cannot prove possession (@spec txn-authorization#offline-verification)", async () => {
    const { createMediatedClient } = await import("../src/index.js");
    const rsTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxnPub = { ...(await exportJWK(asTxn.publicKey)), kid: "as-txn", alg: "ES256" };
    const { server, payments, connectors } = build({
      challengeSigner: { sign: rsTxn.privateKey, kid: "rs-txn", asIssuer: AS_ISSUER },
      txnTokenJwks: { keys: [asTxnPub] },
      asIssuer: AS_ISSUER,
    });
    const challengeRes = await server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-1" },
      TOKEN,
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

    // The in-process mediated channel has no HTTP request to bind a proof to.
    // It carries the ordinary credential class under that documented
    // simplification; a transaction credential is refused outright rather than
    // admitted unproven, and the challenged effect never runs.
    const { client } = await createMediatedClient(server);
    const verdict = await client.callTool("send_remittance_email", { invoice_id: "inv-1" }, txnToken);
    expect(verdict.ok).toBe(false);
    expect(verdict.refusal_reason).toBe("txn_pop_required");
    expect(connectors.ledgerEntries("msn_m5")).toHaveLength(0);
    await client.close();
  });

  it("holds a transaction credential to the full RFC 9449 proof discipline (@spec txn-authorization#offline-verification)", async () => {
    const rsTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxnPub = { ...(await exportJWK(asTxn.publicKey)), kid: "as-txn", alg: "ES256" };
    const { server, payments } = build({
      challengeSigner: { sign: rsTxn.privateKey, kid: "rs-txn", asIssuer: AS_ISSUER },
      txnTokenJwks: { keys: [asTxnPub] },
      asIssuer: AS_ISSUER,
    });
    const challengeRes = await server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-1" },
      TOKEN,
      undefined,
      ACCEPT_CHALLENGE,
    );
    const txn = decodeJwt(challengeRes.transaction_challenge as string).txn as string;
    const mint = async (): Promise<string> =>
      signTxnToken({
        key: asTxn.privateKey,
        txn,
        cnfJkt: TOKEN.cnfJkt,
        parameterDigest: digestFor(payments),
        authorizationDetails: remittanceEntry(),
      });
    const token = await mint();

    // No proof at all. The credential authorizes an irreversible operation
    // under a key the challenge committed to; unproven it would be a bearer
    // token for that operation, so the transport that cannot carry a proof
    // cannot carry this credential either.
    expect((await server.verifyTransactionCredential(token)).ok).toBe(false);
    expect(
      ((await server.verifyTransactionCredential(token)) as { refusal_reason: string }).refusal_reason,
    ).toBe("txn_pop_required");

    // No `ath`: the proof would bind to a KEY alone.
    expect(
      (await server.verifyTransactionCredential(token, await popFor(token, { omitAth: true }))).ok,
    ).toBe(false);

    // `ath` naming a DIFFERENT credential bound to the SAME key. This is the
    // swap `ath` exists to stop: without it the proof minted for one token
    // presents the other.
    const sibling = await mint();
    expect(sibling).not.toBe(token);
    const swapped = await popFor(token, {
      ath: createHash("sha256").update(sibling, "ascii").digest("base64url"),
    });
    expect((await server.verifyTransactionCredential(token, swapped)).ok).toBe(false);

    // A replayed `jti` is single-use within the acceptance window.
    const once = await popFor(token, { jti: "jti-replayed-once" });
    expect((await server.verifyTransactionCredential(token, once)).ok).toBe(true);
    expect((await server.verifyTransactionCredential(token, once)).ok).toBe(false);

    // `iat` outside the window, in BOTH directions.
    const nowS = Math.floor(Date.now() / 1000);
    expect((await server.verifyTransactionCredential(token, await popFor(token, { iat: nowS - 3600 }))).ok).toBe(
      false,
    );
    expect((await server.verifyTransactionCredential(token, await popFor(token, { iat: nowS + 3600 }))).ok).toBe(
      false,
    );

    // A header `jwk` carrying private material proves nothing.
    const priv = (await exportJWK(holderKeys.privateKey)) as Record<string, unknown>;
    const withPrivate = await new SignJWT({
      htu: RS_HTU,
      htm: RS_HTM,
      ath: createHash("sha256").update(token, "ascii").digest("base64url"),
    })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: priv as never })
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .sign(holderKeys.privateKey);
    expect(
      (await server.verifyTransactionCredential(token, { proof: withPrivate, htu: RS_HTU, htm: RS_HTM })).ok,
    ).toBe(false);

    // Every refusal above names the proof, not the credential's own claims.
    const refused = await server.verifyTransactionCredential(token, await popFor(token, { omitAth: true }));
    expect((refused as { refusal_reason: string }).refusal_reason).toBe("txn_cnf_mismatch");

    // ...and a conforming proof still verifies.
    expect((await server.verifyTransactionCredential(token, await popFor(token))).ok).toBe(true);
  });

  it("authorizes the challenged operation alone, never another tool (@spec txn-authorization#transaction-token)", async () => {
    const { generateKeyPair, exportJWK } = await import("jose");
    const rsTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxnPub = { ...(await exportJWK(asTxn.publicKey)), kid: "as-txn", alg: "ES256" };
    const { server, evidence, connectors, payments } = build({
      challengeSigner: { sign: rsTxn.privateKey, kid: "rs-txn", asIssuer: AS_ISSUER },
      txnTokenJwks: { keys: [asTxnPub] },
      asIssuer: AS_ISSUER,
    });
    const challengeRes = await server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-1" },
      TOKEN,
      undefined,
      ACCEPT_CHALLENGE,
    );
    const txn = decodeJwt(challengeRes.transaction_challenge as string).txn as string;
    const credential = await credentialFor(
      server,
      await signTxnToken({
        key: asTxn.privateKey,
        txn,
        cnfJkt: TOKEN.cnfJkt,
        parameterDigest: digestFor(payments),
        authorizationDetails: remittanceEntry(),
      }),
    );

    // It is the credential for ONE retained operation: a read tool and another
    // transaction-tier action under the same credential are both refused, so it
    // never becomes a general Mission-bound credential.
    expect((await server.callReadTool("list_invoices", {}, credential)).refusal_reason).toBe("txn_action_mismatch");
    expect((await server.callWriteTool("schedule_payment", { invoice_id: "inv-1" }, credential)).refusal_reason).toBe(
      "txn_action_mismatch",
    );
    const otherAction = await server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1" }, credential);
    expect(otherAction.ok).toBe(false);
    expect(otherAction.refusal_reason).toBe("txn_action_mismatch");
    expect(connectors.ledgerEntries("msn_m5")).toHaveLength(0);
    expect(evidence.forMission("msn_m5").filter((e) => e.kind === "execution")).toHaveLength(0);

    // The challenged operation itself still runs under it.
    const executed = await server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1" }, credential);
    expect(executed.ok, JSON.stringify(executed)).toBe(true);
  });

  it("retains the destination-local subject, with the origin principal issuer-qualified (@spec txn-authorization#challenge-redemption)", async () => {
    const { generateKeyPair, exportJWK } = await import("jose");
    const { openStore } = await import("@mission/store");
    const { openTxnStores } = await import("../src/index.js");
    const rsTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxnPub = { ...(await exportJWK(asTxn.publicKey)), kid: "as-txn", alg: "ES256" };
    const stores = openTxnStores({ db: openStore("") });
    const { server, payments } = build({
      challengeSigner: { sign: rsTxn.privateKey, kid: "rs-txn", asIssuer: AS_ISSUER },
      txnTokenJwks: { keys: [asTxnPub] },
      asIssuer: AS_ISSUER,
      txnStores: stores,
    });

    // Where the Origin Principal profile applies the Mission claim carries the
    // issuer-qualified origin principal AND the credential keeps its own local
    // `sub`. The TAS mints `sub` from the local subject and leaves
    // `mission.subject` verbatim; the resource retains the pending operation
    // under the SAME rule, so the two agree on both identities.
    const originClaim = {
      ...(TOKEN.missionClaim as unknown as Record<string, unknown>),
      subject: { iss: "https://as.test", sub: "origin-alice" },
    };
    const origin: TokenFacts = { ...TOKEN, missionClaim: originClaim as unknown as TokenFacts["missionClaim"] };
    const challengeRes = await server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-1" },
      origin,
      undefined,
      ACCEPT_CHALLENGE,
    );
    const txn = decodeJwt(challengeRes.transaction_challenge as string).txn as string;
    const pending = stores.pending.get(CANONICAL_RESOURCE, txn);
    // The retained subject is the LOCAL one...
    expect(pending?.subject).toBe("alice");
    // ...and the origin principal survives, issuer-qualified, on the mission
    // claim the challenge copied unchanged.
    expect(pending?.mission.subject).toEqual({ iss: "https://as.test", sub: "origin-alice" });

    // A token minted for the ORIGIN principal in place of the local subject is
    // not this operation's credential: the substitution is exactly what the
    // cross-domain profile keeps apart.
    const mint = (subject: string) =>
      signTxnToken({
        key: asTxn.privateKey,
        txn,
        subject,
        cnfJkt: TOKEN.cnfJkt,
        parameterDigest: digestFor(payments),
        authorizationDetails: remittanceEntry(),
        mission: originClaim,
      });
    const other = await mint("origin-alice");
    const wrong = await server.verifyTransactionCredential(other, await popFor(other));
    expect(wrong.ok === false && wrong.refusal_reason).toBe("txn_subject_mismatch");
    const accepted = await credentialFor(server, await mint("alice"));
    expect(accepted.sub).toBe("alice");
    expect(accepted.missionClaim?.subject).toEqual({ iss: "https://as.test", sub: "origin-alice" });
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
    // No retained operation for this `txn`: the credential never resolves, so
    // no TokenFacts and no tool call can be derived from it at all.
    const res = await server.verifyTransactionCredential(txnToken, await popFor(txnToken));
    expect(res.ok).toBe(false);
    expect(res.ok === false && res.refusal_reason).toBe("txn_unknown");
  });

  it("refuses a transaction token bound to a key the current presenter does not hold", async () => {
    const { generateKeyPair, exportJWK } = await import("jose");
    const rsTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxnPub = { ...(await exportJWK(asTxn.publicKey)), kid: "as-txn", alg: "ES256" };
    const { server, payments } = build({
      challengeSigner: { sign: rsTxn.privateKey, kid: "rs-txn", asIssuer: AS_ISSUER },
      txnTokenJwks: { keys: [asTxnPub] },
      asIssuer: AS_ISSUER,
    });
    const challengeRes = await server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-1" },
      TOKEN,
      undefined,
      ACCEPT_CHALLENGE,
    );
    const txn = decodeJwt(challengeRes.transaction_challenge as string).txn as string;
    // The retained operation committed to the challenged presenter's key; a
    // token bound to a different one is not that operation's credential.
    const txnToken = await signTxnToken({
      key: asTxn.privateKey,
      txn,
      cnfJkt: "jkt-someone-else",
      parameterDigest: digestFor(payments),
      authorizationDetails: remittanceEntry(),
    });
    const res = await server.verifyTransactionCredential(txnToken, await popFor(txnToken));
    expect(res.ok).toBe(false);
    expect(res.ok === false && res.refusal_reason).toBe("txn_cnf_mismatch");
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
      ACCEPT_CHALLENGE,
    );
    const txn = decodeJwt(challengeRes.transaction_challenge as string).txn as string;
    const digest = digestFor(payments);
    /** The refusal reason the credential layer gives, or undefined when it resolves. */
    const present = async (txnToken: string): Promise<string | undefined> => {
      const verified = await server.verifyTransactionCredential(txnToken, await popFor(txnToken));
      return verified.ok ? undefined : verified.refusal_reason;
    };

    // The Mission invariants must be value-equal to the retained operation's.
    const otherMission = await signTxnToken({
      key: asTxn.privateKey,
      txn,
      cnfJkt: TOKEN.cnfJkt,
      parameterDigest: digest,
      authorizationDetails: remittanceEntry(),
      mission: { ...(TOKEN.missionClaim as unknown as Record<string, unknown>), id: "msn_other" },
    });
    expect(await present(otherMission)).toBe("txn_mission_mismatch");

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
    expect(await present(otherAuthority)).toBe("txn_authority_mismatch");

    // And `parameter_digest` is RECOMPUTED from authoritative store state: a
    // record that moved under the operation refuses, whatever the token says.
    const matching = await signTxnToken({
      key: asTxn.privateKey,
      txn,
      cnfJkt: TOKEN.cnfJkt,
      parameterDigest: digest,
      authorizationDetails: remittanceEntry(),
    });
    // The credential itself still resolves (its claim matches the operation the
    // resource retained); the RECOMPUTE against current store state is what
    // refuses, so a record that moved under the operation never executes.
    const moved = await credentialFor(server, matching);
    payments.bumpInvoiceAmount("inv-1", "480.00");
    const refused = await server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1" }, moved);
    expect(refused.refusal_reason).toBe("txn_parameter_mismatch");
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
    const asOrdinary = await server.verifyTransactionCredential(ordinary, await popFor(ordinary));
    expect(asOrdinary.ok).toBe(false);
    expect(asOrdinary.ok === false && asOrdinary.refusal_reason).toBe("txn_invalid");

    // An otherwise well-formed transaction token under an unknown typ.
    const wrongTyp = await signTxnToken({
      key: asTxn.privateKey,
      txn: "txn_wrong_typ",
      cnfJkt: TOKEN.cnfJkt,
      parameterDigest: digestFor(payments),
      authorizationDetails: remittanceEntry(),
      typ: "txn-token+jwt",
    });
    const res = await server.verifyTransactionCredential(wrongTyp, await popFor(wrongTyp));
    expect(res.ok).toBe(false);
    expect(res.ok === false && res.refusal_reason).toBe("txn_invalid");
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
      await credentialFor(a.server, await mint("mtt_one")),
    );
    expect(first.ok, JSON.stringify(first)).toBe(true);

    // A DISTINCT token jti for the same txn, presented at the OTHER replica, is
    // the same replay: refused, never executed as a new attempt.
    const second = await b.server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-1" },
      await credentialFor(b.server, await mint("mtt_two")),
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

    const credentialA = await credentialFor(a.server, await mint("mtt_race_a"));
    const credentialB = await credentialFor(b.server, await mint("mtt_race_b"));
    const [first, second] = await Promise.all([
      a.server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1" }, credentialA),
      b.server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1" }, credentialB),
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
        consume(): never {
          throw new Error("consumption store unavailable");
        },
        commit(): void {},
        get(): undefined {
          return undefined;
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
      await credentialFor(server, txnToken),
    );
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("consumption_unavailable");
    expect(connectors.ledgerEntries("msn_m5")).toHaveLength(0);
  });
});

d("the crash window between consumption and the effect (@spec txn-authorization#offline-verification)", () => {
  /** A challenged remittance, its txn-token, and the operation key the commit
   *  point will compute for it. */
  async function challenged(): Promise<{
    server: McpPaymentsServer;
    connectors: Connectors;
    evidence: EvidenceStore;
    stores: { consumption: TxnConsumptionStore };
    txnToken: string;
    txn: string;
    opKey: string;
  }> {
    const { openStore } = await import("@mission/store");
    const { openTxnStores, operationKey } = await import("../src/index.js");
    const rsTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxn = await generateKeyPair("ES256", { extractable: true });
    const asTxnPub = { ...(await exportJWK(asTxn.publicKey)), kid: "as-txn", alg: "ES256" };
    const stores = openTxnStores({ db: openStore("") });
    const { server, connectors, evidence, payments } = build({
      challengeSigner: { sign: rsTxn.privateKey, kid: "rs-txn", asIssuer: AS_ISSUER },
      txnTokenJwks: { keys: [asTxnPub] },
      asIssuer: AS_ISSUER,
      txnStores: stores,
    });
    const challengeRes = await server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-1" },
      TOKEN,
      undefined,
      ACCEPT_CHALLENGE,
    );
    const txn = decodeJwt(challengeRes.transaction_challenge as string).txn as string;
    const digest = digestFor(payments);
    return {
      server,
      connectors,
      evidence,
      stores,
      txn,
      opKey: operationKey("msn_m5", "payments:remittance.send", digest),
      txnToken: await signTxnToken({
        key: asTxn.privateKey,
        txn,
        cnfJkt: TOKEN.cnfJkt,
        parameterDigest: digest,
        authorizationDetails: remittanceEntry(),
      }),
    };
  }

  it("resumes its own interrupted request instead of reporting a false duplicate", async () => {
    const { server, connectors, stores, txnToken, txn, opKey } = await challenged();

    // The crash: the single use was taken and the effect landed, but the
    // process died before the consumption row could record that. The row says
    // `consumed`, which is indistinguishable from "the effect never happened"
    // to anything that only knows a boolean.
    expect(stores.consumption.consume(CANONICAL_RESOURCE, txn, opKey).first).toBe(true);
    connectors.sendEmail({
      opKey,
      invoiceId: "inv-1",
      to: "acme@vendor.example",
      permitId: "permit-crashed",
      missionId: "msn_m5",
    });

    // The same operation is presented again. It is THIS request resuming, not a
    // replay: refusing it would strand an operation whose effect exists, and
    // re-running it would be a second effect.
    const resumed = await server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-1" },
      await credentialFor(server, txnToken),
    );
    expect(resumed.ok, JSON.stringify(resumed)).toBe(true);
    // The connector's own idempotency reports it: exactly one effect exists.
    expect(resumed.deduped).toBe(true);
    // ...and the operation is now durably settled, so a later presentation is a
    // plain duplicate.
    expect(stores.consumption.get(CANONICAL_RESOURCE, txn)?.state).toBe("effect_committed");
    const again = await server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-1" },
      await credentialFor(server, txnToken),
    );
    expect(again.ok).toBe(false);
    expect(again.refusal_reason).toBe("duplicate_suppressed");
  });

  it("refuses a DIFFERENT operation presented under an already-consumed txn", async () => {
    const { server, connectors, stores, txnToken, txn } = await challenged();
    // Someone else's operation holds the single use for this txn.
    expect(stores.consumption.consume(CANONICAL_RESOURCE, txn, "op:msn_m5:some:other:sha-256:x").first).toBe(
      true,
    );

    const res = await server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-1" },
      await credentialFor(server, txnToken),
    );
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("duplicate_suppressed");
    expect(connectors.ledgerEntries("msn_m5")).toHaveLength(0);
    // The stored consumption is untouched: the refusal does not adopt it.
    expect(stores.consumption.get(CANONICAL_RESOURCE, txn)?.state).toBe("consumed");
  });
});

describe("txn consumption domain (@spec txn-authorization#offline-verification)", () => {
  it("admits the first use of a resource-scoped txn exactly once across replicas sharing the domain", async () => {
    const { openStore } = await import("@mission/store");
    const { openTxnStores } = await import("../src/index.js");
    // Two replicas' handles over ONE database: consumption must be
    // linearizable across every replica that can execute the same operation.
    const shared = openStore("");
    const a = openTxnStores({ db: shared });
    const b = openTxnStores({ db: shared });

    const OP = "op:msn_m5:payments:remittance.send:sha-256:d";
    expect(a.consumption.consume(CANONICAL_RESOURCE, "txn_shared", OP).first).toBe(true);
    const atOther = b.consumption.consume(CANONICAL_RESOURCE, "txn_shared", "op:other");
    expect(atOther.first).toBe(false);
    // The stored record travels with the refusal, so the caller can tell a
    // replay from a resumption of its own interrupted request.
    expect(atOther.first === false && atOther.record.opKey).toBe(OP);
    expect(atOther.first === false && atOther.record.state).toBe("consumed");
    expect(b.consumption.get(CANONICAL_RESOURCE, "txn_shared")?.state).toBe("consumed");

    // The effect's own state is durable, on the SAME row every replica shares.
    a.consumption.commit(CANONICAL_RESOURCE, "txn_shared");
    expect(b.consumption.get(CANONICAL_RESOURCE, "txn_shared")?.state).toBe("effect_committed");
    expect(b.consumption.get(CANONICAL_RESOURCE, "txn_shared")?.committedAt).toBeGreaterThan(0);

    // `txn` is scoped to the resource that challenged for it: the same value at
    // a different resource is a different transaction.
    expect(b.consumption.consume("https://other.test/mcp", "txn_shared", OP).first).toBe(true);
    expect(a.consumption.get("https://other.test/mcp", "txn_shared")?.state).toBe("consumed");
    expect(a.consumption.get(CANONICAL_RESOURCE, "txn_never_seen")).toBeUndefined();
  });
});
