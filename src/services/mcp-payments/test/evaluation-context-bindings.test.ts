/**
 * @spec runtime#evaluation-context-binding (#773): "Adoption MUST preserve
 * existing approval-to-decision, transaction-token, parameter, and
 * operation-idempotency bindings. Moving a fact into the evaluation context
 * MUST NOT permit an earlier approval or operation identity to authorize
 * changed effect parameters after fresh context capture." And "authoritative
 * facts remain available to the PDP wherever policy needs their values".
 *
 * Witnessed under the claimed declaration, through this resource's real PEP,
 * server, transaction tier and transaction-token verification, against a real
 * decision point bound to the same claim, on the real clock (approvals and
 * transaction tokens are time-bound).
 *
 * The FGA layer is a stub that always permits, so this file never skips.
 */

import { createHash, randomUUID } from "node:crypto";
import { calculateJwkThumbprint, decodeJwt, exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { EvaluationContextBindingDeclarations } from "@mission/core";
import { currentContractRef, RUNTIME_SCOPE_CONFIG, pinnedToCurrentContract } from "@mission/demo-data";
import {
  createEphemeralDecisionPoint,
  type EvaluationRequest,
  type EvidenceKeyResolver,
  type Fga,
  type MissionView,
  openEphemeralClaimDomain,
  RUNTIME_POSTURE,
} from "@mission/pdp";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import {
  type ActionApprovalInput,
  buildEffectiveParams,
  CANONICAL_RESOURCE,
  Connectors,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  type ExecutionEvidence,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  parameterDigest,
  PaymentsStore,
  Pep,
  type TokenFacts,
  TransactionEngine,
} from "../src/index.js";
import { ALL_ACTIONS_CREDENTIAL } from "./credential-fixtures.js";

const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
const ISSUER = "https://as.test";
const AS_ISSUER = "https://as.test";
const idem = (): string => `idem_${randomUUID()}`;

const CLAIMED = new EvaluationContextBindingDeclarations({
  ...(structuredClone(RUNTIME_SCOPE_CONFIG) as Record<string, unknown>),
  claims: ["evaluation_context_binding"],
});

const holderKeys = await generateKeyPair("ES256", { extractable: true });
const HOLDER_JKT = await calculateJwkThumbprint(await exportJWK(holderKeys.publicKey));
const rsTxn = await generateKeyPair("ES256", { extractable: true });
const asTxn = await generateKeyPair("ES256", { extractable: true });
const asTxnPub = { ...(await exportJWK(asTxn.publicKey)), kid: "as-txn", alg: "ES256" };

const MISSION_CLAIM = {
  id: "msn_773t",
  issuer: ISSUER,
  authority_hash: "sha-256:msn_773t",
  expires_at: "2100-01-01T00:00:00Z",
  approval_basis: { type: "direct" },
};
const TOKEN: TokenFacts = {
  sub: "alice",
  clientId: "ap-agent",
  clientInstanceId: "inst-1",
  mission: { id: MISSION_CLAIM.id, issuer: ISSUER, authority_hash: MISSION_CLAIM.authority_hash },
  missionClaim: MISSION_CLAIM as TokenFacts["missionClaim"],
  cnfJkt: HOLDER_JKT,
  credentialAuthority: ALL_ACTIONS_CREDENTIAL,
};

const ENTRY_CONSTRAINTS = { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] };
const view = (): MissionView => ({
  id: MISSION_CLAIM.id,
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: MISSION_CLAIM.authority_hash,
  authority_set: [
    // The wire is gated on an action-bound approval bound to its parameter digest.
    pinnedToCurrentContract({
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:payment.execute"],
      constraints: { ...ENTRY_CONSTRAINTS, requires_action_approval: true },
    }),
    pinnedToCurrentContract({ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:remittance.send"], constraints: ENTRY_CONSTRAINTS }),
  ] as MissionView["authority_set"],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
});

/** The approved Resource of an approval given under the contract the wire's entry pins, as a fresh approval records it (#249). */
const APPROVED_RESOURCE = {
  properties: { resource_contract: currentContractRef({ resource: CANONICAL_RESOURCE, actions: ["payments:payment.execute"] }) },
};

function harness() {
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [
      { id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
      { id: "inv-big", vendor_id: "acme", amount: "900.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
    ],
  );
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === MISSION_CLAIM.id && ref.issuer === ISSUER
      ? { view: view(), observation: { state: "active", version: 1, mode: "fresh", freshness_at: new Date().toISOString() } }
      : undefined;
  let pepKeys: EvidenceKeyResolver | undefined;
  const claims = openEphemeralClaimDomain({
    owner: RUNTIME_POSTURE.pdps[0] as string,
    statement: RUNTIME_POSTURE,
    settlementKeys: (params) => pepKeys?.(params),
  });
  const point = createEphemeralDecisionPoint({
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
    emitterId: CANONICAL_RESOURCE,
    audience: CANONICAL_RESOURCE,
    claims,
    evaluationContextBinding: CLAIMED,
  });
  const keys = createEphemeralEvidenceKeys({ decisionPoint: point });
  pepKeys = keys.resolver;
  const evidence = new EvidenceStore(keys.signing, keys.resolver);
  const connectors = new Connectors();
  const requests: EvaluationRequest[] = [];
  const pep = new Pep({
    decide: async (req, options) => {
      requests.push(req);
      return point.decide(req, options);
    },
    payments,
    evidence,
    fga: alwaysAllowFga,
    modelId: "model-773t",
    loadView,
    instanceEpoch: "epoch-773t",
    evaluationContextBinding: () => CLAIMED,
    requiresActionApproval: (action) => action === "payments:remittance.send",
    maxApprovalAgeSeconds: 300,
    challengeSigner: { sign: rsTxn.privateKey, kid: "rs-txn", asIssuer: AS_ISSUER },
  });
  const server = new McpPaymentsServer({
    writeReservations: openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" }),
    pep,
    payments,
    loadView,
    jwks: { keys: [] },
    keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: ["as-txn"] },
    issuer: ISSUER,
    transaction: { engine: new TransactionEngine("epoch-773t"), connectors, evidence },
    txnTokenJwks: { keys: [asTxnPub] },
    asIssuer: AS_ISSUER,
  });
  return {
    pep,
    server,
    payments,
    evidence,
    connectors,
    lastContext: () => requests.at(-1)?.context as unknown as Record<string, unknown> | undefined,
    lastResource: () => requests.at(-1)?.resource as unknown as { properties: Record<string, unknown> } | undefined,
    executions: () => evidence.all().filter((e): e is ExecutionEvidence => e.kind === "execution").map((e) => e.content),
  };
}

/** The parameter digest an approval ceremony binds, computed as the PEP computes it, with no reference to the claim. */
function digestOf(payments: PaymentsStore, action: string, invoiceId = "inv-1"): string {
  const invoice = payments.getInvoice(invoiceId);
  const vendor = invoice ? payments.getVendor(invoice.vendor_id) : undefined;
  if (!invoice || !vendor) throw new Error("seed missing");
  return parameterDigest(buildEffectiveParams({ action, invoice, vendor, resource: CANONICAL_RESOURCE }));
}

async function popFor(credential: string): Promise<{ proof: string; htu: string; htm: string }> {
  const proof = await new SignJWT({
    htu: CANONICAL_RESOURCE,
    htm: "POST",
    ath: createHash("sha256").update(credential, "ascii").digest("base64url"),
  })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(holderKeys.publicKey) })
    .setJti(randomUUID())
    .setIssuedAt()
    .sign(holderKeys.privateKey);
  return { proof, htu: CANONICAL_RESOURCE, htm: "POST" };
}

/** Stand in for the Transaction Authorization Server: a conforming transaction token for `txn`. */
async function txnTokenFor(txn: string, digest: string): Promise<string> {
  return new SignJWT({
    sub: "alice",
    client_id: "ap-agent",
    txn,
    authorization_details: view()
      .authority_set.filter((e) => e.actions.includes("payments:remittance.send"))
      .map((e) => ({ ...e, actions: ["payments:remittance.send"] })),
    parameter_digest: digest,
    mission: MISSION_CLAIM,
    cnf: { jkt: HOLDER_JKT },
  })
    .setProtectedHeader({ alg: "ES256", kid: "as-txn", typ: "mission-txn-token+jwt" })
    .setIssuer(AS_ISSUER)
    .setAudience(CANONICAL_RESOURCE)
    .setIssuedAt()
    .setExpirationTime(Math.floor(Date.now() / 1000) + 300)
    .setJti(`mtt_${randomUUID()}`)
    .sign(asTxn.privateKey);
}

async function challengeFor(h: ReturnType<typeof harness>): Promise<string> {
  const challenged = await h.server.callTransactionTool(
    "send_remittance_email",
    { invoice_id: "inv-1", idempotency_key: idem() },
    TOKEN,
    undefined,
    { acceptTxnChallenge: true },
  );
  if (typeof challenged.transaction_challenge !== "string") throw new Error(JSON.stringify(challenged));
  return challenged.transaction_challenge;
}

describe("adoption keeps the approval and transaction-token bindings (@spec runtime#evaluation-context-binding, #773)", () => {
  it("an action-bound approval bound to parameter_digest satisfies the gate under the claim, and stops satisfying it once the record moves before the decision", async () => {
    const h = harness();
    const approval: ActionApprovalInput = {
      id: "apr_773",
      approved_at: new Date().toISOString(),
      parameter_digest: digestOf(h.payments, "payments:payment.execute"),
      resource: APPROVED_RESOURCE,
    };
    // The gate is live: no approval, no permit.
    const ungated = await h.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: idem() }, TOKEN);
    expect(ungated.denial_reason).toBe("action_approval_required");
    // The approval binds the same parameter digest the request carries
    // beside its context members, and satisfies the gate.
    const approved = await h.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: idem() }, TOKEN, approval);
    expect(approved.permitted, JSON.stringify(approved)).toBe(true);
    expect(h.lastContext()?.parameter_digest).toBe(approval.parameter_digest);
    expect(h.lastContext()?.evaluation_context_digest).toMatch(/^sha-256:/);
    // The record moves in the approval-to-decision interval: a fresh context
    // capture never lets the earlier approval authorize the changed effect.
    h.payments.bumpInvoiceAmount("inv-1", "130.00");
    const stale = await h.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: idem() }, TOKEN, approval);
    expect(stale.permitted).toBe(false);
    expect(stale.denial_reason).toBe("action_approval_required");
  });

  it("a transaction token bound to the challenged operation's parameter_digest verifies and executes once under the claim", async () => {
    const h = harness();
    const challenge = await challengeFor(h);
    const claims = decodeJwt(challenge);
    // The challenge binds the parameter digest the claim leaves unchanged.
    expect(claims.parameter_digest).toBe(digestOf(h.payments, "payments:remittance.send"));
    const token = await txnTokenFor(claims.txn as string, claims.parameter_digest as string);
    const verified = await h.server.verifyTransactionCredential(token, await popFor(token));
    if (!verified.ok) throw new Error(verified.refusal_reason);
    const done = await h.server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1", idempotency_key: idem() }, verified.facts);
    expect(done.ok, JSON.stringify(done)).toBe(true);
    expect(h.lastContext()?.evaluation_context_digest).toMatch(/^sha-256:/);
    expect(h.connectors.committedEffects()).toHaveLength(1);
    const [completed] = h.executions();
    expect(completed?.outcome).toBe("completed");
    expect(completed?.authorized_evaluation_context_digest).toBe(h.lastContext()?.evaluation_context_digest);
  });

  it("a transaction token issued before the record moved is refused under the claim, with no effect", async () => {
    const h = harness();
    const challenge = await challengeFor(h);
    const claims = decodeJwt(challenge);
    const token = await txnTokenFor(claims.txn as string, claims.parameter_digest as string);
    const verified = await h.server.verifyTransactionCredential(token, await popFor(token));
    if (!verified.ok) throw new Error(verified.refusal_reason);
    h.payments.bumpInvoiceAmount("inv-1", "130.00");
    const refused = await h.server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1", idempotency_key: idem() }, verified.facts);
    expect(refused).toEqual({ ok: false, refusal_reason: "txn_parameter_mismatch" });
    expect(h.connectors.committedEffects()).toHaveLength(0);
    expect(h.executions()).toHaveLength(0);
  });
});

describe("authoritative facts still reach policy beside the echoed context digest (@spec runtime#evaluation-context-binding, #773)", () => {
  it("a covered crossing's request carries the amount and target facts policy evaluates, and an over-cap invoice is denied parameter_violation", async () => {
    const h = harness();
    const approval = (invoiceId: string): ActionApprovalInput => ({
      id: `apr_${invoiceId}`,
      approved_at: new Date().toISOString(),
      parameter_digest: digestOf(h.payments, "payments:payment.execute", invoiceId),
      resource: APPROVED_RESOURCE,
    });
    const within = await h.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: idem() }, TOKEN, approval("inv-1"));
    expect(within.permitted, JSON.stringify(within)).toBe(true);
    expect(h.lastContext()?.amount).toEqual({ amount: "125.00", currency: "USD" });
    expect(h.lastResource()?.properties.vendor_id).toBe("acme");
    expect(h.lastContext()?.evaluation_context_digest).toMatch(/^sha-256:/);
    const over = await h.pep.enforce("execute_wire_transfer", { invoice_id: "inv-big", idempotency_key: idem() }, TOKEN, approval("inv-big"));
    expect(over.permitted).toBe(false);
    expect(over.denial_reason).toBe("parameter_violation");
    expect(h.lastContext()?.amount).toEqual({ amount: "900.00", currency: "USD" });
    expect(h.lastContext()?.evaluation_context_digest).toMatch(/^sha-256:/);
  });
});
