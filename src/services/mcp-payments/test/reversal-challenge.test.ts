/**
 * @spec txn-authorization#offline-verification, txn-authorization#resource-challenge,
 * runtime#compound-actions (#252, #1693, D889): a challenged reversal, its
 * approval and its transaction-token retry, end to end.
 *
 * A reversal the deployment gates on an action-bound approval is challenged,
 * the approval is given (a transaction token bound to the challenged
 * operation's parameter digest), and the retry with that token releases
 * exactly one reversal of the committed wire. On the retry this resource
 * recomputes the challenged operation's digest itself: for the compensate
 * crossing, the reversal form rebuilt from the compensation link it
 * establishes again from its own retained, verified evidence and from the
 * committed wire's ledger record, never the invoice form, never the vendor
 * the invoice names now, and never a digest the token or the pending record
 * carries.
 *
 * Witnessed through this resource's real PEP, server, transaction tier and
 * transaction-token verification, against a real decision point, on the real
 * clock (approvals and transaction tokens are time-bound), with and without
 * the Evaluation-Context Binding claim. The FGA layer is a stub that always
 * permits, so this file never skips.
 */

import { createHash, randomUUID } from "node:crypto";
import { calculateJwkThumbprint, decodeJwt, exportJWK, generateKeyPair, type JWTPayload, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { EvaluationContextBindingDeclarations } from "@mission/core";
import { RUNTIME_SCOPE_CONFIG, pinnedToCurrentContract } from "@mission/demo-data";
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
  CANONICAL_RESOURCE,
  Connectors,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  type ExecutionEvidence,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  PaymentsStore,
  Pep,
  type TokenFacts,
  TransactionEngine,
} from "../src/index.js";
import { ALL_ACTIONS_CREDENTIAL } from "./credential-fixtures.js";

const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
const ISSUER = "https://as.test";
const AS_ISSUER = "https://as.test";
const REVERSE = "reverse_wire_transfer";
const EXECUTE = "execute_wire_transfer";
const idem = (): string => `idem_${randomUUID()}`;

const STATEMENT = structuredClone(RUNTIME_SCOPE_CONFIG) as Record<string, unknown>;
const CLAIMED = new EvaluationContextBindingDeclarations({ ...STATEMENT, claims: ["evaluation_context_binding"] });
const UNCLAIMED = new EvaluationContextBindingDeclarations({ ...STATEMENT, claims: [] });
const MODES = [
  ["claiming the binding", CLAIMED],
  ["not claiming the binding", UNCLAIMED],
] as const;

const holderKeys = await generateKeyPair("ES256", { extractable: true });
const HOLDER_JKT = await calculateJwkThumbprint(await exportJWK(holderKeys.publicKey));
const rsTxn = await generateKeyPair("ES256", { extractable: true });
const asTxn = await generateKeyPair("ES256", { extractable: true });
const asTxnPub = { ...(await exportJWK(asTxn.publicKey)), kid: "as-txn", alg: "ES256" };

const MISSION_CLAIM = {
  id: "msn_1693r",
  issuer: ISSUER,
  authority_hash: "sha-256:msn_1693r",
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
    pinnedToCurrentContract({ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:payment.execute"], constraints: ENTRY_CONSTRAINTS }),
    // The reversal is bounded to the paid vendor's tenant.
    pinnedToCurrentContract({
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:payment.reverse"],
      constraints: { ...ENTRY_CONSTRAINTS, tenant: "tenant-a" },
    }),
  ] as MissionView["authority_set"],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
});

/** `gated`: the actions the deployment requires an action-bound approval for. */
function harness(declarations: EvaluationContextBindingDeclarations, gated: readonly string[]) {
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved", tenant: "tenant-a" }],
    [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
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
    evaluationContextBinding: declarations,
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
    // #252: the committed-effect records a compensate crossing reads.
    committedEffects: connectors,
    fga: alwaysAllowFga,
    modelId: "model-1693r",
    loadView,
    instanceEpoch: "epoch-1693r",
    evaluationContextBinding: () => declarations,
    requiresActionApproval: (action) => gated.includes(action),
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
    transaction: { engine: new TransactionEngine("epoch-1693r"), connectors, evidence },
    txnTokenJwks: { keys: [asTxnPub] },
    asIssuer: AS_ISSUER,
  });
  return {
    server,
    payments,
    connectors,
    requests,
    executions: () => evidence.all().filter((e): e is ExecutionEvidence => e.kind === "execution").map((e) => e.content),
    /** The committed wire's ledger record for `inv-1`: its operation key and the vendor it paid. */
    ledgerWire: () =>
      connectors.db.prepare("SELECT op_key, vendor_id FROM ledger WHERE invoice_id = 'inv-1'").get() as
        | { op_key: string; vendor_id: string }
        | undefined,
  };
}
type Harness = ReturnType<typeof harness>;

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

/** Request `tool` on `inv-1` with the challenge signal; the challenge's claims. */
async function challenge(h: Harness, tool: string): Promise<JWTPayload> {
  const challenged = await h.server.callTransactionTool(
    tool,
    { invoice_id: "inv-1", idempotency_key: idem() },
    TOKEN,
    undefined,
    { acceptTxnChallenge: true },
  );
  if (typeof challenged.transaction_challenge !== "string") throw new Error(JSON.stringify(challenged));
  return decodeJwt(challenged.transaction_challenge);
}

/**
 * The approval: stand in for the Transaction Authorization Server, which
 * mints a transaction token for the challenged operation (its `txn`, its
 * operation entry and its parameter digest), verified here as the resource
 * verifies any.
 */
async function approve(h: Harness, claims: JWTPayload): Promise<TokenFacts> {
  const token = await new SignJWT({
    sub: "alice",
    client_id: "ap-agent",
    txn: claims.txn,
    authorization_details: claims.authorization_details,
    parameter_digest: claims.parameter_digest,
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
  const verified = await h.server.verifyTransactionCredential(token, await popFor(token));
  if (!verified.ok) throw new Error(verified.refusal_reason);
  return verified.facts;
}

const retry = (h: Harness, tool: string, facts: TokenFacts) =>
  h.server.callTransactionTool(tool, { invoice_id: "inv-1", idempotency_key: idem() }, facts);

async function commitWire(h: Harness): Promise<void> {
  const committed = await h.server.callTransactionTool(EXECUTE, { invoice_id: "inv-1", idempotency_key: idem() }, TOKEN);
  if (!committed.ok) throw new Error(JSON.stringify(committed));
}

/** Move `inv-1` to a new vendor, then delete that vendor's record: a direct store edit (#1693, D879). */
function orphanInvoice(payments: PaymentsStore): void {
  payments.db.prepare("INSERT INTO vendors (id, name, status, tenant) VALUES ('globex', 'Globex', 'approved', 'tenant-b')").run();
  payments.db.prepare("UPDATE invoices SET vendor_id = 'globex', version = version + 1 WHERE id = 'inv-1'").run();
  payments.db.prepare("DELETE FROM vendors WHERE id = 'globex'").run();
}

/** One completed reversal, offsetting exactly the committed wire, decided on the paid vendor and its tenant. */
function expectOneReversalOfTheWire(h: Harness, wire: { op_key: string } | undefined): void {
  expect(h.connectors.reversalEntries(MISSION_CLAIM.id)).toEqual([
    expect.objectContaining({ reversed_op_key: wire?.op_key, amount: "125.00", currency: "USD" }),
  ]);
  expect(h.requests.at(-1)?.resource.properties).toMatchObject({ vendor_id: "acme", tenant: "tenant-a" });
  expect(h.executions().filter((r) => r.outcome === "completed")).toHaveLength(2);
}

describe("a challenged reversal is approved and retried with its transaction token (@spec txn-authorization#offline-verification, runtime#compound-actions, #252, #1693, D889)", () => {
  for (const [mode, declarations] of MODES) {
    it(`the challenge binds the reversal form, and the retry releases exactly one reversal of the committed wire (${mode})`, async () => {
      const h = harness(declarations, ["payments:payment.reverse"]);
      await commitWire(h);
      const wire = h.ledgerWire();
      const claims = await challenge(h, REVERSE);
      expect(h.connectors.reversalEntries(MISSION_CLAIM.id)).toHaveLength(0);
      const facts = await approve(h, claims);
      const done = await retry(h, REVERSE, facts);
      expect(done.ok, JSON.stringify(done)).toBe(true);
      // The retry's decision request carries the challenged digest.
      expect(h.requests.at(-1)?.context.parameter_digest).toBe(claims.parameter_digest);
      expectOneReversalOfTheWire(h, wire);
    });

    for (const when of ["before the reversal is requested", "between the challenge and the retry"] as const) {
      it(`an invoice reassigned to another vendor whose record is then deleted ${when} still retries to one reversal of the paid wire under tenant-a (${mode})`, async () => {
        const h = harness(declarations, ["payments:payment.reverse"]);
        await commitWire(h);
        const wire = h.ledgerWire();
        if (when === "before the reversal is requested") orphanInvoice(h.payments);
        const claims = await challenge(h, REVERSE);
        const facts = await approve(h, claims);
        if (when === "between the challenge and the retry") orphanInvoice(h.payments);
        expect(h.payments.getVendor(h.payments.getInvoice("inv-1")?.vendor_id ?? "")).toBeUndefined();
        const done = await retry(h, REVERSE, facts);
        expect(done.ok, JSON.stringify(done)).toBe(true);
        expectOneReversalOfTheWire(h, wire);
      });
    }
  }

  for (const [drift, move] of [
    ["the wire's ledger record changed", (h: Harness) => h.connectors.db.prepare("UPDATE ledger SET amount = '99.00' WHERE invoice_id = 'inv-1'").run()],
    ["the link can no longer be established", (h: Harness) => h.connectors.db.prepare("DELETE FROM ledger WHERE invoice_id = 'inv-1'").run()],
  ] as const) {
    it(`a retry after ${drift} between the challenge and the retry is refused txn_parameter_mismatch, with no reversal`, async () => {
      const h = harness(CLAIMED, ["payments:payment.reverse"]);
      await commitWire(h);
      const claims = await challenge(h, REVERSE);
      const facts = await approve(h, claims);
      const sent = h.requests.length;
      move(h);
      const refused = await retry(h, REVERSE, facts);
      expect(refused).toEqual({ ok: false, refusal_reason: "txn_parameter_mismatch" });
      expect(h.requests).toHaveLength(sent);
      expect(h.connectors.reversalEntries(MISSION_CLAIM.id)).toHaveLength(0);
      expect(h.executions().filter((r) => r.outcome !== "completed")).toHaveLength(0);
    });
  }

  it("a second retry with the same transaction token adds no second reversal", async () => {
    const h = harness(CLAIMED, ["payments:payment.reverse"]);
    await commitWire(h);
    const wire = h.ledgerWire();
    const facts = await approve(h, await challenge(h, REVERSE));
    expect((await retry(h, REVERSE, facts)).ok).toBe(true);
    const again = await retry(h, REVERSE, facts);
    expect(again).toEqual({ ok: false, refusal_reason: "duplicate_suppressed" });
    expect(h.connectors.reversalEntries(MISSION_CLAIM.id)).toEqual([expect.objectContaining({ reversed_op_key: wire?.op_key })]);
  });

  it("a challenged ordinary operation still retries unchanged: the wire execute commits once with its invoice-form digest", async () => {
    const h = harness(CLAIMED, ["payments:payment.execute"]);
    const claims = await challenge(h, EXECUTE);
    expect(h.connectors.committedEffects()).toHaveLength(0);
    const facts = await approve(h, claims);
    const done = await retry(h, EXECUTE, facts);
    expect(done.ok, JSON.stringify(done)).toBe(true);
    expect(h.requests.at(-1)?.context.parameter_digest).toBe(claims.parameter_digest);
    expect(h.connectors.committedEffects()).toHaveLength(1);
    expect(await retry(h, EXECUTE, facts)).toEqual({ ok: false, refusal_reason: "duplicate_suppressed" });
    expect(h.connectors.committedEffects()).toHaveLength(1);
  });
});
