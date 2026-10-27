/**
 * @spec runtime#evaluation-context-binding, authzen#context-evaluation-binding,
 * runtime-evidence#execution-evidence-object, runtime-evidence#pre-decision-refusal
 * (#773): Evaluation-Context Binding through this resource's real PEP, its
 * three dispatch paths, its connectors and its evidence store, against a real
 * decision point bound to the same claimed declaration.
 *
 * The covered operations are `payments:payment.execute` (its preflight,
 * prepare and commit crossings take the read, write and transaction paths),
 * `payments:remittance.send` (the transaction path) and the compensate
 * crossing `payments:payment.reverse` (the transaction path, #252), whose
 * facts are the committed wire's. Every other operation is uncovered and
 * keeps its existing behavior.
 *
 * The FGA layer is a stub that always permits, so this file never skips.
 */

import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalDigest, EvaluationContextBindingDeclarations, type JsonValue, type ResourceContractRef } from "@mission/core";
import { RESOURCE_CONTRACTS, RUNTIME_SCOPE_CONFIG } from "@mission/demo-data";
import {
  createEphemeralDecisionPoint,
  type Decision,
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
  captureEvaluationContext,
  Connectors,
  createEphemeralEvidenceKeys,
  credentialAuthorityFrom,
  type DecisionEvidence,
  EvaluationContextSalts,
  EvidenceStore,
  type ExecutionEvidence,
  executionDivergence,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  operationKey,
  PaymentsStore,
  Pep,
  type RefusalRecord,
  type TokenFacts,
  TOOL_ACTIONS,
  TOOLS,
  TransactionEngine,
  type Vendor,
} from "../src/index.js";
import { ALL_ACTIONS_CREDENTIAL } from "./credential-fixtures.js";

const BASE_MS = Date.parse("2026-10-24T12:00:00.000Z");
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
const ISSUER = "https://as.test";

type Statement = Record<string, unknown> & { extensions: Record<string, unknown> };
const SHIPPED = RUNTIME_SCOPE_CONFIG as Statement;

/** The shipped declaration, claimed. */
const claimedStatement = (over: (s: Statement) => Statement = (s) => s): Statement =>
  over({ ...structuredClone(SHIPPED), claims: ["evaluation_context_binding"] });
const CLAIMED = new EvaluationContextBindingDeclarations(claimedStatement());
/** The shipped declaration with no claim: it covers nothing. */
const UNCLAIMED = new EvaluationContextBindingDeclarations({ ...structuredClone(SHIPPED), claims: [] });

interface DescriptorEntry {
  id: string;
  version: string;
  digest: string;
  document: Record<string, unknown>;
}

/**
 * The claimed declaration with `payments:payment.execute` moved to a new
 * descriptor version whose facts are unchanged: only the reference differs.
 */
function republishedPaymentDescriptor(opts: { retainOriginal?: boolean } = {}): EvaluationContextBindingDeclarations {
  const retainOriginal = opts.retainOriginal ?? true;
  return new EvaluationContextBindingDeclarations(
    claimedStatement((s) => {
      const ecb = s.extensions.evaluation_context_binding as {
        operations: Array<{ operation: string; descriptor: { id: string; version: string; digest: string } }>;
        descriptors: DescriptorEntry[];
      };
      const current = ecb.descriptors.find((d) => d.id.endsWith("/payment-execute")) as DescriptorEntry;
      const document = { ...current.document, version: "2026-10-25" };
      const digest = canonicalDigest(document as JsonValue);
      // The earlier version stays published (retained) or is withdrawn, so a
      // binding committed to it can, or cannot, still be recomputed under it.
      if (!retainOriginal) ecb.descriptors = ecb.descriptors.filter((d) => d !== current);
      ecb.descriptors.push({ id: current.id, version: "2026-10-25", digest, document });
      for (const o of ecb.operations) {
        if (o.operation === "payments:payment.execute") o.descriptor = { id: current.id, version: "2026-10-25", digest };
      }
      return s;
    }),
  );
}

const missionToken = (id: string): TokenFacts => ({
  sub: "alice",
  clientId: "ap-agent",
  clientInstanceId: "inst-1",
  mission: { id, issuer: ISSUER, authority_hash: `sha-256:${id}` },
  cnfJkt: "jkt-773",
  credentialAuthority: ALL_ACTIONS_CREDENTIAL,
});
const TOKEN = missionToken("msn_773");
const TOKEN_B = missionToken("msn_773b");

const view = (id: string, constraints: Record<string, unknown> = {}, contract?: ResourceContractRef): MissionView => ({
  id,
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: `sha-256:${id}`,
  authority_set: [
    {
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: [
        "payments:payment.execute",
        "payments:payment.reverse",
        "payments:remittance.send",
        "payments:payment.schedule",
        "payments:invoice.read",
      ],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"], ...constraints },
      ...(contract !== undefined ? { resource_contract: contract } : {}),
    },
  ] as MissionView["authority_set"],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
});

interface Harness {
  server: McpPaymentsServer;
  pep: Pep;
  payments: PaymentsStore;
  evidence: EvidenceStore;
  connectors: Connectors;
  /** Every decision request the PEP sent, in order. */
  requests: EvaluationRequest[];
  /** The context member of the last decision request. */
  lastContext: () => Record<string, unknown> | undefined;
  lastDecision: () => Decision | undefined;
  /** Replace the declaration the PEP reads from here on (the PDP's stays). */
  declareAtPep: (d: EvaluationContextBindingDeclarations) => void;
  /** The salt keeper the PEP reads now; `restart` replaces it with a fresh epoch. */
  salts: () => EvaluationContextSalts;
  restart: () => void;
  /** Rewrite each decision after the PDP returns it, before the PEP sees it. */
  rewrite: (fn: ((d: Decision) => Decision) | undefined) => void;
  /** Replace the Common Constraints on the Mission's entry from the next view on. */
  constrain: (c: Record<string, unknown> | undefined) => void;
}

function harness(
  o: {
    pep?: EvaluationContextBindingDeclarations;
    pdp?: EvaluationContextBindingDeclarations;
    /** The vendor record's tenant (#252 owner review). */
    tenant?: string;
    /** `inv-1`'s issuance instant and classification label. */
    issuedAt?: string;
    classification?: string;
    /** Common Constraints added to the Mission's entry. */
    constraints?: Record<string, unknown>;
    /** The resource contract the Mission's entry pins (#1693, D879). */
    contract?: ResourceContractRef;
  } = {},
): Harness {
  const now = () => new Date(BASE_MS);
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved", ...(o.tenant !== undefined ? { tenant: o.tenant } : {}) }],
    [
      {
        id: "inv-1",
        vendor_id: "acme",
        amount: "125.00",
        currency: "USD",
        payee_account: "acct-acme",
        status: "payable",
        ...(o.issuedAt !== undefined ? { issued_at: o.issuedAt } : {}),
        ...(o.classification !== undefined ? { classification: o.classification } : {}),
      },
      { id: "inv-2", vendor_id: "acme", amount: "75.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
    ],
  );
  let constraints = o.constraints;
  const loadView = (ref: { id: string; issuer: string }) =>
    (ref.id === "msn_773" || ref.id === "msn_773b") && ref.issuer === ISSUER
      ? { view: view(ref.id, constraints, o.contract), observation: { state: "active", version: 1, mode: "fresh", freshness_at: now().toISOString() } }
      : undefined;
  let pepKeys: EvidenceKeyResolver | undefined;
  const claims = openEphemeralClaimDomain({
    owner: RUNTIME_POSTURE.pdps[0] as string,
    statement: RUNTIME_POSTURE,
    now,
    settlementKeys: (params) => pepKeys?.(params),
  });
  const point = createEphemeralDecisionPoint({
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
    emitterId: CANONICAL_RESOURCE,
    audience: CANONICAL_RESOURCE,
    claims,
    evaluationContextBinding: o.pdp ?? CLAIMED,
  });
  const keys = createEphemeralEvidenceKeys({ decisionPoint: point });
  pepKeys = keys.resolver;
  const evidence = new EvidenceStore(keys.signing, keys.resolver);
  const connectors = new Connectors(now);
  const engine = new TransactionEngine("epoch-773", now);
  const requests: EvaluationRequest[] = [];
  let declarations = o.pep ?? CLAIMED;
  let salts = new EvaluationContextSalts();
  let rewrite: ((d: Decision) => Decision) | undefined;
  let decided: Decision | undefined;
  const pep = new Pep({
    decide: async (req, options) => {
      requests.push(req);
      const decision = await point.decide(req, options);
      return rewrite ? rewrite(decision) : decision;
    },
    observe: ({ decision }) => {
      decided = decision;
    },
    payments,
    evidence,
    // #252: the committed-effect records a compensate crossing reads.
    committedEffects: connectors,
    fga: alwaysAllowFga,
    modelId: "model-773",
    loadView,
    instanceEpoch: "epoch-773",
    now,
    evaluationContextBinding: () => declarations,
    evaluationContextSalts: () => salts,
  });
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
    jwks: { keys: [] },
    keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] },
    issuer: ISSUER,
    transaction: { engine, connectors, evidence },
    writeReservations: openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" }),
  });
  return {
    server,
    pep,
    payments,
    evidence,
    connectors,
    requests,
    lastContext: () => requests.at(-1)?.context as unknown as Record<string, unknown> | undefined,
    lastDecision: () => decided,
    declareAtPep: (d) => {
      declarations = d;
    },
    salts: () => salts,
    restart: () => {
      salts = new EvaluationContextSalts();
    },
    rewrite: (fn) => {
      rewrite = fn;
    },
    constrain: (c) => {
      constraints = c;
    },
  };
}

const executions = (h: Harness): ExecutionEvidence["content"][] =>
  h.evidence
    .all()
    .filter((e): e is ExecutionEvidence => e.kind === "execution")
    .map((e) => e.content);
const refusals = (h: Harness): RefusalRecord["content"][] =>
  h.evidence
    .all()
    .filter((e): e is RefusalRecord => e.kind === "refusal")
    .map((e) => e.content);
const decisions = (h: Harness): DecisionEvidence["content"][] =>
  h.evidence
    .all()
    .filter((e): e is DecisionEvidence => e.kind === "decision")
    .map((e) => e.content);

/** Every covered crossing, with the dispatch path it takes. */
const COVERED = [
  { tool: "check_transfer", phase: "preflight", path: "read" },
  { tool: "hold_transfer", phase: "prepare", path: "write" },
  { tool: "execute_wire_transfer", phase: "commit", path: "transaction" },
  { tool: "send_remittance_email", phase: undefined, path: "transaction" },
] as const;
type Crossing = (typeof COVERED)[number];

async function cross(
  h: Harness,
  c: Crossing,
  hook?: () => void,
  invoiceId = "inv-1",
  token: TokenFacts = TOKEN,
): Promise<{ ok: boolean; refusal_reason?: string; denial_reason?: string; result?: unknown }> {
  const args =
    c.path === "transaction" ? { invoice_id: invoiceId, idempotency_key: `idem_${randomUUID()}` } : { invoice_id: invoiceId };
  if (c.path === "read") return h.server.callReadTool(c.tool, args, token, hook);
  if (c.path === "write") return h.server.callWriteTool(c.tool, args, token, hook);
  return h.server.callTransactionTool(c.tool, args, token, hook);
}

const COMMIT = COVERED[2];
const PREPARE = COVERED[1];
const PREFLIGHT = COVERED[0];

describe("Evaluation-Context Binding at the PEP (@spec runtime#evaluation-context-binding, authzen#context-evaluation-binding, #773)", () => {
  it("a covered crossing sends the context digest and the descriptor reference, and executes when the context is unchanged", async () => {
    const h = harness();
    const done = await cross(h, COMMIT);
    expect(done.ok, JSON.stringify(done)).toBe(true);
    const context = h.lastContext() ?? {};
    expect(context.evaluation_context_digest).toMatch(/^sha-256:[A-Za-z0-9_-]{43}$/);
    const declared = CLAIMED.operation("payments:payment.execute", "commit")?.descriptor;
    expect(context.evaluation_context_binding).toEqual(declared);
    // The salt never rides the request.
    expect(JSON.stringify(h.requests.at(-1))).not.toMatch(/"salt/);
    expect((h.lastDecision()?.context.conditions as Record<string, unknown>).evaluation_context_digest).toBe(
      context.evaluation_context_digest,
    );
    // The completed record carries the context pair, both observed and equal.
    const [completed] = executions(h);
    expect(completed?.outcome).toBe("completed");
    expect(completed?.authorized_evaluation_context_digest).toBe(context.evaluation_context_digest);
    expect(completed?.effective_evaluation_context_digest).toBe(context.evaluation_context_digest);
    expect(h.connectors.committedEffects()).toHaveLength(1);
  });

  it("the decision request of a covered crossing carries the context digest and the descriptor reference, built by the PEP alone", async () => {
    const payments = new PaymentsStore();
    payments.seed(
      [{ id: "acme", name: "Acme", status: "approved" }],
      [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
    );
    const keys = createEphemeralEvidenceKeys({ resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE });
    const asked: EvaluationRequest[] = [];
    // A decision function that records the request and decides nothing: the
    // members are the PEP's own construction, before any PDP sees them.
    const pep = new Pep({
      decide: async (req) => {
        asked.push(req);
        throw new Error("no decision in this test");
      },
      payments,
      evidence: new EvidenceStore(keys.signing, keys.resolver),
      fga: alwaysAllowFga,
      modelId: "model-773",
      loadView: (ref) =>
        ref.id === "msn_773" && ref.issuer === ISSUER
          ? { view: view("msn_773"), observation: { state: "active", version: 1, mode: "fresh", freshness_at: new Date(BASE_MS).toISOString() } }
          : undefined,
      instanceEpoch: "epoch-773-unit",
      now: () => new Date(BASE_MS),
      evaluationContextBinding: () => CLAIMED,
    });
    await pep.enforce("hold_transfer", { invoice_id: "inv-1" }, TOKEN);
    await pep.enforce("get_invoice", { invoice_id: "inv-1" }, TOKEN);
    const [covered, uncovered] = asked.map((r) => r.context as unknown as Record<string, unknown>);
    expect(covered?.evaluation_context_digest).toMatch(/^sha-256:[A-Za-z0-9_-]{43}$/);
    expect(covered?.evaluation_context_binding).toEqual(CLAIMED.operation("payments:payment.execute", "prepare")?.descriptor);
    expect(uncovered).not.toHaveProperty("evaluation_context_digest");
    expect(uncovered).not.toHaveProperty("evaluation_context_binding");
  });

  it("the descriptor reference is committed inside the digest with the Mission, the operation, the targets, the facts and the salt", () => {
    const payments = new PaymentsStore();
    payments.seed(
      [{ id: "acme", name: "Acme", status: "approved" }],
      [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
    );
    const salts = new EvaluationContextSalts();
    const mission = { issuer: ISSUER, id: "msn_773" };
    const operation = { action: "payments:payment.execute", phase: "commit" };
    const captured = captureEvaluationContext({ declarations: CLAIMED, salts, mission, operation, invoiceId: "inv-1", payments });
    if (!captured.ok) throw new Error(`capture failed: ${captured.reason}`);
    const version = salts.current() as string;
    const reference = CLAIMED.operation("payments:payment.execute", "commit")?.descriptor;
    const committed = {
      descriptor: reference,
      mission,
      operation,
      targets: [
        { type: "invoice", id: "inv-1" },
        { type: "vendor", id: "acme" },
      ],
      facts: {
        invoice_revision: 1,
        vendor_id: "acme",
        vendor_revision: 1,
        amount: { amount: "125.00", currency: "USD" },
        payee_account: "acct-acme",
      },
      salt: salts.saltFor(version, mission),
      salt_version: version,
    };
    expect(captured.digest).toBe(canonicalDigest(committed as unknown as JsonValue));
    // The same facts under a republished descriptor commit a different digest:
    // an Operation Profile update cannot reinterpret an outstanding permit.
    const republished = captureEvaluationContext({
      declarations: republishedPaymentDescriptor(),
      salts,
      mission,
      operation,
      invoiceId: "inv-1",
      payments,
    });
    if (!republished.ok) throw new Error("republished capture failed");
    expect(republished.held.reference.version).toBe("2026-10-25");
    expect(republished.digest).not.toBe(captured.digest);
  });

  it("agent-supplied values never enter the capture: the facts are the store's, whatever the arguments carry", async () => {
    const h = harness();
    // Past intake, as a caller of the PEP itself: arguments naming the
    // authoritative facts are not read.
    const asked = await h.pep.enforce(
      "execute_wire_transfer",
      { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}`, amount: "1.00", payee_account: "acct-attacker", invoice_version: 99 },
      TOKEN,
    );
    expect(asked.permitted, JSON.stringify(asked)).toBe(true);
    const fromArguments = h.lastContext()?.evaluation_context_digest;
    const plain = await h.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` }, TOKEN);
    expect(plain.permitted).toBe(true);
    expect(h.lastContext()?.evaluation_context_digest).toBe(fromArguments);
    // A change to the store's own record is a different context.
    h.payments.bumpInvoiceAmount("inv-1", "130.00");
    await h.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` }, TOKEN);
    expect(h.lastContext()?.evaluation_context_digest).not.toBe(fromArguments);
  });

  it("an unresolvable fact or an unavailable salt refuses before the decision request, as a Refusal Record evaluation_context_unresolvable", async () => {
    const h = harness();
    // A declared fact the store cannot resolve: the invoice names no payee.
    h.payments.db.prepare("UPDATE invoices SET payee_account = '' WHERE id = ?").run("inv-1");
    const unresolved = await cross(h, COMMIT);
    expect(unresolved).toEqual({ ok: false, refusal_reason: "evaluation_context_unresolvable" });
    // No salt version is live for new bindings.
    const current = h.salts().current() as string;
    h.salts().invalidate(current);
    const unsalted = await cross(h, PREPARE, undefined, "inv-2");
    expect(unsalted).toEqual({ ok: false, refusal_reason: "evaluation_context_unresolvable" });
    // Neither reached the PDP, and each left one signed Refusal Record.
    expect(h.requests).toHaveLength(0);
    expect(decisions(h)).toHaveLength(0);
    expect(executions(h)).toHaveLength(0);
    expect(refusals(h).map((r) => r.denial_reason)).toEqual(["evaluation_context_unresolvable", "evaluation_context_unresolvable"]);
    expect(refusals(h).map((r) => r.resource)).toEqual([
      { type: "invoice", id: "inv-1" },
      { type: "invoice", id: "inv-2" },
    ]);
  });
});

describe("the primary error of a context failure at use, with every available digest pair recorded (@spec runtime-evidence#execution-evidence-object, runtime#evaluation-context-binding, #773)", () => {
  it("a moved authoritative fact on a covered operation is target_drift: zero effects, both digest pairs recorded and each unequal", async () => {
    const h = harness();
    const refused = await cross(h, COMMIT, () => h.payments.bumpInvoiceAmount("inv-1", "480.00"));
    expect(refused).toEqual({ ok: false, refusal_reason: "target_drift" });
    expect(h.connectors.committedEffects()).toHaveLength(0);
    expect(refusals(h)).toHaveLength(0);
    const [record] = executions(h);
    expect(record?.outcome).toBe("suppressed");
    expect(record?.error).toBe("target_drift");
    const [decision] = decisions(h);
    expect(record?.authorized_parameter_digest).toBe(decision?.parameter_digest);
    expect(record?.effective_parameter_digest).toBeDefined();
    expect(record?.effective_parameter_digest).not.toBe(record?.authorized_parameter_digest);
    expect(record?.authorized_evaluation_context_digest).toBe(decision?.evaluation_context_digest);
    expect(record?.effective_evaluation_context_digest).toBeDefined();
    expect(record?.effective_evaluation_context_digest).not.toBe(record?.authorized_evaluation_context_digest);
  });

  it("an agent-supplied parameter that changed is parameter_mismatch, with both digest pairs recorded", async () => {
    const h = harness();
    const permit = await h.pep.enforce("hold_transfer", { invoice_id: "inv-1" }, TOKEN);
    if (!permit.permitted || !permit.attempt || !permit.effective) throw new Error(JSON.stringify(permit));
    // The parameters about to be used name another invoice than the permit.
    permit.effective.invoice_id = "inv-2";
    expect(await h.pep.verifyPermitAtUse(permit.attempt)).toMatchObject({ ok: false, error: "parameter_mismatch" });
    const [record] = executions(h);
    expect(record?.error).toBe("parameter_mismatch");
    expect(record?.effective_parameter_digest).not.toBe(record?.authorized_parameter_digest);
    expect(record?.effective_evaluation_context_digest).toBeDefined();
    expect(record?.effective_evaluation_context_digest).not.toBe(record?.authorized_evaluation_context_digest);
  });

  it("an agent-supplied parameter that changed while an authoritative fact also moved is parameter_mismatch, and the context divergence is still recorded", async () => {
    const h = harness();
    const permit = await h.pep.enforce("hold_transfer", { invoice_id: "inv-1" }, TOKEN);
    if (!permit.permitted || !permit.attempt || !permit.effective) throw new Error(JSON.stringify(permit));
    permit.effective.invoice_id = "inv-2";
    h.payments.bumpInvoiceAmount("inv-2", "76.00");
    expect(await h.pep.verifyPermitAtUse(permit.attempt)).toMatchObject({ ok: false, error: "parameter_mismatch" });
    const [record] = executions(h);
    expect(record?.effective_parameter_digest).not.toBe(record?.authorized_parameter_digest);
    expect(record?.effective_evaluation_context_digest).not.toBe(record?.authorized_evaluation_context_digest);
    expect(record?.effective_evaluation_context_digest).toBeDefined();
  });

  it("an unavailable context is target_drift even where an agent-supplied parameter also changed, and the parameter divergence is still recorded", async () => {
    const h = harness();
    const permit = await h.pep.enforce("hold_transfer", { invoice_id: "inv-1" }, TOKEN);
    if (!permit.permitted || !permit.attempt || !permit.effective) throw new Error(JSON.stringify(permit));
    permit.effective.invoice_id = "inv-2";
    h.restart();
    expect(await h.pep.verifyPermitAtUse(permit.attempt)).toMatchObject({ ok: false, error: "target_drift" });
    const [record] = executions(h);
    expect(record?.error).toBe("target_drift");
    expect(record?.effective_parameter_digest).toBeDefined();
    expect(record?.effective_parameter_digest).not.toBe(record?.authorized_parameter_digest);
    expect(record?.authorized_evaluation_context_digest).toBeDefined();
    expect(record).not.toHaveProperty("effective_evaluation_context_digest");
  });

  it("a declared fact that stops resolving at use is target_drift with no effective context digest, though the parameters still resolve", async () => {
    const h = harness();
    const refused = await cross(h, COMMIT, () =>
      h.payments.db.prepare("UPDATE invoices SET payee_account = '' WHERE id = ?").run("inv-1"),
    );
    expect(refused).toEqual({ ok: false, refusal_reason: "target_drift" });
    expect(h.connectors.committedEffects()).toHaveLength(0);
    const [record] = executions(h);
    expect(record?.error).toBe("target_drift");
    expect(record?.effective_parameter_digest).toBeDefined();
    expect(record).not.toHaveProperty("effective_evaluation_context_digest");
  });

  it("an unavailable fact is target_drift, with no invented comparison: both effective digests absent, both authorized digests kept", async () => {
    const h = harness();
    const refused = await cross(h, COMMIT, () => h.payments.db.prepare("DELETE FROM invoices WHERE id = ?").run("inv-1"));
    expect(refused).toEqual({ ok: false, refusal_reason: "target_drift" });
    expect(h.connectors.committedEffects()).toHaveLength(0);
    const [record] = executions(h);
    expect(record?.error).toBe("target_drift");
    expect(record?.authorized_parameter_digest).toBeDefined();
    expect(record?.authorized_evaluation_context_digest).toBeDefined();
    expect(record).not.toHaveProperty("effective_parameter_digest");
    expect(record).not.toHaveProperty("effective_evaluation_context_digest");
  });

  it("unchanged facts under a changed descriptor are refused by the descriptor-change check, with the effective context digest computed under the retained original and equal to the authorized one", async () => {
    // The declaration names a new descriptor version for the operation; the
    // original stays published. And a declaration that no longer covers the
    // crossing at all.
    for (const declaration of [republishedPaymentDescriptor(), UNCLAIMED]) {
      const h = harness();
      const refused = await cross(h, COMMIT, () => h.declareAtPep(declaration));
      expect(refused).toEqual({ ok: false, refusal_reason: "target_drift" });
      expect(h.connectors.committedEffects()).toHaveLength(0);
      const [record] = executions(h);
      expect(record?.error).toBe("target_drift");
      expect(record?.effective_parameter_digest).toBe(record?.authorized_parameter_digest);
      // Comparable: computed under the committed descriptor and salt version.
      expect(record?.authorized_evaluation_context_digest).toBeDefined();
      expect(record?.effective_evaluation_context_digest).toBe(record?.authorized_evaluation_context_digest);
      // So the audit classification reports no divergence: the refusal is the
      // descriptor change, not context drift.
      expect(executionDivergence(record as ExecutionEvidence["content"])).toEqual({});
    }
  });

  it("a fact that moved under a changed descriptor diverges under the retained original and is target_drift", async () => {
    const h = harness();
    const refused = await cross(h, COMMIT, () => {
      h.declareAtPep(republishedPaymentDescriptor());
      h.payments.bumpInvoiceAmount("inv-1", "130.00");
    });
    expect(refused).toEqual({ ok: false, refusal_reason: "target_drift" });
    expect(h.connectors.committedEffects()).toHaveLength(0);
    const [record] = executions(h);
    expect(record?.error).toBe("target_drift");
    // The effective digest is the moved facts committed under the ORIGINAL
    // descriptor and the binding's salt version, never under the new one.
    const operation = { action: "payments:payment.execute", phase: "commit" };
    const mission = { issuer: ISSUER, id: "msn_773" };
    const underOriginal = captureEvaluationContext({ declarations: CLAIMED, salts: h.salts(), mission, operation, invoiceId: "inv-1", payments: h.payments });
    const underLive = captureEvaluationContext({ declarations: republishedPaymentDescriptor(), salts: h.salts(), mission, operation, invoiceId: "inv-1", payments: h.payments });
    if (!underOriginal.ok || !underLive.ok) throw new Error("capture failed");
    expect(record?.effective_evaluation_context_digest).toBe(underOriginal.digest);
    expect(record?.effective_evaluation_context_digest).not.toBe(underLive.digest);
    expect(record?.effective_evaluation_context_digest).not.toBe(record?.authorized_evaluation_context_digest);
    expect(executionDivergence(record as ExecutionEvidence["content"])).toEqual({ parameter: true, evaluation_context: true });
  });

  it("an unrecoverable descriptor or salt is target_drift with the effective context digest absent and the parameter pair kept", async () => {
    // The committed descriptor is no longer published: the original cannot be
    // recovered, so no comparison is made under any substitute.
    const withdrawn = harness();
    expect(await cross(withdrawn, COMMIT, () => withdrawn.declareAtPep(republishedPaymentDescriptor({ retainOriginal: false })))).toEqual({
      ok: false,
      refusal_reason: "target_drift",
    });
    // The salt version the binding was made under is gone.
    const restarted = harness();
    expect(await cross(restarted, COMMIT, () => restarted.restart())).toEqual({ ok: false, refusal_reason: "target_drift" });
    for (const h of [withdrawn, restarted]) {
      expect(h.connectors.committedEffects()).toHaveLength(0);
      const [record] = executions(h);
      expect(record?.error).toBe("target_drift");
      expect(record?.effective_parameter_digest).toBe(record?.authorized_parameter_digest);
      expect(record?.authorized_evaluation_context_digest).toBeDefined();
      expect(record).not.toHaveProperty("effective_evaluation_context_digest");
    }
  });
});

describe("every phase captures and checks its own context, on every dispatch path (@spec runtime#evaluation-context-binding, runtime#compound-actions, #773)", () => {
  it("each crossing of the compound action commits its own phase: one parameter digest, three distinct context digests", async () => {
    const h = harness();
    const sent: Array<{ parameter: unknown; context: unknown }> = [];
    for (const c of [PREFLIGHT, PREPARE, COMMIT]) {
      const done = await cross(h, c);
      expect(done.ok, `${c.tool}: ${JSON.stringify(done)}`).toBe(true);
      const context = h.lastContext() ?? {};
      expect(context.action_phase).toBe(c.phase);
      sent.push({ parameter: context.parameter_digest, context: context.evaluation_context_digest });
    }
    expect(new Set(sent.map((s) => s.parameter)).size).toBe(1);
    expect(new Set(sent.map((s) => s.context)).size).toBe(3);
  });

  for (const c of COVERED) {
    it(`a fact moved in ${c.tool}'s own window is refused target_drift on the ${c.path} path, with zero effects`, async () => {
      const h = harness();
      const refused = await cross(h, c, () => h.payments.bumpInvoiceAmount("inv-1", "490.00"));
      expect(refused).toEqual({ ok: false, refusal_reason: "target_drift" });
      expect(refused).not.toHaveProperty("result");
      expect(h.connectors.committedEffects()).toHaveLength(0);
      expect(executions(h).map((r) => r.error)).toEqual(["target_drift"]);
    });
  }

  it("a commit permit whose context condition is the prepare crossing's binding is refused target_drift", async () => {
    const h = harness();
    expect((await cross(h, PREPARE)).ok).toBe(true);
    const prepared = h.lastContext()?.evaluation_context_digest;
    h.rewrite((d) => ({
      ...d,
      context: { ...d.context, conditions: { ...(d.context.conditions as object), evaluation_context_digest: prepared } },
    }));
    expect(await cross(h, COMMIT)).toEqual({ ok: false, refusal_reason: "target_drift" });
    expect(h.connectors.committedEffects()).toHaveLength(0);
  });
});

describe("a completed disposition carries the context pair, or is the reported gap (@spec runtime-evidence#execution-evidence-object, #773)", () => {
  for (const c of COVERED) {
    it(`the completed record of ${c.tool} (${c.path} path) mirrors the decided context digest and carries the context re-established before release`, async () => {
      const h = harness();
      const done = await cross(h, c);
      expect(done.ok, JSON.stringify(done)).toBe(true);
      const [decision] = decisions(h);
      expect(decision?.evaluation_context_digest).toMatch(/^sha-256:[A-Za-z0-9_-]{43}$/);
      const completed = executions(h);
      expect(completed.map((r) => r.outcome)).toEqual(["completed"]);
      expect(completed[0]?.authorized_evaluation_context_digest).toBe(decision?.evaluation_context_digest);
      // Re-established under the committed descriptor and salt version, and
      // equal, since nothing moved before release.
      expect(completed[0]?.effective_evaluation_context_digest).toBe(decision?.evaluation_context_digest);
      expect(executionDivergence(completed[0] as ExecutionEvidence["content"])).toEqual({});
    });
  }

  it("a completed disposition whose context cannot be re-established is the reported gap, never a record without the effective context digest", async () => {
    // The control: the same disposition records the pair when the context
    // re-establishes.
    const control = harness();
    const held = await control.pep.enforce("hold_transfer", { invoice_id: "inv-1" }, TOKEN);
    if (!held.permitted || !held.attempt) throw new Error(JSON.stringify(held));
    expect(await control.pep.completeExecution(held.attempt)).toEqual({ recorded: true });
    expect(executions(control)[0]?.effective_evaluation_context_digest).toBe(
      executions(control)[0]?.authorized_evaluation_context_digest,
    );
    // The salt version is lost after the permit: the parameters still resolve,
    // the context does not.
    const h = harness();
    const permit = await h.pep.enforce("hold_transfer", { invoice_id: "inv-1" }, TOKEN);
    if (!permit.permitted || !permit.attempt) throw new Error(JSON.stringify(permit));
    h.restart();
    expect(await h.pep.completeExecution(permit.attempt)).toEqual({
      recorded: false,
      gap: "effective_evaluation_context_digest_unobservable",
    });
    expect(executions(h)).toHaveLength(0);
  });
});

/** The compensate crossing (#252): it offsets the wire `COMMIT` released. */
const REVERSE = "reverse_wire_transfer";
const reverseOperation = { action: "payments:payment.reverse", phase: "compensate" };

/** Commit the wire, then cross the compensation with `hook` in its decision-to-commit window. */
async function reverse(
  h: Harness,
  hook?: () => void,
): Promise<{ ok: boolean; refusal_reason?: string; denial_reason?: string; result?: unknown }> {
  const committed = await cross(h, COMMIT);
  if (!committed.ok) throw new Error(JSON.stringify(committed));
  return h.server.callTransactionTool(REVERSE, { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` }, TOKEN, hook);
}

/** The compensation's own Decision Evidence: the one carrying the link. */
const compensating = (h: Harness): DecisionEvidence["content"] | undefined =>
  decisions(h).find((d) => d.compensates_evaluation_id !== undefined);

/** A capture of the compensate crossing computed independently from the committed wire's ledger record. */
function captureFromWire(h: Harness, decision: DecisionEvidence["content"] | undefined) {
  const wire = decisions(h).find((d) => d.evaluation_id === decision?.compensates_evaluation_id);
  if (!wire || typeof wire.parameter_digest !== "string") throw new Error("no committed wire decision");
  const opKey = operationKey("msn_773", "payments:payment.execute", wire.parameter_digest, "commit");
  return captureEvaluationContext({
    declarations: CLAIMED,
    salts: h.salts(),
    mission: { issuer: ISSUER, id: "msn_773" },
    operation: reverseOperation,
    invoiceId: "inv-1",
    payments: h.payments,
    compensates: { opKey, evaluationId: wire.evaluation_id },
    committedEffects: h.connectors,
  });
}

describe("the compensate crossing captures and checks its own context, from the committed wire (@spec runtime#evaluation-context-binding, runtime#compound-actions, authzen#context-compensation-link, #773, #252)", () => {
  it("captures at the compensate crossing: the request carries compensates_evaluation_id beside the context digest and descriptor, and the completed record carries the pair", async () => {
    const h = harness();
    const done = await reverse(h);
    expect(done.ok, JSON.stringify(done)).toBe(true);
    const context = h.lastContext() ?? {};
    expect(context.action_phase).toBe("compensate");
    expect(context.compensates_evaluation_id).toMatch(/\S/);
    expect(context.evaluation_context_digest).toMatch(/^sha-256:[A-Za-z0-9_-]{43}$/);
    expect(context.evaluation_context_binding).toEqual(CLAIMED.operation("payments:payment.reverse", "compensate")?.descriptor);
    const decision = compensating(h);
    expect(decision?.evaluation_context_digest).toBe(context.evaluation_context_digest);
    expect(decision?.compensates_evaluation_id).toBe(context.compensates_evaluation_id);
    // The completed reversal record carries the pair, observed and equal.
    const completed = executions(h).filter((r) => r.outcome === "completed" && r.evaluation_id === decision?.evaluation_id);
    expect(completed).toHaveLength(1);
    expect(completed[0]?.authorized_evaluation_context_digest).toBe(context.evaluation_context_digest);
    expect(completed[0]?.effective_evaluation_context_digest).toBe(context.evaluation_context_digest);
    expect(h.connectors.reversalEntries("msn_773")).toHaveLength(1);
  });

  it("the descriptor's facts are the committed wire's, not the invoice as it reads now: an invoice that moved after the wire, and again before release, leaves the context unchanged", async () => {
    const h = harness();
    expect((await cross(h, COMMIT)).ok).toBe(true);
    // The invoice moves after its wire committed, before the compensation.
    h.payments.bumpInvoiceAmount("inv-1", "1.00");
    const done = await h.server.callTransactionTool(
      REVERSE,
      { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` },
      TOKEN,
      () => h.payments.bumpInvoiceAmount("inv-1", "2.00"),
    );
    expect(done.ok, JSON.stringify(done)).toBe(true);
    const decision = compensating(h);
    const fromWire = captureFromWire(h, decision);
    if (!fromWire.ok) throw new Error(JSON.stringify(fromWire));
    // The digest sent is the committed wire's facts, committed under the same
    // salt version: the USD 125 the wire paid, not the invoice's USD 1 or 2.
    expect(decision?.evaluation_context_digest).toBe(fromWire.digest);
    const completed = executions(h).find((r) => r.outcome === "completed" && r.evaluation_id === decision?.evaluation_id);
    expect(completed?.effective_evaluation_context_digest).toBe(fromWire.digest);
    // The effect parameters are the wire's too: the reversal form the
    // Decision bound is the one re-derived and offset at release.
    expect(completed?.authorized_parameter_digest).toBe(decision?.parameter_digest);
    expect(completed?.effective_parameter_digest).toBe(decision?.parameter_digest);
    expect(h.connectors.reversalEntries("msn_773")).toEqual([expect.objectContaining({ amount: "125.00", currency: "USD" })]);
  });

  it("a moved fact of the committed wire's record is target_drift with zero effects, both digest pairs recorded and each unequal", async () => {
    const h = harness();
    const refused = await reverse(h, () => {
      h.connectors.db.prepare("UPDATE ledger SET amount = '99.00' WHERE invoice_id = 'inv-1'").run();
    });
    expect(refused).toEqual({ ok: false, refusal_reason: "target_drift" });
    expect(h.connectors.reversalEntries("msn_773")).toHaveLength(0);
    const decision = compensating(h);
    const [record] = executions(h).filter((r) => r.outcome === "suppressed");
    expect(record?.error).toBe("target_drift");
    expect(record?.authorized_parameter_digest).toBe(decision?.parameter_digest);
    expect(record?.effective_parameter_digest).toBeDefined();
    expect(record?.effective_parameter_digest).not.toBe(record?.authorized_parameter_digest);
    expect(record?.authorized_evaluation_context_digest).toBe(decision?.evaluation_context_digest);
    expect(record?.effective_evaluation_context_digest).toBeDefined();
    expect(record?.effective_evaluation_context_digest).not.toBe(record?.authorized_evaluation_context_digest);
    expect(executionDivergence(record as ExecutionEvidence["content"])).toEqual({ parameter: true, evaluation_context: true });
  });

  it("a committed wire record that no longer answers is target_drift, with both effective digests absent and both authorized digests kept", async () => {
    const h = harness();
    const refused = await reverse(h, () => {
      h.connectors.db.prepare("DELETE FROM ledger WHERE invoice_id = 'inv-1'").run();
    });
    expect(refused).toEqual({ ok: false, refusal_reason: "target_drift" });
    expect(h.connectors.reversalEntries("msn_773")).toHaveLength(0);
    const [record] = executions(h).filter((r) => r.outcome === "suppressed");
    expect(record?.error).toBe("target_drift");
    expect(record?.authorized_parameter_digest).toBeDefined();
    expect(record?.authorized_evaluation_context_digest).toBeDefined();
    expect(record).not.toHaveProperty("effective_parameter_digest");
    expect(record).not.toHaveProperty("effective_evaluation_context_digest");
  });

  it("a compensation binding made before a restart is refused before any effect: target_drift, no effective context digest", async () => {
    const h = harness();
    const refused = await reverse(h, () => h.restart());
    expect(refused).toEqual({ ok: false, refusal_reason: "target_drift" });
    expect(h.connectors.reversalEntries("msn_773")).toHaveLength(0);
    const [record] = executions(h).filter((r) => r.outcome === "suppressed");
    expect(record?.error).toBe("target_drift");
    expect(record?.authorized_evaluation_context_digest).toBeDefined();
    expect(record).not.toHaveProperty("effective_evaluation_context_digest");
  });

  it("a deployment that does not claim the extension is unchanged at the compensate crossing: no context members, and a moved fact of the wire's record stays parameter_mismatch", async () => {
    const h = harness({ pep: UNCLAIMED, pdp: UNCLAIMED });
    const refused = await reverse(h, () => {
      h.connectors.db.prepare("UPDATE ledger SET amount = '99.00' WHERE invoice_id = 'inv-1'").run();
    });
    expect(refused).toEqual({ ok: false, refusal_reason: "parameter_mismatch" });
    expect(h.lastContext()).not.toHaveProperty("evaluation_context_digest");
    expect(h.lastContext()?.compensates_evaluation_id).toMatch(/\S/);
    expect(h.connectors.reversalEntries("msn_773")).toHaveLength(0);
    const [record] = executions(h).filter((r) => r.outcome === "suppressed");
    expect(record?.error).toBe("parameter_mismatch");
    expect(record).not.toHaveProperty("authorized_evaluation_context_digest");
  });
});

/** A suppressed compensation whose live resource fact moved: parameters unchanged, context unequal, zero effects. */
function expectLiveFactDrift(h: Harness, refused: { ok: boolean; refusal_reason?: string }): void {
  expect(refused).toEqual({ ok: false, refusal_reason: "target_drift" });
  expect(h.connectors.reversalEntries("msn_773")).toHaveLength(0);
  const decision = compensating(h);
  expect(decision?.decision).toBe("permit");
  const [record] = executions(h).filter((r) => r.outcome === "suppressed");
  expect(record?.error).toBe("target_drift");
  // The parameter pair: the wire's reversal form, re-derived and unchanged.
  expect(record?.authorized_parameter_digest).toBe(decision?.parameter_digest);
  expect(record?.effective_parameter_digest).toBe(record?.authorized_parameter_digest);
  // The context pair: the moved live fact.
  expect(record?.authorized_evaluation_context_digest).toBe(decision?.evaluation_context_digest);
  expect(record?.effective_evaluation_context_digest).toBeDefined();
  expect(record?.effective_evaluation_context_digest).not.toBe(record?.authorized_evaluation_context_digest);
  expect(executionDivergence(record as ExecutionEvidence["content"])).toEqual({ evaluation_context: true });
}

describe("the compensate crossing binds the live resource facts its decision evaluates (@spec runtime#evaluation-context-binding, runtime#compound-actions, resource-access#initial-common-constraints, #773, #252)", () => {
  it("the owner's case: a reversal approved while the vendor belongs to tenant-a, moved to tenant-b before release, is refused target_drift with zero effects", async () => {
    const h = harness({ tenant: "tenant-a", constraints: { tenant: "tenant-a" } });
    expectLiveFactDrift(h, await reverse(h, () => h.payments.setVendorTenant("acme", "tenant-b")));
    // The control: the same move before the decision is refused by the bound.
    const control = harness({ tenant: "tenant-a", constraints: { tenant: "tenant-a" } });
    expect((await cross(control, COMMIT)).ok).toBe(true);
    control.payments.setVendorTenant("acme", "tenant-b");
    const denied = await control.server.callTransactionTool(REVERSE, { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` }, TOKEN);
    expect(denied).toMatchObject({ ok: false, denial_reason: "parameter_violation" });
    expect(control.connectors.reversalEntries("msn_773")).toHaveLength(0);
  });

  it("an invoice whose issuance moved outside the approved bound before release is refused target_drift with zero effects", async () => {
    const h = harness({ issuedAt: "2026-08-15T00:00:00Z", constraints: { resource_issued_after: "2026-07-01T00:00:00Z" } });
    expectLiveFactDrift(h, await reverse(h, () => h.payments.setInvoiceIssuedAt("inv-1", "2026-06-01T00:00:00Z")));
  });

  it("an invoice whose classification moved outside the approved bound before release is refused target_drift with zero effects", async () => {
    const h = harness({ classification: "internal", constraints: { data_classification: ["internal"] } });
    expectLiveFactDrift(h, await reverse(h, () => h.payments.setInvoiceClassification("inv-1", "restricted")));
  });

  for (const [record, remove] of [
    ["invoice", (h: Harness) => h.payments.db.prepare("DELETE FROM invoices WHERE id = 'inv-1'").run()],
    ["vendor", (h: Harness) => h.payments.db.prepare("DELETE FROM vendors WHERE id = 'acme'").run()],
  ] as const) {
    it(`the ${record} record removed between the decision and release is refused target_drift with zero effects, the wire's parameter pair kept and no effective context digest`, async () => {
      const h = harness();
      const refused = await reverse(h, () => remove(h));
      expect(refused).toEqual({ ok: false, refusal_reason: "target_drift" });
      expect(h.connectors.reversalEntries("msn_773")).toHaveLength(0);
      const decision = compensating(h);
      expect(decision?.decision).toBe("permit");
      const [suppressed] = executions(h).filter((r) => r.outcome === "suppressed");
      expect(suppressed?.error).toBe("target_drift");
      expect(suppressed?.authorized_parameter_digest).toBe(decision?.parameter_digest);
      expect(suppressed?.effective_parameter_digest).toBe(suppressed?.authorized_parameter_digest);
      expect(suppressed?.authorized_evaluation_context_digest).toBe(decision?.evaluation_context_digest);
      expect(suppressed).not.toHaveProperty("effective_evaluation_context_digest");
    });
  }

  it("the compensate crossing reads no effect fact from the store: a descriptor naming the invoice's amount for it does not capture", () => {
    const payments = new PaymentsStore();
    payments.seed(
      [{ id: "acme", name: "Acme", status: "approved" }],
      [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
    );
    const connectors = new Connectors(() => new Date(BASE_MS));
    connectors.postWire({
      opKey: "op-wire",
      invoiceId: "inv-1",
      vendorId: "acme",
      payeeAccount: "acct-acme",
      amount: "125.00",
      currency: "USD",
      permitId: "evl-wire",
      missionId: "msn_773",
    });
    const storeAmount = new EvaluationContextBindingDeclarations(
      claimedStatement((st) => {
        const ecb = st.extensions.evaluation_context_binding as {
          operations: Array<{ operation: string; descriptor: { id: string; version: string; digest: string } }>;
          descriptors: DescriptorEntry[];
        };
        const current = ecb.descriptors.find((d) => d.id.endsWith("/payment-reverse")) as DescriptorEntry;
        const facts = (current.document.facts as Array<Record<string, unknown>>).map((f) =>
          f.name === "amount" ? { ...f, resolver: "payments-store:invoice.amount" } : f,
        );
        const document = { ...current.document, version: "2026-10-25-store-amount", facts };
        const digest = canonicalDigest(document as JsonValue);
        ecb.descriptors.push({ id: current.id, version: "2026-10-25-store-amount", digest, document });
        for (const op of ecb.operations) {
          if (op.operation === "payments:payment.reverse") op.descriptor = { id: current.id, version: "2026-10-25-store-amount", digest };
        }
        return st;
      }),
    );
    const capture = (declarations: EvaluationContextBindingDeclarations) =>
      captureEvaluationContext({
        declarations,
        salts: new EvaluationContextSalts(),
        mission: { issuer: ISSUER, id: "msn_773" },
        operation: reverseOperation,
        invoiceId: "inv-1",
        payments,
        compensates: { opKey: "op-wire", evaluationId: "evl-wire" },
        committedEffects: connectors,
      });
    expect(capture(CLAIMED).ok).toBe(true);
    expect(capture(storeAmount)).toEqual({ ok: false, reason: "fact_unresolvable" });
  });
});

describe("a compensating decision and its context are one observation of the live facts (@spec runtime#evaluation-context-binding, resource-access#initial-common-constraints, #773, #252)", () => {
  const CASES = [
    {
      fact: "tenant",
      member: "tenant",
      seed: { tenant: "tenant-a", constraints: { tenant: "tenant-a" } },
      move: (h: Harness) => h.payments.setVendorTenant("acme", "tenant-b"),
      moved: "tenant-b",
    },
    {
      fact: "issuance",
      member: "issued_at",
      seed: { issuedAt: "2026-08-15T00:00:00Z", constraints: { resource_issued_after: "2026-07-01T00:00:00Z" } },
      move: (h: Harness) => h.payments.setInvoiceIssuedAt("inv-1", "2026-06-01T00:00:00Z"),
      moved: "2026-06-01T00:00:00Z",
    },
    {
      fact: "classification",
      member: "data_classification",
      seed: { classification: "internal", constraints: { data_classification: ["internal"] } },
      move: (h: Harness) => h.payments.setInvoiceClassification("inv-1", "restricted"),
      moved: "restricted",
    },
  ] as const;
  for (const c of CASES) {
    it(`the ${c.fact} moved while the link's evidence is verified reaches the decision as moved: the PDP's bound denies, and the request and its committed context carry the same value`, async () => {
      const h = harness(c.seed);
      expect((await cross(h, COMMIT)).ok).toBe(true);
      // The owner's #1663 review 3 scenario: the fact moves inside the
      // awaited verification of the retained evidence the link rests on.
      const verify = h.evidence.verifyRetained.bind(h.evidence);
      let moved = false;
      h.evidence.verifyRetained = async (row) => {
        const valid = await verify(row);
        if (!moved) {
          moved = true;
          c.move(h);
        }
        return valid;
      };
      const result = await h.server.callTransactionTool(REVERSE, { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` }, TOKEN);
      expect(moved).toBe(true);
      // The decision saw the moved fact: the request carries it.
      const request = h.requests.at(-1);
      expect((request?.resource.properties as Record<string, unknown> | undefined)?.[c.member]).toBe(c.moved);
      // Refused at the decision by the PDP's own bound, never at use.
      expect(result).toMatchObject({ ok: false, denial_reason: "parameter_violation" });
      expect(result).not.toHaveProperty("refusal_reason");
      expect(executions(h).filter((r) => r.outcome === "suppressed")).toHaveLength(0);
      expect(h.connectors.reversalEntries("msn_773")).toHaveLength(0);
      // The context the request committed is the same observation.
      const decision = compensating(h);
      expect(decision?.decision).toBe("deny");
      const sameObservation = captureFromWire(h, decision);
      if (!sameObservation.ok) throw new Error(JSON.stringify(sameObservation));
      expect(request?.context.evaluation_context_digest).toBe(sameObservation.digest);
    });
  }
});

/** Add a vendor record: a direct store edit (#1693). */
function addVendor(payments: PaymentsStore, id: string, tenant: string): void {
  payments.db.prepare("INSERT INTO vendors (id, name, status, tenant) VALUES (?, ?, 'approved', ?)").run(id, id, tenant);
}

/**
 * Reassign `inv-1` to another vendor: a direct store edit, since the
 * reference store has no operation that moves an invoice (#1693). A changed
 * authoritative fact, so it bumps the invoice's version.
 */
function reassignInvoice(payments: PaymentsStore, vendorId: string): void {
  payments.db.prepare("UPDATE invoices SET vendor_id = ?, version = version + 1 WHERE id = 'inv-1'").run(vendorId);
}

/** The committed wire's ledger record for `inv-1`: its operation key and the vendor it paid. */
const ledgerWire = (h: Harness) =>
  h.connectors.db.prepare("SELECT op_key, vendor_id FROM ledger WHERE invoice_id = 'inv-1'").get() as
    | { op_key: string; vendor_id: string }
    | undefined;

const reverseArgs = () => ({ invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` });

describe("the compensate crossing checks the current tenant of the vendor the committed wire paid (@spec runtime#evaluation-context-binding, runtime#compound-actions, resource-access#initial-common-constraints, #1693)", () => {
  for (const [mode, declarations] of [
    ["claiming the binding", CLAIMED],
    ["not claiming the binding", UNCLAIMED],
  ] as const) {
    it(`after the invoice moves from the vendor its wire paid to another, a tenant bound naming the paid vendor's tenant permits reversing that wire, and one naming the new vendor's tenant is denied at the decision (${mode})`, async () => {
      // The wire pays acme (tenant-a); the invoice then moves to globex (tenant-b).
      const h = harness({ pep: declarations, pdp: declarations, tenant: "tenant-a", constraints: { tenant: "tenant-a" } });
      expect((await cross(h, COMMIT)).ok).toBe(true);
      const wire = ledgerWire(h);
      expect(wire?.vendor_id).toBe("acme");
      addVendor(h.payments, "globex", "tenant-b");
      reassignInvoice(h.payments, "globex");
      const done = await h.server.callTransactionTool(REVERSE, reverseArgs(), TOKEN);
      expect(done.ok, JSON.stringify(done)).toBe(true);
      // The decision evaluated the vendor the wire paid and that vendor's tenant.
      expect(h.requests.at(-1)?.resource.properties).toMatchObject({ vendor_id: "acme", tenant: "tenant-a" });
      // The reversal offsets the paid vendor's wire.
      expect(h.connectors.reversalEntries("msn_773")).toEqual([
        expect.objectContaining({ reversed_op_key: wire?.op_key, amount: "125.00", currency: "USD" }),
      ]);

      // The same move under a bound naming the new vendor's tenant: the
      // PDP's own bound denies it at the decision, and nothing is offset.
      const other = harness({ pep: declarations, pdp: declarations, tenant: "tenant-a", constraints: { tenant: "tenant-a" } });
      expect((await cross(other, COMMIT)).ok).toBe(true);
      addVendor(other.payments, "globex", "tenant-b");
      reassignInvoice(other.payments, "globex");
      other.constrain({ tenant: "tenant-b" });
      const denied = await other.server.callTransactionTool(REVERSE, reverseArgs(), TOKEN);
      expect(denied).toMatchObject({ ok: false, denial_reason: "parameter_violation" });
      expect(denied).not.toHaveProperty("refusal_reason");
      expect(other.requests.at(-1)?.resource.properties).toMatchObject({ vendor_id: "acme", tenant: "tenant-a" });
      expect(compensating(other)?.decision).toBe("deny");
      expect(executions(other).filter((r) => r.outcome === "suppressed")).toHaveLength(0);
      expect(other.connectors.reversalEntries("msn_773")).toHaveLength(0);
    });
  }

  it("with the invoice moved to another vendor, the paid vendor's tenant moved after the decision is refused target_drift with zero reversal entries", async () => {
    const h = harness({ tenant: "tenant-a", constraints: { tenant: "tenant-a" } });
    expect((await cross(h, COMMIT)).ok).toBe(true);
    addVendor(h.payments, "globex", "tenant-b");
    reassignInvoice(h.payments, "globex");
    expectLiveFactDrift(h, await h.server.callTransactionTool(REVERSE, reverseArgs(), TOKEN, () => h.payments.setVendorTenant("acme", "tenant-c")));
  });

  it("an invoice reassigned to another vendor between the decision and release still releases the reversal of the paid vendor's wire: the context re-established at release is the paid vendor's and equal", async () => {
    const h = harness({ tenant: "tenant-a", constraints: { tenant: "tenant-a" } });
    expect((await cross(h, COMMIT)).ok).toBe(true);
    const wire = ledgerWire(h);
    addVendor(h.payments, "globex", "tenant-b");
    const done = await h.server.callTransactionTool(REVERSE, reverseArgs(), TOKEN, () => reassignInvoice(h.payments, "globex"));
    expect(done.ok, JSON.stringify(done)).toBe(true);
    const decision = compensating(h);
    const completed = executions(h).filter((r) => r.outcome === "completed" && r.evaluation_id === decision?.evaluation_id);
    expect(completed).toHaveLength(1);
    expect(completed[0]?.authorized_evaluation_context_digest).toBe(decision?.evaluation_context_digest);
    expect(completed[0]?.effective_evaluation_context_digest).toBe(decision?.evaluation_context_digest);
    expect(h.connectors.reversalEntries("msn_773")).toEqual([expect.objectContaining({ reversed_op_key: wire?.op_key })]);
  });

  for (const [mode, declarations] of [
    ["claiming the binding", CLAIMED],
    ["not claiming the binding", UNCLAIMED],
  ] as const) {
    it(`the paid vendor's record gone before the decision is refused unknown_vendor with no decision request, though the invoice's current vendor resolves (${mode})`, async () => {
      const h = harness({ pep: declarations, pdp: declarations });
      expect((await cross(h, COMMIT)).ok).toBe(true);
      addVendor(h.payments, "globex", "tenant-b");
      reassignInvoice(h.payments, "globex");
      h.payments.db.prepare("DELETE FROM vendors WHERE id = 'acme'").run();
      const sent = h.requests.length;
      const refused = await h.server.callTransactionTool(REVERSE, reverseArgs(), TOKEN);
      expect(refused).toEqual({ ok: false, refusal_reason: "unknown_vendor" });
      expect(h.requests).toHaveLength(sent);
      expect(compensating(h)).toBeUndefined();
      expect(refusals(h).at(-1)).toMatchObject({
        denial_reason: "target_unresolvable",
        action: { name: "payments:payment.reverse" },
      });
      expect(h.connectors.reversalEntries("msn_773")).toHaveLength(0);
    });
  }

  it("the paid vendor's record removed between the decision and release, with the invoice on another vendor, is refused target_drift with zero reversal entries and no effective context digest", async () => {
    const h = harness();
    expect((await cross(h, COMMIT)).ok).toBe(true);
    addVendor(h.payments, "globex", "tenant-b");
    reassignInvoice(h.payments, "globex");
    const refused = await h.server.callTransactionTool(REVERSE, reverseArgs(), TOKEN, () => {
      h.payments.db.prepare("DELETE FROM vendors WHERE id = 'acme'").run();
    });
    expect(refused).toEqual({ ok: false, refusal_reason: "target_drift" });
    expect(h.connectors.reversalEntries("msn_773")).toHaveLength(0);
    const decision = compensating(h);
    expect(decision?.decision).toBe("permit");
    const [suppressed] = executions(h).filter((r) => r.outcome === "suppressed");
    expect(suppressed?.error).toBe("target_drift");
    expect(suppressed?.authorized_parameter_digest).toBe(decision?.parameter_digest);
    expect(suppressed?.effective_parameter_digest).toBe(suppressed?.authorized_parameter_digest);
    expect(suppressed?.authorized_evaluation_context_digest).toBe(decision?.evaluation_context_digest);
    expect(suppressed).not.toHaveProperty("effective_evaluation_context_digest");
  });

  it("a compensate capture resolves the invoice and the vendor the committed wire paid: read from the store it takes the paid vendor, never the invoice's current vendor, and records handed in naming another vendor do not capture", () => {
    const payments = new PaymentsStore();
    payments.seed(
      [
        { id: "acme", name: "Acme", status: "approved", tenant: "tenant-a" },
        { id: "globex", name: "Globex", status: "approved", tenant: "tenant-b" },
      ],
      // The invoice names globex now; its wire paid acme.
      [{ id: "inv-1", vendor_id: "globex", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
    );
    const connectors = new Connectors(() => new Date(BASE_MS));
    connectors.postWire({
      opKey: "op-wire",
      invoiceId: "inv-1",
      vendorId: "acme",
      payeeAccount: "acct-acme",
      amount: "125.00",
      currency: "USD",
      permitId: "evl-wire",
      missionId: "msn_773",
    });
    const wire = connectors.committedWire("op-wire", "evl-wire");
    const invoice = payments.getInvoice("inv-1");
    if (!wire || !invoice) throw new Error("fixture");
    const salts = new EvaluationContextSalts();
    const capture = (vendorId?: string) =>
      captureEvaluationContext({
        declarations: CLAIMED,
        salts,
        mission: { issuer: ISSUER, id: "msn_773" },
        operation: reverseOperation,
        invoiceId: "inv-1",
        payments,
        compensates: { opKey: "op-wire", evaluationId: "evl-wire" },
        committedEffects: connectors,
        ...(vendorId !== undefined
          ? { records: { invoice, vendor: payments.getVendor(vendorId) as Vendor, payments }, wire }
          : {}),
      });
    const paid = capture("acme");
    if (!paid.ok) throw new Error(JSON.stringify(paid));
    // Read from the store, the vendor is the one the wire paid.
    const read = capture();
    if (!read.ok) throw new Error(JSON.stringify(read));
    expect(read.digest).toBe(paid.digest);
    // Records naming the invoice's current vendor are not the paid vendor's.
    expect(capture("globex")).toEqual({ ok: false, reason: "target_unresolvable" });
  });

  it("the resolver of the tenant of the vendor an invoice names does not serve the compensate crossing: a descriptor naming it there does not capture", () => {
    const payments = new PaymentsStore();
    payments.seed(
      [{ id: "acme", name: "Acme", status: "approved", tenant: "tenant-a" }],
      [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
    );
    const connectors = new Connectors(() => new Date(BASE_MS));
    connectors.postWire({
      opKey: "op-wire",
      invoiceId: "inv-1",
      vendorId: "acme",
      payeeAccount: "acct-acme",
      amount: "125.00",
      currency: "USD",
      permitId: "evl-wire",
      missionId: "msn_773",
    });
    const invoiceVendorTenant = new EvaluationContextBindingDeclarations(
      claimedStatement((st) => {
        const ecb = st.extensions.evaluation_context_binding as {
          operations: Array<{ operation: string; descriptor: { id: string; version: string; digest: string } }>;
          descriptors: DescriptorEntry[];
        };
        const current = ecb.descriptors.find((d) => d.id.endsWith("/payment-reverse")) as DescriptorEntry;
        const facts = (current.document.facts as Array<Record<string, unknown>>).map((f) =>
          f.name === "vendor_tenant" ? { ...f, resolver: "payments-store:vendor.tenant" } : f,
        );
        const document = { ...current.document, version: "2026-10-26-invoice-vendor-tenant", facts };
        const digest = canonicalDigest(document as JsonValue);
        ecb.descriptors.push({ id: current.id, version: "2026-10-26-invoice-vendor-tenant", digest, document });
        for (const op of ecb.operations) {
          if (op.operation === "payments:payment.reverse") op.descriptor = { id: current.id, version: "2026-10-26-invoice-vendor-tenant", digest };
        }
        return st;
      }),
    );
    const capture = (declarations: EvaluationContextBindingDeclarations) =>
      captureEvaluationContext({
        declarations,
        salts: new EvaluationContextSalts(),
        mission: { issuer: ISSUER, id: "msn_773" },
        operation: reverseOperation,
        invoiceId: "inv-1",
        payments,
        compensates: { opKey: "op-wire", evaluationId: "evl-wire" },
        committedEffects: connectors,
      });
    expect(capture(CLAIMED).ok).toBe(true);
    expect(capture(invoiceVendorTenant)).toEqual({ ok: false, reason: "fact_unresolvable" });
  });
});

/** Move `inv-1` to a new vendor `globex`, then delete that vendor's record: the invoice's current vendor no longer resolves (#1693, D879). */
function orphanInvoice(payments: PaymentsStore): void {
  addVendor(payments, "globex", "tenant-b");
  reassignInvoice(payments, "globex");
  payments.db.prepare("DELETE FROM vendors WHERE id = 'globex'").run();
  expect(payments.getVendor(payments.getInvoice("inv-1")?.vendor_id ?? "")).toBeUndefined();
}

describe("the compensate crossing does not depend on the invoice's current vendor (@spec runtime#compound-actions, runtime#evaluation-context-binding, resource-access#initial-common-constraints, #1693, D879)", () => {
  for (const [mode, declarations] of [
    ["claiming the binding", CLAIMED],
    ["not claiming the binding", UNCLAIMED],
  ] as const) {
    it(`an invoice moved to another vendor whose record is then deleted still reverses the wire it paid under a bound on the paid vendor's tenant, offsetting that wire (${mode})`, async () => {
      const h = harness({ pep: declarations, pdp: declarations, tenant: "tenant-a", constraints: { tenant: "tenant-a" } });
      expect((await cross(h, COMMIT)).ok).toBe(true);
      const wire = ledgerWire(h);
      expect(wire?.vendor_id).toBe("acme");
      orphanInvoice(h.payments);
      const done = await h.server.callTransactionTool(REVERSE, reverseArgs(), TOKEN);
      expect(done.ok, JSON.stringify(done)).toBe(true);
      // The decision evaluated the paid vendor and its tenant.
      expect(h.requests.at(-1)?.resource.properties).toMatchObject({ vendor_id: "acme", tenant: "tenant-a" });
      const decision = compensating(h);
      expect(decision?.decision).toBe("permit");
      // The reversal offsets the paid vendor's wire.
      expect(h.connectors.reversalEntries("msn_773")).toEqual([
        expect.objectContaining({ reversed_op_key: wire?.op_key, amount: "125.00", currency: "USD" }),
      ]);
      const completed = executions(h).filter((r) => r.outcome === "completed" && r.evaluation_id === decision?.evaluation_id);
      expect(completed).toHaveLength(1);
      expect(completed[0]?.effective_parameter_digest).toBe(decision?.parameter_digest);
      if (declarations === CLAIMED) {
        expect(completed[0]?.effective_evaluation_context_digest).toBe(decision?.evaluation_context_digest);
      }
    });
  }

  it("an ordinary invoice-scoped operation still refuses unknown_vendor when the invoice's current vendor has no record, before any decision request", async () => {
    for (const [tool, call] of [
      ["get_invoice", (h: Harness) => h.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN)],
      ["execute_wire_transfer", (h: Harness) => cross(h, COMMIT)],
    ] as const) {
      const h = harness();
      orphanInvoice(h.payments);
      const refused = await call(h);
      expect(refused, tool).toEqual({ ok: false, refusal_reason: "unknown_vendor" });
      expect(h.requests, tool).toHaveLength(0);
      expect(refusals(h).at(-1), tool).toMatchObject({
        denial_reason: "target_unresolvable",
        action: { name: TOOL_ACTIONS[tool]?.action },
      });
      expect(h.connectors.committedEffects(), tool).toHaveLength(0);
    }
  });
});

/** The shipped reference to a declared version of the payments contract. */
function contractRef(version: string): ResourceContractRef {
  const [declared] = RESOURCE_CONTRACTS.declarations;
  const v = declared?.versions.find((x) => x.version === version);
  if (!declared || !v) throw new Error(`payments contract ${version} is declared`);
  return { id: declared.id, version: v.version, digest: v.digest };
}
/** Contract version 2026-10-24, naming payments-runtime-profile-v14 (#252), superseded by v15 (#1693). */
const V14_CONTRACT = contractRef("2026-10-24");
/** Contract version 2026-10-26, naming payments-runtime-profile-v15 (#1693), current. */
const V15_CONTRACT = contractRef("2026-10-26");

/** `TOKEN` whose credential's one entry pins `contract`, as the Mission's entry does. */
const pinnedToken = (contract: ResourceContractRef): TokenFacts => ({
  ...TOKEN,
  credentialAuthority: credentialAuthorityFrom([
    {
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: [...new Set(TOOLS.map((t) => t.action))],
      resource_contract: contract,
    },
  ]),
});

const commitArgs = () => ({ invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` });

describe("authority pinned to contract 2026-10-24 (payments-runtime-profile-v14) never gets v15's reversal (@spec runtime#resource-contract, resource-access#resource-contract, runtime#compound-actions, #1693, D879)", () => {
  it("declares 2026-10-26 current under v15 and 2026-10-24 superseded under v14, with a retention", () => {
    const [declared] = RESOURCE_CONTRACTS.declarations;
    const byVersion = (v: string) => declared?.versions.find((x) => x.version === v);
    expect(byVersion("2026-10-26")).toMatchObject({ state: "current", operation_profile: "payments-runtime-profile-v15" });
    expect(byVersion("2026-10-24")).toMatchObject({ state: "superseded", operation_profile: "payments-runtime-profile-v14" });
    expect(byVersion("2026-10-24")?.retained_until).toEqual(expect.any(String));
  });

  it("an entry pinned to 2026-10-24 that requests the reversal is refused resource_contract_unresolvable before any decision request, with zero effects", async () => {
    const h = harness({ contract: V14_CONTRACT, tenant: "tenant-a", constraints: { tenant: "tenant-a" } });
    const token = pinnedToken(V14_CONTRACT);
    // The wire this reversal would offset commits under the same pin.
    const committed = await h.server.callTransactionTool(COMMIT.tool, commitArgs(), token);
    expect(committed.ok, JSON.stringify(committed)).toBe(true);
    const sent = h.requests.length;
    const refused = await h.server.callTransactionTool(REVERSE, reverseArgs(), token);
    expect(refused).toEqual({ ok: false, refusal_reason: "resource_contract_unresolvable" });
    expect(h.requests).toHaveLength(sent);
    expect(compensating(h)).toBeUndefined();
    expect(refusals(h).at(-1)).toMatchObject({
      denial_reason: "resource_contract_unresolvable",
      action: { name: "payments:payment.reverse" },
    });
    expect(executions(h).filter((r) => r.outcome === "suppressed")).toHaveLength(0);
    expect(h.connectors.reversalEntries("msn_773")).toHaveLength(0);
  });

  it("the same 2026-10-24 entry still performs the wire execute and a read as before: each under its pinned contract, with the parameter digest an unpinned entry gets", async () => {
    const pinned = harness({ contract: V14_CONTRACT });
    const token = pinnedToken(V14_CONTRACT);
    const committed = await pinned.server.callTransactionTool(COMMIT.tool, commitArgs(), token);
    expect(committed.ok, JSON.stringify(committed)).toBe(true);
    const commitRequest = pinned.requests.at(-1);
    expect(commitRequest?.resource.properties?.resource_contract).toEqual(V14_CONTRACT);
    expect(pinned.connectors.committedEffects()).toHaveLength(1);
    const read = await pinned.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, token);
    expect(read.ok, JSON.stringify(read)).toBe(true);
    expect(pinned.requests.at(-1)?.resource.properties?.resource_contract).toEqual(V14_CONTRACT);

    // The same execute under an unpinned entry binds the same parameters.
    const unpinned = harness();
    expect((await unpinned.server.callTransactionTool(COMMIT.tool, commitArgs(), TOKEN)).ok).toBe(true);
    const commitDecision = (h: Harness) =>
      decisions(h).find((d) => d.action.name === "payments:payment.execute" && d.action_phase === "commit");
    expect(commitDecision(pinned)?.decision).toBe("permit");
    expect(commitDecision(pinned)?.parameter_digest).toMatch(/^sha-256:/);
    expect(commitDecision(pinned)?.parameter_digest).toBe(commitDecision(unpinned)?.parameter_digest);
  });

  for (const [mode, contract] of [
    ["pinned to 2026-10-26", V15_CONTRACT],
    ["unpinned", undefined],
  ] as const) {
    it(`an entry ${mode} performs the reversal under the paid vendor's current tenant`, async () => {
      const h = harness({ tenant: "tenant-a", constraints: { tenant: "tenant-a" }, ...(contract ? { contract } : {}) });
      const token = contract ? pinnedToken(contract) : TOKEN;
      expect((await h.server.callTransactionTool(COMMIT.tool, commitArgs(), token)).ok).toBe(true);
      const wire = ledgerWire(h);
      addVendor(h.payments, "globex", "tenant-b");
      reassignInvoice(h.payments, "globex");
      const done = await h.server.callTransactionTool(REVERSE, reverseArgs(), token);
      expect(done.ok, JSON.stringify(done)).toBe(true);
      const properties = h.requests.at(-1)?.resource.properties;
      expect(properties).toMatchObject({ vendor_id: "acme", tenant: "tenant-a" });
      if (contract) expect(properties?.resource_contract).toEqual(contract);
      else expect(properties).not.toHaveProperty("resource_contract");
      expect(h.connectors.reversalEntries("msn_773")).toEqual([expect.objectContaining({ reversed_op_key: wire?.op_key })]);
    });
  }
});

describe("restart loses bindings, on every covered dispatch path (@spec runtime#evaluation-context-binding, runtime#single-use-identifiers, #773)", () => {
  for (const c of COVERED) {
    it(`a binding made before a restart is refused before any effect on ${c.tool} (${c.path} path): target_drift, no effective context digest`, async () => {
      const h = harness();
      const refused = await cross(h, c, () => h.restart());
      expect(refused).toEqual({ ok: false, refusal_reason: "target_drift" });
      expect(h.connectors.committedEffects()).toHaveLength(0);
      const [record] = executions(h);
      expect(record?.error).toBe("target_drift");
      expect(record).not.toHaveProperty("effective_evaluation_context_digest");
      expect(record?.effective_parameter_digest).toBe(record?.authorized_parameter_digest);
    });
  }

  it("a rotation retains the earlier version for an outstanding binding on every path, and an explicit invalidation refuses it", async () => {
    for (const c of COVERED) {
      const retained = harness();
      const done = await cross(retained, c, () => retained.salts().rotate());
      expect(done.ok, `${c.tool}: ${JSON.stringify(done)}`).toBe(true);
      const invalidated = harness();
      expect(await cross(invalidated, c, () => invalidated.salts().rotate({ invalidatePrevious: true }))).toEqual({
        ok: false,
        refusal_reason: "target_drift",
      });
      expect(invalidated.connectors.committedEffects()).toHaveLength(0);
    }
  });
});

describe("claim applicability: covered, uncovered and non-claiming (@spec runtime#evaluation-context-binding, authzen#response-context, #773)", () => {
  it("a covered operation whose permit lacks the context condition is refused target_drift with zero effects", async () => {
    const h = harness();
    h.rewrite((d) => {
      const { evaluation_context_digest: _dropped, ...rest } = d.context.conditions as Record<string, unknown>;
      return { ...d, context: { ...d.context, conditions: rest } };
    });
    expect(await cross(h, COMMIT)).toEqual({ ok: false, refusal_reason: "target_drift" });
    expect(h.connectors.committedEffects()).toHaveLength(0);
    expect(executions(h).map((r) => r.error)).toEqual(["target_drift"]);
  });

  it("an uncovered operation refuses a presented context condition as an unrecognized condition", async () => {
    const h = harness();
    h.rewrite((d) => ({
      ...d,
      context: {
        ...d.context,
        conditions: { ...(d.context.conditions as object), evaluation_context_digest: `sha-256:${"A".repeat(43)}` },
      },
    }));
    const refused = await h.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN);
    expect(refused).toEqual({ ok: false, refusal_reason: "condition_unrecognized" });
    expect(refused).not.toHaveProperty("result");
    expect(executions(h).map((r) => r.error)).toEqual(["condition_unrecognized"]);
  });

  it("an uncovered operation and a non-claiming deployment are unchanged: no context members, and a moved fact stays parameter_mismatch", async () => {
    // Uncovered under the claim: the keyed schedule write.
    const claimed = harness();
    const scheduled = await claimed.server.callWriteTool(
      "schedule_payment",
      { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` },
      TOKEN,
      () => claimed.payments.bumpInvoiceAmount("inv-1", "480.00"),
    );
    expect(scheduled).toMatchObject({ ok: false, refusal_reason: "parameter_mismatch" });
    expect(claimed.lastContext()).not.toHaveProperty("evaluation_context_digest");
    expect(claimed.lastContext()).not.toHaveProperty("evaluation_context_binding");
    // A deployment that does not claim the extension, at both ends.
    const plain = harness({ pep: UNCLAIMED, pdp: UNCLAIMED });
    const refused = await cross(plain, COMMIT, () => plain.payments.bumpInvoiceAmount("inv-1", "480.00"));
    expect(refused).toEqual({ ok: false, refusal_reason: "parameter_mismatch" });
    expect(plain.lastContext()).not.toHaveProperty("evaluation_context_digest");
    expect(plain.lastDecision()?.context.conditions).not.toHaveProperty("evaluation_context_digest");
    const [record] = executions(plain);
    expect(record?.error).toBe("parameter_mismatch");
    expect(record).not.toHaveProperty("authorized_evaluation_context_digest");
    expect(decisions(plain)[0]).not.toHaveProperty("evaluation_context_digest");
  });

  it("the parameter digest, the operation key and so the approval and transaction-token bindings are unchanged by the claim", async () => {
    const claimed = harness();
    const plain = harness({ pep: UNCLAIMED, pdp: UNCLAIMED });
    const a = await claimed.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` }, TOKEN);
    const b = await plain.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` }, TOKEN);
    expect(claimed.lastContext()?.parameter_digest).toBe(plain.lastContext()?.parameter_digest);
    expect(a.attempt?.joinKey).toBe(b.attempt?.joinKey);
    expect(a.attempt?.joinKey).toBe(
      operationKey("msn_773", "payments:payment.execute", plain.lastContext()?.parameter_digest as string, "commit"),
    );
  });

  it("a context captured for another Mission is not substitutable: distinct salts and digests, and a permit carrying it is refused target_drift", async () => {
    const h = harness();
    await h.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` }, TOKEN_B);
    const other = h.lastContext()?.evaluation_context_digest;
    await h.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` }, TOKEN);
    const own = h.lastContext()?.evaluation_context_digest;
    expect(other).toBeDefined();
    expect(own).not.toBe(other);
    const version = h.salts().current() as string;
    expect(h.salts().saltFor(version, { issuer: ISSUER, id: "msn_773" })).not.toBe(
      h.salts().saltFor(version, { issuer: ISSUER, id: "msn_773b" }),
    );
    h.rewrite((d) => ({
      ...d,
      context: { ...d.context, conditions: { ...(d.context.conditions as object), evaluation_context_digest: other } },
    }));
    expect(await cross(h, COMMIT)).toEqual({ ok: false, refusal_reason: "target_drift" });
    expect(h.connectors.committedEffects()).toHaveLength(0);
  });
});

describe("the shipped declaration and the Operation Profile agree (@spec runtime#evaluation-context-binding, #773)", () => {
  it("every crossing of a covered class is a covered operation, and every covered crossing captures under the shipped descriptors", () => {
    const declared = new EvaluationContextBindingDeclarations(claimedStatement());
    const payments = new PaymentsStore();
    payments.seed(
      [{ id: "acme", name: "Acme", status: "approved" }],
      [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
    );
    for (const [tool, mapping] of Object.entries(TOOL_ACTIONS)) {
      if (!declared.coveredClasses.includes(mapping.actionClass)) continue;
      expect(declared.covers(mapping.action, mapping.phase), tool).toBe(true);
    }
    const salts = new EvaluationContextSalts();
    // A compensate crossing's facts are a committed wire's ledger record.
    const connectors = new Connectors(() => new Date(BASE_MS));
    connectors.postWire({
      opKey: "op-wire",
      invoiceId: "inv-1",
      vendorId: "acme",
      payeeAccount: "acct-acme",
      amount: "125.00",
      currency: "USD",
      permitId: "evl-wire",
      missionId: "msn_773",
    });
    const compensated = { opKey: "op-wire", evaluationId: "evl-wire" };
    for (const [tool, mapping] of Object.entries(TOOL_ACTIONS)) {
      if (!declared.covers(mapping.action, mapping.phase)) continue;
      const base = {
        declarations: declared,
        salts,
        mission: { issuer: ISSUER, id: "msn_773" },
        operation: { action: mapping.action, ...(mapping.phase !== undefined ? { phase: mapping.phase } : {}) },
        invoiceId: "inv-1",
        payments,
      };
      const captured = mapping.compensates
        ? captureEvaluationContext({ ...base, compensates: compensated, committedEffects: connectors })
        : captureEvaluationContext(base);
      expect(captured.ok, tool).toBe(true);
      if (mapping.compensates) {
        // Its descriptor's facts do not resolve from the invoice.
        expect(captureEvaluationContext(base), tool).toEqual({ ok: false, reason: "fact_unresolvable" });
      }
    }
    expect(Object.values(TOOL_ACTIONS).some((m) => m.compensates && declared.covers(m.action, m.phase))).toBe(true);
  });
});
