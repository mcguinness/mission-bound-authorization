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
import { canonicalDigest, EvaluationContextBindingDeclarations, type JsonValue } from "@mission/core";
import { RUNTIME_SCOPE_CONFIG } from "@mission/demo-data";
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
  TransactionEngine,
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

const view = (id: string): MissionView => ({
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
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
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
}

function harness(o: { pep?: EvaluationContextBindingDeclarations; pdp?: EvaluationContextBindingDeclarations } = {}): Harness {
  const now = () => new Date(BASE_MS);
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [
      { id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
      { id: "inv-2", vendor_id: "acme", amount: "75.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
    ],
  );
  const loadView = (ref: { id: string; issuer: string }) =>
    (ref.id === "msn_773" || ref.id === "msn_773b") && ref.issuer === ISSUER
      ? { view: view(ref.id), observation: { state: "active", version: 1, mode: "fresh", freshness_at: now().toISOString() } }
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
