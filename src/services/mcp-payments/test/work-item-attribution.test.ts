/**
 * @spec harness#work-item-identity, authzen#context-work-item,
 * authzen#decision-conditions `work_item`, runtime-evidence#evidence-extensions
 * `work_item` (#815): the qualified work-item identifier at the PEP.
 *
 * The PEP takes a work item only from the propagated Mission reference that
 * carried it, once that reference verified, and only for the harness the
 * statement names as the attacher for the authenticated client; never from a
 * tool argument. It carries the work item as `context.work_item`, compares
 * the permit's `work_item` condition with it at every use, and records it on
 * Execution Evidence. A permit decided for one work item is refused, with no
 * effect, when it is presented for another.
 *
 * Unconditional: the FGA check is a stub, so this file never skips. The
 * statement that names the attacher and claims a class is a test-only one;
 * the shipped statement claims nothing.
 */

import { generateKeyPairSync, randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  createDecisionPoint,
  type Decision,
  type EvaluationRequest,
  type Fga,
  type MissionView,
  readWorkItemAttribution,
  RUNTIME_POSTURE,
  WORK_ITEM_ATTRIBUTION_EXTENSION,
} from "@mission/pdp";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import {
  CANONICAL_RESOURCE,
  Connectors,
  createEphemeralEvidenceKeys,
  type DecisionEvidence,
  EvidenceStore,
  type ExecutionEvidence,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  PaymentsStore,
  Pep,
  type RequestSignals,
  type TokenFacts,
  TransactionEngine,
} from "../src/index.js";
import { ALL_ACTIONS_CREDENTIAL } from "./credential-fixtures.js";

const ISSUER = "https://as.test";
const HARNESS = "https://harness.example.com";
const W1 = { issuer: HARNESS, id: "work-1" };
const W2 = { issuer: HARNESS, id: "work-2" };
const MISSION_A = "msn_815_a";
const MISSION_B = "msn_815_b";
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
const idem = (): string => `idem_${randomUUID()}`;

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
      actions: ["payments:invoice.read", "payments:invoice.list", "payments:payment.execute"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    },
  ],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
});

/** One client holding credentials for two Missions. */
const token = (mission: string, clientId = "ap-agent"): TokenFacts => ({
  sub: "alice",
  clientId,
  clientInstanceId: "inst-1",
  mission: { id: mission, issuer: ISSUER, authority_hash: `sha-256:${mission}` },
  missionClaim: {
    id: mission,
    issuer: ISSUER,
    authority_hash: `sha-256:${mission}`,
    expires_at: "2100-01-01T00:00:00Z",
    approval_basis: { type: "direct" },
  },
  cnfJkt: "jkt-815",
  credentialAuthority: ALL_ACTIONS_CREDENTIAL,
});

/** The harness's attachment: the reference it propagates, with its work item. */
const attached = (mission: string, workItem: { issuer: string; id: string }): RequestSignals => ({
  missionReference: { id: mission, issuer: ISSUER, workItem },
});

/**
 * A test-only Enforcement Scope Statement: the shipped one plus a work-item
 * declaration naming `ap-agent`'s harness, claimed for `claimed` classes
 * (none: the declaration names the attacher and claims nothing).
 */
function statement(claimed: readonly string[]): unknown {
  const stmt = structuredClone(RUNTIME_POSTURE) as unknown as Record<string, unknown> & { extensions: Record<string, unknown> };
  if (claimed.length > 0) stmt.claims = [WORK_ITEM_ATTRIBUTION_EXTENSION];
  stmt.extensions = {
    ...stmt.extensions,
    [WORK_ITEM_ATTRIBUTION_EXTENSION]: {
      attachers: [{ client_id: "ap-agent", harness: HARNESS }],
      covered_classes: claimed.length > 0 ? [...claimed] : ["consequential_read"],
    },
  };
  return stmt;
}

interface Fixture {
  pep: Pep;
  server: McpPaymentsServer;
  evidence: EvidenceStore;
  connectors: Connectors;
  /** Every decision request the PEP sent, as sent. */
  requests: EvaluationRequest[];
  /** The last decision the PEP obtained. */
  lastDecision: () => Decision | undefined;
  /** Present a captured permit at the next crossings, in place of a fresh decision. */
  replay: (decision: Decision | undefined) => void;
}

function fixture(o: { claimed?: readonly string[]; attachers?: boolean } = {}): Fixture {
  const attribution = readWorkItemAttribution(statement(o.claimed ?? []));
  const pdpKey = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const point = createDecisionPoint({
    evidence: {
      signer: { kid: "pdp-815", key: pdpKey.privateKey },
      verificationKey: pdpKey.publicKey,
      emitterId: CANONICAL_RESOURCE,
      audience: CANONICAL_RESOURCE,
    },
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
    workItemAttributedClasses: attribution.claimedClasses,
  });
  // The shipped ephemeral bundle carries the claim domain the transaction
  // tier needs; a claiming fixture decides through its own decision point.
  const keys =
    (o.claimed ?? []).length > 0
      ? createEphemeralEvidenceKeys({ decisionPoint: point })
      : createEphemeralEvidenceKeys({ resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE });
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [
      { id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
      { id: "inv-2", vendor_id: "acme", amount: "75.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
    ],
  );
  const loadView = (ref: { id: string; issuer: string }) =>
    (ref.id === MISSION_A || ref.id === MISSION_B) && ref.issuer === ISSUER
      ? { view: view(ref.id), observation: { state: "active", version: 1, mode: "fresh", freshness_at: new Date().toISOString() } }
      : undefined;
  const evidence = new EvidenceStore(keys.signing, keys.resolver);
  const connectors = new Connectors();
  const engine = new TransactionEngine("epoch-815");
  const requests: EvaluationRequest[] = [];
  let replayed: Decision | undefined;
  let captured: Decision | undefined;
  const pep = new Pep({
    decide: async (req, options) => {
      requests.push(structuredClone(req));
      if (replayed) return replayed;
      return keys.decide(req, options);
    },
    observe: ({ decision }) => {
      captured = decision;
    },
    payments,
    evidence,
    fga: alwaysAllowFga,
    modelId: "unit-test-model",
    loadView,
    instanceEpoch: "epoch-815",
    ...(o.attachers === false ? {} : { workItemAttachers: attribution.attachers }),
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
    pep,
    server,
    evidence,
    connectors,
    requests,
    lastDecision: () => captured,
    replay: (decision) => {
      replayed = decision;
    },
  };
}

const contextOf = (r: EvaluationRequest | undefined) => r?.context as Record<string, unknown> | undefined;
const conditionsOf = (d: Decision | undefined) => d?.context.conditions as Record<string, unknown> | undefined;
const executions = (f: Fixture) =>
  f.evidence.forMission(MISSION_A).filter((e): e is ExecutionEvidence => e.kind === "execution");
const decisions = (f: Fixture) =>
  f.evidence.forMission(MISSION_A).filter((e): e is DecisionEvidence => e.kind === "decision");

describe("the PEP carries a work item only from the harness's verified attachment (@spec harness#work-item-identity, authzen#context-work-item, #815)", () => {
  it("carries the work item the verified reference attaches as context.work_item, bound into the permit and recorded on Decision Evidence", async () => {
    const f = fixture();
    const res = await f.pep.enforce("get_invoice", { invoice_id: "inv-1" }, token(MISSION_A), undefined, attached(MISSION_A, W1));
    expect(res.permitted, JSON.stringify(res)).toBe(true);
    expect(contextOf(f.requests[0])?.work_item).toEqual(W1);
    expect(conditionsOf(f.lastDecision())?.work_item).toEqual(W1);
    expect(decisions(f).at(-1)?.content.work_item).toEqual(W1);
  });

  it("does not carry a work item whose harness is not the attacher the statement names for the authenticated client", async () => {
    const otherHarness = fixture();
    await otherHarness.pep.enforce(
      "get_invoice",
      { invoice_id: "inv-1" },
      token(MISSION_A),
      undefined,
      attached(MISSION_A, { issuer: "https://other-harness.example.com", id: "work-1" }),
    );
    expect(contextOf(otherHarness.requests[0])?.work_item).toBeUndefined();

    const otherClient = fixture();
    await otherClient.pep.enforce("get_invoice", { invoice_id: "inv-1" }, token(MISSION_A, "other-agent"), undefined, attached(MISSION_A, W1));
    expect(contextOf(otherClient.requests[0])?.work_item).toBeUndefined();

    const noAttacher = fixture({ attachers: false });
    await noAttacher.pep.enforce("get_invoice", { invoice_id: "inv-1" }, token(MISSION_A), undefined, attached(MISSION_A, W1));
    expect(contextOf(noAttacher.requests[0])?.work_item).toBeUndefined();
  });

  it("never reads a work item from tool arguments: alone it is never carried, and beside an attachment the attachment governs", async () => {
    const f = fixture();
    await f.pep.enforce("get_invoice", { invoice_id: "inv-1", work_item: W2 }, token(MISSION_A));
    expect(contextOf(f.requests[0])?.work_item).toBeUndefined();
    await f.pep.enforce("get_invoice", { invoice_id: "inv-1", work_item: W2 }, token(MISSION_A), undefined, attached(MISSION_A, W1));
    expect(contextOf(f.requests[1])?.work_item).toEqual(W1);
    expect(conditionsOf(f.lastDecision())?.work_item).toEqual(W1);
  });

  it("refuses a work item attached under another Mission on a call with this Mission's credential, before any decision (one client, two Missions)", async () => {
    const f = fixture();
    const res = await f.pep.enforce("get_invoice", { invoice_id: "inv-1" }, token(MISSION_A), undefined, attached(MISSION_B, W1));
    expect(res.permitted).toBe(false);
    expect(res.refusal_reason).toBe("mission_reference_conflict");
    expect(f.requests).toHaveLength(0);
    // The same client's credential for the work item's own Mission proceeds.
    const own = await f.pep.enforce("get_invoice", { invoice_id: "inv-1" }, token(MISSION_B), undefined, attached(MISSION_B, W1));
    expect(own.permitted, JSON.stringify(own)).toBe(true);
    expect(contextOf(f.requests[0])?.work_item).toEqual(W1);
  });
});

describe("work-item attribution claimed for a class (@spec authzen#context-work-item, #815)", () => {
  it("denies work_item_context_missing end to end where the class is claimed and nothing is attached, and permits with the attachment", async () => {
    const f = fixture({ claimed: ["consequential_read"] });
    const missing = await f.pep.enforce("get_invoice", { invoice_id: "inv-1", work_item: W1 }, token(MISSION_A));
    expect(missing.permitted).toBe(false);
    expect(missing.denial_reason).toBe("work_item_context_missing");
    const present = await f.pep.enforce("get_invoice", { invoice_id: "inv-1" }, token(MISSION_A), undefined, attached(MISSION_A, W1));
    expect(present.permitted, JSON.stringify(present)).toBe(true);
  });

  it("where no class is claimed, permits with no attachment: Mission-level attribution only", async () => {
    const f = fixture();
    const res = await f.pep.enforce("get_invoice", { invoice_id: "inv-1" }, token(MISSION_A));
    expect(res.permitted, JSON.stringify(res)).toBe(true);
    expect(contextOf(f.requests[0])?.work_item).toBeUndefined();
  });
});

describe("the permit's work_item condition at every use (@spec authzen#decision-conditions, runtime-evidence#evidence-extensions, #815)", () => {
  it("a completed execution's Execution Evidence carries the request's work item", async () => {
    const f = fixture();
    const res = await f.server.callTransactionTool(
      "execute_wire_transfer",
      { invoice_id: "inv-1", idempotency_key: idem() },
      token(MISSION_A),
      undefined,
      attached(MISSION_A, W1),
    );
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect(f.connectors.ledgerEntries(MISSION_A)).toHaveLength(1);
    const completed = executions(f).filter((e) => e.content.outcome === "completed");
    expect(completed).toHaveLength(1);
    expect(completed[0]?.content.work_item).toEqual(W1);
  });

  it("item swap within one Mission: a permit decided for one work item is refused work_item_mismatch with zero effect when presented for another", async () => {
    const f = fixture();
    const decided = await f.pep.enforce(
      "execute_wire_transfer",
      { invoice_id: "inv-1", idempotency_key: idem() },
      token(MISSION_A),
      undefined,
      attached(MISSION_A, W1),
    );
    expect(decided.permitted, JSON.stringify(decided)).toBe(true);
    const permitForW1 = f.lastDecision();
    expect(conditionsOf(permitForW1)?.work_item).toEqual(W1);

    f.replay(permitForW1);
    const refused = await f.server.callTransactionTool(
      "execute_wire_transfer",
      { invoice_id: "inv-1", idempotency_key: idem() },
      token(MISSION_A),
      undefined,
      attached(MISSION_A, W2),
    );
    expect(refused.ok).toBe(false);
    expect(refused.refusal_reason).toBe("work_item_mismatch");
    expect(f.connectors.ledgerEntries(MISSION_A)).toHaveLength(0);
    const suppressed = executions(f).filter((e) => e.content.outcome === "suppressed");
    expect(suppressed).toHaveLength(1);
    expect(suppressed[0]?.content.error).toBe("work_item_mismatch");
    expect(suppressed[0]?.content.work_item).toEqual(W2);
  });

  it("refuses a permit bound to a work item for a request that carries none, and a permit bound to none for a request that carries one", async () => {
    const bound = fixture();
    await bound.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: idem() }, token(MISSION_A), undefined, attached(MISSION_A, W1));
    bound.replay(bound.lastDecision());
    const none = await bound.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: idem() }, token(MISSION_A));
    expect(none.ok).toBe(false);
    expect(none.refusal_reason).toBe("work_item_mismatch");
    expect(bound.connectors.ledgerEntries(MISSION_A)).toHaveLength(0);

    const unbound = fixture();
    await unbound.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: idem() }, token(MISSION_A));
    expect(conditionsOf(unbound.lastDecision())?.work_item).toBeUndefined();
    unbound.replay(unbound.lastDecision());
    const carried = await unbound.server.callTransactionTool(
      "execute_wire_transfer",
      { invoice_id: "inv-1", idempotency_key: idem() },
      token(MISSION_A),
      undefined,
      attached(MISSION_A, W1),
    );
    expect(carried.ok).toBe(false);
    expect(carried.refusal_reason).toBe("work_item_mismatch");
    expect(unbound.connectors.ledgerEntries(MISSION_A)).toHaveLength(0);
  });
});
