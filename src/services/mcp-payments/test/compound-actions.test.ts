/**
 * @spec runtime#compound-actions, runtime#execution-reverification,
 * runtime#idempotency (issue #252 PR C1)
 *
 * `payments:payment.execute` serves three crossings on ONE action identifier:
 * `check_transfer` (preflight), `hold_transfer` (prepare) and
 * `execute_wire_transfer` (commit), over one `{invoice_id}` schema and one
 * invoice, so all three normalize the SAME effect inputs and produce one
 * identical `parameter_digest`. The phase is therefore the only thing that
 * can distinguish their permits, which is what makes these assertions
 * exercise phase binding rather than ordinary action or parameter binding.
 *
 * The three crossings also take the three dispatch paths (`callReadTool`,
 * `callWriteTool`, `callTransactionTool`), only the last of which reaches a
 * connector, so the pre-effect seam is exercised where there is no connector
 * to stop as well as where there is.
 *
 * The compensate crossing (#252 PR C2) is `reverse_wire_transfer`, on its own
 * action identifier `payments:payment.reverse`: it offsets a wire
 * `execute_wire_transfer` committed, through the reference connector, under
 * its own single-use Decision, carrying the link to the committed original
 * that the PEP establishes from its own verified evidence.
 *
 * Unconditional: the FGA check is a stub, so this file never skips.
 */

import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { CATALOG_TOOL_BINDINGS } from "@mission/demo-data";
import { type Decision, DecisionRequestRefused, type EvaluationRequest, type Fga, type MissionView } from "@mission/pdp";
import {
  buildEffectiveParams,
  CANONICAL_RESOURCE,
  Connectors,
  CONNECTOR_TOOLS,
  createEphemeralEvidenceKeys,
  DECISION_EVIDENCE_MEDIA_TYPE,
  type Evidence,
  reconcile,
  type DecisionEvidence,
  EvidenceStore,
  type ExecutionEvidence,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  operationKey,
  parameterDigest,
  PaymentsStore,
  Pep,
  REFUSAL_RECORD_MEDIA_TYPE,
  type RefusalRecord,
  TOOL_ACTIONS,
  TOOLS,
  TransactionEngine,
  type ActionMapping,
  type TokenFacts,
  verifyEvidenceEnvelope,
} from "../src/index.js";
import { ALL_ACTIONS_CREDENTIAL } from "./credential-fixtures.js";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";

const EVIDENCE_KEYS = createEphemeralEvidenceKeys({ resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE });
const BASE_MS = Date.parse("2026-09-08T12:00:00.000Z");
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const AUTHORITY = [
  {
    type: "mission_resource_access",
    resource: CANONICAL_RESOURCE,
    // #252: the compensation's own authority, beside the commit's.
    actions: ["payments:payment.execute", "payments:payment.reverse", "payments:payment.schedule", "payments:invoice.read"],
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];

/** The same Mission authority with no authority to compensate (#252). */
const AUTHORITY_WITHOUT_REVERSE = [
  { ...AUTHORITY[0], actions: AUTHORITY[0]?.actions.filter((a) => a !== "payments:payment.reverse") },
];

const TOKEN: TokenFacts = {
  sub: "alice",
  clientId: "ap-agent",
  clientInstanceId: "inst-1",
  mission: { id: "msn_252", issuer: "https://as.test", authority_hash: "sha-256:m252" },
  missionClaim: {
    id: "msn_252",
    issuer: "https://as.test",
    authority_hash: "sha-256:m252",
    expires_at: "2100-01-01T00:00:00Z",
    approval_basis: { type: "direct" },
  },
  cnfJkt: "jkt-252",
  credentialAuthority: ALL_ACTIONS_CREDENTIAL,
};

interface Harness {
  server: McpPaymentsServer;
  pep: Pep;
  evidence: EvidenceStore;
  connectors: Connectors;
  engine: TransactionEngine;
  payments: PaymentsStore;
  /** The last decision the PEP obtained, captured off `PepDeps.observe`. */
  lastDecision: () => Decision | undefined;
  /** The last decision request envelope the PEP built. */
  lastEnvelope: () => Record<string, unknown> | undefined;
  /** Replay a specific permit for the next crossings, in place of a fresh Decision. */
  replay: (decision: Decision | undefined) => void;
  /** Advance ONLY the PEP's clock: permit initiation validity, not the lease. */
  advancePep: (ms: number) => void;
  /** Suspend the Mission the loader serves, without touching either clock. */
  suspendMission: () => void;
  /** Drop a tool from the Operation Profile, so its phase is unestablishable. */
  dropFromProfile: (tool: string) => void;
  /** Put a dropped tool back, so the profile places its phase again. */
  restoreToProfile: (tool: string) => void;
  /** Replace one tool's Operation Profile entry (#1629), or put the shipped entry back with `undefined`. */
  overrideProfile: (tool: string, mapping: ActionMapping | undefined) => void;
  /** How many decision requests the PEP has sent. */
  decisionRequests: () => number;
  /** What the decision function threw, in order: a PDP refusal before evaluation lands here (#252). */
  decideErrors: () => unknown[];
  digest: () => string;
}

function harness(
  opts: {
    recognizedConditions?: ReadonlySet<string>;
    /** Run inside the PEP's `observe` hook, after the Decision and before admission. */
    onObserve?: (h: Harness) => void;
    /** The Mission's Authority Set, in place of {@link AUTHORITY} (#252). */
    authority?: readonly unknown[];
    /**
     * Rows a durable retention backend hands the evidence store at startup
     * (#252): recovered as held, with no re-verification, which is exactly
     * the state a record changed at rest arrives in.
     */
    preload?: readonly Evidence[];
    /** The reference connectors, shared with another harness's committed effects (#252). */
    connectors?: Connectors;
    /** Rewrite the request on its way to the PDP: a non-conforming requester (#252). */
    rewrite?: (req: EvaluationRequest) => EvaluationRequest;
  } = {},
): Harness {
  let pepNowMs = BASE_MS;
  let state: MissionView["state"] = "active";
  const dropped = new Set<string>();
  const overridden = new Map<string, ActionMapping>();
  let requested = 0;
  const thrown: unknown[] = [];
  let replayed: Decision | undefined;
  let captured: Decision | undefined;
  let envelope: Record<string, unknown> | undefined;
  // Assigned at the end of this factory; the `observe` hook below only reads
  // it once a crossing runs, which is always after that assignment.
  let self: Harness;

  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [
      {
        id: "inv-1",
        vendor_id: "acme",
        amount: "125.00",
        currency: "USD",
        payee_account: "acct-acme",
        status: "payable",
      },
      // A second payable invoice of the same vendor, so a crossing refused at
      // the pre-effect boundary can be followed by a legitimate crossing of a
      // DISTINCT operation identity against this same store. The commit path
      // needs that: its refused attempt had already taken its own single use.
      {
        id: "inv-2",
        vendor_id: "acme",
        amount: "75.00",
        currency: "USD",
        payee_account: "acct-acme",
        status: "payable",
      },
    ],
  );

  const view = (): MissionView => ({
    id: "msn_252",
    issuer: "https://as.test",
    state,
    version: 1,
    authority_hash: "sha-256:m252",
    authority_set: (opts.authority ?? AUTHORITY) as MissionView["authority_set"],
    subject: { iss: "https://as.test", sub: "alice" },
    client_id: "ap-agent",
  });

  // @spec runtime#state-freshness — a synchronous live read, stamped on the
  // PEP's own clock, so the permit cap this deployment now applies
  // (observation plus the class staleness bound) is deterministic here.
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === "msn_252" && ref.issuer === "https://as.test"
      ? { view: view(), observation: { state: view().state, version: view().version, mode: "fresh", freshness_at: new Date(pepNowMs).toISOString() } }
      : undefined;

  const sequences = new Map<string, number>();
  const evidence = new EvidenceStore(
    EVIDENCE_KEYS.signing,
    EVIDENCE_KEYS.resolver,
    opts.preload
      ? {
          nextSequence: (missionId, emitterId, role) => {
            const key = `${missionId} ${emitterId} ${role}`;
            const n = sequences.get(key) ?? 100;
            sequences.set(key, n + 1);
            return n;
          },
          retain: () => {},
          retained: () => (opts.preload ?? []).map((row) => ({ row: row as never })),
        }
      : undefined,
  );
  const connectors = opts.connectors ?? new Connectors(() => new Date(pepNowMs));
  const engine = new TransactionEngine("epoch-252", () => new Date(BASE_MS));

  const pep = new Pep({
    // Replaying a captured permit is how a cross-phase presentation is built:
    // the SAME evaluation identifier, conditions and signed Decision Evidence
    // the earlier crossing was granted, presented at a later crossing.
    decide: async (req, options) => {
      requested += 1;
      if (replayed) return replayed;
      try {
        return await EVIDENCE_KEYS.decide(opts.rewrite ? opts.rewrite(req) : req, options);
      } catch (e) {
        thrown.push(e);
        throw e;
      }
    },
    observe: ({ decision, envelope: request }) => {
      captured = decision;
      envelope = request.context as unknown as Record<string, unknown>;
      opts.onObserve?.(self);
    },
    payments,
    evidence,
    fga: alwaysAllowFga,
    modelId: "unit-test-model",
    loadView,
    instanceEpoch: "epoch-252",
    now: () => new Date(pepNowMs),
    operationProfile: () =>
      Object.fromEntries(
        Object.entries(TOOL_ACTIONS)
          .filter(([tool]) => !dropped.has(tool))
          .map(([tool, mapping]) => [tool, overridden.get(tool) ?? mapping]),
      ) as Record<string, ActionMapping>,
    ...(opts.recognizedConditions ? { recognizedConditions: opts.recognizedConditions } : {}),
  });

  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
    jwks: { keys: [] },
    keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] },
    issuer: "https://as.test",
    transaction: { engine, connectors, evidence },
    writeReservations: openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" }),
  });

  self = {
    server,
    pep,
    evidence,
    connectors,
    engine,
    payments,
    lastDecision: () => captured,
    lastEnvelope: () => envelope,
    replay: (decision) => {
      replayed = decision;
    },
    advancePep: (ms) => {
      pepNowMs += ms;
    },
    suspendMission: () => {
      state = "suspended";
    },
    dropFromProfile: (tool) => {
      dropped.add(tool);
    },
    restoreToProfile: (tool) => {
      dropped.delete(tool);
    },
    overrideProfile: (tool, mapping) => {
      if (mapping === undefined) overridden.delete(tool);
      else overridden.set(tool, mapping);
    },
    decisionRequests: () => requested,
    decideErrors: () => thrown,
    digest: () => {
      const invoice = payments.getInvoice("inv-1");
      const vendor = invoice ? payments.getVendor(invoice.vendor_id) : undefined;
      if (!invoice || !vendor) throw new Error("seed missing inv-1/acme");
      return parameterDigest(
        buildEffectiveParams({
          action: "payments:payment.execute",
          invoice,
          vendor,
          resource: CANONICAL_RESOURCE,
        }),
      );
    },
  };
  return self;
}

/** The permit conditions of a captured decision. */
const conditionsOf = (decision: Decision | undefined) =>
  decision?.context.conditions as { valid_until?: string; action_phase?: string } | undefined;

const executions = (h: Harness): ExecutionEvidence[] =>
  h.evidence.forMission("msn_252").filter((e): e is ExecutionEvidence => e.kind === "execution");
const decisions = (h: Harness): DecisionEvidence[] =>
  h.evidence.forMission("msn_252").filter((e): e is DecisionEvidence => e.kind === "decision");

/** Every crossing of the compound action, with the dispatch path it takes. */
const crossings = [
  { tool: "check_transfer", phase: "preflight", call: "read" },
  { tool: "hold_transfer", phase: "prepare", call: "write" },
  { tool: "execute_wire_transfer", phase: "commit", call: "transaction" },
] as const;

async function cross(
  h: Harness,
  crossing: (typeof crossings)[number],
  hook?: () => void,
  invoiceId = "inv-1",
): Promise<{ ok: boolean; refusal_reason?: string; denial_reason?: string; result?: unknown }> {
  // @spec runtime#idempotency (#917): every crossing is a new intended
  // execution; only the keyed commit crossing takes a key, and intake (D316)
  // refuses one on the two crossings whose served schema declares none.
  const args =
    crossing.call === "transaction"
      ? { invoice_id: invoiceId, idempotency_key: `idem_${randomUUID()}` }
      : { invoice_id: invoiceId };
  if (crossing.call === "read") return h.server.callReadTool(crossing.tool, args, TOKEN, hook);
  if (crossing.call === "write") return h.server.callWriteTool(crossing.tool, args, TOKEN, hook);
  return h.server.callTransactionTool(crossing.tool, args, TOKEN, hook);
}

/**
 * @spec runtime#compound-actions (#252): the compensate crossing, through the
 * served transaction dispatch path. The agent names only the invoice whose
 * wire it asks to reverse, and a fresh key for this one compensation.
 */
async function reverse(
  h: Harness,
  invoiceId = "inv-1",
  idempotencyKey = `idem_${randomUUID()}`,
): Promise<{ ok: boolean; refusal_reason?: string; denial_reason?: string; result?: unknown }> {
  return h.server.callTransactionTool("reverse_wire_transfer", { invoice_id: invoiceId, idempotency_key: idempotencyKey }, TOKEN);
}

/** The Decision Evidence of the commit-phase permit for a wire, the original a compensation links. */
const commitPermitOf = (h: Harness): DecisionEvidence | undefined =>
  decisions(h).find((d) => d.content.decision === "permit" && d.content.action_phase === "commit");

/** The Decision Evidence the compensate crossing obtained. */
const compensating = (h: Harness): DecisionEvidence[] =>
  decisions(h).filter((d) => d.content.action.name === "payments:payment.reverse");

const refusalsOf = (h: Harness): RefusalRecord[] =>
  h.evidence.forMission("msn_252").filter((e): e is RefusalRecord => e.kind === "refusal");

/**
 * A compensation the PEP refused before any decision request because it could
 * not establish the committed original from verified evidence: the
 * diagnostic, no new decision request, no compensating Decision Evidence, no
 * reversal, and one verifiable signed `compensation_link_unavailable` record.
 */
async function expectLinkUnavailable(
  h: Harness,
  res: { ok: boolean; refusal_reason?: string; denial_reason?: string },
  requestsBefore: number,
  label: string,
): Promise<void> {
  expect(res, label).toMatchObject({ ok: false, refusal_reason: "compensation_link_unavailable" });
  expect(h.decisionRequests(), label).toBe(requestsBefore);
  expect(compensating(h), label).toHaveLength(0);
  expect(h.connectors.reversalEntries("msn_252"), label).toHaveLength(0);
  const refusals = refusalsOf(h).filter((r) => r.content.action.name === "payments:payment.reverse");
  expect(refusals, label).toHaveLength(1);
  expect(refusals[0]?.content, label).toMatchObject({
    denial_reason: "compensation_link_unavailable",
    emitter: { role: "pep" },
    mission: { id: "msn_252", issuer: "https://as.test" },
  });
  const content = refusals[0]?.content as RefusalRecord["content"];
  expect(await verifyEvidenceEnvelope(content, REFUSAL_RECORD_MEDIA_TYPE, EVIDENCE_KEYS.resolver), label).toEqual({ valid: true });
}

describe("compound-action phases (@spec runtime#compound-actions)", () => {
  it("obtains its own Decision for the prepare and the commit crossing", async () => {
    const h = harness();
    const seen: string[] = [];
    for (const crossing of crossings) {
      const res = await cross(h, crossing);
      expect(res.ok, `${crossing.tool}: ${JSON.stringify(res)}`).toBe(true);
      const decision = h.lastDecision();
      expect(decision?.decision).toBe(true);
      seen.push(decision?.context.decision_id as string);
    }
    // Three crossings, three distinct evaluation identifiers: no permit was
    // carried from one phase to the next.
    expect(new Set(seen).size).toBe(3);
    const permits = decisions(h).filter((d) => d.content.decision === "permit");
    expect(permits.map((d) => d.content.action_phase)).toEqual(["preflight", "prepare", "commit"]);
    // One identifier and one digest across all three, so only the phase told
    // them apart.
    expect(new Set(permits.map((d) => d.content.action.name))).toEqual(
      new Set(["payments:payment.execute"]),
    );
    expect(new Set(permits.map((d) => d.content.parameter_digest))).toEqual(new Set([h.digest()]));
  });

  it("binds the crossing's phase into conditions.action_phase", async () => {
    const h = harness();
    for (const crossing of crossings) {
      await cross(h, crossing);
      expect(conditionsOf(h.lastDecision())?.action_phase, crossing.tool).toBe(crossing.phase);
    }
    // An operation the Operation Profile places at no phase carries no
    // condition at all, so the member is not merely defaulted everywhere.
    await h.server.callWriteTool("schedule_payment", { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` }, TOKEN);
    expect(h.lastDecision()?.decision).toBe(true);
    expect(conditionsOf(h.lastDecision())?.action_phase).toBeUndefined();
  });

  it("refuses a commit presenting prepare's permit, zero connector effects", async () => {
    const h = harness();
    expect((await cross(h, crossings[1])).ok).toBe(true);
    const preparePermit = h.lastDecision();
    expect(conditionsOf(preparePermit)?.action_phase).toBe("prepare");

    h.replay(preparePermit);
    const refused = await cross(h, crossings[2]);
    expect(refused.ok).toBe(false);
    expect(refused.refusal_reason).toBe("phase_mismatch");
    expect(h.connectors.ledgerEntries("msn_252")).toHaveLength(0);
    const suppressed = executions(h).filter((e) => e.content.outcome === "suppressed");
    expect(suppressed).toHaveLength(1);
    expect(suppressed[0]?.content.error).toBe("phase_mismatch");
    // The refusal happened before redemption, so no operation row was opened
    // under the commit key at all.
    expect(h.engine.state(operationKey("msn_252", "payments:payment.execute", h.digest(), "commit"))).toBeUndefined();
  });

  it("refuses a commit presenting check_transfer's preflight permit", async () => {
    const h = harness();
    expect((await cross(h, crossings[0])).ok).toBe(true);
    const preflightPermit = h.lastDecision();
    expect(conditionsOf(preflightPermit)?.action_phase).toBe("preflight");

    h.replay(preflightPermit);
    const refused = await cross(h, crossings[2]);
    expect(refused.ok).toBe(false);
    expect(refused.refusal_reason).toBe("phase_mismatch");
    expect(h.connectors.ledgerEntries("msn_252")).toHaveLength(0);
    // A preflight Decision cannot be the gate for a consequential phase even
    // though its own crossing was permitted moments earlier.
    expect(executions(h).map((e) => e.content.error)).toEqual(["phase_mismatch"]);
  });

  it("compares the bound phase before any effect on all three dispatch paths", async () => {
    // A preflight crossing releases no connector effect and a prepare
    // crossing releases none either, so the comparison must sit in front of
    // every crossing rather than beside the one commit point.
    const cases = [
      { grant: crossings[1], present: crossings[0] },
      { grant: crossings[0], present: crossings[1] },
      { grant: crossings[1], present: crossings[2] },
    ];
    for (const { grant, present } of cases) {
      const h = harness();
      expect((await cross(h, grant)).ok, grant.tool).toBe(true);
      h.replay(h.lastDecision());
      const refused = await cross(h, present);
      expect(refused.ok, `${grant.tool} -> ${present.tool}`).toBe(false);
      expect(refused.refusal_reason, `${grant.tool} -> ${present.tool}`).toBe("phase_mismatch");
      expect(refused.result).toBeUndefined();
      expect(h.connectors.ledgerEntries("msn_252")).toHaveLength(0);
      expect(executions(h).filter((e) => e.content.error === "phase_mismatch")).toHaveLength(1);
    }
  });

  it("refuses a missing, unknown or malformed phase condition where the profile declares a phase", async () => {
    // Absent where required, and unknown or malformed where required, are the
    // same refusal: none of them establishes the phase the permit bound.
    const source = harness();
    expect((await cross(source, crossings[2])).ok).toBe(true);
    const permit = source.lastDecision();

    for (const bound of [undefined, "settle", "COMMIT", 3, null, { phase: "commit" }]) {
      const conditions = { ...(permit?.context.conditions as Record<string, unknown>) };
      if (bound === undefined) delete conditions.action_phase;
      else conditions.action_phase = bound;
      const h = harness();
      h.replay({ ...permit, context: { ...permit?.context, conditions } } as Decision);
      const refused = await cross(h, crossings[2]);
      expect(refused.ok, JSON.stringify(bound)).toBe(false);
      expect(refused.refusal_reason, JSON.stringify(bound)).toBe("phase_mismatch");
      expect(h.connectors.ledgerEntries("msn_252"), JSON.stringify(bound)).toHaveLength(0);
    }
  });

  it("refuses a phase condition on a crossing whose profile declares no phase", async () => {
    const h = harness();
    expect((await cross(h, crossings[1])).ok).toBe(true);
    h.replay(h.lastDecision());
    // schedule_payment is no phase of a compound action, so a phase condition
    // is unrecognized there and the permit is invalid at that crossing.
    const refused = await h.server.callWriteTool(
      "schedule_payment",
      { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` },
      TOKEN,
    );
    expect(refused.ok).toBe(false);
    expect(refused.refusal_reason).toBe("phase_mismatch");
  });

  it("refuses a crossing whose phase cannot be established at use", async () => {
    // The Operation Profile stops placing the tool between the Decision and
    // its use, so the crossing's own phase is unestablishable: fail closed,
    // never fall back to treating the crossing as unphased.
    const h = harness({ onObserve: (self) => self.dropFromProfile("execute_wire_transfer") });
    const refused = await cross(h, crossings[2]);
    expect(refused.ok).toBe(false);
    expect(refused.refusal_reason).toBe("phase_mismatch");
    expect(h.connectors.ledgerEntries("msn_252")).toHaveLength(0);
  });

  it("refuses a crossing dropped from the Operation Profile after admission, on every dispatch path", async () => {
    // The Operation Profile is live, so admission is not the last word on it.
    // The hook runs in the same decision-to-effect window the expiry case
    // uses, after admission and while the awaited capability and parameter
    // reads are still ahead: the crossing's phase stops being establishable
    // there, and the permit must be refused at the final boundary rather than
    // released on the strength of the earlier comparison.
    for (const crossing of crossings) {
      const h = harness();
      const refused = await cross(h, crossing, () => h.dropFromProfile(crossing.tool));
      expect(refused.ok, crossing.tool).toBe(false);
      expect(refused.refusal_reason, crossing.tool).toBe("phase_mismatch");
      expect(refused.result, crossing.tool).toBeUndefined();
      expect(h.connectors.ledgerEntries("msn_252"), crossing.tool).toHaveLength(0);
      const suppressed = executions(h).filter((e) => e.content.outcome === "suppressed");
      expect(suppressed.map((e) => e.content.error), crossing.tool).toEqual(["phase_mismatch"]);
      if (crossing.call === "transaction") {
        // The attempt had started, so its own redemption is spent and its
        // operation row is abandoned; nothing crossed to the connector.
        const opKey = operationKey("msn_252", "payments:payment.execute", h.digest(), "commit");
        expect(h.engine.state(opKey)).toBe("abandoned");
      }
    }
  });

  it("lets a legitimate crossing through against the same store after a pre-effect profile refusal", async () => {
    // The pre-effect comparison is not a blanket refusal: with the profile
    // whole again, the next crossing of the same phase executes against the
    // store the refused one left behind.
    for (const crossing of crossings) {
      const h = harness();
      const refused = await cross(h, crossing, () => h.dropFromProfile(crossing.tool));
      expect(refused.refusal_reason, crossing.tool).toBe("phase_mismatch");
      h.restoreToProfile(crossing.tool);
      // The commit path's refused attempt took its own single use before the
      // boundary (D28), so the legitimate commit is a DISTINCT operation
      // identity on the same store, never a replay of the abandoned one.
      const invoiceId = crossing.call === "transaction" ? "inv-2" : "inv-1";
      const allowed = await cross(h, crossing, undefined, invoiceId);
      expect(allowed.ok, `${crossing.tool}: ${JSON.stringify(allowed)}`).toBe(true);
      expect(allowed.result, crossing.tool).toBeDefined();
      expect(h.connectors.ledgerEntries("msn_252"), crossing.tool).toHaveLength(
        crossing.call === "transaction" ? 1 : 0,
      );
    }
  });

  it("ignores an agent-supplied action_phase argument and uses the catalog phase", async () => {
    const h = harness();
    // The PEP, handed the argument past the tool boundary, never reads it:
    // the request context and the permit condition both carry the profile's
    // phase, not the argument's.
    const res = await h.pep.enforce("hold_transfer", { invoice_id: "inv-1", action_phase: "commit" }, TOKEN);
    expect(res.permitted, res.refusal_reason ?? res.denial_reason).toBe(true);
    expect(h.lastEnvelope()?.action_phase).toBe("prepare");
    expect(conditionsOf(h.lastDecision())?.action_phase).toBe("prepare");
    // At the served tool boundary the argument is a member of neither
    // crossing's schema, so intake (D316) refuses it before any Decision, and
    // it cannot make a commit crossing accept the prepare permit.
    h.replay(h.lastDecision());
    const prepare = await h.server.callWriteTool("hold_transfer", { invoice_id: "inv-1", action_phase: "commit" }, TOKEN);
    expect(prepare).toEqual({ ok: false, refusal_reason: "invalid_request" });
    const refused = await h.server.callTransactionTool(
      "execute_wire_transfer",
      { invoice_id: "inv-1", action_phase: "prepare", idempotency_key: `idem_${randomUUID()}` },
      TOKEN,
    );
    expect(refused).toEqual({ ok: false, refusal_reason: "invalid_request" });
    expect(h.connectors.ledgerEntries("msn_252")).toHaveLength(0);
  });

  it("treats the permit as invalid when the PEP's recognized set lacks action_phase", async () => {
    // A phase-blind PEP: the must-understand rule makes a permit carrying an
    // unrecognized condition member unusable, so it refuses rather than
    // executing and rather than silently ignoring the phase.
    const h = harness({ recognizedConditions: new Set(["parameter_digest", "valid_until", "use_limit"]) });
    const refused = await cross(h, crossings[2]);
    expect(refused.ok).toBe(false);
    expect(refused.refusal_reason).toBe("unrecognized_condition");
    expect(h.connectors.ledgerEntries("msn_252")).toHaveLength(0);
    expect(executions(h).map((e) => e.content.error)).toEqual(["condition_unrecognized"]);
  });

  it("denies the fresh commit Decision when the Mission deactivates after prepare", async () => {
    const h = harness();
    expect((await cross(h, crossings[1])).ok).toBe(true);
    // The prepare crossing's hold is state, not authority: the commit takes
    // its own Decision against current Mission state and is denied.
    h.suspendMission();
    const refused = await cross(h, crossings[2]);
    expect(refused.ok).toBe(false);
    expect(refused.denial_reason).toBe("mission_inactive");
    expect(h.connectors.ledgerEntries("msn_252")).toHaveLength(0);
  });

  it("records action_phase on Decision Evidence for a permit and for a denial", async () => {
    const h = harness();
    expect((await cross(h, crossings[2])).ok).toBe(true);
    h.suspendMission();
    expect((await cross(h, crossings[2])).ok).toBe(false);
    const [permit, denial] = decisions(h).map((d) => d.content);
    expect(permit?.decision).toBe("permit");
    expect(permit?.action_phase).toBe("commit");
    // Recorded once, top-level: never inside the record's normalized
    // `conditions`, which carry the validity and use bounds only.
    expect(permit?.conditions).toEqual({
      valid_until: expect.any(String),
      use_limit: 1,
    });
    // A denial has no permit condition to mirror and still records the
    // validated request phase.
    expect(denial?.decision).toBe("deny");
    expect(denial?.action_phase).toBe("commit");
    expect(denial?.conditions).toBeUndefined();
  });

  it("keys the operation on the phase where two tools share an action identifier", async () => {
    const digestOf = harness().digest();
    // The identifier and the digest are identical across phases, so without
    // the phase all three crossings would claim ONE key.
    expect(operationKey("msn_252", "payments:payment.execute", digestOf, "prepare")).not.toBe(
      operationKey("msn_252", "payments:payment.execute", digestOf, "commit"),
    );
    // A crossing the profile places at no phase keeps its historical key.
    expect(operationKey("msn_252", "payments:payment.schedule", digestOf)).toBe(
      `op:msn_252:payments:payment.schedule:${digestOf}`,
    );

    const h = harness();
    const committed = await cross(h, crossings[2]);
    expect(committed.ok, JSON.stringify(committed)).toBe(true);
    const opKey = (committed.result as { op_key: string }).op_key;
    // Every consumer keyed on operation identity sees the SAME phase-qualified
    // key: the operation state machine, the connector's own idempotency key,
    // and the join key on Execution Evidence.
    expect(opKey).toBe(operationKey("msn_252", "payments:payment.execute", h.digest(), "commit"));
    expect(h.engine.state(opKey)).toBe("reconciled");
    expect(h.connectors.ledgerEntries("msn_252").map((r) => r.op_key)).toEqual([opKey]);
    expect(executions(h).map((e) => e.op_key)).toEqual([opKey]);

    // A refused prepare crossing over the same identifier keys somewhere
    // else entirely, so one phase cannot burn another's claim.
    const prepared = await h.server.callWriteTool("hold_transfer", { invoice_id: "inv-1" }, TOKEN, () => {
      h.payments.bumpInvoiceAmount("inv-1", "127.00");
    });
    expect(prepared.ok).toBe(false);
    const preparedRecord = executions(h).find((e) => e.content.outcome === "suppressed");
    expect(preparedRecord?.op_key).toContain(":prepare:");
    expect(preparedRecord?.op_key).not.toBe(opKey);
  });

  it("refuses a wrong-phase commit and then lets the legitimate commit through against the same store", async () => {
    // Checking phase BEFORE redemption is what makes both halves pass: a
    // refusal that had burned the redemption row would leave the legitimate
    // commit reporting `permit_consumed`.
    const h = harness();
    expect((await cross(h, crossings[1])).ok).toBe(true);
    h.replay(h.lastDecision());
    expect((await cross(h, crossings[2])).refusal_reason).toBe("phase_mismatch");

    h.replay(undefined);
    const committed = await cross(h, crossings[2]);
    expect(committed.ok, JSON.stringify(committed)).toBe(true);
    expect(h.connectors.ledgerEntries("msn_252")).toHaveLength(1);
  });

  it("offsets a committed wire through the reference connector under a fresh compensate Decision whose evidence links the original commit's evaluation_id", async () => {
    const h = harness();
    const committed = await cross(h, crossings[2]);
    expect(committed.ok, JSON.stringify(committed)).toBe(true);
    const wireOpKey = (committed.result as { op_key: string }).op_key;
    const original = commitPermitOf(h)?.content;
    expect(original?.evaluation_id).toEqual(expect.any(String));

    const reversed = await reverse(h);
    expect(reversed.ok, JSON.stringify(reversed)).toBe(true);
    // The PEP carried the link it established from its own evidence, and the
    // compensation obtained its own Decision: a fresh, single-use permit for
    // its own action, at the compensate phase.
    expect(h.lastEnvelope()?.compensates_evaluation_id).toBe(original?.evaluation_id);
    const records = compensating(h);
    expect(records).toHaveLength(1);
    const record = records[0]?.content;
    expect(record?.decision).toBe("permit");
    expect(record?.action_phase).toBe("compensate");
    expect(record?.compensates_evaluation_id).toBe(original?.evaluation_id);
    expect(record?.evaluation_id).not.toBe(original?.evaluation_id);
    expect(record?.conditions?.use_limit).toBe(1);
    expect(await verifyEvidenceEnvelope(record as never, DECISION_EVIDENCE_MEDIA_TYPE, EVIDENCE_KEYS.resolver)).toEqual({ valid: true });
    // The reference connector offset exactly the committed wire, under the
    // compensation's own operation key and permit, and left the wire's own
    // ledger entry as it was.
    const reverseOpKey = (reversed.result as { op_key: string }).op_key;
    expect(reverseOpKey).toBe(
      operationKey("msn_252", "payments:payment.reverse", record?.parameter_digest as string, "compensate"),
    );
    expect(reverseOpKey).not.toBe(wireOpKey);
    expect(h.connectors.reversalEntries("msn_252")).toEqual([
      expect.objectContaining({
        op_key: reverseOpKey,
        reversed_op_key: wireOpKey,
        invoice_id: "inv-1",
        amount: "125.00",
        currency: "USD",
        permit_id: record?.evaluation_id,
      }),
    ]);
    expect(h.connectors.ledgerEntries("msn_252")).toHaveLength(1);
    // Each effect has its own completed Execution Evidence, and
    // reconciliation joins both: the reversal is an effect of its own permit.
    expect(executions(h).filter((e) => e.content.outcome === "completed").map((e) => e.op_key)).toEqual([wireOpKey, reverseOpKey]);
    expect(reconcile("msn_252", h.evidence, h.connectors).ok).toBe(true);
  });

  it("the PDP refuses a compensate request without compensates_evaluation_id, or with a malformed one, before evaluation", async () => {
    // A requester that drops or garbles the link: the PDP never evaluates the
    // request, so no compensate Decision exists without its required link.
    const cases: Array<[string, (ctx: Record<string, unknown>) => void]> = [
      ["absent", (ctx) => delete ctx.compensates_evaluation_id],
      ["empty", (ctx) => (ctx.compensates_evaluation_id = "")],
      ["outside the identifier syntax", (ctx) => (ctx.compensates_evaluation_id = "dec 1")],
      ["over 64 characters", (ctx) => (ctx.compensates_evaluation_id = "d".repeat(65))],
      ["a number", (ctx) => (ctx.compensates_evaluation_id = 7)],
      ["null", (ctx) => (ctx.compensates_evaluation_id = null)],
    ];
    for (const [label, garble] of cases) {
      const h = harness({
        rewrite: (req) => {
          if (req.context.action_phase !== "compensate") return req;
          const context = { ...req.context } as Record<string, unknown>;
          garble(context);
          return { ...req, context } as EvaluationRequest;
        },
      });
      expect((await cross(h, crossings[2])).ok, label).toBe(true);
      const refused = await reverse(h);
      expect(refused.ok, label).toBe(false);
      const thrown = h.decideErrors();
      expect(thrown, label).toHaveLength(1);
      expect(thrown[0], label).toBeInstanceOf(DecisionRequestRefused);
      expect((thrown[0] as DecisionRequestRefused).denial_reason, label).toBe("compensation_link_invalid");
      expect(compensating(h), label).toHaveLength(0);
      expect(h.connectors.reversalEntries("msn_252"), label).toHaveLength(0);
      expect(executions(h).filter((e) => e.content.outcome !== "completed"), label).toHaveLength(0);
    }
  });

  it("ignores an agent-supplied compensates_evaluation_id argument and links the verified original", async () => {
    const h = harness();
    expect((await cross(h, crossings[1])).ok).toBe(true);
    const heldEvaluation = h.lastDecision()?.context.decision_id as string;
    expect((await cross(h, crossings[2])).ok).toBe(true);
    const original = commitPermitOf(h)?.content.evaluation_id;
    expect(original).not.toBe(heldEvaluation);
    // Handed past the tool boundary, an argument naming another evaluation is
    // never read: the request, the Decision Evidence and the established link
    // all carry the committed original.
    const res = await h.pep.enforce(
      "reverse_wire_transfer",
      { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}`, compensates_evaluation_id: heldEvaluation },
      TOKEN,
    );
    expect(res.permitted, res.refusal_reason ?? res.denial_reason).toBe(true);
    expect(h.lastEnvelope()?.compensates_evaluation_id).toBe(original);
    expect(res.compensates?.evaluationId).toBe(original);
    expect(compensating(h).map((d) => d.content.compensates_evaluation_id)).toEqual([original]);
    // At the served tool boundary the member is in no schema, so intake
    // (D316) refuses it before any Decision, whatever it names.
    const refused = await h.server.callTransactionTool(
      "reverse_wire_transfer",
      { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}`, compensates_evaluation_id: original },
      TOKEN,
    );
    expect(refused).toEqual({ ok: false, refusal_reason: "invalid_request" });
    expect(h.connectors.reversalEntries("msn_252")).toHaveLength(0);
  });

  it("refuses a compensation whose original is unknown before any decision request", async () => {
    // Nothing committed at all.
    const empty = harness();
    await expectLinkUnavailable(empty, await reverse(empty), 0, "no evidence at all");
    // A wire committed for one invoice links nothing for another.
    const h = harness();
    expect((await cross(h, crossings[2])).ok).toBe(true);
    const before = h.decisionRequests();
    await expectLinkUnavailable(h, await reverse(h, "inv-2"), before, "another invoice's wire");
    expect(h.connectors.ledgerEntries("msn_252")).toHaveLength(1);
  });

  it("refuses a compensation whose original was only prepared, held or refused before any decision request", async () => {
    const h = harness();
    expect((await cross(h, crossings[0])).ok).toBe(true);
    expect((await cross(h, crossings[1])).ok).toBe(true);
    // A commit-phase permit whose wire never committed: it expired before the effect.
    const expired = await cross(h, crossings[2], () => h.advancePep(10 * 60 * 1000));
    expect(expired.refusal_reason).toBe("permit_expired");
    expect(commitPermitOf(h)).toBeDefined();
    expect(h.connectors.ledgerEntries("msn_252")).toHaveLength(0);
    h.advancePep(-10 * 60 * 1000);
    const before = h.decisionRequests();
    await expectLinkUnavailable(h, await reverse(h), before, "prepared, held and refused only");
  });

  it("refuses a compensation whose original record does not verify before any decision request", async () => {
    const source = harness();
    expect((await cross(source, crossings[2])).ok).toBe(true);
    const rows = [...source.evidence.all()];
    // A row changed at rest, recovered by the store as held: one member of the
    // commit's Decision Evidence, or of its completed Execution Evidence,
    // under the envelope signed over the original bytes.
    const decisionAltered = rows.map((r) =>
      r.kind === "decision" && r.content.action_phase === "commit"
        ? ({ ...r, content: { ...r.content, evaluated_at: "2026-01-01T00:00:00.000Z" } } as Evidence)
        : r,
    );
    const executionAltered = rows.map((r) =>
      r.kind === "execution" && r.content.outcome === "completed"
        ? ({ ...r, content: { ...r.content, outcome_at: "2026-01-01T00:00:00.000Z" } } as Evidence)
        : r,
    );
    for (const [label, preload] of [
      ["Decision Evidence altered", decisionAltered],
      ["Execution Evidence altered", executionAltered],
    ] as const) {
      const h = harness({ preload, connectors: source.connectors });
      await expectLinkUnavailable(h, await reverse(h), 0, label);
    }
    // Control: the same records unaltered link the original, and the wire is offset.
    const control = harness({ preload: rows, connectors: source.connectors });
    const reversed = await reverse(control);
    expect(reversed.ok, JSON.stringify(reversed)).toBe(true);
    expect(source.connectors.reversalEntries("msn_252")).toHaveLength(1);
  });

  it("refuses the original commit permit presented at the compensating crossing: zero effects, one suppressed Execution Evidence record, no Refusal Record", async () => {
    const h = harness();
    expect((await cross(h, crossings[2])).ok).toBe(true);
    const commitPermit = h.lastDecision();
    expect(conditionsOf(commitPermit)?.action_phase).toBe("commit");
    h.replay(commitPermit);
    const refused = await reverse(h);
    expect(refused.ok).toBe(false);
    expect(refused.refusal_reason).toBe("phase_mismatch");
    expect(h.connectors.reversalEntries("msn_252")).toHaveLength(0);
    expect(h.connectors.ledgerEntries("msn_252")).toHaveLength(1);
    const suppressed = executions(h).filter((e) => e.content.outcome === "suppressed");
    expect(suppressed).toHaveLength(1);
    expect(suppressed[0]?.content.evaluation_id).toBe(commitPermit?.context.decision_id);
    expect(suppressed[0]?.content.error).toBe("phase_mismatch");
    expect(refusalsOf(h)).toHaveLength(0);
  });

  it("denies a compensation the Mission's authority does not cover, though its link to the committed original is established", async () => {
    // The link and the original commit's authority grant nothing: without
    // its own authority the compensation is denied, and the denial still
    // records the validated link.
    const h = harness({ authority: AUTHORITY_WITHOUT_REVERSE });
    expect((await cross(h, crossings[2])).ok).toBe(true);
    const original = commitPermitOf(h)?.content.evaluation_id;
    const denied = await reverse(h);
    expect(denied).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
    expect(h.lastEnvelope()?.compensates_evaluation_id).toBe(original);
    expect(compensating(h).map((d) => [d.content.decision, d.content.action_phase, d.content.compensates_evaluation_id])).toEqual([
      ["deny", "compensate", original],
    ]);
    expect(h.connectors.reversalEntries("msn_252")).toHaveLength(0);
  });

  it("does not offset a committed wire twice under a duplicate compensation", async () => {
    const h = harness();
    expect((await cross(h, crossings[2])).ok).toBe(true);
    const key = `idem_${randomUUID()}`;
    expect((await reverse(h, "inv-1", key)).ok).toBe(true);
    // The same key again: the PDP's claim answers it with the completed
    // compensation, never a second one.
    const again = await reverse(h, "inv-1", key);
    expect(again).toMatchObject({ ok: false, denial_reason: "duplicate_suppressed" });
    // A new key is a new compensation request for an operation already
    // claimed: its fresh permit is refused at use, before the connector.
    const fresh = await reverse(h);
    expect(fresh).toMatchObject({ ok: false, refusal_reason: "permit_consumed" });
    expect(executions(h).filter((e) => e.content.outcome === "suppressed").map((e) => e.content.error)).toEqual([
      "operation_already_claimed",
    ]);
    expect(h.connectors.reversalEntries("msn_252")).toHaveLength(1);
  });

  it("the reference connector offsets a committed wire once, and refuses an unknown or uncommitted one", () => {
    const connectors = new Connectors();
    const wire = { invoiceId: "inv-1", payeeAccount: "acct-acme", amount: "125.00", currency: "USD", missionId: "msn_252" };
    expect(connectors.postWire({ ...wire, opKey: "op:wire", permitId: "dec_wire" })).toEqual({ committed: true, deduped: false });
    const reversal = { reversedOpKey: "op:wire", reversedPermitId: "dec_wire", missionId: "msn_252" };
    expect(connectors.reverseWire({ ...reversal, opKey: "op:rev-1", permitId: "dec_rev_1" })).toEqual({ committed: true, deduped: false });
    // A retry under the same operation key is deduped, not a second offset.
    expect(connectors.reverseWire({ ...reversal, opKey: "op:rev-1", permitId: "dec_rev_1" })).toEqual({ committed: true, deduped: true });
    // A second reversal of the same wire under another operation key is refused.
    expect(connectors.reverseWire({ ...reversal, opKey: "op:rev-2", permitId: "dec_rev_2" })).toEqual({
      committed: false,
      deduped: false,
      refusal: "already_reversed",
    });
    // A wire never committed, and a committed key the link's permit did not commit, are refused.
    for (const named of [
      { reversedOpKey: "op:unknown", reversedPermitId: "dec_wire" },
      { reversedOpKey: "op:wire", reversedPermitId: "dec_other" },
    ]) {
      expect(connectors.reverseWire({ ...named, missionId: "msn_252", opKey: "op:rev-3", permitId: "dec_rev_3" })).toEqual({
        committed: false,
        deduped: false,
        refusal: "wire_not_committed",
      });
    }
    expect(connectors.reversalEntries()).toEqual([expect.objectContaining({ op_key: "op:rev-1", reversed_op_key: "op:wire" })]);
  });
});

describe("permit initiation validity at use (@spec runtime#execution-reverification)", () => {
  it("refuses a permit that expires during an awaited resolver on every dispatch path, with zero effects", async () => {
    for (const crossing of crossings) {
      const h = harness();
      // The hook runs in the decision-to-effect window, after admission and
      // before the awaited capability and parameter reads complete: exactly
      // where a permit can expire while a resolver call is pending.
      const refused = await cross(h, crossing, () => h.advancePep(10 * 60 * 1000));
      expect(refused.ok, crossing.tool).toBe(false);
      expect(refused.refusal_reason, crossing.tool).toBe("permit_expired");
      expect(refused.result, crossing.tool).toBeUndefined();
      expect(h.connectors.ledgerEntries("msn_252"), crossing.tool).toHaveLength(0);
      const suppressed = executions(h).filter((e) => e.content.outcome === "suppressed");
      expect(suppressed.map((e) => e.content.error), crossing.tool).toEqual(["permit_expired"]);
      if (crossing.call === "transaction") {
        // The engine's own lease is untouched here: only the PEP's clock
        // moved, so the gate that fired is permit INITIATION validity, not
        // the lease governing an already-started effect.
        const opKey = operationKey("msn_252", "payments:payment.execute", h.digest(), "commit");
        expect(h.engine.state(opKey)).toBe("abandoned");
        expect(h.engine.leaseValid(opKey)).toBe(true);
      }
    }
  });

  it("takes no redemption when no lease can be derived from the permit's remaining validity", async () => {
    // The boundary case: the permit is valid THROUGH this instant, so
    // admission passes, and there is no interval left for a lease. A lease
    // that could not be derived opens no operation row and takes no
    // redemption, and the refusal names the permit's window rather than a
    // duplicate.
    const source = harness();
    expect((await cross(source, crossings[2])).ok).toBe(true);
    const permit = source.lastDecision();
    const conditions = { ...(permit?.context.conditions as Record<string, unknown>) };
    conditions.valid_until = new Date(BASE_MS).toISOString();

    const h = harness();
    h.replay({ ...permit, context: { ...permit?.context, conditions } } as Decision);
    const refused = await cross(h, crossings[2]);
    expect(refused.refusal_reason).toBe("permit_expired");
    expect(h.connectors.ledgerEntries("msn_252")).toHaveLength(0);
    expect(
      h.engine.state(operationKey("msn_252", "payments:payment.execute", h.digest(), "commit")),
    ).toBeUndefined();
    expect(executions(h).map((e) => e.content.error)).toEqual(["permit_expired"]);
  });

  it("refuses an already-expired permit at admission, before it burns a redemption", async () => {
    const h = harness();
    expect((await cross(h, crossings[2])).ok).toBe(true);
    const permit = h.lastDecision();
    h.replay(permit);
    h.advancePep(10 * 60 * 1000);
    const refused = await cross(h, crossings[2]);
    expect(refused.refusal_reason).toBe("permit_expired");
    // Admission refused before redemption, so the earlier operation row is
    // the only one and it was never rewritten by this attempt.
    const opKey = operationKey("msn_252", "payments:payment.execute", h.digest(), "commit");
    expect(h.engine.state(opKey)).toBe("reconciled");
  });
});

describe("the Operation Profile is the trusted source of a crossing's phase (@spec runtime#compound-actions)", () => {
  it("pins the Operation Profile's phases against the trusted catalog's own per-tool declaration", () => {
    // Two places name the tool set, so they are held equal here: a phase
    // retagged in `catalog.json` without the profile, or the reverse, is a
    // configuration drift the PDP would validate and the PEP would compare
    // against different answers.
    const profile = Object.entries(TOOL_ACTIONS).map(([tool, mapping]) => ({
      tool,
      action: mapping.action,
      action_phase: mapping.phase,
    }));
    const catalog = [...CATALOG_TOOL_BINDINGS].map(([tool, binding]) => ({
      tool,
      action: binding.action,
      action_phase: binding.action_phase,
    }));
    const byTool = (a: { tool: string }, b: { tool: string }) => a.tool.localeCompare(b.tool);
    expect([...profile].sort(byTool)).toEqual([...catalog].sort(byTool));
    // And the served tool list agrees with both.
    expect(TOOLS.map((t) => t.name).sort()).toEqual(Object.keys(TOOL_ACTIONS).sort());
    for (const tool of TOOLS) expect(TOOL_ACTIONS[tool.name]?.action).toBe(tool.action);
  });

  it("declares an explicit connector operation for exactly the committing tools", () => {
    // The `execute_wire_transfer ? postWire : sendEmail` ternary sent an email
    // for any other name reaching the commit point, so a newly served tool of
    // the compound action would have mis-executed. The mapping is exhaustive
    // over the tools that route to a connector.
    const committing = Object.entries(TOOL_ACTIONS)
      .filter(([, mapping]) => mapping.tier === "transaction-assurance")
      .map(([tool]) => tool);
    expect([...CONNECTOR_TOOLS].sort()).toEqual(committing.sort());
  });
});

describe("a phase the PEP cannot establish is refused before any decision request (@spec runtime-evidence#pre-decision-refusal, authzen#failure-condition-coverage, #1629)", () => {
  /** The refusal: the diagnostic, no decision request, no Decision Evidence, no effect, and one verifiable signed `phase_unavailable` record. */
  async function expectPhaseUnavailable(
    h: Harness,
    res: { ok: boolean; refusal_reason?: string; denial_reason?: string },
    label: string,
  ): Promise<void> {
    expect(res, label).toMatchObject({ ok: false, refusal_reason: "phase_unavailable" });
    expect(res.denial_reason, label).toBeUndefined();
    expect(h.decisionRequests(), label).toBe(0);
    expect(decisions(h), label).toHaveLength(0);
    expect(executions(h), label).toHaveLength(0);
    expect(h.connectors.ledgerEntries("msn_252"), label).toHaveLength(0);
    const refusals = h.evidence.forMission("msn_252").filter((e): e is RefusalRecord => e.kind === "refusal");
    expect(refusals, label).toHaveLength(1);
    expect(refusals[0]?.content, label).toMatchObject({
      denial_reason: "phase_unavailable",
      emitter: { role: "pep" },
      action: { name: "payments:payment.execute" },
      mission: { id: "msn_252", issuer: "https://as.test" },
    });
    const content = refusals[0]?.content as RefusalRecord["content"];
    expect(await verifyEvidenceEnvelope(content, REFUSAL_RECORD_MEDIA_TYPE, EVIDENCE_KEYS.resolver), label).toEqual({ valid: true });
  }

  it("refuses a crossing whose Operation Profile entry places no phase, or a phase outside the closed set, on every dispatch path: no decision request, no Decision Evidence, no effect, one signed phase_unavailable Refusal Record", async () => {
    for (const crossing of crossings) {
      const base = TOOL_ACTIONS[crossing.tool] as ActionMapping;
      const { phase: _dropped, ...phaseless } = base;
      for (const [label, entry] of [
        ["no phase", phaseless as ActionMapping],
        ["out-of-set phase", { ...base, phase: "settle" } as unknown as ActionMapping],
      ] as const) {
        const h = harness();
        h.overrideProfile(crossing.tool, entry);
        await expectPhaseUnavailable(h, await cross(h, crossing), `${crossing.tool}: ${label}`);
      }
    }
  });

  it("the same crossings under the shipped Operation Profile reach the PDP with their phase", async () => {
    const h = harness();
    for (const [i, crossing] of crossings.entries()) {
      const res = await cross(h, crossing);
      expect(res.ok, `${crossing.tool}: ${JSON.stringify(res)}`).toBe(true);
      expect(h.decisionRequests()).toBe(i + 1);
      expect(h.lastEnvelope()?.action_phase).toBe(crossing.phase);
    }
    expect(h.evidence.forMission("msn_252").filter((e) => e.kind === "refusal")).toHaveLength(0);
  });
});
