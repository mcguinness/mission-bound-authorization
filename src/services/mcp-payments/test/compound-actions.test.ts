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
 * Unconditional: the FGA check is a stub, so this file never skips.
 */

import { describe, expect, it } from "vitest";
import { CATALOG_TOOL_BINDINGS } from "@mission/demo-data";
import type { Decision, Fga, MissionView } from "@mission/pdp";
import {
  buildEffectiveParams,
  CANONICAL_RESOURCE,
  Connectors,
  CONNECTOR_TOOLS,
  createEphemeralEvidenceKeys,
  type DecisionEvidence,
  EvidenceStore,
  type ExecutionEvidence,
  McpPaymentsServer,
  operationKey,
  parameterDigest,
  PaymentsStore,
  Pep,
  TOOL_ACTIONS,
  TOOLS,
  TransactionEngine,
  type ActionMapping,
  type TokenFacts,
} from "../src/index.js";

const EVIDENCE_KEYS = createEphemeralEvidenceKeys();
const BASE_MS = Date.parse("2026-09-08T12:00:00.000Z");
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const AUTHORITY = [
  {
    type: "mission_resource_access",
    resource: CANONICAL_RESOURCE,
    actions: ["payments:payment.execute", "payments:payment.schedule", "payments:invoice.read"],
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
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
};

interface Harness {
  server: McpPaymentsServer;
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
  digest: () => string;
}

function harness(
  opts: {
    recognizedConditions?: ReadonlySet<string>;
    /** Run inside the PEP's `observe` hook, after the Decision and before admission. */
    onObserve?: (h: Harness) => void;
  } = {},
): Harness {
  let pepNowMs = BASE_MS;
  let state: MissionView["state"] = "active";
  const dropped = new Set<string>();
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
    ],
  );

  const view = (): MissionView => ({
    id: "msn_252",
    issuer: "https://as.test",
    state,
    version: 1,
    authority_hash: "sha-256:m252",
    authority_set: AUTHORITY as MissionView["authority_set"],
    subject: { iss: "https://as.test", sub: "alice" },
    client_id: "ap-agent",
  });

  // @spec runtime#state-freshness — a synchronous live read, stamped on the
  // PEP's own clock, so the permit cap this deployment now applies
  // (observation plus the class staleness bound) is deterministic here.
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === "msn_252" && ref.issuer === "https://as.test"
      ? { view: view(), freshness: { observed_at: new Date(pepNowMs).toISOString(), source: "load_view" } }
      : undefined;

  const evidence = new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver);
  const connectors = new Connectors(() => new Date(pepNowMs));
  const engine = new TransactionEngine("epoch-252", () => new Date(BASE_MS));

  const pep = new Pep({
    // Replaying a captured permit is how a cross-phase presentation is built:
    // the SAME evaluation identifier, conditions and signed Decision Evidence
    // the earlier crossing was granted, presented at a later crossing.
    decide: async (req, options) => {
      if (replayed) return replayed;
      return EVIDENCE_KEYS.decide(req, options);
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
    allowedFreshnessSources: new Set(["load_view"]),
    now: () => new Date(pepNowMs),
    operationProfile: () =>
      Object.fromEntries(
        Object.entries(TOOL_ACTIONS).filter(([tool]) => !dropped.has(tool)),
      ) as Record<string, ActionMapping>,
    ...(opts.recognizedConditions ? { recognizedConditions: opts.recognizedConditions } : {}),
  });

  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
    jwks: { keys: [] },
    issuer: "https://as.test",
    transaction: { engine, connectors, evidence },
  });

  self = {
    server,
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
): Promise<{ ok: boolean; refusal_reason?: string; denial_reason?: string; result?: unknown }> {
  const args = { invoice_id: "inv-1" };
  if (crossing.call === "read") return h.server.callReadTool(crossing.tool, args, TOKEN, hook);
  if (crossing.call === "write") return h.server.callWriteTool(crossing.tool, args, TOKEN, hook);
  return h.server.callTransactionTool(crossing.tool, args, TOKEN, hook);
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
    await h.server.callWriteTool("schedule_payment", { invoice_id: "inv-1" }, TOKEN);
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
    const refused = await h.server.callWriteTool("schedule_payment", { invoice_id: "inv-1" }, TOKEN);
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

  it("ignores an agent-supplied action_phase argument and uses the catalog phase", async () => {
    const h = harness();
    const res = await h.server.callWriteTool(
      "hold_transfer",
      { invoice_id: "inv-1", action_phase: "commit" },
      TOKEN,
    );
    expect(res.ok, JSON.stringify(res)).toBe(true);
    // The request context and the permit condition both carry the profile's
    // phase, not the argument's.
    expect(h.lastEnvelope()?.action_phase).toBe("prepare");
    expect(conditionsOf(h.lastDecision())?.action_phase).toBe("prepare");
    // And the argument cannot make a commit crossing accept this permit.
    h.replay(h.lastDecision());
    const refused = await h.server.callTransactionTool(
      "execute_wire_transfer",
      { invoice_id: "inv-1", action_phase: "prepare" },
      TOKEN,
    );
    expect(refused.refusal_reason).toBe("phase_mismatch");
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
      .filter(([, mapping]) => mapping.actionClass !== undefined)
      .map(([tool]) => tool);
    expect([...CONNECTOR_TOOLS].sort()).toEqual(committing.sort());
  });
});
