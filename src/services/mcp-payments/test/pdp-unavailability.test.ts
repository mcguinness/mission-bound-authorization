import { describe, expect, it, vi } from "vitest";
import { createDecisionChannel, createEphemeralDecisionPoint, type DecisionFn, evaluateRemote, type Fga, isDecisionChannelRefusal, type MissionView, RUNTIME_POSTURE, loadRuntimePosture, relationForAction, stalenessBoundSeconds } from "@mission/pdp";
import { CANONICAL_RESOURCE, createEphemeralEvidenceKeys, EvidenceStore, McpPaymentsServer, PaymentsStore, Pep, type TokenFacts } from "../src/index.js";
import { PaymentsToolCatalog } from "../src/tool-catalog.js";

async function build(mode: "co-resident" | "remote", override?: DecisionFn) {
  const point = createEphemeralDecisionPoint({ emitterId: CANONICAL_RESOURCE, audience: CANONICAL_RESOURCE });
  const keys = createEphemeralEvidenceKeys({ decisionPoint: point });
  const evidence = new EvidenceStore(keys.signing, keys.resolver);
  const payments = new PaymentsStore();
  payments.seed([{ id: "acme", name: "Acme", status: "approved" }], [{ id: "one", vendor_id: "acme", amount: "12.00", currency: "USD", payee_account: "acct", status: "payable" }]);
  const source = new PaymentsToolCatalog().resolve("get_invoice");
  if (!source.catalog_sourced) throw new Error("fixture catalog missing");
  const view: MissionView = {
    id: "msn_remote", issuer: "https://as.test", state: "active", version: 1,
    authority_hash: "sha-256:fixture", subject: { iss: "https://as.test", sub: "alice" }, client_id: "agent",
    authority_set: [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"], constraints: { vendors: ["acme"] }, capability_sources: [{ action: "payments:invoice.read", ...source.binding }] }],
  };
  const fga = { checkWithContext: async () => true } as unknown as Fga;
  const loadView = () => ({ view, freshness: { observed_at: new Date().toISOString(), source: "load_view" } });
  const getOptions = vi.fn(() => ({ view, fga, modelId: "test", now: () => new Date(), stalenessBoundSeconds, relationForAction, allowedFreshnessSources: new Set(["load_view"]) }));
  const channel = await createDecisionChannel(point, { mode, pepId: "payments-pep", audience: CANONICAL_RESOURCE, getOptions });
  const observe = vi.fn();
  const pep = new Pep({ payments, evidence, fga, modelId: "test", loadView, instanceEpoch: "epoch", decide: override ?? channel.decide, observe, allowedFreshnessSources: new Set(["load_view"]) });
  const statement = loadRuntimePosture({ ...RUNTIME_POSTURE, remote_decision_channels: channel.remoteDecisionChannels });
  const server = new McpPaymentsServer({ pep, payments, loadView, issuer: view.issuer, jwks: { keys: [] }, enforcementScopeStatement: statement });
  const token: TokenFacts = { sub: "alice", clientId: "agent", cnfJkt: "jkt", mission: { id: view.id, issuer: view.issuer, authority_hash: view.authority_hash } };
  return { point, channel, server, pep, payments, evidence, token, view, observe, getOptions };
}

describe("configured PDP unavailability (@spec runtime#ride-through, authzen#failure-condition-coverage)", () => {
  it("a real remote hop verifies and retains PDP evidence; a stopped PDP refuses locally without a fabricated decision", async () => {
    const x = await build("remote");
    try {
      expect((await x.server.callReadTool("get_invoice", { invoice_id: "one" }, x.token)).ok).toBe(true);
      expect(x.getOptions).toHaveBeenCalledTimes(1);
      expect(x.evidence.forMission(x.view.id).filter(e => e.kind === "decision")).toHaveLength(1);
      expect((x.server.protectedResourceMetadata().enforcement_scope_statement as typeof RUNTIME_POSTURE).remote_decision_channels).toHaveLength(1);
      await x.channel.close();
      const denied = await x.server.callReadTool("get_invoice", { invoice_id: "one" }, x.token);
      expect(denied.ok).toBe(false);
      expect(denied.result).toBeUndefined();
      expect(denied.refusal_reason).toBe("pdp_unreachable");
      expect(x.observe).toHaveBeenCalledTimes(1);
      const records = x.evidence.forMission(x.view.id);
      expect(records.filter(e => e.kind === "decision")).toHaveLength(1);
      expect(records.filter(e => e.kind === "execution")).toHaveLength(0);
      const refusals = records.filter(e => e.kind === "refusal");
      expect(refusals).toHaveLength(1);
      expect(refusals[0]!.content).toMatchObject({ emitter: { role: "pep" }, denial_reason: "pdp_unreachable", decision: "deny" });
      expect(refusals[0]!.content.evidence_envelope).toBeDefined();
      expect(refusals[0]!.content).not.toHaveProperty("evaluation_id");
    } finally { await x.channel.close(); x.payments.db.close(); }
  });

  it("co-resident remains a direct call with no remote boundary declaration", async () => {
    const x = await build("co-resident");
    try {
      expect((await x.server.callReadTool("get_invoice", { invoice_id: "one" }, x.token)).ok).toBe(true);
      expect(x.getOptions).not.toHaveBeenCalled();
      expect((x.server.protectedResourceMetadata().enforcement_scope_statement as typeof RUNTIME_POSTURE).remote_decision_channels).toEqual([]);
    } finally { await x.channel.close(); x.payments.db.close(); }
  });

  it("an authenticated PDP policy denial remains a Decision with PDP evidence, not a local refusal", async () => {
    const x = await build("remote");
    try {
      x.view.state = "suspended";
      const denied = await x.server.callReadTool("get_invoice", { invoice_id: "one" }, x.token);
      expect(denied.ok).toBe(false);
      expect(denied.denial_reason).toBe("mission_inactive");
      const records = x.evidence.forMission(x.view.id);
      expect(records.filter(e => e.kind === "decision")).toHaveLength(1);
      expect(records.filter(e => e.kind === "refusal")).toHaveLength(0);
    } finally { await x.channel.close(); x.payments.db.close(); }
  });

  it("does not disguise an internal decision-function programming error as an ordinary policy denial", async () => {
    const error = new Error("programming defect");
    const x = await build("co-resident", async () => { throw error; });
    try {
      await expect(x.server.callReadTool("get_invoice", { invoice_id: "one" }, x.token)).rejects.toBe(error);
      expect(x.evidence.all()).toHaveLength(0);
    } finally { await x.channel.close(); x.payments.db.close(); }
  });

  // @spec authzen#failure-condition-coverage, authzen#transport-behavior — a
  // reachable PDP that returns no decision (any non-2xx, 429 and 503 included)
  // is `pdp_unreachable`; `channel_failure` is reserved for a failure of
  // channel authentication or response integrity.
  const remoteWith = (fetchImpl: typeof fetch): DecisionFn =>
    (request) => evaluateRemote(request, { url: "http://pdp.unused.test/evaluate", pepId: "payments-pep", secret: "test-only", fetchImpl });
  const refusesAs = async (fetchImpl: typeof fetch, expected: string) => {
    const x = await build("co-resident", remoteWith(fetchImpl));
    try {
      const refused = await x.server.callReadTool("get_invoice", { invoice_id: "one" }, x.token);
      expect(refused.ok).toBe(false);
      expect(refused.result).toBeUndefined();
      expect(refused.refusal_reason).toBe(expected);
      const records = x.evidence.forMission(x.view.id);
      expect(records.filter(e => e.kind === "decision")).toHaveLength(0);
      expect(records.filter(e => e.kind === "refusal")).toHaveLength(1);
      expect(records.find(e => e.kind === "refusal")!.content).toMatchObject({ denial_reason: expected });
    } finally { await x.channel.close(); x.payments.db.close(); }
  };
  it("refuses a 503 from a reachable PDP as pdp_unreachable, with no PDP decision retained", async () => {
    await refusesAs((async () => new Response("busy", { status: 503 })) as typeof fetch, "pdp_unreachable");
  });
  it("refuses a 429 overload shed as pdp_unreachable, with no PDP decision retained", async () => {
    await refusesAs(
      (async () => new Response("slow down", { status: 429, headers: { "retry-after": "5" } })) as typeof fetch,
      "pdp_unreachable",
    );
  });
  it("refuses an unsigned 200 response as channel_failure, with no PDP decision retained", async () => {
    await refusesAs(
      (async () => new Response('{"decision":true,"context":{"conditions":{}}}')) as typeof fetch,
      "channel_failure",
    );
  });

  // @spec authzen#transport-behavior — "A PEP MUST bound each evaluation call
  // with a timeout inside the action class's staleness budget": the configured
  // channel deadline cannot outlive the declared budget for the class, so a
  // class the statement declares no bound for cannot wait out that deadline.
  it("caps the configured channel deadline by the declared action-class budget", async () => {
    const point = createEphemeralDecisionPoint({ emitterId: CANONICAL_RESOURCE, audience: CANONICAL_RESOURCE });
    const channel = await createDecisionChannel(point, {
      mode: "remote", pepId: "payments-pep", audience: CANONICAL_RESOURCE, timeoutMs: 120_000,
      getOptions: () => new Promise(() => {}),
    });
    try {
      expect(stalenessBoundSeconds("unpublished_class")).toBe(0);
      const started = Date.now();
      const decision = await channel.decide({
        subject: { id: "alice" }, resource: { type: "invoice", id: "one" }, action: { name: "payments:invoice.read" },
        context: { audience: CANONICAL_RESOURCE, mission: { id: "msn_remote", issuer: "https://as.test" }, action_class: "unpublished_class" },
      });
      expect(Date.now() - started).toBeLessThan(5_000);
      expect(decision.decision).toBe(false);
      expect(decision.context.denial_reason).toBe("decision_channel_timeout");
      expect(isDecisionChannelRefusal(decision)).toBe(true);
    } finally { await channel.close(); }
  });
});
