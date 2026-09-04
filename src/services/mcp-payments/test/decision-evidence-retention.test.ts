/**
 * @spec draft-mcguinness-mission-runtime-evidence.md#decision-evidence-object,
 * #decision-evidence-integrity; draft-mcguinness-mission-runtime.md#agent-isolated-evidence-emission
 * (issue #741).
 *
 * The PEP side of the emission boundary: it stores what the PDP emitted, and
 * builds nothing. These cases assert that the enforcement path holds no PDP
 * evidence key at all, that retention verifies the key-to-emitter and
 * key-to-audience binding rather than the `kid` alone, that a permit whose
 * decision left no verifiable Decision Evidence is refused rather than
 * executed, and that a record survives the remote decision channel
 * byte-identically and still verifies at the PEP that receives it.
 *
 * Unconditional: `alwaysAllowFga` stands in for OpenFGA, so this file never
 * skips.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createDecisionEvidenceEmitter,
  createEphemeralDecisionPoint,
  createPdpHttpServer,
  evaluateRemote,
  type EvaluationRequest,
  type Fga,
  type MissionView,
  type PdpHttpServerHandle,
  relationForAction,
  stalenessBoundSeconds,
} from "@mission/pdp";
import { generateKeyPairSync } from "node:crypto";
import {
  buildEvidenceKeyResolver,
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  type DecisionEvidence,
  EvidenceStore,
  McpPaymentsServer,
  PaymentsStore,
  Pep,
  sourceDigestOf,
  type TokenFacts,
} from "../src/index.js";

const ISSUER = "https://as.test";
const NOW = new Date("2026-07-22T12:00:00Z");
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const TOKEN: TokenFacts = {
  sub: "alice",
  clientId: "ap-agent",
  mission: { id: "msn_ret", issuer: ISSUER, authority_hash: "sha-256:rethash" },
  cnfJkt: "jkt-1",
};

const view = (): MissionView => ({
  id: "msn_ret",
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:rethash",
  authority_set: [
    { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] },
  ],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
});

/**
 * One decision point (the PDP side: it decides, and it emits) paired with the
 * enforcement-side key bundle that verifies what it emits (#741, PR #753
 * review). `pdp.emitter` stands in for a PDP that already decided, where a
 * case needs the record itself rather than a decision; nothing the PEP below
 * receives exposes it.
 */
function decisionPointAndKeys(options: { emitterId?: string; audience?: string } = {}) {
  const emitterId = options.emitterId ?? CANONICAL_RESOURCE;
  const audience = options.audience ?? CANONICAL_RESOURCE;
  const pdp = createEphemeralDecisionPoint({ emitterId, audience });
  return { pdp, keys: createEphemeralEvidenceKeys({ emitterId, audience, decisionPoint: pdp }) };
}

function seededPayments(): PaymentsStore {
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [{ id: "inv-1", vendor_id: "acme", amount: "100.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
  );
  return payments;
}

/** One PEP/server pair; `keys` supplies the store's resolver and (optionally) the decision function. */
function buildServer(keys: ReturnType<typeof createEphemeralEvidenceKeys>, withDecisionPoint: boolean) {
  const payments = seededPayments();
  const evidence = new EvidenceStore(keys.signing, keys.resolver);
  const missionView = view();
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === missionView.id && ref.issuer === missionView.issuer
      ? { view: missionView, freshness: { observed_at: new Date().toISOString(), source: "load_view" } }
      : undefined;
  const pep = new Pep({
    payments,
    evidence,
    ...(withDecisionPoint ? { decide: keys.decide } : {}),
    fga: alwaysAllowFga,
    modelId: "unit-test-model",
    loadView,
    instanceEpoch: "epoch-1",
    sourceDigest: sourceDigestOf({ name: "payments" }),
    allowedFreshnessSources: new Set(["load_view"]),
  });
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
    jwks: { keys: [] },
    issuer: ISSUER,
    serverCard: { name: "payments" },
  });
  return { server, evidence };
}

describe("the enforcement path holds no PDP evidence key (@spec runtime-evidence#decision-evidence-object, #741)", () => {
  it("the signer configuration has no `pdp` role to configure", () => {
    const keys = createEphemeralEvidenceKeys();
    expect(Object.keys(keys.signing).sort()).toEqual(["executor", "pep", "receipt_issuer"]);
  });

  it("a store asked to sign a `pdp`-role record fails closed rather than minting one", async () => {
    const keys = createEphemeralEvidenceKeys();
    const evidence = new EvidenceStore(keys.signing, keys.resolver);
    await expect(
      evidence.recordRefusal(CANONICAL_RESOURCE, "pdp", {
        missionId: "msn_ret",
        audience: CANONICAL_RESOURCE,
        action: { name: "payments:invoice.read" },
        denial_reason: "unknown_mission",
      }),
    ).rejects.toThrow(/no signer configured for emitter role "pdp"/);
  });
});

describe("retainDecision verifies before it retains (@spec runtime-evidence#decision-evidence-integrity, #741)", () => {
  it("refuses a genuinely signed record whose emitter id is not the one the key is published for", async () => {
    const keys = createEphemeralEvidenceKeys();
    const impostor = createDecisionEvidenceEmitter({
      // Same key material as nothing the resolver knows: a different emitter
      // claiming this deployment's audience.
      signer: { kid: "ephemeral-pdp", key: generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey },
      emitterId: "https://impersonator.example.com/mcp",
      audience: CANONICAL_RESOURCE,
    });
    const record = await impostor.emit({
      mission: { id: "msn_ret", issuer: ISSUER, policy_view_id: "pv_1" },
      subject: { id: "alice" },
      resource: { type: "invoice", id: "inv-1" },
      action: { name: "payments:invoice.read" },
      audience: CANONICAL_RESOURCE,
      evaluation_id: "dec_impostor",
      decision: "permit",
      evaluated_at: NOW.toISOString(),
    });
    const evidence = new EvidenceStore(keys.signing, keys.resolver);
    await expect(evidence.retainDecision(record)).resolves.toEqual({
      retained: false,
      reason: "key_not_resolvable",
    });
    expect(evidence.all()).toHaveLength(0);
  });

  it("refuses a record for an audience the emitter's key is not published for", async () => {
    const foreign = createEphemeralDecisionPoint({
      emitterId: CANONICAL_RESOURCE,
      audience: "https://other-scope.example.com",
    });
    // The store's resolver is this deployment's, bound to its own audience.
    const deploymentKeys = createEphemeralEvidenceKeys();
    const record = await foreign.emitter.emit({
      mission: { id: "msn_ret", issuer: ISSUER, policy_view_id: "pv_1" },
      subject: { id: "alice" },
      resource: { type: "invoice", id: "inv-1" },
      action: { name: "payments:invoice.read" },
      audience: "https://other-scope.example.com",
      evaluation_id: "dec_scope",
      decision: "permit",
      evaluated_at: NOW.toISOString(),
    });
    const evidence = new EvidenceStore(deploymentKeys.signing, deploymentKeys.resolver);
    await expect(evidence.retainDecision(record)).resolves.toEqual({
      retained: false,
      reason: "key_not_resolvable",
    });
  });

  it("refuses when no verification keys are configured at all, rather than retaining an unverified record", async () => {
    const { pdp, keys } = decisionPointAndKeys();
    const record = await pdp.emitter.emit({
      mission: { id: "msn_ret", issuer: ISSUER, policy_view_id: "pv_1" },
      subject: { id: "alice" },
      resource: { type: "invoice", id: "inv-1" },
      action: { name: "payments:invoice.read" },
      audience: CANONICAL_RESOURCE,
      evaluation_id: "dec_nokeys",
      decision: "permit",
      evaluated_at: NOW.toISOString(),
    });
    const evidence = new EvidenceStore(keys.signing);
    await expect(evidence.retainDecision(record)).resolves.toEqual({
      retained: false,
      reason: "no_verification_keys",
    });
  });

  it("retains the verified record VERBATIM: the retained bytes are the object the PDP signed", async () => {
    const { pdp, keys } = decisionPointAndKeys();
    const record = await pdp.emitter.emit({
      mission: { id: "msn_ret", issuer: ISSUER, policy_view_id: "pv_1" },
      subject: { id: "alice" },
      resource: { type: "invoice", id: "inv-1" },
      action: { name: "payments:invoice.read" },
      audience: CANONICAL_RESOURCE,
      evaluation_id: "dec_verbatim",
      decision: "permit",
      evaluated_at: NOW.toISOString(),
    });
    const evidence = new EvidenceStore(keys.signing, keys.resolver);
    const result = await evidence.retainDecision(record);
    expect(result.retained).toBe(true);
    const retained = evidence.all().find((e): e is DecisionEvidence => e.kind === "decision");
    expect(retained?.content).toBe(record);
    expect(Object.isFrozen(retained?.content)).toBe(true);
  });
});

describe("a permit the PDP did not evidence is refused, never executed (#741)", () => {
  it("a genuinely signed Decision Evidence claiming permit does not flip an otherwise-DENY decision to executed", async () => {
    const keys = createEphemeralEvidenceKeys();
    const decide = keys.decide;
    keys.decide = async (request, options) => {
      const permitted = await decide(request, options);
      expect(permitted.decision).toBe(true);
      // Keep the genuine, correctly scoped signed permit evidence. Only the
      // live decision denies, so failed signature verification cannot prove
      // this invariant by accident.
      return { ...permitted, decision: false, context: { ...permitted.context, denial_reason: "out_of_authority" } };
    };
    const { server, evidence } = buildServer(keys, true);
    const execute = vi.spyOn(server as unknown as { execute(tool: string, args: Record<string, unknown>): unknown }, "execute");
    const res = await server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN);
    expect(res).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
    const retained = evidence.all().find((e): e is DecisionEvidence => e.kind === "decision");
    expect(retained?.content.decision).toBe("permit");
    expect(retained?.content.emitter).toEqual({ id: CANONICAL_RESOURCE, role: "pdp" });
    expect(execute).not.toHaveBeenCalled();
    expect(res.result).toBeUndefined();
  });

  it("refuses the action when the decision carries no Decision Evidence", async () => {
    const keys = createEphemeralEvidenceKeys();
    const { server, evidence } = buildServer(keys, false);
    const res = await server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN);
    expect(res.ok).toBe(false);
    expect(evidence.all().some((e) => e.kind === "decision")).toBe(false);
    const refusal = evidence.all().find((e) => e.kind === "refusal");
    expect(refusal).toBeDefined();
  });

  it("permits and retains when the same decision IS evidenced: the refusal above is the missing record, not the fixture", async () => {
    const keys = createEphemeralEvidenceKeys();
    const { server, evidence } = buildServer(keys, true);
    const res = await server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN);
    expect(res.ok, JSON.stringify(res)).toBe(true);
    const retained = evidence.all().find((e): e is DecisionEvidence => e.kind === "decision");
    expect(retained?.content.decision).toBe("permit");
    expect(retained?.content.emitter).toEqual({ id: CANONICAL_RESOURCE, role: "pdp" });
  });
});

describe("the record survives the remote decision channel byte-identically (@spec runtime#decision-channel, #741)", () => {
  let handle: PdpHttpServerHandle | undefined;
  afterEach(async () => {
    await handle?.close();
    handle = undefined;
  });

  it("a record signed at an out-of-process PDP verifies and is retained at the PEP that received it over the MAC'd hop", async () => {
    const PEP_ID = "mcp-payments-pep";
    const SECRET = "test-shared-secret-do-not-reuse";
    const { pdp, keys } = decisionPointAndKeys();
    const missionView = view();
    handle = await createPdpHttpServer({
      peps: new Map([[PEP_ID, { secret: SECRET, scopes: [CANONICAL_RESOURCE] }]]),
      getOptions: () => ({
        view: missionView,
        fga: alwaysAllowFga,
        modelId: "unit-test-model",
        now: () => NOW,
        stalenessBoundSeconds,
        relationForAction,
      }),
      // The emitter is bound HERE, in the PDP server's own construction, on
      // the PDP side of the network hop: it is reachable from no options
      // object, and the PEP below could not sign a record if it wanted to.
      evidence: pdp.emitter,
      replayWindowSeconds: 30,
    });

    const request: EvaluationRequest = {
      subject: { id: "alice" },
      resource: { type: "invoice", id: "inv-1", properties: { vendor_id: "acme" } },
      action: { name: "payments:invoice.read" },
      context: { audience: CANONICAL_RESOURCE, mission: { id: "msn_ret", issuer: ISSUER } },
    };
    const decision = await evaluateRemote(request, { url: handle.url, pepId: PEP_ID, secret: SECRET });
    expect(decision.decision, JSON.stringify(decision.context)).toBe(true);

    // The PEP holds only public verification keys, and retains what crossed
    // the hop: JSON transport preserved every byte the signature covers.
    const evidence = new EvidenceStore(keys.signing, buildEvidenceKeyResolver(keys.verification));
    const result = await evidence.retainDecision(
      decision.context.decision_evidence as Parameters<typeof evidence.retainDecision>[0],
    );
    expect(result).toMatchObject({ retained: true });
    const retained = evidence.all().find((e): e is DecisionEvidence => e.kind === "decision");
    expect(retained?.content.evaluation_id).toBe(decision.context.evaluation_id);
    expect(retained?.content.emitter).toEqual({ id: CANONICAL_RESOURCE, role: "pdp" });
  });
});
