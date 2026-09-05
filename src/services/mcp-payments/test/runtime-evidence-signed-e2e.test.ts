/**
 * @spec draft-mcguinness-mission-runtime-evidence.md#decision-evidence-object,
 * #decision-evidence-integrity (issue #649 ruling at 41f66a4a).
 *
 * Every other test in this slice (`runtime-evidence-integrity.test.ts`,
 * `mission-receipt.test.ts`) verifies a HAND-BUILT record: it proves the
 * signing/verification primitive is correct in isolation, never that the
 * PDP's own emission path, invoked from the REAL PEP/PDP call site (#741),
 * with its actual optional-member omissions, its actual `deepFreeze`, and
 * its actual `canonicalize` input, produces something an independent
 * verifier accepts. This file closes that gap: one permit and one denial are
 * driven through `McpPaymentsServer` exactly as a real client would, the
 * RETAINED artifact is pulled back out of the store, and verified with a
 * resolver built ONLY from public keys (never any signer config), plus one
 * tamper case on that same retained (deep-frozen) object.
 *
 * Unconditional: `alwaysAllowFga`/`poisonFga` stand in for OpenFGA, so this
 * runs without the live-OpenFGA reachability gate (same pattern
 * `runtime-refusal-backlog.test.ts` uses).
 */

import { describe, expect, it } from "vitest";
import type { Fga, MissionView } from "@mission/pdp";
import {
  buildEvidenceKeyResolver,
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  DECISION_EVIDENCE_MEDIA_TYPE,
  EvidenceStore,
  McpPaymentsServer,
  PaymentsStore,
  Pep,
  type DecisionEvidence,
  type TokenFacts,
  verifyEvidenceEnvelope,
} from "../src/index.js";

const ISSUER = "https://as.test";

const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
/** Proves the denial below is a genuine PDP `evaluate()` outcome, not a bypass. */
const poisonFga = {
  checkWithContext: async () => {
    throw new Error("fga should not have been called on this path");
  },
} as unknown as Fga;

const TOKEN: TokenFacts = {
  sub: "alice",
  clientId: "ap-agent",
  mission: { id: "msn_e2e", issuer: ISSUER, authority_hash: "sha-256:e2ehash" },
  cnfJkt: "jkt-1",
};

function view(actions: string[]): MissionView {
  return {
    id: "msn_e2e",
    issuer: ISSUER,
    state: "active",
    version: 1,
    authority_hash: "sha-256:e2ehash",
    authority_set: actions.length
      ? [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions }]
      : [],
    subject: { iss: ISSUER, sub: "alice" },
    client_id: "ap-agent",
  };
}

/** One seeded invoice, so `get_invoice` reaches the PDP either way (the
 * denial must come from `evaluate()` finding no authority entry, never from
 * an earlier "unknown_invoice" pre-check). */
function seededPayments(): PaymentsStore {
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [{ id: "inv-1", vendor_id: "acme", amount: "100.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
  );
  return payments;
}

function buildServer(missionView: MissionView, fga: Fga) {
  const payments = seededPayments();
  const keys = createEphemeralEvidenceKeys();
  const evidence = new EvidenceStore(keys.signing, keys.resolver);
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === missionView.id && ref.issuer === missionView.issuer
      ? { view: missionView, freshness: { observed_at: new Date().toISOString(), source: "load_view" } }
      : undefined;
  const pep = new Pep({
    payments,
    evidence,
    decide: keys.decide,
    fga,
    modelId: "unit-test-model",
    loadView,
    instanceEpoch: "epoch-1",
    allowedFreshnessSources: new Set(["load_view"]),
  });
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
    jwks: { keys: [] },
    issuer: ISSUER,
  });
  return { server, evidence };
}

describe("a permit and a denial through the real PEP/PDP call sites produce a genuinely signed, independently verifiable retained Decision Evidence record", () => {
  it("permit: the RETAINED artifact (not a hand-built object) verifies against a resolver built from public keys alone", async () => {
    // The PDP's emitter signs under `emitterId: CANONICAL_RESOURCE` and
    // `audience: CANONICAL_RESOURCE` (this deployment's convention: the
    // resource IS the enforcement scope); #739 review point 1 means a
    // resolver no longer verifies a genuinely signed record unless BOTH are
    // supplied exactly.
    const keys = createEphemeralEvidenceKeys({ emitterId: CANONICAL_RESOURCE, audience: CANONICAL_RESOURCE });
    const resolver = buildEvidenceKeyResolver(keys.verification);
    const payments = seededPayments();
    const evidence = new EvidenceStore(keys.signing, resolver);
    const missionView = view(["payments:invoice.read"]);
    const loadView = (ref: { id: string; issuer: string }) =>
      ref.id === missionView.id && ref.issuer === missionView.issuer
        ? { view: missionView, freshness: { observed_at: new Date().toISOString(), source: "load_view" } }
        : undefined;
    const pep = new Pep({
      payments,
      evidence,
      decide: keys.decide,
      fga: alwaysAllowFga,
      modelId: "unit-test-model",
      loadView,
      instanceEpoch: "epoch-1",
      allowedFreshnessSources: new Set(["load_view"]),
    });
    const server = new McpPaymentsServer({
      pep,
      payments,
      loadView,
      jwks: { keys: [] },
      issuer: ISSUER,
    });

    const res = await server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN);
    expect(res.ok, JSON.stringify(res)).toBe(true);

    const permitRecord = evidence
      .all()
      .find((e): e is DecisionEvidence => e.kind === "decision" && e.content.decision === "permit");
    expect(permitRecord).toBeDefined();
    expect(permitRecord?.content.action.name).toBe("payments:invoice.read");

    const verified = await verifyEvidenceEnvelope(permitRecord!.content, DECISION_EVIDENCE_MEDIA_TYPE, resolver);
    expect(verified).toEqual({ valid: true });

    // Tamper the RETAINED artifact (it is deep-frozen: spread-copy first)
    // and confirm the SAME resolver rejects it at the byte-equality step,
    // never reaching (or being fooled by) the still-otherwise-valid envelope.
    const tampered = { ...permitRecord!.content, decision: "deny" as const };
    const tamperResult = await verifyEvidenceEnvelope(tampered, DECISION_EVIDENCE_MEDIA_TYPE, resolver);
    expect(tamperResult).toEqual({ valid: false, reason: "byte_mismatch" });
  });

  it("denial: a genuine PDP out_of_authority deny (FGA never consulted) is retained as a signed Decision Evidence record that independently verifies", async () => {
    // The PDP's emitter signs under `emitterId: CANONICAL_RESOURCE` and
    // `audience: CANONICAL_RESOURCE` (this deployment's convention: the
    // resource IS the enforcement scope); #739 review point 1 means a
    // resolver no longer verifies a genuinely signed record unless BOTH are
    // supplied exactly.
    const keys = createEphemeralEvidenceKeys({ emitterId: CANONICAL_RESOURCE, audience: CANONICAL_RESOURCE });
    const resolver = buildEvidenceKeyResolver(keys.verification);
    const payments = seededPayments();
    const evidence = new EvidenceStore(keys.signing, resolver);
    const missionView = view([]); // no authority entries at all
    const loadView = (ref: { id: string; issuer: string }) =>
      ref.id === missionView.id && ref.issuer === missionView.issuer
        ? { view: missionView, freshness: { observed_at: new Date().toISOString(), source: "load_view" } }
        : undefined;
    const pep = new Pep({
      payments,
      evidence,
      decide: keys.decide,
      fga: poisonFga,
      modelId: "unit-test-model",
      loadView,
      instanceEpoch: "epoch-1",
      allowedFreshnessSources: new Set(["load_view"]),
    });
    const server = new McpPaymentsServer({
      pep,
      payments,
      loadView,
      jwks: { keys: [] },
      issuer: ISSUER,
    });

    const res = await server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN);
    expect(res.ok).toBe(false);
    expect(res.denial_reason).toBe("out_of_authority");

    const denyRecord = evidence
      .all()
      .find((e): e is DecisionEvidence => e.kind === "decision" && e.content.decision === "deny");
    expect(denyRecord).toBeDefined();
    expect(denyRecord?.content.denial_reason).toBe("out_of_authority");

    const verified = await verifyEvidenceEnvelope(denyRecord!.content, DECISION_EVIDENCE_MEDIA_TYPE, resolver);
    expect(verified).toEqual({ valid: true });
  });
});

describe("Decision Evidence per-(mission, emitter, role) sequence allocation", () => {
  it("allocates a monotonically increasing sequence per role, independently per role, even under the SAME mission and emitter id", async () => {
    // Regression coverage for the (mission, id, role) scoping decision: a
    // component playing multiple roles under one id (this deployment's
    // co-located pdp/pep/executor) must not share one counter across roles.
    // The `pdp` counter is the PDP emitter's own (#741), never the PEP store's.
    const { server, evidence } = buildServer(view(["payments:invoice.read"]), alwaysAllowFga);

    await server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN);
    await server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN);
    const decisions = evidence.all().filter((e): e is DecisionEvidence => e.kind === "decision");
    expect(decisions.map((d) => d.content.sequence)).toEqual([0, 1]);
    // Every decision here is emitted under role "pdp": the per-role scoping
    // does not change the within-role monotonic guarantee.
    expect(decisions.every((d) => d.content.emitter.role === "pdp")).toBe(true);
  });
});

describe("buildEvidenceKeyResolver: emitter + audience binding (#739 review point 1)", () => {
  it("rejects a genuinely signed, independently-verifiable retained record when the resolver's keys are registered for a DIFFERENT emitter id (same kid, role, and audience)", async () => {
    const keys = createEphemeralEvidenceKeys({ emitterId: CANONICAL_RESOURCE, audience: CANONICAL_RESOURCE });
    // A resolver built for an IMPERSONATOR component: identical kid/role/
    // audience, but registered under a different emitter.id than the one
    // that actually signed. Pre-#739-review-point-1, `buildEvidenceKeyResolver`
    // never looked at `emitterId` at all, so this would have verified.
    const wronglyScoped = keys.verification.map((k) => ({ ...k, emitterId: "https://impersonator.example.com/mcp" }));
    const resolver = buildEvidenceKeyResolver(wronglyScoped);
    const payments = seededPayments();
    // The STORE resolves correctly (otherwise the PEP refuses the action and
    // retains nothing); `resolver` above is the impersonator's, used only for
    // the after-the-fact verification this case is about.
    const evidence = new EvidenceStore(keys.signing, keys.resolver);
    const missionView = view(["payments:invoice.read"]);
    const loadView = (ref: { id: string; issuer: string }) =>
      ref.id === missionView.id && ref.issuer === missionView.issuer
        ? { view: missionView, freshness: { observed_at: new Date().toISOString(), source: "load_view" } }
        : undefined;
    const pep = new Pep({
      payments,
      evidence,
      decide: keys.decide,
      fga: alwaysAllowFga,
      modelId: "unit-test-model",
      loadView,
      instanceEpoch: "epoch-1",
      allowedFreshnessSources: new Set(["load_view"]),
    });
    const server = new McpPaymentsServer({
      pep,
      payments,
      loadView,
      jwks: { keys: [] },
      issuer: ISSUER,
    });
    const res = await server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN);
    expect(res.ok).toBe(true);
    const permitRecord = evidence
      .all()
      .find((e): e is DecisionEvidence => e.kind === "decision" && e.content.decision === "permit");
    expect(permitRecord).toBeDefined();
    const verified = await verifyEvidenceEnvelope(permitRecord!.content, DECISION_EVIDENCE_MEDIA_TYPE, resolver);
    expect(verified).toEqual({ valid: false, reason: "key_not_resolvable" });
  });

  it("never wildcards a missing audience for a pdp/pep/executor key, even when one is registered without one", () => {
    const keys = createEphemeralEvidenceKeys({
      emitterId: "pdp.example.com",
      audience: "https://erp.example.com",
    });
    // Bypass the type-level requirement the way a deployment misconfiguration
    // (or a pre-#739-review-point-1 caller) might: an audience-unbound pdp
    // key entry.
    const pdpKey = keys.verification.find((k) => k.role === "pdp")!;
    const { audience: _drop, ...audienceless } = pdpKey as { audience?: string } & typeof pdpKey;
    const resolver = buildEvidenceKeyResolver([audienceless as typeof pdpKey]);
    const resolved = resolver({
      kid: pdpKey.kid,
      emitter: { id: "pdp.example.com", role: "pdp" },
      audience: "https://totally-different.example.com",
    });
    expect(resolved).toBeUndefined();
  });

  it("a receipt_issuer key MAY stay audience-unbound (the one role the binding does not require it for)", () => {
    const keys = createEphemeralEvidenceKeys({ roles: ["receipt_issuer"], emitterId: "receipts.example.com" });
    const resolver = buildEvidenceKeyResolver(keys.verification);
    const resolved = resolver({
      kid: keys.verification.find((k) => k.role === "receipt_issuer")!.kid,
      emitter: { id: "receipts.example.com", role: "receipt_issuer" },
      audience: "https://anything.example.com",
    });
    expect(resolved).toBeDefined();
  });
});
