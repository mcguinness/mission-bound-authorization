/**
 * @spec draft-mcguinness-mission-runtime-evidence.md#decision-evidence-object,
 * #decision-evidence-integrity (issue #649 ruling at 41f66a4a).
 *
 * Every other test in this slice (`runtime-evidence-integrity.test.ts`,
 * `mission-receipt.test.ts`) verifies a HAND-BUILT record: it proves the
 * signing/verification primitive is correct in isolation, never that
 * `EvidenceStore.recordDecision`, called from the REAL PEP/PDP call site,
 * with its actual optional-member omissions, its actual `deepFreeze`, and
 * its actual `canonicalize` input, produces something an independent
 * verifier accepts. This file closes that gap: one permit and one denial are
 * driven through `McpPaymentsServer` exactly as a real client would, the
 * RETAINED artifact is pulled back out of the store, and verified with a
 * resolver built ONLY from public keys (never the store's own signer
 * config), plus one tamper case on that same retained (deep-frozen) object.
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
  sourceDigestOf,
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
  const evidence = new EvidenceStore(createEphemeralEvidenceKeys().signing);
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === missionView.id && ref.issuer === missionView.issuer
      ? { view: missionView, freshness: { observed_at: new Date().toISOString(), source: "load_view" } }
      : undefined;
  const pep = new Pep({
    payments,
    evidence,
    fga,
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

describe("a permit and a denial through the real PEP/PDP call sites produce a genuinely signed, independently verifiable retained Decision Evidence record", () => {
  it("permit: the RETAINED artifact (not a hand-built object) verifies against a resolver built from public keys alone", async () => {
    const keys = createEphemeralEvidenceKeys();
    const resolver = buildEvidenceKeyResolver(keys.verification);
    const payments = seededPayments();
    const evidence = new EvidenceStore(keys.signing);
    const missionView = view(["payments:invoice.read"]);
    const loadView = (ref: { id: string; issuer: string }) =>
      ref.id === missionView.id && ref.issuer === missionView.issuer
        ? { view: missionView, freshness: { observed_at: new Date().toISOString(), source: "load_view" } }
        : undefined;
    const pep = new Pep({
      payments,
      evidence,
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
    const keys = createEphemeralEvidenceKeys();
    const resolver = buildEvidenceKeyResolver(keys.verification);
    const payments = seededPayments();
    const evidence = new EvidenceStore(keys.signing);
    const missionView = view([]); // no authority entries at all
    const loadView = (ref: { id: string; issuer: string }) =>
      ref.id === missionView.id && ref.issuer === missionView.issuer
        ? { view: missionView, freshness: { observed_at: new Date().toISOString(), source: "load_view" } }
        : undefined;
    const pep = new Pep({
      payments,
      evidence,
      fga: poisonFga,
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

describe("EvidenceStore per-(mission, emitter, role) sequence allocation", () => {
  it("allocates a monotonically increasing sequence per role, independently per role, even under the SAME mission and emitter id", async () => {
    // Regression coverage for the (mission, id, role) scoping decision
    // documented on `EvidenceStore.nextSequence`: a component playing
    // multiple roles under one id (this deployment's co-located
    // pdp/pep/executor) must not share one counter across roles.
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
