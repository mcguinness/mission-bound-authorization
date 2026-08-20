/**
 * @spec runtime#read-binding, runtime#decision-output (#610)
 *
 * Two fail-open gaps in the PEP, closed here:
 *
 * GAP 1 (read-binding floor): `list_invoices` without `vendor_id` must not
 * return invoices for vendors outside the Mission's Authority Set. The
 * runtime draft's read-binding floor treats this as a bulk, cross-vendor
 * read that MUST be bound (@spec read-binding); these tests need a live
 * OpenFGA-backed PDP (the FGA vendor-constraint check the bound `vendor_id`
 * form reuses) and auto-skip when it is unreachable, matching
 * enforcement.test.ts.
 *
 * GAP 2 (decision-output polarity): a permit whose `decision.context`
 * carries a member this PEP does not recognize as a condition (or as
 * decision metadata) must be refused, never silently granted (@spec
 * decision-output: "a condition the enforcing component does not recognize
 * makes the permit unusable"). These tests mock @mission/pdp's `evaluate`
 * (pass-through by default) so a synthetic unrecognized member can be
 * injected onto an otherwise-ordinary permit without a live PDP, and run
 * unconditionally.
 */

import { describe, expect, it, vi } from "vitest";
import { Fga, type MissionView } from "@mission/pdp";
import * as pdp from "@mission/pdp";
import {
  CANONICAL_RESOURCE,
  EvidenceStore,
  McpPaymentsServer,
  PaymentsStore,
  Pep,
  sourceDigestOf,
  type TokenFacts,
} from "../src/index.js";

// Pass-through by default: every GAP 1 case below exercises the REAL PDP
// over live OpenFGA. Only the GAP 2 test overrides one call, via
// mockResolvedValueOnce, to inject a synthetic unrecognized member.
vi.mock("@mission/pdp", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@mission/pdp")>();
  return { ...actual, evaluate: vi.fn(actual.evaluate) };
});

const API_URL = process.env.OPENFGA_HTTP_URL ?? "https://localhost:8080";
const KEY = process.env.OPENFGA_PRESHARED_KEY ?? "dev-preshared-key-change-me";
const CA = process.env.OPENFGA_CA_CERT;
const ISSUER = "https://as.test";

async function reachable(): Promise<boolean> {
  try {
    if (CA) process.env.NODE_EXTRA_CA_CERTS = CA;
    return (await fetch(`${API_URL}/healthz`, { headers: { authorization: `Bearer ${KEY}` } })).ok;
  } catch {
    return false;
  }
}
const up = await reachable();
const d = up ? describe : describe.skip;
if (!up) console.warn("OpenFGA unreachable; skipping GAP 1 (read-binding) tests in pep-fail-closed.test.ts");

function seedPayments(): PaymentsStore {
  const payments = new PaymentsStore();
  payments.seed(
    [
      { id: "acme", name: "Acme", status: "approved" },
      { id: "globex", name: "Globex", status: "approved" },
    ],
    [
      { id: "inv-acme-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
      { id: "inv-globex-1", vendor_id: "globex", amount: "50.00", currency: "USD", payee_account: "acct-globex", status: "payable" },
    ],
  );
  return payments;
}

d("GAP 1: list_invoices binds its result set to the Mission's Authority Set (@spec read-binding)", () => {
  const missionId = "msn_610_g1";
  const TOKEN: TokenFacts = {
    sub: "alice",
    clientId: "ap-agent",
    mission: { id: missionId, authority_hash: "sha-256:g1hash" },
    cnfJkt: "jkt-1",
  };

  async function build(entry: MissionView["authority_set"][number]): Promise<{
    server: McpPaymentsServer;
    evidence: EvidenceStore;
  }> {
    const conn = await Fga.connect({ apiUrl: API_URL, presharedKey: KEY, caCertPath: CA });
    const view: MissionView = {
      id: missionId,
      issuer: ISSUER,
      state: "active",
      version: 1,
      authority_hash: "sha-256:g1hash",
      authority_set: [entry],
    };
    const payments = seedPayments();
    const evidence = new EvidenceStore();
    const card = { name: "payments", tools: ["list_invoices"] };
    const pep = new Pep({
      payments,
      evidence,
      fga: conn.fga,
      modelId: conn.modelId,
      loadView: (id) => (id === view.id ? view : undefined),
      instanceEpoch: "epoch-1",
      sourceDigest: sourceDigestOf(card),
    });
    const server = new McpPaymentsServer({
      pep,
      payments,
      loadView: (id) => (id === view.id ? view : undefined),
      jwks: { keys: [] },
      issuer: ISSUER,
      serverCard: card,
    });
    return { server, evidence };
  }

  it("no vendor_id, vendor-constrained entry: returns only the constraint's vendors, never the whole store", async () => {
    const { server, evidence } = await build({
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:invoice.list"],
      constraints: { vendors: ["acme"] },
    });
    const res = await server.callReadTool("list_invoices", {}, TOKEN);
    expect(res.ok, JSON.stringify(res)).toBe(true);
    const invoices = res.result as Array<{ id: string; vendor_id: string }>;
    expect(invoices.map((i) => i.vendor_id)).toEqual(["acme"]);
    expect(invoices.some((i) => i.vendor_id === "globex")).toBe(false);
    // The bound read still produces ordinary Decision Evidence.
    const dec = evidence.forMission(missionId).find((e) => e.kind === "decision");
    expect(dec?.decision).toBe(true);
  });

  it("no vendor_id, unconstrained entry: still returns every vendor's invoices (capability-preserving, not a forced narrowing)", async () => {
    const { server } = await build({
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:invoice.list"],
    });
    const res = await server.callReadTool("list_invoices", {}, TOKEN);
    expect(res.ok, JSON.stringify(res)).toBe(true);
    const invoices = res.result as Array<{ vendor_id: string }>;
    expect(invoices.map((i) => i.vendor_id).sort()).toEqual(["acme", "globex"]);
  });

  it("vendor_id outside the entry's vendor constraint is refused out_of_authority, not silently filtered", async () => {
    const { server } = await build({
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:invoice.list"],
      constraints: { vendors: ["acme"] },
    });
    const res = await server.callReadTool("list_invoices", { vendor_id: "globex" }, TOKEN);
    expect(res.ok).toBe(false);
    expect(res.denial_reason).toBe("out_of_authority");
  });

  it("vendor_id inside the entry's vendor constraint is permitted and bound to exactly that vendor", async () => {
    const { server } = await build({
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:invoice.list"],
      constraints: { vendors: ["acme"] },
    });
    const res = await server.callReadTool("list_invoices", { vendor_id: "acme" }, TOKEN);
    expect(res.ok, JSON.stringify(res)).toBe(true);
    const invoices = res.result as Array<{ vendor_id: string }>;
    expect(invoices.map((i) => i.vendor_id)).toEqual(["acme"]);
  });
});

describe("GAP 2: an unrecognized decision-context member makes a permit unusable (@spec decision-output)", () => {
  const missionId = "msn_610_g2";
  const TOKEN: TokenFacts = {
    sub: "alice",
    clientId: "ap-agent",
    mission: { id: missionId, authority_hash: "sha-256:g2hash" },
    cnfJkt: "jkt-1",
  };
  const view: MissionView = {
    id: missionId,
    issuer: ISSUER,
    state: "active",
    version: 1,
    authority_hash: "sha-256:g2hash",
    authority_set: [
      { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:vendor.read"] },
    ],
  };

  function build(): { pep: Pep; evidence: EvidenceStore } {
    const payments = new PaymentsStore();
    const evidence = new EvidenceStore();
    const pep = new Pep({
      payments,
      evidence,
      // Never reached: evaluate() is mocked for this describe block's tests.
      fga: {} as unknown as import("@mission/pdp").Fga,
      modelId: "unused",
      loadView: (id) => (id === view.id ? view : undefined),
      instanceEpoch: "epoch-1",
      sourceDigest: sourceDigestOf({ name: "payments" }),
    });
    return { pep, evidence };
  }

  // Every currently-recognized permit-context member at once (decision
  // metadata + the three genuine conditions): a control proving the
  // enumeration below does not false-positive on the permit shape the real
  // PDP actually produces.
  const FULLY_RECOGNIZED_CONTEXT = {
    decision_id: "dec_1",
    policy_view_id: "pv_1",
    action_class: "irreversible_action",
    class_source: "deployment",
    permit_expires_at: new Date(Date.now() + 120_000).toISOString(),
    single_use: true,
    entry_digest: "sha-256:entry",
    parameter_digest: "sha-256:params",
  };

  it("a permit whose context carries only recognized members is granted", async () => {
    const { pep, evidence } = build();
    vi.mocked(pdp.evaluate).mockResolvedValueOnce({ decision: true, context: { ...FULLY_RECOGNIZED_CONTEXT } });
    const res = await pep.enforce("lookup_vendor", { vendor_id: "acme" }, TOKEN);
    expect(res.permitted, JSON.stringify(res)).toBe(true);
    expect(evidence.forMission(missionId).some((e) => e.kind === "refusal")).toBe(false);
  });

  it("a permit whose context carries ONE unrecognized member is refused with zero effect, never silently granted", async () => {
    const { pep, evidence } = build();
    vi.mocked(pdp.evaluate).mockResolvedValueOnce({
      decision: true,
      context: { ...FULLY_RECOGNIZED_CONTEXT, require_step_up: true },
    });
    const res = await pep.enforce("lookup_vendor", { vendor_id: "acme" }, TOKEN);
    expect(res.permitted).toBe(false);
    expect(res.refusal_reason).toBe("unrecognized_condition");
    const refusal = evidence.forMission(missionId).find((e) => e.kind === "refusal");
    expect(refusal?.refusal_reason).toBe("unrecognized_condition");
    expect(refusal?.emitter).toEqual({ id: CANONICAL_RESOURCE, role: "pep" });
  });

  it("a DENY decision (no permit) is unaffected by the recognized-member enumeration", async () => {
    const { pep } = build();
    vi.mocked(pdp.evaluate).mockResolvedValueOnce({
      decision: false,
      context: { decision_id: "dec_2", policy_view_id: "pv_2", denial_reason: "out_of_authority" },
    });
    const res = await pep.enforce("lookup_vendor", { vendor_id: "acme" }, TOKEN);
    expect(res.permitted).toBe(false);
    expect(res.denial_reason).toBe("out_of_authority");
  });
});
