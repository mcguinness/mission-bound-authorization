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
  createEphemeralEvidenceKeys,
  EvidenceStore,
  McpPaymentsServer,
  PaymentsStore,
  Pep,
  sourceDigestOf,
  type DecisionEvidence,
  type RefusalRecord,
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
      { id: "initech", name: "Initech", status: "approved" },
    ],
    [
      { id: "inv-acme-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
      { id: "inv-globex-1", vendor_id: "globex", amount: "50.00", currency: "USD", payee_account: "acct-globex", status: "payable" },
      { id: "inv-initech-1", vendor_id: "initech", amount: "75.00", currency: "USD", payee_account: "acct-initech", status: "payable" },
    ],
  );
  return payments;
}

d("GAP 1: list_invoices binds its result set to the Mission's Authority Set (@spec read-binding)", () => {
  const missionId = "msn_610_g1";
  const TOKEN: TokenFacts = {
    sub: "alice",
    clientId: "ap-agent",
    mission: { id: missionId, issuer: "https://as.test", authority_hash: "sha-256:g1hash" },
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
      subject: { iss: ISSUER, sub: "alice" },
      client_id: "ap-agent",
    };
    const payments = seedPayments();
    const evidence = new EvidenceStore(createEphemeralEvidenceKeys().signing);
    const card = { name: "payments", tools: ["list_invoices"] };
    const pep = new Pep({
      payments,
      evidence,
      fga: conn.fga,
      modelId: conn.modelId,
      loadView: (ref) =>
        ref.id === view.id && ref.issuer === view.issuer
          ? { view: view, freshness: { observed_at: new Date().toISOString(), source: "load_view" } }
          : undefined,
      instanceEpoch: "epoch-1",
      sourceDigest: sourceDigestOf(card),
      allowedFreshnessSources: new Set(["load_view"]),
    });
    const server = new McpPaymentsServer({
      pep,
      payments,
      loadView: (ref) =>
        ref.id === view.id && ref.issuer === view.issuer
          ? { view: view, freshness: { observed_at: new Date().toISOString(), source: "load_view" } }
          : undefined,
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
    const dec = evidence.forMission(missionId).find((e): e is DecisionEvidence => e.kind === "decision");
    expect(dec?.content.decision).toBe("permit");
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
    expect(invoices.map((i) => i.vendor_id).sort()).toEqual(["acme", "globex", "initech"].sort());
  });

  it("no vendor_id, MULTI-vendor allowlist: returns every allowlisted vendor's invoices and excludes the one left out", async () => {
    const { server } = await build({
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:invoice.list"],
      constraints: { vendors: ["acme", "globex"] },
    });
    const res = await server.callReadTool("list_invoices", {}, TOKEN);
    expect(res.ok, JSON.stringify(res)).toBe(true);
    const invoices = res.result as Array<{ vendor_id: string }>;
    // Both allowlisted vendors are served, not just the FGA check's
    // representative member (@spec read-binding): the result set is bound
    // to the entry's whole vendors array, and "initech" (outside it) never
    // appears.
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

  // @spec runtime#read-binding (finding 1, PR #612 author review): result-set
  // filtering alone is not Runtime parameter binding: a `parameter_digest`
  // must actually enter the PDP request/Decision Evidence, and it must be
  // reverified immediately before execution exactly as the write/transaction
  // paths already do. These three tests prove the digest binding, the
  // omitted-vendor_id normal form, and the reverification, respectively.

  it("a permitted bound read's parameter_digest enters the PDP request and Decision Evidence (list_invoices now builds an Operation Profile, not just a result filter)", async () => {
    const { server, evidence } = await build({
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:invoice.list"],
      constraints: { vendors: ["acme", "globex"] },
    });
    const res = await server.callReadTool("list_invoices", {}, TOKEN);
    expect(res.ok, JSON.stringify(res)).toBe(true);
    const dec = evidence.forMission(missionId).find((e): e is DecisionEvidence => e.kind === "decision");
    // Before this fix, list_invoices never built `effective`, so no
    // parameter_digest ever entered the request or the retained record.
    expect(dec?.content.parameter_digest).toBeDefined();
    expect(dec?.content.parameter_digest).toMatch(/^sha-256:/);
  });

  it("the omitted-vendor_id normal form distinguishes an entry's OWN allowlist from the unconstrained 'all' marker, even when both enumerate the same vendors and serve the identical result set", async () => {
    const constrained = await build({
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:invoice.list"],
      constraints: { vendors: ["acme", "globex", "initech"] }, // == every seeded vendor
    });
    const unconstrained = await build({
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:invoice.list"],
    });
    const resA = await constrained.server.callReadTool("list_invoices", {}, TOKEN);
    const resB = await unconstrained.server.callReadTool("list_invoices", {}, TOKEN);
    expect(resA.ok, JSON.stringify(resA)).toBe(true);
    expect(resB.ok, JSON.stringify(resB)).toBe(true);
    const vendorsOf = (r: typeof resA) =>
      (r.result as Array<{ vendor_id: string }>).map((i) => i.vendor_id).sort();
    // Both serve the identical result set...
    expect(vendorsOf(resA)).toEqual(vendorsOf(resB));
    // ...but the canonical normal form, and so parameter_digest, never
    // collapses the two: a vendor-constrained entry (source "entry") and the
    // explicit all-in-scope marker (source "all") are distinct normal forms
    // regardless of what they happen to enumerate.
    const digestOf = (store: typeof constrained.evidence) =>
      store.forMission(missionId).find((e): e is DecisionEvidence => e.kind === "decision")?.content
        .parameter_digest;
    const digestA = digestOf(constrained.evidence);
    const digestB = digestOf(unconstrained.evidence);
    expect(digestA).toBeDefined();
    expect(digestB).toBeDefined();
    expect(digestA).not.toBe(digestB);
  });

  it("a Mission-authority change landing in the decision->execute window is caught by reverification, never executed on the stale normalized scope (TOCTOU)", async () => {
    const conn = await Fga.connect({ apiUrl: API_URL, presharedKey: KEY, caCertPath: CA });
    let current: MissionView = {
      id: missionId,
      issuer: ISSUER,
      state: "active",
      version: 1,
      authority_hash: "sha-256:g1hash",
      authority_set: [
        {
          type: "mission_resource_access",
          resource: CANONICAL_RESOURCE,
          actions: ["payments:invoice.list"],
          constraints: { vendors: ["acme", "globex"] },
        },
      ],
      subject: { iss: ISSUER, sub: "alice" },
      client_id: "ap-agent",
    };
    const payments = seedPayments();
    const evidence = new EvidenceStore(createEphemeralEvidenceKeys().signing);
    const card = { name: "payments", tools: ["list_invoices"] };
    const loadView = (ref: { id: string; issuer: string }) =>
      ref.id === missionId && ref.issuer === current.issuer
        ? { view: current, freshness: { observed_at: new Date().toISOString(), source: "load_view" } }
        : undefined;
    const pep = new Pep({
      payments,
      evidence,
      fga: conn.fga,
      modelId: conn.modelId,
      loadView,
      instanceEpoch: "epoch-1",
      sourceDigest: sourceDigestOf(card),
      allowedFreshnessSources: new Set(["load_view"]),
    });
    const server = new McpPaymentsServer({ pep, payments, loadView, jwks: { keys: [] }, issuer: ISSUER, serverCard: card });

    const res = await server.callReadTool("list_invoices", {}, TOKEN, () => {
      // Mid-flight, exactly in the decision->execute window: the Mission's
      // own entry narrows from [acme, globex] to [acme], mirroring how
      // callWriteTool's beforeReverify mutates the payments store for a
      // write's TOCTOU proof.
      current = {
        ...current,
        authority_set: [{ ...(current.authority_set[0] as never), constraints: { vendors: ["acme"] } }],
      };
    });
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("parameter_mismatch");
    expect(res.result).toBeUndefined();
  });
});

/**
 * @spec runtime#read-binding: finding 3 (PR #612 author review), one
 * representative vendor cannot authorize a multi-vendor result. The
 * PDP/FGA request previously named only the entry's first allowed vendor
 * while execution returned every vendor in the entry. entry_digest proves
 * the Mission ceiling, never that Resource policy permitted every returned
 * vendor. Unconditional: a stub `Fga` (not live OpenFGA, which this domain
 * model cannot make independently disagree with the Mission's own
 * allowlist, see the manifest row's notes) proves the full production
 * path (pep.ts's `vendor_ids` construction, evaluateInner's per-member
 * loop, and server.ts's execute()): it denies the WHOLE read the moment any
 * one named vendor is refused, so a denied vendor's rows never appear.
 */
describe("finding 3: a multi-vendor list_invoices names every returned vendor to Resource policy, not just one representative (@spec read-binding)", () => {
  const missionId = "msn_612_g3";
  const TOKEN: TokenFacts = {
    sub: "alice",
    clientId: "ap-agent",
    mission: { id: missionId, issuer: "https://as.test", authority_hash: "sha-256:g3hash" },
    cnfJkt: "jkt-1",
  };
  const view: MissionView = {
    id: missionId,
    issuer: ISSUER,
    state: "active",
    version: 1,
    authority_hash: "sha-256:g3hash",
    authority_set: [
      {
        type: "mission_resource_access",
        resource: CANONICAL_RESOURCE,
        actions: ["payments:invoice.list"],
        constraints: { vendors: ["acme", "globex"] },
      },
    ],
    subject: { iss: ISSUER, sub: "alice" },
    client_id: "ap-agent",
  };

  function build(fga: import("@mission/pdp").Fga): { server: McpPaymentsServer } {
    const payments = seedPayments();
    const evidence = new EvidenceStore(createEphemeralEvidenceKeys().signing);
    const card = { name: "payments", tools: ["list_invoices"] };
    const loadView = (ref: { id: string; issuer: string }) =>
      ref.id === missionId && ref.issuer === view.issuer
        ? { view: view, freshness: { observed_at: new Date().toISOString(), source: "load_view" } }
        : undefined;
    const pep = new Pep({
      payments,
      evidence,
      fga,
      modelId: "unit-test-model",
      loadView,
      instanceEpoch: "epoch-1",
      sourceDigest: sourceDigestOf(card),
      allowedFreshnessSources: new Set(["load_view"]),
    });
    const server = new McpPaymentsServer({ pep, payments, loadView, jwks: { keys: [] }, issuer: ISSUER, serverCard: card });
    return { server };
  }

  it("Mission authority includes two vendors; Resource policy denies one: the whole read refuses out_of_authority, never a narrowed result", async () => {
    const denyGlobex = {
      checkWithContext: async (check: { object: string }) => check.object !== "vendor:globex",
    } as unknown as import("@mission/pdp").Fga;
    const { server } = build(denyGlobex);
    const res = await server.callReadTool("list_invoices", {}, TOKEN);
    expect(res.ok).toBe(false);
    expect(res.denial_reason).toBe("out_of_authority");
    // The denied vendor's rows never appear, nor does any OTHER vendor's:
    // this fails the whole read closed, per the response contract having no
    // lane for a partially narrowed permit.
    expect(res.result).toBeUndefined();
  });

  it("Mission authority includes two vendors; Resource policy permits both: the read succeeds with exactly those two vendors' invoices", async () => {
    const allow = { checkWithContext: async () => true } as unknown as import("@mission/pdp").Fga;
    const { server } = build(allow);
    const res = await server.callReadTool("list_invoices", {}, TOKEN);
    expect(res.ok, JSON.stringify(res)).toBe(true);
    const invoices = res.result as Array<{ vendor_id: string }>;
    expect(invoices.map((i) => i.vendor_id).sort()).toEqual(["acme", "globex"]);
  });
});

describe("GAP 2: an unrecognized decision-context member makes a permit unusable (@spec decision-output)", () => {
  const missionId = "msn_610_g2";
  const TOKEN: TokenFacts = {
    sub: "alice",
    clientId: "ap-agent",
    mission: { id: missionId, issuer: "https://as.test", authority_hash: "sha-256:g2hash" },
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
    subject: { iss: ISSUER, sub: "alice" },
    client_id: "ap-agent",
  };

  function build(): { pep: Pep; evidence: EvidenceStore } {
    const payments = new PaymentsStore();
    const evidence = new EvidenceStore(createEphemeralEvidenceKeys().signing);
    const pep = new Pep({
      payments,
      evidence,
      // Never reached: evaluate() is mocked for this describe block's tests.
      fga: {} as unknown as import("@mission/pdp").Fga,
      modelId: "unused",
      loadView: (ref) =>
        ref.id === view.id && ref.issuer === view.issuer
          ? { view: view, freshness: { observed_at: new Date().toISOString(), source: "load_view" } }
          : undefined,
      instanceEpoch: "epoch-1",
      sourceDigest: sourceDigestOf({ name: "payments" }),
    });
    return { pep, evidence };
  }

  // Every currently-recognized permit-context member at once (decision
  // metadata + the profile's own top-level members + the three genuine
  // conditions, NESTED under `conditions` per @spec authzen#response-context):
  // a control proving the enumeration below does not false-positive on the
  // permit shape the real PDP actually produces.
  const FULLY_RECOGNIZED_CONTEXT = {
    decision_id: "dec_1",
    evaluation_id: "dec_1",
    policy_view_id: "pv_1",
    action_class: "irreversible_action",
    class_source: "deployment",
    entry_digest: "sha-256:entry",
    conditions: {
      valid_until: new Date(Date.now() + 120_000).toISOString(),
      use_limit: 1,
      parameter_digest: "sha-256:params",
    },
  };

  it("a permit whose context carries only recognized members is granted", async () => {
    const { pep, evidence } = build();
    vi.mocked(pdp.evaluate).mockResolvedValueOnce({ decision: true, context: { ...FULLY_RECOGNIZED_CONTEXT } });
    const res = await pep.enforce("lookup_vendor", { vendor_id: "acme" }, TOKEN);
    expect(res.permitted, JSON.stringify(res)).toBe(true);
    expect(evidence.forMission(missionId).some((e) => e.kind === "refusal")).toBe(false);
  });

  it("a permit whose context carries ONE unrecognized member INSIDE conditions is refused with zero effect, never silently granted", async () => {
    const { pep, evidence } = build();
    vi.mocked(pdp.evaluate).mockResolvedValueOnce({
      decision: true,
      context: {
        ...FULLY_RECOGNIZED_CONTEXT,
        conditions: { ...FULLY_RECOGNIZED_CONTEXT.conditions, require_step_up: true },
      },
    });
    const res = await pep.enforce("lookup_vendor", { vendor_id: "acme" }, TOKEN);
    expect(res.permitted).toBe(false);
    expect(res.refusal_reason).toBe("unrecognized_condition");
    const refusal = evidence.forMission(missionId).find((e): e is RefusalRecord => e.kind === "refusal");
    expect(refusal?.content.denial_reason).toBe("unrecognized_condition");
    expect(refusal?.content.emitter).toEqual({ id: CANONICAL_RESOURCE, role: "pep" });
  });

  it("a permit whose context carries an UNKNOWN top-level member (outside conditions) is still granted: the must-understand rule is scoped to conditions, never the whole response context", async () => {
    const { pep, evidence } = build();
    vi.mocked(pdp.evaluate).mockResolvedValueOnce({
      decision: true,
      context: { ...FULLY_RECOGNIZED_CONTEXT, next_action: "none", some_future_response_member: "x" },
    });
    const res = await pep.enforce("lookup_vendor", { vendor_id: "acme" }, TOKEN);
    expect(res.permitted, JSON.stringify(res)).toBe(true);
    expect(evidence.forMission(missionId).some((e) => e.kind === "refusal")).toBe(false);
  });

  it("a permit carrying an obligation is refused as unfulfillable_obligation: this PEP implements no obligation type, so presence alone is a deny, distinct from an unrecognized condition", async () => {
    const { pep, evidence } = build();
    vi.mocked(pdp.evaluate).mockResolvedValueOnce({
      decision: true,
      context: { ...FULLY_RECOGNIZED_CONTEXT, obligations: [{ type: "step_up" }] },
    });
    const res = await pep.enforce("lookup_vendor", { vendor_id: "acme" }, TOKEN);
    expect(res.permitted).toBe(false);
    expect(res.refusal_reason).toBe("unfulfillable_obligation");
    const refusal = evidence.forMission(missionId).find((e): e is RefusalRecord => e.kind === "refusal");
    expect(refusal?.content.denial_reason).toBe("unfulfillable_obligation");
  });

  it("a DENY decision (no permit) is unaffected by the recognized-member enumeration", async () => {
    const { pep } = build();
    vi.mocked(pdp.evaluate).mockResolvedValueOnce({
      decision: false,
      context: { decision_id: "dec_2", evaluation_id: "dec_2", policy_view_id: "pv_2", denial_reason: "out_of_authority", reason: "out_of_authority" },
    });
    const res = await pep.enforce("lookup_vendor", { vendor_id: "acme" }, TOKEN);
    expect(res.permitted).toBe(false);
    expect(res.denial_reason).toBe("out_of_authority");
  });
});
