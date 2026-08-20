/**
 * M4 integration tests, scenarios 2 (happy path) and 3 (TOCTOU parameter
 * mismatch), composed in-process: real AS-issued mission view + token facts,
 * live OpenFGA-backed PDP, authoritative payments store, full PEP pipeline.
 * Auto-skips when OpenFGA is unreachable.
 */

import { beforeAll, describe, expect, it } from "vitest";
import { AUTHORITY_ENTRY_TYP, computeAnchor } from "@mission/core";
import { Fga, type MissionView } from "@mission/pdp";
import {
  CANONICAL_RESOURCE,
  EvidenceStore,
  McpPaymentsServer,
  PaymentsStore,
  Pep,
  sourceDigestOf,
  type TokenFacts,
} from "../src/index.js";

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
if (!up) console.warn("OpenFGA unreachable; skipping M4 enforcement tests");

const VIEW: MissionView = {
  id: "msn_m4",
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:m4hash",
  authority_set: [
    {
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:invoice.read", "payments:invoice.list", "payments:payment.schedule"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    },
  ],
};

const TOKEN: TokenFacts = {
  sub: "alice",
  clientId: "ap-agent",
  clientInstanceId: "inst-1",
  mission: { id: "msn_m4", authority_hash: "sha-256:m4hash" },
  cnfJkt: "jkt-1",
};

let fga: Fga;
let modelId: string;
let payments: PaymentsStore;
let evidence: EvidenceStore;
let server: McpPaymentsServer;

/** @spec runtime#state-freshness: a synchronous live read, freshness-
 *  stamped at this read (Finding 1); "load_view" declared trusted below. */
const loadViewFor = (v: MissionView) => (id: string) =>
  id === v.id ? { view: v, freshness: { observed_at: new Date().toISOString(), source: "load_view" } } : undefined;

d("M4 core enforcement tier", () => {
  beforeAll(async () => {
    const conn = await Fga.connect({ apiUrl: API_URL, presharedKey: KEY, caCertPath: CA });
    fga = conn.fga;
    modelId = conn.modelId;
  });

  const build = () => {
    payments = new PaymentsStore();
    payments.seed(
      [
        { id: "acme", name: "Acme", status: "approved" },
        { id: "globex", name: "Globex", status: "pending" },
      ],
      [
        { id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
        { id: "inv-2", vendor_id: "acme", amount: "900.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
        { id: "inv-3", vendor_id: "globex", amount: "50.00", currency: "USD", payee_account: "acct-globex", status: "payable" },
      ],
    );
    evidence = new EvidenceStore();
    const card = { name: "payments", tools: ["get_invoice"] };
    const pep = new Pep({
      payments,
      evidence,
      fga,
      modelId,
      loadView: loadViewFor(VIEW),
      instanceEpoch: "epoch-1",
      sourceDigest: sourceDigestOf(card),
      allowedFreshnessSources: new Set(["load_view"]),
    });
    server = new McpPaymentsServer({
      pep,
      payments,
      loadView: loadViewFor(VIEW),
      jwks: { keys: [] },
      issuer: ISSUER,
      serverCard: card,
    });
  };

  it("scenario 2: happy path -- in-authority read permitted, Decision Evidence recorded", async () => {
    build();
    const res = await server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN);
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect((res.result as { id: string }).id).toBe("inv-1");
    const ev = evidence.forMission("msn_m4");
    expect(ev.some((e) => e.kind === "decision" && e.decision === true && e.action === "payments:invoice.read")).toBe(true);
  });

  it("Decision Evidence carries the PEP emitter and the recomputable entry_digest", async () => {
    build();
    const res = await server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN);
    expect(res.ok, JSON.stringify(res)).toBe(true);
    const dec = evidence.forMission("msn_m4").find((e) => e.kind === "decision");
    expect(dec?.emitter).toEqual({ id: CANONICAL_RESOURCE, role: "pep" });
    // The resolved-scope anchor recomputes over the matched Authority Set entry.
    expect(dec?.kind === "decision" && dec.entry_digest).toBe(
      computeAnchor(AUTHORITY_ENTRY_TYP, VIEW.issuer, VIEW.authority_set[0] as never),
    );
  });

  // @spec mission-substrate#governance-record (minimum-coverage-and-attribution,
  // the positive/negative reliance-decision arm): a DENIED decision is
  // recorded with the same attribution and Mission correlation as a permit,
  // not only the happy path above.
  it("a denied decision also produces attributable, mission-correlated Decision Evidence, not only a permit", async () => {
    build();
    const res = await server.callWriteTool("schedule_payment", { invoice_id: "inv-3" }, TOKEN);
    expect(res.ok, JSON.stringify(res)).toBe(false);
    expect(res.denial_reason).toBe("out_of_authority");
    const dec = evidence.forMission("msn_m4").find((e) => e.kind === "decision" && e.decision === false);
    expect(dec).toBeDefined();
    expect(dec?.mission_id).toBe("msn_m4");
    expect(dec?.emitter).toEqual({ id: CANONICAL_RESOURCE, role: "pep" });
  });

  it("scenario 2: schedule under the cap permitted and reconciles digest at execute", async () => {
    build();
    const res = await server.callWriteTool("schedule_payment", { invoice_id: "inv-1" }, TOKEN);
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect((res.result as { scheduled: boolean }).scheduled).toBe(true);
  });

  it("scenario 3: TOCTOU -- invoice mutated between decision and execute -> parameter_mismatch refusal", async () => {
    build();
    const res = await server.callWriteTool(
      "schedule_payment",
      { invoice_id: "inv-1" },
      TOKEN,
      () => payments.bumpInvoiceAmount("inv-1", "480.00"), // mutate in the window
    );
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("parameter_mismatch");
    const ev = evidence.forMission("msn_m4");
    expect(ev.some((e) => e.kind === "refusal" && e.refusal_reason === "parameter_mismatch")).toBe(true);
    // The Refusal Record identifies its emitting enforcement point too.
    const refusal = ev.find((e) => e.kind === "refusal");
    expect(refusal?.emitter).toEqual({ id: CANONICAL_RESOURCE, role: "pep" });
  });

  it("out-of-authority tool (over-cap invoice) denied out_of_authority... constraint path", async () => {
    build();
    const res = await server.callWriteTool("schedule_payment", { invoice_id: "inv-2" }, TOKEN);
    expect(res.ok).toBe(false);
    expect(res.denial_reason).toBe("constraint_exceeded");
  });

  it("vendor outside constraint denied out_of_authority", async () => {
    build();
    const res = await server.callWriteTool("schedule_payment", { invoice_id: "inv-3" }, TOKEN);
    expect(res.ok).toBe(false);
    expect(res.denial_reason).toBe("out_of_authority");
    // @spec I-D.draft-zehavi-oauth-rar-metadata §4: this out_of_authority is NOT
    // a genuine absence -- payments:payment.schedule IS in the Authority Set,
    // only this vendor is excluded by the constraint -- so the remediation
    // grain must NOT fire (proposing the same entry back would be a false hint).
    expect(res.insufficient_authorization).toBeUndefined();
  });

  // @spec I-D.draft-zehavi-oauth-rar-metadata §4 — the insufficient_authorization
  // remediation grain: a GENUINE absence (the action is nowhere in the
  // Mission's Authority Set, unlike the vendor-constraint case above) carries
  // actionable authorization_details the client could propose next.
  it("action absent from the Authority Set entirely denied out_of_authority WITH the insufficient_authorization grain", async () => {
    build();
    const res = await server.callWriteTool("execute_wire_transfer", { invoice_id: "inv-1" }, TOKEN);
    expect(res.ok).toBe(false);
    expect(res.denial_reason).toBe("out_of_authority");
    expect(res.insufficient_authorization).toBeDefined();
    const ia = res.insufficient_authorization!;
    expect(ia.www_authenticate).toMatch(/^DPoP /); // this RS's tokens are DPoP-bound, not Bearer
    expect(ia.www_authenticate).toContain('error="insufficient_authorization"');
    expect(ia.www_authenticate).toContain(`authorization_remediation=${ia.authorization_remediation}`);
    const decoded = JSON.parse(Buffer.from(ia.authorization_remediation, "base64url").toString("utf8")) as {
      authorization_details: Array<{ type: string; resource: string; actions: string[] }>;
    };
    expect(decoded.authorization_details).toEqual([
      { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:payment.execute"] },
    ]);
  });

  // @spec containment#restoration — containment is the family's monotonic
  // trust ratchet; restoration goes through an Expansion successor with
  // disclosed history, never through "here's how to ask again". The
  // remediation grain must NOT fire for authority_contained.
  it("contained authority denied authority_contained WITHOUT the insufficient_authorization grain", async () => {
    const containedView: MissionView = {
      ...VIEW,
      containment: { version: 1, contained: [{ resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] }] },
    };
    payments = new PaymentsStore();
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
    evidence = new EvidenceStore();
    const card = { name: "payments", tools: ["get_invoice"] };
    const pep = new Pep({
      payments,
      evidence,
      fga,
      modelId,
      loadView: loadViewFor(containedView),
      instanceEpoch: "epoch-1",
      sourceDigest: sourceDigestOf(card),
      allowedFreshnessSources: new Set(["load_view"]),
    });
    const containedServer = new McpPaymentsServer({
      pep,
      payments,
      loadView: loadViewFor(containedView),
      jwks: { keys: [] },
      issuer: ISSUER,
      serverCard: card,
    });
    const res = await containedServer.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN);
    expect(res.ok).toBe(false);
    expect(res.denial_reason).toBe("authority_contained");
    expect(res.insufficient_authorization).toBeUndefined();
  });

  it("mission-scoped tools/list shows only in-authority tools (least exposure)", () => {
    build();
    const tools = server.toolsList(TOKEN).map((t) => t.name).sort();
    expect(tools).toEqual(["get_invoice", "list_invoices", "schedule_payment"]);
    // execute_wire_transfer / send_remittance_email / lookup_vendor not granted.
    expect(tools).not.toContain("execute_wire_transfer");
  });

  it("RFC 9728 PRM advertises mission_bound_authorization_required", () => {
    build();
    const prm = server.protectedResourceMetadata();
    expect(prm.mission_bound_authorization_required).toBe(true);
    expect(prm.resource).toBe(CANONICAL_RESOURCE);
  });
});
