/**
 * @spec resource-access#rs-enforcement, resource-access#initial-common-constraints,
 * resource-access#protected-resource-metadata, runtime#input-parameters (#1266, D457)
 *
 * The payments resource enforces the implemented Common Constraints at its
 * public tool surface, against facts it establishes from its own records:
 * the PEP reads them from the payments store (never from tool arguments),
 * carries them on the decision request, refuses at its own credential bound
 * what they already rule out, and the PDP enforces the Mission and credential
 * bounds against the same facts. A missing fact refuses. A fact that changes
 * between decision and execution refuses at reverification. The protected
 * resource metadata names only keys this resource enforces.
 *
 * Unconditional: the FGA check is a stub, so this file never skips.
 */

import { randomUUID } from "node:crypto";
import { IMPLEMENTED_COMMON_CONSTRAINTS } from "@mission/core";
import { describe, expect, it } from "vitest";
import type { Fga, MissionView } from "@mission/pdp";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import {
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  credentialAuthorityFrom,
  EvidenceStore,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  PaymentsStore,
  Pep,
  TOOLS,
  type TokenFacts,
} from "../src/index.js";

const EVIDENCE_KEYS = createEphemeralEvidenceKeys({ resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE });
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
const MISSION = "msn_1266";
const ISSUER = "https://as.test";
const ALL_ACTIONS = [...new Set(TOOLS.map((t) => t.action))];

const Q3 = { resource_issued_after: "2026-07-01T00:00:00Z", resource_issued_before: "2026-09-30T23:59:59Z" };

interface Harness {
  server: McpPaymentsServer;
  payments: PaymentsStore;
  token: TokenFacts;
  /** The resource members of the last decision request the PEP built. */
  lastResource: () => Record<string, unknown> | undefined;
  /** Whether the PEP asked the PDP for a decision at all on the last call. */
  decisions: () => number;
}

/**
 * One payments resource. `mission` is the matched Authority Set entry's
 * `constraints`; `credential` the credential's own entry's, or `undefined`
 * for a credential covering every action with no restriction (so a test
 * reaches the Mission bound alone).
 */
function harness(opts: { mission?: Record<string, unknown>; credential?: Record<string, unknown> }): Harness {
  const payments = new PaymentsStore();
  payments.seed(
    [
      { id: "acme", name: "Acme", status: "approved", tenant: "payments-demo" },
      { id: "globex", name: "Globex", status: "approved", tenant: "other-tenant" },
      { id: "initech", name: "Initech", status: "approved" },
    ],
    [
      { id: "inv-globex", vendor_id: "globex", amount: "50.00", currency: "USD", payee_account: "acct", status: "payable" },
      { id: "inv-initech", vendor_id: "initech", amount: "50.00", currency: "USD", payee_account: "acct", status: "payable" },
      { id: "inv-q3", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct", status: "payable", issued_at: "2026-08-15T09:30:00Z" },
      { id: "inv-early", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct", status: "payable", issued_at: "2026-06-30T23:59:59Z" },
      { id: "inv-late", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct", status: "payable", issued_at: "2026-10-01T00:00:00Z" },
      { id: "inv-edge", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct", status: "payable", issued_at: "2026-07-01T02:00:00+02:00" },
      { id: "inv-none", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct", status: "payable" },
    ],
  );
  const view: MissionView = {
    id: MISSION,
    issuer: ISSUER,
    state: "active",
    version: 1,
    authority_hash: "sha-256:m1266",
    authority_set: [
      {
        type: "mission_resource_access",
        resource: CANONICAL_RESOURCE,
        actions: ALL_ACTIONS,
        ...(opts.mission ? { constraints: opts.mission } : {}),
      } as MissionView["authority_set"][number],
    ],
    subject: { iss: ISSUER, sub: "alice" },
    client_id: "ap-agent",
  };
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === MISSION && ref.issuer === ISSUER
      ? { view, observation: { state: view.state, version: view.version, mode: "fresh", freshness_at: new Date().toISOString() } }
      : undefined;
  let resource: Record<string, unknown> | undefined;
  let decisions = 0;
  const evidence = new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver);
  const pep = new Pep({
    decide: async (req, options) => {
      decisions++;
      resource = req.resource as unknown as Record<string, unknown>;
      return EVIDENCE_KEYS.decide(req, options);
    },
    payments,
    evidence,
    fga: alwaysAllowFga,
    modelId: "unit-test-model",
    loadView,
    instanceEpoch: "epoch-1266",
  });
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
    jwks: { keys: [] },
    keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] },
    issuer: ISSUER,
    writeReservations: openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" }),
  });
  const token: TokenFacts = {
    sub: "alice",
    clientId: "ap-agent",
    mission: { id: MISSION, issuer: ISSUER, authority_hash: "sha-256:m1266" },
    cnfJkt: "jkt-1266",
    credentialAuthority: credentialAuthorityFrom([
      {
        type: "mission_resource_access",
        resource: CANONICAL_RESOURCE,
        actions: ALL_ACTIONS,
        ...(opts.credential ? { constraints: opts.credential } : {}),
      },
    ]),
  };
  return { server, payments, token, lastResource: () => resource, decisions: () => decisions };
}

const read = (h: Harness, invoiceId: string) => h.server.callReadTool("get_invoice", { invoice_id: invoiceId }, h.token);

describe("the payments resource enforces resource_issued_after and resource_issued_before on the Mission bound (@spec resource-access#rs-enforcement)", () => {
  it("permits a read of an invoice the store records as issued within the window, carrying the store's fact", async () => {
    const h = harness({ mission: Q3 });
    const res = await read(h, "inv-q3");
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect((h.lastResource()?.properties as Record<string, unknown>).issued_at).toBe("2026-08-15T09:30:00Z");
  });

  it("refuses a read of an invoice issued before the after-bound or after the before-bound", async () => {
    const h = harness({ mission: Q3 });
    for (const id of ["inv-early", "inv-late"]) {
      const res = await read(h, id);
      expect(res.ok, id).toBe(false);
      expect(res.denial_reason, id).toBe("parameter_violation");
      expect(res.result, id).toBeUndefined();
    }
  });

  it("treats the after-bound as inclusive across offsets (boundary)", async () => {
    const h = harness({ mission: Q3 });
    expect((await read(h, "inv-edge")).ok).toBe(true);
  });

  it("refuses an invoice whose record carries no issuance instant (missing fact)", async () => {
    // Each bound alone, so neither gate's refusal hides the other's.
    for (const mission of [Q3, { resource_issued_after: Q3.resource_issued_after }, { resource_issued_before: Q3.resource_issued_before }]) {
      const h = harness({ mission });
      const res = await read(h, "inv-none");
      expect(res.ok, JSON.stringify(mission)).toBe(false);
      expect(res.denial_reason, JSON.stringify(mission)).toBe("parameter_violation");
    }
  });

  it("refuses a collection read and a vendor read, which establish no single issuance fact", async () => {
    const h = harness({ mission: Q3 });
    const list = await h.server.callReadTool("list_invoices", {}, h.token);
    expect(list.ok).toBe(false);
    expect(list.result).toBeUndefined();
    const vendor = await h.server.callReadTool("lookup_vendor", { vendor_id: "acme" }, h.token);
    expect(vendor.ok).toBe(false);
  });

  it("never reads the fact from tool arguments: an argument naming an in-window instant is refused at intake", async () => {
    const h = harness({ mission: Q3 });
    const res = await h.server.callReadTool(
      "get_invoice",
      { invoice_id: "inv-late", issued_at: "2026-08-15T00:00:00Z" },
      h.token,
    );
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("invalid_request");
  });

  it("a write within the window executes; one outside it is refused with no effect", async () => {
    const h = harness({ mission: Q3 });
    const ok = await h.server.callWriteTool(
      "schedule_payment",
      { invoice_id: "inv-q3", idempotency_key: `idem_${randomUUID()}` },
      h.token,
    );
    expect(ok.ok, JSON.stringify(ok)).toBe(true);
    const refused = await h.server.callWriteTool(
      "schedule_payment",
      { invoice_id: "inv-late", idempotency_key: `idem_${randomUUID()}` },
      h.token,
    );
    expect(refused.ok).toBe(false);
    expect(refused.denial_reason).toBe("parameter_violation");
  });

  it("refuses a write whose invoice's issuance fact changed between decision and execution", async () => {
    const h = harness({ mission: Q3 });
    const res = await h.server.callWriteTool(
      "schedule_payment",
      { invoice_id: "inv-q3", idempotency_key: `idem_${randomUUID()}` },
      h.token,
      () => h.payments.setInvoiceIssuedAt("inv-q3", "2026-10-15T00:00:00Z"),
    );
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("parameter_mismatch");
  });
});

describe("the payments resource enforces resource_issued_after and resource_issued_before on the credential bound (@spec runtime#input-authority)", () => {
  it("a credential narrower than its Mission is refused at the PEP, before any decision, outside its window", async () => {
    const h = harness({ credential: { resource_issued_after: "2026-08-01T00:00:00Z" } });
    const refused = await read(h, "inv-edge");
    expect(refused.ok).toBe(false);
    expect(refused.denial_reason).toBe("out_of_authority");
    expect(h.decisions()).toBe(0);
    expect((await read(h, "inv-q3")).ok).toBe(true);
  });

  it("a credential bound with no issuance fact to read refuses at the PEP", async () => {
    const h = harness({ credential: Q3 });
    expect((await read(h, "inv-none")).ok).toBe(false);
    expect(h.decisions()).toBe(0);
  });
});

describe("the payments resource enforces tenant against its own ownership records (@spec resource-access#rs-enforcement)", () => {
  const TENANT = { tenant: "payments-demo" };

  it("permits an invoice and a vendor whose records name the bound's tenant, carrying the store's fact", async () => {
    const h = harness({ mission: TENANT });
    const invoice = await read(h, "inv-q3");
    expect(invoice.ok, JSON.stringify(invoice)).toBe(true);
    expect((h.lastResource()?.properties as Record<string, unknown>).tenant).toBe("payments-demo");
    const vendor = await h.server.callReadTool("lookup_vendor", { vendor_id: "acme" }, h.token);
    expect(vendor.ok, JSON.stringify(vendor)).toBe(true);
  });

  it("refuses an invoice and a vendor of another tenant", async () => {
    const h = harness({ mission: TENANT });
    const invoice = await read(h, "inv-globex");
    expect(invoice.ok).toBe(false);
    expect(invoice.denial_reason).toBe("parameter_violation");
    const vendor = await h.server.callReadTool("lookup_vendor", { vendor_id: "globex" }, h.token);
    expect(vendor.ok).toBe(false);
    expect(vendor.denial_reason).toBe("parameter_violation");
  });

  it("refuses a resource whose record names no tenant (missing fact), and a collection read", async () => {
    const h = harness({ mission: TENANT });
    expect((await read(h, "inv-initech")).denial_reason).toBe("parameter_violation");
    expect((await h.server.callReadTool("lookup_vendor", { vendor_id: "initech" }, h.token)).ok).toBe(false);
    expect((await h.server.callReadTool("list_invoices", { vendor_id: "acme" }, h.token)).ok).toBe(false);
  });

  it("a client-supplied tenant cannot establish the fact: the argument is refused at intake", async () => {
    const h = harness({ mission: TENANT });
    const res = await h.server.callReadTool("get_invoice", { invoice_id: "inv-globex", tenant: "payments-demo" }, h.token);
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("invalid_request");
    expect(h.decisions()).toBe(0);
  });

  it("refuses a write whose vendor's tenant changed between decision and execution", async () => {
    const h = harness({ mission: TENANT });
    const res = await h.server.callWriteTool(
      "schedule_payment",
      { invoice_id: "inv-q3", idempotency_key: `idem_${randomUUID()}` },
      h.token,
      () => h.payments.setVendorTenant("acme", "other-tenant"),
    );
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("parameter_mismatch");
  });

  it("a credential bound to a tenant is refused at the PEP, before any decision, for another tenant's invoice", async () => {
    const h = harness({ credential: TENANT });
    const res = await read(h, "inv-globex");
    expect(res.ok).toBe(false);
    expect(res.denial_reason).toBe("out_of_authority");
    expect(h.decisions()).toBe(0);
    expect((await read(h, "inv-q3")).ok).toBe(true);
  });
});

describe("the payments resource fails closed on a constraint it does not enforce (@spec resource-access#rs-enforcement)", () => {
  it("refuses an operation whose matched Mission entry carries a constraints key the resource does not understand", async () => {
    const h = harness({ mission: { x_region: "eu" } });
    const res = await read(h, "inv-q3");
    expect(res.ok).toBe(false);
    expect(res.denial_reason).toBe("parameter_violation");
    expect(res.result).toBeUndefined();
  });
});

describe("protected resource metadata names only enforced constraint keys (@spec resource-access#protected-resource-metadata)", () => {
  it("advertises exactly max_amount, vendors and the Common Constraints it enforces, and no other", () => {
    const h = harness({});
    const supported = h.server.protectedResourceMetadata().mission_constraints_supported as string[];
    expect([...supported].sort()).toEqual(
      ["max_amount", "vendors", "resource_issued_after", "resource_issued_before", "tenant"].sort(),
    );
    // The supported set the Authorization Server admits is the one this resource enforces.
    expect([...supported].sort()).toEqual(
      ["max_amount", "vendors", ...IMPLEMENTED_COMMON_CONSTRAINTS].sort(),
    );
  });
});
