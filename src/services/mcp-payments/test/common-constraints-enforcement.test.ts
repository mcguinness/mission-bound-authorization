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
  Connectors,
  createEphemeralEvidenceKeys,
  credentialAuthorityFrom,
  EvidenceStore,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  PaymentsStore,
  Pep,
  TOOLS,
  type TokenFacts,
  TransactionEngine,
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
  /** The action members of the last decision request the PEP built. */
  lastAction: () => Record<string, unknown> | undefined;
  /** Whether the PEP asked the PDP for a decision at all on the last call. */
  decisions: () => number;
  connectors: Connectors;
  /** The permit conditions of the last decision. */
  lastConditions: () => Record<string, unknown> | undefined;
  /** Advance the one clock the PEP, the PDP and the connectors read. */
  advance: (ms: number) => void;
}

/**
 * One payments resource. `mission` is the matched Authority Set entry's
 * `constraints`; `credential` the credential's own entry's, or `undefined`
 * for a credential covering every action with no restriction (so a test
 * reaches the Mission bound alone).
 */
function harness(opts: {
  mission?: Record<string, unknown>;
  credential?: Record<string, unknown>;
  /** The clock's starting instant (default: now). */
  startMs?: number;
  /** Run after each decision, before the permit is admitted. */
  afterDecision?: (h: Harness) => void;
}): Harness {
  let clockMs = opts.startMs ?? Date.now();
  const clock = () => new Date(clockMs);
  let self: Harness;
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
      ? { view, observation: { state: view.state, version: view.version, mode: "fresh", freshness_at: clock().toISOString() } }
      : undefined;
  let resource: Record<string, unknown> | undefined;
  let action: Record<string, unknown> | undefined;
  let conditions: Record<string, unknown> | undefined;
  let decisions = 0;
  const evidence = new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver);
  const connectors = new Connectors(clock);
  const pep = new Pep({
    decide: async (req, options) => {
      decisions++;
      resource = req.resource as unknown as Record<string, unknown>;
      action = req.action as unknown as Record<string, unknown>;
      const decision = await EVIDENCE_KEYS.decide(req, options);
      conditions = decision.context.conditions as Record<string, unknown> | undefined;
      return decision;
    },
    observe: () => opts.afterDecision?.(self),
    now: clock,
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
    transaction: { engine: new TransactionEngine("epoch-1266", clock), connectors, evidence },
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
  self = {
    server,
    payments,
    token,
    connectors,
    lastResource: () => resource,
    lastAction: () => action,
    lastConditions: () => conditions,
    decisions: () => decisions,
    advance: (ms) => {
      clockMs += ms;
    },
  };
  return self;
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

describe("the payments resource enforces time_window at the point of use (@spec resource-access#initial-common-constraints)", () => {
  const START = Date.parse("2026-10-18T12:00:00Z");
  const at = (seconds: number) => new Date(START + seconds * 1000).toISOString();
  const transfer = (h: Harness, beforeCommit?: () => void) =>
    h.server.callTransactionTool(
      "execute_wire_transfer",
      { invoice_id: "inv-q3", idempotency_key: `idem_${randomUUID()}` },
      h.token,
      beforeCommit,
    );

  it("permits within the window and binds the permit's valid_until to the window's end", async () => {
    const h = harness({ mission: { time_window: { not_before: at(-3600), not_after: at(30) } }, startMs: START });
    const res = await read(h, "inv-q3");
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect(Date.parse(h.lastConditions()?.valid_until as string)).toBe(START + 30_000);
  });

  it("refuses before the window opens and after it closes, with no result", async () => {
    for (const window of [{ not_before: at(60) }, { not_after: at(-1) }]) {
      const h = harness({ mission: { time_window: window }, startMs: START });
      const res = await read(h, "inv-q3");
      expect(res.ok, JSON.stringify(window)).toBe(false);
      expect(res.denial_reason, JSON.stringify(window)).toBe("parameter_violation");
      expect(res.result).toBeUndefined();
    }
  });

  it("refuses at use a permit relied on after the window closed, though the permit's own lifetime had not ended", async () => {
    const h = harness({
      mission: { time_window: { not_after: at(30) } },
      startMs: START,
      afterDecision: (self) => self.advance(31_000),
    });
    const res = await read(h, "inv-q3");
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("permit_expired");
    expect(res.result).toBeUndefined();
  });

  it("refuses a long-running commit whose window closed before the commit, with no effect", async () => {
    // Inside the irreversible class's 30-second state bound, so only the
    // window can end the permit before the commit.
    const h = harness({ mission: { time_window: { not_after: at(10) } }, startMs: START });
    const res = await transfer(h, () => h.advance(15_000));
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("permit_expired");
    expect(h.connectors.ledgerEntries(MISSION)).toHaveLength(0);
  });

  it("the same commit inside the window executes (positive control)", async () => {
    const h = harness({ mission: { time_window: { not_after: at(10) } }, startMs: START });
    const res = await transfer(h, () => h.advance(5_000));
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect(h.connectors.ledgerEntries(MISSION)).toHaveLength(1);
  });

  it("a credential window that has closed is refused at the PEP, before any decision", async () => {
    const h = harness({ credential: { time_window: { not_after: at(-1) } }, startMs: START });
    const res = await read(h, "inv-q3");
    expect(res.ok).toBe(false);
    expect(res.denial_reason).toBe("out_of_authority");
    expect(h.decisions()).toBe(0);
  });

  it("a credential window bounds the permit when the Mission carries none", async () => {
    const h = harness({
      credential: { time_window: { not_after: at(30) } },
      startMs: START,
      afterDecision: (self) => self.advance(31_000),
    });
    const res = await read(h, "inv-q3");
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("permit_expired");
  });
});

describe("the payments resource enforces recipient_domain over every resolved recipient (@spec resource-access#initial-common-constraints)", () => {
  const remit = (h: Harness, beforeCommit?: () => void) =>
    h.server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-q3", idempotency_key: `idem_${randomUUID()}` },
      h.token,
      beforeCommit,
    );
  const sent = (h: Harness) =>
    (h.connectors.db.prepare("SELECT to_addr FROM outbox").all() as { to_addr: string }[]).map((r) => r.to_addr);
  /** acme's remittance goes to its AP inbox and a distribution list. */
  const route = (h: Harness, listMembers: string[]) => {
    h.payments.seedRemittance("acme", ["ap@acme.example", "remit-list@acme.example"]);
    h.payments.setMailList("remit-list@acme.example", listMembers);
  };

  it("sends to the vendor's default address under a domain that contains it, carrying the resolved recipients", async () => {
    const h = harness({ mission: { recipient_domain: "vendor.example" } });
    const res = await remit(h);
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect((h.lastAction()?.properties as Record<string, unknown>).recipients).toEqual(["acme@vendor.example"]);
    expect(sent(h)).toEqual(["acme@vendor.example"]);
  });

  it("checks every recipient a distribution list expands to: one outside the domain refuses, with no email", async () => {
    const h = harness({ mission: { recipient_domain: "acme.example" } });
    route(h, ["treasury@acme.example", "controller@partner.example"]);
    const res = await remit(h);
    expect(res.ok).toBe(false);
    expect(res.denial_reason).toBe("parameter_violation");
    expect((h.lastAction()?.properties as Record<string, unknown>).recipients).toEqual([
      "ap@acme.example",
      "controller@partner.example",
      "treasury@acme.example",
    ]);
    expect(sent(h)).toEqual([]);
  });

  it("sends to exactly the expanded recipients when every one is within the domain", async () => {
    const h = harness({ mission: { recipient_domain: "acme.example" } });
    route(h, ["treasury@acme.example", "controller@EU.ACME.example"]);
    const res = await remit(h);
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect(sent(h)).toEqual(["ap@acme.example, controller@EU.ACME.example, treasury@acme.example"]);
  });

  it("refuses before any decision when the routing cannot be resolved", async () => {
    const h = harness({ mission: { recipient_domain: "acme.example" } });
    route(h, ["loop@acme.example"]);
    h.payments.setMailList("loop@acme.example", ["remit-list@acme.example"]);
    const res = await remit(h);
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("unresolvable_recipients");
    expect(h.decisions()).toBe(0);
    expect(sent(h)).toEqual([]);
  });

  it("refuses a send whose list membership changed between decision and commit, with no email", async () => {
    const h = harness({ mission: { recipient_domain: "acme.example" } });
    route(h, ["treasury@acme.example"]);
    const res = await remit(h, () =>
      h.payments.setMailList("remit-list@acme.example", ["treasury@acme.example", "drop@elsewhere.example"]),
    );
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("parameter_mismatch");
    expect(sent(h)).toEqual([]);
  });

  it("refuses an operation that addresses no recipient under a recipient bound", async () => {
    const h = harness({ mission: { recipient_domain: "acme.example" } });
    const res = await read(h, "inv-q3");
    expect(res.ok).toBe(false);
    expect(res.denial_reason).toBe("parameter_violation");
  });

  it("a recipient named in the arguments cannot establish the fact: it is refused at intake", async () => {
    const h = harness({ mission: { recipient_domain: "vendor.example" } });
    const res = await h.server.callTransactionTool(
      "send_remittance_email",
      { invoice_id: "inv-q3", idempotency_key: `idem_${randomUUID()}`, to: "acme@vendor.example" },
      h.token,
    );
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("invalid_request");
    expect(h.decisions()).toBe(0);
  });

  it("a credential bound to a domain is refused at the PEP, before any decision, for an expanded recipient outside it", async () => {
    const h = harness({ credential: { recipient_domain: "acme.example" } });
    route(h, ["controller@partner.example"]);
    const res = await remit(h);
    expect(res.ok).toBe(false);
    expect(res.denial_reason).toBe("out_of_authority");
    expect(h.decisions()).toBe(0);
    // The same credential reaches a send whose every recipient is inside.
    const inside = harness({ credential: { recipient_domain: "acme.example" } });
    route(inside, ["treasury@acme.example"]);
    expect((await remit(inside)).ok).toBe(true);
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
      ["max_amount", "vendors", "resource_issued_after", "resource_issued_before", "tenant", "time_window", "recipient_domain"].sort(),
    );
    // The supported set the Authorization Server admits is the one this resource enforces.
    expect([...supported].sort()).toEqual(
      ["max_amount", "vendors", ...IMPLEMENTED_COMMON_CONSTRAINTS].sort(),
    );
  });
});
