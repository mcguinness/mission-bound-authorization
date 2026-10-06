/**
 * @spec operation-profile-payments-v1 "Parameter schemas and normalization"
 * and D34 (D316, #1106): the PEP's tool-boundary intake, witnessed over the
 * real MCP channel with a signed Mission-bound token.
 *
 * Every request is validated against its tool's served input schema, read as
 * a closed schema, before any authorization work; a violation is refused
 * `invalid_request` with one Refusal Record and no PDP call. Strings are
 * NFC-normalized first, and target lookup, effective parameters and the
 * effect all use the normalized value.
 *
 * Unconditional: the FGA check is a stub that always permits, so this file
 * never skips.
 */

import { randomUUID } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { TRUSTED_TOOL_CATALOGS } from "@mission/demo-data";
import type { Fga, MissionView } from "@mission/pdp";
import { describe, expect, it } from "vitest";
import {
  CANONICAL_RESOURCE,
  Connectors,
  createEphemeralEvidenceKeys,
  createMediatedClient,
  type DecisionEvidence,
  EvidenceStore,
  McpPaymentsServer,
  PaymentsStore,
  Pep,
  type RefusalRecord,
  TransactionEngine,
} from "../src/index.js";
import { ALL_ACTIONS_CREDENTIAL } from "./credential-fixtures.js";

const EVIDENCE_KEYS = createEphemeralEvidenceKeys();
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
const idem = (): string => `idem_${randomUUID()}`;
const ISSUER = "https://as.test";

/** One invoice id with a composed character, in its two Unicode forms. */
const NFC_ID = "inv-café";
const NFD_ID = "inv-café";

const VIEW: MissionView = {
  id: "msn_1106",
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:intake",
  authority_set: [
    {
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:invoice.read", "payments:invoice.list", "payments:payment.execute"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    },
  ],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
};

async function build() {
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [
      { id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
      { id: NFC_ID, vendor_id: "acme", amount: "75.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
    ],
  );
  const evidence = new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver);
  const connectors = new Connectors();
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === VIEW.id && ref.issuer === VIEW.issuer
      ? { view: VIEW, observation: { state: VIEW.state, version: VIEW.version, mode: "fresh", freshness_at: new Date().toISOString() } }
      : undefined;
  // Every decision request the PEP sends: an intake refusal sends none.
  const pdpCalls: unknown[] = [];
  const pep = new Pep({
    decide: async (req, options) => {
      pdpCalls.push(req);
      return EVIDENCE_KEYS.decide(req, options);
    },
    payments,
    evidence,
    fga: alwaysAllowFga,
    modelId: "unit-test-model",
    loadView,
    instanceEpoch: "epoch-1106",
  });
  const kp = await generateKeyPair("ES256", { extractable: true });
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
    jwks: { keys: [{ ...(await exportJWK(kp.publicKey)), kid: "mission-key", alg: "ES256" }] },
    keyRoles: { accessToken: ["mission-key"], attenuationRoot: [], transactionToken: [] },
    issuer: ISSUER,
    transaction: { engine: new TransactionEngine("epoch-1106"), connectors, evidence },
  });
  const { client } = await createMediatedClient(server);
  const jwt = await new SignJWT({
    client_id: "ap-agent",
    mission: { id: VIEW.id, issuer: ISSUER, authority_hash: VIEW.authority_hash },
    cnf: { jkt: "jkt-1106" },
    authorization_details: [...ALL_ACTIONS_CREDENTIAL],
  })
    .setProtectedHeader({ alg: "ES256", kid: "mission-key", typ: "at+jwt" })
    .setIssuer(ISSUER)
    .setAudience(CANONICAL_RESOURCE)
    .setSubject("alice")
    .setIssuedAt()
    .setJti(randomUUID())
    .setExpirationTime("5m")
    .sign(kp.privateKey);
  return { client, jwt, evidence, connectors, pdpCalls };
}

type Built = Awaited<ReturnType<typeof build>>;

/** The intake refusal: `invalid_request` on the tool result, no PDP call, one Refusal Record. */
function expectIntakeRefusal(h: Built, res: unknown, action: string, label: string) {
  expect(res, label).toEqual({ ok: false, refusal_reason: "invalid_request" });
  expect(h.pdpCalls, label).toHaveLength(0);
  const records = h.evidence.all();
  expect(records.map((r) => r.kind), label).toEqual(["refusal"]);
  const refusal = (records[0] as RefusalRecord).content;
  // The caller-visible diagnostic maps to the enumerated value the signed
  // record carries (`PRE_DECISION_DENIAL_REASON`).
  expect(refusal.denial_reason, label).toBe("request_unsupported");
  expect(refusal.action.name, label).toBe(action);
  expect(h.connectors.ledgerEntries(), label).toHaveLength(0);
}

const decisionsOf = (h: Built) =>
  h.evidence.all().filter((e): e is DecisionEvidence => e.kind === "decision").map((e) => e.content);

describe("intake refuses a request outside the tool's served schema before any PDP call (@spec operation-profile-payments-v1, D316)", () => {
  it("an argument member the served schema does not declare is refused invalid_request with no PDP call and one Refusal Record", async () => {
    // Positive control: the same request without the extra member is permitted.
    const control = await build();
    expect((await control.client.callTool("get_invoice", { invoice_id: "inv-1" }, control.jwt)).ok).toBe(true);
    expect(control.pdpCalls).toHaveLength(1);

    const h = await build();
    const res = await h.client.callTool("get_invoice", { invoice_id: "inv-1", note: "pay soon" }, h.jwt);
    expectIntakeRefusal(h, res, "payments:invoice.read", "unknown member");
  });

  it("an authoritative member (D34) is refused invalid_request with no PDP call and one Refusal Record", async () => {
    // The fields the PEP loads from the payments store, never from the
    // caller: invoice amount, currency, payee account, the invoice's vendor,
    // invoice status, and the record versions.
    const authoritative: Record<string, string> = {
      amount: "1.00",
      currency: "EUR",
      payee_account: "acct-attacker",
      vendor_id: "acme",
      status: "payable",
      invoice_version: "1",
      vendor_version: "1",
    };
    for (const [member, value] of Object.entries(authoritative)) {
      const h = await build();
      const res = await h.client.callTool(
        "execute_wire_transfer",
        { invoice_id: "inv-1", idempotency_key: idem(), [member]: value },
        h.jwt,
      );
      expectIntakeRefusal(h, res, "payments:payment.execute", member);
    }
  });

  it("every served input schema is closed and declares no authoritative member of the invoice it targets", () => {
    const catalog = TRUSTED_TOOL_CATALOGS.find((c) => c.service_id === "payments");
    const tools = (JSON.parse(catalog?.text ?? "{}") as {
      tools: Array<{ name: string; inputSchema: { additionalProperties?: unknown; properties?: Record<string, unknown> } }>;
    }).tools;
    expect(tools.length).toBeGreaterThan(0);
    const authoritative = ["amount", "currency", "payee_account", "status", "version", "invoice_version", "vendor_version"];
    for (const tool of tools) {
      expect(tool.inputSchema.additionalProperties, tool.name).toBe(false);
      const declared = Object.keys(tool.inputSchema.properties ?? {});
      expect(declared.filter((m) => authoritative.includes(m)), tool.name).toEqual([]);
      // `vendor_id` is caller-supplied only where it names the vendor target
      // or filter; on an invoice-targeted tool it is the invoice's own.
      if (declared.includes("invoice_id")) expect(declared, tool.name).not.toContain("vendor_id");
    }
  });
});

describe("intake NFC-normalizes strings before target lookup, effective parameters and execution (@spec operation-profile-payments-v1, D316)", () => {
  it("NFC and NFD forms of one invoice_id resolve the same target, yield the same effective parameters, and execute with the normalized value", async () => {
    expect(NFD_ID).not.toBe(NFC_ID);
    expect(NFD_ID.normalize("NFC")).toBe(NFC_ID);
    const h = await build();

    // The preflight crossing echoes the invoice id it executed with.
    const composed = await h.client.callTool("check_transfer", { invoice_id: NFC_ID }, h.jwt);
    const decomposed = await h.client.callTool("check_transfer", { invoice_id: NFD_ID }, h.jwt);
    expect(composed, JSON.stringify(composed)).toEqual({ ok: true, result: { feasible: true, invoice_id: NFC_ID } });
    expect(decomposed, JSON.stringify(decomposed)).toEqual({ ok: true, result: { feasible: true, invoice_id: NFC_ID } });

    // One target and one parameter digest across both encodings.
    const [first, second] = decisionsOf(h);
    expect(first?.resource.id).toBe(NFC_ID);
    expect(second?.resource.id).toBe(NFC_ID);
    expect(first?.parameter_digest).toBeDefined();
    expect(second?.parameter_digest).toBe(first?.parameter_digest);

    // A read returns the stored invoice for the decomposed form.
    const read = await h.client.callTool("get_invoice", { invoice_id: NFD_ID }, h.jwt);
    expect((read.result as { id?: string } | undefined)?.id).toBe(NFC_ID);

    // The committing crossing digests and posts under the normalized id.
    const wire = await h.client.callTool("execute_wire_transfer", { invoice_id: NFD_ID, idempotency_key: idem() }, h.jwt);
    expect(wire.ok, JSON.stringify(wire)).toBe(true);
    expect(decisionsOf(h).at(-1)?.parameter_digest).toBe(first?.parameter_digest);
    expect(h.connectors.ledgerEntries().map((e) => e.invoice_id)).toEqual([NFC_ID]);
  });
});
