/**
 * @spec runtime-evidence#pre-decision-refusal, authzen#failure-condition-coverage
 * "Mission state not establishable at the PEP" (#1329, D496): a verified
 * Mission-bound token naming a Mission the PEP's loader does not hold.
 *
 * The PEP refuses it at the Mission load, before any decision request, with
 * the deployment's caller-visible diagnostic `unknown_mission` and one signed
 * Refusal Record carrying the enumerated `state_unavailable`. The record
 * digests the pre-request input and carries no `mission` member, because no
 * Mission was established, and the refusal has no business effect. Witnessed
 * over the real MCP channel with a signed token; the decision function
 * records each request it is asked, so "before any decision" is observed.
 *
 * Unconditional: the Mission's contextual check is a stub that always
 * permits, so this file never skips.
 */

import { randomUUID } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import type { Fga, MissionView } from "@mission/pdp";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import { describe, expect, it } from "vitest";
import {
  CANONICAL_RESOURCE,
  Connectors,
  createEphemeralEvidenceKeys,
  createMediatedClient,
  EvidenceStore,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  PaymentsStore,
  Pep,
  REFUSAL_RECORD_MEDIA_TYPE,
  type RefusalRecord,
  TransactionEngine,
  verifyEvidenceEnvelope,
} from "../src/index.js";
import { ALL_ACTIONS_CREDENTIAL } from "./credential-fixtures.js";

const EVIDENCE_KEYS = createEphemeralEvidenceKeys({ resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE });
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
const ISSUER = "https://as.test";
/** A Mission this resource's loader does not hold: the token names it, and it verifies. */
const NOT_HELD = "msn_1329_not_held";

/** The one Mission the loader holds: reads and wires on acme. */
const VIEW: MissionView = {
  id: "msn_1329",
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:m1329",
  authority_set: [
    {
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:invoice.read", "payments:payment.execute"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    },
  ],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
};

/** The resource with its PEP, transaction tier and MCP channel; every decision request the PEP sends is recorded. */
async function build() {
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
  );
  const evidence = new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver);
  const connectors = new Connectors();
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === VIEW.id && ref.issuer === VIEW.issuer
      ? { view: VIEW, observation: { state: VIEW.state, version: VIEW.version, mode: "fresh", freshness_at: new Date().toISOString() } }
      : undefined;
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
    instanceEpoch: "epoch-1329",
  });
  const kp = await generateKeyPair("ES256", { extractable: true });
  const server = new McpPaymentsServer({
    writeReservations: openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" }),
    pep,
    payments,
    loadView,
    jwks: { keys: [{ ...(await exportJWK(kp.publicKey)), kid: "mission-key", alg: "ES256" }] },
    keyRoles: { accessToken: ["mission-key"], attenuationRoot: [], transactionToken: [] },
    issuer: ISSUER,
    transaction: { engine: new TransactionEngine("epoch-1329"), connectors, evidence },
  });
  const { client } = await createMediatedClient(server);
  /** A Mission-bound access token this resource verifies, naming `missionId`. */
  const mint = (missionId: string): Promise<string> =>
    new SignJWT({
      client_id: "ap-agent",
      mission: { id: missionId, issuer: ISSUER, authority_hash: VIEW.authority_hash },
      cnf: { jkt: "jkt-1329" },
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
  return { client, mint, evidence, connectors, pdpCalls, payments };
}

describe("a Mission-bound token whose Mission the PEP cannot establish is refused before any decision (@spec runtime-evidence#pre-decision-refusal, authzen#failure-condition-coverage, #1329)", () => {
  it("refuses a verified token naming a Mission the loader does not hold unknown_mission, with no decision request, one verifiable signed state_unavailable Refusal Record naming no Mission, no Decision Evidence and no effect, on a read and a wire", async () => {
    // Positive control: the same token shape naming the held Mission is
    // admitted and reaches the PDP, so each refusal below is the loader's.
    const control = await build();
    const read = await control.client.callTool("get_invoice", { invoice_id: "inv-1" }, await control.mint(VIEW.id));
    expect(read.ok, JSON.stringify(read)).toBe(true);
    expect(control.pdpCalls).toHaveLength(1);

    const cases: Array<[string, Record<string, unknown>, string]> = [
      ["get_invoice", { invoice_id: "inv-1" }, "payments:invoice.read"],
      ["execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` }, "payments:payment.execute"],
    ];
    for (const [tool, args, action] of cases) {
      const h = await build();
      const res = await h.client.callTool(tool, args, await h.mint(NOT_HELD));
      // `unknown_mission` is this deployment's caller-visible diagnostic; the
      // signed record carries the enumerated value it maps to.
      expect(res, tool).toEqual({ ok: false, refusal_reason: "unknown_mission" });
      expect(h.pdpCalls, tool).toHaveLength(0);
      // One Refusal Record and nothing else: no Decision Evidence, no Execution Evidence.
      expect(h.evidence.all().map((e) => e.kind), tool).toEqual(["refusal"]);
      const refusal = (h.evidence.all()[0] as RefusalRecord).content;
      expect(refusal, tool).toMatchObject({
        decision: "deny",
        denial_reason: "state_unavailable",
        audience: CANONICAL_RESOURCE,
        action: { name: action },
        emitter: { role: "pep" },
        // The digest covers the pre-request input: no evaluation request preceded the refusal.
        request_digest_input: "pre_request",
      });
      // No Mission was established, so the record names none and starts no per-Mission sequence.
      expect(refusal, tool).not.toHaveProperty("mission");
      expect(refusal, tool).not.toHaveProperty("sequence");
      expect(await verifyEvidenceEnvelope(refusal, REFUSAL_RECORD_MEDIA_TYPE, EVIDENCE_KEYS.resolver), tool).toEqual({ valid: true });
      // No effect: no connector ledger entry and the invoice still payable.
      expect(h.connectors.ledgerEntries(), tool).toHaveLength(0);
      expect(h.payments.getInvoice("inv-1")?.status, tool).toBe("payable");
    }
  });
});
