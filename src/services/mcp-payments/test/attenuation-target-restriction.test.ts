/**
 * @spec attenuation#root-mapping, resource-access#resource-matching (#1276,
 * D457): an attenuation root minted for an entry finer than its audience
 * keeps that entry's target restriction at the audience. The Mission names
 * one invoice (`<canonical resource URI>/invoices/inv-1`); the root's `aud`
 * names the payments service identifier and a second resource server. The
 * root carries no resource member, so an `aud` naming the service never
 * widens the tool to the service: the
 * payments resource reads the tool's own target and matches the operation
 * target against it, under its live operation contract. On the -02 wire
 * (#1756) the root maps the entry only to a tool whose operations the
 * resource declares at that target: here, the invoice read under an
 * invoice-level contract, whose target is the invoice. The consumer names
 * the invoked tool by the operation's target, so the substrate itself
 * refuses an invocation whose target is not the tool's.
 *
 * The credential bound refuses before any decision request, so the refusals
 * need no OpenFGA; the permitted case uses a stub FGA that always allows and
 * a permitting Resource policy fixture.
 */

import { deriveAttenuationRoot, MissionKernel, validateMissionIntent } from "@mission/authorization-server";
import { type AttenuationOperations, aatToolId } from "@mission/core";
import { testAuthoritySourceCatalog } from "@mission/authorization-server/test-support";
import type { Fga, MissionView } from "@mission/pdp";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import { exportJWK, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  type ActionMapping,
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  PAYMENTS_INVOICE_CONTRACT,
  PaymentsStore,
  Pep,
  signAatPop,
  TOOL_ACTIONS,
  type TokenFacts,
} from "../src/index.js";

const EVIDENCE_KEYS = createEphemeralEvidenceKeys({ resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE });
const AS_ISS = "https://as.test";
const READ_ACTION = "payments:invoice.read";
const INV1 = `${CANONICAL_RESOURCE}/invoices/inv-1`;
const INV2 = `${CANONICAL_RESOURCE}/invoices/inv-2`;
const CEILING = [{ type: "mission_resource_access", resource: INV1, actions: [READ_ACTION] }] as const;

let view: MissionView;
let facts: TokenFacts;
let tools: Record<string, unknown>;
let root: string;
let holderKeys: { privateKey: CryptoKey; publicKey: CryptoKey };
let invoiceServer: McpPaymentsServer;
let serviceServer: McpPaymentsServer;

const loadView = (ref: { id: string; issuer: string }) =>
  ref.id === view.id && ref.issuer === view.issuer
    ? { view, observation: { state: view.state, version: view.version, mode: "fresh", freshness_at: new Date().toISOString() } }
    : undefined;

const INVOICE_PROFILE: Record<string, ActionMapping> = {
  ...TOOL_ACTIONS,
  get_invoice: { ...(TOOL_ACTIONS.get_invoice as ActionMapping), target: PAYMENTS_INVOICE_CONTRACT },
};

/**
 * The invoice-level deployment's declaration: the invoice read at the one
 * invoice's identifier, its target under the invoice contract.
 */
const INVOICE_OPERATIONS: AttenuationOperations = (resource, action) =>
  resource === INV1 && action === READ_ACTION
    ? [{ name: "get_invoice", arguments: { invoice_id: { required: true } }, establishes: ["vendors", "max_amount"] }]
    : undefined;

/** The presentation of the root by its holder for `get_invoice` on `invoiceId`, naming the tool `server` computes. */
async function presentRoot(server: McpPaymentsServer, toolTarget: string, invoiceId: string): Promise<TokenFacts> {
  const args = JSON.stringify({ invoice_id: invoiceId });
  const pop = await signAatPop({ leaf: root, holderKey: holderKeys.privateKey, tool: aatToolId(toolTarget, READ_ACTION), argumentsJson: args });
  return server.validateAatPresentation({ aat_chain: [root], aat_pop: pop }, "get_invoice", args);
}

beforeAll(async () => {
  const asKeys = await generateKeyPair("ES256", { extractable: true });
  const asPub = { ...(await exportJWK(asKeys.publicKey)), kid: "as-attenuation", alg: "ES256" };
  holderKeys = await generateKeyPair("ES256", { extractable: true });
  const policy = { policy_version: "attn-target-1", ceiling: CEILING };
  const kernel = new MissionKernel({
    issuer: AS_ISS,
    policy: policy as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(CEILING as never, ["ap-agent"], ["bob"]),
    statusKey: asKeys.privateKey,
    statusKid: "as-status",
  });
  const mission = kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Read one invoice", target_resources: [INV1], expires_at: "2027-01-01T00:00:00Z" }),
    ),
    proposedAuthority: CEILING as never,
    subject: { iss: AS_ISS, sub: "alice" },
    approver: { iss: AS_ISS, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: "apev-attn-target",
  });
  view = {
    id: mission.id,
    issuer: AS_ISS,
    state: "active",
    version: 1,
    authority_hash: mission.authority_hash,
    authority_set: mission.authority_set,
    subject: mission.subject,
    client_id: mission.client_id,
  };
  // The root's audiences: the payments service identifier, coarser than the
  // entry, and a second resource server. Neither bounds the tool's target.
  const derived = await deriveAttenuationRoot(kernel, asKeys.privateKey, "as-attenuation", {
    missionId: mission.id,
    aud: [CANONICAL_RESOURCE, "https://ledger.example/mcp"],
    clientId: "ap-agent",
    cnfJwk: await exportJWK(holderKeys.publicKey),
    operations: INVOICE_OPERATIONS,
    delMaxDepth: 0,
  });
  tools = derived.tools;
  root = derived.root;
  const serverUnder = (profile: Record<string, ActionMapping>) =>
    new McpPaymentsServer({
      writeReservations: openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" }),
      pep: new Pep({
        decide: EVIDENCE_KEYS.decide,
        payments: new PaymentsStore(),
        evidence: new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver),
        fga: {} as unknown as Fga,
        modelId: "m",
        loadView,
        instanceEpoch: "epoch-attn-target",
        operationProfile: () => profile,
      }),
      payments: new PaymentsStore(),
      loadView,
      jwks: { keys: [asPub] },
      keyRoles: { accessToken: [], attenuationRoot: ["as-attenuation"], transactionToken: [] },
      issuer: AS_ISS,
    });
  invoiceServer = serverUnder(INVOICE_PROFILE);
  serviceServer = serverUnder(TOOL_ACTIONS);
  facts = await presentRoot(invoiceServer, INV1, "inv-1");
});

/** A PEP over two Acme invoices, under `profile`, with a stub FGA that always allows. */
function pepUnder(profile: Record<string, ActionMapping>): Pep {
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    ["inv-1", "inv-2"].map((id) => ({ id, vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct", status: "payable" })),
  );
  return new Pep({
    decide: EVIDENCE_KEYS.decide,
    payments,
    evidence: new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver),
    fga: { checkWithContext: async () => true } as unknown as Fga,
    modelId: "m",
    loadView,
    instanceEpoch: "epoch-attn-target",
    operationProfile: () => profile,
  });
}

describe("an attenuation root keeps a finer entry's target restriction at a coarser audience (@spec attenuation#root-mapping, #1276)", () => {
  it("the root's tool names the entry's invoice, and at the service audience it covers that invoice alone, never the service or another invoice", async () => {
    expect(Object.keys(tools)).toEqual([`${INV1}#${READ_ACTION}`]);
    expect(facts.mission !== undefined && facts.credentialAuthority).toEqual([
      { type: "mission_resource_access", resource: INV1, actions: [READ_ACTION] },
    ]);
    // Under the invoice contract: inv-1 is the entry's target and permits.
    const invoicePep = pepUnder(INVOICE_PROFILE);
    const permitted = await invoicePep.enforce("get_invoice", { invoice_id: "inv-1" }, facts);
    expect(permitted.permitted, JSON.stringify(permitted)).toBe(true);
    // Another invoice under the same audience: refused by the root's own restriction.
    const sibling = await invoicePep.enforce("get_invoice", { invoice_id: "inv-2" }, facts);
    expect(sibling).toMatchObject({ permitted: false, denial_reason: "out_of_authority" });
    // Under the shipped service-level contract the target is the service the
    // root's aud names; the tool's invoice target does not cover it.
    const servicePep = pepUnder(TOOL_ACTIONS);
    const service = await servicePep.enforce("get_invoice", { invoice_id: "inv-1" }, facts);
    expect(service).toMatchObject({ permitted: false, denial_reason: "out_of_authority" });
    // The proof names the invoked tool by its target: a presentation for
    // another invoice, or at the service-level contract, is refused by the
    // substrate before any credential fact is derived.
    await expect(presentRoot(invoiceServer, INV2, "inv-2")).rejects.toThrow(/step 6b: the leaf does not authorize the tool/);
    await expect(presentRoot(serviceServer, CANONICAL_RESOURCE, "inv-1")).rejects.toThrow(/step 6b/);
  });
});
