/**
 * The composed demo stack: every service wired in one process against a shared
 * in-memory state and one live OpenFGA. This is the single object the exhibit
 * runner, the trace run, and the browser BFF all drive, so all three "see it"
 * surfaces exercise the identical enforcement path.
 */

import { generateKeyPair } from "jose";
import {
  CatalogProvider,
  MissionKernel,
  validateMissionIntent,
} from "@mission/authorization-server";
import { CATALOG_SERVICES, DERIVATION_POLICY } from "@mission/demo-data";
import { Fga, type MissionView } from "@mission/pdp";
import {
  Connectors,
  EvidenceStore,
  McpPaymentsServer,
  PaymentsStore,
  Pep,
  sourceDigestOf,
} from "@mission/mcp-payments";
import { signStatement, TransparencyService, type Receipt, type SignedStatement } from "@mission/transparency";
import { ConsoleBff } from "@mission/console-bff";

export const ISS = "https://as.demo";

export interface DemoStack {
  kernel: MissionKernel;
  fga: Fga;
  modelId: string;
  payments: PaymentsStore;
  evidence: EvidenceStore;
  connectors: Connectors;
  pep: Pep;
  server: McpPaymentsServer;
  transparency: TransparencyService;
  catalog: CatalogProvider;
  bff: ConsoleBff;
  revokedInstances: Set<string>;
  viewFor: (missionId: string) => MissionView | undefined;
  /** Register evidence to the transparency log + retain it for the timeline. */
  publishEvidence: (missionId: string, evidenceType: string, evidence: Record<string, unknown>) => Promise<void>;
}

export async function composeStack(opts: { openfgaUrl: string; presharedKey: string; caCertPath?: string }): Promise<DemoStack> {
  const conn = await Fga.connect({ apiUrl: opts.openfgaUrl, presharedKey: opts.presharedKey, ...(opts.caCertPath ? { caCertPath: opts.caCertPath } : {}) });
  const fga = conn.fga;
  const modelId = conn.modelId;

  const asKeys = await generateKeyPair("ES256", { extractable: true });
  const kernel = new MissionKernel({ issuer: ISS, policy: DERIVATION_POLICY as never, statusKey: asKeys.privateKey, statusKid: "as-status" });

  const payments = new PaymentsStore();
  payments.seed(
    [
      { id: "acme", name: "Acme Corp", status: "approved" },
      { id: "globex", name: "Globex", status: "pending" },
    ],
    [
      { id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme-001", status: "payable" },
      { id: "inv-2", vendor_id: "acme", amount: "900.00", currency: "USD", payee_account: "acct-acme-001", status: "payable" },
      { id: "inv-3", vendor_id: "globex", amount: "50.00", currency: "USD", payee_account: "acct-globex-001", status: "payable" },
    ],
  );

  const evidence = new EvidenceStore();
  const connectors = new Connectors();
  const revokedInstances = new Set<string>();

  // The PDP's view of a mission (in a real deployment fetched from AS/Status).
  const viewFor = (missionId: string): MissionView | undefined => {
    const r = kernel.get(missionId);
    if (!r) return undefined;
    const fresh = kernel.applyExpiry(r);
    return {
      id: fresh.id,
      issuer: fresh.issuer,
      state: fresh.state,
      version: fresh.version,
      authority_hash: fresh.authority_hash,
      authority_set: fresh.authority_set,
    };
  };

  const pep = new Pep({
    payments,
    evidence,
    fga,
    modelId,
    loadView: viewFor,
    instanceEpoch: "demo-epoch",
    sourceDigest: sourceDigestOf({ name: "payments" }),
    revokedInstances,
  });

  const { TransactionEngine } = await import("@mission/mcp-payments");
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView: viewFor,
    jwks: { keys: [] },
    issuer: ISS,
    serverCard: { name: "payments" },
    transaction: { engine: new TransactionEngine("demo-epoch"), connectors, evidence },
  });

  // Transparency + producers.
  const tKeys = await generateKeyPair("ES256", { extractable: true });
  const transparency = new TransparencyService({ key: tKeys.privateKey, kid: "transparency", issuer: "https://transparency.demo" });
  const pdpProducerKeys = await generateKeyPair("ES256", { extractable: true });
  const { exportJWK } = await import("jose");
  const producerPub = { ...(await exportJWK(pdpProducerKeys.publicKey)), kid: "pdp-evidence", alg: "ES256" };
  const tPub = { ...(await exportJWK(tKeys.publicKey)), kid: "transparency", alg: "ES256" };
  const producerKey = { iss: "https://pdp.demo", key: pdpProducerKeys.privateKey, kid: "pdp-evidence" };
  const retainedEvidence = new Map<string, unknown>();
  const receipts = new Map<string, Receipt>();

  const publishEvidence = async (missionId: string, evidenceType: string, ev: Record<string, unknown>) => {
    const stmt = await signStatement(producerKey, { missionId, evidenceType, evidence: ev as never });
    receipts.set(stmt.jws, await transparency.register(stmt));
    retainedEvidence.set(stmt.digest, ev);
  };

  // ARS (denial binding not exercised in the exhibit; present for completeness).
  const { AccessRequestService } = await import("@mission/access-request");
  const arsKeys = await generateKeyPair("ES256", { extractable: true });
  const pdpDenialKeys = await generateKeyPair("ES256", { extractable: true });
  const ars = new AccessRequestService({
    pdpJwks: { keys: [{ ...(await exportJWK(pdpDenialKeys.publicKey)), kid: "pdp", alg: "ES256" } as never] },
    approvalKey: arsKeys.privateKey,
    approvalKid: "ars",
  });

  const bff = new ConsoleBff({
    kernel,
    ars,
    transparency,
    retrieveEvidence: (_m, digest) => retainedEvidence.get(digest),
    producerJwks: { keys: [producerPub as never] },
    serviceJwks: { keys: [tPub as never] },
    receiptFor: (s: SignedStatement) => receipts.get(s.jws),
  });

  const catalog = new CatalogProvider(kernel, CATALOG_SERVICES, { arsIntakeUrl: "https://ars.demo/access-requests", issuer: ISS });

  return {
    kernel,
    fga,
    modelId,
    payments,
    evidence,
    connectors,
    pep,
    server,
    transparency,
    catalog,
    bff,
    revokedInstances,
    viewFor,
    publishEvidence,
  };
}

/** Approve a demo mission for alice, approved by bob (write-bearing governance). */
export function approveDemoMission(stack: DemoStack): { id: string } {
  const intent = validateMissionIntent(
    JSON.stringify({
      goal: "Pay approved Acme invoices for Q3",
      resources: [DERIVATION_POLICY.ceiling[0].resource],
      expires_at: "2027-01-01T00:00:00Z",
      proposed_authority: [
        {
          type: "mission_resource_access",
          resource: DERIVATION_POLICY.ceiling[0].resource,
          actions: ["payments:invoice.read", "payments:payment.schedule", "payments:payment.execute"],
          constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
        },
      ],
    }),
  );
  return stack.kernel.approve({
    intent,
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-demo-${stack.kernel.allMissions().length + 1}`,
  });
}
