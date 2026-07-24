/**
 * The composed demo stack: every service wired in one process against a shared
 * in-memory state and one live OpenFGA. This is the single object the exhibit
 * runner, the trace run, and the browser BFF all drive, so all three "see it"
 * surfaces exercise the identical enforcement path.
 */

import { exportJWK, generateKeyPair } from "jose";
import {
  type AuthorityEntry,
  buildAuthorizationServer,
  CatalogProvider,
  issueCrossDomainGrant,
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
  type PepDeps,
  sourceDigestOf,
} from "@mission/mcp-payments";
import { ResourceAuthorizationServer } from "@mission/ras";
import { SaasMcpServer, SAAS_RESOURCE } from "@mission/mcp-saas";
import { signStatement, TransparencyService, type Receipt, type SignedStatement } from "@mission/transparency";
import { ConsoleBff } from "@mission/console-bff";
import type { AccessRequestService } from "@mission/access-request";

/** Logical issuer for the in-process (non-auth-server) surfaces. */
export const ISS = "https://as.demo";
/** The second trust domain (LedgerCloud) for the cross-domain leg (M9). */
export const RAS_ISS = "https://ras.ledgercloud.test";

/** The cross-domain / real-issuance extras, present only with withAuthServer. */
export interface AuthServerExtras {
  /** Base URL of the running AS provider (all OAuth endpoints derive from it). */
  asUrl: string;
  /** The agent confidential client's private JWK (private_key_jwt signer). */
  agentClientJwk: Record<string, unknown>;
  ras: ResourceAuthorizationServer;
  saas: SaasMcpServer;
  rasIssuer: string;
  saasResource: string;
  /** Issue an ID-JAG cross-domain grant from a mission, DPoP-bound to cnfJkt. */
  issueCrossDomainGrant: (
    missionId: string,
    cnfJkt: string,
  ) => Promise<{ grant: string; jti: string; audienceScoped: AuthorityEntry[] }>;
  /** Stop the AS HTTP listener (the exhibit calls this before exit). */
  closeAuthServer: () => void;
}

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
  ars: AccessRequestService;
  revokedInstances: Set<string>;
  /** The issuer this stack's kernel/tokens use (ISS, or the AS URL). */
  issuer: string;
  viewFor: (missionId: string) => MissionView | undefined;
  /** Register evidence to the transparency log + retain it for the timeline. */
  publishEvidence: (missionId: string, evidenceType: string, evidence: Record<string, unknown>) => Promise<void>;
  /** Install a PEP observer to capture the AuthZEN envelope + PDP decision (demo). */
  onEnforce: (fn: PepDeps["observe"]) => void;
  /** Real-issuance + cross-domain extras; only set when withAuthServer is true. */
  authServer?: AuthServerExtras;
}

export async function composeStack(opts: {
  openfgaUrl: string;
  presharedKey: string;
  caCertPath?: string;
  /**
   * Stand up the real AS provider (buildAuthorizationServer) on an HTTP port and
   * wire the cross-domain RAS + SaaS servers, so a caller can drive real OAuth
   * issuance (PAR -> token) and the ID-JAG leg. The exhibit sets this; the
   * browser and trace surfaces leave it off and use the in-process kernel.
   */
  withAuthServer?: boolean;
  asPort?: number;
}): Promise<DemoStack> {
  const conn = await Fga.connect({ apiUrl: opts.openfgaUrl, presharedKey: opts.presharedKey, ...(opts.caCertPath ? { caCertPath: opts.caCertPath } : {}) });
  const fga = conn.fga;
  const modelId = conn.modelId;

  // Kernel + token-issuer + the RS's token-verification JWKS differ by mode:
  // with the auth server, the real provider owns the kernel and signs tokens;
  // without it, an in-process kernel backs the TokenFacts-driven surfaces.
  let kernel: MissionKernel;
  let issuer: string;
  let serverJwks: { keys: Record<string, unknown>[] };
  let authServer: AuthServerExtras | undefined;

  if (opts.withAuthServer) {
    const asPort = opts.asPort ?? 4400;
    const asUrl = `http://localhost:${asPort}`;
    const as = await buildAuthorizationServer({ issuer: asUrl, allowHeadlessAdjudication: true });
    const asServer = as.provider.listen(asPort);
    kernel = as.kernel;
    issuer = asUrl;
    // The RS verifies real tokens against the AS's published public JWKS.
    serverJwks = (await (await fetch(`${asUrl}/jwks`)).json()) as { keys: Record<string, unknown>[] };

    // Cross-domain (M9): a dedicated ES256 grant key the RAS trusts under the AS
    // issuer (the AS's own token key is RS256 and not exposed; this mirrors the
    // separated-key-purpose design, D39). RAS mints a local token; SaaS enforces
    // from that token alone (token-only PEP, no PDP).
    const xdKeys = await generateKeyPair("ES256", { extractable: true });
    const xdPub = { ...(await exportJWK(xdKeys.publicKey)), kid: "as-crossdomain", alg: "ES256" };
    const rasKeys = await generateKeyPair("ES256", { extractable: true });
    const rasPub = { ...(await exportJWK(rasKeys.publicKey)), kid: "ras-token", alg: "ES256" };
    const ras = new ResourceAuthorizationServer({
      issuer: RAS_ISS,
      trustedIssuers: { [asUrl]: { keys: [xdPub as never] } },
      signKey: rasKeys.privateKey,
      signKid: "ras-token",
    });
    const saas = new SaasMcpServer({ rasIssuer: RAS_ISS, rasJwks: { keys: [rasPub as never] } });
    const resourceToAs = (r: string) => (r === SAAS_RESOURCE ? RAS_ISS : asUrl);
    authServer = {
      asUrl,
      agentClientJwk: as.agentClientJwk,
      ras,
      saas,
      rasIssuer: RAS_ISS,
      saasResource: SAAS_RESOURCE,
      issueCrossDomainGrant: (missionId, cnfJkt) =>
        issueCrossDomainGrant(kernel, xdKeys.privateKey, "as-crossdomain", { missionId, targetAs: RAS_ISS, cnfJkt, resourceToAs }),
      closeAuthServer: () => asServer.close(),
    };
  } else {
    const asKeys = await generateKeyPair("ES256", { extractable: true });
    kernel = new MissionKernel({ issuer: ISS, policy: DERIVATION_POLICY as never, statusKey: asKeys.privateKey, statusKid: "as-status" });
    issuer = ISS;
    serverJwks = { keys: [] };
  }

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
      { id: "inv-seed", vendor_id: "acme", amount: "75.00", currency: "USD", payee_account: "acct-acme-001", status: "payable" },
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

  // PDP denial-binding key: the PEP's requestable signer and the ARS trust the
  // same key so a real binding_token round-trips (M6 JIT/ARAP flow).
  const pdpDenialKeys = await generateKeyPair("ES256", { extractable: true });
  const pdpDenialPub = { ...(await exportJWK(pdpDenialKeys.publicKey)), kid: "pdp-denial", alg: "ES256" };

  let observer: PepDeps["observe"];
  const pep = new Pep({
    payments,
    evidence,
    fga,
    modelId,
    loadView: viewFor,
    instanceEpoch: "demo-epoch",
    sourceDigest: sourceDigestOf({ name: "payments" }),
    revokedInstances,
    observe: (e) => observer?.(e),
    // JIT gate: sending a remittance email is in the mission's authority but
    // requires an action-bound approval, resolved just-in-time via ARAP (M6).
    requiresActionApproval: (action) => action === "payments:remittance.send",
    maxApprovalAgeSeconds: 300,
    requestable: { sign: pdpDenialKeys.privateKey, kid: "pdp-denial", endpoint: "https://ars.demo/access-requests" },
  });

  const { TransactionEngine } = await import("@mission/mcp-payments");
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView: viewFor,
    jwks: serverJwks,
    issuer,
    serverCard: { name: "payments" },
    transaction: { engine: new TransactionEngine("demo-epoch"), connectors, evidence },
  });

  // Transparency + producers.
  const tKeys = await generateKeyPair("ES256", { extractable: true });
  const transparency = new TransparencyService({ key: tKeys.privateKey, kid: "transparency", issuer: "https://transparency.demo" });
  const pdpProducerKeys = await generateKeyPair("ES256", { extractable: true });
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

  // ARS trusts the same PDP denial-binding key the PEP signs requestable
  // denials with, so a JIT access request verifies (M6).
  const { AccessRequestService } = await import("@mission/access-request");
  const arsKeys = await generateKeyPair("ES256", { extractable: true });
  const ars = new AccessRequestService({
    pdpJwks: { keys: [pdpDenialPub as never] },
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

  const catalog = new CatalogProvider(kernel, CATALOG_SERVICES, { arsIntakeUrl: "https://ars.demo/access-requests", issuer });

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
    ars,
    issuer,
    revokedInstances,
    viewFor,
    publishEvidence,
    onEnforce: (fn) => {
      observer = fn;
    },
    ...(authServer ? { authServer } : {}),
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
          actions: ["payments:invoice.read", "payments:payment.schedule", "payments:payment.execute", "payments:remittance.send"],
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
