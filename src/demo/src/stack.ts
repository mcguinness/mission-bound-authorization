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
import { CATALOG_SERVICES, DERIVATION_POLICY, TOPOLOGY } from "@mission/demo-data";
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
import { SaasMcpServer } from "@mission/mcp-saas";
import { signStatement, TransparencyService, type Receipt, type SignedStatement } from "@mission/transparency";
import { ConsoleBff } from "@mission/console-bff";
import type { AccessRequestService } from "@mission/access-request";

/** Logical issuer for the in-process (non-auth-server) surfaces. */
export const ISS = TOPOLOGY.issuers.as;
/** The second trust domain (LedgerCloud) for the cross-domain leg (M9). */
export const RAS_ISS = TOPOLOGY.issuers.ras;

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

  // The Access Request Service adjudicates JIT approvals. Created BEFORE the
  // authorization server so the SAME instance is shared: the AS transaction
  // endpoint opens AROP tasks on it (openForTxn) while the console-bff and demo
  // adjudicate them (D37). The AS-vouched txn path carries no PDP denial-binding
  // to verify, so pdpJwks is empty.
  const { AccessRequestService } = await import("@mission/access-request");
  const arsKeys = await generateKeyPair("ES256", { extractable: true });
  const ars = new AccessRequestService({
    pdpJwks: { keys: [] },
    approvalKey: arsKeys.privateKey,
    approvalKid: "ars",
    // ARAP: the ARS's own identity as approval-state issuer (stable across both
    // modes), audienced to the PDP that re-evaluates the approval.
    issuer: new URL(TOPOLOGY.endpoints.arsIntake).origin,
    approvalAudience: TOPOLOGY.issuers.pdp,
    approvalTtlSeconds: TOPOLOGY.ttls.approvalSeconds,
  });

  // AROP Transaction Challenge wiring, set only on the auth-server path (where a
  // real /transaction endpoint exists): the RS-side challenge signer (rs-txn),
  // and the AS txn public JWKS + issuer the RS validates a presented txn-token
  // against.
  let challengeSigner: { sign: import("jose").CryptoKey; kid: string; txnEndpoint: string; asIssuer: string } | undefined;
  let txnTokenJwks: { keys: Record<string, unknown>[] } | undefined;
  let rsAsIssuer: string | undefined;

  // Kernel + token-issuer + the RS's token-verification JWKS differ by mode:
  // with the auth server, the real provider owns the kernel and signs tokens;
  // without it, an in-process kernel backs the TokenFacts-driven surfaces.
  let kernel: MissionKernel;
  let issuer: string;
  let serverJwks: { keys: Record<string, unknown>[] };
  let authServer: AuthServerExtras | undefined;

  if (opts.withAuthServer) {
    const asPort = opts.asPort ?? TOPOLOGY.ports.as;
    const asUrl = `http://localhost:${asPort}`;
    // The RS's txn-challenge signing key (rs-txn); the AS is configured with its
    // public half so POST /transaction validates challenges from this RS, and
    // opens the AROP task on the SAME ars this stack adjudicates against.
    const rsTxnKey = TOPOLOGY.keys.rsTxn;
    const rsTxnKeys = await generateKeyPair(rsTxnKey.alg, { extractable: true });
    const rsTxnPub = { ...(await exportJWK(rsTxnKeys.publicKey)), kid: rsTxnKey.kid, alg: rsTxnKey.alg };
    const as = await buildAuthorizationServer({
      issuer: asUrl,
      allowHeadlessAdjudication: true,
      resourceTxnJwks: { keys: [rsTxnPub as never] },
      ars,
    });
    const asServer = as.provider.listen(asPort);
    kernel = as.kernel;
    issuer = asUrl;
    // The RS verifies real tokens against the AS's published public JWKS (the
    // as-txn public key is published there too; createLocalJWKSet resolves by kid).
    serverJwks = (await (await fetch(`${asUrl}/jwks`)).json()) as { keys: Record<string, unknown>[] };
    challengeSigner = { sign: rsTxnKeys.privateKey, kid: rsTxnKey.kid, txnEndpoint: `${asUrl}/transaction`, asIssuer: asUrl };
    txnTokenJwks = serverJwks;
    rsAsIssuer = asUrl;

    // Cross-domain (M9): a dedicated ES256 grant key the RAS trusts under the AS
    // issuer (the AS's own token key is RS256 and not exposed; this mirrors the
    // separated-key-purpose design, D39). RAS mints a local token; SaaS enforces
    // from that token alone (token-only PEP, no PDP).
    const crossDomainKey = TOPOLOGY.keys.crossDomain;
    const rasTokenKey = TOPOLOGY.keys.rasToken;
    const saasResource = TOPOLOGY.resources.saas;
    const xdKeys = await generateKeyPair(crossDomainKey.alg, { extractable: true });
    const xdPub = { ...(await exportJWK(xdKeys.publicKey)), kid: crossDomainKey.kid, alg: crossDomainKey.alg };
    const rasKeys = await generateKeyPair(rasTokenKey.alg, { extractable: true });
    const rasPub = { ...(await exportJWK(rasKeys.publicKey)), kid: rasTokenKey.kid, alg: rasTokenKey.alg };
    const ras = new ResourceAuthorizationServer({
      issuer: RAS_ISS,
      trustedIssuers: { [asUrl]: { keys: [xdPub as never] } },
      signKey: rasKeys.privateKey,
      signKid: rasTokenKey.kid,
      localTokenTtlSeconds: TOPOLOGY.ttls.rasLocalTokenSeconds,
      localTokenAudience: saasResource,
    });
    const saas = new SaasMcpServer({
      rasIssuer: RAS_ISS,
      rasJwks: { keys: [rasPub as never] },
      resource: saasResource,
    });
    const resourceToAs = (r: string) => (r === saasResource ? RAS_ISS : asUrl);
    authServer = {
      asUrl,
      agentClientJwk: as.agentClientJwk,
      ras,
      saas,
      rasIssuer: RAS_ISS,
      saasResource,
      issueCrossDomainGrant: (missionId, cnfJkt) =>
        issueCrossDomainGrant(kernel, xdKeys.privateKey, crossDomainKey.kid, {
          missionId,
          targetAs: RAS_ISS,
          clientId: "ap-agent",
          cnfJkt,
          resourceToAs,
        }),
      closeAuthServer: () => asServer.close(),
    };
  } else {
    const asKeys = await generateKeyPair(TOPOLOGY.keys.asStatus.alg, { extractable: true });
    kernel = new MissionKernel({ issuer: ISS, policy: DERIVATION_POLICY as never, statusKey: asKeys.privateKey, statusKid: TOPOLOGY.keys.asStatus.kid });
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
    // requires an action-bound approval, resolved just-in-time. On the auth
    // server path the denial carries an RS-signed txn-challenge (AROP); the
    // client presents it to the AS transaction endpoint, which vouches the
    // approval and issues a txn-token. The approval is never an agent input.
    requiresActionApproval: (action) => action === "payments:remittance.send",
    maxApprovalAgeSeconds: TOPOLOGY.ttls.maxApprovalAgeSeconds,
    ...(challengeSigner ? { challengeSigner } : {}),
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
    // AROP (RS side): validate a presented txn-token against the AS txn public
    // JWKS (published on /jwks under the as-txn kid) and issuer.
    ...(txnTokenJwks ? { txnTokenJwks } : {}),
    ...(rsAsIssuer ? { asIssuer: rsAsIssuer } : {}),
  });

  // Transparency + producers.
  const transparencyKey = TOPOLOGY.keys.transparency;
  const pdpEvidenceKey = TOPOLOGY.keys.pdpEvidence;
  const tKeys = await generateKeyPair(transparencyKey.alg, { extractable: true });
  const transparency = new TransparencyService({ key: tKeys.privateKey, kid: transparencyKey.kid, issuer: TOPOLOGY.issuers.transparency });
  const pdpProducerKeys = await generateKeyPair(pdpEvidenceKey.alg, { extractable: true });
  const producerPub = { ...(await exportJWK(pdpProducerKeys.publicKey)), kid: pdpEvidenceKey.kid, alg: pdpEvidenceKey.alg };
  const tPub = { ...(await exportJWK(tKeys.publicKey)), kid: transparencyKey.kid, alg: transparencyKey.alg };
  const producerKey = { iss: TOPOLOGY.issuers.pdp, key: pdpProducerKeys.privateKey, kid: pdpEvidenceKey.kid };
  const retainedEvidence = new Map<string, unknown>();
  const receipts = new Map<string, Receipt>();

  const publishEvidence = async (missionId: string, evidenceType: string, ev: Record<string, unknown>) => {
    const stmt = await signStatement(producerKey, { missionId, evidenceType, evidence: ev as never });
    receipts.set(stmt.jws, await transparency.register(stmt));
    retainedEvidence.set(stmt.digest, ev);
  };

  const bff = new ConsoleBff({
    kernel,
    ars,
    transparency,
    retrieveEvidence: (_m, digest) => retainedEvidence.get(digest),
    producerJwks: { keys: [producerPub as never] },
    serviceJwks: { keys: [tPub as never] },
    receiptFor: (s: SignedStatement) => receipts.get(s.jws),
  });

  const catalog = new CatalogProvider(kernel, CATALOG_SERVICES, { arsIntakeUrl: TOPOLOGY.endpoints.arsIntake, issuer });

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
