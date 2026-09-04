/**
 * The composed demo stack: every service wired in one process against a shared
 * in-memory state and one live OpenFGA. This is the single object the exhibit
 * runner, the trace run, and the browser BFF all drive, so all three "see it"
 * surfaces exercise the identical enforcement path.
 */

import { createRemoteJWKSet, exportJWK, generateKeyPair } from "jose";
import {
  type AuthorityEntry,
  buildAuthorizationServer,
  type ChallengeIssuers,
  CatalogProvider,
  type DeferralStore,
  issueCrossDomainGrant,
  type IssuerEvidenceStore,
  MissionKernel,
  missionResourceAccessProfile,
  OperationProfileRegistry,
  validateMissionIntent,
} from "@mission/authorization-server";
import { CATALOG_SERVICES, CONTAINMENT_POLICY, DERIVATION_POLICY, type SeededTrustedSource, TOPOLOGY, USERS } from "@mission/demo-data";
import { deriveJoinDelegation, Fga, type MissionView, relationForAction } from "@mission/pdp";
import {
  CANONICAL_RESOURCE,
  Connectors,
  createEphemeralEvidenceKeys,
  createHttpMcpChannel,
  createHttpMediatedClient,
  type DpopKeys,
  EvidenceStore,
  type LoadedView,
  McpPaymentsServer,
  type MediatedToolResult,
  type MissionReference,
  PaymentsStore,
  Pep,
  type PepDeps,
  type ResourceMetadataServer,
  sourceDigestOf,
  startResourceMetadataServer,
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
  /** AROP Deferred Token Response store (drive open/approve/deny headlessly). */
  deferrals: DeferralStore;
  ras: ResourceAuthorizationServer;
  saas: SaasMcpServer;
  rasIssuer: string;
  saasResource: string;
  /**
   * @spec containment#protected-events — the config-seeded trusted protected-event
   * sources with their PER-BOOT keypairs (D25), threaded straight from BuiltAs.
   * seedTrustedSources() mints a fresh keypair per boot, so the private half is
   * unreachable except by reference; the exhibit signs a SOC report (svc:soc)
   * with it to drive real containment (AAM Trust Ratchet).
   */
  protectedEventSources: SeededTrustedSource[];
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
  /** The egress gate's OWN evidence store (D32); the agent run's gate writes here
   * so its records join the Activity Log without relocating the store. */
  egressEvidence: EvidenceStore;
  /** Issuer-side evidence (ingestion + Containment Evidence); set only on the
   * auth-server path (the in-process kernel path retains none). */
  issuerEvidence?: IssuerEvidenceStore;
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
  let challengeSigner: PepDeps["challengeSigner"];
  let txnTokenJwks: { keys: Record<string, unknown>[] } | undefined;
  let rsAsIssuer: string | undefined;
  // @spec txn-authorization#two-phase-expiry — the resource's PUBLISHED
  // txn-challenge key material: served over real HTTP at the resource's
  // `txn_challenge_jwks_uri`, which is where (and only where) the TAS resolves
  // this issuer's keys from.
  let txnChallengePublication: NonNullable<
    ConstructorParameters<typeof McpPaymentsServer>[0]["txnChallenge"]
  > | undefined;
  let metadataServer: ResourceMetadataServer | undefined;

  // Kernel + token-issuer + the RS's token-verification JWKS differ by mode:
  // with the auth server, the real provider owns the kernel and signs tokens;
  // without it, an in-process kernel backs the TokenFacts-driven surfaces.
  let kernel: MissionKernel;
  let issuer: string;
  let serverJwks: { keys: Record<string, unknown>[] };
  let authServer: AuthServerExtras | undefined;
  // Issuer-side evidence store; present only on the auth-server path (the real
  // provider retains ingestion + Containment Evidence there). Exposed so the
  // Activity Log join can read it (BuiltAs.issuerEvidence).
  let issuerEvidenceStore: IssuerEvidenceStore | undefined;
  // Resolved after the RS is constructed; the discovery listener reads it
  // lazily because the resource's own metadata names that listener's origin.
  let paymentsServerRef: McpPaymentsServer | undefined;

  if (opts.withAuthServer) {
    const asPort = opts.asPort ?? TOPOLOGY.ports.as;
    const asUrl = `http://localhost:${asPort}`;
    // The RS's txn-challenge signing key (rs-txn); the AS is configured with its
    // public half so POST /transaction validates challenges from this RS, and
    // opens the AROP task on the SAME ars this stack adjudicates against.
    const rsTxnKey = TOPOLOGY.keys.rsTxn;
    const rsTxnKeys = await generateKeyPair(rsTxnKey.alg, { extractable: true });
    const rsTxnPub = { ...(await exportJWK(rsTxnKeys.publicKey)), kid: rsTxnKey.kid, alg: rsTxnKey.alg };
    // @spec txn-authorization#two-phase-expiry — the resource publishes its
    // challenge-signing keys at `txn_challenge_jwks_uri` and the TAS resolves
    // them THERE over a real fetch. The listener comes up first so its origin
    // can be baked into the URI the resource publishes and the AS resolves.
    const txnTopo = TOPOLOGY.txnChallenge.payments;
    metadataServer = await startResourceMetadataServer(() => paymentsServerRef);
    txnChallengePublication = {
      jwksUri: `${metadataServer.origin}${txnTopo.jwksPath}`,
      jwksPath: txnTopo.jwksPath,
      signingAlgValuesSupported: txnTopo.signingAlgValuesSupported,
      jwks: { keys: [rsTxnPub as never] },
    };
    const challengeIssuers: ChallengeIssuers = new Map([
      [
        CANONICAL_RESOURCE,
        {
          jwks: createRemoteJWKSet(new URL(txnChallengePublication.jwksUri)),
          algs: txnTopo.signingAlgValuesSupported,
        },
      ],
    ]);
    const as = await buildAuthorizationServer({
      issuer: asUrl,
      allowHeadlessAdjudication: true,
      transactionAuthorization: {
        challengeIssuers,
        ars,
        // @spec txn-authorization#two-phase-expiry — the pending workflow's own
        // lifetime and the deployment maximum for an issued transaction token
        // are INDEPENDENT of the challenge's admission window.
        workflowLifetimeSeconds: txnTopo.workflowLifetimeSeconds,
        maxTokenLifetimeSeconds: txnTopo.maxTokenLifetimeSeconds,
        maxApprovalAgeSeconds: TOPOLOGY.ttls.maxApprovalAgeSeconds,
        // @spec txn-authorization#resource-challenge — the Operation Profiles
        // this deployment recognizes. The payments resource challenges with the
        // family's own `mission_resource_access` entry, so that profile governs
        // its operations; an entry naming any other type is refused at
        // admission rather than read structurally.
        operationProfiles: new OperationProfileRegistry().register(
          CANONICAL_RESOURCE,
          missionResourceAccessProfile(),
        ),
        // @spec txn-authorization#challenge-redemption step 7 — the deployment's
        // entitlement and resource-policy decision, run FRESH at completion
        // against LIVE state. A completed approval is context here, never a
        // bypass: each of these denies on its own, after an approval, whenever
        // the input no longer holds -- the Mission is no longer active, the
        // containment overlay has narrowed the entry away, the deployment does
        // not recognize the action, the entry has no vendor scope left, or the
        // local subject is no longer an entitled account.
        freshDecision: async (input) => {
          const view = viewFor(input.missionId);
          if (!view || view.state !== "active") return { decision: "deny", reason: "mission_inactive" };
          const entry = view.authority_set.find(
            (e) => e.resource === input.resource && e.actions.includes(input.action),
          );
          if (!entry) return { decision: "deny", reason: "out_of_authority" };
          const contained = view.containment?.contained.some(
            (c) => c.resource === input.resource && (c.actions === undefined || c.actions.includes(input.action)),
          );
          if (contained) return { decision: "deny", reason: "authority_contained" };
          if (!relationForAction(input.action)) return { decision: "deny", reason: "unknown_action" };
          if (!entry.constraints?.vendors?.length) return { decision: "deny", reason: "no_vendor_scope" };
          // Principal entitlement, from the deployment's own identity config:
          // the DESTINATION-LOCAL subject must still be an account this estate
          // carries. Where the Origin Principal profile applies the decision
          // also receives `originPrincipal`, issuer-qualified and separate; a
          // local account list is never matched against a foreign namespace.
          if (!USERS.some((u) => u.sub === input.subject)) {
            return { decision: "deny", reason: "entitlement_denied" };
          }
          return { decision: "permit" };
        },
      },
    });
    const asServer = as.provider.listen(asPort);
    kernel = as.kernel;
    issuer = asUrl;
    issuerEvidenceStore = as.issuerEvidence;
    // The RS verifies real tokens against the AS's published public JWKS (the
    // as-txn public key is published there too; createLocalJWKSet resolves by kid).
    serverJwks = (await (await fetch(`${asUrl}/jwks`)).json()) as { keys: Record<string, unknown>[] };
    challengeSigner = {
      sign: rsTxnKeys.privateKey,
      kid: rsTxnKey.kid,
      alg: rsTxnKey.alg,
      asIssuer: asUrl,
      lifetimeSeconds: txnTopo.challengeLifetimeSeconds,
    };
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
    // @spec id-continuation-assertion — the continuation ID-JAG is signed by the
    // dedicated as-continuation key the AS generates per boot and publishes on
    // its jwks_uri (fetched above). The RAS trusts it under the AS issuer too, so
    // a continuation ID-JAG redeems into a local token (D39 per-purpose keys).
    const asContinuationKey = TOPOLOGY.keys.asContinuation;
    const asContinuationPub = serverJwks.keys.find((k) => k.kid === asContinuationKey.kid);
    if (!asContinuationPub) {
      throw new Error(`AS jwks_uri is missing the ${asContinuationKey.kid} continuation key`);
    }
    const ras = new ResourceAuthorizationServer({
      issuer: RAS_ISS,
      trustedIssuers: { [asUrl]: { keys: [xdPub as never, asContinuationPub as never] } },
      signKey: rasKeys.privateKey,
      signKid: rasTokenKey.kid,
      localTokenTtlSeconds: TOPOLOGY.ttls.rasLocalTokenSeconds,
      localTokenAudience: saasResource,
      // @spec cross-domain#validation-at-resource-as (S-12): no client is
      // known at boot (the demo agent's DPoP key is generated per session,
      // exhibit.ts); it is onboarded via ras.registerClient() once that key
      // exists, before any cross-domain redemption is attempted.
      registeredClients: {},
      // @spec cross-domain#origin-principal-mapping, #dual-axis (#539): the
      // demo's ID-JAG grants are all base grants over the mission subject
      // { iss: ISS, sub: "alice" } (this AS is its own issuer, so the
      // grant's own (iss, sub) and mission.subject co-resolve via this one
      // entry). Entitlement is this deployment's own local source (the demo
      // runs no separate entitlement service).
      mapping: {
        id: "demo-ras-mapping",
        version: "v1",
        entries: [
          {
            origin: { iss: ISS, sub: "alice" },
            local_sub: "alice-ledgercloud",
            observed_at: "2020-01-01T00:00:00Z",
            valid_until: "2099-01-01T00:00:00Z",
          },
        ],
      },
      // @spec cross-domain#dual-axis (#744): the action- and resource-scoped
      // grain of the same observation. Alice is a currently entitled
      // LedgerCloud account, entitled to read vendors but NOT to write the
      // journal, mirroring the draft's own worked example (invoices.read
      // entitled, journal-entries.write not). The delegated grant carries
      // both actions, so redemption narrows to the entitled subset rather
      // than refusing: the minted local token carries ledger:vendor.read
      // alone, and the SaaS PEP refuses a journal write presented with it.
      entitlement: {
        resolve: async () => ({
          entitled: true,
          observed_at: new Date().toISOString(),
          authority: [{ resource: saasResource, actions: ["ledger:vendor.read"] }],
        }),
      },
      entitlementStalenessBoundSeconds: 86_400,
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
      deferrals: as.deferrals,
      ras,
      saas,
      rasIssuer: RAS_ISS,
      saasResource,
      protectedEventSources: as.protectedEventSources,
      issueCrossDomainGrant: (missionId, cnfJkt) =>
        issueCrossDomainGrant(kernel, xdKeys.privateKey, crossDomainKey.kid, {
          missionId,
          targetAs: RAS_ISS,
          clientId: "ap-agent",
          cnfJkt,
          resourceToAs,
        }),
      closeAuthServer: () => {
        asServer.close();
        void metadataServer?.close();
      },
    };
  } else {
    const asKeys = await generateKeyPair(TOPOLOGY.keys.asStatus.alg, { extractable: true });
    kernel = new MissionKernel({ issuer: ISS, policy: DERIVATION_POLICY as never, containmentPolicy: CONTAINMENT_POLICY as never, statusKey: asKeys.privateKey, statusKid: TOPOLOGY.keys.asStatus.kid });
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

  // @spec runtime-evidence#decision-evidence-integrity (issue #649): a fresh,
  // per-process ES256 signer: fine for this demo stack (nothing outside this
  // process ever needs to verify a record it signs), NOT a substitute for a
  // deployment's own published, durable JWKS.
  const evidence = new EvidenceStore(createEphemeralEvidenceKeys().signing);
  // The egress gate's OWN store (D32); the agent run's EgressGate writes here.
  // Egress stays on the pre-existing unsigned path (issue #649's deferred slice B).
  const egressEvidence = new EvidenceStore();
  const connectors = new Connectors();
  const revokedInstances = new Set<string>();

  // The PDP's view of a mission (in a real deployment fetched from AS/Status).
  // Exposed on ComposedStack for inspection (agent-run.ts's kill-switch poll);
  // callers that need a PDP decision use `loadView` below instead, which pairs
  // this with the freshness of the read.
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
      // @spec authority-server#mission-join rule 5 (#557 review point 2):
      // this is the canonical Mission loader, so it is where a kernel
      // AuthorityEntry's own `delegation` policy gets mapped to the PDP's
      // `join_delegation` member via the shared deterministic adapter,
      // rather than that member existing only in hand-built test fixtures.
      authority_set: fresh.authority_set.map((e) => ({
        ...e,
        ...(e.delegation !== undefined ? { join_delegation: deriveJoinDelegation(e.delegation) } : {}),
      })),
      subject: fresh.subject,
      client_id: fresh.client_id,
      // The containment DELTA (not a filtered set), so the PDP distinguishes
      // never-approved (out_of_authority) from approved-then-contained
      // (authority_contained).
      ...(fresh.containment
        ? {
            containment: {
              version: fresh.containment.containment_version,
              contained: fresh.containment.contained,
            },
          }
        : {}),
    };
  };

  // @spec runtime#state-freshness: this deployment's trusted state sources
  // (its Enforcement Scope Statement would publish this list formally; none
  // exists yet, so it is declared here instead). The demo stack has exactly
  // one: `loadView`'s own synchronous live read of the kernel via `viewFor`,
  // named after the `loadView` dependency it fulfills. A deployment adding
  // Mission Status or Lifecycle Signals would list those sources here too.
  const ALLOWED_FRESHNESS_SOURCES = new Set(["load_view"]);

  // The PDP's dependency-injected loader (@spec runtime#state-freshness):
  // pairs `viewFor`'s live read with the freshness of THIS read. `viewFor` is
  // synchronous with no caching layer, so this call's own wall-clock time is
  // the honest `observed_at` -- the loader asserts it, and the PEP only ever
  // propagates what it asserts, never re-stamping its own clock (Finding 1).
  const loadView = (ref: MissionReference): LoadedView | undefined => {
    const view = viewFor(ref.id);
    if (!view || view.issuer !== ref.issuer) return undefined;
    return { view, freshness: { observed_at: new Date().toISOString(), source: "load_view" } };
  };

  let observer: PepDeps["observe"];
  const pep = new Pep({
    payments,
    evidence,
    fga,
    modelId,
    loadView,
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
    allowedFreshnessSources: ALLOWED_FRESHNESS_SOURCES,
    ...(challengeSigner ? { challengeSigner } : {}),
  });

  const { TransactionEngine } = await import("@mission/mcp-payments");
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
    jwks: serverJwks,
    issuer,
    serverCard: { name: "payments" },
    transaction: { engine: new TransactionEngine("demo-epoch"), connectors, evidence },
    // AROP (RS side): validate a presented txn-token against the AS txn public
    // JWKS (published on /jwks under the as-txn kid) and issuer.
    ...(txnTokenJwks ? { txnTokenJwks } : {}),
    ...(rsAsIssuer ? { asIssuer: rsAsIssuer } : {}),
    ...(txnChallengePublication ? { txnChallenge: txnChallengePublication } : {}),
  });
  paymentsServerRef = server;

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
    // @spec activity-log — the joined read-view reads the producer-retained
    // stores in place (D32): the PEP/transaction store, the egress gate store,
    // and (auth-server path only) the issuer store. No store is relocated.
    activity: {
      evidence: [evidence, egressEvidence],
      ...(issuerEvidenceStore ? { issuerEvidence: issuerEvidenceStore } : {}),
    },
  });

  const catalog = new CatalogProvider(kernel, CATALOG_SERVICES, { arsIntakeUrl: TOPOLOGY.endpoints.arsIntake, issuer });

  return {
    kernel,
    fga,
    modelId,
    payments,
    evidence,
    egressEvidence,
    ...(issuerEvidenceStore ? { issuerEvidence: issuerEvidenceStore } : {}),
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
      target_resources: [DERIVATION_POLICY.ceiling[0].resource],
      expires_at: "2027-01-01T00:00:00Z",
    }),
  );
  return stack.kernel.approve({
    intent,
    // The authority proposal: what the wire submits as the standard RFC 9396
    // authorization_details parameter beside mission_intent.
    proposedAuthority: [
      {
        type: "mission_resource_access",
        resource: DERIVATION_POLICY.ceiling[0].resource,
        actions: ["payments:invoice.read", "payments:payment.schedule", "payments:payment.execute", "payments:remittance.send"],
        constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
      },
    ],
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-demo-${stack.kernel.allMissions().length + 1}`,
  });
}

/**
 * @spec txn-authorization#offline-verification step 2 — present a transaction
 * credential the only way it can be presented: over a REAL HTTP MCP request,
 * DPoP-bound to the key the challenge committed to and naming THIS credential
 * (`ath`). The in-process channel has no request to bind a proof to, so it
 * cannot carry this class at all; the challenged retry goes over HTTP.
 */
export async function callWithTransactionCredential(
  server: McpPaymentsServer,
  credential: string,
  dpopKeys: DpopKeys,
  tool: string,
  args: Record<string, unknown>,
): Promise<MediatedToolResult> {
  const channel = await createHttpMcpChannel(server);
  try {
    const { client, close } = await createHttpMediatedClient(channel.url, credential, dpopKeys);
    try {
      return await client.callTool(tool, args);
    } finally {
      await close();
    }
  } finally {
    await channel.close();
  }
}
