/**
 * The composed demo stack: every service wired in one process against a shared
 * in-memory state and one live OpenFGA. This is the single object the exhibit
 * runner, the trace run, and the browser BFF all drive, so all three "see it"
 * surfaces exercise the identical enforcement path.
 */

import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { createRemoteJWKSet, exportJWK, generateKeyPair } from "jose";
import {
  type AuthorityEntry,
  buildAuthorizationServer,
  MISSION_APPROVAL_SCOPE,
  type ChallengeIssuers,
  CatalogProvider,
  type DeferralStore,
  type DischargeAuthorityPolicy,
  issueCrossDomainGrant,
  type IssuerEvidenceStore,
  MissionKernel,
  missionResourceAccessProfile,
  OperationProfileRegistry,
  type ProviderCapability,
  validateMissionIntent,
} from "@mission/authorization-server";
import { AUDIT_HORIZON_SECONDS, AUTHORITY_SOURCES, CATALOG_SERVICES, CONTAINMENT_POLICY, DERIVATION_POLICY, RAS_LOCAL_POLICY, MAS_JOIN, RUNTIME_SCOPE_CONFIG, type SeededTrustedSource, TOPOLOGY, USERS } from "@mission/demo-data";
import {
  type AuthorityEntry as PdpAuthorityEntry,
  createDecisionPoint,
  createDecisionChannel,
  type IdempotencyClaimDomain,
  loadRuntimePosture,
  openIdempotencyClaimDomain,
  RUNTIME_POSTURE,
  stalenessBound,
  stateSourcePlacement,
  deriveJoinDelegation,
  Fga,
  type MissionView,
  relationForAction,
} from "@mission/pdp";
import {
  ActorRecords,
  buildEvidenceKeyResolver,
  CANONICAL_RESOURCE,
  Connectors,
  createEphemeralEvidenceKeys,
  createHttpMcpChannel,
  createHttpMediatedClient,
  deploymentReceiptIssuerScope,
  deploymentRetentionWindowSeconds,
  type DpopKeys,
  EVIDENCE_KEY_SET_LOCATION,
  EvidenceRetentionStore,
  EvidenceStore,
  type HttpMcpChannel,
  indeterminateClaimAlert,
  type KeyRoles,
  type LoadedView,
  McpPaymentsServer,
  type MediatedToolResult,
  type MissionReference,
  OutcomeReconciler,
  PaymentsStore,
  Pep,
  type PepDeps,
  type ReceiptIssuerScope,
  redemptionStatusFor,
  type ResourceMetadataServer,
  startResourceMetadataServer,
  stderrAlertSink,
  type TokenFacts,
  TransactionEngine,
  openWriteReservationStore,
  type WriteReservationStore,
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

/**
 * D332: the AS capabilities the as-native target enables beyond the always-on
 * issuance profile: exactly the issuance-only floor's `lifecycle-revoke`
 * (#873) and `transaction-authorization`, where the remittance action-bound
 * approval redeems its challenge. Every other optional capability is off, and
 * so are the dev ordinary-token route (`dev-token`) and dev ordinary issuance.
 * `src/docs/initial-runtime-deployment.md` §2 and §9 state the set.
 */
export const AS_NATIVE_CAPABILITIES: ReadonlySet<ProviderCapability> = new Set<ProviderCapability>([
  "lifecycle-revoke",
  "transaction-authorization",
]);

/** The cross-domain / real-issuance extras, present only with withAuthServer. */
export interface AuthServerExtras {
  /** Base URL of the running AS provider (all OAuth endpoints derive from it). */
  asUrl: string;
  /** The agent confidential client's private JWK (private_key_jwt signer). */
  agentClientJwk: Record<string, unknown>;
  /**
   * The sub-agent client's private JWK: a dispatched instance's selected Agent,
   * which redeems the Dispatch Handoff as itself (@spec mission-template#dispatch-handoff).
   */
  childClientJwk: Record<string, unknown>;
  /** Trusted console/driver only. Never included in agent dependencies or tool results. */
  approverServiceToken: string;
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
  /**
   * Stop the AS HTTP listener and the txn-challenge discovery listener; resolves
   * once both ports are released (the exhibit calls this before exit).
   */
  closeAuthServer: () => Promise<void>;
  /**
   * The capability set the AS was built with, as the AS reports it
   * (`BuiltAs.capabilities`): {@link AS_NATIVE_CAPABILITIES} under the
   * `as-native` target. Absent: the full reference assembly, every capability
   * on.
   */
  capabilities?: ReadonlySet<ProviderCapability>;
  /**
   * Whether the AS armed its dev ordinary-token route, as the AS reports it
   * (`BuiltAs.devOrdinaryIssuance`). False on the `as-native` target (D332)
   * unless its test fixture is on.
   */
  devOrdinaryIssuance: boolean;
}

export interface DemoStack {
  kernel: MissionKernel;
  fga: Fga;
  modelId: string;
  payments: PaymentsStore;
  evidence: EvidenceStore;
  /**
   * @spec runtime-evidence#execution-evidence-object (Retention), #594 W4-8:
   * the durable retention store behind `evidence`, and the deployment's
   * published verification key sets. Exposed so an operator surface can read
   * what is retained and which keys are still resolvable.
   */
  evidenceRetention: EvidenceRetentionStore;
  /**
   * The deployment's receipt-issuer designation, or `undefined` where its
   * Enforcement Scope Statement claims no evidence capability, which is what
   * `config/enforcement-scope.json` does today: no designation, so no receipt
   * verification path.
   */
  receiptIssuerScope?: ReceiptIssuerScope;
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
  /**
   * @spec authority-server#mission-join rule 5 (#557) — this deployment's
   * actor records: the delegation edges rule 5 resolves a delegate's current
   * depth from. Deployment STATE, appended at runtime; exposed so an exhibit
   * can record an edge before a delegate joins. Empty, so every delegate join
   * denies until something records one.
   */
  actorRecords: ActorRecords;
  /**
   * @spec authority-server#mission-join (#557) — the MAS-governed HTTP MCP
   * channel: the one route that admits an ORDINARY OAuth credential (no
   * `mission` claim) and joins it against the propagated Mission Reference.
   * Started only when `MAS_JOIN.governed_resources` names this resource, so a
   * deployment governing nothing starts no such listener. The Mission-bound
   * channels are untouched. Close it with `masGovernedChannel.close()`.
   */
  masGovernedChannel?: HttpMcpChannel;
  /**
   * @spec runtime-oauth#token-validation (D315): the HTTP MCP endpoint at the
   * declared resource audience (`url` is exactly `CANONICAL_RESOURCE`),
   * verifying a DPoP proof on every request. Started only for the `as-native`
   * target; Mission-bound only, so it admits no ordinary credential. Close it
   * with `resourceChannel.close()`.
   */
  resourceChannel?: HttpMcpChannel;
  /** The decision channel's mode, as resolved from the option or `MISSION_PDP_MODE`. */
  pdpMode: "co-resident" | "remote";
  /** Trusted operator shutdown/fault-injection seam, never agent-accessible. */
  decisionChannel: { close: () => Promise<void> };
  /**
   * @spec runtime#idempotency (#917): the PDP's Exact claim domain, open
   * single-writer on its configured file for this stack's lifetime. Trusted
   * operator seam: `close()` releases the file (and makes the domain
   * unreachable, so the PDP issues no high-consequence permit after it).
   */
  pdpClaims: IdempotencyClaimDomain;
  /**
   * @spec runtime#idempotency (#918): the PEP's reservation and retention
   * store for keyed reversible writes, open single-writer on its configured
   * file for this stack's lifetime, beside (never inside) the PDP's claims.
   */
  writeReservations: WriteReservationStore;
  /**
   * @spec runtime#evidence (outcome reconciliation) (#1103): the declared
   * reconciler, built from the statement's `outcome_reconciliation`. Returned
   * stopped: the launchers (`pnpm as-native`, `pnpm demo:serve`) start it, and
   * a test runs it with `runOnce()`. Every close path stops it first.
   */
  reconciler: OutcomeReconciler;
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
  /** Default co-resident; MISSION_PDP_MODE=remote selects a real loopback hop. */
  pdpMode?: "co-resident" | "remote";
  /**
   * @spec runtime#idempotency (#917): the claim domain's file. Defaults to
   * `topology.json` `stores.pdpIdempotencyClaims.file`; a test passes its own
   * so concurrent stacks never contend for one single-writer file.
   */
  claimsFile?: string;
  /**
   * @spec runtime#idempotency (#918): the PEP's write-reservation file.
   * Defaults to `topology.json` `stores.pepWriteReservations.file`; a test
   * passes its own, as for `claimsFile`.
   */
  writeReservationsFile?: string;
  /**
   * D284, D315: `as-native` assembles #253's first runtime target. It implies
   * `withAuthServer`, builds the AS with exactly {@link AS_NATIVE_CAPABILITIES}
   * (D332), mounts no MAS join route on the payments resource, and serves the
   * HTTP MCP transport at the declared resource audience with DPoP verified on
   * every request. Absent: the shared demo composition, unchanged.
   */
  target?: "as-native";
  /**
   * TEST FIXTURE ONLY (D332); `pnpm as-native` never sets it. Under the
   * `as-native` target, also enable `dev-token` and dev ordinary issuance, so
   * a negative test can mint the ordinary credential a baseline Join would
   * present. A composition with this on is not the target's capability set,
   * and nothing it shows bears on the target's enabled capabilities. The
   * shared demo composition serves that route regardless.
   */
  testOrdinaryTokenMinting?: boolean;
  /**
   * @spec authority-server#mission-join (#557): the resources this deployment's
   * MAS join governs. Defaults to `config/mas-join.json` `governed_resources`,
   * less the payments resource under the `as-native` target.
   */
  masGovernedResources?: readonly string[];
  /**
   * @spec discharge#discharge-authority (#1144): the policy resolving a
   * `terminal_when` condition's `discharge_authority`, given to the AS and the
   * kernel. The shipped demo registers none, so its Missions carry no
   * completion condition; a composition that registers one gets the discharge
   * operation and, through `viewFor`, the PDP's point-of-use refusal.
   */
  dischargeAuthority?: DischargeAuthorityPolicy;
}): Promise<DemoStack> {
  const asNative = opts.target === "as-native";
  const masGovernedResources =
    opts.masGovernedResources ??
    (asNative ? MAS_JOIN.governed_resources.filter((r) => r !== CANONICAL_RESOURCE) : MAS_JOIN.governed_resources);
  // D315: the as-native target excludes the MAS route (#818 owns it), so a
  // configuration that would still mount it on the payments resource fails
  // startup here, before anything connects or listens.
  if (asNative && masGovernedResources.includes(CANONICAL_RESOURCE)) {
    throw new Error(`the as-native target mounts no MAS join route, but ${CANONICAL_RESOURCE} is configured governed (D315)`);
  }
  const mode = opts.pdpMode ?? process.env.MISSION_PDP_MODE ?? "co-resident";
  if (mode !== "co-resident" && mode !== "remote") throw new Error("MISSION_PDP_MODE must be co-resident or remote");
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
  // @spec runtime-oauth#token-validation (#825, D312): the kids this
  // resource trusts for each token class, from the shipped topology.
  let rsKeyRoles: KeyRoles;
  let authServer: AuthServerExtras | undefined;
  // Issuer-side evidence store; present only on the auth-server path (the real
  // provider retains ingestion + Containment Evidence there). Exposed so the
  // Activity Log join can read it (BuiltAs.issuerEvidence).
  let issuerEvidenceStore: IssuerEvidenceStore | undefined;
  // Resolved after the RS is constructed; the discovery listener reads it
  // lazily because the resource's own metadata names that listener's origin.
  let paymentsServerRef: McpPaymentsServer | undefined;

  if (opts.withAuthServer || asNative) {
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
    const approverServiceToken = crypto.randomUUID();
    // D332: the as-native target's AS runs exactly AS_NATIVE_CAPABILITIES,
    // plus `dev-token` only under the test fixture. The shared demo passes no
    // set, which is the full reference assembly.
    const ordinaryMinting = !asNative || opts.testOrdinaryTokenMinting === true;
    const capabilities: ReadonlySet<ProviderCapability> | undefined = asNative
      ? ordinaryMinting
        ? new Set<ProviderCapability>([...AS_NATIVE_CAPABILITIES, "dev-token"])
        : AS_NATIVE_CAPABILITIES
      : undefined;
    const as = await buildAuthorizationServer({
      issuer: asUrl,
      allowHeadlessAdjudication: true,
      serviceTokenPrincipals: {
        [approverServiceToken]: { principal_id: "svc:approver-console", scopes: [MISSION_APPROVAL_SCOPE],
          approver: { sub: "bob", acr: "mfa", auth_time: Math.floor(Date.now() / 1000) } },
      },
      ...(capabilities ? { capabilities } : {}),
      ...(opts.dischargeAuthority ? { dischargeAuthority: opts.dischargeAuthority } : {}),
      // @spec authority-server#mission-join (#557) — the demo's MAS-governed
      // route acts under an ORDINARY OAuth credential, and no other path in
      // this deployment mints one. The AS itself is unchanged by the Join;
      // this only gives the demo a plain token to present. The as-native
      // target mounts no such route and mints none (D332).
      devOrdinaryIssuance: ordinaryMinting,
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
    // A port already in use refuses startup here, with the discovery
    // listener released, rather than surfacing as an unhandled error event.
    try {
      await new Promise<void>((resolve, reject) => {
        asServer.once("listening", () => resolve());
        asServer.once("error", reject);
      });
    } catch (err) {
      await metadataServer.close();
      throw err;
    }
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
    // Access tokens verify only under the AS token key and transaction
    // tokens only under its txn key, though both come from one JWKS. The
    // AS issues no attenuation roots, so that class is refused here.
    rsKeyRoles = {
      accessToken: [TOPOLOGY.keys.asToken.kid],
      attenuationRoot: [],
      transactionToken: [TOPOLOGY.keys.asTxn.kid],
    };

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
      localCeiling: RAS_LOCAL_POLICY.ceiling,
      localPolicyVersion: RAS_LOCAL_POLICY.policy_version,
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
      childClientJwk: as.childClientJwk,
      approverServiceToken,
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
      closeAuthServer: async () => {
        // Idle keep-alive sockets would hold the close open; drop them so the
        // promise resolves once both ports are released.
        asServer.closeAllConnections();
        await Promise.all([
          new Promise<void>((resolve) => asServer.close(() => resolve())),
          metadataServer?.close(),
        ]);
      },
      ...(as.capabilities ? { capabilities: as.capabilities } : {}),
      devOrdinaryIssuance: as.devOrdinaryIssuance,
    };
  } else {
    const asKeys = await generateKeyPair(TOPOLOGY.keys.asStatus.alg, { extractable: true });
    // @spec mission#authority-sources — the same shipped catalog the wired AS
    // runs with: the kernel takes one REQUIRED catalog on every path, so the
    // no-AS-server composition cannot approve against an invented source.
    kernel = new MissionKernel({
      issuer: ISS,
      policy: DERIVATION_POLICY as never,
      containmentPolicy: CONTAINMENT_POLICY as never,
      authoritySourceCatalog: AUTHORITY_SOURCES as never,
      statusKey: asKeys.privateKey,
      statusKid: TOPOLOGY.keys.asStatus.kid,
      ...(opts.dischargeAuthority ? { dischargeAuthority: opts.dischargeAuthority } : {}),
    });
    issuer = ISS;
    serverJwks = { keys: [] };
    // No AS, so no AS-signed token is verified on this path.
    rsKeyRoles = { accessToken: [], attenuationRoot: [], transactionToken: [] };
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

  // @spec runtime-evidence#decision-evidence-integrity (issue #649, #741): a
  // fresh, per-process ES256 signer per emitter role: fine for this demo
  // stack (nothing outside this process ever needs to verify a record it
  // signs), NOT a substitute for a deployment's own published, durable JWKS.
  //
  // The PDP's Decision Evidence key is its OWN (#741): a distinct kid, static
  // in config with the key generated per boot (D25), never the `pdpEvidence`
  // kid the transparency producer Statements already spend. The runtime
  // profile forbids inferring one key plane's isolation from custody of
  // another, so the two planes do not share a kid. `emitterId`/`audience` are
  // this deployment's real values, so the verifier's key-to-emitter and
  // key-to-audience binding is checked against what the records actually
  // carry rather than a placeholder.
  const decisionEvidenceKey = TOPOLOGY.keys.pdpDecisionEvidence;
  const decisionEvidenceKeys = await generateKeyPair(decisionEvidenceKey.alg, { extractable: true });
  // The decision point owns the emission path (#741, PR #753 review): the
  // emitter is constructed inside `createDecisionPoint` and closed over by
  // `decide`. This wiring, and the PEP it wires, hold the decision function
  // and the published verification material, and nothing that can emit.
  const evidenceKeys = createEphemeralEvidenceKeys();
  // @spec runtime#idempotency (#917, D223): the PDP's Exact claim domain, a
  // durable single-writer SQLite file named in configuration and owned by the
  // statement's one PDP. It verifies settlement against exactly the
  // enforcement keys this PEP signs Execution Evidence with. A file another
  // process holds, or a statement it cannot run, refuses the stack at boot.
  const claimsFile = opts.claimsFile ?? TOPOLOGY.stores.pdpIdempotencyClaims.file;
  mkdirSync(dirname(claimsFile), { recursive: true });
  // @spec runtime#evidence (outcome reconciliation) (#1103): the declared
  // alerting obligation, one JSON line on stderr per alert. A claim that
  // closes indeterminate alerts where the claim domain moves it, after the
  // move commits, so a prior process's claim alerts too.
  const operatorAlerts = stderrAlertSink();
  const pdpClaims = openIdempotencyClaimDomain({
    file: claimsFile,
    owner: RUNTIME_POSTURE.pdps[0] as string,
    statement: RUNTIME_POSTURE,
    settlementKeys: buildEvidenceKeyResolver(evidenceKeys.verification.filter((k) => k.role !== "pdp")),
    onIndeterminate: (claim) => operatorAlerts.alert(indeterminateClaimAlert(claim)),
  });
  const decisionPoint = createDecisionPoint({
    evidence: {
      signer: { kid: decisionEvidenceKey.kid, key: decisionEvidenceKeys.privateKey },
      verificationKey: decisionEvidenceKeys.publicKey,
      emitterId: CANONICAL_RESOURCE,
      audience: CANONICAL_RESOURCE,
    },
    claims: pdpClaims,
  });
  // @spec runtime#idempotency (#918, D223): the PEP's own durable,
  // single-writer reservation store for keyed reversible writes, named in
  // configuration and owned by the statement's PEP location. The server
  // refuses it at construction unless the statement publishes it as the
  // domain of every keyed reversible write.
  const writeReservationsFile = opts.writeReservationsFile ?? TOPOLOGY.stores.pepWriteReservations.file;
  mkdirSync(dirname(writeReservationsFile), { recursive: true });
  const writeReservations = openWriteReservationStore({
    file: writeReservationsFile,
    owner: RUNTIME_POSTURE.mediated_scope.pep_locations[0] as string,
  });
  // @spec runtime-evidence#execution-evidence-object (Retention),
  // #evidence-integrity-signing-keys (#594 W4-8): this deployment's durable
  // retention store, and the key sets it publishes at its own key-set
  // location. The window is the retention floor the runtime profile puts
  // under every runtime-enforced deployment: the Mission audit horizon, since
  // this deployment's statement claims no evidence capability and so declares
  // no longer window of its own.
  const evidenceRetention = new EvidenceRetentionStore({
    retentionWindowSeconds: deploymentRetentionWindowSeconds(RUNTIME_SCOPE_CONFIG, AUDIT_HORIZON_SECONDS),
  });
  for (const key of [
    ...evidenceKeys.verification.filter((k) => k.role !== "pdp"),
    { ...decisionPoint.evidenceVerification, role: "pdp" as const },
  ]) {
    evidenceRetention.publishKey({
      location: EVIDENCE_KEY_SET_LOCATION,
      kid: key.kid,
      emitterId: key.emitterId,
      role: key.role,
      ...(key.audience !== undefined ? { audience: key.audience } : {}),
      // A published set carries JWKs; the PDP's own verification key is a
      // WebCrypto key, so it is exported here rather than at publication.
      publicKey: await exportJWK(key.publicKey as Parameters<typeof exportJWK>[0]),
    });
  }
  const evidence = new EvidenceStore(
    evidenceKeys.signing,
    buildEvidenceKeyResolver([
      ...evidenceKeys.verification.filter((k) => k.role !== "pdp"),
      // Exactly what the decision point publishes for the records it emits.
      { ...decisionPoint.evidenceVerification, role: "pdp" },
    ]),
    evidenceRetention,
  );
  // @spec runtime#runtime-conformance — the deployment's own receipt-issuer
  // designation, over the key sets above and the locations its own statement
  // declares. `undefined` here, and that is the point: config/enforcement-scope.json
  // claims no evidence capability, so this deployment designates no receipt
  // issuer and receipt verification is unreachable for it. Switching the claim
  // on is a deployment assertion, gated on the producer and consumer duties
  // #594's W4-3/W4-4/W4-16 still own.
  const receiptIssuerScope = deploymentReceiptIssuerScope(RUNTIME_SCOPE_CONFIG, evidenceRetention);
  // The egress gate's OWN store (D32); the agent run's EgressGate writes here.
  // Egress stays on the pre-existing unsigned path (issue #649's deferred slice B).
  const egressEvidence = new EvidenceStore();
  const connectors = new Connectors();
  const revokedInstances = new Set<string>();
  // @spec authority-server#mission-join rule 5 (#557) — the deployment's own
  // actor records. Nothing seeds it: a delegate joins only once this
  // deployment has recorded the edge, which is what makes an unrecorded
  // delegate fail closed rather than join on a declared ceiling alone.
  const actorRecords = new ActorRecords();

  // The PDP's view of a mission (in a real deployment fetched from AS/Status).
  // Exposed on ComposedStack for inspection (agent-run.ts's kill-switch poll);
  // callers that need a PDP decision use `loadView` below instead, which pairs
  // this with the freshness of the read.
  const viewFor = (missionId: string): MissionView | undefined => {
    const r = kernel.get(missionId);
    if (!r) return undefined;
    const fresh = kernel.applyExpiry(r);
    // @spec discharge#runtime, discharge#visibility (#1144, D335): the committed
    // discharge DELTA beside the committed set, so the PDP refuses a discharged
    // entry at the point of use (`authority_discharged`, step 5b) and reads a
    // credential's discharge condition through its source entries (step 5c).
    // The PDP cannot detect a missing delta, so this loader supplies it.
    const dischargedDigests = kernel.dischargedEntryDigests(fresh);
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
      ...(dischargedDigests.length > 0 ? { discharged: { entry_digests: dischargedDigests } } : {}),
    };
  };

  // @spec runtime#state-freshness, authzen#context-audience-freshness: this
  // deployment's trusted state source is the one config/enforcement-scope.json
  // publishes ("kernel-committed load_view"): `loadView`'s own synchronous
  // live read of the kernel via `viewFor`, placed with the PEP
  // (`state_source.placement: "pep"`). The PEP supplies that read as
  // `context.mission_state_observation`; the PDP accepts it because the
  // declared placement says the authenticated PEP supplies state from this
  // source, never because the request names a source.
  //
  // The loader pairs `viewFor`'s live read with the observation of THIS read.
  // `viewFor` is synchronous with no caching layer, so this call's own
  // wall-clock time is the honest `freshness_at` in `fresh` mode -- the
  // loader asserts it, and the PEP only ever propagates what it asserts,
  // never re-stamping its own clock (Finding 1).
  const loadView = (ref: MissionReference): LoadedView | undefined => {
    const view = viewFor(ref.id);
    if (!view || view.issuer !== ref.issuer) return undefined;
    return {
      view,
      observation: { state: view.state, version: view.version, mode: "fresh", freshness_at: new Date().toISOString() },
    };
  };

  /**
   * @spec authority-server#mission-join rule 8, bound 1 (#557) — the acting
   * credential's OWN authority, read from the token AS ISSUED: its verified
   * `scope` claim, mapped through the deployment's `scope_actions` to entries
   * on this resource. Client registration is deliberately not consulted; the
   * bound is what the presented credential carries, so a narrower token
   * yields a narrower permit even for the same client. A credential with no
   * scope, or a scope this deployment maps to nothing, resolves to no
   * authority, and the joined route then refuses `out_of_authority` rather
   * than treating an unmapped scope as unbounded.
   */
  const resolveOrdinaryAuthority = (token: TokenFacts): PdpAuthorityEntry[] | undefined => {
    if (token.mission || !token.scope) return undefined;
    const actions = [
      ...new Set(token.scope.split(/\s+/).flatMap((value) => MAS_JOIN.scope_actions[value] ?? [])),
    ];
    if (actions.length === 0) return undefined;
    return [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions }];
  };

  const runtimeDecisionPolicy = {
    requiresActionApproval: (action: string) => action === "payments:remittance.send",
    maxApprovalAgeSeconds: TOPOLOGY.ttls.maxApprovalAgeSeconds,
    stateSourcePlacement: stateSourcePlacement(RUNTIME_POSTURE),
    delegatePolicy: {
      delegates: Object.fromEntries(Object.entries(MAS_JOIN.delegates).map(([id, d]) => [id, { maxDepth: d.max_depth }])),
    },
  };
  // D28: the PEP owns redemption. Its store's epoch is the requester epoch
  // the channel binds, and its read-only answer is retransmission condition 6.
  const engine = new TransactionEngine("demo-epoch");
  const redemption = redemptionStatusFor(engine);
  const pepId = "mcp-payments-pep";
  const decisionChannel = await createDecisionChannel(decisionPoint, {
    mode, pepId, audience: CANONICAL_RESOURCE,
    pepEpoch: redemption.epoch,
    consumptionStatus: redemption.status,
    redeemingExecution: redemption.redeemer,
    getOptions: (request) => {
      const ref = request.context.mission;
      const loaded = ref ? loadView(ref) : undefined;
      if (!loaded) throw new Error("PDP cannot establish the Mission view");
      // @spec authzen#pdp-request rule 1: the PDP side's own read, the one a
      // `pdp` placement relies on; under the published `pep` placement the
      // PEP's observation is relied on instead.
      return {
        view: loaded.view,
        stateObservedAt: loaded.observation.freshness_at,
        fga,
        modelId,
        now: () => new Date(),
        stalenessBound,
        relationForAction,
        ...runtimeDecisionPolicy,
      };
    },
  });
  const enforcementScopeStatement = loadRuntimePosture({ ...RUNTIME_POSTURE, remote_decision_channels: decisionChannel.remoteDecisionChannels });
  let observer: PepDeps["observe"];
  const pep = new Pep({
    payments,
    evidence,
    decide: decisionChannel.decide,
    claims: decisionChannel.claims,
    fga,
    modelId,
    loadView,
    instanceEpoch: "demo-epoch",
    revokedInstances,
    observe: (e) => observer?.(e),
    // JIT gate: sending a remittance email is in the mission's authority but
    // requires an action-bound approval, resolved just-in-time. On the auth
    // server path the denial carries an RS-signed txn-challenge (AROP); the
    // client presents it to the AS transaction endpoint, which vouches the
    // approval and issues a txn-token. The approval is never an agent input.
    ...runtimeDecisionPolicy,
    // @spec authority-server#mission-join (#557) — this deployment's Join
    // configuration, from config/mas-join.json. It is one of the two keys the
    // joined path needs; the other is a route that validates an ordinary
    // credential (the MAS-governed channel below). Configured here even when
    // no such route runs, so a credential with no `mission` claim arriving on
    // a Mission-bound route is still refused by that route's validator rather
    // than by a missing config.
    masJoin: {
      delegatePolicy: {
        delegates: Object.fromEntries(
          Object.entries(MAS_JOIN.delegates).map(([clientId, d]) => [clientId, { maxDepth: d.max_depth }]),
        ),
      },
      resolveOrdinaryAuthority,
      // Rule 5's depth source. The hook takes the canonical (issuer, id) pair
      // and the Mission's own client, so the ledger satisfies it directly.
      resolveDelegateDepth: actorRecords.resolveDepth.bind(actorRecords),
    },
    ...(challengeSigner ? { challengeSigner } : {}),
  });

  const server = new McpPaymentsServer({
    enforcementScopeStatement,
    pep,
    payments,
    loadView,
    jwks: serverJwks,
    keyRoles: rsKeyRoles,
    issuer,
    transaction: { engine, connectors, evidence },
    writeReservations,
    // AROP (RS side): validate a presented txn-token against the AS txn public
    // JWKS (published on /jwks under the as-txn kid) and issuer.
    ...(txnTokenJwks ? { txnTokenJwks } : {}),
    ...(rsAsIssuer ? { asIssuer: rsAsIssuer } : {}),
    ...(txnChallengePublication ? { txnChallenge: txnChallengePublication } : {}),
  });
  paymentsServerRef = server;
  // @spec runtime#evidence (outcome reconciliation) (#1103): this PEP is the
  // statement's responsible component, so it runs the reconciliation over its
  // own claim channel, redemption store, connectors, evidence and
  // reservations. Constructed here and not started: see `DemoStack.reconciler`.
  const reconciler = new OutcomeReconciler({
    statement: RUNTIME_POSTURE,
    component: pepId,
    claims: decisionChannel.claims,
    evidence,
    redemption,
    connectors,
    writeReservations,
    alerts: operatorAlerts,
  });

  // @spec authority-server#mission-join (#557) — the MAS-governed route, on
  // its own listener, started only for a resource this deployment declares
  // governed. It is a SECOND channel: the Mission-bound channels keep
  // `validateCredential` and keep rejecting a credential with no `mission`
  // claim, so turning the Join on never loosens an existing route.
  const masGovernedChannel = masGovernedResources.includes(CANONICAL_RESOURCE)
    ? await createHttpMcpChannel(server, { masGoverned: true })
    : undefined;
  // D315: the as-native target's one resource entry point, at the declared
  // audience itself, so the `htu` a client signs and the `aud` the AS issues
  // name the same URL. It is the Mission-bound channel (`validateCredential`
  // with the request's DPoP proof); the in-process mediated channel is outside
  // this target's claims.
  let resourceChannel: HttpMcpChannel | undefined;
  if (asNative) {
    const audience = new URL(CANONICAL_RESOURCE);
    // A failed startup releases what it already opened: the AS and discovery
    // listeners, the decision channel and both single-writer store files.
    const release = async (): Promise<void> => {
      await reconciler.stop();
      await authServer?.closeAuthServer();
      await decisionChannel.close();
      pdpClaims.close();
      writeReservations.close();
    };
    try {
      resourceChannel = await createHttpMcpChannel(server, { host: audience.hostname, port: Number(audience.port) });
    } catch (err) {
      await release();
      throw err;
    }
    if (resourceChannel.url !== CANONICAL_RESOURCE) {
      await resourceChannel.close();
      await release();
      throw new Error(`the as-native endpoint ${resourceChannel.url} is not the declared audience ${CANONICAL_RESOURCE}`);
    }
  }

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
    decisionChannel,
    pdpClaims,
    writeReservations,
    reconciler,
    fga,
    modelId,
    payments,
    evidence,
    evidenceRetention,
    ...(receiptIssuerScope ? { receiptIssuerScope } : {}),
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
    actorRecords,
    ...(masGovernedChannel ? { masGovernedChannel } : {}),
    ...(resourceChannel ? { resourceChannel } : {}),
    pdpMode: mode,
    viewFor,
    publishEvidence,
    onEnforce: (fn) => {
      observer = fn;
    },
    ...(authServer ? { authServer } : {}),
  };
}

/** The options {@link composeStack} takes. */
export type ComposeStackOptions = Parameters<typeof composeStack>[0];

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
