/**
 * @spec authority-server#mission-join, authority-server#mapping-contract,
 * authority-server#limitations, authority-server#deployment-adoption (#818, D284, D508)
 *
 * The MAS pilot composition: #253's second reference path, a legacy estate
 * joined to Missions through a gateway, assembled from the reference
 * components with nothing stubbed across the estate seam.
 *
 * - The estate authorization server (`estate-as.ts`): a second, independently
 *   configured issuer with its own keys, accounts and client registrations.
 * - The MAS: the reference Mission kernel under its own issuer, which issues
 *   no tokens in this mode. The PEP reads its committed records in process,
 *   as the AS-native target does (D293); Mission Status over HTTP is not part
 *   of this slice.
 * - The gateway: a MAS-governed HTTP MCP route whose resource server trusts
 *   ONLY the estate issuer's published keys and admits only ordinary RFC 9068
 *   tokens (`ordinaryOnly`). It joins each credential to the Mission its
 *   `Mission-Reference` names, under the versioned mapping contract.
 * - The resource route: the payments resource's own Mission-bound route,
 *   which trusts only the Mission Issuer's keys. In MAS mode nothing issues
 *   such a token, so it admits no estate credential.
 * - The PEP and PDP: the reference `Pep` and decision point, sharing one
 *   payments store. Every crossing on either route goes through the PEP.
 * - The Resource policy (#828, #818 slice 2): stored OpenFGA entitlements the
 *   decision point reads with no Mission input, for principals under the
 *   ESTATE issuer: the subject and client the resource authenticated, never
 *   the identities the mapping contract maps them to. The store is attached
 *   (configured store and model, nothing written) or bootstrapped for
 *   development (a fresh store seeded from `config/mas-pilot.json`
 *   `resource_policy` and the payments store's invoice ownership). The PEP's
 *   Mission-authority check reads the same store.
 */

import { exportJWK, generateKeyPair } from "jose";
import { MissionKernel } from "@mission/authorization-server";
import { AUTHORITY_SOURCES, CONTAINMENT_POLICY, DERIVATION_POLICY, TOPOLOGY } from "@mission/demo-data";
import {
  ActorRecords,
  Connectors,
  createEphemeralEvidenceKeys,
  createHttpMcpChannel,
  EvidenceStore,
  type HttpMcpChannel,
  type LoadedView,
  McpPaymentsServer,
  type MissionReference,
  openEphemeralWriteReservationStore,
  PaymentsStore,
  Pep,
  TransactionEngine,
  type WriteReservationStore,
} from "@mission/mcp-payments";
import {
  type EvaluationRequest,
  type Fga,
  fgaResourcePolicy,
  issuerLocalClients,
  issuerLocalPrincipals,
  RUNTIME_POSTURE,
} from "@mission/pdp";
import { kernelMissionView } from "../kernel-mission-view.js";
import { openResourcePolicyStore, type ResourcePolicyStore, seedDevelopmentResourcePolicy } from "../resource-policy-store.js";
import { loadMasPilotConfig, type MasPilotConfig } from "./config.js";
import {
  type EstateAuthorizationServer,
  type EstateClientRegistration,
  startEstateAuthorizationServer,
} from "./estate-as.js";
import { MappingContractCache } from "./mapping-contract.js";

export interface MasPilotOptions {
  /** The OpenFGA the Resource policy and the Mission-authority check read. */
  openfga: { apiUrl: string; presharedKey: string; caCertPath?: string };
  /**
   * @spec runtime#input-resource-policy (#828): attach to a configured
   * Resource-policy store, or bootstrap a development one. No default
   * (`resource-policy-store.ts`).
   */
  resourcePolicyStore: ResourcePolicyStore;
  /** Observes each decision request the PEP submits, before the PDP decides it (tests). */
  observeDecisionRequest?: (request: EvaluationRequest) => void;
  config?: MasPilotConfig;
  now?: () => Date;
  /**
   * The mapping cache's own clock, which stamps each install and so starts
   * its staleness bound. Defaults to `now`. A test sets it behind `now` to
   * install a snapshot that is already stale.
   */
  mappingNow?: () => Date;
}

export interface MasPilot {
  config: MasPilotConfig;
  estate: EstateAuthorizationServer;
  /** The estate's client registrations, with the secrets generated at this boot. */
  estateClients: ReadonlyMap<string, EstateClientRegistration>;
  kernel: MissionKernel;
  missionIssuer: string;
  mapping: MappingContractCache;
  actorRecords: ActorRecords;
  payments: PaymentsStore;
  /** The payments connectors: the wires and emails the resource actually committed. */
  connectors: Connectors;
  /** The PEP's evidence store: every Decision Evidence and Refusal Record it retained. */
  evidence: EvidenceStore;
  /** The Resource-policy store: its ids, so a restart can attach, and whether it was bootstrapped. */
  resourcePolicy: { fga: Fga; storeId: string; modelId: string; development: boolean };
  pep: Pep;
  /** The MAS-governed route that admits estate credentials. */
  gateway: HttpMcpChannel;
  /** The resource's own Mission-bound route. */
  resourceRoute: HttpMcpChannel;
  close: () => Promise<void>;
}

/**
 * The pilot's Mission view loader: the kernel's committed record through the
 * shared projection (`kernel-mission-view.ts`), containment and discharge
 * deltas included, keyed by the canonical pair.
 */
function missionLoader(kernel: MissionKernel): (ref: MissionReference) => LoadedView | undefined {
  return (ref) => {
    const view = kernelMissionView(kernel, ref.id);
    if (!view || view.issuer !== ref.issuer) return undefined;
    return {
      view,
      observation: { state: view.state, version: view.version, mode: "fresh", freshness_at: new Date().toISOString() },
    };
  };
}

/** Assemble and start the pilot. `close()` releases every listener and store it opened. */
export async function composeMasPilot(opts: MasPilotOptions): Promise<MasPilot> {
  const config = opts.config ?? loadMasPilotConfig();
  const missionIssuer = config.mission_issuer;
  const estateClients = new Map<string, EstateClientRegistration>(
    config.estate.clients.map((c) => [c.client_id, { ...c, client_secret: crypto.randomUUID() }]),
  );
  const opened: (() => Promise<void> | void)[] = [];
  const close = async (): Promise<void> => {
    for (const release of opened.splice(0).reverse()) await release();
  };

  try {
    const estate = await startEstateAuthorizationServer({
      issuer: config.estate.issuer,
      host: config.estate.host,
      port: config.estate.port,
      accounts: config.estate.accounts,
      clients: [...estateClients.values()],
      resourceServers: config.estate.resource_servers,
    });
    opened.push(estate.close);
    // The gateway trusts what the estate PUBLISHES at its jwks_uri, fetched
    // over HTTP, not a key handed across in process.
    const published = (await (await fetch(estate.jwksUri)).json()) as { keys: Record<string, unknown>[] };
    const estateKids = published.keys.map((k) => k.kid).filter((kid): kid is string => typeof kid === "string");

    const statusKeys = await generateKeyPair(TOPOLOGY.keys.asStatus.alg, { extractable: true });
    // The pilot MAS's derivation ceiling: the shipped one, with each delegable
    // entry's delegates named by client identifier. The join compares a bare
    // client identifier (rule 4), so a profile matcher such as the shipped
    // `{sub_profile: "ai_agent"}` admits no joined delegate at all.
    const policy = {
      ...DERIVATION_POLICY,
      policy_version: `${DERIVATION_POLICY.policy_version}+${config.pilot}`,
      ceiling: DERIVATION_POLICY.ceiling.map((entry) =>
        entry.delegation
          ? { ...entry, delegation: { ...entry.delegation, allowed_delegates: config.mas_delegates.map((sub) => ({ sub })) } }
          : entry,
      ),
    };
    // An authority source whose ceiling is the deployment's derivation ceiling
    // ("deployment" in config/authority-sources.json) follows the pilot's.
    const shippedCeiling = JSON.stringify(DERIVATION_POLICY.ceiling);
    const authoritySources = {
      ...AUTHORITY_SOURCES,
      entries: AUTHORITY_SOURCES.entries.map((source) =>
        JSON.stringify(source.ceiling) === shippedCeiling ? { ...source, ceiling: policy.ceiling } : source,
      ),
    };
    const kernel = new MissionKernel({
      issuer: missionIssuer,
      policy: policy as never,
      containmentPolicy: CONTAINMENT_POLICY as never,
      authoritySourceCatalog: authoritySources as never,
      statusKey: statusKeys.privateKey,
      statusKid: TOPOLOGY.keys.asStatus.kid,
    });
    opened.push(() => kernel.close());
    // The Mission Issuer's own token-verification key: in MAS mode it signs
    // no access token, so the resource route verifies against a key nothing
    // ever signs with.
    const unusedKid = "mas-pilot-unused";
    const unused = await generateKeyPair("ES256", { extractable: true });
    const missionIssuerJwks = { keys: [{ ...(await exportJWK(unused.publicKey)), kid: unusedKid, alg: "ES256" }] };

    const mappingNow = opts.mappingNow ?? opts.now;
    const mapping = new MappingContractCache({
      maxStaleSeconds: config.mapping_cache.max_stale_seconds,
      ...(mappingNow ? { now: mappingNow } : {}),
    });
    const installed = mapping.install(config.mapping_contract);
    if (!installed.ok) throw new Error(installed.reason);

    const payments = new PaymentsStore();
    payments.seed(
      [
        { id: "acme", name: "Acme Corp", status: "approved" },
        { id: "globex", name: "Globex", status: "pending" },
      ],
      [
        { id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme-001", status: "payable" },
        { id: "inv-2", vendor_id: "acme", amount: "900.00", currency: "USD", payee_account: "acct-acme-001", status: "payable" },
      ],
    );

    // @spec runtime#input-resource-policy (#828): the independently
    // administered Resource policy. Attached, the store is used as it stands;
    // bootstrapped for development, it is seeded with the estate's grants and
    // the invoice ownership above, nothing derived from a Mission or a token.
    const store = await openResourcePolicyStore(opts.openfga, opts.resourcePolicyStore);
    if (store.development) {
      await seedDevelopmentResourcePolicy(store.fga, config.estate.issuer, payments.listInvoices(), config.resource_policy);
    }
    // The principals are issuer-local to the ESTATE: the subject and client
    // the gateway authenticated (the request's `subject` and
    // `context.actor.client_id`). A Mission-side identity, the mapping
    // contract's output, is never a Resource-policy principal here: the
    // policy stays a bound independent of the join (MAS rule 8).
    const resourcePolicy = fgaResourcePolicy(store.fga, {
      principals: issuerLocalPrincipals(config.estate.issuer),
      clients: issuerLocalClients(config.estate.issuer),
    });
    const keys = createEphemeralEvidenceKeys({ resourcePolicy });
    const evidence = new EvidenceStore(keys.signing, keys.resolver);
    const observe = opts.observeDecisionRequest;

    const loadView = missionLoader(kernel);
    const actorRecords = new ActorRecords();
    const pep = new Pep({
      decide: observe
        ? async (request, decisionOptions) => {
            observe(request);
            return keys.decide(request, decisionOptions);
          }
        : keys.decide,
      payments,
      evidence,
      fga: store.fga,
      modelId: store.modelId,
      loadView,
      instanceEpoch: "mas-pilot-epoch",
      ...(opts.now ? { now: opts.now } : {}),
      masJoin: {
        mappingContract: () => mapping.current(),
        resolveDelegateDepth: actorRecords.resolveDepth.bind(actorRecords),
        missionBoundOnlyClasses: new Set(config.mission_bound_only_classes),
      },
    });

    const writeReservations: WriteReservationStore = openEphemeralWriteReservationStore({
      owner: RUNTIME_POSTURE.mediated_scope.pep_locations[0] as string,
    });
    opened.push(() => writeReservations.close());
    const connectors = new Connectors();
    const transaction = { engine: new TransactionEngine("mas-pilot-epoch"), connectors, evidence };

    // The gateway's resource server: the estate issuer's keys only, and every
    // credential it verifies is ordinary.
    const gatewayServer = new McpPaymentsServer({
      pep,
      payments,
      loadView,
      jwks: published,
      keyRoles: { accessToken: estateKids, attenuationRoot: [], transactionToken: [] },
      issuer: estate.issuer,
      ordinaryOnly: true,
      transaction,
      writeReservations,
    });
    const gateway = await createHttpMcpChannel(gatewayServer, { masGoverned: true });
    opened.push(gateway.close);

    // The resource's own route: the Mission Issuer's keys only, Mission-bound
    // credentials only.
    const resourceServer = new McpPaymentsServer({
      pep,
      payments,
      loadView,
      jwks: missionIssuerJwks,
      keyRoles: { accessToken: [unusedKid], attenuationRoot: [], transactionToken: [] },
      issuer: missionIssuer,
      transaction,
      writeReservations,
    });
    const resourceRoute = await createHttpMcpChannel(resourceServer);
    opened.push(resourceRoute.close);

    return {
      config,
      estate,
      estateClients,
      kernel,
      missionIssuer,
      mapping,
      actorRecords,
      payments,
      connectors,
      evidence,
      resourcePolicy: { fga: store.fga, storeId: store.storeId, modelId: store.modelId, development: store.development },
      pep,
      gateway,
      resourceRoute,
      close,
    };
  } catch (e) {
    await close();
    throw e;
  }
}
