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
 *   as the AS-native target does (D293). The separated configuration
 *   (`separated.ts`) instead reads them through the MAS's signed Mission
 *   Status over HTTP, and holds no kernel.
 * - The gateway: a MAS-governed HTTP MCP route whose resource server trusts
 *   ONLY the estate issuer: RFC 9068 JWTs under the keys the estate publishes,
 *   and opaque tokens through RFC 7662 introspection at the estate as the
 *   gateway's registered introspection client (#818 slice 3). Every credential
 *   it admits is ordinary (`ordinaryOnly`). It joins each credential to the
 *   Mission its `Mission-Reference` names, under the versioned mapping
 *   contract.
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
import { CONTAINMENT_POLICY, TOPOLOGY } from "@mission/demo-data";
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
  type MissionViewSource,
  openEphemeralWriteReservationStore,
  PaymentsStore,
  Pep,
  type PepDeps,
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
  type StateSourcePlacement,
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
import { pilotMissionPolicy } from "./mas-policy.js";

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
  /**
   * The introspection endpoint the gateway calls. Defaults to the one the
   * estate publishes. A test points it at a forwarding proxy to inject a
   * timeout or an error on the path to the estate.
   */
  introspectionEndpoint?: string;
  /** The introspection cache's clock. Defaults to `now`. */
  introspectionNow?: () => Date;
  /**
   * The in-process MAS's kernel, owned by its caller (a launcher's reference
   * authorization server). Absent, the pilot builds a bare kernel and closes
   * it with itself. Read by `composeMasPilot` only.
   */
  kernel?: MissionKernel;
}

/** Everything the pilot assembles around its Mission state source, kernel or not. */
export interface MasPilotParts {
  config: MasPilotConfig;
  estate: EstateAuthorizationServer;
  /** The estate's client registrations, with the secrets generated at this boot. */
  estateClients: ReadonlyMap<string, EstateClientRegistration>;
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

export interface MasPilot extends MasPilotParts {
  kernel: MissionKernel;
}

/** The decision point's entry the PEP calls. */
export type PdpDecide = NonNullable<PepDeps["decide"]>;

/**
 * How the assembled pilot reads Mission state, and nothing else about it:
 * the core below never holds a Mission store. `loadView` is the PEP's
 * synchronous read; `viewSource` the remote read it awaits first, where
 * there is one; `decide` wraps the decision point (the separated PDP's own
 * read); `stateSourcePlacement` the declared placement.
 */
export interface MissionStateWiring {
  missionIssuer: string;
  loadView: (ref: MissionReference) => LoadedView | undefined;
  viewSource?: MissionViewSource;
  stateSourcePlacement?: StateSourcePlacement;
  decide?: (inner: PdpDecide) => PdpDecide;
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
  // #818 slice 5B: a launcher's MAS is the reference authorization server in
  // this process, and the pilot reads that server's kernel; the server owns it.
  const owned = opts.kernel === undefined;
  const kernel = opts.kernel ?? (await pilotKernel(config));
  const release = () => {
    if (owned) kernel.close();
  };
  try {
    const parts = await assembleMasPilot(opts, config, { missionIssuer, loadView: missionLoader(kernel) });
    return {
      ...parts,
      kernel,
      close: async () => {
        await parts.close();
        release();
      },
    };
  } catch (e) {
    release();
    throw e;
  }
}

/** A bare kernel under the pilot's policy, the in-process MAS when no server is given. */
async function pilotKernel(config: MasPilotConfig): Promise<MissionKernel> {
  const statusKeys = await generateKeyPair(TOPOLOGY.keys.asStatus.alg, { extractable: true });
  const { policy, authoritySources } = pilotMissionPolicy(config);
  return new MissionKernel({
    issuer: config.mission_issuer,
    policy: policy as never,
    containmentPolicy: CONTAINMENT_POLICY as never,
    authoritySourceCatalog: authoritySources as never,
    statusKey: statusKeys.privateKey,
    statusKid: TOPOLOGY.keys.asStatus.kid,
  });
}

/**
 * Everything but the Mission state source: the estate, the mapping contract,
 * the payments store, the Resource policy, the PEP and decision point, and
 * both routes. Starts each listener and returns `close()`, which releases
 * them; a failure part way releases what it opened.
 */
export async function assembleMasPilot(
  opts: MasPilotOptions,
  config: MasPilotConfig,
  wiring: MissionStateWiring,
): Promise<MasPilotParts> {
  const missionIssuer = wiring.missionIssuer;
  const estateClients = new Map<string, EstateClientRegistration>(
    config.estate.clients.map((c) => [c.client_id, { ...c, client_secret: crypto.randomUUID() }]),
  );
  // The gateway's introspection client at the estate, its secret generated here.
  const introspectionClient = { client_id: config.introspection.client_id, client_secret: crypto.randomUUID() };
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
      introspectionClients: [introspectionClient],
      resourceServers: config.estate.resource_servers,
    });
    opened.push(estate.close);
    // The gateway trusts what the estate PUBLISHES at its jwks_uri, fetched
    // over HTTP, not a key handed across in process.
    const published = (await (await fetch(estate.jwksUri)).json()) as { keys: Record<string, unknown>[] };
    const estateKids = published.keys.map((k) => k.kid).filter((kid): kid is string => typeof kid === "string");

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

    const loadView = wiring.loadView;
    const decidePdp = wiring.decide ? wiring.decide(keys.decide) : keys.decide;
    const actorRecords = new ActorRecords();
    const pep = new Pep({
      decide: observe
        ? async (request, decisionOptions) => {
            observe(request);
            return decidePdp(request, decisionOptions);
          }
        : decidePdp,
      payments,
      evidence,
      fga: store.fga,
      modelId: store.modelId,
      loadView,
      ...(wiring.viewSource ? { viewSource: wiring.viewSource } : {}),
      ...(wiring.stateSourcePlacement ? { stateSourcePlacement: wiring.stateSourcePlacement } : {}),
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
      introspection: {
        endpoint: opts.introspectionEndpoint ?? estate.introspectionEndpoint,
        clientId: introspectionClient.client_id,
        clientSecret: introspectionClient.client_secret,
        timeoutMs: config.introspection.timeout_ms,
        cacheMaxSeconds: config.introspection.cache_max_seconds,
        ...((opts.introspectionNow ?? opts.now) ? { now: (opts.introspectionNow ?? opts.now) as () => Date } : {}),
      },
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
