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
 *
 * The decision point, its Resource policy and the FGA client are injected:
 * the slice's tests pass the reference fixtures, and an OpenFGA-backed
 * composition is a later slice.
 */

import { exportJWK, generateKeyPair } from "jose";
import { MissionKernel } from "@mission/authorization-server";
import { AUTHORITY_SOURCES, CONTAINMENT_POLICY, DERIVATION_POLICY, TOPOLOGY } from "@mission/demo-data";
import {
  ActorRecords,
  Connectors,
  createHttpMcpChannel,
  type EvidenceStore,
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
import { type DecisionFn, deriveJoinDelegation, type Fga, type MissionView, RUNTIME_POSTURE } from "@mission/pdp";
import { loadMasPilotConfig, type MasPilotConfig } from "./config.js";
import {
  type EstateAuthorizationServer,
  type EstateClientRegistration,
  startEstateAuthorizationServer,
} from "./estate-as.js";
import { MappingContractCache } from "./mapping-contract.js";

export interface MasPilotOptions {
  /** The decision point entry the PEP submits to (it closes over the PDP's emission path). */
  decide: DecisionFn;
  /** The PEP's evidence store, wired to the same signing material as `decide`. */
  evidence: EvidenceStore;
  fga: Fga;
  modelId: string;
  config?: MasPilotConfig;
  now?: () => Date;
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
  pep: Pep;
  /** The MAS-governed route that admits estate credentials. */
  gateway: HttpMcpChannel;
  /** The resource's own Mission-bound route. */
  resourceRoute: HttpMcpChannel;
  close: () => Promise<void>;
}

/** The pilot's Mission view loader: the kernel's committed record, keyed by the canonical pair. */
function missionLoader(kernel: MissionKernel): (ref: MissionReference) => LoadedView | undefined {
  return (ref) => {
    const record = kernel.get(ref.id);
    if (!record || record.issuer !== ref.issuer) return undefined;
    const fresh = kernel.applyExpiry(record);
    const view: MissionView = {
      id: fresh.id,
      issuer: fresh.issuer,
      state: fresh.state,
      version: fresh.version,
      authority_hash: fresh.authority_hash,
      authority_set: fresh.authority_set.map((e) => ({
        ...e,
        ...(e.delegation !== undefined ? { join_delegation: deriveJoinDelegation(e.delegation) } : {}),
      })),
      subject: fresh.subject,
      client_id: fresh.client_id,
    };
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

    const mapping = new MappingContractCache({
      maxStaleSeconds: config.mapping_cache.max_stale_seconds,
      ...(opts.now ? { now: opts.now } : {}),
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
    const loadView = missionLoader(kernel);
    const actorRecords = new ActorRecords();
    const pep = new Pep({
      decide: opts.decide,
      payments,
      evidence: opts.evidence,
      fga: opts.fga,
      modelId: opts.modelId,
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
    const transaction = { engine: new TransactionEngine("mas-pilot-epoch"), connectors, evidence: opts.evidence };

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
