/**
 * @spec runtime#state-freshness, authzen#pdp-request rule 1,
 * status#mission-status-caching (#1101, D293, D1258)
 *
 * The separated AS-native configuration's payments resource: the same
 * resource side the co-located target runs (`assemblePaymentsResource`),
 * composed with no Mission kernel. The authorization server runs elsewhere
 * (its own process, `as-serve.ts`), and this composition knows it by its URL
 * and the key its PDP authenticates with.
 *
 * - State: the PDP reads each referenced Mission over the AS's signed Mission
 *   Status (`MissionStatusResolver`), configured from what the AS publishes
 *   (its metadata, `mission_status_endpoint`, `mission_max_stale_seconds` and
 *   Status keys), as the client `pdp_client_id` (private-key JWT). Every
 *   decision reads within its action class's staleness window and every
 *   commit-phase decision reads fresh (`ownReadDecide`); the signed `iat` is
 *   the observation point and the read's reliance bound caps the permit.
 *   The statement declares the source and its `pdp` placement.
 * - The PEP awaits one read per enforcement (`statusViewSource`); its later
 *   synchronous reads answer from the resolver's cache within its bounds.
 * - Authority: the Mission's effective Authority Set is the audience-scoped
 *   `authorization_details` of the same signed Status response, the view the
 *   PDP decides over. An entry the AS no longer lists for this audience is
 *   absent, so its action denies `out_of_authority`. The credential's own
 *   authority stays what the token carries, verified under the AS's
 *   `jwks_uri` with the DPoP proof on every request.
 * - Resource policy: the independently administered OpenFGA store, as the
 *   co-located target reads it.
 * - No budget binding source: this target never meters (D830).
 * - The decision channel is co-resident only: a remote PDP hop reads its own
 *   options server-side, which this configuration does not provide.
 */

import { readTopologyKeys, MAS_JOIN, TOPOLOGY, trustedKids } from "@mission/demo-data";
import {
  CANONICAL_RESOURCE,
  type McpPaymentsServer,
  type MissionReference,
  type ResourceMetadataServer,
  startResourceMetadataServer,
  statusLoadedView,
  statusViewSource,
} from "@mission/mcp-payments";
import {
  MissionStatusResolver,
  missionStatusIssuer,
  ownReadDecide,
  privateKeyJwtClient,
  RUNTIME_POSTURE,
  type RuntimePosture,
} from "@mission/pdp";
import { exportJWK, generateKeyPair, importJWK, type JWK } from "jose";
import { assemblePaymentsResource, type PaymentsResource } from "../payments-resource.js";
import { openResourcePolicyStore, type ResourcePolicyStore } from "../resource-policy-store.js";
import { type AsNativeSeparatedConfig, loadAsNativeSeparatedConfig, separatedAsIssuer, separatedStatement } from "./config.js";

export interface SeparatedAsNativeOptions {
  config?: AsNativeSeparatedConfig;
  openfgaUrl: string;
  presharedKey: string;
  caCertPath?: string;
  resourcePolicyStore: ResourcePolicyStore;
  /** The private key (a JWK with its `kid`) the PDP authenticates with at Mission Status; the AS holds the public half. */
  pdpKey: JWK;
  /** Refused unless co-resident: a remote PDP hop has no read of its own here. */
  pdpMode?: "co-resident" | "remote";
  claimsFile?: string;
  writeReservationsFile?: string;
  evidenceRetentionFile?: string;
  /** The statement; defaults to the published one, declaring this configuration's source. */
  statement?: RuntimePosture;
  /** The resolver's clock. */
  resolverNow?: () => Date;
  /** Override the advertised Status endpoint (a test points it at a proxy). */
  statusEndpoint?: string;
}

/** The separated configuration's resource side: everything it assembles, and no kernel. */
export interface SeparatedAsNative extends PaymentsResource {
  issuer: string;
  statement: RuntimePosture;
  resolver: MissionStatusResolver;
  /** Reload the AS kids this resource trusts from `topology.json`, while serving. */
  reloadTrust(): void;
  /** Stop the reconciler and close every listener and store this composition opened. Idempotent. */
  close(): Promise<void>;
}

export async function composeSeparatedAsNative(opts: SeparatedAsNativeOptions): Promise<SeparatedAsNative> {
  const config = opts.config ?? loadAsNativeSeparatedConfig();
  if ((opts.pdpMode ?? "co-resident") !== "co-resident") {
    throw new Error("the separated AS-native configuration composes a co-resident PDP only: a remote PDP hop has no Mission Status read of its own");
  }
  const issuer = separatedAsIssuer(config);
  const statement = opts.statement ?? separatedStatement(RUNTIME_POSTURE);
  const now = opts.resolverNow;
  // @spec status#mission-status (#1724 D5), #831 C2: the issuer's metadata,
  // read at its URL and refused unless it names that issuer; the Status
  // endpoint it advertises; and its Status keys held through its jwks_uri,
  // the trusted Status kids only.
  const statusIssuer = await missionStatusIssuer(issuer, {
    read: async (url: string) => (await fetch(url)).json(),
    location: issuer,
    kids: trustedKids(TOPOLOGY.keys.asStatus),
    algs: [TOPOLOGY.keys.asStatus.alg],
    ...(now ? { now: () => now().getTime() } : {}),
  });
  const metadata = statusIssuer.metadata as { issuer: string; mission_max_stale_seconds: number };
  const pdpKey = opts.pdpKey;
  if (typeof pdpKey.kid !== "string" || pdpKey.d === undefined) throw new Error("the PDP's key is not a private JWK with a kid");
  const client = privateKeyJwtClient({
    clientId: config.pdp_client_id,
    issuer: metadata.issuer,
    privateKey: (await importJWK(pdpKey, pdpKey.alg ?? "ES256")) as CryptoKey,
    kid: pdpKey.kid,
    ...(pdpKey.alg ? { alg: pdpKey.alg } : {}),
    ...(now ? { now } : {}),
  });
  const resolver = new MissionStatusResolver({
    issuer: metadata.issuer,
    statusEndpoint: opts.statusEndpoint ?? statusIssuer.statusEndpoint,
    audience: CANONICAL_RESOURCE,
    keys: statusIssuer.keys,
    client,
    maxStaleSeconds: metadata.mission_max_stale_seconds,
    timeoutMs: config.state_source.timeout_ms,
    maxResponseBytes: config.state_source.max_response_bytes,
    ...(now ? { now } : {}),
  });

  // @spec txn-authorization#two-phase-expiry: the resource publishes its
  // challenge-signing keys at `txn_challenge_jwks_uri`, on the listener the
  // configuration names, where the AS resolves them.
  const txnTopo = TOPOLOGY.txnChallenge.payments;
  const rsTxnKey = TOPOLOGY.keys.rsTxn;
  const rsTxnKeys = await generateKeyPair(rsTxnKey.alg, { extractable: true });
  const rsTxnPub = { ...(await exportJWK(rsTxnKeys.publicKey)), kid: rsTxnKey.kid, alg: rsTxnKey.alg };
  let serverRef: McpPaymentsServer | undefined;
  const metadataServer: ResourceMetadataServer = await startResourceMetadataServer(() => serverRef, config.txn_challenge_metadata);
  let resource: PaymentsResource;
  try {
    const conn = await openResourcePolicyStore(
      { apiUrl: opts.openfgaUrl, presharedKey: opts.presharedKey, ...(opts.caCertPath ? { caCertPath: opts.caCertPath } : {}) },
      opts.resourcePolicyStore,
    );
    resource = await assemblePaymentsResource({
      opts: {
        ...(opts.claimsFile ? { claimsFile: opts.claimsFile } : {}),
        ...(opts.writeReservationsFile ? { writeReservationsFile: opts.writeReservationsFile } : {}),
        ...(opts.evidenceRetentionFile ? { evidenceRetentionFile: opts.evidenceRetentionFile } : {}),
      },
      durableEvidence: undefined,
      baseStatement: statement,
      masJoin: MAS_JOIN,
      // D315: as at the co-located target, no MAS join route on the payments resource.
      masGovernedResources: MAS_JOIN.governed_resources.filter((r) => r !== CANONICAL_RESOURCE),
      issuer,
      conn,
      mode: "co-resident",
      as: {
        jwksUri: `${issuer}/jwks`,
        jwks: { keys: [] },
        keyRoles: {
          accessToken: trustedKids(TOPOLOGY.keys.asToken),
          attenuationRoot: [],
          transactionToken: trustedKids(TOPOLOGY.keys.asTxn),
        },
        challengeSigner: {
          sign: rsTxnKeys.privateKey,
          kid: rsTxnKey.kid,
          alg: rsTxnKey.alg,
          asIssuer: issuer,
          lifetimeSeconds: txnTopo.challengeLifetimeSeconds,
        },
        asIssuer: issuer,
        txnChallenge: {
          jwksUri: `${metadataServer.origin}${txnTopo.jwksPath}`,
          jwksPath: txnTopo.jwksPath,
          signingAlgValuesSupported: txnTopo.signingAlgValuesSupported,
          jwks: { keys: [rsTxnPub as never] },
        },
      },
      // The PEP's synchronous reads answer from the resolver's cache, within
      // its bounds, after the one read `viewSource` awaits per enforcement.
      loadView: (ref: MissionReference) => {
        const read = resolver.peek(ref);
        return read ? statusLoadedView(read) : undefined;
      },
      viewSource: statusViewSource(resolver),
      decide: ownReadDecide(resolver),
      serveAudience: true,
      release: { closeAuthServer: () => metadataServer.close(), closeOwnedStores: () => {} },
    });
  } catch (err) {
    await metadataServer.close();
    throw err;
  }
  serverRef = resource.server;

  let closing: Promise<void> | undefined;
  const close = (): Promise<void> =>
    (closing ??= (async () => {
      await resource.reconciler.stop();
      await resource.resourceChannel?.close();
      await metadataServer.close();
      await resource.decisionChannel.close();
      resource.pdpClaims.close();
      resource.writeReservations.close();
      resource.evidenceRetention.close();
      resource.evidenceKeySets.close();
    })());
  return {
    ...resource,
    issuer,
    statement,
    resolver,
    reloadTrust: () => {
      const keys = readTopologyKeys();
      resource.server.reloadKeyRoles({
        accessToken: trustedKids(keys.asToken),
        attenuationRoot: [],
        transactionToken: trustedKids(keys.asTxn),
      });
      statusIssuer.trust(trustedKids(keys.asStatus));
    },
    close,
  };
}
