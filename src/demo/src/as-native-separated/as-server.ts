/**
 * @spec runtime#state-freshness, status#mission-status (#1101, D293, D1258)
 *
 * The separated AS-native configuration's authorization server: the AS-native
 * target's (D332) with Mission Status enabled beside its capability set, so a
 * PDP outside this process reads Mission state over the signed Status
 * response. It alone holds the Missions. Its Status clients are given as
 * public registrations, each holding the `mission_status` grant only; the PDP
 * registers `provenance`, so each response commits the `authority_hash` the
 * PDP's committed-set proof reads (D335). Its Transaction Authorization
 * Server is the payments one (`paymentsTransactionAuthorization`), resolving
 * the resource's challenge keys at the URL the configuration names, and its
 * Approver logs in through an upstream OpenID Provider (D496), a party of its
 * own whose issuer and client credentials are given.
 */

import {
  ApprovalSessionStore,
  type BuiltAs,
  buildAuthorizationServer,
  type KernelStoreConfig,
  type LifecycleClientRegistration,
  MISSION_STATUS_SCOPE,
  type ProviderCapability,
  type SigningKeySource,
} from "@mission/authorization-server";
import { AccessRequestService } from "@mission/access-request";
import { TOPOLOGY } from "@mission/demo-data";
import { CANONICAL_RESOURCE } from "@mission/mcp-payments";
import { type RuntimePosture, RUNTIME_POSTURE } from "@mission/pdp";
import { createRemoteJWKSet, generateKeyPair } from "jose";
import { kernelMissionView } from "../kernel-mission-view.js";
import type { StatusClientRegistration } from "../mas-pilot/mas-as.js";
import { paymentsTransactionAuthorization } from "../payments-txn-authorization.js";
import { AS_NATIVE_CAPABILITIES } from "../stack.js";
import { type AsNativeSeparatedConfig, separatedAsIssuer, separatedStatement, txnChallengeOrigin } from "./config.js";

/**
 * D1258: the AS-native target's capability set (D332) with `status` enabled
 * explicitly beside it. The co-located target's set is unchanged.
 */
export const AS_NATIVE_SEPARATED_CAPABILITIES: ReadonlySet<ProviderCapability> = new Set<ProviderCapability>([
  ...AS_NATIVE_CAPABILITIES,
  "status",
]);

export type ApproverLoginConfig = NonNullable<Parameters<typeof buildAuthorizationServer>[0]["approverLogin"]>;

export interface SeparatedAsOptions {
  config: AsNativeSeparatedConfig;
  /** The Mission Status endpoint's clients (public halves), the PDP's among them. */
  statusClients: readonly StatusClientRegistration[];
  /** The Lifecycle console's registration (public half), holding `mission_lifecycle`. */
  lifecycleClient: LifecycleClientRegistration;
  /** The upstream OpenID Provider the Approver logs in through. */
  approverLogin: ApproverLoginConfig;
  /** The statement the AS reads; defaults to the published one, declaring this configuration's source. */
  statement?: RuntimePosture;
  signingKeys?: SigningKeySource;
  kernelStore?: KernelStoreConfig;
  now?: () => Date;
}

export interface SeparatedAs {
  issuer: string;
  built: BuiltAs;
  /** The Access Request Service the TAS opens action-bound approvals on. */
  ars: AccessRequestService;
}

/** Build (not start) the separated configuration's authorization server. */
export async function buildSeparatedAs(opts: SeparatedAsOptions): Promise<SeparatedAs> {
  const issuer = separatedAsIssuer(opts.config);
  const txnTopo = TOPOLOGY.txnChallenge.payments;
  const arsKeys = await generateKeyPair("ES256", { extractable: true });
  const ars = new AccessRequestService({
    pdpJwks: { keys: [] },
    approvalKey: arsKeys.privateKey,
    approvalKid: "ars",
    issuer: new URL(TOPOLOGY.endpoints.arsIntake).origin,
    approvalAudience: TOPOLOGY.issuers.pdp,
    approvalTtlSeconds: TOPOLOGY.ttls.approvalSeconds,
  });
  // @spec txn-authorization#two-phase-expiry — the resource's challenge keys,
  // resolved over a real fetch at the URL it publishes.
  const challengeIssuers = new Map([
    [
      CANONICAL_RESOURCE,
      {
        jwks: createRemoteJWKSet(new URL(`${txnChallengeOrigin(opts.config)}${txnTopo.jwksPath}`)),
        algs: txnTopo.signingAlgValuesSupported,
      },
    ],
  ]);
  let kernelOf: BuiltAs["kernel"] | undefined;
  const transactionAuthorization = paymentsTransactionAuthorization({
    challengeIssuers,
    ars,
    viewFor: (missionId) => (kernelOf ? kernelMissionView(kernelOf, missionId) : undefined),
  });
  const statusClients: LifecycleClientRegistration[] = opts.statusClients.map((c) => ({
    client_id: c.client_id,
    client_name: `${c.client_id} (Mission Status client)`,
    jwks: c.jwks,
    grants: [MISSION_STATUS_SCOPE],
    ...(c.disclose !== undefined ? { disclose: c.disclose } : {}),
  }));
  const built = await buildAuthorizationServer({
    issuer,
    allowHeadlessAdjudication: true,
    approvalSessions: new ApprovalSessionStore(),
    approverLogin: opts.approverLogin,
    lifecycleClients: [opts.lifecycleClient, ...statusClients],
    capabilities: AS_NATIVE_SEPARATED_CAPABILITIES,
    enforcementScopeStatement: opts.statement ?? separatedStatement(RUNTIME_POSTURE),
    devOrdinaryIssuance: false,
    transactionAuthorization,
    ...(opts.signingKeys ? { signingKeys: opts.signingKeys } : {}),
    ...(opts.kernelStore ? { kernelStore: opts.kernelStore } : {}),
    ...(opts.now ? { now: opts.now } : {}),
  });
  kernelOf = built.kernel;
  return { issuer, built, ars };
}
