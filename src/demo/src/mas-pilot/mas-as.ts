/**
 * @spec authority-server#lifecycle-and-state, mission#approval-authentication (#818 slice 5B)
 *
 * The pilot's MAS as the reference authorization server, one definition for
 * the separated MAS process (`mas-serve.ts`) and the in-process launcher
 * (`launcher.ts`): the pilot's derivation ceiling (`mas-policy.ts`), Join
 * Disclosure enrollment from `config/mas-pilot.json` `separated_mas`, the
 * PDP's Status credential where one is given, and the operator's two
 * credentials at this MAS, both generated at each boot and held in memory:
 *
 * - an approval-service principal (`MISSION_APPROVAL_SCOPE`, Approver `bob`),
 *   the shared demo's console path: it decides an approval on the AS's
 *   approval surface (`/interaction/{uid}/decide`) with headless
 *   adjudication. The published approval-authentication floor refuses
 *   high-risk authority approved this way; the pilot's gateway reserves
 *   exactly those classes for Mission-bound credentials, so the floor never
 *   binds on a joined read;
 * - a Lifecycle client (`private_key_jwt`, `mission_lifecycle`) for the
 *   advertised `mission_lifecycle_endpoint`: revoke and contain.
 *
 * The operator console (`operator-console.ts`) holds both and the submitting
 * agent's per-boot key (`BuiltAs.agentClientJwk`).
 */

import {
  type BuiltAs,
  buildAuthorizationServer,
  type LifecycleClientRegistration,
  MISSION_APPROVAL_SCOPE,
  MISSION_STATUS_SCOPE,
  type ServiceTokenPrincipal,
  type SigningKeySource,
} from "@mission/authorization-server";
import { newLifecycleConsole } from "../lifecycle-client.js";
import type { LifecycleConsoleCredentials } from "../lifecycle-client.js";
import type { MasPilotConfig } from "./config.js";
import { pilotMissionPolicy } from "./mas-policy.js";

/** The MAS's issuer: `http://{separated_mas.host}:{separated_mas.port}`, in either topology. */
export const masIssuer = (config: MasPilotConfig): string => `http://${config.separated_mas.host}:${config.separated_mas.port}`;

/** What the operator holds at the MAS: never configured, generated at this boot. */
export interface MasOperatorCredentials {
  /** The submitting agent's (`ap-agent`) private key, for its PAR and token requests. */
  agentClientJwk: Record<string, unknown>;
  /** The approval-service principal's token. */
  approvalToken: string;
  /** The Lifecycle client's identifier and private key. */
  lifecycle: LifecycleConsoleCredentials;
}

export interface PilotMas {
  issuer: string;
  built: BuiltAs;
  operator: MasOperatorCredentials;
}

export interface PilotMasOptions {
  /** The PDP's Status credential, registered for `separated_mas.pdp_principal_id`. Absent: no PDP reads Status here. */
  pdpToken?: string;
  signingKeys?: SigningKeySource;
  kernelStore?: { file: string };
  now?: () => Date;
}

/** Build (not start) the pilot's MAS: the reference authorization server under the pilot's policy. */
export async function buildPilotMas(config: MasPilotConfig, opts: PilotMasOptions = {}): Promise<PilotMas> {
  const issuer = masIssuer(config);
  const separated = config.separated_mas;
  const { policy, authoritySources } = pilotMissionPolicy(config);
  const approvalToken = crypto.randomUUID();
  const lifecycle = await newLifecycleConsole("mas-pilot-lifecycle-console");
  const principals: Record<string, ServiceTokenPrincipal> = {
    [approvalToken]: {
      principal_id: "svc:mas-pilot-approver",
      scopes: [MISSION_APPROVAL_SCOPE],
      approver: { sub: "bob", acr: "mfa", auth_time: Math.floor(Date.now() / 1000) },
    },
    ...(opts.pdpToken ? { [opts.pdpToken]: { principal_id: separated.pdp_principal_id, scopes: [MISSION_STATUS_SCOPE] } } : {}),
  };
  const built = await buildAuthorizationServer({
    issuer,
    allowHeadlessAdjudication: true,
    ...(opts.signingKeys ? { signingKeys: opts.signingKeys } : {}),
    ...(opts.kernelStore ? { kernelStore: opts.kernelStore } : {}),
    derivationPolicy: policy as never,
    authoritySources: authoritySources as never,
    serviceTokenPrincipals: principals,
    lifecycleClients: [lifecycle.registration as LifecycleClientRegistration],
    enrolledJoinPdps: Object.fromEntries(separated.enrolled_pdps.map((e) => [e.principal_id, e.enforcement_scopes])),
    ...(opts.now ? { now: opts.now } : {}),
  });
  return { issuer, built, operator: { agentClientJwk: built.agentClientJwk, approvalToken, lifecycle: lifecycle.credentials } };
}
