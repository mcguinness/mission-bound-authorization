/**
 * @spec authority-server#lifecycle-and-state, mission#approval-authentication (#818 slice 5B)
 *
 * The pilot's MAS as the reference authorization server, one definition for
 * the separated MAS process (`mas-serve.ts`) and the in-process launcher
 * (`launcher.ts`): the pilot's derivation ceiling (`mas-policy.ts`), the
 * enrollment from `config/mas-pilot.json` `separated_mas.enrollment`, keyed
 * by client, each enrollee with its roles (PEP, PDP or both; #1591), the
 * Status clients given (the PDP's among them, #1407), and the
 * operator's two credentials at this MAS, both generated at each boot and
 * held in memory:
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
  type JoinAssertionDeployment,
  type LifecycleClientRegistration,
  MISSION_APPROVAL_SCOPE,
  MISSION_STATUS_SCOPE,
  type ServiceTokenPrincipal,
  type SigningKeySource,
} from "@mission/authorization-server";
import { exportJWK, generateKeyPair, type JWK } from "jose";
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

/**
 * @spec status#mission-status-authentication (#1407): a client of the MAS's
 * Mission Status endpoint: its identifier and the PUBLIC half of its signing
 * key. The private half stays with the client.
 */
export interface StatusClientRegistration {
  client_id: string;
  jwks: { keys: Record<string, unknown>[] };
}

/**
 * A Status client's signing key, generated where the client runs: the private
 * JWK (with its `kid`) for the client, and the registration the MAS needs.
 */
export async function newStatusClientKey(clientId: string): Promise<{ privateJwk: JWK; registration: StatusClientRegistration }> {
  const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
  const kid = `${clientId}-${crypto.randomUUID().slice(0, 8)}`;
  return {
    privateJwk: { ...(await exportJWK(privateKey)), kid, alg: "ES256" },
    registration: { client_id: clientId, jwks: { keys: [{ ...(await exportJWK(publicKey)), kid, alg: "ES256", use: "sig" }] } },
  };
}

/**
 * `MAS_PILOT_STATUS_CLIENTS`: a JSON array of Status client registrations,
 * at least one, each a `client_id` and a JWKS of public keys only.
 */
export function parseStatusClients(raw: string | undefined): StatusClientRegistration[] {
  if (raw === undefined || raw === "") throw new Error("MAS_PILOT_STATUS_CLIENTS registers no Status client");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("MAS_PILOT_STATUS_CLIENTS is not JSON");
  }
  if (!Array.isArray(parsed) || parsed.length === 0) throw new Error("MAS_PILOT_STATUS_CLIENTS must be a non-empty array");
  return parsed.map((c, i) => {
    const entry = c as { client_id?: unknown; jwks?: { keys?: unknown } };
    if (typeof entry.client_id !== "string" || entry.client_id === "" || !Array.isArray(entry.jwks?.keys)) {
      throw new Error(`MAS_PILOT_STATUS_CLIENTS[${i}] must have a client_id and a jwks with keys`);
    }
    return { client_id: entry.client_id, jwks: { keys: entry.jwks.keys as Record<string, unknown>[] } };
  });
}

export interface PilotMasOptions {
  /**
   * The Mission Status endpoint's clients, each holding `mission_status`
   * (#1407): the PDP's (`separated_mas.pdp_client_id`) among them. Absent: no
   * client reads Status here.
   */
  statusClients?: readonly StatusClientRegistration[];
  signingKeys?: SigningKeySource;
  kernelStore?: { file: string };
  /** @spec authority-server#join-assertion (#1454): serve the Join Assertion endpoint with this deployment. */
  joinAssertions?: JoinAssertionDeployment;
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
  };
  const statusClients: LifecycleClientRegistration[] = (opts.statusClients ?? []).map((c) => ({
    client_id: c.client_id,
    client_name: `${c.client_id} (MAS pilot Status client)`,
    jwks: c.jwks,
    grants: [MISSION_STATUS_SCOPE],
  }));
  const built = await buildAuthorizationServer({
    issuer,
    allowHeadlessAdjudication: true,
    ...(opts.signingKeys ? { signingKeys: opts.signingKeys } : {}),
    ...(opts.kernelStore ? { kernelStore: opts.kernelStore } : {}),
    derivationPolicy: policy as never,
    authoritySources: authoritySources as never,
    serviceTokenPrincipals: principals,
    lifecycleClients: [lifecycle.registration as LifecycleClientRegistration, ...statusClients],
    // @spec authority-server#join-disclosure: keyed by the authenticated
    // Status client, the identity the response's `sub` names (#1407).
    joinEnrollment: Object.fromEntries(
      separated.enrollment.map((e) => [e.client_id, { roles: e.roles, enforcementScopes: e.enforcement_scopes }]),
    ),
    ...(opts.joinAssertions ? { joinAssertions: opts.joinAssertions } : {}),
    ...(opts.now ? { now: opts.now } : {}),
  });
  return { issuer, built, operator: { agentClientJwk: built.agentClientJwk, approvalToken, lifecycle: lifecycle.credentials } };
}
