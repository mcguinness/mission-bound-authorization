/**
 * @spec authority-server#mission-join (#818)
 *
 * Shared by the MAS pilot's end-to-end test files: the OpenFGA connection the
 * pilot's Resource policy reads (a live OpenFGA, so the files using it are
 * skipped without one), a pilot whose decision requests are recorded, and the
 * estate-side client steps (approve a Mission, obtain an estate token, call a
 * tool with a `Mission-Reference`).
 */

import { generateKeyPair } from "jose";
import { validateMissionIntent } from "@mission/authorization-server";
import { TOPOLOGY } from "@mission/demo-data";
import { CANONICAL_RESOURCE, createHttpMediatedClient, type DpopKeys } from "@mission/mcp-payments";
import type { EvaluationRequest } from "@mission/pdp";
import { composeMasPilot, type MasPilot } from "../src/mas-pilot/compose.js";
import { loadMasPilotConfig, type MasPilotConfig } from "../src/mas-pilot/config.js";
import { obtainEstateToken } from "../src/mas-pilot/estate-client.js";
import { resourcePolicyAdmin } from "../src/resource-policy-admin.js";
import type { ResourcePolicyStore } from "../src/resource-policy-store.js";

const CA = process.env.OPENFGA_CA_CERT;

/** The OpenFGA the pilot's Resource policy reads: the environment's, else the shipped topology's. */
export const OPENFGA = {
  apiUrl: process.env.OPENFGA_HTTP_URL ?? TOPOLOGY.openfga.url,
  presharedKey: process.env.OPENFGA_PRESHARED_KEY ?? TOPOLOGY.openfga.presharedKey,
  ...(CA ? { caCertPath: CA } : {}),
};

/** Whether a live OpenFGA answers; the pilot's end-to-end files are skipped without one. */
export async function openfgaReachable(): Promise<boolean> {
  try {
    if (CA) process.env.NODE_EXTRA_CA_CERTS = CA;
    return (await fetch(`${OPENFGA.apiUrl}/healthz`, { headers: { authorization: `Bearer ${OPENFGA.presharedKey}` } })).ok;
  } catch {
    return false;
  }
}

/**
 * The pilot configuration with its estate moved to `port`: every place the
 * configuration names the estate issuer (the estate itself, the contract's
 * rows and scope mapping, the route table) names the moved one. Two test
 * files that each run an estate run in parallel, so each needs its own port.
 */
export function relocateEstate(config: MasPilotConfig, port: number): MasPilotConfig {
  const from = config.estate.issuer;
  const to = `http://${config.estate.host}:${port}`;
  const moved = JSON.parse(JSON.stringify(config).split(JSON.stringify(from).slice(1, -1)).join(to)) as MasPilotConfig;
  return { ...moved, estate: { ...moved.estate, issuer: to, port } };
}

export const READ_ACTIONS = ["payments:invoice.read", "payments:invoice.list", "payments:vendor.read"];

export interface Credential {
  token: string;
  dpopKeys: DpopKeys;
}

/** A pilot over the live OpenFGA whose decision requests are recorded, so "reached the PDP" is observable. */
export async function composeRecorded(
  extra: { config?: MasPilotConfig; mappingNow?: () => Date; resourcePolicyStore?: ResourcePolicyStore } = {},
): Promise<{ pilot: MasPilot; requests: EvaluationRequest[] }> {
  const requests: EvaluationRequest[] = [];
  const pilot = await composeMasPilot({
    openfga: OPENFGA,
    resourcePolicyStore: extra.resourcePolicyStore ?? { bootstrap: "development" },
    observeDecisionRequest: (request) => {
      requests.push(request);
    },
    config: extra.config ?? loadMasPilotConfig(),
    ...(extra.mappingNow ? { mappingNow: extra.mappingNow } : {}),
  });
  return { pilot, requests };
}

/** A Mission the MAS kernel approves for `sub` and `clientId` in the Mission's own namespace. */
export function approve(
  pilot: MasPilot,
  sub: string,
  opts: { actions?: string[]; clientId?: string; delegable?: string; label: string },
): string {
  const actions = opts.actions ?? READ_ACTIONS;
  const intent = validateMissionIntent(
    JSON.stringify({ goal: `MAS pilot: ${opts.label}`, target_resources: [CANONICAL_RESOURCE], expires_at: "2027-06-01T00:00:00Z" }),
  );
  return pilot.kernel.approve({
    intent,
    proposedAuthority: [
      {
        type: "mission_resource_access",
        resource: CANONICAL_RESOURCE,
        actions,
        constraints: {
          vendors: ["acme"],
          ...(actions.some((a) => !READ_ACTIONS.includes(a)) ? { max_amount: { amount: "500.00", currency: "USD" } } : {}),
        },
        ...(opts.delegable ? { delegation: { max_depth: 1, allowed_delegates: [{ sub: opts.delegable }] } } : {}),
      },
    ],
    subject: { iss: pilot.missionIssuer, sub },
    approver: { iss: pilot.missionIssuer, sub: "bob" },
    clientId: opts.clientId ?? "ap-agent",
    approvalEventId: `apev-mas-pilot-${opts.label}`,
  }).id;
}

/** An ordinary access token from the estate AS, for one of its registered clients and directory accounts. */
export async function estateToken(pilot: MasPilot, clientId: string, account: string, scope: string): Promise<Credential> {
  const registration = pilot.estateClients.get(clientId);
  if (!registration) throw new Error(`no estate client ${clientId}`);
  const dpopKeys = await generateKeyPair("ES256", { extractable: true });
  const result = await obtainEstateToken({
    issuer: pilot.estate.issuer,
    clientId,
    clientSecret: registration.client_secret,
    redirectUri: registration.redirect_uri,
    account,
    resource: CANONICAL_RESOURCE,
    scope,
    dpopKeys,
  });
  if (!result.ok) throw new Error(`estate token: ${JSON.stringify(result)}`);
  return { token: result.accessToken, dpopKeys };
}

export const reference = (pilot: MasPilot, missionId: string) => `id="${missionId}", issuer="${pilot.missionIssuer}"`;

/** One tool call over the gateway (or another route) with the propagated reference. */
export async function call(
  pilot: MasPilot,
  credential: Credential,
  missionId: string,
  tool: string,
  args: Record<string, unknown>,
  url = pilot.gateway.url,
) {
  const { client, close } = await createHttpMediatedClient(url, credential.token, credential.dpopKeys, {
    "mission-reference": reference(pilot, missionId),
  });
  try {
    return await client.callTool(tool, args);
  } finally {
    await close();
  }
}

/** `pnpm resource-policy` (its own code path), attached to this pilot's store and model. */
export function admin(pilot: MasPilot, ...argv: string[]): Promise<string> {
  return resourcePolicyAdmin(
    argv,
    {
      OPENFGA_STORE_ID: pilot.resourcePolicy.storeId,
      OPENFGA_MODEL_ID: pilot.resourcePolicy.modelId,
      OPENFGA_HTTP_URL: OPENFGA.apiUrl,
      OPENFGA_PRESHARED_KEY: OPENFGA.presharedKey,
      ...(OPENFGA.caCertPath ? { OPENFGA_CA_CERT: OPENFGA.caCertPath } : {}),
    },
    TOPOLOGY.openfga,
  );
}
