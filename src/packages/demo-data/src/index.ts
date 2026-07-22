/**
 * Seed data (single source of demo state; PLAN.md runbook). Keys are
 * generated per boot: nothing here is deterministic across restarts (D25).
 */

import { exportJWK, generateKeyPair } from "jose";

export const CANONICAL_RESOURCE = process.env.MCP_PAYMENTS_RESOURCE ?? "http://localhost:4403/mcp";

export interface SeededUser {
  sub: string;
  name: string;
  roles: string[];
}

export const USERS: SeededUser[] = [
  { sub: "alice", name: "Alice", roles: ["subject"] },
  { sub: "bob", name: "Bob", roles: ["subject", "approver"] },
];

export const VENDORS = [
  { id: "acme", name: "Acme Corp", status: "approved" },
  { id: "globex", name: "Globex", status: "pending" },
] as const;

export const INVOICES = [
  {
    id: "inv-1",
    vendor_id: "acme",
    amount: { amount: "125.00", currency: "USD" },
    status: "payable",
    version: 1,
  },
  {
    id: "inv-2",
    vendor_id: "acme",
    amount: { amount: "900.00", currency: "USD" },
    status: "payable",
    version: 1,
  },
  {
    id: "inv-3",
    vendor_id: "globex",
    amount: { amount: "50.00", currency: "USD" },
    status: "payable",
    version: 1,
  },
] as const;

/** Actions whose presence makes a mission write-bearing (D37 governance). */
export const WRITE_ACTIONS = new Set([
  "payments:payment.schedule",
  "payments:payment.execute",
  "payments:remittance.send",
]);

/**
 * Derivation policy ceiling (@spec mission#authorization-derivation): the
 * AS derives each Authority Set entry as a subset of a proposed entry,
 * bounded by this ceiling. Nothing a client proposes can widen past it.
 */
export const DERIVATION_POLICY = {
  policy_version: "demo-policy-1",
  ceiling: [
    {
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: [
        "payments:invoice.list",
        "payments:invoice.read",
        "payments:vendor.read",
        "payments:payment.schedule",
        "payments:payment.execute",
        "payments:remittance.send",
      ],
      constraints: {
        max_amount: { amount: "500.00", currency: "USD" },
        vendors: ["acme"],
      },
    },
  ],
} as const;

export interface SeededClient {
  metadata: Record<string, unknown>;
  privateJwk: Record<string, unknown>;
}

/** The agent's confidential client: private_key_jwt + separate DPoP key (D38). */
export async function seedAgentClient(): Promise<SeededClient> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  const pub = await exportJWK(publicKey);
  const priv = await exportJWK(privateKey);
  pub.kid = "ap-agent-auth";
  priv.kid = "ap-agent-auth";
  pub.alg = "ES256";
  return {
    metadata: {
      client_id: "ap-agent",
      client_name: "AP Agent",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      redirect_uris: ["http://localhost:9999/cb"],
      token_endpoint_auth_method: "private_key_jwt",
      token_endpoint_auth_signing_alg: "ES256",
      jwks: { keys: [pub] },
      scope: "payments",
      authorization_details_types: ["mission_resource_access"],
    },
    privateJwk: priv as Record<string, unknown>,
  };
}

/** Dev-only service token for control-plane edges (channel matrix). */
export const DEV_SERVICE_TOKEN = "dev-service-token";
