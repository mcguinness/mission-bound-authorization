/** Assembly: kernel + adapters + keys. Used by server.ts and tests. */

import { CANONICAL_RESOURCE, DERIVATION_POLICY, seedAgentClient, USERS } from "@mission/demo-data";
import { exportJWK, generateKeyPair } from "jose";
import type Provider from "oidc-provider";
import { buildProvider } from "./adapters/provider.js";
import { MissionKernel } from "./kernel/kernel.js";

export { MissionKernel, GateError, LifecycleConflictError } from "./kernel/kernel.js";
export { validateMissionIntent, IntentError } from "./kernel/intent.js";
export { deriveAuthoritySet, isSubsetEntry, isSubsetSet } from "./kernel/derive.js";
export * from "./kernel/types.js";

export interface BuiltAs {
  provider: Provider;
  kernel: MissionKernel;
  issuer: string;
  agentClientJwk: Record<string, unknown>;
  canonicalResource: string;
}

export async function buildAuthorizationServer(opts: {
  issuer: string;
  allowHeadlessAdjudication?: boolean;
}): Promise<BuiltAs> {
  // Per-purpose keys on one jwks_uri (@spec mission#as-metadata; matrix D39):
  // as-token signs tokens, as-status signs Status responses.
  const tokenKeys = await generateKeyPair("RS256", { extractable: true });
  const statusKeys = await generateKeyPair("ES256", { extractable: true });
  const tokenJwk = { ...(await exportJWK(tokenKeys.privateKey)), kid: "as-token", alg: "RS256", use: "sig" };
  const statusJwkPriv = { ...(await exportJWK(statusKeys.privateKey)), kid: "as-status", alg: "ES256", use: "sig" };
  const tokenJwkPub = { ...(await exportJWK(tokenKeys.publicKey)), kid: "as-token", alg: "RS256", use: "sig" };
  const statusJwkPub = { ...(await exportJWK(statusKeys.publicKey)), kid: "as-status", alg: "ES256", use: "sig" };

  const agent = await seedAgentClient();
  const kernel = new MissionKernel({
    issuer: opts.issuer,
    policy: DERIVATION_POLICY as never,
    statusKey: statusKeys.privateKey,
    statusKid: "as-status",
  });

  const provider = buildProvider({
    issuer: opts.issuer,
    kernel,
    clients: [agent.metadata],
    jwks: { keys: [tokenJwk, statusJwkPriv] },
    publicJwks: { keys: [tokenJwkPub, statusJwkPub] },
    allowHeadlessAdjudication: opts.allowHeadlessAdjudication ?? false,
    approverRoleSubs: new Set(USERS.filter((u) => u.roles.includes("approver")).map((u) => u.sub)),
  });

  return {
    provider,
    kernel,
    issuer: opts.issuer,
    agentClientJwk: agent.privateJwk,
    canonicalResource: CANONICAL_RESOURCE,
  };
}
