/** Assembly: kernel + adapters + keys. Used by server.ts and tests. */

import { CANONICAL_RESOURCE, DERIVATION_POLICY, seedAgentClient, TOPOLOGY, USERS } from "@mission/demo-data";
import { exportJWK, generateKeyPair } from "jose";
import type Provider from "oidc-provider";
import { buildProvider } from "./adapters/provider.js";
import { MissionKernel } from "./kernel/kernel.js";

export { MissionKernel, GateError, LifecycleConflictError } from "./kernel/kernel.js";
export { validateMissionIntent, IntentError } from "./kernel/intent.js";
export { deriveAuthoritySet, isSubsetEntry, isSubsetSet } from "./kernel/derive.js";
export * from "./kernel/types.js";
export {
  issueCrossDomainGrant,
  audienceScopedAuthority,
  ID_JAG_TYP,
  ID_JAG_TOKEN_TYPE,
} from "./kernel/cross-domain.js";
export {
  CatalogProvider,
  type ServiceSeed,
  type CatalogService,
  type CatalogFilter,
  type ConnectionStatus,
} from "./kernel/catalog.js";
export {
  validateInstanceAssertion,
  newReplayCache,
  InstanceAssertionError,
  CLIENT_INSTANCE_JWT_TYP,
  CLIENT_INSTANCE_TOKEN_TYPE,
  type InstanceIssuer,
  type ValidatedInstance,
} from "./kernel/instance-assertion.js";
export {
  constructDelegatedIssuance,
  delegatedContextActor,
  type DelegatedIssuance,
} from "./kernel/delegation.js";
export {
  createExpansion,
  successorMissionClaim,
  successorWidensOnly,
  type ExpansionInput,
  type ExpansionResult,
} from "./kernel/expansion.js";
export {
  DeferralStore,
  DeferralError,
  DEFERRED_GRANT_TYPE,
  type DeferralPending,
  type DeferredToken,
} from "./kernel/deferred.js";
export {
  signChallenge,
  validateChallenge,
  issueTxnToken,
  TxnReplayCache,
  TXN_CHALLENGE_TYP,
  TXN_TOKEN_TYP,
  type TxnChallengeClaims,
} from "./kernel/txn-challenge.js";

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
  const { asToken, asStatus } = TOPOLOGY.keys;
  const tokenKeys = await generateKeyPair(asToken.alg, { extractable: true });
  const statusKeys = await generateKeyPair(asStatus.alg, { extractable: true });
  const tokenJwk = { ...(await exportJWK(tokenKeys.privateKey)), kid: asToken.kid, alg: asToken.alg, use: "sig" };
  const statusJwkPriv = { ...(await exportJWK(statusKeys.privateKey)), kid: asStatus.kid, alg: asStatus.alg, use: "sig" };
  const tokenJwkPub = { ...(await exportJWK(tokenKeys.publicKey)), kid: asToken.kid, alg: asToken.alg, use: "sig" };
  const statusJwkPub = { ...(await exportJWK(statusKeys.publicKey)), kid: asStatus.kid, alg: asStatus.alg, use: "sig" };

  const agent = await seedAgentClient();
  const kernel = new MissionKernel({
    issuer: opts.issuer,
    policy: DERIVATION_POLICY as never,
    statusKey: statusKeys.privateKey,
    statusKid: asStatus.kid,
  });

  const provider = buildProvider({
    issuer: opts.issuer,
    kernel,
    clients: [agent.metadata],
    jwks: { keys: [tokenJwk, statusJwkPriv] },
    publicJwks: { keys: [tokenJwkPub, statusJwkPub] },
    allowHeadlessAdjudication: opts.allowHeadlessAdjudication ?? false,
    approverRoleSubs: new Set(USERS.filter((u) => u.roles.includes("approver")).map((u) => u.sub)),
    accessTokenTTL: TOPOLOGY.ttls.accessTokenSeconds,
  });

  return {
    provider,
    kernel,
    issuer: opts.issuer,
    agentClientJwk: agent.privateJwk,
    canonicalResource: CANONICAL_RESOURCE,
  };
}
