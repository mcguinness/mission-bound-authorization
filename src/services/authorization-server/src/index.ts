/** Assembly: kernel + adapters + keys. Used by server.ts and tests. */

import { CANONICAL_RESOURCE, DERIVATION_POLICY, seedAgentClient, TOPOLOGY, USERS } from "@mission/demo-data";
import { exportJWK, generateKeyPair, type JWK } from "jose";
import type Provider from "oidc-provider";
import { buildProvider, type TxnArs } from "./adapters/provider.js";
import { DeferralStore } from "./kernel/deferred.js";
import { MissionKernel } from "./kernel/kernel.js";
import { StatusListPublisher } from "./kernel/status-list.js";

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
  type DeferralSlowDown,
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
export {
  StatusListPublisher,
  signStatusListToken,
  verifyStatusListToken,
  readStatus,
  readStatusBit,
  stateToBit,
  statusListUri,
  STATUS_LIST_ID,
  STATUS_LIST_TYP,
  STATUS_LIST_MEDIA_TYPE,
  STATUS_LIST_BITS,
  STATUS_LIST_SIZE,
  STATUS_LIST_TTL_SECONDS,
  STATUS_VALID,
  STATUS_INVALID,
  STATUS_SUSPENDED,
  type StatusListPayload,
  type StatusListClaim,
  type StatusEntry,
  type SignStatusListOptions,
  type VerifyStatusListOptions,
} from "./kernel/status-list.js";

export interface BuiltAs {
  provider: Provider;
  kernel: MissionKernel;
  /** AROP Deferred Token Response store (drive open/approve/deny headlessly). */
  deferrals: DeferralStore;
  issuer: string;
  agentClientJwk: Record<string, unknown>;
  canonicalResource: string;
}

export async function buildAuthorizationServer(opts: {
  issuer: string;
  allowHeadlessAdjudication?: boolean;
  /** The resource's txn-challenge keys, for the transaction endpoint. */
  resourceTxnJwks?: { keys: JWK[] };
  /** AROP transaction task store (AS vouches; owns the txn pending id, D37). */
  ars?: TxnArs;
}): Promise<BuiltAs> {
  // Per-purpose keys on one jwks_uri (@spec mission#as-metadata; matrix D39):
  // as-token signs tokens, as-status signs Status responses, as-txn signs
  // txn-bound single-use approval tokens (AROP Transaction Challenge).
  const { asToken, asStatus, asTxn } = TOPOLOGY.keys;
  const tokenKeys = await generateKeyPair(asToken.alg, { extractable: true });
  const statusKeys = await generateKeyPair(asStatus.alg, { extractable: true });
  const txnKeys = await generateKeyPair(asTxn.alg, { extractable: true });
  const tokenJwk = { ...(await exportJWK(tokenKeys.privateKey)), kid: asToken.kid, alg: asToken.alg, use: "sig" };
  const statusJwkPriv = { ...(await exportJWK(statusKeys.privateKey)), kid: asStatus.kid, alg: asStatus.alg, use: "sig" };
  const txnJwkPriv = { ...(await exportJWK(txnKeys.privateKey)), kid: asTxn.kid, alg: asTxn.alg, use: "sig" };
  const tokenJwkPub = { ...(await exportJWK(tokenKeys.publicKey)), kid: asToken.kid, alg: asToken.alg, use: "sig" };
  const statusJwkPub = { ...(await exportJWK(statusKeys.publicKey)), kid: asStatus.kid, alg: asStatus.alg, use: "sig" };
  const txnJwkPub = { ...(await exportJWK(txnKeys.publicKey)), kid: asTxn.kid, alg: asTxn.alg, use: "sig" };

  const agent = await seedAgentClient();
  // The Status List republisher subscribes to the kernel's lifecycle-commit
  // hook. It is created after the kernel closes over it, but onLifecycleCommit
  // only fires at runtime (post-construction), so the forward reference is safe;
  // the publisher takes a build thunk, never the kernel, to avoid an import cycle.
  let statusListPublisher: StatusListPublisher | undefined;
  const kernel = new MissionKernel({
    issuer: opts.issuer,
    policy: DERIVATION_POLICY as never,
    statusKey: statusKeys.privateKey,
    statusKid: asStatus.kid,
    onLifecycleCommit: () => statusListPublisher?.markDirty(),
  });
  statusListPublisher = new StatusListPublisher(() => kernel.publishStatusList());
  // AROP DTR store, wired onto the real /token deferred grant (D42).
  const deferrals = new DeferralStore(kernel);

  const provider = buildProvider({
    issuer: opts.issuer,
    kernel,
    deferrals,
    statusListPublisher,
    clients: [agent.metadata],
    jwks: { keys: [tokenJwk, statusJwkPriv, txnJwkPriv] },
    publicJwks: { keys: [tokenJwkPub, statusJwkPub, txnJwkPub] },
    allowHeadlessAdjudication: opts.allowHeadlessAdjudication ?? false,
    approverRoleSubs: new Set(USERS.filter((u) => u.roles.includes("approver")).map((u) => u.sub)),
    accessTokenTTL: TOPOLOGY.ttls.accessTokenSeconds,
    txnKey: txnKeys.privateKey,
    txnKid: asTxn.kid,
    ...(opts.resourceTxnJwks ? { resourceTxnJwks: opts.resourceTxnJwks } : {}),
    ...(opts.ars ? { ars: opts.ars } : {}),
  });

  return {
    provider,
    kernel,
    deferrals,
    issuer: opts.issuer,
    agentClientJwk: agent.privateJwk,
    canonicalResource: CANONICAL_RESOURCE,
  };
}
