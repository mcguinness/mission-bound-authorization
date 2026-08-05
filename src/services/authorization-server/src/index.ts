/** Assembly: kernel + adapters + keys. Used by server.ts and tests. */

import { CANONICAL_RESOURCE, DERIVATION_POLICY, seedAgentClient, seedChildClient, TOPOLOGY, USERS } from "@mission/demo-data";
import { exportJWK, generateKeyPair, type JWK } from "jose";
import type Provider from "oidc-provider";
import { buildProvider, type TxnArs } from "./adapters/provider.js";
import { DeferralStore } from "./kernel/deferred.js";
import { MissionKernel } from "./kernel/kernel.js";
import { StatusListPublisher } from "./kernel/status-list.js";
import type { LifecycleCommit } from "./kernel/types.js";

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
  deriveAttenuationRoot,
  mintChildOffline,
  mapAuthorityToTools,
  mapToolsToAuthority,
  AAT_TYP,
  MAX_ROOT_LIFETIME_S,
  type DeriveRootInput,
  type MintChildOptions,
} from "./kernel/attenuation.js";
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
  createChildMission,
  childMissionClaim,
  childEvidenceBytes,
  ChildDelegationError,
  CHILD_EVIDENCE_MEDIA_TYPE,
  MAX_CHILD_DEPTH,
  type ChildActor,
  type ChildDenialReason,
  type CreateChildInput,
  type ChildResult,
} from "./kernel/child-delegation.js";
export {
  mintChildGrant,
  CHILD_GRANT_TYP,
  CHILD_JWT_BEARER_GRANT_TYPE,
  MAX_CHILD_GRANT_LIFETIME_S,
  type MintChildGrantInput,
} from "./adapters/child-grant.js";
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
  /**
   * @spec child-delegation#child-client-identity — the child-actor client's
   * private JWK, so a test can authenticate the child at /token and redeem the
   * child-bound RFC 7523 grant AS ITSELF.
   */
  childClientJwk: Record<string, unknown>;
  canonicalResource: string;
}

export async function buildAuthorizationServer(opts: {
  issuer: string;
  allowHeadlessAdjudication?: boolean;
  /** The resource's txn-challenge keys, for the transaction endpoint. */
  resourceTxnJwks?: { keys: JWK[] };
  /** AROP transaction task store (AS vouches; owns the txn pending id, D37). */
  ars?: TxnArs;
  /**
   * @spec signals#lifecycle-event — an additional lifecycle-commit subscriber,
   * composed with the Status List republisher so BOTH run on every committed
   * transition. Mission Signals injects its emitter's `onCommit` here to emit a
   * `mission.lifecycle-change` SET per consumer. The AS deliberately does NOT
   * import `@mission/signals`: `@mission/signals` imports `LifecycleCommit` from
   * this package, so an import back would form a package reference cycle; the
   * subscriber is injected instead.
   */
  onLifecycleCommit?: (commit: LifecycleCommit) => void;
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
  const child = await seedChildClient();
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
    // Fan the committed transition out to BOTH the Status List republisher (PULL)
    // and any injected subscriber, e.g. the Mission Signals emitter (PUSH).
    onLifecycleCommit: (commit) => {
      statusListPublisher?.markDirty();
      opts.onLifecycleCommit?.(commit);
    },
  });
  statusListPublisher = new StatusListPublisher(() => kernel.publishStatusList());
  // AROP DTR store, wired onto the real /token deferred grant (D42).
  const deferrals = new DeferralStore(kernel);

  const provider = buildProvider({
    issuer: opts.issuer,
    kernel,
    deferrals,
    statusListPublisher,
    clients: [agent.metadata, child.metadata],
    jwks: { keys: [tokenJwk, statusJwkPriv, txnJwkPriv] },
    publicJwks: { keys: [tokenJwkPub, statusJwkPub, txnJwkPub] },
    allowHeadlessAdjudication: opts.allowHeadlessAdjudication ?? false,
    approverRoleSubs: new Set(USERS.filter((u) => u.roles.includes("approver")).map((u) => u.sub)),
    accessTokenTTL: TOPOLOGY.ttls.accessTokenSeconds,
    txnKey: txnKeys.privateKey,
    txnKid: asTxn.kid,
    // @spec child-delegation#child-client-identity — sign the child-bound RFC 7523
    // authorization grant with the AS token key (verifies on the jwks_uri).
    childGrantKey: tokenKeys.privateKey,
    childGrantKid: asToken.kid,
    childGrantAlg: asToken.alg,
    ...(opts.resourceTxnJwks ? { resourceTxnJwks: opts.resourceTxnJwks } : {}),
    ...(opts.ars ? { ars: opts.ars } : {}),
  });

  return {
    provider,
    kernel,
    deferrals,
    issuer: opts.issuer,
    agentClientJwk: agent.privateJwk,
    childClientJwk: child.privateJwk,
    canonicalResource: CANONICAL_RESOURCE,
  };
}
