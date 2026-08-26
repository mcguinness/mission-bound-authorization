/**
 * MCP-shaped resource server for the payments estate. Streamable-HTTP MCP
 * transport is the production swap (O-33); this exposes tools/list and
 * tools/call over JSON with the full PEP pipeline, which is what the core
 * enforcement tier (M4) requires. RFC 9728 PRM is published.
 */

import {
  authorizationDetailsEqual,
  type DpopProofReplay,
  MISSION_TXN_TOKEN_TYP,
  missionInvariantsEqual,
  newDpopProofReplay,
  parseAatToolId,
  readTxnMissionClaim,
  toolsOf,
  verifyAttenuationChain,
} from "@mission/core";
import { calculateJwkThumbprint, createLocalJWKSet, decodeProtectedHeader, type JWK, jwtVerify } from "jose";
import type { ActObject } from "@mission/actor-chain";
import type { Decision, MissionView } from "@mission/pdp";
import {
  type ActionApprovalInput,
  CANONICAL_RESOURCE,
  type EnforceResult,
  type InsufficientAuthorization,
  type LoadedView,
  loadCheckedView,
  type MissionReference,
  type Pep,
  type RequestSignals,
  type TokenFacts,
  TOOL_ACTIONS,
  type TxnCredential,
} from "./pep.js";
import { type DpopPresentation, verifyDpopProof } from "./dpop.js";
import {
  openTxnStores,
  type TxnConsumeOutcome,
  type TxnConsumptionStore,
  type TxnPendingStore,
} from "./txn-store.js";
import type { PaymentsStore } from "./payments-store.js";
import type { Connectors } from "./connectors.js";
import type { EvidenceStore } from "./evidence.js";
import { operationKey, type TransactionEngine } from "./transaction.js";
import { buildEffectiveParams, parameterDigest } from "./effective-params.js";


/**
 * @spec txn-authorization#transaction-token — a transaction token authorizes
 * exactly the challenged operation and MUST NOT be accepted as a general
 * Mission-bound access token for any other purpose. Its `typ` is read before
 * anything else, so it is refused outright rather than parsed on a best-effort
 * basis: every other claim on it (issuer, audience, `cnf`, the `mission`
 * claim) would otherwise satisfy ordinary token validation.
 */
function refuseTransactionToken(accessToken: string): void {
  if (decodeProtectedHeader(accessToken).typ === MISSION_TXN_TOKEN_TYP) {
    throw new Error("a transaction token is not a Mission-bound access token");
  }
}

/**
 * @spec authzen#response-context: a permit's decision conditions
 * (`parameter_digest`/`valid_until`/`use_limit`) live NESTED under
 * `decision.context.conditions`, never as flat top-level members. Every
 * digest reverification site reads through this one accessor so the nesting
 * is never repeated ad hoc.
 */
function permitConditions(decision: Decision | undefined): Record<string, unknown> | undefined {
  return decision?.context.conditions as Record<string, unknown> | undefined;
}

export interface ToolDef {
  name: string;
  description: string;
  action: string;
}

export const TOOLS: ToolDef[] = [
  { name: "list_invoices", description: "List invoices", action: "payments:invoice.list" },
  { name: "get_invoice", description: "Read one invoice", action: "payments:invoice.read" },
  { name: "lookup_vendor", description: "Look up a vendor", action: "payments:vendor.read" },
  { name: "schedule_payment", description: "Schedule a payment", action: "payments:payment.schedule" },
  { name: "execute_wire_transfer", description: "Execute a wire transfer", action: "payments:payment.execute" },
  { name: "send_remittance_email", description: "Send remittance advice", action: "payments:remittance.send" },
];

export interface McpServerDeps {
  pep: Pep;
  payments: PaymentsStore;
  loadView: (ref: MissionReference) => LoadedView | undefined;
  jwks: { keys: Record<string, unknown>[] };
  issuer: string;
  serverCard: unknown;
  /** Transaction-assurance tier (M5); omit for a core-tier-only server. */
  transaction?: { engine: TransactionEngine; connectors: Connectors; evidence: EvidenceStore };
  /**
   * AROP Transaction Challenge (RS side): the AS's txn public JWKS (as-txn key)
   * and issuer, used to validate a presented txn-token. Omit to disable the
   * hybrid txn-token path.
   */
  txnTokenJwks?: { keys: Record<string, unknown>[] };
  asIssuer?: string;
  /**
   * @spec txn-authorization#two-phase-expiry (key discovery) — this resource's
   * PUBLISHED txn-challenge key material and the metadata members that point at
   * it. A Transaction Authorization Server resolves this resource's challenge
   * keys from `jwksUri` and nowhere else.
   */
  txnChallenge?: {
    /** Absolute URI published as `txn_challenge_jwks_uri`. */
    jwksUri: string;
    /** Path this server answers the JWKS on (the `jwksUri` path component). */
    jwksPath: string;
    /** Published as `txn_challenge_signing_alg_values_supported`. */
    signingAlgValuesSupported: string[];
    /** The PUBLIC half of the challenge-signing key(s). */
    jwks: { keys: Record<string, unknown>[] };
  };
  /**
   * @spec txn-authorization#offline-verification — the retained pending
   * operations and the `txn` consumption domain. Injectable so replicas that
   * can execute the same operation share ONE database (consumption must be
   * linearizable across all of them); defaulted to this replica's own
   * in-memory stores.
   */
  txnStores?: { pending: TxnPendingStore; consumption: TxnConsumptionStore };
  /**
   * @spec RFC 9449 §11.1 — the DPoP proof `jti` replay window. Injectable so a
   * deployment can share one across replicas fronted as one resource; defaulted
   * to this replica's own (D27).
   */
  dpopReplay?: DpopProofReplay;
}

/**
 * The transaction-tier verdict. @spec txn-authorization#resource-challenge —
 * `error` and `transaction_challenge` are the upstream wire members, carried
 * verbatim on the tool-result surface; there is no bespoke challenge envelope
 * and no endpoint hint (the client discovers the Transaction Authorization
 * Server through `transaction_authorization_endpoint` in AS metadata).
 */
/**
 * @spec txn-authorization#offline-verification — the outcome of verifying a
 * presented transaction credential. On success the request's TokenFacts are
 * derived FROM the transaction token, so the challenged operation runs under
 * that credential alone; on failure the profile's refusal reason says which
 * check the credential failed.
 */
export type VerifiedTxnCredential =
  | { ok: true; facts: TokenFacts }
  | { ok: false; refusal_reason: string };

export interface TransactionToolResult {
  ok: boolean;
  result?: unknown;
  denial_reason?: string;
  refusal_reason?: string;
  deduped?: boolean;
  access_request?: EnforceResult["access_request"];
  error?: string;
  transaction_challenge?: string;
  insufficient_authorization?: InsufficientAuthorization;
}

export class McpPaymentsServer {
  private readonly resolveKey;
  private readonly resolveTxnKey?: ReturnType<typeof createLocalJWKSet>;
  /** @spec txn-authorization#offline-verification — the retained pending operations. */
  private readonly txnPending: TxnPendingStore;
  /** @spec txn-authorization#offline-verification — the `txn` consumption domain. */
  private readonly txnConsumption: TxnConsumptionStore;
  /** @spec RFC 9449 §11.1 — this resource's DPoP proof `jti` replay window. */
  private readonly dpopReplay: DpopProofReplay;
  constructor(private readonly deps: McpServerDeps) {
    this.resolveKey = createLocalJWKSet(deps.jwks as never);
    if (deps.txnTokenJwks) this.resolveTxnKey = createLocalJWKSet(deps.txnTokenJwks as never);
    const stores = deps.txnStores ?? openTxnStores();
    this.txnPending = stores.pending;
    this.txnConsumption = stores.consumption;
    this.dpopReplay = deps.dpopReplay ?? newDpopProofReplay();
  }

  /**
   * @spec RFC 9449 §4.3 — the ONE proof check every credential class this
   * resource accepts runs, against this replica's replay window.
   */
  private async verifyPresentation(
    accessToken: string,
    expectedJkt: string,
    pop: DpopPresentation,
  ): Promise<void> {
    await verifyDpopProof({
      proof: pop.proof,
      accessToken,
      expectedJkt,
      htu: pop.htu,
      htm: pop.htm,
      replay: this.dpopReplay,
    });
  }

  /** RFC 9728 Protected Resource Metadata. */
  protectedResourceMetadata(): Record<string, unknown> {
    const txn = this.deps.txnChallenge;
    return {
      resource: CANONICAL_RESOURCE,
      authorization_servers: [this.deps.issuer],
      bearer_methods_supported: ["dpop"],
      mission_bound_authorization_required: true,
      mission_constraints_supported: ["max_amount", "vendors"],
      // @spec txn-authorization#two-phase-expiry — key discovery rides the
      // upstream metadata: this is where a TAS resolves this resource's
      // challenge-signing keys, and nowhere else.
      ...(txn
        ? {
            txn_challenge_jwks_uri: txn.jwksUri,
            txn_challenge_signing_alg_values_supported: txn.signingAlgValuesSupported,
          }
        : {}),
    };
  }

  /** The published txn-challenge JWKS, or undefined when none is configured. */
  txnChallengeJwks(): { keys: Record<string, unknown>[] } | undefined {
    return this.deps.txnChallenge?.jwks;
  }

  /** The path {@link txnChallengeJwks} is served on. */
  txnChallengeJwksPath(): string | undefined {
    return this.deps.txnChallenge?.jwksPath;
  }

  /**
   * Validate a DPoP-bound access token, returning TokenFacts.
   * @spec mission#rs-enforcement: enforce from the token (cnf, mission claim).
   */
  async validateToken(accessToken: string, dpopProof: string, htu: string, htm: string): Promise<TokenFacts> {
    refuseTransactionToken(accessToken);
    const { payload } = await jwtVerify(accessToken, this.resolveKey, {
      issuer: this.deps.issuer,
      audience: CANONICAL_RESOURCE,
    });
    const cnf = payload.cnf as { jkt?: string } | undefined;
    if (!cnf?.jkt) throw new Error("token missing cnf.jkt");
    // Verify the DPoP proof and bind it to the token's cnf.jkt AND to the token
    // itself (`ath`), under the same verifier the transaction path uses.
    await this.verifyPresentation(accessToken, cnf.jkt, { proof: dpopProof, htu, htm });

    // @spec cross-domain#mission-subject — readTxnMissionClaim validates the
    // REQUIRED invariants and, when present, the closed {iss, sub} shape of
    // the origin principal; a present-but-malformed `subject` is a refusal
    // here, not a silently dropped member.
    const mission = readTxnMissionClaim(payload.mission);
    if (!mission) throw new Error("token missing mission claim");
    return {
      sub: payload.sub as string,
      clientId: payload.client_id as string,
      // @spec authzen#pdp-request rule 10 — this resource's own verified
      // issuer, never the mission's origin issuer.
      iss: this.deps.issuer,
      ...(payload.act ? { act: payload.act as ActObject } : {}),
      mission: {
        id: mission.id,
        issuer: mission.issuer,
        // @spec mission#the-mission-claim (#702) — NOT on the baseline claim;
        // carried only when the source token's own profile added it.
        ...(mission.authority_hash !== undefined ? { authority_hash: mission.authority_hash } : {}),
        ...(mission.subject ? { subject: mission.subject } : {}),
      },
      missionClaim: mission,
      cnfJkt: cnf.jkt,
      ...(payload.jti ? { jti: payload.jti as string } : {}),
      ...(payload.identity_continuation_handle
        ? { identityContinuationHandle: payload.identity_continuation_handle as string }
        : {}),
    };
  }

  /**
   * Increment-1 mediated-channel credential validation: a documented
   * simplification of {@link validateToken}. Over the in-process MCP transport
   * there is no HTTP request to bind a DPoP proof to (no htu/htm), so this
   * validates the mission access token's signature (jwks), issuer, audience and
   * mission claim and carries the token's `cnf.jkt` into TokenFacts. Live DPoP
   * proof-of-possession over MCP is out of scope for increment 1. The credential
   * still crosses IN the MCP request (in `_meta`) and TokenFacts is derived from
   * a validated token here, never passed through untouched.
   * @spec draft-mcguinness-mission-harness (mediated execution environment)
   */
  async validateMissionToken(accessToken: string): Promise<TokenFacts> {
    refuseTransactionToken(accessToken);
    const { payload } = await jwtVerify(accessToken, this.resolveKey, {
      issuer: this.deps.issuer,
      audience: CANONICAL_RESOURCE,
    });
    const cnf = payload.cnf as { jkt?: string } | undefined;
    if (!cnf?.jkt) throw new Error("token missing cnf.jkt");
    const mission = readTxnMissionClaim(payload.mission);
    if (!mission) throw new Error("token missing mission claim");
    return {
      sub: payload.sub as string,
      clientId: payload.client_id as string,
      iss: this.deps.issuer,
      ...(payload.client_instance_id ? { clientInstanceId: payload.client_instance_id as string } : {}),
      ...(payload.act ? { act: payload.act as ActObject } : {}),
      mission: {
        id: mission.id,
        issuer: mission.issuer,
        // @spec mission#the-mission-claim (#702) — NOT on the baseline claim;
        // carried only when the source token's own profile added it.
        ...(mission.authority_hash !== undefined ? { authority_hash: mission.authority_hash } : {}),
        ...(mission.subject ? { subject: mission.subject } : {}),
      },
      missionClaim: mission,
      cnfJkt: cnf.jkt,
      ...(payload.jti ? { jti: payload.jti as string } : {}),
      ...(payload.identity_continuation_handle
        ? { identityContinuationHandle: payload.identity_continuation_handle as string }
        : {}),
    };
  }

  /**
   * @spec txn-authorization#transaction-token, #offline-verification — the
   * SINGLE OAuth credential a request presents, resolved to TokenFacts.
   *
   * The protected-header `typ` is read BEFORE anything else and decides which
   * class of credential this is: `mission-txn-token+jwt` is the retry of a
   * challenged operation and takes the transaction-credential path below;
   * everything else takes the ordinary path, which still refuses a transaction
   * token outright. There is no second credential and no side channel: a
   * transaction token authorizes the operation this resource challenged for and
   * is never accepted as a general Mission-bound access token.
   *
   * `pop` carries the request's DPoP proof where the transport has an HTTP
   * request to bind one to; the in-process mediated channel omits it, exactly
   * as {@link validateMissionToken} documents for the ordinary class.
   */
  async validateCredential(accessToken: string, pop?: DpopPresentation): Promise<TokenFacts> {
    if (decodeProtectedHeader(accessToken).typ === MISSION_TXN_TOKEN_TYP) {
      const verified = await this.verifyTransactionCredential(accessToken, pop);
      if (!verified.ok) throw new Error(`transaction credential refused: ${verified.refusal_reason}`);
      return verified.facts;
    }
    return pop
      ? this.validateToken(accessToken, pop.proof, pop.htu, pop.htm)
      : this.validateMissionToken(accessToken);
  }

  /**
   * @spec txn-authorization#offline-verification — verify a presented
   * transaction credential locally, in the order the profile fixes:
   *
   *  1. exact `typ`, trusted issuer and signature, intended `aud` (a singleton,
   *     this resource), and the REQUIRED typed claims. An unknown `typ` -- an
   *     ordinary Mission-bound access token, or any other JWT -- never reaches
   *     here (the caller branches on `typ`) and is rejected outright by the
   *     verifier besides;
   *  2. `cnf` proof by the CURRENT presenter, under the same DPoP discipline
   *     the ordinary credential path uses;
   *  3. equality of the `mission` invariants, the operation
   *     `authorization_details`, `cnf`, the subject and `parameter_digest` with
   *     the pending operation this resource RETAINED when it challenged --
   *     never with the token's own account of the operation.
   *
   * The operation-scoped half of step 3 (the action this credential is good
   * for, and the digest RECOMPUTED from the request's own parameters) needs the
   * tool and arguments, so it runs at the call site
   * ({@link verifyChallengedOperation}); step 5 (current local policy,
   * entitlement and Mission state) is the PEP/PDP path the caller runs next,
   * and step 6 (atomic first use) is taken at the commit point.
   */
  async verifyTransactionCredential(
    txnToken: string,
    pop?: DpopPresentation,
  ): Promise<VerifiedTxnCredential> {
    if (!this.resolveTxnKey || !this.deps.asIssuer) return { ok: false, refusal_reason: "txn_not_configured" };
    // @spec txn-authorization#offline-verification step 2 — proof of possession
    // is not optional for a transaction credential. It authorizes an
    // irreversible operation under a key the challenge committed to; accepting
    // it without a proof would make it a BEARER token for that operation. A
    // transport with no request to bind a proof to therefore cannot carry one
    // at all -- it is refused here rather than admitted unproven.
    if (!pop) return { ok: false, refusal_reason: "txn_pop_required" };
    let payload: Record<string, unknown>;
    try {
      // The TAS's token-signing key is trusted through pre-established
      // federation metadata (this JWKS), never through the request.
      ({ payload } = (await jwtVerify(txnToken, this.resolveTxnKey, {
        issuer: this.deps.asIssuer,
        audience: CANONICAL_RESOURCE,
        typ: MISSION_TXN_TOKEN_TYP,
      })) as { payload: Record<string, unknown> });
    } catch {
      return { ok: false, refusal_reason: "txn_invalid" };
    }
    // `aud` is a SINGLETON, exactly this resource; a list is not this profile.
    const cnf = payload.cnf as { jkt?: string } | undefined;
    if (
      typeof payload.aud !== "string" ||
      typeof payload.jti !== "string" ||
      typeof payload.iat !== "number" ||
      typeof payload.exp !== "number" ||
      typeof payload.sub !== "string" ||
      typeof payload.client_id !== "string" ||
      typeof payload.txn !== "string" ||
      typeof payload.parameter_digest !== "string" ||
      typeof cnf?.jkt !== "string"
    ) {
      return { ok: false, refusal_reason: "txn_invalid" };
    }
    const mission = readTxnMissionClaim(payload.mission);
    if (!mission) return { ok: false, refusal_reason: "txn_invalid" };

    // 2. Proof by the CURRENT presenter: this request's proof, under the key
    //    the credential itself is bound to and naming THIS credential (`ath`).
    try {
      await this.verifyPresentation(txnToken, cnf.jkt, pop);
    } catch {
      return { ok: false, refusal_reason: "txn_cnf_mismatch" };
    }

    // 3. Against the RETAINED pending operation.
    const pending = this.txnPending.get(CANONICAL_RESOURCE, payload.txn);
    if (!pending) return { ok: false, refusal_reason: "txn_unknown" };
    if (pending.cnfJkt !== cnf.jkt) return { ok: false, refusal_reason: "txn_cnf_mismatch" };
    if (!missionInvariantsEqual(payload.mission, pending.mission)) {
      return { ok: false, refusal_reason: "txn_mission_mismatch" };
    }
    if (!authorizationDetailsEqual(payload.authorization_details, pending.authorizationDetails)) {
      return { ok: false, refusal_reason: "txn_authority_mismatch" };
    }
    if (payload.parameter_digest !== pending.parameterDigest) {
      return { ok: false, refusal_reason: "txn_parameter_mismatch" };
    }
    // The verified effective subject the challenge was issued for; the origin
    // principal where the Origin Principal profile applies.
    if (payload.sub !== pending.subject) return { ok: false, refusal_reason: "txn_subject_mismatch" };

    // The request runs under THESE claims: subject, client, Mission, actor and
    // presenter key all come from the verified transaction token, so an
    // approval obtained for one Mission cannot carry an operation on another.
    const txn: TxnCredential = {
      txn: payload.txn,
      jti: payload.jti,
      iatS: payload.iat,
      expS: payload.exp,
      parameterDigest: payload.parameter_digest,
    };
    return {
      ok: true,
      facts: {
        sub: payload.sub,
        clientId: payload.client_id,
        // @spec authzen#pdp-request rule 10 — this resource's own verified
        // issuer: the subject the challenge was opened for is a principal in
        // ITS namespace regardless of which credential class retrieved it.
        iss: this.deps.issuer,
        ...(payload.act ? { act: payload.act as ActObject } : {}),
        mission: {
          id: mission.id,
          issuer: mission.issuer,
          // @spec mission#the-mission-claim (#702) — NOT on the baseline
          // claim; carried only when the source token's own profile added it.
          ...(mission.authority_hash !== undefined ? { authority_hash: mission.authority_hash } : {}),
          ...(mission.subject ? { subject: mission.subject } : {}),
        },
        missionClaim: mission,
        cnfJkt: cnf.jkt,
        jti: payload.jti,
        txn,
      },
    };
  }

  /**
   * @spec draft-mcguinness-oauth-mission-attenuation#mission-binding-check
   *
   * Validate a presented Mission-bound Attenuating Agent Token chain (root
   * first) and derive TokenFacts whose effective authority is the LEAF's
   * narrowed tools. Keyed verification, layered on the pure keyless verifier
   * from @mission/core:
   *  - the root is verified under the AS JWKS, audience-scoped, and its `iss`
   *    MUST equal its `mission.issuer` (only the Mission Issuer mints a root);
   *  - each child is verified under the key its parent's `cnf` commits to: the
   *    child's JWS header `jwk` (rejected if it carries private material) MUST
   *    thumbprint to the parent's `cnf.jkt`, and the child MUST verify under it;
   *  - proof-of-possession is verified under the LEAF's `cnf` key.
   *
   * The kill switch (Mission `active` on every presentation) is NOT checked
   * here: it is the existing PEP->PDP state gate on the per-action enforce()
   * path (the returned TokenFacts drives that path), which fails closed on
   * non-active or unestablished Mission state.
   */
  async validateAttenuationChain(
    chain: string[],
    dpopProof: string,
    htu: string,
    htm: string,
  ): Promise<TokenFacts> {
    if (chain.length === 0) throw new Error("empty attenuation chain");

    // Root: under the AS JWKS, audience-scoped, iss == mission.issuer.
    const { payload: rootPayload } = await jwtVerify(chain[0] as string, this.resolveKey, {
      issuer: this.deps.issuer,
      audience: CANONICAL_RESOURCE,
      algorithms: ["ES256"],
    });
    const rootMission = rootPayload.mission as { id: string; issuer: string; authority_hash: string } | undefined;
    if (!rootMission?.id) throw new Error("attenuation root missing mission claim");
    if (rootPayload.iss !== rootMission.issuer) throw new Error("attenuation root iss != mission.issuer");
    let parentCnfJkt = (rootPayload.cnf as { jkt?: string } | undefined)?.jkt;
    if (!parentCnfJkt) throw new Error("attenuation root missing cnf.jkt");

    // Each child: signed by the exact key the parent's cnf commits to.
    let leafPayload = rootPayload;
    for (let i = 1; i < chain.length; i++) {
      const header = decodeProtectedHeader(chain[i] as string);
      const jwk = header.jwk as (JWK & { d?: string }) | undefined;
      if (!jwk) throw new Error("attenuation child missing header jwk");
      if (jwk.d !== undefined) throw new Error("attenuation child header jwk carries private key material");
      if ((await calculateJwkThumbprint(jwk as never)) !== parentCnfJkt) {
        throw new Error("attenuation child not signed by the parent cnf key");
      }
      const { payload } = await jwtVerify(chain[i] as string, jwk as never, { algorithms: ["ES256"] });
      parentCnfJkt = (payload.cnf as { jkt?: string } | undefined)?.jkt;
      if (!parentCnfJkt) throw new Error("attenuation child missing cnf.jkt");
      leafPayload = payload;
    }

    // Keyless structural checks: monotonicity, mission invariance, aud/exp
    // nesting, depth cap, and par_hash linkage over the exact wire bytes.
    const verified = verifyAttenuationChain(chain);
    if (!verified.ok) throw new Error(`attenuation chain invalid: ${verified.reason}`);

    // Proof-of-possession under the LEAF's cnf key.
    const leafCnf = (leafPayload.cnf as { jkt?: string } | undefined)?.jkt;
    if (!leafCnf) throw new Error("attenuation leaf missing cnf.jkt");
    const proofHeader = decodeProtectedHeader(dpopProof);
    if ((await calculateJwkThumbprint(proofHeader.jwk as never)) !== leafCnf) {
      throw new Error("DPoP key does not match leaf cnf.jkt");
    }
    const { payload: proof } = await jwtVerify(dpopProof, proofHeader.jwk as never, {
      typ: "dpop+jwt",
      algorithms: ["ES256"],
    });
    if (proof.htu !== htu || proof.htm !== htm) throw new Error("DPoP htu/htm mismatch");

    // Effective authority = the leaf's narrowed tools, as {resource, actions}.
    const byResource = new Map<string, Set<string>>();
    for (const toolId of Object.keys(toolsOf(verified.leaf))) {
      const { resource, action } = parseAatToolId(toolId);
      (byResource.get(resource) ?? byResource.set(resource, new Set()).get(resource))?.add(action);
    }
    const leafAuthority = [...byResource].map(([resource, actions]) => ({ resource, actions: [...actions] }));

    // @spec cross-domain#mission-subject — the root's origin principal,
    // where the profile applies, carried unchanged into TokenFacts the same
    // way as the other credential classes.
    const missionClaim = readTxnMissionClaim(rootPayload.mission);
    return {
      sub: (leafPayload.sub ?? rootPayload.sub) as string,
      clientId: rootPayload.client_id as string,
      iss: this.deps.issuer,
      mission: {
        id: rootMission.id,
        issuer: rootMission.issuer,
        authority_hash: rootMission.authority_hash,
        ...(missionClaim?.subject ? { subject: missionClaim.subject } : {}),
      },
      ...(missionClaim ? { missionClaim } : {}),
      cnfJkt: leafCnf,
      leafAuthority,
    };
  }

  /** Whether the transaction-assurance tier (M5) is configured on this server. */
  hasTransactionTier(): boolean {
    return this.deps.transaction !== undefined;
  }

  /**
   * Mission-scoped tools/list (@spec least exposure, D22/E): only tools whose
   * action is within the mission's authority are shown.
   */
  toolsList(token: TokenFacts): ToolDef[] {
    const loaded = loadCheckedView(this.deps.loadView, { id: token.mission.id, issuer: token.mission.issuer });
    if (!loaded) return [];
    const granted = new Set(loaded.view.authority_set.flatMap((e) => e.actions));
    return TOOLS.filter((t) => granted.has(t.action));
  }

  /**
   * Read-only tool call: enforce then execute. For a `bindsVendorScope`
   * read (list_invoices), `beforeReverify` is a test hook to mutate Mission
   * state in the decision->execute window, mirroring {@link callWriteTool}'s
   * hook of the same name for the write path's TOCTOU reverification.
   */
  async callReadTool(
    tool: string,
    args: Record<string, unknown>,
    token: TokenFacts,
    beforeReverify?: () => void,
    signals?: RequestSignals,
  ): Promise<{
    ok: boolean;
    result?: unknown;
    denial_reason?: string;
    refusal_reason?: string;
    insufficient_authorization?: InsufficientAuthorization;
  }> {
    if (token.txn) return { ok: false, refusal_reason: "txn_action_mismatch" };
    const res = await this.deps.pep.enforce(tool, args, token, undefined, signals);
    if (!res.permitted) {
      return {
        ok: false,
        ...(res.denial_reason ? { denial_reason: res.denial_reason } : {}),
        ...(res.refusal_reason ? { refusal_reason: res.refusal_reason } : {}),
        ...(res.insufficient_authorization ? { insufficient_authorization: res.insufficient_authorization } : {}),
      };
    }
    if (res.listEffective) {
      beforeReverify?.();
      // @spec runtime#read-binding: reverify the bound list read's
      // normalized parameters immediately before execution, exactly as
      // callWriteTool/callTransactionTool already do for a write.
      const digest = permitConditions(res.decision)?.parameter_digest as string | undefined;
      if (!digest || !(await this.deps.pep.reverifyList(res.listEffective, digest, token))) {
        return { ok: false, refusal_reason: "parameter_mismatch" };
      }
    }
    return { ok: true, result: this.execute(tool, args, res.list_vendor_scope) };
  }

  /**
   * Write tool call, two-phase for TOCTOU (@spec operation-profile): enforce
   * (decision) -> reverify effective params against fresh store state -> execute.
   * `beforeReverify` is a test hook to mutate state in the decision->execute window.
   */
  async callWriteTool(
    tool: string,
    args: Record<string, unknown>,
    token: TokenFacts,
    beforeReverify?: () => void,
    signals?: RequestSignals,
  ): Promise<{
    ok: boolean;
    result?: unknown;
    denial_reason?: string;
    refusal_reason?: string;
    insufficient_authorization?: InsufficientAuthorization;
  }> {
    if (token.txn) return { ok: false, refusal_reason: "txn_action_mismatch" };
    const res = await this.deps.pep.enforce(tool, args, token, undefined, signals);
    if (!res.permitted || !res.effective || !res.decision) {
      return {
        ok: false,
        ...(res.denial_reason ? { denial_reason: res.denial_reason } : {}),
        ...(res.refusal_reason ? { refusal_reason: res.refusal_reason } : {}),
        ...(res.insufficient_authorization ? { insufficient_authorization: res.insufficient_authorization } : {}),
      };
    }
    beforeReverify?.();
    const digest = permitConditions(res.decision)?.parameter_digest as string;
    if (!(await this.deps.pep.reverify(res.effective, digest, token))) {
      return { ok: false, refusal_reason: "parameter_mismatch" };
    }
    return { ok: true, result: this.execute(tool, args) };
  }

  /**
   * @spec runtime transaction-assurance tier, D36 state machine.
   * High-consequence tools (execute_wire_transfer, send_remittance_email):
   * enforce (permit) -> redeem single-use permit -> reverify (TOCTOU) ->
   * commit connector (the commit point) -> Execution Evidence -> reconcile.
   * `beforeCommit` is a test hook for the decision->commit window.
   */
  async callTransactionTool(
    tool: string,
    args: Record<string, unknown>,
    token: TokenFacts,
    beforeCommit?: () => void,
    signals?: RequestSignals,
  ): Promise<TransactionToolResult> {
    const tx = this.deps.transaction;
    if (!tx) throw new Error("transaction tier not configured");

    // @spec txn-authorization#offline-verification — where the credential IS a
    // transaction token, it is matched against the operation THIS resource
    // retained when it issued the challenge, with no call to the Transaction
    // Authorization Server on the request path. The resource reads no approval
    // object off the token: the action-approval context below is derived only
    // from the typed verified claims.
    let derivedApproval: ActionApprovalInput | undefined;
    let consumedTxn: string | undefined;
    if (token.txn) {
      const verified = this.verifyChallengedOperation(token.txn, tool, args);
      if (!verified.ok) return { ok: false, refusal_reason: verified.refusal_reason };
      derivedApproval = verified.approval;
      consumedTxn = token.txn.txn;
    }

    const res = await this.deps.pep.enforce(tool, args, token, derivedApproval, signals);
    // @spec txn-authorization#offline-verification — the resource RETAINS the
    // pending operation when it issues the challenge; the later transaction
    // token is matched against THAT record, never against its own assertions.
    if (res.challenge) this.txnPending.put(res.challenge.pending);
    if (!res.permitted || !res.effective || !res.decision) {
      return {
        ok: false,
        ...(res.denial_reason ? { denial_reason: res.denial_reason } : {}),
        ...(res.refusal_reason ? { refusal_reason: res.refusal_reason } : {}),
        ...(res.access_request ? { access_request: res.access_request } : {}),
        ...(res.challenge
          ? {
              error: res.challenge.error,
              transaction_challenge: res.challenge.transaction_challenge,
            }
          : {}),
        ...(res.insufficient_authorization ? { insufficient_authorization: res.insufficient_authorization } : {}),
      };
    }
    const digest = permitConditions(res.decision)?.parameter_digest as string;
    const permitId = res.decision.context.decision_id as string;
    const opKey = operationKey(token.mission.id, res.effective.action, digest);

    // Single-use permit redemption (D28): replay -> permit_consumed refusal.
    const redeem = tx.engine.redeemPermit({
      permitId,
      opKey,
      missionId: token.mission.id,
      action: res.effective.action,
      leaseSeconds: 30,
    });
    if (!redeem.ok) return { ok: false, refusal_reason: redeem.reason ?? "permit_consumed" };

    beforeCommit?.();

    // TOCTOU re-verify inside the lease, before commit.
    if (!tx.engine.leaseValid(opKey) || !(await this.deps.pep.reverify(res.effective, digest, token))) {
      tx.engine.advance(opKey, "abandoned");
      return { ok: false, refusal_reason: "parameter_mismatch" };
    }

    // @spec txn-authorization#offline-verification — atomic first use of the
    // resource-scoped `txn`, LINEARIZABLE across every replica that can execute
    // this operation and committed BEFORE the irreversible effect. A second,
    // distinct token jti for an already-consumed txn is the same replay: it is
    // refused as duplicate_suppressed and never executed as a new attempt. If
    // the consumption store is unavailable the resource fails CLOSED.
    if (consumedTxn !== undefined) {
      let outcome: TxnConsumeOutcome;
      try {
        outcome = this.txnConsumption.consume(CANONICAL_RESOURCE, consumedTxn, opKey);
      } catch {
        tx.engine.advance(opKey, "abandoned");
        return { ok: false, refusal_reason: "consumption_unavailable" };
      }
      if (!outcome.first) {
        const prior = outcome.record;
        // A DIFFERENT operation under an already-consumed txn, or a txn whose
        // effect already committed, is a replay: refused, never executed as a
        // new attempt.
        if (prior.state === "effect_committed" || prior.opKey !== opKey) {
          tx.engine.advance(opKey, "abandoned");
          return { ok: false, refusal_reason: "duplicate_suppressed" };
        }
        // Otherwise this is THIS operation, consumed but never committed: a
        // crash landed in the window between taking the single use and the
        // effect. Refusing it as a duplicate would strand an operation that
        // never happened. It RESUMES instead -- the connector commit below is
        // idempotent by `op_key`, so at most one effect exists either way.
      }
    }

    // Commit point (D36): connector accepts with the idempotency key.
    const invoice = this.deps.payments.getInvoice(res.effective.invoice_id);
    const commit =
      tool === "execute_wire_transfer"
        ? tx.connectors.postWire({
            opKey,
            invoiceId: res.effective.invoice_id,
            payeeAccount: res.effective.payee_account,
            amount: res.effective.amount.amount,
            currency: res.effective.amount.currency,
            permitId,
            missionId: token.mission.id,
          })
        : tx.connectors.sendEmail({
            opKey,
            invoiceId: res.effective.invoice_id,
            to: `${res.effective.vendor_id}@vendor.example`,
            permitId,
            missionId: token.mission.id,
          });
    tx.engine.advance(opKey, "connector_committed");
    // The effect is durable, so the consumption row says so. A failure to write
    // it leaves the row at `consumed`, which is exactly the resumable state: a
    // later presentation of the same txn under the same operation re-runs the
    // idempotent commit and settles it, and no second effect can exist.
    if (consumedTxn !== undefined) {
      try {
        this.txnConsumption.commit(CANONICAL_RESOURCE, consumedTxn);
      } catch {
        /* self-healing on the resume path above */
      }
    }

    // Execution Evidence, then reconciliation state.
    // @spec runtime-evidence#execution-evidence-object (issue #649):
    // `outcome` is `completed` whether or not the connector commit itself was
    // a dedup of an already-committed effect (`commit.deduped`): either way
    // the action's final disposition IS completed, and the spec's outcome
    // enum has no distinct "deduped" value (dedup is delivery/idempotency
    // bookkeeping, not an execution outcome). `commit.deduped` stays on the
    // caller's own return value (`ok: true, deduped`) below, unchanged.
    // Both parameter-digest members are the SAME `digest`: `reverify()`
    // above already re-confirmed the effective parameters match what the
    // permit authorized before this commit point, the binding-held case.
    await tx.evidence.recordExecution(CANONICAL_RESOURCE, "executor", {
      permitId,
      opKey,
      evaluation_id: permitId,
      mission_id: token.mission.id,
      audience: CANONICAL_RESOURCE,
      authorized_parameter_digest: digest,
      effective_parameter_digest: digest,
      outcome: "completed",
      ...(token.jti
        ? {
            hop_reference: {
              jti: token.jti,
              mission_id: token.mission.id,
              ...(token.identityContinuationHandle
                ? { continuation_handle: token.identityContinuationHandle }
                : {}),
            },
          }
        : {}),
    });
    tx.engine.advance(opKey, "evidence_emitted");
    tx.engine.advance(opKey, "reconciled");

    return {
      ok: true,
      deduped: commit.deduped,
      result: { executed: true, invoice_id: res.effective.invoice_id, op_key: opKey, payee: invoice?.payee_account },
    };
  }

  /**
   * @spec txn-authorization#offline-verification — the operation-scoped half of
   * the verification, taken where the tool and its arguments are known: the
   * credential is good for the CHALLENGED operation and nothing else, so a call
   * whose action or RECOMPUTED `parameter_digest` is not the retained
   * operation's is refused. The digest is recomputed from authoritative store
   * state, never read off the token.
   */
  private verifyChallengedOperation(
    credential: TxnCredential,
    tool: string,
    args: Record<string, unknown>,
  ): { ok: true; approval: ActionApprovalInput } | { ok: false; refusal_reason: string } {
    const pending = this.txnPending.get(CANONICAL_RESOURCE, credential.txn);
    if (!pending) return { ok: false, refusal_reason: "txn_unknown" };
    if (TOOL_ACTIONS[tool]?.action !== pending.action) {
      return { ok: false, refusal_reason: "txn_action_mismatch" };
    }
    const recomputed = this.recomputeParameterDigest(tool, args);
    if (
      recomputed === undefined ||
      recomputed !== pending.parameterDigest ||
      credential.parameterDigest !== recomputed
    ) {
      return { ok: false, refusal_reason: "txn_parameter_mismatch" };
    }

    // A txn whose EFFECT already committed is a replay whatever token jti
    // carries it. A txn merely `consumed` is not decidable here: it may be this
    // very request resuming after a crash between consumption and the effect,
    // and only the commit point holds both operation keys. The authoritative,
    // atomic decision is taken there; this read only lets the resource answer
    // the settled case with the right reason instead of a later one.
    try {
      if (this.txnConsumption.get(CANONICAL_RESOURCE, credential.txn)?.state === "effect_committed") {
        return { ok: false, refusal_reason: "duplicate_suppressed" };
      }
    } catch {
      return { ok: false, refusal_reason: "consumption_unavailable" };
    }

    // The action-approval context the PDP re-evaluates is derived ONLY from
    // these typed, verified claims: the token carries no approval object.
    return {
      ok: true,
      approval: {
        id: `txn:${credential.jti}`,
        approved_at: new Date(credential.iatS * 1000).toISOString(),
        approved_until: new Date(credential.expS * 1000).toISOString(),
        parameter_digest: recomputed,
      },
    };
  }

  /**
   * @spec runtime (parameter binding) — recompute the operation's digest from
   * authoritative store state, exactly as the enforcement path does. The token
   * is matched against THIS value, never against a digest it supplies.
   */
  private recomputeParameterDigest(tool: string, args: Record<string, unknown>): string | undefined {
    const mapping = TOOL_ACTIONS[tool];
    if (!mapping?.needsInvoice) return undefined;
    const invoice = this.deps.payments.getInvoice(String(args.invoice_id ?? ""));
    const vendor = invoice ? this.deps.payments.getVendor(invoice.vendor_id) : undefined;
    if (!invoice || !vendor) return undefined;
    return parameterDigest(
      buildEffectiveParams({ action: mapping.action, invoice, vendor, resource: CANONICAL_RESOURCE }),
    );
  }

  /**
   * @spec runtime#read-binding — `listVendorScope` is the PEP's bound result
   * scope for `list_invoices` (`Pep.enforceInner`'s `bindsVendorScope`
   * branch): the vendor ids the permitted read is limited to, absent only
   * when the Mission's entry is unconstrained and no `vendor_id` was
   * requested. The store filter on `args.vendor_id` stays as a first pass;
   * this filter is the actual binding enforcement, applied regardless of
   * what the caller asked for.
   */
  private execute(tool: string, args: Record<string, unknown>, listVendorScope?: string[]): unknown {
    switch (tool) {
      case "list_invoices": {
        const invoices = this.deps.payments.listInvoices(args.vendor_id ? String(args.vendor_id) : undefined);
        return listVendorScope ? invoices.filter((inv) => listVendorScope.includes(inv.vendor_id)) : invoices;
      }
      case "get_invoice":
        return this.deps.payments.getInvoice(String(args.invoice_id));
      case "lookup_vendor":
        return this.deps.payments.getVendor(String(args.vendor_id));
      case "schedule_payment":
        return { scheduled: true, invoice_id: String(args.invoice_id) };
      default:
        return { ok: true };
    }
  }
}

export { TOOL_ACTIONS };
