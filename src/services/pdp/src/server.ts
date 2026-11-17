/**
 * @spec runtime#decision-channel — a reference remote decision channel: the
 * PDP as an out-of-process HTTP listener, separated from the PEP by a real
 * network hop, rather than the co-resident direct function call the
 * reference deployment used exclusively until now. The draft's baseline
 * requirement for a non-co-resident PEP/PDP boundary: "the decision request
 * and response MUST be integrity-protected and the parties MUST
 * authenticate each other. The PDP MUST accept credential-derived inputs
 * only from a PEP authorized for the declared enforcement scope." This
 * module is the PDP side; {@link ./client.js} is the PEP side.
 *
 * The channel authenticates with a per-PEP shared secret, keyed by a
 * registered PEP identity, and MACs (domain-separated, {@link
 * ./channel-mac.js}) the exact request and response bytes: "a signed
 * decision request and response," one of the draft's named alternatives to
 * mutual TLS. A request that fails authentication, integrity, the replay
 * window, or the scope-authorization check is refused BEFORE `evaluate()`
 * is ever called: the PDP performs zero decision work on an unverified
 * channel.
 *
 * This is a minimal reference topology proving the contract, not a
 * production PDP service: no TLS termination, no persistent nonce store
 * across restarts, no PEP registry beyond the in-memory map the caller
 * supplies. The request body read is bounded ({@link
 * PdpRemoteServerConfig.maxBodyBytes}): an oversized body is refused
 * before it is buffered, so the fail-closed channel behavior this module
 * demonstrates is not obscured by an unbounded read.
 */

import type { ApprovalVerification } from "./approval-binding.js";
import type { ExecutionCapabilityDeclaration } from "./enforcement-scope.js";
import { assertHistoryBinding, type HistoryBinding } from "./history.js";
import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import { contractCanEstablish, type EvaluationContextBindingDeclarations, type OperationContract } from "@mission/core";
import { macEqualHex, macHex, REQUEST_MAC_DOMAIN, RESPONSE_MAC_DOMAIN, sha256Hex } from "./channel-mac.js";
import { requestMacParts } from "./client.js";
import type { DecisionEvidenceEmitter } from "./decision-evidence.js";
import { type ClaimChannel, claimChannelFor } from "./decision-point.js";
import type { DurationLeaseDomain } from "./duration-lease.js";
import {
  carriesSpeculativeItems,
  type Decision,
  type DecisionOptions,
  DecisionRequestRefused,
  type EvaluateOptions,
  type EvaluationRequest,
  evaluate,
  type PdpRefusalRecorder,
  recordPdpRefusal,
  type SpeculativeItemResult,
  SpeculativeRequestMisdirected,
  speculate,
  speculativeRequestFault,
} from "./evaluate.js";
import {
  type ClaimRequester,
  type ClaimResolution,
  ClaimDomainUnavailableError,
  type ConsumptionStatusFn,
  type RedeemingExecutionFn,
  type IdempotencyClaimDomain,
} from "./idempotency-claims.js";
import { type ResourcePolicy, ResourcePolicyUnavailableError } from "./resource-policy.js";

/**
 * One PEP the PDP recognizes: its shared authentication secret and the
 * enforcement scopes (audiences) it is authorized to submit decision
 * requests for (@spec runtime#runtime-conformance: "the remote
 * decision-channel trust mode for every PEP/PDP boundary").
 */
export interface AuthorizedPep {
  secret: string;
  /**
   * @spec runtime#boundary-identifier (#853, D487): the boundary identifiers
   * this PEP is authorized for. A function is read on every request, so the
   * registration follows the declared statement version in force and a
   * cutover moves it with every other consumer.
   */
  scopes: readonly string[] | (() => readonly string[]);
  /**
   * @spec authzen#pdp-request consistency check 11, resource-access#resource-matching
   * (#1276, D457): the operation targets within this PEP's declared
   * enforcement scope, as its registered operation contracts establish them,
   * compared exactly. A decision request naming any other target is refused
   * before evaluation as `operation_target_invalid`. Absent, and with no
   * {@link operationContracts} registered, the PEP may name only a target
   * equal to one of its `scopes`, the service-level contract over its own
   * enforcement scope; this is a channel restriction, never an entry-match
   * fallback, and it narrows rather than widens.
   */
  operationTargets?: readonly string[];
  /**
   * @spec authzen#pdp-request consistency check 11, authzen#context-operation-target
   * (#1276, D457): the operation contracts this PEP is registered for, for
   * the targets an argument-derived contract establishes, which no finite
   * list names. A target one of them can establish (`contractCanEstablish`:
   * a service-level contract's service, or an argument-derived contract's
   * template expanded with one canonically encoded value) is within the
   * PEP's scope. Coverage only: it grants no authority, and the entry match
   * still decides.
   */
  operationContracts?: readonly OperationContract[];
}

/**
 * @spec authzen#pdp-request consistency check 11 (#1276, D457): whether a
 * string target is within the requesting PEP's registration: a listed
 * target, or one a registered operation contract establishes. With neither
 * registered, only a target equal to one of the PEP's scopes.
 */
function targetWithinRegistration(pep: AuthorizedPep, scopes: readonly string[], target: string): boolean {
  if (pep.operationTargets === undefined && pep.operationContracts === undefined) return scopes.includes(target);
  return (
    (pep.operationTargets ?? []).includes(target) ||
    (pep.operationContracts ?? []).some((contract) => contractCanEstablish(contract, target))
  );
}

export interface PdpRemoteServerConfig {
  /** Registered PEPs, keyed by the identity they present in X-Pdp-Pep-Id. */
  peps: ReadonlyMap<string, AuthorizedPep>;
  /**
   * Resolves the decision options (Mission view, FGA client, policy) for a
   * given request. A reference server serves one or many Missions through
   * this indirection; tests fix it to a constant. It carries no emission
   * path: {@link PdpRemoteServerConfig.evidence} is bound once, at server
   * construction, on this side of the channel.
   */
  getOptions: (req: EvaluationRequest) => DecisionOptions | Promise<DecisionOptions>;
  /**
   * @spec runtime-evidence#decision-evidence-object,
   * runtime#agent-isolated-evidence-emission (#741, PR #753 review) — this
   * PDP's Decision Evidence emission path, held on the PDP side of the
   * network hop. The PEP across the channel receives the signed record on
   * the decision response and the verification material for it, never the
   * emitter: it submits requests and verifies answers, and holds no way to
   * mint a record under this PDP's identity.
   */
  evidence?: DecisionEvidenceEmitter;
  /** Replay/freshness window for X-Pdp-Issued-At, seconds. Default 30. */
  replayWindowSeconds?: number;
  /** Maximum accepted request body size, bytes. Default 65536 (64 KiB); a larger body is refused before being buffered. */
  maxBodyBytes?: number;
  /**
   * Injectable in place of the real `evaluate`, so a test can prove exactly
   * how many times the PDP's decision function ran (zero on every
   * channel-boundary refusal). Defaults to the real `evaluate`.
   */
  evaluateFn?: typeof evaluate;
  /**
   * @spec authzen#speculative-evaluations (#2067, D1313): whether this PDP
   * serves speculative evaluation at `POST /speculate`. Absent or false, the
   * route does not exist (404) and nothing on it reaches any decision
   * function: a speculation never falls back to ordinary evaluation.
   */
  speculativeEvaluations?: boolean;
  /** Injectable in place of the real `speculate`, as `evaluateFn` is for `evaluate`. */
  speculateFn?: typeof speculate;
  /**
   * @spec runtime#idempotency (#917): this PDP's claim domain, bound on this
   * side of the network hop exactly as `evidence` is: a request option naming
   * another is stripped.
   */
  claims?: IdempotencyClaimDomain;
  /**
   * @spec runtime#input-resource-policy (#828): this PDP's Resource policy,
   * bound on this side of the network hop exactly as `claims` is: a request
   * option naming another is stripped. Absent here, the decision function
   * must bind one (a decision point's does); the default `evaluate` refuses
   * to decide without one.
   */
  resourcePolicy?: ResourcePolicy;
  /**
   * @spec authzen#pdp-request consistency check 11 (#1276, D457): this PDP's
   * Refusal Record path for a request refused before evaluation, bound on
   * this side of the network hop exactly as `evidence` is: a request option
   * naming another is stripped. It records the channel's own out-of-scope
   * target refusal and is handed to the decision function.
   */
  refusals?: PdpRefusalRecorder;
  /**
   * @spec metering#lease-renewal (#1440): this PDP's duration leases, bound on
   * this side of the network hop exactly as `claims` is: a request option
   * naming another is stripped.
   */
  durationLeases?: DurationLeaseDomain;
  /**
   * @spec authzen#context-action-phase (#1629, D744): the actions this PDP's
   * trusted operation declaration places at the phases of a compound action,
   * bound on this side of the network hop exactly as `claims` is: a request
   * option naming another is stripped. A request for one with no
   * `context.action_phase` is refused before evaluation as `phase_invalid`.
   */
  phasedActions?: ReadonlySet<string>;
  /**
   * @spec authzen#context-evaluation-binding (#773): this PDP's
   * Evaluation-Context Binding claim and declaration, bound on this side of
   * the network hop exactly as `phasedActions` is. Absent, `evaluate` reads
   * the deployment's statement.
   */
  evaluationContextBinding?: EvaluationContextBindingDeclarations;
  /**
   * @spec runtime#classification (#1994): this PDP's operation declarations,
   * the source of the action class set, bound on this side of the network
   * hop exactly as `evaluationContextBinding` is. Absent, `evaluate` reads
   * the deployment's statement.
   */
  operationDeclarations?: ReadonlyArray<ExecutionCapabilityDeclaration>;
  /**
   * @spec authzen#context-history (#2015): this PDP's history policy,
   * retained-evidence reader and key resolver, bound on this side of the
   * network hop exactly as `operationDeclarations` is.
   */
  history?: HistoryBinding;
  /**
   * @spec authzen#context-approval (#2067, D1313): this PDP's trust anchors
   * for integrity-protected approval material, bound on this side of the
   * network hop exactly as `history` is. Absent, no presented approval
   * verifies.
   */
  approvalVerification?: ApprovalVerification;
  /**
   * The settlement and reconciliation channel for one authenticated
   * requester. Defaults to one over {@link PdpRemoteServerConfig.claims}.
   */
  claimsFor?: (requester: ClaimRequester, redeemingExecution?: RedeemingExecutionFn) => ClaimChannel;
  /**
   * @spec runtime#idempotency, retransmission condition 6 (#917): a
   * registered PEP's read-only consumption-status capability, injected by
   * trusted assembly beside the PEP's registration. Absent for a PEP, its
   * answer is `unknown`, which suppresses every retransmission to it.
   */
  consumptionStatus?: (pepId: string) => ConsumptionStatusFn | undefined;
  /**
   * #1016 review round 2: a registered PEP's read-only answer naming the
   * attempt that redeemed a permit, injected beside its registration. Absent,
   * no failed or suppressed outcome from that PEP settles.
   */
  redeemingExecution?: (pepId: string) => RedeemingExecutionFn | undefined;
}

export interface PdpHttpServerHandle {
  url: string;
  port: number;
  close: () => Promise<void>;
}

/** One request that passed every channel gate: authenticated, fresh, unreplayed, parsed and in scope. */
interface AuthenticatedRequest {
  pepId: string;
  nonce: string;
  issuedAt: string;
  rawBody: string;
  body: Record<string, unknown>;
  requester: ClaimRequester;
}

type ChannelRefusalReason =
  | "missing_channel_authentication"
  | "unknown_pep"
  | "invalid_request_signature"
  | "stale_or_future_request"
  | "replayed_request"
  | "malformed_body"
  | "pep_not_authorized_for_scope"
  | "operation_target_invalid"
  | "request_body_too_large";

function headerString(v: string | string[] | undefined): string | undefined {
  if (typeof v === "string") return v;
  if (Array.isArray(v) && v.length === 1 && typeof v[0] === "string") return v[0];
  return undefined;
}

function sendRefusal(
  res: ServerResponse,
  status: number,
  reason: ChannelRefusalReason,
  extraHeaders: Record<string, string> = {},
): void {
  res.writeHead(status, { "content-type": "application/json", ...extraHeaders });
  res.end(JSON.stringify({ error: "decision_channel_refused", reason }));
}

/**
 * @spec authzen#speculative-evaluations (#2067, D1313): the AuthZEN request
 * error for a speculative request sent to the evaluation path. Unsigned and
 * carrying no decision, so no client can read it as one.
 */
function sendSpeculativeMisdirected(res: ServerResponse): void {
  res.writeHead(400, { "content-type": "application/json" });
  res.end(JSON.stringify({ error: "invalid_request", reason: "speculative_request" }));
}

/**
 * Start the reference PDP HTTP listener on an ephemeral 127.0.0.1 port.
 * Every request to POST /evaluate runs the authentication, integrity,
 * freshness/replay, and scope-authorization gates, in that order, before
 * `evaluate()` is invoked; a failure at any gate short-circuits with zero
 * decision work.
 */
export async function createPdpHttpServer(config: PdpRemoteServerConfig): Promise<PdpHttpServerHandle> {
  // @spec authzen#context-history (#2017): refused where it is bound, before
  // the server listens.
  if (config.history !== undefined) assertHistoryBinding(config.history);
  const evaluateImpl = config.evaluateFn ?? evaluate;
  const speculateImpl = config.speculateFn ?? speculate;
  const replayWindowMs = (config.replayWindowSeconds ?? 30) * 1000;
  const maxBodyBytes = config.maxBodyBytes ?? 65536;
  // pepId:nonce -> expiry ms. A reference adapter's in-memory replay guard;
  // a production deployment would use a shared, persistent store.
  const seenNonces = new Map<string, number>();

  function pruneExpired(now: number): void {
    for (const [key, expiry] of seenNonces) {
      if (expiry < now) seenNonces.delete(key);
    }
  }

  /**
   * The channel gates every route runs, in order: a bounded body read,
   * authentication and integrity (the request MAC, covering the epoch header
   * when one is sent), freshness and replay, a parsed body, and the scope
   * check on the audience `audienceOf` names. A failure at any gate is
   * answered here and returns `undefined`: the route does no work at all.
   * `audienceOf: null` leaves the scope check to a route that applies it to
   * each item it serves (`/speculate`), after every other gate has passed.
   */
  async function authenticate(
    req: IncomingMessage,
    res: ServerResponse,
    audienceOf: ((body: Record<string, unknown>) => unknown) | null,
    targetOf?: (body: Record<string, unknown>) => unknown,
  ): Promise<AuthenticatedRequest | undefined> {
    const chunks: Buffer[] = [];
    let receivedBytes = 0;
    for await (const chunk of req as AsyncIterable<Buffer>) {
      receivedBytes += chunk.length;
      if (receivedBytes > maxBodyBytes) {
        // The rest of the oversized body is never read, so this connection
        // cannot be reused for a later request on the same socket: closed
        // explicitly rather than left for the client to discover.
        sendRefusal(res, 413, "request_body_too_large", { connection: "close" });
        req.destroy();
        return undefined;
      }
      chunks.push(chunk);
    }
    const rawBody = Buffer.concat(chunks).toString("utf8");

    const pepId = headerString(req.headers["x-pdp-pep-id"]);
    const signature = headerString(req.headers["x-pdp-signature"]);
    const nonce = headerString(req.headers["x-pdp-nonce"]);
    const issuedAt = headerString(req.headers["x-pdp-issued-at"]);
    const pepEpoch = headerString(req.headers["x-pdp-pep-epoch"]);

    if (pepId === undefined || signature === undefined || nonce === undefined || issuedAt === undefined) {
      sendRefusal(res, 401, "missing_channel_authentication");
      return undefined;
    }
    const pep = config.peps.get(pepId);
    if (!pep) {
      sendRefusal(res, 401, "unknown_pep");
      return undefined;
    }

    // Integrity + mutual authentication: the request's exact bytes, bound to
    // this PEP identity, nonce, issuance time and (when sent) its redemption
    // store's epoch, must match a MAC only a holder of this PEP's registered
    // secret could have produced.
    const expectedSignature = macHex(pep.secret, REQUEST_MAC_DOMAIN, requestMacParts(pepId, nonce, issuedAt, rawBody, pepEpoch));
    if (!macEqualHex(signature, expectedSignature)) {
      sendRefusal(res, 401, "invalid_request_signature");
      return undefined;
    }

    const now = Date.now();
    const issuedAtMs = Number(issuedAt);
    if (!Number.isFinite(issuedAtMs) || Math.abs(now - issuedAtMs) > replayWindowMs) {
      sendRefusal(res, 401, "stale_or_future_request");
      return undefined;
    }
    pruneExpired(now);
    const nonceKey = `${pepId}:${nonce}`;
    if (seenNonces.has(nonceKey)) {
      sendRefusal(res, 401, "replayed_request");
      return undefined;
    }
    seenNonces.set(nonceKey, now + replayWindowMs);

    let body: unknown;
    try {
      body = JSON.parse(rawBody);
    } catch {
      sendRefusal(res, 400, "malformed_body");
      return undefined;
    }
    if (body === null || typeof body !== "object" || Array.isArray(body)) {
      sendRefusal(res, 400, "malformed_body");
      return undefined;
    }
    if (audienceOf === null) {
      return {
        pepId,
        nonce,
        issuedAt,
        rawBody,
        body: body as Record<string, unknown>,
        requester: { pep_id: pepId, pep_epoch: pepEpoch ?? `unbound:${randomUUID()}` },
      };
    }
    const audience = audienceOf(body as Record<string, unknown>);
    if (typeof audience !== "string") {
      sendRefusal(res, 400, "malformed_body");
      return undefined;
    }
    // @spec runtime#decision-channel: "The PDP MUST accept credential-derived
    // inputs only from a PEP authorized for the declared enforcement scope."
    // Checked BEFORE getOptions/evaluate touch anything derived from the
    // request: an unauthorized-for-scope PEP gets zero decision work, not a
    // decision made and then discarded.
    const scopes = typeof pep.scopes === "function" ? pep.scopes() : pep.scopes;
    if (!scopes.includes(audience)) {
      sendRefusal(res, 403, "pep_not_authorized_for_scope");
      return undefined;
    }
    // @spec authzen#pdp-request consistency check 11 (#1276, D457): the
    // operation target is checked on its own, never inferred from the scope
    // check above. A string target outside the requesting PEP's enforcement
    // scope is refused before evaluation and recorded as a Refusal Record
    // `operation_target_invalid`, with zero decision work. A missing or
    // non-string target reaches `evaluate`, which refuses it the same way.
    const target = targetOf?.(body as Record<string, unknown>);
    if (typeof target === "string" && !targetWithinRegistration(pep, scopes, target)) {
      await recordPdpRefusal(config.refusals, "operation_target_invalid", (body as Record<string, unknown>).request);
      sendRefusal(res, 403, "operation_target_invalid");
      return undefined;
    }
    return {
      pepId,
      nonce,
      issuedAt,
      rawBody,
      body: body as Record<string, unknown>,
      // @spec runtime#idempotency, retransmission condition 5 (#917): the
      // requester is the authenticated PEP and its MAC-covered epoch. A
      // request without one gets an epoch nothing else can present, so no
      // stored decision is ever returned to it.
      requester: { pep_id: pepId, pep_epoch: pepEpoch ?? `unbound:${randomUUID()}` },
    };
  }

  /** A 200 bound to the request that produced it, not just to its own bytes. */
  function sendSigned(res: ServerResponse, authed: AuthenticatedRequest, payload: unknown): void {
    const pep = config.peps.get(authed.pepId) as AuthorizedPep;
    const body = JSON.stringify(payload);
    const status = 200;
    // Bound to the request that produced it, not just its own bytes: a
    // response MAC over the body alone lets an intermediary replay an
    // old, validly signed permit as the answer to a different request.
    const responseSignature = macHex(pep.secret, RESPONSE_MAC_DOMAIN, [
      authed.pepId,
      authed.nonce,
      authed.issuedAt,
      sha256Hex(authed.rawBody),
      String(status),
      body,
    ]);
    res.writeHead(status, { "content-type": "application/json", "x-pdp-signature": responseSignature });
    res.end(body);
  }

  async function handleEvaluate(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const authed = await authenticate(
      req,
      res,
      (body) => {
        // @spec authzen#pdp-request: the enforcement scope a request names is
        // its `resource.properties.audience`.
        const request = body.request as EvaluationRequest | undefined;
        return request?.resource?.properties?.audience;
      },
      // #1276, D457: the operation target the entry match reads.
      (body) => (body.request as EvaluationRequest | undefined)?.resource?.properties?.operation_target,
    );
    if (!authed) return;
    const evalRequest = authed.body.request as EvaluationRequest;
    // @spec authzen#speculative-evaluations (#2067, D1313): an evaluation
    // request carrying the speculative request's `items` member is an AuthZEN
    // request error, refused before any decision work and never evaluated as
    // an attempt, whether or not this PDP serves speculation.
    if (carriesSpeculativeItems(evalRequest)) {
      sendSpeculativeMisdirected(res);
      return;
    }
    const opts = await serverOptions(evalRequest, authed);
    let decision: Decision;
    try {
      decision = await evaluateImpl(evalRequest, opts);
    } catch (e) {
      // @spec authzen#pdp-request consistency check 11 (#1276, D457),
      // authzen#context-action-phase (#1629): a request refused before
      // evaluation (already recorded) gets a refusal, never a signed decision.
      if (e instanceof DecisionRequestRefused) {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "decision_request_refused", reason: e.denial_reason }));
        return;
      }
      if (e instanceof SpeculativeRequestMisdirected) {
        sendSpeculativeMisdirected(res);
        return;
      }
      // @spec runtime#idempotency (#917): an unreachable claim domain is no
      // decision at all, never a permit without the claim. 503 is what the
      // PEP's client turns into `pdp_unreachable`.
      if (e instanceof ClaimDomainUnavailableError) {
        res.writeHead(503, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "claim_domain_unavailable" }));
        return;
      }
      // @spec runtime#input-resource-policy (#828): likewise an unreachable
      // Resource policy: no decision, never a refusal it did not reach.
      if (e instanceof ResourcePolicyUnavailableError) {
        res.writeHead(503, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "resource_policy_unavailable" }));
        return;
      }
      throw e;
    }
    sendSigned(res, authed, decision);
  }

  /**
   * The decision options for one request: the caller's `getOptions` result
   * with every PDP-side binding stripped and replaced with this server's own,
   * and the authenticated requester bound.
   */
  async function serverOptions(evalRequest: EvaluationRequest, authed: AuthenticatedRequest): Promise<EvaluateOptions> {
    const opts = { ...(await config.getOptions(evalRequest)) } as EvaluateOptions;
    delete opts.evidence;
    delete opts.claims;
    // @spec metering#topology (#816, decision f): this server takes no budget
    // store, and marks every decision it serves as remote, so a budget-bound
    // Mission is denied `constraint_unsupported` whichever decision function
    // serves it.
    delete opts.budgets;
    opts.decisionChannel = "remote";
    delete (opts as Partial<EvaluateOptions>).resourcePolicy;
    delete opts.requester;
    delete opts.consumptionStatus;
    delete opts.refusals;
    // @spec authzen#context-resource-contract (#249): the PDP's own contract
    // declarations are never a request option; the default is the
    // deployment's statement.
    delete opts.resourceContracts;
    delete opts.durationLeases;
    delete opts.phasedActions;
    delete (opts as Partial<EvaluateOptions>).evaluationContextBinding;
    delete (opts as Partial<EvaluateOptions>).operationDeclarations;
    delete (opts as Partial<EvaluateOptions>).history;
    // @spec authzen#context-approval (#2067): the approval-material trust
    // anchors are this server's own, never a request option.
    delete (opts as Partial<EvaluateOptions>).approvalVerification;
    if (config.evidence) opts.evidence = config.evidence;
    if (config.phasedActions) opts.phasedActions = config.phasedActions;
    if (config.evaluationContextBinding) opts.evaluationContextBinding = config.evaluationContextBinding;
    if (config.operationDeclarations) (opts as Partial<EvaluateOptions>).operationDeclarations = config.operationDeclarations;
    if (config.history) (opts as Partial<EvaluateOptions>).history = config.history;
    if (config.approvalVerification) (opts as Partial<EvaluateOptions>).approvalVerification = config.approvalVerification;
    if (config.durationLeases) opts.durationLeases = config.durationLeases;
    if (config.refusals) opts.refusals = config.refusals;
    if (config.claims) opts.claims = config.claims;
    if (config.resourcePolicy) opts.resourcePolicy = config.resourcePolicy;
    opts.requester = authed.requester;
    const status = config.consumptionStatus?.(authed.pepId);
    if (status) opts.consumptionStatus = status;
    return opts;
  }

  /**
   * @spec authzen#speculative-evaluations (#2067, D1313): previews over the
   * same channel gates as a decision request. The channel's authentication,
   * integrity and replay gates apply to the request as a whole; the scope
   * gates apply to each item, so an item whose audience is outside the
   * PEP's scopes, or whose operation target is outside its registration, is
   * an item error with no decision work and no Refusal Record. Each item's
   * options are resolved for the Mission the shared `context.mission`
   * names; one the PDP cannot establish fails closed as an item error,
   * never evaluated without the Mission. Nothing here emits, records,
   * claims or reserves.
   */
  async function handleSpeculate(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const authed = await authenticate(req, res, null);
    if (!authed) return;
    const request = authed.body.request;
    const fault = speculativeRequestFault(request);
    if (fault !== undefined) {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_request", reason: fault }));
      return;
    }
    const { context: shared, items } = request as { context: Record<string, unknown>; items: Record<string, unknown>[] };
    const pep = config.peps.get(authed.pepId) as AuthorizedPep;
    const scopes = typeof pep.scopes === "function" ? pep.scopes() : pep.scopes;
    const results: SpeculativeItemResult[] = [];
    for (const item of items) {
      const id = item.id as string;
      const resource = item.resource as EvaluationRequest["resource"] | undefined;
      const audience = resource?.properties?.audience;
      if (typeof audience !== "string" || !scopes.includes(audience)) {
        results.push({ id, decision: false, context: { error: { status: 403, message: "pep_not_authorized_for_scope" } } });
        continue;
      }
      const target = resource?.properties?.operation_target;
      if (typeof target === "string" && !targetWithinRegistration(pep, scopes, target)) {
        results.push({ id, decision: false, context: { error: { status: 403, message: "operation_target_invalid" } } });
        continue;
      }
      const own = item.context !== null && typeof item.context === "object" ? (item.context as Record<string, unknown>) : {};
      // The shared context wins here, so the options resolve for the shared
      // Mission; `speculate` refuses a colliding member as an item error.
      const merged = { ...item, context: { ...own, ...shared } } as unknown as EvaluationRequest;
      let opts: EvaluateOptions;
      try {
        opts = await serverOptions(merged, authed);
      } catch {
        results.push({ id, decision: false, context: { error: { status: 400, message: "mission_unrecognized" } } });
        continue;
      }
      try {
        const [result] = (await speculateImpl({ context: shared, items: [item] }, opts)).items;
        results.push(result ?? { id, decision: false, context: { error: { status: 500, message: "no preview" } } });
      } catch {
        results.push({ id, decision: false, context: { error: { status: 503, message: "no decision obtainable" } } });
      }
    }
    sendSigned(res, authed, { items: results });
  }

  /**
   * @spec runtime#idempotency (#917, owner ruling 2026-10-02): settlement
   * and reconciliation behind the same gates as a decision request. The
   * requester they act for is the authenticated PEP and epoch, never a body
   * member.
   */
  async function handleClaims(route: string, req: IncomingMessage, res: ServerResponse): Promise<void> {
    const authed = await authenticate(req, res, (body) => body.audience);
    if (!authed) return;
    const redeemer = config.redeemingExecution?.(authed.pepId);
    const channel =
      config.claimsFor?.(authed.requester, redeemer) ?? claimChannelFor(config.claims, authed.requester, redeemer);
    try {
      if (route === "/claims/settle") {
        sendSigned(res, authed, await channel.settle(authed.body.record));
      } else if (route === "/claims/unresolved") {
        sendSigned(res, authed, { unresolved: await channel.listUnresolved() });
      } else {
        const evaluationId = authed.body.evaluation_id;
        const resolution = authed.body.resolution as ClaimResolution | undefined;
        if (typeof evaluationId !== "string" || (resolution?.kind !== "unredeemed" && resolution?.kind !== "execution_evidence")) {
          sendSigned(res, authed, { accepted: false, reason: "malformed_resolution" });
          return;
        }
        sendSigned(res, authed, await channel.reconcile(evaluationId, resolution));
      }
    } catch (e) {
      if (e instanceof ClaimDomainUnavailableError) {
        res.writeHead(503, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "claim_domain_unavailable" }));
        return;
      }
      throw e;
    }
  }

  const CLAIM_ROUTES = new Set(["/claims/settle", "/claims/unresolved", "/claims/reconcile"]);
  // @spec authzen#speculative-evaluations (#2067, D1313): the speculative
  // route exists only where this PDP serves the feature; without it the
  // route is unknown, so a speculation is never served as an evaluation.
  const speculativeRoute = config.speculativeEvaluations === true;
  const httpServer: HttpServer = createServer((req, res) => {
    const route = req.url ?? "";
    const known = route === "/evaluate" || CLAIM_ROUTES.has(route) || (route === "/speculate" && speculativeRoute);
    if (req.method !== "POST" || !known) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not_found" }));
      return;
    }
    (route === "/evaluate"
      ? handleEvaluate(req, res)
      : route === "/speculate"
        ? handleSpeculate(req, res)
        : handleClaims(route, req, res)
    ).catch(() => {
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "server_error" }));
      } else {
        res.end();
      }
    });
  });

  await new Promise<void>((resolve) => httpServer.listen(0, "127.0.0.1", () => resolve()));
  const addr = httpServer.address();
  const port = typeof addr === "object" && addr !== null ? addr.port : 0;
  const url = `http://127.0.0.1:${port}/evaluate`;

  const close = async (): Promise<void> => {
    httpServer.closeAllConnections();
    await new Promise<void>((resolve, reject) => httpServer.close((err) => (err ? reject(err) : resolve())));
  };

  return { url, port, close };
}
