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

import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import { macEqualHex, macHex, REQUEST_MAC_DOMAIN, RESPONSE_MAC_DOMAIN, sha256Hex } from "./channel-mac.js";
import { requestMacParts } from "./client.js";
import type { DecisionEvidenceEmitter } from "./decision-evidence.js";
import { type ClaimChannel, claimChannelFor } from "./decision-point.js";
import { evaluate, type Decision, type DecisionOptions, type EvaluateOptions, type EvaluationRequest } from "./evaluate.js";
import {
  type ClaimRequester,
  type ClaimResolution,
  ClaimDomainUnavailableError,
  type ConsumptionStatusFn,
  type RedeemingExecutionFn,
  type IdempotencyClaimDomain,
} from "./idempotency-claims.js";

/**
 * One PEP the PDP recognizes: its shared authentication secret and the
 * enforcement scopes (audiences) it is authorized to submit decision
 * requests for (@spec runtime#runtime-conformance: "the remote
 * decision-channel trust mode for every PEP/PDP boundary").
 */
export interface AuthorizedPep {
  secret: string;
  scopes: readonly string[];
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
   * @spec runtime#idempotency (#917): this PDP's claim domain, bound on this
   * side of the network hop exactly as `evidence` is: a request option naming
   * another is stripped.
   */
  claims?: IdempotencyClaimDomain;
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
 * Start the reference PDP HTTP listener on an ephemeral 127.0.0.1 port.
 * Every request to POST /evaluate runs the authentication, integrity,
 * freshness/replay, and scope-authorization gates, in that order, before
 * `evaluate()` is invoked; a failure at any gate short-circuits with zero
 * decision work.
 */
export async function createPdpHttpServer(config: PdpRemoteServerConfig): Promise<PdpHttpServerHandle> {
  const evaluateImpl = config.evaluateFn ?? evaluate;
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
   */
  async function authenticate(
    req: IncomingMessage,
    res: ServerResponse,
    audienceOf: (body: Record<string, unknown>) => unknown,
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
    const audience = body !== null && typeof body === "object" && !Array.isArray(body)
      ? audienceOf(body as Record<string, unknown>)
      : undefined;
    if (typeof audience !== "string") {
      sendRefusal(res, 400, "malformed_body");
      return undefined;
    }
    // @spec runtime#decision-channel: "The PDP MUST accept credential-derived
    // inputs only from a PEP authorized for the declared enforcement scope."
    // Checked BEFORE getOptions/evaluate touch anything derived from the
    // request: an unauthorized-for-scope PEP gets zero decision work, not a
    // decision made and then discarded.
    if (!pep.scopes.includes(audience)) {
      sendRefusal(res, 403, "pep_not_authorized_for_scope");
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
    const authed = await authenticate(req, res, (body) => {
      const request = body.request as EvaluationRequest | undefined;
      return request?.context?.audience;
    });
    if (!authed) return;
    const evalRequest = authed.body.request as EvaluationRequest;
    const opts = { ...(await config.getOptions(evalRequest)) } as EvaluateOptions;
    delete opts.evidence;
    delete opts.claims;
    delete opts.requester;
    delete opts.consumptionStatus;
    if (config.evidence) opts.evidence = config.evidence;
    if (config.claims) opts.claims = config.claims;
    opts.requester = authed.requester;
    const status = config.consumptionStatus?.(authed.pepId);
    if (status) opts.consumptionStatus = status;
    let decision: Decision;
    try {
      decision = await evaluateImpl(evalRequest, opts);
    } catch (e) {
      // @spec runtime#idempotency (#917): an unreachable claim domain is no
      // decision at all, never a permit without the claim. 503 is what the
      // PEP's client turns into `pdp_unreachable`.
      if (e instanceof ClaimDomainUnavailableError) {
        res.writeHead(503, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "claim_domain_unavailable" }));
        return;
      }
      throw e;
    }
    sendSigned(res, authed, decision);
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
  const httpServer: HttpServer = createServer((req, res) => {
    const route = req.url ?? "";
    if (req.method !== "POST" || (route !== "/evaluate" && !CLAIM_ROUTES.has(route))) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not_found" }));
      return;
    }
    (route === "/evaluate" ? handleEvaluate(req, res) : handleClaims(route, req, res)).catch(() => {
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
