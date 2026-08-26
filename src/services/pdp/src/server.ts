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

import { createServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import { macEqualHex, macHex, REQUEST_MAC_DOMAIN, RESPONSE_MAC_DOMAIN, sha256Hex } from "./channel-mac.js";
import { evaluate, type Decision, type EvaluateOptions, type EvaluationRequest } from "./evaluate.js";

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
   * this indirection; tests fix it to a constant.
   */
  getOptions: (req: EvaluationRequest) => EvaluateOptions | Promise<EvaluateOptions>;
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
}

export interface PdpHttpServerHandle {
  url: string;
  port: number;
  close: () => Promise<void>;
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

  async function handleEvaluate(req: IncomingMessage, res: ServerResponse): Promise<void> {
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
        return;
      }
      chunks.push(chunk);
    }
    const rawBody = Buffer.concat(chunks).toString("utf8");

    const pepId = headerString(req.headers["x-pdp-pep-id"]);
    const signature = headerString(req.headers["x-pdp-signature"]);
    const nonce = headerString(req.headers["x-pdp-nonce"]);
    const issuedAt = headerString(req.headers["x-pdp-issued-at"]);

    if (pepId === undefined || signature === undefined || nonce === undefined || issuedAt === undefined) {
      sendRefusal(res, 401, "missing_channel_authentication");
      return;
    }
    const pep = config.peps.get(pepId);
    if (!pep) {
      sendRefusal(res, 401, "unknown_pep");
      return;
    }

    // Integrity + mutual authentication: the request's exact bytes, bound to
    // this PEP identity, nonce, and issuance time, must match a MAC only a
    // holder of this PEP's registered secret could have produced.
    const expectedSignature = macHex(pep.secret, REQUEST_MAC_DOMAIN, [pepId, nonce, issuedAt, rawBody]);
    if (!macEqualHex(signature, expectedSignature)) {
      sendRefusal(res, 401, "invalid_request_signature");
      return;
    }

    const now = Date.now();
    const issuedAtMs = Number(issuedAt);
    if (!Number.isFinite(issuedAtMs) || Math.abs(now - issuedAtMs) > replayWindowMs) {
      sendRefusal(res, 401, "stale_or_future_request");
      return;
    }
    pruneExpired(now);
    const nonceKey = `${pepId}:${nonce}`;
    if (seenNonces.has(nonceKey)) {
      sendRefusal(res, 401, "replayed_request");
      return;
    }
    seenNonces.set(nonceKey, now + replayWindowMs);

    let parsedBody: { request?: EvaluationRequest };
    try {
      parsedBody = JSON.parse(rawBody) as { request?: EvaluationRequest };
    } catch {
      sendRefusal(res, 400, "malformed_body");
      return;
    }
    const evalRequest = parsedBody.request;
    const audience = evalRequest?.context?.audience;
    if (evalRequest === undefined || typeof audience !== "string") {
      sendRefusal(res, 400, "malformed_body");
      return;
    }
    // @spec runtime#decision-channel: "The PDP MUST accept credential-derived
    // inputs only from a PEP authorized for the declared enforcement scope."
    // Checked BEFORE getOptions/evaluate touch anything derived from the
    // request: an unauthorized-for-scope PEP gets zero decision work, not a
    // decision made and then discarded.
    if (!pep.scopes.includes(audience)) {
      sendRefusal(res, 403, "pep_not_authorized_for_scope");
      return;
    }

    const opts = await config.getOptions(evalRequest);
    const decision: Decision = await evaluateImpl(evalRequest, opts);
    const body = JSON.stringify(decision);
    const status = 200;
    // Bound to the request that produced it, not just its own bytes: a
    // response MAC over the body alone lets an intermediary replay an
    // old, validly signed permit as the answer to a different request.
    const responseSignature = macHex(pep.secret, RESPONSE_MAC_DOMAIN, [
      pepId,
      nonce,
      issuedAt,
      sha256Hex(rawBody),
      String(status),
      body,
    ]);
    res.writeHead(status, { "content-type": "application/json", "x-pdp-signature": responseSignature });
    res.end(body);
  }

  const httpServer: HttpServer = createServer((req, res) => {
    if (req.method !== "POST" || req.url !== "/evaluate") {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not_found" }));
      return;
    }
    handleEvaluate(req, res).catch(() => {
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
