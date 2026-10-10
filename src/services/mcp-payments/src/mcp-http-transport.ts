/**
 * @spec draft-mcguinness-mission-harness (mediated execution environment)
 *
 * Increment 3: the mediated MCP channel over a REAL HTTP transport with DPoP
 * proof-of-possession enforced per request. This closes the gap the in-memory
 * channel ({@link ./mcp-transport.ts}) documents: over the in-process transport
 * there is no HTTP request to bind a DPoP proof to, so it validates the token but
 * SKIPS proof-of-possession. Here every HTTP request is gated by a DPoP-auth
 * middleware that reuses the RS's full PoP validator
 * ({@link McpPaymentsServer.validateToken}: token verify + `cnf.jkt` == proof
 * thumbprint + `htu`/`htm` binding) BEFORE the request is dispatched to MCP.
 *
 * The credential no longer rides in `_meta`; it travels in the HTTP headers
 * (`Authorization: DPoP <token>` + `DPoP: <proof>`), exactly as a real MCP-over-
 * HTTP resource server would receive it. `initialize`, `tools/list`, and
 * `tools/call` are ALL gated (the middleware is method- and path-agnostic), so
 * there is no un-gated HTTP path to the PEP.
 *
 * This is additive: the in-memory transport and its no-bypass proof are untouched.
 * Two transports, one PEP ({@link McpPaymentsServer}); only the TokenFacts SOURCE
 * differs (validated HTTP credential here vs validated `_meta` credential there).
 */

import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { FetchLike, Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  CallToolRequestSchema,
  type CallToolResult,
  ListToolsRequestSchema,
  type ListToolsResult,
} from "@modelcontextprotocol/sdk/types.js";
import { ACCEPT_TXN_CHALLENGE_HEADER, acceptsTxnChallenge } from "@mission/core";
import { exportJWK, SignJWT } from "jose";
import { accessTokenHash, DpopReplayUnavailableError } from "./dpop.js";
import type { MediatedToolResult } from "./mcp-transport.js";
import { MISSION_REFERENCE_HEADER, parseMissionReferenceField } from "@mission/core";
import { TOOL_ACTIONS, type RequestSignals, type TokenFacts } from "./pep.js";
import { serveResourceMetadata } from "./resource-metadata.js";
import { dispatchPathFor, type McpPaymentsServer } from "./server.js";

/** The ES256 DPoP keypair the harness holds for the life of a mission credential. */
export interface DpopKeys {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

/** A running HTTP MCP channel: the endpoint URL, its port, and a shutdown hook. */
export interface HttpMcpChannel {
  url: string;
  port: number;
  close: () => Promise<void>;
}

/** The HTTP mediated client surface: tool access with NO `_meta` credential --
 * the mission token + DPoP proof travel in the HTTP headers instead. */
export interface HttpMediatedClient {
  listTools: () => Promise<string[]>;
  callTool: (name: string, args: Record<string, unknown>) => Promise<MediatedToolResult>;
}

/**
 * Who an MCP session belongs to: the holder whose credential opened it. The
 * DPoP key (`cnf.jkt`, which every request's proof re-proves), the token
 * subject and the client. A later credential of the same holder (a refreshed
 * token, or the transaction token bound to the same key) may use the
 * session; any other holder may not.
 */
interface SessionHolder {
  cnfJkt: string;
  sub: string;
  clientId: string;
}

const holderOf = (facts: TokenFacts): SessionHolder => ({
  cnfJkt: facts.cnfJkt,
  sub: facts.sub,
  clientId: facts.clientId,
});

const sameHolder = (a: SessionHolder, b: SessionHolder): boolean =>
  a.cnfJkt === b.cnfJkt && a.sub === b.sub && a.clientId === b.clientId;

/** One MCP session: its own transport and MCP `Server`, and its holder. */
interface McpSession {
  transport: StreamableHTTPServerTransport;
  server: Server;
  holder: SessionHolder;
}

/** The streamable-HTTP transport's own answer for a session it does not hold. */
function sessionNotFound(res: ServerResponse): void {
  res.writeHead(404, { "content-type": "application/json" });
  res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32001, message: "Session not found" }, id: null }));
}

/**
 * The canonical `htu` (RFC 9449): the request URI WITHOUT query or fragment.
 * BOTH the client (from the URL it is handed) and the server middleware (from the
 * reconstructed request URL) derive `htu` through THIS one function, so the two
 * sides can never silently disagree on the form. `origin + pathname` drops the
 * query and fragment.
 */
export function canonicalHtu(input: string | URL): string {
  const u = input instanceof URL ? input : new URL(input);
  return `${u.origin}${u.pathname}`;
}

/**
 * A resource-side DPoP proof (`dpop+jwt`) bound to `dpopKeys`, carrying the
 * canonical `htu`/`htm`, a fresh `jti`, and `iat`. The header `jwk` is the public
 * key, so the RS can compute its thumbprint and match it to the token's `cnf.jkt`.
 *
 * @spec RFC 9449 §4.2 — pass the credential this proof accompanies and the
 * proof carries `ath` too, naming that exact credential. Every request to a
 * Resource Server needs it: without `ath` a proof binds only to a KEY, so two
 * credentials bound to the same key are interchangeable on the wire.
 */
export async function dpopProofFor(
  dpopKeys: DpopKeys,
  htu: string,
  htm: string,
  accessToken?: string,
): Promise<string> {
  const jwk = await exportJWK(dpopKeys.publicKey);
  return new SignJWT({
    htu,
    htm,
    ...(accessToken !== undefined ? { ath: accessTokenHash(accessToken) } : {}),
  })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk })
    .setIssuedAt()
    .setJti(randomUUID())
    .sign(dpopKeys.privateKey);
}


/** Encode a PEP verdict as an MCP tool result: denials are structured results
 * (isError + structuredContent), never thrown transport errors, so the client
 * can read the reason. */
function toCallToolResult(pep: MediatedToolResult): CallToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify(pep) }],
    structuredContent: pep as unknown as Record<string, unknown>,
    isError: !pep.ok,
  };
}

/** Route a tool call to the same PEP methods the direct callers use -- identical
 * to the in-memory channel's routing (only the TokenFacts source differs). */
async function route(
  paymentsServer: McpPaymentsServer,
  name: string,
  args: Record<string, unknown>,
  token: TokenFacts,
  signals?: RequestSignals,
): Promise<MediatedToolResult> {
  // @spec runtime#compound-actions — a `prepare` crossing creates state, so it
  // takes the write path; a `preflight` crossing creates none and takes the
  // read path. Both are consequential enough to reach a Decision and both go
  // through the same pre-effect phase comparison, which is exactly why the
  // comparison cannot live on the connector path alone. @spec
  // runtime#idempotency (#918): every consequential write, the keyed
  // reversible ones included, takes the write path, and only the
  // transaction-assurance tier reaches `callTransactionTool`.
  switch (dispatchPathFor(TOOL_ACTIONS[name], paymentsServer.hasTransactionTier())) {
    case "transaction":
      return paymentsServer.callTransactionTool(name, args, token, undefined, signals);
    case "write":
      return paymentsServer.callWriteTool(name, args, token, undefined, signals);
    default:
      return paymentsServer.callReadTool(name, args, token, undefined, signals);
  }
}

/**
 * Build the MCP `Server` whose handlers read TokenFacts from the middleware-set
 * AuthInfo (`extra.authInfo.extra.tokenFacts`) instead of `_meta`, then delegate
 * to the SAME {@link McpPaymentsServer} methods as the in-memory channel.
 */
function createHttpMcpServer(paymentsServer: McpPaymentsServer): Server {
  const server = new Server(
    { name: "mission-payments-http", version: "0.0.1" },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async (_request, extra): Promise<ListToolsResult> => {
    const token = extra.authInfo?.extra?.tokenFacts as TokenFacts | undefined;
    // No validated credential reached us -> least exposure (should not happen:
    // the middleware gates every request before dispatch).
    if (!token) return { tools: [] };
    return { tools: paymentsServer.capabilityCatalog.toolDefinitions(paymentsServer.toolsList(token).map(t => t.name)) };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request, extra): Promise<CallToolResult> => {
    const token = extra.authInfo?.extra?.tokenFacts as TokenFacts | undefined;
    const signals = extra.authInfo?.extra?.signals as RequestSignals | undefined;
    const args = (request.params.arguments ?? {}) as Record<string, unknown>;
    if (!token) return toCallToolResult({ ok: false, denial_reason: "invalid_credential" });
    const verdict = await route(paymentsServer, request.params.name, args, token, signals);
    return toCallToolResult(verdict);
  });

  return server;
}

/** The Node request carrying the middleware-populated AuthInfo the SDK reads. */
type AuthedRequest = IncomingMessage & { auth?: AuthInfo };

function unauthorized(res: ServerResponse, description: string): void {
  res.writeHead(401, { "content-type": "application/json", "www-authenticate": "DPoP" });
  res.end(JSON.stringify({ error: "invalid_token", error_description: description }));
}

/**
 * @spec runtime-evidence#pre-decision-refusal, #1173 (D375): the proof's
 * replay state is unavailable (the cache is at its bound), so the request is
 * refused before any decision, retryably, and never dispatched.
 */
function replayStateUnavailable(res: ServerResponse, retryAfterS: number): void {
  res.writeHead(503, { "content-type": "application/json", "retry-after": String(retryAfterS) });
  res.end(
    JSON.stringify({ refusal_reason: "state_unavailable", error_description: "DPoP proof replay state is at capacity" }),
  );
}

/**
 * The DPoP-auth middleware, run for EVERY HTTP request before dispatch to MCP,
 * including every request on an established session. Missing/malformed
 * credential or failed proof-of-possession -> 401, and the request is NEVER
 * handed to a transport (the PEP is never reached). Returns the validated
 * facts, or `undefined` once it has answered the request.
 */
async function authenticate(
  req: AuthedRequest,
  res: ServerResponse,
  paymentsServer: McpPaymentsServer,
  masGoverned: boolean,
): Promise<TokenFacts | undefined> {
  const authz = req.headers.authorization;
  const proof = req.headers.dpop;
  if (typeof authz !== "string" || !authz.startsWith("DPoP ")) {
    unauthorized(res, "missing DPoP-scheme access token");
    return undefined;
  }
  if (typeof proof !== "string" || proof.length === 0) {
    unauthorized(res, "missing DPoP proof");
    return undefined;
  }
  const accessToken = authz.slice("DPoP ".length).trim();
  // Reconstruct the SAME canonical htu the client signed: http://<host><path>,
  // query/fragment stripped. htm is the request method.
  const htu = canonicalHtu(new URL(req.url ?? "/", `http://${req.headers.host ?? ""}`));
  const htm = req.method ?? "GET";

  let facts: TokenFacts;
  try {
    // @spec authority-server#mission-join (#557) — a MAS-GOVERNED route
    // admits an ordinary OAuth credential carrying no `mission` claim and
    // joins it against the propagated reference below, so it validates
    // through `validateGatewayCredential`, which verifies once and branches
    // on the VERIFIED payload's claim presence. Every other route keeps
    // `validateCredential` and stays Mission-bound-only.
    //
    // @spec txn-authorization#transaction-token — ONE credential in the
    // Authorization header: an ordinary Mission-bound access token, or the
    // transaction token that authorizes the retry of a challenged operation.
    // Nothing else on this request carries a transaction token.
    facts = masGoverned
      ? await paymentsServer.validateGatewayCredential(accessToken, { proof, htu, htm }, true)
      : await paymentsServer.validateCredential(accessToken, { proof, htu, htm });
  } catch (e) {
    if (e instanceof DpopReplayUnavailableError) {
      replayStateUnavailable(res, e.retryAfterS);
      return undefined;
    }
    unauthorized(res, "DPoP proof-of-possession failed");
    return undefined;
  }

  // @spec txn-authorization#resource-challenge — the client's
  // Accept-Txn-Challenge signal gates the challenge; it travels as an ordinary
  // request header (an RFC 8941 Boolean, so `?1` and nothing else is
  // acceptance) and is carried to the PEP alongside the validated facts.
  const acceptTxnChallenge = acceptsTxnChallenge(req.headers[ACCEPT_TXN_CHALLENGE_HEADER]);
  // @spec authority-server#mission-reference-field — the propagated Mission
  // Reference is a Structured Fields Dictionary on exactly one field line;
  // the raw header view supplies the line count (node joins repeats), and a
  // malformed parse is CARRIED to the PEP, which refuses governed work on
  // it, rather than dropped here.
  let referenceLines = 0;
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    if ((req.rawHeaders[i] ?? "").toLowerCase() === MISSION_REFERENCE_HEADER) referenceLines++;
  }
  const missionReference = parseMissionReferenceField(
    req.headers[MISSION_REFERENCE_HEADER] as string | string[] | undefined,
    referenceLines || 1,
  );
  // The SDK's AuthInfo shape; the MCP handlers read facts from extra.tokenFacts.
  req.auth = {
    token: accessToken,
    clientId: facts.clientId,
    scopes: [],
    extra: {
      tokenFacts: facts,
      signals: { acceptTxnChallenge, ...(missionReference ? { missionReference } : {}) },
    },
  };
  return facts;
}

/**
 * Start a real HTTP MCP channel: a node HTTP server that gates every request with
 * the DPoP-auth middleware, in front of one {@link StreamableHTTPServerTransport}
 * + MCP `Server` per MCP session, so successive and concurrent clients each
 * initialize their own. A session is bound to the holder that opened it
 * ({@link SessionHolder}); a request on it is authenticated like any other and
 * then dispatched only if its holder matches, and is otherwise answered 404
 * `Session not found`, exactly as for a session that does not exist. Binds an
 * ephemeral port on 127.0.0.1 by default and reports the actual URL.
 */
export async function createHttpMcpChannel(
  paymentsServer: McpPaymentsServer,
  opts?: {
    host?: string;
    /**
     * The port to bind. Default 0, an ephemeral port. A deployment serving its
     * declared resource audience passes that audience's port; a port already in
     * use rejects rather than waiting.
     */
    port?: number;
    /**
     * @spec authority-server#mission-join (#557) — this route is MAS-governed:
     * it admits an ordinary OAuth credential with no `mission` claim and joins
     * it against the propagated Mission Reference. Default false, a
     * Mission-bound-only route, so an existing channel is unchanged. A
     * deployment turning this on MUST also configure the PEP's `masJoin`, or
     * every joined request refuses with no usable permit.
     */
    masGoverned?: boolean;
  },
): Promise<HttpMcpChannel> {
  const host = opts?.host ?? "127.0.0.1";
  const masGoverned = opts?.masGoverned ?? false;
  const sessions = new Map<string, McpSession>();

  /**
   * Hand an authenticated request to its session. A request naming a session
   * reaches it only when the session's holder is this request's holder; a
   * request naming none gets a fresh transport and MCP `Server`, which keep
   * the session an `initialize` opens on them. The SDK answers anything else
   * there 400, and that pair is discarded.
   */
  const dispatch = async (req: AuthedRequest, res: ServerResponse, holder: SessionHolder): Promise<void> => {
    const sessionId = req.headers["mcp-session-id"];
    if (sessionId !== undefined) {
      const session = typeof sessionId === "string" ? sessions.get(sessionId) : undefined;
      if (!session || !sameHolder(session.holder, holder)) return sessionNotFound(res);
      return session.transport.handleRequest(req, res);
    }
    const server = createHttpMcpServer(paymentsServer);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      enableJsonResponse: true,
      onsessioninitialized: (id) => {
        sessions.set(id, { transport, server, holder });
      },
    });
    // Closing the session (the client's DELETE, or the channel's close)
    // forgets it.
    transport.onclose = () => {
      if (transport.sessionId !== undefined) sessions.delete(transport.sessionId);
    };
    // The SDK's transport classes model onclose/sessionId as `T | undefined`, which
    // does not satisfy their own `Transport` interface's optional members under this
    // repo's exactOptionalPropertyTypes; cast at the connect boundary only.
    await server.connect(transport as unknown as Transport);
    await transport.handleRequest(req, res);
    if (transport.sessionId === undefined) await server.close().catch(() => {});
  };

  const httpServer: HttpServer = createServer((req, res) => {
    // @spec txn-authorization#two-phase-expiry — the unauthenticated discovery
    // routes (RFC 9728 metadata + txn_challenge_jwks_uri) are served in front of
    // the credential gate: they publish public keys and metadata.
    if (serveResourceMetadata(paymentsServer, req, res)) return;
    const authed = req as AuthedRequest;
    authenticate(authed, res, paymentsServer, masGoverned)
      .then((facts) => (facts ? dispatch(authed, res, holderOf(facts)) : undefined))
      .catch(() => {
        if (!res.headersSent) {
          res.writeHead(500, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "server_error" }));
        } else {
          res.end();
        }
      });
  });

  // Bind 127.0.0.1 explicitly: listen(0) alone binds :: and address() reports an
  // IPv6 host, which would break the URL handed to the client and the Host the
  // server reconstructs htu from.
  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(opts?.port ?? 0, host, () => {
      httpServer.off("error", reject);
      resolve();
    });
  });
  const addr = httpServer.address();
  const port = typeof addr === "object" && addr !== null ? addr.port : 0;
  const url = `http://${host}:${port}/mcp`;

  const close = async (): Promise<void> => {
    for (const session of [...sessions.values()]) await session.server.close().catch(() => {});
    sessions.clear();
    // undici keep-alive would leave sockets idle; drop them so close() resolves.
    httpServer.closeAllConnections();
    await new Promise<void>((resolve, reject) =>
      httpServer.close((err) => (err ? reject(err) : resolve())),
    );
  };

  return { url, port, close };
}

/** A custom fetch that DPoP-binds every request: fresh proof (canonical htu +
 * method) + `Authorization: DPoP <credential>` + `DPoP: <proof>`, merged over
 * any headers the SDK set (content-type, accept, mcp-session-id, ...). The
 * credential is the request's ONE OAuth credential: an ordinary Mission-bound
 * access token, or the transaction token that authorizes the retry of a
 * challenged operation. `extraHeaders` carries per-client request signals such
 * as `Accept-Txn-Challenge`. */
export function dpopFetch(
  credential: string,
  dpopKeys: DpopKeys,
  extraHeaders: Record<string, string> = {},
): FetchLike {
  return async (input, init) => {
    const htu = canonicalHtu(input);
    const htm = init?.method ?? "GET";
    const proof = await dpopProofFor(dpopKeys, htu, htm, credential);
    const headers = new Headers(init?.headers);
    for (const [name, value] of Object.entries(extraHeaders)) headers.set(name, value);
    headers.set("authorization", `DPoP ${credential}`);
    headers.set("dpop", proof);
    return fetch(input, { ...init, headers });
  };
}

/**
 * Connect an HTTP mediated client over the {@link StreamableHTTPClientTransport}
 * whose custom fetch DPoP-binds every request (including `initialize` and the SSE
 * stream). The credential lives in the HTTP headers, so tool access takes NO token
 * argument. Returns the client surface, the MCP session id the server issued,
 * and a `close()` that ends that session at the server (an authenticated
 * DELETE, best effort) before closing the client.
 */
export async function createHttpMediatedClient(
  url: string,
  credential: string,
  dpopKeys: DpopKeys,
  extraHeaders: Record<string, string> = {},
): Promise<{ client: HttpMediatedClient; sessionId: string | undefined; close: () => Promise<void> }> {
  const transport = new StreamableHTTPClientTransport(new URL(url), {
    fetch: dpopFetch(credential, dpopKeys, extraHeaders),
  });
  const mcp = new Client({ name: "mission-harness-http", version: "0.0.1" }, { capabilities: {} });
  await mcp.connect(transport as unknown as Transport);

  const client: HttpMediatedClient = {
    async listTools() {
      const res = await mcp.listTools();
      return res.tools.map((t) => t.name);
    },
    async callTool(name, args) {
      const res = await mcp.callTool({ name, arguments: args });
      return (res.structuredContent ?? { ok: false, refusal_reason: "no_result" }) as unknown as MediatedToolResult;
    },
  };

  return {
    client,
    sessionId: transport.sessionId,
    close: async () => {
      // A credential the resource no longer accepts cannot end the session;
      // the channel's own close() still does.
      await transport.terminateSession().catch(() => {});
      await mcp.close();
    },
  };
}
