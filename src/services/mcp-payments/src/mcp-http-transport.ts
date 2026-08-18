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
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { ACCEPT_TXN_CHALLENGE_HEADER, acceptsTxnChallenge } from "@mission/core";
import { exportJWK, SignJWT } from "jose";
import { accessTokenHash } from "./dpop.js";
import type { MediatedToolResult } from "./mcp-transport.js";
import { TOOL_ACTIONS, type RequestSignals, type TokenFacts } from "./pep.js";
import { serveResourceMetadata } from "./resource-metadata.js";
import type { McpPaymentsServer, ToolDef } from "./server.js";

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

/** Map an internal ToolDef to an MCP `Tool` (least-exposure list entry). */
function toMcpTool(def: ToolDef): Tool {
  const mapping = TOOL_ACTIONS[def.name];
  const inputSchema = mapping?.needsInvoice
    ? { type: "object" as const, properties: { invoice_id: { type: "string" } }, required: ["invoice_id"] }
    : { type: "object" as const, properties: { vendor_id: { type: "string" } } };
  return { name: def.name, description: def.description, inputSchema };
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
  const mapping = TOOL_ACTIONS[name];
  if (mapping?.actionClass && paymentsServer.hasTransactionTier()) {
    return paymentsServer.callTransactionTool(name, args, token, undefined, signals);
  }
  if (name === "schedule_payment" || (mapping?.actionClass && !paymentsServer.hasTransactionTier())) {
    return paymentsServer.callWriteTool(name, args, token);
  }
  return paymentsServer.callReadTool(name, args, token);
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
    return { tools: paymentsServer.toolsList(token).map(toMcpTool) };
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
 * The DPoP-auth middleware, run for EVERY HTTP request before dispatch to MCP.
 * Missing/malformed credential or failed proof-of-possession -> 401, and the
 * request is NEVER handed to the transport (the PEP is never reached).
 */
async function authenticate(
  req: AuthedRequest,
  res: ServerResponse,
  paymentsServer: McpPaymentsServer,
  transport: StreamableHTTPServerTransport,
): Promise<void> {
  const authz = req.headers.authorization;
  const proof = req.headers.dpop;
  if (typeof authz !== "string" || !authz.startsWith("DPoP ")) {
    return unauthorized(res, "missing DPoP-scheme access token");
  }
  if (typeof proof !== "string" || proof.length === 0) {
    return unauthorized(res, "missing DPoP proof");
  }
  const accessToken = authz.slice("DPoP ".length).trim();
  // Reconstruct the SAME canonical htu the client signed: http://<host><path>,
  // query/fragment stripped. htm is the request method.
  const htu = canonicalHtu(new URL(req.url ?? "/", `http://${req.headers.host ?? ""}`));
  const htm = req.method ?? "GET";

  let facts: TokenFacts;
  try {
    // @spec txn-authorization#transaction-token — ONE credential in the
    // Authorization header: an ordinary Mission-bound access token, or the
    // transaction token that authorizes the retry of a challenged operation.
    // Nothing else on this request carries a transaction token.
    facts = await paymentsServer.validateCredential(accessToken, { proof, htu, htm });
  } catch {
    return unauthorized(res, "DPoP proof-of-possession failed");
  }

  // @spec txn-authorization#resource-challenge — the client's
  // Accept-Txn-Challenge signal gates the challenge; it travels as an ordinary
  // request header (an RFC 8941 Boolean, so `?1` and nothing else is
  // acceptance) and is carried to the PEP alongside the validated facts.
  const acceptTxnChallenge = acceptsTxnChallenge(req.headers[ACCEPT_TXN_CHALLENGE_HEADER]);
  // The SDK's AuthInfo shape; the MCP handlers read facts from extra.tokenFacts.
  req.auth = {
    token: accessToken,
    clientId: facts.clientId,
    scopes: [],
    extra: { tokenFacts: facts, signals: { acceptTxnChallenge } },
  };
  await transport.handleRequest(req, res);
}

/**
 * Start a real HTTP MCP channel: a node HTTP server that gates every request with
 * the DPoP-auth middleware, in front of a single {@link StreamableHTTPServerTransport}
 * + MCP `Server`. Binds an ephemeral port on 127.0.0.1 and reports the actual URL.
 */
export async function createHttpMcpChannel(
  paymentsServer: McpPaymentsServer,
  opts?: { host?: string },
): Promise<HttpMcpChannel> {
  const host = opts?.host ?? "127.0.0.1";
  const mcpServer = createHttpMcpServer(paymentsServer);
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
    enableJsonResponse: true,
  });
  // The SDK's transport classes model onclose/sessionId as `T | undefined`, which
  // does not satisfy their own `Transport` interface's optional members under this
  // repo's exactOptionalPropertyTypes; cast at the connect boundary only.
  await mcpServer.connect(transport as unknown as Transport);

  const httpServer: HttpServer = createServer((req, res) => {
    // @spec txn-authorization#two-phase-expiry — the unauthenticated discovery
    // routes (RFC 9728 metadata + txn_challenge_jwks_uri) are served in front of
    // the credential gate: they publish public keys and metadata.
    if (serveResourceMetadata(paymentsServer, req, res)) return;
    authenticate(req as AuthedRequest, res, paymentsServer, transport).catch(() => {
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
  await new Promise<void>((resolve) => httpServer.listen(0, host, () => resolve()));
  const addr = httpServer.address();
  const port = typeof addr === "object" && addr !== null ? addr.port : 0;
  const url = `http://${host}:${port}/mcp`;

  const close = async (): Promise<void> => {
    await transport.close().catch(() => {});
    await mcpServer.close().catch(() => {});
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
 * argument. Returns the client surface plus a `close()`.
 */
export async function createHttpMediatedClient(
  url: string,
  credential: string,
  dpopKeys: DpopKeys,
  extraHeaders: Record<string, string> = {},
): Promise<{ client: HttpMediatedClient; close: () => Promise<void> }> {
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

  return { client, close: async () => { await mcp.close(); } };
}
