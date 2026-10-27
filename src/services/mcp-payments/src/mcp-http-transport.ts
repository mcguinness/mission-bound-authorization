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
import {
  ACCEPT_TXN_CHALLENGE_HEADER,
  type AatJson,
  AatJsonError,
  AatNumber,
  aatIsObject,
  aatToPlainJson,
  acceptsTxnChallenge,
  parseAatJson,
} from "@mission/core";
import { exportJWK, SignJWT } from "jose";
import { AAT_PRESENTATION_META_KEY, readAatPresentation } from "./aat-presentation.js";
import { accessTokenHash, DpopReplayUnavailableError } from "./dpop.js";
import { IntrospectionUnavailableError } from "./introspection.js";
import { originalArgumentsFrom, snapshotArguments } from "./invocation-arguments.js";
import type { MediatedToolResult } from "./mcp-transport.js";
import {
  MCP_REFERENCE_META_KEY,
  MISSION_REFERENCE_HEADER,
  parseMcpReferenceMeta,
  parseMissionReferenceField,
  reconcilePropagatedReferences,
} from "@mission/core";
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
 * the mission token + DPoP proof travel in the HTTP headers instead. An
 * optional `missionReference` rides `params._meta` under the propagation key
 * (@spec authority-server#mcp-reference), typed `unknown` so a caller can
 * present a malformed shape: the server decides what is well-formed. */
export interface HttpMediatedClient {
  listTools: () => Promise<string[]>;
  callTool: (name: string, args: Record<string, unknown>, missionReference?: unknown) => Promise<MediatedToolResult>;
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
    const authSignals = extra.authInfo?.extra?.signals as RequestSignals | undefined;
    const args = (request.params.arguments ?? {}) as Record<string, unknown>;
    if (!token) return toCallToolResult({ ok: false, denial_reason: "invalid_credential" });
    // @spec attenuation#mission-binding-check (#1756 slice B3): a presentation
    // is its request's one credential. A call carrying one on a request the
    // middleware authenticated by its Authorization header has two.
    if (request.params._meta?.[AAT_PRESENTATION_META_KEY] !== undefined && extra.authInfo?.extra?.aatPresented !== true) {
      return toCallToolResult({ ok: false, denial_reason: "invalid_credential" });
    }
    // @spec AAT -02 Section 8 steps 6b and 7f (#1756, D902): the call's
    // original arguments, from the body the middleware read once and parsed
    // losslessly, the same parse this request was dispatched from. A call
    // with none is refused rather than handled from the parsed object alone.
    const invocations = extra.authInfo?.extra?.invocations as ReadonlyMap<string, string> | undefined;
    const key = invocationKey(extra.requestId);
    const argumentsJson = key === undefined ? undefined : invocations?.get(key);
    if (argumentsJson === undefined) return toCallToolResult({ ok: false, refusal_reason: "invalid_request" });
    // @spec authority-server#mcp-reference (#1694): the propagated reference
    // also rides params._meta on each tools/call, and a server that silently
    // ignores that key is not a conforming Mission PEP. It is read with the
    // stdio transport's closed parser and reconciled with the
    // Mission-Reference field the middleware parsed: either alone is the
    // reference, and two carriages that disagree, or a malformed one, reach
    // the PEP as one unusable reference, which it refuses
    // `mission_reference_conflict` (@spec authority-server#reference-verification).
    const { missionReference: fieldReference, ...rest } = authSignals ?? {};
    const missionReference = reconcilePropagatedReferences(
      fieldReference,
      parseMcpReferenceMeta(request.params._meta?.[MCP_REFERENCE_META_KEY]),
    );
    const signals: RequestSignals = {
      ...rest,
      ...(missionReference ? { missionReference } : {}),
      invocation: { argumentsJson },
    };
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
 * @spec AAT -02 Section 8 steps 6b and 7f (#1756, D902): the largest request
 * body the channel reads, the SDK's own bound on one SSE message. The
 * streamable transport set none of its own.
 */
const MAX_REQUEST_BODY_BYTES = 4 * 1024 * 1024;

/** A request body refused before authentication, answered in the SDK transport's own JSON-RPC error shape. */
interface BodyRefusal {
  status: number;
  code: number;
  message: string;
}

/**
 * A POST body read once and validated: `parsedBody` is the lossless parse's
 * plain form and is exactly what the SDK dispatches; `invocations` holds each
 * `tools/call` request's original arguments, serialized from that same parse
 * with their number spellings, keyed by {@link invocationKey}.
 */
interface ValidatedBody {
  parsedBody: unknown;
  invocations: ReadonlyMap<string, string>;
}

/** The key of a JSON-RPC request id among a body's invocations: a string or number id, by type and value. */
function invocationKey(id: unknown): string | undefined {
  if (typeof id === "string") return `s:${id}`;
  if (typeof id === "number") return `n:${id}`;
  return undefined;
}

/** The request body, or `"too_large"` once it passes `limit` (the rest is drained and discarded). */
function readBody(req: IncomingMessage, limit: number): Promise<Buffer | "too_large"> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let over = false;
    req.on("data", (chunk: Buffer) => {
      if (over) return;
      size += chunk.length;
      if (size > limit) {
        over = true;
        chunks.length = 0;
        resolve("too_large");
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (!over) resolve(Buffer.concat(chunks));
    });
    req.on("error", reject);
  });
}

const PARSE_ERROR: BodyRefusal = { status: 400, code: -32700, message: "Parse error: Invalid JSON" };

/**
 * @spec AAT -02 Section 3.4 and Section 8 steps 6b and 7f (#1756, D902):
 * validate a body as UTF-8 JSON with no duplicate member names, keeping each
 * number's source spelling, and collect each `tools/call`'s original
 * arguments. A batch that reuses a `tools/call` id is refused, so no call's
 * arguments can stand in for another's.
 */
function validateBody(raw: Buffer): ValidatedBody | BodyRefusal {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
  } catch {
    return PARSE_ERROR;
  }
  let tree: AatJson;
  try {
    tree = parseAatJson(text);
  } catch (e) {
    if (e instanceof AatJsonError) return PARSE_ERROR;
    throw e;
  }
  const invocations = new Map<string, string>();
  for (const message of Array.isArray(tree) ? tree : [tree]) {
    if (!aatIsObject(message) || message.method !== "tools/call") continue;
    const key = invocationKey(message.id instanceof AatNumber ? message.id.value : message.id);
    // A tools/call with no usable id is not a request the SDK dispatches.
    if (key === undefined) continue;
    if (invocations.has(key)) return { status: 400, code: -32600, message: "Invalid Request: a tools/call id repeats" };
    const params = message.params;
    invocations.set(key, originalArgumentsFrom(aatIsObject(params) ? params.arguments : undefined));
  }
  return { parsedBody: aatToPlainJson(tree), invocations };
}

/**
 * Read and validate a request's body before anything else sees it. A request
 * with no JSON body to read (not a POST, or not `application/json`, which
 * the SDK answers 415 without reading) passes through with none. Returns the
 * validated body, or `undefined` once it has answered the request.
 */
async function readValidatedBody(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<Partial<ValidatedBody> | undefined> {
  if (req.method !== "POST" || !(req.headers["content-type"] ?? "").includes("application/json")) return {};
  const raw = await readBody(req, MAX_REQUEST_BODY_BYTES);
  const body: ValidatedBody | BodyRefusal =
    raw === "too_large" ? { status: 413, code: -32600, message: "Invalid Request: body too large" } : validateBody(raw);
  if ("status" in body) {
    res.writeHead(body.status, { "content-type": "application/json", ...(raw === "too_large" ? { connection: "close" } : {}) });
    res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: body.code, message: body.message }, id: null }));
    return undefined;
  }
  return body;
}

/** The request signals carried to the PEP beside any validated credential. */
function requestSignals(req: IncomingMessage): Pick<RequestSignals, "acceptTxnChallenge" | "missionReference"> {
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
  return { acceptTxnChallenge, ...(missionReference ? { missionReference } : {}) };
}

/**
 * @spec attenuation#mission-binding-check (#1756 slice B3): the one
 * `tools/call` a body presents an attenuation chain for, `"refused"` for a
 * presentation this channel does not take (inside a batch), or undefined
 * when the body presents none. A presentation authorizes exactly one
 * invocation, so it is taken only on a body that is that one call.
 */
function presentedCall(parsedBody: unknown): Record<string, unknown> | "refused" | undefined {
  const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
  const presents = (m: unknown): boolean =>
    isObj(m) && isObj(m.params) && isObj(m.params._meta) && Object.hasOwn(m.params._meta, AAT_PRESENTATION_META_KEY);
  if (Array.isArray(parsedBody)) return parsedBody.some(presents) ? "refused" : undefined;
  return presents(parsedBody) && isObj(parsedBody) && parsedBody.method === "tools/call" ? parsedBody : undefined;
}

/** A body the presentation path does not take, answered in the SDK transport's JSON-RPC error shape. */
function invalidPresentationRequest(res: ServerResponse, message: string): void {
  res.writeHead(400, { "content-type": "application/json" });
  res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32600, message: `Invalid Request: ${message}` }, id: null }));
}

/**
 * @spec attenuation#mission-binding-check, AAT -02 Sections 7 and 8 (#1756
 * slice B3): authenticate a request whose one `tools/call` carries an
 * attenuation presentation. The presentation is the request's one
 * credential: an `Authorization` header beside it is refused, and so is a
 * session, since the proof authorizes this one invocation and opens
 * nothing. The proof is verified against the call's original arguments,
 * from the body this request is dispatched from. A refused presentation is
 * answered 401, a replay state at capacity 503, and the request is never
 * dispatched. Returns the validated facts, or undefined once it has
 * answered the request.
 */
async function authenticatePresentation(
  req: AuthedRequest,
  res: ServerResponse,
  paymentsServer: McpPaymentsServer,
  call: Record<string, unknown>,
  invocations: ReadonlyMap<string, string>,
): Promise<TokenFacts | undefined> {
  if (req.headers.authorization !== undefined) {
    unauthorized(res, "an attenuation presentation is the request's one credential");
    return undefined;
  }
  if (req.headers["mcp-session-id"] !== undefined) {
    invalidPresentationRequest(res, "an attenuation presentation is not made on a session");
    return undefined;
  }
  const params = call.params as Record<string, unknown>;
  const key = invocationKey(call.id);
  const argumentsJson = key === undefined ? undefined : invocations.get(key);
  if (typeof params.name !== "string" || argumentsJson === undefined) {
    invalidPresentationRequest(res, "a presented tools/call names no tool or carries no request id");
    return undefined;
  }
  const presentation = readAatPresentation((params._meta as Record<string, unknown>)[AAT_PRESENTATION_META_KEY]);
  if (presentation === undefined) {
    unauthorized(res, "malformed attenuation presentation");
    return undefined;
  }
  let facts: TokenFacts;
  try {
    facts = await paymentsServer.validateAatPresentation(presentation, params.name, argumentsJson);
  } catch (e) {
    if (e instanceof DpopReplayUnavailableError) {
      replayStateUnavailable(res, e.retryAfterS);
      return undefined;
    }
    unauthorized(res, "attenuation presentation refused");
    return undefined;
  }
  req.auth = {
    token: "",
    clientId: facts.clientId,
    scopes: [],
    extra: { tokenFacts: facts, signals: requestSignals(req), invocations, aatPresented: true },
  };
  return facts;
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
  invocations?: ReadonlyMap<string, string>,
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
    // @spec RFC 7662 (#818 slice 3): an estate that gave no usable
    // introspection answer is not a refusal of the token, and never a permit.
    if (e instanceof IntrospectionUnavailableError) {
      res.writeHead(503, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "temporarily_unavailable", error_description: "token introspection unavailable" }));
      return undefined;
    }
    unauthorized(res, "DPoP proof-of-possession failed");
    return undefined;
  }

  const { acceptTxnChallenge, missionReference } = requestSignals(req);
  // The SDK's AuthInfo shape; the MCP handlers read facts from extra.tokenFacts.
  req.auth = {
    token: accessToken,
    clientId: facts.clientId,
    scopes: [],
    extra: {
      tokenFacts: facts,
      // @spec authority-server#join-assertion-request (#1454): a MAS-governed
      // route hands the PEP the credential it authenticated, for its Join
      // Assertion request.
      signals: {
        ...(acceptTxnChallenge !== undefined ? { acceptTxnChallenge } : {}),
        ...(missionReference ? { missionReference } : {}),
        ...(masGoverned ? { accessToken } : {}),
      },
      // @spec AAT -02 Section 8 steps 6b and 7f (#1756, D902): each tools/call's
      // original arguments, from the body this request is dispatched from.
      ...(invocations ? { invocations } : {}),
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
    /**
     * @spec authority-server#mission-join, mission#authority-proposal (#1531,
     * D741): the resource identifier a MAS-governed route is served under, for
     * a join route that is its own resource. Its RFC 9728 metadata then names
     * this identifier and does not declare Mission-bound-only acceptance
     * (`McpPaymentsServer.joinRouteMetadata`). The enforcement boundary must
     * accept it as an audience alias. Valid only with `masGoverned`; absent,
     * the route publishes this resource's own metadata.
     */
    resource?: string;
  },
): Promise<HttpMcpChannel> {
  const host = opts?.host ?? "127.0.0.1";
  const masGoverned = opts?.masGoverned ?? false;
  const joinResource = opts?.resource;
  if (joinResource !== undefined && !masGoverned) {
    throw new Error("a route's own resource identifier is for a MAS-governed join route only");
  }
  const sessions = new Map<string, McpSession>();

  /**
   * Hand an authenticated request to its session. A request naming a session
   * reaches it only when the session's holder is this request's holder; a
   * request naming none gets a fresh transport and MCP `Server`, which keep
   * the session an `initialize` opens on them. The SDK answers anything else
   * there 400, and that pair is discarded.
   */
  const dispatch = async (
    req: AuthedRequest,
    res: ServerResponse,
    holder: SessionHolder,
    parsedBody: unknown,
  ): Promise<void> => {
    // @spec AAT -02 Section 8 steps 6b and 7f (#1756, D902): the SDK dispatches
    // `parsedBody`, the validated parse of the body read before authentication,
    // never a second parse of its own.
    const sessionId = req.headers["mcp-session-id"];
    if (sessionId !== undefined) {
      const session = typeof sessionId === "string" ? sessions.get(sessionId) : undefined;
      if (!session || !sameHolder(session.holder, holder)) return sessionNotFound(res);
      return session.transport.handleRequest(req, res, parsedBody);
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
    await transport.handleRequest(req, res, parsedBody);
    if (transport.sessionId === undefined) await server.close().catch(() => {});
  };

  /**
   * @spec attenuation#mission-binding-check (#1756 slice B3): hand a request
   * its presentation authenticated to a stateless transport and MCP
   * `Server`, discarded once it is answered. It opens no session.
   */
  const dispatchPresented = async (req: AuthedRequest, res: ServerResponse, parsedBody: unknown): Promise<void> => {
    const server = createHttpMcpServer(paymentsServer);
    // No `sessionIdGenerator`: a stateless transport, which answers without `initialize`.
    const transport = new StreamableHTTPServerTransport({ enableJsonResponse: true });
    await server.connect(transport as unknown as Transport);
    try {
      await transport.handleRequest(req, res, parsedBody);
    } finally {
      await server.close().catch(() => {});
    }
  };

  const httpServer: HttpServer = createServer((req, res) => {
    // @spec txn-authorization#two-phase-expiry — the unauthenticated discovery
    // routes (RFC 9728 metadata + txn_challenge_jwks_uri) are served in front of
    // the credential gate: they publish public keys and metadata.
    if (serveResourceMetadata(paymentsServer, req, res, joinResource)) return;
    const authed = req as AuthedRequest;
    // @spec AAT -02 Section 8 steps 6b and 7f (#1756, D902): the body is read
    // and validated once, before authentication, and that one validated parse
    // is what is dispatched.
    readValidatedBody(req, res)
      .then(async (body) => {
        if (body === undefined) return;
        const presented = presentedCall(body.parsedBody);
        if (presented === "refused") return invalidPresentationRequest(res, "an attenuation presentation is not taken in a batch");
        if (presented !== undefined) {
          const facts = await authenticatePresentation(authed, res, paymentsServer, presented, body.invocations ?? new Map());
          if (facts) await dispatchPresented(authed, res, body.parsedBody);
          return;
        }
        const facts = await authenticate(authed, res, paymentsServer, masGoverned, body.invocations);
        if (facts) await dispatch(authed, res, holderOf(facts), body.parsedBody);
      })
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

/** The answer to one presented tools/call: the HTTP status, and the PEP verdict when the call was dispatched. */
export interface PresentedCallResult {
  status: number;
  verdict?: MediatedToolResult;
  body: unknown;
}

/**
 * @spec attenuation#mission-binding-check, AAT -02 Sections 7 and 8 (#1756
 * slice B3): one `tools/call` whose one credential is an attenuation
 * presentation, POSTed on no session and with no `Authorization` header.
 * The arguments are serialized once, and `present` builds the presentation
 * from that JSON text, so the proof's `hta` covers exactly the arguments the
 * body carries. Its result is typed `unknown` so a caller (and a test) can
 * present a malformed shape. `argumentsText`, when given, is the body's
 * `arguments` text verbatim in place of the snapshot.
 */
export async function callToolWithPresentation(
  url: string,
  name: string,
  args: Record<string, unknown>,
  present: (call: { name: string; argumentsJson: string }) => Promise<unknown>,
  opts: { missionReference?: unknown; headers?: Record<string, string>; argumentsText?: string } = {},
): Promise<PresentedCallResult> {
  const snapshot = snapshotArguments(args);
  const argumentsText = opts.argumentsText ?? snapshot.argumentsJson;
  const presentation = await present({ name, argumentsJson: argumentsText });
  const meta = JSON.stringify({
    [AAT_PRESENTATION_META_KEY]: presentation,
    ...(opts.missionReference !== undefined ? { [MCP_REFERENCE_META_KEY]: opts.missionReference } : {}),
  });
  const body = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":${JSON.stringify(name)},"arguments":${argumentsText},"_meta":${meta}}}`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...(opts.headers ?? {}) },
    body,
  });
  const text = await res.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = text;
  }
  const result = (parsed as { result?: { structuredContent?: unknown } } | undefined)?.result;
  return {
    status: res.status,
    ...(result?.structuredContent !== undefined ? { verdict: result.structuredContent as MediatedToolResult } : {}),
    body: parsed,
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
    async callTool(name, args, missionReference) {
      // @spec AAT -02 Section 8 steps 6b and 7f (#1756, D902): the object API's
      // serialization boundary, as on the in-memory client: the arguments are
      // serialized once, and the call carries exactly that snapshot.
      const snapshot = snapshotArguments(args);
      const res = await mcp.callTool({
        name,
        arguments: snapshot.args,
        ...(missionReference !== undefined ? { _meta: { [MCP_REFERENCE_META_KEY]: missionReference } } : {}),
      });
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
