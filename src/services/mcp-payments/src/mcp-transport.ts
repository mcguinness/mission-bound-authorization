/**
 * @spec draft-mcguinness-mission-harness (mediated execution environment)
 *
 * Increment 1: a REAL Model Context Protocol channel over the existing PEP.
 * This is the harness profile's duty 2 -- "work in a mediated action class has
 * no path that bypasses the enforcement point (PEP)". The MCP `Server` handlers
 * delegate every `tools/list` and `tools/call` to the unchanged
 * {@link McpPaymentsServer}, so the mediated channel enforces identically to the
 * direct PEP path; there is no side door.
 *
 * The mission credential travels IN the MCP request (not a side channel): the
 * client puts the mission access token (JWT) under a namespaced `_meta` key
 * ({@link MISSION_TOKEN_META_KEY}). MCP `_meta` is a passthrough (`z.core.$loose`)
 * object, so the custom key survives the round-trip. The server validates the
 * token (jose, via the RS jwks/issuer it already holds) and derives TokenFacts;
 * a bare TokenFacts object is never accepted over the wire.
 *
 * This realises the O-33 "production swap" the server file comment names: the
 * hand-rolled MCP shape is now driven by the `@modelcontextprotocol/sdk` in-memory
 * transport. The low-level `Server` (not the high-level `McpServer`) is used
 * deliberately: only it exposes a per-request `tools/list` handler, which is
 * what mission-scoped least exposure needs (the tool set depends on the caller's
 * credential, not a static registration).
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  CallToolRequestSchema,
  type CallToolResult,
  ListToolsRequestSchema,
  type ListToolsResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { type InsufficientAuthorization, TOOL_ACTIONS, type TokenFacts } from "./pep.js";
import type { McpPaymentsServer, ToolDef } from "./server.js";

/**
 * The namespaced `_meta` key that carries the mission access token (JWT) across
 * the MCP boundary. Namespaced so it never collides with MCP's own `_meta`
 * members (progressToken, related-task).
 */
export const MISSION_TOKEN_META_KEY = "io.mission-bound/token";

/** The enforcement result the channel surfaces to the client (PEP verdict). */
export interface MediatedToolResult {
  ok: boolean;
  result?: unknown;
  denial_reason?: string;
  refusal_reason?: string;
  deduped?: boolean;
  /** @spec I-D.draft-zehavi-oauth-rar-metadata §4 — present on a genuine
   * out_of_authority denial; see pep.ts's InsufficientAuthorization. */
  insufficient_authorization?: InsufficientAuthorization;
  /**
   * @spec txn-authorization#resource-challenge — the upstream members, carried
   * verbatim onto the tool-result surface: `transaction_authorization_required`
   * plus the signed challenge.
   */
  error?: string;
  transaction_challenge?: string;
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

/** Route a tool call to the same PEP methods the direct callers use. Unknown or
 * ungranted tools fall through to the PEP, which refuses/denies them -- there is
 * no routing shortcut that skips enforcement. */
async function route(
  paymentsServer: McpPaymentsServer,
  name: string,
  args: Record<string, unknown>,
  token: TokenFacts,
): Promise<MediatedToolResult> {
  const mapping = TOOL_ACTIONS[name];
  if (mapping?.actionClass && paymentsServer.hasTransactionTier()) {
    return paymentsServer.callTransactionTool(name, args, token);
  }
  if (name === "schedule_payment" || (mapping?.actionClass && !paymentsServer.hasTransactionTier())) {
    return paymentsServer.callWriteTool(name, args, token);
  }
  return paymentsServer.callReadTool(name, args, token);
}

/**
 * Build a real MCP `Server` whose handlers delegate to the existing
 * McpPaymentsServer. Every request derives TokenFacts from the validated `_meta`
 * credential before touching the PEP.
 */
function createMcpServer(paymentsServer: McpPaymentsServer): Server {
  const server = new Server(
    { name: "mission-payments", version: "0.0.1" },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async (request): Promise<ListToolsResult> => {
    const cred = request.params?._meta?.[MISSION_TOKEN_META_KEY];
    if (typeof cred !== "string") return { tools: [] };
    let token: TokenFacts;
    try {
      token = await paymentsServer.validateCredential(cred);
    } catch {
      // An unvalidated caller sees nothing (fail closed, least exposure).
      return { tools: [] };
    }
    return { tools: paymentsServer.toolsList(token).map(toMcpTool) };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request): Promise<CallToolResult> => {
    const cred = request.params._meta?.[MISSION_TOKEN_META_KEY];
    const args = (request.params.arguments ?? {}) as Record<string, unknown>;
    let token: TokenFacts;
    try {
      if (typeof cred !== "string") throw new Error("missing mission credential in _meta");
      // @spec txn-authorization#transaction-token — ONE credential crosses the
      // boundary: the ordinary Mission-bound token, or the transaction token
      // that authorizes the retry of a challenged operation. There is no
      // separate txn carrier on this channel either.
      //
      // @spec txn-authorization#offline-verification step 2 — but a transaction
      // credential requires proof of possession on the request that presents
      // it, and this channel has no HTTP request to bind a proof to (the
      // documented simplification the ordinary class runs under). The
      // transaction-token path is therefore NOT available here: it is refused
      // outright, with its own reason, rather than admitted unproven. The
      // challenged retry goes over the HTTP transport.
      token = await paymentsServer.validateCredential(cred);
    } catch (e) {
      // No valid credential -> structured denial, not a thrown transport error.
      if (String((e as Error)?.message ?? "").includes("txn_pop_required")) {
        return toCallToolResult({ ok: false, refusal_reason: "txn_pop_required" });
      }
      return toCallToolResult({ ok: false, denial_reason: "invalid_credential" });
    }
    const verdict = await route(paymentsServer, request.params.name, args, token);
    return toCallToolResult(verdict);
  });

  return server;
}

/**
 * Create the mediated MCP channel: a linked in-memory transport pair with the
 * MCP server side already connected. The caller drives the returned client
 * transport (typically via {@link MediatedClient}).
 */
export async function createMcpChannel(
  paymentsServer: McpPaymentsServer,
): Promise<{ clientTransport: InMemoryTransport; server: Server }> {
  const server = createMcpServer(paymentsServer);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  return { clientTransport, server };
}

/**
 * The harness's mediated MCP client. The ONLY tool path is `client.callTool` /
 * `client.listTools`: there is no method that reaches the payments store or PEP
 * except through the MCP request, carrying the mission credential in `_meta`.
 */
export class MediatedClient {
  private readonly client: Client;
  constructor(
    private readonly transport: InMemoryTransport,
    info: { name: string; version: string } = { name: "mission-harness", version: "0.0.1" },
  ) {
    this.client = new Client(info, { capabilities: {} });
  }

  async connect(): Promise<void> {
    await this.client.connect(this.transport);
  }

  /** Mission-scoped tools/list over MCP (credential in `_meta`). */
  async listTools(missionToken: string): Promise<string[]> {
    const res = await this.client.listTools({ _meta: { [MISSION_TOKEN_META_KEY]: missionToken } });
    return res.tools.map((t) => t.name);
  }

  /** tools/call over MCP (credential in `_meta`); returns the PEP verdict. */
  async callTool(name: string, args: Record<string, unknown>, missionToken: string): Promise<MediatedToolResult> {
    const res = await this.client.callTool({
      name,
      arguments: args,
      _meta: { [MISSION_TOKEN_META_KEY]: missionToken },
    });
    return (res.structuredContent ?? { ok: false, refusal_reason: "no_result" }) as unknown as MediatedToolResult;
  }

  async close(): Promise<void> {
    await this.client.close();
  }
}

/** Convenience: build the channel and a connected {@link MediatedClient}. */
export async function createMediatedClient(
  paymentsServer: McpPaymentsServer,
): Promise<{ client: MediatedClient; server: Server }> {
  const { clientTransport, server } = await createMcpChannel(paymentsServer);
  const client = new MediatedClient(clientTransport);
  await client.connect();
  return { client, server };
}
