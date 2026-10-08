/**
 * @spec runtime-oauth#token-validation (D315, #1105): MCP sessions on the HTTP
 * channel. Each client's `initialize` opens its own session, so successive and
 * concurrent clients each get a usable one. A session belongs to the holder
 * whose credential opened it (the DPoP key `cnf.jkt`, the subject and the
 * client): every request on it is still authenticated, and a request from any
 * other holder is answered 404 `Session not found`, as for a session that does
 * not exist, without reaching a handler.
 *
 * The payments server is a stub whose `validateCredential` maps each token to
 * fixed facts, so the holder rule is exercised member by member with no PDP or
 * OpenFGA; `demo/test/as-native-stack.test.ts` covers the same rule on the
 * assembled target with AS-issued tokens and real DPoP proofs.
 */

import { generateKeyPair } from "jose";
import { afterEach, describe, expect, it } from "vitest";
import {
  createHttpMcpChannel,
  createHttpMediatedClient,
  type DpopKeys,
  type HttpMcpChannel,
  type McpPaymentsServer,
  type TokenFacts,
} from "../src/index.js";

/** The holder each token stands for; every token not listed fails validation. */
const HOLDERS: Record<string, { cnfJkt: string; sub: string; clientId: string }> = {
  "tok-owner": { cnfJkt: "jkt-1", sub: "alice", clientId: "ap-agent" },
  // The same holder under another credential (a refreshed token, say).
  "tok-owner-refreshed": { cnfJkt: "jkt-1", sub: "alice", clientId: "ap-agent" },
  "tok-other-key": { cnfJkt: "jkt-2", sub: "alice", clientId: "ap-agent" },
  "tok-other-subject": { cnfJkt: "jkt-1", sub: "bob", clientId: "ap-agent" },
  "tok-other-client": { cnfJkt: "jkt-1", sub: "alice", clientId: "other-agent" },
};

/** A stub payments server: credentials resolve through HOLDERS, and each read is recorded. */
function stubServer(calls: string[]): McpPaymentsServer {
  return {
    validateCredential: async (token: string): Promise<TokenFacts> => {
      const holder = HOLDERS[token];
      if (!holder) throw new Error("credential refused");
      return {
        ...holder,
        mission: { id: "msn_1", issuer: "https://as.test" },
        credentialAuthority: [],
      } as TokenFacts;
    },
    hasTransactionTier: () => false,
    txnChallengeJwks: () => undefined,
    toolsList: () => [{ name: "get_invoice" }],
    capabilityCatalog: { toolDefinitions: (names: string[]) => names.map((name) => ({ name, inputSchema: { type: "object" } })) },
    callReadTool: async (name: string, _args: unknown, token: TokenFacts) => {
      calls.push(`${name}:${token.sub}`);
      return { ok: true, result: { id: "inv-1" } };
    },
  } as unknown as McpPaymentsServer;
}

const channels: HttpMcpChannel[] = [];
afterEach(async () => {
  for (const channel of channels.splice(0)) await channel.close();
});

async function start(calls: string[]): Promise<HttpMcpChannel> {
  const channel = await createHttpMcpChannel(stubServer(calls));
  channels.push(channel);
  return channel;
}

const keys = (): Promise<DpopKeys> => generateKeyPair("ES256", { extractable: true });

/** A raw tools/call carrying `token` (the stub reads no proof) and, optionally, a session id. */
async function rawCall(url: string, token: string, sessionId?: string): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      authorization: `DPoP ${token}`,
      dpop: "stub-proof",
      ...(sessionId ? { "mcp-session-id": sessionId } : {}),
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: "get_invoice", arguments: { invoice_id: "inv-1" } } }),
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

describe("MCP sessions on the HTTP channel (D315, #1105)", () => {
  it("opens a session per initialize: a client after another has closed, and two clients at once, each get a usable session", async () => {
    const calls: string[] = [];
    const channel = await start(calls);
    const ids: (string | undefined)[] = [];
    for (let i = 0; i < 2; i++) {
      const { client, sessionId, close } = await createHttpMediatedClient(channel.url, "tok-owner", await keys());
      ids.push(sessionId);
      expect((await client.callTool("get_invoice", { invoice_id: "inv-1" })).ok).toBe(true);
      await close();
    }
    const a = await createHttpMediatedClient(channel.url, "tok-owner", await keys());
    const b = await createHttpMediatedClient(channel.url, "tok-other-subject", await keys());
    ids.push(a.sessionId, b.sessionId);
    expect((await a.client.callTool("get_invoice", { invoice_id: "inv-1" })).ok).toBe(true);
    expect((await b.client.callTool("get_invoice", { invoice_id: "inv-1" })).ok).toBe(true);
    await a.close();
    await b.close();
    expect(new Set(ids).size).toBe(4);
    expect(calls).toEqual(["get_invoice:alice", "get_invoice:alice", "get_invoice:alice", "get_invoice:bob"]);
  });

  it("dispatches a request on a session only for its holder: another key, subject or client is answered 404 Session not found and reaches no handler, and a refused credential is answered 401", async () => {
    const calls: string[] = [];
    const channel = await start(calls);
    const owner = await createHttpMediatedClient(channel.url, "tok-owner", await keys());
    const sessionId = owner.sessionId as string;
    expect(sessionId).toBeTruthy();
    for (const intruder of ["tok-other-key", "tok-other-subject", "tok-other-client"]) {
      const res = await rawCall(channel.url, intruder, sessionId);
      expect(res.status, intruder).toBe(404);
      expect((res.body.error as { message?: string }).message, intruder).toBe("Session not found");
    }
    // Every request on the session is authenticated first.
    expect((await rawCall(channel.url, "tok-revoked", sessionId)).status).toBe(401);
    // An unknown session id is answered the same way as another holder's.
    expect((await rawCall(channel.url, "tok-owner", "no-such-session")).status).toBe(404);
    expect(calls).toEqual([]);
    // The holder's other credential uses the session; so does the client.
    const refreshed = await rawCall(channel.url, "tok-owner-refreshed", sessionId);
    expect(refreshed.status, JSON.stringify(refreshed.body)).toBe(200);
    expect((await owner.client.callTool("get_invoice", { invoice_id: "inv-1" })).ok).toBe(true);
    expect(calls).toEqual(["get_invoice:alice", "get_invoice:alice"]);
    await owner.close();
  });

  it("ends a session when its client closes, through an authenticated DELETE, and keeps it while the client is open", async () => {
    const channel = await start([]);
    const open = await createHttpMediatedClient(channel.url, "tok-owner", await keys());
    expect((await rawCall(channel.url, "tok-owner", open.sessionId)).status).toBe(200);
    await open.close();
    expect((await rawCall(channel.url, "tok-owner", open.sessionId)).status).toBe(404);
  });
});
