/**
 * @spec AAT -02 Section 3.4 and Section 8 steps 6b and 7f (#1756 slice B2,
 * D902): the raw-JSON invocation boundary. A proof that binds a tool
 * invocation is checked against the arguments as written, so each transport
 * fixes a call's original arguments once and every later step works from
 * that text:
 *
 * - HTTP reads the body once, refuses a malformed body or a duplicate member
 *   name before authentication and dispatch, dispatches exactly that parse,
 *   and hands the tool path the original arguments with their number
 *   spellings;
 * - the in-memory object API serializes the arguments once, and the server
 *   verifies and dispatches that one snapshot;
 * - the PEP's intake receives the original text before it normalizes the
 *   arguments, and refuses text that does not describe the arguments
 *   dispatched.
 *
 * The transport cases run over a stub payments server (as in
 * mcp-http-sessions.test.ts) that records what reaches the tool path; the
 * seam cases run over the real PEP with a stub FGA. Unconditional.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { LATEST_PROTOCOL_VERSION } from "@modelcontextprotocol/sdk/types.js";
import { generateKeyPair } from "jose";
import { afterEach, describe, expect, it } from "vitest";
import type { Fga, MissionView } from "@mission/pdp";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import {
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  createHttpMcpChannel,
  createHttpMediatedClient,
  createMcpChannel,
  credentialAuthorityFrom,
  EvidenceStore,
  type HttpMcpChannel,
  INVOCATION_ARGUMENTS_META_KEY,
  MediatedClient,
  McpPaymentsServer,
  MISSION_TOKEN_META_KEY,
  openEphemeralWriteReservationStore,
  originalArgumentsMatch,
  PaymentsStore,
  Pep,
  type RequestSignals,
  type TokenFacts,
} from "../src/index.js";

/** One call that reached the tool path: its tool, its dispatched arguments, and the transport's signals. */
interface Reached {
  name: string;
  args: Record<string, unknown>;
  signals: RequestSignals | undefined;
}

/** A stub payments server: `tok-owner` is the one valid credential, and each read is recorded. */
function stubServer(reached: Reached[]): McpPaymentsServer {
  return {
    validateCredential: async (token: string): Promise<TokenFacts> => {
      if (token !== "tok-owner") throw new Error("credential refused");
      return {
        cnfJkt: "jkt-1",
        sub: "alice",
        clientId: "ap-agent",
        mission: { id: "msn_1", issuer: "https://as.test" },
        credentialAuthority: [],
      } as unknown as TokenFacts;
    },
    hasTransactionTier: () => false,
    txnChallengeJwks: () => undefined,
    toolsList: () => [{ name: "get_invoice" }],
    capabilityCatalog: { toolDefinitions: (names: string[]) => names.map((name) => ({ name, inputSchema: { type: "object" } })) },
    callReadTool: async (name: string, args: Record<string, unknown>, _token: TokenFacts, _hook: unknown, signals?: RequestSignals) => {
      reached.push({ name, args, signals });
      return { ok: true, result: { id: "inv-1" } };
    },
  } as unknown as McpPaymentsServer;
}

const channels: HttpMcpChannel[] = [];
const closers: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const close of closers.splice(0).reverse()) await close().catch(() => {});
  for (const channel of channels.splice(0)) await channel.close();
});

/** A running HTTP channel over the stub, and a session `tok-owner` opened on it. */
async function httpSession(reached: Reached[]): Promise<{ url: string; sessionId: string }> {
  const channel = await createHttpMcpChannel(stubServer(reached));
  channels.push(channel);
  const { sessionId, close } = await createHttpMediatedClient(
    channel.url,
    "tok-owner",
    await generateKeyPair("ES256", { extractable: true }),
  );
  closers.push(close);
  return { url: channel.url, sessionId: sessionId as string };
}

/** POST `body` as written to the channel, on `sessionId` with `tok-owner` (the stub reads no proof), or with no credential at all. */
async function post(
  url: string,
  sessionId: string | undefined,
  body: string,
  credential = true,
): Promise<{ status: number; json: Record<string, unknown> }> {
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      "mcp-protocol-version": LATEST_PROTOCOL_VERSION,
      ...(credential ? { authorization: "DPoP tok-owner", dpop: "stub-proof" } : {}),
      ...(sessionId ? { "mcp-session-id": sessionId } : {}),
    },
    body,
  });
  return { status: res.status, json: (await res.json()) as Record<string, unknown> };
}

/** A tools/call body, written out by hand so its spelling is exactly what is sent. */
const toolsCall = (id: string, args: string): string =>
  `{"jsonrpc":"2.0","id":${id},"method":"tools/call","params":{"name":"get_invoice","arguments":${args}}}`;

describe("HTTP: the body is read once, validated, and dispatched as validated (@spec AAT -02 Section 8 steps 6b and 7f, #1756, D902)", () => {
  it("refuses a duplicate member name, at the top level or inside the arguments, as a parse error before authentication and dispatch", async () => {
    const reached: Reached[] = [];
    const { url, sessionId } = await httpSession(reached);
    const bodies = [
      toolsCall("7", '{"invoice_id":"inv-1","invoice_id":"inv-2"}'),
      `{"jsonrpc":"2.0","id":7,"id":8,"method":"tools/call","params":{"name":"get_invoice","arguments":{"invoice_id":"inv-1"}}}`,
    ];
    for (const body of bodies) {
      for (const credential of [true, false]) {
        const res = await post(url, sessionId, body, credential);
        expect(res.status, body).toBe(400);
        expect(res.json.error).toMatchObject({ code: -32700 });
      }
    }
    expect(reached).toEqual([]);
  });

  it("hands the tool path the original arguments with each number's source spelling, beside the arguments it dispatched", async () => {
    const reached: Reached[] = [];
    const { url, sessionId } = await httpSession(reached);
    const args = '{"invoice_id":"inv-1","amount":1.50,"count":1e2}';
    const res = await post(url, sessionId, toolsCall("7", args));
    expect(res.status).toBe(200);
    expect(reached).toHaveLength(1);
    expect(reached[0]?.signals?.invocation?.argumentsJson).toBe(args);
    expect(reached[0]?.args).toEqual({ invoice_id: "inv-1", amount: 1.5, count: 100 });
  });

  it("dispatches what it validated: the original text and the dispatched arguments describe one call, and a batch that reuses a tools/call id is refused", async () => {
    const reached: Reached[] = [];
    const { url, sessionId } = await httpSession(reached);
    // An escape the original text need not preserve: the value is the same.
    const res = await post(url, sessionId, toolsCall("7", '{"invoice_id":"inv\\u002d1"}'));
    expect(res.status).toBe(200);
    const call = reached[0] as Reached;
    expect(call.args).toEqual({ invoice_id: "inv-1" });
    expect(originalArgumentsMatch(call.signals?.invocation as { argumentsJson: string }, call.args)).toBe(true);
    // Two calls under one id would leave the id naming either call's arguments.
    const batch = `[${toolsCall("9", '{"invoice_id":"inv-1"}')},${toolsCall("9", '{"invoice_id":"inv-2"}')}]`;
    const refused = await post(url, sessionId, batch);
    expect(refused.status).toBe(400);
    expect(refused.json.error).toMatchObject({ code: -32600 });
    expect(reached).toHaveLength(1);
  });

  it("refuses a body over the bound before reading the rest", async () => {
    const reached: Reached[] = [];
    const { url, sessionId } = await httpSession(reached);
    const padding = "x".repeat(4 * 1024 * 1024);
    const res = await post(url, sessionId, toolsCall("7", `{"invoice_id":"${padding}"}`));
    expect(res.status).toBe(413);
    expect(reached).toEqual([]);
  });

  it("carries a client's call end to end: the original text is the client's one snapshot", async () => {
    const reached: Reached[] = [];
    const channel = await createHttpMcpChannel(stubServer(reached));
    channels.push(channel);
    const { client, close } = await createHttpMediatedClient(
      channel.url,
      "tok-owner",
      await generateKeyPair("ES256", { extractable: true }),
    );
    closers.push(close);
    expect((await client.callTool("get_invoice", { invoice_id: "inv-1" })).ok).toBe(true);
    expect(reached[0]?.signals?.invocation?.argumentsJson).toBe('{"invoice_id":"inv-1"}');
  });
});

describe("in-memory: the object API's serialization boundary (@spec AAT -02 Section 8 steps 6b and 7f, #1756, D902)", () => {
  it("dispatches the client's one snapshot: changing the caller's object after the call starts changes nothing", async () => {
    const reached: Reached[] = [];
    const { clientTransport, server } = await createMcpChannel(stubServer(reached));
    const client = new MediatedClient(clientTransport);
    await client.connect();
    closers.push(async () => {
      await client.close();
      await server.close();
    });
    const args: Record<string, unknown> = { invoice_id: "inv-1" };
    const pending = client.callTool("get_invoice", args, "tok-owner");
    args.invoice_id = "inv-2";
    expect((await pending).ok).toBe(true);
    expect(reached[0]?.args).toEqual({ invoice_id: "inv-1" });
    expect(reached[0]?.signals?.invocation?.argumentsJson).toBe('{"invoice_id":"inv-1"}');
  });

  it("refuses a snapshot that does not describe the arguments sent, or does not parse, and takes one for a caller that sends none", async () => {
    const reached: Reached[] = [];
    const { clientTransport, server } = await createMcpChannel(stubServer(reached));
    const raw = new Client({ name: "raw", version: "0.0.1" }, { capabilities: {} });
    await raw.connect(clientTransport);
    closers.push(async () => {
      await raw.close();
      await server.close();
    });
    const call = async (snapshot?: unknown) =>
      (
        await raw.callTool({
          name: "get_invoice",
          arguments: { invoice_id: "inv-1" },
          _meta: {
            [MISSION_TOKEN_META_KEY]: "tok-owner",
            ...(snapshot !== undefined ? { [INVOCATION_ARGUMENTS_META_KEY]: snapshot } : {}),
          },
        })
      ).structuredContent;
    expect(await call('{"invoice_id":"inv-2"}')).toMatchObject({ ok: false, refusal_reason: "invalid_request" });
    expect(await call('{"invoice_id":"inv-1","invoice_id":"inv-1"}')).toMatchObject({
      ok: false,
      refusal_reason: "invalid_request",
    });
    expect(await call(42)).toMatchObject({ ok: false, refusal_reason: "invalid_request" });
    expect(reached).toEqual([]);
    expect(await call()).toMatchObject({ ok: true });
    expect(reached[0]?.signals?.invocation?.argumentsJson).toBe('{"invoice_id":"inv-1"}');
  });
});

describe("the seam: intake receives the original text before it normalizes the arguments (@spec AAT -02 Section 8 steps 6b and 7f, #1756, D902)", () => {
  const EVIDENCE_KEYS = createEphemeralEvidenceKeys({ resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE });
  const ISSUER = "https://as.test";
  const MISSION = "msn_1756_b2";

  function realServer(): { server: McpPaymentsServer; pep: Pep; evidence: EvidenceStore; decisions: () => number } {
    const payments = new PaymentsStore();
    payments.seed(
      [{ id: "acme", name: "Acme", status: "approved" }],
      [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
    );
    const view: MissionView = {
      id: MISSION,
      issuer: ISSUER,
      state: "active",
      version: 1,
      authority_hash: "sha-256:m1756",
      authority_set: [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] }],
      subject: { iss: ISSUER, sub: "alice" },
      client_id: "ap-agent",
    };
    const loadView = (ref: { id: string; issuer: string }) =>
      ref.id === MISSION && ref.issuer === ISSUER
        ? { view, observation: { state: "active", version: 1, mode: "fresh", freshness_at: new Date().toISOString() } }
        : undefined;
    const evidence = new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver);
    let decisions = 0;
    const pep = new Pep({
      decide: async (req, options) => {
        decisions++;
        return EVIDENCE_KEYS.decide(req, options);
      },
      payments,
      evidence,
      fga: { checkWithContext: async () => true } as unknown as Fga,
      modelId: "unit-test-model",
      loadView,
      instanceEpoch: "epoch-1756-b2",
    });
    const server = new McpPaymentsServer({
      pep,
      payments,
      loadView,
      jwks: { keys: [] },
      keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] },
      issuer: ISSUER,
      writeReservations: openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" }),
    });
    return { server, pep, evidence, decisions: () => decisions };
  }

  const token = {
    sub: "alice",
    clientId: "ap-agent",
    mission: { id: MISSION, issuer: ISSUER, authority_hash: "sha-256:m1756" },
    cnfJkt: "jkt-1756",
    credentialAuthority: credentialAuthorityFrom([
      { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] },
    ]),
  } as unknown as TokenFacts;

  it("hands intake the transport's original text, ahead of normalization", async () => {
    const r = realServer();
    const seen: unknown[] = [];
    const intake = r.pep.intake.bind(r.pep);
    r.pep.intake = (tool, args, facts, invocation) => {
      seen.push(invocation);
      return intake(tool, args, facts, invocation);
    };
    const res = await r.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, token, undefined, {
      invocation: { argumentsJson: '{"invoice_id":"inv-1"}' },
    });
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect(seen).toEqual([{ argumentsJson: '{"invoice_id":"inv-1"}' }]);
  });

  it("refuses invalid_request, before any decision, when the original text does not describe the arguments dispatched", async () => {
    for (const argumentsJson of ['{"invoice_id":"inv-2"}', '{"invoice_id":"inv-1","invoice_id":"inv-1"}', "[]"]) {
      const r = realServer();
      const res = await r.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, token, undefined, {
        invocation: { argumentsJson },
      });
      expect(res, argumentsJson).toMatchObject({ ok: false, refusal_reason: "invalid_request" });
      expect(r.decisions()).toBe(0);
      expect(r.evidence.all().some((e) => e.kind === "refusal")).toBe(true);
    }
  });
});
