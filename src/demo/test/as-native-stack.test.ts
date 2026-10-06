/**
 * @spec runtime-oauth#token-validation (D284, D315, #1105)
 *
 * #253's first runtime target, the AS-native payments composition, exactly as
 * `composeStack({ target: "as-native" })` assembles it for `pnpm as-native`:
 * the real authorization server issues a Mission-bound token over PAR,
 * approval and the token endpoint, and the client presents it over the HTTP
 * MCP transport at the declared resource audience with a DPoP proof. Under
 * D315 that endpoint is the target's only entry point: the in-process
 * mediated channel and the MAS join route are outside it.
 *
 * Two compositions run the same assertions. The first stubs only the OpenFGA
 * client, as `remote-pdp-stack.test.ts` does (the AS, kernel, PEP, PDP,
 * decision channel and Decision Evidence are real), so it runs everywhere. The
 * second ([FGA]) runs against a live OpenFGA and is skipped without one, so
 * only CI with OpenFGA exercises it. Both bind the declared audience's port
 * (4403), so neither runs beside a live `pnpm as-native`.
 */

import { mkdtempSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { calculateJwkThumbprint, exportJWK, generateKeyPair } from "jose";
import { afterAll, beforeAll, describe, expect, it, type MockInstance, vi } from "vitest";
import { CANONICAL_RESOURCE, DEV_SERVICE_TOKEN, TOPOLOGY } from "@mission/demo-data";
import {
  canonicalHtu,
  createHttpMcpChannel,
  createHttpMediatedClient,
  type DpopKeys,
  dpopProofFor,
  type McpPaymentsServer,
} from "@mission/mcp-payments";
import { Fga } from "@mission/pdp";
import { issueMissionToken } from "../src/approval-console.js";
import type { IssuedMission } from "../src/oauth-client.js";
import { composeStack, type DemoStack } from "../src/stack.js";

/** @spec runtime#idempotency (#917): each stack gets its own single-writer claim file. */
const tempClaimsFile = (): string => join(mkdtempSync(join(tmpdir(), "demo-claims-")), "claims.sqlite");
const tempReservationsFile = (): string =>
  join(mkdtempSync(join(tmpdir(), "demo-reservations-")), "write-reservations.sqlite");

const API_URL = process.env.OPENFGA_HTTP_URL ?? TOPOLOGY.openfga.url;
const KEY = process.env.OPENFGA_PRESHARED_KEY ?? TOPOLOGY.openfga.presharedKey;
const CA = process.env.OPENFGA_CA_CERT;

async function reachable(): Promise<boolean> {
  try {
    if (CA) process.env.NODE_EXTRA_CA_CERTS = CA;
    return (await fetch(`${API_URL}/healthz`, { headers: { authorization: `Bearer ${KEY}` } })).ok;
  } catch {
    return false;
  }
}
const up = await reachable();
if (!up) console.warn("OpenFGA unreachable; skipping the [FGA] as-native composition");

/** A raw MCP `tools/call` body: a request the gate must refuse before MCP sees it. */
const toolsCall = (name: string, args: Record<string, unknown>): string =>
  JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } });
/** A raw MCP `initialize`: the request that would open the channel's session. */
const INITIALIZE = JSON.stringify({
  jsonrpc: "2.0",
  id: 0,
  method: "initialize",
  params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "as-native-test", version: "0.0.1" } },
});
const MCP_HEADERS = { "content-type": "application/json", accept: "application/json, text/event-stream" };

describe("the as-native target excludes the MAS join route at startup (D315)", () => {
  it("fails startup, before connecting to anything, when the payments resource is configured governed", async () => {
    const connect = vi.spyOn(Fga, "connect").mockRejectedValue(new Error("OpenFGA was reached"));
    try {
      await expect(
        composeStack({
          openfgaUrl: "http://unused.test",
          presharedKey: "unused",
          target: "as-native",
          masGovernedResources: [CANONICAL_RESOURCE],
          claimsFile: tempClaimsFile(),
          writeReservationsFile: tempReservationsFile(),
        }),
      ).rejects.toThrow(/mounts no MAS join route/);
      expect(connect).not.toHaveBeenCalled();
    } finally {
      connect.mockRestore();
    }
  });

  it("binds the HTTP MCP channel on the port it is given, and rejects rather than waits when that port is taken", async () => {
    const holder = createServer();
    await new Promise<void>((r) => holder.listen(0, "127.0.0.1", () => r()));
    const port = (holder.address() as { port: number }).port;
    try {
      // Binding happens before any request reaches the payments server.
      const stub = {} as McpPaymentsServer;
      await expect(createHttpMcpChannel(stub, { port })).rejects.toThrow(/EADDRINUSE/);
      await new Promise<void>((r) => holder.close(() => r()));
      const channel = await createHttpMcpChannel(stub, { port });
      expect(channel.url).toBe(`http://127.0.0.1:${port}/mcp`);
      await channel.close();
    } finally {
      if (holder.listening) await new Promise<void>((r) => holder.close(() => r()));
    }
  });
});

/**
 * One as-native composition and the target's assertions on it. `live`
 * selects a live OpenFGA; otherwise only the OpenFGA client is stubbed. The
 * negatives run before the one positive: the HTTP channel serves a single MCP
 * session, so only the positive may initialize one.
 */
function targetFixture(opts: { live: boolean; asPort: number }) {
  let stack: DemoStack;
  let connect: MockInstance | undefined;
  let issued: IssuedMission;
  let missionId: string;
  const decisions: { audience: string; permit: boolean }[] = [];

  /** Evidence and decisions so far: a refusal at the gate leaves both unchanged. */
  const snapshot = () => ({
    evidence: stack.evidence.all().length,
    ledger: stack.connectors.ledgerEntries().length,
    decisions: decisions.length,
  });

  return {
    async setup(): Promise<void> {
      if (!opts.live) {
        connect = vi.spyOn(Fga, "connect").mockResolvedValue({
          fga: { checkWithContext: async () => true } as unknown as Fga,
          storeId: "test",
          modelId: "test",
        });
      }
      stack = await composeStack({
        openfgaUrl: opts.live ? API_URL : "http://unused.test",
        presharedKey: opts.live ? KEY : "unused",
        ...(opts.live && CA ? { caCertPath: CA } : {}),
        target: "as-native",
        asPort: opts.asPort,
        claimsFile: tempClaimsFile(),
        writeReservationsFile: tempReservationsFile(),
      });
      stack.onEnforce((e) =>
        decisions.push({ audience: e.envelope.resource.properties.audience, permit: e.decision.decision }),
      );
      const as = stack.authServer;
      if (!as) throw new Error("the as-native target runs the AS");
      // A real Mission-bound token: the agent's PAR, Bob's approval for
      // Alice at the trusted console, and the token endpoint, DPoP-bound.
      issued = await issueMissionToken(
        as.asUrl,
        as.agentClientJwk,
        {
          missionIntent: JSON.stringify({
            intent: {
              goal: "Read approved Acme invoices",
              target_resources: [CANONICAL_RESOURCE],
              expires_at: "2027-01-01T00:00:00Z",
            },
          }),
          authorizationDetails: JSON.stringify([
            {
              type: "mission_resource_access",
              resource: CANONICAL_RESOURCE,
              actions: ["payments:invoice.read"],
              constraints: { vendors: ["acme"] },
            },
          ]),
        },
        as.approverServiceToken,
      );
      const claims = JSON.parse(Buffer.from(issued.accessToken.split(".")[1] as string, "base64url").toString()) as {
        aud: unknown;
        mission?: { id: string };
      };
      if (!claims.mission) throw new Error("the AS issued no Mission-bound token");
      expect(claims.aud).toBe(CANONICAL_RESOURCE);
      missionId = claims.mission.id;
    },

    async teardown(): Promise<void> {
      await stack?.resourceChannel?.close();
      await stack?.masGovernedChannel?.close();
      stack?.authServer?.closeAuthServer();
      await stack?.decisionChannel.close();
      stack?.pdpClaims.close();
      stack?.writeReservations.close();
      stack?.payments.db.close();
      stack?.kernel.db.close();
      connect?.mockRestore();
    },

    topology(): void {
      expect(stack.masGovernedChannel).toBeUndefined();
      expect(stack.resourceChannel?.url).toBe(CANONICAL_RESOURCE);
      expect(stack.issuer).toBe(`http://localhost:${opts.asPort}`);
    },

    async noProof(): Promise<void> {
      const before = snapshot();
      const res = await fetch(CANONICAL_RESOURCE, {
        method: "POST",
        headers: { ...MCP_HEADERS, authorization: `DPoP ${issued.accessToken}` },
        body: toolsCall("get_invoice", { invoice_id: "inv-1" }),
      });
      await res.text();
      expect(res.status).toBe(401);
      expect(res.headers.get("www-authenticate")).toBe("DPoP");
      // Nor can a client without a proof initialize an MCP session.
      const init = await fetch(CANONICAL_RESOURCE, {
        method: "POST",
        headers: { ...MCP_HEADERS, authorization: `DPoP ${issued.accessToken}` },
        body: INITIALIZE,
      });
      await init.text();
      expect(init.status).toBe(401);
      expect(snapshot()).toEqual(before);
    },

    async otherKey(): Promise<void> {
      const before = snapshot();
      const otherKeys: DpopKeys = await generateKeyPair("ES256", { extractable: true });
      const res = await fetch(CANONICAL_RESOURCE, {
        method: "POST",
        headers: {
          ...MCP_HEADERS,
          authorization: `DPoP ${issued.accessToken}`,
          dpop: await dpopProofFor(otherKeys, canonicalHtu(CANONICAL_RESOURCE), "POST", issued.accessToken),
        },
        body: toolsCall("get_invoice", { invoice_id: "inv-1" }),
      });
      await res.text();
      expect(res.status).toBe(401);
      // A well-formed client signing every request under the other key cannot
      // initialize a session.
      await expect(createHttpMediatedClient(CANONICAL_RESOURCE, issued.accessToken, otherKeys)).rejects.toThrow();
      expect(snapshot()).toEqual(before);
    },

    async baselineJoin(): Promise<void> {
      const before = snapshot();
      const as = stack.authServer;
      if (!as) throw new Error("the as-native target runs the AS");
      const keys: DpopKeys = await generateKeyPair("ES256", { extractable: true });
      const jkt = await calculateJwkThumbprint(await exportJWK(keys.publicKey));
      const minted = await fetch(`${as.asUrl}/dev/ordinary-token`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
        body: JSON.stringify({ sub: "alice", client_id: "ap-agent", scope: "payments.read", jkt }),
      });
      expect(minted.status, await minted.clone().text()).toBe(200);
      const ordinary = ((await minted.json()) as { access_token: string }).access_token;
      const claims = JSON.parse(Buffer.from(ordinary.split(".")[1] as string, "base64url").toString()) as Record<
        string,
        unknown
      >;
      expect(claims.mission).toBeUndefined();
      expect(claims.aud).toBe(CANONICAL_RESOURCE);
      // The baseline Join's own request shape: the credential, a valid proof
      // under its key, and the propagated reference naming a live Mission.
      const res = await fetch(CANONICAL_RESOURCE, {
        method: "POST",
        headers: {
          ...MCP_HEADERS,
          authorization: `DPoP ${ordinary}`,
          dpop: await dpopProofFor(keys, canonicalHtu(CANONICAL_RESOURCE), "POST", ordinary),
          "mission-reference": `id="${missionId}", issuer="${stack.issuer}"`,
        },
        body: toolsCall("get_invoice", { invoice_id: "inv-1" }),
      });
      await res.text();
      expect(res.status).toBe(401);
      expect(stack.masGovernedChannel).toBeUndefined();
      expect(snapshot()).toEqual(before);
    },

    async permittedRead(): Promise<void> {
      const before = snapshot();
      const { client, close } = await createHttpMediatedClient(CANONICAL_RESOURCE, issued.accessToken, issued.dpopKeys);
      try {
        const res = await client.callTool("get_invoice", { invoice_id: "inv-1" });
        expect(res.ok, JSON.stringify(res)).toBe(true);
        expect((res.result as { id?: string } | undefined)?.id).toBe("inv-1");
      } finally {
        await close();
      }
      // Exactly one PDP decision, a permit, on the declared audience, and the
      // PDP's own Decision Evidence for this Mission retained by the PEP.
      expect(decisions.slice(before.decisions)).toEqual([{ audience: CANONICAL_RESOURCE, permit: true }]);
      expect(stack.evidence.forMission(missionId).filter((e) => e.kind === "decision")).toHaveLength(1);
    },
  };
}

const stubbed = targetFixture({ live: false, asPort: 14105 });
describe("the as-native target over HTTP MCP with DPoP, OpenFGA client stubbed (D315)", () => {
  beforeAll(stubbed.setup, 60_000);
  afterAll(stubbed.teardown);
  it("mounts no MAS join route and serves the HTTP MCP endpoint at exactly the declared resource audience", () => {
    stubbed.topology();
  });
  it("refuses the AS-issued token with no DPoP proof at the HTTP gate, before the PEP: no evidence and no decision", async () => {
    await stubbed.noProof();
  });
  it("refuses a DPoP proof under a key other than the token's cnf.jkt at the HTTP gate, before the PEP: no evidence and no decision", async () => {
    await stubbed.otherKey();
  });
  it("refuses a baseline-Join credential (an AS-issued ordinary token with no mission claim) with a valid proof: no join route admits it", async () => {
    await stubbed.baselineJoin();
  });
  it("carries the AS-issued Mission-bound token with a valid DPoP proof through mcp-payments and the PDP to one permitted read", async () => {
    await stubbed.permittedRead();
  });
});

const live = targetFixture({ live: true, asPort: 14106 });
const dLive = up ? describe : describe.skip;
dLive("the as-native target over HTTP MCP with DPoP against a live OpenFGA (D315)", () => {
  beforeAll(live.setup, 60_000);
  afterAll(live.teardown);
  it("mounts no MAS join route and serves the HTTP MCP endpoint at exactly the declared resource audience", () => {
    live.topology();
  });
  it("refuses the AS-issued token with no DPoP proof at the HTTP gate, before the PEP: no evidence and no decision", async () => {
    await live.noProof();
  });
  it("refuses a DPoP proof under a key other than the token's cnf.jkt at the HTTP gate, before the PEP: no evidence and no decision", async () => {
    await live.otherKey();
  });
  it("refuses a baseline-Join credential (an AS-issued ordinary token with no mission claim) with a valid proof: no join route admits it", async () => {
    await live.baselineJoin();
  });
  it("carries the AS-issued Mission-bound token with a valid DPoP proof through mcp-payments and the PDP to one permitted read", async () => {
    await live.permittedRead();
  });
});
