/**
 * @spec runtime-oauth#token-validation (D284, D315, D332, #1105)
 *
 * #253's first runtime target, the AS-native payments composition, exactly as
 * `composeStack({ target: "as-native" })` assembles it for `pnpm as-native`:
 * the real authorization server, running the issuance profile plus exactly
 * `lifecycle-revoke` and `transaction-authorization` (D332), issues a
 * Mission-bound token over PAR, approval and the token endpoint, and the
 * client presents it over the HTTP MCP transport at the declared resource
 * audience with a DPoP proof. Under D315 that endpoint is the target's only
 * entry point: the in-process mediated channel and the MAS join route are
 * outside it.
 *
 * Two compositions run the same assertions. The first stubs only the OpenFGA
 * client, as `remote-pdp-stack.test.ts` does (the AS, kernel, PEP, PDP,
 * decision channel and Decision Evidence are real), so it runs everywhere. The
 * second ([FGA]) runs against a live OpenFGA and is skipped without one, so
 * only CI with OpenFGA exercises it. Each also has a second composition with
 * the test-only ordinary-token minting fixture on, used only by the
 * baseline-Join refusal. Every composition binds the declared audience's port
 * (4403), so none runs beside a live `pnpm as-native`.
 */

import { mkdtempSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { calculateJwkThumbprint, decodeJwt, exportJWK, generateKeyPair } from "jose";
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
import { ISSUANCE_ONLY_CAPABILITIES } from "../src/issuance-only.js";
import { clientAssertionSigner, type IssuedMission, tokenGrantRequest } from "../src/oauth-client.js";
import { AS_NATIVE_CAPABILITIES, composeStack, type DemoStack } from "../src/stack.js";

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

const AT_TYPE = "urn:ietf:params:oauth:token-type:access_token";
const TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/** A raw MCP `tools/call` body: a request the gate must refuse before MCP sees it. */
const toolsCall = (name: string, args: Record<string, unknown>): string =>
  JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } });
/** A raw MCP `initialize`: the request that would open a session. */
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

const missionIdOf = (token: string): string => (decodeJwt(token).mission as { id: string }).id;

/**
 * One as-native composition and the target's assertions on it. `live`
 * selects a live OpenFGA; otherwise only the OpenFGA client is stubbed.
 * `ordinaryTokenMinting` turns on the test-only fixture (D332), which only
 * the baseline-Join refusal uses: a composition with it on is not the
 * target's capability set.
 */
function targetFixture(opts: { live: boolean; asPort: number; ordinaryTokenMinting?: boolean }) {
  let stack: DemoStack;
  let connect: MockInstance | undefined;
  /** A read Mission's token: the target's ordinary client. */
  let issued: IssuedMission;
  let missionId: string;
  /** A remittance Mission's token, under its own DPoP key: a second holder. */
  let remit: IssuedMission;
  const decisions: { audience: string; permit: boolean }[] = [];
  const asUrl = `http://localhost:${opts.asPort}`;

  /** Evidence and decisions so far: a refusal at the gate leaves both unchanged. */
  const snapshot = () => ({
    evidence: stack.evidence.all().length,
    ledger: stack.connectors.ledgerEntries().length,
    decisions: decisions.length,
  });

  const authServer = () => {
    if (!stack.authServer) throw new Error("the as-native target runs the AS");
    return stack.authServer;
  };

  /** A real Mission-bound token: the agent's PAR, Bob's approval for Alice at the trusted console, and the token endpoint, DPoP-bound. */
  const issue = (actions: string[], constraints: Record<string, unknown>): Promise<IssuedMission> =>
    issueMissionToken(
      authServer().asUrl,
      authServer().agentClientJwk,
      {
        missionIntent: JSON.stringify({
          intent: {
            goal: "Read approved Acme invoices and send their remittance",
            target_resources: [CANONICAL_RESOURCE],
            expires_at: "2027-01-01T00:00:00Z",
          },
        }),
        authorizationDetails: JSON.stringify([
          { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions, constraints },
        ]),
      },
      authServer().approverServiceToken,
    );
  const issueRead = () => issue(["payments:invoice.read"], { vendors: ["acme"] });

  /** A raw tools/call on the endpoint, outside any MCP client. */
  const post = (headers: Record<string, string>, body = toolsCall("get_invoice", { invoice_id: "inv-1" })) =>
    fetch(CANONICAL_RESOURCE, { method: "POST", headers: { ...MCP_HEADERS, ...headers }, body });

  /** The request headers a holder presents: its credential and a proof under `keys`. */
  const credentialHeaders = async (token: string, keys: DpopKeys): Promise<Record<string, string>> => ({
    authorization: `DPoP ${token}`,
    dpop: await dpopProofFor(keys, canonicalHtu(CANONICAL_RESOURCE), "POST", token),
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
        ...(opts.ordinaryTokenMinting ? { testOrdinaryTokenMinting: true } : {}),
      });
      stack.onEnforce((e) =>
        decisions.push({ audience: e.envelope.resource.properties.audience, permit: e.decision.decision }),
      );
      issued = await issueRead();
      const claims = decodeJwt(issued.accessToken);
      if (!claims.mission) throw new Error("the AS issued no Mission-bound token");
      expect(claims.aud).toBe(CANONICAL_RESOURCE);
      missionId = missionIdOf(issued.accessToken);
      remit = await issue(["payments:invoice.read", "payments:remittance.send"], {
        max_amount: { amount: "500.00", currency: "USD" },
        vendors: ["acme"],
      });
      expect(remit.dpopJkt).not.toBe(issued.dpopJkt);
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
      expect(stack.issuer).toBe(asUrl);
    },

    async capabilitySet(): Promise<void> {
      // D332: the floor's one capability plus transaction authorization, and nothing else.
      expect([...AS_NATIVE_CAPABILITIES].sort()).toEqual(["lifecycle-revoke", "transaction-authorization"]);
      expect(AS_NATIVE_CAPABILITIES).toEqual(new Set([...ISSUANCE_ONLY_CAPABILITIES, "transaction-authorization"]));
      expect(authServer().capabilities).toEqual(AS_NATIVE_CAPABILITIES);
      const meta = (await (await fetch(`${asUrl}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
      // oidc-provider always lists `implicit`; no client registers a response type that uses it.
      expect(meta.grant_types_supported).toEqual(["implicit", "authorization_code", "refresh_token"]);
      expect(meta.transaction_authorization_endpoint).toBe(`${asUrl}/transaction`);
      for (const member of [
        "mission_child_delegation_supported",
        "identity_continuation_supported",
        "identity_chaining_requested_token_types_supported",
        "delegated_refresh_token_profile_supported",
        "userinfo_endpoint",
        "end_session_endpoint",
        "revocation_endpoint",
      ]) {
        expect(meta, member).not.toHaveProperty(member);
      }
    },

    async disabledSurfaces(): Promise<void> {
      // A Mission of its own, so revoking it leaves the other tests' Missions active.
      const spare = await issueRead();
      const spareId = missionIdOf(spare.accessToken);
      const lifecycle = (operation: string) =>
        fetch(`${asUrl}/missions/${spareId}/lifecycle`, {
          method: "POST",
          headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
          body: JSON.stringify({ operation, nonce: randomUUID() }),
        });
      // No token-exchange profile is enabled, so the exchange grant is not registered.
      const exchanged = await tokenGrantRequest(asUrl, authServer().agentClientJwk, spare.dpopKeys, {
        grant_type: TOKEN_EXCHANGE,
        request_refresh_token: "true",
        subject_token: spare.accessToken,
        subject_token_type: AT_TYPE,
        resource: CANONICAL_RESOURCE,
      });
      expect(exchanged.status, JSON.stringify(exchanged.body)).toBe(400);
      expect(exchanged.body.error).toBe("unsupported_grant_type");
      // `lifecycle-extended` is off: suspend is refused and the Mission stays active.
      const suspend = await lifecycle("suspend");
      const suspendBody = (await suspend.json()) as Record<string, unknown>;
      expect(suspend.status, JSON.stringify(suspendBody)).toBe(400);
      expect(suspendBody.error).toBe("invalid_request");
      expect(suspendBody.error_description).toBe("operation suspend is not enabled on this deployment");
      expect(stack.kernel.get(spareId)?.state).toBe("active");
      // `lifecycle-revoke` is on.
      const revoke = await lifecycle("revoke");
      expect(revoke.status, await revoke.clone().text()).toBe(200);
      expect(stack.kernel.get(spareId)?.state).toBe("revoked");
    },

    async devRouteAbsent(): Promise<void> {
      const keys: DpopKeys = await generateKeyPair("ES256", { extractable: true });
      const jkt = await calculateJwkThumbprint(await exportJWK(keys.publicKey));
      const res = await fetch(`${asUrl}/dev/ordinary-token`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
        body: JSON.stringify({ sub: "alice", client_id: "ap-agent", scope: "payments.read", jkt }),
      });
      const body = (await res.json()) as Record<string, unknown>;
      expect(res.status, JSON.stringify(body)).toBe(501);
      expect(body.error).toBe("temporarily_unavailable");
      expect(body).not.toHaveProperty("access_token");
    },

    async noProof(): Promise<void> {
      const before = snapshot();
      const res = await post({ authorization: `DPoP ${issued.accessToken}` });
      await res.text();
      expect(res.status).toBe(401);
      expect(res.headers.get("www-authenticate")).toBe("DPoP");
      // Nor can a client without a proof initialize an MCP session.
      const init = await post({ authorization: `DPoP ${issued.accessToken}` }, INITIALIZE);
      await init.text();
      expect(init.status).toBe(401);
      expect(snapshot()).toEqual(before);
    },

    async otherKey(): Promise<void> {
      const before = snapshot();
      const otherKeys: DpopKeys = await generateKeyPair("ES256", { extractable: true });
      const res = await post(await credentialHeaders(issued.accessToken, otherKeys));
      await res.text();
      expect(res.status).toBe(401);
      // A well-formed client signing every request under the other key cannot
      // initialize a session.
      await expect(createHttpMediatedClient(CANONICAL_RESOURCE, issued.accessToken, otherKeys)).rejects.toThrow();
      expect(snapshot()).toEqual(before);
    },

    async baselineJoin(): Promise<void> {
      const before = snapshot();
      const keys: DpopKeys = await generateKeyPair("ES256", { extractable: true });
      const jkt = await calculateJwkThumbprint(await exportJWK(keys.publicKey));
      // Minted by the test-only fixture's dev route, which the target does not serve.
      const minted = await fetch(`${asUrl}/dev/ordinary-token`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
        body: JSON.stringify({ sub: "alice", client_id: "ap-agent", scope: "payments.read", jkt }),
      });
      expect(minted.status, await minted.clone().text()).toBe(200);
      const ordinary = ((await minted.json()) as { access_token: string }).access_token;
      const claims = decodeJwt(ordinary);
      expect(claims.mission).toBeUndefined();
      expect(claims.aud).toBe(CANONICAL_RESOURCE);
      // The baseline Join's own request shape: the credential, a valid proof
      // under its key, and the propagated reference naming a live Mission.
      const res = await post({
        ...(await credentialHeaders(ordinary, keys)),
        "mission-reference": `id="${missionId}", issuer="${stack.issuer}"`,
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

    async successiveSessions(): Promise<void> {
      const before = snapshot();
      const read = async (client: Awaited<ReturnType<typeof createHttpMediatedClient>>["client"]) => {
        const res = await client.callTool("get_invoice", { invoice_id: "inv-1" });
        expect(res.ok, JSON.stringify(res)).toBe(true);
      };
      // One client after another: the second initializes its own session
      // once the first has closed.
      const sessionIds: (string | undefined)[] = [];
      for (let i = 0; i < 2; i++) {
        const { client, sessionId, close } = await createHttpMediatedClient(
          CANONICAL_RESOURCE,
          issued.accessToken,
          issued.dpopKeys,
        );
        sessionIds.push(sessionId);
        try {
          await read(client);
        } finally {
          await close();
        }
      }
      // And two at once, the second holder's beside the first's.
      const a = await createHttpMediatedClient(CANONICAL_RESOURCE, issued.accessToken, issued.dpopKeys);
      const b = await createHttpMediatedClient(CANONICAL_RESOURCE, remit.accessToken, remit.dpopKeys);
      sessionIds.push(a.sessionId, b.sessionId);
      try {
        await read(a.client);
        await read(b.client);
      } finally {
        await a.close();
        await b.close();
      }
      expect(new Set(sessionIds).size).toBe(4);
      expect(sessionIds.every((id) => typeof id === "string")).toBe(true);
      expect(decisions.slice(before.decisions)).toEqual(
        Array.from({ length: 4 }, () => ({ audience: CANONICAL_RESOURCE, permit: true })),
      );
    },

    async sessionBinding(): Promise<void> {
      const owner = await createHttpMediatedClient(CANONICAL_RESOURCE, issued.accessToken, issued.dpopKeys);
      const sessionId = owner.sessionId;
      if (!sessionId) throw new Error("the endpoint issued no MCP session id");
      const onSession = async (headers: Record<string, string>) => {
        const res = await post({ ...headers, "mcp-session-id": sessionId });
        return { status: res.status, body: (await res.json()) as Record<string, unknown> };
      };
      try {
        const before = snapshot();
        // Authentication runs on every request on the session: the holder's
        // own token with no proof, or with a proof under another key, is
        // refused 401 at the gate.
        expect((await onSession({ authorization: `DPoP ${issued.accessToken}` })).status).toBe(401);
        const otherKeys: DpopKeys = await generateKeyPair("ES256", { extractable: true });
        expect((await onSession(await credentialHeaders(issued.accessToken, otherKeys))).status).toBe(401);
        // Another holder's valid credential carrying this session id is
        // answered as for a session that does not exist.
        const intruder = await onSession(await credentialHeaders(remit.accessToken, remit.dpopKeys));
        expect(intruder.status, JSON.stringify(intruder.body)).toBe(404);
        expect((intruder.body.error as { message?: string } | undefined)?.message).toBe("Session not found");
        expect(snapshot()).toEqual(before);
        // The session still serves its holder.
        const own = await owner.client.callTool("get_invoice", { invoice_id: "inv-1" });
        expect(own.ok, JSON.stringify(own)).toBe(true);
      } finally {
        await owner.close();
      }
      // Closing the client ends the session at the server, for its holder too.
      const ended = await onSession(await credentialHeaders(issued.accessToken, issued.dpopKeys));
      expect(ended.status, JSON.stringify(ended.body)).toBe(404);
    },

    async remittanceApproval(): Promise<void> {
      const as = authServer();
      const remitMissionId = missionIdOf(remit.accessToken);
      const executions = () => stack.evidence.forMission(remitMissionId).filter((e) => e.kind === "execution");
      // @spec runtime#idempotency (#917): one intended execution, one key: the
      // challenged attempt and its retry under the transaction token carry the same.
      const args = { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` };

      // 1. The gated tool over the endpoint, with the base token and the
      //    client's Accept-Txn-Challenge signal: denied, with a challenge.
      const agent = await createHttpMediatedClient(CANONICAL_RESOURCE, remit.accessToken, remit.dpopKeys, {
        "accept-txn-challenge": "?1",
      });
      let challenge: string;
      try {
        const challenged = await agent.client.callTool("send_remittance_email", args);
        expect(challenged.ok).toBe(false);
        expect(challenged.denial_reason).toBe("action_approval_required");
        expect(challenged.error).toBe("transaction_authorization_required");
        challenge = challenged.transaction_challenge as string;
        expect(challenge).toBeTruthy();
      } finally {
        await agent.close();
      }
      const challengeClaims = decodeJwt(challenge);
      expect(challengeClaims.iss).toBe(CANONICAL_RESOURCE);
      expect((challengeClaims.cnf as { jkt: string }).jkt).toBe(remit.dpopJkt);
      // The operation is the Mission's entry narrowed to the one gated action,
      // with no member of the PDP's own view (`join_delegation`).
      const operation = challengeClaims.authorization_details as Record<string, unknown>[];
      expect(operation).toHaveLength(1);
      expect(operation[0]?.actions).toEqual(["payments:remittance.send"]);
      expect(operation[0]).not.toHaveProperty("join_delegation");
      expect(executions()).toHaveLength(0);

      // 2. The transaction endpoint, discovered from AS metadata: the client
      //    authenticates, presents the challenge once with its Mission-bound
      //    token as the subject token, and proves the challenge's cnf key.
      const meta = (await (await fetch(`${as.asUrl}/.well-known/openid-configuration`)).json()) as Record<string, string>;
      const txnEndpoint = meta.transaction_authorization_endpoint as string;
      const assertion = await clientAssertionSigner(as.asUrl, as.agentClientJwk);
      const postTxn = async (payload: Record<string, string>) => {
        const res = await fetch(txnEndpoint, {
          method: "POST",
          headers: {
            "content-type": "application/x-www-form-urlencoded",
            dpop: await dpopProofFor(remit.dpopKeys, txnEndpoint, "POST"),
          },
          body: new URLSearchParams({
            client_id: "ap-agent",
            client_assertion: await assertion(),
            client_assertion_type: CLIENT_ASSERTION_TYPE,
            ...payload,
          }).toString(),
        });
        return { status: res.status, body: (await res.json()) as Record<string, string> };
      };
      const admitted = await postTxn({
        transaction_challenge: challenge,
        subject_token: remit.accessToken,
        subject_token_type: AT_TYPE,
      });
      expect(admitted.status, JSON.stringify(admitted.body)).toBe(200);
      const handle = admitted.body.transaction_authorization_id as string;
      expect(handle).toBeTruthy();
      const pending = await postTxn({ transaction_authorization_id: handle });
      expect(pending.body.error).toBe("authorization_pending");

      // 3. Bob approves the task the AS opened on the in-process approval service.
      const task = stack.ars.pending()[0];
      if (!task) throw new Error("the transaction endpoint opened no approval task");
      await stack.ars.adjudicate(task.id, "approve", "bob");
      const granted = await postTxn({ transaction_authorization_id: handle });
      expect(granted.status, JSON.stringify(granted.body)).toBe(200);
      expect(granted.body.token_type).toBe("DPoP");
      const txnToken = granted.body.access_token as string;

      // 4. The retry over the endpoint, the transaction token its only
      //    credential and DPoP-bound to the same key: executed exactly once.
      const retry = await createHttpMediatedClient(CANONICAL_RESOURCE, txnToken, remit.dpopKeys);
      try {
        const executed = await retry.client.callTool("send_remittance_email", args);
        expect(executed.ok, JSON.stringify(executed)).toBe(true);
        expect(executions()).toHaveLength(1);
        const replay = await retry.client.callTool("send_remittance_email", args);
        expect(replay.ok).toBe(false);
        expect(replay.refusal_reason, JSON.stringify(replay)).toBe("duplicate_suppressed");
        expect(executions()).toHaveLength(1);
      } finally {
        await retry.close();
      }
    },
  };
}

/** The target's own assertions, on a composition with the launcher's options. */
function targetSuite(fixture: ReturnType<typeof targetFixture>): void {
  beforeAll(fixture.setup, 60_000);
  afterAll(fixture.teardown);
  it("mounts no MAS join route and serves the HTTP MCP endpoint at exactly the declared resource audience", () => {
    fixture.topology();
  });
  it("runs exactly the D332 AS capability set, the issuance profile plus lifecycle-revoke and transaction-authorization, and advertises only that surface", async () => {
    await fixture.capabilitySet();
  });
  it("refuses a disabled optional surface with its standard error (token exchange, lifecycle suspend) while lifecycle revoke is served", async () => {
    await fixture.disabledSurfaces();
  });
  it("serves no dev ordinary-token route: it answers 501 temporarily_unavailable and mints nothing", async () => {
    await fixture.devRouteAbsent();
  });
  it("refuses the AS-issued token with no DPoP proof at the HTTP gate, before the PEP: no evidence and no decision", async () => {
    await fixture.noProof();
  });
  it("refuses a DPoP proof under a key other than the token's cnf.jkt at the HTTP gate, before the PEP: no evidence and no decision", async () => {
    await fixture.otherKey();
  });
  it("carries the AS-issued Mission-bound token with a valid DPoP proof through mcp-payments and the PDP to one permitted read", async () => {
    await fixture.permittedRead();
  });
  it("gives each successive and each concurrent client its own MCP session, each with a permitted read", async () => {
    await fixture.successiveSessions();
  });
  it("binds a session to the holder that opened it: every request on it is authenticated, and another holder's credential carrying its id is answered 404 Session not found before the PEP", async () => {
    await fixture.sessionBinding();
  });
  it("denies send_remittance_email with a transaction challenge, redeems the approval at the AS transaction endpoint, and executes the retry under the transaction token exactly once", async () => {
    await fixture.remittanceApproval();
  });
}

/**
 * The baseline-Join refusal, on a composition with the test-only
 * ordinary-token minting fixture on (D332). The fixture exists only to mint
 * the credential this negative presents; it proves nothing about the
 * target's enabled capabilities, which `targetSuite` asserts on a
 * composition without it.
 */
function joinSuite(fixture: ReturnType<typeof targetFixture>): void {
  beforeAll(fixture.setup, 60_000);
  afterAll(fixture.teardown);
  it("refuses a baseline-Join credential (an AS-issued ordinary token with no mission claim) with a valid proof: no join route admits it", async () => {
    await fixture.baselineJoin();
  });
}

describe("the as-native target over HTTP MCP with DPoP, OpenFGA client stubbed (D315)", () => {
  targetSuite(targetFixture({ live: false, asPort: 14105 }));
});
describe("the as-native target with the test-only ordinary-token minting fixture, OpenFGA client stubbed (D315, D332)", () => {
  joinSuite(targetFixture({ live: false, asPort: 14107, ordinaryTokenMinting: true }));
});

const dLive = up ? describe : describe.skip;
dLive("the as-native target over HTTP MCP with DPoP against a live OpenFGA (D315)", () => {
  targetSuite(targetFixture({ live: true, asPort: 14106 }));
});
dLive("the as-native target with the test-only ordinary-token minting fixture against a live OpenFGA (D315, D332)", () => {
  joinSuite(targetFixture({ live: true, asPort: 14108, ordinaryTokenMinting: true }));
});
