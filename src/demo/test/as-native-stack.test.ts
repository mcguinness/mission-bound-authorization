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

import { type ChildProcess, spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { createRequire } from "node:module";
import { connect, createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { ALL_PROVIDER_CAPABILITIES, type ProviderCapability, STATUS_LIST_ID } from "@mission/authorization-server";
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
import { DOMAIN_MODEL, Fga } from "@mission/pdp";
import { issueMissionToken } from "../src/approval-console.js";
import { asNativeLaunchOptions, launchAsNative } from "../src/as-native.js";
import { ISSUANCE_ONLY_CAPABILITIES } from "../src/issuance-only.js";
import {
  clientAssertionSigner,
  type IssuedMission,
  submitMissionApproval,
  tokenGrantRequest,
} from "../src/oauth-client.js";
import { AS_NATIVE_CAPABILITIES, composeStack, type DemoStack } from "../src/stack.js";

type Json = Record<string, unknown>;

/**
 * The stubbed OpenFGA client: the Mission's contextual check and the stored
 * Resource-policy check (#828) both allow, and the development seed writes
 * nowhere.
 */
const STUB_FGA = {
  checkWithContext: async () => true,
  checkStored: async () => true,
  client: { write: async () => ({}) },
  modelId: "test",
} as unknown as Fga;
const STUB_BOOTSTRAP = { fga: STUB_FGA, storeId: "test", modelId: "test" };

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
const JWT_TYPE = "urn:ietf:params:oauth:token-type:jwt";
const ID_JAG_TYPE = "urn:ietf:params:oauth:token-type:id-jag";
const ICA_TYPE = "urn:ietf:params:oauth:token-type:identity-continuation";
const CHAIN_TYPE = "urn:ietf:params:oauth:token-type:mission-delegation-chain";
const JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const DEFERRED = "urn:ietf:params:oauth:grant-type:deferred";
const DISPATCH = "urn:ietf:params:oauth:grant-type:mission-dispatch";

/** The optional capabilities D332 enables beyond the always-on issuance profile, and no others. */
const ENABLED: ReadonlySet<ProviderCapability> = new Set<ProviderCapability>([
  "lifecycle-revoke",
  "transaction-authorization",
]);

async function readJson(res: Response): Promise<Json> {
  const text = await res.text();
  try {
    return JSON.parse(text) as Json;
  } catch {
    return { body: text };
  }
}

/** Whether anything accepts a TCP connection at `url`'s host and port. */
function accepts(url: string): Promise<boolean> {
  const { hostname, port } = new URL(url);
  return new Promise((resolve) => {
    const socket = connect(Number(port), hostname);
    socket.once("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.once("error", () => resolve(false));
  });
}

/** Hold `port` (on `host`, or every interface) until the returned close runs. */
async function holdPort(port: number, host?: string): Promise<() => Promise<void>> {
  const holder = createServer();
  await new Promise<void>((resolve, reject) => {
    holder.once("error", reject);
    if (host === undefined) holder.listen(port, () => resolve());
    else holder.listen(port, host, () => resolve());
  });
  return () => new Promise<void>((resolve) => holder.close(() => resolve()));
}

/**
 * Every listener the running target publishes, read from the resource's own
 * metadata: the resource endpoint, the AS, the txn-challenge discovery
 * listener and, in remote PDP mode, the PDP hop.
 */
async function publishedListeners(): Promise<string[]> {
  const meta = (await (await fetch(new URL("/.well-known/oauth-protected-resource", CANONICAL_RESOURCE))).json()) as Json;
  const statement = meta.enforcement_scope_statement as { remote_decision_channels?: { boundary: string }[] };
  const hops = (statement.remote_decision_channels ?? []).map((c) => /->\s*(\S+)/.exec(c.boundary)?.[1] as string);
  return [
    CANONICAL_RESOURCE,
    ...(meta.authorization_servers as string[]),
    new URL(meta.txn_challenge_jwks_uri as string).origin,
    ...hops,
  ];
}

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
    const bootstrap = vi.spyOn(Fga, "bootstrap").mockRejectedValue(new Error("OpenFGA was reached"));
    const attach = vi.spyOn(Fga, "attach").mockRejectedValue(new Error("OpenFGA was reached"));
    try {
      await expect(
        composeStack({
          openfgaUrl: "http://unused.test",
          presharedKey: "unused",
          target: "as-native",
          masGovernedResources: [CANONICAL_RESOURCE],
          claimsFile: tempClaimsFile(),
          writeReservationsFile: tempReservationsFile(),
          resourcePolicyStore: { bootstrap: "development" },
        }),
      ).rejects.toThrow(/mounts no MAS join route/);
      expect(bootstrap).not.toHaveBeenCalled();
      expect(attach).not.toHaveBeenCalled();
    } finally {
      bootstrap.mockRestore();
      attach.mockRestore();
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
  let fgaBootstrap: MockInstance | undefined;
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

  type Answer = { status: number; body: Json };
  /** A request to the AS; the answer's body is JSON, or `{ body: text }`. */
  const send = async (path: string, init: RequestInit = {}): Promise<Answer> => {
    const res = await fetch(`${asUrl}${path}`, init);
    return { status: res.status, body: await readJson(res) };
  };
  /** A token request as `ap-agent` (private_key_jwt). */
  const token = async (params: Record<string, string>): Promise<Answer> => {
    const assertion = await clientAssertionSigner(asUrl, authServer().agentClientJwk);
    return send("/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        ...params,
        client_assertion: await assertion(),
        client_assertion_type: CLIENT_ASSERTION_TYPE,
      }).toString(),
    });
  };
  /** A lifecycle-endpoint request under the shipped dev service token (`mission_lifecycle`). */
  const lifecycleOn = (id: string, body: Json): Promise<Answer> =>
    send(`/missions/${id}/lifecycle`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
      body: JSON.stringify({ nonce: randomUUID(), ...body }),
    });
  const devRoute = (jkt: string): Promise<Answer> =>
    send("/dev/ordinary-token", {
      method: "POST",
      headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
      body: JSON.stringify({ sub: "alice", client_id: "ap-agent", scope: "payments.read", jkt }),
    });
  const expectUnsupportedGrant = (r: Answer) => {
    expect(r.status, JSON.stringify(r.body)).toBe(400);
    expect(r.body.error).toBe("unsupported_grant_type");
  };
  const expectOperationDisabled = (r: Answer, operation: string) => {
    expect(r.status, JSON.stringify(r.body)).toBe(400);
    expect(r.body.error).toBe("invalid_request");
    expect(r.body.error_description).toBe(`operation ${operation} is not enabled on this deployment`);
  };
  /** A route nothing serves: Koa's plain-text 404, not a JSON refusal from a handler. */
  const expectUnservedRoute = (r: Answer) => {
    expect(r.status, JSON.stringify(r.body)).toBe(404);
    expect(r.body.body).toBe("Not Found");
  };
  const expectUnavailable = (r: Answer) => {
    expect(r.status, JSON.stringify(r.body)).toBe(501);
    expect(r.body.error).toBe("temporarily_unavailable");
  };
  const expectAbsent = (meta: Json, ...members: string[]) => {
    for (const member of members) expect(meta, member).not.toHaveProperty(member);
  };
  const expectGrantUnregistered = (meta: Json, grant: string) =>
    expect(meta.grant_types_supported as string[], grant).not.toContain(grant);

  /**
   * One probe for each optional capability the target leaves off (D332),
   * asserting that capability's standard refusal on the running AS and the
   * absence of the metadata it would advertise: the floor's own probes
   * (`issuance-only-capabilities.test.ts`) on this target. The five
   * token-exchange profiles share one gate: with none enabled the exchange
   * grant is not registered, so each profile's own request is refused
   * `unsupported_grant_type`.
   */
  const disabledProbes: Record<string, (meta: Json) => Promise<void>> = {
    "async-delegation": async (meta) => {
      expectUnsupportedGrant(
        await token({
          grant_type: TOKEN_EXCHANGE,
          request_refresh_token: "true",
          subject_token: issued.accessToken,
          subject_token_type: AT_TYPE,
          resource: CANONICAL_RESOURCE,
        }),
      );
      expectAbsent(meta, "delegated_refresh_token_profile_supported");
    },
    "child-delegation": async (meta) => {
      expectUnsupportedGrant(
        await token({
          grant_type: TOKEN_EXCHANGE,
          subject_token: issued.accessToken,
          subject_token_type: AT_TYPE,
          requested_token_type: JWT_TYPE,
          child_actor: "subagent-invoice-extractor",
          creation_request_id: randomUUID(),
        }),
      );
      // The child's own RFC 7523 redemption grant has a gate of its own.
      expectUnsupportedGrant(await token({ grant_type: JWT_BEARER, assertion: "x.y.z" }));
      expectGrantUnregistered(meta, JWT_BEARER);
      expectAbsent(meta, "mission_child_delegation_supported");
    },
    continuation: async (meta) => {
      expectUnsupportedGrant(
        await token({
          grant_type: TOKEN_EXCHANGE,
          subject_token: "x.y.z",
          subject_token_type: ICA_TYPE,
          requested_token_type: ID_JAG_TYPE,
          audience: TOPOLOGY.issuers.ras,
          resource: TOPOLOGY.resources.saas,
        }),
      );
      expectAbsent(meta, "identity_continuation_supported", "identity_chaining_requested_token_types_supported");
    },
    "cross-org": async () =>
      expectUnsupportedGrant(
        await token({
          grant_type: TOKEN_EXCHANGE,
          subject_token: "x.y.z",
          subject_token_type: CHAIN_TYPE,
          requested_token_type: AT_TYPE,
          resource: CANONICAL_RESOURCE,
        }),
      ),
    expansion: async (meta) => {
      expectUnsupportedGrant(
        await token({
          grant_type: TOKEN_EXCHANGE,
          subject_token: issued.accessToken,
          subject_token_type: AT_TYPE,
          requested_token_type: AT_TYPE,
          creation_request_id: randomUUID(),
        }),
      );
      expectGrantUnregistered(meta, TOKEN_EXCHANGE);
    },
    deferred: async (meta) => {
      expectUnsupportedGrant(await token({ grant_type: DEFERRED, deferral_code: "x" }));
      expectGrantUnregistered(meta, DEFERRED);
    },
    templates: async (meta) => {
      expectUnsupportedGrant(await token({ grant_type: DISPATCH, template_id: "x" }));
      expectGrantUnregistered(meta, DISPATCH);
      for (const path of ["/templates", "/templates/x/lifecycle"]) {
        expectUnavailable(
          await send(path, {
            method: "POST",
            headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
            body: JSON.stringify({}),
          }),
        );
      }
    },
    containment: async () => {
      expectOperationDisabled(
        await lifecycleOn(missionId, {
          operation: "contain",
          event: {
            type: "credential_compromise",
            source: "test",
            observed_at: new Date().toISOString(),
            event_id: randomUUID(),
          },
          remove: [{ resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] }],
        }),
        "contain",
      );
      // Protected-event ingestion is the capability's second surface.
      expectUnavailable(
        await send(`/missions/${missionId}/protected-events`, {
          method: "POST",
          headers: { "content-type": "application/protected-event+jwt" },
          body: "x.y.z",
        }),
      );
    },
    discharge: async (meta) => {
      expectOperationDisabled(
        await lifecycleOn(missionId, { operation: "discharge", entry: "e1", condition: "c1", event_id: randomUUID() }),
        "discharge",
      );
      expectAbsent(meta, "mission_status_signing_alg_values_supported");
    },
    "lifecycle-extended": async () => {
      for (const operation of ["suspend", "resume", "complete"]) {
        expectOperationDisabled(await lifecycleOn(missionId, { operation }), operation);
      }
    },
    status: async (meta) => {
      expectUnservedRoute(
        await send(`/missions/${missionId}/status`, { headers: { "x-service-token": DEV_SERVICE_TOKEN } }),
      );
      expectAbsent(meta, "mission_status_signing_alg_values_supported");
    },
    "status-list": async () => {
      const r = await send(`/statuslist/${STATUS_LIST_ID}`);
      expect(r.status, JSON.stringify(r.body)).toBe(404);
      expect(r.body.error).toBe("not_found");
    },
    "dev-token": async () => {
      const r = await devRoute("x");
      expectUnavailable(r);
      expect(r.body).not.toHaveProperty("access_token");
    },
    oidc: async (meta) => {
      await expect(
        submitMissionApproval(asUrl, authServer().agentClientJwk, {
          scope: "openid",
          missionIntent: JSON.stringify({
            intent: {
              goal: "Read approved Acme invoices",
              target_resources: [CANONICAL_RESOURCE],
              expires_at: "2027-01-01T00:00:00Z",
            },
          }),
        }),
      ).rejects.toThrow(/PAR failed: 400 .*"error":"invalid_scope".*OIDC is not enabled on this deployment/);
      expectUnservedRoute(await send("/me", { headers: { authorization: `Bearer ${issued.accessToken}` } }));
      expectUnservedRoute(await send("/session/end"));
      expectAbsent(meta, "userinfo_endpoint", "end_session_endpoint");
    },
    "token-revocation": async (meta) => {
      expectUnservedRoute(
        await send("/token/revocation", {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ token: issued.accessToken }).toString(),
        }),
      );
      expectAbsent(meta, "revocation_endpoint");
    },
  };

  return {
    async setup(): Promise<void> {
      if (!opts.live) {
        fgaBootstrap = vi.spyOn(Fga, "bootstrap").mockResolvedValue(STUB_BOOTSTRAP);
      }
      stack = await composeStack({
        openfgaUrl: opts.live ? API_URL : "http://unused.test",
        presharedKey: opts.live ? KEY : "unused",
        ...(opts.live && CA ? { caCertPath: CA } : {}),
        target: "as-native",
        asPort: opts.asPort,
        claimsFile: tempClaimsFile(),
        writeReservationsFile: tempReservationsFile(),
        // @spec runtime#input-resource-policy (#828): a development store,
        // seeded with the demo's entitlements (Alice reads and pays Acme).
        resourcePolicyStore: { bootstrap: "development" },
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
      fgaBootstrap?.mockRestore();
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

    async everyDisabledCapability(): Promise<void> {
      // Exactly one probe for every optional capability outside the D332 set.
      expect(Object.keys(disabledProbes).sort()).toEqual(
        ALL_PROVIDER_CAPABILITIES.filter((c) => !ENABLED.has(c)).sort(),
      );
      const meta = (await send("/.well-known/openid-configuration")).body;
      // Every probe runs, so a failure names each capability that answered.
      const answered: string[] = [];
      for (const [capability, probe] of Object.entries(disabledProbes)) {
        try {
          await probe(meta);
        } catch (err) {
          answered.push(`${capability}: ${(err as Error).message.split("\n")[0]}`);
        }
      }
      expect(answered).toEqual([]);
      // Every refusal came before the Mission was touched.
      expect(stack.kernel.get(missionId)?.state).toBe("active");
      expect(stack.kernel.get(missionId)?.version).toBe(1);
    },

    async devRouteAbsent(): Promise<void> {
      // The AS armed no dev ordinary-token signer (D332), as the AS reports it,
      // and the `dev-token` capability is off: two independent locks.
      expect(authServer().devOrdinaryIssuance).toBe(false);
      expect(authServer().capabilities?.has("dev-token")).toBe(false);
      const keys: DpopKeys = await generateKeyPair("ES256", { extractable: true });
      const r = await devRoute(await calculateJwkThumbprint(await exportJWK(keys.publicKey)));
      expectUnavailable(r);
      expect(r.body).not.toHaveProperty("access_token");
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
      // This composition is the target plus the minting fixture, and only that.
      expect(authServer().capabilities).toEqual(new Set<ProviderCapability>([...ENABLED, "dev-token"]));
      expect(authServer().devOrdinaryIssuance).toBe(true);
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

// Every composition binds the declared audience's port, and vitest runs a
// file's describe blocks one after another, each closing before the next.
const stubbed = targetFixture({ live: false, asPort: 14105 });
describe("the as-native target over HTTP MCP with DPoP, OpenFGA client stubbed (D315)", () => {
  beforeAll(stubbed.setup, 60_000);
  afterAll(stubbed.teardown);
  it("mounts no MAS join route and serves the HTTP MCP endpoint at exactly the declared resource audience", () => {
    stubbed.topology();
  });
  it("runs exactly the D332 AS capability set, the issuance profile plus lifecycle-revoke and transaction-authorization, and advertises only that surface", async () => {
    await stubbed.capabilitySet();
  });
  it("refuses a disabled optional surface with its standard error (token exchange, lifecycle suspend) while lifecycle revoke is served", async () => {
    await stubbed.disabledSurfaces();
  });
  it("refuses every optional AS capability outside the D332 set with its standard error: one probe for each of the 15, and no Mission touched", async () => {
    await stubbed.everyDisabledCapability();
  });
  it("serves no dev ordinary-token route: the AS arms no dev ordinary issuance, and the route answers 501 temporarily_unavailable and mints nothing", async () => {
    await stubbed.devRouteAbsent();
  });
  it("refuses the AS-issued token with no DPoP proof at the HTTP gate, before the PEP: no evidence and no decision", async () => {
    await stubbed.noProof();
  });
  it("refuses a DPoP proof under a key other than the token's cnf.jkt at the HTTP gate, before the PEP: no evidence and no decision", async () => {
    await stubbed.otherKey();
  });
  it("carries the AS-issued Mission-bound token with a valid DPoP proof through mcp-payments and the PDP to one permitted read", async () => {
    await stubbed.permittedRead();
  });
  it("gives each successive and each concurrent client its own MCP session, each with a permitted read", async () => {
    await stubbed.successiveSessions();
  });
  it("binds a session to the holder that opened it: every request on it is authenticated, and another holder's credential carrying its id is answered 404 Session not found before the PEP", async () => {
    await stubbed.sessionBinding();
  });
  it("denies send_remittance_email with a transaction challenge, redeems the approval at the AS transaction endpoint, and executes the retry under the transaction token exactly once", async () => {
    await stubbed.remittanceApproval();
  });
});

/**
 * The baseline-Join refusal, on a composition with the test-only
 * ordinary-token minting fixture on (D332). The fixture exists only to mint
 * the credential this negative presents; it proves nothing about the
 * target's enabled capabilities, which the suites without it assert.
 */
const stubbedJoin = targetFixture({ live: false, asPort: 14107, ordinaryTokenMinting: true });
describe("the as-native target with the test-only ordinary-token minting fixture, OpenFGA client stubbed (D315, D332)", () => {
  beforeAll(stubbedJoin.setup, 60_000);
  afterAll(stubbedJoin.teardown);
  it("refuses a baseline-Join credential (an AS-issued ordinary token with no mission claim) with a valid proof: no join route admits it", async () => {
    await stubbedJoin.baselineJoin();
  });
});

/**
 * The published launcher, `pnpm as-native` (D332): its configuration,
 * startup, failure handling and shutdown. The first suite drives the
 * launcher's own functions (`as-native.ts`) in process with only the OpenFGA
 * client stubbed. The second runs the server entry `scripts/as-native.mjs`
 * starts (`as-native-serve.ts`, through the same `tsx` loader) as a child
 * process against a stand-in OpenFGA, from a scratch working directory so its
 * store files stay out of the tree.
 */
const LAUNCH_AS_PORT = 14111;
const AUDIENCE = new URL(CANONICAL_RESOURCE);

describe("the as-native launcher in process, OpenFGA client stubbed (D332)", () => {
  let fgaBootstrap: MockInstance;
  beforeAll(() => {
    fgaBootstrap = vi.spyOn(Fga, "bootstrap").mockResolvedValue(STUB_BOOTSTRAP);
  });
  afterAll(() => fgaBootstrap.mockRestore());

  /** The launcher's own options from `env`, with only this test's AS port and store files added. */
  const launchOptions = (
    env: Record<string, string> = {},
    files = { claimsFile: tempClaimsFile(), writeReservationsFile: tempReservationsFile() },
  ) => ({ ...asNativeLaunchOptions(env), asPort: LAUNCH_AS_PORT, ...files });

  it("composes exactly the target from its own configuration: the D332 capability set, no dev ordinary issuance, no MAS join route and no test fixture", async () => {
    expect(asNativeLaunchOptions({})).toEqual({
      openfgaUrl: TOPOLOGY.openfga.url,
      presharedKey: TOPOLOGY.openfga.presharedKey,
      resourcePolicyStore: { bootstrap: "development" },
      target: "as-native",
    });
    const ca = fileURLToPath(import.meta.url);
    expect(
      asNativeLaunchOptions({
        OPENFGA_HTTP_URL: "https://fga.test:8080",
        OPENFGA_PRESHARED_KEY: "k",
        OPENFGA_CA_CERT: ca,
        MISSION_PDP_MODE: "remote",
      }),
    ).toEqual({
      openfgaUrl: "https://fga.test:8080",
      presharedKey: "k",
      caCertPath: ca,
      pdpMode: "remote",
      resourcePolicyStore: { bootstrap: "development" },
      target: "as-native",
    });
    // @spec runtime#input-resource-policy (#828): a configured store and model
    // are attached, never bootstrapped.
    expect(asNativeLaunchOptions({ OPENFGA_STORE_ID: "store-1", OPENFGA_MODEL_ID: "model-1" }).resourcePolicyStore).toEqual({
      attach: { storeId: "store-1", modelId: "model-1" },
    });
    const launched = await launchAsNative(launchOptions());
    try {
      expect(launched.stack.authServer?.capabilities).toEqual(ENABLED);
      expect(launched.stack.authServer?.devOrdinaryIssuance).toBe(false);
      expect(launched.stack.resourceChannel?.url).toBe(CANONICAL_RESOURCE);
      expect(launched.stack.masGovernedChannel).toBeUndefined();
      expect(launched.summary).toEqual(
        expect.arrayContaining([
          "  AS capabilities    issuance profile + lifecycle-revoke, transaction-authorization",
          "  dev ordinary token not served",
          `  resource audience  ${CANONICAL_RESOURCE}  (HTTP MCP, DPoP verified on every request)`,
          "  MAS join route     not mounted",
        ]),
      );
    } finally {
      await launched.close();
    }
    // Nothing else launches: the test-only fixture and any other target are
    // refused before anything connects.
    fgaBootstrap.mockClear();
    await expect(launchAsNative({ ...launchOptions(), testOrdinaryTokenMinting: true })).rejects.toThrow(
      /never enables the test-only ordinary-token minting fixture/,
    );
    const { target: _target, ...noTarget } = launchOptions();
    await expect(launchAsNative(noTarget)).rejects.toThrow(/composes only the as-native target/);
    expect(fgaBootstrap).not.toHaveBeenCalled();
  });

  it("refuses an unusable configuration by name, before anything connects", () => {
    const cases: [Record<string, string>, RegExp][] = [
      [{ OPENFGA_HTTP_URL: "not a url" }, /^OPENFGA_HTTP_URL is not a URL: not a url$/],
      [{ OPENFGA_HTTP_URL: "ftp://fga.test" }, /^OPENFGA_HTTP_URL is not an http or https URL: ftp:\/\/fga\.test$/],
      [{ OPENFGA_CA_CERT: "/nonexistent/openfga.crt" }, /^OPENFGA_CA_CERT names \/nonexistent\/openfga\.crt, which does not exist/],
      [{ MISSION_PDP_MODE: "bogus" }, /^MISSION_PDP_MODE must be co-resident or remote, not bogus$/],
      [{ OPENFGA_STORE_ID: "store-1" }, /^set both OPENFGA_STORE_ID and OPENFGA_MODEL_ID to attach, or neither$/],
      [{ OPENFGA_MODEL_ID: "model-1" }, /^set both OPENFGA_STORE_ID and OPENFGA_MODEL_ID to attach, or neither$/],
    ];
    for (const [env, message] of cases) expect(() => asNativeLaunchOptions(env), JSON.stringify(env)).toThrow(message);
  });

  it("attaches to a configured Resource-policy store and model: it reads the model back and creates, writes and seeds nothing (#828)", async () => {
    const fga = await startFakeOpenFga();
    try {
      fgaBootstrap.mockClear();
      const launched = await launchAsNative(
        launchOptions({ OPENFGA_HTTP_URL: fga.url, OPENFGA_STORE_ID: FAKE_STORE_ID, OPENFGA_MODEL_ID: FAKE_MODEL_ID }),
      );
      await launched.close();
      expect(fgaBootstrap).not.toHaveBeenCalled();
      expect(fga.requests.map((r) => `${r.method} ${r.path}`)).toEqual([
        `GET /stores/${FAKE_STORE_ID}/authorization-models/${FAKE_MODEL_ID}`,
      ]);
    } finally {
      await fga.close();
    }
  });

  it("refuses startup when the AS port or the declared audience's port is taken, and keeps no port or store file", async () => {
    const files = { claimsFile: tempClaimsFile(), writeReservationsFile: tempReservationsFile() };
    let free = await holdPort(LAUNCH_AS_PORT);
    try {
      await expect(launchAsNative(launchOptions({}, files))).rejects.toThrow(/EADDRINUSE/);
    } finally {
      await free();
    }
    free = await holdPort(Number(AUDIENCE.port), AUDIENCE.hostname);
    try {
      await expect(launchAsNative(launchOptions({}, files))).rejects.toThrow(/EADDRINUSE/);
      expect(await accepts(`http://localhost:${LAUNCH_AS_PORT}`)).toBe(false);
    } finally {
      await free();
    }
    // Neither failure kept a port or a single-writer store: the same configuration starts.
    const launched = await launchAsNative(launchOptions({}, files));
    await launched.close();
  });

  it("closes every listener it published and releases both store files on shutdown, in co-resident and remote PDP mode", async () => {
    for (const mode of ["co-resident", "remote"] as const) {
      const files = { claimsFile: tempClaimsFile(), writeReservationsFile: tempReservationsFile() };
      const launched = await launchAsNative(launchOptions({ MISSION_PDP_MODE: mode }, files));
      const listeners = await publishedListeners();
      expect(listeners, mode).toHaveLength(mode === "remote" ? 4 : 3);
      for (const url of listeners) expect(await accepts(url), `${mode} ${url}`).toBe(true);
      await launched.close();
      for (const url of listeners) expect(await accepts(url), `${mode} ${url} after close`).toBe(false);
      // The store files' single-writer locks are released too: the same files open again.
      const again = await launchAsNative(launchOptions({ MISSION_PDP_MODE: mode }, files));
      await again.close();
    }
  });
});

const FAKE_STORE_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const FAKE_MODEL_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW";

/**
 * A stand-in OpenFGA, recording each request. It answers the calls a
 * development Resource-policy store makes (`Fga.bootstrap`'s store and model,
 * then the seed write) and an attach's model read, which returns the domain
 * model (#828).
 */
async function startFakeOpenFga(): Promise<{
  url: string;
  requests: { method: string; path: string; authorization: string | undefined }[];
  close: () => Promise<void>;
}> {
  const storeId = FAKE_STORE_ID;
  const requests: { method: string; path: string; authorization: string | undefined }[] = [];
  const server: HttpServer = createHttpServer((req, res) => {
    requests.push({ method: req.method ?? "", path: req.url ?? "", authorization: req.headers.authorization });
    req.resume();
    req.on("end", () => {
      const now = new Date().toISOString();
      res.setHeader("content-type", "application/json");
      if (req.method === "POST" && req.url === "/stores") {
        res.writeHead(201).end(JSON.stringify({ id: storeId, name: "mission-payments", created_at: now, updated_at: now }));
      } else if (req.method === "POST" && req.url === `/stores/${storeId}/authorization-models`) {
        res.writeHead(201).end(JSON.stringify({ authorization_model_id: FAKE_MODEL_ID }));
      } else if (req.method === "POST" && req.url === `/stores/${storeId}/write`) {
        res.writeHead(200).end(JSON.stringify({}));
      } else if (req.method === "GET" && req.url === `/stores/${storeId}/authorization-models/${FAKE_MODEL_ID}`) {
        res.writeHead(200).end(JSON.stringify({ authorization_model: { id: FAKE_MODEL_ID, ...DOMAIN_MODEL } }));
      } else {
        res.writeHead(404).end(JSON.stringify({ code: "not_found" }));
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const { port } = server.address() as { port: number };
  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    close: () => {
      server.closeAllConnections();
      return new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

const SERVE_ENTRY = fileURLToPath(new URL("../src/as-native-serve.ts", import.meta.url));
const TSX_LOADER = pathToFileURL(createRequire(import.meta.url).resolve("tsx")).href;

/** The launcher's server entry as its own process, with `env` over a clean OpenFGA and PDP configuration. */
function runLauncher(env: Record<string, string>) {
  const inherited: NodeJS.ProcessEnv = { ...process.env };
  for (const name of [
    "OPENFGA_HTTP_URL",
    "OPENFGA_PRESHARED_KEY",
    "OPENFGA_CA_CERT",
    "OPENFGA_STORE_ID",
    "OPENFGA_MODEL_ID",
    "MISSION_PDP_MODE",
    "NODE_OPTIONS",
  ]) {
    delete inherited[name];
  }
  const child: ChildProcess = spawn(process.execPath, ["--import", TSX_LOADER, SERVE_ENTRY], {
    cwd: mkdtempSync(join(tmpdir(), "as-native-launch-")),
    env: { ...inherited, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout?.on("data", (d: Buffer) => {
    stdout += d.toString();
  });
  child.stderr?.on("data", (d: Buffer) => {
    stderr += d.toString();
  });
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) =>
    child.once("exit", (code, signal) => resolve({ code, signal })),
  );
  const output = () => `stdout:\n${stdout}\nstderr:\n${stderr}`;
  return {
    child,
    exited,
    stdout: () => stdout,
    stderr: () => stderr,
    output,
    /** The exit, or SIGKILL once `ms` pass, so a launcher that unexpectedly starts never outlives its test. */
    settle: async (ms = 60_000) => {
      const timer = setTimeout(() => child.kill("SIGKILL"), ms);
      try {
        return await exited;
      } finally {
        clearTimeout(timer);
      }
    },
    /** Resolve once stdout holds `text`; reject if the process exits or 60 s pass first. */
    waitFor: (text: string) =>
      new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`no "${text}" within 60 s\n${output()}`)), 60_000);
        const check = () => {
          if (stdout.includes(text)) {
            clearTimeout(timer);
            resolve();
          }
        };
        child.stdout?.on("data", check);
        check();
        void exited.then(() => {
          clearTimeout(timer);
          if (!stdout.includes(text)) reject(new Error(`exited before "${text}"\n${output()}`));
        });
      }),
  };
}

/** The startup-failure contract: exit 1, one `as-native: startup failed:` line, no stack trace, never ready. */
function expectStartupFailure(
  run: ReturnType<typeof runLauncher>,
  exit: { code: number | null; signal: NodeJS.Signals | null },
  reason: RegExp,
) {
  expect(exit, run.output()).toEqual({ code: 1, signal: null });
  const lines = run.stderr().split("\n").filter((l) => l.startsWith("as-native: startup failed: "));
  expect(lines, run.output()).toHaveLength(1);
  expect(lines[0], run.output()).toMatch(reason);
  expect(run.stderr(), run.output()).not.toMatch(/^\s+at /m);
  expect(run.stdout(), run.output()).not.toContain("ready.");
}

describe("the as-native launcher process, the entry pnpm as-native runs, against a stand-in OpenFGA (D332)", () => {
  let fga: Awaited<ReturnType<typeof startFakeOpenFga>>;
  beforeAll(async () => {
    fga = await startFakeOpenFga();
  });
  afterAll(() => fga?.close());
  const asUrl = `http://localhost:${TOPOLOGY.ports.as}`;

  it("starts exactly the target and prints it, then on SIGTERM closes every listener and exits 0", async () => {
    const run = runLauncher({ OPENFGA_HTTP_URL: fga.url, OPENFGA_PRESHARED_KEY: "launch-test-key" });
    try {
      await run.waitFor("ready. Ctrl-C to stop.");
      expect(run.stdout()).toContain(`  issuer             ${asUrl}  (JWKS ${asUrl}/jwks)`);
      expect(run.stdout()).toContain("  AS capabilities    issuance profile + lifecycle-revoke, transaction-authorization");
      expect(run.stdout()).toContain("  dev ordinary token not served");
      expect(run.stdout()).toContain(`  resource audience  ${CANONICAL_RESOURCE}  (HTTP MCP, DPoP verified on every request)`);
      expect(run.stdout()).toContain("  MAS join route     not mounted");
      // It connected to the configured OpenFGA under the configured key and,
      // with no store configured, bootstrapped and seeded a development
      // Resource-policy store (#828), naming it so a restart can attach.
      expect(fga.requests.map((r) => `${r.method} ${r.path} ${r.authorization}`)).toEqual([
        "POST /stores Bearer launch-test-key",
        `POST /stores/${FAKE_STORE_ID}/authorization-models Bearer launch-test-key`,
        `POST /stores/${FAKE_STORE_ID}/write Bearer launch-test-key`,
      ]);
      expect(run.stdout()).toContain(`development Resource-policy store ${FAKE_STORE_ID} model ${FAKE_MODEL_ID}`);
      // The AS it serves is the D332 surface, with no dev route.
      const meta = (await (await fetch(`${asUrl}/.well-known/openid-configuration`)).json()) as Json;
      expect(meta.grant_types_supported).toEqual(["implicit", "authorization_code", "refresh_token"]);
      expect(meta.transaction_authorization_endpoint).toBe(`${asUrl}/transaction`);
      const dev = await fetch(`${asUrl}/dev/ordinary-token`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
        body: JSON.stringify({ sub: "alice", client_id: "ap-agent", scope: "payments.read", jkt: "x" }),
      });
      expect(dev.status).toBe(501);
      // The endpoint at the declared audience demands DPoP.
      const gate = await fetch(CANONICAL_RESOURCE, {
        method: "POST",
        headers: MCP_HEADERS,
        body: toolsCall("get_invoice", { invoice_id: "inv-1" }),
      });
      expect(gate.status).toBe(401);
      const listeners = await publishedListeners();
      expect(listeners).toHaveLength(3);
      for (const url of listeners) expect(await accepts(url), url).toBe(true);
      run.child.kill("SIGTERM");
      expect(await run.settle(30_000), run.output()).toEqual({ code: 0, signal: null });
      for (const url of listeners) expect(await accepts(url), `${url} after exit`).toBe(false);
      expect(run.stderr()).not.toContain("failed");
    } finally {
      if (run.child.exitCode === null && run.child.signalCode === null) run.child.kill("SIGKILL");
    }
  }, 120_000);

  it("exits 1 with one startup-failure line, before anything listens, when its configuration is unusable or OpenFGA is unreachable", async () => {
    // A port that was bound a moment ago and is closed now: no OpenFGA answers there.
    const probe = createServer();
    await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", () => resolve()));
    const closed = (probe.address() as { port: number }).port;
    await new Promise<void>((resolve) => probe.close(() => resolve()));
    const cases: [Record<string, string>, RegExp][] = [
      [{ OPENFGA_HTTP_URL: fga.url, MISSION_PDP_MODE: "bogus" }, /MISSION_PDP_MODE must be co-resident or remote, not bogus$/],
      [{ OPENFGA_HTTP_URL: fga.url, OPENFGA_CA_CERT: "/nonexistent/openfga.crt" }, /OPENFGA_CA_CERT names \/nonexistent\/openfga\.crt, which does not exist/],
      [{ OPENFGA_HTTP_URL: fga.url, OPENFGA_STORE_ID: FAKE_STORE_ID }, /set both OPENFGA_STORE_ID and OPENFGA_MODEL_ID to attach, or neither$/],
      [{ OPENFGA_HTTP_URL: `http://127.0.0.1:${closed}` }, /^as-native: startup failed: \S/],
    ];
    for (const [env, reason] of cases) {
      const before = fga.requests.length;
      const run = runLauncher(env);
      expectStartupFailure(run, await run.settle(), reason);
      if (env.OPENFGA_HTTP_URL === fga.url) expect(fga.requests.length, run.output()).toBe(before);
    }
    for (const url of [asUrl, CANONICAL_RESOURCE]) expect(await accepts(url), url).toBe(false);
  }, 120_000);

  it("exits 1 with one startup-failure line, and releases the AS port, when the declared audience's port is taken", async () => {
    const free = await holdPort(Number(AUDIENCE.port), AUDIENCE.hostname);
    try {
      const run = runLauncher({ OPENFGA_HTTP_URL: fga.url });
      expectStartupFailure(run, await run.settle(), /EADDRINUSE/);
      expect(await accepts(asUrl)).toBe(false);
    } finally {
      await free();
    }
  }, 120_000);
});

const dLive = up ? describe : describe.skip;
const live = targetFixture({ live: true, asPort: 14106 });
dLive("the as-native target over HTTP MCP with DPoP against a live OpenFGA (D315)", () => {
  beforeAll(live.setup, 60_000);
  afterAll(live.teardown);
  it("mounts no MAS join route and serves the HTTP MCP endpoint at exactly the declared resource audience", () => {
    live.topology();
  });
  it("runs exactly the D332 AS capability set, the issuance profile plus lifecycle-revoke and transaction-authorization, and advertises only that surface", async () => {
    await live.capabilitySet();
  });
  it("refuses a disabled optional surface with its standard error (token exchange, lifecycle suspend) while lifecycle revoke is served", async () => {
    await live.disabledSurfaces();
  });
  it("refuses every optional AS capability outside the D332 set with its standard error: one probe for each of the 15, and no Mission touched", async () => {
    await live.everyDisabledCapability();
  });
  it("serves no dev ordinary-token route: the AS arms no dev ordinary issuance, and the route answers 501 temporarily_unavailable and mints nothing", async () => {
    await live.devRouteAbsent();
  });
  it("refuses the AS-issued token with no DPoP proof at the HTTP gate, before the PEP: no evidence and no decision", async () => {
    await live.noProof();
  });
  it("refuses a DPoP proof under a key other than the token's cnf.jkt at the HTTP gate, before the PEP: no evidence and no decision", async () => {
    await live.otherKey();
  });
  it("carries the AS-issued Mission-bound token with a valid DPoP proof through mcp-payments and the PDP to one permitted read", async () => {
    await live.permittedRead();
  });
  it("gives each successive and each concurrent client its own MCP session, each with a permitted read", async () => {
    await live.successiveSessions();
  });
  it("binds a session to the holder that opened it: every request on it is authenticated, and another holder's credential carrying its id is answered 404 Session not found before the PEP", async () => {
    await live.sessionBinding();
  });
  it("denies send_remittance_email with a transaction challenge, redeems the approval at the AS transaction endpoint, and executes the retry under the transaction token exactly once", async () => {
    await live.remittanceApproval();
  });
});

const liveJoin = targetFixture({ live: true, asPort: 14108, ordinaryTokenMinting: true });
dLive("the as-native target with the test-only ordinary-token minting fixture against a live OpenFGA (D315, D332)", () => {
  beforeAll(liveJoin.setup, 60_000);
  afterAll(liveJoin.teardown);
  it("refuses a baseline-Join credential (an AS-issued ordinary token with no mission claim) with a valid proof: no join route admits it", async () => {
    await liveJoin.baselineJoin();
  });
});
