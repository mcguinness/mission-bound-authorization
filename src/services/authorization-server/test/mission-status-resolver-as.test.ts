/**
 * @spec authority-server#mission-join rule 2, authority-server#join-disclosure,
 * status#mission-status-caching (#818)
 *
 * The PDP's remote Mission Status resolver (`@mission/pdp`) against the
 * reference authorization server serving Mission Status over HTTP, with no
 * handle on its kernel: the endpoint, the keys and `mission_max_stale_seconds`
 * come from the server's published metadata, the Mission's Subject and client
 * from its Join Disclosure, and state changes from its Lifecycle surface. The
 * PDP is a private-key-JWT client of the advertised Mission Status endpoint
 * (#1407). The test holds the kernel only to approve Missions, as an operator
 * console would.
 */

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { CANONICAL_RESOURCE, DEV_SERVICE_TOKEN, TOPOLOGY } from "@mission/demo-data";
import {
  declaredStatusKeys,
  deriveJoinDelegation,
  type MissionStatusResolution,
  MissionStatusResolver,
  type MissionStatusResolverOptions,
  privateKeyJwtClient,
  type StatusClientCredential,
} from "@mission/pdp";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  type BuiltAs,
  buildAuthorizationServer,
  MISSION_STATUS_SCOPE,
  type MissionRecord,
  validateMissionIntent,
} from "../src/index.js";
import { type LifecycleTestClient, newLifecycleClient } from "./lifecycle-endpoint.helper.js";

const PORT = 14827;
const ISSUER = `http://localhost:${PORT}`;
/** The joining PDP: a Status client enrolled for the payments scope. */
let pdp: LifecycleTestClient;
/** A Status client holding the same grant, enrolled for nothing. */
let reader: LifecycleTestClient;
/** A client the server has never registered. */
let stranger: LifecycleTestClient;
let statusEndpoint: string;

const credential = (client: LifecycleTestClient): StatusClientCredential =>
  privateKeyJwtClient({ clientId: client.clientId, issuer: ISSUER, privateKey: client.privateKey, kid: client.kid, now: clock });

/** The AS's kernel clock and the resolver's, moved together. */
let offsetMs = 0;
const clock = () => new Date(Date.now() + offsetMs);

let as: BuiltAs;
let server: Server;
let published: { keys: Record<string, unknown>[] };
let maxStaleSeconds: number;

const listen = (): Promise<void> =>
  new Promise((resolve) => {
    server = as.provider.listen(PORT, () => resolve());
  });
const stop = (): Promise<void> => {
  server.closeAllConnections();
  return new Promise((resolve) => server.close(() => resolve()));
};

beforeAll(async () => {
  pdp = await newLifecycleClient("resolver-as-pdp");
  reader = await newLifecycleClient("resolver-as-reader");
  stranger = await newLifecycleClient("resolver-as-stranger");
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    now: clock,
    testClients: [pdp.metadata, reader.metadata],
    lifecycleClientGrants: { [pdp.clientId]: [MISSION_STATUS_SCOPE], [reader.clientId]: [MISSION_STATUS_SCOPE] },
    enrolledJoinPdps: { [pdp.clientId]: [CANONICAL_RESOURCE] },
  });
  await listen();
  // What the PDP is configured from is what the server publishes.
  const metadata = (await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json()) as {
    jwks_uri: string;
    mission_max_stale_seconds: number;
    mission_status_endpoint: string;
  };
  published = (await (await fetch(metadata.jwks_uri)).json()) as { keys: Record<string, unknown>[] };
  maxStaleSeconds = metadata.mission_max_stale_seconds;
  statusEndpoint = metadata.mission_status_endpoint;
});

afterAll(async () => {
  if (server.listening) await stop();
});

beforeEach(() => {
  offsetMs = 0;
});

function resolver(extra: Partial<MissionStatusResolverOptions> = {}): MissionStatusResolver {
  return new MissionStatusResolver({
    issuer: ISSUER,
    statusEndpoint,
    audience: CANONICAL_RESOURCE,
    keys: declaredStatusKeys(published as never, [TOPOLOGY.keys.asStatus.kid]),
    client: credential(pdp),
    maxStaleSeconds,
    timeoutMs: 2000,
    maxResponseBytes: 64 * 1024,
    now: clock,
    ...extra,
  });
}

function approve(label: string): MissionRecord {
  return as.kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: `Resolver: ${label}`, target_resources: [CANONICAL_RESOURCE], expires_at: "2027-06-01T00:00:00Z" }),
    ),
    proposedAuthority: [
      {
        type: "mission_resource_access",
        resource: CANONICAL_RESOURCE,
        actions: ["payments:invoice.read", "payments:invoice.list"],
        constraints: { vendors: ["acme"] },
        delegation: { max_depth: 1, allowed_delegates: [{ sub_profile: "ai_agent" }] },
      },
    ],
    subject: { iss: ISSUER, sub: "alice" },
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-resolver-as-${label}-${Math.random().toString(36).slice(2)}`,
  });
}

/** Revoke over the server's Lifecycle surface, as an operator's tool would. */
async function revoke(missionId: string): Promise<void> {
  const res = await fetch(`${ISSUER}/missions/${missionId}/lifecycle`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
    body: JSON.stringify({ operation: "revoke", nonce: crypto.randomUUID() }),
  });
  expect(res.status).toBe(200);
  await res.arrayBuffer();
}

const resolved = (r: MissionStatusResolution) => {
  expect(r.ok, JSON.stringify(r)).toBe(true);
  return r as Extract<MissionStatusResolution, { ok: true }>;
};

describe("the remote resolver against the reference authorization server (@spec authority-server#mission-join rule 2)", () => {
  it("resolves an approved Mission from its signed Status, with the Join Disclosure an enrolled PDP reads", async () => {
    const record = approve("positive");
    const { view, observedAtMs, freshUntilMs, source } = resolved(await resolver().resolve({ id: record.id, issuer: ISSUER }));
    expect(source).toBe("fetched");
    expect(view).toMatchObject({
      id: record.id,
      issuer: ISSUER,
      state: "active",
      version: record.version,
      authority_hash: record.authority_hash,
      subject: { iss: ISSUER, sub: "alice" },
      client_id: "ap-agent",
    });
    const recorded = record.authority_set[0];
    expect(recorded?.delegation).toBeDefined();
    expect(view.authority_set).toEqual([
      expect.objectContaining({
        resource: CANONICAL_RESOURCE,
        actions: recorded?.actions,
        join_delegation: deriveJoinDelegation(recorded?.delegation as never),
      }),
    ]);
    // The observation point is the signed `iat`, and reliance ends at the
    // signed `fresh_until`, inside the advertised maximum staleness.
    expect(Math.abs(observedAtMs - clock().getTime())).toBeLessThan(2000);
    expect(freshUntilMs).toBeGreaterThan(observedAtMs);
    expect(freshUntilMs).toBeLessThanOrEqual(observedAtMs + maxStaleSeconds * 1000);
  });

  it("reads no subject and no client_id with the credential of a PDP the server has not enrolled", async () => {
    const record = approve("not-enrolled");
    const { view } = resolved(await resolver({ client: credential(reader) }).resolve({ id: record.id, issuer: ISSUER }));
    expect(view.state).toBe("active");
    expect("subject" in view).toBe(false);
    expect("client_id" in view).toBe(false);
  });

  it("is refused unauthorized when the server does not know its client", async () => {
    const record = approve("stranger");
    expect(await resolver({ client: credential(stranger) }).resolve({ id: record.id, issuer: ISSUER })).toMatchObject({
      ok: false,
      reason: "unauthorized",
      detail: "invalid_client",
    });
  });

  it("refuses an answer the server signed for another client, as a relay that swaps in its own credential obtains (consumer check 6)", async () => {
    const record = approve("relay");
    // A relay in front of the server that presents its own client's
    // assertion in place of the PDP's: the server answers the relay's client.
    const relay: Server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", async () => {
        const form = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
        form.set("client_assertion", await credential(reader).assertion());
        const upstream = await fetch(statusEndpoint, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: form.toString(),
        });
        res.writeHead(upstream.status, { "content-type": upstream.headers.get("content-type") ?? "text/plain" });
        res.end(Buffer.from(await upstream.arrayBuffer()));
      });
    });
    await new Promise<void>((resolve) => relay.listen(0, "127.0.0.1", resolve));
    try {
      const via = `http://127.0.0.1:${(relay.address() as AddressInfo).port}/mission/status`;
      expect(await resolver({ statusEndpoint: via }).resolve({ id: record.id, issuer: ISSUER })).toMatchObject({
        ok: false,
        reason: "unverifiable",
        detail: "sub",
      });
    } finally {
      relay.closeAllConnections();
      await new Promise<void>((resolve) => relay.close(() => resolve()));
    }
  });

  it("observes a revocation at once on a fresh read, and on a cached read once the signed bound passes", async () => {
    const fresh = approve("revoke-fresh");
    const bounded = approve("revoke-bounded");
    const r = resolver();
    for (const m of [fresh, bounded]) expect(resolved(await r.resolve({ id: m.id, issuer: ISSUER })).view.state).toBe("active");
    await revoke(fresh.id);
    await revoke(bounded.id);

    // A fresh read (the commit phase's) reaches the server and sees it now.
    const now = resolved(await r.resolve({ id: fresh.id, issuer: ISSUER }, { fresh: true }));
    expect(now).toMatchObject({ source: "fetched", view: { state: "terminated" } });

    // A cached read relies on the earlier observation only inside its bound:
    // the answer it reuses is still the one the server signed before the
    // revocation, and once that answer's `fresh_until` passes the next read
    // goes back to the server.
    const within = resolved(await r.resolve({ id: bounded.id, issuer: ISSUER }));
    expect(within).toMatchObject({ source: "cached", view: { state: "active" } });
    offsetMs = within.freshUntilMs - Date.now();
    const after = resolved(await r.resolve({ id: bounded.id, issuer: ISSUER }));
    expect(after).toMatchObject({ source: "fetched", view: { state: "terminated" } });
  });

  it("establishes nothing while the server is down, caches nothing from it, and resolves again once it is back", async () => {
    const record = approve("stop-start");
    const r = resolver();
    const first = resolved(await r.resolve({ id: record.id, issuer: ISSUER }));
    await stop();
    try {
      // A commit-phase read cannot reach the source.
      expect(await r.resolve({ id: record.id, issuer: ISSUER }, { fresh: true })).toMatchObject({
        ok: false,
        reason: "unavailable",
        detail: "transport",
      });
      // An answer whose bound has passed is not reused in the source's absence.
      offsetMs = first.freshUntilMs - Date.now();
      expect(await r.resolve({ id: record.id, issuer: ISSUER })).toMatchObject({ ok: false, reason: "unavailable" });
    } finally {
      await listen();
    }
    expect(resolved(await r.resolve({ id: record.id, issuer: ISSUER }))).toMatchObject({
      source: "fetched",
      view: { state: "active" },
    });
  });

  it("gives up at its deadline on a source that answers too slowly", async () => {
    const record = approve("slow");
    // A forwarding proxy in front of the server that holds each request.
    const proxy: Server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        setTimeout(async () => {
          try {
            const upstream = await fetch(`${ISSUER}${req.url}`, {
              method: "POST",
              headers: { "content-type": String(req.headers["content-type"]) },
              body: Buffer.concat(chunks),
            });
            res.writeHead(upstream.status, { "content-type": upstream.headers.get("content-type") ?? "text/plain" });
            res.end(Buffer.from(await upstream.arrayBuffer()));
          } catch {
            res.destroy();
          }
        }, 1500);
      });
    });
    await new Promise<void>((resolve) => proxy.listen(0, "127.0.0.1", resolve));
    const via = `http://127.0.0.1:${(proxy.address() as AddressInfo).port}`;
    try {
      const r = resolver({ statusEndpoint: `${via}/mission/status`, timeoutMs: 300 });
      const started = Date.now();
      expect(await r.resolve({ id: record.id, issuer: ISSUER })).toMatchObject({ ok: false, reason: "unavailable", detail: "timeout" });
      expect(Date.now() - started).toBeLessThan(1200);
      // The same proxy, given the time, delivers an answer that verifies.
      const patient = resolver({ statusEndpoint: `${via}/mission/status`, timeoutMs: 5000 });
      expect(resolved(await patient.resolve({ id: record.id, issuer: ISSUER })).view.state).toBe("active");
    } finally {
      proxy.closeAllConnections();
      await new Promise<void>((resolve) => proxy.close(() => resolve()));
    }
  });
});
