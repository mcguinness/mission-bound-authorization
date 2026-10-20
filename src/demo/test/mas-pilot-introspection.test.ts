/**
 * @spec authority-server#mission-join rule 8, authority-server#mapping-contract (#818 slice 3; RFC 7662, RFC 7009)
 *
 * The MAS pilot with OPAQUE estate tokens, end to end: the estate issues an
 * opaque, DPoP-bound access token to a client registered for that format, and
 * the gateway validates it by introspection at the estate before the same join,
 * mapping contract, Resource policy and class reservation the JWT path meets.
 * The gateway's introspection calls go through a forwarding proxy, so a test
 * can make the path to the estate time out, fail, or answer for another
 * issuer. Every case runs over a live OpenFGA and is skipped without one.
 */

import { createServer, type IncomingMessage, type Server } from "node:http";
import { generateKeyPair } from "jose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { EvaluationRequest } from "@mission/pdp";
import type { MasPilot } from "../src/mas-pilot/compose.js";
import { loadMasPilotConfig, type MasPilotConfig } from "../src/mas-pilot/config.js";
import { revokeEstateToken } from "../src/mas-pilot/estate-client.js";
import {
  admin,
  approve,
  call,
  composeRecorded,
  estateToken,
  handshakeStatus,
  openfgaReachable,
  READ_ACTIONS,
  relocateEstate,
} from "./mas-pilot-support.js";

const up = await openfgaReachable();
const d = up ? describe : describe.skip;
if (!up) console.warn("OpenFGA unreachable; skipping the MAS pilot introspection tests");

/** This file's estate port; the other pilot files hold their own. */
const ESTATE_PORT = 14825;
const base = relocateEstate(loadMasPilotConfig(), ESTATE_PORT);
/** A short introspection timeout, so the timeout case runs fast. */
const config: MasPilotConfig = { ...base, introspection: { ...base.introspection, timeout_ms: 300 } };
const OPAQUE_CLIENT = "estate-opaque-bot-4e2";
const UPSTREAM = `${config.estate.issuer}/token/introspection`;

/** What the forwarding proxy does with the next introspection call. */
type ProxyMode = "pass" | "delay" | "error" | "garbage" | "foreign-iss";
let mode: ProxyMode = "pass";
let proxy: Server;
let proxyUrl: string;
/** The introspection cache's clock runs this far ahead of real time. */
let cacheClockOffsetMs = 0;

const read = (req: IncomingMessage): Promise<string> =>
  new Promise((resolve) => {
    let s = "";
    req.on("data", (c) => {
      s += c;
    });
    req.on("end", () => resolve(s));
  });

beforeAll(async () => {
  proxy = createServer(async (req, res) => {
    const body = await read(req);
    if (mode === "delay") await new Promise((r) => setTimeout(r, config.introspection.timeout_ms * 3));
    if (mode === "error") {
      res.writeHead(500, { "content-type": "application/json" });
      res.end("{}");
      return;
    }
    if (mode === "garbage") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end("<html>maintenance</html>");
      return;
    }
    try {
      const upstream = await fetch(UPSTREAM, {
        method: "POST",
        headers: { "content-type": String(req.headers["content-type"]), authorization: String(req.headers.authorization) },
        body,
      });
      let text = await upstream.text();
      if (mode === "foreign-iss") {
        const answer = JSON.parse(text) as Record<string, unknown>;
        if (answer.active === true) answer.iss = config.mission_issuer;
        text = JSON.stringify(answer);
      }
      res.writeHead(upstream.status, { "content-type": "application/json" });
      res.end(text);
    } catch {
      if (!res.headersSent) res.writeHead(502);
      res.end();
    }
  });
  await new Promise<void>((resolve) => proxy.listen(0, "127.0.0.1", () => resolve()));
  const addr = proxy.address();
  proxyUrl = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}/introspect`;
});
afterAll(async () => {
  proxy?.closeAllConnections();
  await new Promise<void>((resolve) => (proxy ? proxy.close(() => resolve()) : resolve()));
});

d("MAS pilot introspection: opaque estate tokens at the gateway (#818 slice 3)", () => {
  let pilot: MasPilot;
  let requests: EvaluationRequest[];
  let aliceMission: string;
  let danaMission: string;
  let remitMission: string;

  beforeAll(async () => {
    ({ pilot, requests } = await composeRecorded({
      config,
      introspectionEndpoint: proxyUrl,
      introspectionNow: () => new Date(Date.now() + cacheClockOffsetMs),
    }));
    aliceMission = approve(pilot, "alice", { label: "opaque-alice" });
    danaMission = approve(pilot, "dana", { label: "opaque-dana" });
    remitMission = approve(pilot, "alice", { label: "opaque-remit", actions: [...READ_ACTIONS, "payments:remittance.send"] });
  }, 30_000);
  afterAll(async () => {
    await pilot?.close();
  });
  beforeEach(() => {
    mode = "pass";
    cacheClockOffsetMs = 0;
  });

  const opaque = (account = "u-1001", scope = "invoices.read", resource?: string) =>
    resource === undefined
      ? estateToken(pilot, OPAQUE_CLIENT, account, scope)
      : estateTokenFor(pilot, account, scope, resource);

  it("permits a joined read with an opaque token, its identity read from the estate's introspection", async () => {
    const credential = await opaque();
    expect(credential.token.split(".")).toHaveLength(1);
    const res = await call(pilot, credential, aliceMission, "get_invoice", { invoice_id: "inv-1" });
    expect(res.ok, JSON.stringify(res)).toBe(true);
    const last = requests.at(-1);
    expect(last?.subject).toEqual({ id: "u-1001", properties: { iss: config.estate.issuer } });
    expect(last?.context.actor?.client_id).toBe(OPAQUE_CLIENT);
    expect(last?.context.credential?.issuer).toBe(config.estate.issuer);
  });

  it("bounds the opaque token by its introspected scope: an action that scope does not carry is refused out_of_authority, and a scope that carries it permits", async () => {
    const narrow = await opaque("u-1001", "invoices.read");
    const decided = requests.length;
    const refused = await call(pilot, narrow, aliceMission, "lookup_vendor", { vendor_id: "acme" });
    expect(refused.ok).toBe(false);
    expect(refused.refusal_reason).toBe("out_of_authority");
    expect(requests.length).toBe(decided);
    const wide = await opaque("u-1001", "invoices.read vendors.read");
    const permitted = await call(pilot, wide, aliceMission, "lookup_vendor", { vendor_id: "acme" });
    expect(permitted.ok, JSON.stringify(permitted)).toBe(true);
  });

  it("refuses a token the estate reports inactive, with no decision", async () => {
    const credential = await opaque();
    const unknown = { ...credential, token: `${credential.token}x` };
    const decided = requests.length;
    expect(await handshakeStatus(pilot, unknown, aliceMission)).toBe(401);
    expect(requests.length).toBe(decided);
  });

  it("stops admitting a token revoked at the estate once its positive cache entry ends, within cache_max_seconds", async () => {
    const credential = await opaque();
    expect((await call(pilot, credential, aliceMission, "get_invoice", { invoice_id: "inv-1" })).ok).toBe(true);
    const registration = pilot.estateClients.get(OPAQUE_CLIENT);
    const status = await revokeEstateToken({
      endpoint: pilot.estate.revocationEndpoint,
      clientId: OPAQUE_CLIENT,
      clientSecret: registration?.client_secret ?? "",
      token: credential.token,
    });
    expect(status).toBe(200);
    // Inside the bound the cached introspection still stands: the stated latency.
    expect(await handshakeStatus(pilot, credential, aliceMission)).toBe(200);
    cacheClockOffsetMs = (config.introspection.cache_max_seconds + 1) * 1000;
    const decided = requests.length;
    expect(await handshakeStatus(pilot, credential, aliceMission)).toBe(401);
    expect(requests.length).toBe(decided);
  });

  it("fails closed when introspection does not answer within its timeout, with no decision", async () => {
    const credential = await opaque();
    mode = "delay";
    const decided = requests.length;
    expect(await handshakeStatus(pilot, credential, aliceMission)).toBe(503);
    expect(requests.length).toBe(decided);
  });

  it("fails closed when introspection answers with an error or a body that is not JSON, with no decision", async () => {
    const credential = await opaque();
    const decided = requests.length;
    mode = "error";
    expect(await handshakeStatus(pilot, credential, aliceMission)).toBe(503);
    mode = "garbage";
    expect(await handshakeStatus(pilot, credential, aliceMission)).toBe(503);
    expect(requests.length).toBe(decided);
  });

  it("refuses an opaque token the estate issued for another of its resources, with no decision", async () => {
    const credential = await opaque("u-1001", "invoices.read", "https://ledger.estate.invalid/api");
    const decided = requests.length;
    expect(await handshakeStatus(pilot, credential, aliceMission)).toBe(401);
    expect(requests.length).toBe(decided);
  });

  it("enforces the introspected cnf: the same opaque token with another DPoP key is refused", async () => {
    const credential = await opaque();
    const thief = { token: credential.token, dpopKeys: await generateKeyPair("ES256", { extractable: true }) };
    expect(await handshakeStatus(pilot, thief, aliceMission)).toBe(401);
    expect(await handshakeStatus(pilot, credential, aliceMission)).toBe(200);
  });

  it("refuses an introspection answer that names another issuer, so an introspected identity is only ever the estate's", async () => {
    const credential = await opaque();
    mode = "foreign-iss";
    expect(await handshakeStatus(pilot, credential, aliceMission)).toBe(401);
  });

  it("keeps namespaces apart on the opaque path: estate account alice joins dana's Mission and never alice's", async () => {
    const credential = await opaque("alice");
    const onAlice = await call(pilot, credential, aliceMission, "get_invoice", { invoice_id: "inv-1" });
    expect(onAlice.ok).toBe(false);
    expect(onAlice.denial_reason).toBe("mission_binding_failed");
    const onDana = await call(pilot, credential, danaMission, "get_invoice", { invoice_id: "inv-1" });
    expect(onDana.ok, JSON.stringify(onDana)).toBe(true);
  });

  it("applies the same Resource policy to the introspected client: revoking its authorized_client denies resource_policy", async () => {
    const credential = await opaque();
    await admin(pilot, "revoke", "--iss", config.estate.issuer, "--client", OPAQUE_CLIENT, "--relation", "client", "--vendor", "acme");
    try {
      const res = await call(pilot, credential, aliceMission, "get_invoice", { invoice_id: "inv-1" });
      expect(res.ok).toBe(false);
      expect(res.denial_reason).toBe("resource_policy");
    } finally {
      await admin(pilot, "grant", "--iss", config.estate.issuer, "--client", OPAQUE_CLIENT, "--relation", "client", "--vendor", "acme");
    }
  });

  it("applies the same class reservation: a remittance under an opaque token is denied though scope, Mission and Resource policy allow it", async () => {
    const credential = await opaque("u-1001", "invoices.read remit.send");
    await admin(pilot, "grant", "--iss", config.estate.issuer, "--sub", "u-1001", "--relation", "payer", "--vendor", "acme");
    try {
      const res = await call(pilot, credential, remitMission, "send_remittance_email", {
        invoice_id: "inv-1",
        idempotency_key: "mas-pilot-opaque-remit-01",
      });
      expect(res.ok).toBe(false);
      expect(res.denial_reason).toBe("mission_binding_failed");
      expect(pilot.connectors.committedEffects()).toEqual([]);
    } finally {
      await admin(pilot, "revoke", "--iss", config.estate.issuer, "--sub", "u-1001", "--relation", "payer", "--vendor", "acme");
    }
  });
});

/** An opaque token for another of the estate's resources. */
async function estateTokenFor(pilot: MasPilot, account: string, scope: string, resource: string) {
  const { obtainEstateToken } = await import("../src/mas-pilot/estate-client.js");
  const registration = pilot.estateClients.get(OPAQUE_CLIENT);
  const dpopKeys = await generateKeyPair("ES256", { extractable: true });
  const result = await obtainEstateToken({
    issuer: pilot.estate.issuer,
    clientId: OPAQUE_CLIENT,
    clientSecret: registration?.client_secret ?? "",
    redirectUri: registration?.redirect_uri ?? "",
    account,
    resource,
    scope,
    dpopKeys,
  });
  if (!result.ok) throw new Error(`estate token: ${JSON.stringify(result)}`);
  return { token: result.accessToken, dpopKeys };
}
