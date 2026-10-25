/**
 * @spec authority-server#join-assertion-artifact (#1560)
 *
 * The pilot MAS's join evidence, as an operator reads it: each Join Assertion
 * the MAS mints is a join evidence event on its kernel's store, read through
 * the operator console's MAS half (`GET /missions/{id}/join-evidence`, behind
 * the console's bearer) and served on no route of the MAS's own. The separated
 * MAS process (`mas-serve.ts`), started with a key ring and a kernel store,
 * keeps the events across a restart. The pilot's kernel keeps each event for
 * the deployment's declared audit horizon (`AUDIT_HORIZON_SECONDS`, one year
 * after Mission expiry; D770), not the reusable kernel's 90-day default.
 *
 * Restart scope: the MAS process is started directly (`startMasProcess`, the
 * entry point the launcher spawns); a relaunch through the launcher
 * (`launchMasPilot`) is not witnessed here.
 *
 * No OpenFGA: the first two blocks drive the MAS's service with a deployment
 * double; the third runs the MAS process and the estate it introspects, with
 * no gateway or decision point. The MAS process binds `127.0.0.1:14917` and
 * the estate `14918`.
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  type ActingToken,
  DEFAULT_AUDIT_RETENTION_S,
  initSigningKeyRing,
  type JoinAssertionDeployment,
  reconcileKernelRecovery,
  validateMissionIntent,
} from "@mission/authorization-server";
import { AUDIT_HORIZON_SECONDS, CANONICAL_RESOURCE, TOPOLOGY } from "@mission/demo-data";
import { accessTokenHash } from "@mission/mcp-payments";
import { calculateJwkThumbprint, decodeJwt, exportJWK, generateKeyPair, importJWK, type JWK, SignJWT } from "jose";
import { afterAll, describe, expect, it } from "vitest";
import { loadMasPilotConfig, type MasPilotConfig } from "../src/mas-pilot/config.js";
import { startEstateAuthorizationServer } from "../src/mas-pilot/estate-as.js";
import { obtainEstateToken } from "../src/mas-pilot/estate-client.js";
import { buildPilotMas, newStatusClientKey } from "../src/mas-pilot/mas-as.js";
import { type MasProcess, type MasProcessOptions, startMasProcess } from "../src/mas-pilot/mas-process.js";
import { masConsoleRoutes, startOperatorConsole } from "../src/mas-pilot/operator-console.js";
import { relocateEstate } from "./mas-pilot-support.js";

/** A kernel store's recovery witness, created before the MAS first starts on it (#250 step 3). */
function kernelWitnessFor(storeFile: string, witnessFile: string): string {
  mkdirSync(dirname(storeFile), { recursive: true });
  mkdirSync(dirname(witnessFile), { recursive: true });
  reconcileKernelRecovery({ storeFile, witnessFile, action: "init" });
  return witnessFile;
}

const MAS_PORT = 14917;
const MAS_URL = `http://127.0.0.1:${MAS_PORT}`;
const ESTATE_PORT = 14918;
const ENDPOINT = `${MAS_URL}/mission/join-assertion`;
const INTROSPECTOR = "mas-join-introspector";
/** The pilot kernel's audit retention past the Mission's expiry: the deployment's one-year declaration (D770). */
const AUDIT_RETENTION_MS = AUDIT_HORIZON_SECONDS * 1000;

const dirs: string[] = [];
const closers: Array<() => Promise<void>> = [];

afterAll(async () => {
  for (const close of closers.reverse()) await close().catch(() => {});
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

/** A private-key JWT client assertion for `caller`, audienced to the MAS's issuer identifier. */
async function clientAssertion(caller: string, key: JWK, issuer: string): Promise<string> {
  const iat = Math.floor(Date.now() / 1000);
  return new SignJWT({ jti: crypto.randomUUID() })
    .setProtectedHeader({ alg: "ES256", kid: key.kid as string, typ: "client-authentication+jwt" })
    .setIssuer(caller)
    .setSubject(caller)
    .setAudience(issuer)
    .setIssuedAt(iat)
    .setExpirationTime(iat + 60)
    .sign((await importJWK(key, "ES256")) as CryptoKey);
}

const intentFor = (label: string) =>
  JSON.stringify({ goal: `Join evidence: ${label}`, target_resources: [CANONICAL_RESOURCE], expires_at: "2027-06-01T00:00:00Z" });
const readAuthority = [
  { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"], constraints: { vendors: ["acme"] } },
];

/** A GET at an operator console, with the bearer where one is given. */
async function consoleGet(base: string, path: string, token?: string): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetch(`${base}${path}`, { headers: token ? { authorization: `Bearer ${token}` } : {} });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

describe("the MAS operator console reads join evidence (@spec authority-server#join-assertion-artifact, #1560)", () => {
  it("reads a Mission's join evidence events behind the console's bearer, that Mission's alone, and the MAS serves them on no route of its own", async () => {
    const config = loadMasPilotConfig();
    const pdpClient = config.separated_mas.pdp_client_id;
    const pdp = await newStatusClientKey(pdpClient);
    const known = new Map<string, ActingToken>();
    const deployment: JoinAssertionDeployment = {
      async establishActingToken(form) {
        const token = "accessToken" in form ? known.get(form.accessToken) : undefined;
        return token ? { ok: true, token } : { ok: false, reason: "inactive" };
      },
      evaluateJoin: (token, mission) =>
        token.subject === "u-1001" && mission.subject.sub === "alice" ? { clientId: mission.client_id, disposition: "client", mappingVersion: "mas-pilot-identity@1" } : undefined,
    };
    const mas = await buildPilotMas(config, { statusClients: [pdp.registration], joinAssertions: deployment });
    closers.push(async () => mas.built.kernel.close());
    const approve = (label: string) =>
      mas.built.kernel.approve({
        intent: validateMissionIntent(intentFor(label)),
        proposedAuthority: readAuthority as never,
        subject: { iss: mas.issuer, sub: "alice" },
        approver: { iss: mas.issuer, sub: "bob" },
        clientId: "ap-agent",
        approvalEventId: `apev-join-evidence-console-${label}`,
      });
    const mint = async (missionId: string) => {
      const token = `estate-token-${crypto.randomUUID()}`;
      known.set(token, { issuer: config.estate.issuer, subject: "u-1001", clientId: "estate-ap-bot-7f3", exp: Math.floor(Date.now() / 1000) + 600, cnf: { jkt: "jkt-console" } });
      const answer = await mas.built.joinAssertions?.handle(
        JSON.stringify({
          mission_id: missionId,
          audience: pdpClient,
          access_token: token,
          client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          client_assertion: await clientAssertion(pdpClient, pdp.privateJwk, mas.issuer),
        }),
        "application/json",
        "",
      );
      expect(answer?.status, JSON.stringify(answer?.body)).toBe(200);
      return { token, claims: decodeJwt(answer?.body.assertion as string) };
    };
    const one = approve("one");
    const other = approve("other");
    const first = await mint(one.id);
    await mint(other.id);
    const second = await mint(one.id);

    const token = crypto.randomUUID();
    const operatorConsole = await startOperatorConsole([masConsoleRoutes(mas)], { port: 0, token });
    closers.push(() => operatorConsole.close());
    const path = `/missions/${one.id}/join-evidence`;
    expect(await consoleGet(operatorConsole.url, path)).toEqual({ status: 401, body: { error: "unauthorized" } });
    expect((await consoleGet(operatorConsole.url, path, crypto.randomUUID())).status).toBe(401);
    const read = await consoleGet(operatorConsole.url, path, token);
    expect(read.status).toBe(200);
    expect(read.body).toMatchObject({ mission_id: one.id, issuer: mas.issuer });
    const events = read.body.events as Array<Record<string, unknown>>;
    expect(events.map((e) => (e.token as { sha256: string }).sha256)).toEqual([accessTokenHash(first.token), accessTokenHash(second.token)]);
    expect(events[0]).toEqual({
      mission: { issuer: mas.issuer, id: one.id },
      token: { sha256: accessTokenHash(first.token), jkt: "jkt-console" },
      join: { client_id: "ap-agent", disposition: "client" },
      caller: pdpClient,
      audience: pdpClient,
      mapping_version: "mas-pilot-identity@1",
      iat: first.claims.iat,
      exp: first.claims.exp,
      retain_until: new Date(Date.parse(one.expires_at) + AUDIT_RETENTION_MS).toISOString(),
    });
    expect(((await consoleGet(operatorConsole.url, `/missions/${other.id}/join-evidence`, token)).body.events as unknown[]).length).toBe(1);

    // The MAS's own surface serves no join evidence, with or without the bearer.
    const listening: Server = createServer(mas.built.provider.callback());
    await new Promise<void>((resolve) => listening.listen(0, "127.0.0.1", () => resolve()));
    closers.push(() => new Promise<void>((resolve) => listening.close(() => resolve())));
    const masBase = `http://127.0.0.1:${(listening.address() as AddressInfo).port}`;
    for (const bearer of [undefined, token]) {
      const res = await fetch(`${masBase}${path}`, { headers: bearer ? { authorization: `Bearer ${bearer}` } : {} });
      expect(res.status, bearer ? "with the bearer" : "without").toBe(404);
      expect(await res.text()).not.toContain(accessTokenHash(first.token));
    }
  });
});

describe("the pilot's kernel keeps join evidence for the deployment's audit horizon (@spec authority-server#join-assertion-artifact, #1560, D770)", { timeout: 60_000 }, () => {
  it("keeps an event for one year after its Mission's expiry, the horizon its tombstones share: past the reusable 90-day default and at its retain_until it is kept across a restart, and only a boot after retain_until prunes it", async () => {
    const config = loadMasPilotConfig();
    const pdpClient = config.separated_mas.pdp_client_id;
    const pdp = await newStatusClientKey(pdpClient);
    const dir = mkdtempSync(join(tmpdir(), "mas-pilot-join-horizon-"));
    dirs.push(dir);
    const { asToken, asStatus, asTxn, asContinuation } = TOPOLOGY.keys;
    const keyRing = join(dir, "keys", "ring.json");
    const issuer = `http://${config.separated_mas.host}:${config.separated_mas.port}`;
    await initSigningKeyRing(keyRing, issuer, { asToken, asStatus, asTxn, asContinuation });
    let clockMs = Date.now();
    const known = new Map<string, ActingToken>();
    const deployment: JoinAssertionDeployment = {
      async establishActingToken(form) {
        const token = "accessToken" in form ? known.get(form.accessToken) : undefined;
        return token ? { ok: true, token } : { ok: false, reason: "inactive" };
      },
      evaluateJoin: (token, mission) =>
        token.subject === "u-1001" && mission.subject.sub === "alice" ? { clientId: mission.client_id, disposition: "client", mappingVersion: "mas-pilot-identity@1" } : undefined,
    };
    const boot = () =>
      buildPilotMas(config, {
        statusClients: [pdp.registration],
        signingKeys: { ring: keyRing },
        kernelStore: { file: join(dir, "kernel.db") },
        joinAssertions: deployment,
        now: () => new Date(clockMs),
      });

    const first = await boot();
    expect(first.built.kernel.tombstones.horizons().audit_retention_seconds).toBe(AUDIT_HORIZON_SECONDS);
    const record = first.built.kernel.approve({
      intent: validateMissionIntent(intentFor("horizon")),
      proposedAuthority: readAuthority as never,
      subject: { iss: first.issuer, sub: "alice" },
      approver: { iss: first.issuer, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: `apev-join-evidence-horizon-${crypto.randomUUID()}`,
    });
    const token = `estate-token-${crypto.randomUUID()}`;
    known.set(token, { issuer: config.estate.issuer, subject: "u-1001", clientId: "estate-ap-bot-7f3", exp: Math.floor(Date.now() / 1000) + 600, cnf: { jkt: "jkt-horizon" } });
    const answer = await first.built.joinAssertions?.handle(
      JSON.stringify({
        mission_id: record.id,
        audience: pdpClient,
        access_token: token,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: await clientAssertion(pdpClient, pdp.privateJwk, first.issuer),
      }),
      "application/json",
      "",
    );
    expect(answer?.status, JSON.stringify(answer?.body)).toBe(200);
    first.built.kernel.close();

    const expiry = Date.parse(record.expires_at);
    const retainUntil = expiry + AUDIT_HORIZON_SECONDS * 1000;
    const retained = (mas: Awaited<ReturnType<typeof boot>>) => mas.built.kernel.joinEvidence.forMission(record).map((r) => r.retain_until);
    for (const at of [expiry + DEFAULT_AUDIT_RETENTION_S * 1000 + 1, retainUntil]) {
      clockMs = at;
      const rebooted = await boot();
      try {
        expect(retained(rebooted), new Date(at).toISOString()).toEqual([new Date(retainUntil).toISOString()]);
      } finally {
        rebooted.built.kernel.close();
      }
    }
    clockMs = retainUntil + 1;
    const past = await boot();
    try {
      expect(retained(past)).toEqual([]);
    } finally {
      past.built.kernel.close();
    }
  });
});

/**
 * The separated configuration with the Join Assertion path declared: the
 * estate on its own port, the Mission issuer at the MAS, the MAS on its own
 * port.
 */
function joinConfig(): MasPilotConfig {
  const base = relocateEstate(loadMasPilotConfig(), ESTATE_PORT);
  const moved = JSON.parse(JSON.stringify(base).split(JSON.stringify(base.mission_issuer).slice(1, -1)).join(MAS_URL)) as MasPilotConfig;
  return {
    ...moved,
    separated_mas: { ...moved.separated_mas, port: MAS_PORT },
    join_assertion: { introspection_client_id: INTROSPECTOR, required: false, required_classes: ["consequential_read"], pdp_algorithms: ["ES256"] },
  };
}

describe("the separated MAS process keeps its join evidence across a restart (@spec authority-server#join-assertion-artifact, #1560)", () => {
  it("with a key ring and a kernel store, a minted assertion's event, with its mapping_version, reads back through the MAS's operator console after the MAS restarts", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mas-pilot-join-evidence-"));
    dirs.push(dir);
    const { asToken, asStatus, asTxn, asContinuation } = TOPOLOGY.keys;
    const keyRing = join(dir, "keys", "ring.json");
    await initSigningKeyRing(keyRing, MAS_URL, { asToken, asStatus, asTxn, asContinuation });
    const config = joinConfig();
    const configPath = join(dir, "mas-pilot.json");
    writeFileSync(configPath, JSON.stringify(config));
    const pdpClient = config.separated_mas.pdp_client_id;
    const pdp = await newStatusClientKey(pdpClient);
    const joinIntrospectionSecret = crypto.randomUUID();

    // The estate the MAS introspects, with the MAS's introspection client registered.
    const estateClients = config.estate.clients.map((c) => ({ ...c, client_secret: crypto.randomUUID() }));
    const estate = await startEstateAuthorizationServer({
      issuer: config.estate.issuer,
      host: config.estate.host,
      port: config.estate.port,
      accounts: config.estate.accounts,
      clients: estateClients,
      introspectionClients: [{ client_id: INTROSPECTOR, client_secret: joinIntrospectionSecret }],
      resourceServers: config.estate.resource_servers,
    });
    closers.push(() => estate.close());

    const options: MasProcessOptions = {
      configPath,
      statusClients: [pdp.registration],
      keyRing,
      kernelStore: join(dir, "state", "kernel.db"),
      kernelWitness: kernelWitnessFor(join(dir, "state", "kernel.db"), join(dir, "witness", "kernel.witness")),
      joinIntrospectionSecret,
      operatorConsole: true,
    };
    let mas: MasProcess = await startMasProcess(options);
    closers.push(() => mas.stop());

    const missionId = await mas.approve({
      intent: intentFor("restart"),
      proposedAuthority: readAuthority,
      subject: { iss: MAS_URL, sub: "alice" },
      approver: { iss: MAS_URL, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: `apev-join-evidence-restart-${crypto.randomUUID()}`,
    });
    const bot = estateClients.find((c) => c.client_id === "estate-ap-bot-7f3");
    if (!bot) throw new Error("no estate-ap-bot-7f3 in the configuration");
    const dpopKeys = await generateKeyPair("ES256", { extractable: true });
    const issued = await obtainEstateToken({
      issuer: estate.issuer,
      clientId: bot.client_id,
      clientSecret: bot.client_secret,
      redirectUri: bot.redirect_uri,
      account: "u-1001",
      resource: CANONICAL_RESOURCE,
      scope: "invoices.read",
      dpopKeys,
    });
    if (!issued.ok) throw new Error(`estate token: ${JSON.stringify(issued)}`);
    const res = await fetch(ENDPOINT, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        mission_id: missionId,
        audience: pdpClient,
        access_token: issued.accessToken,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: await clientAssertion(pdpClient, pdp.privateJwk, MAS_URL),
      }),
    });
    const minted = (await res.json()) as Record<string, unknown>;
    expect(res.status, JSON.stringify(minted)).toBe(200);
    const claims = decodeJwt(minted.assertion as string);
    const expected = {
      mission: { issuer: MAS_URL, id: missionId },
      token: { sha256: accessTokenHash(issued.accessToken), jkt: await calculateJwkThumbprint(await exportJWK(dpopKeys.publicKey)) },
      join: { client_id: "ap-agent", disposition: "client" },
      caller: pdpClient,
      audience: pdpClient,
      mapping_version: "mas-pilot-identity@1",
      iat: claims.iat,
      exp: claims.exp,
      retain_until: new Date(Date.parse("2027-06-01T00:00:00Z") + AUDIT_RETENTION_MS).toISOString(),
    };
    expect(claims.mapping_version).toBe("mas-pilot-identity@1");
    const path = `/missions/${missionId}/join-evidence`;
    const first = mas.console;
    if (!first) throw new Error("the MAS process serves no operator console");
    const before = await consoleGet(first.url, path, first.token);
    expect(before.body.events).toEqual([expected]);

    await mas.stop();
    mas = await startMasProcess(options);
    const second = mas.console;
    if (!second) throw new Error("the restarted MAS process serves no operator console");
    expect((await consoleGet(second.url, path)).status).toBe(401);
    const after = await consoleGet(second.url, path, second.token);
    expect(after.status).toBe(200);
    expect(after.body.events).toEqual([expected]);
  }, 180_000);
});
