/**
 * @spec authority-server#join-assertion-request, authority-server#join-assertion-pdp,
 * authority-server#join-authzen (#1454)
 *
 * The separated MAS pilot's Join Assertion path end to end: the MAS in its own
 * process mints sender-bound Join Assertions for estate credentials (a JWT
 * validated under the estate's JWKS, an opaque token introspected as the MAS's
 * own introspection client), the PEP requests one for each joined request and
 * carries it with the credential's digest and thumbprint, and the PDP joins on
 * it. The configuration declares the requirement for `consequential_read`, so
 * a joined read is never decided under the mapping join alone.
 *
 * Each refusal asserts that nothing was disclosed or committed and names its
 * evidence carrier, the PDP's signed Decision Evidence. The PEP's requests to
 * the MAS pass through a test seam (`wrapAssertionSource`) that can substitute
 * what the MAS returned; an assertion the MAS would never mint is signed with
 * the MAS's own Status key, read from the key ring this file initializes.
 */

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { initSigningKeyRing } from "@mission/authorization-server";
import { TOPOLOGY } from "@mission/demo-data";
import { accessTokenHash, CANONICAL_RESOURCE, type DecisionEvidence, type JoinAssertionSource } from "@mission/mcp-payments";
import { type EvaluationRequest, privateKeyJwtClient } from "@mission/pdp";
import { calculateJwkThumbprint, decodeJwt, exportJWK, generateKeyPair, importJWK, type JWK, type JWTPayload, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { composeMasPilot } from "../src/mas-pilot/compose.js";
import { loadMasPilotConfig, type MasPilotConfig, parseMasPilotConfig } from "../src/mas-pilot/config.js";
import { obtainEstateToken } from "../src/mas-pilot/estate-client.js";
import { launchMasPilot, masPilotLaunchOptions } from "../src/mas-pilot/launcher.js";
import { newStatusClientKey } from "../src/mas-pilot/mas-as.js";
import { type MasProcess, startMasProcess } from "../src/mas-pilot/mas-process.js";
import { composeSeparatedMasPilot, type SeparatedMasPilot } from "../src/mas-pilot/separated.js";
import { call, type Credential, estateToken, OPENFGA, openfgaReachable, READ_ACTIONS, relocateEstate } from "./mas-pilot-support.js";

const d = (await openfgaReachable()) ? describe : describe.skip;

const MAS_PORT = 14905;
const MAS_URL = `http://127.0.0.1:${MAS_PORT}`;
const ESTATE_PORT = 14906;
const ENDPOINT = `${MAS_URL}/mission/join-assertion`;
const LEDGER = "https://ledger.estate.invalid/api";
const OTHER_PDP = "mas-pilot-pdp-2";
const DELEGATE = "subagent-invoice-extractor";
const PAYEE = "acct-acme-001";

/**
 * The separated configuration with the Join Assertion path declared: the
 * estate on its own port, the Mission issuer at the MAS, a second PDP enrolled
 * for the payments scope, the JWT bot also registered for the estate's ledger,
 * and an assertion required on every joined read.
 */
function joinConfig(): MasPilotConfig {
  const base = relocateEstate(loadMasPilotConfig(), ESTATE_PORT);
  const moved = JSON.parse(JSON.stringify(base).split(JSON.stringify(base.mission_issuer).slice(1, -1)).join(MAS_URL)) as MasPilotConfig;
  return {
    ...moved,
    estate: {
      ...moved.estate,
      clients: moved.estate.clients.map((c) => (c.client_id === "estate-ap-bot-7f3" ? { ...c, resources: [...c.resources, LEDGER] } : c)),
    },
    separated_mas: {
      ...moved.separated_mas,
      port: MAS_PORT,
      enrolled_pdps: [...moved.separated_mas.enrolled_pdps, { client_id: OTHER_PDP, enforcement_scopes: [CANONICAL_RESOURCE] }],
    },
    join_assertion: { introspection_client_id: "mas-join-introspector", required: false, required_classes: ["consequential_read"] },
  };
}

const dirs: string[] = [];
let config: MasPilotConfig;
let mas: MasProcess;
let pilot: SeparatedMasPilot;
let pdpKey: JWK;
let statusKey: CryptoKey;
let statusKid: string;
const requests: EvaluationRequest[] = [];
/** What the PEP's source returned for each request, after any substitution. */
const obtained: Array<string | undefined> = [];
/** A substitution for one test: given the PEP's request and the real source, what the PEP receives. */
let substitute: ((input: Parameters<JoinAssertionSource["obtain"]>[0], real: JoinAssertionSource) => Promise<string | undefined>) | undefined;

beforeAll(async () => {
  const dir = mkdtempSync(join(tmpdir(), "mas-pilot-join-assertion-"));
  dirs.push(dir);
  const { asToken, asStatus, asTxn, asContinuation } = TOPOLOGY.keys;
  const keyRing = join(dir, "keys", "ring.json");
  await initSigningKeyRing(keyRing, MAS_URL, { asToken, asStatus, asTxn, asContinuation });
  const ring = JSON.parse(readFileSync(keyRing, "utf8")) as { roles: { asStatus: { kid: string; private_jwk: JWK } } };
  statusKid = ring.roles.asStatus.kid;
  statusKey = (await importJWK(ring.roles.asStatus.private_jwk, "ES256")) as CryptoKey;
  config = joinConfig();
  const configPath = join(dir, "mas-pilot.json");
  writeFileSync(configPath, JSON.stringify(config));
  const pdp = await newStatusClientKey(config.separated_mas.pdp_client_id);
  pdpKey = pdp.privateJwk;
  // The MAS's introspection client secret, generated here and given to both
  // the MAS and the estate the pilot starts.
  const joinIntrospectionSecret = crypto.randomUUID();
  mas = await startMasProcess({ configPath, statusClients: [pdp.registration], keyRing, joinIntrospectionSecret });
  pilot = await composeSeparatedMasPilot({
    openfga: OPENFGA,
    resourcePolicyStore: { bootstrap: "development" },
    observeDecisionRequest: (r) => requests.push(r),
    config,
    mas: { url: MAS_URL, pdpKey },
    joinIntrospectionSecret,
    wrapAssertionSource: (real) => ({
      obtain: async (input) => {
        const out = substitute ? await substitute(input, real) : await real.obtain(input);
        obtained.push(out);
        return out;
      },
    }),
  });
}, 120_000);

afterAll(async () => {
  await pilot?.close();
  await mas?.stop();
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

/** A Mission the MAS approves for alice under `ap-agent`; `delegable` lets the extractor act under it. */
function approveAtMas(label: string, delegable = false): Promise<string> {
  return mas.approve({
    intent: JSON.stringify({ goal: `Join Assertion pilot: ${label}`, target_resources: [CANONICAL_RESOURCE], expires_at: "2027-06-01T00:00:00Z" }),
    proposedAuthority: [
      {
        type: "mission_resource_access",
        resource: CANONICAL_RESOURCE,
        actions: READ_ACTIONS,
        constraints: { vendors: ["acme"] },
        ...(delegable ? { delegation: { max_depth: 1, allowed_delegates: [{ sub: DELEGATE }] } } : {}),
      },
    ],
    subject: { iss: MAS_URL, sub: "alice" },
    approver: { iss: MAS_URL, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-join-assertion-${label}-${crypto.randomUUID()}`,
  });
}

/** A request at the MAS's Join Assertion endpoint, as the pilot's enforcement point. */
async function mintAt(body: Record<string, unknown>): Promise<{ status: number; body: Record<string, unknown> }> {
  const caller = privateKeyJwtClient({
    clientId: config.separated_mas.pdp_client_id,
    issuer: MAS_URL,
    audience: ENDPOINT,
    privateKey: (await importJWK(pdpKey, "ES256")) as CryptoKey,
    kid: pdpKey.kid as string,
  });
  const res = await fetch(ENDPOINT, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      ...body,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: await caller.assertion(),
    }),
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

/** The MAS's real assertion for `accessToken`, its claims edited and re-signed with the MAS's Status key. */
async function reSigned(missionId: string, accessToken: string, edit: (claims: JWTPayload) => void): Promise<string> {
  const minted = await mintAt({ mission_id: missionId, audience: config.separated_mas.pdp_client_id, access_token: accessToken });
  const claims = decodeJwt(minted.body.assertion as string);
  edit(claims);
  return new SignJWT(claims).setProtectedHeader({ alg: "ES256", kid: statusKid, typ: "mission-join+jwt" }).sign(statusKey);
}

const decisions = (missionId: string) =>
  pilot.evidence.forMission(missionId).filter((e): e is DecisionEvidence => e.kind === "decision");

/** A read the PDP denied mission_binding_failed: nothing disclosed or committed, and its signed Decision Evidence. */
function expectJoinRefused(res: Record<string, unknown>, missionId: string, label: string): void {
  expect(res, label).toMatchObject({ ok: false, denial_reason: "mission_binding_failed" });
  expect(JSON.stringify(res), label).not.toContain(PAYEE);
  expect(pilot.connectors.committedEffects(), label).toEqual([]);
  const evidence = decisions(missionId).at(-1)?.content as Record<string, unknown> | undefined;
  expect(evidence, label).toMatchObject({ decision: "deny", denial_reason: "mission_binding_failed" });
  expect(evidence?.join_view_id, label).toBeUndefined();
}

/** An estate token for `resource`, bound to `dpopKeys` (a fresh key unless given). */
async function tokenFor(clientId: string, account: string, scope: string, resource: string, keys?: Credential["dpopKeys"]): Promise<Credential> {
  const registration = pilot.estateClients.get(clientId);
  const dpopKeys = keys ?? (await generateKeyPair("ES256", { extractable: true }));
  const result = await obtainEstateToken({
    issuer: pilot.estate.issuer,
    clientId,
    clientSecret: registration?.client_secret as string,
    redirectUri: registration?.redirect_uri as string,
    account,
    resource,
    scope,
    dpopKeys,
  });
  if (!result.ok) throw new Error(`estate token: ${JSON.stringify(result)}`);
  return { token: result.accessToken, dpopKeys };
}

const read = (credential: Credential, missionId: string) => call(pilot, credential, missionId, "get_invoice", { invoice_id: "inv-1" });

d("the separated MAS pilot's Join Assertion path (#1454)", () => {
  it("joins a JWT and an opaque estate credential on the MAS's sender-bound assertion: the PEP carries it with the credential's digest and DPoP key thumbprint, and the PDP permits a read that requires it", async () => {
    substitute = undefined;
    const missionId = await approveAtMas("positive");
    const metadata = (await (await fetch(`${MAS_URL}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
    expect(metadata.mission_join_assertion_endpoint).toBe(ENDPOINT);
    for (const [clientId, format] of [
      ["estate-ap-bot-7f3", "jwt"],
      ["estate-opaque-bot-4e2", "opaque"],
    ] as const) {
      const credential = await estateToken(pilot, clientId, "u-1001", "invoices.read");
      const res = await read(credential, missionId);
      expect(res.ok, `${format}: ${JSON.stringify(res)}`).toBe(true);
      const missionJoin = requests.at(-1)?.context.mission_join as Record<string, unknown>;
      // The Mission's own client: depth 0 in the PEP's actor records.
      expect(missionJoin, format).toEqual({
        delegate_depth: 0,
        assertion: obtained.at(-1),
        token_sha256: accessTokenHash(credential.token),
        token_jkt: await calculateJwkThumbprint(await exportJWK(credential.dpopKeys.publicKey)),
      });
      const claims = decodeJwt(missionJoin.assertion as string);
      expect(claims, format).toMatchObject({
        iss: MAS_URL,
        aud: config.separated_mas.pdp_client_id,
        mission: { id: missionId, issuer: MAS_URL },
        token: { sha256: missionJoin.token_sha256, jkt: missionJoin.token_jkt },
        join: { client_id: "ap-agent", disposition: "client" },
        mapping_version: "mas-pilot-identity@1",
      });
      const evidence = decisions(missionId).at(-1)?.content as Record<string, unknown> | undefined;
      expect(evidence, format).toMatchObject({ decision: "permit" });
      expect(evidence?.join_view_id, format).toBeDefined();
    }
  });

  it("joins a delegate at the depth the MAS's actor records give, and denies when the PEP's actor records report another depth", async () => {
    substitute = undefined;
    const missionId = await approveAtMas("delegate", true);
    const mission = { id: missionId, issuer: MAS_URL };
    await mas.recordActor({ mission, clientId: DELEGATE, delegatedBy: "ap-agent" });
    pilot.actorRecords.record({ mission, clientId: DELEGATE, delegatedBy: "ap-agent" });
    const credential = await estateToken(pilot, "estate-extractor-2c1", "u-1001", "invoices.read");
    const agrees = await read(credential, missionId);
    expect(agrees.ok, JSON.stringify(agrees)).toBe(true);
    expect(requests.at(-1)?.context.mission_join).toMatchObject({ delegate_depth: 1 });
    expect(decodeJwt(obtained.at(-1) as string).join).toEqual({ client_id: DELEGATE, disposition: "delegate", depth: 1 });

    // The PEP's records now put the extractor under a relay: depth 2, where the assertion says 1.
    pilot.actorRecords.record({ mission, clientId: "relay-agent", delegatedBy: "ap-agent" });
    pilot.actorRecords.record({ mission, clientId: DELEGATE, delegatedBy: "relay-agent" });
    const disagrees = await read(credential, missionId);
    expect(requests.at(-1)?.context.mission_join).toMatchObject({ delegate_depth: 2 });
    expect(decodeJwt(obtained.at(-1) as string).join).toMatchObject({ depth: 1 });
    expectJoinRefused(disagrees, missionId, "delegate_depth 2 against join.depth 1");
  });

  it("denies mission_binding_failed, with nothing disclosed, an assertion for another PDP, for another token, bound to another key, expired, or with alg none", async () => {
    const missionId = await approveAtMas("refusals");
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read");
    // Another token bound to the same key: only its digest differs.
    const other = await tokenFor("estate-ap-bot-7f3", "u-1001", "invoices.read", CANONICAL_RESOURCE, credential.dpopKeys);
    const otherJkt = await calculateJwkThumbprint(await exportJWK((await generateKeyPair("ES256", { extractable: true })).publicKey));
    const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");
    const cases: Array<[string, NonNullable<typeof substitute>]> = [
      ["minted for another PDP", async ({ mission, accessToken }) =>
        (await mintAt({ mission_id: mission.id, audience: OTHER_PDP, access_token: accessToken })).body.assertion as string],
      ["minted for another token", (input, real) => real.obtain({ ...input, accessToken: other.token })],
      ["bound to another key", async ({ mission, accessToken }) =>
        reSigned(mission.id, accessToken, (c) => { (c.token as Record<string, unknown>).jkt = otherJkt; })],
      ["expired", async ({ mission, accessToken }) =>
        reSigned(mission.id, accessToken, (c) => { c.iat = Math.floor(Date.now() / 1000) - 120; c.exp = Math.floor(Date.now() / 1000) - 60; })],
      ["alg none", async ({ mission, accessToken }) => {
        const claims = decodeJwt(await reSigned(mission.id, accessToken, () => {}));
        return `${b64({ alg: "none", typ: "mission-join+jwt" })}.${b64(claims)}.`;
      }],
    ];
    for (const [label, swap] of cases) {
      substitute = swap;
      expectJoinRefused(await read(credential, missionId), missionId, label);
      expect((requests.at(-1)?.context.mission_join as Record<string, unknown>).assertion, label).toBe(obtained.at(-1));
    }
    // The same credential with the MAS's own assertion permits.
    substitute = undefined;
    expect((await read(credential, missionId)).ok).toBe(true);
  });

  it("denies a joined read that carries no assertion where the configuration requires one, though the mapping join alone would admit it", async () => {
    const missionId = await approveAtMas("required");
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read");
    substitute = async () => undefined;
    const res = await read(credential, missionId);
    expect(requests.at(-1)?.context.mission_join).toEqual({ delegate_depth: 0 });
    expectJoinRefused(res, missionId, "required, none carried");
    substitute = undefined;
  });

  it("the MAS mints nothing for a token it cannot establish or that does not join: a digest it cannot resolve, a token for another resource, an unmapped or other subject, a delegate it holds no record of or holds too deep", async () => {
    substitute = undefined;
    const missionId = await approveAtMas("mas-refusals", true);
    const mission = { id: missionId, issuer: MAS_URL };
    const pdpAudience = config.separated_mas.pdp_client_id;
    const refused = async (label: string, accessToken: string) => {
      const res = await mintAt({ mission_id: missionId, audience: pdpAudience, access_token: accessToken });
      expect(res, label).toMatchObject({ status: 403, body: { error: "join_failed" } });
    };
    const bot = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read");
    expect((await mintAt({ mission_id: missionId, audience: pdpAudience, access_token: bot.token })).status).toBe(200);
    const digest = await mintAt({
      mission_id: missionId,
      audience: pdpAudience,
      token_sha256: accessTokenHash(bot.token),
      token_jkt: await calculateJwkThumbprint(await exportJWK(bot.dpopKeys.publicKey)),
    });
    expect(digest, "digest form").toMatchObject({ status: 403, body: { error: "join_failed" } });
    await refused("a JWT for the ledger", (await tokenFor("estate-ap-bot-7f3", "u-1001", "invoices.read", LEDGER)).token);
    await refused("an opaque token for the ledger", (await tokenFor("estate-opaque-bot-4e2", "u-1001", "invoices.read", LEDGER)).token);
    await refused("a disabled subject row", (await estateToken(pilot, "estate-ap-bot-7f3", "u-1003", "invoices.read")).token);
    await refused("another person", (await estateToken(pilot, "estate-ap-bot-7f3", "alice", "invoices.read")).token);
    const extractor = (await estateToken(pilot, "estate-extractor-2c1", "u-1001", "invoices.read")).token;
    await refused("a delegate with no actor record", extractor);
    await mas.recordActor({ mission, clientId: "relay-agent", delegatedBy: "ap-agent" });
    await mas.recordActor({ mission, clientId: DELEGATE, delegatedBy: "relay-agent" });
    await refused("a delegate deeper than the contract's max_depth", extractor);
    await mas.recordActor({ mission, clientId: DELEGATE, delegatedBy: "ap-agent" });
    expect((await mintAt({ mission_id: missionId, audience: pdpAudience, access_token: extractor })).status).toBe(200);
  });
});

describe("the Join Assertion path is declared, and runs only where it can (#1454)", () => {
  it("parses a declared join_assertion and refuses a malformed one; absent, the configuration declares no path", () => {
    const shipped = JSON.parse(readFileSync(new URL("../../config/mas-pilot.json", import.meta.url), "utf8")) as Record<string, unknown>;
    expect(parseMasPilotConfig(shipped).join_assertion).toBeUndefined();
    const declared = { introspection_client_id: "mas-join-introspector", required: true, required_classes: ["consequential_read"] };
    expect(parseMasPilotConfig({ ...shipped, join_assertion: declared }).join_assertion).toEqual(declared);
    expect(() => parseMasPilotConfig({ ...shipped, join_assertion: { ...declared, required: "yes" } })).toThrow(/required must be a boolean/);
    expect(() => parseMasPilotConfig({ ...shipped, join_assertion: { ...declared, introspection_client_id: "mas-gateway-introspector" } })).toThrow(
      /client of its own/,
    );
    expect(() => parseMasPilotConfig({ ...shipped, join_assertion: { ...declared, extra: 1 } })).toThrow(/unknown member extra/);
  });

  it("the in-process composition refuses a configuration that declares the path, before it builds anything", async () => {
    await expect(
      composeMasPilot({ openfga: OPENFGA, resourcePolicyStore: { bootstrap: "development" }, config: joinConfig() }),
    ).rejects.toThrow(/separated topology only/);
  });
});

d("the separated MAS pilot refuses a declared Join Assertion path it cannot run (#1454)", () => {
  it("refuses to compose without the MAS's introspection client secret, and the MAS process refuses a secret its configuration does not declare", async () => {
    await expect(
      composeSeparatedMasPilot({ openfga: OPENFGA, resourcePolicyStore: { bootstrap: "development" }, config, mas: { url: MAS_URL, pdpKey } }),
    ).rejects.toThrow(/no secret for the MAS's introspection client/);
    const dir = mkdtempSync(join(tmpdir(), "mas-pilot-join-undeclared-"));
    dirs.push(dir);
    const { join_assertion: _declared, ...undeclared } = config;
    const configPath = join(dir, "mas-pilot.json");
    writeFileSync(configPath, JSON.stringify({ ...undeclared, separated_mas: { ...undeclared.separated_mas, port: MAS_PORT + 2 } }));
    const pdp = await newStatusClientKey(config.separated_mas.pdp_client_id);
    await expect(startMasProcess({ configPath, statusClients: [pdp.registration], joinIntrospectionSecret: "unused" })).rejects.toThrow(
      /MAS_PILOT_JOIN_INTROSPECTION_SECRET is set exactly where the configuration declares join_assertion/,
    );
  });
});

d("the separated launcher runs the declared Join Assertion path (#1454)", () => {
  it("generates the MAS's introspection client secret for the MAS process and the estate, and a joined read that requires an assertion permits, by JWT and by opaque credential", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mas-pilot-join-launcher-"));
    dirs.push(dir);
    const declared = joinConfig();
    const launched = relocateEstate({ ...declared, separated_mas: { ...declared.separated_mas, port: MAS_PORT + 2 } }, ESTATE_PORT + 2);
    const configPath = join(dir, "mas-pilot.json");
    writeFileSync(configPath, JSON.stringify(launched));
    const env = {
      OPENFGA_HTTP_URL: OPENFGA.apiUrl,
      OPENFGA_PRESHARED_KEY: OPENFGA.presharedKey,
      ...(OPENFGA.caCertPath ? { OPENFGA_CA_CERT: OPENFGA.caCertPath } : {}),
      MAS_PILOT_CONFIG: configPath,
      MAS_PILOT_DEVELOPMENT_STORE: "1",
      MISSION_EPHEMERAL_KEYS: "1",
    };
    // A launch that refuses to start fails here, on the assertion.
    const started = await launchMasPilot(masPilotLaunchOptions(env, "separated")).catch((e: unknown) => e);
    expect(started, String(started)).not.toBeInstanceOf(Error);
    const launch = started as Awaited<ReturnType<typeof launchMasPilot>>;
    try {
      expect(launch.summary).toContain("  Join Assertions    requested by the PEP from the MAS; required for consequential_read");
      const request = async (base: string, path: string, body: Record<string, unknown>) => {
        const res = await fetch(`${base}${path}`, {
          method: "POST",
          headers: { authorization: `Bearer ${launch.consoles.token}`, "content-type": "application/json" },
          body: JSON.stringify(body),
        });
        return (await res.json()) as Record<string, unknown>;
      };
      const missionId = (await request(launch.consoles.mas as string, "/missions", { subject: "alice", label: "join-launcher" })).mission_id;
      for (const client of ["estate-ap-bot-7f3", "estate-opaque-bot-4e2"]) {
        const credential = await request(launch.consoles.pilot, "/estate-tokens", { client_id: client, account: "u-1001", scope: "invoices.read" });
        const read = await request(launch.consoles.pilot, "/calls", {
          credential_id: credential.credential_id,
          mission_id: missionId,
          tool: "get_invoice",
          arguments: { invoice_id: "inv-1" },
        });
        expect(read.ok, `${client}: ${JSON.stringify(read)}`).toBe(true);
      }
    } finally {
      await launch.close();
    }
  });
});

describe("the launcher refuses a Join Assertion path it cannot run, before anything connects (#1454)", () => {
  it("refuses the path in process, a running MAS's path without its secret, and a secret where none applies", () => {
    const dir = mkdtempSync(join(tmpdir(), "mas-pilot-join-launcher-refusals-"));
    dirs.push(dir);
    const declaredPath = join(dir, "declared.json");
    writeFileSync(declaredPath, JSON.stringify(joinConfig()));
    const { join_assertion: _declared, ...undeclared } = joinConfig();
    const undeclaredPath = join(dir, "undeclared.json");
    writeFileSync(undeclaredPath, JSON.stringify(undeclared));
    const store = { MAS_PILOT_DEVELOPMENT_STORE: "1" };
    const running = { MAS_PILOT_MAS_URL: MAS_URL, MAS_PILOT_PDP_KEY: JSON.stringify({ kty: "EC", kid: "k", d: "x" }) };
    expect(() => masPilotLaunchOptions({ ...store, MAS_PILOT_CONFIG: declaredPath }, "in-process")).toThrow(/separated topology only/);
    expect(() => masPilotLaunchOptions({ ...store, ...running, MAS_PILOT_CONFIG: declaredPath }, "separated")).toThrow(
      /set MAS_PILOT_JOIN_INTROSPECTION_SECRET/,
    );
    expect(
      masPilotLaunchOptions({ ...store, ...running, MAS_PILOT_CONFIG: declaredPath, MAS_PILOT_JOIN_INTROSPECTION_SECRET: "s" }, "separated")
        .joinIntrospectionSecret,
    ).toBe("s");
    for (const [label, extra] of [
      ["undeclared", { ...running, MAS_PILOT_CONFIG: undeclaredPath }],
      ["a MAS the launcher starts", { MAS_PILOT_CONFIG: declaredPath }],
    ] as const) {
      expect(() => masPilotLaunchOptions({ ...store, ...extra, MAS_PILOT_JOIN_INTROSPECTION_SECRET: "s" }, "separated"), label).toThrow(
        /applies only to a running MAS whose configuration declares join_assertion/,
      );
    }
  });
});
