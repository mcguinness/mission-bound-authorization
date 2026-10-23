/**
 * @spec authority-server#join-assertion, authority-server#join-assertion-request,
 * authority-server#join-assertion-artifact, authority-server#submission-errors,
 * authority-server#discovery (#1454): the MAS's Mission Join Assertion
 * endpoint on the reference authorization server, acting as the MAS.
 *
 * The deployment hook (how the acting token is established at its AS and how
 * the join is evaluated) is a test double here: a table of acting tokens and
 * one mapping rule, so each outcome is driven exactly. The pilot supplies the
 * real estate verification.
 *
 * Covered: discovery; the assertion (`typ`, `alg`, `kid`, `mission`, `token`
 * with one confirmation member, `join`, `aud`, `mapping_version`, an `exp`
 * capped by the token); the outcomes (`invalid_join_request`,
 * `invalid_client`, `not_found` and its visibility set, `join_failed`,
 * `rate_limited`, `unavailable`); the cache key and the rechecks before a
 * cached assertion is served; the join evidence event.
 */

import type { Server } from "node:http";
import { createHash } from "node:crypto";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import {
  createLocalJWKSet,
  decodeJwt,
  decodeProtectedHeader,
  importJWK,
  type JWK,
  jwtVerify,
  SignJWT,
} from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  type ActingToken,
  type BuiltAs,
  buildAuthorizationServer,
  JOIN_ASSERTION_ENDPOINT_PATH,
  type JoinAssertionDeployment,
  JoinAssertionService,
  type MissionKernel,
  type MissionRecord,
  validateMissionIntent,
} from "../src/index.js";
import { CLIENT_ASSERTION_TYPE, type LifecycleTestClient, lifecycleClientAssertion, newLifecycleClient } from "./lifecycle-endpoint.helper.js";

const PORT = 14893;
const ISSUER = `http://localhost:${PORT}`;
const ENDPOINT = `${ISSUER}${JOIN_ASSERTION_ENDPOINT_PATH}`;
const BARE_PORT = 14894;
const BARE_ISSUER = `http://localhost:${BARE_PORT}`;
const ESTATE = "https://estate.example";
const MAPPING_V1 = "mas-pilot-identity@1";
const UNKNOWN = "msn_unknown_0000000000000000000000";

/** The acting tokens the double's AS knows: by token string, each with its own state. */
const tokens = new Map<string, ActingToken | "inactive" | "unavailable">();
let mappingVersion = MAPPING_V1;

const ath = (token: string) => createHash("sha256").update(token, "ascii").digest("base64url");

const deployment = (rate?: { max: number; windowSeconds: number }): JoinAssertionDeployment => ({
  async establishActingToken(form) {
    const known =
      "accessToken" in form ? tokens.get(form.accessToken) : [...tokens.entries()].find(([t]) => ath(t) === form.tokenSha256)?.[1];
    if (known === undefined || known === "inactive") return { ok: false, reason: "inactive" };
    if (known === "unavailable") return { ok: false, reason: "unavailable" };
    return { ok: true, token: known };
  },
  // One documented mapping: estate account u-1001 is alice; estate-bot is the
  // Mission's own client, estate-helper a delegate at depth 1.
  evaluateJoin(token, mission) {
    if (token.issuer !== ESTATE || token.subject !== "u-1001" || mission.subject.sub !== "alice") return undefined;
    if (token.clientId === "estate-bot" && mission.client_id === "ap-agent") {
      return { clientId: "ap-agent", disposition: "client", mappingVersion };
    }
    if (token.clientId === "estate-helper") return { clientId: "helper-agent", disposition: "delegate", depth: 1, mappingVersion };
    return undefined;
  },
  ...(rate ? { rateLimit: rate } : {}),
});

let as: BuiltAs;
let server: Server;
let bare: BuiltAs;
let bareServer: Server;
/** Enrolled for the payments scope: the consuming PDP. */
let pdp: LifecycleTestClient;
/** Enrolled for the payments scope: the PEP that requests on the PDP's behalf. */
let pep: LifecycleTestClient;
/** Registered, enrolled for another scope only. */
let stranger: LifecycleTestClient;
let approvals = 0;

function approve(kernel: MissionKernel = as.kernel): MissionRecord {
  approvals += 1;
  return kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Read Acme invoices", target_resources: [CANONICAL_RESOURCE], expires_at: "2027-01-01T00:00:00Z" }),
    ),
    proposedAuthority: [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] }],
    subject: { iss: ISSUER, sub: "alice" },
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-join-assertion-${approvals}`,
  });
}

/** An acting token the double's AS knows, bound to a key by `jkt` unless told otherwise. */
function actingToken(over: Partial<ActingToken> & { cnf?: ActingToken["cnf"] | null } = {}): string {
  const token = `estate-token-${crypto.randomUUID()}`;
  const { cnf, ...rest } = over;
  tokens.set(token, {
    issuer: ESTATE,
    subject: "u-1001",
    clientId: "estate-bot",
    exp: Math.floor(Date.now() / 1000) + 3600,
    ...(cnf === null ? {} : { cnf: cnf ?? { jkt: `jkt-${token.slice(-8)}` } }),
    ...rest,
  });
  return token;
}

type Answer = { status: number; json: Record<string, unknown>; retryAfter: string | null; wwwAuthenticate: string | null };

async function post(body: unknown, opts: { contentType?: string; raw?: string; url?: string } = {}): Promise<Answer> {
  const res = await fetch(opts.url ?? ENDPOINT, {
    method: "POST",
    headers: { "content-type": opts.contentType ?? "application/json" },
    body: opts.raw ?? JSON.stringify(body),
  });
  return {
    status: res.status,
    json: (await res.json()) as Record<string, unknown>,
    retryAfter: res.headers.get("retry-after"),
    wwwAuthenticate: res.headers.get("www-authenticate"),
  };
}

/** A request from `client`, authenticated by a client assertion whose `aud` is the MAS issuer identifier as its sole value. */
async function request(client: LifecycleTestClient, members: Record<string, unknown>, url = ENDPOINT): Promise<Answer> {
  return post(
    { ...members, client_assertion_type: CLIENT_ASSERTION_TYPE, client_assertion: await lifecycleClientAssertion(ISSUER, client) },
    { url },
  );
}

async function verified(jws: string): Promise<Record<string, unknown>> {
  const jwks = (await (await fetch(`${ISSUER}/jwks`)).json()) as { keys: JWK[] };
  const { payload } = await jwtVerify(jws, createLocalJWKSet(jwks), { typ: "mission-join+jwt", issuer: ISSUER, audience: pdp.clientId });
  return payload as Record<string, unknown>;
}

const events = () => as.joinAssertions?.events().length ?? 0;

beforeAll(async () => {
  pdp = await newLifecycleClient("join-assertion-pdp");
  pep = await newLifecycleClient("join-assertion-pep");
  stranger = await newLifecycleClient("join-assertion-stranger");
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    testClients: [pdp.metadata, pep.metadata, stranger.metadata],
    enrolledJoinPdps: {
      [pdp.clientId]: [CANONICAL_RESOURCE],
      [pep.clientId]: [CANONICAL_RESOURCE],
      [stranger.clientId]: ["https://other.example/api"],
    },
    joinAssertions: deployment(),
  });
  server = as.provider.listen(PORT);
  bare = await buildAuthorizationServer({
    issuer: BARE_ISSUER,
    testClients: [pdp.metadata],
    enrolledJoinPdps: { [pdp.clientId]: [CANONICAL_RESOURCE] },
  });
  bareServer = bare.provider.listen(BARE_PORT);
});

afterAll(() => {
  server?.close();
  bareServer?.close();
});

describe("Join Assertion endpoint discovery (@spec authority-server#discovery, #1454)", () => {
  it("advertises mission_join_assertion_endpoint where the MAS mints assertions, and not where it does not", async () => {
    const meta = (await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
    expect(meta.mission_join_assertion_endpoint).toBe(ENDPOINT);
    expect(meta.mission_status_signing_alg_values_supported).toEqual(["ES256"]);
    const without = (await (await fetch(`${BARE_ISSUER}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
    expect(without.mission_join_assertion_endpoint).toBeUndefined();
  });
});

describe("Join Assertion artifact (@spec authority-server#join-assertion-artifact, #1454)", () => {
  it("mints a sender-bound assertion for an enrolled PDP: typ, a listed alg, iss, mission, token with its one confirmation, join, aud, mapping_version", async () => {
    const record = approve();
    const token = actingToken();
    const before = events();
    const answer = await request(pep, { mission_id: record.id, audience: pdp.clientId, access_token: token });
    expect(answer.status, JSON.stringify(answer.json)).toBe(200);
    const jws = answer.json.assertion as string;
    const header = decodeProtectedHeader(jws);
    expect(header).toMatchObject({ typ: "mission-join+jwt", alg: "ES256" });
    expect(typeof header.kid).toBe("string");
    // Signed with an algorithm the MAS lists in mission_status_signing_alg_values_supported.
    const meta = (await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json()) as {
      mission_status_signing_alg_values_supported: string[];
    };
    expect(meta.mission_status_signing_alg_values_supported).toContain(header.alg);
    const claims = await verified(jws);
    expect(claims).toMatchObject({
      iss: ISSUER,
      aud: pdp.clientId,
      mission: { id: record.id, issuer: ISSUER, authority_hash: record.authority_hash },
      token: { sha256: ath(token), jkt: `jkt-${token.slice(-8)}` },
      join: { client_id: "ap-agent", disposition: "client" },
      mapping_version: MAPPING_V1,
    });
    expect(Object.keys(claims.token as object).sort()).toEqual(["jkt", "sha256"]);
    expect(Object.keys(claims.mission as object).sort()).toEqual(["authority_hash", "id", "issuer"]);
    expect("depth" in (claims.join as object)).toBe(false);
    expect(typeof claims.iat).toBe("number");
    expect((claims.exp as number) - (claims.iat as number)).toBeLessThanOrEqual(300);
    // Each minting is a join evidence event.
    expect(events()).toBe(before + 1);
    expect(as.joinAssertions?.events().at(-1)).toMatchObject({
      mission: { issuer: ISSUER, id: record.id },
      token: { sha256: ath(token) },
      join: { client_id: "ap-agent", disposition: "client" },
      caller: pep.clientId,
      audience: pdp.clientId,
      mapping_version: MAPPING_V1,
    });
  });

  it("caps exp at the acting token's own expiry", async () => {
    const record = approve();
    const soon = Math.floor(Date.now() / 1000) + 30;
    const token = actingToken({ exp: soon });
    const answer = await request(pep, { mission_id: record.id, audience: pdp.clientId, access_token: token });
    expect((await verified(answer.json.assertion as string)).exp).toBe(soon);
  });

  it("binds a certificate-bound token by x5t#S256 alone, from the access token or the digest pair", async () => {
    const record = approve();
    const token = actingToken({ cnf: { "x5t#S256": "x5t-thumbprint" } });
    for (const members of [
      { access_token: token },
      { token_sha256: ath(token), token_x5t: "x5t-thumbprint" },
    ]) {
      const answer = await request(pep, { mission_id: record.id, audience: pdp.clientId, ...members });
      expect(answer.status, JSON.stringify(answer.json)).toBe(200);
      const claims = await verified(answer.json.assertion as string);
      expect(claims.token).toEqual({ sha256: ath(token), "x5t#S256": "x5t-thumbprint" });
    }
  });

  it("carries disposition delegate and the delegate's depth for a delegate's join", async () => {
    const record = approve();
    const token = actingToken({ clientId: "estate-helper" });
    const answer = await request(pep, { mission_id: record.id, audience: pdp.clientId, access_token: token });
    expect((await verified(answer.json.assertion as string)).join).toEqual({ client_id: "helper-agent", disposition: "delegate", depth: 1 });
  });
});

describe("Join Assertion minting, the service alone (@spec authority-server#join-assertion-artifact, #1454)", () => {
  it("mints, with no HTTP route in the way, a join claim for the client and for a delegate, exactly one confirmation member, and aud the request's audience", async () => {
    const service = as.joinAssertions;
    if (!service) throw new Error("no join-assertion service");
    const record = approve();
    const mint = async (token: string, audience: string) => {
      const answer = await service.handle(
        JSON.stringify({
          mission_id: record.id,
          audience,
          access_token: token,
          client_assertion_type: CLIENT_ASSERTION_TYPE,
          client_assertion: await lifecycleClientAssertion(ISSUER, pep),
        }),
        "application/json",
        "",
      );
      expect(answer.status, JSON.stringify(answer.body)).toBe(200);
      return decodeJwt(answer.body.assertion as string);
    };
    const direct = await mint(actingToken(), pdp.clientId);
    expect(direct.join).toEqual({ client_id: "ap-agent", disposition: "client" });
    expect(Object.keys(direct.token as object).sort()).toEqual(["jkt", "sha256"]);
    expect(direct.aud).toBe(pdp.clientId);
    const delegate = await mint(actingToken({ clientId: "estate-helper", cnf: { "x5t#S256": "x5t-delegate" } }), pep.clientId);
    expect(delegate.join).toEqual({ client_id: "helper-agent", disposition: "delegate", depth: 1 });
    expect(Object.keys(delegate.token as object).sort()).toEqual(["sha256", "x5t#S256"]);
    expect(delegate.aud).toBe(pep.clientId);
  });
});

describe("Join Assertion endpoint outcomes (@spec authority-server#join-assertion-request, authority-server#submission-errors, #1454)", () => {
  it("refuses a body that is not a JSON object carrying mission_id, a string audience and exactly one token form invalid_join_request (HTTP 400)", async () => {
    const record = approve();
    const token = actingToken();
    const auth = async () => ({ client_assertion_type: CLIENT_ASSERTION_TYPE, client_assertion: await lifecycleClientAssertion(ISSUER, pep) });
    const cases: Array<[string, Answer]> = [
      ["not JSON", await post(undefined, { raw: "mission_id=x" })],
      ["a form body", await post(undefined, { raw: "mission_id=x", contentType: "application/x-www-form-urlencoded" })],
      ["no mission_id", await post({ audience: pdp.clientId, access_token: token, ...(await auth()) })],
      ["a non-string audience", await post({ mission_id: record.id, audience: 7, access_token: token, ...(await auth()) })],
      ["no token form", await post({ mission_id: record.id, audience: pdp.clientId, ...(await auth()) })],
      ["both token forms", await post({ mission_id: record.id, audience: pdp.clientId, access_token: token, token_sha256: ath(token), token_jkt: "j", ...(await auth()) })],
      ["the digest with no thumbprint", await post({ mission_id: record.id, audience: pdp.clientId, token_sha256: ath(token), ...(await auth()) })],
      ["the digest with two thumbprints", await post({ mission_id: record.id, audience: pdp.clientId, token_sha256: ath(token), token_jkt: "j", token_x5t: "x", ...(await auth()) })],
    ];
    for (const [label, answer] of cases) {
      expect(answer.status, label).toBe(400);
      expect(answer.json.error, label).toBe("invalid_join_request");
      expect("nonce" in answer.json, label).toBe(false);
    }
  });

  it("refuses a failed or absent client authentication invalid_client (HTTP 400), minting nothing: the assertion's aud must be the MAS issuer identifier as its sole value", async () => {
    const record = approve();
    const members = { mission_id: record.id, audience: pdp.clientId, access_token: actingToken() };
    const withAud = async (aud: string | string[]) =>
      post({ ...members, client_assertion_type: CLIENT_ASSERTION_TYPE, client_assertion: await lifecycleClientAssertion(ISSUER, pep, { aud }) });
    const before = events();
    const cases: Array<[string, Answer]> = [
      ["no credential", await post(members)],
      ["aud the join-assertion endpoint", await withAud(ENDPOINT)],
      ["aud the issuer beside another audience", await withAud([ISSUER, ENDPOINT])],
      ["aud another issuer", await withAud("https://other.example.com")],
      ["an unregistered client", await request(await newLifecycleClient("join-assertion-unknown"), members)],
    ];
    for (const [label, answer] of cases) {
      expect(answer.status, label).toBe(400);
      expect(answer.json.error, label).toBe("invalid_client");
      // Not a token challenge.
      expect(answer.wwwAuthenticate, label).toBeNull();
    }
    expect(events()).toBe(before);
  });

  it("accepts a client assertion whose aud is the MAS issuer identifier as its sole value, as a string or a one-element array, as at Mission Status", async () => {
    const record = approve();
    const members = { mission_id: record.id, audience: pdp.clientId, access_token: actingToken() };
    for (const [label, aud] of [["a string", ISSUER], ["a one-element array", [ISSUER]]] as Array<[string, string | string[]]>) {
      const answer = await post({ ...members, client_assertion_type: CLIENT_ASSERTION_TYPE, client_assertion: await lifecycleClientAssertion(ISSUER, pep, { aud }) });
      expect(answer.status, label).toBe(200);
      expect(typeof answer.json.assertion, label).toBe("string");
    }
  });

  it("answers an unknown Mission and a caller outside the visibility set with one not_found; the Mission's own client is inside it", async () => {
    const record = approve();
    const token = actingToken();
    const unknown = await request(pep, { mission_id: UNKNOWN, audience: pdp.clientId, access_token: token });
    const invisible = await request(stranger, { mission_id: record.id, audience: pdp.clientId, access_token: token });
    for (const answer of [unknown, invisible]) {
      expect(answer.status).toBe(404);
      expect(answer.json.error).toBe("not_found");
    }
    expect(invisible.json).toEqual(unknown.json);
    // The Mission's own client (`ap-agent`) sees it.
    const agentKey = await importJWK(as.agentClientJwk as JWK, "ES256");
    const iat = Math.floor(Date.now() / 1000);
    const own = await post({
      mission_id: record.id,
      audience: pdp.clientId,
      access_token: token,
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: await new SignJWT({ jti: crypto.randomUUID() })
        .setProtectedHeader({ alg: "ES256", kid: (as.agentClientJwk as { kid?: string }).kid as string })
        .setIssuer("ap-agent")
        .setSubject("ap-agent")
        .setAudience(ISSUER)
        .setIssuedAt(iat)
        .setExpirationTime(iat + 60)
        .sign(agentKey),
    });
    expect(own.status, JSON.stringify(own.json)).toBe(200);
  });

  it("refuses join_failed (HTTP 403), minting nothing: a revoked Mission, an audience not enrolled, an inactive or expired token, one with no cnf, a mismatched thumbprint, a token that does not join", async () => {
    const record = approve();
    const revoked = approve();
    as.kernel.transition(revoked.id, "revoke");
    const inactive = `estate-token-${crypto.randomUUID()}`;
    tokens.set(inactive, "inactive");
    const cases: Array<[string, Record<string, unknown>]> = [
      ["a revoked Mission", { mission_id: revoked.id, audience: pdp.clientId, access_token: actingToken() }],
      ["an audience not enrolled for the Mission's scope", { mission_id: record.id, audience: stranger.clientId, access_token: actingToken() }],
      ["an audience nobody enrolled", { mission_id: record.id, audience: "https://pdp.elsewhere.example", access_token: actingToken() }],
      ["an inactive token", { mission_id: record.id, audience: pdp.clientId, access_token: inactive }],
      ["an expired token", { mission_id: record.id, audience: pdp.clientId, access_token: actingToken({ exp: Math.floor(Date.now() / 1000) - 1 }) }],
      ["a token with no cnf", { mission_id: record.id, audience: pdp.clientId, access_token: actingToken({ cnf: null }) }],
      ["a token that does not join", { mission_id: record.id, audience: pdp.clientId, access_token: actingToken({ subject: "u-9999" }) }],
    ];
    const mismatched = actingToken();
    cases.push(["a thumbprint that is not the token's", { mission_id: record.id, audience: pdp.clientId, token_sha256: ath(mismatched), token_jkt: "jkt-other" }]);
    const before = events();
    for (const [label, members] of cases) {
      const answer = await request(pep, members);
      expect(answer.status, label).toBe(403);
      expect(answer.json.error, label).toBe("join_failed");
      expect("assertion" in answer.json, label).toBe(false);
    }
    expect(events()).toBe(before);
  });

  it("answers unavailable (HTTP 503) when the acting token's authorization server cannot be asked", async () => {
    const record = approve();
    const token = `estate-token-${crypto.randomUUID()}`;
    tokens.set(token, "unavailable");
    const answer = await request(pep, { mission_id: record.id, audience: pdp.clientId, access_token: token });
    expect(answer.status).toBe(503);
    expect(answer.json.error).toBe("unavailable");
  });

  it("rate-limits requests per caller: rate_limited (HTTP 429) with Retry-After past the bound", async () => {
    const limited = await buildAuthorizationServer({
      issuer: `http://localhost:14895`,
      testClients: [pep.metadata],
      enrolledJoinPdps: { [pep.clientId]: [CANONICAL_RESOURCE] },
      joinAssertions: deployment({ max: 2, windowSeconds: 60 }),
    });
    const listening = limited.provider.listen(14895);
    try {
      const url = `http://localhost:14895${JOIN_ASSERTION_ENDPOINT_PATH}`;
      const members = { mission_id: UNKNOWN, audience: pdp.clientId, access_token: actingToken() };
      const answers: Answer[] = [];
      for (let i = 0; i < 3; i += 1) {
        answers.push(
          await post(
            { ...members, client_assertion_type: CLIENT_ASSERTION_TYPE, client_assertion: await lifecycleClientAssertion("http://localhost:14895", pep) },
            { url },
          ),
        );
      }
      expect(answers.map((a) => a.status)).toEqual([404, 404, 429]);
      expect(answers[2]?.json.error).toBe("rate_limited");
      expect(Number(answers[2]?.retryAfter)).toBeGreaterThan(0);
    } finally {
      listening.close();
    }
  });
});

describe("Join Assertion cache (@spec authority-server#join-assertion-request, #1454)", () => {
  it("serves a repeated request its cached assertion, keyed on the Mission, the token digest and the audience: a change in any one mints anew", async () => {
    const record = approve();
    const other = approve();
    const token = actingToken();
    const members = { mission_id: record.id, audience: pdp.clientId, access_token: token };
    const first = (await request(pep, members)).json.assertion as string;
    const before = events();
    expect((await request(pep, members)).json.assertion).toBe(first);
    expect(events()).toBe(before);
    const variants: Array<[string, Record<string, unknown>]> = [
      ["another Mission", { ...members, mission_id: other.id }],
      ["another token", { ...members, access_token: actingToken() }],
      ["another audience", { ...members, audience: pep.clientId }],
    ];
    for (const [label, changed] of variants) {
      const minted = (await request(pep, changed)).json.assertion as string;
      expect(minted, label).toBeDefined();
      expect(minted, label).not.toBe(first);
    }
    expect(events()).toBe(before + variants.length);
  });

  it("rechecks before serving a cached assertion: a caller outside the visibility set, a revoked Mission and an inactive token are refused, and a changed mapping mints anew", async () => {
    const record = approve();
    const token = actingToken();
    const members = { mission_id: record.id, audience: pdp.clientId, access_token: token };
    const first = (await request(pep, members)).json.assertion as string;
    expect((await request(stranger, members)).status).toBe(404);

    mappingVersion = "mas-pilot-identity@2";
    try {
      const remapped = (await request(pep, members)).json.assertion as string;
      expect(remapped).not.toBe(first);
      expect((await verified(remapped)).mapping_version).toBe("mas-pilot-identity@2");
    } finally {
      mappingVersion = MAPPING_V1;
    }

    tokens.set(token, "inactive");
    expect((await request(pep, members)).json.error).toBe("join_failed");
    tokens.set(token, { issuer: ESTATE, subject: "u-1001", clientId: "estate-bot", exp: Math.floor(Date.now() / 1000) + 3600, cnf: { jkt: "k" } });
    as.kernel.transition(record.id, "revoke");
    expect((await request(pep, members)).json.error).toBe("join_failed");
  });
});


/**
 * #1454 review: the service run directly, so a test can hold it at an await
 * and change the Mission there. `hooks.establish` holds the token check and
 * `hooks.sign` the signing, each on a gate the test releases; `hooks.join`
 * runs inside the join evaluation (after the token check, before signing);
 * `hooks.hash` stands in for a Mission whose `authority_hash` changed.
 */
interface Hooks {
  establish?: () => Promise<void>;
  join?: () => void;
  sign?: () => Promise<void>;
  hash?: () => string | undefined;
}

function heldService(kernel: MissionKernel, hooks: Hooks, enrolled: (clientId: string) => readonly string[] = () => [CANONICAL_RESOURCE]) {
  const inner = deployment();
  const held = {
    currentRecord: (id: string) => {
      const record = kernel.currentRecord(id);
      const hash = hooks.hash?.();
      return record && hash !== undefined ? { ...record, authority_hash: hash } : record;
    },
    get: (id: string) => kernel.get(id),
    nowDate: () => kernel.nowDate(),
    signJoinAssertion: async (...args: Parameters<MissionKernel["signJoinAssertion"]>) => {
      await hooks.sign?.();
      return kernel.signJoinAssertion(...args);
    },
  } as unknown as MissionKernel;
  return new JoinAssertionService({
    issuer: ISSUER,
    kernel: held,
    enrolledScopes: enrolled,
    authenticate: async () => ({ ok: true, clientId: pep.clientId }),
    deployment: {
      ...inner,
      establishActingToken: async (form) => {
        await hooks.establish?.();
        return inner.establishActingToken(form);
      },
      evaluateJoin: (token, mission) => {
        hooks.join?.();
        return inner.evaluateJoin(token, mission);
      },
    },
  });
}

/** A point the service blocks at: the test awaits `reached`, acts, then releases it. */
interface Gate {
  reached: Promise<void>;
  release: () => void;
  wait: () => Promise<void>;
}

function gate(): Gate {
  let arrive = () => {};
  let release = () => {};
  const reached = new Promise<void>((resolve) => {
    arrive = resolve;
  });
  const opened = new Promise<void>((resolve) => {
    release = resolve;
  });
  return {
    reached,
    release: () => release(),
    wait: async () => {
      arrive();
      await opened;
    },
  };
}

const mintBody = (missionId: string, accessToken: string) =>
  JSON.stringify({ mission_id: missionId, audience: pdp.clientId, access_token: accessToken });

/** One request; where `held` is given, the Mission changes while the service waits at its gate. */
async function mintWith(service: JoinAssertionService, missionId: string, accessToken: string, held?: { gate: Gate; change: () => void }) {
  const pending = service.handle(mintBody(missionId, accessToken), "application/json", "");
  if (held) {
    await held.gate.reached;
    held.change();
    held.gate.release();
  }
  return pending;
}

async function expectRefused(service: JoinAssertionService, missionId: string, accessToken: string, label: string, held?: { gate: Gate; change: () => void }) {
  const answer = await mintWith(service, missionId, accessToken, held);
  expect(answer.status, `${label}: ${JSON.stringify(answer.body)}`).toBe(403);
  expect(answer.body.error, label).toBe("join_failed");
  expect("assertion" in answer.body, label).toBe(false);
  expect(service.events(), label).toHaveLength(0);
}

/** The Mission changes three ways: revoked, suspended, and expired on a kernel whose clock the test moves. */
let clockOffsetMs = 0;
let clocked: BuiltAs;
const FAR_TOKEN_EXP = Math.floor(Date.parse("2030-01-01T00:00:00Z") / 1000);
const changes: Array<[string, () => { kernel: MissionKernel; record: MissionRecord; change: () => void }]> = [
  [
    "revoked",
    () => {
      const record = approve();
      return { kernel: as.kernel, record, change: () => as.kernel.transition(record.id, "revoke") };
    },
  ],
  [
    "suspended",
    () => {
      const record = approve();
      return { kernel: as.kernel, record, change: () => as.kernel.transition(record.id, "suspend") };
    },
  ],
  [
    "expired",
    () => {
      clockOffsetMs = 0;
      const record = approve(clocked.kernel);
      return {
        kernel: clocked.kernel,
        record,
        change: () => {
          clockOffsetMs = Date.parse("2027-06-01T00:00:00Z") - Date.now();
        },
      };
    },
  ],
];

describe("Join Assertion minting re-reads the Mission after every await (@spec authority-server#join-assertion-request, #1454 review)", () => {
  beforeAll(async () => {
    // Its own kernel under the same issuer (it serves nothing), so its clock can move alone.
    clocked = await buildAuthorizationServer({ issuer: ISSUER, now: () => new Date(Date.now() + clockOffsetMs) });
  });

  it("refuses join_failed, returning and recording nothing, a Mission revoked, suspended or expired while its acting token is being established", async () => {
    for (const [label, setup] of changes) {
      const { kernel, record, change } = setup();
      const g = gate();
      await expectRefused(heldService(kernel, { establish: g.wait }), record.id, actingToken({ exp: FAR_TOKEN_EXP }), label, { gate: g, change });
    }
  });

  it("refuses join_failed a Mission revoked, suspended or expired after the token check and before signing", async () => {
    for (const [label, setup] of changes) {
      const { kernel, record, change } = setup();
      await expectRefused(heldService(kernel, { join: change }), record.id, actingToken({ exp: FAR_TOKEN_EXP }), label);
    }
  });

  it("refuses join_failed a Mission revoked, suspended or expired while the assertion is signed, and caches nothing it refused", async () => {
    for (const [label, setup] of changes) {
      const { kernel, record, change } = setup();
      const g = gate();
      await expectRefused(heldService(kernel, { sign: g.wait }), record.id, actingToken({ exp: FAR_TOKEN_EXP }), label, { gate: g, change });
    }
    // A refused assertion is not cached: resumed, the same request mints anew.
    const record = approve();
    const token = actingToken();
    const hooks: Hooks = {};
    const service = heldService(as.kernel, hooks);
    const g = gate();
    hooks.sign = g.wait;
    await expectRefused(service, record.id, token, "suspended while signing", { gate: g, change: () => as.kernel.transition(record.id, "suspend") });
    delete hooks.sign;
    as.kernel.transition(record.id, "resume");
    const again = await mintWith(service, record.id, token);
    expect(again.status, JSON.stringify(again.body)).toBe(200);
    expect(service.events()).toHaveLength(1);
  });

  it("does not serve a cached assertion for a Mission revoked while the next request's token is being established", async () => {
    const record = approve();
    const token = actingToken();
    const hooks: Hooks = {};
    const service = heldService(as.kernel, hooks);
    const first = await mintWith(service, record.id, token);
    expect(first.status, JSON.stringify(first.body)).toBe(200);
    const g = gate();
    hooks.establish = g.wait;
    const second = await mintWith(service, record.id, token, { gate: g, change: () => as.kernel.transition(record.id, "revoke") });
    expect(second.status, JSON.stringify(second.body)).toBe(403);
    expect(second.body.error).toBe("join_failed");
    expect("assertion" in second.body).toBe(false);
    expect(service.events()).toHaveLength(1);
  });

  it("refuses join_failed when the Mission's authority_hash changes, or its audience is withdrawn, during the token check or the signing", async () => {
    for (const point of ["establish", "sign"] as const) {
      const hashed = approve();
      let hash: string | undefined;
      const hashGate = gate();
      await expectRefused(heldService(as.kernel, { [point]: hashGate.wait, hash: () => hash }), hashed.id, actingToken(), `authority_hash changed at ${point}`, {
        gate: hashGate,
        change: () => {
          hash = "sha-256:changed";
        },
      });

      const withdrawnFrom = approve();
      let withdrawn = false;
      const enrolled = (clientId: string) => (withdrawn && clientId === pdp.clientId ? [] : [CANONICAL_RESOURCE]);
      const withdrawGate = gate();
      await expectRefused(heldService(as.kernel, { [point]: withdrawGate.wait }, enrolled), withdrawnFrom.id, actingToken(), `audience withdrawn at ${point}`, {
        gate: withdrawGate,
        change: () => {
          withdrawn = true;
        },
      });
    }
  });
});
