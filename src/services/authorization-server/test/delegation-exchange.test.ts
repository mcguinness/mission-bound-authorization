/**
 * @spec mission#delegation, mission#designation, mission#delegation-constraints
 * (#869, #1268, D449): same-Mission delegation by designation, at the token
 * endpoint. The approved agent (ap-agent) designates a sub-agent
 * (subagent-invoice-extractor) by Token Exchange, proving its own token's key;
 * the sub-agent redeems the designation as its own client, proving its own key.
 */
import { floorApprovalHeaders, TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";
import { ApprovalSessionStore } from "../src/index.js";

import { type Server } from "node:http";
import { CANONICAL_RESOURCE, SCOPE_PROJECTION, TOPOLOGY } from "@mission/demo-data";
import {
  calculateJwkThumbprint,
  createLocalJWKSet,
  decodeJwt,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify,
  SignJWT,
} from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { audienceCollision, resourceAudiences } from "../src/adapters/audience-separation.js";
import { ACCESS_TOKEN_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import { ALL_PROVIDER_CAPABILITIES, buildAuthorizationServer, type BuiltAs } from "../src/index.js";
import { TokenIssuanceStore } from "../src/kernel/token-issuance-store.js";

const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
const SUBAGENT = "subagent-invoice-extractor";
const SECOND = "test-second-delegate";
/** An audience the AS issues (a topology resource) that no registered resource server lists. */
const ISSUED_AUDIENCE = TOPOLOGY.resources.hrFiles;
const ALIAS_CLIENT = "test-alias-client";
const UNDECLARED = "test-undeclared-delegate";
const INELIGIBLE = "test-ineligible-delegate";
const RS_PAYMENTS = ["rs-payments", "dev-introspection-rs-payments"] as const;
const RS_ALIAS = ["rs-alias", "dev-introspection-rs-alias"] as const;
const RS_LATE = ["rs-late", "dev-introspection-rs-late"] as const;
/** A resource server accepting an alias the AS never issues as an audience. */
const rsAlias = { principal_id: RS_ALIAS[0], secret: RS_ALIAS[1], audiences: [RESOURCE, ALIAS_CLIENT], disclose: [] as string[] };
/** A resource server that starts accepting a designated client's identifier only after the designation is issued. */
const rsLate = { principal_id: RS_LATE[0], secret: RS_LATE[1], audiences: [RESOURCE], disclose: [] as string[] };
const delegable = (maxDepth = 2) => ({
  type: "mission_resource_access",
  resource: RESOURCE,
  actions: ["payments:invoice.read"],
  constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  delegation: { max_depth: maxDepth, allowed_delegates: [{ sub_profile: "ai_agent" }] },
});

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
type Body = Record<string, unknown>;
type Client = "ap-agent" | typeof SUBAGENT | typeof SECOND | typeof UNDECLARED | "ledger-reconciler";

const sessions = new ApprovalSessionStore();
let secondKeys: Keys;
const dpop = new Map<Client, Keys>();

/** One authorization server under test, with its client keys and request helpers. */
interface Harness {
  as: BuiltAs;
  server: Server;
  issuer: string;
  keys: Map<Client, CryptoKey>;
}

async function harness(port: number, options: Record<string, unknown>): Promise<Harness> {
  const issuer = `http://localhost:${port}`;
  const testClient = async (clientId: string) => ({
    client_id: clientId,
    grant_types: [TOKEN_EXCHANGE_GRANT_TYPE],
    response_types: [],
    redirect_uris: [],
    token_endpoint_auth_method: "private_key_jwt",
    token_endpoint_auth_signing_alg: "ES256",
    jwks: { keys: [{ ...(await exportJWK(secondKeys.publicKey)), kid: `${clientId}-auth`, alg: "ES256" }] },
    authorization_details_types: ["mission_resource_access"],
  });
  const as = await buildAuthorizationServer({
    issuer,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: sessions,
    // A second ai_agent delegate; a client whose identifier is an audience
    // the AS issues; one a registered resource server accepts as an alias;
    // and an eligible client the deployment does not list as designable.
    testClients: await Promise.all([SECOND, ISSUED_AUDIENCE, ALIAS_CLIENT, UNDECLARED, INELIGIBLE].map(testClient)),
    actorProfiles: { [SECOND]: "ai_agent", [ISSUED_AUDIENCE]: "ai_agent", [ALIAS_CLIENT]: "ai_agent", [UNDECLARED]: "ai_agent" },
    designableClients: [SUBAGENT, SECOND, ISSUED_AUDIENCE, ALIAS_CLIENT, INELIGIBLE],
    ...options,
  } as never);
  const server = as.provider.listen(port);
  const keys = new Map<Client, CryptoKey>([
    ["ap-agent", (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey],
    [SUBAGENT, (await importJWK(as.childClientJwk as never, "ES256")) as CryptoKey],
    ["ledger-reconciler", (await importJWK(as.ledgerReconcilerClientJwk as never, "ES256")) as CryptoKey],
    [SECOND, secondKeys.privateKey],
    [UNDECLARED, secondKeys.privateKey],
  ]);
  return { as, server, issuer, keys };
}

const assertion = (h: Harness, client: Client) =>
  new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: `${client}-auth` })
    .setIssuer(client)
    .setSubject(client)
    .setAudience(h.issuer)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(h.keys.get(client) as CryptoKey);

async function proof(h: Harness, keys: Keys, extra: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({ htu: `${h.issuer}/token`, htm: "POST", ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}

async function token(h: Harness, client: Client, keys: Keys, params: Record<string, string>): Promise<{ status: number; body: Body }> {
  const send = async (extra: Record<string, unknown> = {}) =>
    fetch(`${h.issuer}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await proof(h, keys, extra) },
      body: new URLSearchParams({
        ...params,
        client_assertion: await assertion(h, client),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return { status: res.status, body: (await res.json()) as Body };
}

function storeCookies(res: Response, jar: Map<string, string>): void {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
  }
}
const cookieHeader = (jar: Map<string, string>) => [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");

/** PAR, approval and code exchange as ap-agent: an active Mission and its access token. */
async function baseMission(
  h: Harness,
  authority: unknown[] = [delegable()],
): Promise<{ missionId: string; accessToken: string; refreshToken: string }> {
  const jar = new Map<string, string>();
  const verifier = "delegation-exchange-verifier-0123456789-0123456789-01";
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");
  const par = await fetch(`${h.issuer}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: RESOURCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      login_hint: "alice",
      mission_intent: JSON.stringify({ intent: { goal: "Read Acme invoices", target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" } }),
      authorization_details: JSON.stringify(authority),
      client_assertion: await assertion(h, "ap-agent"),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const pushed = (await par.json()) as { request_uri?: string };
  expect(par.status, JSON.stringify(pushed)).toBe(201);
  let res = await fetch(`${h.issuer}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: pushed.request_uri as string })}`, { redirect: "manual" });
  storeCookies(res, jar);
  let location = res.headers.get("location") as string;
  const uid = location.split("/interaction/")[1] as string;
  res = await fetch(`${h.issuer}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...floorApprovalHeaders(sessions, uid, cookieHeader(jar)), "content-type": "application/json" },
    body: JSON.stringify({ decision: "approve" }),
  });
  storeCookies(res, jar);
  location = res.headers.get("location") as string;
  while (location?.startsWith(h.issuer)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader(jar) } });
    storeCookies(res, jar);
    location = res.headers.get("location") as string;
  }
  const code = new URL(location).searchParams.get("code") as string;
  const tok = await token(h, "ap-agent", dpop.get("ap-agent") as Keys, {
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier,
    resource: RESOURCE,
  });
  expect(tok.status, JSON.stringify(tok.body)).toBe(200);
  const accessToken = tok.body.access_token as string;
  return {
    missionId: (decodeJwt(accessToken) as { mission: { id: string } }).mission.id,
    accessToken,
    refreshToken: tok.body.refresh_token as string,
  };
}

/** A designation: `client`, proving `keys`, names `designee` for the presented token. */
const designate = (h: Harness, subjectToken: string, designee: string, client: Client = "ap-agent", keys?: Keys, extra: Record<string, string> = {}) =>
  token(h, client, keys ?? (dpop.get(client) as Keys), {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: subjectToken,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    audience: designee,
    ...extra,
  });

/** A delegated exchange: `client`, proving `keys`, redeems the designation for `resource`. */
const redeem = (h: Harness, designation: string, client: Client = SUBAGENT, keys?: Keys, extra: Record<string, string> = {}, omit: string[] = []) => {
  const params: Record<string, string> = {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: designation,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    resource: RESOURCE,
    ...extra,
  };
  for (const p of omit) delete params[p];
  return token(h, client, keys ?? (dpop.get(client) as Keys), params);
};

async function introspect(h: Harness, tokenValue: string, principal: readonly [string, string] = RS_PAYMENTS): Promise<Body> {
  const res = await fetch(`${h.issuer}/introspect`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${Buffer.from(`${principal[0]}:${principal[1]}`).toString("base64")}`,
    },
    body: new URLSearchParams({ token: tokenValue }).toString(),
  });
  expect(res.status).toBe(200);
  return (await res.json()) as Body;
}

const derivations = (h: Harness, missionId: string) => (h.as.kernel.get(missionId) as { derivation_count?: number }).derivation_count ?? 0;
const jktOf = async (keys: Keys) => calculateJwkThumbprint(await exportJWK(keys.publicKey));
const jtiOf = (jwt: string) => (decodeJwt(jwt) as { jti: string }).jti;

/** The agent's base token, designated to the sub-agent and redeemed: the depth-1 delegated token. */
async function delegatedToSubagent(h: Harness, authority?: unknown[]) {
  const base = await baseMission(h, authority);
  const designation = await designate(h, base.accessToken, SUBAGENT);
  expect(designation.status, JSON.stringify(designation.body)).toBe(200);
  const delegated = await redeem(h, designation.body.access_token as string);
  expect(delegated.status, JSON.stringify(delegated.body)).toBe(200);
  return { ...base, designation: designation.body.access_token as string, delegated: delegated.body.access_token as string };
}

/** The agent's async-family access token (handle, then family) for a fresh Mission. */
async function familyToken(h: Harness): Promise<{ missionId: string; familyToken: string; familyGrant: string; refreshToken: string }> {
  const { missionId, accessToken } = await baseMission(h);
  const agent = dpop.get("ap-agent") as Keys;
  const handle = await token(h, "ap-agent", agent, {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: accessToken,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    audience: "ap-agent",
  });
  expect(handle.status, JSON.stringify(handle.body)).toBe(200);
  const family = await token(h, "ap-agent", agent, {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    request_refresh_token: "true",
    subject_token: handle.body.access_token as string,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    resource: RESOURCE,
    creation_request_id: crypto.randomUUID(),
  });
  expect(family.status, JSON.stringify(family.body)).toBe(200);
  const tokenValue = family.body.access_token as string;
  const familyGrant = h.as.tokenIssuanceStore.resolve(h.issuer, jtiOf(tokenValue))?.grantId as string;
  return { missionId, familyToken: tokenValue, familyGrant, refreshToken: family.body.refresh_token as string };
}

/** RFC 7009: ap-agent revokes `tokenValue` (a refresh token) at the revocation endpoint. */
async function revokeRefreshToken(h: Harness, tokenValue: string): Promise<number> {
  const res = await fetch(`${h.issuer}/token/revocation`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      token: tokenValue,
      token_type_hint: "refresh_token",
      client_assertion: await assertion(h, "ap-agent"),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  return res.status;
}

/**
 * Run `request` with the clock `startMs` from now, jumping it to `afterMs`
 * during the request's first grant lookup: an expiry boundary crossed while
 * the exchange awaits its checks (#1279 review).
 */
async function acrossTheBoundary<T>(h: Harness, startMs: number, afterMs: number, request: () => Promise<T>): Promise<T> {
  const find = h.as.provider.Grant.find.bind(h.as.provider.Grant);
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(startMs);
  const spy = vi.spyOn(h.as.provider.Grant, "find").mockImplementationOnce(async (...args: Parameters<typeof find>) => {
    const grant = await find(...args);
    vi.setSystemTime(afterMs);
    return grant;
  });
  try {
    return await request();
  } finally {
    spy.mockRestore();
    vi.useRealTimers();
  }
}

let on: Harness;
let off: Harness;
let only: Harness;

beforeAll(async () => {
  secondKeys = await generateKeyPair("ES256", { extractable: true });
  for (const c of ["ap-agent", SUBAGENT, SECOND, "ledger-reconciler"] as Client[]) {
    dpop.set(c, await generateKeyPair("ES256", { extractable: true }));
  }
  on = await harness(14870, {
    capabilities: new Set([...ALL_PROVIDER_CAPABILITIES, "delegation"]),
    testIntrospectionPrincipals: [rsAlias, rsLate],
  });
  // The default deployment: no capability set, so the opt-in delegation is off.
  off = await harness(14871, {});
  // Delegation alone, with the payments target not classified Mission-aware.
  only = await harness(14872, {
    capabilities: new Set(["delegation"]),
    scopeProjection: {
      ...SCOPE_PROJECTION,
      audiences: { ...SCOPE_PROJECTION.audiences, [RESOURCE]: { ...(SCOPE_PROJECTION.audiences[RESOURCE] as object), mission_aware: false } },
    },
  });
});
afterAll(() => {
  for (const h of [on, off, only]) h?.server.close();
});

describe("delegation by designation: the agent designates, the sub-agent redeems (@spec mission#delegation, mission#designation)", () => {
  it("issues a designation naming the sub-agent, then a delegated token bound to the sub-agent's own key, counting one derivation each", async () => {
    const { missionId, accessToken } = await baseMission(on);
    const before = derivations(on, missionId);

    const designation = await designate(on, accessToken, SUBAGENT);
    expect(designation.status, JSON.stringify(designation.body)).toBe(200);
    expect(designation.body.token_type).toBe("N_A");
    expect(derivations(on, missionId)).toBe(before + 1);
    const d = decodeJwt(designation.body.access_token as string) as Body;
    expect(d.aud).toBe(SUBAGENT);
    expect(d.may_act).toEqual({ sub: SUBAGENT, iss: on.issuer });
    expect(d.cnf).toBeUndefined();
    expect(d.act).toBeUndefined();
    expect(d.client_id).toBe("ap-agent");
    expect((d.mission as { id: string }).id).toBe(missionId);

    const delegated = await redeem(on, designation.body.access_token as string);
    expect(delegated.status, JSON.stringify(delegated.body)).toBe(200);
    expect(derivations(on, missionId)).toBe(before + 2);
    const t = decodeJwt(delegated.body.access_token as string) as Body;
    expect(t.client_id).toBe(SUBAGENT);
    expect((t.cnf as { jkt: string }).jkt).toBe(await jktOf(dpop.get(SUBAGENT) as Keys));
    expect(t.sub).toBe("alice");
    expect(t.mission).toEqual(d.mission);
    expect(t.aud).toBe(RESOURCE);
    expect(t.act).toEqual({ iss: on.issuer, sub: SUBAGENT, sub_profile: "ai_agent client_instance" });
    // Each surviving entry carries its `delegation` member intact, as the Mission recorded it.
    const recorded = (on.as.kernel.get(missionId)?.authority_set as Body[])[0]?.delegation;
    expect(recorded).toMatchObject(delegable().delegation);
    expect((t.authorization_details as Body[])[0]?.delegation).toEqual(recorded);

    expect((await introspect(on, delegated.body.access_token as string)).active).toBe(true);
  });

  it("a designation's subset authority, Mission claim and life: within 300 s, the presented token and the Mission", async () => {
    const { missionId, accessToken } = await baseMission(on);
    const designation = await designate(on, accessToken, SUBAGENT);
    expect(designation.status).toBe(200);
    const d = decodeJwt(designation.body.access_token as string) as { exp: number; iat: number; mission: unknown; authorization_details: Body[] };
    const presented = decodeJwt(accessToken) as { exp: number; mission: unknown };
    expect(d.mission).toEqual(presented.mission);
    expect(d.exp - d.iat).toBeLessThanOrEqual(300);
    expect(d.exp).toBeLessThanOrEqual(presented.exp);
    expect(d.exp).toBeLessThanOrEqual(Date.parse(on.as.kernel.get(missionId)?.expires_at as string) / 1000);
    expect(d.authorization_details.map((e) => e.resource)).toEqual([RESOURCE]);
  });

  it("a retried redemption is a new counted derivation, not an idempotent replay", async () => {
    const { missionId, accessToken } = await baseMission(on);
    const designation = (await designate(on, accessToken, SUBAGENT)).body.access_token as string;
    const before = derivations(on, missionId);
    const first = await redeem(on, designation);
    const second = await redeem(on, designation);
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(jtiOf(second.body.access_token as string)).not.toBe(jtiOf(first.body.access_token as string));
    expect(derivations(on, missionId)).toBe(before + 2);
  });

  it("under an async family: each exchange counts exactly one derivation, and invalidating the family refuses both and inactivates the delegated token", async () => {
    const { missionId, familyToken: subject, familyGrant } = await familyToken(on);
    expect(on.as.delegationFamilyStore.wasEverFamily(familyGrant)).toBe(true);
    const before = derivations(on, missionId);
    const designation = await designate(on, subject, SUBAGENT);
    expect(designation.status, JSON.stringify(designation.body)).toBe(200);
    expect(derivations(on, missionId)).toBe(before + 1);
    const delegated = await redeem(on, designation.body.access_token as string);
    expect(delegated.status, JSON.stringify(delegated.body)).toBe(200);
    expect(derivations(on, missionId)).toBe(before + 2);
    expect((await introspect(on, delegated.body.access_token as string)).active).toBe(true);

    on.as.delegationFamilyStore.invalidate(familyGrant);
    expect(on.as.kernel.get(missionId)?.state).toBe("active");
    expect(await introspect(on, delegated.body.access_token as string)).toEqual({ active: false });
    const again = await redeem(on, designation.body.access_token as string);
    expect(again.status).toBe(400);
    expect(again.body.error).toBe("invalid_request");
    const fresh = await designate(on, subject, SUBAGENT);
    expect(fresh.status).toBe(400);
    expect(fresh.body.error).toBe("invalid_request");
    expect(derivations(on, missionId)).toBe(before + 2);
  });

  it("RFC 7009 revocation of the family's refresh token refuses new designations and pending redemptions and inactivates the delegated token", async () => {
    const { missionId, familyToken: subject, familyGrant, refreshToken } = await familyToken(on);
    const redeemed = (await designate(on, subject, SUBAGENT)).body.access_token as string;
    const delegated = await redeem(on, redeemed);
    expect(delegated.status, JSON.stringify(delegated.body)).toBe(200);
    const pending = (await designate(on, subject, SUBAGENT)).body.access_token as string;
    expect(await introspect(on, delegated.body.access_token as string)).toMatchObject({ active: true });

    expect(await revokeRefreshToken(on, refreshToken)).toBe(200);
    expect(await on.as.provider.Grant.find(familyGrant)).toBeUndefined();
    expect(on.as.delegationFamilyStore.resolve(familyGrant)).toBeDefined();
    expect(on.as.kernel.get(missionId)?.state).toBe("active");
    const before = derivations(on, missionId);

    expect(await introspect(on, delegated.body.access_token as string)).toEqual({ active: false });
    const again = await redeem(on, pending);
    expect(again.status).toBe(400);
    expect(again.body.error).toBe("invalid_request");
    const fresh = await designate(on, subject, SUBAGENT);
    expect(fresh.status).toBe(400);
    expect(fresh.body.error).toBe("invalid_request");
    expect(derivations(on, missionId)).toBe(before);
  });

  it("revoking the approval grant while the Mission stays active refuses both exchanges and inactivates the delegated token", async () => {
    const { missionId, designation, delegated, accessToken } = await delegatedToSubagent(on);
    const grantId = on.as.kernel.get(missionId)?.grant_id as string;
    await (await on.as.provider.Grant.find(grantId))?.destroy();
    expect(on.as.kernel.get(missionId)?.state).toBe("active");
    const before = derivations(on, missionId);
    expect(await introspect(on, delegated)).toEqual({ active: false });
    const redeemed = await redeem(on, designation);
    expect(redeemed.status).toBe(400);
    expect(redeemed.body.error).toBe("invalid_request");
    const designated = await designate(on, accessToken, SUBAGENT);
    expect(designated.status).toBe(400);
    expect(designated.body.error).toBe("invalid_request");
    expect(derivations(on, missionId)).toBe(before);
  });

  it("a Mission that is not active refuses designation and redemption invalid_request, counting nothing (D369)", async () => {
    const { missionId, accessToken } = await baseMission(on);
    const designation = (await designate(on, accessToken, SUBAGENT)).body.access_token as string;
    on.as.kernel.transition(missionId, "revoke");
    const before = derivations(on, missionId);
    const redeemed = await redeem(on, designation);
    expect(redeemed.status).toBe(400);
    expect(redeemed.body.error).toBe("invalid_request");
    const designated = await designate(on, accessToken, SUBAGENT);
    expect(designated.status).toBe(400);
    expect(designated.body.error).toBe("invalid_request");
    expect(derivations(on, missionId)).toBe(before);
  });
});

describe("who presents which proof (@spec mission#designation, mission#delegation)", () => {
  it("a designation proven under a key other than the presented token's is refused", async () => {
    const { missionId, accessToken } = await baseMission(on);
    const before = derivations(on, missionId);
    const res = await designate(on, accessToken, SUBAGENT, "ap-agent", dpop.get(SUBAGENT));
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_request");
    expect(derivations(on, missionId)).toBe(before);
  });

  it("a client designating a token issued to another client is refused", async () => {
    const { missionId, accessToken } = await baseMission(on);
    const before = derivations(on, missionId);
    // The sub-agent authenticates as itself but presents the agent's token, proven with the agent's key.
    const res = await designate(on, accessToken, SECOND, SUBAGENT, dpop.get("ap-agent"));
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_request");
    expect(res.body.error_description).toMatch(/not issued to the requesting client/);
    expect(derivations(on, missionId)).toBe(before);
  });

  it("a designation cannot itself be designated: it carries no key its holder could prove", async () => {
    const { missionId, accessToken } = await baseMission(on);
    const designation = (await designate(on, accessToken, SUBAGENT)).body.access_token as string;
    const before = derivations(on, missionId);
    const res = await designate(on, designation, SECOND, SUBAGENT);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_request");
    expect(res.body.error_description).toMatch(/sender-constrained/);
    expect(derivations(on, missionId)).toBe(before);
  });

  it("a designation carries only entries the named client may be delegated: a client no entry admits is refused invalid_target", async () => {
    const { missionId, accessToken } = await baseMission(on);
    const presented = (decodeJwt(accessToken) as { authorization_details: Body[] }).authorization_details;
    const designation = await designate(on, accessToken, SUBAGENT);
    expect(designation.status, JSON.stringify(designation.body)).toBe(200);
    const carried = (decodeJwt(designation.body.access_token as string) as { authorization_details: Body[] }).authorization_details;
    for (const entry of carried) expect(presented).toContainEqual(entry);
    // A designable client with no AS-asserted actor profile: no `ai_agent` matcher admits it.
    const before = derivations(on, missionId);
    const refused = await designate(on, accessToken, INELIGIBLE);
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe("invalid_target");
    expect(refused.body.error_description).toMatch(/no entry the designated client may be delegated/);
    expect(derivations(on, missionId)).toBe(before);
  });

  it("a designation naming no registered client is refused invalid_target", async () => {
    const { accessToken } = await baseMission(on);
    const res = await designate(on, accessToken, "no-such-client");
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_target");
  });

  it("a redemption proven under the designator's key is refused: the delegate's key must be its own", async () => {
    const { missionId, accessToken } = await baseMission(on);
    const designation = (await designate(on, accessToken, SUBAGENT)).body.access_token as string;
    const before = derivations(on, missionId);
    const res = await redeem(on, designation, SUBAGENT, dpop.get("ap-agent"));
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_request");
    expect(res.body.error_description).toMatch(/delegate's own key/);
    expect(derivations(on, missionId)).toBe(before);
  });

  it("a client the designation does not name cannot redeem it", async () => {
    const { missionId, accessToken } = await baseMission(on);
    const designation = (await designate(on, accessToken, SUBAGENT)).body.access_token as string;
    const before = derivations(on, missionId);
    const res = await redeem(on, designation, "ledger-reconciler");
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_request");
    expect(res.body.error_description).toMatch(/not a designation naming the requesting client/);
    expect(derivations(on, missionId)).toBe(before);
  });

  it("an access token issued for resource access is not a designation, even presented by an eligible delegate", async () => {
    const { missionId, accessToken } = await baseMission(on);
    const before = derivations(on, missionId);
    const res = await redeem(on, accessToken);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_request");
    expect(res.body.error_description).toMatch(/not a designation naming the requesting client/);
    expect(derivations(on, missionId)).toBe(before);
  });

  it("the delegated exchange identifies the delegate by its client authentication: an actor_token is refused invalid_request", async () => {
    const { accessToken } = await baseMission(on);
    const designation = (await designate(on, accessToken, SUBAGENT)).body.access_token as string;
    const res = await redeem(on, designation, SUBAGENT, undefined, {
      actor_token: designation,
      actor_token_type: "urn:ietf:params:oauth:token-type:jwt",
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_request");
    expect(res.body.error_description).toMatch(/actor_token is not supported/);
  });

  it("a redemption names its target: without a resource it is refused invalid_request", async () => {
    const { accessToken } = await baseMission(on);
    const designation = (await designate(on, accessToken, SUBAGENT)).body.access_token as string;
    const res = await redeem(on, designation, SUBAGENT, undefined, {}, ["resource"]);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_request");
    expect(res.body.error_description).toMatch(/resource/);
  });

  it("a designation is no handle and no async subject: both exchanges refuse it", async () => {
    const { accessToken } = await baseMission(on);
    const designation = (await designate(on, accessToken, SUBAGENT)).body.access_token as string;
    const handle = await designate(on, designation, SUBAGENT, SUBAGENT);
    expect(handle.status).toBe(400);
    expect(handle.body.error).toBe("invalid_request");
    const family = await token(on, SUBAGENT, dpop.get(SUBAGENT) as Keys, {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      request_refresh_token: "true",
      subject_token: designation,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      resource: RESOURCE,
      creation_request_id: crypto.randomUUID(),
    });
    expect(family.status).toBe(400);
    expect(family.body.error).toBe("invalid_request");
  });
});

const actionsOf = (jwt: string): string[] =>
  ((decodeJwt(jwt) as { authorization_details: Body[] }).authorization_details.flatMap((e) => e.actions as string[])).sort();

/** A Mission whose single delegable entry grants two read actions. */
const broadReads = () => ({
  ...delegable(),
  actions: ["payments:invoice.list", "payments:invoice.read"],
  constraints: { vendors: ["acme"] },
});

/** Narrow the Mission's containment by removing `actions` on the payments resource (an authoritative narrowing). */
function contain(h: Harness, missionId: string, actions: string[]): void {
  h.as.kernel.contain(missionId, {
    event: { type: "test.narrowing", source: "delegation-exchange.test", observed_at: new Date().toISOString(), event_id: crypto.randomUUID() },
    remove: [{ resource: RESOURCE, actions }],
  });
}

describe("authority bounds every exchange from the credential and the Mission as they stand (@spec mission#designation, mission#delegation, #869 acceptance)", () => {
  it("a credential narrower than its Mission: neither the designation nor the delegated token regains the omitted action", async () => {
    const { missionId, accessToken } = await baseMission(on, [broadReads()]);
    const recorded = (on.as.kernel.get(missionId)?.authority_set as Body[])[0] as Body;
    expect((recorded.actions as string[]).sort()).toEqual(["payments:invoice.list", "payments:invoice.read"]);
    // The issuer narrows the credential at the async-delegation exchange: a
    // family token carrying one of the Mission's two actions.
    const agent = dpop.get("ap-agent") as Keys;
    const handle = await designate(on, accessToken, "ap-agent");
    expect(handle.status, JSON.stringify(handle.body)).toBe(200);
    const narrow = await token(on, "ap-agent", agent, {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      request_refresh_token: "true",
      subject_token: handle.body.access_token as string,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      resource: RESOURCE,
      creation_request_id: crypto.randomUUID(),
      authorization_details: JSON.stringify([{ ...recorded, actions: ["payments:invoice.read"] }]),
    });
    expect(narrow.status, JSON.stringify(narrow.body)).toBe(200);
    const credential = narrow.body.access_token as string;
    expect(actionsOf(credential)).toEqual(["payments:invoice.read"]);

    const designation = await designate(on, credential, SUBAGENT);
    expect(designation.status, JSON.stringify(designation.body)).toBe(200);
    expect(actionsOf(designation.body.access_token as string)).toEqual(["payments:invoice.read"]);
    const delegated = await redeem(on, designation.body.access_token as string);
    expect(delegated.status, JSON.stringify(delegated.body)).toBe(200);
    expect(actionsOf(delegated.body.access_token as string)).toEqual(["payments:invoice.read"]);
  });

  it("redemption re-reads the Mission's current authority: a containment after the designation narrows the delegated token, and one leaving nothing refuses invalid_target, counting nothing", async () => {
    const { missionId, accessToken } = await baseMission(on, [broadReads()]);
    const designation = (await designate(on, accessToken, SUBAGENT)).body.access_token as string;
    expect(actionsOf(designation)).toEqual(["payments:invoice.list", "payments:invoice.read"]);
    // Control: unchanged, the redemption carries both.
    const control = await redeem(on, designation);
    expect(control.status, JSON.stringify(control.body)).toBe(200);
    expect(actionsOf(control.body.access_token as string)).toEqual(["payments:invoice.list", "payments:invoice.read"]);

    contain(on, missionId, ["payments:invoice.list"]);
    const narrowed = await redeem(on, designation);
    expect(narrowed.status, JSON.stringify(narrowed.body)).toBe(200);
    expect(actionsOf(narrowed.body.access_token as string)).toEqual(["payments:invoice.read"]);

    contain(on, missionId, ["payments:invoice.read"]);
    const before = derivations(on, missionId);
    const refused = await redeem(on, designation);
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe("invalid_target");
    expect(derivations(on, missionId)).toBe(before);
  });

  it("redemption re-evaluates eligibility: a delegate whose AS-asserted profile is withdrawn after the designation is refused invalid_target, counting nothing", async () => {
    const { missionId, accessToken } = await baseMission(on);
    const designation = (await designate(on, accessToken, SUBAGENT)).body.access_token as string;
    // Control: while eligible, the redemption succeeds.
    expect((await redeem(on, designation)).status).toBe(200);

    // The AS's actor-profile registry no longer asserts `ai_agent` for the sub-agent.
    const profile = on.as.kernel.actorProfile.bind(on.as.kernel);
    const spy = vi.spyOn(on.as.kernel, "actorProfile").mockImplementation((sub: string) => (sub === SUBAGENT ? undefined : profile(sub)));
    try {
      const before = derivations(on, missionId);
      const refused = await redeem(on, designation);
      expect(refused.status).toBe(400);
      expect(refused.body.error).toBe("invalid_target");
      expect(derivations(on, missionId)).toBe(before);
    } finally {
      spy.mockRestore();
    }
  });
});

describe("delegation depth from the AS's accounting (@spec mission#delegation-constraints)", () => {
  it("a current delegate designates the next: depth 2 is served within max_depth 2, act naming both delegates, newest outermost", async () => {
    const { missionId, delegated } = await delegatedToSubagent(on);
    const before = derivations(on, missionId);
    const designation = await designate(on, delegated, SECOND, SUBAGENT);
    expect(designation.status, JSON.stringify(designation.body)).toBe(200);
    expect((decodeJwt(designation.body.access_token as string) as Body).act).toBeUndefined();
    const second = await redeem(on, designation.body.access_token as string, SECOND);
    expect(second.status, JSON.stringify(second.body)).toBe(200);
    expect(derivations(on, missionId)).toBe(before + 2);
    const t = decodeJwt(second.body.access_token as string) as Body;
    expect(t.client_id).toBe(SECOND);
    expect((t.cnf as { jkt: string }).jkt).toBe(await jktOf(dpop.get(SECOND) as Keys));
    expect(t.act).toEqual({
      iss: on.issuer,
      sub: SECOND,
      sub_profile: "ai_agent",
      act: { iss: on.issuer, sub: SUBAGENT, sub_profile: "ai_agent client_instance" },
    });
    expect(on.as.tokenIssuanceStore.resolve(on.issuer, jtiOf(second.body.access_token as string))?.depth).toBe(2);
  });

  it("past max_depth the entry narrows out: designating a depth-2 delegate under max_depth 1 is refused invalid_target, counting nothing", async () => {
    const { missionId, delegated } = await delegatedToSubagent(on, [delegable(1)]);
    const before = derivations(on, missionId);
    const res = await designate(on, delegated, SECOND, SUBAGENT);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_target");
    expect(derivations(on, missionId)).toBe(before);
  });

  it("a token whose accounting record is lost, as after a restart, is refused invalid_target though it carries no act", async () => {
    const { missionId, accessToken } = await baseMission(on);
    expect((decodeJwt(accessToken) as Body).act).toBeUndefined();
    on.as.tokenIssuanceStore.remove(on.issuer, jtiOf(accessToken));
    const before = derivations(on, missionId);
    const res = await designate(on, accessToken, SUBAGENT);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_target");
    expect(res.body.error_description).toMatch(/cannot be established/);
    expect(derivations(on, missionId)).toBe(before);
  });

  it("a record whose chain does not match the token's act is refused invalid_target", async () => {
    const { missionId, delegated } = await delegatedToSubagent(on);
    on.as.tokenIssuanceStore.db
      .prepare("UPDATE token_issuance SET chain = '[]' WHERE iss = ? AND jti = ?")
      .run(on.issuer, jtiOf(delegated));
    const before = derivations(on, missionId);
    const res = await designate(on, delegated, SECOND, SUBAGENT);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_target");
    expect(derivations(on, missionId)).toBe(before);
  });
});

describe("lifetimes are absolute across the request (@spec mission#designation, #1279 review)", () => {
  it("a designation whose source expires while the exchange awaits its checks is refused invalid_request, counting nothing", async () => {
    const { missionId, accessToken } = await baseMission(on);
    const exp = decodeJwt(accessToken).exp as number;
    const before = derivations(on, missionId);
    const res = await acrossTheBoundary(on, exp * 1000 - 100, exp * 1000 + 10, () => designate(on, accessToken, SUBAGENT));
    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(res.body.error).toBe("invalid_request");
    expect(res.body.error_description).toMatch(/no lifetime left/);
    expect(derivations(on, missionId)).toBe(before);
  });

  it("a redemption whose designation expires while the exchange awaits its checks is refused invalid_request, counting nothing", async () => {
    const { missionId, accessToken } = await baseMission(on);
    const designation = (await designate(on, accessToken, SUBAGENT)).body.access_token as string;
    const exp = decodeJwt(designation).exp as number;
    const before = derivations(on, missionId);
    const res = await acrossTheBoundary(on, exp * 1000 - 100, exp * 1000 + 10, () => redeem(on, designation));
    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(res.body.error).toBe("invalid_request");
    expect(res.body.error_description).toMatch(/designation has expired/);
    expect(derivations(on, missionId)).toBe(before);
  });
});

describe("one counting and settlement path (@spec mission#delegation, derivation-limits#counted-operations)", () => {
  it("an accounting record that cannot be written refuses, with nothing counted and no token", async () => {
    const { missionId, accessToken } = await baseMission(on);
    const before = derivations(on, missionId);
    const spy = vi.spyOn(TokenIssuanceStore.prototype, "recordDelegation").mockImplementation(() => {
      throw new Error("injected accounting failure");
    });
    try {
      const res = await designate(on, accessToken, SUBAGENT);
      expect(res.status).toBe(500);
      expect(res.body.access_token).toBeUndefined();
    } finally {
      spy.mockRestore();
    }
    expect(derivations(on, missionId)).toBe(before);
  });

  it("a save refused after the count leaves the count spent with no token and no record (the recorded residual)", async () => {
    const { missionId, accessToken } = await baseMission(on);
    const designation = (await designate(on, accessToken, SUBAGENT)).body.access_token as string;
    const before = derivations(on, missionId);
    const recorded = vi.spyOn(TokenIssuanceStore.prototype, "recordDelegation");
    const save = vi.spyOn(on.as.provider.AccessToken.prototype, "save").mockRejectedValueOnce(new Error("injected save failure"));
    try {
      const res = await redeem(on, designation);
      expect(res.status).toBe(500);
      expect(res.body.access_token).toBeUndefined();
    } finally {
      save.mockRestore();
    }
    const jti = (recorded.mock.calls[0]?.[0] as { jti: string }).jti;
    recorded.mockRestore();
    expect(on.as.tokenIssuanceStore.resolve(on.issuer, jti)).toBeUndefined();
    expect(derivations(on, missionId)).toBe(before + 1);
  });
});

describe("a designation authorizes no resource access (@spec mission#designation, mission#composite-active)", () => {
  it("a designation naming a client whose identifier is an audience the AS issues is refused invalid_target, issuing nothing", async () => {
    const { missionId, accessToken } = await baseMission(on);
    const before = derivations(on, missionId);
    const res = await designate(on, accessToken, ISSUED_AUDIENCE);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_target");
    expect(res.body.error_description).toMatch(/audience a resource server accepts/);
    expect(derivations(on, missionId)).toBe(before);
  });

  it("a designation naming a client a resource server accepts as an alias the AS never issues is refused invalid_target, issuing nothing", async () => {
    const { missionId, accessToken } = await baseMission(on);
    expect(resourceAudiences({ issuer: on.issuer, scopeProjection: SCOPE_PROJECTION }).has(ALIAS_CLIENT)).toBe(false);
    const before = derivations(on, missionId);
    const res = await designate(on, accessToken, ALIAS_CLIENT);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_target");
    expect(res.body.error_description).toMatch(/audience a resource server accepts/);
    expect(derivations(on, missionId)).toBe(before);
  });

  it("a designation naming an eligible client for which separation is not established is refused invalid_target, issuing nothing", async () => {
    const { missionId, accessToken } = await baseMission(on);
    const before = derivations(on, missionId);
    const res = await designate(on, accessToken, UNDECLARED);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_target");
    expect(res.body.error_description).toMatch(/separation is not established/);
    expect(derivations(on, missionId)).toBe(before);
  });

  it("the accepted audiences span the issuer, the configured resources and every registered resource server's audiences and aliases, and the Mission's own resources", () => {
    const audiences = resourceAudiences({
      issuer: on.issuer,
      scopeProjection: SCOPE_PROJECTION,
      introspectionPrincipals: [{ ...rsAlias, audience_resources: { "urn:example:alias": ["urn:example:target"] } }],
    });
    expect(audienceCollision(SUBAGENT, audiences)).toBe(false);
    for (const id of [on.issuer, RESOURCE, ALIAS_CLIENT, "urn:example:alias", "urn:example:target"]) {
      expect(audienceCollision(id, audiences), id).toBe(true);
    }
    expect(audienceCollision("urn:example:resource", audiences, ["urn:example:resource"])).toBe(true);
  });

  it("a resource server validating a JWT access token's audience rejects a designation (RFC 9068 Section 4)", async () => {
    const { accessToken } = await baseMission(on);
    const designation = (await designate(on, accessToken, SUBAGENT)).body.access_token as string;
    const jwks = (await (await fetch(`${on.issuer}/jwks`)).json()) as { keys: never[] };
    await expect(
      jwtVerify(designation, createLocalJWKSet(jwks as never), { issuer: on.issuer, audience: RESOURCE }),
    ).rejects.toThrow(/aud/);
  });

  it("introspection reports a designation inactive with no Mission data, even to a resource server that starts accepting the designated client's identifier during its life", async () => {
    const { accessToken } = await baseMission(on);
    const designation = (await designate(on, accessToken, SUBAGENT)).body.access_token as string;
    rsLate.audiences.push(SUBAGENT);
    try {
      expect(await introspect(on, designation, RS_LATE)).toEqual({ active: false });
    } finally {
      rsLate.audiences.pop();
    }
    expect(await introspect(on, designation)).toEqual({ active: false });
  });
});

describe("the exchange selector (@spec mission#delegation)", () => {
  it("with delegation on, an audience naming the requester itself is still the delegation handle", async () => {
    const { accessToken } = await baseMission(on);
    const res = await designate(on, accessToken, "ap-agent");
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const t = decodeJwt(res.body.access_token as string) as Body;
    expect(t.aud).toBe("ap-agent");
    expect((t.cnf as { jkt: string }).jkt).toBe(await jktOf(dpop.get("ap-agent") as Keys));
    expect(t.may_act).toBeUndefined();
  });

  it("with delegation on, each Expansion parameter still selects Expansion", async () => {
    const { accessToken } = await baseMission(on);
    const designation = (await designate(on, accessToken, SUBAGENT)).body.access_token as string;
    for (const [param, value] of [
      ["mission_intent", JSON.stringify({ intent: { goal: "More", target_resources: [RESOURCE] } })],
      ["creation_request_id", crypto.randomUUID()],
      ["predecessor", "msn_x"],
      ["deferral_code", "dc_unknown"],
    ] as const) {
      const res = await redeem(on, designation, SUBAGENT, undefined, { [param]: value });
      expect(res.status, param).toBeGreaterThanOrEqual(400);
      expect(String(res.body.error_description), param).not.toMatch(/designation/);
    }
  });

  it("with delegation on, the conflicting parameters are refused before routing", async () => {
    const { accessToken } = await baseMission(on);
    const res = await designate(on, accessToken, SUBAGENT, "ap-agent", undefined, { resource: RESOURCE });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_request");
    expect(res.body.error_description).toMatch(/cannot be combined with resource/);
  });

  it("a delegated token reaches only a Mission-aware target: otherwise invalid_target, counting nothing (D166)", async () => {
    const { missionId, accessToken } = await baseMission(only);
    const designation = await designate(only, accessToken, SUBAGENT);
    expect(designation.status, JSON.stringify(designation.body)).toBe(200);
    const before = derivations(only, missionId);
    const res = await redeem(only, designation.body.access_token as string);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_target");
    expect(derivations(only, missionId)).toBe(before);
  });
});

describe("runtime enablement is opt-in (@spec mission#conformance, D449)", () => {
  it("with no capability set, delegation is off and both shapes route as before", async () => {
    const { missionId, accessToken } = await baseMission(off);
    const before = derivations(off, missionId);
    const designation = await designate(off, accessToken, SUBAGENT);
    expect(designation.status).toBe(400);
    expect(designation.body.error).toBe("invalid_target");
    expect(designation.body.error_description).toMatch(/delegation handle's audience/);
    const redemption = await redeem(off, accessToken);
    expect(redemption.status).toBe(400);
    expect(redemption.body.error).toBe("invalid_request");
    expect(redemption.body.error_description).toMatch(/creation_request_id required/);
    expect(derivations(off, missionId)).toBe(before);
  });

  it("a set naming only delegation registers Token Exchange and serves the designation", async () => {
    const { accessToken } = await baseMission(only);
    const designation = await designate(only, accessToken, SUBAGENT);
    expect(designation.status, JSON.stringify(designation.body)).toBe(200);
    expect(designation.body.token_type).toBe("N_A");
  });
});
