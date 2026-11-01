/**
 * @spec mission#mission-governed, mission#authority-proposal (#1448, D585):
 * the Mission-governed client rule reaches authorization requests only.
 *
 * Its second rule refuses, with `invalid_request`, an authorization request
 * from a client registered as Mission-governed that carries
 * `authorization_details` but no `mission_intent`, through PAR or at the
 * authorization endpoint, until the request completes. A token request under
 * an existing Mission-bound grant needs no `mission_intent` under that rule,
 * and every other check still applies to it.
 *
 * PAR is witnessed in rar-carriage.test.ts. Covered here:
 *  - the authorization endpoint applies the rule to the request it reads.
 *    The deployment requires PAR, so the endpoint reads a request only from a
 *    pushed request, and PAR refuses the governed omission itself; the witness
 *    stores the pushed request directly, as the PAR endpoint would, so only
 *    the endpoint's own check can refuse it. Controls: the same stored request
 *    from an ungoverned client, and a governed request with `mission_intent`,
 *    each pass the rule and start the interaction;
 *  - the refused request starts no interaction, so nothing of it is resumed;
 *    the governed request with `mission_intent` completes through its resume;
 *  - a direct authorization request without PAR is refused `invalid_request`
 *    for every client, governed or not: the deployment requires PAR;
 *  - a governed client's token requests carry no `mission_intent` and are not
 *    refused for it: a narrowing code exchange and refresh, a self-exchange
 *    (the delegation handle and the family it opens), a designation, and a
 *    governed delegate's delegated exchange. Each keeps its own checks: a
 *    widening request is refused `invalid_authorization_details`, Issuance
 *    Gating and the grant's client binding refuse a refresh, and a designation
 *    proven under another key is refused.
 */
import { renderedRevision, TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";

import type { Server } from "node:http";
import { AUTHORITY_SOURCES, CANONICAL_RESOURCE } from "@mission/demo-data";
import { decodeJwt, exportJWK, generateKeyPair, importJWK, SignJWT, UnsecuredJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ACCESS_TOKEN_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import { ALL_PROVIDER_CAPABILITIES, type BuiltAs, buildAuthorizationServer } from "../src/index.js";
import { delegationHandleParams } from "./delegation-handle.helper.js";

const PORT = 14779;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
const FAR_EXP = "2027-06-01T00:00:00Z";
const VERIFIER = "governed-client-verifier-0123456789-0123456789-0123456";
/** A client registered as Mission-governed, holding the code, refresh and exchange grants. */
const GOVERNED = "test-governed-agent";
/** A delegate registered as Mission-governed, holding the exchange grant only. */
const DELEGATE = "test-governed-delegate";
/** A client with no Mission-governed registration. */
const UNGOVERNED = "ap-agent";
const LIST = "payments:invoice.list";
const READ = "payments:invoice.read";
const EXECUTE = "payments:payment.execute";
const DELEGATION = { max_depth: 2, allowed_delegates: [{ sub_profile: "ai_agent" }] };
const entry = (actions: string[]) => ({
  type: "mission_resource_access",
  resource: RESOURCE,
  actions,
  constraints: { vendors: ["acme"] },
  delegation: DELEGATION,
});
const MISSION_ENTRY = entry([LIST, READ]);
/** A subset of the Mission's authority. */
const NARROWED = [entry([READ])];
/** Beyond the Mission's authority: an action outside the grant. */
const WIDENED = [entry([READ, EXECUTE])];
const INTENT = { intent: { goal: "Read Acme invoices", target_resources: [RESOURCE], expires_at: FAR_EXP } };

type Client = typeof GOVERNED | typeof DELEGATE | typeof UNGOVERNED;
type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
type Json = Record<string, unknown>;
type Entry = { resource: string; actions: string[] };

let as: BuiltAs;
let server: Server;
const clientKeys = new Map<Client, CryptoKey>();

async function newKeys(): Promise<Keys> {
  return (await generateKeyPair("ES256", { extractable: true })) as Keys;
}

async function clientAuth(client: Client): Promise<Record<string, string>> {
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: `${client}-auth` })
    .setIssuer(client)
    .setSubject(client)
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(clientKeys.get(client) as CryptoKey);
  return { client_assertion: assertion, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" };
}

async function pkceChallenge(): Promise<string> {
  return Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER))).toString("base64url");
}

/** The parameters every authorization request here carries. */
async function baseRequest(client: Client): Promise<Record<string, string>> {
  return {
    client_id: client,
    response_type: "code",
    redirect_uri: REDIRECT_URI,
    resource: RESOURCE,
    code_challenge: await pkceChallenge(),
    code_challenge_method: "S256",
  };
}

/** Push an authorization request through PAR as `client`. */
async function push(client: Client, params: Record<string, string>): Promise<{ status: number; body: Json }> {
  const res = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ ...(await baseRequest(client)), ...params, ...(await clientAuth(client)) }).toString(),
  });
  return { status: res.status, body: (await res.json()) as Json };
}

/**
 * Store a pushed authorization request for `client` as the PAR endpoint
 * stores one (oidc-provider 9.10.0 pushed_authorization_request_response.js:
 * an unsecured JWT of the request's parameters, trusted for an authenticated
 * client), without passing it through PAR's own checks. Its request_uri.
 */
async function storePushed(client: Client, params: Json): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const request = new UnsecuredJWT({ ...(await baseRequest(client)), ...params })
    .setIssuedAt(now)
    .setIssuer(client)
    .setAudience(ISSUER)
    .setExpirationTime(now + 60)
    .setNotBefore(now)
    .encode();
  const pushed = new as.provider.PushedAuthorizationRequest({ request, trusted: true } as never);
  return `urn:ietf:params:oauth:request_uri:${await pushed.save(60)}`;
}

type Jar = Map<string, string>;
function keep(res: Response, jar: Jar): void {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
  }
}
const cookie = (jar: Jar) => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");

/** Run `fn`, counting the interactions the provider starts meanwhile. */
async function countingInteractions<T>(fn: () => Promise<T>): Promise<{ result: T; interactions: number }> {
  let interactions = 0;
  const onStarted = () => {
    interactions += 1;
  };
  as.provider.on("interaction.started", onStarted);
  try {
    return { result: await fn(), interactions };
  } finally {
    as.provider.removeListener("interaction.started", onStarted);
  }
}

/** The authorization endpoint for a request_uri: its status and Location. */
async function authorize(client: Client, requestUri: string, jar: Jar): Promise<{ status: number; location: string }> {
  const res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: client, request_uri: requestUri })}`, {
    redirect: "manual",
  });
  keep(res, jar);
  return { status: res.status, location: res.headers.get("location") ?? "" };
}

/** A redirect's target, without its query, and the query; a relative Location resolves on the AS. */
function clientRedirect(location: string): { target: string; query: URLSearchParams } {
  const url = new URL(location, ISSUER);
  return { target: `${url.origin}${url.pathname}`, query: url.searchParams };
}

/**
 * Approve the interaction `location` names and follow the AS's redirects:
 * the URLs visited on the AS, and the final redirect to the client.
 */
async function approveAndResume(location: string, jar: Jar): Promise<{ visited: string[]; final: string }> {
  const uid = location.split("/interaction/")[1] as string;
  const decideHeaders = { ...trustedApprovalHeaders(), "content-type": "application/json", cookie: cookie(jar) };
  const render_revision = await renderedRevision(ISSUER, uid, decideHeaders);
  let res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: decideHeaders,
    body: JSON.stringify({ decision: "approve", render_revision }),
  });
  keep(res, jar);
  const visited: string[] = [];
  let next = res.headers.get("location") ?? "";
  while (next.startsWith(ISSUER)) {
    visited.push(next);
    res = await fetch(next, { redirect: "manual", headers: { cookie: cookie(jar) } });
    keep(res, jar);
    next = res.headers.get("location") ?? "";
  }
  return { visited, final: next };
}

/** PAR with `mission_intent`, the interaction, its approval and the resume: an authorization code for `client`. */
async function approvedCode(client: Client = GOVERNED): Promise<string> {
  const pushed = await push(client, {
    login_hint: "alice",
    mission_intent: JSON.stringify(INTENT),
    authorization_details: JSON.stringify([MISSION_ENTRY]),
  });
  expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
  const jar: Jar = new Map();
  const { location } = await authorize(client, pushed.body.request_uri as string, jar);
  expect(location).toContain("/interaction/");
  const { final } = await approveAndResume(location, jar);
  return new URL(final).searchParams.get("code") as string;
}

async function dpopProof(keys: Keys, extra: Json = {}): Promise<string> {
  return new SignJWT({ htu: `${ISSUER}/token`, htm: "POST", ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}

/** A token request as `client`, proving `keys` by DPoP. No request here carries `mission_intent`. */
async function token(client: Client, keys: Keys, params: Record<string, string>): Promise<{ status: number; body: Json }> {
  expect(params.mission_intent).toBeUndefined();
  const send = async (extra: Json = {}) =>
    fetch(`${ISSUER}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(keys, extra) },
      body: new URLSearchParams({ ...params, ...(await clientAuth(client)) }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return { status: res.status, body: (await res.json()) as Json };
}

const details = (entries: unknown[]) => ({ authorization_details: JSON.stringify(entries) });

const exchange = (code: string, keys: Keys, extra: Record<string, string> = {}) =>
  token(GOVERNED, keys, {
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: VERIFIER,
    resource: RESOURCE,
    ...extra,
  });

const refresh = (client: Client, refreshToken: string, keys: Keys, extra: Record<string, string> = {}) =>
  token(client, keys, { grant_type: "refresh_token", refresh_token: refreshToken, resource: RESOURCE, ...extra });

/** An active Mission of the governed client over MISSION_ENTRY: its access and refresh token. */
async function issue(): Promise<{ missionId: string; accessToken: string; refreshToken: string; keys: Keys }> {
  const keys = await newKeys();
  const exchanged = await exchange(await approvedCode(), keys);
  expect(exchanged.status, JSON.stringify(exchanged.body)).toBe(200);
  const accessToken = exchanged.body.access_token as string;
  const missionId = (decodeJwt(accessToken) as { mission: { id: string } }).mission.id;
  return { missionId, accessToken, refreshToken: exchanged.body.refresh_token as string, keys };
}

const tokenEntries = (accessToken: unknown): Entry[] =>
  (decodeJwt(accessToken as string) as { authorization_details: Entry[] }).authorization_details;
const actionsOf = (entries: Entry[]) => entries.flatMap((e) => e.actions).sort();
const missionOf = (accessToken: unknown) => (decodeJwt(accessToken as string) as { mission: { id: string } }).mission.id;

/** A 200 whose token, and its response where it carries one, hold exactly `actions` of the Mission. */
function expectIssued(res: { status: number; body: Json }, actions: string[], missionId: string): void {
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  const carried = tokenEntries(res.body.access_token);
  expect(actionsOf(carried)).toEqual([...actions].sort());
  for (const e of carried) expect(e.resource).toBe(RESOURCE);
  expect(missionOf(res.body.access_token)).toBe(missionId);
}

function expectRefused(res: { status: number; body: Json }, error: string): void {
  expect(res.status, JSON.stringify(res.body)).toBe(400);
  expect(res.body.error).toBe(error);
  expect(res.body.access_token).toBeUndefined();
}

beforeAll(async () => {
  const governedKeys = await newKeys();
  const delegateKeys = await newKeys();
  clientKeys.set(GOVERNED, governedKeys.privateKey);
  clientKeys.set(DELEGATE, delegateKeys.privateKey);
  const jwk = async (keys: Keys, client: Client) => ({
    keys: [{ ...(await exportJWK(keys.publicKey)), kid: `${client}-auth`, alg: "ES256" }],
  });
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    capabilities: new Set([...ALL_PROVIDER_CAPABILITIES, "delegation"]),
    testClients: [
      {
        client_id: GOVERNED,
        client_name: "Test Governed Agent",
        grant_types: ["authorization_code", "refresh_token", TOKEN_EXCHANGE_GRANT_TYPE],
        response_types: ["code"],
        redirect_uris: [REDIRECT_URI],
        token_endpoint_auth_method: "private_key_jwt",
        token_endpoint_auth_signing_alg: "ES256",
        authorization_details_types: ["mission_resource_access"],
        mission_governed: true,
        jwks: await jwk(governedKeys, GOVERNED),
      },
      {
        client_id: DELEGATE,
        client_name: "Test Governed Delegate",
        grant_types: [TOKEN_EXCHANGE_GRANT_TYPE],
        response_types: [],
        redirect_uris: [],
        token_endpoint_auth_method: "private_key_jwt",
        token_endpoint_auth_signing_alg: "ES256",
        authorization_details_types: ["mission_resource_access"],
        mission_governed: true,
        jwks: await jwk(delegateKeys, DELEGATE),
      },
    ],
    // The governed agent acts for Alice under the shipped user-delegated source.
    authoritySources: {
      ...AUTHORITY_SOURCES,
      entries: AUTHORITY_SOURCES.entries.map((e) => (e.id === "acme-people" ? { ...e, clients: [...e.clients, GOVERNED] } : e)),
    },
    actorProfiles: { [DELEGATE]: "ai_agent" },
    designableClients: [DELEGATE],
  } as never);
  server = as.provider.listen(PORT);
  await new Promise<void>((r) => server.once("listening", () => r()));
  clientKeys.set(UNGOVERNED, (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey);
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

describe("the Mission-governed client rule at the authorization endpoint and its resume (@spec mission#mission-governed, #1448, D585)", () => {
  it("refuses invalid_request at the authorization endpoint a governed client's pushed request carrying authorization_details without mission_intent, starting no interaction to resume", async () => {
    const requestUri = await storePushed(GOVERNED, { authorization_details: [MISSION_ENTRY] });
    const { result, interactions } = await countingInteractions(() => authorize(GOVERNED, requestUri, new Map()));
    expect(result.status).toBe(303);
    const { target, query } = clientRedirect(result.location);
    expect(target).toBe(REDIRECT_URI);
    expect(query.get("error")).toBe("invalid_request");
    expect(query.get("error_description")).toMatch(/Mission-governed/);
    expect(query.get("code")).toBeNull();
    // Refused before any interaction: nothing of this request is resumed.
    expect(interactions).toBe(0);
  });

  it("control: the same stored request from an ungoverned client passes the rule and starts the interaction", async () => {
    const requestUri = await storePushed(UNGOVERNED, { authorization_details: [MISSION_ENTRY] });
    const { result, interactions } = await countingInteractions(() => authorize(UNGOVERNED, requestUri, new Map()));
    expect(result.status).toBe(303);
    expect(result.location).toMatch(/^\/interaction\/[^/]+$/);
    expect(interactions).toBe(1);
  });

  it("control: a governed client's request with mission_intent passes the rule at the authorization endpoint and completes through its resume", async () => {
    const pushed = await push(GOVERNED, {
      login_hint: "alice",
      mission_intent: JSON.stringify(INTENT),
      authorization_details: JSON.stringify([MISSION_ENTRY]),
    });
    expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
    const jar: Jar = new Map();
    const { result, interactions } = await countingInteractions(() => authorize(GOVERNED, pushed.body.request_uri as string, jar));
    expect(result.status).toBe(303);
    expect(result.location).toMatch(/^\/interaction\/[^/]+$/);
    expect(interactions).toBe(1);
    const uid = result.location.split("/interaction/")[1] as string;
    const { visited, final } = await approveAndResume(result.location, jar);
    // The resume route (oidc-provider's /auth/:uid) completed the request.
    expect(visited).toContain(`${ISSUER}/auth/${uid}`);
    const { target, query } = clientRedirect(final);
    expect(target).toBe(REDIRECT_URI);
    expect(query.get("error")).toBeNull();
    expect(query.get("code")).toBeTruthy();
  });

  it("a direct authorization request without PAR is refused invalid_request for a governed and an ungoverned client alike: the deployment requires PAR", async () => {
    for (const client of [GOVERNED, UNGOVERNED] as const) {
      const query = new URLSearchParams({ ...(await baseRequest(client)), authorization_details: JSON.stringify([MISSION_ENTRY]) });
      const { result, interactions } = await countingInteractions(() =>
        fetch(`${ISSUER}/auth?${query}`, { redirect: "manual" }),
      );
      expect(result.status, client).toBe(303);
      const redirect = clientRedirect(result.headers.get("location") ?? "");
      expect(redirect.target).toBe(REDIRECT_URI);
      expect(redirect.query.get("error"), client).toBe("invalid_request");
      expect(redirect.query.get("error_description")).toBe("Pushed Authorization Request must be used");
      expect(interactions).toBe(0);
    }
  });
});

describe("a Mission-governed client's token requests under its Mission-bound grant need no mission_intent (@spec mission#mission-governed, #1448, D585)", () => {
  it("a narrowing refresh carrying authorization_details without mission_intent issues exactly the requested subset, in the token and the response", async () => {
    const m = await issue();
    const res = await refresh(GOVERNED, m.refreshToken, m.keys, details(NARROWED));
    expectIssued(res, [READ], m.missionId);
    expect(res.body.authorization_details).toEqual(tokenEntries(res.body.access_token));
  });

  it("a narrowing code exchange carrying authorization_details without mission_intent issues exactly the requested subset", async () => {
    const keys = await newKeys();
    const res = await exchange(await approvedCode(), keys, details(NARROWED));
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expectIssued(res, [READ], missionOf(res.body.access_token));
    expect(res.body.authorization_details).toEqual(tokenEntries(res.body.access_token));
  });

  it("a widening refresh is still refused invalid_authorization_details, issuing no token", async () => {
    const m = await issue();
    expectRefused(await refresh(GOVERNED, m.refreshToken, m.keys, details(WIDENED)), "invalid_authorization_details");
  });

  it("the grant's client binding and Issuance Gating still refuse a governed client's narrowing refresh", async () => {
    const m = await issue();
    // Another client cannot present the governed client's refresh token.
    expectRefused(await refresh(UNGOVERNED, m.refreshToken, m.keys, details(NARROWED)), "invalid_grant");
    // A Mission that is not active issues nothing.
    as.kernel.transition(m.missionId, "suspend");
    const suspended = await refresh(GOVERNED, m.refreshToken, m.keys, details(NARROWED));
    expectRefused(suspended, "invalid_grant");
    expect(suspended.body.mission_error).toBe("suspended");
  });

  it("a self-exchange without mission_intent issues the delegation handle and opens a family narrowed to exactly the requested subset; a request beyond the presented token is refused invalid_authorization_details", async () => {
    const m = await issue();
    const handle = await token(GOVERNED, m.keys, delegationHandleParams(m.accessToken, GOVERNED));
    expectIssued(handle, [LIST, READ], m.missionId);
    const familyParams = (entries: unknown[]) => ({
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      request_refresh_token: "true",
      subject_token: handle.body.access_token as string,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      resource: RESOURCE,
      creation_request_id: crypto.randomUUID(),
      ...details(entries),
    });
    expectIssued(await token(GOVERNED, m.keys, familyParams(NARROWED)), [READ], m.missionId);
    expectRefused(await token(GOVERNED, m.keys, familyParams(WIDENED)), "invalid_authorization_details");
  });

  it("a governed client's designation and a governed delegate's delegated exchange are issued without mission_intent, each within the presented authority; a designation proven under another key is refused", async () => {
    const m = await issue();
    const designationParams = {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      subject_token: m.accessToken,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      audience: DELEGATE,
    };
    // Possession of the presented token's own key still applies.
    expectRefused(await token(GOVERNED, await newKeys(), designationParams), "invalid_request");

    const designation = await token(GOVERNED, m.keys, designationParams);
    expectIssued(designation, [LIST, READ], m.missionId);
    expect(decodeJwt(designation.body.access_token as string).aud).toBe(DELEGATE);

    const delegated = await token(DELEGATE, await newKeys(), {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      subject_token: designation.body.access_token as string,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      resource: RESOURCE,
    });
    expectIssued(delegated, [LIST, READ], m.missionId);
    expect((decodeJwt(delegated.body.access_token as string).act as { sub: string }).sub).toBe(DELEGATE);
  });
});
