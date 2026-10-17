/**
 * @spec mission#approval-authentication, mission#approval-event (step 2),
 * mission#mission-bound-tokens (#826): the Approver who authenticates and the
 * Mission's Subject are separate identities over the real AS assembly. The
 * Subject is the one the trusted approval surface selected; the provider
 * account is the Approver's, and so is the session of a browser approval,
 * while a headless approval leaves the client's user agent no session at
 * all; every Mission-bound token carries the Subject; and `openid` is
 * available only when one End-User both authenticated in this user agent and
 * is the Subject.
 */

import { type Server } from "node:http";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { decodeJwt, exportJWK, generateKeyPair, importJWK, SignJWT, type CryptoKey, type JWK } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { accountFinder } from "../src/adapters/provider.js";
import { APPROVAL_SUBJECT_HEADER, ApprovalSessionStore, buildAuthorizationServer, type BuiltAs } from "../src/index.js";
import { browserApprovalHeaders, TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";

const PORT = 14771;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource as string;
const VERIFIER = "approver-subject-separation-verifier-0123456789-01";
const RS_PAYMENTS = ["rs-payments", "dev-introspection-rs-payments"] as const;
const READ = [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] }];
const SESSIONS = new ApprovalSessionStore();
/**
 * Clients registered with an OIDC authentication default (D305 item 5): each
 * asks for an Approver strength a delegated approval cannot carry.
 */
const DEFAULT_CLIENTS = {
  "ap-agent-default-acr": { default_acr_values: ["mfa"] },
  "ap-agent-default-max-age": { default_max_age: 300 },
  "ap-agent-require-auth-time": { require_auth_time: true },
} as const;
type ClientId = "ap-agent" | "governed-agent" | keyof typeof DEFAULT_CLIENTS;

let as: BuiltAs;
let server: Server;
const keys: Record<string, CryptoKey> = {};

beforeAll(async () => {
  const testClients: Record<string, unknown>[] = [];
  for (const [clientId, defaults] of Object.entries(DEFAULT_CLIENTS)) {
    const pair = await generateKeyPair("ES256", { extractable: true });
    keys[clientId] = pair.privateKey as CryptoKey;
    testClients.push({
      client_id: clientId,
      client_name: `AP Agent with ${Object.keys(defaults)[0]}`,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      redirect_uris: [REDIRECT_URI],
      token_endpoint_auth_method: "private_key_jwt",
      token_endpoint_auth_signing_alg: "ES256",
      scope: "openid profile email",
      authorization_details_types: ["mission_resource_access"],
      jwks: { keys: [{ ...(await exportJWK(pair.publicKey)), kid: `${clientId}-auth`, alg: "ES256" }] },
      ...defaults,
    });
  }
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: SESSIONS,
    testClients,
  });
  server = as.provider.listen(PORT);
  keys["ap-agent"] = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  keys["governed-agent"] = (await importJWK(as.governedClientJwk as never, "ES256")) as CryptoKey;
});

afterAll(() => {
  server?.close();
});

type Jar = Map<string, string>;
const cookieOf = (jar: Jar) => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
// The raw Set-Cookie line of the provider session, per jar: a remembered
// login carries an expiry, a transient one does not.
const sessionLines = new WeakMap<Jar, string>();
const keep = (jar: Jar, res: Response) => {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
    if ((pair as string).startsWith("_session=")) sessionLines.set(jar, line);
  }
};

const clientAssertion = (client: string) =>
  new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: `${client}-auth` })
    .setIssuer(client)
    .setSubject(client)
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(keys[client] as CryptoKey);

type Approval =
  | { browser: { sub: string; acr?: string; auth_time?: number; subject?: string } }
  | { headless: { sub: string; subject: string | null } };

/** A pushed authorization request for the Read Acme invoices Mission. */
async function push(client: ClientId, extra: Record<string, string>): Promise<Response> {
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER))).toString("base64url");
  return fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: client,
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: RESOURCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      ...extra,
      mission_intent: JSON.stringify({
        intent: { goal: "Read Acme invoices", target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" },
      }),
      authorization_details: JSON.stringify(READ),
      client_assertion: await clientAssertion(client),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
}

/**
 * One authorization in its own user agent (`jar`, fresh unless given): PAR,
 * the trusted approval, and the redirect's code or error.
 */
async function authorize(args: {
  client?: ClientId;
  scope?: string;
  extra?: Record<string, string>;
  decideHeaders?: Record<string, string>;
  approval: Approval;
  jar?: Jar;
  /** The approval surface's decision; `approve` unless given. */
  decision?: string;
  /** Rewrites the resume request (the first redirect back into the issuer after the decision). */
  resume?: { url?: (location: string) => string; method?: string };
  /** Runs after the decision, immediately before the resume. */
  beforeResume?: () => Promise<void>;
}): Promise<{ code?: string; error?: string; jar: Jar; decideStatus: number; resumeCookies: string[] }> {
  const client = args.client ?? "ap-agent";
  const jar = args.jar ?? new Map<string, string>();
  const par = await push(client, { ...(args.scope ? { scope: args.scope } : {}), ...(args.extra ?? {}) });
  expect(par.status, await par.clone().text()).toBe(201);
  const { request_uri } = (await par.json()) as { request_uri: string };
  let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: client, request_uri })}`, {
    redirect: "manual",
    headers: { cookie: cookieOf(jar) },
  });
  keep(jar, res);
  let location = res.headers.get("location") ?? "";
  const uid = location.split("/interaction/")[1] as string;
  const headers =
    "browser" in args.approval
      ? browserApprovalHeaders(SESSIONS, uid, args.approval.browser, cookieOf(jar))
      : { ...trustedApprovalHeaders(args.approval.headless.sub, {}, args.approval.headless.subject), cookie: cookieOf(jar) };
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...headers, ...(args.decideHeaders ?? {}), "content-type": "application/json" },
    body: JSON.stringify({ decision: args.decision ?? "approve" }),
  });
  const decideStatus = res.status;
  keep(jar, res);
  location = res.headers.get("location") ?? "";
  await args.beforeResume?.();
  const resumeCookies: string[] = [];
  let first = true;
  while (location.startsWith(ISSUER)) {
    const url = first && args.resume?.url ? args.resume.url(location) : location;
    const method = first && args.resume?.method ? args.resume.method : "GET";
    first = false;
    res = await fetch(url, { method, redirect: "manual", headers: { cookie: cookieOf(jar) } });
    resumeCookies.push(...res.headers.getSetCookie());
    keep(jar, res);
    location = res.headers.get("location") ?? "";
  }
  const q = location ? new URL(location).searchParams : new URLSearchParams();
  return {
    jar,
    decideStatus,
    resumeCookies,
    ...(q.get("code") ? { code: q.get("code") as string } : {}),
    ...(q.get("error") ? { error: q.get("error") as string } : {}),
  };
}

type Keys = { privateKey: CryptoKey; jwk: JWK };
const newKeys = async (): Promise<Keys> => {
  const pair = await generateKeyPair("ES256", { extractable: true });
  return { privateKey: pair.privateKey as CryptoKey, jwk: await exportJWK(pair.publicKey) };
};

/** The token endpoint with DPoP (one nonce retry) and client authentication. */
async function token(client: string, params: Record<string, string>, k: Keys): Promise<Record<string, unknown>> {
  const htu = `${ISSUER}/token`;
  const proof = (nonce?: string) =>
    new SignJWT({ htu, htm: "POST", ...(nonce ? { nonce } : {}) })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: k.jwk })
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .sign(k.privateKey);
  const send = async (nonce?: string) =>
    fetch(htu, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await proof(nonce) },
      body: new URLSearchParams({
        ...params,
        client_assertion: await clientAssertion(client),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send(nonce);
  const body = (await res.json()) as Record<string, unknown>;
  expect(res.status, JSON.stringify(body)).toBe(200);
  return body;
}

/** One token request with DPoP (one nonce retry), returning the status and body unasserted. */
async function tokenAttempt(client: string, params: Record<string, string>, k: Keys): Promise<{ status: number; body: Record<string, unknown> }> {
  const htu = `${ISSUER}/token`;
  const send = async (nonce?: string) =>
    fetch(htu, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        dpop: await new SignJWT({ htu, htm: "POST", ...(nonce ? { nonce } : {}) })
          .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: k.jwk })
          .setIssuedAt()
          .setJti(crypto.randomUUID())
          .sign(k.privateKey),
      },
      body: new URLSearchParams({
        ...params,
        client_assertion: await clientAssertion(client),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send(nonce);
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

const redeem = (client: string, code: string, k: Keys) =>
  token(client, { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: VERIFIER, resource: RESOURCE }, k);

async function introspect(tokenValue: string): Promise<Record<string, unknown>> {
  const res = await fetch(`${ISSUER}/introspect`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${Buffer.from(`${RS_PAYMENTS[0]}:${RS_PAYMENTS[1]}`).toString("base64")}`,
    },
    body: new URLSearchParams({ token: tokenValue }).toString(),
  });
  expect(res.status).toBe(200);
  return (await res.json()) as Record<string, unknown>;
}

/** The provider session this user agent holds, or undefined. */
async function sessionOf(jar: Jar): Promise<{ accountId?: string; loginTs?: number; acr?: string } | undefined> {
  const id = jar.get("_session");
  if (!id) return undefined;
  return (await as.provider.Session.find(id)) as { accountId?: string; loginTs?: number; acr?: string } | undefined;
}

type StoredSession = { accountId?: string; loginTs?: number; acr?: string; exp?: number };

/**
 * An Alice session from a browser self-approval, then Bob's headless act for
 * her in the same user agent. Only the act's resume is observed: the session
 * saves it causes and the session cookies it sends. The authorization request
 * before it is the client's own and loads Alice's session as usual.
 */
async function aliceSessionThrough(act: { scope?: string; decision?: string; resume?: { url?: (location: string) => string; method?: string } }) {
  const aliceTime = Math.floor(Date.now() / 1000) - 600;
  const first = await authorize({ scope: "openid", approval: { browser: { sub: "alice", acr: "mfa", auth_time: aliceTime } } });
  expect(first.code, first.error).toBeTruthy();
  const aliceSession = first.jar.get("_session") as string;
  expect(((await as.provider.Session.find(aliceSession)) as StoredSession | undefined)?.loginTs).toBe(aliceTime);
  const saved: string[] = [];
  const onSaved = (s: { id?: string }) => {
    if (s.id) saved.push(s.id);
  };
  let expBefore: number | undefined;
  let bob: Awaited<ReturnType<typeof authorize>>;
  try {
    bob = await authorize({
      ...act,
      approval: { headless: { sub: "bob", subject: "alice" } },
      jar: first.jar,
      beforeResume: async () => {
        expBefore = ((await as.provider.Session.find(aliceSession)) as StoredSession | undefined)?.exp;
        as.provider.on("session.saved", onSaved);
      },
    });
  } finally {
    as.provider.off("session.saved", onSaved);
  }
  const after = (await as.provider.Session.find(aliceSession)) as StoredSession | undefined;
  return { bob, jar: first.jar, aliceSession, aliceTime, saved, expBefore, after };
}

/** Alice's session is as she left it: Bob's resume neither saved it nor sent a session cookie. */
function expectAliceUntouched(o: Awaited<ReturnType<typeof aliceSessionThrough>>): void {
  expect(o.saved).not.toContain(o.aliceSession);
  expect(o.bob.resumeCookies.filter((l) => /^_session(?:\.sig)?=/.test(l))).toEqual([]);
  expect(o.jar.get("_session")).toBe(o.aliceSession);
  expect(o.expBefore).toBeDefined();
  expect(o.after?.exp).toBe(o.expBefore);
  expect(o.after?.accountId).toBe("alice");
  expect(o.after?.loginTs).toBe(o.aliceTime);
  expect(o.after?.acr).toBe("mfa");
}

describe("Approver and Subject stay separate identities (@spec mission#approval-authentication, #826)", () => {
  it("refuses openid invalid_scope when the Approver is not the Subject, leaving no Mission, grant, code or session for the Subject", async () => {
    for (const approval of [
      { browser: { sub: "bob", subject: "alice" } },
      { headless: { sub: "bob", subject: "alice" } },
    ] as Approval[]) {
      const before = as.kernel.allMissions().length;
      let grants = 0;
      const onGrant = () => {
        grants += 1;
      };
      as.provider.on("grant.saved", onGrant);
      let r: Awaited<ReturnType<typeof authorize>>;
      try {
        r = await authorize({ scope: "openid", approval });
      } finally {
        as.provider.off("grant.saved", onGrant);
      }
      expect(r.error).toBe("invalid_scope");
      expect(r.code).toBeUndefined();
      expect(as.kernel.allMissions()).toHaveLength(before);
      expect(grants).toBe(0);
      // No authentication session for Alice arose from Bob's approval.
      expect((await sessionOf(r.jar))?.accountId).not.toBe("alice");
    }
  });

  it("approves for another principal without openid: the token and introspection carry the Subject, the record the Approver, and the provider account and session the Approver", async () => {
    const authTime = Math.floor(Date.now() / 1000) - 90;
    const r = await authorize({ approval: { browser: { sub: "bob", acr: "mfa", auth_time: authTime, subject: "alice" } } });
    expect(r.code, r.error).toBeTruthy();
    // The session is Bob's own, with his achieved authentication, never Alice's.
    const session = await sessionOf(r.jar);
    expect(session?.accountId).toBe("bob");
    expect(session?.loginTs).toBe(authTime);
    expect(session?.acr).toBe("mfa");
    expect(sessionLines.get(r.jar)?.toLowerCase()).toContain("expires=");

    const k = await newKeys();
    const issued = await redeem("ap-agent", r.code as string, k);
    expect(issued.id_token).toBeUndefined();
    const at = decodeJwt(issued.access_token as string);
    expect(at.sub).toBe("alice");
    const missionId = (at.mission as { id: string }).id;
    const record = as.kernel.get(missionId);
    expect(record?.subject).toEqual({ iss: ISSUER, sub: "alice" });
    expect(record?.approval_basis.consent_principal).toEqual({ iss: ISSUER, sub: "bob" });
    // The provider grant belongs to the account that authenticated.
    const grant = (await as.provider.Grant.find(record?.grant_id as string)) as { accountId?: string };
    expect(grant.accountId).toBe("bob");
    expect((await introspect(issued.access_token as string)).sub).toBe("alice");

    // UserInfo never answers about Alice on Bob's approval.
    const userinfoUrl = `${ISSUER}/me`;
    const ath = Buffer.from(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(issued.access_token as string)),
    ).toString("base64url");
    const userinfo = await fetch(userinfoUrl, {
      headers: {
        authorization: `DPoP ${issued.access_token as string}`,
        dpop: await new SignJWT({ htu: userinfoUrl, htm: "GET", ath })
          .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: k.jwk })
          .setIssuedAt()
          .setJti(crypto.randomUUID())
          .sign(k.privateKey),
      },
    });
    expect(userinfo.status).not.toBe(200);
    expect(await userinfo.text()).not.toContain('"sub":"alice"');

    // Refresh keeps the distinction: the new access token and the refresh
    // token's introspection both carry the Subject.
    const refreshed = await token("ap-agent", { grant_type: "refresh_token", refresh_token: issued.refresh_token as string }, k);
    expect(decodeJwt(refreshed.access_token as string).sub).toBe("alice");
    expect((await introspect(issued.refresh_token as string)).sub).toBe("alice");
  });

  it("self-approval keeps OIDC: the ID Token, the token and the session agree on the one End-User, with the achieved authentication time", async () => {
    const authTime = Math.floor(Date.now() / 1000) - 120;
    // max_age asks for auth_time in the ID Token (OpenID Connect Core 3.1.2.1).
    const r = await authorize({
      scope: "openid",
      extra: { max_age: "3600" },
      approval: { browser: { sub: "alice", acr: "mfa", auth_time: authTime } },
    });
    expect(r.code, r.error).toBeTruthy();
    const issued = await redeem("ap-agent", r.code as string, await newKeys());
    const idToken = decodeJwt(issued.id_token as string);
    expect(idToken.sub).toBe("alice");
    // The approval click is not an authentication: auth_time is the login's.
    expect(idToken.auth_time).toBe(authTime);
    expect(decodeJwt(issued.access_token as string).sub).toBe("alice");
    expect((await sessionOf(r.jar))?.accountId).toBe("alice");
  });

  it("refuses openid on a headless approval even for the Approver's own Mission: no End-User authenticated in this user agent", async () => {
    const before = as.kernel.allMissions().length;
    const r = await authorize({ scope: "openid", approval: { headless: { sub: "alice", subject: null } } });
    expect(r.error).toBe("invalid_scope");
    expect(as.kernel.allMissions()).toHaveLength(before);
  });

  it("approves an organizational workload Subject: the token carries the workload, and the approval leaves no authentication session", async () => {
    const r = await authorize({ client: "governed-agent", approval: { headless: { sub: "bob", subject: "acme-accounts-payable" } } });
    expect(r.code, r.error).toBeTruthy();
    expect(r.jar.has("_session")).toBe(false);
    const issued = await redeem("governed-agent", r.code as string, await newKeys());
    const at = decodeJwt(issued.access_token as string);
    expect(at.sub).toBe("acme-accounts-payable");
    expect(as.kernel.get((at.mission as { id: string }).id)?.authority_source.type).toBe("organizational");
    // And a workload Subject never yields an ID Token.
    const refused = await authorize({ client: "governed-agent", scope: "openid", approval: { browser: { sub: "bob", subject: "acme-accounts-payable" } } });
    expect(refused.error).toBe("invalid_scope");
  });

  it("a headless approval leaves the client's user agent no End-User session: the resume's login is destroyed and never delivered, and the code still redeems and refreshes", async () => {
    // oidc-provider finishes the interaction through a login; capture the
    // session that login wrote, to show it does not outlive the response.
    const resumed: string[] = [];
    const onSuccess = (ctx: { oidc: { session?: { id?: string; accountId?: string } } }) => {
      if (ctx.oidc.session?.accountId === "bob" && ctx.oidc.session.id) resumed.push(ctx.oidc.session.id);
    };
    as.provider.on("authorization.success", onSuccess);
    let r: Awaited<ReturnType<typeof authorize>>;
    try {
      r = await authorize({ approval: { headless: { sub: "bob", subject: "alice" } } });
    } finally {
      as.provider.off("authorization.success", onSuccess);
    }
    expect(r.code, r.error).toBeTruthy();
    expect(resumed).toHaveLength(1);
    expect(await as.provider.Session.find(resumed[0] as string)).toBeUndefined();
    expect(r.jar.has("_session")).toBe(false);
    expect(sessionLines.get(r.jar)).toBeUndefined();
    // The code is not bound to the session that no longer exists.
    const k = await newKeys();
    const issued = await redeem("ap-agent", r.code as string, k);
    expect(decodeJwt(issued.access_token as string).sub).toBe("alice");
    const refreshed = await token("ap-agent", { grant_type: "refresh_token", refresh_token: issued.refresh_token as string }, k);
    expect(decodeJwt(refreshed.access_token as string).sub).toBe("alice");
  });

  // oidc-provider's router accepts more than the canonical `/auth/<uid>`: it
  // is not strict about a trailing slash, matches case-insensitively, serves
  // HEAD on the GET route, and resumes the interaction its resume cookie names
  // whatever uid the path carries. A client that owns the user agent can send
  // any of these, so the teardown must hold for every resume the provider
  // accepts, not only the canonical path.
  it.each([
    ["a trailing slash", { url: (l: string) => `${l}/` }],
    ["an uppercase path", { url: (l: string) => l.replace("/auth/", "/AUTH/") }],
    ["a different path uid", { url: (l: string) => l.replace(/\/auth\/[^/?]+/, "/auth/not-the-interaction") }],
    ["a HEAD request", { method: "HEAD" }],
  ] as const)("a headless resume through %s still leaves the client's user agent no End-User session", async (_form, resume) => {
    const resumed: string[] = [];
    const onSuccess = (ctx: { oidc: { session?: { id?: string; accountId?: string } } }) => {
      if (ctx.oidc.session?.accountId === "bob" && ctx.oidc.session.id) resumed.push(ctx.oidc.session.id);
    };
    as.provider.on("authorization.success", onSuccess);
    let r: Awaited<ReturnType<typeof authorize>>;
    try {
      r = await authorize({ approval: { headless: { sub: "bob", subject: "alice" } }, resume });
    } finally {
      as.provider.off("authorization.success", onSuccess);
    }
    // Whether or not this form completes the authorization, no session the
    // resume's login wrote survives it, and none reaches the user agent.
    for (const id of resumed) expect(await as.provider.Session.find(id)).toBeUndefined();
    expect(r.jar.has("_session")).toBe(false);
    expect(sessionLines.get(r.jar)).toBeUndefined();
  });

  it("an Alice session established before Bob approves for her is neither read nor refreshed by Bob's headless act, which still completes", async () => {
    // Bob approves for Alice in the same user agent: the resume never sees
    // Alice's session, so it neither asks to end it nor renews it.
    const o = await aliceSessionThrough({});
    expect(o.bob.code, o.bob.error).toBeTruthy();
    expectAliceUntouched(o);
  });

  it.each([
    ["an openid refusal", { scope: "openid" }, "invalid_scope"],
    ["a denial", { decision: "deny" }, "access_denied"],
  ] as const)("Bob's headless act ending in %s neither reads nor refreshes an Alice session, and leaves a fresh user agent no session", async (_end, act, error) => {
    const o = await aliceSessionThrough(act);
    expect(o.bob.error).toBe(error);
    expect(o.bob.code).toBeUndefined();
    expectAliceUntouched(o);
    // In a user agent with no session, the refused act leaves none.
    const fresh = await authorize({ ...act, approval: { headless: { sub: "bob", subject: "alice" } } });
    expect(fresh.error).toBe(error);
    expect(fresh.jar.has("_session")).toBe(false);
    expect(fresh.resumeCookies.filter((l) => /^_session(?:\.sig)?=/.test(l))).toEqual([]);
  });

  it.each([
    ["a trailing slash", { url: (l: string) => `${l}/` }],
    ["an uppercase path", { url: (l: string) => l.replace("/auth/", "/AUTH/") }],
    ["a different path uid", { url: (l: string) => l.replace(/\/auth\/[^/?]+/, "/auth/not-the-interaction") }],
    ["a HEAD request", { method: "HEAD" }],
  ] as const)("a refused headless resume through %s neither reads nor refreshes an Alice session", async (_form, resume) => {
    expectAliceUntouched(await aliceSessionThrough({ scope: "openid", resume }));
  });

  it("a later prompt=none request naming the Subject is not satisfied by another principal's approval", async () => {
    const approved = await authorize({ approval: { headless: { sub: "bob", subject: "alice" } } });
    expect(approved.code, approved.error).toBeTruthy();
    // The same user agent now asks to be authorized silently as Alice. Bob's
    // approval established no session for her, and every Mission request
    // needs its own approval, so nothing is issued silently.
    const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER))).toString("base64url");
    const par = await fetch(`${ISSUER}/request`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: "ap-agent",
        response_type: "code",
        redirect_uri: REDIRECT_URI,
        resource: RESOURCE,
        code_challenge: challenge,
        code_challenge_method: "S256",
        scope: "openid",
        prompt: "none",
        login_hint: "alice",
        mission_intent: JSON.stringify({
          intent: { goal: "Read Acme invoices", target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" },
        }),
        authorization_details: JSON.stringify(READ),
        client_assertion: await clientAssertion("ap-agent"),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
    expect(par.status, await par.clone().text()).toBe(201);
    const { request_uri } = (await par.json()) as { request_uri: string };
    let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`, {
      redirect: "manual",
      headers: { cookie: cookieOf(approved.jar) },
    });
    let location = res.headers.get("location") ?? "";
    while (location.startsWith(ISSUER)) {
      res = await fetch(location, { redirect: "manual", headers: { cookie: cookieOf(approved.jar) } });
      location = res.headers.get("location") ?? "";
    }
    const q = new URL(location).searchParams;
    expect(q.get("code")).toBeNull();
    expect(q.get("error")).toBeTruthy();
  });

  it("refuses a Subject selection the Approver may not approve for, and ignores a client's login_hint, before any Mission", async () => {
    const before = as.kernel.allMissions().length;
    const tampered = await authorize({ approval: { headless: { sub: "alice", subject: "bob" } } });
    expect(tampered.decideStatus).toBe(403);
    const unknown = await authorize({ approval: { headless: { sub: "bob", subject: "mallory" } } });
    expect(unknown.decideStatus).toBe(403);
    expect(as.kernel.allMissions()).toHaveLength(before);
    // The header is the headless service's channel only: on a browser
    // session it selects nothing, and the session's own selection stands.
    // Nor does the client's login_hint naming Alice select her.
    const browser = await authorize({
      extra: { login_hint: "alice" },
      approval: { browser: { sub: "bob" } },
      decideHeaders: { [APPROVAL_SUBJECT_HEADER]: "alice" },
    });
    expect(browser.code, browser.error).toBeTruthy();
    const issued = await redeem("ap-agent", browser.code as string, await newKeys());
    const missionId = (decodeJwt(issued.access_token as string).mission as { id: string }).id;
    expect(as.kernel.get(missionId)?.subject.sub).toBe("bob");
  });

  it("a delegated request cannot ask for the Approver's acr_values or max_age: without openid, PAR refuses them invalid_request before any interaction", async () => {
    for (const extra of [{ acr_values: "mfa" }, { max_age: "300" }]) {
      const par = await push("ap-agent", extra);
      expect(par.status).toBe(400);
      expect(((await par.json()) as { error?: string }).error).toBe("invalid_request");
    }
  });

  it("self-approval keeps one End-User across a hint, a later prompt=none and a request without openid, and UserInfo refuses the Mission-bound token", async () => {
    const authTime = Math.floor(Date.now() / 1000) - 120;
    // A login_hint concerns the Approver who authenticates (D158): one naming
    // Bob neither changes who authenticated nor selects the Subject.
    // max_age asks for auth_time in the ID Token (OpenID Connect Core 3.1.2.1).
    const hinted = await authorize({
      scope: "openid",
      extra: { login_hint: "bob", max_age: "3600" },
      approval: { browser: { sub: "alice", acr: "mfa", auth_time: authTime } },
    });
    expect(hinted.code, hinted.error).toBeTruthy();
    const k = await newKeys();
    const issued = await redeem("ap-agent", hinted.code as string, k);
    expect(decodeJwt(issued.id_token as string).sub).toBe("alice");
    expect(decodeJwt(issued.id_token as string).auth_time).toBe(authTime);
    expect(decodeJwt(issued.access_token as string).sub).toBe("alice");
    const session = await sessionOf(hinted.jar);
    expect(session?.accountId).toBe("alice");
    expect(session?.loginTs).toBe(authTime);
    expect(session?.acr).toBe("mfa");

    // UserInfo does not accept the Mission-bound access token, which is
    // audienced to the resource, so it never asserts another End-User.
    const userinfoUrl = `${ISSUER}/me`;
    const ath = Buffer.from(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(issued.access_token as string)),
    ).toString("base64url");
    const userinfo = await fetch(userinfoUrl, {
      headers: {
        authorization: `DPoP ${issued.access_token as string}`,
        dpop: await new SignJWT({ htu: userinfoUrl, htm: "GET", ath })
          .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: k.jwk })
          .setIssuedAt()
          .setJti(crypto.randomUUID())
          .sign(k.privateKey),
      },
    });
    expect(userinfo.status).toBe(401);

    // A later prompt=none request in Alice's user agent is not satisfied by
    // her session: every Mission needs its own approval. Her session stands.
    const before = as.kernel.allMissions().length;
    const par = await push("ap-agent", { scope: "openid", prompt: "none" });
    expect(par.status).toBe(201);
    const { request_uri } = (await par.json()) as { request_uri: string };
    let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`, {
      redirect: "manual",
      headers: { cookie: cookieOf(hinted.jar) },
    });
    let location = res.headers.get("location") ?? "";
    while (location.startsWith(ISSUER)) {
      res = await fetch(location, { redirect: "manual", headers: { cookie: cookieOf(hinted.jar) } });
      location = res.headers.get("location") ?? "";
    }
    const q = new URL(location).searchParams;
    expect(q.get("code")).toBeNull();
    expect(q.get("error")).toBe("consent_required");
    expect(as.kernel.allMissions()).toHaveLength(before);
    const after = await sessionOf(hinted.jar);
    expect(after?.accountId).toBe("alice");
    expect(after?.loginTs).toBe(authTime);

    // Without openid, a self-approval still issues no ID Token, while the
    // session and the token name the one End-User.
    const plain = await authorize({ approval: { browser: { sub: "alice", acr: "mfa", auth_time: authTime } } });
    expect(plain.code, plain.error).toBeTruthy();
    const plainIssued = await redeem("ap-agent", plain.code as string, await newKeys());
    expect(plainIssued.id_token).toBeUndefined();
    expect(decodeJwt(plainIssued.access_token as string).sub).toBe("alice");
    expect((await sessionOf(plain.jar))?.accountId).toBe("alice");
  });

  it("does not support the claims parameter: discovery says so, and a request carrying an essential acr gets no essential-claim treatment (a disclosed limitation)", async () => {
    const discovery = (await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
    expect(discovery.claims_parameter_supported).toBe(false);
    const claims = JSON.stringify({ id_token: { acr: { essential: true, values: ["urn:example:acr:strong"] } } });
    const r = await authorize({
      scope: "openid",
      extra: { claims },
      approval: { browser: { sub: "alice", acr: "mfa", auth_time: Math.floor(Date.now() / 1000) - 60 } },
    });
    expect(r.code, r.error).toBeTruthy();
    const idToken = decodeJwt((await redeem("ap-agent", r.code as string, await newKeys())).id_token as string);
    expect(idToken.sub).toBe("alice");
    expect(idToken.acr).toBeUndefined();
  });

  // This AS configures no acr values, so oidc-provider holds a registration
  // naming default_acr_values invalid: such a client is refused outright,
  // with or without openid, before any interaction.
  it("a client registered with default_acr_values is refused invalid_client_metadata on every request, before any interaction, creating nothing", async () => {
    const before = as.kernel.allMissions().length;
    for (const extra of [{}, { scope: "openid" }]) {
      const par = await push("ap-agent-default-acr", extra);
      expect(par.status).toBe(400);
      expect(((await par.json()) as { error?: string }).error).toBe("invalid_client_metadata");
    }
    expect(as.kernel.allMissions()).toHaveLength(before);
  });

  it.each(["ap-agent-default-max-age", "ap-agent-require-auth-time"] as const)(
    "a client registered with an authentication default (%s) cannot have it honored on a delegated approval: without openid PAR refuses, with openid the delegated approval refuses, creating nothing",
    async (clientId) => {
      const par = await push(clientId, {});
      expect(par.status).toBe(400);
      const body = (await par.json()) as { error?: string; error_description?: string };
      expect(body.error).toBe("invalid_request");
      expect(body.error_description).toMatch(/openid scope must be requested for clients with/);
      const before = as.kernel.allMissions().length;
      const r = await authorize({ client: clientId, scope: "openid", approval: { browser: { sub: "bob", subject: "alice" } } });
      expect(r.error).toBe("invalid_scope");
      expect(r.code).toBeUndefined();
      expect(as.kernel.allMissions()).toHaveLength(before);
    },
  );

  it("a code whose Mission is gone before its first redemption is refused invalid_grant and issues no token", async () => {
    const before = new Set(as.kernel.allMissions().map((m) => m.id));
    const r = await authorize({ approval: { headless: { sub: "bob", subject: "alice" } } });
    expect(r.code, r.error).toBeTruthy();
    const created = as.kernel.allMissions().filter((m) => !before.has(m.id));
    expect(created).toHaveLength(1);
    as.kernel.db.prepare("DELETE FROM missions WHERE id = ?").run(created[0]!.id);
    expect(as.kernel.get(created[0]!.id)).toBeUndefined();
    const res = await tokenAttempt(
      "ap-agent",
      { grant_type: "authorization_code", code: r.code as string, redirect_uri: REDIRECT_URI, code_verifier: VERIFIER, resource: RESOURCE },
      await newKeys(),
    );
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_grant");
    expect(res.body.access_token).toBeUndefined();
  });

  it("knows no account for an id outside the deployment, and no profile for a workload principal", async () => {
    const find = accountFinder(new Set(["alice", "bob", "acme-accounts-payable"]));
    expect(await find({}, "mallory")).toBeUndefined();
    const workload = await find({}, "acme-accounts-payable");
    expect(await workload?.claims()).toEqual({ sub: "acme-accounts-payable" });
    const user = await find({}, "bob");
    expect((await user?.claims())?.email).toBeTruthy();
  });
});
