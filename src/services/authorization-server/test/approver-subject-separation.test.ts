/**
 * @spec mission#approval-authentication, mission#approval-event (step 2),
 * mission#mission-bound-tokens (#826): the Approver who authenticates and the
 * Mission's Subject are separate identities over the real AS assembly. The
 * Subject is the one the trusted approval surface selected; the provider
 * account and session are the Approver's; every Mission-bound token carries
 * the Subject; and `openid` is available only when one End-User both
 * authenticated in this user agent and is the Subject.
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

let as: BuiltAs;
let server: Server;
const keys: Record<string, CryptoKey> = {};

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: SESSIONS,
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

/**
 * One authorization in its own user agent (`jar`, fresh unless given): PAR,
 * the trusted approval, and the redirect's code or error.
 */
async function authorize(args: {
  client?: "ap-agent" | "governed-agent";
  scope?: string;
  extra?: Record<string, string>;
  decideHeaders?: Record<string, string>;
  approval: Approval;
  jar?: Jar;
}): Promise<{ code?: string; error?: string; jar: Jar; decideStatus: number }> {
  const client = args.client ?? "ap-agent";
  const jar = args.jar ?? new Map<string, string>();
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER))).toString("base64url");
  const par = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: client,
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: RESOURCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      ...(args.scope ? { scope: args.scope } : {}),
      ...(args.extra ?? {}),
      mission_intent: JSON.stringify({
        intent: { goal: "Read Acme invoices", target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" },
      }),
      authorization_details: JSON.stringify(READ),
      client_assertion: await clientAssertion(client),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  expect(par.status, await par.clone().text()).toBe(201);
  const { request_uri } = (await par.json()) as { request_uri: string };
  let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: client, request_uri })}`, { redirect: "manual" });
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
    body: JSON.stringify({ decision: "approve" }),
  });
  const decideStatus = res.status;
  keep(jar, res);
  location = res.headers.get("location") ?? "";
  while (location.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieOf(jar) } });
    keep(jar, res);
    location = res.headers.get("location") ?? "";
  }
  const q = location ? new URL(location).searchParams : new URLSearchParams();
  return {
    jar,
    decideStatus,
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

describe("Approver and Subject stay separate identities (@spec mission#approval-authentication, #826)", () => {
  it("refuses openid invalid_scope when the Approver is not the Subject, leaving no Mission, grant, code or session for the Subject", async () => {
    for (const approval of [
      { browser: { sub: "bob", subject: "alice" } },
      { headless: { sub: "bob", subject: "alice" } },
    ] as Approval[]) {
      const before = as.kernel.allMissions().length;
      const r = await authorize({ scope: "openid", approval });
      expect(r.error).toBe("invalid_scope");
      expect(r.code).toBeUndefined();
      expect(as.kernel.allMissions()).toHaveLength(before);
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
    expect(record?.approver).toEqual({ iss: ISSUER, sub: "bob" });
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

  it("approves an organizational workload Subject: the token carries the workload, and the only authentication is the Approver's", async () => {
    const r = await authorize({ client: "governed-agent", approval: { headless: { sub: "bob", subject: "acme-accounts-payable" } } });
    expect(r.code, r.error).toBeTruthy();
    const session = await sessionOf(r.jar);
    expect(session?.accountId).toBe("bob");
    // A headless approval logs the Approver in only transiently: this user
    // agent is the client's, not Bob's.
    expect(sessionLines.get(r.jar)?.toLowerCase()).not.toContain("expires=");
    const issued = await redeem("governed-agent", r.code as string, await newKeys());
    const at = decodeJwt(issued.access_token as string);
    expect(at.sub).toBe("acme-accounts-payable");
    expect(as.kernel.get((at.mission as { id: string }).id)?.authority_source.type).toBe("organizational");
    // And a workload Subject never yields an ID Token.
    const refused = await authorize({ client: "governed-agent", scope: "openid", approval: { browser: { sub: "bob", subject: "acme-accounts-payable" } } });
    expect(refused.error).toBe("invalid_scope");
  });

  it("an Alice session established before Bob approves for her is never refreshed by Bob's act", async () => {
    const aliceTime = Math.floor(Date.now() / 1000) - 600;
    const first = await authorize({ scope: "openid", approval: { browser: { sub: "alice", acr: "mfa", auth_time: aliceTime } } });
    expect(first.code, first.error).toBeTruthy();
    expect((await sessionOf(first.jar))?.loginTs).toBe(aliceTime);
    // Bob approves for Alice in the same user agent. Whatever the provider
    // does with the existing session, Alice's authentication is not renewed.
    await authorize({ approval: { headless: { sub: "bob", subject: "alice" } }, jar: first.jar });
    const after = await sessionOf(first.jar);
    expect(after?.accountId === "alice" ? after.loginTs : aliceTime).toBe(aliceTime);
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
    const browser = await authorize({
      approval: { browser: { sub: "bob" } },
      decideHeaders: { [APPROVAL_SUBJECT_HEADER]: "alice" },
    });
    expect(browser.code, browser.error).toBeTruthy();
    const record = as.kernel.allMissions().at(-1);
    expect(record?.subject.sub).toBe("bob");
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
