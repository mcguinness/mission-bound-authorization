/**
 * @spec mission#approval-authentication (#1320, D496): the approval
 * surface's Approver login as an OpenID Connect relying party, over HTTP on
 * the real AS assembly. The upstream provider here is a stub the test
 * controls: it answers the authorization request with a code, checks the
 * client's credentials and PKCE at its token endpoint, and returns the ID
 * Token each case shapes, signed with its published key unless the case
 * says otherwise. So each check of OpenID Connect Core 1.0 Section 3.1.3.7
 * and the identity mapping is exercised alone, and so is the floor over the
 * context the token carries.
 *
 * A refused login records no approval session: the decision that follows is
 * 401, and no Mission, Grant or code exists. A login the provider completed
 * records the token's `acr` and `auth_time`, which the published floor then
 * evaluates, refusing high-risk authority `access_denied` before any
 * Mission, Grant or code.
 */
import { createHash, randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { DERIVATION_POLICY, demoReconciliationTemplate, DEV_SERVICE_TOKEN } from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, SignJWT, type CryptoKey, type JWK } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { ApprovalSessionStore, buildAuthorizationServer, type BuiltAs, loginCookieName } from "../src/index.js";
import type { AuthorityEntry } from "../src/kernel/types.js";

const PORT = 14921;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const PAYMENTS = DERIVATION_POLICY.ceiling[0].resource as string;
const VERIFIER = "approver-login-verifier-0123456789-0123456789-0123";
const CLIENT_ID = "mission-approval-surface";
const CLIENT_SECRET = randomBytes(24).toString("base64url");
/** An issuer the AS's mapping names, which is not the provider it logs in through. */
const OTHER_ISSUER = "https://idp.elsewhere.example";

const READ: AuthorityEntry[] = [{ type: "mission_resource_access", resource: PAYMENTS, actions: ["payments:invoice.read"] }];
const REMIT: AuthorityEntry[] = [
  {
    type: "mission_resource_access",
    resource: PAYMENTS,
    actions: ["payments:invoice.read", "payments:remittance.send"],
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];

const now = () => Math.floor(Date.now() / 1000);

/** What the stub provider saw of one authorization request. */
interface SeenRequest {
  params: URLSearchParams;
  nonce: string;
  challenge: string;
}

/** How a case shapes the ID Token: claims over the defaults, and the key that signs it. */
type Shape = (base: Record<string, unknown>) => { claims: Record<string, unknown>; key?: CryptoKey };

let op: { issuer: string; server: Server; key: CryptoKey; rogue: CryptoKey; seen: SeenRequest[]; shape: Shape; responseIss?: string };
let as: BuiltAs;
let server: Server;
const sessions = new ApprovalSessionStore();

beforeAll(async () => {
  const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
  const rogue = (await generateKeyPair("ES256", { extractable: true })).privateKey;
  const jwk = { ...(await exportJWK(publicKey)), kid: "op-1", alg: "ES256", use: "sig" } as JWK;
  const codes = new Map<string, SeenRequest>();
  const opServer = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", op.issuer);
    const json = (status: number, body: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (url.pathname === "/.well-known/openid-configuration") {
      json(200, {
        issuer: op.issuer,
        authorization_endpoint: `${op.issuer}/auth`,
        token_endpoint: `${op.issuer}/token`,
        jwks_uri: `${op.issuer}/jwks`,
        authorization_response_iss_parameter_supported: true,
        id_token_signing_alg_values_supported: ["ES256"],
      });
      return;
    }
    if (url.pathname === "/jwks") {
      json(200, { keys: [jwk] });
      return;
    }
    if (url.pathname === "/auth") {
      // The provider authenticated the account; this stub skips straight to the code.
      const seen = {
        params: url.searchParams,
        nonce: url.searchParams.get("nonce") ?? "",
        challenge: url.searchParams.get("code_challenge") ?? "",
      };
      op.seen.push(seen);
      const code = randomBytes(16).toString("base64url");
      codes.set(code, seen);
      const back = new URL(url.searchParams.get("redirect_uri") as string);
      back.searchParams.set("code", code);
      back.searchParams.set("state", url.searchParams.get("state") as string);
      back.searchParams.set("iss", op.responseIss ?? op.issuer);
      res.writeHead(303, { location: back.toString() });
      res.end();
      return;
    }
    if (url.pathname === "/token" && req.method === "POST") {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const form = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
      const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");
      const seen = codes.get(form.get("code") ?? "");
      codes.delete(form.get("code") ?? "");
      if (req.headers.authorization !== `Basic ${basic}`) return json(401, { error: "invalid_client" });
      const verifier = form.get("code_verifier") ?? "";
      if (!seen || createHash("sha256").update(verifier).digest("base64url") !== seen.challenge) {
        return json(400, { error: "invalid_grant" });
      }
      const t = now();
      const shaped = op.shape({ iss: op.issuer, sub: "idp-bob", aud: CLIENT_ID, iat: t, exp: t + 300, nonce: seen.nonce, acr: "mfa", auth_time: t });
      const idToken = await new SignJWT(shaped.claims)
        .setProtectedHeader({ alg: "ES256", kid: "op-1" })
        .sign(shaped.key ?? op.key);
      json(200, { access_token: "opaque", token_type: "Bearer", expires_in: 300, id_token: idToken });
      return;
    }
    json(404, { error: "not_found" });
  });
  await new Promise<void>((r) => opServer.listen(0, "127.0.0.1", () => r()));
  op = {
    issuer: `http://127.0.0.1:${(opServer.address() as AddressInfo).port}`,
    server: opServer,
    key: privateKey,
    rogue,
    seen: [],
    shape: (base) => ({ claims: base }),
  };
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    approvalSessions: sessions,
    approverLogin: {
      issuer: op.issuer,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      idTokenSigningAlgs: ["ES256"],
      identities: [
        { iss: op.issuer, sub: "idp-bob", approver: "bob" },
        { iss: OTHER_ISSUER, sub: "idp-carol", approver: "dana" },
      ],
      acrValues: ["mfa"],
    },
  });
  server = as.provider.listen(PORT);
});

afterAll(() => {
  server?.close();
  op?.server.closeAllConnections();
  op?.server.close();
});

type Jar = Map<string, string>;
const cookieOf = (jar: Jar) => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
const keep = (jar: Jar, res: Response) => {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
  }
};

/**
 * A browser's cookie store with path matching (RFC 6265 Sections 5.1.4 and
 * 5.3): each cookie keeps its `Path` (the request's default path when the
 * attribute is absent), and a request carries only the cookies whose path
 * matches its own. A cookie is keyed by its name and path, so two cookies of
 * one name on different paths coexist, as in a browser.
 */
type PathJar = Map<string, { name: string; value: string; path: string }>;
const defaultPath = (requestPath: string): string => {
  const slash = requestPath.lastIndexOf("/");
  return slash <= 0 ? "/" : requestPath.slice(0, slash);
};
const pathMatches = (requestPath: string, cookiePath: string): boolean =>
  requestPath === cookiePath ||
  (requestPath.startsWith(cookiePath) && (cookiePath.endsWith("/") || requestPath[cookiePath.length] === "/"));
const storeByPath = (jar: PathJar, url: string, res: Response): void => {
  const requestPath = new URL(url).pathname;
  for (const line of res.headers.getSetCookie()) {
    const [pair, ...attrs] = line.split(";").map((x) => x.trim());
    const eq = (pair as string).indexOf("=");
    const declared = attrs.find((a) => /^path=/i.test(a))?.slice(5);
    const path = declared?.startsWith("/") ? declared : defaultPath(requestPath);
    const name = (pair as string).slice(0, eq);
    jar.set(`${name} ${path}`, { name, value: (pair as string).slice(eq + 1), path });
  }
};
const cookiesFor = (jar: PathJar, url: string): string => {
  const requestPath = new URL(url).pathname;
  return [...jar]
    .filter(([, c]) => pathMatches(requestPath, c.path))
    .map(([, c]) => `${c.name}=${c.value}`)
    .join("; ");
};

/** The agent's PAR and authorization request: an approval interaction and its user agent's cookies. */
async function pendingApproval(authority: AuthorityEntry[]): Promise<{ uid: string; jar: Jar }> {
  const key = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(key);
  const par = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: PAYMENTS,
      code_challenge: createHash("sha256").update(VERIFIER).digest("base64url"),
      code_challenge_method: "S256",
      mission_intent: JSON.stringify({
        intent: { goal: "Pay Acme invoices", target_resources: [PAYMENTS], expires_at: "2027-01-01T00:00:00Z" },
      }),
      authorization_details: JSON.stringify(authority),
      client_assertion: assertion,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  expect(par.status, await par.clone().text()).toBe(201);
  const { request_uri } = (await par.json()) as { request_uri: string };
  const jar: Jar = new Map();
  const res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`, { redirect: "manual" });
  keep(jar, res);
  return { uid: (res.headers.get("location") ?? "").split("/interaction/")[1] as string, jar };
}

/** The Approver's login through the provider, in the Approver's own user agent (`approver`). */
async function logIn(
  uid: string,
  approver: Jar,
  subject = "alice",
): Promise<{ status: number; csrf?: string; description?: string; callback: string }> {
  let res = await fetch(`${ISSUER}/interaction/${uid}/approver-login?${new URLSearchParams({ subject })}`, {
    redirect: "manual",
    headers: { cookie: cookieOf(approver) },
  });
  expect(res.status, await res.clone().text()).toBe(303);
  keep(approver, res);
  res = await fetch(res.headers.get("location") as string, { redirect: "manual" });
  const callback = res.headers.get("location") as string;
  expect(callback.startsWith(`${ISSUER}/approver-login/callback?`)).toBe(true);
  return complete(callback, approver);
}

/** Deliver the provider's authorization response to the callback, in `approver`'s user agent. */
async function complete(callback: string, approver: Jar): Promise<{ status: number; csrf?: string; description?: string; callback: string }> {
  const res = await fetch(callback, { redirect: "manual", headers: { cookie: cookieOf(approver) } });
  keep(approver, res);
  const text = await res.text();
  if (res.status !== 200) {
    let description = text;
    try {
      description = (JSON.parse(text) as { error_description?: string }).error_description ?? text;
    } catch {
      // Not a JSON refusal: keep the body as it came.
    }
    return { status: res.status, description, callback };
  }
  return { status: 200, csrf: /name="mission-approval-csrf" content="([^"]+)"/.exec(text)?.[1] as string, callback };
}

/** The Approver's decision on the interaction, then the redirect's code or error. */
async function decide(uid: string, jar: Jar, approver: Jar, csrf: string | undefined) {
  let res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: {
      "content-type": "application/json",
      cookie: [cookieOf(jar), cookieOf(approver)].filter(Boolean).join("; "),
      ...(csrf ? { "x-csrf-token": csrf } : {}),
    },
    body: JSON.stringify({ decision: "approve" }),
  });
  if (res.status !== 303) return { status: res.status };
  keep(jar, res);
  let location = res.headers.get("location") ?? "";
  while (location.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieOf(jar) } });
    keep(jar, res);
    location = res.headers.get("location") ?? "";
  }
  const q = new URL(location).searchParams;
  return {
    status: 303,
    ...(q.get("code") ? { code: q.get("code") as string } : {}),
    ...(q.get("error") ? { error: q.get("error") as string } : {}),
    ...(q.get("error_description") ? { description: q.get("error_description") as string } : {}),
  };
}

/**
 * One approval through a login whose ID Token `shape` forms: the login's
 * outcome, the decision's, and the Missions and provider Grants the attempt
 * created.
 */
async function approveThroughLogin(authority: AuthorityEntry[], shape: Shape = (b) => ({ claims: b })) {
  op.shape = shape;
  const missionsBefore = as.kernel.allMissions().length;
  let grants = 0;
  const onGrant = () => {
    grants += 1;
  };
  as.provider.on("grant.saved", onGrant);
  try {
    const { uid, jar } = await pendingApproval(authority);
    const approver: Jar = new Map();
    const login = await logIn(uid, approver);
    const decision = await decide(uid, jar, approver, login.csrf);
    return { login, decision, missions: as.kernel.allMissions().length - missionsBefore, grants };
  } finally {
    as.provider.off("grant.saved", onGrant);
  }
}

/** A refused login: no session, so the decision is unauthenticated, and nothing exists. */
function expectLoginRefused(r: Awaited<ReturnType<typeof approveThroughLogin>>, reason: RegExp): void {
  expect(r.login.status).toBe(401);
  expect(r.login.description).toMatch(reason);
  expect(r.decision.status).toBe(401);
  expect(r.missions).toBe(0);
  expect(r.grants).toBe(0);
}

/** A login the floor does not accept for this authority: access_denied, and nothing exists. */
function expectFloorRefused(r: Awaited<ReturnType<typeof approveThroughLogin>>, reason: RegExp): void {
  expect(r.login.status).toBe(200);
  expect(r.decision.error).toBe("access_denied");
  expect(r.decision.description).toMatch(reason);
  expect(r.decision).not.toHaveProperty("code");
  expect(r.missions).toBe(0);
  expect(r.grants).toBe(0);
}

describe("the approval surface's upstream Approver login (@spec mission#approval-authentication, #1320, D496)", () => {
  it("admits high-risk authority after a login whose validated ID Token carries mfa: the mapped Approver, the token's acr and auth_time, and the selected Subject are recorded", async () => {
    const authTime = now() - 7;
    const established = vi.spyOn(sessions, "establish");
    try {
      const r = await approveThroughLogin(REMIT, (b) => ({ claims: { ...b, auth_time: authTime } }));
      expect(r.login.status, r.login.description).toBe(200);
      expect(established).toHaveBeenCalledTimes(1);
      expect(established.mock.calls[0]?.[1]).toEqual({ sub: "bob", acr: "mfa", auth_time: authTime, subject: "alice" });
      expect(r.decision.code, r.decision.description).toBeTruthy();
      expect(r.missions).toBe(1);
      const record = as.kernel.allMissions().at(-1);
      expect(record?.approval_basis.consent_principal).toEqual({ iss: ISSUER, sub: "bob" });
      expect(record?.subject).toEqual({ iss: ISSUER, sub: "alice" });
    } finally {
      established.mockRestore();
    }
    // The request the provider received: code flow, PKCE S256, a nonce, a
    // fresh login, and the requested acr.
    const sent = op.seen.at(-1)?.params;
    expect(sent?.get("response_type")).toBe("code");
    expect(sent?.get("scope")).toBe("openid");
    expect(sent?.get("code_challenge_method")).toBe("S256");
    expect(sent?.get("nonce")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(sent?.get("prompt")).toBe("login");
    expect(sent?.get("acr_values")).toBe("mfa");
  });

  it("refuses high-risk authority after a password-only login (acr pwd): access_denied, with no Mission, Grant or code", async () => {
    const r = await approveThroughLogin(REMIT, (b) => ({ claims: { ...b, acr: "pwd" } }));
    expectFloorRefused(r, /does not satisfy the high-risk-authority floor/);
  });

  it("refuses high-risk authority after a login whose auth_time is older than the floor allows: access_denied, with no Mission, Grant or code", async () => {
    const r = await approveThroughLogin(REMIT, (b) => ({ claims: { ...b, auth_time: now() - 301 } }));
    expectFloorRefused(r, /older than the high-risk-authority floor allows/);
  });

  it("admits low-risk authority after a password-only login: the floor does not apply", async () => {
    const r = await approveThroughLogin(READ, (b) => ({ claims: { ...b, acr: "pwd" } }));
    expect(r.login.status, r.login.description).toBe(200);
    expect(r.decision.code, r.decision.description).toBeTruthy();
    expect(r.missions).toBe(1);
  });

  it("refuses an ID Token whose signature does not verify against the provider's published keys, recording no login", async () => {
    const r = await approveThroughLogin(REMIT, (b) => ({ claims: b, key: op.rogue }));
    expectLoginRefused(r, /does not verify against the provider's keys/);
  });

  it("refuses an ID Token from another issuer, recording no login", async () => {
    const r = await approveThroughLogin(REMIT, (b) => ({ claims: { ...b, iss: OTHER_ISSUER } }));
    expectLoginRefused(r, /iss claim is not valid/);
  });

  it("refuses an ID Token for another audience, or for this client and another, recording no login", async () => {
    expectLoginRefused(await approveThroughLogin(REMIT, (b) => ({ claims: { ...b, aud: "another-client" } })), /aud claim is not valid/);
    expectLoginRefused(
      await approveThroughLogin(REMIT, (b) => ({ claims: { ...b, aud: [CLIENT_ID, "another-client"] } })),
      /audience other than this client/,
    );
  });

  it("refuses an ID Token whose nonce is not the one this login sent, recording no login", async () => {
    const r = await approveThroughLogin(REMIT, (b) => ({ claims: { ...b, nonce: randomBytes(32).toString("base64url") } }));
    expectLoginRefused(r, /nonce is not this login's/);
  });

  it("refuses an expired ID Token, and one issued longer ago than the login accepts, recording no login", async () => {
    expectLoginRefused(await approveThroughLogin(REMIT, (b) => ({ claims: { ...b, exp: now() - 30 } })), /exp claim is not valid/);
    expectLoginRefused(await approveThroughLogin(REMIT, (b) => ({ claims: { ...b, iat: now() - 600 } })), /iat claim is not valid/);
  });

  it("refuses an ID Token without acr or auth_time, recording no login", async () => {
    expectLoginRefused(
      await approveThroughLogin(REMIT, (b) => {
        const { acr: _acr, ...claims } = b;
        return { claims };
      }),
      /acr/,
    );
    expectLoginRefused(
      await approveThroughLogin(REMIT, (b) => {
        const { auth_time: _authTime, ...claims } = b;
        return { claims };
      }),
      /auth_time/,
    );
  });

  it("maps the issuer-qualified identity: a subject the mapping names only under another issuer logs no one in", async () => {
    const r = await approveThroughLogin(REMIT, (b) => ({ claims: { ...b, sub: "idp-carol" } }));
    expectLoginRefused(r, /not mapped to an Approver/);
  });

  it("refuses an authorization response that names another issuer (RFC 9207), recording no login", async () => {
    op.responseIss = OTHER_ISSUER;
    try {
      const r = await approveThroughLogin(REMIT);
      expectLoginRefused(r, /login response comes from another issuer/);
    } finally {
      op.responseIss = undefined;
    }
  });

  it("completes two logins started one after the other in one browser that delivers cookies by path, and each approval decides (RFC 6265 Section 5.1.4)", async () => {
    op.shape = (b) => ({ claims: b });
    const first = await pendingApproval(REMIT);
    const second = await pendingApproval(REMIT);
    const browser: PathJar = new Map();
    const get = async (url: string) => {
      const res = await fetch(url, { redirect: "manual", headers: { cookie: cookiesFor(browser, url) } });
      storeByPath(browser, url, res);
      return res;
    };
    /** Start a login at the AS and pass the provider's authorization endpoint: the callback URL it returns to. */
    const start = async (uid: string): Promise<string> => {
      const started = await get(`${ISSUER}/interaction/${uid}/approver-login?subject=alice`);
      expect(started.status).toBe(303);
      const auth = await fetch(started.headers.get("location") as string, { redirect: "manual" });
      return auth.headers.get("location") as string;
    };
    const firstCallback = await start(first.uid);
    const secondCallback = await start(second.uid);
    const login = async (callback: string) => {
      const res = await get(callback);
      const text = await res.text();
      return { status: res.status, text, csrf: /name="mission-approval-csrf" content="([^"]+)"/.exec(text)?.[1] };
    };
    const secondLogin = await login(secondCallback);
    expect(secondLogin.status, secondLogin.text).toBe(200);
    const firstLogin = await login(firstCallback);
    expect(firstLogin.status, firstLogin.text).toBe(200);
    // Each approval session is scoped to its own interaction, and decides it.
    for (const [pending, session] of [
      [first, firstLogin],
      [second, secondLogin],
    ] as const) {
      const url = `${ISSUER}/interaction/${pending.uid}/decide`;
      const approverCookies = cookiesFor(browser, url);
      expect(approverCookies.split("; ").filter((c) => c.startsWith("mission_approver_session="))).toHaveLength(1);
      const approver: Jar = new Map(approverCookies.split("; ").map((c) => [c.slice(0, c.indexOf("=")), c.slice(c.indexOf("=") + 1)]));
      const decision = await decide(pending.uid, pending.jar, approver, session.csrf);
      expect(decision.code, decision.description).toBeTruthy();
    }
    // Each login's binding went only to the callback.
    const bindings = [...browser.values()].filter((c) => !c.name.startsWith("mission_approver_session"));
    expect(bindings).toHaveLength(2);
    for (const c of bindings) expect(c.path).toBe("/approver-login/callback");
  });

  it("completes a login only in the user agent that started it, and only once", async () => {
    op.shape = (b) => ({ claims: b });
    const { uid, jar } = await pendingApproval(REMIT);
    const approver: Jar = new Map();
    let res = await fetch(`${ISSUER}/interaction/${uid}/approver-login?subject=alice`, { redirect: "manual" });
    keep(approver, res);
    res = await fetch(res.headers.get("location") as string, { redirect: "manual" });
    const callback = res.headers.get("location") as string;
    const state = new URL(callback).searchParams.get("state") as string;
    expect(approver.get(loginCookieName(state))).toMatch(/^[A-Za-z0-9_-]{43}$/);
    // Another user agent, holding no binding, cannot complete it.
    const elsewhere = await complete(callback, new Map());
    expect(elsewhere.status).toBe(401);
    expect(elsewhere.description).toMatch(/user agent other than the one that started it/);
    // The started login is consumed by that attempt, and a replay of the
    // response completes nothing either.
    const replay = await complete(callback, approver);
    expect(replay.status).toBe(401);
    expect(replay.description).toMatch(/names no login this server started/);
    expect((await decide(uid, jar, approver, undefined)).status).toBe(401);
  });
});

describe("the Approver login for a template consent (@spec mission-template#template-consent, mission#approval-authentication, #1119)", () => {
  /** A proposal of the demo reconciliation template, and its consent page URL. */
  const proposeTemplate = async (): Promise<{ id: string; consentPage: string }> => {
    const { approver: _approver, approval_event_id: _event, issuer: _issuer, ...body } = demoReconciliationTemplate(ISSUER);
    const res = await fetch(`${ISSUER}/templates/proposals`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
      body: JSON.stringify(body),
    });
    expect(res.status).toBe(201);
    const { proposal_id: id } = (await res.json()) as { proposal_id: string };
    return { id, consentPage: `${ISSUER}/templates/proposals/${id}` };
  };

  /**
   * The Approver's browser: open the consent page, follow its sign-in link
   * through the provider, then the callback page's Continue link back to the
   * consent page. Returns the browser's cookies and that page.
   */
  const logInThroughPage = async (consentPage: string): Promise<{ browser: PathJar; html: string }> => {
    const browser: PathJar = new Map();
    const first = await (await fetch(consentPage)).text();
    const signIn = /<a href="([^"]+)">Sign in to decide<\/a>/.exec(first)?.[1] as string;
    expect(signIn).toBe(`${new URL(consentPage).pathname}/approver-login`);
    let url = new URL(signIn, ISSUER).toString();
    let res = await fetch(url, { redirect: "manual" });
    expect(res.status).toBe(303);
    storeByPath(browser, url, res);
    res = await fetch(res.headers.get("location") as string, { redirect: "manual" });
    url = res.headers.get("location") as string;
    res = await fetch(url, { redirect: "manual", headers: { cookie: cookiesFor(browser, url) } });
    expect(res.status).toBe(200);
    storeByPath(browser, url, res);
    const callback = await res.text();
    const next = /<a href="([^"]+)">Continue to the approval<\/a>/.exec(callback)?.[1] as string;
    expect(next).toBe(new URL(consentPage).pathname);
    url = new URL(next, ISSUER).toString();
    const html = await (await fetch(url, { headers: { cookie: cookiesFor(browser, url) } })).text();
    return { browser, html };
  };

  /**
   * Submit the consent page's form as a browser does: to its action, with its
   * hidden fields and the pressed button's value, form-encoded, from the
   * issuer's origin, carrying the cookies the action's path receives.
   */
  const submitConsentForm = async (
    browser: PathJar,
    html: string,
    decision: "approve" | "deny",
    tamper: (fields: URLSearchParams) => void = () => {},
  ): Promise<Response> => {
    const action = /<form method="post" action="([^"]+)">/.exec(html)?.[1] as string;
    expect(action).toBeDefined();
    expect(html).toContain(`<button name="decision" value="${decision}">`);
    const fields = new URLSearchParams();
    for (const m of html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g)) fields.set(m[1] as string, m[2] as string);
    fields.set("decision", decision);
    tamper(fields);
    const url = new URL(action, ISSUER).toString();
    return fetch(url, {
      method: "POST",
      redirect: "manual",
      headers: { "content-type": "application/x-www-form-urlencoded", origin: ISSUER, cookie: cookiesFor(browser, url) },
      body: fields.toString(),
    });
  };

  it("login, Continue, then the page's Approve: the session cookie is scoped to the consent page, the form carries the login's CSRF secret, and the logged-in Approver is the template's approver of record", async () => {
    op.shape = (b) => ({ claims: b });
    const { id, consentPage } = await proposeTemplate();
    // A template consent selects no Subject.
    expect((await fetch(`${consentPage}/approver-login?subject=alice`, { redirect: "manual" })).status).toBe(400);
    const { browser, html } = await logInThroughPage(consentPage);
    const session = [...browser.values()].find((c) => c.name === "mission_approver_session");
    expect(session?.path).toBe(`/templates/proposals/${id}`);
    const res = await submitConsentForm(browser, html, "approve");
    expect(res.status, await res.clone().text()).toBe(303);
    expect(res.headers.get("location")).toBe(`/templates/proposals/${id}`);
    const after = await (await fetch(consentPage, { headers: { cookie: cookiesFor(browser, consentPage) } })).text();
    const templateId = /approved as template <code>([^<]+)<\/code>/.exec(after)?.[1] as string;
    expect(as.templateStore.get(templateId)?.approver).toEqual({ iss: ISSUER, sub: "bob" });
  });

  it("login, Continue, then the page's Deny: the proposal is denied and no template is created", async () => {
    op.shape = (b) => ({ claims: b });
    const { id, consentPage } = await proposeTemplate();
    const { browser, html } = await logInThroughPage(consentPage);
    const res = await submitConsentForm(browser, html, "deny");
    expect(res.status).toBe(303);
    expect(await (await fetch(consentPage)).text()).toContain("This proposal was denied.");
    expect(as.templateStore.getByApprovalEvent(`apev_${id}`)).toBeUndefined();
  });

  it("refuses the page's form when its CSRF secret is not the login's, deciding nothing", async () => {
    op.shape = (b) => ({ claims: b });
    const { id, consentPage } = await proposeTemplate();
    const { browser, html } = await logInThroughPage(consentPage);
    const res = await submitConsentForm(browser, html, "approve", (f) => f.set("csrf_token", "not-the-login-secret"));
    expect(res.status).toBe(401);
    expect(as.templateStore.getByApprovalEvent(`apev_${id}`)).toBeUndefined();
    // The genuine form still decides.
    expect((await submitConsentForm(browser, html, "approve")).status).toBe(303);
  });
});
