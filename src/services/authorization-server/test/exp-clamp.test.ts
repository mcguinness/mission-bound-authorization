/**
 * @spec mission#mission-bound-tokens — "A credential the Mission Issuer derives
 * MUST have an `exp` that does not exceed the Mission's `expires_at`" (#894
 * item 1). oidc-provider mints the code exchange's and refresh's credentials
 * itself, so the clamp is its `ttl` configuration (`clampToMission` in
 * adapters/provider.ts). These tests drive a Mission whose `expires_at` falls
 * inside each credential's configured lifetime and read the minted `exp`
 * back, plus a far Mission as the control.
 */
import { browserApprovalHeaders, TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";

import { type Server } from "node:http";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { decodeJwt, exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { buildAuthorizationServer, type BuiltAs, ApprovalSessionStore } from "../src/index.js";

const PORT = 14745;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
const VERIFIER = "exp-clamp-verifier-0123456789-0123456789-0123456789";
const AT_TTL = 300; // topology.json ttls.accessTokenSeconds
const RT_TTL = 14 * 24 * 60 * 60; // oidc-provider's refresh-token default
const CODE_TTL = 60; // oidc-provider's authorization-code default
const ID_TOKEN_TTL = 60 * 60; // oidc-provider's ID Token default
const AUTHORITY = [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] }];

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
type Json = Record<string, unknown>;

let as: BuiltAs;
let server: Server;
let clientKey: CryptoKey;
let dpop: Keys;

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
const inSeconds = (seconds: number): string => new Date(Date.now() + seconds * 1000).toISOString();
const epoch = (iso: string): number => Math.floor(Date.parse(iso) / 1000);

async function clientAssertion(): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(clientKey);
}

async function dpopProof(extra: Json = {}): Promise<string> {
  return new SignJWT({ htu: `${ISSUER}/token`, htm: "POST", ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(dpop.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(dpop.privateKey);
}

async function token(params: Record<string, string>): Promise<{ status: number; body: Json }> {
  const send = async (extra: Json = {}) =>
    fetch(`${ISSUER}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(extra) },
      body: new URLSearchParams({
        ...params,
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return { status: res.status, body: (await res.json()) as Json };
}

/**
 * PAR, approval and the authorization resume: the final redirect to the
 * client. `beforeResume` runs after the approval decision, before the resume
 * request that mints the authorization code.
 */
async function authorizationRedirect(
  expiresAt: string | undefined,
  extra: Record<string, string> = {},
  beforeResume: () => void = () => {},
  // A trusted browser approval (#826): the Approver authenticated in this
  // user agent, which an ID Token requires; otherwise the headless service.
  browser?: { sub: string; subject?: string },
): Promise<URL> {
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER)),
  ).toString("base64url");
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
      login_hint: "alice",
      ...(expiresAt
        ? {
            mission_intent: JSON.stringify({
              intent: { goal: "Read Acme invoices", target_resources: [RESOURCE], expires_at: expiresAt },
            }),
          }
        : {}),
      authorization_details: JSON.stringify(AUTHORITY),
      ...extra,
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const pushed = (await par.json()) as Json;
  expect(par.status, JSON.stringify(pushed)).toBe(201);
  const jar = new Map<string, string>();
  const keep = (res: Response) => {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = (pair as string).indexOf("=");
      jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
    }
  };
  const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
  let res = await fetch(
    `${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: String(pushed.request_uri) })}`,
    { redirect: "manual" },
  );
  keep(res);
  let location = res.headers.get("location") ?? "";
  if (location.includes("/interaction/")) {
    const uid = location.split("/interaction/")[1] as string;
    res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
      method: "POST",
      redirect: "manual",
      headers: {
        ...(browser ? browserApprovalHeaders(SESSIONS, uid, browser, cookie()) : { ...trustedApprovalHeaders(), cookie: cookie() }),
        "content-type": "application/json",
      },
      body: JSON.stringify({ decision: "approve" }),
    });
    keep(res);
    location = res.headers.get("location") ?? "";
  }
  beforeResume();
  while (location.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookie() } });
    keep(res);
    location = res.headers.get("location") ?? "";
  }
  return new URL(location);
}

/** PAR, approval and the redirect: an authorization code under a Mission ending at `expiresAt`. */
async function authorize(
  expiresAt: string | undefined,
  extra: Record<string, string> = {},
  browser?: { sub: string; subject?: string },
): Promise<string> {
  const redirect = await authorizationRedirect(expiresAt, extra, () => {}, browser);
  const code = redirect.searchParams.get("code");
  expect(code, redirect.href).toBeTruthy();
  return code as string;
}

const exchange = (code: string) =>
  token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: VERIFIER, resource: RESOURCE });

const refresh = (refreshToken: string) => token({ grant_type: "refresh_token", refresh_token: refreshToken });

/** The stored refresh token's `iat` and `exp`, read back from oidc-provider. */
async function storedRefreshToken(value: string): Promise<{ iat: number; exp: number }> {
  const rt = (await as.provider.RefreshToken.find(value)) as { iat: number; exp: number } | undefined;
  expect(rt).toBeDefined();
  return rt as { iat: number; exp: number };
}

/** The Mission a minted access token is bound to, and its `expires_at` in epoch seconds. */
function missionOf(accessToken: string): { id: string; expS: number } {
  const id = (decodeJwt(accessToken).mission as { id: string }).id;
  return { id, expS: epoch(as.kernel.get(id)?.expires_at as string) };
}

// The trusted browser login for approvals an ID Token can describe (#826).
const SESSIONS = new ApprovalSessionStore();

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: SESSIONS,
  });
  server = as.provider.listen(PORT);
  await new Promise<void>((r) => server.once("listening", () => r()));
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  dpop = (await generateKeyPair("ES256", { extractable: true })) as Keys;
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("credentials never outlive the Mission (@spec mission#mission-bound-tokens)", () => {
  it("code exchange: the access token, refresh token and authorization code all expire no later than a Mission ending inside their lifetimes", async () => {
    const code = await authorize(inSeconds(30));
    const stored = (await as.provider.AuthorizationCode.find(code)) as { iat: number; exp: number };
    const res = await exchange(code);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const at = decodeJwt(res.body.access_token as string) as { iat: number; exp: number };
    const { expS } = missionOf(res.body.access_token as string);

    expect(at.exp).toBeLessThanOrEqual(expS);
    expect(at.exp - at.iat).toBeLessThan(AT_TTL);
    expect(at.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(res.body.expires_in as number).toBeLessThanOrEqual(expS - at.iat);

    const rt = await storedRefreshToken(res.body.refresh_token as string);
    expect(rt.exp).toBeLessThanOrEqual(expS);
    expect(rt.exp - rt.iat).toBeLessThan(RT_TTL);

    expect(stored.exp).toBeLessThanOrEqual(expS);
    expect(stored.exp - stored.iat).toBeLessThan(CODE_TTL);
  });

  it("an ID Token issued on the code exchange expires no later than the Mission", async () => {
    // An ID Token describes the End-User this interaction authenticated: a
    // self-approval in this user agent (#826).
    const res = await exchange(await authorize(inSeconds(30), { scope: "openid" }, { sub: "alice" }));
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const idToken = decodeJwt(res.body.id_token as string) as { iat: number; exp: number };
    const { expS } = missionOf(res.body.access_token as string);
    expect(idToken.exp).toBeLessThanOrEqual(expS);
    expect(idToken.exp - idToken.iat).toBeLessThan(ID_TOKEN_TTL);
  });

  it("a non-rotating refresh: the new access token expires no later than the Mission and the refresh token is kept", async () => {
    const first = await exchange(await authorize(inSeconds(30)));
    expect(first.status, JSON.stringify(first.body)).toBe(200);
    const presented = first.body.refresh_token as string;
    const res = await refresh(presented);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.refresh_token).toBe(presented);
    const at = decodeJwt(res.body.access_token as string) as { iat: number; exp: number };
    const { expS } = missionOf(res.body.access_token as string);
    expect(at.exp).toBeLessThanOrEqual(expS);
    expect(at.exp - at.iat).toBeLessThan(AT_TTL);
  });

  it(
    "a rotating refresh: the rotated refresh token and the new access token expire no later than the Mission",
    async () => {
      const first = await exchange(await authorize(inSeconds(10)));
      expect(first.status, JSON.stringify(first.body)).toBe(200);
      const presented = first.body.refresh_token as string;
      const { expS } = missionOf(first.body.access_token as string);
      // A non-family refresh token rotates once 70% of its lifetime has passed,
      // and its lifetime is now the Mission's remainder: wait to about 80%.
      const original = await storedRefreshToken(presented);
      await sleep((original.iat + 0.8 * (original.exp - original.iat)) * 1000 - Date.now());

      const res = await refresh(presented);
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      const rotated = res.body.refresh_token as string;
      expect(rotated).toBeTruthy();
      expect(rotated).not.toBe(presented);
      expect((await storedRefreshToken(rotated)).exp).toBeLessThanOrEqual(expS);
      const at = decodeJwt(res.body.access_token as string) as { exp: number };
      expect(at.exp).toBeLessThanOrEqual(expS);
    },
    20_000,
  );

  it(
    "a refresh after expires_at is refused invalid_grant by the expired refresh token itself, before the state gate (no mission_error)",
    async () => {
      const expiresAt = inSeconds(3);
      const first = await exchange(await authorize(expiresAt));
      expect(first.status, JSON.stringify(first.body)).toBe(200);
      const { id } = missionOf(first.body.access_token as string);
      await sleep(Date.parse(expiresAt) - Date.now() + 300);
      const res = await refresh(first.body.refresh_token as string);
      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(res.body.error).toBe("invalid_grant");
      expect(res.body.mission_error).toBeUndefined();
      // The gate never ran, so the lazy expiry commit did not land either.
      expect(as.kernel.get(id)?.state).toBe("active");
    },
    15_000,
  );

  it("control: a Mission far from expiry gets the full 300 s access token, the 14-day refresh token and the 60 s code", async () => {
    const code = await authorize(inSeconds(60 * 24 * 3600));
    const stored = (await as.provider.AuthorizationCode.find(code)) as { iat: number; exp: number };
    expect(stored.exp - stored.iat).toBe(CODE_TTL);
    const res = await exchange(code);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const at = decodeJwt(res.body.access_token as string) as { iat: number; exp: number };
    expect(at.exp - at.iat).toBe(AT_TTL);
    expect(res.body.expires_in).toBe(AT_TTL);
    const rt = await storedRefreshToken(res.body.refresh_token as string);
    expect(rt.exp - rt.iat).toBe(RT_TTL);
    const refreshed = await refresh(res.body.refresh_token as string);
    expect(refreshed.status, JSON.stringify(refreshed.body)).toBe(200);
    const next = decodeJwt(refreshed.body.access_token as string) as { iat: number; exp: number };
    expect(next.exp - next.iat).toBe(AT_TTL);
  });

  it(
    "a refresh or access token saved for a Mission already past expires_at is refused as the state gate refuses, and the expiry commits",
    async () => {
      const expiresAt = inSeconds(3);
      const first = await exchange(await authorize(expiresAt));
      expect(first.status, JSON.stringify(first.body)).toBe(200);
      const { id } = missionOf(first.body.access_token as string);
      const grantId = as.kernel.get(id)?.grant_id as string;
      const client = await as.provider.Client.find("ap-agent");
      await sleep(Date.parse(expiresAt) - Date.now() + 300);
      expect(as.kernel.get(id)?.state).toBe("active"); // not yet materialized
      // A refresh token has no extraTokenClaims gate at all (a rotated one is
      // saved before the access token is gated), so the lifetime hook is the
      // only check that meets the expired Mission: it refuses, and commits the
      // expiry, rather than saving a 0 s or negative lifetime.
      const rt = new as.provider.RefreshToken({ accountId: "alice", client, grantId });
      await expect(rt.save()).rejects.toMatchObject({ error: "invalid_grant", missionError: "expired" });
      expect(as.kernel.get(id)?.termination?.reason).toBe("expired");
      // An access token's lifetime is also evaluated before its gate; it is refused the same way.
      const at = new as.provider.AccessToken({ accountId: "alice", client, grantId });
      await expect(at.save()).rejects.toMatchObject({ error: "invalid_grant", missionError: "expired" });
    },
    15_000,
  );

  it("a credential minted with under one second of Mission left is refused, never given a 0 s or overrunning lifetime", async () => {
    const first = await exchange(await authorize(inSeconds(30)));
    expect(first.status, JSON.stringify(first.body)).toBe(200);
    const { id } = missionOf(first.body.access_token as string);
    const record = as.kernel.get(id);
    const client = await as.provider.Client.find("ap-agent");
    // The lifetime clock reads 500 ms before expires_at; the kernel's own clock
    // is real time, so the state gate still passes.
    vi.spyOn(Date, "now").mockReturnValue(Date.parse(record?.expires_at as string) - 500);
    const at = new as.provider.AccessToken({ accountId: "alice", client, grantId: record?.grant_id as string });
    await expect(at.save()).rejects.toMatchObject({
      error: "invalid_grant",
      missionError: "expired",
      error_detail: "the Mission expires before a credential can be issued",
    });
    vi.restoreAllMocks();
    expect(as.kernel.get(id)?.state).toBe("active");
  });

  it("an authorization resumed with under one second of Mission left redirects access_denied, never invalid_grant, and issues no code", async () => {
    const expiresAt = inSeconds(30);
    const codesSaved: unknown[] = [];
    const onCode = (code: unknown) => codesSaved.push(code);
    as.provider.on("authorization_code.saved", onCode);
    try {
      // The resume request (which mints the code) runs with the lifetime clock
      // 500 ms before expires_at; the kernel's clock is real time, so the
      // Mission is still active and the state gate passes.
      const redirect = await authorizationRedirect(expiresAt, {}, () => {
        vi.spyOn(Date, "now").mockReturnValue(Date.parse(expiresAt) - 500);
      });
      vi.restoreAllMocks();
      expect(redirect.origin + redirect.pathname).toBe(REDIRECT_URI);
      expect(redirect.searchParams.get("error")).toBe("access_denied");
      expect(redirect.searchParams.get("error")).not.toBe("invalid_grant");
      expect(redirect.searchParams.get("error_description")).toBe(
        "the Mission expires before the authorization can complete",
      );
      expect(redirect.searchParams.get("code")).toBeNull();
      expect(codesSaved).toHaveLength(0);
    } finally {
      as.provider.removeListener("authorization_code.saved", onCode);
    }
  });

  it("an authorization resumed after expires_at redirects access_denied, never invalid_grant, and commits the expiry", async () => {
    const expiresAt = inSeconds(30);
    // Past expires_at by both the lifetime clock and the kernel's own clock,
    // so the hook's state-gate branch is the one that refuses.
    const late = Date.parse(expiresAt) + 1_000;
    const redirect = await authorizationRedirect(expiresAt, {}, () => {
      vi.spyOn(Date, "now").mockReturnValue(late);
      vi.spyOn(as.kernel as unknown as { now: () => Date }, "now").mockReturnValue(new Date(late));
    });
    vi.restoreAllMocks();
    expect(redirect.searchParams.get("error")).toBe("access_denied");
    expect(redirect.searchParams.get("error_description")).toBe(
      "the Mission expires before the authorization can complete",
    );
    expect(redirect.searchParams.get("code")).toBeNull();
    const mission = as.kernel.allMissions().find((m) => Date.parse(m.expires_at) === Date.parse(expiresAt));
    expect(mission?.termination?.reason).toBe("expired");
  });

  it("a token under a grant that is not Mission-bound keeps oidc-provider's configured lifetimes", async () => {
    // The approval interaction only creates Missions, so an ordinary grant is
    // not reachable over the code flow here; the lifetime hook is read directly.
    const client = await as.provider.Client.find("ap-agent");
    const ordinary = { accountId: "alice", client, grantId: "an-ordinary-grant" };
    const bare = new as.provider.AccessToken(ordinary) as unknown as { expiration: number };
    expect(bare.expiration).toBe(ID_TOKEN_TTL); // oidc-provider's 1 h default, no resource server
    const resourceBound = new as.provider.AccessToken(ordinary) as unknown as {
      resourceServer: unknown;
      expiration: number;
    };
    resourceBound.resourceServer = new as.provider.ResourceServer(RESOURCE, {
      scope: "",
      accessTokenTTL: AT_TTL,
      accessTokenFormat: "jwt",
    } as never);
    expect(resourceBound.expiration).toBe(AT_TTL);
    expect((new as.provider.RefreshToken(ordinary) as unknown as { expiration: number }).expiration).toBe(RT_TTL);
    expect((new as.provider.AuthorizationCode(ordinary) as unknown as { expiration: number }).expiration).toBe(CODE_TTL);
  });
});
