/**
 * AROP Deferred Token Response (DTR) over real HTTP: the deferred grant on the
 * REAL /token endpoint. The client authenticates (private_key_jwt + DPoP), then
 * either INITIATES a deferral (grant_type=deferred + deferred_authorization) ->
 * HTTP 400 authorization_pending + deferral_code, or POLLS it (grant_type=
 * deferred + deferral_code) -> RFC 8628-shaped errors until approval, then a
 * REAL resource-bound mission JWT carrying the ACTIVE Mission unchanged (D42).
 * The token MUST be a resource-bound JWT (not opaque): aud = the resource,
 * cnf.jkt = the DPoP key, a `mission` claim, exp <= approved_until.
 */

import { type Server } from "node:http";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import {
  calculateJwkThumbprint,
  createRemoteJWKSet,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify,
  SignJWT,
} from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  buildAuthorizationServer,
  DEFERRED_GRANT_TYPE,
  type AuthorityEntry,
  type BuiltAs,
} from "../src/index.js";

const PORT = 14460;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;

type DpopKeys = { privateKey: CryptoKey; publicKey: CryptoKey };

let as: BuiltAs;
let asServer: Server;
let clientKey: CryptoKey;
let dpopKeys: DpopKeys;
let dpopJkt: string;
let missionId = "";

const cookies = new Map<string, string>();
function cookieHeader(jar: Map<string, string> = cookies): string {
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}
function storeCookies(res: Response, jar: Map<string, string> = cookies): void {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
  }
}

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

async function dpopProof(
  htu: string,
  htm: string,
  keys: DpopKeys = dpopKeys,
  extra: Record<string, unknown> = {},
): Promise<string> {
  return new SignJWT({ htu, htm, ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}

/** POST /token with private_key_jwt + DPoP, with the mandatory dpop-nonce retry. */
async function tokenRequest(params: Record<string, string>, keys: DpopKeys = dpopKeys): Promise<Response> {
  const htu = `${ISSUER}/token`;
  const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
    fetch(htu, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(htu, "POST", keys, extra) },
      body: new URLSearchParams({
        ...params,
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return res;
}

/** Full PAR -> approval -> token dance yielding an ACTIVE mission (grant-bound). */
async function issueBaseMissionToken(): Promise<{ token: string; missionId: string }> {
  const verifier = "dtr-endpoint-verifier-0123456789-0123456789-01234";
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
  ).toString("base64url");
  // @spec mission#submission-via-par — the wire value is the Submission envelope.
  const intent = JSON.stringify({
    intent: {
      goal: "Pay Acme invoices and send remittance",
      resources: [RESOURCE],
      expires_at: "2027-01-01T00:00:00Z",
    },
  });
  const authorizationDetails = JSON.stringify([
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: ["payments:invoice.read", "payments:remittance.send"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    },
  ]);
  const par = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      scope: "payments",
      resource: RESOURCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      mission_intent: intent,
      authorization_details: authorizationDetails,
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const { request_uri } = (await par.json()) as { request_uri: string };

  const authUrl = `${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`;
  let res = await fetch(authUrl, { redirect: "manual" });
  storeCookies(res);
  let location = res.headers.get("location") as string;
  const uid = location.split("/interaction/")[1] as string;

  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/json", cookie: cookieHeader() },
    body: JSON.stringify({ decision: "approve", approver: "bob", subject: "alice" }),
  });
  storeCookies(res);
  location = res.headers.get("location") as string;
  while (location?.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader() } });
    storeCookies(res);
    location = res.headers.get("location") as string;
  }
  const code = new URL(location).searchParams.get("code") as string;

  const tok = await tokenRequest({
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier,
    resource: RESOURCE,
  });
  const body = (await tok.json()) as { access_token: string };
  const claims = JSON.parse(Buffer.from(body.access_token.split(".")[1] as string, "base64url").toString()) as {
    mission: { id: string };
  };
  return { token: body.access_token, missionId: claims.mission.id };
}

/** Initiate a deferral for a mission subset (grant_type=deferred, no code). */
async function initiate(requested: AuthorityEntry[]): Promise<Response> {
  return tokenRequest({
    grant_type: DEFERRED_GRANT_TYPE,
    deferred_authorization: JSON.stringify({ mission_id: missionId, requested }),
  });
}
/** Poll/redeem a deferral by its deferral_code (grant_type=deferred). */
async function poll(deferralCode: string): Promise<Response> {
  return tokenRequest({ grant_type: DEFERRED_GRANT_TYPE, deferral_code: deferralCode });
}

/** A genuine subset of the base Mission's single authority entry, narrowed by action. */
function subset(actions: string[]): AuthorityEntry[] {
  const base = (as.kernel.get(missionId) as { authority_set: AuthorityEntry[] }).authority_set[0] as AuthorityEntry;
  return [{ ...base, actions }];
}

beforeAll(async () => {
  as = await buildAuthorizationServer({ issuer: ISSUER, allowHeadlessAdjudication: true });
  asServer = as.provider.listen(PORT);
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  dpopKeys = await generateKeyPair("ES256", { extractable: true });
  dpopJkt = await calculateJwkThumbprint(await exportJWK(dpopKeys.publicKey));

  const base = await issueBaseMissionToken();
  missionId = base.missionId;
});

afterAll(() => {
  asServer?.close();
});

describe("AS deferred grant on /token (AROP Deferred Token Response, DTR -00, D42)", () => {
  it("initiates, pends, slow_downs, then on approval issues a REAL resource-bound mission token (single-use)", async () => {
    const requested = subset(["payments:remittance.send"]);

    // 1. Initiation -> 400 authorization_pending + deferral_code, no access_token.
    const initRes = await initiate(requested);
    const initBody = (await initRes.json()) as {
      error?: string;
      deferral_code?: string;
      expires_in?: number;
      interval?: number;
      access_token?: string;
    };
    expect(initRes.status, JSON.stringify(initBody)).toBe(400);
    expect(initBody.error).toBe("authorization_pending");
    expect(initBody.deferral_code).toMatch(/^dfr_/);
    expect(initBody.expires_in).toBe(600);
    expect(initBody.interval).toBe(5);
    expect(initBody.access_token).toBeUndefined();
    expect(initRes.headers.get("cache-control")).toContain("no-store");
    const code = initBody.deferral_code as string;

    // 2. Poll before approval -> 400 authorization_pending.
    const p1 = await poll(code);
    const p1Body = (await p1.json()) as { error?: string };
    expect(p1.status).toBe(400);
    expect(p1Body.error).toBe("authorization_pending");

    // 3. Poll again immediately (too fast) -> 400 slow_down (RFC 8628). Pin
    // last_polled_at to now so the too-fast condition is deterministic: on a
    // loaded CI the two round-trips above could otherwise exceed the 5s
    // interval and flip this to authorization_pending.
    as.deferrals.db
      .prepare("UPDATE deferrals SET last_polled_at = ? WHERE deferral_code = ?")
      .run(Date.now(), code);
    const p2 = await poll(code);
    const p2Body = (await p2.json()) as { error?: string };
    expect(p2.status).toBe(400);
    expect(p2Body.error).toBe("slow_down");

    // 4. Approve (headless) with a second-aligned approval expiry that bounds the credential.
    const approvedUntil = new Date((Math.floor(Date.now() / 1000) + 120) * 1000).toISOString();
    as.deferrals.approve(code, approvedUntil);
    const okRes = await poll(code);
    const okBody = (await okRes.json()) as {
      access_token?: string;
      token_type?: string;
      expires_in?: number;
      scope?: string;
      authorization_details?: AuthorityEntry[];
    };
    expect(okRes.status, JSON.stringify(okBody)).toBe(200);
    expect(okBody.token_type).toBe("DPoP");
    expect(okBody.scope).toBe("payments");
    expect(okBody.access_token).toBeTruthy();
    expect(okRes.headers.get("cache-control")).toContain("no-store");
    // TTL clamped below the default RS TTL (300) by approved_until.
    expect(okBody.expires_in as number).toBeGreaterThan(0);
    expect(okBody.expires_in as number).toBeLessThan(300);

    // 5. Assert the token is REAL (JWT, resource-bound), not opaque.
    const jwt = okBody.access_token as string;
    expect(jwt.split(".")).toHaveLength(3);
    const jwks = createRemoteJWKSet(new URL(`${ISSUER}/jwks`));
    const { payload } = await jwtVerify(jwt, jwks, { issuer: ISSUER, audience: RESOURCE });
    expect(payload.aud).toBe(RESOURCE);
    expect((payload.mission as { id: string }).id).toBe(missionId);
    expect((payload.mission as { predecessor?: string }).predecessor).toBeUndefined();
    expect((payload.cnf as { jkt: string }).jkt).toBe(dpopJkt);
    expect(payload.exp as number).toBeLessThanOrEqual(Math.floor(Date.parse(approvedUntil) / 1000));
    // The issuer-derived RAR subset is echoed on the token.
    expect((payload.authorization_details as AuthorityEntry[])[0]?.actions).toEqual(["payments:remittance.send"]);

    // 6. Re-redeem the same code -> 400 invalid_grant (single-use, draft §5.6).
    const reRes = await poll(code);
    const reBody = (await reRes.json()) as { error?: string; access_token?: string };
    expect(reRes.status).toBe(400);
    expect(reBody.error).toBe("invalid_grant");
    expect(reBody.access_token).toBeUndefined();
  });

  it("7. an unknown deferral_code -> 400 invalid_grant", async () => {
    const res = await poll("dfr_does-not-exist");
    const body = (await res.json()) as { error?: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("invalid_grant");
  });

  it("8. an approver denial -> 400 access_denied (distinct from invalid_grant)", async () => {
    const initBody = (await (await initiate(subset(["payments:invoice.read"]))).json()) as { deferral_code: string };
    as.deferrals.deny(initBody.deferral_code);
    const res = await poll(initBody.deferral_code);
    const body = (await res.json()) as { error?: string; access_token?: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("access_denied");
    expect(body.access_token).toBeUndefined();
  });

  it("9. a deferral polled after its lifetime -> 400 expired_token", async () => {
    const initBody = (await (await initiate(subset(["payments:invoice.read", "payments:remittance.send"]))).json()) as {
      deferral_code: string;
    };
    // Backdate created_at past the advertised 600s lifetime (real endpoint, injected clock).
    as.deferrals.db
      .prepare("UPDATE deferrals SET created_at = ? WHERE deferral_code = ?")
      .run(Date.now() - 700_000, initBody.deferral_code);
    const res = await poll(initBody.deferral_code);
    const body = (await res.json()) as { error?: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("expired_token");
  });

  it("10. increments derivation_count exactly ONCE per redemption (O-36: no double-gate)", async () => {
    const count = () => (as.kernel.get(missionId) as { derivation_count: number }).derivation_count;
    const before = count();
    const initBody = (await (await initiate(subset(["payments:invoice.read"]))).json()) as { deferral_code: string };
    // open() is read-only; it must not have moved the counter.
    expect(count()).toBe(before);
    as.deferrals.approve(initBody.deferral_code, new Date((Math.floor(Date.now() / 1000) + 120) * 1000).toISOString());
    const ok = await poll(initBody.deferral_code);
    expect(ok.status, JSON.stringify(await ok.clone().json())).toBe(200);
    // The authoritative gate runs once (extraTokenClaims at mint); redeem() no
    // longer gates. Before O-36 this delta was 2.
    expect(count() - before).toBe(1);
  });
});
