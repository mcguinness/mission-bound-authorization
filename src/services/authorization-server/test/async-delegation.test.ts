/**
 * @spec async-delegation — the async-delegation continuation transport on the real
 * /token endpoint.
 *
 * An acting client presents a base mission ACCESS token (RFC 8693 subject_token,
 * subject_token_type = access_token) with request_refresh_token=true and receives an
 * initial DPoP-bound access token AND a rotated, sender-constrained refresh token,
 * both bound to a NEW per-delegation Grant tracked in the DelegationFamilyStore.
 * Refresh redemption is ordinary native grant_type=refresh_token.
 *
 * Guardrails proven here:
 *   1. per-delegation grant isolation — an async-family RT reuse wipe leaves the
 *      Mission's code-flow refresh token and child-creation working;
 *   2. single count — derivation_count rises by exactly 1 across issuance + N
 *      refreshes; an ordinary code-flow refresh still increments;
 *   3. refreshed access tokens stay audienced to the target;
 *   4. addResourceScope(target) present (else refresh filters the scope empty);
 *   5. the refresh token is sender-constrained (a fresh DPoP proof per refresh; a
 *      wrong key fails jkt verification);
 *   6. request_refresh_token survives token-endpoint param stripping (a successful
 *      async issuance IS the survival proof: absent the flag the ICA path would run);
 *   7. mandatory rotation — a consumed-RT retry trips reuse detection, killing THIS
 *      family only;
 *   plus absolute-lifetime clamping and family revocation on terminal lifecycle paths.
 */

import { type Server } from "node:http";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import {
  calculateJwkThumbprint,
  createRemoteJWKSet,
  decodeJwt,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify,
  SignJWT,
} from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TOKEN_EXCHANGE_GRANT_TYPE, ACCESS_TOKEN_TOKEN_TYPE, JWT_TOKEN_TYPE } from "../src/adapters/continuation-grant.js";
import { buildAuthorizationServer, type BuiltAs } from "../src/index.js";

const PORT = 14480;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE; // served by ISSUER (intra-domain target)
const FAR_EXP = "2027-01-01T00:00:00Z";

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };

let as: BuiltAs;
let asServer: Server;
let clientKey: CryptoKey; // ap-agent private_key_jwt key (kid ap-agent-auth)
let childClientKey: CryptoKey; // child actor private_key_jwt key
let codeDpop: Keys; // DPoP key for the base-mission code flow
let actingDpop: Keys; // DPoP key for the async exchange + refreshes (a DIFFERENT key)
let actingJkt: string;
let remoteJwks: ReturnType<typeof createRemoteJWKSet>;

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** The Mission's full Authority Set (two actions, so a strict subset exists). */
const fullAuthority = () => [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions: ["payments:invoice.read", "payments:remittance.send"],
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];

/** A strict subset of the full authority (narrowed by action). */
const confinedAuthority = () => [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions: ["payments:invoice.read"],
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];

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

async function childClientAssertion(): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "subagent-invoice-extractor-auth" })
    .setIssuer("subagent-invoice-extractor")
    .setSubject("subagent-invoice-extractor")
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(childClientKey);
}

async function dpopProof(keys: Keys, extra: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({ htu: `${ISSUER}/token`, htm: "POST", ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}

function cookieHeader(jar: Map<string, string>): string {
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}
function storeCookies(res: Response, jar: Map<string, string>): void {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
  }
}

/** POST /token with ap-agent private_key_jwt + a code-flow DPoP proof (nonce retry). */
async function codeTokenRequest(params: Record<string, string>): Promise<Response> {
  const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
    fetch(`${ISSUER}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(codeDpop, extra) },
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

/**
 * Full PAR -> approval -> token code flow yielding an ACTIVE Mission, a base mission
 * ACCESS token (DPoP-bound to codeDpop), and the Mission's code-flow refresh token.
 */
async function issueBaseMission(expiresAt: string = FAR_EXP): Promise<{
  missionId: string;
  baseAccessToken: string;
  missionRefreshToken: string;
}> {
  const jar = new Map<string, string>();
  const verifier = "async-delegation-verifier-0123456789-0123456789-0123";
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
  ).toString("base64url");
  const intent = JSON.stringify({
    goal: "Pay Acme invoices and send remittance",
    resources: [RESOURCE],
    expires_at: expiresAt,
    proposed_authority: fullAuthority(),
  });
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
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const { request_uri } = (await par.json()) as { request_uri: string };

  let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`, {
    redirect: "manual",
  });
  storeCookies(res, jar);
  let location = res.headers.get("location") as string;
  const uid = location.split("/interaction/")[1] as string;

  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/json", cookie: cookieHeader(jar) },
    body: JSON.stringify({ decision: "approve", approver: "bob", subject: "alice" }),
  });
  storeCookies(res, jar);
  location = res.headers.get("location") as string;
  while (location?.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader(jar) } });
    storeCookies(res, jar);
    location = res.headers.get("location") as string;
  }
  const code = new URL(location).searchParams.get("code") as string;

  const tok = await codeTokenRequest({
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier,
    resource: RESOURCE,
  });
  const body = (await tok.json()) as { access_token: string; refresh_token: string };
  expect(tok.status, JSON.stringify(body)).toBe(200);
  const claims = decodeJwt(body.access_token) as { mission: { id: string } };
  return { missionId: claims.mission.id, baseAccessToken: body.access_token, missionRefreshToken: body.refresh_token };
}

interface ExchangeOpts {
  authorizationDetails?: unknown;
  resource?: string;
}

/** POST /token: token-exchange + request_refresh_token=true (the async transport). */
async function asyncDelegate(baseAccessToken: string, opts: ExchangeOpts = {}): Promise<Response> {
  const params: Record<string, string> = {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    request_refresh_token: "true",
    subject_token: baseAccessToken,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    resource: opts.resource ?? RESOURCE,
  };
  if (opts.authorizationDetails !== undefined) {
    params.authorization_details = JSON.stringify(opts.authorizationDetails);
  }
  const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
    fetch(`${ISSUER}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(actingDpop, extra) },
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

/** Native grant_type=refresh_token with a FRESH DPoP proof (default key = actingDpop). */
async function refreshFamily(refreshToken: string, keys: Keys = actingDpop): Promise<Response> {
  const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
    fetch(`${ISSUER}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(keys, extra) },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return res;
}

/**
 * Create a Child Mission via the RFC 8693 token exchange (request side of #448's
 * possession fix). subject_token is the parent Mission's code-flow ACCESS token
 * (bound to `codeDpop`); possession is proven by a DPoP proof over that SAME key
 * (codeTokenRequest signs with codeDpop). The parent is resolved FROM subject_token;
 * `parent` is a non-authoritative cross-check. No refresh token is involved.
 */
async function createChildViaExchange(subjectToken: string, parentId: string): Promise<Response> {
  return codeTokenRequest({
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: subjectToken,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    requested_token_type: JWT_TOKEN_TYPE,
    parent: parentId,
    mission_intent: JSON.stringify({
      goal: "Extract Acme invoices",
      resources: [RESOURCE],
      expires_at: FAR_EXP,
      proposed_authority: confinedAuthority(),
    }),
    child_actor: JSON.stringify({ sub: "subagent-invoice-extractor", sub_profile: "ai_agent" }),
  });
}

beforeAll(async () => {
  as = await buildAuthorizationServer({ issuer: ISSUER, allowHeadlessAdjudication: true });
  asServer = as.provider.listen(PORT);
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  childClientKey = (await importJWK(as.childClientJwk as never, "ES256")) as CryptoKey;
  codeDpop = await generateKeyPair("ES256", { extractable: true });
  actingDpop = await generateKeyPair("ES256", { extractable: true });
  actingJkt = await calculateJwkThumbprint(await exportJWK(actingDpop.publicKey));
  remoteJwks = createRemoteJWKSet(new URL(`${ISSUER}/jwks`));
});

afterAll(() => {
  asServer?.close();
});

describe("async-delegation issuance (@spec async-delegation)", () => {
  it("mints an initial DPoP-bound access token (aud=target, mission claim, confined authorization_details) AND a refresh token; request_refresh_token survives stripping", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const res = await asyncDelegate(baseAccessToken, { authorizationDetails: confinedAuthority() });
    const body = (await res.json()) as {
      access_token?: string;
      token_type?: string;
      expires_in?: number;
      refresh_token?: string;
      authorization_details?: unknown;
      error?: string;
    };
    // A 200 with a refresh_token IS the survival proof: had request_refresh_token
    // been stripped, the ICA path would run and reject the missing requested_token_type.
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(body.token_type).toBe("DPoP");
    expect(typeof body.refresh_token).toBe("string");
    expect((body.refresh_token as string).length).toBeGreaterThan(0);
    expect(body.expires_in).toBeGreaterThan(0);
    expect(res.headers.get("cache-control")).toContain("no-store");
    expect(body.authorization_details).toEqual(confinedAuthority());

    const { payload } = await jwtVerify(body.access_token as string, remoteJwks, {
      issuer: ISSUER,
      audience: RESOURCE,
    });
    expect(payload.aud).toBe(RESOURCE);
    expect((payload.cnf as { jkt?: string }).jkt).toBe(actingJkt); // sender-constrained to the acting DPoP key
    expect((payload.mission as { id?: string }).id).toBe(missionId);
    expect(payload.authorization_details).toEqual(confinedAuthority());

    // The family is recorded (grant_id -> mission_id).
    const families = as.delegationFamilyStore.familiesForMission(missionId);
    expect(families).toHaveLength(1);
    expect(as.delegationFamilyStore.resolve(families[0] as string)?.missionId).toBe(missionId);
  });

  it("confinement: an absent authorization_details confines to the full active Authority Set (the derived set, not the raw proposal)", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const derived = as.kernel.get(missionId)?.authority_set;
    const res = await asyncDelegate(baseAccessToken); // no authorization_details
    const body = (await res.json()) as { access_token?: string; authorization_details?: unknown };
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(body.authorization_details).toEqual(derived);
    const { payload } = await jwtVerify(body.access_token as string, remoteJwks, { issuer: ISSUER, audience: RESOURCE });
    expect(payload.authorization_details).toEqual(derived);
  });
});

describe("async-delegation disconnected refresh (@spec async-delegation)", () => {
  it("grant_type=refresh_token with no resource -> a new access token audienced to the target + a rotated refresh token", async () => {
    const { baseAccessToken } = await issueBaseMission();
    const first = (await (await asyncDelegate(baseAccessToken, { authorizationDetails: confinedAuthority() })).json()) as {
      refresh_token: string;
      access_token: string;
    };

    const res = await refreshFamily(first.refresh_token);
    const body = (await res.json()) as {
      access_token?: string;
      refresh_token?: string;
      token_type?: string;
      error?: string;
    };
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(body.token_type).toBe("DPoP");
    // Mandatory rotation: a fresh refresh token value is returned.
    expect(body.refresh_token).toBeTruthy();
    expect(body.refresh_token).not.toBe(first.refresh_token);

    // The refreshed access token is still audienced to the target (resource carried
    // on the refresh token) and still sender-constrained to the acting key, and it
    // still projects the confined subset (guardrail: refreshed AT authorization_details).
    const { payload } = await jwtVerify(body.access_token as string, remoteJwks, { issuer: ISSUER, audience: RESOURCE });
    expect(payload.aud).toBe(RESOURCE);
    expect((payload.cnf as { jkt?: string }).jkt).toBe(actingJkt);
    expect(payload.authorization_details).toEqual(confinedAuthority());
  });

  it("sender-constrained refresh token: a DPoP proof from the WRONG key fails jkt verification", async () => {
    const { baseAccessToken } = await issueBaseMission();
    const { refresh_token } = (await (await asyncDelegate(baseAccessToken)).json()) as { refresh_token: string };
    // Present the code-flow DPoP key (not the acting key the refresh token is bound to).
    const res = await refreshFamily(refresh_token, codeDpop);
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
  });
});

describe("containment refresh-path conformance (derivation MUST NOT carry a contained capability)", () => {
  const containRemittance = (missionId: string, eventId: string): void => {
    as.kernel.contain(missionId, {
      event: {
        type: "tainted_read",
        source: "https://siem.example/detections",
        observed_at: new Date().toISOString(),
        event_id: eventId,
      },
      remove: [{ resource: RESOURCE, actions: ["payments:remittance.send"] }],
    });
  };

  /** The Mission's derived set with remittance.send stripped (the expected effective projection). */
  const withoutRemittance = (missionId: string): unknown =>
    (as.kernel.get(missionId)?.authority_set ?? []).map((e) => ({
      ...e,
      actions: e.actions.filter((a) => a !== "payments:remittance.send"),
    }));

  it("contain, then refresh the async-delegation family: the refreshed access token EXCLUDES the contained capability", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const first = (await (await asyncDelegate(baseAccessToken)).json()) as {
      refresh_token: string;
      authorization_details?: unknown;
    };
    // Pre-containment the family grant carries the FULL derived set (the rar
    // copied at issuance): this is exactly the copy that must not be echoed.
    expect(first.authorization_details).toEqual(as.kernel.get(missionId)?.authority_set);

    containRemittance(missionId, "ce-async-1");

    const res = await refreshFamily(first.refresh_token);
    const body = (await res.json()) as { access_token?: string; authorization_details?: unknown; error?: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    // The stored grant still holds the issuance-time copy, but the token
    // response re-projects it through the effective set: remittance.send is gone.
    expect(body.authorization_details).toEqual(withoutRemittance(missionId));
    const { payload } = await jwtVerify(body.access_token as string, remoteJwks, { issuer: ISSUER, audience: RESOURCE });
    expect(payload.authorization_details).toEqual(withoutRemittance(missionId));
  });

  it("contain, then refresh the CODE-FLOW mission grant: same conformance on the approval grant's copied rar", async () => {
    const { missionId, missionRefreshToken } = await issueBaseMission();
    containRemittance(missionId, "ce-code-1");
    const res = await refreshFamily(missionRefreshToken, codeDpop); // the mission grant's own RT
    const body = (await res.json()) as { access_token?: string; authorization_details?: unknown; error?: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(body.authorization_details).toEqual(withoutRemittance(missionId));
    const payload = decodeJwt(body.access_token as string);
    expect(payload.authorization_details).toEqual(withoutRemittance(missionId));
  });

  it("regression: a no-containment mission's refresh is byte-identical to issuance (fast path)", async () => {
    const { baseAccessToken } = await issueBaseMission();
    const first = (await (await asyncDelegate(baseAccessToken)).json()) as {
      refresh_token: string;
      access_token: string;
      authorization_details?: unknown;
    };
    const res = await refreshFamily(first.refresh_token);
    const body = (await res.json()) as { access_token?: string; authorization_details?: unknown; error?: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    // Byte-identical authorization_details across issuance and refresh.
    expect(JSON.stringify(body.authorization_details)).toBe(JSON.stringify(first.authorization_details));
    expect(JSON.stringify(decodeJwt(body.access_token as string).authorization_details)).toBe(
      JSON.stringify(decodeJwt(first.access_token).authorization_details),
    );
  });
});

describe("async-delegation single count (@spec async-delegation)", () => {
  it("derivation_count rises by exactly 1 across issuance + N refreshes", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const before = as.kernel.get(missionId)?.derivation_count as number;

    const first = (await (await asyncDelegate(baseAccessToken)).json()) as { refresh_token: string };
    const afterExchange = as.kernel.get(missionId)?.derivation_count as number;
    expect(afterExchange - before).toBe(1); // the SINGLE family count (gateDerivation)

    // N refreshes re-gate with gateActive only (no increment).
    let rt = first.refresh_token;
    for (let i = 0; i < 3; i++) {
      const b = (await (await refreshFamily(rt)).json()) as { refresh_token?: string; error?: string };
      expect(b.error, `refresh ${i}`).toBeUndefined();
      rt = b.refresh_token as string;
    }
    const afterRefreshes = as.kernel.get(missionId)?.derivation_count as number;
    expect(afterRefreshes).toBe(afterExchange);
    expect(afterRefreshes - before).toBe(1);
  });

  it("regression: an ordinary code-flow refresh STILL increments derivation_count", async () => {
    const { missionId, missionRefreshToken } = await issueBaseMission();
    const before = as.kernel.get(missionId)?.derivation_count as number;
    const res = await refreshFamily(missionRefreshToken, codeDpop); // the mission grant's own RT
    const body = (await res.json()) as { access_token?: string; error?: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    const after = as.kernel.get(missionId)?.derivation_count as number;
    expect(after).toBe(before + 1);
  });
});

describe("async-delegation terminal paths (@spec async-delegation)", () => {
  it("revoke Mission -> next refresh invalid_grant + the family is destroyed", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const { refresh_token } = (await (await asyncDelegate(baseAccessToken)).json()) as { refresh_token: string };
    const grantId = as.delegationFamilyStore.familiesForMission(missionId)[0] as string;
    expect(as.delegationFamilyStore.resolve(grantId)?.missionId).toBe(missionId);

    as.kernel.transition(missionId, "revoke");
    // The fan-out marked the family terminal AND destroyed its oidc grant.
    expect(as.delegationFamilyStore.resolve(grantId)).toBeUndefined();

    const res = await refreshFamily(refresh_token);
    const body = (await res.json()) as { access_token?: string; error?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    // Assert on the error itself, not merely on "not 200": a claimless 200 must fail loudly.
    expect(body.error).toBe("invalid_grant");
    expect(body.access_token).toBeUndefined();
  });

  it("absolute-lifetime clamp: the initial access token exp never exceeds the Mission expires_at", async () => {
    const expiresAt = new Date(Date.now() + 60_000).toISOString(); // 60s < the 300s AT default
    const { missionId, baseAccessToken } = await issueBaseMission(expiresAt);
    const { access_token } = (await (await asyncDelegate(baseAccessToken)).json()) as { access_token: string };
    const atExp = decodeJwt(access_token).exp as number;
    const missionExp = Math.floor(Date.parse(as.kernel.get(missionId)?.expires_at as string) / 1000);
    expect(atExp).toBeLessThanOrEqual(missionExp);
    expect(atExp).toBeGreaterThan(Math.floor(Date.now() / 1000)); // still in the future
  });

  it(
    "absolute-lifetime: the refresh token cannot outlive the Mission (ttl.RefreshToken clamp)",
    async () => {
      const expiresAt = new Date(Date.now() + 4_000).toISOString();
      const { missionId, baseAccessToken } = await issueBaseMission(expiresAt);
      const { refresh_token } = (await (await asyncDelegate(baseAccessToken)).json()) as { refresh_token: string };
      const grantId = as.delegationFamilyStore.familiesForMission(missionId)[0] as string;

      // Wait until just past the Mission expires_at (computed relative to expiresAt so
      // setup time cannot cause a false failure). The refresh token TTL was clamped to
      // the Mission lifetime, so it cannot outlive the Mission.
      await sleep(Date.parse(expiresAt) - Date.now() + 700);

      const res = await refreshFamily(refresh_token);
      const body = (await res.json()) as { access_token?: string; error?: string };
      expect(res.status, JSON.stringify(body)).toBe(400);
      expect(body.error).toBe("invalid_grant");
      expect(body.access_token).toBeUndefined();

      // DISCRIMINATOR for the ttl.RefreshToken clamp: oidc-provider rejected on
      // refresh-token EXPIRY, before any mission gate ran, so the lazy mission-expiry
      // commit never landed and the family is STILL active. Absent the clamp the
      // refresh token would still be valid, the refresh would reach extraTokenClaims
      // -> gateActive -> applyExpiry, and THAT commit would have marked the family
      // terminal (resolve -> undefined). So "still active" proves the clamp fired.
      expect(as.delegationFamilyStore.resolve(grantId)?.state).toBe("active");
    },
    15_000,
  );

  it("terminal subscriber covers a non-revoke path: an expiry commit terminates the family (family-revoke-on-all-terminal-paths)", async () => {
    // A far-future Mission so the family is live; then land the expiry commit
    // explicitly (the same applyExpiry the kernel runs lazily). This exercises the
    // SAME single fan-out funnel as revoke/complete/cascade/supersede, keyed on
    // commit.id, proving the subscriber is not revoke-specific.
    const shortExp = new Date(Date.now() + 1_000).toISOString();
    const { missionId, baseAccessToken } = await issueBaseMission(shortExp);
    await asyncDelegate(baseAccessToken);
    const grantId = as.delegationFamilyStore.familiesForMission(missionId)[0] as string;
    expect(as.delegationFamilyStore.resolve(grantId)?.missionId).toBe(missionId);

    await sleep(1_200); // past shortExp
    // Land the lazy expiry: applyExpiry commits `expired` and fires the fan-out
    // (familyStore terminal marking is synchronous, so resolve is undefined at once).
    const rec = as.kernel.get(missionId);
    as.kernel.applyExpiry(rec as NonNullable<typeof rec>);
    expect(as.kernel.get(missionId)?.state).toBe("expired");
    expect(as.delegationFamilyStore.resolve(grantId)).toBeUndefined();
  }, 15_000);
});

describe("async-delegation blast-radius isolation (@spec async-delegation)", () => {
  it("a family RT reuse wipe kills THIS family only; the Mission code-flow RT and child-creation still succeed", async () => {
    const { missionId, baseAccessToken, missionRefreshToken } = await issueBaseMission();
    const { refresh_token: familyRt } = (await (await asyncDelegate(baseAccessToken, {
      authorizationDetails: confinedAuthority(),
    })).json()) as { refresh_token: string };
    const grantId = as.delegationFamilyStore.familiesForMission(missionId)[0] as string;

    // Rotate once (familyRt consumed, familyRt2 issued).
    const rotated = (await (await refreshFamily(familyRt)).json()) as { refresh_token: string };
    expect(rotated.refresh_token).toBeTruthy();

    // Retry the CONSUMED familyRt -> reuse detection wipes THIS per-delegation grant.
    const reuse = await refreshFamily(familyRt);
    const reuseBody = (await reuse.json()) as { error?: string };
    expect(reuse.status, JSON.stringify(reuseBody)).toBe(400);
    expect(reuseBody.error).toBe("invalid_grant");

    // The new family RT is now dead too (whole family wiped).
    const deadFamily = await refreshFamily(rotated.refresh_token);
    expect(deadFamily.status).toBe(400);

    // ISOLATION (1): the Mission's code-flow refresh token STILL refreshes -> the
    // Mission approval grant was untouched by the per-delegation wipe.
    const codeRefresh = await refreshFamily(missionRefreshToken, codeDpop);
    const codeBody = (await codeRefresh.json()) as { access_token?: string; error?: string };
    expect(codeRefresh.status, JSON.stringify(codeBody)).toBe(200);
    expect(codeBody.access_token).toBeTruthy();

    // ISOLATION (2): child-creation under the SAME Mission still succeeds -> the
    // base Mission access token still resolves the parent and the grant is intact.
    const created = await createChildViaExchange(baseAccessToken, missionId);
    const createdBody = (await created.json()) as { mission_id?: string; error?: string; mission_denial_reason?: string };
    expect(created.status, JSON.stringify(createdBody)).toBe(200);
    expect(createdBody.mission_id).toBeTruthy();

    void grantId;
  });
});

describe("async-delegation discovery (@spec async-delegation#discovery)", () => {
  it("advertises delegated_refresh_token_profile_supported (alongside identity_continuation_supported)", async () => {
    const meta = (await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
    expect(meta.delegated_refresh_token_profile_supported).toBe(true);
    expect(meta.identity_continuation_supported).toBe(true);
  });
});
