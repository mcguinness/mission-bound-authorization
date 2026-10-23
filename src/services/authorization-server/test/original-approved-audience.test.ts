/**
 * @spec mission#transformation-capabilities, mission#token-response,
 * mission#error-mapping (#1503 finding 7, D620)
 *
 * "An entry's original approved audience is the audience or audiences that
 * mapping assigned the entry when the Mission was approved. ... The AS MUST
 * retain that association with the Mission; a later change to the mapping
 * does not redefine it." Without `narrowing`, "a token
 * request that would issue an entry to another audience is refused with
 * `invalid_target`". This reference declares no `narrowing` capability.
 *
 * Every Mission here approves one `prefix` entry over the payments origin.
 * Under the shipped mapping only the payments audience serves it, so that is
 * its original approved audience. A case then adds a second audience within
 * the origin, which also serves the entry. The authorization request named
 * both audiences, so oidc-provider grants a token for either; only the
 * retained association decides.
 */

import type { Server } from "node:http";
import { APPROVAL_FLOOR, AUTHORITY_SOURCES, SCOPE_PROJECTION } from "@mission/demo-data";
import { type CryptoKey, decodeJwt, exportJWK, generateKeyPair, importJWK, type JWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ApprovalSessionStore, type AuthorityEntry, type BuiltAs, buildAuthorizationServer } from "../src/index.js";
import { floorApprovalHeaders, TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";

const PORT = 14813;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const PKCE_VERIFIER = "original-audience-verifier-0123456789-0123456789";
const ORIGIN = "http://localhost:4403/";
/** The payments audience the shipped mapping names: the entry's original approved audience. */
const PAYMENTS = "http://localhost:4403/mcp";
/** An audience within the payments origin that the mapping names only after approval. */
const ADDED = "http://localhost:4403/reports";
const READ = "payments:invoice.read";

const ENTRY = { type: "mission_resource_access", resource: ORIGIN, resource_match: "prefix", actions: [READ] } as AuthorityEntry;
const CEILING: AuthorityEntry[] = [ENTRY];

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey; jwk: JWK };
type Json = Record<string, unknown>;
type TokenResponse = { status: number; body: Json };

/** The live mapping the AS reads at approval and at every issuance. */
const MAPPING = structuredClone(SCOPE_PROJECTION);
const SESSIONS = new ApprovalSessionStore();
let as: BuiltAs;
let asServer: Server;
let agentKey: CryptoKey;

/** Run `body` while the mapping also names {@link ADDED}, an `authorization_details` audience. */
async function withAddedAudience(body: () => Promise<void>): Promise<void> {
  const audiences = MAPPING.audiences as Record<string, unknown>;
  audiences[ADDED] = {
    version: "original-audience-1",
    mission_aware: true,
    mode: "authorization_details",
    mission_constraints_supported: [],
  };
  try {
    await body();
  } finally {
    delete audiences[ADDED];
  }
}

async function newKeys(): Promise<Keys> {
  const k = await generateKeyPair("ES256", { extractable: true });
  return { ...k, jwk: await exportJWK(k.publicKey) };
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
    .sign(agentKey);
}

/** PAR naming both audiences, then Bob's browser approval for alice: the authorization code. */
async function approve(): Promise<string> {
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(PKCE_VERIFIER)),
  ).toString("base64url");
  const form = new URLSearchParams({
    client_id: "ap-agent",
    response_type: "code",
    redirect_uri: REDIRECT_URI,
    code_challenge: challenge,
    code_challenge_method: "S256",
    login_hint: "alice",
    mission_intent: JSON.stringify({
      intent: { goal: "Read invoices", target_resources: [ORIGIN], expires_at: "2099-01-01T00:00:00Z" },
    }),
    authorization_details: JSON.stringify([ENTRY]),
    client_assertion: await clientAssertion(),
    client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
  });
  form.append("resource", PAYMENTS);
  form.append("resource", ADDED);
  const parRes = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });
  const par = (await parRes.json()) as Json;
  expect(parRes.status, JSON.stringify(par)).toBe(201);
  const cookies = new Map<string, string>();
  const cookie = () => [...cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  const keep = (res: Response) => {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = (pair as string).indexOf("=");
      cookies.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
    }
  };
  let res = await fetch(
    `${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: par.request_uri as string })}`,
    { redirect: "manual" },
  );
  keep(res);
  let location = res.headers.get("location") as string;
  const uid = location.split("/interaction/")[1] as string;
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...floorApprovalHeaders(SESSIONS, uid, cookie()), "content-type": "application/json" },
    body: JSON.stringify({ decision: "approve" }),
  });
  keep(res);
  location = res.headers.get("location") as string;
  while (location?.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookie() } });
    keep(res);
    location = res.headers.get("location") as string;
  }
  const code = new URL(location).searchParams.get("code");
  expect(code, location).toBeTruthy();
  return code as string;
}

/** A DPoP-bound token request, retried once with the server's nonce. */
async function token(params: Record<string, string>, keys: Keys): Promise<TokenResponse> {
  const htu = `${ISSUER}/token`;
  const send = async (extra: Json = {}) =>
    fetch(htu, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        dpop: await new SignJWT({ htm: "POST", htu, ...extra })
          .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: keys.jwk })
          .setIssuedAt()
          .setJti(crypto.randomUUID())
          .sign(keys.privateKey),
      },
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

function redeem(code: string, keys: Keys, resource: string): Promise<TokenResponse> {
  return token(
    { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: PKCE_VERIFIER, resource },
    keys,
  );
}

function refresh(refreshToken: string, keys: Keys, resource: string): Promise<TokenResponse> {
  return token({ grant_type: "refresh_token", refresh_token: refreshToken, resource }, keys);
}

function expectUnapproved(res: TokenResponse): void {
  expect(res.status, JSON.stringify(res.body)).toBe(400);
  expect(res.body.error).toBe("invalid_target");
  expect(res.body.error_description).toMatch(
    new RegExp(`audience ${ADDED} is not an original approved audience of the entry for ${ORIGIN}`),
  );
  expect(res.body.access_token).toBeUndefined();
}

function expectIssuedFor(res: TokenResponse, audience: string): void {
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  const claims = decodeJwt(res.body.access_token as string);
  expect(claims.aud).toBe(audience);
  const carried = (claims.authorization_details as Json[]).map(({ capability_sources: _s, ...e }) => e);
  expect(carried).toEqual([ENTRY]);
}

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: SESSIONS,
    scopeProjection: MAPPING,
    derivationPolicy: { policy_version: "original-audience-1503", ceiling: CEILING },
    approvalFloor: {
      ...APPROVAL_FLOOR,
      classification: [
        ...APPROVAL_FLOOR.classification,
        { type: "mission_resource_access" as const, resource: ORIGIN, actions: { [READ]: "consequential_read" as const } },
      ],
    },
    authoritySources: {
      ...AUTHORITY_SOURCES,
      entries: AUTHORITY_SOURCES.entries.map((e) => (e.id === "acme-people" ? { ...e, ceiling: CEILING as never } : e)),
    },
  });
  asServer = as.provider.listen(PORT);
  agentKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
});

afterAll(() => {
  asServer?.close();
});

describe("an entry's original approved audience is the one the trusted mapping assigned at approval (@spec mission#transformation-capabilities, mission#error-mapping, #1503 finding 7)", () => {
  it("a code exchange for an audience the mapping gained after approval is refused invalid_target, issuing no token, while a Mission approved after the change is issued for it", async () => {
    const before = await approve();
    await withAddedAudience(async () => {
      expectUnapproved(await redeem(before, await newKeys(), ADDED));
      const after = await approve();
      expectIssuedFor(await redeem(after, await newKeys(), ADDED), ADDED);
    });
  });

  it("a refresh naming an audience the mapping gained after approval is refused invalid_target, and the same refresh token still refreshes for the original approved audience", async () => {
    const keys = await newKeys();
    const issued = await redeem(await approve(), keys, PAYMENTS);
    expectIssuedFor(issued, PAYMENTS);
    const rt = issued.body.refresh_token as string;
    expect(rt).toBeTruthy();
    await withAddedAudience(async () => {
      expectUnapproved(await refresh(rt, keys, ADDED));
      expectIssuedFor(await refresh(rt, keys, PAYMENTS), PAYMENTS);
    });
  });

  it("before the mapping names the added audience, a token for it fails closed on the mapping, not on the retained association (boundary)", async () => {
    const res = await redeem(await approve(), await newKeys(), ADDED);
    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(res.body.error).toBe("invalid_target");
    expect(res.body.error_description).toMatch(new RegExp(`no scope-projection mapping for audience ${ADDED}`));
  });
});
