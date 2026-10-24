/**
 * @spec mission#transformation-capabilities, mission#token-response,
 * mission#error-mapping (#1503 finding 7, D620, D733)
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
 *
 * D733 ruling 1: a token for an audience carries only the entries whose
 * original approved audience includes it. The second suite approves an entry
 * for the payments audience and one for the SaaS audience, and each token
 * carries its own audience's entry alone.
 */

import type { Server } from "node:http";
import { APPROVAL_FLOOR, AUTHORITY_SOURCES, SCOPE_PROJECTION } from "@mission/demo-data";
import { type CryptoKey, decodeJwt, exportJWK, generateKeyPair, importJWK, type JWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { CHILD_JWT_BEARER_GRANT_TYPE } from "../src/adapters/child-grant.js";
import { ACCESS_TOKEN_TOKEN_TYPE, JWT_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import { ApprovalSessionStore, type AuthorityEntry, type BuiltAs, buildAuthorizationServer } from "../src/index.js";
import { floorApprovalHeaders, renderedRevision, TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";

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

/** The SaaS audience the shipped mapping names, and an entry approved for it alone. */
const SAAS = "http://localhost:4406/mcp";
const VENDOR_READ = "ledger:vendor.read";

const ENTRY = { type: "mission_resource_access", resource: ORIGIN, resource_match: "prefix", actions: [READ] } as AuthorityEntry;
const SAAS_ENTRY = { type: "mission_resource_access", resource: SAAS, actions: [VENDOR_READ] } as AuthorityEntry;

/** Entries that permit Child Missions, for the child redemption case. */
const LIST = "payments:invoice.list";
const CHILDREN = {
  max_depth: 1,
  allowed_delegates: [{ sub_profile: "ai_agent" }],
  children: { max_children: 5, max_child_depth: 1, allowed_child_actors: [{ sub_profile: "ai_agent" }] },
};
const ORIGIN_CHILDREN = { type: "mission_resource_access", resource: ORIGIN, resource_match: "prefix", actions: [LIST], delegation: CHILDREN } as AuthorityEntry;
const ADDED_CHILDREN = { type: "mission_resource_access", resource: ADDED, actions: [LIST], delegation: CHILDREN } as AuthorityEntry;
const CHILD_ACTOR = "subagent-invoice-extractor";
const CEILING: AuthorityEntry[] = [ENTRY, SAAS_ENTRY, ORIGIN_CHILDREN, ADDED_CHILDREN];

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

/**
 * PAR naming `resources` (both payments audiences by default), then Bob's
 * browser approval for alice: the authorization code.
 */
async function approve(
  proposal: AuthorityEntry[] = [ENTRY],
  resources: string[] = [PAYMENTS, ADDED],
  targets: string[] = [ORIGIN],
): Promise<string> {
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
      intent: { goal: "Read invoices", target_resources: targets, expires_at: "2099-01-01T00:00:00Z" },
    }),
    authorization_details: JSON.stringify(proposal),
    client_assertion: await clientAssertion(),
    client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
  });
  for (const resource of resources) form.append("resource", resource);
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
  // The decision names the rendering the Approver saw (#1446).
  const decideHeaders = floorApprovalHeaders(SESSIONS, uid, cookie());
  const render_revision = await renderedRevision(ISSUER, uid, decideHeaders);
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...decideHeaders, "content-type": "application/json" },
    body: JSON.stringify({ decision: "approve", render_revision }),
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
async function token(params: Record<string, string> | URLSearchParams, keys: Keys): Promise<TokenResponse> {
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
      body: await (async () => {
        const body = new URLSearchParams(params);
        body.set("client_assertion", await clientAssertion());
        body.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        return body.toString();
      })(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return { status: res.status, body: (await res.json()) as Json };
}

function redeem(code: string, keys: Keys, resource: string | string[]): Promise<TokenResponse> {
  const params = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: PKCE_VERIFIER,
  });
  for (const r of [resource].flat()) params.append("resource", r);
  return token(params, keys);
}

function refresh(refreshToken: string, keys: Keys, resource: string, details?: AuthorityEntry[]): Promise<TokenResponse> {
  return token(
    {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      resource,
      ...(details ? { authorization_details: JSON.stringify(details) } : {}),
    },
    keys,
  );
}

function expectUnapproved(res: TokenResponse, audience = ADDED): void {
  expect(res.status, JSON.stringify(res.body)).toBe(400);
  expect(res.body.error).toBe("invalid_target");
  expect(res.body.error_description).toMatch(
    new RegExp(`audience ${audience} is not an original approved audience of any entry the token would carry`),
  );
  expect(res.body.access_token).toBeUndefined();
}

const withoutBindings = (entries: unknown): Json[] =>
  (entries as Json[]).map(({ capability_sources: _s, ...e }) => e);

/** A 200 for `audience` whose token and response both carry exactly `entries`. */
function expectIssuedFor(res: TokenResponse, audience: string, entries: AuthorityEntry[] = [ENTRY]): void {
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  const claims = decodeJwt(res.body.access_token as string);
  expect(claims.aud).toBe(audience);
  expect(withoutBindings(claims.authorization_details)).toEqual(entries);
  expect(withoutBindings(res.body.authorization_details)).toEqual(entries);
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
        { type: "mission_resource_access" as const, resource: ORIGIN, actions: { [READ]: "consequential_read" as const, [LIST]: "consequential_read" as const } },
        { type: "mission_resource_access" as const, resource: SAAS, actions: { [VENDOR_READ]: "consequential_read" as const } },
        // A prefix entry over the origin meets every classification within it, the reports resource's included.
        { type: "mission_resource_access" as const, resource: ADDED, actions: { [READ]: "consequential_read" as const, [LIST]: "consequential_read" as const } },
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

  it("a refresh refused for an audience the mapping gained after approval spends no rotating refresh token: it still refreshes for the original approved audience (#1604 review)", async () => {
    const keys = await newKeys();
    const issued = await redeem(await approve(), keys, PAYMENTS);
    expectIssuedFor(issued, PAYMENTS);
    const rt = issued.body.refresh_token as string;
    const stored = await as.provider.RefreshToken.find(rt);
    const iat = stored?.iat as number;
    const exp = stored?.exp as number;
    expect(exp).toBeGreaterThan(iat);
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      // Past 70% of its lifetime, oidc-provider rotates the token on its next use.
      vi.setSystemTime((iat + Math.ceil((exp - iat) * 0.75)) * 1000);
      expect((await as.provider.RefreshToken.find(rt))?.ttlPercentagePassed()).toBeGreaterThanOrEqual(70);
      await withAddedAudience(async () => {
        expectUnapproved(await refresh(rt, keys, ADDED));
        const retried = await refresh(rt, keys, PAYMENTS);
        expectIssuedFor(retried, PAYMENTS);
        // The retry itself rotated the token: the refusal before it did not.
        expect(retried.body.refresh_token).toBeTruthy();
        expect(retried.body.refresh_token).not.toBe(rt);
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("an audience the retained association names but the mapping no longer names fails closed on the mapping: retention never extends issuance past the current mapping (boundary)", async () => {
    let code = "";
    await withAddedAudience(async () => {
      code = await approve();
    });
    const res = await redeem(code, await newKeys(), ADDED);
    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(res.body.error).toBe("invalid_target");
    expect(res.body.error_description).toMatch(new RegExp(`no scope-projection mapping for audience ${ADDED}`));
  });

  it("a Mission whose record retains no association fails closed: its refresh is refused invalid_target rather than read from today's mapping (D733 ruling 4)", async () => {
    const keys = await newKeys();
    const issued = await redeem(await approve(), keys, PAYMENTS);
    expectIssuedFor(issued, PAYMENTS);
    const missionId = issued.body.mission_id as string;
    // A record stored before the association was retained: the column is empty.
    as.kernel.db.prepare("UPDATE missions SET approved_audiences_json = NULL WHERE id = ?").run(missionId);
    expect(as.kernel.get(missionId)?.approved_audiences).toBeUndefined();
    expectUnapproved(await refresh(issued.body.refresh_token as string, keys, PAYMENTS), PAYMENTS);
  });
});

describe("a token for an audience carries only the entries approved for it (@spec mission#token-response, mission#error-mapping, #1503 finding 7, D733)", () => {
  const approveBoth = () => approve([ENTRY, SAAS_ENTRY], [PAYMENTS, SAAS], [ORIGIN, SAAS]);

  it("a Mission approving an entry for each of two audiences issues each audience a token carrying only its own entry: the other audience's entry does not ride", async () => {
    const keys = await newKeys();
    const payments = await redeem(await approveBoth(), keys, PAYMENTS);
    expectIssuedFor(payments, PAYMENTS, [ENTRY]);
    const saas = await refresh(payments.body.refresh_token as string, keys, SAAS);
    expectIssuedFor(saas, SAAS, [SAAS_ENTRY]);
  });

  it("a token request that explicitly names an entry approved for another audience is refused invalid_target, issuing no token and spending no refresh token", async () => {
    const keys = await newKeys();
    const payments = await redeem(await approveBoth(), keys, PAYMENTS);
    expectIssuedFor(payments, PAYMENTS, [ENTRY]);
    const rt = payments.body.refresh_token as string;
    const refused = await refresh(rt, keys, PAYMENTS, [SAAS_ENTRY]);
    expect(refused.status, JSON.stringify(refused.body)).toBe(400);
    expect(refused.body.error).toBe("invalid_target");
    expect(refused.body.error_description).toMatch(
      new RegExp(`audience ${PAYMENTS} is not an original approved audience of the requested entry for ${SAAS}`),
    );
    expect(refused.body.access_token).toBeUndefined();
    expectIssuedFor(await refresh(rt, keys, PAYMENTS, [ENTRY]), PAYMENTS, [ENTRY]);
  });

  it("a token request naming both audiences is refused invalid_target, and a separate token is issued for each (multi-audience)", async () => {
    const keys = await newKeys();
    const combined = await redeem(await approveBoth(), keys, [PAYMENTS, SAAS]);
    expect(combined.status, JSON.stringify(combined.body)).toBe(400);
    expect(combined.body.error).toBe("invalid_target");
    expect(combined.body.access_token).toBeUndefined();
    const payments = await redeem(await approveBoth(), keys, PAYMENTS);
    expectIssuedFor(payments, PAYMENTS, [ENTRY]);
    expectIssuedFor(await refresh(payments.body.refresh_token as string, keys, SAAS), SAAS, [SAAS_ENTRY]);
  });
});

describe("a child's redemption carries only the entries approved for its audience (@spec mission#token-response, #1503 finding 7, D733)", () => {
  /** The child actor's own client authentication and DPoP proof, retried once with the server's nonce. */
  async function childRedeem(assertion: string, keys: Keys): Promise<TokenResponse> {
    const childKey = (await importJWK(as.childClientJwk as never, "ES256")) as CryptoKey;
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
          grant_type: CHILD_JWT_BEARER_GRANT_TYPE,
          assertion,
          client_assertion: await new SignJWT({})
            .setProtectedHeader({ alg: "ES256", kid: `${CHILD_ACTOR}-auth` })
            .setIssuer(CHILD_ACTOR)
            .setSubject(CHILD_ACTOR)
            .setAudience(ISSUER)
            .setIssuedAt()
            .setExpirationTime("2m")
            .setJti(crypto.randomUUID())
            .sign(childKey),
          client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        }).toString(),
      });
    let res = await send();
    const nonce = res.headers.get("dpop-nonce");
    if (res.status === 400 && nonce) res = await send({ nonce });
    return { status: res.status, body: (await res.json()) as Json };
  }

  it("a Child Mission whose entries are approved for different audiences redeems a token for its first entry's audience without the entry approved only for the other", async () => {
    await withAddedAudience(async () => {
      // The parent approves the origin prefix (both audiences) and the reports entry (that audience alone).
      const keys = await newKeys();
      const parentToken = await redeem(await approve([ORIGIN_CHILDREN, ADDED_CHILDREN], [PAYMENTS, ADDED], [ORIGIN, ADDED]), keys, ADDED);
      expect(parentToken.status, JSON.stringify(parentToken.body)).toBe(200);
      const parentId = parentToken.body.mission_id as string;
      const parent = as.kernel.get(parentId);
      parent?.authority_set.forEach((e, i) =>
        expect(parent.approved_audiences?.[i], e.resource as string).toEqual(e.resource === ORIGIN ? [PAYMENTS, ADDED] : [ADDED]),
      );
      // A child within the token's authority: a payments entry, and a reports
      // entry inside both parent entries, so its association is the reports
      // audience alone.
      const payments = { type: "mission_resource_access", resource: PAYMENTS, actions: [LIST] } as AuthorityEntry;
      const reports = { type: "mission_resource_access", resource: ADDED, actions: [LIST] } as AuthorityEntry;
      const created = await token(
        {
          grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
          subject_token: parentToken.body.access_token as string,
          subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
          requested_token_type: JWT_TOKEN_TYPE,
          creation_request_id: crypto.randomUUID(),
          login_hint: "alice",
          mission_intent: JSON.stringify({
            intent: { goal: "List Acme invoices and reports", target_resources: [PAYMENTS, ADDED], expires_at: "2099-01-01T00:00:00Z" },
          }),
          authorization_details: JSON.stringify([payments, reports]),
          child_actor: JSON.stringify({ sub: CHILD_ACTOR, sub_profile: "ai_agent" }),
        },
        keys,
      );
      expect(created.status, JSON.stringify(created.body)).toBe(200);
      const child = as.kernel.get(created.body.mission_id as string);
      expect(child?.authority_set[0]?.resource).toBe(PAYMENTS);
      child?.authority_set.forEach((e, i) =>
        expect(child.approved_audiences?.[i], e.resource as string).toEqual(e.resource === PAYMENTS ? [PAYMENTS, ADDED] : [ADDED]),
      );
      expect(child?.authority_set.some((e) => e.resource === ADDED)).toBe(true);

      const issued = await childRedeem(created.body.access_token as string, await newKeys());
      expect(issued.status, JSON.stringify(issued.body)).toBe(200);
      const claims = decodeJwt(issued.body.access_token as string);
      expect(claims.aud).toBe(PAYMENTS);
      expect((claims.authorization_details as Json[]).map((e) => e.resource)).toEqual([PAYMENTS]);
      expect((issued.body.authorization_details as Json[]).map((e) => e.resource)).toEqual([PAYMENTS]);
    });
  });
});
