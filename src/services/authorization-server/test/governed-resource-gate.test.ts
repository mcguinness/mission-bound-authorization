/**
 * @spec mission#authority-proposal, mission#mission-claim-reservation
 * (#1531, D741): a Mission-governed resource gets no token outside a Mission,
 * on any grant type, over the real AS assembly.
 *
 * A resource is governed by the deployment's classification or by protected
 * resource metadata the AS has authenticated; the two sources are joined so
 * that neither clears the other. A token request with no qualifying Mission
 * binding whose token would carry a governed audience, named or inferred, is
 * refused `invalid_target` once it is otherwise processable, whole when any
 * one of its audiences is governed, and on a refresh before the refresh token
 * is consumed or rotated. Authentication, syntax and grant-validation
 * failures keep their errors, and a grant bound to a Mission that is not
 * `active` keeps the Issuance Gating refusal.
 *
 * Ordinary grants: the reference's authorization endpoint answers a request
 * with no `mission_intent` only from an ordinary grant the session already
 * holds (mission-approval-interaction.test.ts), so the ordinary codes here are
 * seeded under ordinary provider Grants and redeemed at the real token
 * endpoint. `client_credentials` is enabled by the test-only build option.
 * The device authorization endpoint accepts only a Mission submission, and
 * every token exchange derives from a Mission-bound subject token, so neither
 * has an ordinary path to refuse; an ordinary subject token is refused by the
 * exchange's own subject validation.
 */

import { type Server } from "node:http";
import { CANONICAL_RESOURCE, DEV_SERVICE_TOKEN, GOVERNED_RESOURCES, TOPOLOGY } from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, SignJWT, type CryptoKey, type JWK } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  ApprovalSessionStore,
  buildAuthorizationServer,
  type BuiltAs,
  governedResourceRefusal,
  isMissionGovernedResource,
  withoutGovernedResource,
} from "../src/index.js";
import { browserApprovalHeaders, renderedRevision, TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";

const PORT = 15311;
const ISSUER = `http://localhost:${PORT}`;
const UNGOVERNED_PORT = 15312;
const UNGOVERNED_ISSUER = `http://localhost:${UNGOVERNED_PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const VERIFIER = "governed-resource-gate-verifier-0123456789-0123456789";
const SESSIONS = new ApprovalSessionStore();
const ALICE = { sub: "alice", acr: "mfa" };

/** The reports resource: classified governed here, so a Mission on it exercises the precedence rule. */
const PLAIN = TOPOLOGY.resources.plainRs;
/** Classified governed by the deployment, with no metadata. */
const CLASSIFIED = "https://classified.governed.test/api";
/** Unclassified, with authenticated metadata declaring the requirement. */
const DECLARED = "https://declared.governed.test/api";
/** Classified `not_governed` locally, with authenticated metadata declaring the requirement. */
const LOCALLY_UNGOVERNED = "https://locally-ungoverned.governed.test/api";
/** Classified governed, with authenticated metadata setting the member to `false`. */
const CLASSIFIED_METADATA_FALSE = "https://classified-false.governed.test/api";
/** Classified governed, with an authenticated metadata record that omits the member. */
const CLASSIFIED_METADATA_OMITS = "https://classified-omits.governed.test/api";
/** Unclassified, with authenticated metadata setting the member to `false`: not governed. */
const METADATA_FALSE = "https://metadata-false.ungoverned.test/api";
/** Neither classified nor described: not governed. */
const UNGOVERNED = "https://ungoverned.test/api";

const POLICY = {
  classification: {
    [PLAIN]: "governed",
    [CLASSIFIED]: "governed",
    [LOCALLY_UNGOVERNED]: "not_governed",
    [CLASSIFIED_METADATA_FALSE]: "governed",
    [CLASSIFIED_METADATA_OMITS]: "governed",
    [CANONICAL_RESOURCE]: "governed",
    // The AS's default audience (`defaultResource` is the issuer).
    [ISSUER]: "governed",
  },
  authenticated_metadata: {
    [DECLARED]: { mission_bound_authorization_required: true },
    [LOCALLY_UNGOVERNED]: { mission_bound_authorization_required: true },
    [CLASSIFIED_METADATA_FALSE]: { mission_bound_authorization_required: false },
    [CLASSIFIED_METADATA_OMITS]: {},
    [METADATA_FALSE]: { mission_bound_authorization_required: false },
  },
} as const;

const PUBLIC_CLIENT = "gate-public-client";
const CC_CLIENT = "gate-cc-client";

let as: BuiltAs;
let server: Server;
let ungoverned: BuiltAs;
let ungovernedServer: Server;
let agentKey: CryptoKey;
let ccKey: CryptoKey;

beforeAll(async () => {
  const cc = await generateKeyPair("ES256", { extractable: true });
  ccKey = cc.privateKey as CryptoKey;
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: SESSIONS,
    governedResources: POLICY,
    testClientCredentials: true,
    devOrdinaryIssuance: true,
    testClients: [
      {
        // A public client: oidc-provider rotates its refresh token on every
        // refresh (lib/helpers/defaults.js rotateRefreshToken), so the
        // refresh-before-rotation witness sees a consumed token.
        client_id: PUBLIC_CLIENT,
        client_name: "Governed-resource gate public client",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        redirect_uris: [REDIRECT_URI],
        token_endpoint_auth_method: "none",
        scope: "openid",
      },
      {
        client_id: CC_CLIENT,
        client_name: "Governed-resource gate client credentials client",
        grant_types: ["client_credentials"],
        response_types: [],
        redirect_uris: [],
        token_endpoint_auth_method: "private_key_jwt",
        token_endpoint_auth_signing_alg: "ES256",
        jwks: { keys: [{ ...(await exportJWK(cc.publicKey)), kid: "gate-cc-auth", alg: "ES256" }] },
      },
    ],
  });
  server = as.provider.listen(PORT);
  agentKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  ungoverned = await buildAuthorizationServer({
    issuer: UNGOVERNED_ISSUER,
    governedResources: withoutGovernedResource(POLICY, CANONICAL_RESOURCE),
    devOrdinaryIssuance: true,
  });
  ungovernedServer = ungoverned.provider.listen(UNGOVERNED_PORT);
});

afterAll(() => {
  server?.close();
  ungovernedServer?.close();
});

type Keys = { privateKey: CryptoKey; jwk: JWK };
const newKeys = async (): Promise<Keys> => {
  const pair = await generateKeyPair("ES256", { extractable: true });
  return { privateKey: pair.privateKey as CryptoKey, jwk: await exportJWK(pair.publicKey) };
};

const assertion = (clientId: string, kid: string, key: CryptoKey, audience = ISSUER) =>
  new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid })
    .setIssuer(clientId)
    .setSubject(clientId)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(key);

type Client = "ap-agent" | typeof PUBLIC_CLIENT | typeof CC_CLIENT;

/** How `client` authenticates on a form: an assertion, a bad one, or (public) its identifier. */
async function clientAuth(client: Client, bad = false): Promise<[string, string][]> {
  if (client === PUBLIC_CLIENT) return [["client_id", PUBLIC_CLIENT]];
  const key = bad ? ((await generateKeyPair("ES256")).privateKey as CryptoKey) : client === CC_CLIENT ? ccKey : agentKey;
  const kid = client === CC_CLIENT ? "gate-cc-auth" : "ap-agent-auth";
  return [
    ["client_assertion", await assertion(client, kid, key)],
    ["client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"],
  ];
}

type Answer = { status: number; body: Record<string, unknown> };

/**
 * A token request: `params` as name-value pairs (a name may repeat), the
 * client's authentication, and a DPoP proof under `dpop` when given (one
 * nonce retry).
 */
async function tokenRequest(
  params: [string, string][],
  client: Client,
  opts: { dpop?: Keys; badAuth?: boolean } = {},
): Promise<Answer> {
  const htu = `${ISSUER}/token`;
  const proof = (k: Keys, nonce?: string) =>
    new SignJWT({ htu, htm: "POST", ...(nonce ? { nonce } : {}) })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: k.jwk })
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .sign(k.privateKey);
  const send = async (nonce?: string) =>
    fetch(htu, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        ...(opts.dpop ? { dpop: await proof(opts.dpop, nonce) } : {}),
      },
      body: new URLSearchParams([...params, ...(await clientAuth(client, opts.badAuth))]).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (opts.dpop && res.status === 400 && nonce) res = await send(nonce);
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

const CHALLENGE = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER))).toString(
  "base64url",
);

/**
 * An ordinary authorization code: issued under a provider Grant this AS never
 * bound to a Mission, for `resource` (one indicator, or several), as the
 * reference's authorization endpoint issues one from an ordinary grant the
 * session holds. `expiresIn` seeds a short-lived code.
 */
async function ordinaryCode(
  clientId: Client,
  resource: string | string[],
  opts: { expiresIn?: number } = {},
): Promise<{ code: string; grantId: string }> {
  const grant = new as.provider.Grant({ accountId: "alice", clientId });
  grant.addOIDCScope("openid");
  const grantId = await grant.save();
  const client = await as.provider.Client.find(clientId);
  const code = new as.provider.AuthorizationCode({
    client,
    accountId: "alice",
    grantId,
    redirectUri: REDIRECT_URI,
    scope: "openid",
    codeChallenge: CHALLENGE,
    codeChallengeMethod: "S256",
    resource,
    expiresWithSession: false,
    authTime: Math.floor(Date.now() / 1000),
    ...(opts.expiresIn !== undefined ? { expiresIn: opts.expiresIn } : {}),
  } as never);
  return { code: await code.save(), grantId };
}

const redeemParams = (code: string, resource?: string | string[]): [string, string][] => [
  ["grant_type", "authorization_code"],
  ["code", code],
  ["redirect_uri", REDIRECT_URI],
  ["code_verifier", VERIFIER],
  ...[resource ?? []].flat().map((r): [string, string] => ["resource", r]),
];

const refreshParams = (refreshToken: string, resource?: string | string[]): [string, string][] => [
  ["grant_type", "refresh_token"],
  ["refresh_token", refreshToken],
  ...[resource ?? []].flat().map((r): [string, string] => ["resource", r]),
];

const ccParams = (resource?: string | string[]): [string, string][] => [
  ["grant_type", "client_credentials"],
  ...[resource ?? []].flat().map((r): [string, string] => ["resource", r]),
];

/** A JWT's payload. */
function claimsOf(token: unknown): Record<string, unknown> {
  return JSON.parse(Buffer.from(String(token).split(".")[1] as string, "base64url").toString()) as Record<string, unknown>;
}

/** The governed-resource refusal for `resource`: `invalid_target`, its description, and no token. */
function expectGovernedRefusal(answer: Answer, resource: string): void {
  expect(answer.status, JSON.stringify(answer.body)).toBe(400);
  expect(answer.body.error).toBe("invalid_target");
  expect(answer.body.error_description).toBe(governedResourceRefusal(resource));
  expect(answer.body).not.toHaveProperty("access_token");
  expect(answer.body).not.toHaveProperty("refresh_token");
}

/** An ordinary access token, with no `mission` claim, for `audience`. */
function expectOrdinaryToken(answer: Answer, audience: string): Record<string, unknown> {
  expect(answer.status, JSON.stringify(answer.body)).toBe(200);
  const claims = claimsOf(answer.body.access_token);
  expect(claims.aud).toBe(audience);
  expect(claims).not.toHaveProperty("mission");
  expect(answer.body).not.toHaveProperty("mission_id");
  return claims;
}

// --- The Mission flow (Intent-only on the reports resource, Alice approves in the browser) ---

type Jar = Map<string, string>;
const cookieOf = (jar: Jar) => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
const keep = (jar: Jar, res: Response) => {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
  }
};

function codeOrUid(location: string): { uid?: string; code?: string } {
  if (location.includes("/interaction/")) return { uid: location.split("/interaction/")[1] as string };
  const code = location ? new URL(location).searchParams.get("code") : null;
  return code ? { code } : {};
}

/** A Mission on the reports resource, approved by Alice: its id and the authorization code its approval returned. */
async function approvedMissionCode(goal: string): Promise<{ missionId: string | undefined; code: string; jar: Jar }> {
  const pushed = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams([
      ["client_id", "ap-agent"],
      ["response_type", "code"],
      ["redirect_uri", REDIRECT_URI],
      ["resource", PLAIN],
      ["scope", "openid"],
      ["code_challenge", CHALLENGE],
      ["code_challenge_method", "S256"],
      ["mission_intent", JSON.stringify({ intent: { goal, target_resources: [PLAIN], expires_at: "2027-01-01T00:00:00Z" } })],
      ...(await clientAuth("ap-agent")),
    ]).toString(),
  });
  const requestUri = ((await pushed.json()) as { request_uri: string }).request_uri;
  expect(pushed.status).toBe(201);
  const jar: Jar = new Map();
  const opened = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: requestUri })}`, {
    redirect: "manual",
  });
  keep(jar, opened);
  const uid = codeOrUid(opened.headers.get("location") ?? "").uid as string;
  expect(uid).toBeTruthy();
  const headers = { ...browserApprovalHeaders(SESSIONS, uid, ALICE, cookieOf(jar)), "content-type": "application/json" };
  const render_revision = await renderedRevision(ISSUER, uid, headers);
  let res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers,
    body: JSON.stringify({ decision: "approve", render_revision }),
  });
  expect(res.status, await res.clone().text()).toBeLessThan(400);
  keep(jar, res);
  let location = res.headers.get("location") ?? "";
  while (location.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieOf(jar) } });
    keep(jar, res);
    location = res.headers.get("location") ?? "";
  }
  const code = codeOrUid(location).code as string;
  expect(code, location).toBeTruthy();
  const stored = (await as.provider.AuthorizationCode.find(code)) as { grantId?: string } | undefined;
  return { missionId: stored?.grantId ? as.kernel.findByGrant(stored.grantId)?.id : undefined, code, jar };
}

describe("governed-resource classification (@spec mission#authority-proposal, #1531)", () => {
  it("the predicate joins the deployment's classification and authenticated metadata so that neither clears the other", () => {
    expect(isMissionGovernedResource(POLICY, CLASSIFIED)).toBe(true);
    expect(isMissionGovernedResource(POLICY, DECLARED)).toBe(true);
    expect(isMissionGovernedResource(POLICY, LOCALLY_UNGOVERNED)).toBe(true);
    expect(isMissionGovernedResource(POLICY, CLASSIFIED_METADATA_FALSE)).toBe(true);
    expect(isMissionGovernedResource(POLICY, CLASSIFIED_METADATA_OMITS)).toBe(true);
    expect(isMissionGovernedResource(POLICY, METADATA_FALSE)).toBe(false);
    expect(isMissionGovernedResource(POLICY, UNGOVERNED)).toBe(false);
  });

  it("the shipped policy classifies the payments resource governed, by classification and by its published metadata", () => {
    expect(GOVERNED_RESOURCES.classification[CANONICAL_RESOURCE]).toBe("governed");
    expect(GOVERNED_RESOURCES.authenticated_metadata[CANONICAL_RESOURCE]).toEqual({ mission_bound_authorization_required: true });
    expect(isMissionGovernedResource(withoutGovernedResource(GOVERNED_RESOURCES, CANONICAL_RESOURCE), CANONICAL_RESOURCE)).toBe(false);
  });
});

describe("a Mission-governed resource gets no token outside a Mission, on every grant type (@spec mission#authority-proposal, #1531)", () => {
  it("authorization code: an ordinary code naming a governed resource is refused invalid_target, and one naming an ungoverned resource redeems to an ordinary token with no mission claim", async () => {
    const governed = await ordinaryCode(PUBLIC_CLIENT, CLASSIFIED);
    expectGovernedRefusal(await tokenRequest(redeemParams(governed.code, CLASSIFIED), PUBLIC_CLIENT), CLASSIFIED);
    const ordinary = await ordinaryCode(PUBLIC_CLIENT, UNGOVERNED);
    const issued = await tokenRequest(redeemParams(ordinary.code, UNGOVERNED), PUBLIC_CLIENT);
    expectOrdinaryToken(issued, UNGOVERNED);
    expect(issued.body.refresh_token).toBeTruthy();
    expect(as.kernel.findByGrant(ordinary.grantId)).toBeUndefined();
  });

  it("client credentials (test configuration): a governed resource is refused invalid_target, and an ungoverned one is issued a token with no mission claim", async () => {
    expectGovernedRefusal(await tokenRequest(ccParams(CLASSIFIED), CC_CLIENT), CLASSIFIED);
    const issued = await tokenRequest(ccParams(UNGOVERNED), CC_CLIENT);
    const claims = expectOrdinaryToken(issued, UNGOVERNED);
    expect(claims.client_id).toBe(CC_CLIENT);
  });

  it("refresh: an ordinary refresh naming a governed resource the refresh token carries is refused invalid_target, and the same refresh token redeems for an ungoverned resource", async () => {
    const { code } = await ordinaryCode(PUBLIC_CLIENT, [UNGOVERNED, CLASSIFIED]);
    const first = await tokenRequest(redeemParams(code, UNGOVERNED), PUBLIC_CLIENT);
    expectOrdinaryToken(first, UNGOVERNED);
    const refreshToken = first.body.refresh_token as string;
    expectGovernedRefusal(await tokenRequest(refreshParams(refreshToken, CLASSIFIED), PUBLIC_CLIENT), CLASSIFIED);
    const refreshed = await tokenRequest(refreshParams(refreshToken, UNGOVERNED), PUBLIC_CLIENT);
    expectOrdinaryToken(refreshed, UNGOVERNED);
  });

  it("the development mint route never mints for a governed resource, and mints an ordinary token where its audience is not governed", async () => {
    const mint = (issuer: string) =>
      fetch(`${issuer}/dev/ordinary-token`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
        body: JSON.stringify({ sub: "alice", client_id: "ap-agent", scope: "payments.read", jkt: "0".repeat(43) }),
      });
    const refused = await mint(ISSUER);
    const refusedBody = (await refused.json()) as Record<string, unknown>;
    expect(refused.status, JSON.stringify(refusedBody)).toBe(400);
    expect(refusedBody).toEqual({ error: "invalid_target", error_description: governedResourceRefusal(CANONICAL_RESOURCE) });
    const minted = await mint(UNGOVERNED_ISSUER);
    const mintedBody = (await minted.json()) as Record<string, unknown>;
    expect(minted.status, JSON.stringify(mintedBody)).toBe(200);
    const claims = claimsOf(mintedBody.access_token);
    expect(claims.aud).toBe(CANONICAL_RESOURCE);
    expect(claims).not.toHaveProperty("mission");
  });

  it("token exchange: an ordinary access token presented as the async-delegation exchange's subject token for a governed resource is refused by the exchange's subject validation, and no token is issued", async () => {
    const keys = await newKeys();
    const { code } = await ordinaryCode("ap-agent", UNGOVERNED);
    const ordinary = await tokenRequest(redeemParams(code, UNGOVERNED), "ap-agent", { dpop: keys });
    expectOrdinaryToken(ordinary, UNGOVERNED);
    const exchanged = await tokenRequest(
      [
        ["grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"],
        ["subject_token", ordinary.body.access_token as string],
        ["subject_token_type", "urn:ietf:params:oauth:token-type:access_token"],
        ["request_refresh_token", "true"],
        ["resource", CLASSIFIED],
      ],
      "ap-agent",
      { dpop: keys },
    );
    // The async-delegation exchange issues a resource token from an access
    // token subject; it requires the subject's Mission.
    expect(exchanged.status, JSON.stringify(exchanged.body)).toBe(400);
    expect(exchanged.body).toEqual({ error: "invalid_request", error_description: "subject_token is missing the mission claim" });
  });
});

describe("authenticated metadata classifies a resource, and neither source weakens the other (@spec mission#authority-proposal, #1531)", () => {
  it("a resource the deployment does not classify, whose authenticated metadata declares mission_bound_authorization_required true, is refused like a classified one", async () => {
    expectGovernedRefusal(await tokenRequest(ccParams(DECLARED), CC_CLIENT), DECLARED);
    const { code } = await ordinaryCode(PUBLIC_CLIENT, DECLARED);
    expectGovernedRefusal(await tokenRequest(redeemParams(code, DECLARED), PUBLIC_CLIENT), DECLARED);
  });

  it("a less restrictive local classification does not override metadata declaring the requirement", async () => {
    expectGovernedRefusal(await tokenRequest(ccParams(LOCALLY_UNGOVERNED), CC_CLIENT), LOCALLY_UNGOVERNED);
  });

  it("metadata setting the member false, or omitting it, does not clear the deployment's classification; false metadata on an unclassified resource leaves it ungoverned", async () => {
    expectGovernedRefusal(await tokenRequest(ccParams(CLASSIFIED_METADATA_FALSE), CC_CLIENT), CLASSIFIED_METADATA_FALSE);
    expectGovernedRefusal(await tokenRequest(ccParams(CLASSIFIED_METADATA_OMITS), CC_CLIENT), CLASSIFIED_METADATA_OMITS);
    expectOrdinaryToken(await tokenRequest(ccParams(METADATA_FALSE), CC_CLIENT), METADATA_FALSE);
  });
});

describe("every audience the token would carry, named or inferred (@spec mission#authority-proposal, #1531)", () => {
  it("an authorization code naming no resource, whose granted resource is governed, is refused invalid_target", async () => {
    const { code } = await ordinaryCode(PUBLIC_CLIENT, CLASSIFIED);
    expectGovernedRefusal(await tokenRequest(redeemParams(code), PUBLIC_CLIENT), CLASSIFIED);
  });

  it("a refresh naming no resource, whose refresh token carries a governed resource, is refused before the refresh token is consumed", async () => {
    const { code } = await ordinaryCode(PUBLIC_CLIENT, [UNGOVERNED, CLASSIFIED]);
    const first = await tokenRequest(redeemParams(code, UNGOVERNED), PUBLIC_CLIENT);
    const refreshToken = first.body.refresh_token as string;
    const stored = (await as.provider.RefreshToken.find(refreshToken)) as { resource?: unknown } | undefined;
    // The refresh token carries both indicators, so a refresh naming none
    // infers both (oidc-provider refuses more than one; this gate first).
    expect(stored?.resource).toEqual([UNGOVERNED, CLASSIFIED]);
    expectGovernedRefusal(await tokenRequest(refreshParams(refreshToken), PUBLIC_CLIENT), CLASSIFIED);
    expectOrdinaryToken(await tokenRequest(refreshParams(refreshToken, UNGOVERNED), PUBLIC_CLIENT), UNGOVERNED);
  });

  it("client credentials naming no resource is refused when the AS's default audience (its issuer) is governed", async () => {
    expectGovernedRefusal(await tokenRequest(ccParams(), CC_CLIENT), ISSUER);
  });

  it("a client credentials request naming an ungoverned and a governed resource is refused whole with the governed-resource refusal; no token is issued for the ungoverned one", async () => {
    expectGovernedRefusal(await tokenRequest(ccParams([UNGOVERNED, CLASSIFIED]), CC_CLIENT), CLASSIFIED);
  });

  it("a refresh naming an ungoverned and a governed resource is refused whole before consumption, and the refresh token still redeems for the ungoverned one alone", async () => {
    const { code } = await ordinaryCode(PUBLIC_CLIENT, [UNGOVERNED, CLASSIFIED]);
    const first = await tokenRequest(redeemParams(code, UNGOVERNED), PUBLIC_CLIENT);
    const refreshToken = first.body.refresh_token as string;
    expectGovernedRefusal(await tokenRequest(refreshParams(refreshToken, [UNGOVERNED, CLASSIFIED]), PUBLIC_CLIENT), CLASSIFIED);
    expectOrdinaryToken(await tokenRequest(refreshParams(refreshToken, UNGOVERNED), PUBLIC_CLIENT), UNGOVERNED);
  });
});

describe("the refusal is invalid_target once the request is otherwise processable; earlier failures keep their errors (@spec mission#authority-proposal, #1531)", () => {
  it("a client authentication failure keeps invalid_client", async () => {
    const answer = await tokenRequest(ccParams(CLASSIFIED), CC_CLIENT, { badAuth: true });
    expect(answer.status).toBe(401);
    expect(answer.body.error).toBe("invalid_client");
  });

  it("a syntax failure keeps invalid_request", async () => {
    const answer = await tokenRequest([...ccParams(CLASSIFIED), ["authorization_details", "[]"]], CC_CLIENT);
    expect(answer.status).toBe(400);
    expect(answer.body.error).toBe("invalid_request");
    const missing = await tokenRequest(
      [
        ["grant_type", "authorization_code"],
        ["redirect_uri", REDIRECT_URI],
        ["resource", CLASSIFIED],
      ],
      PUBLIC_CLIENT,
    );
    expect(missing.body.error).toBe("invalid_request");
  });

  it("an invalid or expired grant keeps invalid_grant", async () => {
    const unknown = await tokenRequest(redeemParams("not-a-code", CLASSIFIED), PUBLIC_CLIENT);
    expect(unknown.body.error).toBe("invalid_grant");
    const unknownRefresh = await tokenRequest(refreshParams("not-a-refresh-token", CLASSIFIED), PUBLIC_CLIENT);
    expect(unknownRefresh.body.error).toBe("invalid_grant");
    const { code } = await ordinaryCode(PUBLIC_CLIENT, CLASSIFIED, { expiresIn: 1 });
    await new Promise((resolve) => setTimeout(resolve, 2100));
    const expired = await tokenRequest(redeemParams(code, CLASSIFIED), PUBLIC_CLIENT);
    expect(expired.body.error).toBe("invalid_grant");
  });

  it("a code under a grant bound to a suspended Mission keeps the Issuance Gating refusal (invalid_grant), never invalid_target, for a governed resource", async () => {
    const { missionId, code } = await approvedMissionCode("Read the quarterly reports (suspended before redemption)");
    expect(missionId).toBeTruthy();
    as.kernel.transition(missionId as string, "suspend");
    const answer = await tokenRequest(redeemParams(code, PLAIN), "ap-agent", { dpop: await newKeys() });
    expect(answer.status, JSON.stringify(answer.body)).toBe(400);
    expect(answer.body.error).toBe("invalid_grant");
    expect(answer.body).not.toHaveProperty("access_token");
  });

  it("a refresh under a grant bound to a suspended Mission keeps the Issuance Gating refusal (invalid_grant), never invalid_target, for a governed resource", async () => {
    const { missionId, code } = await approvedMissionCode("Read the quarterly reports (suspended before refresh)");
    const keys = await newKeys();
    const redeemed = await tokenRequest(redeemParams(code, PLAIN), "ap-agent", { dpop: keys });
    expect(redeemed.status, JSON.stringify(redeemed.body)).toBe(200);
    expect(claimsOf(redeemed.body.access_token).mission).toMatchObject({ id: missionId });
    as.kernel.transition(missionId as string, "suspend");
    const answer = await tokenRequest(refreshParams(redeemed.body.refresh_token as string, PLAIN), "ap-agent", { dpop: keys });
    expect(answer.status, JSON.stringify(answer.body)).toBe(400);
    expect(answer.body.error).toBe("invalid_grant");
    expect(answer.body).not.toHaveProperty("access_token");
  });
});
