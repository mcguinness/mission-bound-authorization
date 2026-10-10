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

import { TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";

import { type Server } from "node:http";
import { type AuthorityEntry, canonicalize, type JsonValue } from "@mission/core";
import { CANONICAL_RESOURCE, TOPOLOGY } from "@mission/demo-data";
import {
  calculateJwkThumbprint,
  createRemoteJWKSet,
  decodeJwt,
  exportJWK,
  generateKeyPair,
  importJWK,
  type JWK,
  jwtVerify,
  SignJWT,
} from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { CHILD_JWT_BEARER_GRANT_TYPE } from "../src/adapters/child-grant.js";
import { TOKEN_EXCHANGE_GRANT_TYPE, ACCESS_TOKEN_TOKEN_TYPE, JWT_TOKEN_TYPE, presentedTokenAuthority } from "../src/adapters/continuation-grant.js";
import { buildAuthorizationServer, type BuiltAs, SourceUnavailableError } from "../src/index.js";
import { GateError } from "../src/kernel/kernel.js";

const PORT = 14480;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE; // served by ISSUER (intra-domain target)
const FAR_EXP = "2027-01-01T00:00:00Z";
/**
 * @spec async-delegation (#651): the TEST-ONLY child actor client, with the
 * jwt-bearer, token-exchange and refresh_token grant types, so a Child Mission
 * naming it as `child_actor` can mint and refresh a child-rooted family through
 * /token. Registered through the AS builder's `testClients` seam;
 * config/clients.json is untouched.
 */
const EXCHANGER_CLIENT_ID = "test-child-exchanger";
/**
 * The TEST-ONLY jwt-bearer-only child actor (#1158, D361): a registration
 * without the token-exchange grant, which redeems its child grant but cannot
 * open a delegation family. The shipped `subagent-invoice-extractor` carries
 * token exchange (it continues a dispatched instance it was handed), so the
 * grant-registration refusal is pinned on this distinct client.
 */
const BEARER_ONLY_CLIENT_ID = "test-child-jwt-bearer-only";

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };

let as: BuiltAs;
let asTokenKey: CryptoKey; // the test-held AS token key (testTokenSigningJwk)
let asServer: Server;
let clientKey: CryptoKey; // ap-agent private_key_jwt key (kid ap-agent-auth)
let childClientKey: CryptoKey; // child actor private_key_jwt key
let exchangerClientKey: CryptoKey; // TEST-ONLY child actor private_key_jwt key (#651)
let bearerOnlyClientKey: CryptoKey; // TEST-ONLY jwt-bearer-only child actor key (#1158)
let codeDpop: Keys; // DPoP key for the base-mission code flow
let actingDpop: Keys; // DPoP key for the async exchange + refreshes (the code-flow key, #1157)
let otherDpop: Keys; // a key bound to nothing (the wrong-key cases)
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

async function exchangerClientAssertion(): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: `${EXCHANGER_CLIENT_ID}-auth` })
    .setIssuer(EXCHANGER_CLIENT_ID)
    .setSubject(EXCHANGER_CLIENT_ID)
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(exchangerClientKey);
}

async function bearerOnlyClientAssertion(): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: `${BEARER_ONLY_CLIENT_ID}-auth` })
    .setIssuer(BEARER_ONLY_CLIENT_ID)
    .setSubject(BEARER_ONLY_CLIENT_ID)
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(bearerOnlyClientKey);
}

/** The private_key_jwt assertion of the client a flow authenticates AS. */
function assertionFor(actingAs: ActingClient | undefined): Promise<string> {
  if (actingAs === "child") return childClientAssertion();
  if (actingAs === "exchanger") return exchangerClientAssertion();
  if (actingAs === "bearerOnly") return bearerOnlyClientAssertion();
  return clientAssertion();
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
async function issueBaseMission(
  expiresAt: string = FAR_EXP,
  authority: unknown = fullAuthority(),
): Promise<{
  missionId: string;
  baseAccessToken: string;
  missionRefreshToken: string;
}> {
  const jar = new Map<string, string>();
  const verifier = "async-delegation-verifier-0123456789-0123456789-0123";
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
  ).toString("base64url");
  // @spec mission#submission-via-par — the wire value is the Submission envelope.
  const intent = JSON.stringify({
    intent: {
      goal: "Pay Acme invoices and send remittance",
      target_resources: [RESOURCE],
      expires_at: expiresAt,
    },
  });
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
      mission_intent: intent,
      authorization_details: JSON.stringify(authority),
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
    headers: { ...trustedApprovalHeaders(), "content-type": "application/json", cookie: cookieHeader(jar) },
    body: JSON.stringify({ decision: "approve" }),
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

/**
 * Which registered client a /token request authenticates as. Default (absent) is
 * the acting client `ap-agent`. @spec #651 — the async-delegation exchange
 * requires the `subject_token`'s client_id to equal the authenticated client
 * (continuation-grant.ts), so a family rooted at a Child Mission's own access
 * token is opened by that Mission's OWN child actor: `child` is the shipped one,
 * `exchanger` the test-only one, `bearerOnly` the test-only jwt-bearer-only one
 * (so the exchange is refused).
 */
type ActingClient = "child" | "exchanger" | "bearerOnly";

interface ExchangeOpts {
  authorizationDetails?: unknown;
  resource?: string;
  /** @spec continuation#transport-async — REQUIRED; `null` omits it (the missing-param test). */
  creationRequestId?: string | null;
  /** Authenticate as a child actor client instead of `ap-agent` (@see ActingClient). */
  actingAs?: ActingClient;
  /**
   * Present `baseAccessToken` itself as the subject_token. By default the
   * helper first exchanges it for the acting client's delegation handle
   * (#1157, D358), which the transport requires; a refusal test presenting a
   * resource-audienced token sets this.
   */
  rawSubject?: boolean;
  /** The key the async exchange's DPoP proof is signed under (default: `actingDpop`). */
  keys?: Keys;
  /** Extra request parameters (the conflict cases). */
  extraParams?: Record<string, string>;
}

/** The client_id each {@link ActingClient} authenticates as. */
function clientIdFor(actingAs: ActingClient | undefined): string {
  if (actingAs === "child") return "subagent-invoice-extractor";
  if (actingAs === "exchanger") return EXCHANGER_CLIENT_ID;
  if (actingAs === "bearerOnly") return BEARER_ONLY_CLIENT_ID;
  return "ap-agent";
}

/**
 * POST /token: the delegation-handle request (#1157, D358). An RFC 8693
 * exchange whose `audience` is the acting client's own client_id; the DPoP
 * proof is over the presented token's own key, which the handle keeps.
 */
async function delegationHandleRequest(
  subjectToken: string,
  actingAs?: ActingClient,
  keys: Keys = actingDpop,
  extraParams: Record<string, string> = {},
): Promise<Response> {
  const params: Record<string, string> = {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: subjectToken,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    audience: clientIdFor(actingAs),
    ...extraParams,
  };
  const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
    fetch(`${ISSUER}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(keys, extra) },
      body: new URLSearchParams({
        ...params,
        client_assertion: await assertionFor(actingAs),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return res;
}

/** The acting client's delegation handle for `subjectToken`; throws on a refusal. */
async function delegationHandle(subjectToken: string, actingAs?: ActingClient): Promise<string> {
  const res = await delegationHandleRequest(subjectToken, actingAs);
  const body = (await res.json()) as { access_token?: string };
  if (res.status !== 200 || typeof body.access_token !== "string") {
    throw new Error(`delegation handle request refused: ${res.status} ${JSON.stringify(body)}`);
  }
  return body.access_token;
}

/** POST /token: token-exchange + request_refresh_token=true (the async transport). */
async function asyncDelegate(baseAccessToken: string, opts: ExchangeOpts = {}): Promise<Response> {
  const subjectToken = opts.rawSubject ? baseAccessToken : await delegationHandle(baseAccessToken, opts.actingAs);
  const params: Record<string, string> = {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    request_refresh_token: "true",
    subject_token: subjectToken,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    resource: opts.resource ?? RESOURCE,
    ...opts.extraParams,
  };
  if (opts.creationRequestId !== null) {
    params.creation_request_id = opts.creationRequestId ?? crypto.randomUUID();
  }
  if (opts.authorizationDetails !== undefined) {
    params.authorization_details = JSON.stringify(opts.authorizationDetails);
  }
  const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
    fetch(`${ISSUER}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(opts.keys ?? actingDpop, extra) },
      body: new URLSearchParams({
        ...params,
        client_assertion: await assertionFor(opts.actingAs),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return res;
}

/** POST /token grant_type=jwt-bearer: the child actor redeems its child-bound
 *  assertion AS ITSELF for its own DPoP-bound Mission access token. */
async function childRedeem(
  assertion: string,
  actingAs: ActingClient = "child",
  keys: Keys = actingDpop,
): Promise<Response> {
  const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
    fetch(`${ISSUER}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(keys, extra) },
      body: new URLSearchParams({
        grant_type: CHILD_JWT_BEARER_GRANT_TYPE,
        assertion,
        client_assertion: await assertionFor(actingAs),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return res;
}

/**
 * Native grant_type=refresh_token with a FRESH DPoP proof (default key =
 * actingDpop). The per-delegation Grant is owned by the client that opened the
 * family, so a child-rooted family (#651) refreshes as that child actor.
 */
async function refreshFamily(
  refreshToken: string,
  keys: Keys = actingDpop,
  actingAs?: ActingClient,
): Promise<Response> {
  const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
    fetch(`${ISSUER}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(keys, extra) },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_assertion: await assertionFor(actingAs),
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
async function createChildViaExchange(
  subjectToken: string,
  parentId: string,
  childActorSub = "subagent-invoice-extractor",
): Promise<Response> {
  return codeTokenRequest({
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: subjectToken,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    requested_token_type: JWT_TOKEN_TYPE,
    creation_request_id: crypto.randomUUID(),
    parent: parentId,
    login_hint: "alice",
    mission_intent: JSON.stringify({
      intent: {
        goal: "Extract Acme invoices",
        target_resources: [RESOURCE],
        expires_at: FAR_EXP,
      },
    }),
    authorization_details: JSON.stringify(confinedAuthority()),
    child_actor: JSON.stringify({ sub: childActorSub, sub_profile: "ai_agent" }),
  });
}

/**
 * @spec issuance-grant#effective-set-projection (#617 review 1) — the injected
 * authority source's outage switch. Set to a message to make every Effective
 * Authority Set resolution raise the TRANSIENT class; undefined delegates to
 * the kernel (byte-identical to the un-injected default, which is what every
 * other test in this file exercises).
 */
let sourceOutage: string | undefined;

const RETRY_AFTER_SECONDS = 7;

beforeAll(async () => {
  // @spec async-delegation (#651) — the TEST-ONLY child actor registration (see
  // EXCHANGER_CLIENT_ID). The test holds the private half and signs its own
  // client assertions; the AS only ever sees the public JWK.
  const exchangerKeys = await generateKeyPair("ES256", { extractable: true });
  exchangerClientKey = exchangerKeys.privateKey;
  const exchangerJwk = {
    ...(await exportJWK(exchangerKeys.publicKey)),
    kid: `${EXCHANGER_CLIENT_ID}-auth`,
    alg: "ES256",
  };
  const bearerOnlyKeys = await generateKeyPair("ES256", { extractable: true });
  bearerOnlyClientKey = bearerOnlyKeys.privateKey;
  const bearerOnlyJwk = {
    ...(await exportJWK(bearerOnlyKeys.publicKey)),
    kid: `${BEARER_ONLY_CLIENT_ID}-auth`,
    alg: "ES256",
  };
  // A test-held AS token key, so a test can sign a token the AS never mints
  // (one without authorization_details) with a key on jwks_uri.
  const asTokenKeys = await generateKeyPair(TOPOLOGY.keys.asToken.alg, { extractable: true });
  asTokenKey = asTokenKeys.privateKey;
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    testTokenSigningJwk: (await exportJWK(asTokenKeys.privateKey)) as JWK,
    allowHeadlessAdjudication: true, serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    authoritySource: {
      effectiveAuthoritySet: (record) => {
        if (sourceOutage !== undefined) throw new SourceUnavailableError(sourceOutage);
        return as.kernel.effectiveAuthoritySet(record);
      },
    },
    stateRecoveryRetryAfter: RETRY_AFTER_SECONDS,
    testClients: [
      {
        client_id: EXCHANGER_CLIENT_ID,
        client_name: "Invoice Extraction Sub-Agent (token-exchange capable)",
        grant_types: [CHILD_JWT_BEARER_GRANT_TYPE, TOKEN_EXCHANGE_GRANT_TYPE, "refresh_token"],
        response_types: [],
        redirect_uris: [],
        token_endpoint_auth_method: "private_key_jwt",
        token_endpoint_auth_signing_alg: "ES256",
        jwks: { keys: [exchangerJwk] },
        authorization_details_types: ["mission_resource_access"],
      },
      {
        client_id: BEARER_ONLY_CLIENT_ID,
        client_name: "Invoice Extraction Sub-Agent (jwt-bearer only)",
        grant_types: [CHILD_JWT_BEARER_GRANT_TYPE],
        response_types: [],
        redirect_uris: [],
        token_endpoint_auth_method: "private_key_jwt",
        token_endpoint_auth_signing_alg: "ES256",
        jwks: { keys: [bearerOnlyJwk] },
        authorization_details_types: ["mission_resource_access"],
      },
    ],
    // @spec draft-mcguinness-oauth-mission#per-entry-enforcement — the AS asserts
    // the test-only child actors' type, exactly as config does for the shipped one.
    actorProfiles: { [EXCHANGER_CLIENT_ID]: "ai_agent", [BEARER_ONLY_CLIENT_ID]: "ai_agent" },
  });
  asServer = as.provider.listen(PORT);
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  childClientKey = (await importJWK(as.childClientJwk as never, "ES256")) as CryptoKey;
  codeDpop = await generateKeyPair("ES256", { extractable: true });
  // #1157 (D358): the delegation handle keeps the presented token's key, and
  // the exchange proves possession of it, so the family is bound to the
  // code-flow key; there is no separate acting key to re-bind to.
  actingDpop = codeDpop;
  otherDpop = await generateKeyPair("ES256", { extractable: true });
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
    expect(body.authorization_details).toMatchObject(confinedAuthority());

    const { payload } = await jwtVerify(body.access_token as string, remoteJwks, {
      issuer: ISSUER,
      audience: RESOURCE,
    });
    expect(payload.aud).toBe(RESOURCE);
    expect((payload.cnf as { jkt?: string }).jkt).toBe(actingJkt); // sender-constrained to the acting DPoP key
    expect((payload.mission as { id?: string }).id).toBe(missionId);
    expect(payload.authorization_details).toMatchObject(confinedAuthority());

    // @spec capability-binding#capability-source-binding (#657 B2) — the extra
    // member `toMatchObject` tolerates above is the issuer's own recorded
    // provenance, inherited by the wire-confined subset at mint through the
    // asymmetric projection. Assert it exactly, so the relaxed matcher never
    // silently admits something else.
    const minted = (payload.authorization_details as AuthorityEntry[])[0];
    expect(minted?.capability_sources).toEqual(
      (as.kernel.get(missionId)?.authority_set ?? [])
        .flatMap((e) => e.capability_sources ?? [])
        .filter((b) => b.action === "payments:invoice.read"),
    );
    expect(minted?.capability_sources?.length).toBeGreaterThan(0);

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

describe("the presented token's own authority bounds the family (@spec mission#self-exchange rule 2, #825 PR 2c)", () => {
  /** A family access token confined to the invoice read: a real token narrower than its Mission, same client, no act. */
  async function narrowerToken(): Promise<{ token: string; authority: unknown; derived: unknown }> {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const res = await asyncDelegate(baseAccessToken, { authorizationDetails: confinedAuthority() });
    const body = (await res.json()) as { access_token: string; authorization_details: unknown };
    expect(res.status, JSON.stringify(body)).toBe(200);
    return { token: body.access_token, authority: body.authorization_details, derived: as.kernel.get(missionId)?.authority_set };
  }

  it("confines an absent request to the presented token's authority, never the Mission's", async () => {
    const narrow = await narrowerToken();
    expect(narrow.authority).not.toEqual(narrow.derived);
    const res = await asyncDelegate(narrow.token); // no authorization_details
    const body = (await res.json()) as { access_token?: string; authorization_details?: unknown };
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(body.authorization_details).toEqual(narrow.authority);
    const { payload } = await jwtVerify(body.access_token as string, remoteJwks, { issuer: ISSUER, audience: RESOURCE });
    expect(payload.authorization_details).toEqual(narrow.authority);
  });

  it("refuses a request beyond the presented token's authority, though the Mission allows it", async () => {
    const narrow = await narrowerToken();
    const res = await asyncDelegate(narrow.token, { authorizationDetails: fullAuthority() });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_authorization_details");
    expect(body.error_description).toContain("presented token");
  });

  it("permits a request within the presented token's authority", async () => {
    const narrow = await narrowerToken();
    const res = await asyncDelegate(narrow.token, { authorizationDetails: confinedAuthority() });
    const body = (await res.json()) as { authorization_details?: unknown };
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(body.authorization_details).toEqual(narrow.authority);
  });
});

describe("a retry recovers a recorded family only within the presented token (@spec mission#self-exchange rule 2, #1153 review, D353)", () => {
  /** A broad family under one creation_request_id, plus a narrower and an equivalent token for the same Mission. */
  async function broadFamily(crashed: boolean) {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const narrow = (await (await asyncDelegate(baseAccessToken, { authorizationDetails: confinedAuthority() })).json()) as { access_token: string };
    const equivalent = (await (await asyncDelegate(baseAccessToken)).json()) as { access_token: string };
    const creationRequestId = crypto.randomUUID();
    const res = await asyncDelegate(baseAccessToken, { creationRequestId }); // authorization_details omitted
    const broad = (await res.json()) as { access_token: string; authorization_details: unknown };
    expect(res.status, JSON.stringify(broad)).toBe(200);
    if (crashed) {
      // The crash window: the family exists and was counted, but no response was delivered.
      const grants = as.delegationFamilyStore.familiesForMission(missionId);
      const grantId = grants[grants.length - 1];
      as.kernel.db
        .prepare("UPDATE creation_idempotency SET state = 'reserved', mission_id = NULL, completed_at = NULL, delivery_json = ? WHERE creation_request_id = ?")
        .run(JSON.stringify({ grant_id: grantId, target: RESOURCE }), creationRequestId);
    }
    return { narrow: narrow.access_token, equivalent: equivalent.access_token, creationRequestId, broad };
  }

  for (const crashed of [false, true]) {
    const state = crashed ? "created before a crash" : "completed";
    it(`refuses a narrower token recovering a broader family ${state}, with authorization_details omitted`, async () => {
      const f = await broadFamily(crashed);
      const retry = await asyncDelegate(f.narrow, { creationRequestId: f.creationRequestId });
      const body = (await retry.json()) as { error?: string; error_description?: string };
      expect(retry.status, JSON.stringify(body)).toBe(400);
      expect(body.error).toBe("invalid_authorization_details");
      expect(body.error_description).toContain("presented token");
    });

    it(`recovers a family ${state} with an equivalent replacement token`, async () => {
      const f = await broadFamily(crashed);
      const retry = await asyncDelegate(f.equivalent, { creationRequestId: f.creationRequestId });
      const body = (await retry.json()) as { access_token?: string; authorization_details?: unknown };
      expect(retry.status, JSON.stringify(body)).toBe(200);
      expect(body.authorization_details).toEqual(f.broad.authorization_details);
      if (!crashed) expect(body.access_token).toBe(f.broad.access_token);
    });
  }
});

describe("the presented token's authority bounds a Child Mission (@spec child-delegation#attenuation, #825, D353)", () => {
  /** The child-creation exchange as ap-agent, presenting `subjectToken` under `keys`. */
  async function createChild(
    subjectToken: string,
    parentId: string,
    opts: { keys?: Keys; authorizationDetails?: unknown; creationRequestId?: string } = {},
  ): Promise<Response> {
    const params: Record<string, string> = {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      subject_token: subjectToken,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      requested_token_type: JWT_TOKEN_TYPE,
      creation_request_id: opts.creationRequestId ?? crypto.randomUUID(),
      parent: parentId,
      mission_intent: JSON.stringify({
        intent: { goal: "Extract Acme invoices", target_resources: [RESOURCE], expires_at: FAR_EXP },
      }),
      child_actor: JSON.stringify({ sub: "subagent-invoice-extractor", sub_profile: "ai_agent" }),
      authorization_details: JSON.stringify(opts.authorizationDetails ?? confinedAuthority()),
    };
    const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
      fetch(`${ISSUER}/token`, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          dpop: await dpopProof(opts.keys ?? actingDpop, extra),
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
    return res;
  }

  /**
   * A Mission with three family access tokens, all bound to the acting key:
   * `broad` (the Mission's whole authority), `narrow` (the invoice read,
   * keeping the Mission entry's delegation right), and `undelegable` (the
   * invoice read without that right).
   */
  async function tokens(): Promise<{ missionId: string; broad: string; narrow: string; undelegable: string }> {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const family = async (authorizationDetails?: unknown): Promise<string> => {
      const res = await asyncDelegate(baseAccessToken, authorizationDetails ? { authorizationDetails } : {});
      const body = (await res.json()) as { access_token: string };
      expect(res.status, JSON.stringify(body)).toBe(200);
      return body.access_token;
    };
    const readEntry = as.kernel
      .get(missionId)
      ?.authority_set.find((e) => e.actions.includes("payments:invoice.read"));
    expect(readEntry?.delegation).toBeDefined();
    return {
      missionId,
      broad: await family(),
      narrow: await family(confinedAuthority().map((e) => ({ ...e, delegation: readEntry?.delegation }))),
      undelegable: await family(confinedAuthority()),
    };
  }

  /**
   * A family token for the invoice read whose delegation right carries the
   * Mission entry's `children` object changed by `restrict`, and the matching
   * child proposal (the same restricted delegation), so the authority bound
   * passes and the token's child-creation controls decide (#1192 review).
   */
  async function restricted(
    baseAccessToken: string,
    missionId: string,
    restrict: (children: Record<string, unknown>) => void,
  ): Promise<{ token: string; proposal: unknown }> {
    const entry = as.kernel.get(missionId)?.authority_set.find((e) => e.actions.includes("payments:invoice.read"));
    const delegation = structuredClone(entry?.delegation) as Record<string, unknown>;
    restrict(delegation.children as Record<string, unknown>);
    const proposal = confinedAuthority().map((e) => ({ ...e, delegation }));
    const res = await asyncDelegate(baseAccessToken, { authorizationDetails: proposal });
    const body = (await res.json()) as { access_token: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    return { token: body.access_token, proposal };
  }

  it.each([
    ["allowed_child_actors: []", (c: Record<string, unknown>) => { c.allowed_child_actors = []; }, "child_actor_not_allowed"],
    ["max_children: 0", (c: Record<string, unknown>) => { c.max_children = 0; }, "fanout_exceeded"],
  ] as const)(
    "the presented token's children control %s refuses this creation, though the parent permits it",
    async (_label, restrict, reason) => {
      const { missionId, baseAccessToken } = await issueBaseMission();
      const { token, proposal } = await restricted(baseAccessToken, missionId, restrict);
      const before = as.kernel.findChildren(missionId).length;
      const res = await createChild(token, missionId, { authorizationDetails: proposal });
      const body = (await res.json()) as { error?: string; mission_denial_reason?: string };
      expect(res.status, JSON.stringify(body)).toBe(400);
      expect(body.error).toBe("invalid_request");
      expect(body.mission_denial_reason).toBe(reason);
      expect(as.kernel.findChildren(missionId)).toHaveLength(before);
    },
  );

  it("the presented token's max_children bounds the parent's count; the broad token still creates", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const { token, proposal } = await restricted(baseAccessToken, missionId, (c) => { c.max_children = 1; });
    const first = await createChild(token, missionId, { authorizationDetails: proposal });
    expect(first.status, JSON.stringify(await first.clone().json())).toBe(200);
    const second = await createChild(token, missionId, { authorizationDetails: proposal });
    const body = (await second.json()) as { mission_denial_reason?: string };
    expect(second.status, JSON.stringify(body)).toBe(400);
    expect(body.mission_denial_reason).toBe("fanout_exceeded");
    const broadRes = await asyncDelegate(baseAccessToken);
    const broad = ((await broadRes.json()) as { access_token: string }).access_token;
    const third = await createChild(broad, missionId, { authorizationDetails: proposal });
    expect(third.status, JSON.stringify(await third.clone().json())).toBe(200);
  });

  it("a retry recovers a recorded child only when the presented token's controls admit it (actor, count)", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const broadRes = await asyncDelegate(baseAccessToken);
    const broad = ((await broadRes.json()) as { access_token: string }).access_token;

    // Actor eligibility: a child recorded under the broad token is not recovered by a token that admits no child actor.
    const actors = await restricted(baseAccessToken, missionId, (c) => { c.allowed_child_actors = []; });
    const cridA = crypto.randomUUID();
    const createdA = await createChild(broad, missionId, { authorizationDetails: actors.proposal, creationRequestId: cridA });
    const createdABody = (await createdA.json()) as { mission_id?: string };
    expect(createdA.status, JSON.stringify(createdABody)).toBe(200);
    const refusedA = await createChild(actors.token, missionId, { authorizationDetails: actors.proposal, creationRequestId: cridA });
    const refusedABody = (await refusedA.json()) as { mission_denial_reason?: string; access_token?: string };
    expect(refusedA.status, JSON.stringify(refusedABody)).toBe(400);
    expect(refusedABody.mission_denial_reason).toBe("child_actor_not_allowed");
    expect(refusedABody.access_token).toBeUndefined();

    // Fan-out: the recorded child counts once. max_children 0 refuses its recovery; max_children 2 admits it.
    const none = await restricted(baseAccessToken, missionId, (c) => { c.max_children = 0; });
    const cridC = crypto.randomUUID();
    const createdC = await createChild(broad, missionId, { authorizationDetails: none.proposal, creationRequestId: cridC });
    const createdCBody = (await createdC.json()) as { mission_id?: string };
    expect(createdC.status, JSON.stringify(createdCBody)).toBe(200);
    const refusedC = await createChild(none.token, missionId, { authorizationDetails: none.proposal, creationRequestId: cridC });
    const refusedCBody = (await refusedC.json()) as { mission_denial_reason?: string };
    expect(refusedC.status, JSON.stringify(refusedCBody)).toBe(400);
    expect(refusedCBody.mission_denial_reason).toBe("fanout_exceeded");
    // Two non-terminal children are now drawn on the entry: a token whose max_children admits them recovers.
    const room = await restricted(baseAccessToken, missionId, (c) => { c.max_children = 2; });
    const recovered = await createChild(room.token, missionId, { authorizationDetails: none.proposal, creationRequestId: cridC });
    const recoveredBody = (await recovered.json()) as { mission_id?: string };
    expect(recovered.status, JSON.stringify(recoveredBody)).toBe(200);
    expect(recoveredBody.mission_id).toBe(createdCBody.mission_id);
  });

  it("creates a child within the presented token's authority", async () => {
    const { missionId, narrow } = await tokens();
    const res = await createChild(narrow, missionId);
    const body = (await res.json()) as { mission_id?: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    const child = as.kernel.get(body.mission_id as string);
    expect(child?.parent?.id).toBe(missionId);
    expect(child?.authority_set.flatMap((e) => e.actions)).toEqual(["payments:invoice.read"]);
  });

  it("refuses a child from a token without the delegation right, though the parent carries it", async () => {
    const { missionId, undelegable } = await tokens();
    const before = as.kernel.findChildren(missionId).length;
    const res = await createChild(undelegable, missionId);
    const body = (await res.json()) as { error?: string; mission_denial_reason?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.mission_denial_reason).toBe("not_strict_subset");
    expect(as.kernel.findChildren(missionId)).toHaveLength(before);
  });

  it("refuses a child proposal beyond the presented token's authority with not_strict_subset, though the parent allows it", async () => {
    const { missionId, narrow } = await tokens();
    const before = as.kernel.findChildren(missionId).length;
    const res = await createChild(narrow, missionId, { authorizationDetails: fullAuthority() });
    const body = (await res.json()) as { error?: string; mission_denial_reason?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.mission_denial_reason).toBe("not_strict_subset");
    expect(as.kernel.findChildren(missionId)).toHaveLength(before);
  });

  it("refuses a subject_token whose authority cannot be read, creating nothing", async () => {
    const { missionId } = await tokens();
    const actingJkt = await calculateJwkThumbprint(await exportJWK(actingDpop.publicKey));
    const now = Math.floor(Date.now() / 1000);
    const record = as.kernel.get(missionId);
    const token = await new SignJWT({
      client_id: "ap-agent",
      sub: record?.subject.sub,
      mission: { id: missionId, issuer: ISSUER },
      cnf: { jkt: actingJkt },
    })
      .setProtectedHeader({ alg: TOPOLOGY.keys.asToken.alg, kid: TOPOLOGY.keys.asToken.kid, typ: "at+jwt" })
      .setIssuer(ISSUER)
      .setAudience(RESOURCE)
      .setIssuedAt(now)
      .setExpirationTime(now + 120)
      .setJti(crypto.randomUUID())
      .sign(asTokenKey);
    const before = as.kernel.findChildren(missionId).length;
    const res = await createChild(token, missionId);
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toContain("no readable authorization_details");
    expect(as.kernel.findChildren(missionId)).toHaveLength(before);
  });

  it("a retry recovers a recorded child only within the presented token; an equivalent token recovers it", async () => {
    const { missionId, broad, narrow } = await tokens();
    const crid = crypto.randomUUID();
    const first = await createChild(broad, missionId, { authorizationDetails: fullAuthority(), creationRequestId: crid });
    const firstBody = (await first.json()) as { mission_id?: string };
    expect(first.status, JSON.stringify(firstBody)).toBe(200);
    // Same client, key, Mission and request: the narrower token cannot recover the broader child.
    const refused = await createChild(narrow, missionId, { authorizationDetails: fullAuthority(), creationRequestId: crid });
    const refusedBody = (await refused.json()) as { error?: string; mission_denial_reason?: string; access_token?: string };
    expect(refused.status, JSON.stringify(refusedBody)).toBe(400);
    expect(refusedBody.error).toBe("invalid_request");
    expect(refusedBody.mission_denial_reason).toBe("not_strict_subset");
    expect(refusedBody.access_token).toBeUndefined();
    // An equivalent broad token recovers the same child.
    const again = await createChild(broad, missionId, { authorizationDetails: fullAuthority(), creationRequestId: crid });
    const againBody = (await again.json()) as { mission_id?: string };
    expect(again.status, JSON.stringify(againBody)).toBe(200);
    expect(againBody.mission_id).toBe(firstBody.mission_id);
  });
});

describe("a no-actor exchange is open only to the Mission's approved agent (@spec mission#self-exchange rule 1, #1153 review, D353)", () => {
  it("refuses invalid_request when the authenticated client is not the Mission Record's client_id, though the token names it", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    // The handle is minted while the agent is approved; the AS never issues a
    // mismatched token, so the Mission Record is changed under it.
    const handle = await delegationHandle(baseAccessToken);
    as.kernel.db.prepare("UPDATE missions SET client_id = ? WHERE id = ?").run("another-approved-agent", missionId);
    const res = await asyncDelegate(handle, { rawSubject: true });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toContain("approved agent");
    // The delegation-handle request applies the same rule (#1157).
    const handleRes = await delegationHandleRequest(baseAccessToken);
    const handleBody = (await handleRes.json()) as { error?: string; error_description?: string };
    expect(handleRes.status, JSON.stringify(handleBody)).toBe(400);
    expect(handleBody.error).toBe("invalid_request");
    expect(handleBody.error_description).toContain("approved agent");
  });
});

describe("presentedTokenAuthority reads a token's authority in full or not at all (@spec mission#self-exchange rule 2, #1153 review, D353)", () => {
  const entry = { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] };
  it("returns the entries of a well-formed authorization_details", () => {
    expect(presentedTokenAuthority({ authorization_details: [entry] })).toEqual([entry]);
  });
  it.each([
    ["absent", {}],
    ["empty", { authorization_details: [] }],
    ["not an array", { authorization_details: entry }],
    ["an entry without its resource", { authorization_details: [{ type: entry.type, actions: entry.actions }] }],
    ["an entry with a non-string action", { authorization_details: [{ ...entry, actions: [1] }] }],
  ])("returns nothing for authorization_details that is %s", (_label, claims) => {
    expect(presentedTokenAuthority(claims as Record<string, unknown>)).toBeUndefined();
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
    expect(payload.authorization_details).toMatchObject(confinedAuthority());
  });

  it("sender-constrained refresh token: a DPoP proof from the WRONG key fails jkt verification", async () => {
    const { baseAccessToken } = await issueBaseMission();
    const { refresh_token } = (await (await asyncDelegate(baseAccessToken)).json()) as { refresh_token: string };
    // Present a key the refresh token is not bound to.
    const res = await refreshFamily(refresh_token, otherDpop);
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

  /**
   * The Mission's derived set with remittance.send stripped (the expected
   * effective projection). @spec mission#authorization-derivation (#743) —
   * the payments ceiling is now two entries (money-bearing / read-only), so
   * `fullAuthority`'s single mixed proposal derives two fragments; an entry
   * left with zero actions after stripping is dropped, mirroring the real
   * projection (`intersectForProjection` drops an empty-action fragment
   * rather than carrying a dangling entry).
   */
  const withoutRemittance = (missionId: string): unknown =>
    (as.kernel.get(missionId)?.authority_set ?? [])
      .map((e) => ({
        ...e,
        actions: e.actions.filter((a) => a !== "payments:remittance.send"),
      }))
      .filter((e) => e.actions.length > 0);

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

  it("full containment (#589): containing exactly the FAMILY's own narrower ceiling fails the refresh invalid_grant, even though the Mission's wider authority_set is not fully contained", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const first = (await (await asyncDelegate(baseAccessToken, { authorizationDetails: confinedAuthority() })).json()) as {
      refresh_token: string;
      authorization_details?: unknown;
    };
    expect(first.authorization_details).toMatchObject(confinedAuthority());

    // Contain exactly the family's own capability (invoice.read only). The
    // Mission still holds remittance.send, so the MISSION-WIDE effective set
    // is NOT empty (a mission-level-only check, like the pre-#589
    // gateDerivation gate, would miss this): only the FAMILY's narrower
    // ceiling has collapsed.
    as.kernel.contain(missionId, {
      event: {
        type: "tainted_read",
        source: "https://siem.example/detections",
        observed_at: new Date().toISOString(),
        event_id: "ce-async-full-family",
      },
      remove: [{ resource: RESOURCE, actions: ["payments:invoice.read"] }],
    });
    expect(as.kernel.effectiveAuthoritySet(as.kernel.get(missionId) as never)).not.toEqual([]);

    const res = await refreshFamily(first.refresh_token);
    const body = (await res.json()) as { error?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");

    // A retry with the SAME (already rotated-and-discarded) refresh token
    // also fails closed via oidc-provider's ordinary reuse detection,
    // independent of the containment check above: the family is never
    // resurrected by retrying.
    const retry = await refreshFamily(first.refresh_token);
    const retryBody = (await retry.json()) as { error?: string };
    expect(retry.status, JSON.stringify(retryBody)).toBe(400);
    expect(retryBody.error).toBe("invalid_grant");
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

  it("full containment (#589): containing the WHOLE resource fails a CODE-FLOW refresh invalid_grant (authority fully contained)", async () => {
    const { missionId, missionRefreshToken } = await issueBaseMission();
    as.kernel.contain(missionId, {
      event: {
        type: "tainted_read",
        source: "https://siem.example/detections",
        observed_at: new Date().toISOString(),
        event_id: "ce-code-full",
      },
      remove: [{ resource: RESOURCE }],
    });
    expect(as.kernel.effectiveAuthoritySet(as.kernel.get(missionId) as never)).toEqual([]);

    const res = await refreshFamily(missionRefreshToken, codeDpop);
    const body = (await res.json()) as { error?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
  });

  it("#589: a refresh family never re-widens across a contain sequence; the Mission's state version is monotonic and every refresh observes the current (never a rolled-back) one", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const first = (await (await asyncDelegate(baseAccessToken)).json()) as {
      refresh_token: string;
      authorization_details?: unknown;
    };
    const v0 = as.kernel.get(missionId)?.version as number;

    containRemittance(missionId, "ce-async-mono-1");
    const v1 = as.kernel.get(missionId)?.version as number;
    expect(v1).toBeGreaterThan(v0);

    const res1 = await refreshFamily(first.refresh_token);
    const body1 = (await res1.json()) as { refresh_token?: string; authorization_details?: unknown; error?: string };
    expect(res1.status, JSON.stringify(body1)).toBe(200);
    expect(body1.authorization_details).toEqual(withoutRemittance(missionId));

    // A second, independent narrowing: the version advances again, and the
    // NEXT refresh's projected remainder is a subset of the FIRST refresh's
    // remainder, never a superset. The kernel always recomputes from the
    // pristine grant ceiling through the CURRENT (monotonically narrowing)
    // effective set, so there is no separate "ceiling" value that a stale
    // read could roll back: every refresh observes the live, strictly
    // monotonic state version, which is what "retains the highest observed
    // version" reduces to when there is exactly one authoritative record and
    // no external cache in front of it (disclosed in the accompanying report:
    // true rollback defense against a STALE EXTERNAL source has no
    // constructible scenario in this single-process kernel; it matters for
    // the not-yet-implemented issuance-grant external-consuming-AS path).
    as.kernel.contain(missionId, {
      event: {
        type: "tainted_read",
        source: "https://siem.example/detections",
        observed_at: new Date().toISOString(),
        event_id: "ce-async-mono-2",
      },
      remove: [{ resource: RESOURCE, actions: ["payments:invoice.read"] }],
    });
    const v2 = as.kernel.get(missionId)?.version as number;
    expect(v2).toBeGreaterThan(v1);

    const res2 = await refreshFamily(body1.refresh_token as string);
    const body2 = (await res2.json()) as { error?: string };
    expect(res2.status, JSON.stringify(body2)).toBe(400);
    expect(body2.error).toBe("invalid_grant"); // now fully contained: never a re-widened 200
  });

  it("#589: an active Mission with a still-VALID Status List bit still narrows on refresh (the bit alone is insufficient)", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const first = (await (await asyncDelegate(baseAccessToken)).json()) as { refresh_token: string };
    const idx = as.kernel.participateInStatusList(missionId);

    containRemittance(missionId, "ce-async-statuslist");

    // Lifecycle state is untouched by containment: the Mission is still
    // `active`, so its Status List bit is still VALID (0x00).
    const record = as.kernel.get(missionId) as NonNullable<ReturnType<typeof as.kernel.get>>;
    expect(record.state).toBe("active");
    expect(idx).toBeGreaterThanOrEqual(0);

    // Despite the VALID bit, the refresh still narrows: the coarse two-bit
    // lifecycle signal does not observe containment, but the Effective
    // Authority Set projection (which does not consult the Status List bit
    // at all) still does.
    const res = await refreshFamily(first.refresh_token);
    const body = (await res.json()) as { authorization_details?: unknown; error?: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(body.authorization_details).toEqual(withoutRemittance(missionId));
  });

  it("regression: a no-containment mission's refresh preserves the canonical issuance commitment", async () => {
    const { baseAccessToken } = await issueBaseMission();
    const first = (await (await asyncDelegate(baseAccessToken)).json()) as {
      refresh_token: string;
      access_token: string;
      authorization_details?: unknown;
    };
    const res = await refreshFamily(first.refresh_token);
    const body = (await res.json()) as { access_token?: string; authorization_details?: unknown; error?: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    // Canonical-byte-identical authority across issuance and refresh (JSON member order is not significant).
    expect(canonicalize(body.authorization_details as JsonValue)).toBe(canonicalize(first.authorization_details as JsonValue));
    expect(canonicalize(decodeJwt(body.access_token as string).authorization_details as JsonValue)).toBe(
      canonicalize(decodeJwt(first.access_token).authorization_details as JsonValue),
    );
  });
});

/**
 * @spec issuance-grant#effective-set-projection (#617 review 1) — the
 * TRANSIENT authority-source class. An unavailable, unverifiable, or
 * rolled-back source says nothing about the credential's authority, so the
 * refusal is `temporarily_unavailable` with HTTP 503 (machine-readable, not an
 * `error_description` to parse) and it consumes NOTHING: the presented
 * credential is retryable exactly as held.
 */
describe("transient authority-source failure (@spec issuance-grant#effective-set-projection)", () => {
  it("on refresh: refuses temporarily_unavailable (503 + Retry-After) and consumes neither the presented refresh token nor its rotation; the SAME token then succeeds", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const first = (await (await asyncDelegate(baseAccessToken)).json()) as {
      refresh_token: string;
      authorization_details?: unknown;
    };
    expect(typeof first.refresh_token).toBe("string");

    sourceOutage = "mission status source unreachable";
    let res: Response;
    try {
      res = await refreshFamily(first.refresh_token);
    } finally {
      sourceOutage = undefined;
    }
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(503);
    expect(body.error).toBe("temporarily_unavailable");
    // NOT server_error: OIDCProviderError computes expose = status < 500, and
    // err_out.js replaces a non-exposed error with a generic server_error body.
    expect(body.error_description).toMatch(/unreachable/);
    expect(res.headers.get("retry-after")).toBe(String(RETRY_AFTER_SECONDS));

    // The refusal landed in rotateRefreshToken, BEFORE refreshToken.consume()
    // and before the rotated token was saved, so the client's own credential is
    // untouched: the SAME refresh token still redeems once the source recovers.
    // (A refusal thrown from the rar hook or extraTokenClaims instead would have
    // consumed it, and this retry would fail "refresh token already used".)
    const retry = await refreshFamily(first.refresh_token);
    const retryBody = (await retry.json()) as {
      access_token?: string;
      refresh_token?: string;
      authorization_details?: unknown;
      error?: string;
    };
    expect(retry.status, JSON.stringify(retryBody)).toBe(200);
    expect(retryBody.authorization_details).toEqual(as.kernel.get(missionId)?.authority_set);
    expect(typeof retryBody.refresh_token).toBe("string");
    expect(retryBody.refresh_token).not.toBe(first.refresh_token); // rotation happened NOW, not then
  });

  it("at the initial exchange: refuses 503 before the idempotency reservation, so the SAME creation_request_id still redeems", async () => {
    const { baseAccessToken } = await issueBaseMission();
    const creationRequestId = crypto.randomUUID();
    // The handle is minted before the outage: this case is the exchange's own refusal.
    const handle = await delegationHandle(baseAccessToken);

    sourceOutage = "mission status source returned a rolled-back state version";
    let res: Response;
    try {
      res = await asyncDelegate(handle, { creationRequestId, rawSubject: true });
    } finally {
      sourceOutage = undefined;
    }
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(503);
    expect(body.error).toBe("temporarily_unavailable");
    expect(body.error_description).toMatch(/rolled-back/);
    expect(res.headers.get("retry-after")).toBe(String(RETRY_AFTER_SECONDS));

    // Nothing was consumed: no reservation, no family, no derivation count, so
    // the retry is a FIRST presentation of that creation_request_id, not a
    // recovery of a failed one (which would replay the stored refusal).
    const retry = await asyncDelegate(handle, { creationRequestId, rawSubject: true });
    const retryBody = (await retry.json()) as { refresh_token?: string; error?: string };
    expect(retry.status, JSON.stringify(retryBody)).toBe(200);
    expect(typeof retryBody.refresh_token).toBe("string");
  });

  it("the permanent class is unaffected: a fully narrowed family still refuses invalid_grant with 400, never 503", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const first = (await (await asyncDelegate(baseAccessToken, { authorizationDetails: confinedAuthority() })).json()) as {
      refresh_token: string;
    };
    as.kernel.contain(missionId, {
      event: {
        type: "tainted_read",
        source: "https://siem.example/detections",
        observed_at: new Date().toISOString(),
        event_id: "ce-transient-contrast",
      },
      remove: [{ resource: RESOURCE }],
    });
    const res = await refreshFamily(first.refresh_token);
    const body = (await res.json()) as { error?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(res.headers.get("retry-after")).toBeNull();
  });
});

/**
 * @spec issuance-grant#effective-set-projection (#617 review 3) — the durable
 * Mission-bound grant discriminator. "No Mission resolved" used to mean "not a
 * Mission-bound grant" at both token-plane hooks, so a Mission-bound grant
 * whose record became unresolvable fell through to the fail-OPEN branch: the
 * stored issuance-time authorization_details were reissued, with NO `mission`
 * claim, at exactly the moment the state gate could not be evaluated.
 */
describe("unresolvable Mission fails closed (@spec issuance-grant#effective-set-projection)", () => {
  /** Purge ONLY the Mission record; the index is a separate store by design. */
  const purgeMission = (missionId: string): void => {
    as.kernel.db.prepare("DELETE FROM missions WHERE id = ?").run(missionId);
    expect(as.kernel.get(missionId)).toBeUndefined();
  };

  it("a per-delegation family grant whose Mission record is purged refuses refresh instead of reissuing its stale authority", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const first = (await (await asyncDelegate(baseAccessToken, { authorizationDetails: confinedAuthority() })).json()) as {
      refresh_token: string;
      authorization_details?: unknown;
    };
    expect(first.authorization_details).toMatchObject(confinedAuthority());

    purgeMission(missionId);

    const res = await refreshFamily(first.refresh_token);
    const body = (await res.json()) as { error?: string; access_token?: string; authorization_details?: unknown };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.access_token).toBeUndefined();
    expect(body.authorization_details).toBeUndefined();
  });

  it("the Mission's OWN code-flow grant fails closed the same way once its record is purged", async () => {
    const { missionId, missionRefreshToken } = await issueBaseMission();
    purgeMission(missionId);
    const res = await refreshFamily(missionRefreshToken, codeDpop);
    const body = (await res.json()) as { error?: string; access_token?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.access_token).toBeUndefined();
  });

  it("a LIVE Mission whose grant_id column has moved on still refreshes, gated and claimed through the index (never a false refusal, never a claimless token)", async () => {
    const { missionId, missionRefreshToken } = await issueBaseMission();
    // Rebind the Mission to a different grant id: the credential's own grant is
    // no longer what `missions.grant_id` holds, so findByGrant misses while the
    // Mission is perfectly live. The index must RESOLVE it (gate + project),
    // not refuse it, and not fall through to the claimless pass-through.
    as.kernel.bindGrant(missionId, "rebound-grant-id-for-test");
    const res = await refreshFamily(missionRefreshToken, codeDpop);
    const body = (await res.json()) as { access_token?: string; authorization_details?: unknown; error?: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(body.authorization_details).toEqual(as.kernel.get(missionId)?.authority_set);
    const { payload } = await jwtVerify(body.access_token as string, remoteJwks, {
      issuer: ISSUER,
      audience: RESOURCE,
    });
    // The `mission` claim is still attached: extraTokenClaims resolved the
    // Mission through the index rather than returning {}.
    expect((payload.mission as { id?: string } | undefined)?.id).toBe(missionId);
  });

  it("the index is the discriminator: it survives the Mission's deletion, and an unknown grant resolves undefined (the pass-through case)", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const first = (await (await asyncDelegate(baseAccessToken)).json()) as { refresh_token: string };
    expect(typeof first.refresh_token).toBe("string");

    const recorded = as.kernel.db
      .prepare("SELECT grant_id FROM missions WHERE id = ?")
      .get(missionId) as { grant_id: string };
    expect(as.kernel.missionBoundGrants.resolve(recorded.grant_id)).toEqual({
      missionId,
      kind: "approval",
    });

    purgeMission(missionId);
    // Append-only: the binding outlives the record it refers to, which is the
    // whole point (a discriminator cleaned up with the Mission would answer
    // "not Mission-bound" for exactly the grants it exists to catch).
    expect(as.kernel.missionBoundGrants.resolve(recorded.grant_id)?.missionId).toBe(missionId);
    // An ordinary (never Mission-bound) grant is a miss, so the hooks pass it
    // through untouched rather than refusing it.
    expect(as.kernel.missionBoundGrants.resolve("some-unbound-grant-id")).toBeUndefined();
  });
});

describe("async-delegation single count (@spec async-delegation)", () => {
  it("derivation_count rises by exactly 1 across issuance + N refreshes", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    // #1157: the delegation handle is its own counted derivation, requested
    // before the baseline; the counts below are the family exchange's.
    const handle = await delegationHandle(baseAccessToken);
    const before = as.kernel.get(missionId)?.derivation_count as number;

    const first = (await (await asyncDelegate(handle, { rawSubject: true })).json()) as { refresh_token: string };
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
    // The synchronous projection marked the family terminal at once.
    expect(as.delegationFamilyStore.resolve(grantId)).toBeUndefined();
    // @spec control-plane#fanout — the oidc grant revocation leaves this
    // process, so it is a DURABLE delivery captured in the terminal
    // transition's own transaction, not a fire-and-forget promise with a
    // swallowed rejection. Its row is pending until the drain awaits it.
    const revokeEventId = (
      as.kernel.db
        .prepare("SELECT event_id FROM lifecycle_events WHERE mission_id = ? ORDER BY seq DESC LIMIT 1")
        .get(missionId) as { event_id: string }
    ).event_id;
    expect(as.kernel.outbox.deliveries(revokeEventId)).toEqual([
      expect.objectContaining({
        subscriber: "delegation-family-grant-revoke",
        disposition: "pending",
        attempts: 0,
      }),
    ]);
    expect(await as.provider.Grant.find(grantId)).toBeDefined();

    await as.kernel.drainLifecycleOutbox();
    expect(as.kernel.outbox.deliveries(revokeEventId)[0]?.disposition).toBe("accepted");
    expect(await as.provider.Grant.find(grantId)).toBeUndefined();

    const res = await refreshFamily(refresh_token);
    const body = (await res.json()) as { access_token?: string; error?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    // Assert on the error itself, not merely on "not 200": a claimless 200 must fail loudly.
    expect(body.error).toBe("invalid_grant");
    expect(body.access_token).toBeUndefined();
  });

  it("revoke Mission -> a new async-delegation exchange is refused invalid_request, opening no family and counting no derivation (@spec mission#issuance-gating, #1154)", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    // The handle is taken while the Mission is active; the async exchange then
    // presents it after the revocation.
    const handle = await delegationHandle(baseAccessToken);
    as.kernel.transition(missionId, "revoke");
    const countBefore = as.kernel.get(missionId)?.derivation_count;
    const res = await asyncDelegate(handle, { rawSubject: true });
    const body = (await res.json()) as { error?: string; access_token?: string; refresh_token?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    // The exchange refuses invalid_request; a refresh of a family opened before
    // the revocation keeps invalid_grant (the test above).
    expect(body.error).toBe("invalid_request");
    expect(body.access_token).toBeUndefined();
    expect(body.refresh_token).toBeUndefined();
    expect(as.delegationFamilyStore.familiesForMission(missionId)).toEqual([]);
    expect(as.kernel.get(missionId)?.derivation_count).toBe(countBefore);
  });

  it("a Mission at its derivation limit refuses a new async-delegation exchange with invalid_grant, a limit and not a lifecycle refusal, opening no family (@spec derivation-limits, mission#issuance-gating, #1154)", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    // The handle request is itself a counted derivation, so the limit is set
    // after it: the async exchange is the derivation the limit refuses.
    const handle = await delegationHandle(baseAccessToken);
    const count = as.kernel.get(missionId)?.derivation_count as number;
    as.kernel.db.prepare("UPDATE missions SET derivation_limit = ? WHERE id = ?").run(count, missionId);
    const res = await asyncDelegate(handle, { rawSubject: true });
    const body = (await res.json()) as { error?: string; refresh_token?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.refresh_token).toBeUndefined();
    // The provisional family is rolled back: none resolves as live.
    for (const grantId of as.delegationFamilyStore.familiesForMission(missionId)) {
      expect(as.delegationFamilyStore.resolve(grantId)).toBeUndefined();
    }
    expect(as.kernel.get(missionId)?.derivation_count).toBe(count);
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

  it("absolute-lifetime clamp: a family refresh's access token and rotated refresh token never exceed the Mission expires_at (@spec mission#mission-bound-tokens)", async () => {
    // The family refresh is oidc-provider's native refresh_token grant: its
    // access token took the resource server's flat 300 s before ttl.AccessToken
    // clamped it (#894 item 1).
    const expiresAt = new Date(Date.now() + 60_000).toISOString(); // 60s < the 300s AT default
    const { missionId, baseAccessToken } = await issueBaseMission(expiresAt);
    const { refresh_token } = (await (await asyncDelegate(baseAccessToken)).json()) as { refresh_token: string };
    const res = await refreshFamily(refresh_token);
    const body = (await res.json()) as { access_token: string; refresh_token: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    const missionExp = Math.floor(Date.parse(as.kernel.get(missionId)?.expires_at as string) / 1000);
    const at = decodeJwt(body.access_token) as { iat: number; exp: number };
    expect(at.exp).toBeLessThanOrEqual(missionExp);
    expect(at.exp - at.iat).toBeLessThan(300);
    const rotated = (await as.provider.RefreshToken.find(body.refresh_token)) as { exp: number } | undefined;
    expect(rotated?.exp).toBeLessThanOrEqual(missionExp);
  });

  /**
   * Count the refresh tokens oidc-provider saves while `fn` runs, with
   * `Date.now` (the clock token lifetimes are computed on) fixed at `nowMs`.
   * The kernel's own clock stays real time, so the Mission is still `active`.
   */
  async function refreshTokensSavedAt<T>(nowMs: number, fn: () => Promise<T>): Promise<{ result: T; saved: number }> {
    let saved = 0;
    const onSaved = () => {
      saved += 1;
    };
    as.provider.on("refresh_token.saved", onSaved);
    vi.spyOn(Date, "now").mockReturnValue(nowMs);
    try {
      return { result: await fn(), saved };
    } finally {
      vi.restoreAllMocks();
      as.provider.removeListener("refresh_token.saved", onSaved);
    }
  }

  /** A Mission expires_at at a whole second plus 500 ms, `seconds` out. */
  const halfSecondExpiry = (seconds: number): { iso: string; ms: number } => {
    const ms = (Math.floor(Date.now() / 1000) + seconds) * 1000 + 500;
    return { iso: new Date(ms).toISOString(), ms };
  };

  it("fractional-second boundary: an async-delegation exchange with 0.9 s of Mission left is refused invalid_request with mission_error expired and saves no family refresh token (@spec mission#mission-bound-tokens, mission#issuance-gating)", async () => {
    const expiry = halfSecondExpiry(10);
    const { baseAccessToken } = await issueBaseMission(expiry.iso);
    // The handle is minted with time to spare; the 0.9 s case is the exchange's.
    const handle = await delegationHandle(baseAccessToken);
    const { result: res, saved } = await refreshTokensSavedAt(expiry.ms - 900, () =>
      asyncDelegate(handle, { rawSubject: true }),
    );
    const body = (await res.json()) as { error?: string; mission_error?: string; refresh_token?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    // A Token Exchange refuses a Mission that is not active with invalid_request
    // (RFC 8693 Section 2.2.2, #1154); the family refresh below keeps invalid_grant.
    expect(body.error).toBe("invalid_request");
    expect(body.mission_error).toBe("expired");
    expect(body.refresh_token).toBeUndefined();
    expect(saved).toBe(0);
  });

  it("fractional-second boundary: a family refresh token lives exactly until expires_at, and a family refresh with 0.9 s left is refused invalid_grant with mission_error expired and no refresh token saved (@spec mission#mission-bound-tokens, mission#issuance-gating)", async () => {
    const expiry = halfSecondExpiry(20);
    const { missionId, baseAccessToken } = await issueBaseMission(expiry.iso);
    // Open the family 5.4 s before expires_at: its refresh token's lifetime is
    // the Mission's remaining whole seconds, so it expires at floor(expires_at).
    const opened = await refreshTokensSavedAt(expiry.ms - 5_400, () => asyncDelegate(baseAccessToken));
    const family = (await opened.result.json()) as { refresh_token: string };
    expect(opened.result.status, JSON.stringify(family)).toBe(200);
    expect(opened.saved).toBe(1);
    const missionExp = Math.floor(Date.parse(as.kernel.get(missionId)?.expires_at as string) / 1000);
    const stored = (await as.provider.RefreshToken.find(family.refresh_token)) as { exp: number };
    expect(stored.exp).toBe(missionExp);

    // 0.9 s before expires_at the presented token is still valid, so the
    // refresh reaches rotation: the rotated token would have under a second.
    const { result: res, saved } = await refreshTokensSavedAt(expiry.ms - 900, () => refreshFamily(family.refresh_token));
    const body = (await res.json()) as { error?: string; mission_error?: string; refresh_token?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.mission_error).toBe("expired");
    expect(body.refresh_token).toBeUndefined();
    expect(saved).toBe(0);
  });

  it("family lifetime policy: on a Mission longer than 14 days the family refresh token still lives exactly until expires_at (@spec mission#mission-bound-tokens)", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission(FAR_EXP);
    const { refresh_token } = (await (await asyncDelegate(baseAccessToken)).json()) as { refresh_token: string };
    const stored = (await as.provider.RefreshToken.find(refresh_token)) as { iat: number; exp: number };
    const missionExp = Math.floor(Date.parse(as.kernel.get(missionId)?.expires_at as string) / 1000);
    expect(stored.exp - stored.iat).toBeGreaterThan(14 * 24 * 60 * 60);
    expect(stored.exp).toBeLessThanOrEqual(missionExp);
    expect(missionExp - stored.exp).toBeLessThanOrEqual(1);
  });

  it("fractional-second boundary: a family refresh token saved 0.9 s before an expires_at at .95 s is refused, never given the 1 s that would outlive the Mission (@spec mission#mission-bound-tokens)", async () => {
    const ms = (Math.floor(Date.now() / 1000) + 20) * 1000 + 950;
    const { missionId, baseAccessToken } = await issueBaseMission(new Date(ms).toISOString());
    const { refresh_token } = (await (await asyncDelegate(baseAccessToken)).json()) as { refresh_token: string };
    expect(refresh_token).toBeTruthy();
    const grantId = as.delegationFamilyStore.familiesForMission(missionId)[0] as string;
    const client = await as.provider.Client.find("ap-agent");
    // floor(now) + 1 here would be one second past floor(expires_at), 50 ms
    // past expires_at itself: the overrun a 1 s floor produced.
    vi.spyOn(Date, "now").mockReturnValue(ms - 900);
    try {
      const rt = new as.provider.RefreshToken({ accountId: "alice", client, grantId });
      await expect(rt.save()).rejects.toMatchObject({ error: "invalid_grant", missionError: "expired" });
    } finally {
      vi.restoreAllMocks();
    }
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
    // 3 s, not less: every credential is clamped to the Mission's expires_at
    // (@spec mission#mission-bound-tokens), the authorization code included, so
    // the code flow and the exchange need the Mission to outlive them.
    const shortExp = new Date(Date.now() + 3_000).toISOString();
    const { missionId, baseAccessToken } = await issueBaseMission(shortExp);
    await asyncDelegate(baseAccessToken);
    const grantId = as.delegationFamilyStore.familiesForMission(missionId)[0] as string;
    expect(as.delegationFamilyStore.resolve(grantId)?.missionId).toBe(missionId);

    await sleep(Date.parse(shortExp) - Date.now() + 200); // past shortExp
    // Land the lazy expiry: applyExpiry commits `expired` and fires the fan-out
    // (familyStore terminal marking is synchronous, so resolve is undefined at once).
    const rec = as.kernel.get(missionId);
    as.kernel.applyExpiry(rec as NonNullable<typeof rec>);
    expect(as.kernel.get(missionId)?.termination?.reason).toBe("expired");
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

describe("async-delegation creation idempotency (@spec continuation#transport-async — #485)", () => {
  type ExchangeBody = {
    access_token?: string;
    refresh_token?: string;
    authorization_details?: unknown;
    error?: string;
    error_description?: string;
  };

  it("lost-response retry returns the SAME family (stored response verbatim); derivation_count consumed ONCE; no second family", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    // #1157: the delegation handle is its own counted derivation, requested
    // before the baseline; the counts below are the family exchange's.
    const handle = await delegationHandle(baseAccessToken);
    const before = as.kernel.get(missionId)?.derivation_count as number;
    const creationRequestId = crypto.randomUUID();

    const first = await asyncDelegate(handle, {
      rawSubject: true,
      authorizationDetails: confinedAuthority(),
      creationRequestId,
    });
    const firstBody = (await first.json()) as ExchangeBody;
    expect(first.status, JSON.stringify(firstBody)).toBe(200);

    // The lost-response retry: same creation_request_id, fresh DPoP proof
    // (same acting key), same inputs.
    const retry = await asyncDelegate(handle, {
      rawSubject: true,
      authorizationDetails: confinedAuthority(),
      creationRequestId,
    });
    const retryBody = (await retry.json()) as ExchangeBody;
    expect(retry.status, JSON.stringify(retryBody)).toBe(200);
    // The initial refresh token is unconsumed: the STORED response is returned.
    expect(retryBody.access_token).toBe(firstBody.access_token);
    expect(retryBody.refresh_token).toBe(firstBody.refresh_token);
    expect(retryBody.authorization_details).toMatchObject(confinedAuthority());

    // ONE family, ONE derivation across both presentations.
    expect(as.delegationFamilyStore.familiesForMission(missionId)).toHaveLength(1);
    expect(as.kernel.get(missionId)?.derivation_count).toBe(before + 1);

    // The recovered refresh token is live: a native refresh succeeds.
    const refreshed = await refreshFamily(retryBody.refresh_token as string);
    expect(refreshed.status).toBe(200);
  });

  it("retry after the initial refresh token was consumed is REFUSED: consumption proves delivery; the rotated head stays the sole live lineage", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    // #1157: the delegation handle is its own counted derivation, requested
    // before the baseline; the counts below are the family exchange's.
    const handle = await delegationHandle(baseAccessToken);
    const before = as.kernel.get(missionId)?.derivation_count as number;
    const creationRequestId = crypto.randomUUID();

    const first = (await (
      await asyncDelegate(handle, { rawSubject: true,  authorizationDetails: confinedAuthority(), creationRequestId })
    ).json()) as ExchangeBody;
    // A -> B: consume the initial refresh token (the family's native rotation).
    const rotated = (await (await refreshFamily(first.refresh_token as string)).json()) as ExchangeBody;
    expect(rotated.refresh_token).toBeTruthy();

    // Creation recovery is REFUSED: a rotating family is a single lineage and
    // recovery must never mint an independent sibling refresh token into it.
    const retry = await asyncDelegate(handle, {
      rawSubject: true,
      authorizationDetails: confinedAuthority(),
      creationRequestId,
    });
    const retryBody = (await retry.json()) as ExchangeBody;
    expect(retry.status, JSON.stringify(retryBody)).toBe(400);
    expect(retryBody.error).toBe("invalid_grant");
    expect(retryBody.error_description).toContain("already delivered");

    // ONE family, ONE derivation; nothing new was minted.
    expect(as.delegationFamilyStore.familiesForMission(missionId)).toHaveLength(1);
    expect(as.kernel.get(missionId)?.derivation_count).toBe(before + 1);

    // B stays the SOLE live head: the rotated token still refreshes (no reuse
    // wipe, no sibling), audienced to the target and bound to the acting key.
    const refreshed = await refreshFamily(rotated.refresh_token as string);
    const refreshedBody = (await refreshed.json()) as ExchangeBody;
    expect(refreshed.status, JSON.stringify(refreshedBody)).toBe(200);
    const { payload } = await jwtVerify(refreshedBody.access_token as string, remoteJwks, {
      issuer: ISSUER,
      audience: RESOURCE,
    });
    expect((payload.cnf as { jkt?: string }).jkt).toBe(actingJkt);
    expect((payload.mission as { id?: string }).id).toBe(missionId);
    expect(as.kernel.get(missionId)?.derivation_count).toBe(before + 1);
  });

  it("concurrent first presentations of the same creation_request_id: exactly ONE family + one derivation count; every response is coherent or in-progress", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    // #1157: the delegation handle is its own counted derivation, requested
    // before the baseline; the counts below are the family exchange's.
    const handle = await delegationHandle(baseAccessToken);
    const before = as.kernel.get(missionId)?.derivation_count as number;
    const creationRequestId = crypto.randomUUID();

    const results = await Promise.all([
      asyncDelegate(handle, { rawSubject: true,  authorizationDetails: confinedAuthority(), creationRequestId }),
      asyncDelegate(handle, { rawSubject: true,  authorizationDetails: confinedAuthority(), creationRequestId }),
    ]);
    const bodies = (await Promise.all(results.map((r) => r.json()))) as ExchangeBody[];

    // Exactly ONE family and ONE derivation, however the race resolved.
    expect(as.delegationFamilyStore.familiesForMission(missionId)).toHaveLength(1);
    expect(as.kernel.get(missionId)?.derivation_count).toBe(before + 1);

    // Each response is a coherent delivery (200 with a live family refresh
    // token) or the retryable in-progress result; at least one delivered.
    let delivered = 0;
    for (const [i, res] of results.entries()) {
      const body = bodies[i] as ExchangeBody;
      if (res.status === 200) {
        delivered += 1;
        expect(body.refresh_token, JSON.stringify(body)).toBeTruthy();
        expect(body.authorization_details).toMatchObject(confinedAuthority());
      } else {
        expect(res.status, JSON.stringify(body)).toBe(400);
        expect(body.error).toBe("invalid_request");
        expect(body.error_description).toContain("in progress");
      }
    }
    expect(delivered).toBeGreaterThanOrEqual(1);
  });

  it("crash simulation: a family-created reservation without completion RESUMES delivery of the SAME family (no second family, no recount)", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    // #1157: the delegation handle is its own counted derivation, requested
    // before the baseline; the counts below are the family exchange's.
    const handle = await delegationHandle(baseAccessToken);
    const creationRequestId = crypto.randomUUID();
    const first = (await (
      await asyncDelegate(handle, { rawSubject: true,  authorizationDetails: confinedAuthority(), creationRequestId })
    ).json()) as ExchangeBody;
    const after = as.kernel.get(missionId)?.derivation_count as number;
    const grantId = as.delegationFamilyStore.familiesForMission(missionId)[0] as string;

    // Rewind the operation to FAMILY-CREATED: as if the process crashed after
    // the atomic family-created transition (family + single count committed)
    // but before the response was delivered.
    as.kernel.db
      .prepare(
        "UPDATE creation_idempotency SET state = 'reserved', mission_id = NULL, completed_at = NULL, delivery_json = ? WHERE creation_request_id = ?",
      )
      .run(JSON.stringify({ grant_id: grantId, target: RESOURCE }), creationRequestId);

    const retry = await asyncDelegate(handle, {
      rawSubject: true,
      authorizationDetails: confinedAuthority(),
      creationRequestId,
    });
    const body = (await retry.json()) as ExchangeBody;
    expect(retry.status, JSON.stringify(body)).toBe(200);
    // Freshly issued initial tokens for the RECORDED family.
    expect(body.refresh_token).toBeTruthy();
    expect(body.refresh_token).not.toBe(first.refresh_token);
    expect(body.authorization_details).toMatchObject(confinedAuthority());

    // The SAME family, no recount.
    expect(as.delegationFamilyStore.familiesForMission(missionId)).toHaveLength(1);
    expect(as.kernel.get(missionId)?.derivation_count).toBe(after);

    // The resumed delivery is live: it refreshes under the recorded family.
    const refreshed = await refreshFamily(body.refresh_token as string);
    expect(refreshed.status).toBe(200);
    // And the operation is completed again: a further retry returns the
    // resumed response verbatim while its refresh token is unconsumed... but
    // the refresh above consumed it, so creation recovery now refuses.
    const post = await asyncDelegate(handle, {
      rawSubject: true,
      authorizationDetails: confinedAuthority(),
      creationRequestId,
    });
    const postBody = (await post.json()) as ExchangeBody;
    expect(post.status, JSON.stringify(postBody)).toBe(400);
    expect(postBody.error).toBe("invalid_grant");
    expect(postBody.error_description).toContain("already delivered");
  });

  it("same creation_request_id + different fingerprint -> invalid_request (identifier reuse, not a retry)", async () => {
    const { baseAccessToken } = await issueBaseMission();
    const creationRequestId = crypto.randomUUID();
    const first = await asyncDelegate(baseAccessToken, {
      authorizationDetails: confinedAuthority(),
      creationRequestId,
    });
    expect(first.status).toBe(200);

    // Same identifier, DIFFERENT requested confined subset (the full set).
    const reused = await asyncDelegate(baseAccessToken, { creationRequestId });
    const body = (await reused.json()) as ExchangeBody;
    expect(reused.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toContain("different creation request");
  });

  it("missing creation_request_id -> invalid_request", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    // #1157: the delegation handle is its own counted derivation, requested
    // before the baseline; the counts below are the family exchange's.
    const handle = await delegationHandle(baseAccessToken);
    const before = as.kernel.get(missionId)?.derivation_count as number;
    const res = await asyncDelegate(handle, { rawSubject: true,  creationRequestId: null });
    const body = (await res.json()) as ExchangeBody;
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toContain("creation_request_id");
    // Nothing was created or counted.
    expect(as.delegationFamilyStore.familiesForMission(missionId)).toHaveLength(0);
    expect(as.kernel.get(missionId)?.derivation_count).toBe(before);
  });
});

describe("async-delegation family fallback preserves lineage (@spec child-delegation#parent-member, expansion#predecessor-member, #651)", () => {
  /** A narrower authority than fullAuthority(), so an expansion below genuinely widens. */
  const readOnlyAuthority = () => [
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: ["payments:invoice.read"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    },
  ];

  it("successor-rooted: a family opened from a Successor Mission's own access token preserves `predecessor` on the initial token and after refresh", async () => {
    const { missionId: predecessorId, baseAccessToken: predecessorAccessToken } = await issueBaseMission(
      FAR_EXP,
      readOnlyAuthority(),
    );

    // Widen via the expansion exchange (deferred): ap-agent + codeDpop, the same
    // client/key the predecessor's own code flow authenticated with.
    const opened = await codeTokenRequest({
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      subject_token: predecessorAccessToken,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      login_hint: "alice",
      mission_intent: JSON.stringify({
        intent: {
          goal: "Widen for the async-delegation family lineage regression (#651)",
          target_resources: [RESOURCE],
          expires_at: FAR_EXP,
        },
      }),
      authorization_details: JSON.stringify(fullAuthority()),
      creation_request_id: crypto.randomUUID(),
    });
    const ob = (await opened.json()) as { error?: string; deferral_code?: string };
    expect(opened.status, JSON.stringify(ob)).toBe(400);
    expect(ob.error).toBe("authorization_pending");

    as.expansionDeferrals.approve(ob.deferral_code as string, {
      approver: { iss: ISSUER, sub: "bob" },
      approvalEventId: `apev-651-${crypto.randomUUID()}`,
      approvedUntil: FAR_EXP,
    });
    const poll = await codeTokenRequest({
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      deferral_code: ob.deferral_code as string,
    });
    const pb = (await poll.json()) as { access_token?: string };
    expect(poll.status, JSON.stringify(pb)).toBe(200);
    const successorAccessToken = pb.access_token as string;
    const successorClaims = decodeJwt(successorAccessToken) as {
      client_id?: string;
      mission?: { id?: string; predecessor?: string };
    };
    // asyncDelegate()'s default acting client is ap-agent: the successor must
    // still be owned by it (expansion never reassigns client_id).
    expect(successorClaims.client_id).toBe("ap-agent");
    const successorId = successorClaims.mission?.id as string;
    expect(successorClaims.mission?.predecessor).toBe(predecessorId);

    // Open an async-delegation family ROOTED at the Successor Mission's OWN
    // access token (subject_token). Before the fix this silently dropped
    // `predecessor` from the family fallback's claim (provider.ts #651).
    const first = await asyncDelegate(successorAccessToken);
    const firstBody = (await first.json()) as { access_token?: string; refresh_token?: string };
    expect(first.status, JSON.stringify(firstBody)).toBe(200);
    const { payload: initialPayload } = await jwtVerify(firstBody.access_token as string, remoteJwks, {
      issuer: ISSUER,
      audience: RESOURCE,
    });
    const initialMission = initialPayload.mission as { id?: string; predecessor?: string };
    expect(initialMission.id).toBe(successorId);
    expect(initialMission.predecessor).toBe(predecessorId);

    // The family fallback re-projects lineage on every refresh too.
    const refreshed = await refreshFamily(firstBody.refresh_token as string);
    const refreshedBody = (await refreshed.json()) as { access_token?: string };
    expect(refreshed.status, JSON.stringify(refreshedBody)).toBe(200);
    const { payload: refreshedPayload } = await jwtVerify(refreshedBody.access_token as string, remoteJwks, {
      issuer: ISSUER,
      audience: RESOURCE,
    });
    const refreshedMission = refreshedPayload.mission as { id?: string; predecessor?: string };
    expect(refreshedMission.id).toBe(successorId);
    expect(refreshedMission.predecessor).toBe(predecessorId);
  });

  it("child-rooted: a family opened from a Child Mission's own access token preserves `parent` on the initial token and after refresh", async () => {
    // The parent Mission, then a Child Mission whose actor is the test-only
    // child client (the shipped one cannot exchange; see the negative below).
    const { missionId: parentId, baseAccessToken } = await issueBaseMission();
    const created = await createChildViaExchange(baseAccessToken, parentId, EXCHANGER_CLIENT_ID);
    const createdBody = (await created.json()) as { access_token?: string; mission_id?: string };
    expect(created.status, JSON.stringify(createdBody)).toBe(200);
    const childId = createdBody.mission_id as string;

    // @spec child-delegation#child-client-identity — the child redeems its OWN
    // child-bound assertion AS ITSELF for its own DPoP-bound access token.
    const redeemed = await childRedeem(createdBody.access_token as string, "exchanger");
    const redeemedBody = (await redeemed.json()) as { access_token?: string };
    expect(redeemed.status, JSON.stringify(redeemedBody)).toBe(200);
    const childAccessToken = redeemedBody.access_token as string;
    const childClaims = decodeJwt(childAccessToken) as {
      client_id?: string;
      mission?: { id?: string; parent?: { id?: string } };
    };
    expect(childClaims.client_id).toBe(EXCHANGER_CLIENT_ID);
    expect(childClaims.mission?.id).toBe(childId);
    expect(childClaims.mission?.parent?.id).toBe(parentId);

    // Open an async-delegation family ROOTED at the Child Mission's OWN access
    // token (subject_token), authenticated as the child actor itself. Before
    // the fix the INITIAL mint silently dropped `parent` (provider.ts #651).
    const first = await asyncDelegate(childAccessToken, { actingAs: "exchanger" });
    const firstBody = (await first.json()) as { access_token?: string; refresh_token?: string };
    expect(first.status, JSON.stringify(firstBody)).toBe(200);
    const { payload: initialPayload } = await jwtVerify(firstBody.access_token as string, remoteJwks, {
      issuer: ISSUER,
      audience: RESOURCE,
    });
    const initialMission = initialPayload.mission as { id?: string; parent?: { id?: string } };
    expect(initialMission.id).toBe(childId);
    expect(initialMission.parent?.id).toBe(parentId);

    // The family fallback re-projects lineage on every refresh too. The
    // per-delegation Grant is owned by the child actor, so it refreshes as itself.
    const refreshed = await refreshFamily(firstBody.refresh_token as string, actingDpop, "exchanger");
    const refreshedBody = (await refreshed.json()) as { access_token?: string };
    expect(refreshed.status, JSON.stringify(refreshedBody)).toBe(200);
    const { payload: refreshedPayload } = await jwtVerify(refreshedBody.access_token as string, remoteJwks, {
      issuer: ISSUER,
      audience: RESOURCE,
    });
    const refreshedMission = refreshedPayload.mission as { id?: string; parent?: { id?: string } };
    expect(refreshedMission.id).toBe(childId);
    expect(refreshedMission.parent?.id).toBe(parentId);
  });

  /**
   * The grant-registration boundary: a child actor registered for the
   * jwt-bearer grant alone redeems its assertion but cannot open a delegation
   * family. Pinned on a distinct test-only client (#1158, D361): the shipped
   * child actor carries token exchange.
   */
  it("a jwt-bearer-only child actor registration permits redemption but refuses the async-delegation exchange", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const created = await createChildViaExchange(baseAccessToken, missionId, BEARER_ONLY_CLIENT_ID);
    const createdBody = (await created.json()) as { access_token?: string; mission_id?: string };
    expect(created.status, JSON.stringify(createdBody)).toBe(200);

    const redeemed = await childRedeem(createdBody.access_token as string, "bearerOnly");
    const redeemedBody = (await redeemed.json()) as { access_token?: string };
    expect(redeemed.status, JSON.stringify(redeemedBody)).toBe(200);
    const childAccessToken = redeemedBody.access_token as string;

    // The grant-type refusal precedes any exchange handler, so the raw token
    // shows it (a delegation-handle request is refused the same way).
    const res = await asyncDelegate(childAccessToken, { actingAs: "bearerOnly", rawSubject: true });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toContain("not allowed for this client");
  });

  it("the TEST-ONLY testClients seam refuses to redefine a config-shipped client", async () => {
    // The seam ADDS registrations; a duplicate client_id would silently
    // redefine what config/clients.json ships.
    await expect(
      buildAuthorizationServer({
        issuer: `http://localhost:${PORT + 1}`,
        testClients: [{ client_id: "subagent-invoice-extractor", grant_types: [TOKEN_EXCHANGE_GRANT_TYPE] }],
      }),
    ).rejects.toThrow(/MUST NOT redefine the config-shipped client subagent-invoice-extractor/);
  });
});

describe("async-delegation discovery (@spec async-delegation#discovery)", () => {
  it("advertises delegated_refresh_token_profile_supported (alongside identity_continuation_supported)", async () => {
    const meta = (await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
    expect(meta.delegated_refresh_token_profile_supported).toBe(true);
    expect(meta.identity_continuation_supported).toBe(true);
  });
});

describe("the async-delegation subject_token is a delegation handle (@spec continuation#transport-async, draft-zhu-oauth-async-delegation-05 Section 4.3, #1157)", () => {
  it("refuses a resource-audienced Mission access token: its audience is not the acting client", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    expect(decodeJwt(baseAccessToken).aud).toBe(RESOURCE);
    const count = as.kernel.get(missionId)?.derivation_count;
    const res = await asyncDelegate(baseAccessToken, { rawSubject: true });
    const body = (await res.json()) as { error?: string; error_description?: string; refresh_token?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toContain("not a delegation handle audienced to the acting client");
    expect(body.refresh_token).toBeUndefined();
    expect(as.kernel.get(missionId)?.derivation_count).toBe(count);
  });

  it("refuses a handle presented under another key: client authentication never satisfies its sender constraint", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const handle = await delegationHandle(baseAccessToken);
    const count = as.kernel.get(missionId)?.derivation_count;
    const res = await asyncDelegate(handle, { rawSubject: true, keys: otherDpop });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toContain("does not match the subject_token confirmation key");
    expect(as.kernel.get(missionId)?.derivation_count).toBe(count);
  });

  it("recovery revalidates the handle: a retry presenting the raw token or another key never retrieves the recorded family", async () => {
    const { baseAccessToken } = await issueBaseMission();
    const handle = await delegationHandle(baseAccessToken);
    const creationRequestId = crypto.randomUUID();
    const first = await asyncDelegate(handle, { rawSubject: true, creationRequestId });
    const firstBody = (await first.json()) as { refresh_token?: string };
    expect(first.status, JSON.stringify(firstBody)).toBe(200);

    const raw = await asyncDelegate(baseAccessToken, { rawSubject: true, creationRequestId });
    const rawBody = (await raw.json()) as { error?: string; error_description?: string; refresh_token?: string };
    expect(raw.status, JSON.stringify(rawBody)).toBe(400);
    expect(rawBody.error_description).toContain("not a delegation handle");
    expect(rawBody.refresh_token).toBeUndefined();

    const wrongKey = await asyncDelegate(handle, { rawSubject: true, creationRequestId, keys: otherDpop });
    const wrongBody = (await wrongKey.json()) as { error?: string; error_description?: string; refresh_token?: string };
    expect(wrongKey.status, JSON.stringify(wrongBody)).toBe(400);
    expect(wrongBody.error_description).toContain("does not match the subject_token confirmation key");
    expect(wrongBody.refresh_token).toBeUndefined();

    // The handle itself still recovers the recorded family.
    const again = await asyncDelegate(handle, { rawSubject: true, creationRequestId });
    const againBody = (await again.json()) as { refresh_token?: string };
    expect(again.status, JSON.stringify(againBody)).toBe(200);
    expect(againBody.refresh_token).toBe(firstBody.refresh_token);
  });
});

describe("the delegation-handle request (@spec continuation#transport-async, mission#self-exchange, #1157, D358)", () => {
  it("mints a handle audienced to the requesting client, under the presented token's key, with its authority and no scope, as one counted derivation", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const count = as.kernel.get(missionId)?.derivation_count;
    const res = await delegationHandleRequest(baseAccessToken);
    const body = (await res.json()) as {
      access_token?: string;
      issued_token_type?: string;
      token_type?: string;
      scope?: string;
      authorization_details?: unknown;
    };
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(body.issued_token_type).toBe(ACCESS_TOKEN_TOKEN_TYPE);
    expect(body.token_type).toBe("DPoP");
    expect(body.scope).toBeUndefined();
    expect(res.headers.get("cache-control")).toContain("no-store");
    const claims = decodeJwt(body.access_token as string);
    expect(claims.aud).toBe("ap-agent");
    expect(claims.client_id).toBe("ap-agent");
    expect((claims.cnf as { jkt?: string }).jkt).toBe(actingJkt);
    expect((claims.mission as { id?: string }).id).toBe(missionId);
    expect(claims.scope).toBeUndefined();
    expect(claims.authorization_details).toEqual(decodeJwt(baseAccessToken).authorization_details);
    expect(body.authorization_details).toEqual(claims.authorization_details);
    // Core Self-Exchange rule 3: the exchange is a derivation, counted once.
    expect(as.kernel.get(missionId)?.derivation_count).toBe((count as number) + 1);
  });

  it("bounds the handle by the presented token's own authority, never the Mission's (rule 2)", async () => {
    const { baseAccessToken } = await issueBaseMission();
    // A narrower Mission access token: a family token confined to one action.
    const family = await asyncDelegate(baseAccessToken, { authorizationDetails: confinedAuthority() });
    const familyBody = (await family.json()) as { access_token?: string };
    expect(family.status, JSON.stringify(familyBody)).toBe(200);
    const res = await delegationHandleRequest(familyBody.access_token as string);
    const body = (await res.json()) as { access_token?: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    const actions = (decodeJwt(body.access_token as string).authorization_details as Array<{ actions: string[] }>)
      .flatMap((e) => e.actions);
    expect(actions).toEqual(["payments:invoice.read"]);
  });

  it("refuses an audience other than the requesting client's own client_id", async () => {
    const { baseAccessToken } = await issueBaseMission();
    const res = await delegationHandleRequest(baseAccessToken, undefined, actingDpop, { audience: RESOURCE });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_target");
    expect(body.error_description).toContain("own client_id");
  });

  it("refuses a DPoP proof under a key other than the presented token's", async () => {
    const { baseAccessToken } = await issueBaseMission();
    const res = await delegationHandleRequest(baseAccessToken, undefined, otherDpop);
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toContain("does not match the subject_token confirmation key");
  });

  it("refuses a client presenting a token issued to another client", async () => {
    const { baseAccessToken } = await issueBaseMission();
    const res = await delegationHandleRequest(baseAccessToken, "child");
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toContain("not issued to the requesting client");
  });

  it("refuses a Mission that is no longer active", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    as.kernel.transition(missionId, "revoke");
    const res = await delegationHandleRequest(baseAccessToken);
    const body = (await res.json()) as { error?: string; error_description?: string; mission_error?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    // @spec mission#issuance-gating (#1154, D369): a Token Exchange refuses an
    // inactive Mission with invalid_request, keeping mission_error.
    expect(body.error).toBe("invalid_request");
    expect(body.mission_error).toBe("revoked");
    expect(body.error_description).toContain("terminated");
  });

  it("narrows the handle by the Mission's current effective set, and refuses when nothing survives", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const contain = (eventId: string, remove: Array<{ resource: string; actions?: string[] }>) =>
      as.kernel.contain(missionId, {
        event: {
          type: "tainted_read",
          source: "https://siem.example/detections",
          observed_at: new Date().toISOString(),
          event_id: eventId,
        },
        remove,
      });
    contain(crypto.randomUUID(), [{ resource: RESOURCE, actions: ["payments:remittance.send"] }]);
    const narrowed = await delegationHandleRequest(baseAccessToken);
    const narrowedBody = (await narrowed.json()) as { access_token?: string };
    expect(narrowed.status, JSON.stringify(narrowedBody)).toBe(200);
    const actions = (decodeJwt(narrowedBody.access_token as string).authorization_details as Array<{ actions: string[] }>)
      .flatMap((e) => e.actions);
    expect(actions).toContain("payments:invoice.read");
    expect(actions).not.toContain("payments:remittance.send");

    contain(crypto.randomUUID(), [{ resource: RESOURCE }]);
    const none = await delegationHandleRequest(baseAccessToken);
    const noneBody = (await none.json()) as { error?: string; error_description?: string };
    expect(none.status, JSON.stringify(noneBody)).toBe(400);
    expect(noneBody.error).toBe("invalid_grant");
    expect(noneBody.error_description).toContain("no longer within the Mission's effective authority");
  });

  it("a lifecycle refusal at the handle's counted derivation is invalid_request with mission_error; a derivation-cap refusal stays invalid_grant (D369)", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const spy = vi.spyOn(as.kernel, "gateDerivation");
    try {
      // A Mission that expires between the early check and the count.
      spy.mockImplementationOnce(() => {
        throw new GateError("mission_expired", `mission ${missionId} is expired`);
      });
      const lifecycle = await delegationHandleRequest(baseAccessToken);
      const lifecycleBody = (await lifecycle.json()) as { error?: string; mission_error?: string; access_token?: string };
      expect(lifecycle.status, JSON.stringify(lifecycleBody)).toBe(400);
      expect(lifecycleBody.error).toBe("invalid_request");
      expect(lifecycleBody.mission_error).toBe("expired");
      expect(lifecycleBody.access_token).toBeUndefined();

      spy.mockImplementationOnce(() => {
        throw new GateError("derivation_cap_exhausted", `mission ${missionId} has no derivations left`);
      });
      const capped = await delegationHandleRequest(baseAccessToken);
      const cappedBody = (await capped.json()) as { error?: string };
      expect(capped.status, JSON.stringify(cappedBody)).toBe(400);
      expect(cappedBody.error).toBe("invalid_grant");

      // A Mission revoked between the early check and the count: the
      // diagnostic is read from the Mission as observed at the refusal.
      spy.mockImplementationOnce(() => {
        as.kernel.transition(missionId, "revoke");
        throw new GateError("mission_not_active", `mission ${missionId} is terminated`);
      });
      const revoked = await delegationHandleRequest(baseAccessToken);
      const revokedBody = (await revoked.json()) as { error?: string; mission_error?: string };
      expect(revoked.status, JSON.stringify(revokedBody)).toBe(400);
      expect(revokedBody.error).toBe("invalid_request");
      expect(revokedBody.mission_error).toBe("revoked");
    } finally {
      spy.mockRestore();
    }
  });

  it("refuses audience combined with the async selector before routing: no family and no derivation count (#1157 review P2)", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const handle = await delegationHandle(baseAccessToken);
    const count = as.kernel.get(missionId)?.derivation_count;
    // The async exchange carrying audience, with or without the access-token
    // requested_token_type: both are refused before either exchange runs.
    const cases = [
      asyncDelegate(handle, { rawSubject: true, extraParams: { audience: "ap-agent" } }),
      asyncDelegate(handle, {
        rawSubject: true,
        extraParams: { audience: "ap-agent", requested_token_type: ACCESS_TOKEN_TOKEN_TYPE },
      }),
    ];
    for (const res of await Promise.all(cases)) {
      const body = (await res.json()) as { error?: string; error_description?: string; refresh_token?: string };
      expect(res.status, JSON.stringify(body)).toBe(400);
      expect(body.error).toBe("invalid_request");
      expect(body.error_description).toContain("cannot be combined with request_refresh_token");
      expect(body.refresh_token).toBeUndefined();
    }
    expect(as.delegationFamilyStore.familiesForMission(missionId)).toHaveLength(0);
    expect(as.kernel.get(missionId)?.derivation_count).toBe(count);
  });

  it("refuses scope and authorization_details, and never routes a request combining audience with another exchange's parameter", async () => {
    const { baseAccessToken } = await issueBaseMission();
    const refusal = async (extra: Record<string, string>) => {
      const res = await delegationHandleRequest(baseAccessToken, undefined, actingDpop, extra);
      return { status: res.status, ...((await res.json()) as { error?: string; error_description?: string }) };
    };
    const scoped = await refusal({ scope: "payments" });
    expect(scoped.status).toBe(400);
    expect(scoped.error).toBe("invalid_scope");
    const detailed = await refusal({ authorization_details: JSON.stringify(confinedAuthority()) });
    expect(detailed.status).toBe(400);
    expect(detailed.error).toBe("invalid_request");
    expect(detailed.error_description).toContain("narrow it at the async-delegation exchange");
    for (const [param, value] of [
      ["mission_intent", "{}"],
      ["resource", RESOURCE],
      ["creation_request_id", crypto.randomUUID()],
    ] as const) {
      const combined = await refusal({ [param]: value });
      expect(combined.status, param).toBe(400);
      expect(combined.error, param).toBe("invalid_request");
      expect(combined.error_description, param).toContain(`cannot be combined with ${param}`);
    }
  });
});

describe("a fully contained family is refused after rotation, within the owner's boundary (#914 ruling 3)", () => {
  const contain = (missionId: string, eventId: string, remove: Array<{ resource: string; actions?: string[] }>) =>
    as.kernel.contain(missionId, {
      event: {
        type: "tainted_read",
        source: "https://siem.example/detections",
        observed_at: new Date().toISOString(),
        event_id: eventId,
      },
      remove,
    });
  const remittanceOnly = () => [
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: ["payments:remittance.send"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    },
  ];
  const actionsOf = (details: unknown): string[] =>
    ((details ?? []) as Array<{ actions: string[] }>).flatMap((e) => e.actions);
  /** Run `fn`, counting the refresh tokens oidc-provider saves meanwhile. */
  async function savingRefreshTokens<T>(fn: () => Promise<T>): Promise<{ result: T; saved: number }> {
    let saved = 0;
    const onSaved = () => {
      saved += 1;
    };
    as.provider.on("refresh_token.saved", onSaved);
    try {
      return { result: await fn(), saved };
    } finally {
      as.provider.removeListener("refresh_token.saved", onSaved);
    }
  }

  it("(a) and (b): a family whose ENTIRE confined subset is contained is refused, while a sibling family and the approval grant with surviving authority still refresh", async () => {
    const { missionId, baseAccessToken, missionRefreshToken } = await issueBaseMission();
    const a = (await (await asyncDelegate(baseAccessToken, { authorizationDetails: confinedAuthority() })).json()) as {
      refresh_token: string;
    };
    const b = (await (await asyncDelegate(baseAccessToken, { authorizationDetails: remittanceOnly() })).json()) as {
      refresh_token: string;
    };
    // Contain exactly family A's whole subset (invoice.read); B's survives.
    contain(missionId, "ce-family-a-whole", [{ resource: RESOURCE, actions: ["payments:invoice.read"] }]);

    const refusedA = await savingRefreshTokens(() => refreshFamily(a.refresh_token));
    const bodyA = (await refusedA.result.json()) as { error?: string; access_token?: string };
    expect(refusedA.result.status, JSON.stringify(bodyA)).toBe(400);
    expect(bodyA.error).toBe("invalid_grant");
    expect(bodyA.access_token).toBeUndefined();
    // Refused after rotation, at the `rar` hook: a rotated token was saved.
    // The boundary permits this ordering; it does not require it.
    expect(refusedA.saved).toBe(1);

    const okB = await refreshFamily(b.refresh_token);
    const bodyB = (await okB.json()) as { authorization_details?: unknown };
    expect(okB.status, JSON.stringify(bodyB)).toBe(200);
    expect(actionsOf(bodyB.authorization_details)).toEqual(["payments:remittance.send"]);

    const okApproval = await refreshFamily(missionRefreshToken, codeDpop);
    const bodyApproval = (await okApproval.json()) as { authorization_details?: unknown };
    expect(okApproval.status, JSON.stringify(bodyApproval)).toBe(200);
    expect(actionsOf(bodyApproval.authorization_details)).not.toContain("payments:invoice.read");
  });

  it("boundary: a family whose confined subset is only PARTLY contained narrows and is not refused", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    // The full derived set: invoice.read and remittance.send.
    const c = (await (await asyncDelegate(baseAccessToken)).json()) as { refresh_token: string };
    contain(missionId, "ce-family-c-part", [{ resource: RESOURCE, actions: ["payments:invoice.read"] }]);
    const res = await refreshFamily(c.refresh_token);
    const body = (await res.json()) as { authorization_details?: unknown };
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(actionsOf(body.authorization_details)).toEqual(["payments:remittance.send"]);
  });

  it("(c): an Expansion successor is authorized from a Mission access token, never from the contained family's consumed refresh token", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const a = (await (await asyncDelegate(baseAccessToken, { authorizationDetails: confinedAuthority() })).json()) as {
      refresh_token: string;
    };
    contain(missionId, "ce-family-a-expansion", [{ resource: RESOURCE, actions: ["payments:invoice.read"] }]);
    expect((await refreshFamily(a.refresh_token)).status).toBe(400); // A's token is now consumed

    // Restoring invoice.read widens the contained effective set: an expansion,
    // whose subject_token is the predecessor's Mission ACCESS token (#448: a
    // refresh token is never accepted there).
    const opened = await codeTokenRequest({
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      subject_token: baseAccessToken,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      login_hint: "alice",
      mission_intent: JSON.stringify({
        intent: { goal: "Restore invoice reads after review", target_resources: [RESOURCE], expires_at: FAR_EXP },
      }),
      authorization_details: JSON.stringify(fullAuthority()),
      creation_request_id: crypto.randomUUID(),
    });
    const ob = (await opened.json()) as { error?: string; deferral_code?: string };
    expect(opened.status, JSON.stringify(ob)).toBe(400);
    expect(ob.error).toBe("authorization_pending");
    as.expansionDeferrals.approve(ob.deferral_code as string, {
      approver: { iss: ISSUER, sub: "bob" },
      approvalEventId: "apev-restore-after-family-containment",
      approvedUntil: FAR_EXP,
    });
    const polled = await codeTokenRequest({
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      deferral_code: ob.deferral_code as string,
    });
    const pb = (await polled.json()) as { access_token?: string; mission_id?: string; authorization_details?: unknown };
    expect(polled.status, JSON.stringify(pb)).toBe(200);
    expect(pb.mission_id).not.toBe(missionId);
    expect(actionsOf(pb.authorization_details)).toContain("payments:invoice.read");
  });
});
