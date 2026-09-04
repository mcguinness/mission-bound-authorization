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
import { CHILD_JWT_BEARER_GRANT_TYPE } from "../src/adapters/child-grant.js";
import { TOKEN_EXCHANGE_GRANT_TYPE, ACCESS_TOKEN_TOKEN_TYPE, JWT_TOKEN_TYPE } from "../src/adapters/continuation-grant.js";
import { buildAuthorizationServer, type BuiltAs, SourceUnavailableError } from "../src/index.js";

const PORT = 14480;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE; // served by ISSUER (intra-domain target)
const FAR_EXP = "2027-01-01T00:00:00Z";
/**
 * @spec async-delegation (#651) — the TEST-ONLY child actor client. The shipped
 * child actor (`subagent-invoice-extractor`, config/clients.json) is granted
 * only the jwt-bearer grant type, so it cannot open an async-delegation family
 * over real HTTP; that block is pinned as its own negative below. This client
 * clones that registration and adds the token-exchange and refresh_token grant
 * types, so a Child Mission naming it as `child_actor` can mint and refresh a
 * child-rooted family through /token. Registered through the AS builder's
 * `testClients` seam; config/clients.json is untouched.
 */
const EXCHANGER_CLIENT_ID = "test-child-exchanger";

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };

let as: BuiltAs;
let asServer: Server;
let clientKey: CryptoKey; // ap-agent private_key_jwt key (kid ap-agent-auth)
let childClientKey: CryptoKey; // child actor private_key_jwt key
let exchangerClientKey: CryptoKey; // TEST-ONLY child actor private_key_jwt key (#651)
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

/** The private_key_jwt assertion of the client a flow authenticates AS. */
function assertionFor(actingAs: ActingClient | undefined): Promise<string> {
  if (actingAs === "child") return childClientAssertion();
  if (actingAs === "exchanger") return exchangerClientAssertion();
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
      scope: "payments",
      resource: RESOURCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
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

/**
 * Which registered client a /token request authenticates as. Default (absent) is
 * the acting client `ap-agent`. @spec #651 — the async-delegation exchange
 * requires the `subject_token`'s client_id to equal the authenticated client
 * (continuation-grant.ts), so a family rooted at a Child Mission's own access
 * token is opened by that Mission's OWN child actor: `child` is the shipped one
 * (jwt-bearer only, so the exchange is refused), `exchanger` the test-only one.
 */
type ActingClient = "child" | "exchanger";

interface ExchangeOpts {
  authorizationDetails?: unknown;
  resource?: string;
  /** @spec continuation#transport-async — REQUIRED; `null` omits it (the missing-param test). */
  creationRequestId?: string | null;
  /** Authenticate as a child actor client instead of `ap-agent` (@see ActingClient). */
  actingAs?: ActingClient;
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
  if (opts.creationRequestId !== null) {
    params.creation_request_id = opts.creationRequestId ?? crypto.randomUUID();
  }
  if (opts.authorizationDetails !== undefined) {
    params.authorization_details = JSON.stringify(opts.authorizationDetails);
  }
  const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
    fetch(`${ISSUER}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(actingDpop, extra) },
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
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
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
        scope: "payments",
        authorization_details_types: ["mission_resource_access"],
      },
    ],
    // @spec draft-mcguinness-oauth-mission#per-entry-enforcement — the AS asserts
    // the test-only child actor's type, exactly as config does for the shipped one.
    actorProfiles: { [EXCHANGER_CLIENT_ID]: "ai_agent" },
  });
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
    expect(first.authorization_details).toEqual(confinedAuthority());

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

    sourceOutage = "mission status source returned a rolled-back state version";
    let res: Response;
    try {
      res = await asyncDelegate(baseAccessToken, { creationRequestId });
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
    const retry = await asyncDelegate(baseAccessToken, { creationRequestId });
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
    expect(first.authorization_details).toEqual(confinedAuthority());

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
    const before = as.kernel.get(missionId)?.derivation_count as number;
    const creationRequestId = crypto.randomUUID();

    const first = await asyncDelegate(baseAccessToken, {
      authorizationDetails: confinedAuthority(),
      creationRequestId,
    });
    const firstBody = (await first.json()) as ExchangeBody;
    expect(first.status, JSON.stringify(firstBody)).toBe(200);

    // The lost-response retry: same creation_request_id, fresh DPoP proof
    // (same acting key), same inputs.
    const retry = await asyncDelegate(baseAccessToken, {
      authorizationDetails: confinedAuthority(),
      creationRequestId,
    });
    const retryBody = (await retry.json()) as ExchangeBody;
    expect(retry.status, JSON.stringify(retryBody)).toBe(200);
    // The initial refresh token is unconsumed: the STORED response is returned.
    expect(retryBody.access_token).toBe(firstBody.access_token);
    expect(retryBody.refresh_token).toBe(firstBody.refresh_token);
    expect(retryBody.authorization_details).toEqual(confinedAuthority());

    // ONE family, ONE derivation across both presentations.
    expect(as.delegationFamilyStore.familiesForMission(missionId)).toHaveLength(1);
    expect(as.kernel.get(missionId)?.derivation_count).toBe(before + 1);

    // The recovered refresh token is live: a native refresh succeeds.
    const refreshed = await refreshFamily(retryBody.refresh_token as string);
    expect(refreshed.status).toBe(200);
  });

  it("retry after the initial refresh token was consumed is REFUSED: consumption proves delivery; the rotated head stays the sole live lineage", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const before = as.kernel.get(missionId)?.derivation_count as number;
    const creationRequestId = crypto.randomUUID();

    const first = (await (
      await asyncDelegate(baseAccessToken, { authorizationDetails: confinedAuthority(), creationRequestId })
    ).json()) as ExchangeBody;
    // A -> B: consume the initial refresh token (the family's native rotation).
    const rotated = (await (await refreshFamily(first.refresh_token as string)).json()) as ExchangeBody;
    expect(rotated.refresh_token).toBeTruthy();

    // Creation recovery is REFUSED: a rotating family is a single lineage and
    // recovery must never mint an independent sibling refresh token into it.
    const retry = await asyncDelegate(baseAccessToken, {
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
    const before = as.kernel.get(missionId)?.derivation_count as number;
    const creationRequestId = crypto.randomUUID();

    const results = await Promise.all([
      asyncDelegate(baseAccessToken, { authorizationDetails: confinedAuthority(), creationRequestId }),
      asyncDelegate(baseAccessToken, { authorizationDetails: confinedAuthority(), creationRequestId }),
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
        expect(body.authorization_details).toEqual(confinedAuthority());
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
    const creationRequestId = crypto.randomUUID();
    const first = (await (
      await asyncDelegate(baseAccessToken, { authorizationDetails: confinedAuthority(), creationRequestId })
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

    const retry = await asyncDelegate(baseAccessToken, {
      authorizationDetails: confinedAuthority(),
      creationRequestId,
    });
    const body = (await retry.json()) as ExchangeBody;
    expect(retry.status, JSON.stringify(body)).toBe(200);
    // Freshly issued initial tokens for the RECORDED family.
    expect(body.refresh_token).toBeTruthy();
    expect(body.refresh_token).not.toBe(first.refresh_token);
    expect(body.authorization_details).toEqual(confinedAuthority());

    // The SAME family, no recount.
    expect(as.delegationFamilyStore.familiesForMission(missionId)).toHaveLength(1);
    expect(as.kernel.get(missionId)?.derivation_count).toBe(after);

    // The resumed delivery is live: it refreshes under the recorded family.
    const refreshed = await refreshFamily(body.refresh_token as string);
    expect(refreshed.status).toBe(200);
    // And the operation is completed again: a further retry returns the
    // resumed response verbatim while its refresh token is unconsumed... but
    // the refresh above consumed it, so creation recovery now refuses.
    const post = await asyncDelegate(baseAccessToken, {
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
    const before = as.kernel.get(missionId)?.derivation_count as number;
    const res = await asyncDelegate(baseAccessToken, { creationRequestId: null });
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
   * Separate coverage for the SHIPPED registration, which is deliberately
   * narrower than the test-only one above: config/clients.json grants
   * "subagent-invoice-extractor" only the jwt-bearer grant type, so the shipped
   * child actor redeems its assertion but cannot open a delegation family. The
   * test pins that as an executable fact; it flips if the registration widens.
   */
  it("the SHIPPED child actor registration permits redemption but refuses the async-delegation exchange", async () => {
    const { missionId, baseAccessToken } = await issueBaseMission();
    const created = await createChildViaExchange(baseAccessToken, missionId);
    const createdBody = (await created.json()) as { access_token?: string; mission_id?: string };
    expect(created.status, JSON.stringify(createdBody)).toBe(200);

    const redeemed = await childRedeem(createdBody.access_token as string);
    const redeemedBody = (await redeemed.json()) as { access_token?: string };
    expect(redeemed.status, JSON.stringify(redeemedBody)).toBe(200);
    const childAccessToken = redeemedBody.access_token as string;

    const res = await asyncDelegate(childAccessToken, { actingAs: "child" });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toContain("not allowed for this client");
  });

  it("the TEST-ONLY testClients seam refuses to redefine a config-shipped client", async () => {
    // The seam ADDS registrations; a duplicate client_id would silently widen
    // what config/clients.json ships, which is the block the negative above pins.
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
