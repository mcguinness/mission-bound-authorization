/**
 * #2009 P5 step 4: the OAuth binding's baseline flow on the reference
 * Authorization Server's minimal configuration, with the optional
 * capabilities unclaimed (`@spec mission#conformance`,
 * mission#optional-capabilities).
 *
 * The configuration claims the Mission Issuer role and nothing more. Its
 * capability set holds one entry, `lifecycle-revoke`: the binding requires a
 * Mission Issuer to accept a revocation by `mission_id` through an
 * authenticated means independent of possession of any token
 * (mission#revocation), and the reference's only such surface is the
 * Mission Lifecycle endpoint's `revoke` operation. No Delegation,
 * Self-Exchange, Introspection or Cross-Domain capability, no evidence type,
 * no standing-consent basis, and no other companion surface is enabled:
 * Revocation propagation (`mission_max_stale_seconds`) and Derivation Limits
 * are off too (#2018). The authorization-details type is
 * `mission_resource_access`, the only type the reference supports.
 *
 * The Approver authenticates for real: the approval surface logs Bob in as
 * an OpenID Connect relying party of the reference upstream provider, by
 * password and a one-time code, and records the `acr` and `auth_time` of the
 * ID Token it validates. No headless adjudication or service-token approval
 * input is configured. The resource server is `plain-rs` (no Mission code,
 * JWT validation only), which authorizes on the `scope` the AS projects.
 *
 * The file runs on a controlled clock (D1091).
 */
const controlledClock = await vi.hoisted(async () => {
  const { CONTROLLED_CLOCK_MS, installControlledClock } = await import("./controlled-clock.helper.js");
  return installControlledClock(CONTROLLED_CLOCK_MS);
});

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
  APPROVER_LOGIN_CALLBACK_PATH,
  ApprovalSessionStore,
  buildAuthorizationServer,
  type BuiltAs,
  type ProviderCapability,
} from "@mission/authorization-server";
import { IssuerKeys } from "@mission/core";
import { INTROSPECTION_PRINCIPALS, type IntrospectionPrincipal, TOPOLOGY, trustedKids } from "@mission/demo-data";
import { plainResourceServer } from "@mission/plain-rs";
import { decodeJwt, generateKeyPair } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { resolveMissionApproval, type UpstreamApprovalConsole } from "../src/approval-console.js";
import { type ApproverAccount, type ApproverIdp, startApproverIdp } from "../src/approver-idp.js";
import { type LifecycleConsoleCredentials, newLifecycleConsole, requestLifecycle } from "../src/lifecycle-client.js";
import { clientAssertionSigner, type CookieJar, type DpopKeys, dpopProofFor, jarClosures, tokenGrantRequest } from "../src/oauth-client.js";
import { CONTROLLED_CLOCK_MS } from "./controlled-clock.helper.js";

type Json = Record<string, unknown>;

/**
 * The minimal configuration's capability set: only the token-independent
 * revocation surface the baseline requires.
 */
const MINIMAL_CAPABILITIES: ReadonlySet<ProviderCapability> = new Set<ProviderCapability>(["lifecycle-revoke"]);

/** The plain RS audience: the shipped `scope_only` scope-projection mapping entry's key. */
const AUDIENCE = TOPOLOGY.resources.plainRs;
const REDIRECT_URI = "http://localhost:9999/cb";
const VERIFIER = "minimal-baseline-config-verifier-0123456789-0123456789";
const ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
const APPROVER = { sub: "idp-bob", username: "bob@acme.example" };
/** The Intent's requested expiry, a week after the controlled instant. */
const EXPIRES_AT = new Date(CONTROLLED_CLOCK_MS + 7 * 86_400_000).toISOString().replace(".000Z", "Z");
const READ = [{ type: "mission_resource_access", resource: AUDIENCE, actions: ["reports:report.read"] }];

let as: BuiltAs;
let asUrl: string;
let asServer: Server;
let rsUrl: string;
let rsServer: Server;
let idp: ApproverIdp;
let bob: UpstreamApprovalConsole;
let lifecycleConsole: LifecycleConsoleCredentials;

/** A listener on any free port, its handler attached once the party behind it exists. */
async function listening(): Promise<{ server: Server; origin: string }> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  return { server, origin: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

async function readJson(res: Response): Promise<Json> {
  const text = await res.text();
  try {
    return JSON.parse(text) as Json;
  } catch {
    return { body: text };
  }
}

/** The Submission envelope for the reports Intent, with any extra envelope or Intent members. */
function envelope(opts: { intent?: Json; evidence?: unknown } = {}): string {
  return JSON.stringify({
    intent: { goal: "Read the quarterly reports", target_resources: [AUDIENCE], expires_at: EXPIRES_AT, ...opts.intent },
    ...(opts.evidence !== undefined ? { evidence: opts.evidence } : {}),
  });
}

/** A Pushed Authorization Request as `ap-agent` (private_key_jwt). */
async function par(params: Record<string, string>): Promise<{ status: number; body: Json }> {
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER)),
  ).toString("base64url");
  const assertion = await clientAssertionSigner(asUrl, as.agentClientJwk);
  const res = await fetch(`${asUrl}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: AUDIENCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      ...params,
      client_assertion: await assertion(),
      client_assertion_type: ASSERTION_TYPE,
    }).toString(),
  });
  return { status: res.status, body: await readJson(res) };
}

/**
 * Resolve the approval as Bob, returning the code and the approval page the
 * console rendered to him before deciding, read from the wire unchanged.
 */
async function approveReadingPage(pending: { uid: string; jar: CookieJar }): Promise<{ code: string; page: string }> {
  const pageUrl = `${asUrl}/interaction/${pending.uid}`;
  const pages: string[] = [];
  const realFetch = globalThis.fetch;
  const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const res = await realFetch(input, init);
    if (String(input) === pageUrl && (init?.method ?? "GET") === "GET") pages.push(await res.clone().text());
    return res;
  });
  try {
    const code = (await resolveMissionApproval(asUrl, bob, pending, "approve", "alice")) as string;
    expect(pages).toHaveLength(1);
    return { code, page: pages[0] as string };
  } finally {
    spy.mockRestore();
  }
}

/** The front channel: redeem the `request_uri` and land on the approval interaction. */
async function startInteraction(requestUri: string): Promise<{ uid: string; jar: CookieJar }> {
  const jar: CookieJar = new Map();
  const { storeCookies } = jarClosures(jar);
  const res = await fetch(`${asUrl}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: requestUri })}`, {
    redirect: "manual",
  });
  storeCookies(res);
  const location = res.headers.get("location") ?? "";
  expect(location).toContain("/interaction/");
  return { uid: location.split("/interaction/")[1] as string, jar };
}

/** One call to `plain-rs`, DPoP-bound to the token's key. */
async function callRs(method: "GET" | "POST", accessToken: string, keys: DpopKeys) {
  const url = `${rsUrl}/api/reports`;
  const res = await fetch(url, {
    method,
    headers: {
      authorization: `DPoP ${accessToken}`,
      dpop: await dpopProofFor(keys, url, method, accessToken),
      ...(method === "POST" ? { "content-type": "application/json" } : {}),
    },
    ...(method === "POST" ? { body: JSON.stringify({ title: "Q3" }) } : {}),
  });
  return { status: res.status, body: await readJson(res), challenge: res.headers.get("www-authenticate") };
}

beforeAll(async () => {
  const asListener = await listening();
  asServer = asListener.server;
  asUrl = asListener.origin;
  idp = await startApproverIdp({ redirectUri: `${asUrl}${APPROVER_LOGIN_CALLBACK_PATH}`, accounts: [APPROVER] });
  bob = { upstream: { account: idp.accounts.get(APPROVER.username) as ApproverAccount, secondFactor: "code" } };
  const console_ = await newLifecycleConsole();
  lifecycleConsole = console_.credentials;
  as = await buildAuthorizationServer({
    issuer: asUrl,
    capabilities: MINIMAL_CAPABILITIES,
    approvalSessions: new ApprovalSessionStore(),
    approverLogin: {
      issuer: idp.issuer,
      clientId: idp.client.clientId,
      clientSecret: idp.client.clientSecret,
      idTokenSigningAlgs: ["ES256"],
      identities: [{ iss: idp.issuer, sub: APPROVER.sub, approver: "bob" }],
      acrValues: ["mfa"],
    },
    lifecycleClients: [console_.registration],
  });
  asServer.on("request", as.provider.callback());

  const rsListener = await listening();
  rsServer = rsListener.server;
  rsUrl = rsListener.origin;
  const keys = new IssuerKeys({
    jwksUri: `${asUrl}/jwks`,
    roles: { accessToken: { kids: trustedKids(TOPOLOGY.keys.asToken), algs: [TOPOLOGY.keys.asToken.alg] } },
  });
  const handle = plainResourceServer({
    issuer: asUrl,
    audience: AUDIENCE,
    keys: keys.resolver("accessToken") as never,
    baseUrl: rsUrl,
  });
  rsServer.on("request", (req, res) => void handle(req, res));
});

afterAll(async () => {
  for (const server of [asServer, rsServer]) {
    server?.closeAllConnections();
    server?.close();
  }
  await idp?.close();
  controlledClock.restore();
});

describe("the baseline flow on the minimal configuration, optional capabilities unclaimed (#2009 P5 step 4; @spec mission#conformance)", () => {
  // State carried from step to step, in order.
  let requestUri = "";
  let code = "";
  let missionId = "";
  let accessToken = "";
  let refreshToken = "";
  let dpopKeys: DpopKeys;
  let approvalPage = "";

  it("PAR accepts a Mission Intent in the Submission envelope with an authority proposal (@spec mission#submission-via-par)", async () => {
    const pushed = await par({ mission_intent: envelope(), authorization_details: JSON.stringify(READ) });
    expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
    requestUri = String(pushed.body.request_uri);
    expect(requestUri).toMatch(/^urn:ietf:params:oauth:request_uri:/);
  });

  it("an Approver authenticated at the upstream provider approves, and the AS commits one active Mission with the code (@spec mission#approval-event, mission#approval-authentication)", async () => {
    const before = as.kernel.allMissions().length;
    const pending = await startInteraction(requestUri);
    // Nothing exists before the decision.
    expect(as.kernel.allMissions()).toHaveLength(before);
    const logins = idp.logins.length;
    const approved = await approveReadingPage(pending);
    code = approved.code;
    approvalPage = approved.page;
    expect(code).toBeTruthy();
    // The approval surface logged Bob in at the provider by password and a one-time code.
    expect(idp.logins.slice(logins)).toEqual([expect.objectContaining({ sub: APPROVER.sub, acr: "mfa", factors: ["pwd", "otp"] })]);
    const created = as.kernel.allMissions().slice(before);
    expect(created).toHaveLength(1);
    const record = created[0] as unknown as Json;
    missionId = String(record.id);
    expect(record.state).toBe("active");
    expect(record.approval_basis).toMatchObject({ type: "direct" });
    expect(record.authority_set).toEqual(READ);
    expect(typeof record.intent_hash).toBe("string");
    expect(typeof record.authority_hash).toBe("string");
  });

  it("without Derivation Limits the approval page renders no derivation limit and the record establishes none (#2018; @spec derivation-limits#approval-rendering, derivation-limits#record-member)", () => {
    // The page Bob reviewed is the approval page: it shows the derived authority.
    expect(approvalPage).toContain("reports:report.read");
    expect(approvalPage).not.toMatch(/derivation limit/i);
    const record = as.kernel.get(missionId) as unknown as Json;
    expect(record.derivation_limit).toBeNull();
    expect(record.intent as Json).not.toHaveProperty("requested_derivation_limit");
  });

  it("the code redeems for a Mission-bound access token carrying exactly the approved authority (@spec mission#mission-bound-tokens, mission#mission-response-parameters)", async () => {
    dpopKeys = await generateKeyPair("ES256", { extractable: true });
    const redeemed = await tokenGrantRequest(asUrl, as.agentClientJwk, dpopKeys, {
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: VERIFIER,
      resource: AUDIENCE,
    });
    expect(redeemed.status, JSON.stringify(redeemed.body)).toBe(200);
    expect(redeemed.body.token_type).toBe("DPoP");
    expect(redeemed.body.mission_id).toBe(missionId);
    expect(typeof redeemed.body.mission_expires_at).toBe("string");
    expect(redeemed.body.authorization_details).toEqual(READ);
    accessToken = String(redeemed.body.access_token);
    refreshToken = String(redeemed.body.refresh_token ?? "");
    expect(refreshToken).not.toBe("");
    const claims = decodeJwt(accessToken);
    expect(claims.mission).toMatchObject({ id: missionId, issuer: asUrl });
    expect(claims.aud).toBe(AUDIENCE);
    expect(claims.scope).toBe("reports.read");
    expect(claims.cnf).toHaveProperty("jkt");
    expect(claims.act).toBeUndefined();
  });

  it("the resource server honors the token for the approved operation and refuses an operation outside it (@spec mission#rs-mission-unaware)", async () => {
    const read = await callRs("GET", accessToken, dpopKeys);
    expect(read.status, JSON.stringify(read.body)).toBe(200);
    const write = await callRs("POST", accessToken, dpopKeys);
    expect(write.status, JSON.stringify(write.body)).toBe(403);
    expect(write.challenge).toContain('error="insufficient_scope"');
  });

  it("refresh while the Mission is active issues a token bound to the same Mission (@spec mission#refresh-tokens)", async () => {
    const refreshed = await tokenGrantRequest(asUrl, as.agentClientJwk, dpopKeys, {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    });
    expect(refreshed.status, JSON.stringify(refreshed.body)).toBe(200);
    expect((decodeJwt(String(refreshed.body.access_token)).mission as Json).id).toBe(missionId);
    accessToken = String(refreshed.body.access_token);
    refreshToken = String(refreshed.body.refresh_token ?? refreshToken);
    expect((await callRs("GET", accessToken, dpopKeys)).status).toBe(200);
  });

  it("a party holding none of the Mission's tokens revokes it by mission_id through an authenticated means (@spec mission#revocation)", async () => {
    const revoke = await requestLifecycle(asUrl, lifecycleConsole, {
      mission_id: missionId,
      operation: "revoke",
      nonce: crypto.randomUUID(),
    });
    expect(revoke.status, revoke.text).toBe(200);
    const record = as.kernel.get(missionId);
    expect(record?.state).toBe("terminated");
    expect(record?.termination?.reason).toBe("revoked");
  });

  it("after revocation the refresh is refused invalid_grant and issues nothing; the issued access token is not recalled at a token-only resource server (@spec mission#refusing-a-derivation, mission#revocation)", async () => {
    const refused = await tokenGrantRequest(asUrl, as.agentClientJwk, dpopKeys, {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    });
    // The Lifecycle endpoint's revoke also destroys the Mission's OAuth grant,
    // so the refresh fails on its grant before the state gate runs.
    expect(refused.status, JSON.stringify(refused.body)).toBe(400);
    expect(refused.body.error).toBe("invalid_grant");
    expect(refused.body).not.toHaveProperty("access_token");
    // Token validity and Mission validity are distinct: a consumer enforcing
    // from the token alone can honor it until it expires.
    expect((await callRs("GET", accessToken, dpopKeys)).status).toBe(200);
  });
});

describe("what this configuration does not implement is refused as the binding states (#2009 P5 step 4)", () => {
  it("without Derivation Limits a requested_derivation_limit is refused invalid_request under Closed top levels, while the identical Intent without it is accepted (#2018; @spec mission#submission-via-par, derivation-limits#introduction)", async () => {
    const refused = await par({
      mission_intent: envelope({ intent: { requested_derivation_limit: 5 } }),
      authorization_details: JSON.stringify(READ),
    });
    expect(refused.status, JSON.stringify(refused.body)).toBe(400);
    expect(refused.body.error).toBe("invalid_request");
    expect(refused.body.error_description).toBe("unknown top-level member: requested_derivation_limit");
    expect(refused.body).not.toHaveProperty("request_uri");
    const accepted = await par({ mission_intent: envelope(), authorization_details: JSON.stringify(READ) });
    expect(accepted.status, JSON.stringify(accepted.body)).toBe(201);
  });

  it("without Introspection /introspect is not served (404) and neither introspection member is advertised (#2018; @spec mission#optional-capabilities, mission#introspection)", async () => {
    // The shipped plain-rs principal, which an introspecting plain-rs would use.
    const principal = INTROSPECTION_PRINCIPALS.find((p) => p.principal_id === "rs-plain") as IntrospectionPrincipal;
    const res = await fetch(`${asUrl}/introspect`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${Buffer.from(`${principal.principal_id}:${principal.secret}`).toString("base64")}`,
      },
      body: new URLSearchParams({ token: "x.y.z" }).toString(),
    });
    const body = await readJson(res);
    expect(res.status, JSON.stringify(body)).toBe(404);
    expect(body).not.toHaveProperty("active");
    const meta = (await (await fetch(`${asUrl}/.well-known/openid-configuration`)).json()) as Json;
    expect(meta).not.toHaveProperty("introspection_endpoint");
    expect(meta).not.toHaveProperty("introspection_endpoint_auth_methods_supported");
  });

  it("without Revocation propagation mission_max_stale_seconds is not advertised, and the only Mission Status metadata is what the Lifecycle revoke surface owns (#2018; @spec status#as-metadata, status#conformance)", async () => {
    const meta = (await (await fetch(`${asUrl}/.well-known/openid-configuration`)).json()) as Json;
    expect(meta).not.toHaveProperty("mission_max_stale_seconds");
    // Mission Lifecycle, revoke only, advertises its endpoint, its
    // authentication metadata and the response-signing algorithms.
    expect(meta.mission_lifecycle_endpoint_auth_methods_supported).toEqual(["private_key_jwt"]);
    expect(meta.mission_lifecycle_endpoint_auth_signing_alg_values_supported).toEqual(["ES256"]);
    expect(meta.mission_status_signing_alg_values_supported).toEqual(["ES256"]);
    const owned = new Set([
      "mission_bound_authorization_supported",
      "mission_lifecycle_endpoint",
      "mission_lifecycle_endpoint_auth_methods_supported",
      "mission_lifecycle_endpoint_auth_signing_alg_values_supported",
      "mission_status_signing_alg_values_supported",
    ]);
    // No other `mission_` member: the binding's own claim and the revoke surface's.
    expect(Object.keys(meta).filter((k) => k.startsWith("mission_") && !owned.has(k))).toEqual([]);
  });

  it("an evidence entry of a type the AS does not support is refused invalid_mission_intent_evidence, and one without a type invalid_request (@spec mission#intent-submission-evidence, mission#conformance-roles)", async () => {
    const unsupported = await par({
      mission_intent: envelope({ evidence: [{ type: "urn:example:intent-evidence:admission", assertion: "x" }] }),
      authorization_details: JSON.stringify(READ),
    });
    expect(unsupported.status, JSON.stringify(unsupported.body)).toBe(400);
    expect(unsupported.body.error).toBe("invalid_mission_intent_evidence");
    const untyped = await par({
      mission_intent: envelope({ evidence: [{ assertion: "x" }] }),
      authorization_details: JSON.stringify(READ),
    });
    expect(untyped.status, JSON.stringify(untyped.body)).toBe(400);
    expect(untyped.body.error).toBe("invalid_request");
  });

  it("an authority proposal of an unsupported authorization_details type is refused invalid_authorization_details (@spec mission#proposal-validation)", async () => {
    const pushed = await par({
      mission_intent: envelope(),
      authorization_details: JSON.stringify([{ type: "urn:example:unsupported-type", resource: AUDIENCE }]),
    });
    expect(pushed.status, JSON.stringify(pushed.body)).toBe(400);
    expect(pushed.body.error).toBe("invalid_authorization_details");
  });

  it("without Self-Exchange or Delegation the Token Exchange grant is not supported: a no-actor exchange is refused unsupported_grant_type (@spec mission#self-exchange)", async () => {
    // A fresh Mission-bound token, so the refusal is not the revoked Mission's.
    const pushed = await par({ mission_intent: envelope(), authorization_details: JSON.stringify(READ) });
    expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
    const pending = await startInteraction(String(pushed.body.request_uri));
    const issuedCode = (await resolveMissionApproval(asUrl, bob, pending, "approve", "alice")) as string;
    const keys = await generateKeyPair("ES256", { extractable: true });
    const redeemed = await tokenGrantRequest(asUrl, as.agentClientJwk, keys, {
      grant_type: "authorization_code",
      code: issuedCode,
      redirect_uri: REDIRECT_URI,
      code_verifier: VERIFIER,
      resource: AUDIENCE,
    });
    expect(redeemed.status, JSON.stringify(redeemed.body)).toBe(200);
    const exchange = await tokenGrantRequest(asUrl, as.agentClientJwk, keys, {
      grant_type: TOKEN_EXCHANGE,
      subject_token: String(redeemed.body.access_token),
      subject_token_type: ACCESS_TOKEN_TYPE,
      resource: AUDIENCE,
    });
    expect(exchange.status, JSON.stringify(exchange.body)).toBe(400);
    expect(exchange.body.error).toBe("unsupported_grant_type");
  });

  it("the metadata claims Mission-bound authorization and advertises no optional or companion capability beyond the revocation surface (@spec mission#discovery, mission#claiming-conformance)", async () => {
    const meta = (await (await fetch(`${asUrl}/.well-known/openid-configuration`)).json()) as Json;
    expect(meta.mission_bound_authorization_supported).toBe(true);
    // oidc-provider always lists `implicit`; its token endpoint refuses it.
    expect(meta.grant_types_supported).toEqual(["implicit", "authorization_code", "refresh_token"]);
    expect(meta.authorization_details_types_supported).toEqual(["mission_resource_access"]);
    for (const member of [
      "mission_child_delegation_supported",
      "mission_device_authorization_supported",
      "identity_continuation_supported",
      "delegated_refresh_token_profile_supported",
      "deferred_token_response_supported",
      "mission_status_endpoint",
      "mission_join_assertion_endpoint",
      "transaction_authorization_endpoint",
      "device_authorization_endpoint",
      "revocation_endpoint",
      "userinfo_endpoint",
    ]) {
      expect(meta, member).not.toHaveProperty(member);
    }
    // The one enabled surface: the token-independent revocation means.
    expect(meta.mission_lifecycle_endpoint).toBe(`${asUrl}/mission/lifecycle`);
  });
});
