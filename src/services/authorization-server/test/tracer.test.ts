/**
 * The M1 tracer slice (plan § 5): PAR intent -> approval -> mission-bound
 * DPoP token -> minimal PDP evaluation -> get_invoice through an MCP
 * skeleton, plus introspection, signed Status, and lifecycle gating on the
 * wire. The PDP and MCP pieces here are throwaway-grade by design.
 */

import { TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";

import { createServer, type Server } from "node:http";
import { CANONICAL_RESOURCE, DEV_SERVICE_TOKEN, INVOICES } from "@mission/demo-data";
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
import { buildAuthorizationServer, type AuthorityEntry, type BuiltAs } from "../src/index.js";

const PORT = 14400;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";

let as: BuiltAs;
let asServer: Server;
let clientKey: CryptoKey;
let dpopKeys: { privateKey: CryptoKey; publicKey: CryptoKey };
let dpopJkt: string;
const cookies = new Map<string, string>();

function cookieHeader(): string {
  return [...cookies.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}
function storeCookies(res: Response): void {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    cookies.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
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

async function dpopProof(htu: string, htm: string, extra: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({ htu, htm, ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(dpopKeys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(dpopKeys.privateKey);
}

async function tokenRequest(params: Record<string, string>): Promise<Response> {
  const htu = `${ISSUER}/token`;
  let res = await fetch(htu, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      dpop: await dpopProof(htu, "POST"),
    },
    body: new URLSearchParams({
      ...params,
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) {
    res = await fetch(htu, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        dpop: await dpopProof(htu, "POST", { nonce }),
      },
      body: new URLSearchParams({
        ...params,
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  }
  return res;
}

/** Throwaway PDP stub: contextual authority check over the mission's set. */
function pdpEvaluate(action: string, resource: string, authority: AuthorityEntry[]): boolean {
  return authority.some((e) => e.resource === resource && e.actions.includes(action));
}

/** Throwaway MCP skeleton: token validation + PDP stub + one tool. */
function startMcpSkeleton(port: number): Server {
  const jwks = createRemoteJWKSet(new URL(`${ISSUER}/jwks`));
  const server = createServer(async (req, res) => {
    try {
      const auth = req.headers.authorization ?? "";
      if (!auth.startsWith("DPoP ")) throw new Error("expected DPoP scheme");
      const { payload } = await jwtVerify(auth.slice(5), jwks, {
        issuer: ISSUER,
        audience: CANONICAL_RESOURCE,
      });
      const mission = payload.mission as { id: string } | undefined;
      if (!mission) throw new Error("missing mission claim");
      const record = as.kernel.get(mission.id);
      if (!record || record.state !== "active") throw new Error("mission not active");
      if (!pdpEvaluate("payments:invoice.read", CANONICAL_RESOURCE, record.authority_set)) {
        throw new Error("out of authority");
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(INVOICES[0]));
    } catch (e) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: (e as Error).message }));
    }
  });
  server.listen(port);
  return server;
}

let mcpServer: Server;
let accessToken = "";
let refreshToken = "";
let missionId = "";

beforeAll(async () => {
  as = await buildAuthorizationServer({ issuer: ISSUER, allowHeadlessAdjudication: true, serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS });
  asServer = as.provider.listen(PORT);
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  dpopKeys = await generateKeyPair("ES256", { extractable: true });
  dpopJkt = await calculateJwkThumbprint(await exportJWK(dpopKeys.publicKey));
  mcpServer = startMcpSkeleton(14431);
});

afterAll(() => {
  asServer?.close();
  mcpServer?.close();
});

describe("M1 tracer slice", () => {
  const verifier = "tracer-verifier-0123456789-0123456789-0123456789";
  let requestUri = "";
  let code = "";

  it("PAR accepts the mission_intent and returns a request_uri", async () => {
    const challenge = Buffer.from(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
    ).toString("base64url");
    // @spec mission#submission-via-par — the wire value is the Submission envelope.
    const intent = JSON.stringify({
      intent: {
        goal: "Pay Acme invoices for Q3",
        target_resources: [CANONICAL_RESOURCE],
        expires_at: "2027-01-01T00:00:00Z",
      },
    });
    const authorizationDetails = JSON.stringify([
      {
        type: "mission_resource_access",
        resource: CANONICAL_RESOURCE,
        actions: ["payments:invoice.list", "payments:invoice.read", "payments:payment.schedule"],
      },
    ]);
    const res = await fetch(`${ISSUER}/request`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: "ap-agent",
        response_type: "code",
        redirect_uri: REDIRECT_URI,
        scope: "payments",
        resource: CANONICAL_RESOURCE,
        code_challenge: challenge,
        code_challenge_method: "S256",
        login_hint: "alice",
        mission_intent: intent,
        authorization_details: authorizationDetails,
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
    const body = (await res.json()) as { request_uri?: string };
    expect(res.status).toBe(201);
    requestUri = body.request_uri as string;
    expect(requestUri).toMatch(/^urn:/);
  });

  it("authorization redirects to the interaction; headless approval by Bob issues a code", async () => {
    const authUrl = `${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: requestUri })}`;
    let res = await fetch(authUrl, { redirect: "manual" });
    storeCookies(res);
    let location = res.headers.get("location") as string;
    expect(location).toContain("/interaction/");
    const uid = location.split("/interaction/")[1] as string;

    res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
      method: "POST",
      redirect: "manual",
      headers: { ...trustedApprovalHeaders(), "content-type": "application/json", cookie: cookieHeader() },
      body: JSON.stringify({ decision: "approve" }),
    });
    storeCookies(res);
    location = res.headers.get("location") as string;

    while (location?.startsWith(ISSUER)) {
      res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader() } });
      storeCookies(res);
      location = res.headers.get("location") as string;
    }
    expect(location).toContain(`${REDIRECT_URI}?`);
    code = new URL(location).searchParams.get("code") as string;
    expect(code).toBeTruthy();
  });

  it("token exchange yields a DPoP-bound JWT AT with the mission claim and RAR echo", async () => {
    const res = await tokenRequest({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
      resource: CANONICAL_RESOURCE,
    });
    const body = (await res.json()) as Record<string, unknown>;
    expect(res.status, JSON.stringify(body)).toBe(200);
    accessToken = body.access_token as string;
    refreshToken = body.refresh_token as string;
    expect(body.token_type).toBe("DPoP");
    expect(refreshToken).toBeTruthy();
    expect(body.authorization_details).toBeDefined();

    const claims = JSON.parse(
      Buffer.from((accessToken.split(".")[1] as string), "base64url").toString(),
    ) as Record<string, never>;
    const mission = claims.mission as { id: string; issuer: string; authority_hash?: string };
    expect(mission.issuer).toBe(ISSUER);
    // @spec mission#the-mission-claim (#702) — the baseline claim is exactly
    // {id, issuer}; authority_hash is not carried here (no companion profile
    // is in play on this plain authorization_code exchange).
    expect(mission.authority_hash).toBeUndefined();
    expect((claims.cnf as { jkt: string }).jkt).toBe(dpopJkt);
    expect(claims.aud).toBe(CANONICAL_RESOURCE);
    missionId = mission.id;
    const record = as.kernel.get(missionId);
    expect(record?.approver.sub).toBe("bob");
    expect(record?.subject.sub).toBe("alice");
  });

  it("the MCP skeleton serves get_invoice after PDP-stub evaluation", async () => {
    const res = await fetch("http://localhost:14431/tools/get_invoice", {
      headers: { authorization: `DPoP ${accessToken}` },
    });
    const body = (await res.json()) as { id?: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(body.id).toBe("inv-1");
  });

  it("the adapter introspection route reports the mission member", async () => {
    const res = await fetch(`${ISSUER}/introspect`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${Buffer.from("rs-payments:dev-introspection-rs-payments").toString("base64")}`,
      },
      body: new URLSearchParams({ token: accessToken }).toString(),
    });
    const body = (await res.json()) as { active: boolean; mission?: { state: string } };
    expect(body.active).toBe(true);
    expect(body.mission?.state).toBe("active");
  });

  it("the signed Status endpoint returns a verifiable mission-status-response+jwt", async () => {
    const res = await fetch(
      `${ISSUER}/missions/${missionId}/status?audience=${encodeURIComponent(CANONICAL_RESOURCE)}&nonce=n-1`,
      { headers: { "x-service-token": DEV_SERVICE_TOKEN } },
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/mission-status-response+jwt");
    const jws = await res.text();
    const jwks = createRemoteJWKSet(new URL(`${ISSUER}/jwks`));
    const { payload, protectedHeader } = await jwtVerify(jws, jwks, {
      issuer: ISSUER,
      audience: CANONICAL_RESOURCE,
    });
    expect(protectedHeader.typ).toBe("mission-status-response+jwt");
    const mission = payload.mission as { state: string; fresh_until: string };
    expect(mission.state).toBe("active");
    expect(payload.nonce).toBe("n-1");
  });

  it("suspend gates refresh with invalid_grant; resume restores issuance", async () => {
    const lifecycle = (operation: string) =>
      fetch(`${ISSUER}/missions/${missionId}/lifecycle`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
        body: JSON.stringify({ operation }),
      });
    expect((await (await lifecycle("suspend")).json() as { state: string }).state).toBe("suspended");

    let res = await tokenRequest({ grant_type: "refresh_token", refresh_token: refreshToken });
    let body = (await res.json()) as {
      error?: string;
      mission_error?: string;
      refresh_token?: string;
      access_token?: string;
    };
    expect(res.status).toBe(400);
    expect(body.error).toBe("invalid_grant");
    // @spec mission#error-mapping — a suspended Mission is a companion
    // (Mission Status) state with no core `mission_error` value of its own;
    // this deployment omits the diagnostic rather than misreport it as
    // `mission_revoked` (@see gateErrorToMissionError).
    expect(body.mission_error).toBeUndefined();

    expect((await (await lifecycle("resume")).json() as { state: string }).state).toBe("active");
    res = await tokenRequest({ grant_type: "refresh_token", refresh_token: refreshToken });
    body = (await res.json()) as { error?: string; refresh_token?: string; access_token?: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    refreshToken = body.refresh_token ?? refreshToken;
    accessToken = body.access_token as string;
  });

  it("revocation destroys the grant: refresh fails and introspection reports the state", async () => {
    const res1 = await fetch(`${ISSUER}/missions/${missionId}/lifecycle`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
      body: JSON.stringify({ operation: "revoke" }),
    });
    expect(((await res1.json()) as { state: string }).state).toBe("revoked");

    const res2 = await tokenRequest({ grant_type: "refresh_token", refresh_token: refreshToken });
    expect(res2.status).toBe(400);
    // This demo deployment satisfies "revocation stops refresh" by destroying
    // the underlying OAuth Grant directly on a terminal transition (the
    // lifecycle route above), so refresh fails via oidc-provider's own grant
    // lookup, never reaching gateDerivation/MissionGrantError: no
    // `mission_error` is expected on THIS path (@spec mission#issuance-gating
    // is satisfied either way; @see mission#error-mapping.mission-error-wire-carrier
    // for the path that does carry it, exercised where the Mission's own
    // `derivation_limit` gates a still-valid grant).
    const res2Body = (await res2.json()) as { error?: string; mission_error?: string };
    expect(res2Body.error).toBe("invalid_grant");

    const res3 = await fetch(`${ISSUER}/introspect`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${Buffer.from("rs-payments:dev-introspection-rs-payments").toString("base64")}`,
      },
      body: new URLSearchParams({ token: accessToken }).toString(),
    });
    const body = (await res3.json()) as { mission?: { state: string } };
    expect(body.mission?.state).toBe("revoked");
  });

  it("AS metadata advertises mission_bound_authorization_supported and the adapter introspection endpoint", async () => {
    const meta = (await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json()) as Record<
      string,
      unknown
    >;
    expect(meta.mission_bound_authorization_supported).toBe(true);
    expect(meta.introspection_endpoint).toBe(`${ISSUER}/introspect`);
    expect(meta.pushed_authorization_request_endpoint).toBe(`${ISSUER}/request`);
  });

  it("publishes authorization_details_types_metadata_endpoint (@spec mission#other-types, I-D.draft-zehavi-oauth-rar-metadata)", async () => {
    const meta = (await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json()) as Record<
      string,
      unknown
    >;
    expect(meta.authorization_details_types_metadata_endpoint).toBe(`${ISSUER}/authorization-details-types`);
    // @spec mission#other-types: the metadata endpoint's key set IS
    // authorization_details_types_supported -- verified empirically (oidc-provider
    // publishes the latter from the configured richAuthorizationRequests `types`),
    // not merely assumed.
    expect(meta.authorization_details_types_supported).toEqual(["mission_resource_access"]);

    const res = await fetch(`${ISSUER}/authorization-details-types`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/json");
    const body = (await res.json()) as Record<
      string,
      { schema?: Record<string, unknown>; schema_uri?: string; version?: string }
    >;
    expect(Object.keys(body)).toEqual(meta.authorization_details_types_supported);
    const entry = body.mission_resource_access;
    expect(entry?.schema).toBeDefined();
    expect(entry?.schema_uri).toBeUndefined(); // mutually exclusive with `schema`
    expect((entry?.schema as Record<string, unknown>)?.properties).toMatchObject({
      type: { const: "mission_resource_access" },
    });
  });
});

/**
 * @spec mission#issuance-gating, mission#error-mapping — a positive wire
 * proof that `mission_error` reaches the client with a NON-undefined value
 * (the suspend/revoke scenarios above only prove the splice mechanism fires
 * without a value, since suspended has no mapped value and revoked destroys
 * the grant before gateDerivation ever runs). A Mission whose own
 * `requested_derivation_limit` is 1 exhausts its cap on the SECOND
 * derivation with no lifecycle transition at all, so the grant stays valid
 * and nothing short-circuits before MissionGrantError/grant.error runs.
 */
describe("mission_error wire carriage: derivations_exhausted (@spec mission#error-mapping)", () => {
  it("a Mission capped at requested_derivation_limit 1 refuses its second derivation with invalid_grant + mission_error=derivations_exhausted", async () => {
    const verifier = "cap-verifier-0123456789-0123456789-0123456789";
    const challenge = Buffer.from(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
    ).toString("base64url");
    const intent = JSON.stringify({
      intent: {
        goal: "One-shot invoice read",
        target_resources: [CANONICAL_RESOURCE],
        expires_at: "2027-01-01T00:00:00Z",
        requested_derivation_limit: 1,
      },
    });
    const authorizationDetails = JSON.stringify([
      { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] },
    ]);
    const parRes = await fetch(`${ISSUER}/request`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: "ap-agent",
        response_type: "code",
        redirect_uri: REDIRECT_URI,
        scope: "payments",
        resource: CANONICAL_RESOURCE,
        code_challenge: challenge,
        code_challenge_method: "S256",
        login_hint: "alice",
        mission_intent: intent,
        authorization_details: authorizationDetails,
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
    const requestUri = ((await parRes.json()) as { request_uri?: string }).request_uri as string;
    expect(requestUri).toMatch(/^urn:/);

    let res = await fetch(
      `${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: requestUri })}`,
      { redirect: "manual" },
    );
    storeCookies(res);
    let location = res.headers.get("location") as string;
    const uid = location.split("/interaction/")[1] as string;
    res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
      method: "POST",
      redirect: "manual",
      headers: { ...trustedApprovalHeaders(), "content-type": "application/json", cookie: cookieHeader() },
      body: JSON.stringify({ decision: "approve" }),
    });
    storeCookies(res);
    location = res.headers.get("location") as string;
    while (location?.startsWith(ISSUER)) {
      res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader() } });
      storeCookies(res);
      location = res.headers.get("location") as string;
    }
    const code = new URL(location).searchParams.get("code") as string;

    // Derivation #1 (the code exchange itself): succeeds, and exhausts the cap.
    const first = await tokenRequest({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
      resource: CANONICAL_RESOURCE,
    });
    const firstBody = (await first.json()) as { access_token?: string; refresh_token?: string; error?: string };
    expect(first.status, JSON.stringify(firstBody)).toBe(200);

    // Derivation #2 (a refresh): refused, grant still valid, no lifecycle
    // transition anywhere in this test -- the only refusal path available is
    // gateDerivation -> MissionGrantError -> the grant.error splice.
    const second = await tokenRequest({
      grant_type: "refresh_token",
      refresh_token: firstBody.refresh_token as string,
    });
    const secondBody = (await second.json()) as { error?: string; mission_error?: string };
    expect(second.status, JSON.stringify(secondBody)).toBe(400);
    expect(secondBody.error).toBe("invalid_grant");
    expect(secondBody.mission_error).toBe("derivations_exhausted");
  });
});
