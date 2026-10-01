/**
 * The issuance-only launcher's capability set (#873, PR #891 review). The
 * launcher's assembly (`startIssuanceOnly`) enables the issuance profile plus
 * the lifecycle endpoint's `revoke`, and nothing else. Each test drives one
 * excluded path against that assembly over real HTTP and asserts the exact
 * standard refusal, so a path that silently succeeded, or refused for an
 * unrelated reason, fails. The last group covers the capability gates the
 * launcher's own wiring already shadows, on an assembly that does wire them,
 * and the default assembly, which must stay the full provider.
 */
import { randomUUID } from "node:crypto";
import type { Server } from "node:http";
import {
  buildAuthorizationServer,
  type BuiltAs,
  type ProviderCapability,
  STATUS_LIST_ID,
} from "@mission/authorization-server";
import {
  type CryptoKey,
  decodeJwt,
  exportJWK,
  generateKeyPair,
  importJWK,
  type JWK,
  SignJWT,
} from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  type IssuanceOnlyDeployment,
  ISSUANCE_ONLY_CAPABILITIES,
  PLAIN_RS_AUDIENCE,
  startIssuanceOnly,
} from "../src/issuance-only.js";

type Json = Record<string, unknown>;
type Keys = { publicJwk: JWK; privateKey: CryptoKey };

const TE = "urn:ietf:params:oauth:grant-type:token-exchange";
const AT_TYPE = "urn:ietf:params:oauth:token-type:access_token";
const JWT_TYPE = "urn:ietf:params:oauth:token-type:jwt";
const ID_JAG_TYPE = "urn:ietf:params:oauth:token-type:id-jag";
const ICA_TYPE = "urn:ietf:params:oauth:token-type:identity-continuation";
const CHAIN_TYPE = "urn:ietf:params:oauth:token-type:mission-delegation-chain";
const JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const DEFERRED = "urn:ietf:params:oauth:grant-type:deferred";
const DISPATCH = "urn:ietf:params:oauth:grant-type:mission-dispatch";
const ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const REDIRECT_URI = "http://localhost:9999/cb";
const VERIFIER = "issuance-only-capabilities-verifier-0123456789-0123456789";
const READ = [{ type: "mission_resource_access", resource: PLAIN_RS_AUDIENCE, actions: ["reports:report.read"] }];
/**
 * Metadata members no assembly advertises (#897): no capability controls them,
 * because the provider serves neither surface. The token endpoint parses no
 * `mission_attenuation_root`, and no route serves the in-process catalog.
 */
const WITHDRAWN_MEMBERS = ["mission_attenuation_supported", "service_catalog_endpoint"];

const AS_PORT = 14664;
const RS_PORT = 14665;

let deployment: IssuanceOnlyDeployment;
let asUrl: string;
/** An active Mission's DPoP-bound access token, issued through the launcher. */
let base: { accessToken: string; missionId: string; keys: Keys };

async function newKeys(): Promise<Keys> {
  const k = await generateKeyPair("ES256", { extractable: true });
  return { publicJwk: await exportJWK(k.publicKey), privateKey: k.privateKey };
}

function proof(keys: Keys, htm: string, htu: string, extra: Json = {}): Promise<string> {
  return new SignJWT({ htm, htu, ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: keys.publicJwk })
    .setIssuedAt()
    .setJti(randomUUID())
    .sign(keys.privateKey);
}

async function clientAssertion(issuer: string, clientId: string, kid: string, jwk: Json): Promise<string> {
  const key = (await importJWK(jwk as JWK, "ES256")) as CryptoKey;
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid })
    .setIssuer(clientId)
    .setSubject(clientId)
    .setAudience(issuer)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(randomUUID())
    .sign(key);
}

const agentAssertion = (issuer: string, as: BuiltAs) =>
  clientAssertion(issuer, "ap-agent", "ap-agent-auth", as.agentClientJwk as Json);

async function readJson(res: Response): Promise<Json> {
  const text = await res.text();
  try {
    return JSON.parse(text) as Json;
  } catch {
    return { body: text };
  }
}

/** A token request as `ap-agent` (private_key_jwt), with a DPoP proof. */
async function token(
  issuer: string,
  as: BuiltAs,
  params: Record<string, string>,
  keys?: Keys,
): Promise<{ status: number; body: Json }> {
  const htu = `${issuer}/token`;
  const send = async (extra: Json = {}) =>
    fetch(htu, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        ...(keys ? { dpop: await proof(keys, "POST", htu, extra) } : {}),
      },
      body: new URLSearchParams({
        ...params,
        client_assertion: await agentAssertion(issuer, as),
        client_assertion_type: ASSERTION_TYPE,
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return { status: res.status, body: await readJson(res) };
}

function parBody(extra: Record<string, string> = {}): Record<string, string> {
  return {
    client_id: "ap-agent",
    response_type: "code",
    redirect_uri: REDIRECT_URI,
    resource: PLAIN_RS_AUDIENCE,
    code_challenge: VERIFIER_CHALLENGE,
    code_challenge_method: "S256",
    login_hint: "alice",
    mission_intent: JSON.stringify({
      intent: {
        goal: "Read the quarterly reports",
        target_resources: [PLAIN_RS_AUDIENCE],
        expires_at: new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
      },
    }),
    authorization_details: JSON.stringify(READ),
    ...extra,
  };
}

let VERIFIER_CHALLENGE = "";

async function par(extra: Record<string, string> = {}): Promise<{ status: number; body: Json }> {
  const res = await fetch(`${asUrl}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      ...parBody(extra),
      client_assertion: await agentAssertion(asUrl, deployment.as),
      client_assertion_type: ASSERTION_TYPE,
    }).toString(),
  });
  return { status: res.status, body: await readJson(res) };
}

/** PAR, approval by the approver console, and the code exchange: an active Mission. */
async function issueBase(): Promise<{ accessToken: string; missionId: string; keys: Keys }> {
  const pushed = await par();
  expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
  const cookies = new Map<string, string>();
  const keep = (res: Response) => {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = (pair as string).indexOf("=");
      cookies.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
    }
  };
  const cookie = () => [...cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  let res = await fetch(
    `${asUrl}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: String(pushed.body.request_uri) })}`,
    { redirect: "manual" },
  );
  keep(res);
  const uid = (res.headers.get("location") ?? "").split("/interaction/")[1] ?? "";
  res = await fetch(`${asUrl}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: {
      "content-type": "application/json",
      cookie: cookie(),
      "x-service-token": deployment.credentials.approverServiceToken,
    },
    body: JSON.stringify({ decision: "approve" }),
  });
  keep(res);
  let location = res.headers.get("location") ?? "";
  while (location.startsWith(asUrl)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookie() } });
    keep(res);
    location = res.headers.get("location") ?? "";
  }
  const code = new URL(location).searchParams.get("code") ?? "";
  const keys = await newKeys();
  const exchanged = await token(
    asUrl,
    deployment.as,
    { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: VERIFIER, resource: PLAIN_RS_AUDIENCE },
    keys,
  );
  expect(exchanged.status, JSON.stringify(exchanged.body)).toBe(200);
  const accessToken = String(exchanged.body.access_token);
  const missionId = (decodeJwt(accessToken).mission as { id: string }).id;
  return { accessToken, missionId, keys };
}

async function lifecycle(missionId: string, body: Json): Promise<{ status: number; body: Json }> {
  const res = await fetch(`${asUrl}/missions/${missionId}/lifecycle`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-service-token": deployment.credentials.lifecycleServiceToken },
    body: JSON.stringify({ nonce: randomUUID(), ...body }),
  });
  return { status: res.status, body: await readJson(res) };
}

/** A route nothing serves: Koa's plain-text 404, not a JSON refusal from a handler. */
function expectUnservedRoute(r: { status: number; body: Json }) {
  expect(r.status, JSON.stringify(r.body)).toBe(404);
  expect(r.body.body).toBe("Not Found");
}

function expectUnsupportedGrant(r: { status: number; body: Json }) {
  expect(r.status, JSON.stringify(r.body)).toBe(400);
  expect(r.body.error).toBe("unsupported_grant_type");
}

function expectOperationDisabled(r: { status: number; body: Json }, operation: string) {
  expect(r.status, JSON.stringify(r.body)).toBe(400);
  expect(r.body.error).toBe("invalid_request");
  expect(r.body.error_description).toBe(`operation ${operation} is not enabled on this deployment`);
}

beforeAll(async () => {
  VERIFIER_CHALLENGE = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER)),
  ).toString("base64url");
  deployment = await startIssuanceOnly({ introspection: false, asPort: AS_PORT, rsPort: RS_PORT });
  asUrl = deployment.credentials.asUrl;
  base = await issueBase();
});

afterAll(async () => {
  await deployment?.close();
});

describe("the issuance-only launcher refuses every excluded path (#873)", () => {
  it("async-delegation token exchange (request_refresh_token) is refused unsupported_grant_type", async () => {
    const r = await token(
      asUrl,
      deployment.as,
      {
        grant_type: TE,
        request_refresh_token: "true",
        subject_token: base.accessToken,
        subject_token_type: AT_TYPE,
        resource: PLAIN_RS_AUDIENCE,
        creation_request_id: randomUUID(),
        authorization_details: JSON.stringify(READ),
      },
      await newKeys(),
    );
    expectUnsupportedGrant(r);
  });

  it("child creation token exchange (requested_token_type jwt) is refused unsupported_grant_type", async () => {
    const r = await token(
      asUrl,
      deployment.as,
      {
        grant_type: TE,
        subject_token: base.accessToken,
        subject_token_type: AT_TYPE,
        requested_token_type: JWT_TYPE,
        child_actor: "subagent-invoice-extractor",
        creation_request_id: randomUUID(),
        authorization_details: JSON.stringify(READ),
      },
      base.keys,
    );
    expectUnsupportedGrant(r);
  });

  it("the child jwt-bearer grant is refused unsupported_grant_type, and the child client is not registered", async () => {
    const r = await token(asUrl, deployment.as, { grant_type: JWT_BEARER, assertion: "x.y.z" });
    expectUnsupportedGrant(r);
    const child = await fetch(`${asUrl}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: JWT_BEARER,
        assertion: "x.y.z",
        client_assertion: await clientAssertion(
          asUrl,
          "subagent-invoice-extractor",
          "subagent-invoice-extractor-auth",
          deployment.as.childClientJwk as Json,
        ),
        client_assertion_type: ASSERTION_TYPE,
      }).toString(),
    });
    const body = await readJson(child);
    expect(child.status, JSON.stringify(body)).toBe(401);
    expect(body.error).toBe("invalid_client");
  });

  it("cross-domain continuation (ICA subject token to an ID-JAG) is refused unsupported_grant_type", async () => {
    const r = await token(asUrl, deployment.as, {
      grant_type: TE,
      subject_token: "x.y.z",
      subject_token_type: ICA_TYPE,
      requested_token_type: ID_JAG_TYPE,
      audience: "http://localhost:4405",
      resource: "http://localhost:4406/mcp",
    });
    expectUnsupportedGrant(r);
  });

  it("the cross-organization chain exchange is refused unsupported_grant_type", async () => {
    const r = await token(asUrl, deployment.as, {
      grant_type: TE,
      subject_token: "x.y.z",
      subject_token_type: CHAIN_TYPE,
      requested_token_type: AT_TYPE,
      resource: PLAIN_RS_AUDIENCE,
    });
    expectUnsupportedGrant(r);
  });

  it("the expansion exchange (requested_token_type access_token) is refused unsupported_grant_type", async () => {
    const r = await token(
      asUrl,
      deployment.as,
      {
        grant_type: TE,
        subject_token: base.accessToken,
        subject_token_type: AT_TYPE,
        requested_token_type: AT_TYPE,
        creation_request_id: randomUUID(),
        mission_intent: JSON.stringify({
          intent: {
            goal: "Read and write the quarterly reports",
            target_resources: [PLAIN_RS_AUDIENCE],
            expires_at: new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
          },
        }),
      },
      base.keys,
    );
    expectUnsupportedGrant(r);
  });

  it("the AROP deferred grant is refused unsupported_grant_type", async () => {
    const r = await token(asUrl, deployment.as, { grant_type: DEFERRED, deferral_code: "x" });
    expectUnsupportedGrant(r);
  });

  it("template dispatch is refused unsupported_grant_type, and the template admin routes answer 501", async () => {
    const r = await token(asUrl, deployment.as, { grant_type: DISPATCH, template_id: "x" }, await newKeys());
    expectUnsupportedGrant(r);
    for (const path of ["/templates", "/templates/x/lifecycle"]) {
      const res = await fetch(`${asUrl}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-service-token": deployment.credentials.lifecycleServiceToken },
        body: JSON.stringify({}),
      });
      expect(res.status, path).toBe(501);
      expect((await readJson(res)).error).toBe("temporarily_unavailable");
    }
  });

  it("the lifecycle contain operation is refused invalid_request and the Mission stays active", async () => {
    const r = await lifecycle(base.missionId, {
      operation: "contain",
      event: { type: "credential_compromise", source: "test", observed_at: new Date().toISOString(), event_id: randomUUID() },
      remove: [{ resource: PLAIN_RS_AUDIENCE, actions: ["reports:report.read"] }],
    });
    expectOperationDisabled(r, "contain");
    expect(deployment.as.kernel.get(base.missionId)?.state).toBe("active");
    expect(deployment.as.kernel.get(base.missionId)?.version).toBe(1);
  });

  it("protected-event ingestion answers 501 temporarily_unavailable", async () => {
    const res = await fetch(`${asUrl}/missions/${base.missionId}/protected-events`, {
      method: "POST",
      headers: { "content-type": "application/protected-event+jwt" },
      body: "x.y.z",
    });
    expect(res.status).toBe(501);
    expect((await readJson(res)).error).toBe("temporarily_unavailable");
  });

  it("the lifecycle discharge operation is refused invalid_request", async () => {
    const r = await lifecycle(base.missionId, {
      operation: "discharge",
      entry: "e1",
      condition: "c1",
      event_id: randomUUID(),
    });
    expectOperationDisabled(r, "discharge");
  });

  it("the lifecycle suspend, resume and complete operations are refused invalid_request and the Mission stays active", async () => {
    for (const operation of ["suspend", "resume", "complete"]) {
      expectOperationDisabled(await lifecycle(base.missionId, { operation }), operation);
    }
    expect(deployment.as.kernel.get(base.missionId)?.state).toBe("active");
  });

  it("the Mission Status operation is not served (404)", async () => {
    const res = await fetch(`${asUrl}/missions/${base.missionId}/status`, {
      headers: { "x-service-token": deployment.credentials.lifecycleServiceToken },
    });
    expectUnservedRoute({ status: res.status, body: await readJson(res) });
  });

  it("the Mission Status List is not served (404 not_found)", async () => {
    const res = await fetch(`${asUrl}/statuslist/${STATUS_LIST_ID}`);
    expect(res.status).toBe(404);
    expect((await readJson(res)).error).toBe("not_found");
  });

  it("transaction authorization answers 501 temporarily_unavailable", async () => {
    const res = await fetch(`${asUrl}/transaction`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "",
    });
    expect(res.status).toBe(501);
    expect((await readJson(res)).error).toBe("temporarily_unavailable");
  });

  it("the dev ordinary-token route answers 501 temporarily_unavailable", async () => {
    const res = await fetch(`${asUrl}/dev/ordinary-token`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-service-token": deployment.credentials.lifecycleServiceToken },
      body: JSON.stringify({ sub: "alice", scope: "reports.read" }),
    });
    expect(res.status).toBe(501);
    expect((await readJson(res)).error).toBe("temporarily_unavailable");
  });

  it("OIDC is off: openid is refused invalid_scope at PAR, and userinfo and RP-initiated logout are not served", async () => {
    const pushed = await par({ scope: "openid" });
    expect(pushed.status, JSON.stringify(pushed.body)).toBe(400);
    expect(pushed.body.error).toBe("invalid_scope");
    expect(pushed.body.error_description).toBe("OIDC is not enabled on this deployment");
    const userinfo = await fetch(`${asUrl}/me`, { headers: { authorization: `Bearer ${base.accessToken}` } });
    expectUnservedRoute({ status: userinfo.status, body: await readJson(userinfo) });
    const logout = await fetch(`${asUrl}/session/end`);
    expectUnservedRoute({ status: logout.status, body: await readJson(logout) });
  });

  it("RFC 7009 token revocation is not served (404)", async () => {
    const res = await fetch(`${asUrl}/token/revocation`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: base.accessToken }).toString(),
    });
    expectUnservedRoute({ status: res.status, body: await readJson(res) });
  });

  it("the metadata advertises only the enabled surface", async () => {
    const meta = (await (await fetch(`${asUrl}/.well-known/openid-configuration`)).json()) as Json;
    // oidc-provider always lists `implicit`; its token endpoint refuses it, and
    // no client registers a response type that uses it.
    expect(meta.grant_types_supported).toEqual(["implicit", "authorization_code", "refresh_token"]);
    for (const member of [
      "mission_child_delegation_supported",
      "identity_continuation_supported",
      "delegated_refresh_token_profile_supported",
      "transaction_authorization_endpoint",
      "userinfo_endpoint",
      "end_session_endpoint",
      "revocation_endpoint",
      ...WITHDRAWN_MEMBERS,
    ]) {
      expect(meta, member).not.toHaveProperty(member);
    }
    expect(meta.mission_bound_authorization_supported).toBe(true);
    expect(meta.introspection_endpoint).toBe(`${asUrl}/introspect`);
    // The revocation-propagation bound the 300 s access-token lifetime is sized to.
    expect(meta.mission_max_stale_seconds).toBe(300);
  });
});

/** Boot an assembly on `port` with the given options. */
async function boot(
  port: number,
  opts: Omit<Parameters<typeof buildAuthorizationServer>[0], "issuer">,
): Promise<{ as: BuiltAs; issuer: string; close: () => Promise<void> }> {
  const issuer = `http://localhost:${port}`;
  const as = await buildAuthorizationServer({ issuer, ...opts });
  const server: Server = as.provider.listen(port);
  await new Promise<void>((r) => server.once("listening", () => r()));
  return { as, issuer, close: () => new Promise<void>((r) => server.close(() => r())) };
}

describe("capability gates the launcher's wiring shadows, and the default assembly (#873)", () => {
  it("with the exchange grant registered for one profile, a disabled profile's exchange is refused invalid_request", async () => {
    const caps = new Set<ProviderCapability>([...ISSUANCE_ONLY_CAPABILITIES, "child-delegation"]);
    const { as, issuer, close } = await boot(14666, { capabilities: caps });
    try {
      const r = await token(issuer, as, {
        grant_type: TE,
        request_refresh_token: "true",
        subject_token: "x.y.z",
        subject_token_type: AT_TYPE,
        resource: PLAIN_RS_AUDIENCE,
      });
      expect(r.status, JSON.stringify(r.body)).toBe(400);
      expect(r.body.error).toBe("invalid_request");
      expect(r.body.error_description).toBe("this token exchange (async-delegation) is not enabled on this deployment");
    } finally {
      await close();
    }
  });

  it("an assembly that wires transaction authorization and dev issuance but leaves both capabilities off answers 501 and advertises neither", async () => {
    const { issuer, close } = await boot(14667, {
      capabilities: ISSUANCE_ONLY_CAPABILITIES,
      devOrdinaryIssuance: true,
      transactionAuthorization: {} as never,
    });
    try {
      const txn = await fetch(`${issuer}/transaction`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: "",
      });
      expect(txn.status).toBe(501);
      expect((await readJson(txn)).error).toBe("temporarily_unavailable");
      const dev = await fetch(`${issuer}/dev/ordinary-token`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-service-token": "dev-service-token" },
        body: JSON.stringify({ sub: "alice", scope: "reports.read" }),
      });
      expect(dev.status).toBe(501);
      expect((await readJson(dev)).error).toBe("temporarily_unavailable");
      const meta = (await (await fetch(`${issuer}/.well-known/openid-configuration`)).json()) as Json;
      expect(meta).not.toHaveProperty("transaction_authorization_endpoint");
    } finally {
      await close();
    }
  });

  it("the default assembly (no capability set) is the full provider: every grant registered and every capability member advertised, and no withdrawn member", async () => {
    const { issuer, close } = await boot(14668, {});
    try {
      const meta = (await (await fetch(`${issuer}/.well-known/openid-configuration`)).json()) as Json;
      expect(new Set(meta.grant_types_supported as string[])).toEqual(
        new Set(["implicit", "authorization_code", "refresh_token", DEFERRED, JWT_BEARER, DISPATCH, TE]),
      );
      for (const member of [
        "mission_child_delegation_supported",
        "identity_continuation_supported",
        "delegated_refresh_token_profile_supported",
        "userinfo_endpoint",
        "end_session_endpoint",
        "revocation_endpoint",
      ]) {
        expect(meta, member).toHaveProperty(member);
      }
      for (const member of WITHDRAWN_MEMBERS) {
        expect(meta, member).not.toHaveProperty(member);
      }
    } finally {
      await close();
    }
  });
});
