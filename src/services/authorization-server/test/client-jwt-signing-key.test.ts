/**
 * @spec #831 (role binding): an ID Token, the one JWT the provider signs for
 * a client here, uses the access-token key alone. The provider selects a key
 * by algorithm, so while its keystore held every AS role's signing key a
 * client registered for another role's algorithm (ES256) got an ID Token
 * signed under the Mission Status key. The keystore now holds the
 * access-token key alone, so such a registration is refused at the client's
 * first request, and a client on the default receives an ID Token under the
 * access-token key.
 */
import { type Server } from "node:http";
import { AUTHORITY_SOURCES, CANONICAL_RESOURCE, TOPOLOGY } from "@mission/demo-data";
import { type CryptoKey, decodeProtectedHeader, exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { floorApprovalHeaders, renderedRevision, TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";
import { ApprovalSessionStore, buildAuthorizationServer, type BuiltAs } from "../src/index.js";

const PORT = 14612;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const ID_TOKEN_ES256 = "test-id-token-es256";

type Body = Record<string, unknown>;
const sessions = new ApprovalSessionStore();
let as: BuiltAs;
let server: Server;
const clientKeys = new Map<string, CryptoKey>();

/** A test client like the agent, with one signed-response algorithm set. */
async function testClient(clientId: string, metadata: Body): Promise<Body> {
  const keys = await generateKeyPair("ES256", { extractable: true });
  clientKeys.set(clientId, keys.privateKey);
  return {
    client_id: clientId,
    client_name: clientId,
    grant_types: ["authorization_code"],
    response_types: ["code"],
    redirect_uris: [REDIRECT_URI],
    token_endpoint_auth_method: "private_key_jwt",
    token_endpoint_auth_signing_alg: "ES256",
    scope: "openid profile email",
    authorization_details_types: ["mission_resource_access"],
    jwks: { keys: [{ ...(await exportJWK(keys.publicKey)), kid: `${clientId}-auth`, alg: "ES256", use: "sig" }] },
    ...metadata,
  };
}

const assertion = (clientId: string) =>
  new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: `${clientId}-auth` })
    .setIssuer(clientId)
    .setSubject(clientId)
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(clientKeys.get(clientId) as CryptoKey);

const verifier = "client-jwt-signing-key-verifier-0123456789-0123456789";

/** A pushed authorization request for an OpenID Connect sign-in under a Mission. */
async function par(clientId: string): Promise<{ status: number; body: Body }> {
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");
  const res = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: clientId,
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      scope: "openid",
      resource: CANONICAL_RESOURCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      login_hint: "alice",
      mission_intent: JSON.stringify({ intent: { goal: "Read Acme invoices", target_resources: [CANONICAL_RESOURCE], expires_at: "2027-01-01T00:00:00Z" } }),
      authorization_details: JSON.stringify([
        { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"], constraints: { vendors: ["acme"] } },
      ]),
      client_assertion: await assertion(clientId),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  return { status: res.status, body: (await res.json()) as Body };
}

/** The rest of the sign-in: Alice approves for herself (openid needs the Subject), then the code exchange. */
async function signIn(clientId: string, requestUri: string): Promise<Body> {
  const jar = new Map<string, string>();
  const store = (res: Response) => {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = (pair as string).indexOf("=");
      jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
    }
  };
  const cookie = () => [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: clientId, request_uri: requestUri })}`, { redirect: "manual" });
  store(res);
  let location = res.headers.get("location") as string;
  const uid = location.split("/interaction/")[1] as string;
  const headers = { ...floorApprovalHeaders(sessions, uid, cookie(), { sub: "alice", subject: null }), "content-type": "application/json" };
  const render_revision = await renderedRevision(ISSUER, uid, headers);
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers,
    body: JSON.stringify({ decision: "approve", render_revision }),
  });
  store(res);
  location = res.headers.get("location") as string;
  while (location?.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookie() } });
    store(res);
    location = res.headers.get("location") as string;
  }
  const code = new URL(location).searchParams.get("code") as string;
  const dpop = await generateKeyPair("ES256", { extractable: true });
  const proof = await new SignJWT({ htu: `${ISSUER}/token`, htm: "POST" })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(dpop.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(dpop.privateKey);
  const tok = await fetch(`${ISSUER}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", dpop: proof },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
      resource: CANONICAL_RESOURCE,
      client_assertion: await assertion(clientId),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const body = (await tok.json()) as Body;
  expect(tok.status, JSON.stringify(body)).toBe(200);
  return body;
}

beforeAll(async () => {
  const testClients = [await testClient(ID_TOKEN_ES256, { id_token_signed_response_alg: "ES256" })];
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: sessions,
    testClients,
    actorProfiles: { [ID_TOKEN_ES256]: "ai_agent" },
    authoritySources: {
      ...AUTHORITY_SOURCES,
      entries: AUTHORITY_SOURCES.entries.map((e) =>
        e.id === "acme-people" ? { ...e, clients: [...(e.clients ?? []), ID_TOKEN_ES256] } : e,
      ),
    },
  } as never);
  server = as.provider.listen(PORT);
  clientKeys.set("ap-agent", (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey);
});

afterAll(() => {
  server?.close();
});

describe("client-facing JWTs use the access-token key alone (@spec #831 role binding)", () => {
  it("refuses a client registered for ES256 ID Tokens: the provider would sign one under another role's key", async () => {
    const { status, body } = await par(ID_TOKEN_ES256);
    expect(status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_client_metadata");
    expect(body.error_description).toContain(`id_token_signed_response_alg must be '${TOPOLOGY.keys.asToken.alg}'`);
  });

  it("signs a default client's ID Token under the access-token key", async () => {
    const pushed = await par("ap-agent");
    expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
    const tokens = await signIn("ap-agent", pushed.body.request_uri as string);
    expect(decodeProtectedHeader(tokens.id_token as string)).toMatchObject({
      alg: TOPOLOGY.keys.asToken.alg,
      kid: TOPOLOGY.keys.asToken.kid,
    });
  });
});
