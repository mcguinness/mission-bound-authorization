/**
 * @spec mission#self-exchange, mission#optional-capabilities (#1892, D1031):
 * self-exchange is an optional capability. An AS that does not support the
 * Token Exchange grant type refuses a no-actor exchange with
 * `unsupported_grant_type` (RFC 6749 Section 5.2), issuing nothing.
 *
 * Built with every capability except the token-exchange profiles, so the
 * exchange grant is not registered. Covered:
 *  - discovery does not advertise the Token Exchange grant type;
 *  - a no-actor exchange presenting the Mission's own access token is refused
 *    `unsupported_grant_type` with no token member;
 *  - control: the same Mission's refresh succeeds, so the refusal is the
 *    grant's absence and not a defect of the Mission or the client.
 */

import type { Server } from "node:http";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ACCESS_TOKEN_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import {
  ALL_PROVIDER_CAPABILITIES,
  type BuiltAs,
  buildAuthorizationServer,
  TOKEN_EXCHANGE_CAPABILITIES,
} from "../src/index.js";
import { renderedRevision, TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";

const PORT = 14862;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
const FAR_EXP = "2027-06-01T00:00:00Z";
const VERIFIER = "self-exchange-off-verifier-0123456789-0123456789-0123456789";
const READ = [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] }];

/** Every capability except the token-exchange profiles: the exchange grant is not registered. */
const NO_TOKEN_EXCHANGE = new Set(ALL_PROVIDER_CAPABILITIES.filter((c) => !TOKEN_EXCHANGE_CAPABILITIES.includes(c)));

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
type Json = Record<string, unknown>;

let as: BuiltAs;
let server: Server;
let clientKey: CryptoKey;

async function newKeys(): Promise<Keys> {
  return (await generateKeyPair("ES256", { extractable: true })) as Keys;
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

async function dpopProof(keys: Keys, extra: Json = {}): Promise<string> {
  return new SignJWT({ htu: `${ISSUER}/token`, htm: "POST", ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}

async function token(params: Record<string, string>, keys: Keys): Promise<{ status: number; body: Json }> {
  const send = async (extra: Json = {}) =>
    fetch(`${ISSUER}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(keys, extra) },
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

/** PAR, approval and the code exchange: an active Mission's access and refresh token. */
async function issue(): Promise<{ accessToken: string; refreshToken: string; keys: Keys }> {
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER)),
  ).toString("base64url");
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
      mission_intent: JSON.stringify({
        intent: { goal: "Read Acme invoices", target_resources: [RESOURCE], expires_at: FAR_EXP },
      }),
      authorization_details: JSON.stringify(READ),
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const pushed = (await par.json()) as Json;
  expect(par.status, JSON.stringify(pushed)).toBe(201);
  const jar = new Map<string, string>();
  const keep = (res: Response) => {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = (pair as string).indexOf("=");
      jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
    }
  };
  const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
  let res = await fetch(
    `${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: String(pushed.request_uri) })}`,
    { redirect: "manual" },
  );
  keep(res);
  const uid = (res.headers.get("location") ?? "").split("/interaction/")[1] as string;
  const decideHeaders = { ...trustedApprovalHeaders(), "content-type": "application/json", cookie: cookie() };
  const render_revision = await renderedRevision(ISSUER, uid, decideHeaders);
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: decideHeaders,
    body: JSON.stringify({ decision: "approve", render_revision }),
  });
  keep(res);
  let location = res.headers.get("location") ?? "";
  while (location.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookie() } });
    keep(res);
    location = res.headers.get("location") ?? "";
  }
  const code = new URL(location).searchParams.get("code") as string;
  const keys = await newKeys();
  const exchanged = await token(
    { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: VERIFIER, resource: RESOURCE },
    keys,
  );
  expect(exchanged.status, JSON.stringify(exchanged.body)).toBe(200);
  return { accessToken: exchanged.body.access_token as string, refreshToken: exchanged.body.refresh_token as string, keys };
}

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    capabilities: NO_TOKEN_EXCHANGE,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
  });
  server = as.provider.listen(PORT);
  await new Promise<void>((r) => server.once("listening", () => r()));
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

describe("an AS without the Token Exchange grant refuses a self-exchange (@spec mission#self-exchange, mission#optional-capabilities, #1892, D1031)", () => {
  it("does not advertise the Token Exchange grant type", async () => {
    const res = await fetch(`${ISSUER}/.well-known/oauth-authorization-server`);
    const meta = (await res.json()) as { grant_types_supported?: string[] };
    expect(meta.grant_types_supported ?? []).not.toContain(TOKEN_EXCHANGE_GRANT_TYPE);
  });

  it("refuses a no-actor exchange of the Mission's own access token with unsupported_grant_type, issuing nothing, while the Mission's refresh still succeeds", async () => {
    const m = await issue();
    const exchanged = await token(
      {
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        subject_token: m.accessToken,
        subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
        resource: RESOURCE,
      },
      m.keys,
    );
    expect(exchanged.status, JSON.stringify(exchanged.body)).toBe(400);
    expect(exchanged.body.error).toBe("unsupported_grant_type");
    expect(exchanged.body.access_token).toBeUndefined();
    expect(exchanged.body.refresh_token).toBeUndefined();

    const refreshed = await token({ grant_type: "refresh_token", refresh_token: m.refreshToken }, m.keys);
    expect(refreshed.status, JSON.stringify(refreshed.body)).toBe(200);
  });
});
