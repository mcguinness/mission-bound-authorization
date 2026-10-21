/**
 * @spec resource-access#resource-contract, resource-access#subset step 4,
 * mission#introspection, issuance-grant#effective-set-projection (#249,
 * D553): the `resource_contract` reference through the real authorization
 * server over the shipped configuration. A proposal carrying the payments
 * contract's current reference is approved with it, `authority_hash`
 * commits it, and the code exchange, refresh, introspection and the
 * async-delegation Token Exchange each carry it exactly; an exchange that
 * removes, replaces or adds a reference is refused.
 */

import type { Server } from "node:http";
import { authorityHash, type JsonValue, type ResourceContractRef } from "@mission/core";
import { DERIVATION_POLICY, RESOURCE_CONTRACTS } from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ACCESS_TOKEN_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import { type AuthorityEntry, type BuiltAs, buildAuthorizationServer } from "../src/index.js";
import { TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";
import { delegationHandleParams } from "./delegation-handle.helper.js";

const PORT = 14251;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = DERIVATION_POLICY.ceiling[0]?.resource as string;
const FAR_EXP = "2027-06-01T00:00:00Z";
const VERIFIER = "resource-contract-verifier-0123456789-0123456789-0123";

const [DECLARED] = RESOURCE_CONTRACTS.declarations;
const CURRENT = DECLARED?.versions.find((v) => v.state === "current");
const SHIPPED: ResourceContractRef = {
  id: DECLARED?.id as string,
  version: CURRENT?.version as string,
  digest: CURRENT?.digest as string,
};
/** Well formed, never declared. */
const OTHER: ResourceContractRef = { ...SHIPPED, version: "1999-01-01" };

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
type Json = Record<string, unknown>;

let as: BuiltAs;
let server: Server;
let clientKey: CryptoKey;

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

async function approve(proposal: AuthorityEntry[]): Promise<URL> {
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER))).toString("base64url");
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
        intent: { goal: "Review third-quarter Acme invoices", target_resources: [RESOURCE], expires_at: FAR_EXP },
      }),
      authorization_details: JSON.stringify(proposal),
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
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...trustedApprovalHeaders(), "content-type": "application/json", cookie: cookie() },
    body: JSON.stringify({ decision: "approve" }),
  });
  keep(res);
  let location = res.headers.get("location") ?? "";
  while (location.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookie() } });
    keep(res);
    location = res.headers.get("location") ?? "";
  }
  return new URL(location);
}

async function issue(proposal: AuthorityEntry[]): Promise<{ at: string; rt: string; keys: Keys; missionId: string }> {
  const redirect = await approve(proposal);
  const code = redirect.searchParams.get("code");
  expect(code, redirect.toString()).toBeTruthy();
  const keys = (await generateKeyPair("ES256", { extractable: true })) as Keys;
  const exchanged = await token(
    { grant_type: "authorization_code", code: code as string, redirect_uri: REDIRECT_URI, code_verifier: VERIFIER, resource: RESOURCE },
    keys,
  );
  expect(exchanged.status, JSON.stringify(exchanged.body)).toBe(200);
  const at = exchanged.body.access_token as string;
  return { at, rt: exchanged.body.refresh_token as string, keys, missionId: (claims(at).mission as { id: string }).id };
}

const claims = (jwt: string): Json => JSON.parse(Buffer.from(jwt.split(".")[1] as string, "base64url").toString()) as Json;
const contractsOf = (details: unknown): unknown[] => (details as AuthorityEntry[]).map((e) => e.resource_contract);

async function introspect(tokenValue: string): Promise<Json> {
  const res = await fetch(`${ISSUER}/introspect`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${Buffer.from("rs-payments:dev-introspection-rs-payments").toString("base64")}`,
    },
    body: new URLSearchParams({ token: tokenValue }).toString(),
  });
  expect(res.status).toBe(200);
  return (await res.json()) as Json;
}

async function exchange(base: string, keys: Keys, requested?: AuthorityEntry[]): Promise<{ status: number; body: Json }> {
  const handle = await token(delegationHandleParams(base, "ap-agent"), keys);
  expect(handle.status, JSON.stringify(handle.body)).toBe(200);
  return token(
    {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      request_refresh_token: "true",
      subject_token: handle.body.access_token as string,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      resource: RESOURCE,
      creation_request_id: crypto.randomUUID(),
      ...(requested ? { authorization_details: JSON.stringify(requested) } : {}),
    },
    keys,
  );
}

const read = (r?: ResourceContractRef): AuthorityEntry[] => [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions: ["payments:invoice.read"],
    constraints: { vendors: ["acme"] },
    ...(r ? { resource_contract: r } : {}),
  } as AuthorityEntry,
];

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
  });
  server = as.provider.listen(PORT);
  await new Promise<void>((r) => server.once("listening", () => r()));
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

describe("the resource contract reference survives every issuance path exactly (@spec resource-access#resource-contract, #249)", () => {
  let issued: { at: string; rt: string; keys: Keys; missionId: string };

  beforeAll(async () => {
    issued = await issue(read(SHIPPED));
  });

  it("the approval records the proposed current reference, authority_hash commits it, and the code-exchanged token carries it", () => {
    const record = as.kernel.get(issued.missionId);
    expect(record?.authority_set.map((e) => e.resource_contract)).toEqual([SHIPPED]);
    expect(record?.authority_hash).toBe(authorityHash(ISSUER, record?.authority_set as unknown as JsonValue[]));
    expect(contractsOf(claims(issued.at).authorization_details)).toEqual([SHIPPED]);
  });

  it("a refreshed access token and introspection carry it unchanged", async () => {
    const refreshed = await token({ grant_type: "refresh_token", refresh_token: issued.rt, resource: RESOURCE }, issued.keys);
    expect(refreshed.status, JSON.stringify(refreshed.body)).toBe(200);
    expect(contractsOf(claims(refreshed.body.access_token as string).authorization_details)).toEqual([SHIPPED]);
    expect(contractsOf((await introspect(issued.at)).authorization_details)).toEqual([SHIPPED]);
  });

  it("an async-delegation Token Exchange carries it, whether it requests nothing narrower or restates it", async () => {
    const carried = await exchange(issued.at, issued.keys);
    expect(carried.status, JSON.stringify(carried.body)).toBe(200);
    expect(contractsOf(claims(carried.body.access_token as string).authorization_details)).toEqual([SHIPPED]);
    const restated = await exchange(issued.at, issued.keys, read(SHIPPED));
    expect(restated.status, JSON.stringify(restated.body)).toBe(200);
    expect(contractsOf(claims(restated.body.access_token as string).authorization_details)).toEqual([SHIPPED]);
  });

  it("a Token Exchange that removes or replaces the reference is refused invalid_authorization_details: neither is narrowing", async () => {
    for (const requested of [read(), read(OTHER)]) {
      const res = await exchange(issued.at, issued.keys, requested);
      expect(res.status, JSON.stringify(requested)).toBe(400);
      expect(res.body.error, JSON.stringify(requested)).toBe("invalid_authorization_details");
    }
  });

  it("a Token Exchange that adds a reference to an entry approved without one is refused: an unpinned approval never gains one", async () => {
    const unpinned = await issue(read());
    expect(contractsOf(claims(unpinned.at).authorization_details)).toEqual([undefined]);
    const res = await exchange(unpinned.at, unpinned.keys, read(SHIPPED));
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_authorization_details");
  });
});
