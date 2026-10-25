/**
 * @spec mission#authority-sources, mission#mission-bound-tokens,
 * mission#designation (#1313 item 1): the actor model under an
 * `organizational` source, end to end over the real AS assembly.
 *
 * The organizational principal `acme-accounts-payable` is the Subject; the
 * administrator `bob`, who approves for it and may activate its source,
 * approves headlessly. The Agent is a test registration added to the shipped
 * `acme-accounts-payable` source: the shipped `governed-agent` holds no Token
 * Exchange grant, so it cannot designate a delegate, although the governed
 * policy's ceiling admits `ai_agent` delegates. Everything else (the governed
 * policy, the principal, the activator, the designable sub-agent) is the
 * shipped configuration, with the opt-in `delegation` capability on.
 *
 * The steps run in order and share one Mission: whatever the source, the
 * token's `client_id` names the Agent, the Subject stays in `sub`, and a
 * delegate is carried in `act`.
 */

import { type Server } from "node:http";
import { AUTHORITY_SOURCES, DERIVATION_POLICY } from "@mission/demo-data";
import { calculateJwkThumbprint, decodeJwt, exportJWK, generateKeyPair, importJWK, SignJWT, type CryptoKey, type JWK } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ACCESS_TOKEN_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import { ALL_PROVIDER_CAPABILITIES, buildAuthorizationServer, type BuiltAs } from "../src/index.js";
import { renderedRevision, TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";

const PORT = 14313;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource as string;
const VERIFIER = "organizational-principal-agent-verifier-0123456789-01";

/** The test Agent, a client of the shipped organizational source. */
const AGENT = "test-organizational-agent";
const SOURCE = "acme-accounts-payable";
const ORGANIZATION = "acme-accounts-payable";
const APPROVER = "bob";
/** The shipped designable sub-agent (`config/delegation.json`). */
const SUBAGENT = "subagent-invoice-extractor";

const READ = [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] }];

let as: BuiltAs;
let server: Server;
const clientKeys = new Map<string, CryptoKey>();

beforeAll(async () => {
  const agentPair = await generateKeyPair("ES256", { extractable: true });
  clientKeys.set(AGENT, agentPair.privateKey as CryptoKey);
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    capabilities: new Set([...ALL_PROVIDER_CAPABILITIES, "delegation"]),
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    testClients: [
      {
        client_id: AGENT,
        client_name: "Test Organizational Agent",
        grant_types: ["authorization_code", "refresh_token", TOKEN_EXCHANGE_GRANT_TYPE],
        response_types: ["code"],
        redirect_uris: [REDIRECT_URI],
        token_endpoint_auth_method: "private_key_jwt",
        token_endpoint_auth_signing_alg: "ES256",
        authorization_details_types: ["mission_resource_access"],
        jwks: { keys: [{ ...(await exportJWK(agentPair.publicKey)), kid: `${AGENT}-auth`, alg: "ES256" }] },
      },
    ],
    // The shipped catalog, with the test Agent added to the organizational source.
    authoritySources: {
      ...AUTHORITY_SOURCES,
      entries: AUTHORITY_SOURCES.entries.map((e) => (e.id === SOURCE ? { ...e, clients: [...e.clients, AGENT] } : e)),
    },
  });
  server = as.provider.listen(PORT);
  clientKeys.set(SUBAGENT, (await importJWK(as.childClientJwk as never, "ES256")) as CryptoKey);
});

afterAll(() => {
  server?.close();
});

const clientAuth = async (client: string = AGENT) => ({
  client_assertion: await new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: `${client}-auth` })
    .setIssuer(client)
    .setSubject(client)
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(clientKeys.get(client) as CryptoKey),
  client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
});

/**
 * The Agent's headless submission (PAR, then the authorization request with
 * no End-User present), approved on the trusted approval service by the
 * administrator for the organizational Subject. Returns the redirect's code.
 */
async function submitAndApprove(): Promise<string> {
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER))).toString("base64url");
  const par = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: AGENT,
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: RESOURCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      mission_intent: JSON.stringify({
        intent: { goal: "Read Acme invoices for accounts payable", target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" },
      }),
      authorization_details: JSON.stringify(READ),
      ...(await clientAuth()),
    }).toString(),
  });
  expect(par.status, await par.clone().text()).toBe(201);
  const { request_uri } = (await par.json()) as { request_uri: string };
  const jar = new Map<string, string>();
  const keep = (res: Response) => {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = (pair as string).indexOf("=");
      jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
    }
  };
  const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
  let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: AGENT, request_uri })}`, { redirect: "manual" });
  keep(res);
  let location = res.headers.get("location") ?? "";
  const uid = location.split("/interaction/")[1] as string;
  const decideHeaders = { ...trustedApprovalHeaders(APPROVER, {}, ORGANIZATION), cookie: cookie(), "content-type": "application/json" };
  const render_revision = await renderedRevision(ISSUER, uid, decideHeaders);
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: decideHeaders,
    body: JSON.stringify({ decision: "approve", render_revision }),
  });
  keep(res);
  location = res.headers.get("location") ?? "";
  while (location.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookie() } });
    keep(res);
    location = res.headers.get("location") ?? "";
  }
  const q = new URL(location).searchParams;
  expect(q.get("code"), q.get("error_description") ?? q.get("error") ?? location).toBeTruthy();
  return q.get("code") as string;
}

type Keys = { privateKey: CryptoKey; jwk: JWK };

const newKeys = async (): Promise<Keys> => {
  const pair = await generateKeyPair("ES256", { extractable: true });
  return { privateKey: pair.privateKey as CryptoKey, jwk: await exportJWK(pair.publicKey) };
};

/** The token endpoint as `client` (the Agent by default), with DPoP under `k` (one nonce retry). */
async function token(params: Record<string, string>, k: Keys, client: string = AGENT): Promise<Record<string, unknown>> {
  const htu = `${ISSUER}/token`;
  const proof = (nonce?: string) =>
    new SignJWT({ htu, htm: "POST", ...(nonce ? { nonce } : {}) })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: k.jwk })
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .sign(k.privateKey);
  const send = async (nonce?: string) =>
    fetch(htu, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await proof(nonce) },
      body: new URLSearchParams({ ...params, ...(await clientAuth(client)) }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send(nonce);
  const body = (await res.json()) as Record<string, unknown>;
  expect(res.status, JSON.stringify(body)).toBe(200);
  return body;
}

/** A Token Exchange of `subjectToken` for an access token. */
const exchange = (subjectToken: string, extra: Record<string, string>): Record<string, string> => ({
  grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
  subject_token: subjectToken,
  subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
  requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
  ...extra,
});

// One Mission, shared by the ordered steps below.
let keys: Keys;
let missionId: string;
let issued: Record<string, unknown>;

describe("an agent acting for an organizational principal (@spec mission#authority-sources, mission#mission-bound-tokens, mission#designation, #1313)", () => {
  it("step 1 (record): the administrator's headless approval records the organizational principal as Subject, the Agent as client and the organizational source", async () => {
    const before = as.kernel.allMissions().length;
    const code = await submitAndApprove();
    expect(as.kernel.allMissions()).toHaveLength(before + 1);
    keys = await newKeys();
    issued = await token(
      { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: VERIFIER, resource: RESOURCE },
      keys,
    );
    missionId = (decodeJwt(issued.access_token as string).mission as { id: string }).id;
    const record = as.kernel.get(missionId);
    expect(record?.subject).toEqual({ iss: ISSUER, sub: ORGANIZATION });
    expect(record?.client_id).toBe(AGENT);
    expect(record?.authority_source.type).toBe("organizational");
    expect(record?.authority_source.policy).toMatchObject({ id: "acme-accounts-payable-controls", version: "2026-09-01" });
    expect(record?.approval_basis.consent_principal).toEqual({ iss: ISSUER, sub: APPROVER });
  });

  it("step 2 (token): the access token's sub is the organizational principal, not the Approver, its client_id the Agent, and it carries no act", async () => {
    const at = decodeJwt(issued.access_token as string);
    expect(at.sub).toBe(ORGANIZATION);
    expect(at.sub).not.toBe(APPROVER);
    expect(at.client_id).toBe(AGENT);
    expect(at.act).toBeUndefined();
    expect((at.mission as { id: string }).id).toBe(missionId);
    expect(as.kernel.get(missionId)?.authority_source.type).toBe("organizational");
  });

  it("step 3 (same-Mission delegation): the Agent designates a sub-agent, and the sub-agent's redeemed token keeps the organizational principal as sub, names the sub-agent in act and carries the sub-agent as client_id", async () => {
    // The Agent, proving its own token's key, names the sub-agent.
    const designation = await token(exchange(issued.access_token as string, { audience: SUBAGENT }), keys);
    const d = decodeJwt(designation.access_token as string);
    expect(d.aud).toBe(SUBAGENT);
    expect(d.client_id).toBe(AGENT);
    expect(d.sub).toBe(ORGANIZATION);
    expect(d.act).toBeUndefined();
    expect((d.mission as { id: string }).id).toBe(missionId);

    // The sub-agent redeems the designation as its own client, proving its own key.
    const subagentKeys = await newKeys();
    const delegated = await token(exchange(designation.access_token as string, { resource: RESOURCE }), subagentKeys, SUBAGENT);
    const t = decodeJwt(delegated.access_token as string);
    // The Subject does not change: still the organizational principal, never the delegate.
    expect(t.sub).toBe(ORGANIZATION);
    expect(t.sub).not.toBe(SUBAGENT);
    // The requesting client is the sub-agent; the Mission's Agent is unchanged.
    expect(t.client_id).toBe(SUBAGENT);
    expect(as.kernel.get(missionId)?.client_id).toBe(AGENT);
    // The delegate is carried in act.
    expect(t.act).toEqual({ iss: ISSUER, sub: SUBAGENT, sub_profile: "ai_agent client_instance" });
    expect((t.cnf as { jkt?: string } | undefined)?.jkt).toBe(await calculateJwkThumbprint(subagentKeys.jwk));
    expect((t.mission as { id: string }).id).toBe(missionId);
  });
});
