/**
 * @spec mission#authority-sources, mission#mission-bound-tokens,
 * mission#approval-event, status#lifecycle-authorization (#1194): an agent
 * acting for its own workload principal, end to end over the real AS assembly
 * and the shipped configuration.
 *
 * The agent `ledger-reconciler` submits its own request headlessly. The
 * administrator `dana`, authorized to approve for the workload principal
 * `agt_ledger_reconciler` and to activate its `service_owned` source, approves
 * it on the trusted approval service. Each identity is established on its own:
 * the Subject is the approval surface's selection, the client is the
 * authenticated client, and the source comes from configuration. Nothing here
 * derives one of them from another or from the source type.
 *
 * The steps run in order and share one Mission. Same-Mission delegation runs
 * by designation (@spec mission#designation, #869): the agent names a sub-agent
 * for its own token, and the sub-agent redeems the designation as itself. The
 * opt-in `delegation` capability is enabled for that step; every other
 * capability is the default.
 */

import { type Server } from "node:http";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { calculateJwkThumbprint, decodeJwt, exportJWK, generateKeyPair, importJWK, SignJWT, type CryptoKey, type JWK } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ACCESS_TOKEN_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import { ALL_PROVIDER_CAPABILITIES, buildAuthorizationServer, type BuiltAs, MISSION_LIFECYCLE_SCOPE } from "../src/index.js";
import { TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";
import { delegationHandleParams } from "./delegation-handle.helper.js";

const PORT = 14194;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource as string;
const VERIFIER = "workload-principal-agent-verifier-0123456789-0123";
const RS_PAYMENTS = ["rs-payments", "dev-introspection-rs-payments"] as const;

const AGENT = "ledger-reconciler";
const WORKLOAD = "agt_ledger_reconciler";
const ADMIN = "dana";
/** The shipped designable sub-agent (`config/delegation.json`). */
const SUBAGENT = "subagent-invoice-extractor";

/** The approval service's token: it may approve, and holds no lifecycle grant. */
const APPROVAL_ONLY_TOKEN = Object.keys(TEST_APPROVAL_PRINCIPALS)[0] as string;
/** The administrator's operational credential, holding the lifecycle grant. */
const LIFECYCLE_TOKEN = "test-only-lifecycle-admin-1194";
/** The workload principal's own credential: the Mission's Subject, holding no lifecycle grant. */
const SUBJECT_TOKEN = "test-only-workload-subject-1503";

const READ = [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] }];
const SCHEDULE = [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:payment.schedule"] }];

let as: BuiltAs;
let server: Server;
const clientKeys = new Map<string, CryptoKey>();

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    capabilities: new Set([...ALL_PROVIDER_CAPABILITIES, "delegation"]),
    serviceTokenPrincipals: {
      ...TEST_APPROVAL_PRINCIPALS,
      [LIFECYCLE_TOKEN]: { principal_id: "svc:lifecycle-admin", scopes: [MISSION_LIFECYCLE_SCOPE] },
      [SUBJECT_TOKEN]: { principal_id: WORKLOAD, scopes: [] },
    },
  });
  server = as.provider.listen(PORT);
  clientKeys.set(AGENT, (await importJWK(as.ledgerReconcilerClientJwk as never, "ES256")) as CryptoKey);
  clientKeys.set(SUBAGENT, (await importJWK(as.childClientJwk as never, "ES256")) as CryptoKey);
});

afterAll(() => {
  server?.close();
});

const clientAssertion = (client: string) =>
  new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: `${client}-auth` })
    .setIssuer(client)
    .setSubject(client)
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(clientKeys.get(client) as CryptoKey);

const clientAuth = async (client: string = AGENT) => ({
  client_assertion: await clientAssertion(client),
  client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
});

/**
 * The agent's own headless submission (PAR, then the authorization request
 * with no End-User present), approved on the trusted approval service by
 * `approver` for the selected `subject`. Returns the redirect's code or error.
 */
async function submitAndApprove(
  approver: string,
  subject: string,
  authorizationDetails: unknown[] = READ,
): Promise<{ code?: string; error?: string; errorDescription?: string; decideStatus: number; cookies: string[] }> {
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
        intent: {
          goal: "Reconcile Acme invoices against the ledger",
          target_resources: [RESOURCE],
          expires_at: "2027-01-01T00:00:00Z",
        },
      }),
      authorization_details: JSON.stringify(authorizationDetails),
      ...(await clientAuth()),
    }).toString(),
  });
  expect(par.status, await par.clone().text()).toBe(201);
  const { request_uri } = (await par.json()) as { request_uri: string };
  const jar = new Map<string, string>();
  const cookies: string[] = [];
  const keep = (res: Response) => {
    for (const line of res.headers.getSetCookie()) {
      cookies.push(line);
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
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...trustedApprovalHeaders(approver, {}, subject), cookie: cookie(), "content-type": "application/json" },
    body: JSON.stringify({ decision: "approve" }),
  });
  const decideStatus = res.status;
  keep(res);
  location = res.headers.get("location") ?? "";
  while (location.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookie() } });
    keep(res);
    location = res.headers.get("location") ?? "";
  }
  const q = location ? new URL(location).searchParams : new URLSearchParams();
  return {
    decideStatus,
    cookies,
    ...(q.get("code") ? { code: q.get("code") as string } : {}),
    ...(q.get("error") ? { error: q.get("error") as string } : {}),
    ...(q.get("error_description") ? { errorDescription: q.get("error_description") as string } : {}),
  };
}

type Keys = { privateKey: CryptoKey; jwk: JWK };

const newKeys = async (): Promise<Keys> => {
  const pair = await generateKeyPair("ES256", { extractable: true });
  return { privateKey: pair.privateKey as CryptoKey, jwk: await exportJWK(pair.publicKey) };
};

/** The token endpoint as `client` (the agent by default), with DPoP under `k` (one nonce retry). */
async function tokenRequest(
  params: Record<string, string>,
  k: Keys,
  client: string = AGENT,
): Promise<{ status: number; body: Record<string, unknown> }> {
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
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

async function token(params: Record<string, string>, k: Keys, client: string = AGENT): Promise<Record<string, unknown>> {
  const { status, body } = await tokenRequest(params, k, client);
  expect(status, JSON.stringify(body)).toBe(200);
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

async function introspect(tokenValue: string): Promise<Record<string, unknown>> {
  const res = await fetch(`${ISSUER}/introspect`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${Buffer.from(`${RS_PAYMENTS[0]}:${RS_PAYMENTS[1]}`).toString("base64")}`,
    },
    body: new URLSearchParams({ token: tokenValue }).toString(),
  });
  expect(res.status).toBe(200);
  return (await res.json()) as Record<string, unknown>;
}

/** A Lifecycle request; it carries the REQUIRED nonce (@spec status#idempotency) unless `body` names one. */
const lifecycle = (missionId: string, body: Record<string, unknown>, serviceToken: string): Promise<Response> =>
  fetch(`${ISSUER}/missions/${missionId}/lifecycle`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-service-token": serviceToken },
    body: JSON.stringify({ nonce: crypto.randomUUID(), ...body }),
  });

// One Mission, shared by the ordered steps below.
let keys: Keys;
let missionId: string;
let issued: Record<string, unknown>;

describe("an agent acting for its own workload principal (@spec mission#authority-sources, mission#mission-bound-tokens, status#lifecycle-authorization, #1194)", () => {
  it("step 1 (submission and approval): the agent pushes its own request, the administrator approves it headlessly for the workload principal, and no authentication session results", async () => {
    const before = as.kernel.allMissions().length;
    const r = await submitAndApprove(ADMIN, WORKLOAD);
    expect(r.code, r.error).toBeTruthy();
    // A headless approval establishes no End-User session in the agent's user agent.
    expect(r.cookies.some((line) => line.startsWith("_session="))).toBe(false);
    expect(as.kernel.allMissions()).toHaveLength(before + 1);
    keys = await newKeys();
    issued = await token(
      { grant_type: "authorization_code", code: r.code as string, redirect_uri: REDIRECT_URI, code_verifier: VERIFIER, resource: RESOURCE },
      keys,
    );
    missionId = (decodeJwt(issued.access_token as string).mission as { id: string }).id;
    expect(missionId).toBeTruthy();
  });

  it("step 1a (approval authorization): an Approver not authorized to approve for the workload principal is refused before any Mission", async () => {
    const before = as.kernel.allMissions().length;
    // bob approves for alice and the organizational principal, not for this workload.
    const r = await submitAndApprove("bob", WORKLOAD);
    expect(r.decideStatus).toBe(403);
    expect(r.code).toBeUndefined();
    expect(as.kernel.allMissions()).toHaveLength(before);
  });

  it("step 1b (source ceiling): a request beyond the service_owned source's own authority is refused access_denied, creating no Mission", async () => {
    const before = as.kernel.allMissions().length;
    // payment.schedule lies within the deployment ceiling but not within the
    // agent's own provisioned authority.
    const r = await submitAndApprove(ADMIN, WORKLOAD, SCHEDULE);
    expect(r.error).toBe("access_denied");
    expect(r.errorDescription).toMatch(/exceeds the authority of the service_owned source 'ledger-reconciler'/);
    expect(r.code).toBeUndefined();
    expect(as.kernel.allMissions()).toHaveLength(before);
  });

  it("step 2 (record): the Mission records the workload principal as Subject, the agent as client, the administrator as consent principal, and the service_owned source", () => {
    const record = as.kernel.get(missionId);
    expect(record?.subject).toEqual({ iss: ISSUER, sub: WORKLOAD });
    expect(record?.client_id).toBe(AGENT);
    expect(record?.authority_source).toEqual({ type: "service_owned" });
    expect(record?.approval_basis.type).toBe("direct");
    expect(record?.approval_basis.consent_principal).toEqual({ iss: ISSUER, sub: ADMIN });
    expect(record?.approval_basis.activation_actor).toEqual({ iss: ISSUER, sub: ADMIN });
  });

  it("step 3 (token): the access token's sub is the workload principal, its client_id the agent, and it carries no act", async () => {
    expect(issued.id_token).toBeUndefined();
    const at = decodeJwt(issued.access_token as string);
    expect(at.sub).toBe(WORKLOAD);
    expect(at.sub).not.toBe(ADMIN);
    expect(at.client_id).toBe(AGENT);
    expect(at.act).toBeUndefined();
    expect((at.mission as { id: string }).id).toBe(missionId);
    expect((await introspect(issued.access_token as string)).sub).toBe(WORKLOAD);
  });

  it("step 4 (refresh): the refreshed token keeps the workload principal as sub and the agent as client_id, with no act", async () => {
    const refreshed = await token({ grant_type: "refresh_token", refresh_token: issued.refresh_token as string }, keys);
    const at = decodeJwt(refreshed.access_token as string);
    expect(at.sub).toBe(WORKLOAD);
    expect(at.client_id).toBe(AGENT);
    expect(at.act).toBeUndefined();
    expect((at.mission as { id: string }).id).toBe(missionId);
    issued = { ...issued, ...refreshed };
  });

  it("step 5 (same-Mission delegation): the agent designates a sub-agent, and the sub-agent's redeemed token keeps the workload principal as sub, names the sub-agent in act, binds the sub-agent's own key and carries the sub-agent as client_id", async () => {
    // The agent, proving its own token's key, names the sub-agent.
    const designation = await token(exchange(issued.access_token as string, { audience: SUBAGENT }), keys);
    const d = decodeJwt(designation.access_token as string);
    expect(d.aud).toBe(SUBAGENT);
    expect(d.client_id).toBe(AGENT);
    expect(d.act).toBeUndefined();
    expect((d.mission as { id: string }).id).toBe(missionId);

    // The sub-agent redeems the designation as its own client, proving its own key.
    const subagentKeys = await newKeys();
    const delegated = await token(exchange(designation.access_token as string, { resource: RESOURCE }), subagentKeys, SUBAGENT);
    const t = decodeJwt(delegated.access_token as string);
    // The Subject does not change: still the agent's own workload principal.
    expect(t.sub).toBe(WORKLOAD);
    // The requesting client is the sub-agent; the Mission's Agent stays ledger-reconciler.
    expect(t.client_id).toBe(SUBAGENT);
    expect(as.kernel.get(missionId)?.client_id).toBe(AGENT);
    // The delegate is carried in act.
    expect(t.act).toEqual({ iss: ISSUER, sub: SUBAGENT, sub_profile: "ai_agent client_instance" });
    // Bound to the sub-agent's own key, not the agent's.
    const jkt = (t.cnf as { jkt?: string } | undefined)?.jkt;
    expect(jkt).toBe(await calculateJwkThumbprint(subagentKeys.jwk));
    expect(jkt).not.toBe(await calculateJwkThumbprint(keys.jwk));
    expect((t.mission as { id: string }).id).toBe(missionId);

    const introspected = await introspect(delegated.access_token as string);
    expect(introspected.active).toBe(true);
    expect(introspected.sub).toBe(WORKLOAD);
  });

  it("step 6 (the agent's own exchange): a no-actor Token Exchange by the agent succeeds while the Mission is active, keeping the workload principal as sub", async () => {
    const handle = await token(delegationHandleParams(issued.access_token as string, AGENT), keys);
    const claims = decodeJwt(handle.access_token as string);
    expect(claims.sub).toBe(WORKLOAD);
    expect(claims.client_id).toBe(AGENT);
    expect(claims.act).toBeUndefined();
    expect((claims.mission as { id: string }).id).toBe(missionId);
  });

  it("step 7 (lifecycle authorization): a caller without the lifecycle grant, the approval service included, is refused revoke with the not-found response and the Mission stays active", async () => {
    const nonce = crypto.randomUUID();
    const refused = await lifecycle(missionId, { operation: "revoke", nonce }, APPROVAL_ONLY_TOKEN);
    const refusedBody = (await refused.json()) as Record<string, unknown>;
    expect(refused.status).toBe(404);
    expect(refusedBody.error).toBe("not_found");
    // The same response an unknown Mission reference gets: no enumeration oracle.
    const unknown = await lifecycle("msn_no_such_mission_1194", { operation: "revoke", nonce }, LIFECYCLE_TOKEN);
    expect(unknown.status).toBe(404);
    expect(refusedBody).toEqual(await unknown.json());
    expect(as.kernel.get(missionId)?.state).toBe("active");
  });

  it("step 7a (no role entitlement): the Mission's Subject, authenticated as itself, and its Approver, carried by the approval service, are each refused revoke without the deployment's lifecycle authorization, and the Mission stays active", async () => {
    // @spec mission#revocation (#1503 finding 14): the Subject and the Approver
    // are parties the deployment's policy can authorize; neither role alone does.
    const record = as.kernel.get(missionId);
    expect(record?.subject.sub).toBe(WORKLOAD);
    expect(Object.values(TEST_APPROVAL_PRINCIPALS)[0]?.approver?.sub).toBe(record?.approval_basis.consent_principal.sub);
    for (const caller of [SUBJECT_TOKEN, APPROVAL_ONLY_TOKEN]) {
      const refused = await lifecycle(missionId, { operation: "revoke" }, caller);
      expect(refused.status, caller).toBe(404);
      expect(((await refused.json()) as Record<string, unknown>).error, caller).toBe("not_found");
    }
    expect(as.kernel.get(missionId)?.state).toBe("active");
  });

  it("step 8 (revoke): the administrator's lifecycle grant revokes the Mission, after which refresh and the agent's exchange are refused", async () => {
    const res = await lifecycle(missionId, { operation: "revoke" }, LIFECYCLE_TOKEN);
    const text = await res.text();
    expect(res.status, text).toBe(200);
    // The signed state-only Mission Status Response (@spec status#mission-lifecycle-endpoint).
    const body = (decodeJwt(text) as { mission: { state?: string; termination?: { reason?: string } } }).mission;
    expect(body.state).toBe("terminated");
    expect(body.termination?.reason).toBe("revoked");

    const refresh = await tokenRequest({ grant_type: "refresh_token", refresh_token: issued.refresh_token as string }, keys);
    expect(refresh.status).toBe(400);
    expect(refresh.body.error).toBe("invalid_grant");
    expect(refresh.body.access_token).toBeUndefined();

    // @spec mission#issuance-gating (#1154, D369): a Token Exchange refuses an
    // inactive Mission with invalid_request, carrying the mission_error.
    const exchange = await tokenRequest(delegationHandleParams(issued.access_token as string, AGENT), keys);
    expect(exchange.status).toBe(400);
    expect(exchange.body.error).toBe("invalid_request");
    expect(exchange.body.mission_error).toBe("revoked");
    expect(exchange.body.access_token).toBeUndefined();
  });
});
