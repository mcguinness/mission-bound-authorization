/**
 * @spec child-delegation#derivation-budget, derivation-limits#effective-limit
 * (#1119, D327, D577)
 *
 * The endpoint witness for a policy_drawdown child's derivation limit. The
 * deployment's delegable payments entry commits a `child_creation_policy`
 * whose snapshot states the per-child figure, `derivation_limit_ceiling: 3`,
 * and the deployment's own ceiling is far above it (100). A Parent Mission is
 * approved through PAR and the approval page, so its entry carries that
 * reference; a child created through the RFC 8693 token exchange records a
 * limit at or below the committed figure, whatever it requests and whatever
 * the deployment's ceiling now is, and starts its own count.
 */

import { type Server } from "node:http";
import { activationPolicyDigest } from "@mission/core";
import { AUTHORITY_SOURCES, CANONICAL_RESOURCE, DERIVATION_POLICY } from "@mission/demo-data";
import { decodeJwt, exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ACCESS_TOKEN_TOKEN_TYPE, JWT_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import { ApprovalSessionStore, buildAuthorizationServer, type BuiltAs } from "../src/index.js";
import { floorApprovalHeaders, TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";

const PORT = 14983;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
const PARENT_EXP = "2027-01-01T00:00:00Z";
const FLOOR_SESSIONS = new ApprovalSessionStore();

/** The committed child creation policy: its snapshot states the per-child figure. */
const POLICY_ID = "urn:policy:child-limit-endpoint";
const SNAPSHOT = {
  version: "1",
  content_type: "application/json",
  content: JSON.stringify({ rule: "children within the entry", derivation_limit_ceiling: 3 }),
};
const POLICY_REF = { id: POLICY_ID, version: "1", digest: activationPolicyDigest(ISSUER, SNAPSHOT) };

/** The shipped policy, every delegable entry committing the policy, the deployment ceiling at 100. */
const policy = {
  ...DERIVATION_POLICY,
  derivation_limit_ceiling: 100,
  ceiling: DERIVATION_POLICY.ceiling.map((entry) => {
    const delegation = (entry as { delegation?: { children?: Record<string, unknown> } }).delegation;
    if (!delegation?.children) return entry;
    return { ...entry, delegation: { ...delegation, children: { ...delegation.children, child_creation_policy: POLICY_REF } } };
  }),
};

/** The shipped catalog, its user-delegated source bound to that policy's ceiling (it names the deployment's). */
const authoritySources = {
  ...AUTHORITY_SOURCES,
  entries: AUTHORITY_SOURCES.entries.map((entry) =>
    entry.ceiling === undefined || entry.id !== "acme-people" ? entry : { ...entry, ceiling: policy.ceiling },
  ),
};

type DpopKeys = { privateKey: CryptoKey; publicKey: CryptoKey };
let as: BuiltAs;
let asServer: Server;
let clientKey: CryptoKey;
let dpopKeys: DpopKeys;

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

/** POST /token with private_key_jwt + DPoP, with the dpop-nonce retry. */
async function tokenRequest(params: Record<string, string>): Promise<Response> {
  const htu = `${ISSUER}/token`;
  const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
    fetch(htu, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(htu, "POST", extra) },
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

/** The parent's entry, and the child's strict subset of it. */
const parentEntry = () => ({
  type: "mission_resource_access",
  resource: RESOURCE,
  actions: ["payments:invoice.list", "payments:invoice.read"],
});
const readEntry = () => ({
  type: "mission_resource_access",
  resource: RESOURCE,
  actions: ["payments:invoice.read"],
  constraints: { vendors: ["acme"] },
});

/** PAR -> approval page -> token: an active Parent Mission and its access token. */
async function issueParentMission(): Promise<{ missionId: string; accessToken: string }> {
  const jar = new Map<string, string>();
  const verifier = "child-limit-endpoint-verifier-0123456789-0123456789";
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
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
        intent: { goal: "Reconcile Acme invoices", target_resources: [RESOURCE], expires_at: PARENT_EXP },
      }),
      authorization_details: JSON.stringify([parentEntry()]),
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
    headers: { ...floorApprovalHeaders(FLOOR_SESSIONS, uid, cookieHeader(jar)), "content-type": "application/json" },
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
  const tok = await tokenRequest({
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier,
    resource: RESOURCE,
  });
  const body = (await tok.json()) as { access_token: string };
  expect(tok.status, `parent token: ${JSON.stringify(body)} (code ${code}, location ${location})`).toBe(200);
  const claims = decodeJwt(body.access_token) as { mission: { id: string } };
  return { missionId: claims.mission.id, accessToken: body.access_token };
}

/** Create a Child Mission through the RFC 8693 exchange, requesting `limit` (or none). */
async function createChild(subjectToken: string, limit?: number): Promise<Response> {
  return tokenRequest({
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: subjectToken,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    requested_token_type: JWT_TOKEN_TYPE,
    creation_request_id: crypto.randomUUID(),
    login_hint: "alice",
    mission_intent: JSON.stringify({
      intent: {
        goal: "Extract Acme invoices",
        target_resources: [RESOURCE],
        expires_at: PARENT_EXP,
        ...(limit === undefined ? {} : { requested_derivation_limit: limit }),
      },
    }),
    authorization_details: JSON.stringify([readEntry()]),
    child_actor: JSON.stringify({ sub: "subagent-invoice-extractor", sub_profile: "ai_agent" }),
  });
}

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: FLOOR_SESSIONS,
    derivationPolicy: policy as never,
    authoritySources: authoritySources as never,
    activationPolicies: { [POLICY_ID]: SNAPSHOT },
  });
  asServer = as.provider.listen(PORT);
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  dpopKeys = await generateKeyPair("ES256", { extractable: true });
});

afterAll(() => {
  asServer?.close();
});

describe("a child's derivation limit at the token exchange (@spec child-delegation#derivation-budget, derivation-limits#effective-limit, #1119)", () => {
  it("records at most the entry's committed per-child figure over a higher deployment ceiling, whatever the child requests, each child starting its own count", async () => {
    const parent = await issueParentMission();
    const approved = as.kernel.get(parent.missionId)?.authority_set[0] as {
      delegation?: { children?: { child_creation_policy?: unknown } };
    };
    expect(approved.delegation?.children?.child_creation_policy, "the parent's entry commits the policy").toEqual(POLICY_REF);
    for (const [limit, recorded] of [[undefined, 3], [50, 3], [2, 2]] as const) {
      const res = await createChild(parent.accessToken, limit);
      const body = (await res.json()) as { access_token?: string; error?: string; error_description?: string };
      expect(res.status, JSON.stringify(body)).toBe(200);
      const childId = (decodeJwt(body.access_token as string) as { mission: { id: string } }).mission.id;
      const child = as.kernel.get(childId);
      expect(child?.derivation_limit, String(limit)).toBe(recorded);
      expect(child?.derivation_count, String(limit)).toBe(0);
    }
  });
});
