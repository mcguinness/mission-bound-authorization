/**
 * @spec runtime#input-authority-dependency (#830, D798): the issuance gates
 * consult the declared authority dependency beside the `active` check.
 *
 * The authorization server is assembled with the deployment's declaration
 * (config/authority-dependencies.json: the Mission Subject's continuing
 * delegation to the Mission's client, governing user-delegated Missions) and
 * an identity-state resolver over a controlled source and clock. A disabled
 * Subject's approval is refused `access_denied`; a derivation under a
 * Mission whose dependency is not established (a code redemption, a refresh
 * before its refresh token is consumed, a token exchange) is refused
 * `invalid_grant`, with no `mission_error`. An approver's departure leaves the
 * Subject's Missions alone, a stale observation fails closed, and an outage
 * with a still-valid cached observation keeps issuing.
 */

import type { Server } from "node:http";
import {
  type AuthorityDependencyDeclaration,
  AuthorityDependencyEvidence,
  AuthorityDependencyResolver,
} from "@mission/core";
import { AUTHORITY_DEPENDENCIES, parseIdentityState, TOPOLOGY } from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, SignJWT, type CryptoKey, type JWK } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ApprovalSessionStore, buildAuthorizationServer, type BuiltAs, IntentError, validateMissionIntent } from "../src/index.js";
import { browserApprovalHeaders, renderedRevision, TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";
import { delegationHandleParams } from "./delegation-handle.helper.js";

const PORT = 15321;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const VERIFIER = "authority-dependency-gates-verifier-0123456789-0123456789";
const PLAIN = TOPOLOGY.resources.plainRs;
const SESSIONS = new ApprovalSessionStore();
const ALICE = { sub: "alice", acr: "mfa" };
const SHIPPED: readonly { sub: string; status?: string; withdrawn_delegations?: string[] }[] = [
  { sub: "alice" },
  { sub: "bob" },
  { sub: "dana" },
];

let source: unknown = SHIPPED;
let nowMs = Date.now();
const evidence = new AuthorityDependencyEvidence();
const resolver = new AuthorityDependencyResolver({
  issuer: ISSUER,
  read: async () => {
    if (source instanceof Error) throw source;
    return source;
  },
  parse: (raw) => parseIdentityState(raw),
  now: () => nowMs,
});

let as: BuiltAs;
let server: Server;
let agentKey: CryptoKey;

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: SESSIONS,
    authorityDependency: {
      declaration: AUTHORITY_DEPENDENCIES[0] as AuthorityDependencyDeclaration,
      resolver,
      evidence,
      now: () => nowMs,
    },
  });
  server = as.provider.listen(PORT);
  agentKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
});

afterAll(() => {
  server?.close();
});

/** Point the identity source at `records` (an Error for an outage) and read it. */
async function observe(records: unknown): Promise<boolean> {
  source = records;
  return resolver.refresh();
}

const clientAuth = async (): Promise<[string, string][]> => [
  [
    "client_assertion",
    await new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
      .setIssuer("ap-agent")
      .setSubject("ap-agent")
      .setAudience(ISSUER)
      .setIssuedAt()
      .setExpirationTime("2m")
      .setJti(crypto.randomUUID())
      .sign(agentKey),
  ],
  ["client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"],
];

type Keys = { privateKey: CryptoKey; jwk: JWK };
const newKeys = async (): Promise<Keys> => {
  const pair = await generateKeyPair("ES256", { extractable: true });
  return { privateKey: pair.privateKey as CryptoKey, jwk: await exportJWK(pair.publicKey) };
};

/** A token request as `ap-agent`, DPoP-bound under `keys` (one nonce retry). */
async function tokenRequest(params: Record<string, string>, keys: Keys): Promise<{ status: number; body: Record<string, unknown> }> {
  const htu = `${ISSUER}/token`;
  const proof = (nonce?: string) =>
    new SignJWT({ htu, htm: "POST", ...(nonce ? { nonce } : {}) })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: keys.jwk })
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .sign(keys.privateKey);
  const send = async (nonce?: string) =>
    fetch(htu, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await proof(nonce) },
      body: new URLSearchParams([...Object.entries(params), ...(await clientAuth())]).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send(nonce);
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

const CHALLENGE = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER))).toString("base64url");

type Jar = Map<string, string>;
const cookieOf = (jar: Jar) => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
const keep = (jar: Jar, res: Response) => {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
  }
};

/** A user-delegated Mission on the reports resource for Alice, approved by her: its id and the code the approval returned. */
async function approvedCode(goal: string): Promise<{ missionId: string; code: string }> {
  const pushed = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams([
      ["client_id", "ap-agent"],
      ["response_type", "code"],
      ["redirect_uri", REDIRECT_URI],
      ["resource", PLAIN],
      ["scope", "openid"],
      ["code_challenge", CHALLENGE],
      ["code_challenge_method", "S256"],
      ["mission_intent", JSON.stringify({ intent: { goal, target_resources: [PLAIN], expires_at: "2027-01-01T00:00:00Z" } })],
      ...(await clientAuth()),
    ]).toString(),
  });
  expect(pushed.status).toBe(201);
  const requestUri = ((await pushed.json()) as { request_uri: string }).request_uri;
  const jar: Jar = new Map();
  const opened = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: requestUri })}`, { redirect: "manual" });
  keep(jar, opened);
  const uid = (opened.headers.get("location") ?? "").split("/interaction/")[1] as string;
  const headers = { ...browserApprovalHeaders(SESSIONS, uid, ALICE, cookieOf(jar)), "content-type": "application/json" };
  const render_revision = await renderedRevision(ISSUER, uid, headers);
  let res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers,
    body: JSON.stringify({ decision: "approve", render_revision }),
  });
  expect(res.status, await res.clone().text()).toBeLessThan(400);
  keep(jar, res);
  let location = res.headers.get("location") ?? "";
  while (location.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieOf(jar) } });
    keep(jar, res);
    location = res.headers.get("location") ?? "";
  }
  const code = new URL(location).searchParams.get("code") as string;
  expect(code, location).toBeTruthy();
  const stored = (await as.provider.AuthorizationCode.find(code)) as { grantId?: string } | undefined;
  return { missionId: as.kernel.findByGrant(stored?.grantId as string)?.id as string, code };
}

const redeem = (code: string, keys: Keys) =>
  tokenRequest({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: VERIFIER, resource: PLAIN }, keys);

/** A user-delegated Mission for Alice approved at the kernel by `approver`. */
function approveAtKernel(approver: string) {
  return as.kernel.approve({
    intent: validateMissionIntent(JSON.stringify({ goal: `gate fixture approved by ${approver}`, target_resources: [PLAIN], expires_at: "2027-01-01T00:00:00Z" })),
    proposedAuthority: [{ type: "mission_resource_access", resource: PLAIN, actions: ["reports:report.read"] }],
    subject: { iss: ISSUER, sub: "alice" },
    approver: { iss: ISSUER, sub: approver },
    clientId: "ap-agent",
    approvalEventId: `apev-dep-${crypto.randomUUID()}`,
  });
}

/** The gate refusal a derivation under a Mission whose dependency is not established receives. */
function expectDependencyRefusal(res: { status: number; body: Record<string, unknown> }, label: string): void {
  expect(res.status, `${label}: ${JSON.stringify(res.body)}`).toBe(400);
  expect(res.body.error, label).toBe("invalid_grant");
  expect(res.body, label).not.toHaveProperty("mission_error");
  expect(res.body, label).not.toHaveProperty("access_token");
}

describe("the issuance gates consult the declared authority dependency beside the active check (@spec runtime#input-authority-dependency, #830)", () => {
  it("refuses the approval of a user-delegated Mission for a disabled Subject access_denied, and retains it at the AS", async () => {
    nowMs = Date.now();
    await observe([{ sub: "alice", status: "disabled" }, { sub: "bob" }]);
    expect(() => approveAtKernel("bob")).toThrow(IntentError);
    try {
      approveAtKernel("bob");
    } catch (e) {
      expect((e as IntentError).code).toBe("access_denied");
    }
    expect(evidence.entries().at(-1)).toMatchObject({ enforcer: "as", failure: "invalidated", action: "approval", subject: { sub: "alice" } });
    await observe(SHIPPED);
    expect(approveAtKernel("bob").state).toBe("active");
  });

  it("refuses a code redemption invalid_grant once the Subject withdraws the delegation from the client", async () => {
    nowMs = Date.now();
    await observe(SHIPPED);
    const { missionId, code } = await approvedCode("Read the quarterly reports (withdrawn before redemption)");
    await observe([{ sub: "alice", withdrawn_delegations: ["ap-agent"] }, { sub: "bob" }, { sub: "dana" }]);
    expectDependencyRefusal(await redeem(code, await newKeys()), "withdrawn");
    expect(evidence.entries().at(-1)).toMatchObject({ enforcer: "as", failure: "withdrawn", mission: { id: missionId }, action: "derivation" });
    await observe(SHIPPED);
  });

  it("refuses a refresh invalid_grant once the Subject is disabled, before the refresh token is spent; re-enabled, the same refresh token redeems", async () => {
    nowMs = Date.now();
    await observe(SHIPPED);
    const { missionId, code } = await approvedCode("Read the quarterly reports (disabled before refresh)");
    const keys = await newKeys();
    const redeemed = await redeem(code, keys);
    expect(redeemed.status, JSON.stringify(redeemed.body)).toBe(200);
    const refreshToken = redeemed.body.refresh_token as string;
    await observe([{ sub: "alice", status: "disabled" }, { sub: "bob" }, { sub: "dana" }]);
    expectDependencyRefusal(await tokenRequest({ grant_type: "refresh_token", refresh_token: refreshToken, resource: PLAIN }, keys), "disabled");
    // A token exchange of the Mission's access token is refused the same way.
    expectDependencyRefusal(await tokenRequest(delegationHandleParams(redeemed.body.access_token as string, "ap-agent"), keys), "exchange");
    await observe(SHIPPED);
    const again = await tokenRequest({ grant_type: "refresh_token", refresh_token: refreshToken, resource: PLAIN }, keys);
    expect(again.status, JSON.stringify(again.body)).toBe(200);
    expect(as.kernel.get(missionId)?.state).toBe("active");
  });

  it("leaves the Subject's Mission alone when its approver departs: only the Subject's own state and delegation govern it", async () => {
    nowMs = Date.now();
    await observe(SHIPPED);
    const record = approveAtKernel("bob");
    await observe([{ sub: "alice" }, { sub: "bob", status: "deprovisioned" }, { sub: "dana" }]);
    expect(() => as.kernel.checkDerivation(record.id)).not.toThrow();
    await observe([{ sub: "alice", status: "disabled" }, { sub: "bob" }, { sub: "dana" }]);
    expect(() => as.kernel.checkDerivation(record.id)).toThrow(/declared authority dependency is not established/);
    await observe(SHIPPED);
  });

  it("fails closed at the gate once the observation is older than its bound, and keeps issuing through an outage while the cached observation is within its validity", async () => {
    nowMs = Date.now();
    await observe(SHIPPED);
    const record = approveAtKernel("alice");
    const base = nowMs;
    expect(await observe(new Error("identity source unreachable"))).toBe(false);
    nowMs = base + 200_000;
    expect(() => as.kernel.checkDerivation(record.id)).not.toThrow();
    nowMs = base + 300_000;
    expect(() => as.kernel.checkDerivation(record.id)).toThrow(/declared authority dependency is not established/);
    expect(evidence.entries().at(-1)).toMatchObject({ enforcer: "as", failure: "unavailable" });
    nowMs = Date.now();
    await observe(SHIPPED);
  });
});
