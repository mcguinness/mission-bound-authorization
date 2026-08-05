/**
 * @spec draft-mcguinness-oauth-mission-child-delegation (#child-creation,
 * #child-client-identity, #request-processing, #discovery)
 *
 * Child Mission creation wired onto the real OAuth surface. The parent pushes
 * the child-creation params (mission_intent + parent + parent_token +
 * child_actor) via PAR and presents the request_uri to the back-channel
 * /child-missions route; the AS resolves the Parent Mission from parent_token
 * (RESOLVE-ONLY: no rotation, no replay), runs createChildMission, and returns
 * the child-bound RFC 7523 JWT authorization grant. Covered here:
 *   - happy path: a Child Mission is created; the assertion carries the
 *     `mission.parent` lineage and an `authority_hash` over the CHILD set;
 *   - parent != the Mission resolved from parent_token -> parent_mismatch;
 *   - front-channel presentation of parent_token -> invalid_request;
 *   - parent_token is neither rotated nor replay-flagged by child creation;
 *   - discovery advertises mission_child_delegation_supported.
 * The child redeeming the assertion AS ITSELF at /token (which needs the child
 * to be a registered OAuth client) is deferred to PR4b -- see the skipped test.
 */

import { type Server } from "node:http";
import { CANONICAL_RESOURCE, DEV_SERVICE_TOKEN } from "@mission/demo-data";
import { decodeJwt, exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildAuthorizationServer, type BuiltAs } from "../src/index.js";

const PORT = 14470;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
const PARENT_EXP = "2027-01-01T00:00:00Z";

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

/** POST /token with private_key_jwt + DPoP, with the mandatory dpop-nonce retry. */
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

const parentAuthority = () => [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions: ["payments:invoice.read", "payments:remittance.send"],
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];

/** A strict subset of the parent authority (narrowed by action; constraints restated). */
const childAuthority = () => [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions: ["payments:invoice.read"],
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];

/** Full PAR -> approval -> token dance yielding an ACTIVE parent Mission + its refresh token. */
async function issueParentMission(): Promise<{ missionId: string; refreshToken: string }> {
  const jar = new Map<string, string>();
  const verifier = "child-endpoint-verifier-0123456789-0123456789-0123";
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
  ).toString("base64url");
  const intent = JSON.stringify({
    goal: "Pay Acme invoices and send remittance",
    resources: [RESOURCE],
    expires_at: PARENT_EXP,
    proposed_authority: parentAuthority(),
  });
  const par = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      scope: "payments",
      resource: RESOURCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      mission_intent: intent,
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
    headers: { "content-type": "application/json", cookie: cookieHeader(jar) },
    body: JSON.stringify({ decision: "approve", approver: "bob", subject: "alice" }),
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
  const body = (await tok.json()) as { access_token: string; refresh_token: string };
  const claims = decodeJwt(body.access_token) as { mission: { id: string } };
  return { missionId: claims.mission.id, refreshToken: body.refresh_token };
}

/** Push the child-creation params via PAR; returns the request_uri. */
async function pushChildPar(fields: {
  parent: string;
  parentToken: string;
  childActor: Record<string, unknown>;
  intent?: unknown;
}): Promise<string> {
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode("child-par-verifier-0123456789-0123456789-01")),
  ).toString("base64url");
  const intent = JSON.stringify(
    fields.intent ?? {
      goal: "Extract Acme invoices",
      resources: [RESOURCE],
      expires_at: PARENT_EXP,
      proposed_authority: childAuthority(),
    },
  );
  const res = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      scope: "payments",
      resource: RESOURCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      mission_intent: intent,
      parent: fields.parent,
      parent_token: fields.parentToken,
      child_actor: JSON.stringify(fields.childActor),
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const body = (await res.json()) as { request_uri?: string; error?: string };
  expect(res.status, JSON.stringify(body)).toBe(201);
  return body.request_uri as string;
}

/** Redeem a pushed child request on the (service-token-authenticated) back channel. */
async function createChild(requestUri: string): Promise<Response> {
  return fetch(`${ISSUER}/child-missions`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
    body: JSON.stringify({ request_uri: requestUri, client_id: "ap-agent" }),
  });
}

let parent: { missionId: string; refreshToken: string };

beforeAll(async () => {
  as = await buildAuthorizationServer({ issuer: ISSUER, allowHeadlessAdjudication: true });
  asServer = as.provider.listen(PORT);
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  dpopKeys = await generateKeyPair("ES256", { extractable: true });
  parent = await issueParentMission();
});

afterAll(() => {
  asServer?.close();
});

describe("child Mission creation on the AS surface (@spec child-delegation#child-creation)", () => {
  it("PAR + back-channel redemption creates a Child Mission and returns a child-bound grant", async () => {
    const requestUri = await pushChildPar({
      parent: parent.missionId,
      parentToken: parent.refreshToken,
      childActor: { sub: "subagent-extractor", sub_profile: "ai_agent" },
    });
    const res = await createChild(requestUri);
    const body = (await res.json()) as {
      mission_id?: string;
      parent?: { id: string; depth: number };
      grant_type?: string;
      assertion?: string;
    };
    expect(res.status, JSON.stringify(body)).toBe(201);
    expect(body.grant_type).toBe("urn:ietf:params:oauth:grant-type:jwt-bearer");
    expect(body.parent?.id).toBe(parent.missionId);

    // The Child Mission is committed, active, and lineage-linked.
    const child = as.kernel.get(body.mission_id as string);
    expect(child?.state).toBe("active");
    expect(child?.parent?.id).toBe(parent.missionId);
    // @spec #child-client-identity — client_id == the child actor's sub.
    expect(child?.client_id).toBe("subagent-extractor");

    // @spec #child-client-identity / #parent-member — the grant reference carries
    // the parent lineage and an authority_hash over the CHILD set (not the parent's).
    const a = decodeJwt(body.assertion as string) as {
      aud: string;
      sub: string;
      client_id: string;
      mission: { id: string; authority_hash: string; parent?: { id: string; depth: number } };
    };
    expect(a.aud).toBe(`${ISSUER}/token`);
    // sub = the Mission subject (inherited from the parent); client_id = the child actor.
    expect(a.sub).toBe("alice");
    expect(a.client_id).toBe("subagent-extractor");
    expect(a.mission.id).toBe(body.mission_id);
    expect(a.mission.parent?.id).toBe(parent.missionId);
    expect(a.mission.parent?.depth).toBe(1);
    expect(a.mission.authority_hash).toMatch(/^sha-256:/);
    expect(a.mission.authority_hash).toBe(child?.authority_hash);
    const parentRecord = as.kernel.get(parent.missionId);
    expect(a.mission.authority_hash).not.toBe(parentRecord?.authority_hash);
  });

  it("rejects an unauthenticated /child-missions request (@spec #request-processing step 1)", async () => {
    const requestUri = await pushChildPar({
      parent: parent.missionId,
      parentToken: parent.refreshToken,
      childActor: { sub: "subagent-extractor", sub_profile: "ai_agent" },
    });
    // No x-service-token: the back-channel creation route must not proceed.
    const res = await fetch(`${ISSUER}/child-missions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ request_uri: requestUri }),
    });
    expect(res.status).toBe(401);
  });

  it("parent != the Mission resolved from parent_token -> parent_mismatch (invalid_grant)", async () => {
    const requestUri = await pushChildPar({
      parent: "msn_not-the-resolved-parent",
      parentToken: parent.refreshToken,
      childActor: { sub: "subagent-extractor", sub_profile: "ai_agent" },
    });
    const res = await createChild(requestUri);
    const body = (await res.json()) as { error?: string; mission_denial_reason?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
    // @spec #denial-reasons — the symbolic reason rides in mission_denial_reason.
    expect(body.mission_denial_reason).toBe("parent_mismatch");
  });

  it("front-channel presentation of parent_token -> invalid_request (@spec #child-creation)", async () => {
    // Push a child request, then resolve the request_uri at /auth (the front
    // channel). loadPushedAuthorizationRequest rehydrates parent_token before
    // checkExtraParams re-runs on route `authorization`, so the guard fires.
    const requestUri = await pushChildPar({
      parent: parent.missionId,
      parentToken: parent.refreshToken,
      childActor: { sub: "subagent-extractor", sub_profile: "ai_agent" },
    });
    const res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: requestUri })}`, {
      redirect: "manual",
    });
    // The error is redirected to the client's redirect_uri.
    const location = res.headers.get("location") as string;
    const q = new URL(location).searchParams;
    expect(q.get("error")).toBe("invalid_request");
    expect(q.get("error_description")).toContain("back-channel");
  });

  it("child creation neither rotates nor replay-flags parent_token (@spec #child-creation)", async () => {
    // A dedicated parent so the closing refresh cannot disturb other tests.
    const p = await issueParentMission();

    // Two child creations under the same parent_token both succeed (resolve-only).
    for (const sub of ["subagent-a", "subagent-b"]) {
      const requestUri = await pushChildPar({
        parent: p.missionId,
        parentToken: p.refreshToken,
        childActor: { sub, sub_profile: "ai_agent" },
      });
      const res = await createChild(requestUri);
      expect(res.status, await res.clone().text()).toBe(201);
    }

    // The SAME token still redeems as a normal refresh -> proves child creation
    // did not consume/rotate it and did not fire replay detection.
    const refresh = await tokenRequest({ grant_type: "refresh_token", refresh_token: p.refreshToken });
    const rbody = (await refresh.json()) as { access_token?: string; error?: string };
    expect(refresh.status, JSON.stringify(rbody)).toBe(200);
    expect(rbody.access_token).toBeTruthy();
  });

  it("discovery advertises mission_child_delegation_supported (@spec #discovery)", async () => {
    const res = await fetch(`${ISSUER}/.well-known/openid-configuration`);
    const meta = (await res.json()) as Record<string, unknown>;
    expect(res.status).toBe(200);
    expect(meta.mission_child_delegation_supported).toBe(true);
    // Sanity: the sibling attenuation flag is unaffected.
    expect(meta.mission_attenuation_supported).toBe(true);
  });

  // PR4b: the child redeeming the child-bound assertion AS ITSELF at /token
  // (RFC 7523 JWT-bearer) requires the child actor to be a registered OAuth
  // client so it can authenticate at the token endpoint -- no path to that stays
  // within this PR's allowed surface (it needs config/clients.json + demo-data).
  // PR4 lands PAR resolution + createChildMission wiring + assertion minting +
  // discovery; PR4b lands only this redemption leg.
  it.skip("PR4b: child redeems the child-bound grant AS ITSELF for a DPoP-bound child token", () => {});
});
