/**
 * @spec draft-mcguinness-oauth-mission-child-delegation (#child-creation,
 * #child-client-identity, #request-processing, #discovery)
 *
 * Child Mission creation wired onto the real OAuth surface as an RFC 8693 token
 * exchange. The parent presents its Mission-bound ACCESS token as `subject_token`
 * (`subject_token_type` = access_token) at the /token endpoint under
 * grant_type=token-exchange with requested_token_type=jwt, authenticating with
 * private_key_jwt and proving possession with a DPoP proof over that token's OWN
 * confirmation key. The AS resolves the Parent Mission FROM `subject_token` (the
 * token selects the Mission; `parent` is a non-authoritative cross-check),
 * verifies possession, runs createChildMission, and returns the child-bound RFC
 * 7523 JWT authorization grant. A reusable bearer refresh credential MUST NOT
 * carry possession (#448). Covered here:
 *   - happy path: a Child Mission is created; the assertion carries the
 *     `mission.parent` lineage and an `authority_hash` over the CHILD set;
 *   - an UNauthenticated creation request is rejected by client auth;
 *   - parent cross-check != the Mission resolved from subject_token -> parent_mismatch;
 *   - a refresh token as subject_token -> invalid_request (#448 possession rule);
 *   - the parent access token is not consumed and child creation is NON-derivation;
 *   - possession: a wrong-key DPoP proof / a missing DPoP proof are refused;
 *   - discovery advertises mission_child_delegation_supported;
 *   - PR4b: the child actor (a registered OAuth client) redeems the child-bound
 *     assertion AS ITSELF at /token for a DPoP-bound child access token, with the
 *     client_id security gate, lazy Grant binding, and single-derivation gating.
 */

import { type Server } from "node:http";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import {
  calculateJwkThumbprint,
  createRemoteJWKSet,
  decodeJwt,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify,
  SignJWT,
} from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  ACCESS_TOKEN_TOKEN_TYPE,
  JWT_TOKEN_TYPE,
  REFRESH_TOKEN_TOKEN_TYPE,
  TOKEN_EXCHANGE_GRANT_TYPE,
} from "../src/adapters/continuation-grant.js";
import { buildAuthorizationServer, type BuiltAs } from "../src/index.js";
import { aiAgents } from "./actor-profiles.helper.js";

const PORT = 14470;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
const PARENT_EXP = "2027-01-01T00:00:00Z";

type DpopKeys = { privateKey: CryptoKey; publicKey: CryptoKey };

const CHILD_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";

let as: BuiltAs;
let asServer: Server;
let clientKey: CryptoKey;
let dpopKeys: DpopKeys;
/** The child actor's confidential-client key + its OWN DPoP key (distinct from the parent's). */
let childClientKey: CryptoKey;
let childDpopKeys: DpopKeys;

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

/** private_key_jwt for the child actor client (@spec #child-client-identity). */
async function childClientAssertion(): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "subagent-invoice-extractor-auth" })
    .setIssuer("subagent-invoice-extractor")
    .setSubject("subagent-invoice-extractor")
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(childClientKey);
}

async function childDpopProof(htu: string, htm: string, extra: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({ htu, htm, ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(childDpopKeys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(childDpopKeys.privateKey);
}

/** POST /token as the child actor (private_key_jwt + child DPoP), with the dpop-nonce retry. */
async function childTokenRequest(params: Record<string, string>): Promise<Response> {
  const htu = `${ISSUER}/token`;
  const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
    fetch(htu, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await childDpopProof(htu, "POST", extra) },
      body: new URLSearchParams({
        ...params,
        client_assertion: await childClientAssertion(),
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
async function issueParentMission(): Promise<{ missionId: string; refreshToken: string; accessToken: string }> {
  const jar = new Map<string, string>();
  const verifier = "child-endpoint-verifier-0123456789-0123456789-0123";
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
  ).toString("base64url");
  const intent = JSON.stringify({
    goal: "Pay Acme invoices and send remittance",
    resources: [RESOURCE],
    expires_at: PARENT_EXP,
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
      authorization_details: JSON.stringify(parentAuthority()),
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
  return { missionId: claims.mission.id, refreshToken: body.refresh_token, accessToken: body.access_token };
}

/** POST /token token-exchange with a DPoP proof signed by an ARBITRARY key (nonce retry). */
async function tokenRequestWithDpop(dpop: DpopKeys, params: Record<string, string>): Promise<Response> {
  const htu = `${ISSUER}/token`;
  const proof = async (extra: Record<string, unknown>): Promise<string> =>
    new SignJWT({ htu, htm: "POST", ...extra })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(dpop.publicKey) })
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .sign(dpop.privateKey);
  const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
    fetch(htu, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await proof(extra) },
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

/**
 * Create a Child Mission via the RFC 8693 token exchange. `subject_token` is the
 * parent's Mission-bound ACCESS token (bound to `dpopKeys`); possession is proven
 * by a DPoP proof over that SAME key (verifySubjectPossession: presenter jkt ===
 * subject_token cnf.jkt). The parent is resolved FROM `subject_token`; `parent` is
 * a non-authoritative cross-check. No refresh token is involved (#448).
 */
async function createChildViaExchange(fields: {
  subjectToken: string;
  childActor: Record<string, unknown>;
  parent?: string;
  intent?: unknown;
  actorToken?: string;
}): Promise<Response> {
  const params: Record<string, string> = {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: fields.subjectToken,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    requested_token_type: JWT_TOKEN_TYPE,
    mission_intent: JSON.stringify(
      fields.intent ?? {
        goal: "Extract Acme invoices",
        resources: [RESOURCE],
        expires_at: PARENT_EXP,
      },
    ),
    authorization_details: JSON.stringify(childAuthority()),
    child_actor: JSON.stringify(fields.childActor),
  };
  if (fields.parent !== undefined) params.parent = fields.parent;
  if (fields.actorToken !== undefined) params.actor_token = fields.actorToken;
  return tokenRequest(params);
}

let parent: { missionId: string; refreshToken: string };

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    // subagent-extractor / subagent-invoice-extractor are shipped in config;
    // these are the endpoint suite's additional child actors.
    actorProfiles: aiAgents("subagent-actor-ok", "subagent-other", "subagent-a", "subagent-b"),
  });
  asServer = as.provider.listen(PORT);
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  dpopKeys = await generateKeyPair("ES256", { extractable: true });
  childClientKey = (await importJWK(as.childClientJwk as never, "ES256")) as CryptoKey;
  childDpopKeys = await generateKeyPair("ES256", { extractable: true });
  parent = await issueParentMission();
});

afterAll(() => {
  asServer?.close();
});

describe("child Mission creation on the AS surface (@spec child-delegation#child-creation)", () => {
  it("token exchange (subject_token = parent access token) creates a Child Mission and returns a child-bound grant", async () => {
    const res = await createChildViaExchange({
      subjectToken: parent.accessToken,
      parent: parent.missionId,
      childActor: { sub: "subagent-extractor", sub_profile: "ai_agent" },
    });
    const body = (await res.json()) as {
      access_token?: string;
      issued_token_type?: string;
      token_type?: string;
      mission_id?: string;
      parent?: { id: string; depth: number };
    };
    expect(res.status, JSON.stringify(body)).toBe(200);
    // @spec #child-creation, RFC 8693 Section 2.2.1 — the response is a
    // token-exchange-shaped issuance: no `grant_type` (a token response never
    // carries one).
    expect(body).not.toHaveProperty("grant_type");
    expect(body.issued_token_type).toBe("urn:ietf:params:oauth:token-type:jwt");
    expect(body.token_type).toBe("N_A");
    expect(body.parent?.id).toBe(parent.missionId);

    // The Child Mission is committed, active, and lineage-linked.
    const child = as.kernel.get(body.mission_id as string);
    expect(child?.state).toBe("active");
    expect(child?.parent?.id).toBe(parent.missionId);
    // @spec #child-client-identity — client_id == the child actor's sub.
    expect(child?.client_id).toBe("subagent-extractor");

    // @spec #child-client-identity / #parent-member — the grant reference carries
    // the parent lineage and an authority_hash over the CHILD set (not the parent's).
    const a = decodeJwt(body.access_token as string) as {
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

  it("rejects an unauthenticated creation request at /token (client auth identifies the acting agent; @spec #request-processing step 1)", async () => {
    // No client_assertion: oidc-provider's client-auth middleware rejects BEFORE
    // the token-exchange handler runs (client auth precedes the grant dispatch).
    const res = await fetch(`${ISSUER}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        subject_token: parent.accessToken,
        subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
        requested_token_type: JWT_TOKEN_TYPE,
      }).toString(),
    });
    const body = (await res.json()) as { error?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    // No client_id and no client_assertion: the client-auth layer rejects before
    // the grant handler (no authentication mechanism was provided).
    expect(body.error).toBe("invalid_request");
  });

  it("parent cross-check != the Mission resolved from subject_token -> parent_mismatch (invalid_grant)", async () => {
    const res = await createChildViaExchange({
      subjectToken: parent.accessToken,
      parent: "msn_not-the-resolved-parent",
      childActor: { sub: "subagent-extractor", sub_profile: "ai_agent" },
    });
    const body = (await res.json()) as { error?: string; mission_denial_reason?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
    // @spec #denial-reasons — the symbolic reason rides in mission_denial_reason.
    expect(body.mission_denial_reason).toBe("parent_mismatch");
  });

  it("a refresh token as subject_token is rejected (#448: a reusable bearer refresh credential MUST NOT carry possession)", async () => {
    // The load-bearing possession invariant: only the parent's sender-constrained
    // Mission ACCESS token may carry possession. Presenting the parent's refresh
    // token as subject_token is refused at verification order step 1.
    const res = await tokenRequest({
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      subject_token: parent.refreshToken,
      subject_token_type: REFRESH_TOKEN_TOKEN_TYPE,
      requested_token_type: JWT_TOKEN_TYPE,
      mission_intent: JSON.stringify({
        goal: "Extract Acme invoices",
        resources: [RESOURCE],
        expires_at: PARENT_EXP,
      }),
      authorization_details: JSON.stringify(childAuthority()),
      child_actor: JSON.stringify({ sub: "subagent-extractor", sub_profile: "ai_agent" }),
    });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toContain("refresh token");
  });

  it("the parent access token is not consumed: two child creations under the same subject_token both succeed, and neither derives the parent (NON-derivation)", async () => {
    // A dedicated parent so this suite's fan-out cannot disturb other tests.
    const p = await issueParentMission();
    const derivBefore = as.kernel.get(p.missionId)?.derivation_count;

    // Two child creations under the SAME parent access token both succeed: the
    // subject_token is a proof of possession, not a single-use credential.
    for (const sub of ["subagent-a", "subagent-b"]) {
      const res = await createChildViaExchange({
        subjectToken: p.accessToken,
        parent: p.missionId,
        childActor: { sub, sub_profile: "ai_agent" },
      });
      expect(res.status, await res.clone().text()).toBe(200);
    }

    // @spec #child-creation NON-derivation: child creation makes a NEW Mission and
    // MUST NOT consume the parent's derivation counter (createChildMission uses the
    // active-state check, not gateDerivation).
    expect(as.kernel.get(p.missionId)?.derivation_count).toBe(derivBefore);
  });

  it("possession: an exchange DPoP proof from a key other than the subject_token cnf is refused (invalid_grant)", async () => {
    const wrongDpop = await generateKeyPair("ES256", { extractable: true });
    const res = await tokenRequestWithDpop(wrongDpop, {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      subject_token: parent.accessToken,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      requested_token_type: JWT_TOKEN_TYPE,
      mission_intent: JSON.stringify({
        goal: "Extract Acme invoices",
        resources: [RESOURCE],
        expires_at: PARENT_EXP,
      }),
      authorization_details: JSON.stringify(childAuthority()),
      child_actor: JSON.stringify({ sub: "subagent-extractor", sub_profile: "ai_agent" }),
    });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toContain("confirmation key");
  });

  it("possession: an exchange with no DPoP proof is refused (invalid_dpop_proof)", async () => {
    const res = await fetch(`${ISSUER}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        subject_token: parent.accessToken,
        subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
        requested_token_type: JWT_TOKEN_TYPE,
        mission_intent: JSON.stringify({
          goal: "Extract Acme invoices",
          resources: [RESOURCE],
          expires_at: PARENT_EXP,
        }),
        authorization_details: JSON.stringify(childAuthority()),
        child_actor: JSON.stringify({ sub: "subagent-extractor", sub_profile: "ai_agent" }),
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
    const body = (await res.json()) as { error?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_dpop_proof");
  });

  it("actor_token (verification step 4): a presenter-key-signed actor_token whose cnf matches the presenter key is carried and the child is created", async () => {
    // Phase 1 CARRIES actor_token; it does NOT restructure the act chain (#433).
    // The actor_token MUST be signed by the presenter's DPoP key and its cnf.jkt
    // MUST equal the presenter key. The acting agent itself is identified by client
    // auth (ap-agent); actor_token is an additional sender-constraint on the key.
    const p = await issueParentMission();
    const jkt = await calculateJwkThumbprint(await exportJWK(dpopKeys.publicKey));
    const actorToken = await new SignJWT({ cnf: { jkt } })
      .setProtectedHeader({ alg: "ES256" })
      .setIssuer("ap-agent")
      .setSubject("ap-agent")
      .setIssuedAt()
      .setExpirationTime("2m")
      .sign(dpopKeys.privateKey);
    const res = await createChildViaExchange({
      subjectToken: p.accessToken,
      parent: p.missionId,
      childActor: { sub: "subagent-actor-ok", sub_profile: "ai_agent" },
      actorToken,
    });
    const body = (await res.json()) as { mission_id?: string; error?: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(body.mission_id).toBeTruthy();
  });

  it("actor_token (verification step 4): an actor_token whose cnf is NOT the presenter key is refused (invalid_grant)", async () => {
    const otherKey = await generateKeyPair("ES256", { extractable: true });
    const otherJkt = await calculateJwkThumbprint(await exportJWK(otherKey.publicKey));
    // Signed with the PRESENTER key (so verification against the DPoP key succeeds),
    // but naming a DIFFERENT key in cnf -> the sender-constraint check fails.
    const actorToken = await new SignJWT({ cnf: { jkt: otherJkt } })
      .setProtectedHeader({ alg: "ES256" })
      .setIssuer("ap-agent")
      .setSubject("ap-agent")
      .setIssuedAt()
      .setExpirationTime("2m")
      .sign(dpopKeys.privateKey);
    const res = await createChildViaExchange({
      subjectToken: parent.accessToken,
      parent: parent.missionId,
      childActor: { sub: "subagent-extractor", sub_profile: "ai_agent" },
      actorToken,
    });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toContain("not sender-constrained to the presenter key");
  });

  it("discovery advertises mission_child_delegation_supported (@spec #discovery)", async () => {
    const res = await fetch(`${ISSUER}/.well-known/openid-configuration`);
    const meta = (await res.json()) as Record<string, unknown>;
    expect(res.status).toBe(200);
    expect(meta.mission_child_delegation_supported).toBe(true);
    // Sanity: the sibling attenuation flag is unaffected.
    expect(meta.mission_attenuation_supported).toBe(true);
  });

});

/**
 * @spec child-delegation#child-client-identity, #worked-example — PR4b: the child
 * actor is now a registered OAuth client (subagent-invoice-extractor) and redeems
 * the child-bound RFC 7523 JWT authorization grant AS ITSELF at /token, receiving
 * a DPoP-bound child access token. A dedicated parent isolates these children
 * from the creation-suite's fan-out accounting.
 */
describe("PR4b: child redeems the child-bound grant AS ITSELF at /token (@spec #child-client-identity)", () => {
  let p: { missionId: string; refreshToken: string };
  const remoteJwks = createRemoteJWKSet(new URL(`${ISSUER}/jwks`));

  /** Create a Child Mission under `p` and return its id + the child-bound assertion. */
  async function makeChild(actor: Record<string, unknown>): Promise<{ missionId: string; assertion: string }> {
    const res = await createChildViaExchange({
      subjectToken: p.accessToken,
      parent: p.missionId,
      childActor: actor,
    });
    const body = (await res.json()) as { mission_id?: string; access_token?: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    return { missionId: body.mission_id as string, assertion: body.access_token as string };
  }

  beforeAll(async () => {
    p = await issueParentMission();
  });

  it("happy path: child redeems its assertion -> 200 DPoP-bound child token carrying the child mission", async () => {
    const { missionId, assertion } = await makeChild({ sub: "subagent-invoice-extractor", sub_profile: "ai_agent" });

    // ADVISOR CHECK 1 (single-gate): derivation_count is 0 pre-redemption.
    expect(as.kernel.get(missionId)?.derivation_count).toBe(0);
    expect(as.kernel.get(missionId)?.grant_id).toBeNull();

    const res = await childTokenRequest({ grant_type: CHILD_GRANT_TYPE, assertion });
    const body = (await res.json()) as {
      access_token?: string;
      token_type?: string;
      scope?: string;
      expires_in?: number;
      authorization_details?: unknown;
      error?: string;
      error_description?: string;
    };
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(body.token_type).toBe("DPoP");
    expect(body.scope).toBe("payments");
    expect(res.headers.get("cache-control")).toContain("no-store");

    // The token is a real, resource-bound JWT (verifies on the AS jwks_uri).
    const jwt = body.access_token as string;
    const { payload } = await jwtVerify(jwt, remoteJwks, { issuer: ISSUER, audience: RESOURCE });
    expect(payload.aud).toBe(RESOURCE);
    expect(payload.sub).toBe("alice"); // Mission subject, inherited from the parent
    expect(payload.client_id).toBe("subagent-invoice-extractor"); // the child actor, AS ITSELF

    // cnf.jkt is the CHILD's OWN DPoP key (independently derived, not the parent's).
    const childJkt = await calculateJwkThumbprint(await exportJWK(childDpopKeys.publicKey));
    expect((payload.cnf as { jkt?: string })?.jkt).toBe(childJkt);

    // authorization_details deep-equals the CHILD Authority Set (the record is authoritative).
    const child = as.kernel.get(missionId);
    expect(body.authorization_details).toEqual(child?.authority_set);
    expect(payload.authorization_details).toEqual(child?.authority_set);

    // ADVISOR CHECK 1 (mission-claim presence): the claim MUST be present. It is
    // absent (silently) if the Grant->findByGrant binding is keyed wrong, so this
    // is asserted BEFORE drilling into its members.
    const mission = payload.mission as
      | { id?: string; authority_hash?: string; parent?: { id?: string; depth?: number } }
      | undefined;
    expect(mission, "child mission claim must be present on the token").toBeDefined();
    expect(mission?.id).toBe(missionId);
    // The child hash commits the CHILD set; it differs from the parent's.
    expect(mission?.authority_hash).toBe(child?.authority_hash);
    expect(mission?.authority_hash).not.toBe(as.kernel.get(p.missionId)?.authority_hash);
    // The child mission claim carries the parent lineage member.
    expect(mission?.parent?.id).toBe(p.missionId);
    expect(mission?.parent?.depth).toBe(1);

    // ADVISOR CHECK 1 (binding + single gate): findByGrant resolves to THIS child at
    // the moment extraTokenClaims fired (proven by the mission claim above), and the
    // derivation_count incremented EXACTLY ONCE (0 -> 1; no double-gate).
    const boundGrant = as.kernel.get(missionId)?.grant_id as string;
    expect(boundGrant).toBeTruthy();
    expect(as.kernel.findByGrant(boundGrant)?.id).toBe(missionId);
    expect(as.kernel.get(missionId)?.derivation_count).toBe(1);
  });

  it("ADVISOR CHECK 2 (reuse branch): the same assertion redeems again via grant reuse (no duplicate Grant)", async () => {
    const { missionId, assertion } = await makeChild({ sub: "subagent-invoice-extractor", sub_profile: "ai_agent" });

    const first = await childTokenRequest({ grant_type: CHILD_GRANT_TYPE, assertion });
    const firstBody = (await first.json()) as { access_token?: string };
    expect(first.status, JSON.stringify(firstBody)).toBe(200);
    const grantAfterFirst = as.kernel.get(missionId)?.grant_id as string;
    expect(grantAfterFirst).toBeTruthy();
    expect(as.kernel.get(missionId)?.derivation_count).toBe(1);

    // Redeem the SAME assertion a second time within its lifetime.
    const second = await childTokenRequest({ grant_type: CHILD_GRANT_TYPE, assertion });
    const secondBody = (await second.json()) as { access_token?: string };
    expect(second.status, JSON.stringify(secondBody)).toBe(200);

    // Same mission on both tokens; the second went through the record.grant_id REUSE
    // branch (grant_id unchanged -> no duplicate Grant was created).
    const m1 = decodeJwt(firstBody.access_token as string) as { mission: { id: string } };
    const m2 = decodeJwt(secondBody.access_token as string) as { mission: { id: string } };
    expect(m2.mission.id).toBe(m1.mission.id);
    expect(as.kernel.get(missionId)?.grant_id).toBe(grantAfterFirst);
    // Exactly one derivation increment per redemption (no unexpected extra jump).
    expect(as.kernel.get(missionId)?.derivation_count).toBe(2);
  });

  it("ADVISOR CHECK 3 (security gate): a non-named redeemer fails at the client_id-mismatch gate", async () => {
    // A child whose actor is NOT the authenticating client. Creation succeeds
    // (policy's allowed_child_actors matches sub_profile: ai_agent), so the
    // assertion names client_id = "subagent-other".
    const other = await makeChild({ sub: "subagent-other", sub_profile: "ai_agent" });

    // subagent-invoice-extractor (jwt-bearer-allowed -> reaches the handler)
    // presents subagent-other's assertion. This is the load-bearing gate: the
    // authenticated client != the assertion's client_id.
    const res = await childTokenRequest({ grant_type: CHILD_GRANT_TYPE, assertion: other.assertion });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
    // Assert THIS gate specifically (several gates return invalid_grant).
    expect(body.error_description).toContain("does not match the authenticated client");
  });

  it("ADVISOR CHECK 3 (parent cannot redeem): the parent client is not even allowed the grant type", async () => {
    // The parent (ap-agent) conveys the child assertion but cannot redeem it. It
    // does not reach the client_id gate: oidc-provider rejects at the client
    // grant_types allowlist first (ap-agent has no jwt-bearer grant type). This is
    // the STRONGER real boundary, and it is why the parent can safely convey the
    // assertion (@spec #child-client-identity).
    const { assertion } = await makeChild({ sub: "subagent-invoice-extractor", sub_profile: "ai_agent" });
    const res = await tokenRequest({ grant_type: CHILD_GRANT_TYPE, assertion });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toContain("not allowed for this client");
  });

  it("ancestor gate: a revoked parent cascades the child, so redemption fails invalid_grant", async () => {
    // Dedicated parent: revoke cascades to ITS children only (@spec #cascade).
    const dedicated = await issueParentMission();
    const created = await createChildViaExchange({
      subjectToken: dedicated.accessToken,
      parent: dedicated.missionId,
      childActor: { sub: "subagent-invoice-extractor", sub_profile: "ai_agent" },
    });
    const { access_token: assertion } = (await created.json()) as { access_token: string };
    expect(created.status).toBe(200);

    // Revoke the parent BEFORE redemption: the child is cascaded terminal and the
    // ancestor-active gate refuses the derivation.
    as.kernel.transition(dedicated.missionId, "revoke");

    const res = await childTokenRequest({ grant_type: CHILD_GRANT_TYPE, assertion });
    const body = (await res.json()) as { error?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
  });
});
