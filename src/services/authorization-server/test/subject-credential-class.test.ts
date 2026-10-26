/**
 * @spec #831 (role binding): the credential class of a `subject_token`. Every
 * Token Exchange path that takes a Mission access token as its subject
 * verifies it under the AS's access-token signing key alone and as an RFC
 * 9068 `at+jwt`, so no other credential this AS signs under the same issuer
 * (a transaction token above all, which carries a `mission` claim and a `cnf`
 * of its own) is accepted in its place.
 *
 * One AS, built from a key ring this suite creates so it holds every role's
 * private key, serves the seven paths: the five that resolve their subject
 * through `verifySubjectPossession` (child creation, Expansion, the Dispatch
 * Handoff, designation, the delegation handle) and the two that verify it
 * themselves (the delegated exchange, which redeems a designation, and the
 * async-delegation transport, which takes a delegation handle). Each path is
 * driven four ways, each from a fresh legitimate credential:
 *
 * - a real transaction token, minted by the transaction endpoint for a real
 *   Mission and bound to the presenter's key;
 * - the legitimate credential's claims, typed `at+jwt`, re-signed under the
 *   AS's transaction-token key: the key-role check alone refuses it;
 * - the same claims under the access-token key, typed as a transaction
 *   token: the token-type check alone refuses it;
 * - the legitimate credential itself, which still succeeds.
 *
 * The ring is rotated before the AS starts (#831 B2): the access-token and
 * transaction-token roles sign under generation 2, with generation 1 in
 * overlap, so every artifact here carries its role's active `kid`.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AccessRequestService } from "@mission/access-request";
import { CANONICAL_RESOURCE, demoReconciliationTemplate, DEV_SERVICE_TOKEN, TOPOLOGY } from "@mission/demo-data";
import {
  calculateJwkThumbprint,
  createLocalJWKSet,
  type CryptoKey,
  decodeJwt,
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  importJWK,
  type JWK,
  SignJWT,
} from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { floorApprovalHeaders, renderedRevision, TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";
import { delegationHandleParams } from "./delegation-handle.helper.js";
import { confirmRing } from "./ring-confirm.helper.js";
import {
  ACCESS_TOKEN_TOKEN_TYPE,
  JWT_TOKEN_TYPE,
  TOKEN_EXCHANGE_GRANT_TYPE,
} from "../src/adapters/continuation-grant.js";
import { MISSION_DISPATCH_GRANT_TYPE } from "../src/adapters/provider.js";
import {
  activateSigningKeyGeneration,
  ALL_PROVIDER_CAPABILITIES,
  ApprovalSessionStore,
  type AuthorityEntry,
  buildAuthorizationServer,
  type BuiltAs,
  type ChallengeIssuers,
  initSigningKeyRing,
  MISSION_TXN_TOKEN_TYP,
  missionResourceAccessProfile,
  OperationProfileRegistry,
  stageSigningKeyGeneration,
  TXN_CHALLENGE_TYP,
} from "../src/index.js";
import { type AsSigningKeys, loadSigningKeyRing } from "../src/kernel/signing-key-ring.js";

const PORT = 14610;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
const SUBAGENT = "subagent-invoice-extractor";
const FAR = "2027-01-01T00:00:00Z";
const ROLES = {
  asToken: TOPOLOGY.keys.asToken,
  asStatus: TOPOLOGY.keys.asStatus,
  asTxn: TOPOLOGY.keys.asTxn,
  asContinuation: TOPOLOGY.keys.asContinuation,
};
/** The fragments of the two credential-class refusals' `error_description`. */
const WRONG_KEY = "not signed by this AS's access-token key";
const WRONG_TYPE = "not an access token";
const CREDENTIAL_CLASS = /not signed by this AS's access-token key|not an access token/;

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
type Body = Record<string, unknown>;
type Answer = { status: number; body: Body };
type Client = "ap-agent" | typeof SUBAGENT;

const sessions = new ApprovalSessionStore();
const dirs: string[] = [];
let as: BuiltAs;
let server: Server;
let ring: AsSigningKeys;
let ars: AccessRequestService;
let rsTxnKeys: Keys;
let presenter: Keys;
let presenterJkt: string;
let subagentDpop: Keys;
const clientKeys = new Map<Client, CryptoKey>();
/** A real transaction token, bound to `presenter`, for a real Mission. */
let transactionToken: string;

const entry = (actions: string[], extra: Record<string, unknown> = {}) => ({
  type: "mission_resource_access",
  resource: RESOURCE,
  actions,
  constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  ...extra,
});
const delegable = () => entry(["payments:invoice.read"], { delegation: { max_depth: 2, allowed_delegates: [{ sub_profile: "ai_agent" }] } });

function assertion(client: Client, audience = ISSUER): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: `${client}-auth` })
    .setIssuer(client)
    .setSubject(client)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(clientKeys.get(client) as CryptoKey);
}

async function proof(keys: Keys, htu: string, extra: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({ htu, htm: "POST", ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}

/** POST /token as `client`, proving `keys`, with the dpop-nonce retry. */
async function token(client: Client, keys: Keys, params: Record<string, string>): Promise<Answer> {
  const htu = `${ISSUER}/token`;
  const send = async (extra: Record<string, unknown> = {}) =>
    fetch(htu, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await proof(keys, htu, extra) },
      body: new URLSearchParams({
        ...params,
        client_assertion: await assertion(client),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return { status: res.status, body: (await res.json()) as Body };
}

function storeCookies(res: Response, jar: Map<string, string>): void {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
  }
}
const cookieHeader = (jar: Map<string, string>) => [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");

/** PAR, approval and code exchange: an active Mission and its access token, bound to `presenter`. */
async function mission(authority: unknown[]): Promise<{ missionId: string; accessToken: string }> {
  const jar = new Map<string, string>();
  const verifier = "subject-credential-class-verifier-0123456789-0123456789";
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");
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
      mission_intent: JSON.stringify({ intent: { goal: "Reconcile Acme invoices", target_resources: [RESOURCE], expires_at: FAR } }),
      authorization_details: JSON.stringify(authority),
      client_assertion: await assertion("ap-agent"),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const { request_uri } = (await par.json()) as { request_uri: string };
  let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`, { redirect: "manual" });
  storeCookies(res, jar);
  let location = res.headers.get("location") as string;
  const uid = location.split("/interaction/")[1] as string;
  const headers = { ...floorApprovalHeaders(sessions, uid, cookieHeader(jar)), "content-type": "application/json" };
  const render_revision = await renderedRevision(ISSUER, uid, headers);
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers,
    body: JSON.stringify({ decision: "approve", render_revision }),
  });
  storeCookies(res, jar);
  location = res.headers.get("location") as string;
  while (location?.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader(jar) } });
    storeCookies(res, jar);
    location = res.headers.get("location") as string;
  }
  const code = new URL(location).searchParams.get("code") as string;
  const tok = await token("ap-agent", presenter, {
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier,
    resource: RESOURCE,
  });
  expect(tok.status, JSON.stringify(tok.body)).toBe(200);
  const accessToken = tok.body.access_token as string;
  return { missionId: (decodeJwt(accessToken).mission as { id: string }).id, accessToken };
}

/** POST /transaction as ap-agent, proving `presenter`. */
async function postTransaction(payload: Record<string, string>): Promise<Answer> {
  const htu = `${ISSUER}/transaction`;
  const res = await fetch(htu, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", dpop: await proof(presenter, htu) },
    body: new URLSearchParams({
      client_id: "ap-agent",
      client_assertion: await assertion("ap-agent"),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      ...payload,
    }).toString(),
  });
  return { status: res.status, body: (await res.json()) as Body };
}

/** An initial transaction submission: a challenge for `missionId`'s remittance entry, presenting `subjectToken`. */
async function initiateTransaction(subjectToken: string, missionId: string): Promise<Answer> {
  const requested = (as.kernel.get(missionId)?.authority_set as AuthorityEntry[])
    .filter((e) => e.actions.includes("payments:remittance.send"))
    .map(({ capability_sources: _provenance, ...e }) => ({ ...e, actions: ["payments:remittance.send"] }));
  const challenge = await new SignJWT({
    txn: `txn_${crypto.randomUUID()}`,
    authorization_details: requested,
    reason: "over-cap remittance requires approval",
    parameter_digest: "sha-256:aa11bb22cc33dd44",
    mission: decodeJwt(subjectToken).mission,
    cnf: { jkt: presenterJkt },
  })
    .setProtectedHeader({ alg: "ES256", kid: "rs-txn", typ: TXN_CHALLENGE_TYP })
    .setIssuer(RESOURCE)
    .setAudience(ISSUER)
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .setExpirationTime("300s")
    .sign(rsTxnKeys.privateKey);
  return postTransaction({
    transaction_challenge: challenge,
    subject_token: subjectToken,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
  });
}

/** A transaction token from the transaction endpoint: challenge, submission, approval, poll. */
async function transactionTokenFor(accessToken: string, missionId: string): Promise<string> {
  const init = await initiateTransaction(accessToken, missionId);
  expect(init.status, JSON.stringify(init.body)).toBe(200);
  const task = ars.pending()[0];
  expect(await ars.adjudicate(task?.id as string, "approve", "bob")).not.toBeNull();
  const polled = await postTransaction({ transaction_authorization_id: init.body.transaction_authorization_id as string });
  expect(polled.status, JSON.stringify(polled.body)).toBe(200);
  return polled.body.access_token as string;
}

/** `credential`'s claims re-signed under `role`'s ring key, typed `typ`. */
async function resigned(credential: string, role: "asToken" | "asTxn", typ: string): Promise<string> {
  return new SignJWT(decodeJwt(credential) as Body)
    .setProtectedHeader({ alg: ROLES[role].alg, kid: ring[role].kid, typ })
    .sign(ring[role].privateKey);
}

/** The key-role witness: a legitimate credential's claims, typed `at+jwt`, under the transaction-token key. */
const underAnotherRole = (credential: string) => resigned(credential, "asTxn", "at+jwt");
/** The token-type witness: the same claims under the access-token key, typed as a transaction token. */
const asAnotherType = (credential: string) => resigned(credential, "asToken", MISSION_TXN_TOKEN_TYP);

/** One Token Exchange path: its legitimate subject credential, the request, and what success looks like. */
interface Path {
  name: string;
  /** The path's code for an unacceptable subject_token (RFC 8693 Section 2.2.2; the Dispatch Handoff's own). */
  refusal: "invalid_request" | "invalid_grant";
  legitimate: () => Promise<string>;
  send: (subjectToken: string) => Promise<Answer>;
  succeeded: (answer: Answer) => void;
}

const exchange = (subjectToken: string, extra: Record<string, string>) => ({
  grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
  subject_token: subjectToken,
  subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
  ...extra,
});

async function designation(): Promise<string> {
  const { accessToken } = await mission([delegable()]);
  const answer = await token("ap-agent", presenter, exchange(accessToken, { requested_token_type: ACCESS_TOKEN_TOKEN_TYPE, audience: SUBAGENT }));
  expect(answer.status, JSON.stringify(answer.body)).toBe(200);
  return answer.body.access_token as string;
}

async function delegationHandle(): Promise<string> {
  const { accessToken } = await mission([entry(["payments:invoice.read", "payments:remittance.send"])]);
  const answer = await token("ap-agent", presenter, delegationHandleParams(accessToken, "ap-agent"));
  expect(answer.status, JSON.stringify(answer.body)).toBe(200);
  return answer.body.access_token as string;
}

async function dispatchedInstance(): Promise<string> {
  const created = await fetch(`${ISSUER}/templates`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
    body: JSON.stringify({ ...demoReconciliationTemplate(ISSUER), approval_event_id: `class-tmpl-${crypto.randomUUID()}` }),
  });
  const { template_id } = (await created.json()) as { template_id: string };
  const answer = await token("ap-agent", presenter, {
    grant_type: MISSION_DISPATCH_GRANT_TYPE,
    template_id,
    mission_intent: JSON.stringify({ intent: { goal: "reconcile Acme invoices", target_resources: [RESOURCE], expires_at: FAR } }),
    dispatch_event_id: `class-evt-${crypto.randomUUID()}`,
  });
  expect(answer.status, JSON.stringify(answer.body)).toBe(200);
  return answer.body.access_token as string;
}

const PATHS: Path[] = [
  {
    name: "child creation",
    refusal: "invalid_request",
    legitimate: async () => (await mission([entry(["payments:invoice.read", "payments:remittance.send"])])).accessToken,
    send: (subjectToken) =>
      token(
        "ap-agent",
        presenter,
        exchange(subjectToken, {
          requested_token_type: JWT_TOKEN_TYPE,
          creation_request_id: crypto.randomUUID(),
          login_hint: "alice",
          mission_intent: JSON.stringify({ intent: { goal: "Extract Acme invoices", target_resources: [RESOURCE], expires_at: FAR } }),
          authorization_details: JSON.stringify([entry(["payments:invoice.read"])]),
          child_actor: JSON.stringify({ sub: "subagent-extractor", sub_profile: "ai_agent" }),
        }),
      ),
    succeeded: ({ status, body }) => {
      expect(status, JSON.stringify(body)).toBe(200);
      expect(typeof body.mission_id).toBe("string");
    },
  },
  {
    name: "Expansion",
    refusal: "invalid_request",
    legitimate: async () => (await mission([entry(["payments:invoice.read"])])).accessToken,
    send: (subjectToken) =>
      token(
        "ap-agent",
        presenter,
        exchange(subjectToken, {
          requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
          login_hint: "alice",
          mission_intent: JSON.stringify({ intent: { goal: "Widen to add remittance", target_resources: [RESOURCE], expires_at: FAR } }),
          authorization_details: JSON.stringify([entry(["payments:invoice.read", "payments:remittance.send"])]),
          creation_request_id: crypto.randomUUID(),
          completion_mode: "deferred",
        }),
      ),
    // A widening initiation defers: authorization_pending with a deferral code.
    succeeded: ({ status, body }) => {
      expect(status, JSON.stringify(body)).toBe(400);
      expect(body.error).toBe("authorization_pending");
      expect(typeof body.deferral_code).toBe("string");
    },
  },
  {
    name: "the Dispatch Handoff",
    refusal: "invalid_grant",
    legitimate: dispatchedInstance,
    send: (subjectToken) =>
      token("ap-agent", presenter, exchange(subjectToken, { requested_token_type: JWT_TOKEN_TYPE, mission_dispatch_handoff: "true" })),
    succeeded: ({ status, body }) => {
      expect(status, JSON.stringify(body)).toBe(200);
      expect(body.issued_token_type).toBe(JWT_TOKEN_TYPE);
      // The handoff grant is signed under the access-token role's active generation (#831 B2).
      expect(decodeProtectedHeader(body.access_token as string).kid).toBe(ring.asToken.kid);
    },
  },
  {
    name: "designation",
    refusal: "invalid_request",
    legitimate: async () => (await mission([delegable()])).accessToken,
    send: (subjectToken) =>
      token("ap-agent", presenter, exchange(subjectToken, { requested_token_type: ACCESS_TOKEN_TOKEN_TYPE, audience: SUBAGENT })),
    succeeded: ({ status, body }) => {
      expect(status, JSON.stringify(body)).toBe(200);
      expect(body.token_type).toBe("N_A");
    },
  },
  {
    name: "the delegation handle",
    refusal: "invalid_request",
    legitimate: async () => (await mission([entry(["payments:invoice.read", "payments:remittance.send"])])).accessToken,
    send: (subjectToken) => token("ap-agent", presenter, delegationHandleParams(subjectToken, "ap-agent")),
    succeeded: ({ status, body }) => {
      expect(status, JSON.stringify(body)).toBe(200);
      expect(decodeJwt(body.access_token as string).aud).toBe("ap-agent");
    },
  },
  {
    name: "the delegated exchange (a designation redeemed)",
    refusal: "invalid_request",
    legitimate: designation,
    send: (subjectToken) =>
      token(SUBAGENT, subagentDpop, exchange(subjectToken, { requested_token_type: ACCESS_TOKEN_TOKEN_TYPE, resource: RESOURCE })),
    succeeded: ({ status, body }) => {
      expect(status, JSON.stringify(body)).toBe(200);
      expect(decodeJwt(body.access_token as string).client_id).toBe(SUBAGENT);
    },
  },
  {
    name: "the async-delegation transport (a delegation handle)",
    refusal: "invalid_request",
    legitimate: delegationHandle,
    send: (subjectToken) =>
      token("ap-agent", presenter, {
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        request_refresh_token: "true",
        subject_token: subjectToken,
        subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
        resource: RESOURCE,
        creation_request_id: crypto.randomUUID(),
        authorization_details: JSON.stringify([entry(["payments:invoice.read"])]),
      }),
    succeeded: ({ status, body }) => {
      expect(status, JSON.stringify(body)).toBe(200);
      expect(typeof body.refresh_token).toBe("string");
    },
  },
];

function refused({ status, body }: Answer, code: Path["refusal"], cause: string | RegExp): void {
  expect(status, JSON.stringify(body)).toBe(400);
  expect(body.error, JSON.stringify(body)).toBe(code);
  expect(body.error_description, JSON.stringify(body)).toMatch(cause);
  expect(body.access_token, JSON.stringify(body)).toBeUndefined();
}

beforeAll(async () => {
  const dir = mkdtempSync(join(tmpdir(), "subject-credential-class-"));
  dirs.push(dir);
  const ringFile = join(dir, "keys", "ring.json");
  await initSigningKeyRing(ringFile, ISSUER, ROLES);
  for (const role of ["asToken", "asTxn"]) await stageSigningKeyGeneration(ringFile, ISSUER, ROLES, role);
  await confirmRing(ringFile, ISSUER, ROLES);
  for (const role of ["asToken", "asTxn"]) {
    await activateSigningKeyGeneration(ringFile, ISSUER, ROLES, role, { minPublishedS: 0 });
  }
  ring = await loadSigningKeyRing(ringFile, ISSUER, ROLES);
  expect([ring.asToken.kid, ring.asTxn.kid]).toEqual(["as-token-2", "as-txn-2"]);

  rsTxnKeys = await generateKeyPair("ES256", { extractable: true });
  const rsTxnPublic = { ...(await exportJWK(rsTxnKeys.publicKey)), kid: "rs-txn", alg: "ES256" } as JWK;
  const challengeIssuers: ChallengeIssuers = new Map([[RESOURCE, { jwks: createLocalJWKSet({ keys: [rsTxnPublic] }), algs: ["ES256"] }]]);
  const arsKeys = await generateKeyPair("ES256", { extractable: true });
  ars = new AccessRequestService({
    pdpJwks: { keys: [] },
    approvalKey: arsKeys.privateKey,
    approvalKid: "ars",
    issuer: "https://ars.test",
    approvalAudience: "https://pdp.test",
    approvalTtlSeconds: 300,
  });

  as = await buildAuthorizationServer({
    issuer: ISSUER,
    signingKeys: { ring: ringFile },
    capabilities: new Set([...ALL_PROVIDER_CAPABILITIES, "delegation"]),
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: sessions,
    transactionAuthorization: {
      challengeIssuers,
      ars,
      operationProfiles: new OperationProfileRegistry().register(RESOURCE, missionResourceAccessProfile()),
      workflowLifetimeSeconds: 600,
      maxTokenLifetimeSeconds: 300,
      freshDecision: async () => ({ decision: "permit" }),
    },
  });
  server = as.provider.listen(PORT);
  clientKeys.set("ap-agent", (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey);
  clientKeys.set(SUBAGENT, (await importJWK(as.childClientJwk as never, "ES256")) as CryptoKey);
  presenter = await generateKeyPair("ES256", { extractable: true });
  presenterJkt = await calculateJwkThumbprint(await exportJWK(presenter.publicKey));
  subagentDpop = await generateKeyPair("ES256", { extractable: true });

  const base = await mission([entry(["payments:invoice.read", "payments:remittance.send"])]);
  transactionToken = await transactionTokenFor(base.accessToken, base.missionId);
}, 60_000);

afterAll(() => {
  server?.close();
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

describe("a subject_token is a Mission access token: the AS's access-token key and the at+jwt type (@spec #831 role binding)", () => {
  it("the fixture's transaction token is a real one: this AS's issuer, its transaction-token key and type, a mission claim and the presenter's cnf", () => {
    const claims = decodeJwt(transactionToken);
    const header = JSON.parse(Buffer.from(transactionToken.split(".")[0] as string, "base64url").toString()) as Body;
    expect(claims.iss).toBe(ISSUER);
    expect(header.kid).toBe(ring.asTxn.kid);
    expect(header.typ).toBe(MISSION_TXN_TOKEN_TYP);
    expect(typeof (claims.mission as { id?: unknown }).id).toBe("string");
    expect((claims.cnf as { jkt?: string }).jkt).toBe(presenterJkt);
  });

  for (const path of PATHS) {
    // A template title, so a ledger citation of one path's case resolves (scripts/test-title-paths.mjs).
    describe(`${path.name}`, () => {
      // Both checks refuse a transaction token, so either alone suffices here;
      // the two witnesses below each isolate one check.
      it("refuses a transaction token presented as the subject_token, as another credential class", async () => {
        refused(await path.send(transactionToken), path.refusal, CREDENTIAL_CLASS);
      });

      it("refuses the legitimate credential's claims, typed at+jwt, under the transaction-token key (key role)", async () => {
        refused(await path.send(await underAnotherRole(await path.legitimate())), path.refusal, WRONG_KEY);
      });

      it("refuses the legitimate credential's claims under the access-token key, typed as a transaction token (token type)", async () => {
        refused(await path.send(await asAnotherType(await path.legitimate())), path.refusal, WRONG_TYPE);
      });

      it("still accepts the legitimate credential", async () => {
        path.succeeded(await path.send(await path.legitimate()));
      });
    });
  }
});

/** `credential`'s claims, under its own type, re-signed under the transaction-token key. */
const sameTypeUnderAnotherRole = (credential: string) =>
  resigned(credential, "asTxn", JSON.parse(Buffer.from(credential.split(".")[0] as string, "base64url").toString()).typ as string);

const JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/** A child-bound grant for the sub-agent, from a real child creation. */
async function childGrant(): Promise<string> {
  const { accessToken } = await mission([entry(["payments:invoice.read", "payments:remittance.send"])]);
  const answer = await token(
    "ap-agent",
    presenter,
    exchange(accessToken, {
      requested_token_type: JWT_TOKEN_TYPE,
      creation_request_id: crypto.randomUUID(),
      login_hint: "alice",
      mission_intent: JSON.stringify({ intent: { goal: "Extract Acme invoices", target_resources: [RESOURCE], expires_at: FAR } }),
      authorization_details: JSON.stringify([entry(["payments:invoice.read"])]),
      child_actor: JSON.stringify({ sub: SUBAGENT, sub_profile: "ai_agent" }),
    }),
  );
  expect(answer.status, JSON.stringify(answer.body)).toBe(200);
  return answer.body.access_token as string;
}

/** A Dispatch Handoff grant naming the sub-agent, from a real dispatched instance. */
async function handoffGrant(): Promise<string> {
  const instance = await dispatchedInstance();
  const answer = await token("ap-agent", presenter, exchange(instance, { requested_token_type: JWT_TOKEN_TYPE, mission_dispatch_handoff: "true" }));
  expect(answer.status, JSON.stringify(answer.body)).toBe(200);
  return answer.body.access_token as string;
}

/** RFC 7662 introspection as the payments resource server. */
async function introspect(tokenValue: string): Promise<Body> {
  const res = await fetch(`${ISSUER}/introspect`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${Buffer.from("rs-payments:dev-introspection-rs-payments").toString("base64")}`,
    },
    body: new URLSearchParams({ token: tokenValue }).toString(),
  });
  expect(res.status).toBe(200);
  return (await res.json()) as Body;
}

describe("the AS's other verifiers and its provider sign and accept only under the access-token key (@spec #831 role binding)", () => {
  it("the transaction endpoint refuses a subject_token typed at+jwt under the transaction-token key, and admits the real one", async () => {
    const { accessToken, missionId } = await mission([entry(["payments:invoice.read", "payments:remittance.send"])]);
    const forged = await initiateTransaction(await sameTypeUnderAnotherRole(accessToken), missionId);
    expect(forged.status, JSON.stringify(forged.body)).toBe(400);
    expect(forged.body.error).toBe("invalid_grant");
    expect(forged.body.error_description).toContain("subject_token did not verify");
    const real = await initiateTransaction(accessToken, missionId);
    expect(real.status, JSON.stringify(real.body)).toBe(200);
    expect(real.body.transaction_authorization_id).toMatch(/^txa_/);
  });

  it("introspection reports an at+jwt under the transaction-token key inactive, and the real access token active", async () => {
    const { accessToken } = await mission([entry(["payments:invoice.read"])]);
    expect(await introspect(await sameTypeUnderAnotherRole(accessToken))).toEqual({ active: false });
    expect((await introspect(accessToken)).active).toBe(true);
  });

  it("a child-bound grant under the transaction-token key is refused at redemption, and the real one redeems", async () => {
    const grant = await childGrant();
    const forged = await token(SUBAGENT, subagentDpop, { grant_type: JWT_BEARER, assertion: await sameTypeUnderAnotherRole(grant) });
    expect(forged.status, JSON.stringify(forged.body)).toBe(400);
    expect(forged.body.error).toBe("invalid_grant");
    expect(forged.body.access_token).toBeUndefined();
    const real = await token(SUBAGENT, subagentDpop, { grant_type: JWT_BEARER, assertion: grant });
    expect(real.status, JSON.stringify(real.body)).toBe(200);
  });

  it("a Dispatch Handoff grant under the transaction-token key is refused at redemption, and the real one redeems", async () => {
    const grant = await handoffGrant();
    const forged = await token(SUBAGENT, subagentDpop, { grant_type: JWT_BEARER, assertion: await sameTypeUnderAnotherRole(grant) });
    expect(forged.status, JSON.stringify(forged.body)).toBe(400);
    expect(forged.body.error).toBe("invalid_grant");
    expect(forged.body.access_token).toBeUndefined();
    const real = await token(SUBAGENT, subagentDpop, { grant_type: JWT_BEARER, assertion: grant });
    expect(real.status, JSON.stringify(real.body)).toBe(200);
  });

  it("the jwks_uri publishes every role's public key, and no private member, though the provider holds the access-token key alone", async () => {
    const meta = (await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json()) as Body;
    // A browser fetches keys cross-origin: the provider's CORS handling stays
    // on the route (the preflight and the GET both answer for the origin).
    const origin = "https://app.example.com";
    const preflight = await fetch(meta.jwks_uri as string, {
      method: "OPTIONS",
      headers: { origin, "access-control-request-method": "GET" },
    });
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get("access-control-allow-origin")).toBe(origin);
    const res = await fetch(meta.jwks_uri as string, { headers: { origin } });
    expect(res.status).toBe(200);
    expect(res.headers.get("access-control-allow-origin")).toBe(origin);
    expect(res.headers.get("vary")).toContain("Origin");
    expect(res.headers.get("content-type")).toContain("application/jwk-set+json");
    const { keys } = (await res.json()) as { keys: Body[] };
    expect(keys.map((k) => k.kid).sort()).toEqual(Object.values(ring).flatMap((r) => r.published.map((k) => k.kid)).sort());
    expect(keys).toHaveLength(6);
    for (const k of keys) {
      for (const priv of ["d", "p", "q", "dp", "dq", "qi"]) expect(k, `${k.kid} ${priv}`).not.toHaveProperty(priv);
    }
  });
});
