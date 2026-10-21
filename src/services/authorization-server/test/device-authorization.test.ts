/**
 * @spec device-authorization (#1202): the reference AS side of Mission Device
 * Authorization over the real AS assembly, with the opt-in
 * `device-authorization` capability on. A client with no redirect submits its
 * Mission Intent at the RFC 8628 device authorization endpoint; the Approver
 * enters the `user_code` on a second user agent, authenticates, confirms the
 * code and decides; the creation commit makes the `device_code` redeemable;
 * the client's poll returns the Mission-bound tokens with `mission_id`,
 * `mission_expires_at` and the granted `authorization_details`.
 *
 * `agent-A1` (public) and `parent-P` (confidential, `private_key_jwt`) are the
 * clients the shipped `acme-people` authority source names, registered here
 * with the device grant. Alice is the Subject; Bob approves for her.
 */

import { type Server } from "node:http";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { decodeJwt, exportJWK, generateKeyPair, importJWK, SignJWT, type CryptoKey, type JWK } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  ALL_PROVIDER_CAPABILITIES,
  ApprovalSessionStore,
  buildAuthorizationServer,
  type BuiltAs,
  IntentError,
  type ProviderCapability,
  registerIntentSubmissionEvidenceType,
  unregisterIntentSubmissionEvidenceType,
} from "../src/index.js";
import { browserApprovalHeaders } from "./approval-fixture.js";

const PORT = 14763;
const ISSUER = `http://localhost:${PORT}`;
const OFF_PORT = 14764;
const OFF_ISSUER = `http://localhost:${OFF_PORT}`;
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource as string;
const READ = [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] }];
const INTENT = { goal: "Reconcile Q3 invoices.", target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" };
const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const PUBLIC = "agent-A1";
const CONFIDENTIAL = "parent-P";
const CLIENT_NAME = "<b>Invoice CLI</b>";
/** A public client registered for no authorization_details type. */
const NO_RAR = "device-no-rar";
const SESSIONS = new ApprovalSessionStore();
const REDIRECT_URI = "http://localhost:9999/cb";
const FORM = { "content-type": "application/x-www-form-urlencoded" };
const ALICE_BY_BOB = { sub: "bob", subject: "alice" };
const CONFIRMED = { decision: "approve", confirm_user_code: true, confirm_started: true };

// A test Intent Submission Evidence type (this file only; the shipped registry
// is empty): a closed {type, assertion} entry whose verification fails for
// the assertion "fail".
const EVIDENCE_TYPE = "urn:test:intent-evidence:device";
registerIntentSubmissionEvidenceType(EVIDENCE_TYPE, {
  validate(entry) {
    if (typeof entry.assertion !== "string" || Object.keys(entry).some((k) => k !== "type" && k !== "assertion")) {
      throw new IntentError("invalid_mission_intent_evidence", "test evidence: {type, assertion} only");
    }
  },
  async verify(input) {
    if (input.entry.assertion === "fail") throw new Error("test evidence: verification failed");
    return { presenter_client: input.presenter.clientId, bound_intent_hash: input.intentHash };
  },
});

const deviceClient = (extra: Record<string, unknown>) => ({
  grant_types: [DEVICE_GRANT, "refresh_token"],
  response_types: [],
  redirect_uris: [],
  authorization_details_types: ["mission_resource_access"],
  ...extra,
});

let as: BuiltAs;
let off: BuiltAs;
let server: Server;
let offServer: Server;
let confidentialKey: CryptoKey;
let strangerKey: CryptoKey;
let agentKey: CryptoKey;

beforeAll(async () => {
  const pair = await generateKeyPair("ES256", { extractable: true });
  confidentialKey = pair.privateKey as CryptoKey;
  const confidentialJwk = { ...(await exportJWK(pair.publicKey)), kid: `${CONFIDENTIAL}-auth`, alg: "ES256", use: "sig" };
  strangerKey = (await generateKeyPair("ES256")).privateKey as CryptoKey;
  const publicClient = deviceClient({ client_id: PUBLIC, client_name: CLIENT_NAME, token_endpoint_auth_method: "none" });
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    approvalSessions: SESSIONS,
    capabilities: new Set<ProviderCapability>([...ALL_PROVIDER_CAPABILITIES, "device-authorization"]),
    testClients: [
      publicClient,
      // Registered for the authorization-code flow too, so a browser can hold
      // a provider session and grant for it from an earlier approval.
      deviceClient({
        client_id: CONFIDENTIAL,
        token_endpoint_auth_method: "private_key_jwt",
        token_endpoint_auth_signing_alg: "ES256",
        jwks: { keys: [confidentialJwk] },
        grant_types: [DEVICE_GRANT, "authorization_code", "refresh_token"],
        response_types: ["code"],
        redirect_uris: [REDIRECT_URI],
      }),
      deviceClient({
        client_id: NO_RAR,
        token_endpoint_auth_method: "none",
        grant_types: [DEVICE_GRANT, "authorization_code"],
        response_types: ["code"],
        redirect_uris: [REDIRECT_URI],
        authorization_details_types: [],
      }),
    ],
  });
  server = as.provider.listen(PORT);
  agentKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  // The default assembly: no capability set, so the opt-in capability is off.
  off = await buildAuthorizationServer({ issuer: OFF_ISSUER, approvalSessions: SESSIONS, testClients: [publicClient] });
  offServer = off.provider.listen(OFF_PORT);
});

afterAll(() => {
  server?.close();
  offServer?.close();
  unregisterIntentSubmissionEvidenceType(EVIDENCE_TYPE);
});

type Jar = Map<string, string>;
const cookieOf = (jar: Jar) => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
const keep = (jar: Jar, res: Response) => {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
  }
};
const hidden = (html: string, name: string): string => {
  const m = new RegExp(`name="${name}" value="([^"]*)"`).exec(html);
  if (!m) throw new Error(`no ${name} input in ${html.slice(0, 400)}`);
  return m[1] as string;
};

const assertion = (client: string, key: CryptoKey, aud = ISSUER) =>
  new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: `${client}-auth` })
    .setIssuer(client)
    .setSubject(client)
    .setAudience(aud)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(key);

/** The client's own authentication, or its `client_id` alone when public. */
async function clientAuth(client: string): Promise<Record<string, string>> {
  return client === CONFIDENTIAL
    ? { client_assertion: await assertion(CONFIDENTIAL, confidentialKey), client_assertion_type: JWT_BEARER }
    : { client_id: client };
}

async function postForm(url: string, pairs: [string, string][]): Promise<{ status: number; body: Record<string, unknown> }> {
  const body = new URLSearchParams();
  for (const [k, v] of pairs) body.append(k, v);
  const res = await fetch(url, { method: "POST", headers: FORM, body: body.toString() });
  const text = await res.text();
  try {
    return { status: res.status, body: JSON.parse(text) as Record<string, unknown> };
  } catch {
    return { status: res.status, body: { text } };
  }
}

/** A device authorization request for the Reconcile Q3 invoices Mission. */
async function deviceAuthorize(
  client: string = PUBLIC,
  extra: Record<string, string> = {},
  opts: { issuer?: string; omit?: string[]; pairs?: [string, string][] } = {},
): Promise<{ status: number; body: Record<string, unknown> }> {
  const params: Record<string, string> = {
    ...(await clientAuth(client)),
    resource: RESOURCE,
    mission_intent: JSON.stringify({ intent: INTENT }),
    authorization_details: JSON.stringify(READ),
    ...extra,
  };
  for (const k of opts.omit ?? []) delete params[k];
  return postForm(`${opts.issuer ?? ISSUER}/device/auth`, [...Object.entries(params), ...(opts.pairs ?? [])]);
}

/**
 * The verification user agent: the `user_code` typed at the verification URI
 * or arriving through `verification_uri_complete`, then the provider's
 * confirmation, which starts the approval interaction. Returns its uid.
 */
async function enterCode(
  userCode: string,
  jar: Jar,
  how: "typed" | "complete" = "typed",
  injected: Record<string, string> = {},
): Promise<string> {
  const url =
    how === "typed" ? `${ISSUER}/device` : `${ISSUER}/device?${new URLSearchParams({ user_code: userCode, ...injected })}`;
  let res = await fetch(url, { headers: { cookie: cookieOf(jar) }, redirect: "manual" });
  keep(jar, res);
  let html = await res.text();
  const form = (xsrf: string, more: Record<string, string> = {}) =>
    new URLSearchParams({ xsrf, user_code: userCode, ...injected, ...more }).toString();
  res = await fetch(`${ISSUER}/device`, {
    method: "POST",
    redirect: "manual",
    headers: { ...FORM, cookie: cookieOf(jar) },
    body: form(hidden(html, "xsrf")),
  });
  keep(jar, res);
  html = await res.text();
  res = await fetch(`${ISSUER}/device`, {
    method: "POST",
    redirect: "manual",
    headers: { ...FORM, cookie: cookieOf(jar) },
    body: form(hidden(html, "xsrf"), { confirm: "yes" }),
  });
  keep(jar, res);
  const location = res.headers.get("location") ?? "";
  expect(location, await res.text()).toMatch(/\/interaction\/[^/]+$/);
  return location.split("/interaction/")[1] as string;
}

/** The confirmation page the provider shows before the interaction starts. */
async function confirmationPage(userCode: string, jar: Jar): Promise<string> {
  let res = await fetch(`${ISSUER}/device`, { headers: { cookie: cookieOf(jar) } });
  keep(jar, res);
  const html = await res.text();
  res = await fetch(`${ISSUER}/device`, {
    method: "POST",
    headers: { ...FORM, cookie: cookieOf(jar) },
    body: new URLSearchParams({ xsrf: hidden(html, "xsrf"), user_code: userCode }).toString(),
  });
  keep(jar, res);
  return res.text();
}

async function approvalPage(uid: string, headers: Record<string, string>, query = ""): Promise<{ status: number; html: string }> {
  const res = await fetch(`${ISSUER}/interaction/${uid}${query}`, { headers });
  return { status: res.status, html: await res.text() };
}

async function decide(uid: string, headers: Record<string, string>, body: Record<string, unknown>): Promise<{ status: number; text: string }> {
  const res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...headers, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: res.status, text: await res.text() };
}

type Keys = { privateKey: CryptoKey; jwk: JWK };
const newKeys = async (): Promise<Keys> => {
  const pair = await generateKeyPair("ES256", { extractable: true });
  return { privateKey: pair.privateKey as CryptoKey, jwk: await exportJWK(pair.publicKey) };
};

/** The token endpoint with a DPoP proof under `k` and the given client authentication. */
async function token(
  params: Record<string, string>,
  auth: Record<string, string>,
  k?: Keys,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const htu = `${ISSUER}/token`;
  const headers: Record<string, string> = { ...FORM };
  if (k) {
    headers.dpop = await new SignJWT({ htu, htm: "POST" })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: k.jwk })
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .sign(k.privateKey);
  }
  const res = await fetch(htu, { method: "POST", headers, body: new URLSearchParams({ ...params, ...auth }).toString() });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

/** A device access token request: the poll. */
async function poll(client: string, deviceCode: string, k?: Keys, extra: Record<string, string> = {}) {
  return token({ grant_type: DEVICE_GRANT, device_code: deviceCode, ...extra }, await clientAuth(client), k);
}

interface Session {
  deviceCode: string;
  userCode: string;
  uid: string;
  /** The verification user agent's cookies, with no Approver session. */
  jar: Jar;
  /** The same user agent with the Approver authenticated. */
  headers: Record<string, string>;
}

/** A device session up to the Approver's authenticated approval page, before any decision. */
async function pendingSession(
  client: string = PUBLIC,
  approver: { sub: string; subject?: string; acr?: string } = ALICE_BY_BOB,
  extra: Record<string, string> = {},
  how: "typed" | "complete" = "typed",
): Promise<Session> {
  const da = await deviceAuthorize(client, extra);
  expect(da.status, JSON.stringify(da.body)).toBe(200);
  const jar: Jar = new Map();
  const uid = await enterCode(da.body.user_code as string, jar, how);
  return {
    deviceCode: da.body.device_code as string,
    userCode: da.body.user_code as string,
    uid,
    jar,
    headers: browserApprovalHeaders(SESSIONS, uid, approver, cookieOf(jar)),
  };
}

/** A device session the Approver approved. */
async function approvedSession(
  client: string = PUBLIC,
  approver: { sub: string; subject?: string; acr?: string } = ALICE_BY_BOB,
  extra: Record<string, string> = {},
): Promise<Session> {
  const s = await pendingSession(client, approver, extra);
  const decided = await decide(s.uid, s.headers, CONFIRMED);
  expect(decided.status, decided.text).toBe(200);
  return s;
}

const missionOf = (uid: string) => as.kernel.findByApprovalEvent(`apev_${uid}`);

/** Lapse a device code's lifetime, as time passing would. */
async function lapse(deviceCode: string): Promise<void> {
  const code = await as.provider.DeviceCode.find(deviceCode, { ignoreExpiration: true });
  if (!code) throw new Error("no device code");
  code.exp = Math.floor(Date.now() / 1000) - 1;
  await code.save();
}

/**
 * A complete authorization-code approval by `approver` in the user agent
 * `jar`, which then holds the provider's End-User session and a grant for
 * the client. Returns the approval interaction's uid.
 */
async function browserCodeApproval(client: string, key: CryptoKey, jar: Jar, approver: { sub: string }, scope: string) {
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode("device-authorization-verifier-0123456789-0123")),
  ).toString("base64url");
  const par = await postForm(`${ISSUER}/request`, [
    ["client_id", client],
    ["response_type", "code"],
    ["redirect_uri", REDIRECT_URI],
    ["resource", RESOURCE],
    ["scope", scope],
    ["code_challenge", challenge],
    ["code_challenge_method", "S256"],
    ["mission_intent", JSON.stringify({ intent: INTENT })],
    ["authorization_details", JSON.stringify(READ)],
    ["client_assertion", await assertion(client, key)],
    ["client_assertion_type", JWT_BEARER],
  ]);
  expect(par.status, JSON.stringify(par.body)).toBe(201);
  let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: client, request_uri: par.body.request_uri as string })}`, {
    redirect: "manual",
    headers: { cookie: cookieOf(jar) },
  });
  keep(jar, res);
  const uid = (res.headers.get("location") ?? "").split("/interaction/")[1] as string;
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...browserApprovalHeaders(SESSIONS, uid, approver, cookieOf(jar)), "content-type": "application/json" },
    body: JSON.stringify({ decision: "approve" }),
  });
  keep(jar, res);
  let location = res.headers.get("location") ?? "";
  while (location.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieOf(jar) } });
    keep(jar, res);
    location = res.headers.get("location") ?? "";
  }
  expect(new URL(location).searchParams.get("code"), location).toBeTruthy();
  return uid;
}

/** A pushed authorization request for the same submission, for the error mapping at PAR. */
async function push(
  missionIntent: string,
  proposal: string,
  client = "ap-agent",
): Promise<{ status: number; body: Record<string, unknown> }> {
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode("device-authorization-verifier-0123456789-0123")),
  ).toString("base64url");
  const auth: [string, string][] =
    client === "ap-agent"
      ? [
          ["client_assertion", await assertion("ap-agent", agentKey)],
          ["client_assertion_type", JWT_BEARER],
        ]
      : [];
  return postForm(`${ISSUER}/request`, [
    ["client_id", client],
    ["response_type", "code"],
    ["redirect_uri", REDIRECT_URI],
    ["resource", RESOURCE],
    ["code_challenge", challenge],
    ["code_challenge_method", "S256"],
    ["mission_intent", missionIntent],
    ["authorization_details", proposal],
    ...auth,
  ]);
}

describe("Mission Device Authorization discovery (@spec device-authorization#discovery, #1202)", () => {
  it("advertises mission_device_authorization_supported with the device authorization endpoint only where the opt-in capability is on", async () => {
    const meta = (await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
    expect(meta.mission_bound_authorization_supported).toBe(true);
    expect(meta.mission_device_authorization_supported).toBe(true);
    expect(meta.device_authorization_endpoint).toBe(`${ISSUER}/device/auth`);
    expect(meta.grant_types_supported).toContain(DEVICE_GRANT);
    // The default assembly enables every other capability, never this one.
    const offMeta = (await (await fetch(`${OFF_ISSUER}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
    expect(offMeta.mission_bound_authorization_supported).toBe(true);
    expect(offMeta.mission_device_authorization_supported).toBeUndefined();
    expect(offMeta.device_authorization_endpoint).toBeUndefined();
    expect(offMeta.grant_types_supported).not.toContain(DEVICE_GRANT);
  });

  it("creates no Mission from a mission_intent at the device authorization endpoint of an assembly without the opt-in capability", async () => {
    const refused = await deviceAuthorize(PUBLIC, {}, { issuer: OFF_ISSUER });
    expect(refused.status).toBe(404);
    expect(refused.body.device_code).toBeUndefined();
    expect(off.kernel.allMissions()).toHaveLength(0);
  });
});

describe("Mission Device Authorization request (@spec device-authorization#request, #1202)", () => {
  it("refuses mission_intent with a request or request_uri parameter as invalid_request, issuing no device_code", async () => {
    for (const extra of [{ request: "eyJhbGciOiJub25lIn0.e30." }, { request_uri: "urn:ietf:params:oauth:request_uri:abc" }]) {
      const res = await deviceAuthorize(PUBLIC, extra);
      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(res.body.error).toBe("invalid_request");
      expect(res.body.device_code).toBeUndefined();
      expect(res.body.user_code).toBeUndefined();
    }
  });

  it("refuses a signed Request Object as request_not_supported, issuing no device_code (#1503)", async () => {
    // Request Objects are accepted at PAR only (@spec mission#submission-via-par);
    // this one is well formed and signed with the client's registered key.
    const request = await new SignJWT({ client_id: CONFIDENTIAL, resource: RESOURCE })
      .setProtectedHeader({ alg: "ES256", kid: `${CONFIDENTIAL}-auth` })
      .setIssuer(CONFIDENTIAL)
      .setAudience(ISSUER)
      .setIssuedAt()
      .setExpirationTime("1m")
      .sign(confidentialKey);
    const res = await deviceAuthorize(CONFIDENTIAL, { request }, { omit: ["mission_intent", "authorization_details"] });
    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(res.body.error).toBe("request_not_supported");
    expect(res.body.device_code).toBeUndefined();
  });

  it("validates the whole submission before issuing a device_code, refusing with the code PAR assigns", async () => {
    const other = "http://localhost:4999/elsewhere";
    const cases: { name: string; intent: unknown; proposal: unknown }[] = [
      { name: "bare Intent, not the envelope", intent: INTENT, proposal: READ },
      { name: "unknown envelope member", intent: { intent: INTENT, note: "x" }, proposal: READ },
      { name: "Intent missing its goal", intent: { intent: { ...INTENT, goal: undefined } }, proposal: READ },
      { name: "unsupported evidence type", intent: { intent: INTENT, evidence: [{ type: "urn:example:unknown" }] }, proposal: READ },
      { name: "evidence failing its schema", intent: { intent: INTENT, evidence: [{ type: EVIDENCE_TYPE }] }, proposal: READ },
      {
        name: "evidence failing verification",
        intent: { intent: INTENT, evidence: [{ type: EVIDENCE_TYPE, assertion: "fail" }] },
        proposal: READ,
      },
      { name: "resource outside target_resources", intent: { intent: INTENT }, proposal: [{ ...READ[0], resource: other }] },
      { name: "unadvertised type", intent: { intent: INTENT }, proposal: [{ type: "payment_initiation", resource: RESOURCE }] },
      { name: "entry failing its schema", intent: { intent: INTENT }, proposal: [{ type: "mission_resource_access", resource: RESOURCE }] },
    ];
    for (const c of cases) {
      const missionIntent = JSON.stringify(c.intent);
      const proposal = JSON.stringify(c.proposal);
      const atPar = await push(missionIntent, proposal);
      expect(atPar.status, `${c.name} at PAR: ${JSON.stringify(atPar.body)}`).toBe(400);
      const res = await deviceAuthorize(PUBLIC, { mission_intent: missionIntent, authorization_details: proposal });
      expect(res.status, `${c.name}: ${JSON.stringify(res.body)}`).toBe(400);
      expect(res.body.error, c.name).toBe(atPar.body.error);
      expect(res.body.device_code, c.name).toBeUndefined();
      expect(res.body.user_code, c.name).toBeUndefined();
    }
    // A type the client is not registered for, refused as PAR refuses it.
    const unregistered = await push(JSON.stringify({ intent: INTENT }), JSON.stringify(READ), NO_RAR);
    expect(unregistered.status, JSON.stringify(unregistered.body)).toBe(400);
    const notAllowed = await deviceAuthorize(NO_RAR);
    expect(notAllowed.status, JSON.stringify(notAllowed.body)).toBe(400);
    expect(notAllowed.body.error).toBe(unregistered.body.error);
    expect(notAllowed.body.device_code).toBeUndefined();
    // A repeated proposal is refused before anything else.
    const repeated = await deviceAuthorize(PUBLIC, {}, { pairs: [["authorization_details", JSON.stringify(READ)]] });
    expect(repeated.status).toBe(400);
    expect(repeated.body.error).toBe("invalid_request");
    expect(repeated.body.device_code).toBeUndefined();
  });

  // @spec mission#submission-processing (#1411): the earliest failing step's
  // error, on this carrier as at PAR.
  it("refuses a submission failing two checks with the earliest step's error, as PAR does, issuing no device_code", async () => {
    const other = "http://localhost:4999/elsewhere";
    const cases: { name: string; intent: unknown; proposal: unknown; error: string }[] = [
      {
        name: "Intent failing validation with a malformed proposal",
        intent: { intent: { ...INTENT, goal: 17 } },
        proposal: [{ ...READ[0], actions: 17 }],
        error: "invalid_request",
      },
      {
        name: "resource outside target_resources with an unsupported evidence type",
        intent: { intent: INTENT, evidence: [{ type: "urn:example:unknown" }] },
        proposal: [{ ...READ[0], resource: other }],
        error: "invalid_request",
      },
      {
        name: "resource outside target_resources with evidence failing verification",
        intent: { intent: INTENT, evidence: [{ type: EVIDENCE_TYPE, assertion: "fail" }] },
        proposal: [{ ...READ[0], resource: other }],
        error: "invalid_request",
      },
    ];
    for (const c of cases) {
      const missionIntent = JSON.stringify(c.intent);
      const proposal = JSON.stringify(c.proposal);
      const atPar = await push(missionIntent, proposal);
      expect(atPar.status, `${c.name} at PAR: ${JSON.stringify(atPar.body)}`).toBe(400);
      expect(atPar.body.error, `${c.name} at PAR`).toBe(c.error);
      const res = await deviceAuthorize(PUBLIC, { mission_intent: missionIntent, authorization_details: proposal });
      expect(res.status, `${c.name}: ${JSON.stringify(res.body)}`).toBe(400);
      expect(res.body.error, c.name).toBe(c.error);
      expect(res.body.device_code, c.name).toBeUndefined();
    }
  });

  // @spec resource-access#entry-validation (#1278, D457): the provider's RAR
  // check never runs at this endpoint, so every `locations` value, including
  // `null`, `""` and a malformed one, reaches the shared proposal validator.
  it("refuses a proposal entry carrying locations, whatever its value, with invalid_authorization_details, issuing no device_code", async () => {
    const missionIntent = JSON.stringify({ intent: INTENT });
    for (const locations of [[], [RESOURCE], null, "", { uri: RESOURCE }]) {
      const before = as.kernel.allMissions().length;
      const proposal = JSON.stringify([{ ...READ[0], locations }]);
      const res = await deviceAuthorize(PUBLIC, { mission_intent: missionIntent, authorization_details: proposal });
      expect(res.status, `${JSON.stringify(locations)}: ${JSON.stringify(res.body)}`).toBe(400);
      expect(res.body.error).toBe("invalid_authorization_details");
      expect(res.body.error_description).toMatch(/locations must be absent/);
      expect(res.body.device_code).toBeUndefined();
      expect(res.body.user_code).toBeUndefined();
      expect(as.kernel.allMissions().length).toBe(before);
    }
  });

  // @spec mission#subset (#1399, D538): an unsupported top-level member
  // reaches the shared proposal validator, which refuses it by presence.
  it("refuses a proposal entry carrying an unsupported member, whatever its value, with invalid_authorization_details, issuing no device_code", async () => {
    const missionIntent = JSON.stringify({ intent: INTENT });
    for (const invoice_ids of [["INV-7"], [], null, ""]) {
      const before = as.kernel.allMissions().length;
      const proposal = JSON.stringify([{ ...READ[0], invoice_ids }]);
      const res = await deviceAuthorize(PUBLIC, { mission_intent: missionIntent, authorization_details: proposal });
      expect(res.status, `${JSON.stringify(invoice_ids)}: ${JSON.stringify(res.body)}`).toBe(400);
      expect(res.body.error).toBe("invalid_authorization_details");
      expect(res.body.error_description).toMatch(/invoice_ids is not a supported member/);
      expect(res.body.device_code).toBeUndefined();
      expect(res.body.user_code).toBeUndefined();
      expect(as.kernel.allMissions().length).toBe(before);
    }
  });

  it("answers a device request without mission_intent with a refusal, never an ordinary device authorization session", async () => {
    for (const omit of [["mission_intent", "authorization_details"], ["mission_intent"]]) {
      const res = await deviceAuthorize(PUBLIC, { scope: "openid" }, { omit });
      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(res.body.error).toBe("invalid_request");
      expect(res.body.device_code).toBeUndefined();
    }
  });

  it("creates the Mission from the whole submission: the bound Intent, evidence and proposal, and a Mission-bound token", async () => {
    const s = await approvedSession(PUBLIC, ALICE_BY_BOB, {
      mission_intent: JSON.stringify({ intent: INTENT, evidence: [{ type: EVIDENCE_TYPE, assertion: "ok" }] }),
    });
    const record = missionOf(s.uid);
    expect(record?.intent).toEqual(INTENT);
    expect(record?.submission_evidence).toEqual([
      expect.objectContaining({ type: EVIDENCE_TYPE, facts: expect.objectContaining({ presenter_client: PUBLIC }) }),
    ]);
    expect(record?.proposed_authority).toEqual(READ);
    expect(record?.proposal_hash).toBeDefined();
    expect(record?.client_id).toBe(PUBLIC);
    const res = await poll(PUBLIC, s.deviceCode, await newKeys());
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const claims = decodeJwt(res.body.access_token as string);
    expect((claims.mission as { id?: string }).id).toBe(record?.id);
  });
});

describe("Mission Device Authorization session binding (@spec device-authorization#session-binding, #1202)", () => {
  it("ignores mission_intent, authorization_details and scope presented at the verification URI", async () => {
    const da = await deviceAuthorize();
    const injected = {
      mission_intent: JSON.stringify({ intent: { ...INTENT, goal: "Wire the treasury out." } }),
      authorization_details: JSON.stringify([{ ...READ[0], actions: ["payments:invoice.pay"] }]),
      scope: "openid",
    };
    const jar: Jar = new Map();
    const uid = await enterCode(da.body.user_code as string, jar, "complete", injected);
    const headers = browserApprovalHeaders(SESSIONS, uid, ALICE_BY_BOB, cookieOf(jar));
    const page = await approvalPage(uid, headers, `?${new URLSearchParams(injected)}`);
    expect(page.status, page.html).toBe(200);
    expect(page.html).toContain("Reconcile Q3 invoices.");
    expect(page.html).not.toContain("Wire the treasury out.");
    expect(page.html).not.toContain("payments:invoice.pay");
    expect((await decide(uid, headers, CONFIRMED)).status).toBe(200);
    const record = missionOf(uid);
    expect(record?.intent).toEqual(INTENT);
    expect(record?.proposed_authority).toEqual(READ);
    const res = await poll(PUBLIC, da.body.device_code as string, await newKeys());
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.id_token).toBeUndefined();
  });

  it("ignores mission_intent on the device access token request: the Mission is the bound one, unchanged", async () => {
    const s = await approvedSession();
    const record = missionOf(s.uid);
    const res = await poll(PUBLIC, s.deviceCode, await newKeys(), {
      mission_intent: JSON.stringify({ intent: { ...INTENT, goal: "Wire the treasury out." } }),
    });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.mission_id).toBe(record?.id);
    expect((decodeJwt(res.body.access_token as string).mission as { id?: string }).id).toBe(record?.id);
    expect(as.kernel.get(record?.id as string)?.intent).toEqual(INTENT);
  });

  it("applies a decision only to the session whose user_code was entered: a swapped code in the decision changes nothing", async () => {
    const a = await pendingSession();
    const b = await deviceAuthorize();
    expect(b.status).toBe(200);
    const decided = await decide(a.uid, a.headers, { ...CONFIRMED, user_code: b.body.user_code });
    expect(decided.status, decided.text).toBe(200);
    const pending = await poll(PUBLIC, b.body.device_code as string, await newKeys());
    expect(pending.status).toBe(400);
    expect(pending.body.error).toBe("authorization_pending");
    const redeemed = await poll(PUBLIC, a.deviceCode, await newKeys());
    expect(redeemed.status, JSON.stringify(redeemed.body)).toBe(200);
    expect(redeemed.body.mission_id).toBe(missionOf(a.uid)?.id);
  });

  it("refuses a device access token request from another client than the bound one with invalid_grant", async () => {
    const bound = await approvedSession(PUBLIC);
    const byOther = await poll(CONFIDENTIAL, bound.deviceCode, await newKeys());
    expect(byOther.status).toBe(400);
    expect(byOther.body.error).toBe("invalid_grant");
    expect(byOther.body.access_token).toBeUndefined();
    const confidential = await approvedSession(CONFIDENTIAL);
    const byPublic = await poll(PUBLIC, confidential.deviceCode, await newKeys());
    expect(byPublic.status).toBe(400);
    expect(byPublic.body.error).toBe("invalid_grant");
    expect(byPublic.body.access_token).toBeUndefined();
    // Each bound client still redeems its own session.
    expect((await poll(PUBLIC, bound.deviceCode, await newKeys())).status).toBe(200);
    expect((await poll(CONFIDENTIAL, confidential.deviceCode, await newKeys())).status).toBe(200);
  });

  it("refuses a request omitting or failing the bound client's authentication with invalid_client, and never refuses a public client for its absence", async () => {
    const s = await approvedSession(CONFIDENTIAL);
    const params = { grant_type: DEVICE_GRANT, device_code: s.deviceCode };
    const omitted = await token(params, { client_id: CONFIDENTIAL }, await newKeys());
    expect(omitted.status).toBe(401);
    expect(omitted.body.error).toBe("invalid_client");
    expect(omitted.body.access_token).toBeUndefined();
    const failed = await token(
      params,
      { client_assertion: await assertion(CONFIDENTIAL, strangerKey), client_assertion_type: JWT_BEARER },
      await newKeys(),
    );
    expect(failed.status).toBe(401);
    expect(failed.body.error).toBe("invalid_client");
    expect(failed.body.access_token).toBeUndefined();
    expect((await poll(CONFIDENTIAL, s.deviceCode, await newKeys())).status).toBe(200);
    // A public client identifies itself with its client_id and no authentication.
    const pub = await approvedSession(PUBLIC);
    const identified = await token({ grant_type: DEVICE_GRANT, device_code: pub.deviceCode }, { client_id: PUBLIC }, await newKeys());
    expect(identified.status, JSON.stringify(identified.body)).toBe(200);
  });
});

describe("Mission Device Authorization approval (@spec device-authorization#approval, #1202)", () => {
  it("reaches no decision on an entered user_code alone: the Approver must authenticate, and the Subject is the approval surface's", async () => {
    const s = await pendingSession(PUBLIC, ALICE_BY_BOB, { login_hint: "dana" });
    const cookie = cookieOf(s.jar);
    const page = await approvalPage(s.uid, { cookie });
    expect(page.status).toBe(401);
    expect(page.html).not.toContain("decision");
    const decided = await decide(s.uid, { cookie }, CONFIRMED);
    expect(decided.status).toBe(401);
    expect(missionOf(s.uid)).toBeUndefined();
    const pending = await poll(PUBLIC, s.deviceCode, await newKeys());
    expect(pending.body.error).toBe("authorization_pending");
    // Authenticated, the decision binds the Subject the approval surface selected.
    expect((await decide(s.uid, s.headers, CONFIRMED)).status).toBe(200);
    expect(missionOf(s.uid)?.subject).toEqual({ iss: ISSUER, sub: "alice" });
  });

  it("always runs the approval: a provider session and grant the verification user agent already holds never complete a Mission device session", async () => {
    const jar: Jar = new Map();
    const earlier = await browserCodeApproval(CONFIDENTIAL, confidentialKey, jar, { sub: "alice" }, "openid");
    expect(missionOf(earlier)?.state).toBe("active");
    // An Intent-only device request whose scope that grant already holds.
    const da = await deviceAuthorize(CONFIDENTIAL, { scope: "openid" }, { omit: ["authorization_details"] });
    expect(da.status, JSON.stringify(da.body)).toBe(200);
    const uid = await enterCode(da.body.user_code as string, jar);
    const pending = await poll(CONFIDENTIAL, da.body.device_code as string, await newKeys());
    expect(pending.status).toBe(400);
    expect(pending.body.error).toBe("authorization_pending");
    expect(missionOf(uid)).toBeUndefined();
    const page = await approvalPage(uid, browserApprovalHeaders(SESSIONS, uid, { sub: "alice" }, cookieOf(jar)));
    expect(page.html).toContain('name="confirm_user_code"');
  });

  it("creates the Mission active with the decision, which alone makes the device_code redeemable", async () => {
    const s = await pendingSession();
    const before = await poll(PUBLIC, s.deviceCode, await newKeys());
    expect(before.status).toBe(400);
    expect(before.body.error).toBe("authorization_pending");
    expect(missionOf(s.uid)).toBeUndefined();
    expect((await decide(s.uid, s.headers, CONFIRMED)).status).toBe(200);
    // No visit to the provider's device resume: the commit itself activated the code.
    const record = missionOf(s.uid);
    expect(record?.state).toBe("active");
    const after = await poll(PUBLIC, s.deviceCode, await newKeys());
    expect(after.status, JSON.stringify(after.body)).toBe(200);
    expect(after.body.mission_id).toBe(record?.id);
  });

  it("creates no Mission for a decision reached after the session expired or ended", async () => {
    const expired = await pendingSession();
    await lapse(expired.deviceCode);
    const late = await decide(expired.uid, expired.headers, CONFIRMED);
    expect(late.status).toBe(400);
    expect(missionOf(expired.uid)).toBeUndefined();
    const ended = await pendingSession();
    const code = await as.provider.DeviceCode.find(ended.deviceCode, { ignoreExpiration: true });
    if (!code) throw new Error("no device code");
    code.error = "access_denied";
    code.errorDescription = "ended by the authorization server";
    await code.save();
    const afterEnd = await decide(ended.uid, ended.headers, CONFIRMED);
    expect(afterEnd.status).toBe(400);
    expect(missionOf(ended.uid)).toBeUndefined();
    // The session the AS ended answers its next poll access_denied.
    expect((await poll(PUBLIC, ended.deviceCode, await newKeys())).body.error).toBe("access_denied");
  });

  it("recovers from a grant-store failure before the commit: no Mission exists, the session stays pending, and a retry completes one Mission", async () => {
    const s = await pendingSession();
    const fault = vi.spyOn(as.provider.Grant.prototype, "save").mockRejectedValueOnce(new Error("grant store fault"));
    const first = await decide(s.uid, s.headers, CONFIRMED);
    fault.mockRestore();
    expect(first.status).toBe(500);
    // #916: the grant is saved before the record commits, so the fault leaves no Mission.
    expect(missionOf(s.uid)).toBeUndefined();
    expect((await poll(PUBLIC, s.deviceCode, await newKeys())).body.error).toBe("authorization_pending");
    const retry = await decide(s.uid, s.headers, CONFIRMED);
    expect(retry.status, retry.text).toBe(200);
    const committed = missionOf(s.uid);
    expect(committed?.state).toBe("active");
    expect(as.kernel.allMissions().filter((m) => m.approval_event_id === `apev_${s.uid}`)).toHaveLength(1);
    const res = await poll(PUBLIC, s.deviceCode, await newKeys());
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.mission_id).toBe(committed?.id);
  });

  it("recovers from a failed activation write: a retry reuses the committed Mission and its grant", async () => {
    const s = await pendingSession();
    const fault = vi.spyOn(as.provider.DeviceCode.prototype, "save").mockRejectedValueOnce(new Error("device code store fault"));
    const first = await decide(s.uid, s.headers, CONFIRMED);
    fault.mockRestore();
    expect(first.status).toBe(500);
    const committed = missionOf(s.uid);
    expect(committed?.grant_id).toBeTruthy();
    expect((await poll(PUBLIC, s.deviceCode, await newKeys())).body.error).toBe("authorization_pending");
    expect((await decide(s.uid, s.headers, CONFIRMED)).status).toBe(200);
    expect(as.kernel.allMissions().filter((m) => m.approval_event_id === `apev_${s.uid}`)).toHaveLength(1);
    expect(missionOf(s.uid)?.grant_id).toBe(committed?.grant_id);
    expect((await poll(PUBLIC, s.deviceCode, await newKeys())).body.mission_id).toBe(committed?.id);
  });

  it("never activates a retried decision whose committed Mission is no longer active: the session ends denied", async () => {
    const s = await pendingSession();
    // The activation write is the step after the commit (#916), so a fault there leaves a committed Mission.
    const fault = vi.spyOn(as.provider.DeviceCode.prototype, "save").mockRejectedValueOnce(new Error("device code store fault"));
    expect((await decide(s.uid, s.headers, CONFIRMED)).status).toBe(500);
    fault.mockRestore();
    as.kernel.transition(missionOf(s.uid)?.id as string, "revoke");
    const retry = await decide(s.uid, s.headers, CONFIRMED);
    expect(retry.status).toBe(200);
    expect(retry.text).toContain("Mission not approved");
    expect((await poll(PUBLIC, s.deviceCode, await newKeys())).body.error).toBe("access_denied");
  });

  it("holds the device approval to the published approval-authentication floor: high-risk authority needs an accepted acr", async () => {
    // Remitting is high-risk under config/approval-floor.json; the floor
    // accepts only mfa on the browser surface inside its age bound.
    const remit = JSON.stringify([
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:invoice.read", "payments:remittance.send"],
        constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
      },
    ]);
    const weak = await pendingSession(PUBLIC, { ...ALICE_BY_BOB, acr: "password" }, { authorization_details: remit });
    expect((await decide(weak.uid, weak.headers, CONFIRMED)).status).toBe(200);
    expect(missionOf(weak.uid)).toBeUndefined();
    expect((await poll(PUBLIC, weak.deviceCode, await newKeys())).body.error).toBe("access_denied");
    const strong = await pendingSession(PUBLIC, { ...ALICE_BY_BOB, acr: "mfa" }, { authorization_details: remit });
    expect((await decide(strong.uid, strong.headers, CONFIRMED)).status).toBe(200);
    expect(missionOf(strong.uid)?.state).toBe("active");
    expect((await poll(PUBLIC, strong.deviceCode, await newKeys())).status).toBe(200);
  });

  it("names the requesting client from registration data, whether the AS authenticated it, and its client-supplied name as inert text", async () => {
    const pub = await pendingSession(PUBLIC);
    const page = await approvalPage(pub.uid, pub.headers);
    expect(page.status, page.html).toBe(200);
    expect(page.html).toContain(`<code>${PUBLIC}</code>`);
    expect(page.html).toContain("did not authenticate this client");
    expect(page.html).toContain("&lt;b&gt;Invoice CLI&lt;/b&gt;");
    expect(page.html).not.toContain(CLIENT_NAME);
    const confidential = await pendingSession(CONFIDENTIAL);
    const confidentialPage = await approvalPage(confidential.uid, confidential.headers);
    expect(confidentialPage.html).toContain(`<code>${CONFIDENTIAL}</code>`);
    expect(confidentialPage.html).toContain("The authorization server authenticated this client.");
    // The provider's own confirmation page renders the name inert too.
    const da = await deviceAuthorize(PUBLIC);
    const confirm = await confirmationPage(da.body.user_code as string, new Map());
    expect(confirm).toContain("&lt;b&gt;Invoice CLI&lt;/b&gt;");
    expect(confirm).not.toContain(CLIENT_NAME);
  });

  it("names the Subject the authority is granted for, self-approval included", async () => {
    const forAlice = await pendingSession(PUBLIC, ALICE_BY_BOB);
    expect((await approvalPage(forAlice.uid, forAlice.headers)).html).toContain('<p class="subject"><code>alice</code></p>');
    const self = await pendingSession(PUBLIC, { sub: "alice" });
    expect((await approvalPage(self.uid, self.headers)).html).toContain('<p class="subject"><code>alice</code></p>');
    const bobSelf = await pendingSession(PUBLIC, { sub: "bob" });
    expect((await approvalPage(bobSelf.uid, bobSelf.headers)).html).toContain('<p class="subject"><code>bob</code></p>');
  });

  it("displays the user_code and asks for both confirmations before the decision, typed or through verification_uri_complete", async () => {
    for (const how of ["typed", "complete"] as const) {
      const s = await pendingSession(PUBLIC, ALICE_BY_BOB, {}, how);
      const page = await approvalPage(s.uid, s.headers);
      expect(page.html).toContain(`<code class="user-code">${s.userCode}</code>`);
      expect(page.html).toContain('name="confirm_user_code"');
      expect(page.html).toContain('name="confirm_started"');
      for (const partial of [
        { decision: "approve" },
        { decision: "approve", confirm_user_code: true },
        { decision: "approve", confirm_started: true },
      ]) {
        const refused = await decide(s.uid, s.headers, partial);
        expect(refused.status, how).toBe(400);
        expect(missionOf(s.uid), how).toBeUndefined();
      }
      expect((await poll(PUBLIC, s.deviceCode, await newKeys())).body.error).toBe("authorization_pending");
      expect((await decide(s.uid, s.headers, CONFIRMED)).status).toBe(200);
      expect(missionOf(s.uid)?.state).toBe("active");
    }
  });
});

describe("Mission Device Authorization polling (@spec device-authorization#polling, #1202)", () => {
  it("answers access_denied after a decline, a refused creation commit or an abort, and invalid_scope for openid when the Approver is not the Subject", async () => {
    const declined = await pendingSession();
    expect((await decide(declined.uid, declined.headers, { decision: "deny" })).status).toBe(200);
    expect((await poll(PUBLIC, declined.deviceCode, await newKeys())).body.error).toBe("access_denied");
    expect(missionOf(declined.uid)).toBeUndefined();
    // Dana activates no source this client resolves: the commit creates no Mission.
    const refused = await pendingSession(PUBLIC, { sub: "dana" });
    expect((await decide(refused.uid, refused.headers, CONFIRMED)).status).toBe(200);
    expect(missionOf(refused.uid)).toBeUndefined();
    expect((await poll(PUBLIC, refused.deviceCode, await newKeys())).body.error).toBe("access_denied");
    const openid = await pendingSession(PUBLIC, ALICE_BY_BOB, { scope: "openid" });
    expect((await decide(openid.uid, openid.headers, CONFIRMED)).status).toBe(200);
    expect(missionOf(openid.uid)).toBeUndefined();
    expect((await poll(PUBLIC, openid.deviceCode, await newKeys())).body.error).toBe("invalid_scope");
    // The Approver aborts at the provider's code confirmation.
    const da = await deviceAuthorize();
    const jar: Jar = new Map();
    const confirm = await confirmationPage(da.body.user_code as string, jar);
    const res = await fetch(`${ISSUER}/device`, {
      method: "POST",
      headers: { ...FORM, cookie: cookieOf(jar) },
      body: new URLSearchParams({ xsrf: hidden(confirm, "xsrf"), user_code: da.body.user_code as string, abort: "yes" }).toString(),
    });
    expect(res.status).toBe(200);
    expect((await poll(PUBLIC, da.body.device_code as string, await newKeys())).body.error).toBe("access_denied");
  });

  it("answers expired_token once a pending session's device_code lifetime elapsed", async () => {
    const s = await pendingSession();
    await lapse(s.deviceCode);
    const res = await poll(PUBLIC, s.deviceCode, await newKeys());
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("expired_token");
    expect(res.body.access_token).toBeUndefined();
  });

  it("answers expired_token for an approved device_code that expired unredeemed, its Mission still active", async () => {
    const s = await approvedSession();
    await lapse(s.deviceCode);
    const res = await poll(PUBLIC, s.deviceCode, await newKeys());
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("expired_token");
    expect(res.body.access_token).toBeUndefined();
    expect(as.kernel.get(missionOf(s.uid)?.id as string)?.state).toBe("active");
  });

  it("refuses redemption with the issuance-gating refusal once the Mission was revoked after approval", async () => {
    const s = await approvedSession();
    as.kernel.transition(missionOf(s.uid)?.id as string, "revoke");
    const res = await poll(PUBLIC, s.deviceCode, await newKeys());
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_grant");
    expect(res.body.access_token).toBeUndefined();
  });

  it("refuses redemption with the issuance-gating refusal once the Mission expired after approval", async () => {
    const expiresAt = new Date(Math.ceil(Date.now() / 1000) * 1000 + 2000).toISOString().replace(".000Z", "Z");
    const s = await approvedSession(PUBLIC, ALICE_BY_BOB, {
      mission_intent: JSON.stringify({ intent: { ...INTENT, expires_at: expiresAt } }),
    });
    expect(missionOf(s.uid)?.expires_at).toBe(expiresAt);
    await new Promise((r) => setTimeout(r, Date.parse(expiresAt) - Date.now() + 200));
    const res = await poll(PUBLIC, s.deviceCode, await newKeys());
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_grant");
    expect(res.body.access_token).toBeUndefined();
  });
});

describe("Mission Device Authorization issuance (@spec device-authorization#issuance, #1202)", () => {
  it("returns the Mission-bound token with mission_id, mission_expires_at and the granted authorization_details", async () => {
    const s = await approvedSession();
    const record = missionOf(s.uid);
    const keys = await newKeys();
    const res = await poll(PUBLIC, s.deviceCode, keys);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.mission_id).toBe(record?.id);
    expect(res.body.mission_expires_at).toBe(record?.expires_at);
    // The granted authority is the Mission's derived Authority Set, which the
    // token carries too.
    expect(res.body.authorization_details).toEqual(record?.authority_set);
    expect(res.body.authorization_details).toEqual([expect.objectContaining(READ[0])]);
    expect(res.body.token_type).toBe("DPoP");
    expect(typeof res.body.refresh_token).toBe("string");
    const claims = decodeJwt(res.body.access_token as string);
    expect(claims.sub).toBe("alice");
    expect(claims.aud).toBe(RESOURCE);
    expect(claims.authorization_details).toEqual(res.body.authorization_details);
    expect((claims.mission as { id?: string }).id).toBe(record?.id);
  });

  it("refuses every later request presenting a redeemed device_code with invalid_grant", async () => {
    const s = await approvedSession();
    expect((await poll(PUBLIC, s.deviceCode, await newKeys())).status).toBe(200);
    const replay = await poll(PUBLIC, s.deviceCode, await newKeys());
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe("invalid_grant");
    expect(replay.body.access_token).toBeUndefined();
  });

  it("yields exactly one success response to concurrent requests presenting one approved device_code", async () => {
    const s = await approvedSession();
    const keys = await Promise.all(Array.from({ length: 6 }, () => newKeys()));
    const results = await Promise.all(keys.map((k) => poll(PUBLIC, s.deviceCode, k)));
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
    for (const r of results.filter((x) => x.status !== 200)) expect(r.body.error).toBe("invalid_grant");
  });

  it("roots the Mission's grant lineage at the device grant: every refresh resolves to the same Mission", async () => {
    const s = await approvedSession();
    const record = missionOf(s.uid);
    const keys = await newKeys();
    const first = await poll(PUBLIC, s.deviceCode, keys);
    expect(first.status, JSON.stringify(first.body)).toBe(200);
    let refreshToken = first.body.refresh_token as string;
    // The second refresh also presents another Intent, which changes nothing.
    const other = JSON.stringify({ intent: { ...INTENT, goal: "Wire the treasury out." } });
    for (const extra of [{}, { mission_intent: other }]) {
      const refreshed = await token(
        { grant_type: "refresh_token", refresh_token: refreshToken, ...extra },
        { client_id: PUBLIC },
        keys,
      );
      expect(refreshed.status, JSON.stringify(refreshed.body)).toBe(200);
      expect((decodeJwt(refreshed.body.access_token as string).mission as { id?: string }).id).toBe(record?.id);
      refreshToken = (refreshed.body.refresh_token as string | undefined) ?? refreshToken;
    }
  });

  it("issues an ID Token on a self-approved openid request, reporting openid in the granted scope", async () => {
    const s = await approvedSession(PUBLIC, { sub: "alice" }, { scope: "openid" });
    const res = await poll(PUBLIC, s.deviceCode, await newKeys());
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(typeof res.body.id_token).toBe("string");
    expect(String(res.body.scope).split(" ")).toContain("openid");
  });
});
