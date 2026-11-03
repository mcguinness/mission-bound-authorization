/**
 * @spec request-provenance#capture, request-provenance#intake-isolation,
 * request-provenance#signing, request-provenance#assertion,
 * request-provenance#recorded-facts, request-provenance#privacy-considerations
 * (#939 slice 2b-1, D1119 Q6)
 *
 * The demo request intake (`request-intake.ts`) end to end, in one
 * in-process test assembly on ephemeral ports and a controlled clock:
 *
 *  - the reference IdP (`approver-idp.ts`), hosting the originator Alice,
 *    with the intake registered as a relying party of its own;
 *  - the intake, which logs Alice in there with her password and the
 *    one-time code her enrolled device receives, captures her instruction in
 *    that session, and signs only from that capture through the workflow
 *    token;
 *  - the authorization server, with `mission-request-provenance` enabled for
 *    this assembly only, through the build option, from a trust
 *    configuration built from `intake.signer()` by
 *    `parseRequestProvenanceConfig`, and required for every push;
 *  - a stand-in shaper, playing ap-agent, that holds only what the console
 *    hands it: the instruction and the workflow token.
 *
 * No assertion here is minted by the test for the intake: each comes from
 * the intake's endpoints. The test mints only what an untrusted party could
 * (the agent's own key) or what a different configured signer would (the
 * device-style signer, a key the test holds), to show the authorization
 * server refusing them.
 *
 * The privacy probe checks this service's outputs over the inputs it tries.
 * The intake never discloses a capture secret, so only the secretless half
 * of the probe can run here; the library's privacy tests confirm the true
 * instruction under the secret and isolate each change of request, media
 * type and secret. No number of passing cases is a proof of cryptographic
 * secrecy.
 */

const controlledClock = await vi.hoisted(async () => {
  const { CONTROLLED_CLOCK_MS, installControlledClock } = await import("./controlled-clock.helper.js");
  return installControlledClock(CONTROLLED_CLOCK_MS);
});

import { createHash, createHmac, randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
  APPROVER_LOGIN_CALLBACK_PATH,
  ApprovalSessionStore,
  buildAuthorizationServer,
  provisionalIntentHash,
} from "@mission/authorization-server";
import { CANONICAL_RESOURCE, parseRequestProvenanceConfig } from "@mission/demo-data";
import {
  createRequestIntake,
  type JsonObject,
  requestDigest,
  requestDigestInput,
} from "@mission/request-provenance";
import { exportJWK, generateKeyPair } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { type ApprovalConsole, recordApproverLogin, resolveMissionApproval } from "../src/approval-console.js";
import { type ApproverAccount, type ApproverIdp, type CompletedLogin, startApproverIdp } from "../src/approver-idp.js";
import { clientAssertionSigner, submitMissionApproval } from "../src/oauth-client.js";
import {
  CAPTURE_PAGE_MEDIA_TYPE,
  REQUEST_INTAKE_CAPTURE_PATH,
  REQUEST_INTAKE_CLIENT_ID,
  REQUEST_INTAKE_SESSION_COOKIE,
  type RequestIntakeService,
  startRequestIntake,
} from "../src/request-intake.js";
import { FIXTURE_EXPIRES_AT } from "./relative-expiry.helper.js";

type Json = Record<string, unknown>;
type BuiltAs = Awaited<ReturnType<typeof buildAuthorizationServer>>;

const TYPE = "mission-request-provenance";
const AGENT = "ap-agent";
const MEDIA_TYPE = "text/plain;charset=utf-8";
const INSTRUCTION = "Read the approved invoices for Acme, nothing else.";
/** The intake's and the authorization server's maximum capture age. */
const MAX_CAPTURE_AGE_S = 60;
const ALICE = { sub: "idp-alice", username: "alice@acme.example" };
const DEVICE_SIGNER = "https://device-signer.example.org";
const DEVICE_KID = "device-1";
const DEVICE_CHANNEL = "https://device-signer.example.org/ch/app";
const AUTHORIZATION_DETAILS = JSON.stringify([
  { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] },
]);
const PUSHED_REQUEST_URN = "urn:ietf:params:oauth:request_uri:";

let idp: ApproverIdp;
let alice: ApproverAccount;
let intake: RequestIntakeService;
let asIssuer: string;
let asServer: Server;
let as: BuiltAs;
/** A second IdP and intake: a workflow this intake did not create. */
let otherIdp: ApproverIdp;
let otherIntake: RequestIntakeService;
const sessions = new ApprovalSessionStore();
let deviceKey: CryptoKey;

/** A listener on any free port, its handler attached once the party behind it exists. */
async function listening(): Promise<{ server: Server; origin: string }> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  return { server, origin: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

/** Start an intake for `audience` and an IdP hosting Alice, with the intake registered there. */
async function intakeWithIdp(audience: string): Promise<{ intake: RequestIntakeService; idp: ApproverIdp }> {
  let provider: ApproverIdp | undefined;
  const service = await startRequestIntake({
    audience,
    presenter: { client_id: AGENT },
    maxCaptureAgeSeconds: MAX_CAPTURE_AGE_S,
    assertionLifetimeSeconds: 60,
    originatorIdp: async (redirectUri) => {
      provider = await startApproverIdp({
        redirectUri: `${audience}${APPROVER_LOGIN_CALLBACK_PATH}`,
        accounts: [ALICE],
        clients: [{ clientId: REQUEST_INTAKE_CLIENT_ID, redirectUri }],
        idTokenAmr: true,
      });
      const credentials = provider.clients.get(REQUEST_INTAKE_CLIENT_ID) as { clientId: string; clientSecret: string };
      return { issuer: provider.issuer, ...credentials, originators: [ALICE.sub], acrValues: ["mfa"] };
    },
  });
  return { intake: service, idp: provider as ApproverIdp };
}

beforeAll(async () => {
  // The authorization server's listener first: the intake signs for its
  // issuer, and the authorization server trusts the intake's key.
  const listener = await listening();
  asServer = listener.server;
  asIssuer = listener.origin;
  ({ intake, idp } = await intakeWithIdp(asIssuer));
  alice = idp.accounts.get(ALICE.username) as ApproverAccount;
  ({ intake: otherIntake, idp: otherIdp } = await intakeWithIdp(asIssuer));

  const device = await generateKeyPair("ES256", { extractable: true });
  deviceKey = device.privateKey;
  const deviceJwk = await exportJWK(device.publicKey);
  const trust = parseRequestProvenanceConfig({
    enabled: true,
    clock_skew_seconds: 5,
    max_assertion_lifetime_seconds: 120,
    max_capture_age_seconds: MAX_CAPTURE_AGE_S,
    signers: [
      intake.signer(),
      // A device-style signer: a key the AS bound to someone other than Alice.
      {
        iss: DEVICE_SIGNER,
        keys: [{ kid: DEVICE_KID, public_jwk: { kty: "EC", crv: "P-256", x: deviceJwk.x, y: deviceJwk.y }, evidence_types: [TYPE], algs: ["ES256"] }],
        originators: [{ iss: idp.issuer, sub: "idp-bob" }],
        channel_types: [DEVICE_CHANNEL],
      },
    ],
  });
  as = await buildAuthorizationServer({
    issuer: asIssuer,
    allowHeadlessAdjudication: true,
    approvalSessions: sessions,
    requiredIntentEvidenceTypes: [TYPE],
    requestProvenance: { config: trust },
  });
  asServer.on("request", as.provider.callback());
});

afterAll(async () => {
  asServer?.closeAllConnections();
  asServer?.close();
  await intake?.close();
  await otherIntake?.close();
  await idp?.close();
  await otherIdp?.close();
  controlledClock.restore();
});

/** A user agent: one cookie jar per origin, as a browser keeps them. */
class UserAgent {
  private readonly jars = new Map<string, Map<string, string>>();

  async fetch(url: string | URL, init: RequestInit = {}): Promise<Response> {
    const target = new URL(url);
    const jar = this.jars.get(target.origin) ?? new Map<string, string>();
    this.jars.set(target.origin, jar);
    const headers = new Headers(init.headers);
    if (jar.size) headers.set("cookie", [...jar].map(([k, v]) => `${k}=${v}`).join("; "));
    const res = await fetch(target, { ...init, headers, redirect: "manual" });
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = (pair as string).indexOf("=");
      jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
    }
    return res;
  }

  cookie(origin: string, name: string): string | undefined {
    return this.jars.get(origin)?.get(name);
  }
}

/**
 * Alice signs in at `service` through `provider`, in a user agent of her own:
 * her password, then the code her device received, or no second factor. The
 * user agent, the console, holds the intake session; the provider's own
 * record of the login is returned beside it.
 */
async function signIn(
  secondFactor: "code" | "skip",
  service: RequestIntakeService = intake,
  provider: ApproverIdp = idp,
): Promise<{ ua: UserAgent; login: CompletedLogin }> {
  const account = provider.accounts.get(ALICE.username) as ApproverAccount;
  const ua = new UserAgent();
  let res = await ua.fetch(`${service.issuer}/login`);
  expect(res.status).toBe(303);
  res = await ua.fetch(res.headers.get("location") as string);
  const page = new URL(res.headers.get("location") as string, provider.issuer);
  const form = (step: string, body: Record<string, string>) =>
    ua.fetch(new URL(`${page.pathname}/${step}`, provider.issuer), {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(body).toString(),
    });
  const before = provider.logins.length;
  expect((await form("password", { username: account.username, password: account.password })).status).toBe(200);
  res = secondFactor === "code" ? await form("code", { code: account.device.latest() as string }) : await form("skip", {});
  let location = res.headers.get("location");
  while (location && new URL(location, provider.issuer).origin === provider.issuer) {
    res = await ua.fetch(new URL(location, provider.issuer));
    location = res.headers.get("location");
  }
  expect(location && new URL(location).origin).toBe(service.issuer);
  // The callback opens the session and sends the user agent on to the capture page.
  res = await ua.fetch(location as string);
  expect(res.status, await res.clone().text()).toBe(303);
  expect(res.headers.get("location")).toBe(`${service.issuer}${REQUEST_INTAKE_CAPTURE_PATH}`);
  expect(ua.cookie(service.issuer, REQUEST_INTAKE_SESSION_COOKIE)).toBeTruthy();
  res = await ua.fetch(res.headers.get("location") as string);
  expect(res.status, await res.clone().text()).toBe(200);
  expect(res.headers.get("content-type")).toBe("text/html; charset=utf-8");
  expect(provider.logins.length).toBe(before + 1);
  return { ua, login: provider.logins.at(-1) as CompletedLogin };
}

const captureBody = (instruction: string, mediaType = MEDIA_TYPE): Json => ({
  instruction: Buffer.from(instruction, "utf8").toString("base64url"),
  media_type: mediaType,
});

/** A capture request, from `ua` (the console) or, absent, from a party holding no intake session. */
async function capture(ua: UserAgent | undefined, body: unknown, headers: Record<string, string> = {}, service = intake) {
  const init = {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  };
  const res = ua ? await ua.fetch(`${service.issuer}/capture`, init) : await fetch(`${service.issuer}/capture`, init);
  return { status: res.status, body: (await res.json()) as Json };
}

async function captured(ua: UserAgent, instruction = INSTRUCTION, mediaType = MEDIA_TYPE, service = intake) {
  const r = await capture(ua, captureBody(instruction, mediaType), {}, service);
  expect(r.status, JSON.stringify(r.body)).toBe(201);
  return r.body as { capture_id: string; workflow_token: string };
}

/** A signing request, as the shaper makes it: the workflow token as a bearer credential, no cookie. */
async function sign(token: string | undefined, body: unknown, extraHeaders: Record<string, string> = {}, path = "/sign") {
  const res = await fetch(`${intake.issuer}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(token !== undefined ? { authorization: `Bearer ${token}` } : {}),
      ...extraHeaders,
    },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as Json };
}

/** No assertion: a refusal, and the intake issued nothing. */
function expectNoAssertion(r: { status: number; body: Json }, assertionsBefore: number): void {
  expect(r.status, JSON.stringify(r.body)).toBeGreaterThanOrEqual(400);
  expect(r.status).toBeLessThan(500);
  expect(r.body).not.toHaveProperty("assertion");
  expect(intake.counts().assertions).toBe(assertionsBefore);
}

/** The stand-in shaper's Intent: it reads the instruction and copies none of its wording. */
const shapeIntent = (goal = "Read approved invoices"): JsonObject => ({
  goal,
  target_resources: [CANONICAL_RESOURCE],
  expires_at: FIXTURE_EXPIRES_AT,
});

/**
 * The stand-in shaper, playing ap-agent: its one input is the console's
 * handoff, the instruction it must shape and the workflow token. It holds no
 * intake session and no capture_id. It shapes, then asks the intake to sign.
 */
async function shaper(handoff: { instruction: string; workflowToken: string }) {
  const shapingStartedAt = Math.floor(Date.now() / 1000);
  const keys = Object.keys(handoff).sort();
  const intent = shapeIntent();
  const signed = await sign(handoff.workflowToken, { intent });
  return { keys, shapingStartedAt, intent, signed };
}

const decodePart = (part: string): Json => JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as Json;
const claimsOf = (assertion: unknown): Json => decodePart(String(assertion).split(".")[1] as string);
const headerOf = (assertion: unknown): Json => decodePart(String(assertion).split(".")[0] as string);
/** A NumericDate as the RFC 3339 timestamp the facts record. */
const rfc3339 = (s: number) => `${new Date(s * 1000).toISOString().slice(0, 19)}Z`;

const PKCE_VERIFIER = "request-intake-e2e-verifier-0123456789-0123456789";
const pkceChallenge = () => createHash("sha256").update(PKCE_VERIFIER).digest("base64url");

/** A pushed authorization request as ap-agent carrying `submission`: the raw status and body. */
async function push(submission: unknown): Promise<{ status: number; body: Json }> {
  const assertion = await (await clientAssertionSigner(asIssuer, as.agentClientJwk))();
  const res = await fetch(`${asIssuer}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: AGENT,
      response_type: "code",
      redirect_uri: "http://localhost:9999/cb",
      resource: CANONICAL_RESOURCE,
      code_challenge: pkceChallenge(),
      code_challenge_method: "S256",
      mission_intent: JSON.stringify(submission),
      authorization_details: AUTHORIZATION_DETAILS,
      client_assertion: assertion,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  return { status: res.status, body: (await res.json()) as Json };
}

function expectEvidenceRefusal(r: { status: number; body: Json }, reason: string): void {
  expect(r.status, JSON.stringify(r.body)).toBe(400);
  expect(r.body.error).toBe("invalid_mission_intent_evidence");
  expect(String(r.body.error_description)).toContain(reason);
}

/** Push, authorize, render and approve, as Bob on the trusted approval surface: the Mission the approval created. */
async function approveThrough(intent: JsonObject, entry: Json) {
  const pending = await submitMissionApproval(asIssuer, as.agentClientJwk, {
    missionIntent: JSON.stringify({ intent, evidence: [entry] }),
    authorizationDetails: AUTHORIZATION_DETAILS,
  });
  expect(pending.par.response.request_uri.startsWith(PUSHED_REQUEST_URN)).toBe(true);
  const approver: ApprovalConsole = { sessions, login: recordApproverLogin({ sub: "bob", acr: "mfa" }) };
  const code = await resolveMissionApproval(asIssuer, approver, pending, "approve");
  expect(code).toBeTruthy();
  const record = as.kernel.findByApprovalEvent(`apev_${pending.uid}`);
  expect(record).toBeDefined();
  return record as NonNullable<typeof record>;
}

describe("the demo request intake end to end (@spec request-provenance#capture, request-provenance#signing, request-provenance#assertion, request-provenance#recorded-facts, #939 slice 2b-1)", () => {
  it("Alice signs in at the IdP with her password and her device's code, the console captures her instruction, the shaper holding only the instruction and the workflow token obtains an assertion, and the push, authorization, rendering and decision record exactly that login's and capture's facts", async () => {
    // The login, some seconds before the capture, so its auth_time is its own.
    controlledClock.advance(5_000);
    const { ua, login } = await signIn("code");
    expect(login).toMatchObject({ sub: ALICE.sub, factors: ["pwd", "otp"], acr: "mfa" });
    controlledClock.advance(7_000);

    // 1. Capture, in Alice's session, before any shaping.
    const assertionsBefore = intake.counts().assertions;
    const capturesBefore = intake.counts().captures;
    const receipt = await captured(ua);
    expect(Object.keys(receipt).sort()).toEqual(["capture_id", "workflow_token"]);
    expect(Buffer.from(receipt.workflow_token, "base64url")).toHaveLength(32);
    expect(intake.counts().captures).toBe(capturesBefore + 1);
    expect(intake.counts().assertions).toBe(assertionsBefore);

    // 2. The console hands the shaper the instruction and the workflow token, nothing else.
    controlledClock.advance(3_000);
    const shaped = await shaper({ instruction: INSTRUCTION, workflowToken: receipt.workflow_token });
    expect(shaped.keys).toEqual(["instruction", "workflowToken"]);
    expect(shaped.signed.status, JSON.stringify(shaped.signed.body)).toBe(200);
    const entry = shaped.signed.body;
    expect(Object.keys(entry).sort()).toEqual(["assertion", "type"]);
    expect(entry.type).toBe(TYPE);
    const claims = claimsOf(entry.assertion);
    expect(headerOf(entry.assertion)).toEqual({ typ: "mission-request-provenance+jwt", alg: "ES256", kid: intake.kid });

    // Capture preceded shaping.
    expect(claims.captured_at as number).toBeLessThan(shaped.shapingStartedAt);
    expect(login.auth_time).toBeLessThan(claims.captured_at as number);
    // The intake's own computation, for the one AS it serves: this instance's issuer.
    expect(intake.audience).toBe(as.provider.issuer);
    expect(claims.aud).toBe(as.provider.issuer);
    expect(claims.intent_hash).toBe(provisionalIntentHash(as.provider.issuer, shaped.intent as never));
    // The presenter captured with the request: the one client the intake serves, no cnf.
    expect(claims.presenter).toEqual({ client_id: AGENT });
    expect(claims.originator).toEqual({ iss: idp.issuer, sub: ALICE.sub });
    expect(claims.channel).toEqual({ type: intake.channelType, acr: login.acr, amr: login.factors, auth_time: login.auth_time });

    // 3. The push (201), the authorization endpoint, the rendering and the decision.
    const record = await approveThrough(shaped.intent, entry);
    expect(record.submission_evidence).toHaveLength(1);
    expect(record.submission_evidence?.[0]?.type).toBe(TYPE);
    expect(record.submission_evidence?.[0]?.facts).toEqual({
      signer: { iss: intake.issuer, kid: intake.kid },
      originator: { iss: idp.issuer, sub: ALICE.sub },
      channel: { type: intake.channelType, acr: login.acr, amr: login.factors, auth_time: login.auth_time },
      captured_at: rfc3339(claims.captured_at as number),
      request_digest: claims.request_digest,
      assertion_id: claims.jti,
      capture_id: receipt.capture_id,
    });
    expect(String(claims.request_digest)).toMatch(/^hmac-sha-256:[A-Za-z0-9_-]{43}$/);
    expect(intake.counts().assertions).toBe(assertionsBefore + 1);
  });

  it("a password-only login yields the channel the IdP asserted for that login: acr pwd, amr pwd and its own auth_time, recorded at the push", async () => {
    controlledClock.advance(4_000);
    const { ua, login } = await signIn("skip");
    expect(login).toMatchObject({ sub: ALICE.sub, factors: ["pwd"], acr: "pwd" });
    controlledClock.advance(6_000);
    const receipt = await captured(ua);
    const shaped = await shaper({ instruction: INSTRUCTION, workflowToken: receipt.workflow_token });
    expect(shaped.signed.status, JSON.stringify(shaped.signed.body)).toBe(200);
    const claims = claimsOf(shaped.signed.body.assertion);
    expect(claims.channel).toEqual({ type: intake.channelType, acr: "pwd", amr: ["pwd"], auth_time: login.auth_time });
    expect(login.auth_time).toBeLessThan(claims.captured_at as number);
    const record = await approveThrough(shaped.intent, shaped.signed.body);
    expect(record.submission_evidence?.[0]?.facts?.channel).toEqual(claims.channel);
  });
});

describe("capture needs the originator's intake session (@spec request-provenance#capture, request-provenance#intake-isolation, #939 slice 2b-1)", () => {
  it("refuses a capture with no intake session, a forged session cookie, or the workflow token as its credential, and creates no capture record", async () => {
    const { ua } = await signIn("code");
    const token = (await captured(ua)).workflow_token;
    const before = intake.counts().captures;
    const refusals = [
      await capture(undefined, captureBody(INSTRUCTION)),
      await capture(undefined, captureBody(INSTRUCTION), { cookie: `${REQUEST_INTAKE_SESSION_COOKIE}=${randomBytes(32).toString("base64url")}` }),
      await capture(undefined, captureBody(INSTRUCTION), { authorization: `Bearer ${token}` }),
    ];
    for (const r of refusals) {
      expect(r.status, JSON.stringify(r.body)).toBe(401);
      expect(r.body).not.toHaveProperty("capture_id");
      expect(r.body).not.toHaveProperty("workflow_token");
    }
    expect(intake.counts().captures).toBe(before);
    // The session itself still captures.
    await captured(ua);
    expect(intake.counts().captures).toBe(before + 1);
  });

  it("serves the capture page only in the originator's intake session and with no parameter: HTML whose one script posts to the capture endpoint from this origin (#939 slice 2b-2)", async () => {
    const page = `${intake.issuer}${REQUEST_INTAKE_CAPTURE_PATH}`;
    const forged = { cookie: `${REQUEST_INTAKE_SESSION_COOKIE}=${randomBytes(32).toString("base64url")}` };
    for (const res of [await fetch(page), await fetch(page, { headers: forged })]) {
      expect(res.status).toBe(401);
      expect(((await res.json()) as Json).error).toBe("login_required");
    }
    const { ua } = await signIn("code");
    expect((await ua.fetch(`${page}?instruction=x`)).status).toBe(400);
    const res = await ua.fetch(page);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(res.headers.get("cache-control")).toBe("no-store");
    const csp = res.headers.get("content-security-policy") as string;
    const nonce = /script-src 'nonce-([A-Za-z0-9_-]+)'/.exec(csp)?.[1];
    expect(nonce).toBeTruthy();
    expect(csp).toContain("connect-src 'self'");
    expect(csp).toContain("form-action 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    const html = await res.text();
    expect(html).toContain('<form id="capture">');
    expect(html).toContain(`<script nonce="${nonce}">`);
    expect(html.match(/<script/g)).toHaveLength(1);
    expect(html).toContain(`fetch(${JSON.stringify(REQUEST_INTAKE_CAPTURE_PATH)}`);
    expect(html).toContain(JSON.stringify(CAPTURE_PAGE_MEDIA_TYPE));
    // The page creates no capture record.
    const before = intake.counts().captures;
    await ua.fetch(page);
    expect(intake.counts().captures).toBe(before);
  });

  it.each([
    ["originator", { originator: { iss: "https://idp.example.org", sub: "mallory" } }],
    ["channel", { channel: { type: "https://intake.example.org/ch/app", acr: "mfa", amr: ["pwd", "otp"] } }],
    ["presenter", { presenter: { client_id: "agent-A1" } }],
    ["workflow", { workflow: "wf-chosen" }],
    ["captured_at", { captured_at: 1 }],
  ])("refuses a capture whose body names %s, in the originator's own session, and creates no capture record", async (_name, extra) => {
    const { ua } = await signIn("code");
    const before = intake.counts().captures;
    const r = await capture(ua, { ...captureBody(INSTRUCTION), ...extra });
    expect(r.status, JSON.stringify(r.body)).toBe(400);
    expect(r.body).not.toHaveProperty("capture_id");
    expect(intake.counts().captures).toBe(before);
    // The same session and instruction, without the member, capture.
    await captured(ua);
    expect(intake.counts().captures).toBe(before + 1);
  });
});

describe("shaper-supplied capture substitution (@spec request-provenance#signing, request-provenance#intake-isolation, #939 slice 2b-1)", () => {
  it("yields no assertion for an unknown workflow token, another intake's workflow token or no token, while the workflow's own token signs", async () => {
    const { ua } = await signIn("code");
    const mine = await captured(ua);
    const elsewhere = await captured((await signIn("code", otherIntake, otherIdp)).ua, INSTRUCTION, MEDIA_TYPE, otherIntake);
    const before = intake.counts().assertions;
    expectNoAssertion(await sign(randomBytes(32).toString("base64url"), { intent: shapeIntent() }), before);
    expectNoAssertion(await sign(elsewhere.workflow_token, { intent: shapeIntent() }), before);
    expectNoAssertion(await sign(undefined, { intent: shapeIntent() }), before);
    expectNoAssertion(await sign(undefined, { intent: shapeIntent() }, { authorization: `Basic ${Buffer.from(`${AGENT}:x`).toString("base64")}` }), before);
    // The console's session is no signing credential either.
    const viaSession = await ua.fetch(`${intake.issuer}/sign`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ intent: shapeIntent() }),
    });
    expect(viaSession.status).toBe(401);
    expect(intake.counts().assertions).toBe(before);
    const signed = await sign(mine.workflow_token, { intent: shapeIntent() });
    expect(signed.status, JSON.stringify(signed.body)).toBe(200);
    expect(claimsOf(signed.body.assertion).capture_id).toBe(mine.capture_id);
  });

  it("yields no assertion for a signing request naming a capture_id, forged or another workflow's, beside the Intent", async () => {
    const { ua } = await signIn("code");
    const mine = await captured(ua);
    const theirs = await captured(ua, "Pay every invoice from Globex.");
    const before = intake.counts().assertions;
    for (const captureId of [randomBytes(16).toString("base64url"), theirs.capture_id, mine.capture_id]) {
      expectNoAssertion(await sign(mine.workflow_token, { intent: shapeIntent(), capture_id: captureId }), before);
    }
    const signed = await sign(mine.workflow_token, { intent: shapeIntent() });
    expect(claimsOf(signed.body.assertion).capture_id).toBe(mine.capture_id);
  });

  it.each([
    ["intent_hash", { intent_hash: "sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }],
    ["request_digest", { request_digest: "hmac-sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }],
    ["digest", { digest: "sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }],
    ["originator", { originator: { iss: "https://idp.example.org", sub: "mallory" } }],
    ["channel", { channel: { type: "https://intake.example.org/ch/app", acr: "mfa" } }],
    ["presenter", { presenter: { client_id: AGENT } }],
    ["audience", { audience: "https://other-as.example.org" }],
    ["aud", { aud: "https://other-as.example.org" }],
  ])("yields no assertion for a signing request naming %s, and the workflow's next assertion carries the captured facts unchanged", async (_name, extra) => {
    const { ua, login } = await signIn("code");
    const receipt = await captured(ua);
    const before = intake.counts().assertions;
    expectNoAssertion(await sign(receipt.workflow_token, { intent: shapeIntent(), ...extra }), before);
    const signed = await sign(receipt.workflow_token, { intent: shapeIntent() });
    expect(signed.status, JSON.stringify(signed.body)).toBe(200);
    const claims = claimsOf(signed.body.assertion);
    expect(claims).toMatchObject({
      aud: asIssuer,
      intent_hash: provisionalIntentHash(asIssuer, shapeIntent() as never),
      presenter: { client_id: AGENT },
      originator: { iss: idp.issuer, sub: ALICE.sub },
      channel: { type: intake.channelType, acr: login.acr, amr: login.factors, auth_time: login.auth_time },
      capture_id: receipt.capture_id,
    });
    expect(claims.presenter).toEqual({ client_id: AGENT });
  });

  it("the shaper, holding only the instruction and the workflow token, can create no capture record and alter none", async () => {
    const { ua } = await signIn("code");
    const receipt = await captured(ua);
    const first = await sign(receipt.workflow_token, { intent: shapeIntent() });
    const before = intake.counts();
    // A capture attempted with what the shaper holds, the original wording or its own.
    for (const instruction of [INSTRUCTION, "Pay every invoice from Globex."]) {
      for (const headers of [{}, { authorization: `Bearer ${receipt.workflow_token}` }]) {
        const r = await capture(undefined, captureBody(instruction), headers);
        expect(r.status, JSON.stringify(r.body)).toBe(401);
      }
    }
    expect(intake.counts()).toEqual(before);
    // The workflow's record is unchanged: the next assertion carries the same capture.
    const next = await sign(receipt.workflow_token, { intent: shapeIntent() });
    const [a, b] = [claimsOf(first.body.assertion), claimsOf(next.body.assertion)];
    expect(b.request_digest).toBe(a.request_digest);
    expect(b.captured_at).toBe(a.captured_at);
    expect(b.capture_id).toBe(receipt.capture_id);
    expect(b.jti).not.toBe(a.jti);
  });
});

describe("self-declared device identity at the push (@spec request-provenance#trust-configuration, request-provenance#verification, #939 slice 2b-1)", () => {
  /** Mint as `issuer`, under `kid` and `key`, claiming Alice and the intake's channel, for the Intent and this AS. */
  async function mintAs(issuer: string, kid: string, key: CryptoKey, channelType = intake.channelType) {
    const own = createRequestIntake({ issuer, kid, signingKey: key, assertionLifetimeSeconds: 60, maxCaptureAgeSeconds: 60 });
    const receipt = own.capture({
      workflow: "wf-agent",
      instruction: Buffer.from(INSTRUCTION, "utf8"),
      mediaType: MEDIA_TYPE,
      originator: { iss: idp.issuer, sub: ALICE.sub },
      channel: { type: channelType, acr: "mfa", amr: ["pwd", "otp"], auth_time: Math.floor(Date.now() / 1000) },
      presenter: { client_id: AGENT },
    });
    const signed = await own.sign({ captureId: receipt.captureId, workflow: "wf-agent", audience: asIssuer, intent: shapeIntent() });
    return signed.entry;
  }

  it("refuses invalid_mission_intent_evidence at step 3 an assertion the agent signs with its own key, under its own iss or the intake's", async () => {
    const agentKey = (await generateKeyPair("ES256", { extractable: true })).privateKey;
    expectEvidenceRefusal(await push({ intent: shapeIntent(), evidence: [await mintAs(`https://${AGENT}.example.org`, "ap-agent-device-1", agentKey)] }), "step 3");
    expectEvidenceRefusal(await push({ intent: shapeIntent(), evidence: [await mintAs(intake.issuer, "ap-agent-device-1", agentKey)] }), "step 3");
  });

  it("refuses invalid_mission_intent_evidence at step 8 an assertion from a configured device-style signer whose bound originator is someone other than the one it names", async () => {
    expectEvidenceRefusal(
      await push({ intent: shapeIntent(), evidence: [await mintAs(DEVICE_SIGNER, DEVICE_KID, deviceKey, DEVICE_CHANNEL)] }),
      "step 8",
    );
  });
});

describe("missing required evidence at the push (@spec request-provenance#verification, #939 slice 2b-1)", () => {
  it("refuses invalid_mission_intent_evidence a push from ap-agent without the entry where the AS requires mission-request-provenance, and accepts the intake's entry", async () => {
    const r = await push({ intent: shapeIntent() });
    expectEvidenceRefusal(r, `required evidence type absent: ${TYPE}`);
    const { ua } = await signIn("code");
    const receipt = await captured(ua);
    const signed = await sign(receipt.workflow_token, { intent: shapeIntent() });
    const accepted = await push({ intent: shapeIntent(), evidence: [signed.body] });
    expect(accepted.status, JSON.stringify(accepted.body)).toBe(201);
  });
});

describe("a dictionary probe over the service's assertions (@spec request-provenance#privacy-considerations, request-provenance#assertion, #939 slice 2b-1)", () => {
  const CANDIDATES = ["Yes", "No", "Pay Acme", "Pay Acme.", "Pay Acme!", "pay acme.", "Pay Globex.", "Cancel it.", "Approve all."];

  /** Every secretless encoding of a value a holder might test a guess against. */
  function secretlessForms(bytes: Buffer): string[] {
    const sha = createHash("sha256").update(bytes).digest();
    return [
      bytes.toString("utf8"),
      bytes.toString("hex"),
      bytes.toString("base64"),
      bytes.toString("base64url"),
      sha.toString("hex"),
      sha.toString("base64"),
      sha.toString("base64url"),
      `sha-256:${sha.toString("base64url")}`,
    ].filter((s) => s.length > 0);
  }

  /** Secretless commitments to a candidate instruction under the media type, guessed secrets included. */
  function candidateProbes(candidate: string): string[] {
    const bytes = Buffer.from(candidate, "utf8");
    const input = requestDigestInput(MEDIA_TYPE, bytes);
    const probes = [...secretlessForms(bytes), ...secretlessForms(input)];
    for (const guess of [Buffer.alloc(32), Buffer.from(Array.from({ length: 32 }, (_, i) => i + 1))]) {
      probes.push(requestDigest(guess, MEDIA_TYPE, bytes));
    }
    probes.push(`hmac-sha-256:${createHmac("sha256", Buffer.alloc(0)).update(input).digest("base64url")}`);
    return probes;
  }

  /** Every string in a JSON value, member names included, numbers as text. */
  function stringLeaves(value: unknown): string[] {
    if (typeof value === "string") return [value];
    if (typeof value === "number" || typeof value === "boolean") return [String(value)];
    if (Array.isArray(value)) return value.flatMap(stringLeaves);
    if (value !== null && typeof value === "object") return Object.entries(value).flatMap(([k, v]) => [k, ...stringLeaves(v)]);
    return [];
  }

  it("no member of the service's assertions other than intent_hash, nor of the recorded facts, equals or contains a secretless commitment to any candidate of a low-entropy instruction set", async () => {
    const { ua } = await signIn("code");
    const published: [string, unknown][] = [];
    for (const instruction of CANDIDATES) {
      const receipt = await captured(ua, instruction);
      const signed = await sign(receipt.workflow_token, { intent: shapeIntent() });
      expect(signed.status, JSON.stringify(signed.body)).toBe(200);
      const claims = claimsOf(signed.body.assertion);
      for (const [name, value] of Object.entries(claims)) if (name !== "intent_hash") published.push([`${instruction}: ${name}`, value]);
      published.push([`${instruction}: header`, headerOf(signed.body.assertion)]);
      if (instruction === "Pay Acme.") {
        const record = await approveThrough(shapeIntent(), signed.body);
        published.push([`${instruction}: facts`, record.submission_evidence?.[0]?.facts]);
      }
    }
    // A probe shorter than 8 characters (a bare word) is matched only as a
    // whole value, since a random identifier can contain two letters by chance.
    for (const candidate of CANDIDATES) {
      for (const probe of candidateProbes(candidate)) {
        for (const [where, value] of published) {
          const hit = stringLeaves(value).some((leaf) => (probe.length >= 8 ? leaf.includes(probe) : leaf === probe));
          expect(hit, `${candidate} via ${where}`).toBe(false);
        }
      }
    }
  });

  it("request_digest differs for the same instruction and media type captured again, and for another instruction or media type", async () => {
    const { ua } = await signIn("code");
    const digestOf = async (instruction: string, mediaType: string) => {
      const receipt = await captured(ua, instruction, mediaType);
      const signed = await sign(receipt.workflow_token, { intent: shapeIntent() });
      return claimsOf(signed.body.assertion).request_digest as string;
    };
    const digests = [
      await digestOf("Pay Acme.", MEDIA_TYPE),
      await digestOf("Pay Acme.", MEDIA_TYPE),
      await digestOf("Pay Acme!", MEDIA_TYPE),
      await digestOf("Pay Acme.", "text/plain"),
    ];
    expect(new Set(digests).size).toBe(digests.length);
  });
});

describe("a revision past the maximum capture age needs a new capture (@spec request-provenance#signing, #939 slice 2b-1)", () => {
  it("a revised Intent within the maximum capture age gets a fresh assertion from the same capture, and past it the service yields none until the originator's instruction is captured again", async () => {
    const { ua } = await signIn("code");
    const receipt = await captured(ua);
    const first = await sign(receipt.workflow_token, { intent: shapeIntent() });
    expect(first.status, JSON.stringify(first.body)).toBe(200);
    // Within the maximum capture age: a revision gets a fresh jti from the same capture.
    const revised = shapeIntent("Read approved invoices from October");
    const second = await sign(receipt.workflow_token, { intent: revised });
    expect(second.status, JSON.stringify(second.body)).toBe(200);
    const [a, b] = [claimsOf(first.body.assertion), claimsOf(second.body.assertion)];
    expect(b.jti).not.toBe(a.jti);
    expect(b.intent_hash).toBe(provisionalIntentHash(asIssuer, revised as never));
    expect(b.intent_hash).not.toBe(a.intent_hash);
    expect(b.capture_id).toBe(receipt.capture_id);
    expect(b.request_digest).toBe(a.request_digest);
    expect((await push({ intent: revised, evidence: [second.body] })).status).toBe(201);

    // Past the maximum capture age: no assertion for a further revision.
    controlledClock.advance((MAX_CAPTURE_AGE_S + 2) * 1000);
    expect(Math.floor(Date.now() / 1000) - (a.captured_at as number)).toBeGreaterThan(MAX_CAPTURE_AGE_S);
    const before = intake.counts().assertions;
    const late = await sign(receipt.workflow_token, { intent: shapeIntent("Read approved invoices from November") });
    expectNoAssertion(late, before);
    expect(late.body.error).toBe("capture_too_old");

    // A new capture, the instruction received from the originator again, signs.
    const again = await captured(ua);
    const fresh = await sign(again.workflow_token, { intent: shapeIntent("Read approved invoices from November") });
    expect(fresh.status, JSON.stringify(fresh.body)).toBe(200);
    const c = claimsOf(fresh.body.assertion);
    expect(c.capture_id).toBe(again.capture_id);
    expect(c.capture_id).not.toBe(receipt.capture_id);
    expect(c.captured_at as number).toBeGreaterThan(a.captured_at as number);
  });
});
