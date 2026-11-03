/**
 * @spec request-provenance#capture, request-provenance#intake-isolation
 * (#939 slice 2b-2, D1221)
 *
 * The as-native target launched with its opt-in request intake
 * (`MISSION_REQUEST_INTAKE=1`, which configures the demo request intake and
 * the AS's `mission-request-provenance` type together), driven by a real
 * browser: system Google Chrome through `playwright-core`, headless. Chrome
 * opens the intake's login, completes Alice's password and one-time code at
 * the reference IdP, follows the callback to the capture page, submits her
 * instruction there and reads the workflow token from the page. The test's
 * agent code then shapes an Intent, asks the intake to sign it with that
 * token, and pushes it as ap-agent; Bob approves at the trusted approval
 * console, logging in at the same IdP as an account of his own.
 *
 * Chrome is the cookie and session witness: what it stores for the intake's
 * session cookie, what a page's script can read, and what it sends on a
 * request another site initiates and to another port of the same host.
 * `localhost` and `127.0.0.1` are different sites, so a page this test serves
 * on `localhost` is cross-site to the intake on `127.0.0.1`. On one host,
 * though, every port is the same site and receives the same cookies (RFC 6265
 * Section 8.5): the IdP and the intake receive each other's, which this file
 * witnesses rather than hides. A deployment gives each party its own host.
 *
 * Two choices keep it deterministic beside the parallel suite:
 *
 *  - The payments resource audience is this file's own
 *    (`MCP_PAYMENTS_RESOURCE`, set before any module loads), so this
 *    composition never contends for 4403 with another file's.
 *  - The Node services run on the controlled clock, installed before any
 *    module loads and advanced by the test, but anchored at the instant the
 *    file loads rather than at the fixed `CONTROLLED_CLOCK_MS`: Chrome's
 *    cookie store keeps the host's clock, and the reference IdP's
 *    oidc-provider cookies carry an absolute `Expires` computed from the Node
 *    clock, so a fixed instant more than their lifetime behind the host's
 *    date makes Chrome discard them and no login completes. Every instant the
 *    test uses derives from that clock, never from a fixed date.
 *
 * The test fails when Chrome does not launch. `MISSION_SKIP_BROWSER=1` skips
 * it, for a contributor without Chrome; the skip is announced, never silent.
 */

const hoisted = await vi.hoisted(async () => {
  const resource = process.env.MCP_PAYMENTS_RESOURCE;
  process.env.MCP_PAYMENTS_RESOURCE = "http://localhost:15172/mcp";
  const { installControlledClock } = await import("./controlled-clock.helper.js");
  return { resource, clock: installControlledClock(Date.now()) };
});

import { mkdtempSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { provisionalIntentHash } from "@mission/authorization-server";
import { CANONICAL_RESOURCE, REQUEST_PROVENANCE_CONFIG } from "@mission/demo-data";
import { Fga } from "@mission/pdp";
import { type Browser, type BrowserContext, chromium, type Page } from "playwright-core";
import { afterAll, beforeAll, describe, expect, it, type MockInstance, vi } from "vitest";
import { resolveMissionApproval, type UpstreamApprovalConsole } from "../src/approval-console.js";
import type { CompletedLogin } from "../src/approver-idp.js";
import { type AsNativeLaunch, asNativeLaunchOptions, launchAsNative } from "../src/as-native.js";
import { clientAssertionSigner, submitMissionApproval } from "../src/oauth-client.js";
import { REQUEST_INTAKE_CAPTURE_PATH, REQUEST_INTAKE_SESSION_COOKIE } from "../src/request-intake.js";
import { daysFromNow } from "./relative-expiry.helper.js";

type Json = Record<string, unknown>;

const SKIP_BROWSER = process.env.MISSION_SKIP_BROWSER === "1";
if (SKIP_BROWSER) console.warn("MISSION_SKIP_BROWSER=1: skipping the real-browser witness of the request intake (#939 slice 2b-2)");
const browserDescribe = SKIP_BROWSER ? describe.skip : describe;

// A browser, a whole target and its shutdown take longer than the defaults under a loaded suite.
vi.setConfig({ testTimeout: 60_000, hookTimeout: 120_000 });

const AS_PORT = 15171;
const TYPE = "mission-request-provenance";
const AGENT = "ap-agent";
const INSTRUCTION = "Read the approved invoices for Acme, nothing else.";
const STUB_BOOTSTRAP = {
  fga: { checkWithContext: async () => true, checkStored: async () => true, client: { write: async () => ({}) }, modelId: "test" },
  storeId: "test",
  modelId: "test",
};
const AUTHORIZATION_DETAILS = JSON.stringify([
  { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"], constraints: { vendors: ["acme"] } },
]);

let browser: Browser | undefined;
let launched: AsNativeLaunch | undefined;
let fgaBootstrap: MockInstance | undefined;
/** Pages a third party serves, on loopback: reached as `localhost` (another site) or `127.0.0.1` (the intake's site). */
let pages: { server: Server; port: number } | undefined;

const authServer = () => {
  const as = launched?.stack.authServer;
  if (!as) throw new Error("the as-native target runs the AS");
  return as;
};
const intake = () => {
  const composed = authServer().requestIntake;
  if (!composed) throw new Error("MISSION_REQUEST_INTAKE=1 starts the request intake");
  return composed;
};
const provider = () => {
  const idp = authServer().approverProvider;
  if (!idp) throw new Error("the as-native target starts the upstream provider");
  return idp;
};

/** Third-party pages that send Chrome to the intake: a top-level form POST to the capture endpoint, and a link to the capture page. */
async function startThirdPartyPages(): Promise<{ server: Server; port: number }> {
  const server = createServer((req, res) => {
    const target = `${intake().service.issuer}${REQUEST_INTAKE_CAPTURE_PATH}`;
    const body =
      req.url === "/post"
        ? `<form method="post" action="${target}" enctype="text/plain"><input type="hidden" name="instruction" value="Pay every invoice from Globex."><button id="submit">Send</button></form>`
        : req.url === "/link"
          ? `<a id="go" href="${target}">Capture</a>`
          : "";
    res.statusCode = body ? 200 : 404;
    res.setHeader("content-type", "text/html; charset=utf-8");
    res.end(`<!doctype html><html><head><meta charset="utf-8"><title>Elsewhere</title></head><body>${body}</body></html>`);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  return { server, port: (server.address() as AddressInfo).port };
}

beforeAll(async () => {
  if (SKIP_BROWSER) return;
  try {
    browser = await chromium.launch({ channel: "chrome", headless: true });
  } catch (e) {
    throw new Error(
      `Chrome did not launch (playwright-core, channel "chrome", headless); set MISSION_SKIP_BROWSER=1 to skip this witness: ${(e as Error).message}`,
    );
  }
  fgaBootstrap = vi.spyOn(Fga, "bootstrap").mockResolvedValue(STUB_BOOTSTRAP as never);
  launched = await launchAsNative({
    ...asNativeLaunchOptions({ MISSION_REQUEST_INTAKE: "1", MISSION_EPHEMERAL_KEYS: "1", MISSION_EPHEMERAL_EVIDENCE_KEYS: "1" }),
    asPort: AS_PORT,
    claimsFile: join(mkdtempSync(join(tmpdir(), "intake-browser-claims-")), "claims.sqlite"),
    writeReservationsFile: join(mkdtempSync(join(tmpdir(), "intake-browser-reservations-")), "write-reservations.sqlite"),
  });
  pages = await startThirdPartyPages();
}, 120_000);

afterAll(async () => {
  await browser?.close();
  if (pages) await new Promise<void>((resolve) => pages?.server.close(() => resolve()));
  await launched?.close();
  fgaBootstrap?.mockRestore();
  hoisted.clock.restore();
  if (hoisted.resource === undefined) delete process.env.MCP_PAYMENTS_RESOURCE;
  else process.env.MCP_PAYMENTS_RESOURCE = hoisted.resource;
}, 120_000);

/** Whether anything accepts a TCP connection at `url`. */
async function accepts(url: string): Promise<boolean> {
  try {
    await fetch(url, { signal: AbortSignal.timeout(2_000) });
    return true;
  } catch {
    return false;
  }
}

/** One cookie's value in a Cookie header, or undefined. */
function cookieIn(header: string | undefined, name: string): string | undefined {
  return (header ?? "")
    .split(";")
    .map((s) => s.trim())
    .find((s) => s.startsWith(`${name}=`))
    ?.slice(name.length + 1);
}

/**
 * Alice, in Chrome: the intake's login, her password and the code her device
 * received at the IdP, and the callback on to the capture page. Returns the
 * page and the IdP's own record of the login.
 */
async function signIn(context: BrowserContext): Promise<{ page: Page; login: CompletedLogin }> {
  const { service, originator } = intake();
  const before = provider().logins.length;
  const page = await context.newPage();
  await page.goto(`${service.issuer}/login`);
  await page.waitForURL((url) => url.origin === provider().issuer && url.pathname.startsWith("/interaction/"));
  await page.fill('input[name="username"]', originator.username);
  await page.fill('input[name="password"]', originator.password);
  await page.click('form[action$="/password"] button');
  await page.waitForSelector('input[name="code"]');
  await page.fill('input[name="code"]', originator.device.latest() as string);
  await page.click('form[action$="/code"] button');
  await page.waitForURL(`${service.issuer}${REQUEST_INTAKE_CAPTURE_PATH}`);
  await page.waitForSelector("form#capture");
  expect(provider().logins.length).toBe(before + 1);
  return { page, login: provider().logins.at(-1) as CompletedLogin };
}

/** Submit `instruction` on the intake's capture page, and read the handoff the page shows. */
async function captureOnPage(page: Page, instruction: string): Promise<{ captureId: string; workflowToken: string }> {
  await page.fill('textarea[name="instruction"]', instruction);
  const [response] = await Promise.all([
    page.waitForResponse((r) => r.url() === `${intake().service.issuer}${REQUEST_INTAKE_CAPTURE_PATH}` && r.request().method() === "POST"),
    page.click("form#capture button"),
  ]);
  expect(response.status()).toBe(201);
  await page.waitForSelector("#handoff:not([hidden])");
  return {
    captureId: (await page.textContent("#capture-id")) as string,
    workflowToken: (await page.textContent("#workflow-token")) as string,
  };
}

/** The agent's Intent: shaped from the instruction, copying none of its wording. */
const shapeIntent = (goal = "Read approved Acme invoices"): Json => ({
  goal,
  target_resources: [CANONICAL_RESOURCE],
  expires_at: daysFromNow(30),
});

/** The agent asks the intake to sign: the workflow token as a bearer credential, no cookie. */
async function sign(workflowToken: string, intent: Json): Promise<{ status: number; body: Json }> {
  const res = await fetch(`${intake().service.issuer}/sign`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${workflowToken}` },
    body: JSON.stringify({ intent }),
  });
  return { status: res.status, body: (await res.json()) as Json };
}

/** A pushed authorization request as ap-agent carrying `intent` and, where given, `entry`: the raw status and body. */
async function push(intent: Json, entry?: Json): Promise<{ status: number; body: Json }> {
  const { asUrl, agentClientJwk } = authServer();
  const assertion = await (await clientAssertionSigner(asUrl, agentClientJwk))();
  const res = await fetch(`${asUrl}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: AGENT,
      response_type: "code",
      redirect_uri: "http://localhost:9999/cb",
      resource: CANONICAL_RESOURCE,
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      code_challenge_method: "S256",
      mission_intent: JSON.stringify(entry ? { intent, evidence: [entry] } : { intent }),
      authorization_details: AUTHORIZATION_DETAILS,
      client_assertion: assertion,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  return { status: res.status, body: (await res.json()) as Json };
}

const claimsOf = (assertion: unknown): Json =>
  JSON.parse(Buffer.from(String(assertion).split(".")[1] as string, "base64url").toString("utf8")) as Json;
/** A NumericDate as the RFC 3339 timestamp the facts record. */
const rfc3339 = (s: number) => `${new Date(s * 1000).toISOString().slice(0, 19)}Z`;

browserDescribe("the as-native target with MISSION_REQUEST_INTAKE=1, its originator in real Chrome (@spec request-provenance#capture, request-provenance#intake-isolation, #939 slice 2b-2, D1221)", () => {
  it("launches the intake and the AS together: the summary names the intake's login, the intake signs for this AS, the originator and the Approver are distinct accounts at the IdP, and a push without the intake's entry is still accepted, since the type is not required", async () => {
    expect(launched?.summary).toContain(
      `  request intake     ${intake().service.issuer}/login  (mission-request-provenance accepted, not required; originator login at the approver login provider)`,
    );
    expect(intake().service.audience).toBe(authServer().asUrl);
    const approver = (authServer().approverConsole as UpstreamApprovalConsole).upstream.account;
    expect(intake().originator.sub).toBe("idp-alice");
    expect(approver.sub).toBe("idp-bob");
    expect(intake().originator.device).not.toBe(approver.device);
    const withoutEntry = await push(shapeIntent());
    expect(withoutEntry.status, JSON.stringify(withoutEntry.body)).toBe(201);
  });

  it("Alice signs in through Chrome at the IdP with her password and her device's code, captures her instruction on the intake's page and reads the workflow token there; the agent's push as ap-agent with the intake's assertion is approved by Bob, and the Mission's facts carry her login's acr, amr and auth_time and the intake's signer", async () => {
    const context = await (browser as Browser).newContext();
    try {
      const { page, login } = await signIn(context);
      expect(login).toMatchObject({ sub: "idp-alice", factors: ["pwd", "otp"], acr: "mfa" });
      // The capture, some seconds after the login, so its auth_time is its own.
      hoisted.clock.advance(3_000);
      const before = intake().service.counts();
      const receipt = await captureOnPage(page, INSTRUCTION);
      expect(intake().service.counts()).toEqual({ captures: before.captures + 1, assertions: before.assertions });
      expect(Buffer.from(receipt.workflowToken, "base64url")).toHaveLength(32);

      // The agent, holding the instruction and the token the page showed, shapes and asks for a signature.
      hoisted.clock.advance(2_000);
      const shapingStartedAt = Math.floor(Date.now() / 1000);
      const intent = shapeIntent();
      const signed = await sign(receipt.workflowToken, intent);
      expect(signed.status, JSON.stringify(signed.body)).toBe(200);
      expect(signed.body.type).toBe(TYPE);
      const claims = claimsOf(signed.body.assertion);
      expect(claims.captured_at as number).toBeLessThan(shapingStartedAt);
      expect(login.auth_time).toBeLessThan(claims.captured_at as number);
      expect(claims).toMatchObject({
        iss: intake().service.issuer,
        aud: authServer().asUrl,
        intent_hash: provisionalIntentHash(authServer().asUrl, intent as never),
        presenter: { client_id: AGENT },
        originator: { iss: provider().issuer, sub: "idp-alice" },
        channel: { type: intake().service.channelType, acr: "mfa", amr: ["pwd", "otp"], auth_time: login.auth_time },
        capture_id: receipt.captureId,
      });

      // The push, and Bob's approval at the trusted console (his own login at the IdP).
      const pending = await submitMissionApproval(authServer().asUrl, authServer().agentClientJwk, {
        missionIntent: JSON.stringify({ intent, evidence: [signed.body] }),
        authorizationDetails: AUTHORIZATION_DETAILS,
      });
      expect(await resolveMissionApproval(authServer().asUrl, authServer().approverConsole, pending, "approve")).toBeTruthy();
      expect(provider().logins.at(-1)?.sub).toBe("idp-bob");
      const record = launched?.stack.kernel.findByApprovalEvent(`apev_${pending.uid}`);
      expect(record?.submission_evidence).toHaveLength(1);
      expect(record?.submission_evidence?.[0]?.type).toBe(TYPE);
      expect(record?.submission_evidence?.[0]?.facts).toEqual({
        signer: { iss: intake().service.issuer, kid: intake().service.kid },
        originator: { iss: provider().issuer, sub: "idp-alice" },
        channel: { type: intake().service.channelType, acr: login.acr, amr: login.factors, auth_time: login.auth_time },
        captured_at: rfc3339(claims.captured_at as number),
        request_digest: claims.request_digest,
        assertion_id: claims.jti,
        capture_id: receipt.captureId,
      });
    } finally {
      await context.close();
    }
  });

  it("Chrome stores the intake's session cookie HttpOnly, SameSite=Strict, Path=/ and host-only, and the intake's page cannot read it from document.cookie", async () => {
    const context = await (browser as Browser).newContext();
    try {
      const { page } = await signIn(context);
      const stored = (await context.cookies(intake().service.issuer)).filter((c) => c.name === REQUEST_INTAKE_SESSION_COOKIE);
      expect(stored).toHaveLength(1);
      // Host-only: Chrome records a host-only cookie under the bare host, with no leading dot.
      expect(stored[0]).toMatchObject({ domain: "127.0.0.1", path: "/", httpOnly: true, sameSite: "Strict", secure: false });
      expect(stored[0]?.expires).toBeGreaterThan(0);
      // Not for another host name, though it resolves to the same address.
      expect((await context.cookies(`http://localhost:${AS_PORT}`)).map((c) => c.name)).not.toContain(REQUEST_INTAKE_SESSION_COOKIE);
      // The page's script cannot read it, though Chrome sends it with the page's own request.
      expect(page.url()).toBe(`${intake().service.issuer}${REQUEST_INTAKE_CAPTURE_PATH}`);
      expect(await page.evaluate(() => document.cookie)).not.toContain(REQUEST_INTAKE_SESSION_COOKIE);
      const sent = page.waitForRequest((r) => r.url() === `${intake().service.issuer}${REQUEST_INTAKE_CAPTURE_PATH}` && r.method() === "POST");
      await captureOnPage(page, INSTRUCTION);
      expect(cookieIn((await (await sent).allHeaders()).cookie, REQUEST_INTAKE_SESSION_COOKIE)).toBe(stored[0]?.value);
    } finally {
      await context.close();
    }
  });

  it("a page on localhost, another site, reaches the intake without the session: Chrome sends no Strict cookie, so its top-level form POST to /capture is refused 401 with no capture record and its link to the capture page is refused 401, while the intake's own page captures", async () => {
    const context = await (browser as Browser).newContext();
    try {
      const { page } = await signIn(context);
      const capturePath = `${intake().service.issuer}${REQUEST_INTAKE_CAPTURE_PATH}`;
      const before = intake().service.counts().captures;
      const elsewhere = await context.newPage();

      // A cross-site top-level form POST.
      await elsewhere.goto(`http://localhost:${pages?.port}/post`);
      const [posted] = await Promise.all([
        elsewhere.waitForResponse((r) => r.url() === capturePath && r.request().method() === "POST"),
        elsewhere.click("#submit"),
      ]);
      expect(posted.status()).toBe(401);
      expect(((await posted.json()) as Json).error).toBe("login_required");
      expect(cookieIn((await posted.request().allHeaders()).cookie, REQUEST_INTAKE_SESSION_COOKIE)).toBeUndefined();
      expect(intake().service.counts().captures).toBe(before);

      // A cross-site top-level link to the capture page: a GET, which a Lax cookie would accompany.
      await elsewhere.goto(`http://localhost:${pages?.port}/link`);
      const [linked] = await Promise.all([
        elsewhere.waitForResponse((r) => r.url() === capturePath && r.request().method() === "GET"),
        elsewhere.click("#go"),
      ]);
      expect(linked.status()).toBe(401);
      expect(cookieIn((await linked.request().allHeaders()).cookie, REQUEST_INTAKE_SESSION_COOKIE)).toBeUndefined();

      // The intake's own page, in the same browser and session, captures.
      await captureOnPage(page, INSTRUCTION);
      expect(intake().service.counts().captures).toBe(before + 1);
    } finally {
      await context.close();
    }
  });

  it("the loopback limitation (RFC 6265 Section 8.5): cookies are scoped by host, not port, so Chrome sends the intake's session cookie to the IdP on the same host and another port, the IdP's session cookie to the intake, and the session cookie with a form POST from a page on another port of the intake's host", async () => {
    const context = await (browser as Browser).newContext();
    try {
      const { page } = await signIn(context);
      const [session] = (await context.cookies(intake().service.issuer)).filter((c) => c.name === REQUEST_INTAKE_SESSION_COOKIE);
      expect(session).toBeDefined();
      // The IdP receives the intake's session cookie.
      const atIdp = await page.goto(`${provider().issuer}/.well-known/openid-configuration`);
      expect(atIdp?.status()).toBe(200);
      expect(cookieIn((await atIdp?.request().allHeaders())?.cookie, REQUEST_INTAKE_SESSION_COOKIE)).toBe(session?.value);
      // The intake receives the IdP's session cookie.
      const atIntake = await page.goto(`${intake().service.issuer}${REQUEST_INTAKE_CAPTURE_PATH}`);
      expect(atIntake?.status()).toBe(200);
      expect(cookieIn((await atIntake?.request().allHeaders())?.cookie, "_idp_session")).toBeTruthy();
      // A page on another port of 127.0.0.1 is the intake's site: its form POST
      // carries the session, and only the capture endpoint's JSON body refuses it.
      const before = intake().service.counts().captures;
      const sameSite = await context.newPage();
      await sameSite.goto(`http://127.0.0.1:${pages?.port}/post`);
      const [posted] = await Promise.all([
        sameSite.waitForResponse((r) => r.url() === `${intake().service.issuer}${REQUEST_INTAKE_CAPTURE_PATH}` && r.request().method() === "POST"),
        sameSite.click("#submit"),
      ]);
      expect(cookieIn((await posted.request().allHeaders()).cookie, REQUEST_INTAKE_SESSION_COOKIE)).toBe(session?.value);
      expect(posted.status()).toBe(415);
      expect(intake().service.counts().captures).toBe(before);
    } finally {
      await context.close();
    }
  });

  it("the intake signs up to the AS's declared maximum capture age and refuses past it: one bound, config/request-provenance.json's, for both halves", async () => {
    const bound = REQUEST_PROVENANCE_CONFIG.max_capture_age_seconds;
    const context = await (browser as Browser).newContext();
    try {
      const { page } = await signIn(context);
      const receipt = await captureOnPage(page, INSTRUCTION);
      // Five seconds inside the bound: the intake signs, and the AS accepts the push.
      hoisted.clock.advance((bound - 5) * 1000);
      const inside = await sign(receipt.workflowToken, shapeIntent());
      expect(inside.status, JSON.stringify(inside.body)).toBe(200);
      const claims = claimsOf(inside.body.assertion);
      expect((claims.iat as number) - (claims.captured_at as number)).toBeGreaterThanOrEqual(bound - 6);
      const accepted = await push(shapeIntent(), inside.body);
      expect(accepted.status, JSON.stringify(accepted.body)).toBe(201);
      // Five seconds past it: the intake signs nothing.
      hoisted.clock.advance(10_000);
      const assertions = intake().service.counts().assertions;
      const late = await sign(receipt.workflowToken, shapeIntent());
      expect(late.status, JSON.stringify(late.body)).toBe(400);
      expect(late.body.error).toBe("capture_too_old");
      expect(intake().service.counts().assertions).toBe(assertions);
    } finally {
      await context.close();
    }
  });

  it("closes the request intake's listener, with the IdP's, when the target closes", async () => {
    const urls = [intake().service.issuer, provider().issuer];
    for (const url of urls) expect(await accepts(url), url).toBe(true);
    await launched?.close();
    for (const url of urls) expect(await accepts(url), `${url} after close`).toBe(false);
  });
});
