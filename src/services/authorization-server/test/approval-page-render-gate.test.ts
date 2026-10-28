/**
 * @spec mission#direct-approval-steps, mission#approval-preparation (#1802):
 * the AS performs the direct approval steps in order, so the Mission approval
 * page (`GET /interaction/{uid}`) renders the step-5 consent only after step 1
 * established the Approver (from this user agent's approval session or a
 * trusted headless approval service, never the interaction cookie the
 * initiating client also holds, and with the authentication the published
 * floor and the client's request require), step 2 the Subject and the
 * Approver's authority to approve for it, and step 3 the authority source and
 * the Approver's authority to activate it. A refused principal is shown
 * nothing of the request and gets no render revision; a refusal of that
 * Approver alone leaves the interaction pending for another. The decision
 * runs every check again, so authority withdrawn or authentication aged out
 * after the rendering still refuses there. When the Approver is not the
 * Subject, the page names the Subject.
 *
 * The browser authorization-code and headless paths; the device path's cases
 * are in device-authorization.test.ts, the login link's in
 * approver-login.test.ts.
 */

import { type Server } from "node:http";
import { APPROVAL_FLOOR, type ApprovalFloorPolicy, DERIVATION_POLICY, USERS } from "@mission/demo-data";
import { type CryptoKey, importJWK, SignJWT } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { RENDER_REVISION_HEADER } from "../src/adapters/approval-render-revision.js";
import { ApprovalSessionStore, buildAuthorizationServer, type BuiltAs } from "../src/index.js";
import { browserApprovalHeaders, floorApprovalHeaders, TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";

const PORT = 14967;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const GOAL_MARK = "RENDER-GATE-GOAL-7f3a reconcile the Q3 invoices";
const BOUNDS_MARK = "RENDER-GATE-BOUNDS-91c2 only vendor ACME";
const INTENT = {
  goal: GOAL_MARK,
  task_bounds: [BOUNDS_MARK],
  target_resources: [RESOURCE],
  expires_at: new Date(Date.now() + 86_400_000).toISOString().replace(/\.\d{3}Z$/, "Z"),
};
/** Read-only: the approval-authentication floor does not apply. */
const READ = [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read", "payments:invoice.list"] }];
/** Remittance is high-risk authority: the floor applies. */
const REMIT = [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions: ["payments:invoice.read", "payments:remittance.send"],
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];

/** Vendor reads: admitted by the derivation policy, and left unclassified by this suite's floor policy. */
const UNCLASSIFIED = [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:vendor.read"] }];
/** A proposal no ceiling admits: derivation refuses it. */
const UNDERIVABLE = [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:not.a.real.action"] }];
/** The shipped floor, except that it does not classify `payments:vendor.read`. */
const FLOOR_POLICY: ApprovalFloorPolicy = {
  ...APPROVAL_FLOOR,
  classification: APPROVAL_FLOOR.classification.map((c) => {
    if (c.resource !== RESOURCE) return c;
    const actions = { ...c.actions };
    delete actions["payments:vendor.read"];
    return { ...c, actions };
  }),
};

const SESSIONS = new ApprovalSessionStore();
/** The deployment's approve-for policy (identity.json), held here so a test can withdraw an Approver's authority. */
const APPROVES_FOR = new Map(USERS.map((u) => [u.sub, new Set(u.approves_for)]));
let as: BuiltAs;
let server: Server;
let agentKey: CryptoKey;

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    approvalSessions: SESSIONS,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approverApprovesFor: APPROVES_FOR,
    approvalFloor: FLOOR_POLICY,
  });
  server = as.provider.listen(PORT);
  await new Promise<void>((r) => server.once("listening", () => r()));
  agentKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
});

afterEach(() => {
  vi.restoreAllMocks();
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

async function clientAssertion(): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(agentKey);
}

/**
 * The CLIENT pushes the request and follows the authorization redirect itself,
 * as the demo's agent helper does. The cookies it then holds are
 * oidc-provider's interaction cookies, nothing else.
 */
async function open(proposal: unknown[] = READ, extra: Record<string, string> = {}): Promise<{ uid: string; cookie: string; names: string[] }> {
  const verifier = `render-gate-${crypto.randomUUID()}-0123456789`;
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
      mission_intent: JSON.stringify({ intent: INTENT }),
      authorization_details: JSON.stringify(proposal),
      ...extra,
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const pushed = (await par.json()) as { request_uri: string };
  expect(par.status, JSON.stringify(pushed)).toBe(201);
  const res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: pushed.request_uri })}`, {
    redirect: "manual",
  });
  const pairs = res.headers.getSetCookie().map((line) => line.split(";")[0] as string);
  return {
    uid: (res.headers.get("location") as string).split("/interaction/")[1] as string,
    cookie: pairs.join("; "),
    names: pairs.map((p) => p.split("=")[0] as string),
  };
}

async function render(uid: string, headers: Record<string, string>) {
  const { "content-type": _type, "x-csrf-token": _csrf, ...viewing } = headers;
  const res = await fetch(`${ISSUER}/interaction/${uid}`, { headers: viewing });
  return { status: res.status, revision: res.headers.get(RENDER_REVISION_HEADER), html: await res.text() };
}

/** Decide, then follow the completion to the client's redirect URI. */
async function decide(uid: string, headers: Record<string, string>, render_revision?: string | null) {
  let res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...headers, "content-type": "application/json" },
    body: JSON.stringify({ decision: "approve", ...(render_revision ? { render_revision } : {}) }),
  });
  const status = res.status;
  if (status !== 303) {
    const text = await res.text();
    let error: string | undefined;
    try {
      error = (JSON.parse(text) as { error?: string }).error;
    } catch {}
    return { status, error };
  }
  const cookie = headers.cookie ?? "";
  let location = res.headers.get("location") as string;
  while (location?.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie } });
    location = res.headers.get("location") as string;
  }
  const q = new URL(location).searchParams;
  return { status, code: q.get("code") ?? undefined, error: q.get("error") ?? undefined, description: q.get("error_description") ?? undefined };
}

const unescape = (s: string) => s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
const derivedOn = (html: string) => {
  const derived = /<h2>Derived authority \(what approval grants\)<\/h2><pre>([\s\S]*?)<\/pre>/.exec(html)?.[1];
  return derived ? (JSON.parse(unescape(derived)) as Array<{ resource: string; actions: string[] }>) : undefined;
};

/** The step-5 content: the Intent, the derived set, the receiving client and the source. */
function expectRendered(html: string) {
  expect(html).toContain(GOAL_MARK);
  expect(html).toContain(BOUNDS_MARK);
  expect(derivedOn(html)?.map(({ resource, actions }) => ({ resource, actions }))).toEqual([
    { resource: RESOURCE, actions: ["payments:invoice.read", "payments:invoice.list"] },
  ]);
  expect(html).toContain('<code class="client-id">ap-agent</code>');
  expect(html).toContain("<h2>Authority source (whose authority this draws on)</h2>");
}

/** None of it: no Intent, task bounds, target resource, derived entry, client, Subject or source. */
function expectNothingOfTheRequest(html: string) {
  expect(html).not.toContain(GOAL_MARK);
  expect(html).not.toContain(BOUNDS_MARK);
  expect(html).not.toContain(RESOURCE);
  expect(html).not.toContain("payments:");
  expect(html).not.toContain("ap-agent");
  expect(html).not.toContain("alice");
  expect(html).not.toContain("user_delegated");
  expect(html).not.toContain("Authority source");
  expect(html).not.toContain('value="approve"');
}

const nothingCreated = async (uid: string) => {
  expect(as.kernel.findByApprovalEvent(`apev_${uid}`)).toBeUndefined();
};

describe("the approval page renders only after steps 1 to 3 (@spec mission#direct-approval-steps, mission#approval-preparation, #1802)", () => {
  it("answers the interaction cookie alone, with no Approver session, 401 and nothing of the request; an authorized Approver then renders and approves the same interaction", async () => {
    const flow = await open();
    expect(flow.names.every((n) => n.startsWith("_interaction"))).toBe(true);
    const anonymous = await render(flow.uid, { cookie: flow.cookie });
    expect(anonymous.status).toBe(401);
    expect(anonymous.revision).toBeNull();
    expect(anonymous.html).toContain('<p class="approval-notice" data-error="unauthorized">');
    expectNothingOfTheRequest(anonymous.html);
    await nothingCreated(flow.uid);
    // The interaction is still pending for the Approver.
    const bob = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    const shown = await render(flow.uid, bob);
    expect(shown.status).toBe(200);
    expectRendered(shown.html);
    expect((await decide(flow.uid, bob, shown.revision)).code).toBeTruthy();
  });

  it("refuses an authenticated Approver who may not activate the established source 403 before rendering, leaving the interaction pending", async () => {
    const flow = await open();
    // Dana (mfa) approves for herself; the source ap-agent resolves names Alice and Bob as activators.
    const dana = browserApprovalHeaders(SESSIONS, flow.uid, { sub: "dana", acr: "mfa" }, flow.cookie);
    const refused = await render(flow.uid, dana);
    expect(refused.status).toBe(403);
    expect(refused.revision).toBeNull();
    expect(refused.html).toContain('<p class="approval-notice" data-error="access_denied">');
    expectNothingOfTheRequest(refused.html.replace("dana", ""));
    // Her decision names no rendering and approves nothing.
    expect((await decide(flow.uid, dana)).status).toBe(409);
    await nothingCreated(flow.uid);
    const bob = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    const shown = await render(flow.uid, bob);
    expect(shown.status).toBe(200);
    expect((await decide(flow.uid, bob, shown.revision)).code).toBeTruthy();
  });

  it("refuses an authenticated Approver with no approve-for authority over the selected Subject 403 approval_forbidden before rendering: Alice for Bob, and Dana for Alice", async () => {
    for (const [approver, subject] of [
      ["alice", "bob"],
      ["dana", "alice"],
    ] as const) {
      const flow = await open();
      const headers = browserApprovalHeaders(SESSIONS, flow.uid, { sub: approver, acr: "mfa", subject }, flow.cookie);
      const refused = await render(flow.uid, headers);
      expect(refused.status, approver).toBe(403);
      expect(refused.revision, approver).toBeNull();
      expect(refused.html, approver).toContain('<p class="approval-notice" data-error="approval_forbidden">');
      expectNothingOfTheRequest(refused.html);
      expect(refused.html).not.toContain("bob");
      // The decision's own check refuses it too.
      const decided = await decide(flow.uid, headers);
      expect(decided.status, approver).toBe(403);
      expect(decided.error, approver).toBe("approval_forbidden");
      await nothingCreated(flow.uid);
    }
  });

  it("refuses a self-approval of write-bearing authority 403 approval_forbidden before rendering: it needs a distinct Approver (D37)", async () => {
    const flow = await open([{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:payment.schedule"] }]);
    const alice = browserApprovalHeaders(SESSIONS, flow.uid, { sub: "alice", acr: "mfa" }, flow.cookie);
    const refused = await render(flow.uid, alice);
    expect(refused.status).toBe(403);
    expect(refused.revision).toBeNull();
    expect(refused.html).toContain('data-error="approval_forbidden"');
    expectNothingOfTheRequest(refused.html);
    // Bob, a distinct Approver with the approver role, renders it.
    expect((await render(flow.uid, floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie))).status).toBe(200);
  });

  it("treats a login whose recorded authentication time is in the future as no Approver: 401 and nothing of the request", async () => {
    const flow = await open();
    const future = browserApprovalHeaders(SESSIONS, flow.uid, { sub: "bob", acr: "mfa", subject: "alice", auth_time: Math.floor(Date.now() / 1000) + 3600 }, flow.cookie);
    const refused = await render(flow.uid, future);
    expect(refused.status).toBe(401);
    expect(refused.html).toContain('data-error="unauthorized"');
    expectNothingOfTheRequest(refused.html);
  });

  it("asks a login the approval-authentication floor refuses to sign in again, with nothing of the request and no revision", async () => {
    const flow = await open(REMIT);
    const weak = browserApprovalHeaders(SESSIONS, flow.uid, { sub: "bob", acr: "password", subject: "alice" }, flow.cookie);
    const stepUp = await render(flow.uid, weak);
    expect(stepUp.status).toBe(401);
    expect(stepUp.revision).toBeNull();
    expect(stepUp.html).toContain('<p class="approval-notice" data-error="insufficient_user_authentication">');
    expectNothingOfTheRequest(stepUp.html);
    // A login that meets it renders the page.
    const strong = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    expect((await render(flow.uid, strong)).status).toBe(200);
  });

  it("asks a login that fails the client's requested acr_values or max_age to sign in again, with nothing of the request", async () => {
    // oidc-provider accepts acr_values and max_age only with openid, which only a self-approval may carry (#826).
    const acr = await open(READ, { scope: "openid", acr_values: "mfa" });
    const password = browserApprovalHeaders(SESSIONS, acr.uid, { sub: "alice", acr: "password" }, acr.cookie);
    const refusedAcr = await render(acr.uid, password);
    expect(refusedAcr.status).toBe(401);
    expect(refusedAcr.html).toContain('data-error="insufficient_user_authentication"');
    expectNothingOfTheRequest(refusedAcr.html);
    expect((await render(acr.uid, browserApprovalHeaders(SESSIONS, acr.uid, { sub: "alice", acr: "mfa" }, acr.cookie))).status).toBe(200);
    const age = await open(READ, { scope: "openid", max_age: "60" });
    const stale = browserApprovalHeaders(SESSIONS, age.uid, { sub: "alice", acr: "mfa", auth_time: Math.floor(Date.now() / 1000) - 120 }, age.cookie);
    const refusedAge = await render(age.uid, stale);
    expect(refusedAge.status).toBe(401);
    expect(refusedAge.revision).toBeNull();
    expect(refusedAge.html).toContain('data-error="insufficient_user_authentication"');
    expectNothingOfTheRequest(refusedAge.html);
  });

  it("refuses a headless approval service naming a Subject its Approver may not approve for 403 before rendering", async () => {
    const flow = await open();
    // The service's Approver is Bob, who approves for Alice and the organizational principal, not Dana.
    const service = { ...trustedApprovalHeaders("bob", { approver_acr: "mfa" }, "dana"), cookie: flow.cookie };
    const refused = await render(flow.uid, service);
    expect(refused.status).toBe(403);
    expect(refused.revision).toBeNull();
    expect(refused.html).toContain('data-error="approval_forbidden"');
    expectNothingOfTheRequest(refused.html.replace("dana", ""));
    await nothingCreated(flow.uid);
  });

  it("refuses a headless rendering of authority behind a browser-only floor, whatever acr its registration claims", async () => {
    const flow = await open(REMIT);
    const service = { ...trustedApprovalHeaders("bob", { approver_acr: "mfa" }, "alice"), cookie: flow.cookie };
    const refused = await render(flow.uid, service);
    expect(refused.status).toBe(401);
    expect(refused.revision).toBeNull();
    expect(refused.html).toContain('data-error="insufficient_user_authentication"');
    expectNothingOfTheRequest(refused.html);
    // Read-only authority invokes no floor: the same service renders it.
    const read = await open();
    expect((await render(read.uid, { ...trustedApprovalHeaders("bob", {}, "alice"), cookie: read.cookie })).status).toBe(200);
  });

  it("refuses at the decision an Approver whose approve-for authority is withdrawn after the rendering, creating nothing", async () => {
    const flow = await open();
    const bob = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    const shown = await render(flow.uid, bob);
    expect(shown.status).toBe(200);
    const bobs = APPROVES_FOR.get("bob") as Set<string>;
    bobs.delete("alice");
    try {
      const decided = await decide(flow.uid, bob, shown.revision);
      expect(decided.status).toBe(403);
      expect(decided.error).toBe("approval_forbidden");
    } finally {
      bobs.add("alice");
    }
    await nothingCreated(flow.uid);
  });

  it("refuses at the decision a login that ages past the client's requested max_age after the rendering, creating nothing", async () => {
    const t = Math.floor(Date.now() / 1000);
    const clock = vi.spyOn(as.kernel, "nowDate").mockReturnValue(new Date(t * 1000));
    const flow = await open(READ, { scope: "openid", max_age: "60" });
    const alice = browserApprovalHeaders(SESSIONS, flow.uid, { sub: "alice", acr: "mfa", auth_time: t - 30 }, flow.cookie);
    const shown = await render(flow.uid, alice);
    expect(shown.status).toBe(200);
    clock.mockReturnValue(new Date((t + 60) * 1000));
    const decided = await decide(flow.uid, alice, shown.revision);
    expect(decided.error).toBe("access_denied");
    expect(decided.description).toMatch(/did not satisfy the requested acr_values\/max_age/);
    expect(decided.code).toBeUndefined();
    await nothingCreated(flow.uid);
  });

  it("names the Subject the authority is granted for when the Approver is not the Subject, from the authenticated approval surface's selection", async () => {
    const forAlice = await open(READ, { login_hint: "dana" });
    const bob = floorApprovalHeaders(SESSIONS, forAlice.uid, forAlice.cookie);
    const page = await render(forAlice.uid, bob);
    expect(page.status).toBe(200);
    expect(page.html).toContain('<h2>Subject (the authority is granted for)</h2><p class="subject"><code>alice</code></p>');
    // login_hint names the Approver, never the Subject.
    expect(page.html).not.toContain("dana");
    // A self-approval names no separate Subject.
    const self = await open();
    const alice = browserApprovalHeaders(SESSIONS, self.uid, { sub: "alice", acr: "mfa" }, self.cookie);
    const own = await render(self.uid, alice);
    expect(own.status).toBe(200);
    expect(own.html).not.toContain("Subject (the authority is granted for)");
  });

  it("answers a refusal no Approver can lift with nothing of the request to a principal without approve-for authority: unclassified authority", async () => {
    const flow = await open(UNCLASSIFIED);
    // Alice may not approve for Bob; the request's own authority is also unclassified.
    const alice = browserApprovalHeaders(SESSIONS, flow.uid, { sub: "alice", acr: "mfa", subject: "bob" }, flow.cookie);
    const withheld = await render(flow.uid, alice);
    expect(withheld.status).toBe(400);
    expect(withheld.revision).toBeNull();
    const body = JSON.parse(withheld.html) as { error: string; error_description: string };
    expect(body.error).toBe("access_denied");
    expect(body.error_description).toBe("this request cannot be approved; its details are shown only to an Approver who may approve it");
    expect(withheld.html).not.toContain("vendor.read");
    expect(withheld.html).not.toContain("payments:");
    expect(withheld.html).not.toContain(RESOURCE);
    expect(withheld.html).not.toContain(GOAL_MARK);
    expect(withheld.html).not.toContain(BOUNDS_MARK);
    // Bob, who may approve it, is told the cause.
    const bob = await render(flow.uid, floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie));
    expect(bob.status).toBe(400);
    expect((JSON.parse(bob.html) as { error_description: string }).error_description).toMatch(/does not name payments:vendor\.read/);
  });

  it("answers a derivation refusal with nothing of the request to a principal who may not activate the source, and names its cause to one who may", async () => {
    const flow = await open(UNDERIVABLE);
    // Dana approves for herself, but may not activate the source ap-agent resolves.
    const dana = await render(flow.uid, browserApprovalHeaders(SESSIONS, flow.uid, { sub: "dana", acr: "mfa" }, flow.cookie));
    expect(dana.status).toBe(400);
    const withheld = JSON.parse(dana.html) as { error: string; error_description: string };
    expect(withheld.error).toBe("invalid_authorization_details");
    expect(withheld.error_description).toBe("this request cannot be approved; its details are shown only to an Approver who may approve it");
    expect(dana.html).not.toContain("payments:");
    expect(dana.html).not.toContain(RESOURCE);
    expect(dana.html).not.toContain(GOAL_MARK);
    const bob = await render(flow.uid, floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie));
    expect(bob.status).toBe(400);
    const named = JSON.parse(bob.html) as { error: string; error_description: string };
    expect(named.error).toBe("invalid_authorization_details");
    expect(named.error_description).not.toBe(withheld.error_description);
  });

  it("control: an authenticated Approver who may approve and activate is shown the page and approves", async () => {
    const flow = await open();
    const bob = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    const page = await render(flow.uid, bob);
    expect(page.status).toBe(200);
    expect(page.revision).toBeTruthy();
    expectRendered(page.html);
    const decided = await decide(flow.uid, bob, page.revision);
    expect(decided.code).toBeTruthy();
    const record = as.kernel.findByApprovalEvent(`apev_${flow.uid}`);
    expect(record?.subject.sub).toBe("alice");
    expect(record?.approval_basis.consent_principal?.sub).toBe("bob");
  });
});
