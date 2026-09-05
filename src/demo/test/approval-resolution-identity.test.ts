import type { Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Hono } from "hono";
import { SessionStore } from "@mission/console-bff";
import { CANONICAL_RESOURCE, DEV_SERVICE_TOKEN } from "@mission/demo-data";
import { ApprovalSessionStore, buildAuthorizationServer, MISSION_APPROVAL_SCOPE } from "@mission/authorization-server";
import { clientAssertionSigner, dpopProofFor, jarClosures, redeemMissionApproval, submitMissionApproval, type IssueOpts, type IssuedMission, type SubmittedApproval } from "../src/oauth-client.js";
import { resolveMissionApproval } from "../src/approval-console.js";
import { installConsoleSessionBoundary } from "../src/console-session-boundary.js";

const ISSUER = "http://localhost:14959";
const TRUSTED = "independent-approver-identity-test";
const WEAK = "weak-approver-identity-test";
const ALICE = "alice-approver-identity-test";
const sessions = new ApprovalSessionStore();
let as: Awaited<ReturnType<typeof buildAuthorizationServer>>;
let server: Server;
let agentCredential: IssuedMission;
const defaults: IssueOpts = {
  missionIntent: JSON.stringify({ intent: { goal: "Read approved invoices", target_resources: [CANONICAL_RESOURCE], expires_at: "2027-01-01T00:00:00Z" } }),
  authorizationDetails: JSON.stringify([{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] }]),
  scope: "payments openid",
};
beforeAll(async () => {
  const now = Math.floor(Date.now() / 1000);
  as = await buildAuthorizationServer({ issuer: ISSUER, allowHeadlessAdjudication: true, approvalSessions: sessions,
    serviceTokenPrincipals: {
      [TRUSTED]: { principal_id: "svc:trusted-console", scopes: [MISSION_APPROVAL_SCOPE], approver: { sub: "bob", acr: "mfa", auth_time: now } },
      [WEAK]: { principal_id: "svc:weak-console", scopes: [MISSION_APPROVAL_SCOPE], approver: { sub: "bob", acr: "password", auth_time: now - 3600 } },
      [ALICE]: { principal_id: "svc:alice-console", scopes: [MISSION_APPROVAL_SCOPE], approver: { sub: "alice", acr: "mfa", auth_time: now } },
    } });
  server = as.provider.listen(14959);
  const bootstrap = await submitMissionApproval(ISSUER, as.agentClientJwk, defaults);
  const code = await resolveMissionApproval(ISSUER, TRUSTED, bootstrap, "approve");
  agentCredential = await redeemMissionApproval(ISSUER, as.agentClientJwk, { code: code!, par: bootstrap.par });
});
afterAll(() => server?.close());
const pending = (opts: Partial<IssueOpts> = {}) => submitMissionApproval(ISSUER, as.agentClientJwk, { ...defaults, ...opts });
const decide = (p: SubmittedApproval, body: Record<string, unknown> = { decision: "approve" }, headers: Record<string, string> = {}) => fetch(`${ISSUER}/interaction/${p.uid}/decide`, {
  method: "POST", redirect: "manual", headers: { "content-type": "application/json", cookie: jarClosures(p.jar).cookieHeader(), ...headers }, body: JSON.stringify(body),
});

describe("approval resolution establishes identity from the surface (#759, #761)", () => {
  it("enabled headless mode refuses all agent-held credentials and cookies for both approve and deny, then the independent approver succeeds", async () => {
    const p = await pending();
    const before = as.kernel.allMissions().length;
    const assertion = await (await clientAssertionSigner(ISSUER, as.agentClientJwk))();
    for (const decision of ["approve", "deny"]) {
      for (const headers of [{}, { "x-service-token": DEV_SERVICE_TOKEN }, { authorization: `Bearer ${assertion}`, "x-service-token": DEV_SERVICE_TOKEN },
        { authorization: `DPoP ${agentCredential.accessToken}`, dpop: await dpopProofFor(agentCredential.dpopKeys, `${ISSUER}/interaction/${p.uid}/decide`, "POST", agentCredential.accessToken), "x-service-token": DEV_SERVICE_TOKEN }]) {
        const r = await decide(p, { decision }, headers);
        expect(r.status).toBe(401);
      }
    }
    expect(as.kernel.allMissions()).toHaveLength(before);
    // Same real pending interaction still completes: none of the refusals finished it.
    expect(await resolveMissionApproval(ISSUER, TRUSTED, p, "approve")).toBeTruthy();
    const record = as.kernel.allMissions().at(-1)!;
    expect(record.approver.sub).toBe("bob");
    expect(record.subject.sub).toBe("alice");
  });

  it("refuses every identity-bearing body member loudly, even with a valid approver credential", async () => {
    const p = await pending();
    const before = as.kernel.allMissions().length;
    for (const key of ["approver", "subject", "approver_acr", "approver_auth_time"]) {
      const r = await decide(p, { decision: "approve", [key]: "caller-asserted" }, { "x-service-token": TRUSTED });
      expect(r.status).toBe(400);
      expect(await r.json()).toMatchObject({ error: "invalid_request" });
    }
    expect(as.kernel.allMissions()).toHaveLength(before);
    expect(await resolveMissionApproval(ISSUER, TRUSTED, p, "approve")).toBeTruthy();
  });

  it("independent browser login requires its own session, CSRF, origin, and interaction binding", async () => {
    const p = await pending({ acrValues: "mfa" });
    const other = await pending();
    // Only trusted login integration establishes this record; no HTTP route does so.
    const login = sessions.establish(p.uid, { sub: "bob", acr: "mfa", auth_time: Math.floor(Date.now() / 1000) });
    const headers = { cookie: jarClosures(p.jar).cookieHeader() + "; " + login.cookie, "x-csrf-token": login.csrf, origin: ISSUER };
    expect((await decide(p, { decision: "approve" }, { ...headers, "x-csrf-token": "wrong" })).status).toBe(401);
    expect((await decide(p, { decision: "approve" }, { ...headers, origin: "https://attacker.test" })).status).toBe(401);
    expect((await decide(other, { decision: "approve" }, { ...headers, cookie: jarClosures(other.jar).cookieHeader() + "; " + login.cookie })).status).toBe(401);
    expect((await decide(p, { decision: "approve", approver: "alice" }, headers)).status).toBe(400);
    expect((await decide(p, { decision: "approve" }, headers)).status).toBe(303);
    expect(as.kernel.allMissions().at(-1)!.approver.sub).toBe("bob");
  });

  it("a service token without the approval scope cannot resolve, even though it authenticates other console operations", async () => {
    const p = await pending();
    expect((await decide(p, { decision: "deny" }, { "x-service-token": DEV_SERVICE_TOKEN })).status).toBe(401);
    expect(await resolveMissionApproval(ISSUER, TRUSTED, p, "deny")).toBeUndefined();
  });

  it("requested authentication strength is checked against the surface context, including stale authentication", async () => {
    for (const opts of [{ acrValues: "mfa" }, { maxAge: "0" }]) {
      const p = await pending(opts);
      await expect(resolveMissionApproval(ISSUER, WEAK, p, "approve")).rejects.toThrow("access_denied");
    }
    const p = await pending({ acrValues: "mfa" });
    expect(await resolveMissionApproval(ISSUER, TRUSTED, p, "approve")).toBeTruthy();
  });

  it("the pushed login_hint is resolved and authorized, never accepted as an arbitrary Subject", async () => {
    for (const [hint, token] of [["unknown-person", TRUSTED], ["bob", ALICE]]) {
      const p = await pending({ loginHint: hint });
      expect((await decide(p, { decision: "approve" }, { "x-service-token": token! })).status).toBe(403);
    }
  });

  it("write-bearing distinctness and role checks run over the resolved identities", async () => {
    const p = await pending({ loginHint: "bob", authorizationDetails: JSON.stringify([{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:payment.execute"], constraints: { max_amount: { amount: "100.00", currency: "USD" }, vendors: ["acme"] } }]) });
    const before = as.kernel.allMissions().length;
    expect((await decide(p, { decision: "approve" }, { "x-service-token": TRUSTED })).status).toBe(403);
    expect(as.kernel.allMissions()).toHaveLength(before);
  });

  it("headless mode defaults off and a service approver cannot bypass that default", async () => {
    const issuer = "http://localhost:14960";
    const closed = await buildAuthorizationServer({ issuer, serviceTokenPrincipals: { [TRUSTED]: { principal_id: "svc:trusted", scopes: [MISSION_APPROVAL_SCOPE], approver: { sub: "bob", acr: "mfa", auth_time: Math.floor(Date.now() / 1000) } } } });
    const listener = closed.provider.listen(14960);
    try {
      const p = await submitMissionApproval(issuer, closed.agentClientJwk, defaults);
      const r = await fetch(`${issuer}/interaction/${p.uid}/decide`, { method: "POST", headers: { "content-type": "application/json", "x-service-token": TRUSTED, cookie: jarClosures(p.jar).cookieHeader() }, body: JSON.stringify({ decision: "approve" }) });
      expect(r.status).toBe(401);
      expect(closed.kernel.allMissions()).toEqual([]);
    } finally { listener.close(); }
  });

  it("the demo console proxy rejects the agent channel while its independently authenticated session resolves a real interaction", async () => {
    const p = await pending();
    const app = new Hono();
    const session = new SessionStore().create("bob", ["operator", "approver"]);
    installConsoleSessionBoundary(app, session);
    let resolutions = 0;
    app.get("/bff/session", c => c.json({ csrf: session.csrf }));
    app.post("/bff/approver/adjudicate", async c => {
      const { decision } = await c.req.json();
      const code = await resolveMissionApproval(ISSUER, TRUSTED, p, decision);
      resolutions++;
      return c.json({ code });
    });
    const agentHeaders = { "content-type": "application/json", cookie: jarClosures(p.jar).cookieHeader(), "x-service-token": DEV_SERVICE_TOKEN, authorization: `Bearer ${await (await clientAssertionSigner(ISSUER, as.agentClientJwk))()}` };
    expect((await app.request("/bff/session", { headers: agentHeaders })).status).toBe(401);
    expect((await app.request("/console/session", { method: "POST", headers: agentHeaders })).status).toBe(401);
    for (const decision of ["approve", "deny"]) expect((await app.request("/bff/approver/adjudicate", { method: "POST", headers: agentHeaders, body: JSON.stringify({ decision }) })).status).toBe(401);
    expect(resolutions).toBe(0);
    const login = await app.request("/console/session", { method: "POST", headers: { authorization: `Bearer ${session.id}` } });
    const cookie = login.headers.get("set-cookie")!.split(";")[0]!;
    const trusted = { "content-type": "application/json", cookie, "x-csrf": session.csrf };
    expect((await app.request("/bff/approver/adjudicate", { method: "POST", headers: { ...trusted, "x-csrf": "wrong" }, body: JSON.stringify({ decision: "approve" }) })).status).toBe(403);
    expect((await app.request("/bff/approver/adjudicate", { method: "POST", headers: trusted, body: JSON.stringify({ decision: "approve" }) })).status).toBe(200);
    expect(resolutions).toBe(1);
  });
});
