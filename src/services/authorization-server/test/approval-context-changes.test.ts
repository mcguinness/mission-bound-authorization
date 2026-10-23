/**
 * @spec mission#approval-context-changes, mission#approval-event (#1446, D583):
 * Changes Before the Decision. An approval rests on the rendering its Approver
 * was shown: each rendering to an authenticated principal gets a protected
 * revision committing the complete context it showed, the decision names the
 * latest revision rendered to that principal, and the AS re-establishes and
 * compares the context at the decision and again, synchronously, before the
 * commit. A change (the derived Authority Set, the authority source, or a
 * policy input, even one that leaves every anchor equal) creates no Mission,
 * grant or code and asks for a fresh decision on the page rendered again.
 */

import { createHash } from "node:crypto";
import { type Server } from "node:http";
import { authorityHash, intentHash, type JsonValue } from "@mission/core";
import { DERIVATION_POLICY, SCOPE_PROJECTION } from "@mission/demo-data";
import { type CryptoKey, importJWK, SignJWT } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { RENDER_REVISION_HEADER } from "../src/adapters/approval-render-revision.js";
import type { AuthoritySourceResolver } from "../src/kernel/authority-source.js";
import { ApprovalSessionStore, buildAuthorizationServer, type BuiltAs } from "../src/index.js";
import { floorApprovalHeaders, TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";

const PORT = 14988;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const INTENT = {
  goal: "Reconcile Q3 invoices",
  target_resources: [RESOURCE],
  expires_at: new Date(Date.now() + 86_400_000).toISOString().replace(/\.\d{3}Z$/, "Z"),
};
/** A read-only proposal, so a headless approval is not refused by the approval-authentication floor. */
const PROPOSAL = [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read", "payments:invoice.list"] }];

/** This suite's own policy inputs, which tests change between rendering and decision and restore after. */
const POLICY = structuredClone(DERIVATION_POLICY);
const MAPPING = structuredClone(SCOPE_PROJECTION);
const POLICY_AS_GIVEN = structuredClone(POLICY);
const MAPPING_AS_GIVEN = structuredClone(MAPPING);
const restore = (target: Record<string, unknown>, given: Record<string, unknown>) => {
  for (const k of Object.keys(target)) delete target[k];
  Object.assign(target, structuredClone(given));
};

const SESSIONS = new ApprovalSessionStore();
let as: BuiltAs;
let server: Server;
let agentKey: CryptoKey;

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    approvalSessions: SESSIONS,
    derivationPolicy: POLICY,
    scopeProjection: MAPPING,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
  });
  server = as.provider.listen(PORT);
  await new Promise<void>((r) => server.once("listening", () => r()));
  agentKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
});

afterEach(() => {
  restore(POLICY as unknown as Record<string, unknown>, POLICY_AS_GIVEN as unknown as Record<string, unknown>);
  restore(MAPPING as unknown as Record<string, unknown>, MAPPING_AS_GIVEN as unknown as Record<string, unknown>);
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

/** A pushed request for the read-only proposal, taken to its approval interaction. */
async function open(intent: typeof INTENT = INTENT): Promise<{ uid: string; cookie: string }> {
  const verifier = `approval-context-changes-${crypto.randomUUID()}-0123456789`;
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
      mission_intent: JSON.stringify({ intent }),
      authorization_details: JSON.stringify(PROPOSAL),
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const pushed = (await par.json()) as { request_uri: string };
  expect(par.status, JSON.stringify(pushed)).toBe(201);
  const res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: pushed.request_uri })}`, {
    redirect: "manual",
  });
  const cookie = res.headers
    .getSetCookie()
    .map((line) => line.split(";")[0])
    .join("; ");
  return { uid: (res.headers.get("location") as string).split("/interaction/")[1] as string, cookie };
}

/** Render the approval page with these headers: its status, the revision it minted, if any, and the page. */
async function render(uid: string, headers: Record<string, string>): Promise<{ status: number; revision: string | null; html: string }> {
  const { "content-type": _type, ...rendering } = headers;
  const res = await fetch(`${ISSUER}/interaction/${uid}`, { headers: rendering });
  const html = await res.text();
  return { status: res.status, revision: res.headers.get(RENDER_REVISION_HEADER), html };
}

/** Hold the AS's own clock, which establishes every effective expiry, at this instant. */
function clockAt(ms: number) {
  vi.spyOn(as.kernel as unknown as { now: () => Date }, "now").mockImplementation(() => new Date(ms));
}

/** The provider grant's save, its first call held until released; later calls pass straight through. */
function holdFirstGrantSave() {
  let release!: () => void;
  const gate = new Promise<void>((r) => {
    release = r;
  });
  const state = { saving: false, calls: 0 };
  const save = as.provider.Grant.prototype.save;
  vi.spyOn(as.provider.Grant.prototype, "save").mockImplementation(async function (this: object, ...args: unknown[]) {
    state.calls += 1;
    if (state.calls === 1) {
      state.saving = true;
      await gate;
    }
    return (save as (...a: unknown[]) => Promise<string>).apply(this, args);
  });
  const saving = async () => {
    while (!state.saving) await new Promise((r) => setTimeout(r, 5));
  };
  return { release, saving, calls: () => state.calls };
}

async function decide(uid: string, headers: Record<string, string>, body: Record<string, unknown>) {
  const res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...headers, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let json: { error?: string; changed?: string[] } = {};
  try {
    json = JSON.parse(text);
  } catch {}
  return { status: res.status, json, location: res.headers.get("location") };
}

const approve = (render_revision?: string | null) => ({ decision: "approve", ...(render_revision ? { render_revision } : {}) });
const grantIdFor = (uid: string) => createHash("sha256").update(`mission-approval-grant:${uid}`).digest("base64url");

/** Nothing was created for this interaction: no Mission, no provider grant (and so no code). */
async function expectNothingCreated(uid: string) {
  expect(as.kernel.findByApprovalEvent(`apev_${uid}`)).toBeUndefined();
  expect(await as.provider.Grant.find(grantIdFor(uid))).toBeUndefined();
}

/** Drop invoice.list from every ceiling entry: the derived set narrows. */
function narrowCeiling() {
  for (const entry of POLICY.ceiling) {
    (entry as { actions: string[] }).actions = (entry as { actions: string[] }).actions.filter((a) => a !== "payments:invoice.list");
  }
}

const derivedNow = () =>
  as.kernel.derive(as.kernel.validateSubmission(JSON.stringify({ intent: INTENT })).intent, PROPOSAL as never);
const withoutSources = (entries: unknown[]) => (entries as Record<string, unknown>[]).map(({ capability_sources: _, ...rest }) => rest);

/** The anchors a Mission records are computed over the context approved: its Intent and its committed set. */
function expectAnchorsOverApproved(record: { intent_hash?: string; authority_hash?: string; authority_set?: unknown[] } | undefined) {
  const intent = as.kernel.validateSubmission(JSON.stringify({ intent: INTENT })).intent;
  expect(record?.intent_hash).toBe(intentHash(ISSUER, intent as unknown as JsonValue));
  expect(record?.authority_hash).toBe(authorityHash(ISSUER, record?.authority_set as JsonValue[]));
}

describe("Changes Before the Decision (@spec mission#approval-context-changes, #1446)", () => {
  it("an unchanged context approves on its rendering's revision, and the Mission commits the rendered set", async () => {
    const flow = await open();
    const headers = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    const { status, revision } = await render(flow.uid, headers);
    expect(status).toBe(200);
    expect(revision).toBeTruthy();
    const rendered = derivedNow();
    const decided = await decide(flow.uid, headers, approve(revision));
    expect(decided.status, JSON.stringify(decided.json)).toBe(303);
    const record = as.kernel.findByApprovalEvent(`apev_${flow.uid}`);
    expect(withoutSources(record?.authority_set as unknown[])).toEqual(rendered);
    expectAnchorsOverApproved(record);
  });

  it("a decision with no rendering, or after only an anonymous rendering, approves nothing", async () => {
    const flow = await open();
    // An anonymous rendering (the interaction cookie, no approval session) is a preview: no revision.
    expect((await render(flow.uid, { cookie: flow.cookie })).revision).toBeNull();
    const headers = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    for (const body of [approve(), approve("not-a-revision")]) {
      const decided = await decide(flow.uid, headers, body);
      expect(decided.status, JSON.stringify(body)).toBe(409);
      expect(decided.json.error, JSON.stringify(body)).toBe("rendering_required");
    }
    await expectNothingCreated(flow.uid);
  });

  it("a narrower ceiling between rendering and decision creates nothing; a fresh decision on the page rendered again commits exactly the narrower context", async () => {
    const flow = await open();
    const headers = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    const first = await render(flow.uid, headers);
    narrowCeiling();
    // Compared before any write: the provider grant is never saved for the stale decision.
    const saves = vi.spyOn(as.provider.Grant.prototype, "save");
    const stale = await decide(flow.uid, headers, approve(first.revision));
    expect(stale.status, JSON.stringify(stale.json)).toBe(409);
    expect(stale.json.error).toBe("approval_context_changed");
    expect(saves).not.toHaveBeenCalled();
    saves.mockRestore();
    expect(stale.json.changed).toEqual(expect.arrayContaining(["authority_hash", "derivation_policy"]));
    await expectNothingCreated(flow.uid);
    // The changed revision is retired: it never approves, even resent.
    expect((await decide(flow.uid, headers, approve(first.revision))).json.error).toBe("rendering_required");
    const again = await render(flow.uid, headers);
    const narrower = derivedNow();
    const decided = await decide(flow.uid, headers, approve(again.revision));
    expect(decided.status, JSON.stringify(decided.json)).toBe(303);
    const record = as.kernel.findByApprovalEvent(`apev_${flow.uid}`);
    expect(withoutSources(record?.authority_set as unknown[])).toEqual(narrower);
    expect(narrower.flatMap((e) => e.actions)).not.toContain("payments:invoice.list");
    expectAnchorsOverApproved(record);
  });

  it("a wider ceiling between rendering and decision creates nothing", async () => {
    narrowCeiling();
    const flow = await open();
    const headers = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    const first = await render(flow.uid, headers);
    restore(POLICY as unknown as Record<string, unknown>, POLICY_AS_GIVEN as unknown as Record<string, unknown>);
    const stale = await decide(flow.uid, headers, approve(first.revision));
    expect(stale.status, JSON.stringify(stale.json)).toBe(409);
    expect(stale.json.changed).toEqual(expect.arrayContaining(["authority_hash"]));
    await expectNothingCreated(flow.uid);
  });

  it("a policy edit that leaves every anchor and the effective expires_at equal still changes the context: a lifetime bound past the requested expiry", async () => {
    const flow = await open();
    const headers = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    const first = await render(flow.uid, headers);
    (POLICY as { max_mission_lifetime_s: number | null }).max_mission_lifetime_s = 7 * 86_400;
    const saves = vi.spyOn(as.provider.Grant.prototype, "save");
    const stale = await decide(flow.uid, headers, approve(first.revision));
    expect(stale.status, JSON.stringify(stale.json)).toBe(409);
    // Only the policy input changed: the anchors, the source, the effective expiry and every other input agree.
    expect(stale.json.changed).toEqual(["derivation_policy"]);
    // Compared before any write.
    expect(saves).not.toHaveBeenCalled();
    await expectNothingCreated(flow.uid);
  });

  it("a shorter lifetime bound changes the effective expires_at: nothing is created", async () => {
    const flow = await open();
    const headers = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    const first = await render(flow.uid, headers);
    (POLICY as { max_mission_lifetime_s: number | null }).max_mission_lifetime_s = 3600;
    const saves = vi.spyOn(as.provider.Grant.prototype, "save");
    const stale = await decide(flow.uid, headers, approve(first.revision));
    expect(stale.status, JSON.stringify(stale.json)).toBe(409);
    expect(stale.json.error).toBe("approval_context_changed");
    expect(stale.json.changed).toEqual(["expires_at", "derivation_policy"]);
    expect(saves).not.toHaveBeenCalled();
    await expectNothingCreated(flow.uid);
  });

  it("the Mission commits the effective expires_at its rendering showed: a lifetime measured from a later decision never moves it", async () => {
    (POLICY as { max_mission_lifetime_s: number | null }).max_mission_lifetime_s = 60;
    const flow = await open();
    const headers = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    const t0 = Math.floor(Date.now() / 1000) * 1000;
    const shown = new Date(t0 + 60_000).toISOString();
    clockAt(t0);
    const { revision, html } = await render(flow.uid, headers);
    expect(html).toContain(`<time class="mission-expires-at" datetime="${shown}">`);
    clockAt(t0 + 5_000);
    const decided = await decide(flow.uid, headers, approve(revision));
    expect(decided.status, JSON.stringify(decided.json)).toBe(303);
    const record = as.kernel.findByApprovalEvent(`apev_${flow.uid}`);
    expect(record?.created_at).toBe(new Date(t0 + 5_000).toISOString());
    expect(record?.expires_at).toBe(shown);
  });

  it("a rendering whose effective expires_at has passed asks for a fresh decision, which commits the expiry rendered again", async () => {
    (POLICY as { max_mission_lifetime_s: number | null }).max_mission_lifetime_s = 60;
    const flow = await open();
    const headers = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    const t0 = Math.floor(Date.now() / 1000) * 1000;
    clockAt(t0);
    const first = await render(flow.uid, headers);
    clockAt(t0 + 61_000);
    const stale = await decide(flow.uid, headers, approve(first.revision));
    expect(stale.status, JSON.stringify(stale.json)).toBe(409);
    expect(stale.json.error).toBe("approval_context_changed");
    expect(stale.json.changed).toEqual(["expires_at"]);
    await expectNothingCreated(flow.uid);
    const again = await render(flow.uid, headers);
    expect((await decide(flow.uid, headers, approve(again.revision))).status).toBe(303);
    expect(as.kernel.findByApprovalEvent(`apev_${flow.uid}`)?.expires_at).toBe(new Date(t0 + 121_000).toISOString());
  });

  it("a requested expiry that passes while the decision commits gets its mapped refusal, not a request to review it again", async () => {
    (POLICY as { max_mission_lifetime_s: number | null }).max_mission_lifetime_s = 60;
    const t0 = Math.floor(Date.now() / 1000) * 1000;
    // Rendered under the lifetime bound (t0 + 60s), short of the requested expiry (t0 + 100s).
    const flow = await open({ ...INTENT, expires_at: new Date(t0 + 100_000).toISOString().replace(/\.\d{3}Z$/, "Z") });
    const headers = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    clockAt(t0);
    const { revision } = await render(flow.uid, headers);
    clockAt(t0 + 50_000);
    const hold = holdFirstGrantSave();
    const held = decide(flow.uid, headers, approve(revision));
    await hold.saving();
    clockAt(t0 + 101_000);
    hold.release();
    const decided = await held;
    expect(decided.status, JSON.stringify(decided.json)).toBe(303);
    const resumed = await fetch(decided.location as string, { redirect: "manual", headers: { cookie: flow.cookie } });
    expect(new URL(resumed.headers.get("location") as string).searchParams.get("error")).toBe("invalid_request");
    expect(as.kernel.findByApprovalEvent(`apev_${flow.uid}`)).toBeUndefined();
  });

  it("a scope projection change is a changed policy input", async () => {
    const flow = await open();
    const headers = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    const first = await render(flow.uid, headers);
    (MAPPING as unknown as Record<string, unknown>).edited_for_test = true;
    const stale = await decide(flow.uid, headers, approve(first.revision));
    expect(stale.status, JSON.stringify(stale.json)).toBe(409);
    expect(stale.json.changed).toEqual(["scope_projection"]);
    await expectNothingCreated(flow.uid);
  });

  it("an authority source change between rendering and decision creates nothing", async () => {
    const flow = await open();
    const headers = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    const first = await render(flow.uid, headers);
    const resolver = (as.kernel as unknown as { sourceResolver: AuthoritySourceResolver }).sourceResolver;
    const original = resolver.resolveForApproval.bind(resolver);
    vi.spyOn(resolver, "resolveForApproval").mockImplementation((input) => ({ ...original(input), catalogRevision: "sha-256:changed-catalog" }));
    const stale = await decide(flow.uid, headers, approve(first.revision));
    expect(stale.status, JSON.stringify(stale.json)).toBe(409);
    expect(stale.json.changed).toEqual(["source"]);
    await expectNothingCreated(flow.uid);
  });

  it("a stale form after a newer rendering approves nothing; the latest rendering does", async () => {
    const flow = await open();
    const headers = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    const older = await render(flow.uid, headers);
    const newer = await render(flow.uid, headers);
    expect(newer.revision).not.toBe(older.revision);
    const stale = await decide(flow.uid, headers, approve(older.revision));
    expect(stale.status).toBe(409);
    expect(stale.json.error).toBe("rendering_required");
    await expectNothingCreated(flow.uid);
    expect((await decide(flow.uid, headers, approve(newer.revision))).status).toBe(303);
  });

  it("a revision rendered in one approval session approves nothing in another", async () => {
    const flow = await open();
    const shown = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    const { revision } = await render(flow.uid, shown);
    const other = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    const decided = await decide(flow.uid, other, approve(revision));
    expect(decided.status).toBe(409);
    expect(decided.json.error).toBe("rendering_required");
    await expectNothingCreated(flow.uid);
  });

  it("a change while the decision commits (during the grant save) creates no Mission and leaves no grant", async () => {
    const flow = await open();
    const headers = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    const { revision } = await render(flow.uid, headers);
    let release!: () => void;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    let saving = false;
    const save = as.provider.Grant.prototype.save;
    vi.spyOn(as.provider.Grant.prototype, "save").mockImplementation(async function (this: object, ...args: unknown[]) {
      saving = true;
      await gate;
      return (save as (...a: unknown[]) => Promise<string>).apply(this, args);
    });
    const held = decide(flow.uid, headers, approve(revision));
    while (!saving) await new Promise((r) => setTimeout(r, 5));
    (POLICY as { max_mission_lifetime_s: number | null }).max_mission_lifetime_s = 3600;
    release();
    const decided = await held;
    expect(decided.status, JSON.stringify(decided.json)).toBe(409);
    expect(decided.json.error).toBe("approval_context_changed");
    expect(decided.json.changed).toEqual(["expires_at", "derivation_policy"]);
    await expectNothingCreated(flow.uid);
  });

  it("a decision held in its grant save never writes over or destroys the grant a newer decision commits", async () => {
    const flow = await open();
    const headers = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    const older = await render(flow.uid, headers);
    const hold = holdFirstGrantSave();
    const first = decide(flow.uid, headers, approve(older.revision));
    await hold.saving();
    narrowCeiling();
    const newer = await render(flow.uid, headers);
    const second = decide(flow.uid, headers, approve(newer.revision));
    // The newer decision waits for the held one: its grant save has not started.
    await new Promise((r) => setTimeout(r, 50));
    expect(hold.calls()).toBe(1);
    hold.release();
    const [a, b] = await Promise.all([first, second]);
    expect(a.status, JSON.stringify(a.json)).toBe(409);
    expect(a.json.error).toBe("approval_context_changed");
    expect(b.status, JSON.stringify(b.json)).toBe(303);
    const record = as.kernel.findByApprovalEvent(`apev_${flow.uid}`);
    expect(record?.state).toBe("active");
    expect(record?.grant_id).toBe(grantIdFor(flow.uid));
    const grant = (await as.provider.Grant.find(grantIdFor(flow.uid))) as { rar?: { actions: string[] }[] } | undefined;
    expect(grant).toBeDefined();
    expect(grant?.rar).toEqual(record?.authority_set);
    expect(grant?.rar?.flatMap((e) => e.actions)).not.toContain("payments:invoice.list");
  });

  it("a decision that fails its commit re-check retires only its own rendering: a newer one still approves", async () => {
    const flow = await open();
    const headers = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    const older = await render(flow.uid, headers);
    const hold = holdFirstGrantSave();
    const first = decide(flow.uid, headers, approve(older.revision));
    await hold.saving();
    narrowCeiling();
    const newer = await render(flow.uid, headers);
    hold.release();
    expect((await first).json.error).toBe("approval_context_changed");
    const decided = await decide(flow.uid, headers, approve(newer.revision));
    expect(decided.status, JSON.stringify(decided.json)).toBe(303);
  });

  it("a second decision on the same rendering waits for the first and recovers its commit, even when a change lands between them", async () => {
    const flow = await open();
    const headers = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    const { revision } = await render(flow.uid, headers);
    const commit = as.kernel.approve.bind(as.kernel);
    vi.spyOn(as.kernel, "approve").mockImplementationOnce((...args: Parameters<typeof commit>) => {
      const record = commit(...args);
      // The ceiling narrows right after the first commit, while the second decision waits its turn.
      narrowCeiling();
      return record;
    });
    const hold = holdFirstGrantSave();
    const first = decide(flow.uid, headers, approve(revision));
    await hold.saving();
    const second = decide(flow.uid, headers, approve(revision));
    await new Promise((r) => setTimeout(r, 50));
    expect(hold.calls()).toBe(1);
    hold.release();
    const [a, b] = await Promise.all([first, second]);
    expect(a.status, JSON.stringify(a.json)).toBe(303);
    expect(b.status, JSON.stringify(b.json)).toBe(303);
    const record = as.kernel.findByApprovalEvent(`apev_${flow.uid}`);
    expect(record?.grant_id).toBe(grantIdFor(flow.uid));
    // The committed decision's grant, as committed: the wider set the first decision approved.
    const grant = (await as.provider.Grant.find(grantIdFor(flow.uid))) as { rar?: { actions: string[] }[] } | undefined;
    expect(grant?.rar).toEqual(record?.authority_set);
    expect(grant?.rar?.flatMap((e) => e.actions)).toContain("payments:invoice.list");
  });

  it("a retry of a committed decision recovers it, even after a policy input changed", async () => {
    const flow = await open();
    const headers = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    const { revision } = await render(flow.uid, headers);
    expect((await decide(flow.uid, headers, approve(revision))).status).toBe(303);
    const committed = as.kernel.findByApprovalEvent(`apev_${flow.uid}`);
    narrowCeiling();
    const retry = await decide(flow.uid, headers, approve(revision));
    expect(retry.status, JSON.stringify(retry.json)).toBe(303);
    expect(as.kernel.findByApprovalEvent(`apev_${flow.uid}`)?.id).toBe(committed?.id);
  });

  it("a context that no longer admits approval gets its mapped refusal, not a request to review it again", async () => {
    const flow = await open();
    const headers = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    const { revision } = await render(flow.uid, headers);
    for (const entry of POLICY.ceiling) (entry as { actions: string[] }).actions = [];
    const decided = await decide(flow.uid, headers, approve(revision));
    expect(decided.status, JSON.stringify(decided.json)).toBe(303);
    const resumed = await fetch(decided.location as string, { redirect: "manual", headers: { cookie: flow.cookie } });
    const error = new URL(resumed.headers.get("location") as string).searchParams.get("error");
    expect(error).toMatch(/^(access_denied|invalid_authorization_details)$/);
    await expectNothingCreated(flow.uid);
  });

  it("a headless approval service renders before deciding, and its revision binds to the Subject it named", async () => {
    const flow = await open();
    const forAlice = { cookie: flow.cookie, ...trustedApprovalHeaders("bob", {}, "alice") };
    const { revision } = await render(flow.uid, forAlice);
    expect(revision).toBeTruthy();
    const forOther = { cookie: flow.cookie, ...trustedApprovalHeaders("bob", {}, null) };
    const crossed = await decide(flow.uid, forOther, approve(revision));
    expect(crossed.status).toBe(409);
    expect(crossed.json.error).toBe("rendering_required");
    await expectNothingCreated(flow.uid);
    expect((await decide(flow.uid, forAlice, approve(revision))).status).toBe(303);
  });
});

describe("a pushed request that no longer validates is refused, never a 500 (@spec mission#approval-event, mission#error-mapping, #1610)", () => {
  /** An Intent whose own expires_at is 100 seconds after t0. */
  const expiringAt = (t0: number) => ({ ...INTENT, expires_at: new Date(t0 + 100_000).toISOString().replace(/\.\d{3}Z$/, "Z") });

  it("a render after the request's expires_at passed refuses invalid_request", async () => {
    const t0 = Math.floor(Date.now() / 1000) * 1000;
    const flow = await open(expiringAt(t0));
    const headers = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    clockAt(t0 + 101_000);
    const page = await render(flow.uid, headers);
    expect(page.status, page.html).toBe(400);
    expect((JSON.parse(page.html) as { error?: string }).error).toBe("invalid_request");
    expect(page.revision).toBeNull();
  });

  it("a decision after the request's expires_at passed completes the request invalid_request and creates nothing", async () => {
    const t0 = Math.floor(Date.now() / 1000) * 1000;
    const flow = await open(expiringAt(t0));
    const headers = floorApprovalHeaders(SESSIONS, flow.uid, flow.cookie);
    clockAt(t0);
    const { revision } = await render(flow.uid, headers);
    clockAt(t0 + 101_000);
    const decided = await decide(flow.uid, headers, approve(revision));
    expect(decided.status, JSON.stringify(decided.json)).toBe(303);
    const resumed = await fetch(decided.location as string, { redirect: "manual", headers: { cookie: flow.cookie } });
    expect(new URL(resumed.headers.get("location") as string).searchParams.get("error")).toBe("invalid_request");
    await expectNothingCreated(flow.uid);
  });
});
