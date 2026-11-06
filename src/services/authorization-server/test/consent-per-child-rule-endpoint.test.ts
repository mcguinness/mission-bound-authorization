/**
 * @spec derivation-limits#approval-rendering, derivation-limits#effective-limit,
 * child-delegation#subtree-rendering (#2040, D1260 ruling 3)
 *
 * The per-child rule on the approval surfaces of the standing consents under
 * which policy creates Missions, for each delegable entry with no
 * `child_creation_policy`: the Progressive ceiling consent on the Mission
 * approval page, the Expansion deferral page and its ceiling re-consent, and
 * the Mission Template consent page. Each renders the rule and the maximum
 * (here the deployment's per-child figure, 3), each decision is bound to the
 * figure rendered, and the consent retains that figure, so the Missions
 * created under it later take it whatever the deployment's figure has since
 * become. The deployment policy is held by reference, so a case edits its
 * figure in place, as an operator edits a policy under an unchanged
 * `policy_version`. The restart witnesses are in consent-per-child-rule.test.ts.
 */

import { type Server } from "node:http";
import {
  CANONICAL_RESOURCE,
  DERIVATION_POLICY,
  demoReconciliationTemplate,
  DEV_SERVICE_TOKEN,
  PROGRESSIVE_PROFILE,
} from "@mission/demo-data";
import { type CryptoKey, importJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { RENDER_REVISION_HEADER } from "../src/adapters/approval-render-revision.js";
import { assembledCeilingOffer, type CeilingConsent, progressiveFromProfile } from "../src/kernel/progressive.js";
import type { AuthorityEntry, MissionRecord } from "../src/kernel/types.js";
import {
  ApprovalSessionStore,
  buildAuthorizationServer,
  type BuiltAs,
  createChildMission,
  dispatchFromTemplate,
  validateMissionIntent,
} from "../src/index.js";
import {
  browserApprovalHeaders,
  floorApprovalHeaders,
  TEST_APPROVAL_PRINCIPALS,
  trustedApprovalHeaders,
} from "./approval-fixture.js";

/** The controlled clock every component here reads, installed before any import runs (D1091). */
const controlledClock = await vi.hoisted(async () => {
  const { CONTROLLED_CLOCK_MS, installControlledClock } = await import("./controlled-clock.helper.js");
  return installControlledClock(CONTROLLED_CLOCK_MS);
});

const PORT = 15411;
const ISSUER = `http://localhost:${PORT}`;
const RESOURCE = CANONICAL_RESOURCE;
const REDIRECT_URI = "http://localhost:9999/cb";
const FAR_EXP = "2027-01-01T00:00:00Z";
const SESSIONS = new ApprovalSessionStore();

/** The shipped policy with a per-child figure of 3, held by reference so a case can edit it in place. */
const POLICY = { ...DERIVATION_POLICY, derivation_limit_ceiling: 3 as number | null };
const PUBLISHED = progressiveFromProfile(PROGRESSIVE_PROFILE);
/** The payments ceiling exactly as the policy states it: both entries grant children with no child_creation_policy. */
const FULL_CEILING = DERIVATION_POLICY.ceiling.filter((e) => e.resource === RESOURCE) as unknown as AuthorityEntry[];
const OFFER = { authority_ceiling: FULL_CEILING, drawdown_policy: { id: "drawdown-std", version: "1" } };
/** The offer as the page renders it and a consent commits it: its contract references assembled from configuration. */
const assembled = (): CeilingConsent => assembledCeilingOffer(OFFER, as.kernel.resourceContracts()) as CeilingConsent;
const DISPATCH = { version: "1", content_type: "application/json", content: JSON.stringify({ id: "test-dispatch" }) };

const RULE_3 =
  "Each child Mission created under this consent establishes its own derivation limit from its own request, never above 3.";
const SCOPE =
  "This maximum is local to each child Mission: it is not a budget across the Missions this consent admits, their descendants, or their lifetimes.";

let as: BuiltAs;
let server: Server;
let agentKey: CryptoKey;

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    derivationPolicy: POLICY as never,
    approvalSessions: SESSIONS,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    activationPolicies: PUBLISHED.policies,
    progressive: { ...PUBLISHED.options, ceilingOffer: () => OFFER },
    dispatchPolicies: { "test-dispatch": DISPATCH },
  });
  server = as.provider.listen(PORT);
  agentKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
});

afterAll(() => {
  server?.close();
  controlledClock.restore();
});

/** Runs `body` with the deployment's per-child figure set to `figure`, restoring 3 after. */
async function withFigure<T>(figure: number | null, body: () => Promise<T> | T): Promise<T> {
  POLICY.derivation_limit_ceiling = figure;
  try {
    return await body();
  } finally {
    POLICY.derivation_limit_ceiling = 3;
  }
}

/** The items of every `ul.<cls>` on a page. */
function items(html: string, cls: string): string[][] {
  return [...html.matchAll(new RegExp(`<ul class="${cls}">(.*?)</ul>`, "g"))].map((list) =>
    [...(list[1] as string).matchAll(/<li>(.*?)<\/li>/g)].map((m) => m[1] as string),
  );
}

const readEntry = (actions: string[]) => ({
  type: "mission_resource_access",
  resource: RESOURCE,
  actions,
  constraints: { vendors: ["acme"] },
});

const intentJson = (goal: string) => JSON.stringify({ intent: { goal, target_resources: [RESOURCE], expires_at: FAR_EXP } });
const intent = (goal: string) =>
  validateMissionIntent(JSON.stringify({ goal, target_resources: [RESOURCE], expires_at: FAR_EXP }), { now: as.kernel.nowDate() });

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

function cookies(res: Response, jar: Map<string, string>): void {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
  }
}

/** PAR and /auth for a read Mission: the interaction and the Approver's headers on it. */
async function interaction(): Promise<{ uid: string; headers: Record<string, string> }> {
  const jar = new Map<string, string>();
  const par = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: RESOURCE,
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      code_challenge_method: "S256",
      login_hint: "alice",
      mission_intent: intentJson("Read Acme invoices"),
      authorization_details: JSON.stringify([readEntry(["payments:invoice.read"])]),
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const parBody = (await par.json()) as { request_uri: string };
  expect(par.status, JSON.stringify(parBody)).toBe(201);
  const res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: parBody.request_uri })}`, {
    redirect: "manual",
  });
  cookies(res, jar);
  const uid = (res.headers.get("location") as string).split("/interaction/")[1] as string;
  const cookie = [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  return { uid, headers: floorApprovalHeaders(SESSIONS, uid, cookie) };
}

describe("the Mission approval page renders the per-child rule a Progressive ceiling consent retains (#2040; @spec derivation-limits#approval-rendering, progressive#progressive-authorization)", () => {
  it("renders, for each delegable entry of the offered ceiling, the per-child rule, its maximum and its local scope, and an approval consenting the ceiling retains that figure for each ceiling entry", async () => {
    const { uid, headers } = await interaction();
    const page = await fetch(`${ISSUER}/interaction/${uid}`, { headers: { cookie: headers.cookie as string } });
    expect(page.status).toBe(200);
    const revision = page.headers.get(RENDER_REVISION_HEADER) as string;
    const blocks = items(await page.text(), "ceiling-child-subtree");
    expect(blocks).toHaveLength(FULL_CEILING.length);
    for (const lines of blocks) {
      expect(lines).toContain(RULE_3);
      expect(lines).toContain(SCOPE);
    }
    const decided = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
      method: "POST",
      redirect: "manual",
      headers: { ...headers, "content-type": "application/json" },
      body: JSON.stringify({ decision: "approve", render_revision: revision, ...assembled() }),
    });
    expect(decided.status, await decided.text()).toBeLessThan(400);
    // The decision resumes the authorization request, which commits the Mission.
    for (let location = decided.headers.get("location"); location?.startsWith(ISSUER); ) {
      const next = await fetch(location, { redirect: "manual", headers: { cookie: headers.cookie as string } });
      location = next.headers.get("location");
    }
    const mission = as.kernel.findByApprovalEvent(`apev_${uid}`) as MissionRecord;
    expect(mission.authority_ceiling).toEqual(assembled().authority_ceiling);
    expect(mission.ceiling_child_derivation_maxima).toEqual(FULL_CEILING.map(() => ({ finite: 3 })));
  });
});

describe("the Expansion approval page renders and binds the per-child rule its decision retains (#2040; @spec derivation-limits#approval-rendering, expansion#completion-modes)", () => {
  const predecessor = (ceiling = false): MissionRecord =>
    as.kernel.approve({
      intent: intent("Read Acme invoices"),
      proposedAuthority: [readEntry(["payments:invoice.read"])] as never,
      subject: { iss: ISSUER, sub: "alice" },
      approver: { iss: ISSUER, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: `pred-${crypto.randomUUID()}`,
      ...(ceiling ? { ceiling: assembled() } : {}),
    });
  /** A deferral widening `pred` by a separate list entry. */
  const open = (pred: MissionRecord): string =>
    as.expansionDeferrals.open({
      predecessorId: pred.id,
      intent: intent(`Widen ${crypto.randomUUID()}`),
      proposedAuthority: [readEntry(["payments:invoice.read"]), readEntry(["payments:invoice.list"])] as never,
      clientId: "ap-agent",
      jkt: "jkt",
      creationRequestId: crypto.randomUUID(),
    }).deferral_code;
  const render = async (code: string, headers: Record<string, string>) => {
    const res = await fetch(`${ISSUER}/expansions/deferrals/${code}`, { headers });
    const html = await res.text();
    expect(res.status, html.slice(0, 300)).toBe(200);
    return { html, revision: res.headers.get(RENDER_REVISION_HEADER) as string };
  };
  const decide = (code: string, headers: Record<string, string>, extra: Record<string, unknown>) =>
    fetch(`${ISSUER}/expansions/deferrals/${code}/decide`, {
      method: "POST",
      headers: { ...headers, "content-type": "application/json" },
      body: JSON.stringify({ decision: "approve", ...extra }),
    });
  const complete = (code: string): MissionRecord => {
    const result = as.expansionDeferrals.redeem(code);
    if (!("successor" in result)) throw new Error(`completion refused: ${JSON.stringify(result)}`);
    return result.successor;
  };

  it("renders the per-child rule and maximum for each delegable entry of the successor, and the figure the approval retains is the one rendered: completed after the deployment's figure is removed, the entry the Expansion adds retains 3 and its child records 3", async () => {
    const code = open(predecessor());
    const headers = trustedApprovalHeaders("bob");
    const { html, revision } = await render(code, headers);
    const blocks = items(html, "child-subtree");
    expect(blocks).toHaveLength(2);
    for (const lines of blocks) {
      expect(lines).toContain(RULE_3);
      expect(lines).toContain(SCOPE);
    }
    const approved = await decide(code, headers, { render_revision: revision });
    expect(approved.status, await approved.text()).toBe(200);
    const successor = await withFigure(null, () => complete(code));
    expect(successor.child_derivation_maxima).toEqual([{ finite: 3 }, { finite: 3 }]);
    const childOf = createChildMission(as.kernel, {
      parentId: successor.id,
      intent: intent("List Acme invoices"),
      proposedAuthority: [readEntry(["payments:invoice.list"])] as never,
      childActor: { sub: "subagent-invoice-extractor", sub_profile: "ai_agent" },
    }).child;
    expect(childOf.derivation_limit).toBe(3);
  });

  it("a per-child figure changed between the rendering and the decision approves nothing: the decision is refused approval_context_changed naming child_derivation, the deferral stays pending, and a fresh rendering approves the figure it shows", async () => {
    const code = open(predecessor());
    const headers = trustedApprovalHeaders("bob");
    const first = await render(code, headers);
    const stale = await withFigure(10, async () => {
      const res = await decide(code, headers, { render_revision: first.revision });
      return { status: res.status, body: (await res.json()) as { error: string; changed: string[] } };
    });
    expect(stale.status).toBe(409);
    expect(stale.body.error).toBe("approval_context_changed");
    expect(stale.body.changed).toContain("child_derivation");
    expect(as.kernel.db.prepare("SELECT state FROM expansion_deferrals WHERE deferral_code = ?").get(code)).toEqual({
      state: "authorization_pending",
    });
    const fresh = await withFigure(10, async () => {
      const rendered = await render(code, headers);
      expect(items(rendered.html, "child-subtree")[1]).toContain(
        "Each child Mission created under this consent establishes its own derivation limit from its own request, never above 10.",
      );
      return (await decide(code, headers, { render_revision: rendered.revision })).status;
    });
    expect(fresh).toBe(200);
    expect(complete(code).child_derivation_maxima).toEqual([{ finite: 3 }, { finite: 10 }]);
  });

  it("renders the per-child rule for each delegable entry of the ceiling re-consent it offers, and a re-consent retains that figure with the successor's ceiling through the completion", async () => {
    const code = open(predecessor(true));
    const headers = floorApprovalHeaders(SESSIONS, code, "");
    const { html, revision } = await render(code, headers);
    const blocks = items(html, "reconsent-child-subtree");
    expect(blocks).toHaveLength(FULL_CEILING.length);
    for (const lines of blocks) expect(lines).toContain(RULE_3);
    const approved = await decide(code, headers, { render_revision: revision, reconsent: true });
    expect(approved.status, await approved.text()).toBe(200);
    const successor = await withFigure(10, () => complete(code));
    expect(successor.ceiling_child_derivation_maxima).toEqual(FULL_CEILING.map(() => ({ finite: 3 })));
  });
});

describe("the Mission Template consent page renders the per-child rule the template retains (#2040; @spec derivation-limits#approval-rendering, mission-template#template-consent)", () => {
  /** The demo body with one delegable ceiling entry, the policy's own read entry. */
  const proposalBody = (): Record<string, unknown> => {
    const { approver: _a, approval_event_id: _e, issuer: _i, ...body } = demoReconciliationTemplate(ISSUER);
    const delegable = { ...(FULL_CEILING[0] as AuthorityEntry), actions: ["payments:invoice.read"] };
    return { ...body, ceiling: [delegable], dispatch_policy: { id: "test-dispatch", version: "1" } };
  };
  const propose = async (): Promise<string> => {
    const res = await fetch(`${ISSUER}/templates/proposals`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
      body: JSON.stringify(proposalBody()),
    });
    const body = (await res.json()) as { proposal_id: string };
    expect(res.status, JSON.stringify(body)).toBe(201);
    return body.proposal_id;
  };
  const loggedIn = (id: string) => browserApprovalHeaders(SESSIONS, id, { sub: "bob" }, "");
  const page = async (id: string) => (await fetch(`${ISSUER}/templates/proposals/${id}`, { headers: { cookie: loggedIn(id).cookie as string } })).text();
  const decide = (id: string) =>
    fetch(`${ISSUER}/templates/proposals/${id}/decide`, {
      method: "POST",
      headers: { "content-type": "application/json", ...loggedIn(id) },
      body: JSON.stringify({ decision: "approve" }),
    });

  it("renders, for each delegable ceiling entry, the per-child rule, its maximum and its local scope, and the approval retains that figure: an instance dispatched after the deployment's figure is raised retains 3", async () => {
    const id = await propose();
    const [lines] = items(await page(id), "template-child-subtree");
    expect(lines).toContain(RULE_3);
    expect(lines).toContain(SCOPE);
    const approved = await decide(id);
    const { template_id } = (await approved.json()) as { template_id: string };
    expect(approved.status).toBe(201);
    const template = as.templateStore.get(template_id);
    expect(template?.ceiling_child_derivation_maxima).toEqual([{ finite: 3 }]);
    const instance = await withFigure(10, () =>
      dispatchFromTemplate(as.kernel, as.templateStore, {
        templateId: template_id,
        dispatchEventId: `dsp-${crypto.randomUUID()}`,
        dispatcher: "ap-agent",
        intent: intent("Read Acme invoices"),
        proposedAuthority: [readEntry(["payments:invoice.read"])] as never,
        subject: { iss: ISSUER, sub: "bob" },
        policyVersion: POLICY.policy_version,
        dispatchPolicies: { "test-dispatch": DISPATCH },
      }).mission,
    );
    expect(instance.child_derivation_maxima).toEqual([{ finite: 3 }]);
  });

  it("a per-child figure changed since the proposal is neither rendered nor consented to: the page states why, the decision creates no template, and once restored the same proposal is approved", async () => {
    const id = await propose();
    await withFigure(10, async () => {
      const html = await page(id);
      expect(html).toContain("per-child derivation limit changed since this template was proposed");
      expect(items(html, "template-child-subtree")).toEqual([]);
      const refused = await decide(id);
      expect(refused.status).toBe(403);
      expect(as.templateStore.getByApprovalEvent(`apev_${id}`)).toBeUndefined();
    });
    const approved = await decide(id);
    expect(approved.status).toBe(201);
    expect(as.templateStore.getByApprovalEvent(`apev_${id}`)?.ceiling_child_derivation_maxima).toEqual([{ finite: 3 }]);
  });
});
