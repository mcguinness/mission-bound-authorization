/**
 * @spec draft-mcguinness-oauth-mission-template (#template-consent),
 * draft-mcguinness-mission-derivation-limits (#approval-rendering) (#1119)
 *
 * The human consent to a Mission Template. An administrator proposes the
 * template body (POST /templates/proposals, service-token admin plane); the
 * Approver reads the consent page and decides. Covered here:
 *   - the minimum disclosure, rendered before any template exists;
 *   - each dispatched instance's derivation-limit rule, maximum and scope,
 *     beside max_active and the dispatch rate;
 *   - approval by the authenticated Approver, who becomes the approver of
 *     record, with the activated authority source retained;
 *   - refusal while the Dispatch Policy the proposal pinned has changed;
 *   - the decision's authentication, the absent Subject, a denial, and an
 *     Approver not authorized to activate the source;
 *   - refusals at the proposal.
 */

import { type Server } from "node:http";
import { DERIVATION_POLICY, demoReconciliationTemplate, DEV_SERVICE_TOKEN, TRUSTED_TOOL_CATALOGS } from "@mission/demo-data";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  MACHINE_SPEED_STATEMENT,
  PROHIBITED_CLASSES_STATEMENT,
  TEMPLATE_CEILING_STATEMENT,
} from "../src/adapters/template-consent.js";
import { ApprovalSessionStore, buildAuthorizationServer, type BuiltAs } from "../src/index.js";
import {
  browserApprovalHeaders,
  floorApprovalHeaders,
  TEST_APPROVAL_PRINCIPALS,
  trustedApprovalHeaders,
} from "./approval-fixture.js";

const PORT = 14987;
const ISSUER = `http://localhost:${PORT}`;
const SESSIONS = new ApprovalSessionStore();

const heldPolicy = (id: string, rule: { derivation_limit_ceiling?: number | null } = {}) => ({
  version: "1",
  content_type: "application/json",
  content: JSON.stringify({ id, ...rule }),
});
/** Held by reference, so a test can edit it in place, as an operator edits a policy under an unchanged version. */
const EDITABLE = heldPolicy("test-editable", { derivation_limit_ceiling: 3 });

let as: BuiltAs;
let server: Server;

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    approvalSessions: SESSIONS,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    dispatchPolicies: {
      "test-limit-3": heldPolicy("test-limit-3", { derivation_limit_ceiling: 3 }),
      "test-editable": EDITABLE,
    },
  });
  server = as.provider.listen(PORT);
});

afterAll(() => {
  server?.close();
});

/** The demo reconciliation template as a proposal: no approver, approval event or issuer. */
function proposalBody(policy = "test-limit-3"): Record<string, unknown> {
  const { approver: _approver, approval_event_id: _event, issuer: _issuer, ...body } = demoReconciliationTemplate(ISSUER);
  return { ...body, dispatch_policy: { id: policy, version: "1" } };
}

async function propose(body: unknown, token: string | null = DEV_SERVICE_TOKEN): Promise<Response> {
  return fetch(`${ISSUER}/templates/proposals`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(token !== null ? { "x-service-token": token } : {}) },
    body: JSON.stringify(body),
  });
}

async function proposed(policy?: string): Promise<string> {
  const res = await propose(proposalBody(policy));
  const body = (await res.json()) as { proposal_id: string; consent_uri: string };
  expect(res.status, JSON.stringify(body)).toBe(201);
  expect(body.consent_uri).toBe(`${ISSUER}/templates/proposals/${body.proposal_id}`);
  return body.proposal_id;
}

async function page(id: string, cookie?: string): Promise<{ status: number; html: string }> {
  const res = await fetch(`${ISSUER}/templates/proposals/${id}`, cookie ? { headers: { cookie } } : {});
  return { status: res.status, html: await res.text() };
}

/** The Template Ceiling the page renders. */
function renderedCeiling(html: string): Array<Record<string, unknown>> {
  const text = (/<pre class="template-ceiling">([\s\S]*?)<\/pre>/.exec(html)?.[1] as string)
    .replace(/&quot;/g, '"')
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
  return JSON.parse(text) as Array<Record<string, unknown>>;
}

/** The items of the page's `ul.<cls>`, or none. */
function items(html: string, cls: string): string[] {
  const list = new RegExp(`<ul class="${cls}">(.*?)</ul>`).exec(html);
  return list ? [...(list[1] as string).matchAll(/<li>(.*?)<\/li>/g)].map((m) => m[1] as string) : [];
}

async function decide(id: string, decision: string, headers: Record<string, string>, extra: Record<string, unknown> = {}) {
  return fetch(`${ISSUER}/templates/proposals/${id}/decide`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify({ decision, ...extra }),
  });
}

/** An Approver logged in on the consent page's user agent, keyed by the proposal. */
const loggedIn = (id: string, sub = "bob") => browserApprovalHeaders(SESSIONS, id, { sub }, "");

describe("the human consent to a Mission Template (@spec mission-template#template-consent, #1119)", () => {
  it("renders the minimum disclosure before any template exists: the Template Ceiling as the maximum authority, machine-speed dispatch with no per-instance approval, and the high-consequence classes policy never dispatches", async () => {
    const id = await proposed();
    const { status, html } = await page(id);
    expect(status).toBe(200);
    expect(items(html, "template-statements")).toEqual([
      TEMPLATE_CEILING_STATEMENT,
      MACHINE_SPEED_STATEMENT,
      PROHIBITED_CLASSES_STATEMENT,
    ]);
    // The proposed ceiling, with the trusted capability bindings it will commit.
    expect(renderedCeiling(html).map(({ capability_sources: _bindings, ...entry }) => entry)).toEqual(proposalBody().ceiling);
    // Only the user agent holding the Approver's login for this proposal is
    // offered the decision, and its form carries that login's CSRF secret.
    expect(html).not.toContain("<form");
    expect(html).toContain('<p class="sign-in">');
    const session = loggedIn(id);
    const signedIn = (await page(id, session.cookie)).html;
    expect(signedIn).toContain(`<form method="post" action="/templates/proposals/${id}/decide">`);
    expect(signedIn).toContain(`<input type="hidden" name="csrf_token" value="${session["x-csrf-token"]}">`);
    expect(as.templateStore.getByApprovalEvent(`apev_${id}`)).toBeUndefined();
  });

  it("renders each dispatched instance's derivation-limit rule, its maximum and its local scope beside max_active and the dispatch rate (@spec derivation-limits#approval-rendering)", async () => {
    const finite = items((await page(await proposed())).html, "dispatch-bounds");
    expect(finite).toEqual([
      "At most 5 dispatched instances are active at once.",
      "At most 30 dispatches per minute.",
      "Each dispatched instance created under this consent establishes its own derivation limit from its own request, never above 3.",
      "This maximum is local to each dispatched instance: it is not a budget across the Missions this consent admits, their descendants, or their lifetimes.",
      "The refreshes of an async delegation family are not counted against this limit.",
      "Each dispatched instance establishes and counts its own limit, so this consent admits up to 5 such limits at once, and more over time.",
    ]);
    // A Dispatch Policy stating no maximum: the rendering says none is guaranteed.
    const none = items((await page(await proposed("read-only-reconciliation"))).html, "dispatch-bounds");
    expect(none[2]).toBe(
      "Each dispatched instance created under this consent establishes its own derivation limit from its own request; no finite maximum is guaranteed.",
    );
  });

  it("an approval by the authenticated Approver creates the template, with that Approver of record and the authority source it activates retained beside the consented template_version", async () => {
    const id = await proposed();
    const res = await decide(id, "approve", loggedIn(id));
    const body = (await res.json()) as { template_id: string; template_version: string; template_hash: string };
    expect(res.status, JSON.stringify(body)).toBe(201);
    const template = as.templateStore.get(body.template_id);
    expect(template?.approver).toEqual({ iss: ISSUER, sub: "bob" });
    expect(template?.template_version).toBe("demo-reconciliation-1");
    expect(template?.template_hash).toBe(body.template_hash);
    // The template commits the Dispatch Policy whose figure the page rendered.
    expect(template?.dispatch_policy).toMatchObject({ id: "test-limit-3", version: "1", digest: expect.any(String) });
    expect(template?.authority_source.type).toBe("user_delegated");
    expect(as.templateStore.getByApprovalEvent(`apev_${id}`)?.id).toBe(body.template_id);
    // Settled: the page reports the template, and no second decision is taken.
    const after = await page(id);
    expect(after.html).toContain(`approved as template <code>${body.template_id}</code>`);
    expect(after.html).not.toContain("<form");
    expect((await decide(id, "approve", loggedIn(id))).status).toBe(400);
  });

  it("retains an organizational authority source with its governed policy reference, with the consenting Approver and the consented template_version", async () => {
    const res = await propose({
      ...proposalBody(),
      recipients: { subjects: [{ iss: ISSUER, sub: "acme-accounts-payable" }], agents: ["governed-agent"] },
    });
    const { proposal_id: id } = (await res.json()) as { proposal_id: string };
    expect(res.status).toBe(201);
    const approved = await decide(id, "approve", loggedIn(id));
    const body = (await approved.json()) as { template_id: string };
    expect(approved.status, JSON.stringify(body)).toBe(201);
    const template = as.templateStore.get(body.template_id);
    expect(template?.authority_source).toMatchObject({
      type: "organizational",
      policy: { id: "acme-accounts-payable-controls", version: "2026-09-01", digest: expect.any(String) },
    });
    expect(template?.approver).toEqual({ iss: ISSUER, sub: "bob" });
    expect(template?.template_version).toBe("demo-reconciliation-1");
  });

  it("refuses the consent while the Dispatch Policy the template was proposed under has changed: the page states why and offers no decision, and no template is created; restored, the same proposal is approved", async () => {
    const id = await proposed("test-editable");
    const original = EDITABLE.content;
    EDITABLE.content = JSON.stringify({ id: "test-editable", derivation_limit_ceiling: 50 });
    try {
      const { html } = await page(id, loggedIn(id).cookie);
      expect(html).toContain('<p class="consent-refused">The Dispatch Policy test-editable version 1 is not the one');
      expect(html).not.toContain("<form");
      expect(items(html, "dispatch-bounds")).toEqual([]);
      const refused = await decide(id, "approve", loggedIn(id));
      expect(refused.status).toBe(403);
      expect(((await refused.json()) as { error: string }).error).toBe("access_denied");
      expect(as.templateStore.getByApprovalEvent(`apev_${id}`)).toBeUndefined();
    } finally {
      EDITABLE.content = original;
    }
    const approved = await decide(id, "approve", loggedIn(id));
    expect(approved.status).toBe(201);
    expect(items((await page(await proposed("test-editable"))).html, "dispatch-bounds")[2]).toContain("never above 3.");
  });

  it("renders the Template Ceiling with its trusted capability bindings, discarding caller-supplied ones, and the approval commits exactly the ceiling rendered (@spec capability-binding#conformance)", async () => {
    const forged = {
      action: "payments:invoice.read",
      tool_id: "mcp://forged.example/tools/anything",
      source_uri: "https://forged.example/catalog",
      source_digest: "sha-256:AAAA",
      operation_ref: "anything",
    };
    const body = proposalBody();
    const ceiling = (body.ceiling as Array<Record<string, unknown>>).map((entry) => ({ ...entry, capability_sources: [forged] }));
    const res = await propose({ ...body, ceiling });
    const { proposal_id: id } = (await res.json()) as { proposal_id: string };
    expect(res.status).toBe(201);
    const session = loggedIn(id);
    const rendered = renderedCeiling((await page(id, session.cookie)).html);
    expect(JSON.stringify(rendered)).not.toContain("forged.example");
    expect(JSON.stringify(rendered)).toContain("mcp://payments.demo/tools/");
    const approved = await decide(id, "approve", session);
    const { template_id } = (await approved.json()) as { template_id: string };
    expect(approved.status).toBe(201);
    expect(as.templateStore.get(template_id)?.ceiling).toEqual(rendered);
  });

  it("refuses the consent while a trusted capability definition of the ceiling has changed since the proposal: the page offers no decision and no template is created; restored, the same proposal is approved (@spec capability-binding#conformance)", async () => {
    const id = await proposed();
    const catalog = TRUSTED_TOOL_CATALOGS.find((c) => c.service_id === "payments") as { text: string };
    const original = catalog.text;
    const edited = JSON.parse(original) as { tools: Array<{ description?: string }> };
    for (const tool of edited.tools) tool.description = `${tool.description ?? ""} (edited after the proposal)`;
    catalog.text = JSON.stringify(edited);
    try {
      const { html } = await page(id, loggedIn(id).cookie);
      expect(html).toContain('<p class="consent-refused">The trusted capability bindings of the Template Ceiling changed');
      expect(html).not.toContain("<form");
      const refused = await decide(id, "approve", loggedIn(id));
      expect(refused.status).toBe(403);
      expect(((await refused.json()) as { error: string }).error).toBe("access_denied");
      expect(as.templateStore.getByApprovalEvent(`apev_${id}`)).toBeUndefined();
    } finally {
      catalog.text = original;
    }
    expect((await decide(id, "approve", loggedIn(id))).status).toBe(201);
  });

  it("decides only for an authenticated Approver, never one the request names, and selects no Subject; a denial creates no template", async () => {
    const id = await proposed();
    expect((await decide(id, "approve", {})).status).toBe(401);
    expect((await decide(id, "approve", loggedIn(id), { approver: "bob" })).status).toBe(400);
    const selecting = await decide(id, "approve", trustedApprovalHeaders("bob", {}, "alice"));
    expect(selecting.status).toBe(400);
    expect(((await selecting.json()) as { error_description: string }).error_description).toBe(
      "a template consent selects no Subject",
    );
    const denied = await decide(id, "deny", trustedApprovalHeaders("bob", {}, null));
    expect(denied.status).toBe(200);
    expect(await denied.json()).toEqual({ proposal_id: id, state: "denied" });
    expect(as.templateStore.getByApprovalEvent(`apev_${id}`)).toBeUndefined();
    expect((await decide(id, "approve", trustedApprovalHeaders("bob", {}, null))).status).toBe(400);
    expect((await page(id)).html).toContain("This proposal was denied.");
  });

  it("holds the consent to the approval-authentication floor for everything the Template Ceiling admits: high-risk authority is refused after a password-only login and through a headless approval service, creating no template, and approved after an mfa login (@spec mission#approval-authentication)", async () => {
    const remit = [
      {
        type: "mission_resource_access",
        resource: DERIVATION_POLICY.ceiling[0]?.resource as string,
        actions: ["payments:invoice.read", "payments:remittance.send"],
        constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
      },
    ];
    const res = await propose({ ...proposalBody(), ceiling: remit });
    const { proposal_id: id } = (await res.json()) as { proposal_id: string };
    expect(res.status).toBe(201);
    for (const headers of [loggedIn(id), trustedApprovalHeaders("bob", {}, null)]) {
      const refused = await decide(id, "approve", headers);
      expect(refused.status).toBe(403);
      expect(((await refused.json()) as { error: string }).error).toBe("access_denied");
    }
    expect(as.templateStore.getByApprovalEvent(`apev_${id}`)).toBeUndefined();
    const approved = await decide(id, "approve", floorApprovalHeaders(SESSIONS, id, "", { subject: null }));
    expect(approved.status).toBe(201);
  });

  it("refuses an Approver not authorized to activate the template's authority source, creating no template", async () => {
    const id = await proposed();
    const refused = await decide(id, "approve", loggedIn(id, "dana"));
    expect(refused.status).toBe(400);
    expect(as.templateStore.getByApprovalEvent(`apev_${id}`)).toBeUndefined();
    expect((await decide(id, "approve", loggedIn(id))).status).toBe(201);
  });

  it("refuses at the proposal: a named approver, approval event or issuer, a missing service token, a malformed body, and a Dispatch Policy this issuer does not hold", async () => {
    for (const member of ["approver", "approval_event_id", "issuer"]) {
      const res = await propose({ ...proposalBody(), [member]: "x" });
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error_description: string }).error_description).toContain(`carries no ${member}`);
    }
    expect((await propose(proposalBody(), null)).status).toBe(401);
    const { ceiling: _ceiling, ...noCeiling } = proposalBody();
    expect((await propose(noCeiling)).status).toBe(400);
    const unheld = await propose(proposalBody("not-held"));
    expect(unheld.status).toBe(400);
    expect(((await unheld.json()) as { error_description: string }).error_description).toBe(
      "dispatch_policy not-held version 1 is not a Dispatch Policy this issuer holds",
    );
    expect((await page("tcon_unknown")).status).toBe(404);
    expect((await decide("tcon_unknown", "approve", loggedIn("tcon_unknown"))).status).toBe(404);
  });
});
