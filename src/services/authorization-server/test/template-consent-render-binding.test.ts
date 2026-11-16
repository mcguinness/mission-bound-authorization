/**
 * @spec mission-template#template-consent, derivation-limits#approval-rendering,
 * mission#approval-context-changes (#2057, D1293)
 *
 * A Mission Template consent decision approves only the latest rendering of
 * the consent page made to the deciding principal, and only while the
 * context that rendering committed is unchanged. The proposal pins (#2047)
 * keep the content consistent; the render revision is the proof that the
 * Approver was shown it. Each rendering to an authenticated principal (an
 * approval session, or the trusted headless approval service) retains a
 * revision committing the proposal, its pins, the policies held and the
 * disclosure; a rendering that refuses the disclosure retains none. Covered
 * here, through the real consent page and decide routes, under a controlled
 * clock:
 *   - a decision with no rendering;
 *   - a rendering made only while a policy was withdrawn or changed, decided
 *     after it is restored;
 *   - a stale rendering, and a held policy edited between rendering and
 *     decision;
 *   - a revision rendered to another principal;
 *   - recovery through a fresh rendering.
 * The disclosure refusals of #2047 keep their codes and precedence, and the
 * service-token stand-in (POST /templates) is untouched.
 */

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { activationPolicyDigest } from "@mission/core";
import { AUTHORITY_SOURCES, CANONICAL_RESOURCE, DERIVATION_POLICY, demoReconciliationTemplate, DEV_SERVICE_TOKEN, TOPOLOGY } from "@mission/demo-data";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { RENDER_REVISION_HEADER } from "../src/adapters/approval-render-revision.js";
import type { RegisteredActivationPolicy } from "../src/kernel/activation-policy.js";
import type { AuthorityEntry } from "../src/kernel/types.js";
import { ApprovalSessionStore, buildAuthorizationServer, type BuiltAs } from "../src/index.js";
import { browserApprovalHeaders, TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";

/** The controlled clock every component here reads, installed before any import runs (D1091). */
const controlledClock = await vi.hoisted(async () => {
  const { CONTROLLED_CLOCK_MS, installControlledClock } = await import("./controlled-clock.helper.js");
  return installControlledClock(CONTROLLED_CLOCK_MS);
});

const PAYMENTS = CANONICAL_RESOURCE;
const PLAIN = TOPOLOGY.resources.plainRs;
const READ = ["payments:invoice.read"];
const A_ID = "urn:policy:binding-child-a";
const B_ID = "urn:policy:binding-child-b";
const snapshot = (limit: number): RegisteredActivationPolicy => ({
  version: "1",
  content_type: "application/json",
  content: JSON.stringify({ rule: "children within the entry", derivation_limit_ceiling: limit }),
});
const dispatchPolicy = (id: string, limit: number) => ({
  version: "1",
  content_type: "application/json",
  content: JSON.stringify({ id, derivation_limit_ceiling: limit }),
});

/** The per-child rule the template's delegable entry commits through child creation policy A. */
const CHILD_RULE = "Each child Mission created under this consent establishes its own derivation limit from its own request, never above 3.";
/** The per-instance rule the Dispatch Policy states. */
const INSTANCE_RULE = "Each dispatched instance created under this consent establishes its own derivation limit from its own request, never above 3.";
const UNHELD_A = `child creation policy ${A_ID} version 1 is not one this issuer holds at its committed digest`;

interface Deployment {
  as: BuiltAs;
  issuer: string;
  server: Server;
  sessions: ApprovalSessionStore;
  /** The activation policies held, by reference: a case withdraws, edits and restores one in place. */
  held: Record<string, RegisteredActivationPolicy>;
  /** The Dispatch Policies held, by reference, likewise. */
  dispatch: Record<string, ReturnType<typeof dispatchPolicy>>;
  /** The payments read entry, committing child creation policy A. */
  readEntry: AuthorityEntry;
}

/**
 * A deployment whose payments read entry commits child creation policy A and
 * whose plain RS entry commits B, both held, with two Dispatch Policies held:
 * the template's (`test-dispatch`) and another (`test-other`).
 */
async function deploy(): Promise<Deployment> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const ref = (id: string, s: RegisteredActivationPolicy) => ({ id, version: "1", digest: activationPolicyDigest(issuer, s) });
  const aSnapshot = snapshot(3);
  const bSnapshot = snapshot(4);
  const ceiling = DERIVATION_POLICY.ceiling.map((entry, i) => {
    const e = entry as unknown as AuthorityEntry;
    if (e.resource === PAYMENTS && i === 0) {
      const children = (e.delegation as unknown as { children: Record<string, unknown> }).children;
      return { ...e, delegation: { ...e.delegation, children: { ...children, child_creation_policy: ref(A_ID, aSnapshot) } } };
    }
    if (e.resource === PLAIN) return { ...e, delegation: { max_depth: 1, children: { max_children: 2, child_creation_policy: ref(B_ID, bSnapshot) } } };
    return e;
  }) as unknown as AuthorityEntry[];
  const held: Record<string, RegisteredActivationPolicy> = { [A_ID]: aSnapshot, [B_ID]: bSnapshot };
  const dispatch = { "test-dispatch": dispatchPolicy("test-dispatch", 3), "test-other": dispatchPolicy("test-other", 7) };
  const sessions = new ApprovalSessionStore();
  try {
    const as = await buildAuthorizationServer({
      issuer,
      derivationPolicy: { ...DERIVATION_POLICY, derivation_limit_ceiling: null, ceiling } as never,
      authoritySources: {
        ...AUTHORITY_SOURCES,
        entries: AUTHORITY_SOURCES.entries.map((e) => (e.id === "acme-people" ? { ...e, ceiling } : e)),
      } as never,
      approvalSessions: sessions,
      allowHeadlessAdjudication: true,
      serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
      activationPolicies: held,
      dispatchPolicies: dispatch,
    });
    server.on("request", as.provider.callback());
    const readEntry = ceiling.find((e) => e.resource === PAYMENTS && e.actions.includes(READ[0] as string)) as AuthorityEntry;
    return { as, issuer, server, sessions, held, dispatch, readEntry };
  } catch (e) {
    server.close();
    throw e;
  }
}

let d: Deployment;

beforeAll(async () => {
  d = await deploy();
});

afterAll(() => {
  d?.server.closeAllConnections();
  d?.server.close();
  controlledClock.restore();
});

/** Runs `body` with activation policy `id` replaced by `value` (undefined withdraws it), restoring it after. */
async function replaced<T>(id: string, value: RegisteredActivationPolicy | undefined, body: () => Promise<T>): Promise<T> {
  const kept = d.held[id] as RegisteredActivationPolicy;
  if (value === undefined) delete d.held[id];
  else d.held[id] = value;
  try {
    return await body();
  } finally {
    d.held[id] = kept;
  }
}

/**
 * Runs `body` with Dispatch Policy `id` edited in place under its unchanged
 * version to state `limit`, as an operator edits a policy, restoring it after.
 */
async function editedDispatch<T>(id: string, limit: number, body: () => Promise<T>): Promise<T> {
  const policy = d.dispatch[id] as ReturnType<typeof dispatchPolicy>;
  const kept = policy.content;
  policy.content = JSON.stringify({ id, derivation_limit_ceiling: limit });
  try {
    return await body();
  } finally {
    policy.content = kept;
  }
}

/** A proposal of the demo template whose ceiling is the payments read entry, under `test-dispatch`. */
async function proposed(): Promise<string> {
  const { approver: _a, approval_event_id: _e, issuer: _i, ...body } = demoReconciliationTemplate(d.issuer);
  const res = await fetch(`${d.issuer}/templates/proposals`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
    body: JSON.stringify({ ...body, ceiling: [{ ...d.readEntry, actions: READ }], dispatch_policy: { id: "test-dispatch", version: "1" } }),
  });
  const out = (await res.json()) as { proposal_id: string };
  expect(res.status, JSON.stringify(out)).toBe(201);
  return out.proposal_id;
}

/** Bob's approval session for the proposal: one user agent's login. */
const login = (id: string) => browserApprovalHeaders(d.sessions, id, { sub: "bob" }, "");
/** The trusted headless approval service, acting as Bob and selecting no Subject. */
const service = () => trustedApprovalHeaders("bob", {}, null);

/** The consent page rendered to the principal `headers` authenticate (none: an anonymous request). */
async function render(id: string, headers: Record<string, string> = {}) {
  const { "content-type": _t, "x-csrf-token": _c, ...rendering } = headers;
  const res = await fetch(`${d.issuer}/templates/proposals/${id}`, { headers: rendering });
  return { status: res.status, html: await res.text(), revision: res.headers.get(RENDER_REVISION_HEADER) };
}

/** An approval by the principal `headers` authenticate, naming `revision` (undefined: none). */
async function approve(id: string, headers: Record<string, string>, revision?: string | null) {
  const res = await fetch(`${d.issuer}/templates/proposals/${id}/decide`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify({ decision: "approve", ...(revision !== undefined ? { render_revision: revision } : {}) }),
  });
  return { status: res.status, body: (await res.json()) as { template_id?: string; error?: string; error_description?: string; changed?: string[] } };
}

/** The items of every `ul.<cls>` on a page. */
const lines = (html: string, cls: string): string[] =>
  [...html.matchAll(new RegExp(`<ul class="${cls}">(.*?)</ul>`, "g"))].flatMap((list) =>
    [...(list[1] as string).matchAll(/<li>(.*?)<\/li>/g)].map((m) => m[1] as string),
  );

/** The Template Ceiling a page renders. */
function renderedCeiling(html: string): unknown {
  const text = (/<pre class="template-ceiling">([\s\S]*?)<\/pre>/.exec(html)?.[1] as string)
    .replace(/&quot;/g, '"')
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
  return JSON.parse(text);
}

const noTemplate = (id: string) => expect(d.as.templateStore.getByApprovalEvent(`apev_${id}`)).toBeUndefined();

describe("a Mission Template consent decision approves only the latest rendering made to the deciding principal (#2057, D1293; @spec mission-template#template-consent, derivation-limits#approval-rendering)", () => {
  it("a decision with no rendering approves nothing: an approval naming no revision, or one this issuer never issued, is refused rendering_required for a browser login and for the headless approval service, creating no template and leaving the proposal pending; an anonymous rendering issues no revision", async () => {
    const id = await proposed();
    // Anonymous: the page offers only the sign-in, and retains no revision.
    const anonymous = await render(id);
    expect(anonymous.status).toBe(200);
    expect(anonymous.html).not.toContain("<form");
    expect(anonymous.revision).toBeNull();
    const session = login(id);
    for (const headers of [session, service()]) {
      for (const revision of [undefined, "never-issued"]) {
        const refused = await approve(id, headers, revision);
        expect(refused.status).toBe(409);
        expect(refused.body.error).toBe("rendering_required");
      }
    }
    noTemplate(id);
    // Still pending: the session's page offers the decision.
    expect((await render(id, session)).html).toContain(`<form method="post" action="/templates/proposals/${id}/decide">`);
  });

  it("a rendering made only while a child creation policy the ceiling commits was withdrawn approves nothing once it is restored: that page showed no rule, offered no decision and issued no revision, a decision then is refused access_denied, and the decision after restoration is refused rendering_required, creating no template; a fresh rendering shows the rule and approves", async () => {
    const id = await proposed();
    const session = login(id);
    await replaced(A_ID, undefined, async () => {
      for (const headers of [session, service()]) {
        const windowed = await render(id, headers);
        expect(windowed.html).toContain(UNHELD_A);
        expect(windowed.html).not.toContain(CHILD_RULE);
        expect(windowed.html).not.toContain("<form");
        expect(windowed.revision).toBeNull();
      }
      // #2047's refusal keeps its code and precedence while the policy is withdrawn.
      const refused = await approve(id, session);
      expect(refused.status).toBe(403);
      expect(refused.body.error).toBe("access_denied");
    });
    for (const headers of [session, service()]) {
      const late = await approve(id, headers);
      expect(late.status).toBe(409);
      expect(late.body.error).toBe("rendering_required");
    }
    noTemplate(id);
    const fresh = await render(id, session);
    expect(lines(fresh.html, "template-child-subtree")).toContain(CHILD_RULE);
    const approved = await approve(id, session, fresh.revision);
    expect(approved.status, JSON.stringify(approved.body)).toBe(201);
  });

  it("a rendering made only while the Dispatch Policy the template was proposed under was changed approves nothing once it is restored: that page showed no derivation limit, offered no decision and issued no revision, and the decision after restoration is refused rendering_required, creating no template; a fresh rendering shows the limit and approves", async () => {
    const id = await proposed();
    const session = login(id);
    await editedDispatch("test-dispatch", 50, async () => {
      const windowed = await render(id, session);
      expect(windowed.html).toContain('<p class="consent-refused">The Dispatch Policy test-dispatch version 1 is not the one');
      expect(lines(windowed.html, "dispatch-bounds")).toEqual([]);
      expect(windowed.html).not.toContain("<form");
      expect(windowed.revision).toBeNull();
    });
    const late = await approve(id, session);
    expect(late.status).toBe(409);
    expect(late.body.error).toBe("rendering_required");
    noTemplate(id);
    const fresh = await render(id, session);
    expect(lines(fresh.html, "dispatch-bounds")).toContain(INSTANCE_RULE);
    const approved = await approve(id, session, fresh.revision);
    expect(approved.status, JSON.stringify(approved.body)).toBe(201);
  });

  it("a stale rendering approves nothing: once the page is rendered again to the same principal, the earlier revision is refused rendering_required, creating no template", async () => {
    const id = await proposed();
    const session = login(id);
    const first = await render(id, session);
    const second = await render(id, session);
    expect(first.revision).toBeTruthy();
    expect(second.revision).toBeTruthy();
    expect(second.revision).not.toBe(first.revision);
    const stale = await approve(id, session, first.revision);
    expect(stale.status).toBe(409);
    expect(stale.body.error).toBe("rendering_required");
    noTemplate(id);
  });

  it("a held policy edited between the rendering and the decision changes the context: a child creation policy another entry commits, or another Dispatch Policy, edited in place is refused approval_context_changed naming held_policies, creating no template, and the rendering it presented is retired", async () => {
    const id = await proposed();
    const session = login(id);
    const edits: Array<() => Promise<{ status: number; body: { error?: string; changed?: string[] } }>> = [
      async () => {
        const { revision } = await render(id, session);
        return replaced(B_ID, snapshot(9), () => approve(id, session, revision));
      },
      async () => {
        const { revision } = await render(id, session);
        const refused = await editedDispatch("test-other", 9, () => approve(id, session, revision));
        // Retired: restored, the same rendering still approves nothing.
        const retired = await approve(id, session, revision);
        expect(retired.status).toBe(409);
        expect(retired.body.error).toBe("rendering_required");
        return refused;
      },
    ];
    for (const edit of edits) {
      const refused = await edit();
      expect(refused.status).toBe(409);
      expect(refused.body.error).toBe("approval_context_changed");
      expect(refused.body.changed).toEqual(["held_policies"]);
      noTemplate(id);
    }
  });

  it("a revision rendered to another principal approves nothing: one rendered in another approval session, or to the headless approval service, is refused rendering_required, creating no template; the session's own latest rendering then approves", async () => {
    const id = await proposed();
    const mine = login(id);
    const other = login(id);
    const { revision } = await render(id, mine);
    for (const headers of [other, service()]) {
      const foreign = await approve(id, headers, revision);
      expect(foreign.status).toBe(409);
      expect(foreign.body.error).toBe("rendering_required");
    }
    const serviceRendering = await render(id, service());
    expect(serviceRendering.revision).toBeTruthy();
    const crossed = await approve(id, other, serviceRendering.revision);
    expect(crossed.status).toBe(409);
    expect(crossed.body.error).toBe("rendering_required");
    noTemplate(id);
    const approved = await approve(id, mine, revision);
    expect(approved.status, JSON.stringify(approved.body)).toBe(201);
  });

  it("a fresh rendering recovers a refused decision: after a context change, a new rendering to the same principal carries its revision in the form and approves, and the template commits the ceiling and the Dispatch Policy that rendering showed; the spent revision decides nothing again", async () => {
    const id = await proposed();
    const session = login(id);
    const first = await render(id, session);
    const refused = await replaced(B_ID, snapshot(9), () => approve(id, session, first.revision));
    expect(refused.body.error).toBe("approval_context_changed");
    const fresh = await render(id, session);
    expect(fresh.html).toContain(`<input type="hidden" name="render_revision" value="${fresh.revision}">`);
    expect(lines(fresh.html, "template-child-subtree")).toContain(CHILD_RULE);
    const approved = await approve(id, session, fresh.revision);
    expect(approved.status, JSON.stringify(approved.body)).toBe(201);
    const template = d.as.templateStore.get(approved.body.template_id as string);
    expect(template?.ceiling).toEqual(renderedCeiling(fresh.html));
    expect(template?.dispatch_policy).toMatchObject({ id: "test-dispatch", version: "1", digest: expect.any(String) });
    expect(template?.approver).toEqual({ iss: d.issuer, sub: "bob" });
    const again = await approve(id, session, fresh.revision);
    expect(again.status).toBe(400);
    expect(d.as.templateStore.getByApprovalEvent(`apev_${id}`)?.id).toBe(template?.id);
  });
});
