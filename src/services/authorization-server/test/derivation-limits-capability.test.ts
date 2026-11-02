/**
 * #2018: Mission Derivation Limits as a deployment switch
 * (`derivation-limits`, adapters/capabilities.ts). An AS that does not
 * implement the profile "establishes no derivation limit, and its
 * closed-top-level validation refuses a submitted `requested_derivation_limit`
 * as an unknown member" (derivation-limits#introduction; the OAuth binding's
 * Closed top levels rule, mission#submission-via-par). Each wire assembly
 * here is the minimal configuration (`lifecycle-revoke` only) with or
 * without the switch. The disabled configuration's wire witness is also
 * demo/test/minimal-baseline-config.test.ts.
 *
 * The file runs on a controlled clock (D1091).
 */
const controlledClock = await vi.hoisted(async () => {
  const { CONTROLLED_CLOCK_MS, installControlledClock } = await import("./controlled-clock.helper.js");
  return installControlledClock(CONTROLLED_CLOCK_MS);
});

import { activationPolicyDigest } from "@mission/core";
import { AUTHORITY_SOURCES, DERIVATION_POLICY, DEV_SERVICE_TOKEN, demoReconciliationTemplate, TOPOLOGY } from "@mission/demo-data";
import { afterAll, describe, expect, it, vi } from "vitest";
import { approvalDerivationRendering } from "../src/adapters/provider.js";
import {
  ALL_PROVIDER_CAPABILITIES,
  ApprovalSessionStore,
  type AuthorityEntry,
  ChildDelegationError,
  createChildMission,
  type MissionRecord,
  type ProviderCapability,
} from "../src/index.js";
import { browserApprovalHeaders } from "./approval-fixture.js";
import { approve, decideApproval, par, READ, startAs, type SwitchedAs } from "./capability-switch.helper.js";

afterAll(() => controlledClock.restore());

const MINIMAL: ProviderCapability[] = ["lifecycle-revoke"];

describe("the Derivation Limits capability switch at intake and approval (#2018; @spec mission#submission-via-par, derivation-limits#introduction)", () => {
  it("on, a requested_derivation_limit is accepted, the approval page renders the limit, and the Mission establishes it", async () => {
    const h = await startAs([...MINIMAL, "derivation-limits"]);
    try {
      const pushed = await par(h, { requested_derivation_limit: 5 });
      expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
      const { page, missionId } = await approve(h, String(pushed.body.request_uri));
      expect(page).toContain("Derivation limit (established): at most 5 token derivations from this Mission.");
      const record = h.as.kernel.get(missionId) as MissionRecord;
      expect(record.derivation_limit).toBe(5);
      expect(record.intent.requested_derivation_limit).toBe(5);
    } finally {
      await h.close();
    }
  });

  it("off, a requested_derivation_limit is refused invalid_request as an unknown member while the identical Intent without it is accepted, and the approval page renders no derivation limit", async () => {
    const h = await startAs(MINIMAL);
    try {
      const refused = await par(h, { requested_derivation_limit: 5 });
      expect(refused.status, JSON.stringify(refused.body)).toBe(400);
      expect(refused.body.error).toBe("invalid_request");
      expect(refused.body.error_description).toBe("unknown top-level member: requested_derivation_limit");
      const accepted = await par(h);
      expect(accepted.status, JSON.stringify(accepted.body)).toBe(201);
      const { page, missionId } = await approve(h, String(accepted.body.request_uri));
      expect(page).toContain("reports:report.read");
      expect(page).not.toMatch(/derivation limit/i);
      expect(h.as.kernel.get(missionId)?.derivation_limit).toBeNull();
    } finally {
      await h.close();
    }
  });
});

describe("with Derivation Limits off no Mission establishes a derivation limit (#2018; @spec derivation-limits#introduction, derivation-limits#effective-limit)", () => {
  it("construction refuses a deployment policy that sets derivation_limit_ceiling", async () => {
    await expect(startAs(MINIMAL, { derivationPolicy: { ...DERIVATION_POLICY, derivation_limit_ceiling: 10 } })).rejects.toThrow(
      "the derivation policy sets derivation_limit_ceiling, but this deployment does not implement Derivation Limits (the derivation-limits capability is off)",
    );
    const on = await startAs([...MINIMAL, "derivation-limits"], { derivationPolicy: { ...DERIVATION_POLICY, derivation_limit_ceiling: 10 } });
    await on.close();
  });

  it("the kernel resolves no limit from a request, never turns a standing consent's finite maximum into no limit, and refuses to commit a record carrying either Derivation Limits member", async () => {
    const off = await startAs(MINIMAL);
    const on = await startAs([...MINIMAL, "derivation-limits"]);
    try {
      expect(on.as.kernel.resolveDerivationLimit(5)).toBe(5);
      expect(on.as.kernel.standingConsentDerivationLimit(undefined, { finite: 3 })).toBe(3);
      expect(off.as.kernel.resolveDerivationLimit(5)).toBeNull();
      // A consent guaranteeing no finite maximum records none; a finite one
      // is refused, never recorded as no limit (#2018 review F1).
      expect(off.as.kernel.standingConsentDerivationLimit(undefined, { finite: null })).toBeNull();
      expect(off.as.kernel.standingConsentMaximumRefusal({ finite: null })).toBeUndefined();
      expect(on.as.kernel.standingConsentMaximumRefusal({ finite: 3 })).toBeUndefined();
      expect(off.as.kernel.standingConsentMaximumRefusal({ finite: 3 })).toMatch(/committed a per-Mission derivation limit of at most 3/);
      expect(() => off.as.kernel.standingConsentDerivationLimit(undefined, { finite: 3 })).toThrow(
        "a standing consent committed a finite derivation_limit maximum of 3, which this deployment cannot record: Derivation Limits is off",
      );
      // Every creator funnels through insertRecord: a record a path built with
      // either member is refused there, and nothing is committed.
      const pushed = await par(off);
      const { missionId } = await approve(off, String(pushed.body.request_uri));
      const base = off.as.kernel.get(missionId) as MissionRecord;
      const fresh = (id: string, change: Partial<MissionRecord>): MissionRecord =>
        ({ ...structuredClone(base), id, ...change }) as MissionRecord;
      const count = off.as.kernel.allMissions().length;
      expect(() => off.as.kernel.insertRecord(fresh("msn_dl_limit", { derivation_limit: 3 }), undefined, { source: { inherited: base.authority_source }, audiences: "fresh" } as never)).toThrow(
        "would establish derivation_limit 3, but this deployment does not implement Derivation Limits",
      );
      expect(() =>
        off.as.kernel.insertRecord(
          fresh("msn_dl_request", { intent: { ...base.intent, requested_derivation_limit: 5 } }),
          undefined,
          { source: { inherited: base.authority_source }, audiences: "fresh" } as never,
        ),
      ).toThrow("would commit requested_derivation_limit, but this deployment does not implement Derivation Limits");
      expect(off.as.kernel.allMissions()).toHaveLength(count);
    } finally {
      await off.close();
      await on.close();
    }
  });

  it("a Mission Template's consent disclosure states no derivation-limit rule, which binds only a deployment adopting Derivation Limits (@spec mission-template#template-consent)", async () => {
    const policies = {
      "test-limit-3": { version: "1", content_type: "application/json", content: JSON.stringify({ id: "test-limit-3", derivation_limit_ceiling: 3 }) },
    };
    const templateBody = (h: SwitchedAs, n: number) => ({
      ...demoReconciliationTemplate(h.issuer),
      approval_event_id: `tmpl-dl-switch-${n}`,
      dispatch_policy: { id: "test-limit-3", version: "1" },
    });
    const create = async (h: SwitchedAs, n: number) => {
      const res = await fetch(`${h.issuer}/templates`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
        body: JSON.stringify(templateBody(h, n)),
      });
      return { status: res.status, body: (await res.json()) as { disclosure?: Record<string, unknown> } };
    };
    const withTemplates = ALL_PROVIDER_CAPABILITIES.filter((c) => c !== "derivation-limits");
    const off = await startAs(withTemplates, { dispatchPolicies: policies });
    const on = await startAs(ALL_PROVIDER_CAPABILITIES, { dispatchPolicies: policies });
    try {
      const offCreated = await create(off, 1);
      expect(offCreated.status, JSON.stringify(offCreated.body)).toBe(201);
      expect(offCreated.body.disclosure).toHaveProperty("max_active");
      expect(offCreated.body.disclosure).not.toHaveProperty("derivation_limit");
      const onCreated = await create(on, 2);
      expect(onCreated.status, JSON.stringify(onCreated.body)).toBe(201);
      expect((onCreated.body.disclosure?.derivation_limit as string[])[0]).toBe(
        "Each dispatched instance created under this consent establishes its own derivation limit from its own request, never above 3.",
      );
    } finally {
      await off.close();
      await on.close();
    }
  });

  it("the approval disclosure for a delegable entry keeps the Child Delegation lines and drops the per-child derivation-limit rule (@spec child-delegation#subtree-rendering)", () => {
    const entry = {
      type: "mission_resource_access",
      resource: "https://payments.test/mcp",
      actions: ["payments:invoice.read"],
      delegation: { max_depth: 1, children: { max_children: 2 } },
    } as AuthorityEntry;
    const render = (derivationLimits: boolean) =>
      approvalDerivationRendering({
        derivationLimits,
        limit: null,
        deploymentCeiling: 4,
        authority: [entry],
        held: (() => undefined) as never,
        asyncDelegation: false,
        progressive: true,
      });
    const on = render(true);
    expect(on.established[0]).toBe("No derivation limit is established for this Mission: the number of tokens derived from it is not bounded.");
    expect(on.children[0]?.lines).toContain(
      "Each child Mission created under this consent establishes its own derivation limit from its own request, never above 4.",
    );
    expect(on.progressive).toBeDefined();
    const off = render(false);
    expect(off.established).toEqual([]);
    expect(off.progressive).toBeUndefined();
    expect(off.children[0]?.lines).toContain("Concurrent children: at most 2 concurrently non-terminal child Missions (a limit on children at one time, not on children created over the Mission's lifetime).");
    expect(off.children[0]?.lines.some((l) => /derivation limit/i.test(l))).toBe(false);
  });
});

/** Every default capability but Derivation Limits: Child Delegation and Templates stay on. */
const WITHOUT_DERIVATION_LIMITS = ALL_PROVIDER_CAPABILITIES.filter((c) => c !== "derivation-limits");

describe("the decision's per-child disclosure guard follows the Derivation Limits switch, with Child Delegation on (#2018 review F2; @spec derivation-limits#approval-rendering, child-delegation#subtree-rendering)", () => {
  /**
   * The plain RS entry made delegable, its children committing a child
   * creation policy this issuer does not hold, so its per-child figure
   * cannot be read; the user-delegated source bound to that ceiling.
   */
  const UNHELD = {
    id: "urn:policy:child-unheld",
    version: "1",
    digest: activationPolicyDigest("https://as.test", { content_type: "application/json", content: "{}" }),
  };
  const policy = {
    ...DERIVATION_POLICY,
    derivation_limit_ceiling: null,
    ceiling: DERIVATION_POLICY.ceiling.map((entry) =>
      entry.resource !== TOPOLOGY.resources.plainRs
        ? entry
        : { ...entry, delegation: { max_depth: 1, children: { max_children: 2, child_creation_policy: UNHELD } } },
    ),
  };
  const authoritySources = {
    ...AUTHORITY_SOURCES,
    entries: AUTHORITY_SOURCES.entries.map((entry) =>
      entry.ceiling === undefined || entry.id !== "acme-people" ? entry : { ...entry, ceiling: policy.ceiling },
    ),
  };
  const deployment = (capabilities: ProviderCapability[]) =>
    startAs(capabilities, { derivationPolicy: policy as never, authoritySources: authoritySources as never });
  const CHILD_LINES = [
    "Child Missions created by policy under this approval (no approval of their own)",
    "Concurrent children: at most 2 concurrently non-terminal child Missions (a limit on children at one time, not on children created over the Mission's lifetime).",
    "Child depth: at most 1 (the default).",
    "No finite aggregate bound on this entry's subtree is enforced: no limit applies to children created over the Mission's lifetime.",
  ];

  it("on, the approval is refused access_denied, creating no Mission, while the per-child figure cannot be shown", async () => {
    const h = await deployment(ALL_PROVIDER_CAPABILITIES as ProviderCapability[]);
    try {
      const pushed = await par(h);
      expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
      const { page, location, created } = await decideApproval(h, String(pushed.body.request_uri));
      for (const line of CHILD_LINES) expect(page).toContain(line);
      expect(page).toContain("The per-child derivation limit cannot be shown: child creation policy urn:policy:child-unheld version 1");
      expect(location.searchParams.get("error")).toBe("access_denied");
      expect(location.searchParams.get("error_description")).toContain("The per-child derivation limit cannot be shown");
      expect(location.searchParams.get("code")).toBeNull();
      expect(created).toEqual([]);
    } finally {
      await h.close();
    }
  });

  it("off, the same approval renders the Child Delegation lines and no derivation limit and is approved; the unheld policy still refuses a child at creation, policy_denied", async () => {
    const h = await deployment(WITHOUT_DERIVATION_LIMITS);
    try {
      const pushed = await par(h);
      expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
      const { page, location, created } = await decideApproval(h, String(pushed.body.request_uri));
      for (const line of CHILD_LINES) expect(page).toContain(line);
      expect(page).not.toMatch(/derivation limit/i);
      expect(location.searchParams.get("code")).toBeTruthy();
      expect(created).toHaveLength(1);
      const parent = h.as.kernel.get(created[0] as string) as MissionRecord;
      expect((parent.authority_set[0] as { delegation?: { children?: unknown } }).delegation?.children).toMatchObject({
        child_creation_policy: UNHELD,
      });
      // The policy-integrity check, which is Child Delegation's own, still runs.
      try {
        createChildMission(h.as.kernel, {
          parentId: parent.id,
          intent: h.as.kernel.validateIntent(
            JSON.stringify({ goal: "sub", target_resources: [TOPOLOGY.resources.plainRs], expires_at: parent.expires_at }),
          ),
          proposedAuthority: READ as AuthorityEntry[],
          childActor: { sub: "subagent-invoice-extractor", sub_profile: "ai_agent" },
        });
        expect.unreachable();
      } catch (e) {
        expect(e).toBeInstanceOf(ChildDelegationError);
        expect((e as ChildDelegationError).reason).toBe("policy_denied");
        expect((e as Error).message).toBe("child creation policy urn:policy:child-unheld does not match its committed digest");
      }
      expect(h.as.kernel.allMissions()).toHaveLength(1);
    } finally {
      await h.close();
    }
  });
});

describe("the Mission Template consent page follows the Derivation Limits switch, with Templates on (#2018 review F2; @spec mission-template#template-consent, derivation-limits#approval-rendering)", () => {
  const SESSIONS = new ApprovalSessionStore();
  /** Held by reference, so a test can edit it in place under an unchanged version. */
  const editable = () => ({
    version: "1",
    content_type: "application/json",
    content: JSON.stringify({ id: "test-limit-3", derivation_limit_ceiling: 3 }),
  });
  const deployment = (capabilities: readonly ProviderCapability[], held: ReturnType<typeof editable>) =>
    startAs(capabilities, { approvalSessions: SESSIONS, dispatchPolicies: { "test-limit-3": held } });
  /** The demo reconciliation template as a proposal under `test-limit-3`. */
  const proposalBody = (issuer: string) => {
    const { approver: _approver, approval_event_id: _event, issuer: _issuer, ...body } = demoReconciliationTemplate(issuer);
    return { ...body, dispatch_policy: { id: "test-limit-3", version: "1" } };
  };
  const propose = async (h: SwitchedAs): Promise<string> => {
    const res = await fetch(`${h.issuer}/templates/proposals`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
      body: JSON.stringify(proposalBody(h.issuer)),
    });
    const body = (await res.json()) as { proposal_id: string };
    expect(res.status, JSON.stringify(body)).toBe(201);
    return body.proposal_id;
  };
  const loggedIn = (id: string) => browserApprovalHeaders(SESSIONS, id, { sub: "bob" }, "");
  const page = async (h: SwitchedAs, id: string) =>
    (await fetch(`${h.issuer}/templates/proposals/${id}`, { headers: { cookie: loggedIn(id).cookie as string } })).text();
  const items = (html: string, cls: string): string[] => {
    const list = new RegExp(`<ul class="${cls}">(.*?)</ul>`).exec(html);
    return list ? [...(list[1] as string).matchAll(/<li>(.*?)<\/li>/g)].map((m) => m[1] as string) : [];
  };
  const decide = (h: SwitchedAs, id: string) =>
    fetch(`${h.issuer}/templates/proposals/${id}/decide`, {
      method: "POST",
      headers: { "content-type": "application/json", ...loggedIn(id) },
      body: JSON.stringify({ decision: "approve" }),
    });
  const BOUNDS = ["At most 5 dispatched instances are active at once.", "At most 30 dispatches per minute."];

  it("on, the page renders each dispatched instance's derivation-limit rule beside max_active and the dispatch rate", async () => {
    const h = await deployment(ALL_PROVIDER_CAPABILITIES, editable());
    try {
      const html = await page(h, await propose(h));
      expect(items(html, "dispatch-bounds")).toEqual([
        ...BOUNDS,
        "Each dispatched instance created under this consent establishes its own derivation limit from its own request, never above 3.",
        "This maximum is local to each dispatched instance: it is not a budget across the Missions this consent admits, their descendants, or their lifetimes.",
        "The refreshes of an async delegation family are not counted against this limit.",
        "Each dispatched instance establishes and counts its own limit, so this consent admits up to 5 such limits at once, and more over time.",
      ]);
    } finally {
      await h.close();
    }
  });

  it("off, the page renders max_active, the dispatch rate, the statements and the ceiling and no derivation limit, the consent is approved, and a changed Dispatch Policy is still refused", async () => {
    const held = editable();
    const h = await deployment(WITHOUT_DERIVATION_LIMITS, held);
    try {
      const id = await propose(h);
      const html = await page(h, id);
      expect(items(html, "dispatch-bounds")).toEqual(BOUNDS);
      expect(items(html, "template-statements")).toHaveLength(3);
      expect(html).toContain('<pre class="template-ceiling">');
      expect(html).toContain(`<form method="post" action="/templates/proposals/${id}/decide">`);
      expect(html).not.toMatch(/derivation limit/i);
      const approved = await decide(h, id);
      expect(approved.status).toBe(201);
      expect(h.as.templateStore.getByApprovalEvent(`apev_${id}`)).toBeDefined();
      // A Dispatch Policy edited under its version after the proposal: the
      // consent is refused for the change, naming no derivation limit.
      const changed = await propose(h);
      const original = held.content;
      held.content = JSON.stringify({ id: "test-limit-3", derivation_limit_ceiling: 50 });
      try {
        const refusedPage = await page(h, changed);
        expect(refusedPage).toContain(
          '<p class="consent-refused">The Dispatch Policy test-limit-3 version 1 is not the one this template was proposed under. This consent is refused; propose the template again.</p>',
        );
        expect(refusedPage).not.toContain("<form");
        const refused = await decide(h, changed);
        expect(refused.status).toBe(403);
        expect(h.as.templateStore.getByApprovalEvent(`apev_${changed}`)).toBeUndefined();
      } finally {
        held.content = original;
      }
    } finally {
      await h.close();
    }
  });
});
