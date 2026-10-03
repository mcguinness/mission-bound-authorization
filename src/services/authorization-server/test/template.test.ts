import { activationPolicyDigest, authorityHash, intentHash } from "@mission/core";
import { DEMO_DISPATCH_POLICIES, demoReconciliationTemplate, DERIVATION_POLICY } from "@mission/demo-data";
import { type CryptoKey, generateKeyPair } from "jose";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  createExpansion,
  createTemplate,
  type CreateTemplateInput,
  DispatchError,
  type DispatchInput,
  type DispatchPolicies,
  dispatchFromTemplate,
  IntentError,
  MissionKernel,
  type MissionRecord,
  selectDispatchAgent,
  TemplateError,
  TemplateStore,
} from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISS = "https://as.test";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const POLICY_VERSION = DERIVATION_POLICY.policy_version;
const T0 = Date.parse("2026-07-01T00:00:00Z");
/** The shared clock: fixed at T0 unless a test moves it; reset before each test. */
let clockMs = T0;
const now = () => new Date(clockMs);

let key: CryptoKey;
let kernel: MissionKernel;
let store: TemplateStore;
let tmplSeq = 0;
let dspSeq = 0;

beforeAll(async () => {
  key = (await generateKeyPair("ES256")).privateKey;
});

beforeEach(() => {
  clockMs = T0;
  // Two Approvers, both real here: the templates this suite builds are
  // consented by "human-approver", and the shipped demo descriptor it also
  // exercises names "bob".
  kernel = new MissionKernel({ issuer: ISS, policy: DERIVATION_POLICY as never, authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["worker", "intruder", "subagent-invoice-extractor", "orchestrator"], ["human-approver", "bob"]), statusKey: key, statusKid: "as-status", now });
  store = new TemplateStore(now);
});

/**
 * @spec mission#standing-consent-bases — the Dispatch Policy snapshots this
 * suite's issuer holds, by id. A template commits the named snapshot's digest;
 * a Dispatch evaluates the registry it is handed, and a multi-Agent template's
 * selection rule is the snapshot's own `select_agent` member.
 */
const snapshotOf = (id: string, content = JSON.stringify({ id, rule: "dispatch within the template ceiling" })) => ({
  version: "1",
  content_type: "application/json",
  content,
});
/** A held snapshot whose selection rule names `agent`. */
const selecting = (id: string, agent: string) => snapshotOf(id, JSON.stringify({ id, select_agent: agent }));
const REGISTRY: DispatchPolicies = {
  "test-policy": snapshotOf("test-policy"),
  "names-unlisted": selecting("names-unlisted", "intruder"),
  "route-extractor": selecting("route-extractor", "subagent-invoice-extractor"),
  route: selecting("route", "subagent-invoice-extractor"),
};
const policyRef = (id: string) => ({ id, version: "1" });

/** A template ceiling entry on the payments resource (constraints restated so
 *  the double intersection is constraint-attributable). */
const ceilEntry = (actions: string[], maxAmount = "200.00"): AuthorityEntry => ({
  type: "mission_resource_access",
  resource: RESOURCE,
  actions,
  constraints: { max_amount: { amount: maxAmount, currency: "USD" }, vendors: ["acme"] },
});

const mkTemplate = (over: Partial<CreateTemplateInput> = {}) =>
  createTemplate(store, {
    template_version: "tmpl-v1",
    issuer: ISS,
    approver: { iss: ISS, sub: "human-approver" },
    ceiling: [ceilEntry(["payments:invoice.read", "payments:vendor.read", "payments:payment.schedule"])],
    dispatch_policy: policyRef("test-policy"),
    dispatchers: ["orchestrator"],
    recipients: { subjects: [{ iss: ISS, sub: "alice" }], agents: ["worker"] },
    per_instance_lifetime_s: 3600,
    max_active: 3,
    rate_per_min: 5,
    review_cadence_s: 86400,
    approval_event_id: `tmpl-ev-${tmplSeq++}`,
    expires_at: "2026-12-01T00:00:00Z",
    ...over,
  }, { ...kernel.authoritySourceOptions(), dispatchPolicies: REGISTRY });

/** An untrusted Intent proposing the given actions (default max_amount 500,
 *  which is exactly the policy ceiling, so any narrower final is attributable). */
const intentOf = (actions: string[], opts: { maxAmount?: string; expiresAt?: string } = {}) =>
  // kernel.validateIntent judges the requested ceiling against the INJECTED
  // clock (@spec mission#mission-intent), the same instant dispatch commits at.
  kernel.validateIntent(
    JSON.stringify({
      goal: "reconcile Acme",
      target_resources: [RESOURCE],
      expires_at: opts.expiresAt ?? "2027-01-01T00:00:00Z",
    }),
  );

/** @spec mission#authority-proposal — a dispatcher proposal on the standard
 *  carriage: the entries previously carried inside the Intent. */
const proposalOf = (actions: string[], maxAmount = "500.00"): AuthorityEntry[] => [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions,
    constraints: { max_amount: { amount: maxAmount, currency: "USD" } },
  },
];

const dispatch = (templateId: string, over: Partial<DispatchInput> = {}) =>
  dispatchFromTemplate(kernel, store, {
    templateId,
    dispatchEventId: `dsp-${dspSeq++}`,
    dispatcher: "orchestrator",
    intent: intentOf(["payments:invoice.read"]),
    subject: { iss: ISS, sub: "alice" },
    policyVersion: POLICY_VERSION,
    dispatchPolicies: REGISTRY,
    ...over,
  });

const amountOf = (m: { authority_set: AuthorityEntry[] }) =>
  m.authority_set[0]?.constraints?.max_amount?.amount;

describe("createTemplate (@spec mission-template)", () => {
  it("commits review_cadence_s in template_hash", () => {
    const a = mkTemplate({ review_cadence_s: 3600 });
    const b = mkTemplate({ review_cadence_s: 7200 });
    expect(a.template_hash).not.toBe(b.template_hash);
    expect(store.get(b.id)?.review_cadence_s).toBe(7200);
  });

  it("computes a stable template_hash and is idempotent by approval_event_id", () => {
    const t = mkTemplate({ approval_event_id: "consent-1" });
    expect(t.id).toMatch(/^tmpl_/);
    expect(t.template_hash).toMatch(/^sha-256:/);
    expect(t.state).toBe("active");
    // Re-consent with the same approval event returns the SAME template.
    const again = createTemplate(store, {
      template_version: "tmpl-v1",
      issuer: ISS,
      approver: { iss: ISS, sub: "human-approver" },
      ceiling: [ceilEntry(["payments:invoice.read"])],
      dispatch_policy: policyRef("test-policy"),
      dispatchers: ["orchestrator"],
      recipients: { subjects: [{ iss: ISS, sub: "alice" }], agents: ["worker"] },
      per_instance_lifetime_s: 3600,
      max_active: 3,
      rate_per_min: 5,
      review_cadence_s: 86400,
      approval_event_id: "consent-1",
      expires_at: "2026-12-01T00:00:00Z",
    }, kernel.authoritySourceOptions());
    expect(again.id).toBe(t.id);
    expect(again.template_hash).toBe(t.template_hash);
  });

  // @spec mission#standing-consent-bases — the consented template commits the
  // Dispatch Policy as an activation policy reference whose digest the issuer
  // computes from the snapshot it holds.
  it("commits the Dispatch Policy's content digest in template_hash and refuses a policy the issuer does not hold", () => {
    const t = mkTemplate();
    expect(t.dispatch_policy).toEqual({
      id: "test-policy",
      version: "1",
      digest: activationPolicyDigest(ISS, snapshotOf("test-policy")),
    });
    // Same id and version, different content: a different template_hash.
    const edited = createTemplate(
      store,
      {
        template_version: "tmpl-v1",
        issuer: ISS,
        approver: { iss: ISS, sub: "human-approver" },
        ceiling: [ceilEntry(["payments:invoice.read", "payments:vendor.read", "payments:payment.schedule"])],
        dispatch_policy: policyRef("test-policy"),
        dispatchers: ["orchestrator"],
        recipients: { subjects: [{ iss: ISS, sub: "alice" }], agents: ["worker"] },
        per_instance_lifetime_s: 3600,
        max_active: 3,
        rate_per_min: 5,
        review_cadence_s: 86400,
        approval_event_id: `tmpl-ev-${tmplSeq++}`,
        expires_at: "2026-12-01T00:00:00Z",
      },
      {
        ...kernel.authoritySourceOptions(),
        dispatchPolicies: { "test-policy": snapshotOf("test-policy", '{"rule":"edited"}') },
      },
    );
    expect(edited.dispatch_policy.digest).not.toBe(t.dispatch_policy.digest);
    expect(edited.template_hash).not.toBe(t.template_hash);
    // A request-body digest is never a fact: the issuer computes it.
    const claimed = mkTemplate({
      dispatch_policy: { ...policyRef("test-policy"), digest: "sha-256:forged" } as never,
    });
    expect(claimed.dispatch_policy.digest).toBe(t.dispatch_policy.digest);
    // An unheld policy, a version the issuer does not hold, or a malformed name refuses.
    expect(() => mkTemplate({ dispatch_policy: policyRef("unheld") })).toThrow(TemplateError);
    expect(() => mkTemplate({ dispatch_policy: { id: "test-policy", version: "2" } })).toThrow(TemplateError);
    expect(() => mkTemplate({ dispatch_policy: "test-policy" as never })).toThrow(TemplateError);
  });

  it("refuses an empty ceiling or non-positive bounds (TemplateError)", () => {
    expect(() => mkTemplate({ ceiling: [] })).toThrow(TemplateError);
    expect(() => mkTemplate({ per_instance_lifetime_s: 0 })).toThrow(TemplateError);
    expect(() => mkTemplate({ max_active: 0 })).toThrow(TemplateError);
    expect(() => mkTemplate({ rate_per_min: -1 })).toThrow(TemplateError);
    // @spec mission-template#the-mission-template — review_cadence is a
    // REQUIRED positive integer number of seconds.
    expect(() => mkTemplate({ review_cadence_s: 0 })).toThrow(TemplateError);
    expect(() => mkTemplate({ review_cadence_s: 1.5 })).toThrow(TemplateError);
    expect(() => mkTemplate({ review_cadence_s: undefined as never })).toThrow(TemplateError);
  });

  it("refuses dispatchers that are not a non-empty array of client_id strings (@spec mission-template#the-mission-template)", () => {
    expect(() => mkTemplate({ dispatchers: [] })).toThrow(/dispatchers must be a non-empty array of client_id strings/);
    expect(() => mkTemplate({ dispatchers: [""] })).toThrow(TemplateError);
  });

  it("refuses recipients that are not an object of non-empty subjects ({iss, sub}) and agents (@spec mission-template#the-mission-template)", () => {
    expect(() => mkTemplate({ recipients: ["worker"] as never })).toThrow(/recipients must be an object/);
    expect(() => mkTemplate({ recipients: { subjects: [], agents: ["worker"] } })).toThrow(/recipients\.subjects/);
    expect(() => mkTemplate({ recipients: { subjects: [{ iss: ISS } as never], agents: ["worker"] } })).toThrow(/recipients\.subjects/);
    expect(() => mkTemplate({ recipients: { subjects: [{ iss: ISS, sub: "alice" }], agents: [] } })).toThrow(/recipients\.agents/);
  });
});

describe("dispatchFromTemplate double intersection (@spec mission-template#dispatch)", () => {
  it("clips by the TEMPLATE ceiling: an intent within policy but broader than the template narrows to the template", () => {
    // Template caps at 200; policy allows 500. The intent proposes 500 and both
    // actions, so any narrowing to 200 / dropped action is the TEMPLATE's doing.
    const t = mkTemplate({ ceiling: [ceilEntry(["payments:invoice.read"], "200.00")] });
    const intent = intentOf(["payments:invoice.read", "payments:payment.schedule"], { maxAmount: "500.00" });
    // Under policy alone the derivation would keep 500 and both actions.
    // @spec mission#authorization-derivation (#743) — template mode against
    // the real DERIVATION_POLICY now derives TWO fragments (the payments
    // ceiling is a money-bearing entry and a read-only entry), so the
    // payment.schedule fragment is selected by action, not `derived[0]`.
    const derived = kernel.derive(intent);
    const scheduleFragment = derived.find((e) => e.actions.includes("payments:payment.schedule"));
    expect(scheduleFragment?.constraints?.max_amount?.amount).toBe("500.00");
    // The dispatched instance is clipped to the template: 200, invoice.read only.
    const { mission } = dispatch(t.id, { intent });
    expect(amountOf(mission)).toBe("200.00");
    expect(mission.authority_set[0]?.actions).toEqual(["payments:invoice.read"]);
  });

  it("clips by the POLICY ceiling: an intent above policy narrows to policy even under a wide template", () => {
    // Template equals the policy cap (500), so the only effective clip is policy.
    const t = mkTemplate({ ceiling: [ceilEntry(["payments:invoice.read"], "500.00")] });
    const { mission } = dispatch(t.id, { intent: intentOf(["payments:invoice.read"], { maxAmount: "999.00" }) });
    expect(amountOf(mission)).toBe("500.00");
  });

  it("empty template intersection -> out_of_template_ceiling", () => {
    // Template permits only invoice.read; the intent asks only for payment.schedule
    // (valid under policy, so the FIRST derivation succeeds), leaving an empty
    // second intersection.
    const t = mkTemplate({ ceiling: [ceilEntry(["payments:invoice.read"], "200.00")] });
    try {
      dispatch(t.id, {
        intent: intentOf(["payments:payment.schedule"]),
        proposedAuthority: proposalOf(["payments:payment.schedule"]),
      });
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(DispatchError);
      expect((e as DispatchError).reason).toBe("out_of_template_ceiling");
    }
  });

  it("an intent empty under the POLICY surfaces as IntentError, NOT out_of_template_ceiling", () => {
    const t = mkTemplate();
    // A bogus action is in neither policy nor template: the first derivation
    // (kernel.derive) throws IntentError, which must propagate unmapped.
    expect(() =>
      dispatch(t.id, {
        intent: intentOf(["payments:bogus.action"]),
        proposedAuthority: proposalOf(["payments:bogus.action"]),
      }),
    ).toThrow(IntentError);
  });

  it("asserts final is a subset of both ceilings and recomputes authority_hash over final (differs from template_hash)", () => {
    const t = mkTemplate({ ceiling: [ceilEntry(["payments:invoice.read", "payments:payment.schedule"], "200.00")] });
    const { mission } = dispatch(t.id, { intent: intentOf(["payments:invoice.read", "payments:payment.schedule"]) });
    // authority_hash is over the INSTANCE's own final set, not the template body.
    expect(mission.authority_hash).toBe(authorityHash(ISS, mission.authority_set as never));
    expect(mission.authority_hash).not.toBe(t.template_hash);
    // Lineage carries the template commitment.
    expect(mission.template?.id).toBe(t.id);
    expect(mission.template?.template_hash).toBe(t.template_hash);
    expect(mission.template?.template_version).toBe("tmpl-v1");
    expect(mission.template?.dispatch_policy).toEqual({
      id: "test-policy",
      version: "1",
      digest: activationPolicyDigest(ISS, snapshotOf("test-policy")),
    });
  });
});

describe("dispatch gates (@spec mission-template#dispatch-refusals)", () => {
  it("records the TEMPLATE approver as the human of record (not the dispatcher)", () => {
    const t = mkTemplate();
    const { mission } = dispatch(t.id);
    expect(mission.approver).toEqual({ iss: ISS, sub: "human-approver" });
    expect(mission.approver.sub).not.toBe("orchestrator");
    expect(mission.client_id).toBe("worker"); // recipient becomes client_id
    expect(mission.subject).toEqual({ iss: ISS, sub: "alice" });
    expect(mission.policy_version).toBe(POLICY_VERSION);
  });

  it("is idempotent on a repeated dispatchEventId (same mission, no second dispatch row)", () => {
    const t = mkTemplate();
    const r1 = dispatch(t.id, { dispatchEventId: "evt-fixed" });
    const r2 = dispatch(t.id, { dispatchEventId: "evt-fixed" });
    expect(r2.mission.id).toBe(r1.mission.id);
    // Only ONE dispatch_events row was recorded for the template.
    expect(store.dispatchesSince(t.id, "1970-01-01T00:00:00Z")).toBe(1);
  });

  it("clamps expires_at to the earliest of intent / now+lifetime / template (verbatim)", () => {
    const t = mkTemplate({ per_instance_lifetime_s: 3600, expires_at: "2026-12-01T00:00:00Z" });
    // (i) intent is the earliest -> verbatim intent string.
    expect(dispatch(t.id, { intent: intentOf(["payments:invoice.read"], { expiresAt: "2026-07-01T00:30:00Z" }) }).mission.expires_at).toBe(
      "2026-07-01T00:30:00Z",
    );
    // (ii) now + per_instance_lifetime_s is the earliest -> synthesized string.
    expect(dispatch(t.id, { intent: intentOf(["payments:invoice.read"], { expiresAt: "2027-01-01T00:00:00Z" }) }).mission.expires_at).toBe(
      "2026-07-01T01:00:00.000Z",
    );
    // (iii) the template expiry is the earliest -> verbatim template string.
    const tShort = mkTemplate({ per_instance_lifetime_s: 999999, expires_at: "2026-07-01T00:10:00Z" });
    expect(dispatch(tShort.id, { intent: intentOf(["payments:invoice.read"], { expiresAt: "2027-01-01T00:00:00Z" }) }).mission.expires_at).toBe(
      "2026-07-01T00:10:00Z",
    );
  });

  /** A refused Dispatch commits nothing: no Mission and no dispatch event. */
  const expectNothingCommitted = (templateId: string, missionsBefore: number) => {
    expect(kernel.allMissions().length).toBe(missionsBefore);
    expect(store.dispatchesSince(templateId, "1970-01-01T00:00:00.000Z")).toBe(0);
  };

  it("refuses a dispatcher or recipient not on the template's lists", () => {
    const t = mkTemplate();
    const before = kernel.allMissions().length;
    try {
      dispatch(t.id, { dispatcher: "intruder" });
      expect.unreachable();
    } catch (e) {
      expect((e as DispatchError).reason).toBe("dispatcher_not_allowed");
    }
    expectNothingCommitted(t.id, before);
    // The Agent is never request-selected, so an unlisted one is reachable only
    // through a Dispatch Policy that names it; the membership check refuses it.
    const multi = mkTemplate({ recipients: { subjects: [{ iss: ISS, sub: "alice" }], agents: ["worker", "subagent-invoice-extractor"] }, dispatch_policy: policyRef("names-unlisted") });
    try {
      dispatch(multi.id);
      expect.unreachable();
    } catch (e) {
      expect((e as DispatchError).reason).toBe("recipient_not_allowed");
    }
    expectNothingCommitted(multi.id, before);
  });

  // @spec mission-template#the-mission-template — the Mission Issuer selects
  // the instance's Agent from `agents` under the Dispatch Policy, never from
  // Dispatcher input: one listed Agent directly; several through the policy's
  // selection rule, never by array position.
  // @spec mission-template#dispatch (step 3), mission#standing-consent-bases —
  // a Dispatch Policy whose snapshot no longer matches the committed digest
  // never adjudicates a Dispatch, even under an unchanged version.
  it("refuses dispatch_policy_changed when the held policy's content, version, or presence changes, committing nothing", () => {
    const t = mkTemplate();
    const before = kernel.allMissions().length;
    const changes: DispatchPolicies[] = [
      { "test-policy": snapshotOf("test-policy", '{"rule":"edited under the same version"}') },
      { "test-policy": { ...snapshotOf("test-policy"), version: "2" } },
      {},
    ];
    for (const dispatchPolicies of changes) {
      try {
        dispatch(t.id, { dispatchPolicies });
        expect.unreachable();
      } catch (e) {
        expect((e as DispatchError).reason).toBe("dispatch_policy_changed");
      }
      expect(kernel.allMissions().length).toBe(before);
      expect(store.dispatchesSince(t.id, "1970-01-01T00:00:00.000Z")).toBe(0);
    }
    // The held snapshot it committed still dispatches.
    expect(dispatch(t.id).mission.template?.dispatch_policy).toEqual(t.dispatch_policy);
  });

  it("selects the one listed Agent directly and ignores an Agent named in the dispatch input", () => {
    const t = mkTemplate();
    expect(dispatch(t.id).mission.client_id).toBe("worker");
    expect(dispatch(t.id, { recipient: "intruder" } as Partial<DispatchInput>).mission.client_id).toBe("worker");
  });

  it("with several listed Agents, selects the Agent the committed Dispatch Policy snapshot names, and refuses agent_not_selected when it names none", () => {
    const agents = ["worker", "subagent-invoice-extractor"];
    const t = mkTemplate({ recipients: { subjects: [{ iss: ISS, sub: "alice" }], agents }, dispatch_policy: policyRef("route-extractor") });
    const { mission } = dispatch(t.id);
    // Not the first listed Agent: the snapshot's rule, not array order, selected it.
    expect(mission.client_id).toBe("subagent-invoice-extractor");

    // A held, matching policy whose snapshot names no Agent selects none.
    const none = mkTemplate({ recipients: { subjects: [{ iss: ISS, sub: "alice" }], agents }, dispatch_policy: policyRef("test-policy") });
    const before = kernel.allMissions().length;
    try {
      dispatch(none.id);
      expect.unreachable();
    } catch (e) {
      expect((e as DispatchError).reason).toBe("agent_not_selected");
    }
    expect(kernel.allMissions().length).toBe(before);
    expect(store.dispatchesSince(none.id, "1970-01-01T00:00:00.000Z")).toBe(0);
  });

  // @spec mission#standing-consent-bases — the selection rule Dispatch
  // evaluates is the committed snapshot itself: re-pointing it, even under an
  // unchanged version, is a changed policy, never a new selection.
  it("a selection rule changed after consent is dispatch_policy_changed, never a new selection", () => {
    const agents = ["worker", "subagent-invoice-extractor"];
    const t = mkTemplate({ recipients: { subjects: [{ iss: ISS, sub: "alice" }], agents }, dispatch_policy: policyRef("test-policy") });
    const before = kernel.allMissions().length;
    // Consented under a snapshot that selects no Agent.
    try {
      dispatch(t.id);
      expect.unreachable();
    } catch (e) {
      expect((e as DispatchError).reason).toBe("agent_not_selected");
    }
    // The held policy now names an allowed Agent, under the same id and version.
    const repointed: DispatchPolicies = { "test-policy": selecting("test-policy", "worker") };
    expect(selectDispatchAgent(store.get(t.id) as never, repointed)).toBeUndefined();
    try {
      dispatch(t.id, { dispatchPolicies: repointed });
      expect.unreachable();
    } catch (e) {
      expect((e as DispatchError).reason).toBe("dispatch_policy_changed");
    }
    expect(kernel.allMissions().length).toBe(before);
    expect(store.dispatchesSince(t.id, "1970-01-01T00:00:00.000Z")).toBe(0);
  });

  // @spec mission-template#dispatch — the selected Agent is part of the
  // committed instance: a retried Dispatch returns it and never selects again.
  it("a retried Dispatch returns the committed Agent without selecting again", () => {
    const t = mkTemplate({ recipients: { subjects: [{ iss: ISS, sub: "alice" }], agents: ["worker", "subagent-invoice-extractor"] }, dispatch_policy: policyRef("route") });
    const first = dispatch(t.id, { dispatchEventId: "evt-agent-retry" });
    expect(first.mission.client_id).toBe("subagent-invoice-extractor");
    // A retry under a policy that would now select differently, or under none
    // at all, returns the committed instance: it never selects (or verifies) again.
    const changed = dispatch(t.id, { dispatchEventId: "evt-agent-retry", dispatchPolicies: { route: selecting("route", "worker") } });
    expect(changed.mission.id).toBe(first.mission.id);
    expect(changed.mission.client_id).toBe("subagent-invoice-extractor");
    const unresolvable = dispatch(t.id, { dispatchEventId: "evt-agent-retry", dispatchPolicies: {} });
    expect(unresolvable.mission.id).toBe(first.mission.id);
    expect(unresolvable.mission.client_id).toBe("subagent-invoice-extractor");
  });

  it("refuses a Subject that matches a listed subject in only one of iss and sub (@spec mission-template#the-mission-template)", () => {
    const t = mkTemplate();
    const before = kernel.allMissions().length;
    // A local principal that is not a listed recipient is refused by the
    // recipient gate. A principal from another issuer namespace never reaches
    // it: the deployment's namespace check (#829) refuses it first, before the
    // dispatch idempotency check, as access_denied.
    try {
      dispatch(t.id, { subject: { iss: ISS, sub: "mallory" } });
      expect.unreachable();
    } catch (e) {
      expect((e as DispatchError).reason).toBe("recipient_not_allowed");
    }
    expectNothingCommitted(t.id, before);
    try {
      dispatch(t.id, { subject: { iss: "https://other.example", sub: "alice" } });
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(IntentError);
      expect((e as IntentError).code).toBe("access_denied");
    }
    expectNothingCommitted(t.id, before);
  });

  // @spec mission-template#template-consent — standing consent decays: the
  // Issuer dispatches nothing from a template whose most recent human approval
  // is OLDER than its review_cadence, measured from that approval (the
  // template's created_at). "Older than" is strict: at exactly the bound,
  // dispatch proceeds. A fresh approval re-consents as a new template.
  it("refuses dispatch once the template's approval is older than review_cadence, allows it exactly at the bound, and commits nothing on refusal", () => {
    const t = mkTemplate({ review_cadence_s: 3600 });
    expect(t.created_at).toBe(new Date(T0).toISOString());
    clockMs = T0 + 3600 * 1000;
    const atBound = dispatch(t.id);
    expect(atBound.mission.approval_basis?.approved_at).toBe(t.created_at);
    const before = kernel.allMissions().length;
    clockMs = T0 + 3601 * 1000;
    try {
      dispatch(t.id);
      expect.unreachable();
    } catch (e) {
      expect((e as DispatchError).reason).toBe("review_overdue");
    }
    expect(kernel.allMissions().length).toBe(before);
    expect(store.dispatchesSince(t.id, "1970-01-01T00:00:00.000Z")).toBe(1);
    const renewed = mkTemplate({ review_cadence_s: 3600 });
    expect(dispatch(renewed.id).mission.approval_basis?.approved_at).toBe(renewed.created_at);
  });

  it("refuses beyond max_active, and a slot frees when an instance terminates", () => {
    const t = mkTemplate({ max_active: 2, rate_per_min: 100 });
    const a = dispatch(t.id);
    dispatch(t.id);
    try {
      dispatch(t.id);
      expect.unreachable();
    } catch (e) {
      expect((e as DispatchError).reason).toBe("max_active_exceeded");
    }
    // Terminate one instance: its slot frees (the store counts its rows, the
    // dispatcher filters terminal via kernel.get) so a fresh dispatch succeeds.
    kernel.transition(a.mission.id, "revoke");
    expect(dispatch(t.id).mission.state).toBe("active");
  });

  it("refuses beyond rate_per_min in the trailing window", () => {
    const t = mkTemplate({ rate_per_min: 2, max_active: 100 });
    dispatch(t.id);
    dispatch(t.id);
    try {
      dispatch(t.id);
      expect.unreachable();
    } catch (e) {
      expect((e as DispatchError).reason).toBe("rate_exceeded");
    }
  });

  it("refuses a final authority containing a dispatch-prohibited action", () => {
    const t = mkTemplate({ ceiling: [ceilEntry(["payments:invoice.read", "payments:payment.execute"], "300.00")] });
    // Absent the prohibition, execute dispatches fine (it is within both ceilings).
    expect(dispatch(t.id, { intent: intentOf(["payments:payment.execute"]) }).mission.state).toBe("active");
    // With the prohibition (from config), the same dispatch is refused.
    try {
      dispatch(t.id, {
        intent: intentOf(["payments:payment.execute"]),
        dispatchProhibitedActions: ["payments:payment.execute"],
      });
      expect.unreachable();
    } catch (e) {
      expect((e as DispatchError).reason).toBe("dispatch_prohibited_class");
    }
  });

  it("refuses dispatch from a revoked or expired template (template_not_active)", () => {
    const revoked = mkTemplate();
    store.revoke(revoked.id);
    try {
      dispatch(revoked.id);
      expect.unreachable();
    } catch (e) {
      expect((e as DispatchError).reason).toBe("template_not_active");
    }
    const expired = mkTemplate({ expires_at: "2026-06-01T00:00:00Z" }); // before `now`
    try {
      dispatch(expired.id);
      expect.unreachable();
    } catch (e) {
      expect((e as DispatchError).reason).toBe("template_not_active");
    }
  });

  it("throws a plain Error for an unknown template", () => {
    expect(() => dispatch("tmpl_does_not_exist")).toThrow(/unknown template/);
  });
});

describe("instance ordinariness (@spec mission-template#dispatch)", () => {
  it("the dispatched instance behaves as an ordinary Mission: gate, contain, expand", () => {
    const t = mkTemplate({ ceiling: [ceilEntry(["payments:invoice.read", "payments:payment.schedule"], "200.00")] });
    const { mission } = dispatch(t.id, {
      intent: intentOf(["payments:invoice.read", "payments:payment.schedule"]),
    });

    // Gated derivation succeeds for the active instance.
    expect(() => kernel.gateDerivation(mission.id)).not.toThrow();

    // Containment narrows the instance like any Mission.
    const contained = kernel.contain(mission.id, {
      event: { type: "anomaly", source: "pdp", observed_at: now().toISOString(), event_id: "cev-1" },
      remove: [{ resource: RESOURCE, actions: ["payments:payment.schedule"] }],
    });
    expect(contained.record.version).toBe(2);
    expect(kernel.effectiveAuthoritySet(contained.record)[0]?.actions).toEqual(["payments:invoice.read"]);

    // Expansion creates a successor from the instance.
    const exp = createExpansion(kernel, {
      predecessorId: mission.id,
      intent: intentOf(["payments:invoice.read"]),
      approver: { iss: ISS, sub: "human-approver" },
      approvalEventId: "exp-1",
      approvedUntil: "2027-01-01T00:00:00Z",
    });
    expect(exp.successor.state).toBe("active");
    expect(exp.predecessor).toBe(mission.id);
  });

  it("persists the template lineage: kernel.get round-trips MissionRecord.template", () => {
    const t = mkTemplate();
    const { mission } = dispatch(t.id);
    // Reads through rowToRecord (the schema's template_json column), not the
    // in-memory record dispatch returned.
    const persisted = kernel.get(mission.id);
    expect(persisted?.template).toEqual(mission.template);
    expect(persisted?.template?.id).toBe(t.id);
  });
});

describe("approval basis (@spec mission#approval-basis, mission-template#template-lineage)", () => {
  it("records a template basis, round-tripped through the store, with the Dispatcher distinct from the consenting human", () => {
    const t = mkTemplate();
    const { mission } = dispatch(t.id, { dispatchEventId: "dsp-basis-1" });
    const persisted = kernel.get(mission.id);
    expect(persisted?.approval_basis).toEqual({
      type: "template",
      consent_principal: { iss: ISS, sub: "human-approver" },
      activation: {
        template_id: t.id,
        template_version: t.template_version,
        template_hash: t.template_hash,
        dispatch_event_id: "dsp-basis-1",
      },
      activation_actor: { iss: ISS, sub: "orchestrator" },
      root_commitment: t.template_hash,
      // @spec mission#mission-record (#580) — the RETAINED template record's
      // consent instant for this exact version, never the dispatch request's.
      approved_at: t.created_at,
    });
    // approver IS approval_basis.consent_principal (D48/O-38 convergence).
    expect(persisted?.approver).toEqual(persisted?.approval_basis.consent_principal);
    // The Dispatcher (activation_actor) is distinct from the consenting human.
    expect(persisted?.approval_basis.activation_actor).not.toEqual(
      persisted?.approval_basis.consent_principal,
    );
    // Not folded into either integrity anchor: recomputing both from `intent`
    // and `authority_set` alone still matches, so approval_basis carries no
    // weight in the digests (the lock's hashing decision, made checkable).
    expect(mission.intent_hash).toBe(intentHash(ISS, mission.intent as never));
    expect(mission.authority_hash).toBe(authorityHash(ISS, mission.authority_set as never));
  });

  it("discloses approval_basis.type via introspection only to a privileged caller (#702: not on the baseline claim)", () => {
    const t = mkTemplate();
    const { mission } = dispatch(t.id);
    const fresh = kernel.get(mission.id) as MissionRecord;
    const claim = kernel.missionClaim(fresh);
    expect(Object.keys(claim).sort()).toEqual(["id", "issuer"]);
    const privileged = kernel.introspectionProjection(fresh, { disclose: new Set(["provenance"]) });
    expect(privileged.approval_basis).toEqual({ type: "template" });
  });
});

describe("seeded demo reconciliation template (@spec mission-template)", () => {
  it("createTemplate accepts the demo descriptor and it dispatches a read-only instance", () => {
    // The artifact the wire PR + demo consume: prove it both constructs AND
    // dispatches, against the same DERIVATION_POLICY the demo AS uses.
    const t = createTemplate(store, demoReconciliationTemplate(ISS) as never, {
      ...kernel.authoritySourceOptions(),
      dispatchPolicies: DEMO_DISPATCH_POLICIES,
    });
    const { mission } = dispatchFromTemplate(kernel, store, {
      templateId: t.id,
      dispatchEventId: "demo-dsp-1",
      dispatchPolicies: DEMO_DISPATCH_POLICIES,
      dispatcher: "ap-agent",
      intent: intentOf(["payments:invoice.read", "payments:vendor.read"]),
      // The demo instance acts for the template's consenting human, its one
      // listed Subject, exactly as the /token dispatch grant establishes it.
      subject: { iss: ISS, sub: "bob" },
      policyVersion: POLICY_VERSION,
    });
    expect(mission.state).toBe("active");
    expect(mission.client_id).toBe("subagent-invoice-extractor");
    expect(mission.approver).toEqual({ iss: ISS, sub: "bob" });
    // Read-only: no write/execute action survives the template ceiling.
    const actions = mission.authority_set.flatMap((e) => e.actions);
    expect(actions).toContain("payments:invoice.read");
    expect(actions).not.toContain("payments:payment.execute");
    expect(actions).not.toContain("payments:payment.schedule");
  });
});
