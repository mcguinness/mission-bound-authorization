import { authorityHash, intentHash } from "@mission/core";
import { demoReconciliationTemplate, DERIVATION_POLICY } from "@mission/demo-data";
import { type CryptoKey, generateKeyPair } from "jose";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  createExpansion,
  createTemplate,
  type CreateTemplateInput,
  DispatchError,
  type DispatchInput,
  dispatchFromTemplate,
  IntentError,
  MissionKernel,
  type MissionRecord,
  TemplateError,
  TemplateStore,
  validateMissionIntent,
} from "../src/index.js";

const ISS = "https://as.test";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const POLICY_VERSION = DERIVATION_POLICY.policy_version;
const now = () => new Date("2026-07-01T00:00:00Z");

let key: CryptoKey;
let kernel: MissionKernel;
let store: TemplateStore;
let tmplSeq = 0;
let dspSeq = 0;

beforeAll(async () => {
  key = (await generateKeyPair("ES256")).privateKey;
});

beforeEach(() => {
  kernel = new MissionKernel({ issuer: ISS, policy: DERIVATION_POLICY as never, statusKey: key, statusKid: "as-status", now });
  store = new TemplateStore(now);
});

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
    dispatch_policy: "test-policy",
    dispatchers: ["orchestrator"],
    recipients: ["worker"],
    per_instance_lifetime_s: 3600,
    max_active: 3,
    rate_per_min: 5,
    approval_event_id: `tmpl-ev-${tmplSeq++}`,
    expires_at: "2026-12-01T00:00:00Z",
    ...over,
  });

/** An untrusted Intent proposing the given actions (default max_amount 500,
 *  which is exactly the policy ceiling, so any narrower final is attributable). */
const intentOf = (actions: string[], opts: { maxAmount?: string; expiresAt?: string } = {}) =>
  validateMissionIntent(
    JSON.stringify({
      goal: "reconcile Acme",
      resources: [RESOURCE],
      expires_at: opts.expiresAt ?? "2027-01-01T00:00:00Z",
      proposed_authority: [
        {
          type: "mission_resource_access",
          resource: RESOURCE,
          actions,
          constraints: { max_amount: { amount: opts.maxAmount ?? "500.00", currency: "USD" }, vendors: ["acme"] },
        },
      ],
    }),
  );

const dispatch = (templateId: string, over: Partial<DispatchInput> = {}) =>
  dispatchFromTemplate(kernel, store, {
    templateId,
    dispatchEventId: `dsp-${dspSeq++}`,
    dispatcher: "orchestrator",
    recipient: "worker",
    intent: intentOf(["payments:invoice.read"]),
    subject: { iss: ISS, sub: "alice" },
    policyVersion: POLICY_VERSION,
    ...over,
  });

const amountOf = (m: { authority_set: AuthorityEntry[] }) =>
  m.authority_set[0]?.constraints?.max_amount?.amount;

describe("createTemplate (@spec mission-template)", () => {
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
      dispatch_policy: "test-policy",
      dispatchers: ["orchestrator"],
      recipients: ["worker"],
      per_instance_lifetime_s: 3600,
      max_active: 3,
      rate_per_min: 5,
      approval_event_id: "consent-1",
      expires_at: "2026-12-01T00:00:00Z",
    });
    expect(again.id).toBe(t.id);
    expect(again.template_hash).toBe(t.template_hash);
  });

  it("refuses an empty ceiling or non-positive bounds (TemplateError)", () => {
    expect(() => mkTemplate({ ceiling: [] })).toThrow(TemplateError);
    expect(() => mkTemplate({ per_instance_lifetime_s: 0 })).toThrow(TemplateError);
    expect(() => mkTemplate({ max_active: 0 })).toThrow(TemplateError);
    expect(() => mkTemplate({ rate_per_min: -1 })).toThrow(TemplateError);
  });
});

describe("dispatchFromTemplate double intersection (@spec mission-template#dispatch)", () => {
  it("clips by the TEMPLATE ceiling: an intent within policy but broader than the template narrows to the template", () => {
    // Template caps at 200; policy allows 500. The intent proposes 500 and both
    // actions, so any narrowing to 200 / dropped action is the TEMPLATE's doing.
    const t = mkTemplate({ ceiling: [ceilEntry(["payments:invoice.read"], "200.00")] });
    const intent = intentOf(["payments:invoice.read", "payments:payment.schedule"], { maxAmount: "500.00" });
    // Under policy alone the derivation would keep 500 and both actions.
    const derived = kernel.derive(intent);
    expect(amountOf({ authority_set: derived })).toBe("500.00");
    expect(derived[0]?.actions).toContain("payments:payment.schedule");
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
      dispatch(t.id, { intent: intentOf(["payments:payment.schedule"]) });
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
    expect(() => dispatch(t.id, { intent: intentOf(["payments:bogus.action"]) })).toThrow(IntentError);
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
    expect(mission.template?.dispatch_policy).toBe("test-policy");
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

  it("refuses a dispatcher or recipient not on the template's lists", () => {
    const t = mkTemplate();
    try {
      dispatch(t.id, { dispatcher: "intruder" });
      expect.unreachable();
    } catch (e) {
      expect((e as DispatchError).reason).toBe("dispatcher_not_allowed");
    }
    try {
      dispatch(t.id, { recipient: "intruder" });
      expect.unreachable();
    } catch (e) {
      expect((e as DispatchError).reason).toBe("recipient_not_allowed");
    }
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

  it("carries approval_basis.type on the mission claim", () => {
    const t = mkTemplate();
    const { mission } = dispatch(t.id);
    const claim = kernel.missionClaim(kernel.get(mission.id) as MissionRecord);
    expect(claim.approval_basis).toEqual({ type: "template" });
  });
});

describe("seeded demo reconciliation template (@spec mission-template)", () => {
  it("createTemplate accepts the demo descriptor and it dispatches a read-only instance", () => {
    // The artifact the wire PR + demo consume: prove it both constructs AND
    // dispatches, against the same DERIVATION_POLICY the demo AS uses.
    const t = createTemplate(store, demoReconciliationTemplate(ISS) as never);
    const { mission } = dispatchFromTemplate(kernel, store, {
      templateId: t.id,
      dispatchEventId: "demo-dsp-1",
      dispatcher: "ap-agent",
      recipient: "subagent-invoice-extractor",
      intent: intentOf(["payments:invoice.read", "payments:vendor.read"]),
      subject: { iss: ISS, sub: "alice" },
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
