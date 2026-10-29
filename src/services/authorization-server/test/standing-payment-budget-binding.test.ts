/**
 * @spec draft-mcguinness-mission-metering (#metering, #capacity-across-missions),
 * draft-mcguinness-oauth-mission-template (#standing-payment-exception)
 * (#813, #816, D830 rulings 1, 2, 4 and 5, decision d)
 *
 * The budget binding the kernel derives for a Mission in a standing-payment
 * lineage, the binding the PDP meters under: from the dispatched instance's
 * admission and the Dispatch Policy snapshot its activation retained, never
 * from a template store or a request. A standing payment whose binding cannot
 * be derived is reported underivable, which the PDP refuses; a Mission outside
 * every standing-payment lineage has none.
 */
import { DERIVATION_POLICY, DISPATCH_PROHIBITED_ACTIONS } from "@mission/demo-data";
import { type CryptoKey, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  createExpansion,
  createTemplate,
  type DispatchPolicies,
  dispatchFromTemplate,
  MissionKernel,
  type ProhibitedPredicateMapping,
  STANDING_PAYMENT_OPERATION,
  standingPaymentBudgetBindingOf,
  TemplateStore,
} from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISS = "https://as.test";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const T0 = Date.parse("2026-10-26T00:00:00Z");
const CLIENTS = ["worker", "orchestrator", "subagent-invoice-extractor"];
const now = () => new Date(T0);

const TERMS = {
  operation: STANDING_PAYMENT_OPERATION,
  resource: RESOURCE,
  destinations: { acme: "acct-acme-0001", globex: "acct-globex-0001" },
  max_amount: { amount: "500.00", currency: "USD" },
  budget: { owner: "payments-operator", id: "ap-standing-binding", currency: "USD", limit: "5000.00", per_instance_max: "1000.00" },
  approval_governance: {
    recency: {
      ceilings: { default: 86400 },
      clock_skew_s: 60,
      exceptions: { irreversible_action: { max_age_s: 3600 }, consumption_bound: { max_age_s: 3600 } },
    },
  },
};
const REGISTRY: DispatchPolicies = {
  "sp-binding": {
    version: "1",
    content_type: "application/json",
    content: JSON.stringify({ id: "sp-binding", derivation_limit_ceiling: 3, standing_payment: TERMS }),
  },
  // A second policy committing another budget, owner, limit and payee, so a
  // binding member taken from anywhere but the instance's own policy differs.
  "sp-binding-treasury": {
    version: "1",
    content_type: "application/json",
    content: JSON.stringify({
      id: "sp-binding-treasury",
      derivation_limit_ceiling: 3,
      standing_payment: {
        ...TERMS,
        destinations: { acme: "acct-acme-0002" },
        budget: { owner: "treasury-operator", id: "tr-standing-binding", currency: "USD", limit: "8000.00", per_instance_max: "1000.00" },
      },
    }),
  },
};
const MAPPING: ProhibitedPredicateMapping = {
  classesOf: (_entry, action) =>
    ({ "payments:payment.execute": ["irreversible_action"], "payments:invoice.read": ["consequential_read"] })[action],
  externalCommunicationActions: new Set(),
  isCrossDomain: () => false,
};
const MAX_BUDGET = { amount: "1000.00", currency: "USD" };

let key: CryptoKey;
let seq = 0;

beforeAll(async () => {
  key = (await generateKeyPair("ES256")).privateKey;
});

/** A fresh kernel with one consented standing-payment template and one dispatched instance. */
function dispatched(policyId = "sp-binding") {
  const kernel = new MissionKernel({
    issuer: ISS,
    policy: DERIVATION_POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, CLIENTS, ["human-approver", "worker", "orchestrator"]),
    statusKey: key,
    statusKid: "as-status",
    now,
  });
  const store = new TemplateStore(now);
  const template = createTemplate(
    store,
    {
      template_version: `sp-binding-${seq}`,
      issuer: ISS,
      approver: { iss: ISS, sub: "human-approver" },
      ceiling: [
        {
          type: "mission_resource_access",
          resource: RESOURCE,
          actions: [STANDING_PAYMENT_OPERATION],
          constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
        },
      ],
      dispatch_policy: { id: policyId, version: "1" },
      dispatchers: ["orchestrator"],
      recipients: { subjects: [{ iss: ISS, sub: "alice" }], agents: ["worker"] },
      per_instance_lifetime_s: 3600,
      max_active: 3,
      rate_per_min: 5,
      review_cadence_s: 86400,
      approval_event_id: `sp-binding-ev-${seq++}`,
      expires_at: "2026-12-01T00:00:00Z",
    },
    {
      ...kernel.authoritySourceOptions(),
      dispatchPolicies: REGISTRY,
      standingPayment: {
        consent: {
          interactive: true,
          principal: { iss: ISS, sub: "human-approver" },
          acr: "mfa",
          auth_time: Math.floor(T0 / 1000),
          floors: ["high-risk-authority"],
          render_revision: `rev-${seq}`,
          proposal_id: `tcon_${seq}`,
          decided_at: new Date(T0).toISOString(),
        },
        budgets: kernel.standingPayments,
        isClient: (sub) => CLIENTS.includes(sub),
        now,
      },
    },
  );
  const intent = (maxBudget = MAX_BUDGET) =>
    kernel.validateIntent(
      JSON.stringify({ goal: "pay approved Acme invoices", target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z", max_budget: maxBudget }),
      { admitMaxBudget: true },
    );
  const { mission } = dispatchFromTemplate(kernel, store, {
    templateId: template.id,
    dispatchEventId: `sp-binding-dsp-${seq++}`,
    dispatcher: "orchestrator",
    intent: intent(),
    subject: { iss: ISS, sub: "alice" },
    policyVersion: DERIVATION_POLICY.policy_version,
    dispatchPolicies: REGISTRY,
    dispatchProhibitedActions: DISPATCH_PROHIBITED_ACTIONS,
    standingPayment: { mapping: MAPPING },
  });
  const successor = () =>
    createExpansion(kernel, {
      predecessorId: mission.id,
      intent: intent(),
      approver: { iss: ISS, sub: "human-approver" },
      approvalEventId: `sp-binding-exp-${seq++}`,
      approvedUntil: "2027-01-01T00:00:00Z",
    }).successor;
  /** An ordinary Mission, outside every standing-payment lineage. */
  const ordinary = () =>
    kernel.approve({
      intent: kernel.validateIntent(JSON.stringify({ goal: "read invoices", target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" })),
      proposedAuthority: [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] }],
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "human-approver" },
      clientId: "worker",
      approvalEventId: `sp-binding-ordinary-${seq++}`,
    });
  return { kernel, template, mission, successor, ordinary };
}

describe("the budget binding the kernel derives for a standing payment (@spec metering#metering, mission-template#standing-payment-exception, #813, #816, decision d)", () => {
  it("derives a dispatched instance's binding from the Dispatch Policy snapshot its activation retained: the budget, its limit, the committed policy and destinations, and the instance bound keyed by the instance itself (#813, #816)", () => {
    const { kernel, template, mission } = dispatched();
    expect(standingPaymentBudgetBindingOf(kernel, mission)).toEqual({
      kind: "bound",
      binding: {
        owner: "payments-operator",
        budget_id: "ap-standing-binding",
        currency: "USD",
        limit: "5000.00",
        policy: template.dispatch_policy,
        destinations: { acme: "acct-acme-0001", globex: "acct-globex-0001" },
        instance: { max_budget: MAX_BUDGET, root_mission_id: mission.id },
      },
    });
  });

  it("derives the budget owner, identifier, limit and destinations from the instance's own committed Dispatch Policy: an instance under a policy committing another budget derives that budget (#813, #816)", () => {
    const { kernel, template, mission } = dispatched("sp-binding-treasury");
    expect(template.dispatch_policy.id).toBe("sp-binding-treasury");
    expect(standingPaymentBudgetBindingOf(kernel, mission)).toEqual({
      kind: "bound",
      binding: {
        owner: "treasury-operator",
        budget_id: "tr-standing-binding",
        currency: "USD",
        limit: "8000.00",
        policy: template.dispatch_policy,
        destinations: { acme: "acct-acme-0002" },
        instance: { max_budget: MAX_BUDGET, root_mission_id: mission.id },
      },
    });
  });

  it("derives for an expansion successor the binding of the dispatched instance it descends from, keyed by that instance, so the successor continues both counters (@spec metering#capacity-across-missions, #813, #816)", () => {
    const { kernel, mission, successor } = dispatched();
    const next = successor();
    expect(next.predecessor).toBe(mission.id);
    expect(standingPaymentBudgetBindingOf(kernel, next)).toEqual(standingPaymentBudgetBindingOf(kernel, mission));
  });

  it("derives no binding for a Mission outside every standing-payment lineage (#813, #816)", () => {
    const { kernel, ordinary } = dispatched();
    expect(standingPaymentBudgetBindingOf(kernel, ordinary())).toEqual({ kind: "unbound" });
  });

  it("reports underivable, never unbound, a standing payment whose retained snapshot is gone or no longer reproduces its digest, whose admission names another Dispatch Policy or budget than the instance commits, whose Mission does not carry the instance's max_budget, a Mission recorded as a Child Mission anywhere in the lineage, or a successor or child whose predecessor or parent record the kernel no longer holds (#813, #816, decision d)", () => {
    const cases: Array<[string, (k: ReturnType<typeof dispatched>) => { id: string }, (k: ReturnType<typeof dispatched>) => string]> = [
      [
        "the retained snapshot is gone",
        ({ kernel, mission }) => {
          kernel.db.prepare("DELETE FROM activation_policy_snapshots").run();
          return mission;
        },
        () => "Dispatch Policy sp-binding version 1: retained snapshot unavailable",
      ],
      [
        "the retained snapshot no longer reproduces its digest",
        ({ kernel, mission }) => {
          const tampered = JSON.stringify({ id: "sp-binding", derivation_limit_ceiling: 3, standing_payment: { ...TERMS, destinations: { acme: "acct-attacker-0001" } } });
          kernel.db.prepare("UPDATE activation_policy_snapshots SET content = ?").run(Buffer.from(tampered, "utf8"));
          return mission;
        },
        () => "Dispatch Policy sp-binding version 1: retained snapshot mismatch",
      ],
      [
        "the admission names another Dispatch Policy than the instance commits",
        ({ kernel, mission, template }) => {
          const other = { ...template.dispatch_policy, version: "2" };
          kernel.db.prepare("UPDATE standing_payment_admissions SET dispatch_policy_json = ? WHERE mission_id = ?").run(JSON.stringify(other), mission.id);
          return mission;
        },
        ({ mission }) => `standing-payment instance ${mission.id} commits another Dispatch Policy than its admission`,
      ],
      [
        "the admission names another budget than the policy's",
        ({ kernel, mission }) => {
          kernel.db.prepare("UPDATE standing_payment_admissions SET budget_id = ? WHERE mission_id = ?").run("ap-standing-other", mission.id);
          return mission;
        },
        () => "Dispatch Policy sp-binding names another budget than the one pinned at consent",
      ],
      [
        "the Mission does not carry the instance's max_budget",
        ({ kernel, mission }) => {
          kernel.db
            .prepare("UPDATE standing_payment_admissions SET max_budget_json = ? WHERE mission_id = ?")
            .run(JSON.stringify({ amount: "900.00", currency: "USD" }), mission.id);
          return mission;
        },
        ({ mission }) => `mission ${mission.id} does not carry the max_budget of standing-payment instance ${mission.id}`,
      ],
      [
        "a Mission recorded as a Child Mission of the instance",
        ({ kernel, mission, ordinary }) => {
          const child = ordinary();
          const parent = { id: mission.id, issuer: ISS, authority_hash: mission.authority_hash, depth: 1 };
          kernel.db.prepare("UPDATE missions SET parent_id = ?, parent_json = ? WHERE id = ?").run(mission.id, JSON.stringify(parent), child.id);
          return child;
        },
        ({ mission }) => `descends as a Child Mission from standing-payment instance ${mission.id}, whose budget accounting covers no child`,
      ],
      [
        "a Mission recorded as a Child Mission of the instance's successor",
        ({ kernel, successor, ordinary }) => {
          const next = successor();
          const child = ordinary();
          const parent = { id: next.id, issuer: ISS, authority_hash: next.authority_hash, depth: 1 };
          kernel.db.prepare("UPDATE missions SET parent_id = ?, parent_json = ? WHERE id = ?").run(next.id, JSON.stringify(parent), child.id);
          return child;
        },
        ({ mission }) => `descends as a Child Mission from standing-payment instance ${mission.id}, whose budget accounting covers no child`,
      ],
      [
        "a child whose parent record is gone",
        ({ kernel, ordinary }) => {
          const child = ordinary();
          const parent = { id: "msn_gone", issuer: ISS, authority_hash: "sha-256:gone", depth: 1 };
          kernel.db.prepare("UPDATE missions SET parent_id = ?, parent_json = ? WHERE id = ?").run("msn_gone", JSON.stringify(parent), child.id);
          return child;
        },
        () => "names parent msn_gone, which this kernel holds no record of",
      ],
      [
        "the successor's predecessor record is gone",
        ({ kernel, mission, successor }) => {
          const next = successor();
          kernel.db.prepare("DELETE FROM missions WHERE id = ?").run(mission.id);
          return next;
        },
        ({ mission }) => `names predecessor ${mission.id}, which this kernel holds no record of`,
      ],
    ];
    for (const [label, damage, reason] of cases) {
      const k = dispatched();
      expect(standingPaymentBudgetBindingOf(k.kernel, k.mission).kind, label).toBe("bound");
      const target = damage(k);
      const record = k.kernel.get(target.id);
      if (!record) throw new Error(`${label}: no record of ${target.id}`);
      const derived = standingPaymentBudgetBindingOf(k.kernel, record);
      expect(derived.kind, label).toBe("underivable");
      expect(derived.kind === "underivable" ? derived.reason : "", label).toContain(reason(k));
    }
  });
});
