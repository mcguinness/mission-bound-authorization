/**
 * @spec draft-mcguinness-oauth-mission-template (#prohibited-classes,
 * #dispatch, #template-consent, #instance-composition),
 * draft-mcguinness-mission-approval-governance (#recency-evaluation,
 * #recency-high-risk, #atomic-commitment, #re-check) (#813, D814, D830)
 *
 * The one standing-payment dispatch workflow, at the kernel: a template whose
 * committed Dispatch Policy states `standing_payment` terms dispatches
 * `payments:payment.execute` unattended under the opt-in capability (here the
 * `standingPayment` dispatch input), waiving only that operation's
 * `irreversible_action` predicate. Covered here: the admission and its
 * refusals, the consent conditions, the ceiling defects, the instance's
 * `max_budget`, the budget identity across policy successors, the lineage
 * rules, the Approval Governance Record and its recency boundary, and the
 * dispatch accounting committed in the instance's own transaction.
 */
import { DERIVATION_POLICY, DISPATCH_PROHIBITED_ACTIONS } from "@mission/demo-data";
import { type CryptoKey, exportJWK, generateKeyPair } from "jose";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  type AuthorityEntry,
  ChildDelegationError,
  type CreateTemplateInput,
  createChildMission,
  createExpansion,
  createTemplate,
  DispatchError,
  type DispatchInput,
  type DispatchPolicies,
  deriveAttenuationRoot,
  deriveCrossOrgRoot,
  dispatchFromTemplate,
  IntentError,
  issueCrossDomainGrant,
  MissionKernel,
  type ProhibitedPredicateMapping,
  recheckTemplateApprovalRecord,
  STANDING_PAYMENT_OPERATION,
  StandingPaymentLineageError,
  standingPaymentRootOf,
  TEMPLATE_RECORDING_RULE_ID,
  type TemplateConsentProvenance,
  TemplateError,
  TemplateStore,
} from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISS = "https://as.test";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const POLICY_VERSION = DERIVATION_POLICY.policy_version;
const T0 = Date.parse("2026-07-01T00:00:00Z");
const CLIENTS = ["worker", "orchestrator", "subagent-invoice-extractor"];
let clockMs = T0;
const now = () => new Date(clockMs);

let key: CryptoKey;
let kernel: MissionKernel;
let store: TemplateStore;
let seq = 0;

beforeAll(async () => {
  key = (await generateKeyPair("ES256")).privateKey;
});

beforeEach(() => {
  clockMs = T0;
  // The Agent and the Dispatcher are activators too, so a consent naming
  // either passes the source's activation gate and meets the
  // standing-payment consent rule itself.
  kernel = new MissionKernel({
    issuer: ISS,
    policy: DERIVATION_POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, CLIENTS, [
      "human-approver",
      "worker",
      "orchestrator",
    ]),
    statusKey: key,
    statusKid: "as-status",
    now,
  });
  store = new TemplateStore(now);
});

afterEach(() => {
  vi.restoreAllMocks();
});

/** The committed standing-payment terms (@spec mission-template#prohibited-classes, #813). */
const TERMS = {
  operation: STANDING_PAYMENT_OPERATION,
  resource: RESOURCE,
  destinations: { acme: "acct-acme-0001" },
  max_amount: { amount: "500.00", currency: "USD" },
  budget: {
    owner: "payments-operator",
    id: "ap-standing-2026",
    currency: "USD",
    limit: "5000.00",
    per_instance_max: "1000.00",
  },
  approval_governance: {
    recency: {
      ceilings: { default: 86400 },
      clock_skew_s: 60,
      exceptions: {
        irreversible_action: { max_age_s: 3600 },
        consumption_bound: { max_age_s: 7200 },
      },
    },
  },
};
type Terms = typeof TERMS;

/** A held Dispatch Policy snapshot stating `terms`. */
const spPolicy = (id: string, terms: unknown = TERMS, version = "1") => ({
  version,
  content_type: "application/json",
  content: JSON.stringify({ id, derivation_limit_ceiling: 3, standing_payment: terms }),
});
const withGovernance = (recency: Terms["approval_governance"]["recency"]): Terms => ({
  ...TERMS,
  approval_governance: { recency },
});

const REGISTRY: DispatchPolicies = {
  "sp-policy": spPolicy("sp-policy"),
  "sp-no-consumption-exception": spPolicy(
    "sp-no-consumption-exception",
    withGovernance({
      ceilings: { default: 86400 },
      clock_skew_s: 60,
      exceptions: { irreversible_action: { max_age_s: 3600 } } as never,
    }),
  ),
  "sp-no-irreversible-exception": spPolicy(
    "sp-no-irreversible-exception",
    withGovernance({
      ceilings: { default: 86400 },
      clock_skew_s: 60,
      exceptions: { consumption_bound: { max_age_s: 7200 } } as never,
    }),
  ),
  "sp-default-stricter": spPolicy(
    "sp-default-stricter",
    withGovernance({
      ceilings: { default: 1800 },
      clock_skew_s: 60,
      exceptions: {
        irreversible_action: { max_age_s: 3600 },
        consumption_bound: { max_age_s: 7200 },
      },
    }),
  ),
  "sp-no-destinations": spPolicy("sp-no-destinations", { ...TERMS, destinations: {} }),
  "sp-budget-no-limit": spPolicy("sp-budget-no-limit", {
    ...TERMS,
    budget: { owner: TERMS.budget.owner, id: "ap-no-limit", currency: "USD", per_instance_max: "1000.00" },
  }),
};

/** The published classification the admission reads, per action. */
const CLASSES: Record<string, string[]> = {
  "payments:payment.execute": ["irreversible_action"],
  "payments:invoice.read": ["consequential_read"],
  "payments:invoice.list": ["consequential_read"],
  "payments:vendor.read": ["consequential_read"],
  "payments:payment.schedule": ["consequential_write"],
  "payments:remittance.send": ["external_commitment"],
};
const mappingOf = (
  over: {
    classes?: Record<string, string[]>;
    external?: string[];
    crossDomain?: (r: string) => boolean;
  } = {},
): ProhibitedPredicateMapping => ({
  classesOf: (_entry, action) => (over.classes ?? CLASSES)[action],
  externalCommunicationActions: new Set(over.external ?? []),
  isCrossDomain: over.crossDomain ?? (() => false),
});

/** A human consent at the approval floor, as the approval surface records it. */
const humanConsent = (
  sub = "human-approver",
  over: Partial<TemplateConsentProvenance> = {},
): TemplateConsentProvenance => ({
  interactive: true,
  principal: { iss: ISS, sub },
  acr: "mfa",
  auth_time: Math.floor(clockMs / 1000),
  floors: ["high-risk-authority"],
  render_revision: `rev-${seq}`,
  proposal_id: `tcon_${seq}`,
  decided_at: new Date(clockMs).toISOString(),
  ...over,
});

/** The standing payment's ceiling entry: one resource, a per-payment bound, committed destinations. */
const paymentEntry = (over: Partial<AuthorityEntry> = {}): AuthorityEntry => ({
  type: "mission_resource_access",
  resource: RESOURCE,
  actions: ["payments:payment.execute"],
  constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  ...over,
});

const body = (over: Partial<CreateTemplateInput> = {}): CreateTemplateInput => ({
  template_version: "sp-v1",
  issuer: ISS,
  approver: { iss: ISS, sub: "human-approver" },
  ceiling: [paymentEntry()],
  dispatch_policy: { id: "sp-policy", version: "1" },
  dispatchers: ["orchestrator"],
  recipients: { subjects: [{ iss: ISS, sub: "alice" }], agents: ["worker"] },
  per_instance_lifetime_s: 3600,
  max_active: 3,
  rate_per_min: 5,
  review_cadence_s: 86400,
  approval_event_id: `sp-ev-${seq++}`,
  expires_at: "2026-12-01T00:00:00Z",
  ...over,
});

/** Consent under the capability, with `consent` (a human at the floor unless replaced). */
const consentTo = (
  over: Partial<CreateTemplateInput> = {},
  opts: { consent?: TemplateConsentProvenance | null; policies?: DispatchPolicies } = {},
) => {
  const input = body(over);
  const consent =
    opts.consent === null ? undefined : (opts.consent ?? humanConsent(input.approver.sub));
  return createTemplate(store, input, {
    ...kernel.authoritySourceOptions(),
    dispatchPolicies: opts.policies ?? REGISTRY,
    standingPayment: {
      ...(consent ? { consent } : {}),
      budgets: kernel.standingPayments,
      isClient: (sub) => CLIENTS.includes(sub),
      now,
    },
  });
};

const intentWith = (
  maxBudget: { amount: string; currency: string } | null = { amount: "1000.00", currency: "USD" },
) =>
  kernel.validateIntent(
    JSON.stringify({
      goal: "pay approved Acme invoices",
      target_resources: [RESOURCE],
      expires_at: "2027-01-01T00:00:00Z",
      ...(maxBudget ? { max_budget: maxBudget } : {}),
    }),
    { admitMaxBudget: true },
  );

/** Dispatch with the capability on (the `standingPayment` input), unless `over` removes it. */
const dispatch = (templateId: string, over: Partial<DispatchInput> = {}, mapping = mappingOf()) =>
  dispatchFromTemplate(kernel, store, {
    templateId,
    dispatchEventId: `dsp-${seq++}`,
    dispatcher: "orchestrator",
    intent: intentWith(),
    subject: { iss: ISS, sub: "alice" },
    policyVersion: POLICY_VERSION,
    dispatchPolicies: REGISTRY,
    dispatchProhibitedActions: DISPATCH_PROHIBITED_ACTIONS,
    standingPayment: { mapping },
    ...over,
  });

const missionCount = (): number =>
  (kernel.db.prepare("SELECT COUNT(*) AS n FROM missions").get() as { n: number }).n;

/** The dispatch's refusal reason; fails when it did not refuse with a DispatchError. */
const refusal = (run: () => unknown): { reason: string; message: string } => {
  try {
    run();
  } catch (e) {
    if (e instanceof DispatchError) return { reason: e.reason, message: e.message };
    throw e;
  }
  throw new Error("the dispatch was not refused");
};

describe("standing-payment dispatch admission (@spec mission-template#prohibited-classes, #813)", () => {
  it("dispatches a standing-payment instance unattended with the capability on, waiving only the payment's irreversible_action predicate (#813)", () => {
    const t = consentTo();
    const { mission } = dispatch(t.id);
    expect(mission.state).toBe("active");
    expect(mission.authority_set.flatMap((e) => e.actions)).toEqual([STANDING_PAYMENT_OPERATION]);
    expect(mission.intent.max_budget).toEqual({ amount: "1000.00", currency: "USD" });
    expect(kernel.get(mission.id)?.state).toBe("active");
  });

  it("commits the instance's Approval Governance Record under the template recording rule, and a re-check replays it from retained state (@spec approval-governance#re-check, #813)", () => {
    const t = consentTo();
    const { mission } = dispatch(t.id);
    const record = kernel.governanceRecords.forMission(mission.id);
    expect(record?.approval_policy.id).toBe(TEMPLATE_RECORDING_RULE_ID);
    expect(record?.assertions).toHaveLength(1);
    expect(record?.assertions[0]?.kind).toBe("policy");
    expect(record?.assertions[0]?.principal).toEqual({ iss: ISS, sub: "human-approver" });
    expect(record?.assertions[0]?.authority).toEqual({
      policy_id: "sp-policy",
      version: "1",
      approved_at: t.created_at,
    });
    expect(recheckTemplateApprovalRecord(kernel, mission, record as never)).toEqual({
      rechecked: true,
    });
    const rule = JSON.parse(
      Buffer.from(
        kernel.templateApprovalRecords.ruleSnapshot(
          ISS,
          (record as { approval_policy: never }).approval_policy,
        )?.content ?? [],
      ).toString("utf8"),
    ) as { recency: { exceptions: Record<string, unknown> } };
    expect(Object.keys(rule.recency.exceptions).sort()).toEqual([
      "consumption_bound",
      "irreversible_action",
    ]);
  });

  it("records the admission with the policy's budget identity and the instance's max_budget, and counts the dispatch in the kernel database (#813)", () => {
    const t = consentTo();
    const { mission } = dispatch(t.id);
    expect(kernel.standingPayments.admission(mission.id)).toEqual({
      mission_id: mission.id,
      template_id: t.id,
      dispatch_policy: t.dispatch_policy,
      budget: { owner: "payments-operator", id: "ap-standing-2026" },
      max_budget: { amount: "1000.00", currency: "USD" },
      admitted_at: mission.created_at,
    });
    expect(kernel.standingPayments.dispatchedInstances(t.id)).toEqual([mission.id]);
    // The template store's own trail is not the standing payment's accounting.
    expect(store.dispatchesSince(t.id, "1970-01-01T00:00:00.000Z")).toBe(0);
  });

  it("refuses the payment dispatch_prohibited_class with the capability off, exactly as without the workflow (#813)", () => {
    const t = consentTo();
    const r = refusal(() =>
      dispatch(t.id, { standingPayment: undefined, intent: intentWith(null) } as never),
    );
    expect(r.reason).toBe("dispatch_prohibited_class");
    expect(r.message).toBe("instance authority includes a dispatch-prohibited action");
  });

  it("refuses dispatch_policy_changed when the committed Dispatch Policy was superseded by a new version (#813)", () => {
    const t = consentTo();
    const r = refusal(() =>
      dispatch(t.id, {
        dispatchPolicies: { ...REGISTRY, "sp-policy": spPolicy("sp-policy", TERMS, "2") },
      }),
    );
    expect(r.reason).toBe("dispatch_policy_changed");
  });

  it("refuses dispatch_prohibited_class when the committed policy has no class-named exception for the consumption bound, committing nothing (@spec approval-governance#recency-high-risk, #813)", () => {
    const t = consentTo({ dispatch_policy: { id: "sp-no-consumption-exception", version: "1" } });
    const before = missionCount();
    const r = refusal(() => dispatch(t.id));
    expect(r.reason).toBe("dispatch_prohibited_class");
    expect(r.message).toMatch(
      /governance_high_risk: the high-risk class consumption_bound has no committed class-named exception/,
    );
    expect(missionCount()).toBe(before);
    expect(kernel.standingPayments.dispatchedInstances(t.id)).toEqual([]);
  });

  it("refuses dispatch_prohibited_class when the committed policy has no class-named exception for the irreversible action (@spec approval-governance#recency-high-risk, #813)", () => {
    const t = consentTo({ dispatch_policy: { id: "sp-no-irreversible-exception", version: "1" } });
    const r = refusal(() => dispatch(t.id));
    expect(r.reason).toBe("dispatch_prohibited_class");
    expect(r.message).toMatch(
      /the high-risk class irreversible_action has no committed class-named exception/,
    );
    expect(kernel.standingPayments.dispatchedInstances(t.id)).toEqual([]);
  });
});

describe("standing-payment consent (@spec mission-template#template-consent, #813)", () => {
  it("retains the human consent provenance with the template, outside template_hash (#813)", () => {
    const consent = humanConsent();
    const t = consentTo({}, { consent });
    expect(t.consent_provenance).toEqual(consent);
    // The same consented body under another provenance commits the same hash.
    const again = consentTo(
      { approval_event_id: "sp-ev-same-body" },
      { consent: humanConsent("human-approver", { render_revision: "other" }) },
    );
    const twin = consentTo({ approval_event_id: "sp-ev-same-body-2" });
    expect(again.template_hash).toBe(twin.template_hash);
  });

  it("refuses a standing-payment template with no human consent at the approval floor, as the service-token stand-in and the boot seed present (#813)", () => {
    expect(() => consentTo({}, { consent: null })).toThrow(TemplateError);
    expect(() => consentTo({}, { consent: null })).toThrow(
      /consented only by a human Approver at the approval floor/,
    );
  });

  it("refuses a standing-payment template whose consent is not an interactive login, so no agent-held key or assertion consents (#813)", () => {
    const headless = {
      ...humanConsent(),
      interactive: false,
    } as unknown as TemplateConsentProvenance;
    expect(() => consentTo({}, { consent: headless })).toThrow(
      /consented only by a human Approver at the approval floor/,
    );
    const noFloor = humanConsent("human-approver", { floors: [] });
    expect(() => consentTo({}, { consent: noFloor })).toThrow(
      /consented only by a human Approver at the approval floor/,
    );
  });

  it("refuses a standing-payment template consented by its own Agent, so an agent never approves itself (#813)", () => {
    expect(() => consentTo({ approver: { iss: ISS, sub: "worker" } })).toThrow(
      "the consenting principal worker is a Dispatcher or an Agent; a standing-payment template is consented by a human",
    );
  });

  it("refuses a standing-payment template consented by its Dispatcher (#813)", () => {
    expect(() => consentTo({ approver: { iss: ISS, sub: "orchestrator" } })).toThrow(
      "the consenting principal orchestrator is a Dispatcher or an Agent; a standing-payment template is consented by a human",
    );
  });

  it("refuses a dispatch from a standing-payment template that retains no human consent, even one created before the capability (#813)", () => {
    // Created as the capability-off stand-in would: no standing-payment consent rule ran.
    const t = createTemplate(store, body(), {
      ...kernel.authoritySourceOptions(),
      dispatchPolicies: REGISTRY,
    });
    kernel.standingPayments.bindBudget("sp-policy", TERMS.budget, new Date(clockMs).toISOString());
    const r = refusal(() => dispatch(t.id));
    expect(r.reason).toBe("dispatch_prohibited_class");
    expect(r.message).toMatch(/carries no human consent at the approval floor/);
  });
});

describe("prohibited predicates the standing payment never waives (@spec mission-template#prohibited-classes, #813)", () => {
  it("refuses remittance in a standing-payment ceiling dispatch_prohibited_class (#813)", () => {
    const t = consentTo({
      ceiling: [
        paymentEntry({ actions: ["payments:payment.execute", "payments:remittance.send"] }),
      ],
    });
    const r = refusal(() => dispatch(t.id));
    expect(r.reason).toBe("dispatch_prohibited_class");
    expect(r.message).toBe(
      "payments:remittance.send is a dispatch-prohibited action no standing payment waives",
    );
  });

  it("refuses the payment when the published mapping also classifies it as privileged administration (#813)", () => {
    const t = consentTo();
    const mapping = mappingOf({
      classes: {
        ...CLASSES,
        [STANDING_PAYMENT_OPERATION]: ["irreversible_action", "privileged_administration"],
      },
    });
    const r = refusal(() => dispatch(t.id, {}, mapping));
    expect(r.reason).toBe("dispatch_prohibited_class");
    expect(r.message).toMatch(
      /satisfies the prohibited predicate privileged_administration, which no standing payment waives/,
    );
  });

  it("refuses the payment when the published mapping also classifies it as an external commitment (#813)", () => {
    const t = consentTo();
    const mapping = mappingOf({
      classes: {
        ...CLASSES,
        [STANDING_PAYMENT_OPERATION]: ["irreversible_action", "external_commitment"],
      },
    });
    const r = refusal(() => dispatch(t.id, {}, mapping));
    expect(r.reason).toBe("dispatch_prohibited_class");
    expect(r.message).toMatch(
      /satisfies the prohibited predicate external_commitment, which no standing payment waives/,
    );
  });

  it("refuses the payment when it satisfies the external-communication predicate (#813)", () => {
    const t = consentTo();
    const r = refusal(() =>
      dispatch(t.id, {}, mappingOf({ external: [STANDING_PAYMENT_OPERATION] })),
    );
    expect(r.reason).toBe("dispatch_prohibited_class");
    expect(r.message).toMatch(
      /satisfies the prohibited predicate external_communication, which no standing payment waives/,
    );
  });

  it("refuses the payment on a cross-domain resource (#813)", () => {
    const t = consentTo();
    const r = refusal(() => dispatch(t.id, {}, mappingOf({ crossDomain: (r) => r === RESOURCE })));
    expect(r.reason).toBe("dispatch_prohibited_class");
    expect(r.message).toMatch(
      /satisfies the prohibited predicate cross_domain, which no standing payment waives/,
    );
  });

  it("refuses an action the published mapping does not classify (#813)", () => {
    const t = consentTo();
    const { [STANDING_PAYMENT_OPERATION]: _dropped, ...unclassified } = CLASSES;
    const r = refusal(() => dispatch(t.id, {}, mappingOf({ classes: unclassified })));
    expect(r.reason).toBe("dispatch_prohibited_class");
    expect(r.message).toMatch(/does not classify payments:payment.execute/);
  });
});

describe("standing-payment ceiling defects (@spec mission-template#prohibited-classes, #813)", () => {
  it("refuses a Dispatch Policy that commits no destination (#813)", () => {
    expect(() =>
      consentTo({ dispatch_policy: { id: "sp-no-destinations", version: "1" } }),
    ).toThrow(/destinations commits no beneficiary/);
  });

  it("refuses a ceiling vendor the Dispatch Policy commits no destination for (#813)", () => {
    expect(() =>
      consentTo({
        ceiling: [
          paymentEntry({
            constraints: {
              max_amount: { amount: "500.00", currency: "USD" },
              vendors: ["acme", "globex"],
            },
          }),
        ],
      }),
    ).toThrow(
      "the Template Ceiling: entry 0 names vendor globex, which the Dispatch Policy commits no destination for",
    );
  });

  it("refuses a ceiling that bounds the payment with no per-payment max_amount (#813)", () => {
    expect(() =>
      consentTo({ ceiling: [paymentEntry({ constraints: { vendors: ["acme"] } })] }),
    ).toThrow(
      "the Template Ceiling: entry 0 names payments:payment.execute with no per-payment max_amount",
    );
  });

  it("refuses a ceiling whose per-payment bound is in a currency other than USD (#813)", () => {
    expect(() =>
      consentTo({
        ceiling: [
          paymentEntry({
            constraints: { max_amount: { amount: "500.00", currency: "EUR" }, vendors: ["acme"] },
          }),
        ],
      }),
    ).toThrow("the Template Ceiling: entry 0 bounds payments:payment.execute in EUR, not USD");
  });

  it("refuses a ceiling whose per-payment bound is above the policy's max_amount (#813)", () => {
    expect(() =>
      consentTo({
        ceiling: [
          paymentEntry({
            constraints: { max_amount: { amount: "500.01", currency: "USD" }, vendors: ["acme"] },
          }),
        ],
      }),
    ).toThrow(
      "the Template Ceiling: entry 0 bounds each payment above the Dispatch Policy's max_amount of 500.00",
    );
  });

  it("refuses a ceiling that names more than one resource (#813)", () => {
    expect(() =>
      consentTo({
        ceiling: [
          paymentEntry(),
          {
            type: "mission_resource_access",
            resource: "http://localhost:4410/api",
            actions: ["reports:report.read"],
          },
        ],
      }),
    ).toThrow(
      /entry 1 names http:\/\/localhost:4410\/api; a standing-payment ceiling names exactly one resource/,
    );
  });

  it("refuses a ceiling entry carrying a child or delegation grant (#813)", () => {
    expect(() =>
      consentTo({
        ceiling: [
          paymentEntry({ delegation: { max_depth: 1, children: { max_children: 1 } } as never }),
        ],
      }),
    ).toThrow(
      "the Template Ceiling: entry 0 carries delegation; a standing-payment ceiling admits no child and no delegation",
    );
  });
});

describe("standing-payment instance max_budget (@spec metering#bounds, #813 ruling 2)", () => {
  it("refuses dispatch_prohibited_class an instance whose max_budget is above the policy's per_instance_max (#813)", () => {
    const t = consentTo();
    const r = refusal(() =>
      dispatch(t.id, { intent: intentWith({ amount: "1000.01", currency: "USD" }) }),
    );
    expect(r.reason).toBe("dispatch_prohibited_class");
    expect(r.message).toBe(
      "max_budget of 1000.01 is above the Dispatch Policy's per_instance_max of 1000.00",
    );
  });

  it("refuses dispatch_prohibited_class an instance whose Intent carries no max_budget (#813)", () => {
    const t = consentTo();
    const r = refusal(() => dispatch(t.id, { intent: intentWith(null) }));
    expect(r.reason).toBe("dispatch_prohibited_class");
    expect(r.message).toBe("a standing-payment instance's Intent carries max_budget");
  });

  it("refuses an instance whose max_budget is in a currency other than the budget's (#813)", () => {
    const t = consentTo();
    const r = refusal(() =>
      dispatch(t.id, { intent: intentWith({ amount: "100.00", currency: "EUR" }) }),
    );
    expect(r.reason).toBe("dispatch_prohibited_class");
    expect(r.message).toBe("max_budget is in EUR, not the budget's USD");
  });

  it("refuses max_budget on the dispatch of a template that is not a standing payment (#813)", () => {
    const t = createTemplate(
      store,
      body({
        ceiling: [paymentEntry({ actions: ["payments:invoice.read"] })],
        dispatch_policy: { id: "plain", version: "1" },
      }),
      {
        ...kernel.authoritySourceOptions(),
        dispatchPolicies: {
          plain: { version: "1", content_type: "application/json", content: "{}" },
        },
      },
    );
    expect(() =>
      dispatch(t.id, {
        dispatchPolicies: {
          plain: { version: "1", content_type: "application/json", content: "{}" },
        },
      }),
    ).toThrow(IntentError);
  });
});

describe("standing-payment budget identity (@spec mission-template#prohibited-classes, #813 ruling 1)", () => {
  it("refuses a policy successor that changes the budget identity, so no re-consent starts a fresh counter (#813)", () => {
    consentTo();
    const successor = {
      ...REGISTRY,
      "sp-policy": spPolicy(
        "sp-policy",
        { ...TERMS, budget: { ...TERMS.budget, id: "ap-standing-2027" } },
        "2",
      ),
    };
    expect(() =>
      consentTo(
        { template_version: "sp-v2", dispatch_policy: { id: "sp-policy", version: "2" } },
        { policies: successor },
      ),
    ).toThrow(
      "Dispatch Policy sp-policy commits budget payments-operator/ap-standing-2026; a successor naming payments-operator/ap-standing-2027 would start a fresh counter",
    );
    expect(kernel.standingPayments.budgetBinding("sp-policy")).toEqual({
      owner: "payments-operator",
      id: "ap-standing-2026",
    });
  });

  it("admits a policy successor that keeps the budget identity, and the pinned identity is unchanged (#813)", () => {
    const first = consentTo();
    const successor = {
      ...REGISTRY,
      "sp-policy": spPolicy(
        "sp-policy",
        { ...TERMS, budget: { ...TERMS.budget, limit: "6000.00" } },
        "2",
      ),
    };
    const second = consentTo(
      { template_version: "sp-v2", dispatch_policy: { id: "sp-policy", version: "2" } },
      { policies: successor },
    );
    expect(second.id).not.toBe(first.id);
    expect(kernel.standingPayments.budgetBinding("sp-policy")).toEqual({
      owner: "payments-operator",
      id: "ap-standing-2026",
    });
  });

  it("refuses another Dispatch Policy claiming a budget identity already pinned to a standing approval (#813)", () => {
    consentTo();
    const other = { ...REGISTRY, "sp-other": spPolicy("sp-other") };
    expect(() =>
      consentTo({ dispatch_policy: { id: "sp-other", version: "1" } }, { policies: other }),
    ).toThrow(
      "budget payments-operator/ap-standing-2026 is committed by Dispatch Policy sp-policy, not sp-other",
    );
  });
});

describe("standing-payment lineage (@spec mission-template#instance-composition, #813 ruling 3)", () => {
  it("refuses a Child Mission of a standing-payment instance delegation_not_permitted (#813)", () => {
    const t = consentTo();
    const { mission } = dispatch(t.id);
    let caught: unknown;
    try {
      createChildMission(kernel, {
        parentId: mission.id,
        intent: kernel.validateIntent(
          JSON.stringify({
            goal: "pay one invoice",
            target_resources: [RESOURCE],
            expires_at: "2027-01-01T00:00:00Z",
          }),
        ),
        proposedAuthority: [paymentEntry()],
        childActor: { sub: "subagent-invoice-extractor", sub_profile: "ai_agent" },
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ChildDelegationError);
    expect((caught as ChildDelegationError).reason).toBe("delegation_not_permitted");
    expect((caught as Error).message).toMatch(
      new RegExp(`descends from standing-payment instance ${mission.id}`),
    );
  });

  it("admits an expansion successor of a standing-payment instance that keeps its max_budget, in the same standing-payment lineage (#813)", () => {
    const t = consentTo();
    const { mission } = dispatch(t.id);
    const { successor } = createExpansion(kernel, {
      predecessorId: mission.id,
      intent: intentWith(),
      approver: { iss: ISS, sub: "human-approver" },
      approvalEventId: `exp-${seq++}`,
      approvedUntil: "2027-01-01T00:00:00Z",
    });
    expect(successor.state).toBe("active");
    expect(standingPaymentRootOf(kernel, successor)?.mission_id).toBe(mission.id);
  });

  it("refuses an expansion successor of a standing-payment instance that changes or drops its max_budget (#813)", () => {
    const t = consentTo();
    const { mission } = dispatch(t.id);
    for (const cap of [{ amount: "900.00", currency: "USD" }, null]) {
      expect(() =>
        createExpansion(kernel, {
          predecessorId: mission.id,
          intent: intentWith(cap),
          approver: { iss: ISS, sub: "human-approver" },
          approvalEventId: `exp-${seq++}`,
          approvedUntil: "2027-01-01T00:00:00Z",
        }),
      ).toThrow(
        `a successor of standing-payment instance ${mission.id} keeps its max_budget of 1000.00 USD`,
      );
    }
  });
});

describe("standing-payment derivations refused (@spec mission-template#prohibited-classes, #813 ruling 3)", () => {
  const RAS = "https://ras.test";

  it("refuses a cross-domain grant from a standing-payment instance (#813)", async () => {
    const t = consentTo();
    const { mission } = dispatch(t.id);
    await expect(
      issueCrossDomainGrant(kernel, key, "as-token", {
        missionId: mission.id,
        targetAs: RAS,
        clientId: "worker",
        cnfJkt: "jkt-1",
        resourceToAs: () => RAS,
      }),
    ).rejects.toThrow(
      new StandingPaymentLineageError(
        `mission ${mission.id} descends from standing-payment instance ${mission.id}; a cross-domain grant would not share its budget accounting, so it is refused (#813)`,
      ),
    );
  });

  it("refuses a cross-domain grant from an expansion successor of a standing-payment instance, through its lineage (#813)", async () => {
    const t = consentTo();
    const { mission } = dispatch(t.id);
    const { successor } = createExpansion(kernel, {
      predecessorId: mission.id,
      intent: intentWith(),
      approver: { iss: ISS, sub: "human-approver" },
      approvalEventId: `exp-${seq++}`,
      approvedUntil: "2027-01-01T00:00:00Z",
    });
    await expect(
      issueCrossDomainGrant(kernel, key, "as-token", {
        missionId: successor.id,
        targetAs: RAS,
        clientId: "worker",
        cnfJkt: "jkt-2",
        resourceToAs: () => RAS,
      }),
    ).rejects.toThrow(
      `mission ${successor.id} descends from standing-payment instance ${mission.id}`,
    );
  });

  it("refuses a cross-organization delegation root from a standing-payment instance (#813)", async () => {
    const t = consentTo();
    const { mission } = dispatch(t.id);
    const cnfJwk = await exportJWK(
      (await generateKeyPair("ES256", { extractable: true })).publicKey,
    );
    await expect(
      deriveCrossOrgRoot(kernel, key, "as-token", {
        missionId: mission.id,
        aud: RESOURCE,
        clientId: "worker",
        cnfJwk,
        actor: { iss: "https://id.example", sub: "wl-worker" },
        mappingVersion: "map-1",
      }),
    ).rejects.toThrow(
      new StandingPaymentLineageError(
        `mission ${mission.id} descends from standing-payment instance ${mission.id}; a cross-organization delegation root would not share its budget accounting, so it is refused (#813)`,
      ),
    );
  });

  it("refuses an attenuation root, the offline delegation carrier, from a standing-payment instance (#813)", async () => {
    const t = consentTo();
    const { mission } = dispatch(t.id);
    await expect(
      deriveAttenuationRoot(kernel, key, "as-token", {
        missionId: mission.id,
        aud: RESOURCE,
        clientId: "worker",
        cnfJkt: "jkt-3",
      }),
    ).rejects.toThrow(
      new StandingPaymentLineageError(
        `mission ${mission.id} descends from standing-payment instance ${mission.id}; an attenuation root would not share its budget accounting, so it is refused (#813)`,
      ),
    );
  });
});

describe("standing-payment dispatch accounting (@spec mission-template#dispatch, #813)", () => {
  it("refuses max_active_exceeded once the template's active instances reach max_active, counting only committed instances (#813)", () => {
    const t = consentTo({ max_active: 2 });
    const a = dispatch(t.id).mission;
    const b = dispatch(t.id).mission;
    const r = refusal(() => dispatch(t.id));
    expect(r.reason).toBe("max_active_exceeded");
    expect(kernel.standingPayments.dispatchedInstances(t.id).sort()).toEqual([a.id, b.id].sort());
  });

  it("refuses rate_exceeded past the dispatch rate, counted in the kernel database (#813)", () => {
    const t = consentTo({ rate_per_min: 1, max_active: 3 });
    dispatch(t.id);
    const r = refusal(() => dispatch(t.id));
    expect(r.reason).toBe("rate_exceeded");
    expect(kernel.standingPayments.dispatchedInstances(t.id)).toHaveLength(1);
  });

  it("leaves no dispatch accounting row when the instance insert fails inside the creation transaction (#813)", () => {
    const t = consentTo();
    vi.spyOn(kernel, "insertRecord").mockImplementationOnce(() => {
      throw new Error("crash during the instance insert");
    });
    expect(() => dispatch(t.id)).toThrow("crash during the instance insert");
    expect(kernel.standingPayments.dispatchedInstances(t.id)).toEqual([]);
  });

  it("leaves no instance when the dispatch accounting write fails inside the creation transaction (#813)", () => {
    const t = consentTo();
    const before = missionCount();
    vi.spyOn(kernel.standingPayments, "recordDispatchInCallerTx").mockImplementationOnce(() => {
      throw new Error("crash during the accounting write");
    });
    expect(() => dispatch(t.id)).toThrow("crash during the accounting write");
    expect(missionCount()).toBe(before);
  });

  it("rolls back the instance and its dispatch accounting together when recording the admission fails (#813)", () => {
    const t = consentTo();
    const before = missionCount();
    vi.spyOn(kernel.standingPayments, "recordAdmissionInCallerTx").mockImplementationOnce(() => {
      throw new Error("crash after the instance insert");
    });
    expect(() => dispatch(t.id)).toThrow("crash after the instance insert");
    expect(missionCount()).toBe(before);
    expect(kernel.standingPayments.dispatchedInstances(t.id)).toEqual([]);
  });
});

describe("standing-payment recency boundary (@spec approval-governance#recency-evaluation, #1546, #813)", () => {
  it("admits a dispatch at exactly the class-named exception's maximum age of the template consent (#813)", () => {
    const t = consentTo();
    clockMs = T0 + 3600 * 1000;
    const { mission } = dispatch(t.id);
    expect(mission.state).toBe("active");
  });

  it("refuses dispatch_prohibited_class a dispatch one second past the class-named exception's maximum age, committing nothing (#813)", () => {
    const t = consentTo();
    clockMs = T0 + 3601 * 1000;
    const before = missionCount();
    const r = refusal(() => dispatch(t.id));
    expect(r.reason).toBe("dispatch_prohibited_class");
    expect(r.message).toMatch(
      /governance_recency: the template consent is older than the applicable maximum of 3600s/,
    );
    expect(missionCount()).toBe(before);
    expect(kernel.standingPayments.dispatchedInstances(t.id)).toEqual([]);
  });

  it("applies the default recency ceiling where it is stricter than the exception, at both sides of the boundary (#813)", () => {
    const t = consentTo({ dispatch_policy: { id: "sp-default-stricter", version: "1" } });
    clockMs = T0 + 1800 * 1000;
    expect(dispatch(t.id).mission.state).toBe("active");
    clockMs = T0 + 1801 * 1000;
    const r = refusal(() => dispatch(t.id));
    expect(r.reason).toBe("dispatch_prohibited_class");
    expect(r.message).toMatch(/applicable maximum of 1800s/);
  });
});

/** Rewrite a stored template's columns, as a store written by an earlier build or edited at rest would hold them. */
const tamper = (templateId: string, columns: Record<string, string>) => {
  for (const [column, value] of Object.entries(columns)) {
    store.db.prepare(`UPDATE templates SET ${column} = ? WHERE id = ?`).run(value, templateId);
  }
};

describe("standing-payment dispatch-time re-checks (@spec mission-template#prohibited-classes, #813)", () => {
  it("refuses dispatch_prohibited_class at dispatch when the stored Template Ceiling has lost its per-payment max_amount, committing no instance (#813)", () => {
    const t = consentTo();
    tamper(t.id, {
      ceiling_json: JSON.stringify([paymentEntry({ constraints: { vendors: ["acme"] } })]),
    });
    const before = missionCount();
    const r = refusal(() => dispatch(t.id));
    expect(r.reason).toBe("dispatch_prohibited_class");
    expect(r.message).toBe(
      "the Template Ceiling: entry 0 names payments:payment.execute with no per-payment max_amount",
    );
    expect(missionCount()).toBe(before);
  });

  it("refuses dispatch_prohibited_class at dispatch when the stored Template Ceiling bounds the payment in a currency other than the budget's, committing no instance (#813)", () => {
    // A derivation policy bounding the payment in EUR, so the instance keeps
    // the stored ceiling's EUR bound through the double intersection.
    const euro = structuredClone(DERIVATION_POLICY) as {
      ceiling: Array<{
        actions: string[];
        constraints?: { max_amount?: { amount: string; currency: string } };
      }>;
    };
    for (const entry of euro.ceiling) {
      if (entry.actions.includes(STANDING_PAYMENT_OPERATION) && entry.constraints?.max_amount) {
        entry.constraints.max_amount = { amount: "500.00", currency: "EUR" };
      }
    }
    kernel = new MissionKernel({
      issuer: ISS,
      policy: euro as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(euro.ceiling, CLIENTS, [
        "human-approver",
        "worker",
        "orchestrator",
      ]),
      statusKey: key,
      statusKid: "as-status",
      now,
    });
    const t = consentTo();
    tamper(t.id, {
      ceiling_json: JSON.stringify([
        paymentEntry({
          constraints: { max_amount: { amount: "500.00", currency: "EUR" }, vendors: ["acme"] },
        }),
      ]),
    });
    const before = missionCount();
    const r = refusal(() => dispatch(t.id));
    expect(r.reason).toBe("dispatch_prohibited_class");
    expect(r.message).toBe(
      "the Template Ceiling: entry 0 bounds payments:payment.execute in EUR, not USD",
    );
    expect(missionCount()).toBe(before);
  });

  it("refuses dispatch_prohibited_class at dispatch when the stored Template Ceiling names a vendor the policy commits no destination for, committing no instance (#813)", () => {
    const t = consentTo();
    tamper(t.id, {
      ceiling_json: JSON.stringify([
        paymentEntry({
          constraints: {
            max_amount: { amount: "500.00", currency: "USD" },
            vendors: ["acme", "globex"],
          },
        }),
      ]),
    });
    const before = missionCount();
    const r = refusal(() => dispatch(t.id));
    expect(r.reason).toBe("dispatch_prohibited_class");
    expect(r.message).toBe(
      "the Template Ceiling: entry 0 names vendor globex, which the Dispatch Policy commits no destination for",
    );
    expect(missionCount()).toBe(before);
  });

  it("refuses dispatch_prohibited_class at dispatch a template whose committed Dispatch Policy commits no destination, created before the capability (#813)", () => {
    const t = createTemplate(
      store,
      body({ dispatch_policy: { id: "sp-no-destinations", version: "1" } }),
      {
        ...kernel.authoritySourceOptions(),
        dispatchPolicies: REGISTRY,
      },
    );
    tamper(t.id, { consent_provenance_json: JSON.stringify(humanConsent()) });
    const r = refusal(() => dispatch(t.id));
    expect(r.reason).toBe("dispatch_prohibited_class");
    expect(r.message).toBe(
      `template ${t.id} dispatch policy sp-no-destinations states unusable standing-payment terms: standing_payment: destinations commits no beneficiary: it is a non-empty object of vendor_id to payee_account`,
    );
  });

  it("refuses dispatch_prohibited_class at dispatch a template whose committed Dispatch Policy's budget omits its limit, created before the capability (#813, D877)", () => {
    const t = createTemplate(store, body({ dispatch_policy: { id: "sp-budget-no-limit", version: "1" } }), {
      ...kernel.authoritySourceOptions(),
      dispatchPolicies: REGISTRY,
    });
    tamper(t.id, { consent_provenance_json: JSON.stringify(humanConsent()) });
    const r = refusal(() => dispatch(t.id));
    expect(r.reason).toBe("dispatch_prohibited_class");
    expect(r.message).toBe(
      `template ${t.id} dispatch policy sp-budget-no-limit states unusable standing-payment terms: standing_payment: budget is not {owner, id, currency, limit, per_instance_max}`,
    );
  });

  it("refuses dispatch_prohibited_class a standing payment whose authority would also carry payments:payment.reverse, an irreversible operation the exception does not designate (#813, D877)", () => {
    // A derivation policy that grants the reversal beside the payment, so the
    // instance keeps it through the double intersection.
    const withReverse = structuredClone(DERIVATION_POLICY) as { ceiling: Array<{ actions: string[] }> };
    for (const entry of withReverse.ceiling) {
      if (entry.actions.includes(STANDING_PAYMENT_OPERATION)) entry.actions.push("payments:payment.reverse");
    }
    kernel = new MissionKernel({
      issuer: ISS,
      policy: withReverse as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(withReverse.ceiling, CLIENTS, ["human-approver", "worker", "orchestrator"]),
      statusKey: key,
      statusKid: "as-status",
      now,
    });
    const t = consentTo({ ceiling: [paymentEntry({ actions: [STANDING_PAYMENT_OPERATION, "payments:payment.reverse"] })] });
    const before = missionCount();
    const r = refusal(() =>
      dispatch(t.id, {}, mappingOf({ classes: { ...CLASSES, "payments:payment.reverse": ["irreversible_action"] } })),
    );
    expect(r.reason).toBe("dispatch_prohibited_class");
    expect(r.message).toBe("payments:payment.reverse is a dispatch-prohibited action no standing payment waives");
    expect(missionCount()).toBe(before);
  });

  it("refuses dispatch_prohibited_class at dispatch a template whose stored approver of record is its Dispatcher (#813)", () => {
    const t = consentTo();
    tamper(t.id, {
      approver_sub: "orchestrator",
      consent_provenance_json: JSON.stringify(humanConsent("orchestrator")),
    });
    const r = refusal(() => dispatch(t.id));
    expect(r.reason).toBe("dispatch_prohibited_class");
    expect(r.message).toBe(
      `template ${t.id} was consented by a Dispatcher or an Agent, not a human`,
    );
  });

  it("refuses dispatch_prohibited_class at dispatch a template whose stored approver of record is the instance's Agent, committing no instance (#813)", () => {
    const t = consentTo();
    tamper(t.id, {
      approver_sub: "worker",
      consent_provenance_json: JSON.stringify(humanConsent("worker")),
    });
    const before = missionCount();
    const r = refusal(() => dispatch(t.id));
    expect(r.reason).toBe("dispatch_prohibited_class");
    expect(r.message).toBe(
      `template ${t.id} was consented by a Dispatcher or an Agent, not a human`,
    );
    expect(missionCount()).toBe(before);
  });
});

describe("standing-payment budget commitment (@spec mission-template#prohibited-classes, #813 ruling 1)", () => {
  for (const member of ["owner", "id", "currency", "limit", "per_instance_max"] as const) {
    it(`refuses a Dispatch Policy whose budget omits ${member} (#813)`, () => {
      const { [member]: _omitted, ...budget } = TERMS.budget;
      const id = `sp-budget-without-${member}`;
      const policies = { ...REGISTRY, [id]: spPolicy(id, { ...TERMS, budget }) };
      expect(() => consentTo({ dispatch_policy: { id, version: "1" } }, { policies })).toThrow(
        `dispatch_policy ${id}: standing_payment: budget is not {owner, id, currency, limit, per_instance_max}`,
      );
    });
  }
});
