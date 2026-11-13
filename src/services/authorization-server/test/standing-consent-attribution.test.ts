import { DERIVATION_POLICY } from "@mission/demo-data";
import { withTransaction } from "@mission/store";
import { type CryptoKey, generateKeyPair } from "jose";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  activateGovernedPolicy,
  type ApprovalBasis,
  type AuthorityEntry,
  createChildMission,
  createTemplate,
  dispatchFromTemplate,
  type DispatchPolicies,
  type GovernedPolicyRoot,
  governedPolicyConsentDisclosure,
  MissionKernel,
  type MissionRecord,
  recordGovernedPolicyConsent,
  type RegisteredActivationPolicy,
  TemplateStore,
  validateMissionIntent,
} from "../src/index.js";
import { assembledCeilingOffer, createCeilingDrawdownInCallerTx } from "../src/kernel/progressive.js";
import { aiAgents } from "./actor-profiles.helper.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

/**
 * @spec derivation-limits#approval-rendering, approval-governance#standing-consent-bases,
 * mission#record-principal-members (#2065): a Mission created under a
 * standing-consent basis has no human approval, and so no consent rendering,
 * of its own. Its record attributes the only human approval behind it to the
 * standing consent: the basis is the standing-consent type, never `direct`
 * (the basis of a human approval event, whose rendering step approves the
 * Mission); no `human` mechanism decided it; the human of record is the
 * standing consent's Approver, at the consent's instant; the party that
 * triggered it is not that human; and its approval event is its own
 * activation, never the standing approval's.
 *
 * Each standing consent here is given at T0 and each instance is created an
 * hour later, so the instance's creation instant can never pass for the
 * consent instant. Each record is read back from the store.
 */

const ISS = "https://as.test";
const T0 = Date.parse("2026-07-01T00:00:00Z");
const HOUR = 3_600_000;
let clockMs = T0;
const now = () => new Date(clockMs);
const iso = (ms: number) => new Date(ms).toISOString();
const EXP = "2027-01-01T00:00:00Z";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const ACTORS = aiAgents("child-agent");
const permitAll = () => true;

let key: CryptoKey;
let seq = 0;
beforeAll(async () => {
  key = (await generateKeyPair("ES256")).privateKey;
});
beforeEach(() => {
  clockMs = T0;
});

const intentFor = (goal: string) =>
  validateMissionIntent(JSON.stringify({ goal, target_resources: [RESOURCE], expires_at: EXP }), { now: now() });

/** A read on the payments resource, restating its constraints; `delegation` where children are granted. */
const read = (delegation?: Record<string, unknown>): AuthorityEntry[] => [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions: ["payments:invoice.read"],
    constraints: { vendors: ["acme"] },
    ...(delegation ? { delegation: delegation as NonNullable<AuthorityEntry["delegation"]> } : {}),
  },
];
const GRANTS = { max_depth: 2, children: { max_children: 5, max_child_depth: 2 } };

type Principal = { iss: string; sub: string };

/** What the standing consent behind an instance fixed, and who triggered the instance. */
interface StandingConsent {
  type: Exclude<ApprovalBasis["type"], "direct">;
  /** The human who approved the standing consent. */
  approver: Principal;
  /** The instant that human approved it. */
  approvedAt: string;
  /** The approval event of the standing consent itself. */
  approvalEventId: string;
  /** The party that triggered this instance. */
  activationActor: Principal;
  /** The decision mechanism the basis names: none (fixed by its type) or a policy. */
  adjudication: "absent" | "policy";
}

/**
 * The record attributes no human approval, and so no consent rendering, to
 * the instance's own creation: only the standing consent's.
 */
const expectNoOwnApprovalAttributed = (kernel: MissionKernel, id: string, consent: StandingConsent) => {
  const m = kernel.get(id) as MissionRecord;
  const basis = m.approval_basis as ApprovalBasis & {
    approved_at?: string;
    activation_actor?: Principal;
    adjudication?: { kind: string };
  };
  // The instance is created an hour after the standing consent.
  expect(m.created_at).toBe(iso(T0 + HOUR));
  expect(consent.approvedAt).toBe(iso(T0));
  // Not a direct basis: no human approval event, and so no rendering, created this Mission.
  expect(basis.type).toBe(consent.type);
  // No human mechanism decided this instance.
  if (consent.adjudication === "absent") {
    expect(basis).not.toHaveProperty("adjudication");
  } else {
    expect(basis.adjudication?.kind).toBe("policy");
  }
  // The human of record is the standing consent's Approver, at the consent's instant, not this creation's.
  expect(basis.consent_principal).toEqual(consent.approver);
  expect(basis.approved_at).toBe(consent.approvedAt);
  expect(basis.approved_at).not.toBe(m.created_at);
  // The party that triggered this instance is not the consenting human.
  expect(basis.activation_actor).toEqual(consent.activationActor);
  expect(basis.activation_actor).not.toEqual(basis.consent_principal);
  // Its approval event is its own activation, never the standing approval's.
  expect(m.approval_event_id).not.toBe(consent.approvalEventId);
};

describe("a Mission created under a standing consent has no human approval, and so no consent rendering, of its own (#2065; @spec derivation-limits#approval-rendering, approval-governance#standing-consent-bases)", () => {
  it("a template instance: the record attributes the approval to the template's consenting human at the consent instant, triggered by the Dispatcher, under its own dispatch event", () => {
    const registry: DispatchPolicies = {
      "urn:policy:dispatch": { version: "1", content_type: "application/json", content: '{"rule":"within the ceiling"}' },
    };
    const kernel = new MissionKernel({
      issuer: ISS,
      policy: DERIVATION_POLICY as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["worker", "orchestrator"], ["human-approver"]),
      statusKey: key,
      statusKid: "as-status",
      now,
    });
    const store = new TemplateStore(now);
    const template = createTemplate(
      store,
      {
        template_version: "tmpl-v1",
        issuer: ISS,
        approver: { iss: ISS, sub: "human-approver" },
        ceiling: read(),
        dispatch_policy: { id: "urn:policy:dispatch", version: "1" },
        dispatchers: ["orchestrator"],
        recipients: { subjects: [{ iss: ISS, sub: "alice" }], agents: ["worker"] },
        per_instance_lifetime_s: 30 * 86400,
        max_active: 5,
        rate_per_min: 5,
        review_cadence_s: 30 * 86400,
        approval_event_id: `tmpl-ev-${seq++}`,
        expires_at: "2026-12-01T00:00:00Z",
      } as never,
      {
        ...kernel.authoritySourceOptions(),
        dispatchPolicies: registry,
        ceilingChildMaxima: (entries) => kernel.establishedChildMaxima(entries),
      },
    );
    clockMs = T0 + HOUR;
    const instance = dispatchFromTemplate(kernel, store, {
      templateId: template.id,
      dispatchEventId: `dsp-${seq++}`,
      dispatcher: "orchestrator",
      intent: intentFor("read Acme invoices"),
      subject: { iss: ISS, sub: "alice" },
      policyVersion: DERIVATION_POLICY.policy_version,
      dispatchPolicies: registry,
    }).mission;
    expectNoOwnApprovalAttributed(kernel, instance.id, {
      type: "template",
      approver: { iss: ISS, sub: "human-approver" },
      approvedAt: template.created_at,
      approvalEventId: template.approval_event_id,
      activationActor: { iss: ISS, sub: "orchestrator" },
      adjudication: "absent",
    });
  });

  it("a policy_drawdown child: the record attributes the approval to the parent's Approver at the parent's approval instant, triggered by the parent's client, under its own creation event", () => {
    const kernel = new MissionKernel({
      issuer: ISS,
      policy: DERIVATION_POLICY as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["parent-agent"], ["bob"]),
      statusKey: key,
      statusKid: "as-status",
      now,
      actorProfiles: ACTORS,
      childCreationPolicy: permitAll,
    });
    const parent = kernel.approve({
      intent: intentFor("Pay Acme invoices"),
      proposedAuthority: read(GRANTS),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "parent-agent",
      approvalEventId: `apev-${seq++}`,
    });
    clockMs = T0 + HOUR;
    const { child } = createChildMission(kernel, {
      parentId: parent.id,
      intent: intentFor(`child of ${parent.id}`),
      proposedAuthority: read(GRANTS),
      childActor: { sub: "child-agent", sub_profile: "ai_agent" },
    });
    expectNoOwnApprovalAttributed(kernel, child.id, {
      type: "policy_drawdown",
      approver: { iss: ISS, sub: "bob" },
      approvedAt: parent.created_at,
      approvalEventId: parent.approval_event_id,
      activationActor: { iss: ISS, sub: "parent-agent" },
      adjudication: "absent",
    });
  });

  it("a ceiling_drawdown successor: the record attributes the approval to the ceiling's consenting Approver at the ceiling consent instant, decided by the drawdown policy and triggered by the requesting client, under its own event", () => {
    const POLICY: RegisteredActivationPolicy = {
      version: "1",
      content_type: "application/json",
      content: JSON.stringify({ max_added_actions: 1, ceiling_review_cadence_s: 2_592_000 }),
    };
    const kernel = new MissionKernel({
      issuer: ISS,
      policy: DERIVATION_POLICY as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["parent-agent"], ["bob"]),
      statusKey: key,
      statusKid: "as-status",
      now,
      activationPolicies: { "drawdown-std": POLICY },
    });
    const ceiling = DERIVATION_POLICY.ceiling.filter((e) => e.resource === RESOURCE) as unknown as AuthorityEntry[];
    const predecessor = kernel.approve({
      intent: intentFor("Read Acme invoices"),
      proposedAuthority: read(),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "parent-agent",
      approvalEventId: `pred-${seq++}`,
      ceiling: assembledCeilingOffer(
        { authority_ceiling: ceiling, drawdown_policy: { id: "drawdown-std", version: "1" } },
        kernel.resourceContracts(),
      ) as never,
    });
    clockMs = T0 + HOUR;
    const successor = withTransaction(kernel.db, () =>
      createCeilingDrawdownInCallerTx(kernel, {
        predecessorId: predecessor.id,
        intent: intentFor("Widen to the invoice list"),
        proposedAuthority: [
          { ...(read()[0] as AuthorityEntry), actions: ["payments:invoice.read", "payments:invoice.list"] },
        ],
        activationActor: { iss: ISS, sub: "parent-agent" },
        policy: { ref: predecessor.drawdown_policy as never, snapshot: POLICY },
        restrictionsAtAdjudication: { containment: 0, discharge: 0 },
      }),
    );
    expectNoOwnApprovalAttributed(kernel, successor.id, {
      type: "ceiling_drawdown",
      approver: { iss: ISS, sub: "bob" },
      approvedAt: predecessor.ceiling_consented_at as string,
      approvalEventId: predecessor.approval_event_id,
      activationActor: { iss: ISS, sub: "parent-agent" },
      adjudication: "policy",
    });
  });

  it("a governed_policy activation: the record attributes the approval to the root's consenting human at the consent instant, decided by policy and triggered by the requesting client, under its own approval event", () => {
    const root: GovernedPolicyRoot = {
      admits: { clients: ["svc-agent"], subjects: ["svc-reconciler"], authority_sources: ["service_owned"] },
      authority_ceiling: read(),
      lifetime: { max_lifetime_s: 30 * 86400 },
      rules: { max_entries: 3 },
      recency: { ceilings: { default: 30 * 86400 }, clock_skew_s: 60 },
      classification: {
        standard: [
          "payments:invoice.list",
          "payments:invoice.read",
          "payments:vendor.read",
          "payments:payment.schedule",
          "payments:payment.schedule.cancel",
        ],
        irreversible_action: ["payments:payment.execute"],
        external_commitment: ["payments:remittance.send"],
      },
    };
    const held: RegisteredActivationPolicy = { version: "1", content_type: "application/json", content: JSON.stringify(root) };
    const kernel = new MissionKernel({
      issuer: ISS,
      policy: DERIVATION_POLICY as never,
      authoritySourceCatalog: {
        humanPrincipals: ["dana"],
        entries: [
          {
            id: "reconciler",
            type: "service_owned",
            clients: ["svc-agent"],
            subjects: ["svc-reconciler"],
            activators: ["dana"],
            principals: ["svc-reconciler"],
            ceiling: DERIVATION_POLICY.ceiling,
          },
        ],
      } as never,
      statusKey: key,
      statusKid: "as-status",
      now,
      governedPolicyApproval: { roots: { "urn:policy:root": held }, approvers: { "urn:policy:root": ["dana"] } },
    });
    const consent = recordGovernedPolicyConsent(kernel, {
      root: { id: "urn:policy:root", version: "1" },
      approver: { iss: ISS, sub: "dana" },
      consentEventId: `gpce-${seq++}`,
      disclosure: governedPolicyConsentDisclosure(kernel, { id: "urn:policy:root", version: "1" }).commitment,
    });
    clockMs = T0 + HOUR;
    const { mission } = activateGovernedPolicy(kernel, {
      consentId: consent.consent_id,
      approvalEventId: `ape-${seq++}`,
      intent: intentFor("Reconcile Acme invoices"),
      clientId: "svc-agent",
    });
    expectNoOwnApprovalAttributed(kernel, mission.id, {
      type: "governed_policy",
      approver: { iss: ISS, sub: "dana" },
      approvedAt: consent.approved_at,
      approvalEventId: consent.consent_event_id,
      activationActor: { iss: ISS, sub: "svc-agent" },
      adjudication: "policy",
    });
  });
});
