import { DERIVATION_POLICY } from "@mission/demo-data";
import { withTransaction } from "@mission/store";
import { type CryptoKey, generateKeyPair } from "jose";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  activateGovernedPolicy,
  type AuthorityEntry,
  createChildMission,
  createTemplate,
  dispatchFromTemplate,
  type DispatchPolicies,
  type GovernedPolicyRoot,
  MissionKernel,
  type MissionRecord,
  recordGovernedPolicyConsent,
  type RegisteredActivationPolicy,
  TemplateStore,
  validateMissionIntent,
} from "../src/index.js";
import { createCeilingDrawdownInCallerTx } from "../src/kernel/progressive.js";
import { aiAgents } from "./actor-profiles.helper.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

/**
 * @spec child-delegation#record-requirements, mission#standing-consent-bases
 * (#1514): a `policy_drawdown` child's `approved_at` is the human approval
 * instant of the root its authority traces to. A `direct` Parent's approval
 * event was that approval; a standing-consent Parent's was an activation, so
 * the child takes the Parent's own `approval_basis.approved_at`, through any
 * number of generations. Each standing consent here is given at T0, and every
 * later activation an hour apart, so an activation instant can never pass for
 * the consent instant.
 */

const ISS = "https://as.test";
const T0 = Date.parse("2026-07-01T00:00:00Z");
const HOUR = 3_600_000;
let clockMs = T0;
const now = () => new Date(clockMs);
const at = (hours: number) => {
  clockMs = T0 + hours * HOUR;
};
const iso = (ms: number) => new Date(ms).toISOString();
const EXP = "2027-01-01T00:00:00Z";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const ACTORS = aiAgents("child-agent", "grandchild-agent");
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

/** A read on the payments resource, restating its constraints; `delegation` when a generation must grant further children. */
const read = (delegation?: Record<string, unknown>): AuthorityEntry[] => [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions: ["payments:invoice.read"],
    constraints: { vendors: ["acme"] },
    ...(delegation ? { delegation: delegation as AuthorityEntry["delegation"] } : {}),
  },
];
const GRANTS = { max_depth: 2, children: { max_children: 5, max_child_depth: 2 } };

const childOf = (kernel: MissionKernel, parent: MissionRecord, actor: string, delegation?: Record<string, unknown>) =>
  createChildMission(kernel, {
    parentId: parent.id,
    intent: intentFor(`child of ${parent.id}`),
    proposedAuthority: read(delegation),
    childActor: { sub: actor, sub_profile: "ai_agent" },
  }).child;

/** The two generations the reference admits below `root` (its hard maximum child depth), an hour apart. */
const generations = (kernel: MissionKernel, root: MissionRecord, startHour: number) => {
  at(startHour);
  const child = childOf(kernel, root, "child-agent", GRANTS);
  at(startHour + 1);
  const grandchild = childOf(kernel, child, "grandchild-agent");
  expect(grandchild.parent?.depth).toBe(2);
  return [child, grandchild];
};

const approvedAtOf = (m: MissionRecord) => (m.approval_basis as { approved_at?: string }).approved_at;

describe("a child's approved_at follows the root its authority traces to (@spec child-delegation#record-requirements, #1514)", () => {
  it("a direct Parent: every generation carries the Parent's approval instant, its approval event", () => {
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
    expect(parent.created_at).toBe(iso(T0));
    const line = generations(kernel, parent, 1);
    for (const m of line) {
      expect(m.approval_basis.type).toBe("policy_drawdown");
      expect(approvedAtOf(m)).toBe(parent.created_at);
    }
    // The second generation onward is a child of a standing-consent Parent: its
    // Parent's activation instant is not the approval it traces to.
    expect(approvedAtOf(line[1] as MissionRecord)).not.toBe((line[0] as MissionRecord).created_at);
  });

  it("a template instance: the child and its descendants carry the template's approval, not the dispatch", () => {
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
      actorProfiles: ACTORS,
      childCreationPolicy: permitAll,
    });
    const store = new TemplateStore(now);
    const template = createTemplate(
      store,
      {
        template_version: "tmpl-v1",
        issuer: ISS,
        approver: { iss: ISS, sub: "human-approver" },
        ceiling: read(GRANTS),
        dispatch_policy: { id: "urn:policy:dispatch", version: "1" },
        dispatchers: ["orchestrator"],
        recipients: { subjects: [{ iss: ISS, sub: "alice" }], agents: ["worker"] },
        per_instance_lifetime_s: 30 * 86400,
        max_active: 50,
        rate_per_min: 50,
        review_cadence_s: 30 * 86400,
        approval_event_id: `tmpl-ev-${seq++}`,
        expires_at: "2026-12-01T00:00:00Z",
      } as never,
      { ...kernel.authoritySourceOptions(), dispatchPolicies: registry },
    );
    at(1);
    const instance = dispatchFromTemplate(kernel, store, {
      templateId: template.id,
      dispatchEventId: `dsp-${seq++}`,
      dispatcher: "orchestrator",
      intent: intentFor("read Acme invoices"),
      subject: { iss: ISS, sub: "alice" },
      policyVersion: DERIVATION_POLICY.policy_version,
      dispatchPolicies: registry,
    }).mission;
    expect(approvedAtOf(instance)).toBe(template.created_at);
    expect(instance.created_at).not.toBe(template.created_at);
    for (const m of generations(kernel, instance, 2)) {
      expect(approvedAtOf(m)).toBe(template.created_at);
    }
  });

  it("a governed_policy activation: the child carries the root consent's approval, not the activation", () => {
    const CLASSIFICATION: GovernedPolicyRoot["classification"] = {
      standard: [
        "payments:invoice.list",
        "payments:invoice.read",
        "payments:vendor.read",
        "payments:payment.schedule",
        "payments:payment.schedule.cancel",
      ],
      irreversible_action: ["payments:payment.execute"],
      external_commitment: ["payments:remittance.send"],
    };
    const root: GovernedPolicyRoot = {
      admits: { clients: ["svc-agent"], subjects: ["svc-reconciler"], authority_sources: ["service_owned"] },
      authority_ceiling: read(GRANTS),
      lifetime: { max_lifetime_s: 30 * 86400 },
      rules: { max_entries: 3 },
      recency: { ceilings: { default: 30 * 86400 }, clock_skew_s: 60 },
      classification: CLASSIFICATION,
    };
    const held = (doc: GovernedPolicyRoot): RegisteredActivationPolicy => ({ version: "1", content_type: "application/json", content: JSON.stringify(doc) });
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
      actorProfiles: ACTORS,
      childCreationPolicy: permitAll,
      governedPolicyApproval: { roots: { "urn:policy:root": held(root) }, approvers: { "urn:policy:root": ["dana"] } },
    });
    const consent = recordGovernedPolicyConsent(kernel, {
      root: { id: "urn:policy:root", version: "1" },
      approver: { iss: ISS, sub: "dana" },
      consentEventId: `gpce-${seq++}`,
    });
    at(1);
    const { mission } = activateGovernedPolicy(kernel, {
      consentId: consent.consent_id,
      approvalEventId: `ape-${seq++}`,
      intent: intentFor("Reconcile Acme invoices"),
      clientId: "svc-agent",
    });
    expect(approvedAtOf(mission)).toBe(iso(T0));
    expect(mission.created_at).toBe(iso(T0 + HOUR));
    for (const m of generations(kernel, mission, 2)) {
      expect(approvedAtOf(m)).toBe(iso(T0));
    }
  });

  it("a ceiling_drawdown successor: the child carries the ceiling consent, not the drawdown", () => {
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
      actorProfiles: ACTORS,
      childCreationPolicy: permitAll,
      activationPolicies: { "drawdown-std": POLICY },
    });
    const ceiling = DERIVATION_POLICY.ceiling.filter((e) => e.resource === RESOURCE) as unknown as AuthorityEntry[];
    const predecessor = kernel.approve({
      intent: intentFor("Read Acme invoices"),
      proposedAuthority: read(GRANTS),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "parent-agent",
      approvalEventId: `pred-${seq++}`,
      ceiling: { authority_ceiling: ceiling, drawdown_policy: { id: "drawdown-std", version: "1" } },
    });
    expect(predecessor.ceiling_consented_at).toBe(iso(T0));
    at(1);
    const successor = withTransaction(kernel.db, () =>
      createCeilingDrawdownInCallerTx(kernel, {
        predecessorId: predecessor.id,
        intent: intentFor("Widen to the invoice list"),
        proposedAuthority: [
          { ...(read(GRANTS)[0] as AuthorityEntry), actions: ["payments:invoice.read", "payments:invoice.list"] },
        ],
        activationActor: { iss: ISS, sub: "parent-agent" },
        policy: { ref: predecessor.drawdown_policy as never, snapshot: POLICY },
        restrictionsAtAdjudication: { containment: 0, discharge: 0 },
      }),
    );
    expect(successor.approval_basis.type).toBe("ceiling_drawdown");
    expect(approvedAtOf(successor)).toBe(iso(T0));
    for (const m of generations(kernel, successor, 2)) {
      expect(approvedAtOf(m)).toBe(iso(T0));
    }
  });
});
