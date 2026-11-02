/**
 * @spec runtime#classification (#1735, #1994), runtime-evidence#decision-evidence-object
 * `action_classes`
 *
 * An action that satisfies more than one class predicate takes the
 * requirements of every such class: classification under one class waives
 * none that another applicable predicate imposes. Comparable bounds resolve
 * to the tighter; a duty any applicable class carries applies, and the action
 * is refused when it cannot satisfy every one; an exemption stated for one
 * class relieves only what it names. The PDP computes the class set from its
 * own operation declarations: `payments:remittance.send` is assigned
 * `external_commitment` (the class the PEP sends) and the shipped statement
 * declares `irreversible_action` beside it.
 *
 * The clock is fixed at one instant (D1091), and no OpenFGA is needed: the
 * authority check is stubbed to allow, so each assertion is the class rule's.
 */

import { generateKeyPairSync } from "node:crypto";
import { pinnedToCurrentContract, RUNTIME_SCOPE_CONFIG } from "@mission/demo-data";
import { describe, expect, it } from "vitest";
import type { Fga } from "../src/fga.js";
import {
  applicableActionClasses,
  createDecisionEvidenceEmitter,
  type DecisionEvidenceObject,
  evaluate,
  type EvaluateOptions,
  type EvaluationRequest,
  executionLeaseMaxSecondsOver,
  loadRuntimePosture,
  type MissionView,
  relationForAction,
  RUNTIME_POSTURE,
  stalenessBound,
} from "../src/index.js";
import {
  EVALUATION_CONTEXT_UNCLAIMED_FIXTURE,
  RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
  withCurrentContractReference,
} from "../src/test-support.js";
import { freshKey, openTestClaims } from "./claim-fixture.js";
import { withCredential } from "./with-credential.js";

const RESOURCE = "http://localhost:4403/mcp";
const ISSUER = "https://as.test";
const NOW = new Date("2026-09-14T12:00:00Z");
const allowFga = { checkWithContext: async () => true } as unknown as Fga;
const REMIT = "payments:remittance.send";
const READ = "payments:invoice.read";

const view = (actions: string[]): MissionView => ({
  id: "msn_multi_1",
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:testhash",
  authority_set: [pinnedToCurrentContract({ type: "mission_resource_access" as const, resource: RESOURCE, actions })],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
});

/** A request as the payments PEP sends it, with its state observation `ageSeconds` old. */
const request = (action: string, actionClass: string, ageSeconds: number, extra: Record<string, unknown> = {}): EvaluationRequest =>
  withCredential(withCurrentContractReference({
    subject: { id: "alice" },
    resource: { type: "invoice", id: "inv-1", properties: { audience: RESOURCE, operation_target: RESOURCE, vendor_id: "acme" } },
    // @spec runtime#idempotency (#917): a high-consequence permit is claimed
    // first, under the request's key.
    action: { name: action, ...(action === REMIT ? { properties: { idempotency_key: freshKey() } } : {}) },
    context: {
      mission: { id: "msn_multi_1", issuer: ISSUER, authority_hash: "sha-256:testhash" },
      action_class: actionClass,
      mission_state_observation: {
        state: "active",
        mode: "fresh",
        freshness_at: new Date(NOW.getTime() - ageSeconds * 1000).toISOString(),
      },
      ...extra,
    },
  } as EvaluationRequest));

function emitter() {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return createDecisionEvidenceEmitter({ signer: { kid: "multi-class-test", key: privateKey }, emitterId: RESOURCE, audience: RESOURCE });
}

const options = (actions: string[], over: Partial<EvaluateOptions> = {}): EvaluateOptions =>
  ({
    view: view(actions),
    fga: allowFga,
    modelId: "multi-class-test-model",
    now: () => NOW,
    stalenessBound,
    relationForAction,
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
    evaluationContextBinding: EVALUATION_CONTEXT_UNCLAIMED_FIXTURE,
    stateSourcePlacement: "pep",
    claims: openTestClaims({ now: () => NOW }),
    ...over,
  }) as EvaluateOptions;

const AMOUNT = { amount: { amount: "125.00", currency: "USD" }, parameter_digest: "sha-256:remit-pd" };

describe("an action several class predicates apply to takes every applicable class's requirements (@spec runtime#classification, #1735, #1994)", () => {
  it("declares remittance.send under external_commitment and irreversible_action, and payment.execute's commit phase under its own class alone", () => {
    expect(applicableActionClasses(RUNTIME_POSTURE, "external_commitment", REMIT)).toEqual([
      "external_commitment",
      "irreversible_action",
    ]);
    expect(applicableActionClasses(RUNTIME_POSTURE, "irreversible_action", "payments:payment.execute", "commit")).toEqual([
      "irreversible_action",
    ]);
  });

  it("refuses remittance.send on a 45-second-old observation: the irreversible class's 30-second bound applies, although 60 seconds is the external-commitment bound", async () => {
    const decision = await evaluate(request(REMIT, "external_commitment", 45, AMOUNT), options([REMIT], { evidence: emitter() }));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("stale_state");
    const record = decision.context.decision_evidence as DecisionEvidenceObject;
    expect(record.action_class).toBe("external_commitment");
    expect(record.action_classes).toEqual(["external_commitment", "irreversible_action"]);
  });

  it("caps a fresh remittance permit at the tighter window: valid 30 seconds past the observation, not the external-commitment 60, single use, with every applied class recorded", async () => {
    const decision = await evaluate(request(REMIT, "external_commitment", 0, AMOUNT), options([REMIT], { evidence: emitter() }));
    expect(decision.decision).toBe(true);
    const conditions = decision.context.conditions as { valid_until: string; use_limit?: number };
    expect(Date.parse(conditions.valid_until)).toBe(NOW.getTime() + 30_000);
    expect(conditions.use_limit).toBe(1);
    const record = decision.context.decision_evidence as DecisionEvidenceObject;
    expect(record.decision).toBe("permit");
    expect(record.action_classes).toEqual(["external_commitment", "irreversible_action"]);
  });

  it("requires the action-bound approval a further class carries, which the assigned class alone would not", async () => {
    const approvalFor = (cls: string) => (_action: string, c: string | undefined) => c === cls;
    const further = await evaluate(
      request(REMIT, "external_commitment", 0, AMOUNT),
      options([REMIT], { requiresActionApproval: approvalFor("irreversible_action") }),
    );
    expect(further.decision).toBe(false);
    expect(further.context.denial_reason).toBe("action_approval_required");
    const unrelated = await evaluate(
      request(REMIT, "external_commitment", 0, AMOUNT),
      options([REMIT], { requiresActionApproval: approvalFor("privileged_administration") }),
    );
    expect(unrelated.decision).toBe(true);
  });

  it("refuses when a non-comparable duty of a further class is unmet: work-item attribution claimed for irreversible_action", async () => {
    const claimed = { workItemAttributedClasses: new Set(["irreversible_action"]) };
    const missing = await evaluate(request(REMIT, "external_commitment", 0, AMOUNT), options([REMIT], claimed));
    expect(missing.decision).toBe(false);
    expect(missing.context.denial_reason).toBe("work_item_context_missing");
    const attributed = await evaluate(
      request(REMIT, "external_commitment", 0, { ...AMOUNT, work_item: { issuer: "https://harness.test", id: "work-1" } }),
      options([REMIT], claimed),
    );
    expect(attributed.decision).toBe(true);
  });

  it("an exemption stated for one class relieves only what it names: audit_only's no-freshness posture does not relieve a further write class's bound", async () => {
    const withWrite = { actionClassesFor: (_a: string, assigned: string) => (assigned === "audit_only" ? ["consequential_write"] : []) };
    const exemptOnly = await evaluate(request(READ, "audit_only", 3600), options([READ]));
    expect(exemptOnly.decision).toBe(true);
    const alsoWrite = await evaluate(request(READ, "audit_only", 3600), options([READ], withWrite));
    expect(alsoWrite.decision).toBe(false);
    expect(alsoWrite.context.denial_reason).toBe("stale_state");
  });

  it("omits action_classes on a decision only one class applies to", async () => {
    const decision = await evaluate(request(READ, "consequential_read", 0), options([READ], { evidence: emitter() }));
    expect(decision.decision).toBe(true);
    const record = decision.context.decision_evidence as DecisionEvidenceObject;
    expect(record.action_class).toBe("consequential_read");
    expect(record).not.toHaveProperty("action_classes");
  });

  it("takes the tightest published execution lease across the classes that apply", () => {
    const statement = structuredClone(RUNTIME_SCOPE_CONFIG) as {
      extensions: { transaction_assurance: Array<{ mediated_class_or_scope: string; execution_lease_max_seconds: number }> };
    };
    const external = statement.extensions.transaction_assurance.find((d) => d.mediated_class_or_scope === "external_commitment");
    if (!external) throw new Error("fixture: no external_commitment declaration");
    external.execution_lease_max_seconds = 60;
    const posture = loadRuntimePosture(statement);
    expect(executionLeaseMaxSecondsOver(posture, ["external_commitment"])).toBe(60);
    expect(executionLeaseMaxSecondsOver(posture, applicableActionClasses(posture, "external_commitment", REMIT))).toBe(30);
  });
});
