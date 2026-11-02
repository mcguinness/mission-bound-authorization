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
  channelDeadlineMs,
  createDecisionEvidenceEmitter,
  DecisionRequestRefused,
  type ExecutionCapabilityDeclaration,
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
    // A PDP-side declaration bound directly: the shipped loader admits further
    // classes only among the high-consequence ones, but the PDP rule holds for
    // any set its declarations name.
    const withWrite = {
      operationDeclarations: [
        { operation: READ, action_class: "audit_only", additional_action_classes: ["consequential_write"] } as unknown as ExecutionCapabilityDeclaration,
      ],
    };
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

describe("the class set comes from this PDP's own declarations (@spec runtime#classification, authzen#context-action-phase, #1994 cold read)", () => {
  it("takes the declaration's own class beside a mislabeled assignment: remittance.send labeled consequential_write still takes external_commitment and irreversible_action, and is refused at 45 seconds", async () => {
    const decision = await evaluate(request(REMIT, "consequential_write", 45, AMOUNT), options([REMIT], { evidence: emitter() }));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("stale_state");
    const record = decision.context.decision_evidence as DecisionEvidenceObject;
    expect(record.action_class).toBe("consequential_write");
    expect(record.action_classes).toEqual(["consequential_write", "external_commitment", "irreversible_action"]);
  });

  it("refuses phase_invalid, before evaluation, a phase on remittance.send, which the declarations name without one; an undeclared phase of a compound action still decides", async () => {
    const refusal = await evaluate(
      request(REMIT, "external_commitment", 0, { ...AMOUNT, action_phase: "commit" }),
      options([REMIT]),
    ).then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(refusal).toBeInstanceOf(DecisionRequestRefused);
    expect((refusal as DecisionRequestRefused).denial_reason).toBe("phase_invalid");
    const preflight = await evaluate(
      request("payments:payment.execute", "consequential_read", 0, { action_phase: "preflight" }),
      options(["payments:payment.execute"]),
    );
    expect(preflight.context).toHaveProperty("decision_id");
  });

  it("refuses at load a further class beside an assigned class that is not high-consequence, and a further class that is not", () => {
    type Entry = { operation: string; action_class: string; additional_action_classes?: string[] };
    const withFurther = (operation: string, further: string[]) => {
      const statement = structuredClone(RUNTIME_SCOPE_CONFIG) as { extensions: { execution_capabilities: Entry[] } };
      const entry = statement.extensions.execution_capabilities.find((d) => d.operation === operation);
      if (!entry) throw new Error(`fixture: no declaration for ${operation}`);
      entry.additional_action_classes = further;
      return statement;
    };
    expect(() => loadRuntimePosture(withFurther("payments:payment.schedule", ["irreversible_action"]))).toThrow(
      "high-consequence",
    );
    expect(() => loadRuntimePosture(withFurther(REMIT, ["consequential_write"]))).toThrow("high-consequence");
    expect(() => loadRuntimePosture(withFurther(REMIT, ["irreversible_action"]))).not.toThrow();
  });

  it("refuses at load a compound operation whose declared phases carry different further classes; a phased operation every declared phase of which carries the same set loads", () => {
    type Entry = { operation: string; phase?: string; action_class: string; additional_action_classes?: string[] };
    const withFurther = (operation: string, phase: string, further: string[]) => {
      const statement = structuredClone(RUNTIME_SCOPE_CONFIG) as { extensions: { execution_capabilities: Entry[] } };
      const entry = statement.extensions.execution_capabilities.find((d) => d.operation === operation && d.phase === phase);
      if (!entry) throw new Error(`fixture: no declaration for ${operation} ${phase}`);
      entry.additional_action_classes = further;
      return statement;
    };
    expect(() => loadRuntimePosture(withFurther("payments:payment.execute", "commit", ["external_commitment"]))).toThrow(
      "every declared phase of a compound operation carries the same further classes",
    );
    expect(() => loadRuntimePosture(withFurther("payments:payment.reverse", "compensate", ["external_commitment"]))).not.toThrow();
  });

  it("refuses phase_invalid, before evaluation, a phase a compound operation with further classes does not declare, or no phase; a declared phase decides", async () => {
    const PAY = "payments:payment.execute";
    const declarations = {
      operationDeclarations: [
        {
          operation: PAY,
          phase: "commit",
          action_class: "irreversible_action",
          additional_action_classes: ["external_commitment"],
        } as unknown as ExecutionCapabilityDeclaration,
      ],
    };
    const refusalOf = (req: EvaluationRequest) =>
      evaluate(req, options([PAY], declarations)).then(
        () => undefined,
        (e: unknown) => e,
      );
    for (const extra of [{ action_phase: "preflight" }, {}]) {
      const refusal = await refusalOf(request(PAY, "consequential_read", 0, extra));
      expect(refusal, JSON.stringify(extra)).toBeInstanceOf(DecisionRequestRefused);
      expect((refusal as DecisionRequestRefused).denial_reason).toBe("phase_invalid");
    }
    const declared = await evaluate(request(PAY, "irreversible_action", 0, { action_phase: "commit" }), options([PAY], declarations));
    expect(declared.context).toHaveProperty("decision_id");
  });

  it("bounds the remote decision call by the tightest window across the set: 30 seconds for remittance.send, 60 for external_commitment alone", () => {
    expect(channelDeadlineMs("external_commitment", 120_000, REMIT)).toBe(30_000);
    expect(channelDeadlineMs("external_commitment", 120_000)).toBe(60_000);
  });

  it("issues the irreversible class's 120-second permit lifetime to a remittance, where no staleness window caps it below", async () => {
    const wide = { stalenessBound: () => ({ kind: "bounded" as const, seconds: 600 }) };
    const remit = await evaluate(request(REMIT, "external_commitment", 0, AMOUNT), options([REMIT], wide));
    expect(remit.decision).toBe(true);
    expect(Date.parse((remit.context.conditions as { valid_until: string }).valid_until)).toBe(NOW.getTime() + 120_000);
    const alone = await evaluate(
      request(REMIT, "external_commitment", 0, AMOUNT),
      options([REMIT], { ...wide, operationDeclarations: [] }),
    );
    expect(alone.decision).toBe(true);
    expect(Date.parse((alone.context.conditions as { valid_until: string }).valid_until)).toBe(NOW.getTime() + 300_000);
  });
});
