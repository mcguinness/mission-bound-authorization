/**
 * @spec authzen#context-work-item, authzen#decision-conditions `work_item`,
 * authzen#projections, runtime-evidence#evidence-extensions `work_item`,
 * harness#work-item-identity (#815): the qualified work-item identifier at
 * the PDP.
 *
 * A malformed `context.work_item` is an unusable input, refused before
 * evaluation in any class as `work_item_invalid` (a Refusal Record, no
 * decision, no Decision Evidence); an absent one is the evaluated denial
 * `work_item_context_missing`, only in a class the PDP's own statement claims
 * work-item attribution for. A present, well-formed one is
 * bound into the permit's `work_item` condition and recorded on Decision
 * Evidence, and it is part of the authorization binding and the cache key, so
 * a retransmission never hands one work item's permit to another.
 *
 * Unconditional: the FGA layer is a stub that always permits, and the claim
 * domain is a real SQLite file in a fresh temporary directory.
 */

import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  createDecisionEvidenceEmitter,
  type DecisionEvidenceEmitter,
  type DecisionEvidenceObject,
  evaluationRequestDigest,
} from "../src/decision-evidence.js";
import { createDecisionPoint } from "../src/decision-point.js";
import {
  type Decision,
  type DecisionOptions,
  DecisionRequestRefused,
  evaluate as evaluateRequest,
  type EvaluateOptions,
  type EvaluationRequest,
  type PdpRefusal,
} from "../src/evaluate.js";
import { createPdpRefusalRecorder, type PdpRefusalRecord } from "../src/refusal-record.js";
import { type EvidenceKeyResolver, REFUSAL_RECORD_MEDIA_TYPE, verifyEvidenceEnvelope } from "../src/runtime-evidence-integrity.js";
import type { Fga } from "../src/fga.js";
import { type ConsumptionStatusFn, type IdempotencyClaimDomain, openIdempotencyClaimDomain } from "../src/idempotency-claims.js";
import { MISSION_RESOURCE_ACCESS_TYPE, type MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBound } from "../src/policy.js";
import { decisionCacheKey } from "../src/projections.js";
import { RUNTIME_POSTURE } from "../src/runtime-posture.js";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "../src/test-support.js";
import { readWorkItemAttribution, WORK_ITEM_ATTRIBUTION_EXTENSION } from "../src/work-item.js";
import { CLAIM_OWNER, freshKey } from "./claim-fixture.js";
import { withCredential } from "./with-credential.js";

const evaluate = (req: EvaluationRequest, opts: EvaluateOptions) => evaluateRequest(withCredential(req), opts);

const RESOURCE = "http://localhost:4403/mcp";
const ISSUER = "https://as.test";
const HARNESS = "https://harness.example.com";
const NOW = new Date("2026-10-25T12:00:00Z");
const W1 = { issuer: HARNESS, id: "work-1" };
const W2 = { issuer: HARNESS, id: "work-2" };
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const evidenceKey = generateKeyPairSync("ec", { namedCurve: "P-256" });
const EMITTER = createDecisionEvidenceEmitter({
  signer: { kid: "pdp-815", key: evidenceKey.privateKey },
  emitterId: RESOURCE,
  audience: RESOURCE,
});

const view: MissionView = {
  id: "msn_815",
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:h815",
  authority_set: [
    {
      type: MISSION_RESOURCE_ACCESS_TYPE,
      resource: RESOURCE,
      actions: ["payments:invoice.read", "payments:payment.execute"],
    },
  ],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
};

/** A consequential read by default; `execute` makes it an irreversible, keyed one. */
function request(o: { workItem?: unknown; execute?: boolean; key?: string } = {}): EvaluationRequest {
  return {
    subject: { id: "alice", properties: { iss: ISSUER } },
    resource: { type: "invoice", id: "inv-1", properties: { audience: RESOURCE, operation_target: RESOURCE, vendor_id: "acme" } },
    action: {
      name: o.execute ? "payments:payment.execute" : "payments:invoice.read",
      ...(o.execute ? { properties: { idempotency_key: o.key ?? freshKey() } } : {}),
    },
    context: {
      mission: { id: view.id, issuer: ISSUER },
      actor: { client_id: "ap-agent" },
      action_class: o.execute ? "irreversible_action" : "consequential_read",
      ...(o.execute ? { parameter_digest: "sha-256:operation-815" } : {}),
      mission_state_observation: { state: "active", mode: "fresh", freshness_at: NOW.toISOString() },
      ...(o.workItem !== undefined ? { work_item: o.workItem } : {}),
    },
  };
}

function options(over: Partial<EvaluateOptions> = {}): EvaluateOptions {
  return {
    view,
    fga: alwaysAllowFga,
    modelId: "model-815",
    now: () => NOW,
    stalenessBound,
    relationForAction,
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
    stateSourcePlacement: "pep",
    evidence: EMITTER,
    ...over,
  };
}

const evidenceOf = (d: Decision) => d.context.decision_evidence as DecisionEvidenceObject | undefined;
const conditionsOf = (d: Decision) => d.context.conditions as Record<string, unknown> | undefined;

describe("the work-item context at the PDP (@spec authzen#context-work-item, #815)", () => {
  it("on a class no statement claims, carries a present work item into the permit's work_item condition and Decision Evidence, and permits without one", async () => {
    const carried = await evaluate(request({ workItem: W1 }), options());
    expect(carried.decision, JSON.stringify(carried.context)).toBe(true);
    expect(conditionsOf(carried)?.work_item).toEqual(W1);
    expect(evidenceOf(carried)?.work_item).toEqual(W1);
    // Recorded once, top-level: the record's normalized conditions do not repeat it.
    expect((evidenceOf(carried)?.conditions as Record<string, unknown> | undefined)?.work_item).toBeUndefined();

    const absent = await evaluate(request(), options());
    expect(absent.decision, JSON.stringify(absent.context)).toBe(true);
    expect(conditionsOf(absent)?.work_item).toBeUndefined();
    expect(evidenceOf(absent)?.work_item).toBeUndefined();
  });

  it("on a class the statement claims work-item attribution for, denies work_item_context_missing with no work item and permits with one", async () => {
    const claimed = options({ workItemAttributedClasses: new Set(["consequential_read"]) });
    const missing = await evaluate(request(), claimed);
    expect(missing.decision).toBe(false);
    expect(missing.context.denial_reason).toBe("work_item_context_missing");
    expect(missing.context.reason).toBe("work_item_context_missing");
    expect(evidenceOf(missing)?.denial_reason).toBe("work_item_context_missing");

    const present = await evaluate(request({ workItem: W1 }), claimed);
    expect(present.decision, JSON.stringify(present.context)).toBe(true);
    expect(conditionsOf(present)?.work_item).toEqual(W1);
  });

  it("refuses a malformed work item before evaluation as work_item_invalid, claimed or not: no decision, no evaluation_id, no Decision Evidence and no FGA check", async () => {
    const malformed: unknown[] = [
      "work-1",
      null,
      { id: "work-1" },
      { issuer: HARNESS },
      { issuer: HARNESS, id: "" },
      { issuer: HARNESS, id: 7 },
      { issuer: HARNESS, id: "work-1", mission: view.id },
      [HARNESS, "work-1"],
    ];
    for (const workItem of malformed) {
      for (const claimed of [undefined, new Set(["consequential_read"])]) {
        const label = `${JSON.stringify(workItem)} claimed=${claimed !== undefined}`;
        const refusals: PdpRefusal[] = [];
        const emitted: unknown[] = [];
        let fgaCalls = 0;
        const req = withCredential(request({ workItem }));
        const outcome = await evaluateRequest(req, {
          ...options(claimed ? { workItemAttributedClasses: claimed } : {}),
          fga: { checkWithContext: async () => (fgaCalls += 1) > 0 } as unknown as Fga,
          evidence: { emit: async (record: unknown) => emitted.push(record) } as unknown as DecisionEvidenceEmitter,
          refusals: (r) => refusals.push(r),
        }).then(
          (decision) => ({ decision }),
          (error: unknown) => ({ error }),
        );
        expect(outcome, label).toEqual({ error: expect.any(DecisionRequestRefused) });
        expect((outcome as { error: DecisionRequestRefused }).error.denial_reason, label).toBe("work_item_invalid");
        expect(refusals.map((r) => r.denial_reason), label).toEqual(["work_item_invalid"]);
        expect(refusals[0]?.evaluation_request, label).toBe(req);
        expect(emitted, label).toHaveLength(0);
        expect(fgaCalls, label).toBe(0);
      }
    }
  });

  it("records the work_item_invalid refusal as a PDP-signed Refusal Record over the request as submitted, with no evaluation_id", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const retained: PdpRefusalRecord[] = [];
    const refusals = createPdpRefusalRecorder({
      signer: { kid: "pdp-815-refusal", key: privateKey },
      emitterId: "pdp.example",
      scope: RESOURCE,
      retain: (record) => retained.push(record),
      now: () => NOW,
    });
    const resolve: EvidenceKeyResolver = ({ kid, emitter }) =>
      kid === "pdp-815-refusal" && emitter.id === "pdp.example" && emitter.role === "pdp" ? { key: publicKey } : undefined;
    const req = withCredential(request({ workItem: { issuer: HARNESS, id: "work-1", extra: "x" } }));
    await expect(evaluateRequest(req, options({ refusals }))).rejects.toBeInstanceOf(DecisionRequestRefused);
    expect(retained).toHaveLength(1);
    expect(retained[0]).toMatchObject({
      audience: RESOURCE,
      action: { name: "payments:invoice.read" },
      decision: "deny",
      denial_reason: "work_item_invalid",
      evaluation_request_digest: evaluationRequestDigest(req),
      request_digest_input: "decision_request",
      emitter: { id: "pdp.example", role: "pdp" },
    });
    expect(retained[0]).not.toHaveProperty("evaluation_id");
    expect(await verifyEvidenceEnvelope(retained[0] as PdpRefusalRecord, REFUSAL_RECORD_MEDIA_TYPE, resolve)).toEqual({ valid: true });
  });

  it("the decision point applies its own claimed classes and strips any an enforcement component supplies", async () => {
    const pointOptions = (over: Record<string, unknown>) =>
      ({
        view,
        fga: alwaysAllowFga,
        modelId: "model-815",
        now: () => NOW,
        stalenessBound,
        relationForAction,
        stateSourcePlacement: "pep",
        ...over,
      }) as unknown as DecisionOptions;
    const claiming = createDecisionPoint({
      resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
      workItemAttributedClasses: new Set(["consequential_read"]),
    });
    const denied = await claiming.decide(withCredential(request()), pointOptions({ workItemAttributedClasses: new Set() }));
    expect(denied.decision).toBe(false);
    expect(denied.context.denial_reason).toBe("work_item_context_missing");

    const notClaiming = createDecisionPoint({ resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE });
    const permitted = await notClaiming.decide(
      withCredential(request()),
      pointOptions({ workItemAttributedClasses: new Set(["consequential_read"]) }),
    );
    expect(permitted.decision, JSON.stringify(permitted.context)).toBe(true);
  });
});

describe("the work item is part of the authorization binding and the cache key (@spec authzen#projections, authzen#context-work-item, #815)", () => {
  it("two requests that differ only in their work item have different cache keys, and an identical one the same", () => {
    const one = decisionCacheKey(request({ workItem: W1 }), view, "model-815");
    expect(decisionCacheKey(request({ workItem: W1 }), view, "model-815")).toBe(one);
    expect(decisionCacheKey(request({ workItem: W2 }), view, "model-815")).not.toBe(one);
    expect(decisionCacheKey(request(), view, "model-815")).not.toBe(one);
  });

  it("a duplicate keyed dispatch of the same work item is the retransmission of its permit, and another work item under the same key never receives it", async () => {
    const file = join(mkdtempSync(join(tmpdir(), "claim-815-")), "claims.sqlite");
    const claims: IdempotencyClaimDomain = openIdempotencyClaimDomain({
      file,
      owner: CLAIM_OWNER,
      statement: RUNTIME_POSTURE as never,
      now: () => NOW,
      settlementKeys: () => undefined,
    });
    const unconsumed: ConsumptionStatusFn = () => "unconsumed";
    const opts = options({ claims, requester: { pep_id: "mcp-payments-pep", pep_epoch: "epoch-815" }, consumptionStatus: unconsumed });
    const key = freshKey();
    const first = await evaluate(request({ execute: true, key, workItem: W1 }), opts);
    expect(first.decision, JSON.stringify(first.context)).toBe(true);
    expect(conditionsOf(first)?.work_item).toEqual(W1);

    // Duplicate dispatch of the same work item: the same permit, same work item.
    const resent = await evaluate(request({ execute: true, key, workItem: W1 }), opts);
    expect(resent.context.evaluation_id).toBe(first.context.evaluation_id);
    expect(conditionsOf(resent)?.work_item).toEqual(W1);

    // Another work item under the same key and operation: never W1's permit.
    const other = await evaluate(request({ execute: true, key, workItem: W2 }), opts);
    expect(other.decision).toBe(false);
    expect(other.context.evaluation_id).not.toBe(first.context.evaluation_id);
    expect(other.context.denial_reason).toBe("duplicate_suppressed");
    expect(conditionsOf(other)).toBeUndefined();
    claims.close();
  });
});

describe("the statement's work-item declaration (@spec harness#work-item-identity, #815)", () => {
  const claiming = (decl: Record<string, unknown>, claimed = true) => {
    const stmt = structuredClone(RUNTIME_POSTURE) as unknown as Record<string, unknown> & { extensions: Record<string, unknown> };
    if (claimed) stmt.claims = [WORK_ITEM_ATTRIBUTION_EXTENSION];
    stmt.extensions = { ...stmt.extensions, [WORK_ITEM_ATTRIBUTION_EXTENSION]: decl };
    return stmt;
  };

  it("the shipped statement names no attacher and claims no class", () => {
    const read = readWorkItemAttribution(RUNTIME_POSTURE);
    expect(read.attachers.size).toBe(0);
    expect(read.claimedClasses.size).toBe(0);
  });

  it("a claimed declaration yields its attachers and covered classes; without the claim it names attachers and claims no class", () => {
    const decl = { attachers: [{ client_id: "ap-agent", harness: HARNESS }], covered_classes: ["consequential_read"] };
    const read = readWorkItemAttribution(claiming(decl));
    expect(read.attachers.get("ap-agent")).toBe(HARNESS);
    expect([...read.claimedClasses]).toEqual(["consequential_read"]);
    const unclaimed = readWorkItemAttribution(claiming(decl, false));
    expect(unclaimed.attachers.get("ap-agent")).toBe(HARNESS);
    expect(unclaimed.claimedClasses.size).toBe(0);
  });

  it("refuses a declaration it cannot read in full", () => {
    const bad: Array<Record<string, unknown>> = [
      { attachers: [{ client_id: "ap-agent" }], covered_classes: ["consequential_read"] },
      {
        attachers: [
          { client_id: "ap-agent", harness: HARNESS },
          { client_id: "ap-agent", harness: "https://other.example" },
        ],
        covered_classes: ["consequential_read"],
      },
      { attachers: [{ client_id: "ap-agent", harness: HARNESS }], covered_classes: ["privileged_administration"] },
      { attachers: [], covered_classes: ["consequential_read"] },
      { attachers: [{ client_id: "ap-agent", harness: HARNESS }], covered_classes: [] },
    ];
    for (const decl of bad) expect(() => readWorkItemAttribution(claiming(decl)), JSON.stringify(decl)).toThrow();
    const claimedWithoutDeclaration = structuredClone(RUNTIME_POSTURE) as unknown as Record<string, unknown>;
    claimedWithoutDeclaration.claims = [WORK_ITEM_ATTRIBUTION_EXTENSION];
    expect(() => readWorkItemAttribution(claimedWithoutDeclaration)).toThrow();
  });
});
