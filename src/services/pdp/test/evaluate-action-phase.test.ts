/**
 * @spec authzen#context-action-phase, authzen#failure-condition-coverage,
 * runtime-evidence#pre-decision-refusal (#1629, D744): "The PDP MUST refuse,
 * before evaluation, a request whose `action_phase` is outside this set, or is
 * absent where its trusted operation declaration requires a phase". The
 * refusal is a decision input the PDP cannot use, not an evaluated policy
 * denial: a Refusal Record `phase_invalid`, with no decision, no
 * `evaluation_id` and no Decision Evidence. The trusted declaration is the
 * PDP-side `phasedActions` binding, never a request member or a caller's
 * option.
 *
 * The FGA layer is a counting stub that always permits, so only evaluate()'s
 * own steps and the decision channel decide, and this file never skips.
 */

import { generateKeyPairSync } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { evaluateRemote } from "../src/client.js";
import { createEphemeralDecisionPoint } from "../src/decision-point.js";
import { type DecisionEvidenceEmitter, evaluationRequestDigest } from "../src/decision-evidence.js";
import {
  type DecisionOptions,
  DecisionRequestRefused,
  evaluate as evaluateRequest,
  type EvaluateOptions,
  type EvaluationRequest,
  type PdpRefusal,
} from "../src/evaluate.js";
import type { Fga } from "../src/fga.js";
import { MISSION_RESOURCE_ACCESS_TYPE, type MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBound } from "../src/policy.js";
import { createPdpRefusalRecorder, type PdpRefusalRecord } from "../src/refusal-record.js";
import { type EvidenceKeyResolver, REFUSAL_RECORD_MEDIA_TYPE, verifyEvidenceEnvelope } from "../src/runtime-evidence-integrity.js";
import { createPdpHttpServer, type PdpHttpServerHandle } from "../src/server.js";
import {
  EVALUATION_CONTEXT_UNCLAIMED_FIXTURE,
  RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
  resourcePolicyFixture,
  withCurrentContractReference,
} from "../src/test-support.js";
import { withCredential } from "./with-credential.js";
import { pinnedToCurrentContract } from "@mission/demo-data";

const AUDIENCE = "http://localhost:4403/mcp";
const NOW = new Date("2026-10-23T12:00:00Z");
const PEP_ID = "mcp-payments-pep";
const SECRET = "test-shared-secret-1629";
const PAY = "payments:payment.execute";
const READ = "payments:invoice.read";
/** The trusted operation declaration: the shipped catalog places payments:payment.execute at phases. */
const PHASED = new Set([PAY]);

/** An FGA stub that permits and counts every check, so a refusal before evaluation shows zero. */
function countingFga(): { fga: Fga; calls: () => number } {
  let calls = 0;
  const fga = {
    checkWithContext: async () => {
      calls += 1;
      return true;
    },
  } as unknown as Fga;
  return { fga, calls: () => calls };
}

const view = (): MissionView => ({
  id: "msn_1629",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:h1629",
  authority_set: [pinnedToCurrentContract({ type: MISSION_RESOURCE_ACCESS_TYPE, resource: AUDIENCE, actions: [PAY, READ] })],
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
});

/**
 * A request for `action` at `phase`; `undefined` omits the member. A
 * `compensate` request carries the link to a committed effect it requires
 * (#252), so the phase alone decides each case here.
 */
const request = (phase: unknown, action = PAY): EvaluationRequest =>
  withCredential(withCurrentContractReference({
    subject: { id: "alice", properties: { iss: "https://as.test" } },
    resource: { type: "invoice", id: "inv-1", properties: { audience: AUDIENCE, operation_target: AUDIENCE, vendor_id: "acme" } },
    action: { name: action },
    context: {
      mission: { id: "msn_1629", issuer: "https://as.test" },
      actor: { client_id: "ap-agent" },
      parameter_digest: "sha-256:pd1629",
      ...(phase !== undefined ? { action_phase: phase } : {}),
      ...(phase === "compensate" ? { compensates_evaluation_id: "dec_committed_1629" } : {}),
    },
  } as EvaluationRequest));

const decisionOptions = (fga: Fga): DecisionOptions => ({
  view: view(),
  fga,
  modelId: "model-1629",
  now: () => NOW,
  stalenessBound,
  relationForAction,
});

/** Every shape outside the closed set: case, padding, empty, and non-strings. */
const OUT_OF_SET: Array<[string, unknown]> = [
  ["unknown phase", "settle"],
  ["upper case", "COMMIT"],
  ["trailing space", "prepare "],
  ["empty", ""],
  ["null", null],
  ["number", 3],
  ["array", ["commit"]],
  ["object", { phase: "commit" }],
];

interface Outcome {
  outcome: { decision: unknown } | { error: unknown };
  refusals: PdpRefusal[];
  emitted: unknown[];
  fgaCalls: number;
  policyQueries: number;
}

/** Evaluate in process with counting FGA, Resource policy, evidence and refusal paths. */
async function inProcess(req: EvaluationRequest, over: Partial<EvaluateOptions> = {}): Promise<Outcome> {
  const { fga, calls } = countingFga();
  const policy = resourcePolicyFixture();
  const refusals: PdpRefusal[] = [];
  const emitted: unknown[] = [];
  const evidence = { emit: async (record: unknown) => emitted.push(record) } as unknown as DecisionEvidenceEmitter;
  const outcome = await evaluateRequest(req, {
    ...decisionOptions(fga),
    resourcePolicy: policy,
    evidence,
    refusals: (r) => refusals.push(r),
    // #773: a deployment that does not claim Evaluation-Context Binding; the
    // phase is this file's subject (evaluate-evaluation-context.test.ts
    // witnesses the claimed path, refused after the phase).
    evaluationContextBinding: EVALUATION_CONTEXT_UNCLAIMED_FIXTURE,
    ...over,
  }).then(
    (decision) => ({ decision }),
    (error: unknown) => ({ error }),
  );
  return { outcome, refusals, emitted, fgaCalls: calls(), policyQueries: policy.queries.length };
}

function expectRefusedPhaseInvalid(o: Outcome, req: EvaluationRequest, label: string): void {
  expect(o.outcome, label).toEqual({ error: expect.any(DecisionRequestRefused) });
  expect((o.outcome as { error: DecisionRequestRefused }).error.denial_reason, label).toBe("phase_invalid");
  expect(o.refusals, label).toHaveLength(1);
  expect(o.refusals[0], label).toMatchObject({ denial_reason: "phase_invalid", missionId: "msn_1629", audience: AUDIENCE });
  expect(o.refusals[0]?.evaluation_request, label).toBe(req);
  expect(o.emitted, label).toHaveLength(0);
  expect(o.fgaCalls, label).toBe(0);
  expect(o.policyQueries, label).toBe(0);
}

let handle: PdpHttpServerHandle | undefined;
afterEach(async () => {
  await handle?.close();
  handle = undefined;
});

describe("the PDP refuses an unusable action phase before evaluation (@spec authzen#context-action-phase, authzen#failure-condition-coverage, runtime-evidence#pre-decision-refusal, #1629)", () => {
  it("refuses an action_phase outside the closed set before evaluation as phase_invalid: no decision, no Decision Evidence, no FGA check and no Resource policy query", async () => {
    for (const [label, phase] of OUT_OF_SET) {
      const req = request(phase);
      expectRefusedPhaseInvalid(await inProcess(req), req, label);
    }
    // Control: every phase in the closed set is evaluated and echoed on the permit.
    for (const phase of ["preflight", "prepare", "commit", "compensate"]) {
      const o = await inProcess(request(phase));
      const decision = (o.outcome as { decision: { decision: boolean; context: Record<string, unknown> } }).decision;
      expect(decision?.decision, `${phase}: ${JSON.stringify(o.outcome)}`).toBe(true);
      expect((decision.context.conditions as { action_phase?: string }).action_phase).toBe(phase);
      expect(o.refusals, phase).toHaveLength(0);
      expect(o.emitted, phase).toHaveLength(1);
    }
  });

  it("refuses a request with no action_phase for an action the trusted operation declaration places at phases, and never infers a phase for it", async () => {
    const req = request(undefined);
    expectRefusedPhaseInvalid(await inProcess(req, { phasedActions: PHASED }), req, "phaseless phased action");
    // The same declaration admits the same action at a declared phase.
    const phased = await inProcess(request("prepare"), { phasedActions: PHASED });
    expect((phased.outcome as { decision: { decision: boolean } }).decision?.decision, JSON.stringify(phased.outcome)).toBe(true);
    // An action the declaration does not place at phases needs none.
    const read = await inProcess(request(undefined, READ), { phasedActions: PHASED });
    const readDecision = (read.outcome as { decision: { decision: boolean; context: Record<string, unknown> } }).decision;
    expect(readDecision?.decision, JSON.stringify(read.outcome)).toBe(true);
    expect((readDecision.context.conditions as { action_phase?: string }).action_phase).toBeUndefined();
    // With no declaration the PDP requires no phase, so the phaseless request is evaluated.
    const undeclared = await inProcess(request(undefined));
    expect((undeclared.outcome as { decision: { decision: boolean } }).decision?.decision, JSON.stringify(undeclared.outcome)).toBe(true);
  });

  it("checks the operation target first: a request failing both is refused once, as operation_target_invalid", async () => {
    const req = request("settle");
    (req.resource.properties as Record<string, unknown>).operation_target = "/mcp";
    const o = await inProcess(req, { phasedActions: PHASED });
    expect((o.outcome as { error: DecisionRequestRefused }).error.denial_reason).toBe("operation_target_invalid");
    expect(o.refusals.map((r) => r.denial_reason)).toEqual(["operation_target_invalid"]);
  });

  it("records the refusal as a PDP-signed Refusal Record over the request as submitted, naming no Mission and no evaluation", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const retained: PdpRefusalRecord[] = [];
    const refusals = createPdpRefusalRecorder({
      signer: { kid: "pdp-1629", key: privateKey },
      emitterId: "pdp.example",
      scope: AUDIENCE,
      retain: (record) => retained.push(record),
      now: () => NOW,
    });
    const resolve: EvidenceKeyResolver = ({ kid, emitter }) =>
      kid === "pdp-1629" && emitter.id === "pdp.example" && emitter.role === "pdp" ? { key: publicKey } : undefined;
    const outOfSet = request("settle");
    const missing = request(undefined);
    await expect(inProcess(outOfSet, { refusals }).then((o) => o.outcome)).resolves.toEqual({ error: expect.any(DecisionRequestRefused) });
    await expect(inProcess(missing, { refusals, phasedActions: PHASED }).then((o) => o.outcome)).resolves.toEqual({
      error: expect.any(DecisionRequestRefused),
    });
    expect(retained).toHaveLength(2);
    for (const [record, req] of [
      [retained[0], outOfSet],
      [retained[1], missing],
    ] as const) {
      expect(record).toMatchObject({
        audience: AUDIENCE,
        action: { name: PAY },
        resource: { type: "invoice", id: "inv-1" },
        decision: "deny",
        denial_reason: "phase_invalid",
        evaluated_at: NOW.toISOString(),
        evaluation_request_digest: evaluationRequestDigest(req),
        request_digest_input: "decision_request",
        subject: { id: "alice", properties: { iss: "https://as.test" } },
        emitter: { id: "pdp.example", role: "pdp" },
      });
      expect(record).not.toHaveProperty("mission");
      expect(record).not.toHaveProperty("evaluation_id");
      expect(await verifyEvidenceEnvelope(record as PdpRefusalRecord, REFUSAL_RECORD_MEDIA_TYPE, resolve)).toEqual({ valid: true });
    }
  });

  it("a decision point applies its own phase declaration, and a caller's options cannot replace or remove it", async () => {
    const { fga } = countingFga();
    const refusals: PdpRefusal[] = [];
    const point = createEphemeralDecisionPoint({
      emitterId: "pdp-1629",
      audience: AUDIENCE,
      resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
      refusals: (r) => refusals.push(r),
      phasedActions: PHASED,
      evaluationContextBinding: EVALUATION_CONTEXT_UNCLAIMED_FIXTURE,
    });
    // A widened options object naming an empty declaration is stripped, never applied.
    const widened = { ...decisionOptions(fga), phasedActions: new Set<string>() } as DecisionOptions;
    await expect(point.decide(request(undefined), widened)).rejects.toBeInstanceOf(DecisionRequestRefused);
    expect(refusals.map((r) => r.denial_reason)).toEqual(["phase_invalid"]);
    const permitted = await point.decide(request("commit"), decisionOptions(fga));
    expect(permitted.decision, JSON.stringify(permitted.context)).toBe(true);
    // A decision point bound to no declaration requires no phase, whatever the caller names.
    const open = createEphemeralDecisionPoint({
      emitterId: "pdp-1629",
      audience: AUDIENCE,
      resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
      evaluationContextBinding: EVALUATION_CONTEXT_UNCLAIMED_FIXTURE,
    });
    const claimed = { ...decisionOptions(fga), phasedActions: PHASED } as DecisionOptions;
    expect((await open.decide(request(undefined), claimed)).decision).toBe(true);
  });

  it("the remote PDP refuses an out-of-set phase, and a missing phase its declaration requires, before evaluation as phase_invalid, with a signed Refusal Record and no decision work", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const retained: PdpRefusalRecord[] = [];
    const { fga, calls } = countingFga();
    const policy = resourcePolicyFixture();
    handle = await createPdpHttpServer({
      peps: new Map([[PEP_ID, { secret: SECRET, scopes: [AUDIENCE] }]]),
      // A request option naming an empty declaration is stripped: the server's own applies.
      getOptions: () => ({ ...decisionOptions(fga), phasedActions: new Set<string>() }) as DecisionOptions,
      evaluateFn: evaluateRequest,
      resourcePolicy: policy,
      phasedActions: PHASED,
      evaluationContextBinding: EVALUATION_CONTEXT_UNCLAIMED_FIXTURE,
      refusals: createPdpRefusalRecorder({
        signer: { kid: "pdp-1629", key: privateKey },
        emitterId: "pdp.example",
        scope: AUDIENCE,
        retain: (record) => retained.push(record),
        now: () => NOW,
      }),
    });
    const server = handle;
    const ask = (req: EvaluationRequest) => evaluateRemote(req, { url: server.url, pepId: PEP_ID, secret: SECRET });
    const cases: Array<[string, EvaluationRequest]> = [
      ...OUT_OF_SET.map(([label, phase]): [string, EvaluationRequest] => [label, request(phase)]),
      ["missing where the declaration requires one", request(undefined)],
    ];
    for (const [label, req] of cases) {
      const refused = await ask(req);
      expect(refused.decision, label).toBe(false);
      expect(refused.context, label).toMatchObject({ denial_reason: "decision_channel_refused", channel_status: 400 });
      expect(refused.context, label).not.toHaveProperty("decision_evidence");
      expect(refused.context, label).not.toHaveProperty("evaluation_id");
      expect(retained.at(-1), label).toMatchObject({
        denial_reason: "phase_invalid",
        audience: AUDIENCE,
        decision: "deny",
        evaluation_request_digest: evaluationRequestDigest(req),
        emitter: { id: "pdp.example", role: "pdp" },
      });
      expect(retained.at(-1), label).not.toHaveProperty("mission");
    }
    expect(retained).toHaveLength(cases.length);
    expect(calls()).toBe(0);
    expect(policy.queries).toHaveLength(0);
    const resolve: EvidenceKeyResolver = ({ kid, emitter }) =>
      kid === "pdp-1629" && emitter.id === "pdp.example" && emitter.role === "pdp" ? { key: publicKey } : undefined;
    for (const record of retained) {
      expect(await verifyEvidenceEnvelope(record, REFUSAL_RECORD_MEDIA_TYPE, resolve)).toEqual({ valid: true });
    }
    // Control: the same channel and Mission evaluate a declared phase, and an undeclared action with none.
    const served = await ask(request("commit"));
    expect(served.decision, JSON.stringify(served.context)).toBe(true);
    const read = await ask(request(undefined, READ));
    expect(read.decision, JSON.stringify(read.context)).toBe(true);
    expect(calls()).toBeGreaterThan(0);
    expect(retained).toHaveLength(cases.length);
  });
});
