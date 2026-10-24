/**
 * @spec authzen#context-evaluation-binding, authzen#response-context,
 * authzen#failure-condition-coverage, runtime#evaluation-context-binding,
 * runtime-evidence#decision-evidence-object, runtime-evidence#pre-decision-refusal
 * (#773): the PDP's side of Evaluation-Context Binding. For an operation its
 * trusted declaration covers, it validates the PEP-supplied context digest and
 * descriptor reference before evaluation, refusing unusable inputs as a
 * Refusal Record `evaluation_context_invalid`; it echoes the validated digest
 * as the permit condition without recomputing it, and Decision Evidence
 * records the validated digest and reference, never malformed input.
 *
 * The FGA layer is a counting stub that always permits, so this file never
 * skips.
 */

import { generateKeyPairSync } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { EvaluationContextBindingDeclarations } from "@mission/core";
import { RUNTIME_SCOPE_CONFIG } from "@mission/demo-data";
import { evaluateRemote } from "../src/client.js";
import { createEphemeralDecisionPoint } from "../src/decision-point.js";
import {
  createDecisionEvidenceEmitter,
  type DecisionEvidenceObject,
  evaluationRequestDigest,
} from "../src/decision-evidence.js";
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
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE, resourcePolicyFixture } from "../src/test-support.js";
import { withCredential } from "./with-credential.js";

const AUDIENCE = "http://localhost:4403/mcp";
const NOW = new Date("2026-10-24T12:00:00Z");
const PEP_ID = "mcp-payments-pep";
const SECRET = "test-shared-secret-773";
const PAY = "payments:payment.execute";
const READ = "payments:invoice.read";

/** The shipped declaration, claimed: the payments operations it lists are covered. */
const CLAIMED = new EvaluationContextBindingDeclarations({
  ...(RUNTIME_SCOPE_CONFIG as Record<string, unknown>),
  claims: ["evaluation_context_binding"],
});
const DECLARED = CLAIMED.operation(PAY, "commit")?.descriptor as { id: string; version: string; digest: string };
const DIGEST = `sha-256:${"Q".repeat(43)}`;

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

const view = (actions: string[] = [PAY, READ]): MissionView => ({
  id: "msn_773",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:h773",
  authority_set: [{ type: MISSION_RESOURCE_ACCESS_TYPE, resource: AUDIENCE, actions }],
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
});

/** A request for `action` at `phase`, with the given context inputs (`undefined` omits a member). */
const request = (inputs: { digest?: unknown; binding?: unknown }, action = PAY, phase: string | undefined = "commit"): EvaluationRequest =>
  withCredential({
    subject: { id: "alice", properties: { iss: "https://as.test" } },
    resource: { type: "invoice", id: "inv-1", properties: { audience: AUDIENCE, operation_target: AUDIENCE, vendor_id: "acme" } },
    action: { name: action },
    context: {
      mission: { id: "msn_773", issuer: "https://as.test" },
      actor: { client_id: "ap-agent" },
      parameter_digest: "sha-256:pd773",
      ...(phase !== undefined ? { action_phase: phase } : {}),
      ...(inputs.digest !== undefined ? { evaluation_context_digest: inputs.digest } : {}),
      ...(inputs.binding !== undefined ? { evaluation_context_binding: inputs.binding } : {}),
    },
  } as EvaluationRequest);

const decisionOptions = (fga: Fga, v: MissionView = view()): DecisionOptions => ({
  view: v,
  fga,
  modelId: "model-773",
  now: () => NOW,
  stalenessBound,
  relationForAction,
});

/** A real Decision Evidence emitter, so the signed record is what the assertions read. */
function emitter() {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return createDecisionEvidenceEmitter({ signer: { kid: "pdp-773", key: privateKey }, emitterId: "pdp.example", audience: AUDIENCE });
}

interface Outcome {
  outcome: { decision: { decision: boolean; context: Record<string, unknown> } } | { error: unknown };
  refusals: PdpRefusal[];
  evidence: DecisionEvidenceObject | undefined;
  fgaCalls: number;
  policyQueries: number;
}

async function inProcess(req: EvaluationRequest, over: Partial<EvaluateOptions> = {}, v?: MissionView): Promise<Outcome> {
  const { fga, calls } = countingFga();
  const policy = resourcePolicyFixture();
  const refusals: PdpRefusal[] = [];
  const outcome = await evaluateRequest(req, {
    ...decisionOptions(fga, v),
    resourcePolicy: policy,
    evidence: emitter(),
    refusals: (r) => refusals.push(r),
    evaluationContextBinding: CLAIMED,
    ...over,
  }).then(
    (decision) => ({ decision: decision as unknown as { decision: boolean; context: Record<string, unknown> } }),
    (error: unknown) => ({ error }),
  );
  const evidence =
    "decision" in outcome ? (outcome.decision.context.decision_evidence as DecisionEvidenceObject | undefined) : undefined;
  return { outcome, refusals, evidence, fgaCalls: calls(), policyQueries: policy.queries.length };
}

/** Inputs a covered operation's request cannot be decided with. */
const UNUSABLE: Array<[string, { digest?: unknown; binding?: unknown }]> = [
  ["both missing", {}],
  ["digest missing", { binding: DECLARED }],
  ["binding missing", { digest: DIGEST }],
  ["digest unprefixed", { digest: "Q".repeat(43), binding: DECLARED }],
  ["digest a number", { digest: 7, binding: DECLARED }],
  ["binding a string", { digest: DIGEST, binding: DECLARED.id }],
  ["binding with an extra member", { digest: DIGEST, binding: { ...DECLARED, salt: "x" } }],
  ["binding naming another version", { digest: DIGEST, binding: { ...DECLARED, version: "2020-01-01" } }],
  ["binding naming another digest", { digest: DIGEST, binding: { ...DECLARED, digest: `sha-256:${"Z".repeat(43)}` } }],
];

let handle: PdpHttpServerHandle | undefined;
afterEach(async () => {
  await handle?.close();
  handle = undefined;
});

describe("the PDP validates the evaluation-context inputs of a covered operation before evaluation (@spec authzen#context-evaluation-binding, authzen#failure-condition-coverage, runtime-evidence#pre-decision-refusal, #773)", () => {
  it("refuses missing, malformed or incompatible inputs as evaluation_context_invalid: no decision, no Decision Evidence, no FGA check and no Resource policy query", async () => {
    for (const [label, inputs] of UNUSABLE) {
      const req = request(inputs);
      const o = await inProcess(req);
      expect(o.outcome, label).toEqual({ error: expect.any(DecisionRequestRefused) });
      expect((o.outcome as { error: DecisionRequestRefused }).error.denial_reason, label).toBe("evaluation_context_invalid");
      expect(o.refusals.map((r) => r.denial_reason), label).toEqual(["evaluation_context_invalid"]);
      expect(o.refusals[0]?.evaluation_request, label).toBe(req);
      expect(o.fgaCalls, label).toBe(0);
      expect(o.policyQueries, label).toBe(0);
    }
  });

  it("checks the phase first: a request failing both is refused once, as phase_invalid", async () => {
    const o = await inProcess(request({}, PAY, "settle"));
    expect((o.outcome as { error: DecisionRequestRefused }).error.denial_reason).toBe("phase_invalid");
    expect(o.refusals.map((r) => r.denial_reason)).toEqual(["phase_invalid"]);
  });

  it("records the refusal as a PDP-signed Refusal Record over the request as submitted, naming no Mission and no evaluation", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const retained: PdpRefusalRecord[] = [];
    const refusals = createPdpRefusalRecorder({
      signer: { kid: "pdp-773", key: privateKey },
      emitterId: "pdp.example",
      scope: AUDIENCE,
      retain: (record) => retained.push(record),
      now: () => NOW,
    });
    const req = request({ digest: DIGEST });
    await expect(inProcess(req, { refusals }).then((o) => o.outcome)).resolves.toEqual({ error: expect.any(DecisionRequestRefused) });
    expect(retained).toHaveLength(1);
    expect(retained[0]).toMatchObject({
      audience: AUDIENCE,
      action: { name: PAY },
      decision: "deny",
      denial_reason: "evaluation_context_invalid",
      evaluation_request_digest: evaluationRequestDigest(req),
      request_digest_input: "decision_request",
      emitter: { id: "pdp.example", role: "pdp" },
    });
    expect(retained[0]).not.toHaveProperty("mission");
    expect(retained[0]).not.toHaveProperty("evaluation_id");
    const resolve: EvidenceKeyResolver = ({ kid, emitter: e }) =>
      kid === "pdp-773" && e.id === "pdp.example" && e.role === "pdp" ? { key: publicKey } : undefined;
    expect(await verifyEvidenceEnvelope(retained[0] as PdpRefusalRecord, REFUSAL_RECORD_MEDIA_TYPE, resolve)).toEqual({ valid: true });
  });

  it("the remote PDP refuses unusable inputs before evaluation with a signed Refusal Record, and a caller's options cannot remove its declaration", async () => {
    const retained: PdpRefusalRecord[] = [];
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const { fga, calls } = countingFga();
    handle = await createPdpHttpServer({
      peps: new Map([[PEP_ID, { secret: SECRET, scopes: [AUDIENCE] }]]),
      // A request option naming a declaration that covers nothing is stripped.
      getOptions: () =>
        ({ ...decisionOptions(fga), evaluationContextBinding: new EvaluationContextBindingDeclarations({}) }) as DecisionOptions,
      evaluateFn: evaluateRequest,
      resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
      evaluationContextBinding: CLAIMED,
      refusals: createPdpRefusalRecorder({
        signer: { kid: "pdp-773", key: privateKey },
        emitterId: "pdp.example",
        scope: AUDIENCE,
        retain: (record) => retained.push(record),
        now: () => NOW,
      }),
    });
    const server = handle;
    const ask = (req: EvaluationRequest) => evaluateRemote(req, { url: server.url, pepId: PEP_ID, secret: SECRET });
    const refused = await ask(request({ binding: DECLARED }));
    expect(refused.decision).toBe(false);
    expect(refused.context).toMatchObject({ denial_reason: "decision_channel_refused", channel_status: 400 });
    expect(retained.map((r) => r.denial_reason)).toEqual(["evaluation_context_invalid"]);
    expect(calls()).toBe(0);
    const served = await ask(request({ digest: DIGEST, binding: DECLARED }));
    expect(served.decision, JSON.stringify(served.context)).toBe(true);
    expect((served.context.conditions as Record<string, unknown>).evaluation_context_digest).toBe(DIGEST);
    await handle.close();
    // A server bound to a declaration that claims nothing evaluates the
    // request its claimed peer refused: its own binding applies, never the
    // shipped statement's or a caller's.
    handle = await createPdpHttpServer({
      peps: new Map([[PEP_ID, { secret: SECRET, scopes: [AUDIENCE] }]]),
      getOptions: () => ({ ...decisionOptions(fga), evaluationContextBinding: CLAIMED }) as DecisionOptions,
      evaluateFn: evaluateRequest,
      resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
      evaluationContextBinding: new EvaluationContextBindingDeclarations({}),
    });
    const open = handle;
    const unclaimed = await evaluateRemote(request({ binding: DECLARED }), { url: open.url, pepId: PEP_ID, secret: SECRET });
    expect(unclaimed.decision, JSON.stringify(unclaimed.context)).toBe(true);
  });
});

describe("the PDP echoes the validated context digest and records the binding (@spec authzen#response-context, runtime#evaluation-context-binding, runtime-evidence#decision-evidence-object, #773)", () => {
  it("returns the supplied digest as the permit condition, unrecomputed, and Decision Evidence records the same digest and the descriptor reference", async () => {
    const o = await inProcess(request({ digest: DIGEST, binding: DECLARED }));
    const decision = (o.outcome as { decision: { decision: boolean; context: Record<string, unknown> } }).decision;
    expect(decision.decision, JSON.stringify(decision.context)).toBe(true);
    // Equal to the validated request's digest: an observation echoed, never recomputed.
    expect((decision.context.conditions as Record<string, unknown>).evaluation_context_digest).toBe(DIGEST);
    expect(o.evidence?.evaluation_context_digest).toBe(DIGEST);
    expect(o.evidence?.evaluation_context_binding).toEqual(DECLARED);
    // Recorded once, top level: never inside the record's conditions.
    expect(o.evidence?.conditions).not.toHaveProperty("evaluation_context_digest");
    expect(JSON.stringify(o.evidence)).not.toMatch(/"salt/);
    // Authoritative facts still reach policy through the existing inputs.
    expect(o.policyQueries).toBeGreaterThan(0);
  });

  it("records the validated inputs on a denial for a covered operation, where no condition exists", async () => {
    const o = await inProcess(request({ digest: DIGEST, binding: DECLARED }), {}, view([READ]));
    const decision = (o.outcome as { decision: { decision: boolean; context: Record<string, unknown> } }).decision;
    expect(decision.decision).toBe(false);
    expect(o.evidence?.decision).toBe("deny");
    expect(o.evidence?.evaluation_context_digest).toBe(DIGEST);
    expect(o.evidence?.evaluation_context_binding).toEqual(DECLARED);
  });

  it("neither requires, echoes nor records context inputs for an operation the declaration does not cover, or when the deployment does not claim it", async () => {
    // An uncovered operation carrying inputs.
    const uncovered = await inProcess(request({ digest: DIGEST, binding: DECLARED }, READ, undefined));
    const permit = (uncovered.outcome as { decision: { decision: boolean; context: Record<string, unknown> } }).decision;
    expect(permit.decision, JSON.stringify(permit.context)).toBe(true);
    expect(permit.context.conditions).not.toHaveProperty("evaluation_context_digest");
    expect(uncovered.evidence).not.toHaveProperty("evaluation_context_digest");
    expect(uncovered.evidence).not.toHaveProperty("evaluation_context_binding");
    // A covered operation under a statement that does not claim the extension needs none.
    const unclaimed = await inProcess(request({}), {
      evaluationContextBinding: new EvaluationContextBindingDeclarations({
        ...(RUNTIME_SCOPE_CONFIG as Record<string, unknown>),
        claims: [],
      }),
    });
    const plain = (unclaimed.outcome as { decision: { decision: boolean; context: Record<string, unknown> } }).decision;
    expect(plain.decision, JSON.stringify(plain.context)).toBe(true);
    expect(plain.context.conditions).not.toHaveProperty("evaluation_context_digest");
  });

  it("a decision point applies its own declaration, and a caller's options cannot replace it", async () => {
    const { fga } = countingFga();
    const refusals: PdpRefusal[] = [];
    const point = createEphemeralDecisionPoint({
      emitterId: "pdp-773",
      audience: AUDIENCE,
      resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
      refusals: (r) => refusals.push(r),
      evaluationContextBinding: CLAIMED,
    });
    const widened = {
      ...decisionOptions(fga),
      evaluationContextBinding: new EvaluationContextBindingDeclarations({}),
    } as DecisionOptions;
    await expect(point.decide(request({}), widened)).rejects.toBeInstanceOf(DecisionRequestRefused);
    expect(refusals.map((r) => r.denial_reason)).toEqual(["evaluation_context_invalid"]);
    const permitted = await point.decide(request({ digest: DIGEST, binding: DECLARED }), decisionOptions(fga));
    expect((permitted.context.conditions as Record<string, unknown>).evaluation_context_digest).toBe(DIGEST);
    // A decision point bound to a declaration that claims nothing requires no
    // context, though the shipped statement claims the extension and the
    // caller names the claimed declaration.
    const unclaimed = createEphemeralDecisionPoint({
      emitterId: "pdp-773",
      audience: AUDIENCE,
      resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
      evaluationContextBinding: new EvaluationContextBindingDeclarations({}),
    });
    const naming = { ...decisionOptions(fga), evaluationContextBinding: CLAIMED } as DecisionOptions;
    const open = await unclaimed.decide(request({}), naming);
    expect(open.decision, JSON.stringify(open.context)).toBe(true);
    expect(open.context.conditions).not.toHaveProperty("evaluation_context_digest");
    // A decision point with no binding of its own applies the shipped
    // statement, which claims the extension: a caller cannot switch it off.
    const statement = createEphemeralDecisionPoint({
      emitterId: "pdp-773",
      audience: AUDIENCE,
      resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
    });
    await expect(statement.decide(request({}), widened)).rejects.toBeInstanceOf(DecisionRequestRefused);
  });
});

describe("Decision Evidence never signs a context binding it did not establish (@spec runtime-evidence#decision-evidence-object, #773)", () => {
  const base = {
    mission: { id: "msn_773", issuer: "https://as.test", policy_view_id: "pv-773" },
    subject: { id: "alice" },
    resource: { type: "invoice", id: "inv-1" },
    action: { name: PAY },
    audience: AUDIENCE,
    evaluation_id: "dec_773",
    evaluated_at: NOW.toISOString(),
    parameter_digest: "sha-256:pd773",
  };

  it("omits malformed context input from the signed record rather than recording it as an established binding", async () => {
    const malformed: Array<[string, unknown, unknown]> = [
      ["unprefixed digest", "Q".repeat(43), DECLARED],
      ["digest without a reference", DIGEST, undefined],
      ["reference with an extra member", DIGEST, { ...DECLARED, salt: "x" }],
      ["reference naming no URI", DIGEST, { ...DECLARED, id: "not a uri" }],
    ];
    for (const [label, digest, binding] of malformed) {
      const record = await emitter().emit({
        ...base,
        decision: "deny",
        denial_reason: "out_of_authority",
        evaluation_context_digest: digest as string,
        ...(binding !== undefined ? { evaluation_context_binding: binding as typeof DECLARED } : {}),
      });
      expect(record, label).not.toHaveProperty("evaluation_context_digest");
      expect(record, label).not.toHaveProperty("evaluation_context_binding");
    }
    const established = await emitter().emit({
      ...base,
      decision: "deny",
      denial_reason: "out_of_authority",
      evaluation_context_digest: DIGEST,
      evaluation_context_binding: DECLARED,
    });
    expect(established.evaluation_context_digest).toBe(DIGEST);
    expect(established.evaluation_context_binding).toEqual(DECLARED);
  });

  it("refuses to sign a permit whose recorded digest differs from the live condition", async () => {
    await expect(
      emitter().emit({
        ...base,
        decision: "permit",
        entry_digest: "sha-256:e773",
        conditions: { valid_until: NOW.toISOString(), parameter_digest: "sha-256:pd773", evaluation_context_digest: DIGEST },
        evaluation_context_digest: `sha-256:${"Z".repeat(43)}`,
        evaluation_context_binding: DECLARED,
      }),
    ).rejects.toThrow(/context binding differs/);
  });
});
