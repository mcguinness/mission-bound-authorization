/**
 * @spec authzen#context-compensation-link, authzen#pdp-consistency-checks,
 * authzen#failure-condition-coverage, runtime-evidence#pre-decision-refusal,
 * runtime-evidence#decision-evidence-object `compensates_evaluation_id` (#252):
 * a request whose `action_phase` is `compensate` carries
 * `context.compensates_evaluation_id`, the `evaluation_id` of the committed
 * effect it offsets, and any request that carries one carries a well-formed
 * evaluation identifier. Otherwise the request is unusable, refused before
 * evaluation as a Refusal Record `compensation_link_invalid`, with no
 * decision, no `evaluation_id` and no Decision Evidence: no compensate-phase
 * Decision is issued without its required link. A usable link is recorded on
 * Decision Evidence, on a permit and on a denial; it confers no authority.
 *
 * The FGA layer is a counting stub that always permits, so only evaluate()'s
 * own steps and the decision channel decide, and this file never skips.
 */

import { generateKeyPairSync } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { evaluateRemote } from "../src/client.js";
import {
  createDecisionEvidenceEmitter,
  type DecisionEvidenceEmissionInput,
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
import {
  DECISION_EVIDENCE_MEDIA_TYPE,
  type EvidenceKeyResolver,
  REFUSAL_RECORD_MEDIA_TYPE,
  verifyEvidenceEnvelope,
} from "../src/runtime-evidence-integrity.js";
import { createPdpHttpServer, type PdpHttpServerHandle } from "../src/server.js";
import { resourcePolicyFixture } from "../src/test-support.js";
import { withCredential } from "./with-credential.js";

const AUDIENCE = "http://localhost:4403/mcp";
const NOW = new Date("2026-10-24T12:00:00Z");
const PEP_ID = "mcp-payments-pep";
const SECRET = "test-shared-secret-252";
const REVERSE = "payments:payment.reverse";
const PAY = "payments:payment.execute";
/** The evaluation identifier of the committed wire a compensation offsets. */
const ORIGINAL = "dec_3f2b9c1e-0d4a-4e8b-9a7c-5e6f7a8b9c0d";

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

const view = (actions: string[] = [PAY, REVERSE]): MissionView => ({
  id: "msn_252",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:h252",
  authority_set: [{ type: MISSION_RESOURCE_ACCESS_TYPE, resource: AUDIENCE, actions }],
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
});

/** A request at `phase` carrying `link`; `undefined` omits either member. */
const request = (phase: unknown, link: unknown, action = REVERSE): EvaluationRequest =>
  withCredential({
    subject: { id: "alice", properties: { iss: "https://as.test" } },
    resource: { type: "invoice", id: "inv-1", properties: { audience: AUDIENCE, operation_target: AUDIENCE, vendor_id: "acme" } },
    action: { name: action },
    context: {
      mission: { id: "msn_252", issuer: "https://as.test" },
      actor: { client_id: "ap-agent" },
      parameter_digest: "sha-256:pd252",
      ...(phase !== undefined ? { action_phase: phase } : {}),
      ...(link !== undefined ? { compensates_evaluation_id: link } : {}),
    },
  } as EvaluationRequest);

const decisionOptions = (fga: Fga, actions?: string[]): DecisionOptions => ({
  view: view(actions),
  fga,
  modelId: "model-252",
  now: () => NOW,
  stalenessBound,
  relationForAction,
});

/** Every link that is not a well-formed evaluation identifier. */
const MALFORMED: Array<[string, unknown]> = [
  ["empty", ""],
  ["a space", "dec 1"],
  ["a reserved character", "dec_1/2"],
  ["over 64 characters", "d".repeat(65)],
  ["null", null],
  ["a number", 7],
  ["an array", [ORIGINAL]],
  ["an object", { evaluation_id: ORIGINAL }],
];

/** A real PDP evidence emitter and the resolver that verifies what it signs. */
function signingEmitter() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const emitter = createDecisionEvidenceEmitter({ signer: { kid: "pdp-252", key: privateKey }, emitterId: "pdp.example", audience: AUDIENCE });
  const resolve: EvidenceKeyResolver = ({ kid, emitter: e }) =>
    kid === "pdp-252" && e.id === "pdp.example" && e.role === "pdp" ? { key: publicKey } : undefined;
  return { emitter, resolve };
}

interface Outcome {
  outcome: { decision: { decision: boolean; context: Record<string, unknown> } } | { error: unknown };
  refusals: PdpRefusal[];
  fgaCalls: number;
  policyQueries: number;
}

/** Evaluate in process with counting FGA, Resource policy, a signing evidence emitter and a refusal path. */
async function inProcess(req: EvaluationRequest, over: Partial<EvaluateOptions> = {}, actions?: string[]): Promise<Outcome> {
  const { fga, calls } = countingFga();
  const policy = resourcePolicyFixture();
  const refusals: PdpRefusal[] = [];
  const outcome = await evaluateRequest(req, {
    ...decisionOptions(fga, actions),
    resourcePolicy: policy,
    evidence: signingEmitter().emitter,
    refusals: (r) => refusals.push(r),
    ...over,
  }).then(
    (decision) => ({ decision: decision as { decision: boolean; context: Record<string, unknown> } }),
    (error: unknown) => ({ error }),
  );
  return { outcome, refusals, fgaCalls: calls(), policyQueries: policy.queries.length };
}

function expectRefusedLinkInvalid(o: Outcome, req: EvaluationRequest, label: string): void {
  expect(o.outcome, label).toEqual({ error: expect.any(DecisionRequestRefused) });
  expect((o.outcome as { error: DecisionRequestRefused }).error.denial_reason, label).toBe("compensation_link_invalid");
  expect(o.refusals, label).toHaveLength(1);
  expect(o.refusals[0], label).toMatchObject({ denial_reason: "compensation_link_invalid", missionId: "msn_252", audience: AUDIENCE });
  expect(o.refusals[0]?.evaluation_request, label).toBe(req);
  expect(o.fgaCalls, label).toBe(0);
  expect(o.policyQueries, label).toBe(0);
}

let handle: PdpHttpServerHandle | undefined;
afterEach(async () => {
  await handle?.close();
  handle = undefined;
});

describe("the PDP refuses an unusable compensation link before evaluation (@spec authzen#context-compensation-link, authzen#pdp-consistency-checks, authzen#failure-condition-coverage, runtime-evidence#pre-decision-refusal, #252)", () => {
  it("refuses a compensate-phase request with no compensates_evaluation_id, or a malformed one, before evaluation as compensation_link_invalid: no decision, no Decision Evidence, no FGA check and no Resource policy query", async () => {
    for (const [label, link] of [["absent", undefined] as [string, unknown], ...MALFORMED]) {
      const req = request("compensate", link);
      expectRefusedLinkInvalid(await inProcess(req), req, label);
    }
    // Control: a well-formed link is evaluated.
    const o = await inProcess(request("compensate", ORIGINAL));
    expect((o.outcome as { decision: { decision: boolean } }).decision?.decision, JSON.stringify(o.outcome)).toBe(true);
    expect(o.refusals).toHaveLength(0);
  });

  it("refuses a malformed compensates_evaluation_id on a request of another phase, and evaluates one of another phase that carries none", async () => {
    for (const [label, link] of MALFORMED) {
      const req = request("commit", link, PAY);
      expectRefusedLinkInvalid(await inProcess(req), req, label);
    }
    const plain = await inProcess(request("commit", undefined, PAY));
    expect((plain.outcome as { decision: { decision: boolean } }).decision?.decision, JSON.stringify(plain.outcome)).toBe(true);
  });

  it("checks the phase first: a request failing both is refused once, as phase_invalid", async () => {
    const o = await inProcess(request("settle", ""));
    expect((o.outcome as { error: DecisionRequestRefused }).error.denial_reason).toBe("phase_invalid");
    expect(o.refusals.map((r) => r.denial_reason)).toEqual(["phase_invalid"]);
  });

  it("records the refusal as a PDP-signed Refusal Record over the request as submitted, naming no Mission and no evaluation", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const retained: PdpRefusalRecord[] = [];
    const refusals = createPdpRefusalRecorder({
      signer: { kid: "pdp-252", key: privateKey },
      emitterId: "pdp.example",
      scope: AUDIENCE,
      retain: (record) => retained.push(record),
      now: () => NOW,
    });
    const resolve: EvidenceKeyResolver = ({ kid, emitter }) =>
      kid === "pdp-252" && emitter.id === "pdp.example" && emitter.role === "pdp" ? { key: publicKey } : undefined;
    const missing = request("compensate", undefined);
    await expect(inProcess(missing, { refusals }).then((o) => o.outcome)).resolves.toEqual({ error: expect.any(DecisionRequestRefused) });
    expect(retained).toHaveLength(1);
    expect(retained[0]).toMatchObject({
      audience: AUDIENCE,
      action: { name: REVERSE },
      resource: { type: "invoice", id: "inv-1" },
      decision: "deny",
      denial_reason: "compensation_link_invalid",
      evaluated_at: NOW.toISOString(),
      evaluation_request_digest: evaluationRequestDigest(missing),
      request_digest_input: "decision_request",
      emitter: { id: "pdp.example", role: "pdp" },
    });
    expect(retained[0]).not.toHaveProperty("mission");
    expect(retained[0]).not.toHaveProperty("evaluation_id");
    expect(await verifyEvidenceEnvelope(retained[0] as PdpRefusalRecord, REFUSAL_RECORD_MEDIA_TYPE, resolve)).toEqual({ valid: true });
  });

  it("the remote PDP refuses a compensate-phase request with no link, or a malformed one, before evaluation as compensation_link_invalid, with a signed Refusal Record and no decision work", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const retained: PdpRefusalRecord[] = [];
    const { fga, calls } = countingFga();
    const policy = resourcePolicyFixture();
    handle = await createPdpHttpServer({
      peps: new Map([[PEP_ID, { secret: SECRET, scopes: [AUDIENCE] }]]),
      getOptions: () => decisionOptions(fga),
      evaluateFn: evaluateRequest,
      resourcePolicy: policy,
      refusals: createPdpRefusalRecorder({
        signer: { kid: "pdp-252", key: privateKey },
        emitterId: "pdp.example",
        scope: AUDIENCE,
        retain: (record) => retained.push(record),
        now: () => NOW,
      }),
    });
    const server = handle;
    const ask = (req: EvaluationRequest) => evaluateRemote(req, { url: server.url, pepId: PEP_ID, secret: SECRET });
    const cases: Array<[string, EvaluationRequest]> = [
      ["absent", request("compensate", undefined)],
      ...MALFORMED.map(([label, link]): [string, EvaluationRequest] => [label, request("compensate", link)]),
    ];
    for (const [label, req] of cases) {
      const refused = await ask(req);
      expect(refused.decision, label).toBe(false);
      expect(refused.context, label).toMatchObject({ denial_reason: "decision_channel_refused", channel_status: 400 });
      expect(refused.context, label).not.toHaveProperty("decision_evidence");
      expect(refused.context, label).not.toHaveProperty("evaluation_id");
      expect(retained.at(-1), label).toMatchObject({
        denial_reason: "compensation_link_invalid",
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
      kid === "pdp-252" && emitter.id === "pdp.example" && emitter.role === "pdp" ? { key: publicKey } : undefined;
    for (const record of retained) {
      expect(await verifyEvidenceEnvelope(record, REFUSAL_RECORD_MEDIA_TYPE, resolve)).toEqual({ valid: true });
    }
    // Control: the same channel evaluates a compensate-phase request with a well-formed link.
    const served = await ask(request("compensate", ORIGINAL));
    expect(served.decision, JSON.stringify(served.context)).toBe(true);
    expect(calls()).toBeGreaterThan(0);
    expect(retained).toHaveLength(cases.length);
  });
});

describe("Decision Evidence records the validated compensation link (@spec runtime-evidence#decision-evidence-object, authzen#context-compensation-link, #252)", () => {
  it("records compensates_evaluation_id on a compensate-phase permit and denial, signed, and never as a permit condition", async () => {
    const { emitter, resolve } = signingEmitter();
    const permit = await inProcess(request("compensate", ORIGINAL), { evidence: emitter });
    const permitted = (permit.outcome as { decision: { decision: boolean; context: Record<string, unknown> } }).decision;
    expect(permitted.decision, JSON.stringify(permit.outcome)).toBe(true);
    const permitRecord = permitted.context.decision_evidence as DecisionEvidenceObject;
    expect(permitRecord).toMatchObject({ decision: "permit", action_phase: "compensate", compensates_evaluation_id: ORIGINAL });
    expect(permitted.context.conditions).not.toHaveProperty("compensates_evaluation_id");
    expect(await verifyEvidenceEnvelope(permitRecord, DECISION_EVIDENCE_MEDIA_TYPE, resolve)).toEqual({ valid: true });
    // The link confers no authority: without the compensating action in the
    // Authority Set the request is denied, and the denial records the link.
    const deny = await inProcess(request("compensate", ORIGINAL), { evidence: emitter }, [PAY]);
    const denied = (deny.outcome as { decision: { decision: boolean; context: Record<string, unknown> } }).decision;
    expect(denied.decision).toBe(false);
    expect(denied.context.denial_reason).toBe("out_of_authority");
    const denialRecord = denied.context.decision_evidence as DecisionEvidenceObject;
    expect(denialRecord).toMatchObject({ decision: "deny", action_phase: "compensate", compensates_evaluation_id: ORIGINAL });
    expect(await verifyEvidenceEnvelope(denialRecord, DECISION_EVIDENCE_MEDIA_TYPE, resolve)).toEqual({ valid: true });
  });

  it("the emitter never signs a compensate-phase record without a well-formed link, and never signs a malformed one", async () => {
    const { emitter } = signingEmitter();
    const input: DecisionEvidenceEmissionInput = {
      mission: { id: "msn_252", issuer: "https://as.test", policy_view_id: "pv_252" },
      subject: { id: "alice" },
      resource: { type: "invoice", id: "inv-1" },
      action: { name: REVERSE },
      audience: AUDIENCE,
      evaluation_id: "dec_compensating",
      decision: "deny",
      denial_reason: "out_of_authority",
      evaluated_at: NOW.toISOString(),
      evaluation_request_digest: "sha-256:rd252",
    };
    for (const link of [undefined, "", "dec 1", "d".repeat(65)]) {
      await expect(
        emitter.emit({ ...input, action_phase: "compensate", ...(link !== undefined ? { compensates_evaluation_id: link } : {}) }),
        JSON.stringify(link),
      ).rejects.toThrow(/compensate-phase decision requires compensates_evaluation_id/);
    }
    const linked = await emitter.emit({ ...input, action_phase: "compensate", compensates_evaluation_id: ORIGINAL });
    expect(linked.compensates_evaluation_id).toBe(ORIGINAL);
    // Elsewhere a malformed value is omitted from the signed record, never signed.
    const other = await emitter.emit({ ...input, action: { name: PAY }, compensates_evaluation_id: "dec 1" });
    expect(other).not.toHaveProperty("compensates_evaluation_id");
  });
});
