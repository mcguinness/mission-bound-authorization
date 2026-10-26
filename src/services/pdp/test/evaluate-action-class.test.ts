/**
 * @spec runtime#classification, authzen#pdp-consistency-checks,
 * authzen#failure-condition-coverage, runtime-evidence#pre-decision-refusal
 * (#956, D814): a mediated request that reaches the PDP with no action class
 * established is a request fault. It is refused before evaluation as a
 * Refusal Record `action_class_missing`, never evaluated under, or recorded
 * as, a default class such as `consequential_read`.
 */
import { generateKeyPairSync } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { evaluateRemote } from "../src/client.js";
import { type DecisionEvidenceEmitter, evaluationRequestDigest } from "../src/decision-evidence.js";
import {
  type DecisionOptions,
  DecisionRequestRefused,
  evaluate as evaluateRequest,
  type EvaluationRequest,
} from "../src/evaluate.js";
import type { Fga } from "../src/fga.js";
import { MISSION_RESOURCE_ACCESS_TYPE, type MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBound } from "../src/policy.js";
import { createPdpRefusalRecorder, type PdpRefusalRecord } from "../src/refusal-record.js";
import { type EvidenceKeyResolver, REFUSAL_RECORD_MEDIA_TYPE, verifyEvidenceEnvelope } from "../src/runtime-evidence-integrity.js";
import { createPdpHttpServer, type PdpHttpServerHandle } from "../src/server.js";
import { EVALUATION_CONTEXT_UNCLAIMED_FIXTURE, resourcePolicyFixture } from "../src/test-support.js";
import { withCredential } from "./with-credential.js";

const AUDIENCE = "http://localhost:4403/mcp";
const NOW = new Date("2026-10-25T12:00:00Z");
const PEP_ID = "mcp-payments-pep";
const SECRET = "test-shared-secret-956";
const READ = "payments:invoice.read";

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
  id: "msn_956",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:h956",
  authority_set: [{ type: MISSION_RESOURCE_ACCESS_TYPE, resource: AUDIENCE, actions: [READ] }],
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
});

/** A request whose `action_class` is set as given; `undefined` is passed through, never defaulted. */
const request = (actionClass: string | undefined): EvaluationRequest =>
  withCredential({
    subject: { id: "alice", properties: { iss: "https://as.test" } },
    resource: { type: "invoice", id: "inv-1", properties: { audience: AUDIENCE, operation_target: AUDIENCE, vendor_id: "acme" } },
    action: { name: READ },
    context: {
      mission: { id: "msn_956", issuer: "https://as.test" },
      actor: { client_id: "ap-agent" },
      action_class: actionClass,
      parameter_digest: "sha-256:pd956",
    },
  } as EvaluationRequest);

const decisionOptions = (fga: Fga): DecisionOptions => ({
  view: view(),
  fga,
  modelId: "model-956",
  now: () => NOW,
  stalenessBound,
  relationForAction,
});

function recorder(retained: PdpRefusalRecord[]) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const refusals = createPdpRefusalRecorder({
    signer: { kid: "pdp-956", key: privateKey },
    emitterId: "pdp.example",
    scope: AUDIENCE,
    retain: (record) => retained.push(record),
    now: () => NOW,
  });
  const resolve: EvidenceKeyResolver = ({ kid, emitter }) =>
    kid === "pdp-956" && emitter.id === "pdp.example" && emitter.role === "pdp" ? { key: publicKey } : undefined;
  return { refusals, resolve };
}

let handle: PdpHttpServerHandle | undefined;
afterEach(async () => {
  await handle?.close();
  handle = undefined;
});

describe("an unclassified mediated request is a request fault (@spec runtime#classification, authzen#pdp-consistency-checks, runtime-evidence#pre-decision-refusal, #956)", () => {
  it("records the refusal as a PDP-signed Refusal Record action_class_missing over the request as submitted, naming no class, no Mission and no evaluation", async () => {
    const retained: PdpRefusalRecord[] = [];
    const { refusals, resolve } = recorder(retained);
    const { fga, calls } = countingFga();
    const policy = resourcePolicyFixture();
    const emitted: unknown[] = [];
    const evidence = { emit: async (record: unknown) => emitted.push(record) } as unknown as DecisionEvidenceEmitter;
    const options = {
      ...decisionOptions(fga),
      resourcePolicy: policy,
      evidence,
      refusals,
      evaluationContextBinding: EVALUATION_CONTEXT_UNCLAIMED_FIXTURE,
    };
    const unclassified = request(undefined);
    await expect(evaluateRequest(unclassified, options)).rejects.toBeInstanceOf(DecisionRequestRefused);
    expect(retained).toHaveLength(1);
    const record = retained[0] as PdpRefusalRecord;
    expect(record).toMatchObject({
      audience: AUDIENCE,
      action: { name: READ },
      decision: "deny",
      denial_reason: "action_class_missing",
      evaluated_at: NOW.toISOString(),
      evaluation_request_digest: evaluationRequestDigest(unclassified),
      request_digest_input: "decision_request",
      emitter: { id: "pdp.example", role: "pdp" },
    });
    expect(record).not.toHaveProperty("action_class");
    expect(record).not.toHaveProperty("class_source");
    expect(record).not.toHaveProperty("mission");
    expect(record).not.toHaveProperty("evaluation_id");
    expect(JSON.stringify(record)).not.toContain("consequential_read");
    expect(await verifyEvidenceEnvelope(record, REFUSAL_RECORD_MEDIA_TYPE, resolve)).toEqual({ valid: true });
    expect(emitted).toHaveLength(0);
    expect(calls()).toBe(0);
    expect(policy.queries).toHaveLength(0);
    // Control: the PEP-assigned class is evaluated and permitted, with Decision Evidence.
    const classed = await evaluateRequest(request("consequential_read"), options);
    expect(classed.decision, JSON.stringify(classed.context)).toBe(true);
    expect(emitted).toHaveLength(1);
    expect(retained).toHaveLength(1);
  });

  it("the remote PDP refuses an unclassified mediated request before evaluation as action_class_missing, with a signed Refusal Record and no decision work", async () => {
    const retained: PdpRefusalRecord[] = [];
    const { refusals, resolve } = recorder(retained);
    const { fga, calls } = countingFga();
    const policy = resourcePolicyFixture();
    handle = await createPdpHttpServer({
      peps: new Map([[PEP_ID, { secret: SECRET, scopes: [AUDIENCE] }]]),
      getOptions: () => decisionOptions(fga),
      evaluateFn: evaluateRequest,
      resourcePolicy: policy,
      evaluationContextBinding: EVALUATION_CONTEXT_UNCLAIMED_FIXTURE,
      refusals,
    });
    const server = handle;
    const ask = (req: EvaluationRequest) => evaluateRemote(req, { url: server.url, pepId: PEP_ID, secret: SECRET });
    const unclassified = request(undefined);
    const refused = await ask(unclassified);
    expect(refused.decision).toBe(false);
    expect(refused.context).toMatchObject({ denial_reason: "decision_channel_refused", channel_status: 400 });
    expect(refused.context).not.toHaveProperty("decision_evidence");
    expect(refused.context).not.toHaveProperty("evaluation_id");
    expect(retained).toHaveLength(1);
    expect(retained[0]).toMatchObject({
      denial_reason: "action_class_missing",
      decision: "deny",
      evaluation_request_digest: evaluationRequestDigest(unclassified),
      emitter: { id: "pdp.example", role: "pdp" },
    });
    expect(retained[0]).not.toHaveProperty("action_class");
    expect(await verifyEvidenceEnvelope(retained[0] as PdpRefusalRecord, REFUSAL_RECORD_MEDIA_TYPE, resolve)).toEqual({ valid: true });
    expect(calls()).toBe(0);
    expect(policy.queries).toHaveLength(0);
    // Control: the same channel evaluates the request carrying its class.
    const served = await ask(request("consequential_read"));
    expect(served.decision, JSON.stringify(served.context)).toBe(true);
    expect(retained).toHaveLength(1);
  });
});
