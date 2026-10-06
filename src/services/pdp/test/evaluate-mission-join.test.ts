/**
 * @spec authority-server#mission-join (#557 review point 1)
 *
 * The PDP's OWN resolution of the baseline MAS Join's rules 3-6, integrated
 * into `evaluate()` via `context.mission_join` / `EvaluateOptions.delegatePolicy`
 * (moved here from a PEP-side helper call, per review: "the spec assigns the
 * subject/client/delegate join to the PDP... carry the ordinary credential
 * facts, propagated Mission reference, mapping result, and delegation depth
 * into the PDP request and resolve there"). `mas-join.test.ts` covers
 * `resolveBaselineJoin` standalone; this file proves the PDP actually calls
 * it, denies before ever exposing a fallback authoritySet, and records
 * `join_view_id` in the signed Decision Evidence of a decision that rode the
 * joined path (rule 9, #972 item 27a), never on the response context.
 */

import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { Fga } from "../src/fga.js";
import { evaluate, type EvaluationRequest, type EvaluateOptions } from "../src/evaluate.js";
import {
  createDecisionEvidenceEmitter,
  DECISION_EVIDENCE_MEDIA_TYPE,
  type DecisionEvidenceObject,
  verifyEvidenceEnvelope,
} from "../src/index.js";
import { MISSION_RESOURCE_ACCESS_TYPE, type AuthorityEntry, type MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBound } from "../src/policy.js";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "../src/test-support.js";

const RESOURCE = "http://localhost:4403/mcp";
const NOW = new Date("2026-08-23T12:00:00Z");
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const READ = "payments:invoice.read";
const SUBJECT = { iss: "https://idp.test", sub: "alice" };

const DIRECT_ENTRY: AuthorityEntry = { type: MISSION_RESOURCE_ACCESS_TYPE, resource: RESOURCE, actions: [READ] };
const DELEGABLE_ENTRY: AuthorityEntry = {
  type: MISSION_RESOURCE_ACCESS_TYPE,
  resource: RESOURCE,
  actions: [READ],
  join_delegation: { max_depth: 1, allowed_delegates: ["delegate-a"] },
};

const view: MissionView = {
  id: "msn_557_pdp",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:testhash",
  authority_set: [DIRECT_ENTRY],
  subject: SUBJECT,
  client_id: "ap-agent",
};

const baseOpts = (extra: Partial<EvaluateOptions> = {}): EvaluateOptions => ({
  view,
  fga: alwaysAllowFga,
  modelId: "unit-test-model",
  now: () => NOW,
  stalenessBound,
  relationForAction,
  resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
  stateSourcePlacement: "pep" as const,
  ...extra,
});

/**
 * Evaluate with a real Decision Evidence emitter and return the signed record
 * an independent verifier accepted, so every `join_view_id` assertion below
 * reads the SIGNED record, not an unsigned copy.
 */
async function evaluated(request: EvaluationRequest, opts: EvaluateOptions) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const kid = "pdp-join-evidence-test";
  const emitter = createDecisionEvidenceEmitter({ signer: { kid, key: privateKey }, emitterId: RESOURCE, audience: RESOURCE });
  const resolve = (params: { kid: string; emitter: { id: string; role: string }; audience?: string }) =>
    params.kid === kid && params.emitter.role === "pdp" && params.emitter.id === RESOURCE && params.audience === RESOURCE
      ? { key: publicKey }
      : undefined;
  const decision = await evaluate(request, { ...opts, evidence: emitter });
  const record = decision.context.decision_evidence as DecisionEvidenceObject;
  expect(await verifyEvidenceEnvelope(record, DECISION_EVIDENCE_MEDIA_TYPE, resolve)).toEqual({ valid: true });
  return { decision, record, resolve };
}

/** A `fresh` Mission state observation read at the decision instant. */
const OBSERVED = { state: "active", mode: "fresh", freshness_at: NOW.toISOString() };

const joinReq = (over: Partial<EvaluationRequest> = {}): EvaluationRequest => ({
  subject: { id: SUBJECT.sub, properties: { iss: SUBJECT.iss } },
  resource: { type: "invoice", id: "inv-1", properties: { audience: RESOURCE, vendor_id: "acme" } },
  action: { name: READ },
  context: {
    mission: { id: view.id, issuer: view.issuer },
    actor: { client_id: "ap-agent" },
    mission_join: {},
    // REQUIRED under the declared pep placement (#1049 owner ruling).
    mission_state_observation: OBSERVED,
  },
  ...over,
});

describe("evaluate(): baseline MAS Join, direct client (@spec authority-server#mission-join rules 1-4, 7, #557 review point 1)", () => {
  it("permits when context.mission_join is present and the subject/client match directly, recording join_view_id in its signed Decision Evidence", async () => {
    const { decision, record } = await evaluated(joinReq(), baseOpts());
    expect(decision.decision, JSON.stringify(decision)).toBe(true);
    expect(record.join_view_id).toMatch(/^sha-256:/);
  });

  it("never records join_view_id for an ORDINARY Mission-bound request (context.mission_join absent): the existing path is untouched", async () => {
    const { decision, record } = await evaluated(
      joinReq({
        context: {
          mission: { id: view.id, issuer: view.issuer },
          actor: { client_id: "ap-agent" },
          mission_state_observation: OBSERVED,
        },
      }),
      baseOpts(),
    );
    expect(decision.decision, JSON.stringify(decision)).toBe(true);
    expect(record).not.toHaveProperty("join_view_id");
  });
});

describe("evaluate(): the joined-view commitment rides signed Decision Evidence only (@spec authority-server#join-rules rule 9, #972 item 27a)", () => {
  it("signs join_view_id into the record: altering it fails verification", async () => {
    const { record, resolve } = await evaluated(joinReq(), baseOpts());
    expect(record.join_view_id).toMatch(/^sha-256:/);
    const altered = { ...record, join_view_id: "sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" };
    expect((await verifyEvidenceEnvelope(altered, DECISION_EVIDENCE_MEDIA_TYPE, resolve)).valid).toBe(false);
  });

  it("carries no view identifier on the AuthZEN response context of a joined decision", async () => {
    const { decision } = await evaluated(joinReq(), baseOpts());
    expect(decision.context).not.toHaveProperty("join_view_id");
  });

  it("records the same join_view_id on a policy denial reached after a successful join", async () => {
    const permit = await evaluated(joinReq(), baseOpts());
    const denial = await evaluated(joinReq({ action: { name: "payments:invoice.approve" } }), baseOpts());
    expect(denial.decision.decision).toBe(false);
    expect(denial.record.denial_reason).not.toBe("mission_binding_failed");
    expect(denial.record.join_view_id).toMatch(/^sha-256:/);
    expect(denial.record.join_view_id).toBe(permit.record.join_view_id);
  });

  it("omits join_view_id from the Decision Evidence of a failed join", async () => {
    const { decision, record } = await evaluated(
      joinReq({ subject: { id: "mallory", properties: { iss: SUBJECT.iss } } }),
      baseOpts(),
    );
    expect(decision.decision).toBe(false);
    expect(record.denial_reason).toBe("mission_binding_failed");
    expect(record).not.toHaveProperty("join_view_id");
  });
});

describe("evaluate(): baseline MAS Join, mission_binding_failed (@spec authority-server#mission-join rule 6, #557 review point 1)", () => {
  it("denies mission_binding_failed when the authenticated subject does not match the Mission's subject, resolved BY THE PDP", async () => {
    const decision = await evaluate(
      joinReq({ subject: { id: "mallory", properties: { iss: SUBJECT.iss } } }),
      baseOpts(),
    );
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("mission_binding_failed");
    // No fallback: a failed join never exposes any authoritySet-derived
    // evidence (rule 6).
    expect(decision.context.entry_digest).toBeUndefined();
  });

  it("denies mission_binding_failed when context.actor.client_id is missing entirely on the Join path", async () => {
    const decision = await evaluate(joinReq({ context: { ...joinReq().context, actor: undefined } }), baseOpts());
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("mission_binding_failed");
  });

  it("denies mission_binding_failed for an unrecognized client with no delegate policy configured, never falling back to the Mission's full authority", async () => {
    const decision = await evaluate(
      joinReq({ context: { ...joinReq().context, actor: { client_id: "unrecognized-client" } } }),
      baseOpts(),
    );
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("mission_binding_failed");
  });
});

describe("evaluate(): baseline MAS Join, delegate narrowing (@spec authority-server#mission-join rule 5, #557 review point 1)", () => {
  const delegateView: MissionView = { ...view, authority_set: [DIRECT_ENTRY, DELEGABLE_ENTRY] };

  it("permits an authorized delegate within its recorded depth, narrowed to the delegable subset, and carries delegate_depth from the request", async () => {
    const decision = await evaluate(
      joinReq({
        context: {
          ...joinReq().context,
          actor: { client_id: "delegate-a" },
          mission_join: { delegate_depth: 1 },
        },
      }),
      baseOpts({ view: delegateView, delegatePolicy: { delegates: { "delegate-a": { maxDepth: 3 } } } }),
    );
    expect(decision.decision, JSON.stringify(decision)).toBe(true);
  });

  it("denies mission_binding_failed for a delegate whose recorded depth exceeds the entry's own join_delegation.max_depth, even though the deployment's DelegatePolicy permits deeper delegation (#557 review point 3)", async () => {
    const decision = await evaluate(
      joinReq({
        context: {
          ...joinReq().context,
          actor: { client_id: "delegate-a" },
          mission_join: { delegate_depth: 2 }, // exceeds DELEGABLE_ENTRY's join_delegation.max_depth: 1
        },
      }),
      baseOpts({ view: delegateView, delegatePolicy: { delegates: { "delegate-a": { maxDepth: 3 } } } }),
    );
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("mission_binding_failed");
  });

  it("records a DIFFERENT join_view_id for the delegate's narrowed view than the direct client's full view", async () => {
    const direct = await evaluated(joinReq(), baseOpts());
    const delegate = await evaluated(
      joinReq({
        context: {
          ...joinReq().context,
          actor: { client_id: "delegate-a" },
          mission_join: { delegate_depth: 1 },
        },
      }),
      baseOpts({ view: delegateView, delegatePolicy: { delegates: { "delegate-a": { maxDepth: 3 } } } }),
    );
    expect(direct.decision.decision).toBe(true);
    expect(delegate.decision.decision).toBe(true);
    expect(delegate.record.join_view_id).toMatch(/^sha-256:/);
    expect(delegate.record.join_view_id).not.toBe(direct.record.join_view_id);
  });
});
