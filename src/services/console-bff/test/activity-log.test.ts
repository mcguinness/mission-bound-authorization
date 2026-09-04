/**
 * @spec activity-log (AAM Agent Activity Log) — the read-side join over the
 * UNIFIED evidence contract. Covers: (1) a join over hand-built records from all
 * emitter roles for one Mission, in stable order with the right per-entry
 * fields; (2) the task-run graph (template-dispatched Mission + a continued hop
 * + a Child Mission threaded under the run by lineage/correlation); (3) the
 * ingestion -> Containment Evidence -> `authority_contained` denial correlating
 * into an adjacent sequence by event_id/mission_id; (4) determinism; (5) the
 * no-issuer-source path; and the ConsoleBff read surface (operator role + join).
 */

import { generateKeyPairSync } from "node:crypto";
import { exportJWK, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { MissionKernel, validateMissionIntent } from "@mission/authorization-server";
import type { ContainmentEvidence } from "@mission/authorization-server";
import type { DecisionEvidenceObject, EvidenceEnvelope, Evidence, ExecutionEvidenceObject, RefusalRecordObject } from "@mission/mcp-payments";
import { createDecisionEvidenceEmitter } from "@mission/pdp";
import { buildEvidenceKeyResolver, EvidenceStore } from "@mission/mcp-payments";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { activityByTrace, AuthzError, buildActivityLog, ConsoleBff } from "../src/index.js";
import { testAuthoritySourceCatalog } from "@mission/authorization-server/test-support";

const M = "msn_run_1";
const TRACE = "trace-abc";

/**
 * A structurally-shaped but unverified `evidence_envelope`: these fixtures
 * are hand-built `Evidence` rows exercising the read-side JOIN
 * (`toEntry`/`buildActivityLog`), never signature verification, so a fixed
 * placeholder is fine wherever a `content` object's REQUIRED envelope member
 * is needed only to satisfy the type.
 */
const FAKE_ENVELOPE: EvidenceEnvelope = {
  format: "jws-compact",
  value: "eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIiwidHlwIjoieCIsImN0eSI6InkifQ.e30.sig",
};

/** The emitter role of a raw `Evidence` row, decision/refusal/execution's now living under `.content`. */
function emitterRoleOf(r: Evidence): string | undefined {
  switch (r.kind) {
    case "decision":
    case "refusal":
    case "execution":
      return r.content.emitter.role;
    default:
      return r.emitter?.role;
  }
}

/** One record per emitter role, one Mission, ascending timestamps. */
function allRoleRecords(): Evidence[] {
  const decisionContent: DecisionEvidenceObject = {
    evidence_id: "evd_1",
    evaluation_id: "dec_1",
    mission: { id: M, issuer: "https://as.test", policy_view_id: "pv-1", authority_hash: "sha-256:ah" },
    subject: { id: "alice" },
    resource: { type: "invoice", id: "inv-1" },
    action: { name: "payments:invoice.read" },
    audience: "https://payments.example",
    action_class: "consequential_read",
    class_source: "default",
    decision: "permit",
    entry_digest: "sha-256:entry",
    sequence: 0,
    emitter: { id: "pdp-1", role: "pdp" },
    evaluated_at: "2026-01-01T00:00:01.000Z",
    evidence_envelope: FAKE_ENVELOPE,
  };
  const deniedContent: DecisionEvidenceObject = {
    evidence_id: "evd_2",
    evaluation_id: "dec_2",
    mission: { id: M, issuer: "https://as.test", policy_view_id: "pv-1", authority_hash: "sha-256:ah" },
    subject: { id: "alice" },
    resource: { type: "invoice", id: "inv-1" },
    action: { name: "payments:payment.execute" },
    audience: "https://payments.example",
    action_class: "irreversible_action",
    class_source: "deployment",
    decision: "deny",
    denial_reason: "out_of_authority",
    sequence: 0,
    emitter: { id: "pep-1", role: "pdp" },
    evaluated_at: "2026-01-01T00:00:02.000Z",
    evidence_envelope: FAKE_ENVELOPE,
  };
  const executionContent: ExecutionEvidenceObject = {
    execution_id: "exe_1",
    evaluation_id: "dec_2",
    mission_id: M,
    audience: "https://payments.example",
    outcome: "completed",
    outcome_at: "2026-01-01T00:00:03.000Z",
    sequence: 0,
    emitter: { id: "exec-1", role: "executor" },
    evidence_envelope: FAKE_ENVELOPE,
  };
  const refusalContent: RefusalRecordObject = {
    refusal_id: "ref_1",
    audience: "https://payments.example",
    action: { name: "egress:webhook" },
    decision: "deny",
    denial_reason: "egress_undeclared:webhook",
    evaluated_at: "2026-01-01T00:00:05.000Z",
    mission: { id: M, issuer: "https://as.test", authority_hash: "sha-256:ah" },
    sequence: 1,
    emitter: { id: "harness-1", role: "pep" },
    evidence_envelope: FAKE_ENVELOPE,
  };
  return [
    {
      kind: "decision",
      mission_id: M,
      at: "2026-01-01T00:00:01.000Z",
      trace_id: TRACE,
      content: decisionContent,
    },
    {
      kind: "decision",
      mission_id: M,
      at: "2026-01-01T00:00:02.000Z",
      trace_id: TRACE,
      content: deniedContent,
    },
    {
      kind: "execution",
      mission_id: M,
      permit_id: "p1",
      op_key: "op:1",
      at: "2026-01-01T00:00:03.000Z",
      trace_id: TRACE,
      content: executionContent,
    },
    {
      kind: "egress",
      channel_class: "inference_api",
      destination: "https://api.anthropic.com/v1/messages",
      outcome: "permitted",
      mission_id: M,
      authority_hash: "sha-256:ah",
      action: "egress:inference_api",
      instance_epoch: "e",
      at: "2026-01-01T00:00:04.000Z",
      trace_id: TRACE,
      scope_statement_digest: "sha-256:scope",
      emitter: { id: "egress-1", role: "egress" },
    },
    {
      kind: "refusal",
      mission_id: M,
      at: "2026-01-01T00:00:05.000Z",
      trace_id: TRACE,
      content: refusalContent,
    },
    {
      kind: "ingestion",
      event_type: "vendor.compromised",
      source: "https://threatfeed.example",
      outcome: "applied",
      rule_id: "rule-vendor",
      mission_id: M,
      event_id: "evt-1",
      at: "2026-01-01T00:00:06.000Z",
      trace_id: TRACE,
      emitter: { id: "issuer-1", role: "issuer" },
    },
  ];
}

describe("activity-log join: all emitter roles, one Mission, stable order", () => {
  it("returns every role's record with the right per-entry fields", () => {
    const run = buildActivityLog(M, { evidence: allRoleRecords() });

    expect(run.mission_id).toBe(M);
    expect(run.children).toEqual([]);
    expect(run.entries).toHaveLength(6);
    // Stable order (by timestamp). Decision Evidence's emitter role is
    // ALWAYS `pdp` (runtime-evidence.md #decision-evidence-object); a
    // Refusal Record's is `pdp` or `pep` (this fixture uses `pep`).
    expect(run.entries.map((e) => e.role)).toEqual(["pdp", "pdp", "executor", "egress", "pep", "issuer"]);
    expect(run.entries.map((e) => e.kind)).toEqual([
      "decision",
      "decision",
      "execution",
      "egress",
      "refusal",
      "ingestion",
    ]);

    const [pdp, deny, exec, egress, refusal, ing] = run.entries;
    // PDP decision: resolved-scope anchor + verdict + decision id.
    expect(pdp?.decision).toBe(true);
    expect(pdp?.entry_digest).toBe("sha-256:entry");
    expect(pdp?.decision_id).toBe("dec_1");
    expect(pdp?.emitter_id).toBe("pdp-1");
    // Denial: normalized denial_reason.
    expect(deny?.decision).toBe(false);
    expect(deny?.denial_reason).toBe("out_of_authority");
    // Executor: outcome (runtime-evidence.md's closed enum: completed/failed/suppressed).
    expect(exec?.outcome).toBe("completed");
    // Egress: destination as the requested resource + scope digest.
    expect(egress?.resource).toBe("https://api.anthropic.com/v1/messages");
    expect(egress?.outcome).toBe("permitted");
    expect(egress?.scope_statement_digest).toBe("sha-256:scope");
    // Refusal: denial_reason.
    expect(refusal?.denial_reason).toBe("egress_undeclared:webhook");
    // Issuer ingestion: event type + event id + outcome.
    expect(ing?.action).toBe("vendor.compromised");
    expect(ing?.event_id).toBe("evt-1");
    expect(ing?.outcome).toBe("applied");

    // All correlated by one trace (a task run shares one trace_id).
    expect(run.entries.every((e) => e.trace_id === TRACE)).toBe(true);

    // The trace-grouped view reads the same run as one flat ordered sequence.
    const byTrace = activityByTrace(TRACE, { evidence: allRoleRecords() });
    expect(byTrace.map((e) => e.role)).toEqual(["pdp", "pdp", "executor", "egress", "pep", "issuer"]);
    expect(activityByTrace("nope", { evidence: allRoleRecords() })).toEqual([]);
  });
});

describe("activity-log task-run graph: template -> dispatched Mission -> hop -> child", () => {
  it("threads a continued hop and a Child Mission under the run", () => {
    const template = {
      id: "tmpl_recon",
      issuer: "https://as.test",
      template_version: "1",
      template_hash: "sha-256:tmpl",
      dispatch_policy: "dp-1",
    };
    const parentRef = {
      id: "msn_root",
      issuer: "https://as.test",
      authority_hash: "sha-256:ah",
      depth: 1,
      cascade_mode: "revoke" as const,
    };
    const evidence: Evidence[] = [
      // A continued hop on the root: hop_reference is the join key to the hop.
      // @spec runtime-evidence#decision-evidence-object: Decision Evidence
      // carries no `hop_reference` in this deployment (only Execution
      // Evidence and Refusal Records do; see evidence.ts's file header),
      // so the hop join here is exercised on a Refusal Record instead.
      {
        kind: "refusal",
        mission_id: "msn_root",
        at: "2026-02-01T00:00:01.000Z",
        trace_id: "t-graph",
        content: {
          refusal_id: "ref_root",
          audience: "https://payments.example",
          action: { name: "payments:invoice.read" },
          decision: "deny",
          denial_reason: "permit_expired",
          evaluated_at: "2026-02-01T00:00:01.000Z",
          mission: { id: "msn_root", issuer: "https://as.test", authority_hash: "sha-256:ah" },
          hop_reference: { jti: "jag-1", mission_id: "msn_root", continuation_handle: "handle-1" },
          sequence: 0,
          emitter: { id: "pep-1", role: "pep" },
          evidence_envelope: FAKE_ENVELOPE,
        },
      },
      // A record on the Child Mission.
      {
        kind: "execution",
        mission_id: "msn_child",
        permit_id: "p2",
        op_key: "op:child",
        at: "2026-02-01T00:00:02.000Z",
        trace_id: "t-graph",
        content: {
          execution_id: "exe_2",
          evaluation_id: "dec_child",
          mission_id: "msn_child",
          audience: "https://payments.example",
          outcome: "completed",
          outcome_at: "2026-02-01T00:00:02.000Z",
          sequence: 0,
          emitter: { id: "pep-1", role: "pep" },
          evidence_envelope: FAKE_ENVELOPE,
        },
      },
    ];
    const run = buildActivityLog("msn_root", {
      evidence,
      missions: [
        { id: "msn_root", template },
        { id: "msn_child", parent: parentRef },
      ],
    });

    // Root carries its template lineage and the hop entry.
    expect(run.mission_id).toBe("msn_root");
    expect(run.lineage.template?.id).toBe("tmpl_recon");
    expect(run.entries).toHaveLength(1);
    expect(run.entries[0]?.hop_reference?.jti).toBe("jag-1");
    expect(run.entries[0]?.hop_reference?.continuation_handle).toBe("handle-1");

    // The Child Mission threads under the run via parent lineage.
    expect(run.children).toHaveLength(1);
    const child = run.children[0];
    expect(child?.mission_id).toBe("msn_child");
    expect(child?.lineage.parent?.id).toBe("msn_root");
    expect(child?.entries).toHaveLength(1);
    expect(child?.entries[0]?.outcome).toBe("completed");
  });
});

describe("activity-log correlation: ingestion -> containment -> authority_contained", () => {
  it("places the ingestion, its Containment Evidence, and the denial adjacently", () => {
    const EVT = "evt-contain-1";
    const ingestion: Evidence = {
      kind: "ingestion",
      event_type: "vendor.compromised",
      source: "https://threatfeed.example",
      outcome: "applied",
      rule_id: "rule-vendor",
      mission_id: M,
      event_id: EVT,
      at: "2026-03-01T00:00:01.000Z",
      trace_id: "t-contain",
      emitter: { id: "issuer-1", role: "issuer" },
    };
    const containment: ContainmentEvidence = {
      evidence_id: "cnt_1",
      mission: { id: M, issuer: "https://as.test", authority_hash: "sha-256:ah" },
      event: { type: "vendor.compromised", source: "https://threatfeed.example", observed_at: "2026-03-01T00:00:01.500Z", event_id: EVT },
      policy: "rule-vendor",
      prior_version: 1,
      new_version: 2,
      prior_containment_version: 0,
      new_containment_version: 1,
      removed: [{ resource: "https://payments.example", actions: ["payments:payment.execute"] }],
      created_at: "2026-03-01T00:00:02.000Z",
    };
    const denial: Evidence = {
      kind: "decision",
      mission_id: M,
      at: "2026-03-01T00:00:03.000Z",
      trace_id: "t-contain",
      content: {
        evidence_id: "evd_contained",
        evaluation_id: "dec_contained",
        mission: { id: M, issuer: "https://as.test", policy_view_id: "pv-1", authority_hash: "sha-256:ah" },
        subject: { id: "alice" },
        resource: { type: "invoice", id: "inv-1" },
        action: { name: "payments:payment.execute" },
        audience: "https://payments.example",
        action_class: "irreversible_action",
        class_source: "deployment",
        decision: "deny",
        denial_reason: "authority_contained",
        sequence: 1,
        emitter: { id: "pep-1", role: "pdp" },
        evaluated_at: "2026-03-01T00:00:03.000Z",
        evidence_envelope: FAKE_ENVELOPE,
      },
    };

    const run = buildActivityLog(M, { evidence: [ingestion, denial], containment: [containment] });

    // Adjacent sequence in causal order.
    expect(run.entries.map((e) => e.kind)).toEqual(["ingestion", "containment", "decision"]);
    const [ing, cont, den] = run.entries;
    // Correlation: ingestion and Containment Evidence share the event_id.
    expect(ing?.event_id).toBe(EVT);
    expect(cont?.event_id).toBe(EVT);
    // The Containment Evidence carries the overlay version and issuer role.
    expect(cont?.kind).toBe("containment");
    expect(cont?.role).toBe("issuer");
    expect(cont?.containment_version).toBe(1);
    // The subsequent denial cites authority_contained on the same Mission.
    expect(den?.denial_reason).toBe("authority_contained");
    expect([ing?.mission_id, cont?.mission_id, den?.mission_id]).toEqual([M, M, M]);
  });
});

describe("activity-log determinism and absent sources", () => {
  it("same inputs -> same ordered output, regardless of input array order", () => {
    const records = allRoleRecords();
    const a = buildActivityLog(M, { evidence: records });
    const b = buildActivityLog(M, { evidence: records });
    expect(b).toEqual(a);
    // Timestamp is the primary key, so a reversed input yields the same order.
    const c = buildActivityLog(M, { evidence: [...records].reverse() });
    expect(c.entries.map((e) => e.role)).toEqual(a.entries.map((e) => e.role));
  });

  it("returns a well-formed run when issuer/lineage sources are absent", () => {
    // The no-auth-server demo surface retains no issuer records and passes no
    // Mission lineage: PEP records only, empty children, empty lineage.
    const pepOnly: Evidence[] = allRoleRecords().filter((r) => emitterRoleOf(r) === "pep");
    const run = buildActivityLog(M, { evidence: pepOnly });
    expect(run.mission_id).toBe(M);
    expect(run.lineage).toEqual({});
    expect(run.children).toEqual([]);
    expect(run.entries).toHaveLength(1);
    expect(run.entries[0]?.role).toBe("pep");
  });
});

describe("ConsoleBff.activityLog read surface (operator role + join)", () => {
  let bff: ConsoleBff;
  let missionId: string;

  beforeAll(async () => {
    const keys = await generateKeyPair("ES256", { extractable: true });
    await exportJWK(keys.publicKey);
    const kernel = new MissionKernel({
      issuer: "https://as.test",
      policy: DERIVATION_POLICY as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["ap-agent"], ["bob"]),
      statusKey: keys.privateKey,
      statusKid: "as-status",
    });
    const mission = kernel.approve({
      intent: validateMissionIntent(
        JSON.stringify({
          goal: "Pay",
          target_resources: [DERIVATION_POLICY.ceiling[0].resource],
          expires_at: "2027-01-01T00:00:00Z",
        }),
      ),
      subject: { iss: "https://as.test", sub: "alice" },
      approver: { iss: "https://as.test", sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: "apev-activity",
    });
    missionId = mission.id;

    // Two producer-retained stores, read in place (D32): a PEP store and an
    // egress store. The gate/PEP stay the sole writers; the BFF only reads.
    // @spec runtime-evidence#decision-evidence-object (#741): the PDP emits
    // and signs Decision Evidence; the PEP store verifies and retains it. The
    // BFF reads the retained rows either way.
    const pdpKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const AUDIENCE = "https://payments.example";
    const EMITTER = "https://payments.example/mcp";
    const emitter = createDecisionEvidenceEmitter({
      signer: { kid: "pdp-test", key: pdpKeys.privateKey },
      emitterId: EMITTER,
      audience: AUDIENCE,
    });
    const pepStore = new EvidenceStore(
      undefined,
      buildEvidenceKeyResolver([
        { kid: "pdp-test", publicKey: pdpKeys.publicKey, role: "pdp", emitterId: EMITTER, audience: AUDIENCE },
      ]),
    );
    const egressStore = new EvidenceStore();
    const retained = await pepStore.retainDecision(
      await emitter.emit({
        mission: {
          id: missionId,
          issuer: "https://as.test",
          policy_view_id: "pv-1",
          authority_hash: mission.authority_hash,
        },
        subject: { id: "alice" },
        resource: { type: "invoice", id: "inv-1" },
        action: { name: "payments:invoice.read" },
        audience: AUDIENCE,
        evaluation_id: "dec_activity",
        decision: "permit",
        evaluated_at: new Date().toISOString(),
      }),
    );
    expect(retained.retained).toBe(true);
    egressStore.record({
      kind: "egress",
      channel_class: "inference_api",
      destination: "https://api.anthropic.com/v1/messages",
      outcome: "permitted",
      mission_id: missionId,
      authority_hash: mission.authority_hash,
      action: "egress:inference_api",
      instance_epoch: "e",
      emitter: { id: "egress", role: "egress" },
    });

    bff = new ConsoleBff({
      kernel,
      ars: {} as never,
      transparency: {} as never,
      retrieveEvidence: () => undefined,
      producerJwks: { keys: [] },
      serviceJwks: { keys: [] },
      receiptFor: () => undefined,
      // Issuer source deliberately absent (mirrors the no-auth-server surface).
      activity: { evidence: [pepStore, egressStore] },
    });
  });

  it("requires the operator role on both read methods", () => {
    expect(() => bff.activityLog(undefined, missionId)).toThrow(AuthzError);
    expect(() => bff.activityByTrace(undefined, "t")).toThrow(AuthzError);
    const approver = bff.sessions.create("bob", ["approver"]);
    expect(() => bff.activityLog(approver, missionId)).toThrow(/operator required/);
    expect(() => bff.activityByTrace(approver, "t")).toThrow(/operator required/);
  });

  it("joins the injected producer stores into the Mission's timeline", () => {
    const op = bff.sessions.create("olivia", ["operator"]);
    const run = bff.activityLog(op, missionId);
    expect(run.mission_id).toBe(missionId);
    expect(run.entries).toHaveLength(2);
    expect(new Set(run.entries.map((e) => e.role))).toEqual(new Set(["pdp", "egress"]));
    // The trace method reads the same injected sources; an unmatched trace joins
    // to nothing (record() stamps trace_id only under an active span, absent here).
    expect(bff.activityByTrace(op, "no-such-trace")).toEqual([]);
  });
});
