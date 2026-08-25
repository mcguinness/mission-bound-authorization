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

import { exportJWK, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { MissionKernel, validateMissionIntent } from "@mission/authorization-server";
import type { ContainmentEvidence } from "@mission/authorization-server";
import type { Evidence } from "@mission/mcp-payments";
import { EvidenceStore } from "@mission/mcp-payments";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { activityByTrace, AuthzError, buildActivityLog, ConsoleBff } from "../src/index.js";

const M = "msn_run_1";
const TRACE = "trace-abc";

/** One record per emitter role, one Mission, ascending timestamps. */
function allRoleRecords(): Evidence[] {
  return [
    {
      kind: "decision",
      decision: true,
      mission_id: M,
      authority_hash: "sha-256:ah",
      action: "payments:invoice.read",
      instance_epoch: "e",
      at: "2026-01-01T00:00:01.000Z",
      trace_id: TRACE,
      decision_id: "dec_1",
      policy_view_id: "pv-1",
      entry_digest: "sha-256:entry",
      emitter: { id: "pdp-1", role: "pdp" },
    },
    {
      kind: "decision",
      decision: false,
      mission_id: M,
      authority_hash: "sha-256:ah",
      action: "payments:payment.execute",
      instance_epoch: "e",
      at: "2026-01-01T00:00:02.000Z",
      trace_id: TRACE,
      decision_id: "dec_2",
      denial_reason: "out_of_authority",
      emitter: { id: "pep-1", role: "pep" },
    },
    {
      kind: "execution",
      permit_id: "p1",
      op_key: "op:1",
      outcome: "committed",
      mission_id: M,
      authority_hash: "sha-256:ah",
      action: "payments:payment.execute",
      instance_epoch: "e",
      at: "2026-01-01T00:00:03.000Z",
      trace_id: TRACE,
      emitter: { id: "exec-1", role: "executor" },
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
      refusal_reason: "egress_undeclared:webhook",
      mission_id: M,
      authority_hash: "sha-256:ah",
      action: "egress:webhook",
      instance_epoch: "e",
      at: "2026-01-01T00:00:05.000Z",
      trace_id: TRACE,
      emitter: { id: "harness-1", role: "harness" },
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
    // Stable order (by timestamp): pdp, pep, executor, egress, harness, issuer.
    expect(run.entries.map((e) => e.role)).toEqual(["pdp", "pep", "executor", "egress", "harness", "issuer"]);
    expect(run.entries.map((e) => e.kind)).toEqual([
      "decision",
      "decision",
      "execution",
      "egress",
      "refusal",
      "ingestion",
    ]);

    const [pdp, pep, exec, egress, harness, ing] = run.entries;
    // PDP decision: resolved-scope anchor + verdict + decision id.
    expect(pdp?.decision).toBe(true);
    expect(pdp?.entry_digest).toBe("sha-256:entry");
    expect(pdp?.decision_id).toBe("dec_1");
    expect(pdp?.emitter_id).toBe("pdp-1");
    // PEP denial: normalized denial_reason.
    expect(pep?.decision).toBe(false);
    expect(pep?.denial_reason).toBe("out_of_authority");
    // Executor: outcome.
    expect(exec?.outcome).toBe("committed");
    // Egress: destination as the requested resource + scope digest.
    expect(egress?.resource).toBe("https://api.anthropic.com/v1/messages");
    expect(egress?.outcome).toBe("permitted");
    expect(egress?.scope_statement_digest).toBe("sha-256:scope");
    // Harness refusal: refusal_reason normalized to denial_reason.
    expect(harness?.denial_reason).toBe("egress_undeclared:webhook");
    // Issuer ingestion: event type + event id + outcome.
    expect(ing?.action).toBe("vendor.compromised");
    expect(ing?.event_id).toBe("evt-1");
    expect(ing?.outcome).toBe("applied");

    // All correlated by one trace (a task run shares one trace_id).
    expect(run.entries.every((e) => e.trace_id === TRACE)).toBe(true);

    // The trace-grouped view reads the same run as one flat ordered sequence.
    const byTrace = activityByTrace(TRACE, { evidence: allRoleRecords() });
    expect(byTrace.map((e) => e.role)).toEqual(["pdp", "pep", "executor", "egress", "harness", "issuer"]);
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
      {
        kind: "decision",
        decision: true,
        mission_id: "msn_root",
        authority_hash: "sha-256:ah",
        action: "payments:invoice.read",
        instance_epoch: "e",
        at: "2026-02-01T00:00:01.000Z",
        trace_id: "t-graph",
        decision_id: "dec_root",
        hop_reference: { jti: "jag-1", mission_id: "msn_root", continuation_handle: "handle-1" },
        emitter: { id: "pep-1", role: "pep" },
      },
      // A record on the Child Mission.
      {
        kind: "execution",
        permit_id: "p2",
        op_key: "op:child",
        outcome: "committed",
        mission_id: "msn_child",
        authority_hash: "sha-256:ah-child",
        action: "payments:payment.execute",
        instance_epoch: "e",
        at: "2026-02-01T00:00:02.000Z",
        trace_id: "t-graph",
        emitter: { id: "pep-1", role: "pep" },
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
    expect(child?.entries[0]?.outcome).toBe("committed");
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
      decision: false,
      mission_id: M,
      authority_hash: "sha-256:ah",
      action: "payments:payment.execute",
      instance_epoch: "e",
      at: "2026-03-01T00:00:03.000Z",
      trace_id: "t-contain",
      decision_id: "dec_contained",
      denial_reason: "authority_contained",
      emitter: { id: "pep-1", role: "pep" },
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
    const pepOnly: Evidence[] = allRoleRecords().filter((r) => r.emitter?.role === "pep");
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
    const pepStore = new EvidenceStore();
    const egressStore = new EvidenceStore();
    pepStore.record({
      kind: "decision",
      decision: true,
      mission_id: missionId,
      authority_hash: mission.authority_hash,
      action: "payments:invoice.read",
      instance_epoch: "e",
      emitter: { id: "pep", role: "pep" },
    });
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
    expect(new Set(run.entries.map((e) => e.role))).toEqual(new Set(["pep", "egress"]));
    // The trace method reads the same injected sources; an unmatched trace joins
    // to nothing (record() stamps trace_id only under an active span, absent here).
    expect(bff.activityByTrace(op, "no-such-trace")).toEqual([]);
  });
});
