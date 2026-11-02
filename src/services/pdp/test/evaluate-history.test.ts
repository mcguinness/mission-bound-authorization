/**
 * @spec authzen#context-history, runtime-evidence#evidence-extensions
 * `mission_history` (#2015, D1223)
 *
 * The PDP's own policy selects the history predicates an operation requires;
 * the PDP evaluates each against the deployment's retained evidence, verifying
 * every record against the trusted signer for its role, validating each
 * Execution Evidence record's link to a permit of the same Mission and
 * audience, and failing closed when the history cannot be established. No
 * outcome comes from the request. The outcomes are recorded in Decision
 * Evidence on every decision once policy selected a predicate.
 *
 * The retained records here are signed directly, a Decision Evidence key for
 * the `pdp` role and an Execution Evidence key for the `pep` role, and the
 * resolver binds each key to its emitter's scope. The clock is fixed at one
 * instant (D1091); no OpenFGA is needed.
 */

import { generateKeyPairSync } from "node:crypto";
import { pinnedToCurrentContract } from "@mission/demo-data";
import { afterEach, describe, expect, it } from "vitest";
import { evaluateRemote } from "../src/client.js";
import type { Fga } from "../src/fga.js";
import {
  createDecisionEvidenceEmitter,
  DECISION_EVIDENCE_MEDIA_TYPE,
  type DecisionEvidenceObject,
  EXECUTION_EVIDENCE_MEDIA_TYPE,
  evaluate,
  type EvaluateOptions,
  type EvaluationRequest,
  type EvidenceKeyResolver,
  type HistoryBinding,
  type HistoryPredicate,
  type MissionView,
  relationForAction,
  signEvidenceEnvelope,
  stalenessBound,
} from "../src/index.js";
import { createPdpHttpServer, type PdpHttpServerHandle } from "../src/server.js";
import {
  EVALUATION_CONTEXT_UNCLAIMED_FIXTURE,
  RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
  withCurrentContractReference,
} from "../src/test-support.js";
import { openTestClaims } from "./claim-fixture.js";
import { withCredential } from "./with-credential.js";

const RESOURCE = "http://localhost:4403/mcp";
const OTHER_AUDIENCE = "http://localhost:4499/other";
const ISSUER = "https://as.test";
const MISSION = "msn_history_1";
const NOW = new Date("2026-09-14T12:00:00Z");
const READ = "payments:invoice.read";
const PDP_ID = "pdp.history";
const PEP_ID = "pep.history";
const allowFga = { checkWithContext: async () => true } as unknown as Fga;

const pdpKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });
const pepKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });
const rogueKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });

/** Binds each key to its emitter's role and id; anything else resolves to no key. */
const resolveKey: EvidenceKeyResolver = ({ kid, emitter }) => {
  if (kid === "hist-pdp" && emitter.role === "pdp" && emitter.id === PDP_ID) return { key: pdpKeys.publicKey };
  if (kid === "hist-pep" && emitter.role === "pep" && emitter.id === PEP_ID) return { key: pepKeys.publicKey };
  return undefined;
};

interface DecisionShape {
  evaluation_id: string;
  action_class: string;
  action_classes?: string[];
  decision?: "permit" | "deny";
  mission?: string;
  audience?: string;
  /** This record's position in the PDP's (Mission, emitter) stream; 0 unless the store holds more than one. */
  sequence?: number;
}

/** A record signed in the PEP's role with the PEP's own trusted key: a valid signature, the wrong signer for a decision. */
const AS_PEP = { key: pepKeys.privateKey, kid: "hist-pep", emitter: { id: PEP_ID, role: "pep" } };

/** A retained Decision Evidence record, signed by the trusted PDP key unless `key` (or `as`) says otherwise. */
async function decisionRecord(
  d: DecisionShape,
  key = pdpKeys.privateKey,
  as?: { key: typeof pdpKeys.privateKey; kid: string; emitter: { id: string; role: string } },
): Promise<Record<string, unknown>> {
  const unsigned = {
    evidence_id: `evd_${d.evaluation_id}`,
    evaluation_id: d.evaluation_id,
    mission: { id: d.mission ?? MISSION, issuer: ISSUER, policy_view_id: "pv_history" },
    subject: { id: "alice" },
    resource: { type: "invoice", id: "inv-1" },
    action: { name: "payments:payment.schedule" },
    audience: d.audience ?? RESOURCE,
    action_class: d.action_class,
    ...(d.action_classes !== undefined ? { action_classes: d.action_classes } : {}),
    class_source: "deployment",
    decision: d.decision ?? "permit",
    sequence: d.sequence ?? 0,
    emitter: as?.emitter ?? { id: PDP_ID, role: "pdp" },
    evaluated_at: NOW.toISOString(),
  };
  return {
    ...unsigned,
    evidence_envelope: await signEvidenceEnvelope(unsigned, DECISION_EVIDENCE_MEDIA_TYPE, { kid: as?.kid ?? "hist-pdp", key: as?.key ?? key }),
  };
}

interface ExecutionShape {
  evaluation_id: string;
  outcome: "completed" | "failed" | "suppressed";
  mission?: string;
  audience?: string;
  /** This record's position in the PEP's (Mission, emitter) stream. */
  sequence?: number;
}

/** A retained Execution Evidence record, signed by the trusted PEP key. */
async function executionRecord(e: ExecutionShape): Promise<Record<string, unknown>> {
  const unsigned = {
    execution_id: `exe_${e.evaluation_id}_${e.outcome}`,
    evaluation_id: e.evaluation_id,
    mission_id: e.mission ?? MISSION,
    audience: e.audience ?? RESOURCE,
    outcome: e.outcome,
    outcome_at: NOW.toISOString(),
    sequence: e.sequence ?? 0,
    emitter: { id: PEP_ID, role: "pep" },
  };
  return {
    ...unsigned,
    evidence_envelope: await signEvidenceEnvelope(unsigned, EXECUTION_EVIDENCE_MEDIA_TYPE, { kid: "hist-pep", key: pepKeys.privateKey }),
  };
}

const WRITE_COMPLETED: HistoryPredicate = { predicate: "action_class_completed", action_class: "consequential_write" };

/** A history binding whose policy selects `selected` for the read, over `records` (or a reader that fails). */
function historyBinding(
  records: ReadonlyArray<unknown> | "unavailable",
  selected: HistoryPredicate[] = [WRITE_COMPLETED],
  seen: Array<{ id: string; issuer: string }> = [],
): HistoryBinding {
  return {
    policy: (input) => (input.action === READ ? selected : []),
    reader: {
      records: async (mission) => {
        seen.push(mission);
        if (records === "unavailable") throw new Error("evidence store unavailable");
        return records;
      },
    },
    resolveKey,
  };
}

const view: MissionView = {
  id: MISSION,
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:historyhash",
  authority_set: [pinnedToCurrentContract({ type: "mission_resource_access" as const, resource: RESOURCE, actions: [READ] })],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
};

const request = (extra: Record<string, unknown> = {}, missionId = MISSION): EvaluationRequest =>
  withCredential(
    withCurrentContractReference({
      subject: { id: "alice" },
      resource: { type: "invoice", id: "inv-1", properties: { audience: RESOURCE, operation_target: RESOURCE, vendor_id: "acme" } },
      action: { name: READ },
      context: {
        mission: { id: missionId, issuer: ISSUER, authority_hash: "sha-256:historyhash" },
        action_class: "consequential_read",
        mission_state_observation: { state: "active", mode: "fresh", freshness_at: NOW.toISOString() },
        ...extra,
      },
    } as EvaluationRequest),
  );

function emitter() {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return createDecisionEvidenceEmitter({ signer: { kid: "history-test", key: privateKey }, emitterId: RESOURCE, audience: RESOURCE });
}

const options = (history: HistoryBinding | undefined): EvaluateOptions =>
  ({
    view,
    fga: allowFga,
    modelId: "history-test-model",
    now: () => NOW,
    stalenessBound,
    relationForAction,
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
    evaluationContextBinding: EVALUATION_CONTEXT_UNCLAIMED_FIXTURE,
    stateSourcePlacement: "pep",
    claims: openTestClaims({ now: () => NOW }),
    evidence: emitter(),
    ...(history ? { history } : {}),
  }) as EvaluateOptions;

const historyOf = (decision: { context: Record<string, unknown> }) =>
  (decision.context.decision_evidence as DecisionEvidenceObject).mission_history;

describe("the History Context evaluates policy-selected predicates against verified, linked retained evidence (@spec authzen#context-history, #2015)", () => {
  it("permits when a verified consequential_write permit has a linked completed execution, reads only the established Mission's history, and records the outcome", async () => {
    const seen: Array<{ id: string; issuer: string }> = [];
    const records = [await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write" }), await executionRecord({ evaluation_id: "w1", outcome: "completed" })];
    const decision = await evaluate(request(), options(historyBinding(records, [WRITE_COMPLETED], seen)));
    expect(decision.decision, JSON.stringify(decision.context)).toBe(true);
    expect(seen).toEqual([{ id: MISSION, issuer: ISSUER }]);
    expect(historyOf(decision)).toEqual([{ predicate: "action_class_completed", action_class: "consequential_write", outcome: "satisfied" }]);
    // Control: without a history binding no predicate is selected and none is recorded.
    const unbound = await evaluate(request(), options(undefined));
    expect(unbound.decision).toBe(true);
    expect(historyOf(unbound)).toBeUndefined();
  });

  it("denies history_not_satisfied, recording not_satisfied, when no permit of the class is retained", async () => {
    const records = [await decisionRecord({ evaluation_id: "r1", action_class: "consequential_read" }), await executionRecord({ evaluation_id: "r1", outcome: "completed" })];
    const decision = await evaluate(request(), options(historyBinding(records)));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(decision)).toEqual([{ predicate: "action_class_completed", action_class: "consequential_write", outcome: "not_satisfied" }]);
  });

  it("denies history_not_satisfied when a permit of the class has no completed execution: one failed, one with none", async () => {
    const failed = [await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write" }), await executionRecord({ evaluation_id: "w1", outcome: "failed" })];
    const decision = await evaluate(request(), options(historyBinding(failed)));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(decision)?.[0]?.outcome).toBe("not_satisfied");
    const pending = [
      await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write" }),
      await executionRecord({ evaluation_id: "w1", outcome: "completed" }),
      await decisionRecord({ evaluation_id: "w2", action_class: "consequential_write", sequence: 1 }),
    ];
    const second = await evaluate(request(), options(historyBinding(pending)));
    expect(second.decision).toBe(false);
    expect(historyOf(second)?.[0]?.outcome).toBe("not_satisfied");
  });

  it("fails closed when the PDP's Decision Evidence stream is incomplete: a sequence gap, a reused position, or no valid position", async () => {
    // Control: a contiguous stream of two completed writes satisfies the predicate.
    const w1 = await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write", sequence: 0 });
    const w1Done = await executionRecord({ evaluation_id: "w1", outcome: "completed", sequence: 0 });
    const w3Done = await executionRecord({ evaluation_id: "w3", outcome: "completed", sequence: 1 });
    const contiguous = [w1, w1Done, await decisionRecord({ evaluation_id: "w3", action_class: "consequential_write", sequence: 1 }), w3Done];
    const satisfied = await evaluate(request(), options(historyBinding(contiguous)));
    expect(satisfied.decision, JSON.stringify(satisfied.context)).toBe(true);
    // The store omits position 1, a permit of the class with no completed execution:
    // every permit it returns completed, but the history is not complete.
    const gap = [w1, w1Done, await decisionRecord({ evaluation_id: "w3", action_class: "consequential_write", sequence: 2 }), w3Done];
    const omitted = await evaluate(request(), options(historyBinding(gap)));
    expect(omitted.decision).toBe(false);
    expect(omitted.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(omitted)).toEqual([{ predicate: "action_class_completed", action_class: "consequential_write", outcome: "unavailable" }]);
    // Two records at one position: the emitter never issues a position twice.
    const reused = [w1, w1Done, await decisionRecord({ evaluation_id: "w3", action_class: "consequential_write", sequence: 0 }), w3Done];
    const twice = await evaluate(request(), options(historyBinding(reused)));
    expect(twice.decision).toBe(false);
    expect(twice.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(twice)?.[0]?.outcome).toBe("unavailable");
    // A record with no valid position cannot be placed in the stream.
    const unplaced = [await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write", sequence: -1 }), w1Done];
    const negative = await evaluate(request(), options(historyBinding(unplaced)));
    expect(negative.decision).toBe(false);
    expect(negative.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(negative)?.[0]?.outcome).toBe("unavailable");
  });

  it("fails closed, recording unavailable, when the evidence store cannot be consulted", async () => {
    const decision = await evaluate(request(), options(historyBinding("unavailable")));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(decision)).toEqual([{ predicate: "action_class_completed", action_class: "consequential_write", outcome: "unavailable" }]);
  });

  it("fails closed when a retained record does not verify: a permit signed by an untrusted key, or an execution altered after signing", async () => {
    const forged = [
      await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write" }, rogueKeys.privateKey),
      await executionRecord({ evaluation_id: "w1", outcome: "completed" }),
    ];
    const decision = await evaluate(request(), options(historyBinding(forged)));
    expect(decision.decision).toBe(false);
    expect(historyOf(decision)?.[0]?.outcome).toBe("unavailable");
    const failedExecution = await executionRecord({ evaluation_id: "w1", outcome: "failed" });
    const altered = [
      await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write" }),
      { ...failedExecution, outcome: "completed" },
    ];
    const second = await evaluate(request(), options(historyBinding(altered)));
    expect(second.decision).toBe(false);
    expect(historyOf(second)?.[0]?.outcome).toBe("unavailable");
  });

  it("fails closed when an execution's link cannot be established: recorded for another audience, or naming no retained permit", async () => {
    const otherAudience = [
      await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write" }),
      await executionRecord({ evaluation_id: "w1", outcome: "completed", audience: OTHER_AUDIENCE }),
    ];
    const decision = await evaluate(request(), options(historyBinding(otherAudience)));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(decision)?.[0]?.outcome).toBe("unavailable");
    const orphan = [
      await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write" }),
      await executionRecord({ evaluation_id: "w1", outcome: "completed" }),
      await executionRecord({ evaluation_id: "w-missing", outcome: "completed" }),
    ];
    const second = await evaluate(request(), options(historyBinding(orphan)));
    expect(second.decision).toBe(false);
    expect(historyOf(second)?.[0]?.outcome).toBe("unavailable");
  });

  it("fails closed when the store returns a record of another Mission", async () => {
    const records = [
      await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write" }),
      await executionRecord({ evaluation_id: "w1", outcome: "completed" }),
      await decisionRecord({ evaluation_id: "x1", action_class: "consequential_write", mission: "msn_other" }),
    ];
    const decision = await evaluate(request(), options(historyBinding(records)));
    expect(decision.decision).toBe(false);
    expect(historyOf(decision)?.[0]?.outcome).toBe("unavailable");
  });

  it("never counts another Mission's history: a store holding only another Mission's completed write fails closed", async () => {
    const records = [
      await decisionRecord({ evaluation_id: "x1", action_class: "consequential_write", mission: "msn_other" }),
      await executionRecord({ evaluation_id: "x1", outcome: "completed", mission: "msn_other" }),
    ];
    const decision = await evaluate(request(), options(historyBinding(records)));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(decision)?.[0]?.outcome).toBe("unavailable");
  });

  it("does not take a permit signed in the PEP's role as Decision Evidence, although its key verifies for that role", async () => {
    const records = [
      await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write" }, undefined, AS_PEP),
      await executionRecord({ evaluation_id: "w1", outcome: "completed" }),
    ];
    const decision = await evaluate(request(), options(historyBinding(records)));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(decision)?.[0]?.outcome).toBe("unavailable");
  });

  it("does not accept a predicate outcome asserted through context.mission_history: the outcome comes from the evidence, never the request", async () => {
    const asserted = {
      mission_history: {
        attribute_values: { action_class_completed: true, consequential_write: "satisfied" },
        outcome: "satisfied",
        results: [{ predicate: "action_class_completed", action_class: "consequential_write", outcome: "satisfied" }],
      },
    };
    const decision = await evaluate(request(asserted), options(historyBinding([])));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(decision)).toEqual([{ predicate: "action_class_completed", action_class: "consequential_write", outcome: "not_satisfied" }]);
  });

  it("refuses an unrecognized policy-selected predicate as not establishable, even where every recognized one is satisfied", async () => {
    const records = [await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write" }), await executionRecord({ evaluation_id: "w1", outcome: "completed" })];
    const decision = await evaluate(request(), options(historyBinding(records, [WRITE_COMPLETED, { predicate: "backup_was_recent" }])));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(decision)).toEqual([
      { predicate: "action_class_completed", action_class: "consequential_write", outcome: "satisfied" },
      { predicate: "backup_was_recent", outcome: "unavailable" },
    ]);
  });

  it("counts a permit by membership in action_classes, so a pending execution of a further class keeps the predicate unsatisfied", async () => {
    const commit: HistoryPredicate = { predicate: "action_class_completed", action_class: "external_commitment" };
    const completedSingle = [
      await decisionRecord({ evaluation_id: "e1", action_class: "external_commitment" }),
      await executionRecord({ evaluation_id: "e1", outcome: "completed" }),
    ];
    const satisfied = await evaluate(request(), options(historyBinding(completedSingle, [commit])));
    expect(satisfied.decision, JSON.stringify(satisfied.context)).toBe(true);
    const withPendingFurther = [
      ...completedSingle,
      await decisionRecord({ evaluation_id: "p1", action_class: "irreversible_action", action_classes: ["irreversible_action", "external_commitment"], sequence: 1 }),
    ];
    const pending = await evaluate(request(), options(historyBinding(withPendingFurther, [commit])));
    expect(pending.decision).toBe(false);
    expect(pending.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(pending)?.[0]?.outcome).toBe("not_satisfied");
  });

  it("falls back to action_class only where action_classes is absent: a record listing action_classes is counted by membership alone", async () => {
    const records = [
      await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write" }),
      await executionRecord({ evaluation_id: "w1", outcome: "completed" }),
      // Signed by the trusted PDP but listing classes that exclude its own `action_class`:
      // it is not a consequential_write permit, so its missing execution does not count.
      await decisionRecord({ evaluation_id: "x1", action_class: "consequential_write", action_classes: ["irreversible_action", "external_commitment"], sequence: 1 }),
    ];
    const decision = await evaluate(request(), options(historyBinding(records)));
    expect(decision.decision, JSON.stringify(decision.context)).toBe(true);
    expect(historyOf(decision)?.[0]?.outcome).toBe("satisfied");
  });

  it("records mission_history on a decision denied before the Mission is established, each selected predicate unavailable", async () => {
    const records = [await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write" }), await executionRecord({ evaluation_id: "w1", outcome: "completed" })];
    const seen: Array<{ id: string; issuer: string }> = [];
    const decision = await evaluate(request({}, "msn_not_this_view"), options(historyBinding(records, [WRITE_COMPLETED], seen)));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("view_inconsistent");
    expect(seen).toHaveLength(0);
    expect(historyOf(decision)).toEqual([{ predicate: "action_class_completed", action_class: "consequential_write", outcome: "unavailable" }]);
  });
});

describe("the remote PDP binds the history PDP-side (@spec authzen#context-history, #2015)", () => {
  let handle: PdpHttpServerHandle | undefined;
  afterEach(async () => {
    await handle?.close();
    handle = undefined;
  });

  it("denies history_not_satisfied over the decision channel under its own binding, and permits once the retained history satisfies it", async () => {
    const SECRET = "history-shared-secret";
    let records: unknown[] = [];
    const binding: HistoryBinding = {
      policy: (input) => (input.action === READ ? [WRITE_COMPLETED] : []),
      reader: { records: async () => records },
      resolveKey,
    };
    const callerOptions = { ...options(undefined) } as Partial<EvaluateOptions>;
    delete callerOptions.evidence;
    delete callerOptions.claims;
    handle = await createPdpHttpServer({
      peps: new Map([[PEP_ID, { secret: SECRET, scopes: [RESOURCE] }]]),
      getOptions: () => callerOptions as never,
      evaluateFn: evaluate,
      resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
      evaluationContextBinding: EVALUATION_CONTEXT_UNCLAIMED_FIXTURE,
      history: binding,
    });
    const server = handle;
    const ask = (req: EvaluationRequest) => evaluateRemote(req, { url: server.url, pepId: PEP_ID, secret: SECRET });
    const denied = await ask(request());
    expect(denied.decision).toBe(false);
    expect(denied.context.denial_reason).toBe("history_not_satisfied");
    records = [await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write" }), await executionRecord({ evaluation_id: "w1", outcome: "completed" })];
    const permitted = await ask(request());
    expect(permitted.decision, JSON.stringify(permitted.context)).toBe(true);
  });
});
