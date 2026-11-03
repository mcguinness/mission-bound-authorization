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
 * resolver binds each key to its emitter's role and id, as
 * `HistoryBinding.resolveKey` requires. The clock is fixed at one
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
  type HistorySelectionInput,
  type MissionView,
  REFUSAL_RECORD_MEDIA_TYPE,
  relationForAction,
  signEvidenceEnvelope,
  stalenessBound,
  type UnauthorizedExecutionFlag,
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
  /** Members signed as given, replacing the shape's own: how a malformed record is built. */
  overrides?: Record<string, unknown>;
  /** Members left out of the signed record. */
  omit?: string[];
}

/** The signed record: `base` with `overrides` applied and `omit` removed. */
function shaped(base: Record<string, unknown>, overrides: Record<string, unknown> = {}, omit: string[] = []): Record<string, unknown> {
  const out: Record<string, unknown> = { ...base, ...overrides };
  for (const member of omit) delete out[member];
  return out;
}

/** A record signed in the PEP's role with the PEP's own trusted key: a valid signature, the wrong signer for a decision. */
const AS_PEP = { key: pepKeys.privateKey, kid: "hist-pep", emitter: { id: PEP_ID, role: "pep" } };

/** The PEP's own key and id, the record claiming the `pdp` role: the resolver publishes that key for `pep` only. */
const PEP_KEY_CLAIMING_PDP = { key: pepKeys.privateKey, kid: "hist-pep", emitter: { id: PEP_ID, role: "pdp" } };

/** The PDP's own key, signing an Execution Evidence record in its `pdp` role: a valid signature, the wrong signer for an execution. */
const AS_PDP = { key: pdpKeys.privateKey, kid: "hist-pdp", emitter: { id: PDP_ID, role: "pdp" } };

/** The classes whose permits carry `use_limit: 1` (runtime#classification, authzen#decision-conditions). */
const HIGH_CONSEQUENCE = ["irreversible_action", "external_commitment", "privileged_administration"];

/** A permit's validity bound, one minute past the fixed clock. */
const VALID_UNTIL = "2026-09-14T12:01:00Z";

/**
 * A retained Decision Evidence record, signed by the trusted PDP key unless `key` (or `as`) says otherwise.
 * A permit carries the `conditions` it requires: `valid_until`, and `use_limit: 1` where a
 * high-consequence class applies; a lower-consequence permit carries no use limit.
 */
async function decisionRecord(
  d: DecisionShape,
  key = pdpKeys.privateKey,
  as?: { key: typeof pdpKeys.privateKey; kid: string; emitter: { id: string; role: string } },
): Promise<Record<string, unknown>> {
  const unsigned = shaped({
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
    ...((d.decision ?? "permit") === "permit"
      ? {
          conditions: {
            valid_until: VALID_UNTIL,
            ...((d.action_classes ?? [d.action_class]).some((c) => HIGH_CONSEQUENCE.includes(c)) ? { use_limit: 1 } : {}),
          },
        }
      : {}),
    sequence: d.sequence ?? 0,
    emitter: as?.emitter ?? { id: PDP_ID, role: "pdp" },
    evaluated_at: NOW.toISOString(),
  }, d.overrides, d.omit);
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
  /** Defaults to one id per (evaluation, outcome). */
  execution_id?: string;
  outcome_at?: string;
  /** Members signed as given, replacing the shape's own. */
  overrides?: Record<string, unknown>;
  /** Members left out of the signed record. */
  omit?: string[];
}

/** A retained Execution Evidence record, signed by the trusted PEP key unless `as` says otherwise. */
async function executionRecord(
  e: ExecutionShape,
  as?: { key: typeof pepKeys.privateKey; kid: string; emitter: { id: string; role: string } },
): Promise<Record<string, unknown>> {
  const unsigned = shaped({
    execution_id: e.execution_id ?? `exe_${e.evaluation_id}_${e.outcome}`,
    evaluation_id: e.evaluation_id,
    mission_id: e.mission ?? MISSION,
    audience: e.audience ?? RESOURCE,
    outcome: e.outcome,
    outcome_at: e.outcome_at ?? NOW.toISOString(),
    sequence: e.sequence ?? 0,
    emitter: as?.emitter ?? { id: PEP_ID, role: "pep" },
  }, e.overrides, e.omit);
  return {
    ...unsigned,
    evidence_envelope: await signEvidenceEnvelope(unsigned, EXECUTION_EVIDENCE_MEDIA_TYPE, { kid: as?.kid ?? "hist-pep", key: as?.key ?? pepKeys.privateKey }),
  };
}

const WRITE_COMPLETED: HistoryPredicate = { predicate: "action_class_completed", action_class: "consequential_write" };

/** Digests in the canonical `sha-256:` form: a permit's parameter digest, another, and its context digest. */
const DIGEST_A = `sha-256:${Buffer.alloc(32, 1).toString("base64url")}`;
const DIGEST_B = `sha-256:${Buffer.alloc(32, 2).toString("base64url")}`;
const DIGEST_C = `sha-256:${Buffer.alloc(32, 3).toString("base64url")}`;

/** An execution's authorized digests, mirroring a permit bound to DIGEST_A and DIGEST_C. */
const AUTHORIZED = { authorized_parameter_digest: DIGEST_A, authorized_evaluation_context_digest: DIGEST_C };

/** `binding` with a sink collecting every unauthorized-execution flag into `flags`. */
function flagging(binding: HistoryBinding, flags: UnauthorizedExecutionFlag[]): HistoryBinding {
  return { ...binding, onUnauthorizedExecution: (flag) => flags.push(flag) };
}

/** A single-use permit's decision conditions. */
const SINGLE_USE = { use_limit: 1, valid_until: VALID_UNTIL };

/** The predicate an irreversible step's precondition names. */
const IRREVERSIBLE_COMPLETED: HistoryPredicate = { predicate: "action_class_completed", action_class: "irreversible_action" };

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

  it("selects predicates from the validated operation target and audience, never the request's resource type or id", async () => {
    const inputs: HistorySelectionInput[] = [];
    const binding: HistoryBinding = {
      ...historyBinding([]),
      policy: (input) => {
        inputs.push(input);
        return [WRITE_COMPLETED];
      },
    };
    const decision = await evaluate(request(), options(binding));
    expect(decision.context.denial_reason).toBe("history_not_satisfied");
    expect(inputs).toEqual([{ action: READ, operationTarget: RESOURCE, audience: RESOURCE, mission: { id: MISSION, issuer: ISSUER } }]);
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
    expect(second.context.denial_reason).toBe("history_not_satisfied");
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
    // A record with no valid position cannot be placed in the stream, whatever origin the binding declares.
    const unplaced = [await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write", sequence: -1 }), w1Done];
    const negative = await evaluate(request(), options({ ...historyBinding(unplaced), sequenceOrigin: () => -1 }));
    expect(negative.decision).toBe(false);
    expect(negative.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(negative)?.[0]?.outcome).toBe("unavailable");
  });

  it("fails closed when a Decision Evidence stream does not start at its origin: 0 for the reference emitter, or the origin the binding declares", async () => {
    // From the owner's review probe "reference stream missing its initial zero" (#2017):
    // a store returning the stream from position 1 has omitted position 0.
    const w1Done = await executionRecord({ evaluation_id: "w1", outcome: "completed" });
    const suffix = [await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write", sequence: 1 }), w1Done];
    const decision = await evaluate(request(), options(historyBinding(suffix)));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(decision)).toEqual([{ predicate: "action_class_completed", action_class: "consequential_write", outcome: "unavailable" }]);
    // A deployment whose emitter starts elsewhere declares the origin; the returned minimum never sets it.
    const fromFive = [
      await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write", sequence: 5 }),
      w1Done,
      await decisionRecord({ evaluation_id: "w2", action_class: "consequential_write", sequence: 6 }),
      await executionRecord({ evaluation_id: "w2", outcome: "completed", sequence: 1 }),
    ];
    const origins: Array<{ id: string; role: string }> = [];
    const declared = await evaluate(
      request(),
      options({
        ...historyBinding(fromFive),
        sequenceOrigin: (emitter) => {
          origins.push(emitter);
          return emitter.id === PDP_ID ? 5 : undefined;
        },
      }),
    );
    expect(declared.decision, JSON.stringify(declared.context)).toBe(true);
    expect(origins).toEqual([{ id: PDP_ID, role: "pdp" }]);
    const undeclared = await evaluate(request(), options(historyBinding(fromFive)));
    expect(undeclared.decision).toBe(false);
    expect(historyOf(undeclared)?.[0]?.outcome).toBe("unavailable");
  });

  it("counts a record delivered twice once, and fails closed when one execution_id carries different content", async () => {
    const w1 = await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write" });
    const w1Done = await executionRecord({ evaluation_id: "w1", outcome: "completed", execution_id: "exe_w1" });
    const redelivered = await evaluate(request(), options(historyBinding([w1, w1Done, w1, w1Done])));
    expect(redelivered.decision, JSON.stringify(redelivered.context)).toBe(true);
    expect(historyOf(redelivered)?.[0]?.outcome).toBe("satisfied");
    // The same execution_id signed again with a different outcome_at: not a redelivery.
    const reissued = await executionRecord({ evaluation_id: "w1", outcome: "completed", execution_id: "exe_w1", outcome_at: "2026-09-14T11:59:00Z" });
    const conflicting = await evaluate(request(), options(historyBinding([w1, w1Done, reissued])));
    expect(conflicting.decision).toBe(false);
    expect(conflicting.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(conflicting)?.[0]?.outcome).toBe("unavailable");
  });

  it("counts a single-use permit's completed use although a later replay was suppressed permit_consumed, in either record order", async () => {
    // From the owner's review probe "suppressed replay does not undo an authorized completion" (#2017).
    const w1 = await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write", overrides: { conditions: SINGLE_USE } });
    const completed = await executionRecord({ evaluation_id: "w1", outcome: "completed", execution_id: "exe_w1_use", sequence: 0 });
    const replay = await executionRecord({ evaluation_id: "w1", outcome: "suppressed", execution_id: "exe_w1_replay", sequence: 1, overrides: { error: "permit_consumed" } });
    for (const records of [[w1, completed, replay], [w1, replay, completed]]) {
      const decision = await evaluate(request(), options(historyBinding(records)));
      expect(decision.decision, JSON.stringify(decision.context)).toBe(true);
      expect(historyOf(decision)).toEqual([{ predicate: "action_class_completed", action_class: "consequential_write", outcome: "satisfied" }]);
    }
  });

  it("counts a multi-use permit's completed use beside a failed one, in either record order", async () => {
    // From the owner's review probe "distinct multi-use failed and completed executions satisfy the per-permit predicate" (#2017).
    const w1 = await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write" });
    const failed = await executionRecord({ evaluation_id: "w1", outcome: "failed", execution_id: "exe_w1_first", sequence: 0, overrides: { error: "urn:example:execution-failed" } });
    const completed = await executionRecord({ evaluation_id: "w1", outcome: "completed", execution_id: "exe_w1_second", sequence: 1 });
    for (const records of [[w1, failed, completed], [w1, completed, failed]]) {
      const decision = await evaluate(request(), options(historyBinding(records)));
      expect(decision.decision, JSON.stringify(decision.context)).toBe(true);
      expect(historyOf(decision)).toEqual([{ predicate: "action_class_completed", action_class: "consequential_write", outcome: "satisfied" }]);
    }
  });

  it("counts every attempted use against use_limit: a failed and a completed use exceed use_limit 1 but not use_limit 2, in either record order", async () => {
    // From the owner's re-review probes "failed plus completed exceeds use_limit 1" and its use_limit 2 control (#2017).
    const digests = { authorized_parameter_digest: DIGEST_A, effective_parameter_digest: DIGEST_A };
    const failed = await executionRecord({ evaluation_id: "w1", outcome: "failed", execution_id: "use_0", sequence: 0, overrides: { ...digests, error: "urn:example:execution-failed" } });
    const done = await executionRecord({ evaluation_id: "w1", outcome: "completed", execution_id: "use_1", sequence: 1, overrides: digests });
    for (const [limit, outcome] of [
      [1, "unavailable"],
      [2, "satisfied"],
    ] as const) {
      const permit = await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write", overrides: { conditions: { ...SINGLE_USE, use_limit: limit }, parameter_digest: DIGEST_A } });
      for (const records of [[permit, failed, done], [permit, done, failed]]) {
        const label = `use_limit ${limit}, ${records[1] === failed ? "failed first" : "completed first"}`;
        const decision = await evaluate(request(), options(historyBinding(records)));
        expect(decision.decision, label).toBe(outcome === "satisfied");
        if (outcome !== "satisfied") expect(decision.context.denial_reason, label).toBe("history_not_satisfied");
        expect(historyOf(decision)?.[0]?.outcome, label).toBe(outcome);
      }
    }
  });

  it("accepts two completed uses of an unrestricted permit, but not of a single-use permit, in either record order; a malformed use_limit fails closed", async () => {
    const first = await executionRecord({ evaluation_id: "w1", outcome: "completed", execution_id: "exe_w1_first", sequence: 0 });
    const second = await executionRecord({ evaluation_id: "w1", outcome: "completed", execution_id: "exe_w1_second", sequence: 1 });
    const unrestricted = await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write" });
    const singleUse = await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write", overrides: { conditions: SINGLE_USE } });
    for (const [a, b] of [[first, second], [second, first]]) {
      const twice = await evaluate(request(), options(historyBinding([unrestricted, a, b])));
      expect(twice.decision, JSON.stringify(twice.context)).toBe(true);
      expect(historyOf(twice)?.[0]?.outcome).toBe("satisfied");
      // A single-use identifier consumed twice: which completion was the authorized one is not established.
      const overUsed = await evaluate(request(), options(historyBinding([singleUse, a, b])));
      expect(overUsed.decision).toBe(false);
      expect(overUsed.context.denial_reason).toBe("history_not_satisfied");
      expect(historyOf(overUsed)?.[0]?.outcome).toBe("unavailable");
    }
    const malformed = await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write", overrides: { conditions: { ...SINGLE_USE, use_limit: "1" } } });
    const unreadable = await evaluate(request(), options(historyBinding([malformed, first])));
    expect(unreadable.decision).toBe(false);
    expect(unreadable.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(unreadable)?.[0]?.outcome).toBe("unavailable");
  });

  it("fails closed when Decision Evidence records with different content share an evaluation_id, in either order", async () => {
    const permit = await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write", sequence: 0 });
    const deny = await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write", decision: "deny", sequence: 1 });
    const completed = await executionRecord({ evaluation_id: "w1", outcome: "completed" });
    for (const records of [[permit, deny, completed], [deny, permit, completed]]) {
      const decision = await evaluate(request(), options(historyBinding(records)));
      expect(decision.decision).toBe(false);
      expect(decision.context.denial_reason).toBe("history_not_satisfied");
      expect(historyOf(decision)?.[0]?.outcome).toBe("unavailable");
    }
  });

  it("fails closed, recording unavailable, when the evidence store cannot be consulted", async () => {
    const decision = await evaluate(request(), options(historyBinding("unavailable")));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(decision)).toEqual([{ predicate: "action_class_completed", action_class: "consequential_write", outcome: "unavailable" }]);
  });

  it("fails closed, recording unavailable, when the evidence store does not answer within the binding's read bound, and aborts the read", async () => {
    const records = [await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write" }), await executionRecord({ evaluation_id: "w1", outcome: "completed" })];
    const signals: AbortSignal[] = [];
    /** A store that answers with a satisfying history, `delayMs` real milliseconds late (a duration, not a clock instant). */
    const slowBinding = (delayMs: number, readTimeoutMs: number): HistoryBinding => ({
      policy: (input) => (input.action === READ ? [WRITE_COMPLETED] : []),
      reader: {
        records: (_mission, opts) => {
          if (opts) signals.push(opts.signal);
          return new Promise((resolve) => setTimeout(() => resolve(records), delayMs));
        },
      },
      resolveKey,
      readTimeoutMs,
    });
    // Control: the same history, answered within the bound, satisfies the predicate.
    const prompt = await evaluate(request(), options(slowBinding(0, 1000)));
    expect(prompt.decision, JSON.stringify(prompt.context)).toBe(true);
    expect(signals.at(-1)?.aborted).toBe(false);
    const late = await evaluate(request(), options(slowBinding(80, 20)));
    expect(late.decision).toBe(false);
    expect(late.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(late)).toEqual([{ predicate: "action_class_completed", action_class: "consequential_write", outcome: "unavailable" }]);
    expect(signals.at(-1)?.aborted).toBe(true);
    // A bound that is not a positive integer of milliseconds bounds nothing: no history is established.
    const unbounded = await evaluate(request(), options({ ...historyBinding(records), readTimeoutMs: 0 }));
    expect(unbounded.decision).toBe(false);
    expect(unbounded.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(unbounded)?.[0]?.outcome).toBe("unavailable");
  });

  it("fails closed when a retained record does not verify: a permit signed by an untrusted key, or an execution altered after signing", async () => {
    const forged = [
      await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write" }, rogueKeys.privateKey),
      await executionRecord({ evaluation_id: "w1", outcome: "completed" }),
    ];
    const decision = await evaluate(request(), options(historyBinding(forged)));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(decision)?.[0]?.outcome).toBe("unavailable");
    const failedExecution = await executionRecord({ evaluation_id: "w1", outcome: "failed" });
    const altered = [
      await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write" }),
      { ...failedExecution, outcome: "completed" },
    ];
    const second = await evaluate(request(), options(historyBinding(altered)));
    expect(second.decision).toBe(false);
    expect(second.context.denial_reason).toBe("history_not_satisfied");
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
    expect(second.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(second)?.[0]?.outcome).toBe("unavailable");
  });

  it("fails closed when a record's audience is absent: an execution without one, a permit and its execution both without one, or a deny without one", async () => {
    const w1 = await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write" });
    const unscopedExecution = [w1, await executionRecord({ evaluation_id: "w1", outcome: "completed", omit: ["audience"] })];
    const first = await evaluate(request(), options(historyBinding(unscopedExecution)));
    expect(first.decision).toBe(false);
    expect(first.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(first)?.[0]?.outcome).toBe("unavailable");
    const bothUnscoped = [
      await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write", omit: ["audience"] }),
      await executionRecord({ evaluation_id: "w1", outcome: "completed", omit: ["audience"] }),
    ];
    const second = await evaluate(request(), options(historyBinding(bothUnscoped)));
    expect(second.decision).toBe(false);
    expect(second.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(second)?.[0]?.outcome).toBe("unavailable");
    // A deny no execution links to still carries its REQUIRED audience.
    const unscopedDeny = [
      w1,
      await executionRecord({ evaluation_id: "w1", outcome: "completed" }),
      await decisionRecord({ evaluation_id: "d2", action_class: "consequential_write", decision: "deny", sequence: 1, omit: ["audience"] }),
    ];
    const third = await evaluate(request(), options(historyBinding(unscopedDeny)));
    expect(third.decision).toBe(false);
    expect(third.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(third)?.[0]?.outcome).toBe("unavailable");
  });

  it("fails closed when an execution's authorized digests are not its permit's: a parameter or context digest that differs, is missing, or has no permit digest to mirror", async () => {
    const P = "sha-256:permit-parameters";
    const C = "sha-256:permit-context";
    const permit = await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write", overrides: { parameter_digest: P, evaluation_context_digest: C } });
    const linked = { authorized_parameter_digest: P, effective_parameter_digest: P, authorized_evaluation_context_digest: C, effective_evaluation_context_digest: C };
    // Control: an execution mirroring both of the permit's digests links.
    const matching = await evaluate(request(), options(historyBinding([permit, await executionRecord({ evaluation_id: "w1", outcome: "completed", overrides: linked })])));
    expect(matching.decision, JSON.stringify(matching.context)).toBe(true);
    const deviations: Array<[string, Record<string, unknown>, string[]]> = [
      ["other parameter digest", { ...linked, authorized_parameter_digest: "sha-256:other", effective_parameter_digest: "sha-256:other" }, []],
      ["missing parameter digest", linked, ["authorized_parameter_digest", "effective_parameter_digest"]],
      ["other context digest", { ...linked, authorized_evaluation_context_digest: "sha-256:other", effective_evaluation_context_digest: "sha-256:other" }, []],
      ["missing context digest", linked, ["authorized_evaluation_context_digest", "effective_evaluation_context_digest"]],
    ];
    for (const [label, overrides, omit] of deviations) {
      const records = [permit, await executionRecord({ evaluation_id: "w1", outcome: "completed", overrides, omit })];
      const decision = await evaluate(request(), options(historyBinding(records)));
      expect(decision.decision, label).toBe(false);
      expect(decision.context.denial_reason, label).toBe("history_not_satisfied");
      expect(historyOf(decision)?.[0]?.outcome, label).toBe("unavailable");
    }
    // An execution carrying digests its permit never bound.
    const unbound = await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write" });
    for (const [label, overrides] of [
      ["parameter digest without a permit digest", { authorized_parameter_digest: P, effective_parameter_digest: P }],
      ["context digest without a permit digest", { authorized_evaluation_context_digest: C, effective_evaluation_context_digest: C }],
    ] as const) {
      const records = [unbound, await executionRecord({ evaluation_id: "w1", outcome: "completed", overrides })];
      const decision = await evaluate(request(), options(historyBinding(records)));
      expect(decision.decision, label).toBe(false);
      expect(decision.context.denial_reason, label).toBe("history_not_satisfied");
      expect(historyOf(decision)?.[0]?.outcome, label).toBe("unavailable");
    }
  });

  it("counts a completed execution whose effective digests equal its authorized digests in both families", async () => {
    // From the owner's review probe "equal effective digests preserve the positive completion" (#2017), with both families.
    const flags: UnauthorizedExecutionFlag[] = [];
    const permit = await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write", overrides: { parameter_digest: DIGEST_A, evaluation_context_digest: DIGEST_C } });
    const matching = await executionRecord({ evaluation_id: "w1", outcome: "completed", overrides: { ...AUTHORIZED, effective_parameter_digest: DIGEST_A, effective_evaluation_context_digest: DIGEST_C } });
    const decision = await evaluate(request(), options(flagging(historyBinding([permit, matching]), flags)));
    expect(decision.decision, JSON.stringify(decision.context)).toBe(true);
    expect(historyOf(decision)?.[0]?.outcome).toBe("satisfied");
    expect(flags).toEqual([]);
  });

  it("counts no completed execution whose effective digest differs from its authorized one, in either family: it is flagged as an unauthorized execution and the permit stays not_satisfied", async () => {
    // From the owner's review probes "unauthorized effective_parameter_digest / effective_evaluation_context_digest cannot satisfy completion" (#2017).
    const permit = await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write", overrides: { parameter_digest: DIGEST_A, evaluation_context_digest: DIGEST_C } });
    const matching = { ...AUTHORIZED, effective_parameter_digest: DIGEST_A, effective_evaluation_context_digest: DIGEST_C };
    for (const [family, deviation] of [
      ["parameter", { effective_parameter_digest: DIGEST_B }],
      ["evaluation_context", { effective_evaluation_context_digest: DIGEST_B }],
    ] as const) {
      const flags: UnauthorizedExecutionFlag[] = [];
      const unauthorized = await executionRecord({ evaluation_id: "w1", outcome: "completed", execution_id: "exe_w1_deviated", overrides: { ...matching, ...deviation } });
      const decision = await evaluate(request(), options(flagging(historyBinding([permit, unauthorized]), flags)));
      expect(decision.decision, family).toBe(false);
      expect(decision.context.denial_reason, family).toBe("history_not_satisfied");
      expect(historyOf(decision)?.[0]?.outcome, family).toBe("not_satisfied");
      const flag = { mission: { id: MISSION, issuer: ISSUER }, execution_id: "exe_w1_deviated", evaluation_id: "w1", outcome: "completed", deviations: [family] };
      expect(flags, family).toEqual([flag]);
      // A further, authorized completion of the same unrestricted permit satisfies it; the deviation stays flagged.
      const authorized = await executionRecord({ evaluation_id: "w1", outcome: "completed", execution_id: "exe_w1_authorized", sequence: 1, overrides: matching });
      const later = await evaluate(request(), options(flagging(historyBinding([permit, unauthorized, authorized]), flags)));
      expect(later.decision, family).toBe(true);
      expect(flags, family).toEqual([flag, flag]);
    }
    // A failed execution that deviated is flagged too, and is no completion either way.
    const flags: UnauthorizedExecutionFlag[] = [];
    const failed = await executionRecord({ evaluation_id: "w1", outcome: "failed", execution_id: "exe_w1_failed", overrides: { ...matching, effective_parameter_digest: DIGEST_B, error: "urn:example:execution-failed" } });
    const authorized = await executionRecord({ evaluation_id: "w1", outcome: "completed", execution_id: "exe_w1_authorized", sequence: 1, overrides: matching });
    const decision = await evaluate(request(), options(flagging(historyBinding([permit, failed, authorized]), flags)));
    expect(decision.decision, JSON.stringify(decision.context)).toBe(true);
    expect(flags).toEqual([{ mission: { id: MISSION, issuer: ISSUER }, execution_id: "exe_w1_failed", evaluation_id: "w1", outcome: "failed", deviations: ["parameter"] }]);
  });

  it("leaves completion unestablishable when a completed execution lacks the effective digest its authorized digest requires, in either family", async () => {
    // From the owner's review probe "missing effective digest cannot establish completed execution" (#2017), with both families.
    const permit = await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write", overrides: { parameter_digest: DIGEST_A, evaluation_context_digest: DIGEST_C } });
    for (const [family, effective] of [
      ["parameter", { effective_evaluation_context_digest: DIGEST_C }],
      ["evaluation_context", { effective_parameter_digest: DIGEST_A }],
    ] as const) {
      const missing = await executionRecord({ evaluation_id: "w1", outcome: "completed", overrides: { ...AUTHORIZED, ...effective } });
      const decision = await evaluate(request(), options(historyBinding([permit, missing])));
      expect(decision.decision, family).toBe(false);
      expect(decision.context.denial_reason, family).toBe("history_not_satisfied");
      expect(historyOf(decision)?.[0]?.outcome, family).toBe("unavailable");
    }
    // Control: a suppressed execution may lack it, where the PEP could not establish what it would have run.
    const suppressed = await executionRecord({ evaluation_id: "w1", outcome: "suppressed", overrides: { ...AUTHORIZED, error: "target_drift" } });
    const control = await evaluate(request(), options(historyBinding([permit, suppressed])));
    expect(control.decision).toBe(false);
    expect(historyOf(control)?.[0]?.outcome).toBe("not_satisfied");
  });

  it("fails closed when the store returns a record of another Mission", async () => {
    const records = [
      await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write" }),
      await executionRecord({ evaluation_id: "w1", outcome: "completed" }),
      await decisionRecord({ evaluation_id: "x1", action_class: "consequential_write", mission: "msn_other" }),
    ];
    const decision = await evaluate(request(), options(historyBinding(records)));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("history_not_satisfied");
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

  it("does not take a permit signed with the PEP's key while claiming the pdp role: the resolver binds the key to its role", async () => {
    const records = [
      await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write" }, undefined, PEP_KEY_CLAIMING_PDP),
      await executionRecord({ evaluation_id: "w1", outcome: "completed" }),
    ];
    const decision = await evaluate(request(), options(historyBinding(records)));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(decision)?.[0]?.outcome).toBe("unavailable");
  });

  it("does not take an execution signed in the PDP's role as Execution Evidence, although its key verifies for that role", async () => {
    const records = [
      await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write" }),
      await executionRecord({ evaluation_id: "w1", outcome: "completed" }, AS_PDP),
    ];
    const decision = await evaluate(request(), options(historyBinding(records)));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(decision)?.[0]?.outcome).toBe("unavailable");
  });

  it("fails closed when an execution links to a deny rather than a permit", async () => {
    const records = [
      await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write", sequence: 0 }),
      await executionRecord({ evaluation_id: "w1", outcome: "completed", sequence: 0 }),
      await decisionRecord({ evaluation_id: "d2", action_class: "consequential_write", decision: "deny", sequence: 1 }),
      await executionRecord({ evaluation_id: "d2", outcome: "completed", sequence: 1 }),
    ];
    const decision = await evaluate(request(), options(historyBinding(records)));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(decision)?.[0]?.outcome).toBe("unavailable");
  });

  it("fails closed when the store returns a record of no known kind, such as a Refusal Record", async () => {
    const refusal = {
      refusal_id: "ref_history_1",
      mission: { id: MISSION, issuer: ISSUER },
      audience: RESOURCE,
      denial_reason: "operation_target_invalid",
      refused_at: NOW.toISOString(),
      sequence: 1,
      emitter: { id: PDP_ID, role: "pdp" },
    };
    const records = [
      await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write" }),
      await executionRecord({ evaluation_id: "w1", outcome: "completed" }),
      { ...refusal, evidence_envelope: await signEvidenceEnvelope(refusal, REFUSAL_RECORD_MEDIA_TYPE, { kid: "hist-pdp", key: pdpKeys.privateKey }) },
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
    // The recorded member is the PDP's own evaluation, not the asserted one.
    expect(historyOf(decision)).not.toEqual(asserted.mission_history.results);
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

  it("falls back to action_class only where action_classes is absent: a listing record counts by membership alone, and a pending single-class permit keeps the predicate unsatisfied", async () => {
    // Conformant records only: m1 lists the named class beside its assigned one; w2 carries no
    // action_classes, so its action_class alone names the class that applied to it.
    const m1 = await decisionRecord({ evaluation_id: "m1", action_class: "irreversible_action", action_classes: ["irreversible_action", "consequential_write"], sequence: 0 });
    const m1Done = await executionRecord({ evaluation_id: "m1", outcome: "completed", sequence: 0 });
    // Where action_classes is present it alone decides: m1 counts for consequential_write
    // although its assigned action_class is irreversible_action.
    const listed = await evaluate(request(), options(historyBinding([m1, m1Done])));
    expect(listed.decision, JSON.stringify(listed.context)).toBe(true);
    expect(historyOf(listed)?.[0]?.outcome).toBe("satisfied");
    const w2 = await decisionRecord({ evaluation_id: "w2", action_class: "consequential_write", sequence: 1 });
    const pending = await evaluate(request(), options(historyBinding([m1, m1Done, w2])));
    expect(pending.decision).toBe(false);
    expect(pending.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(pending)?.[0]?.outcome).toBe("not_satisfied");
    // Control: once w2's execution completes, both permits of the class have completed.
    const w2Done = await executionRecord({ evaluation_id: "w2", outcome: "completed", sequence: 1 });
    const satisfied = await evaluate(request(), options(historyBinding([m1, m1Done, w2, w2Done])));
    expect(satisfied.decision, JSON.stringify(satisfied.context)).toBe(true);
    expect(historyOf(satisfied)?.[0]?.outcome).toBe("satisfied");
  });

  it("fails closed on a permit without the conditions its applied classes require: none at all, or a high-consequence class without use_limit 1, read across action_classes", async () => {
    const cases: Array<[string, DecisionShape, HistoryPredicate, number]> = [
      // From the owner's re-review probe "high-consequence permit missing conditions is not unrestricted" (#2017):
      // the fixture now signs conditions by default, so the probe omits them explicitly.
      ["irreversible without conditions", { evaluation_id: "w1", action_class: "irreversible_action", overrides: { parameter_digest: DIGEST_A }, omit: ["conditions"] }, IRREVERSIBLE_COMPLETED, 2],
      ["write without conditions", { evaluation_id: "w1", action_class: "consequential_write", omit: ["conditions"] }, WRITE_COMPLETED, 1],
      ["irreversible without use_limit", { evaluation_id: "w1", action_class: "irreversible_action", overrides: { conditions: { valid_until: VALID_UNTIL } } }, IRREVERSIBLE_COMPLETED, 1],
      ["irreversible with use_limit 2", { evaluation_id: "w1", action_class: "irreversible_action", overrides: { conditions: { valid_until: VALID_UNTIL, use_limit: 2 } } }, IRREVERSIBLE_COMPLETED, 1],
      [
        "write listing irreversible, without use_limit",
        { evaluation_id: "w1", action_class: "consequential_write", action_classes: ["consequential_write", "irreversible_action"], overrides: { conditions: { valid_until: VALID_UNTIL } } },
        WRITE_COMPLETED,
        1,
      ],
    ];
    for (const [label, shape, predicate, uses] of cases) {
      const records = [await decisionRecord(shape)];
      for (let i = 0; i < uses; i++) {
        const digests = shape.overrides?.parameter_digest ? { authorized_parameter_digest: DIGEST_A, effective_parameter_digest: DIGEST_A } : {};
        records.push(await executionRecord({ evaluation_id: "w1", outcome: "completed", execution_id: `use_${i}`, sequence: i, overrides: digests }));
      }
      const decision = await evaluate(request(), options(historyBinding(records, [predicate])));
      expect(decision.decision, label).toBe(false);
      expect(decision.context.denial_reason, label).toBe("history_not_satisfied");
      expect(historyOf(decision)?.[0]?.outcome, label).toBe("unavailable");
    }
    // Controls: a lower-consequence permit may omit use_limit, a deny carries no conditions,
    // and a single-use irreversible permit with one completion satisfies.
    const unrestricted = [
      await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write", overrides: { conditions: { valid_until: VALID_UNTIL } }, sequence: 0 }),
      await executionRecord({ evaluation_id: "w1", outcome: "completed" }),
      await decisionRecord({ evaluation_id: "d2", action_class: "consequential_write", decision: "deny", sequence: 1 }),
    ];
    const lower = await evaluate(request(), options(historyBinding(unrestricted)));
    expect(lower.decision, JSON.stringify(lower.context)).toBe(true);
    const singleUse = [
      await decisionRecord({ evaluation_id: "w1", action_class: "irreversible_action", overrides: { conditions: SINGLE_USE } }),
      await executionRecord({ evaluation_id: "w1", outcome: "completed" }),
    ];
    const high = await evaluate(request(), options(historyBinding(singleUse, [IRREVERSIBLE_COMPLETED])));
    expect(high.decision, JSON.stringify(high.context)).toBe(true);
  });

  it("fails closed on a malformed Decision Evidence member rather than leaving the record uncounted", async () => {
    const w1 = await decisionRecord({ evaluation_id: "w1", action_class: "consequential_write", sequence: 0 });
    const w1Done = await executionRecord({ evaluation_id: "w1", outcome: "completed", sequence: 0 });
    const malformed: Array<[string, DecisionShape, boolean]> = [
      // action_classes that leaves out the record's own action_class.
      ["omits action_class", { evaluation_id: "x1", action_class: "consequential_write", action_classes: ["irreversible_action", "external_commitment"] }, false],
      // action_classes holding a non-string, beside a completed execution.
      ["non-string member", { evaluation_id: "x2", action_class: "consequential_write", overrides: { action_classes: ["consequential_write", 7] } }, true],
      // an action_class that is not a string.
      ["non-string action_class", { evaluation_id: "x3", action_class: "consequential_write", overrides: { action_class: 7 } }, false],
      // a decision outside permit and deny.
      ["unknown decision", { evaluation_id: "x4", action_class: "consequential_write", overrides: { decision: "Permit" } }, false],
    ];
    for (const [label, shape, executed] of malformed) {
      const records = [w1, w1Done, await decisionRecord({ ...shape, sequence: 1 })];
      if (executed) records.push(await executionRecord({ evaluation_id: shape.evaluation_id, outcome: "completed", sequence: 1 }));
      const decision = await evaluate(request(), options(historyBinding(records)));
      expect(decision.decision, label).toBe(false);
      expect(decision.context.denial_reason, label).toBe("history_not_satisfied");
      expect(historyOf(decision)?.[0]?.outcome, label).toBe("unavailable");
    }
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
