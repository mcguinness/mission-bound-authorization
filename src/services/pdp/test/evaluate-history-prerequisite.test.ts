/**
 * @spec harness#work-item-prerequisite, authzen#context-history (#815, D1223)
 *
 * `work_item_prerequisite_completed`, the harness-owned history predicate: a
 * policy-named operation of a named class completed for the request's work
 * item, on the request's operation target, at the revision the PEP captured
 * for that target. The PDP joins the request to a verified permit and its
 * linked authorized completion, whose `result_summary` records the target and
 * revision its effect acted on. Every verification, linkage and fail-closed
 * rule of the History reader (#2015) applies unchanged.
 *
 * The retained records are signed directly, a Decision Evidence key for the
 * `pdp` role and an Execution Evidence key for the `pep` role, the resolver
 * binding each key to its emitter's role and id. The clock is fixed at one
 * instant (D1091); no OpenFGA is needed. The end-to-end composition through
 * the PEP and its evidence store is `mcp-payments`'
 * `work-item-prerequisite.test.ts`.
 */

import { generateKeyPairSync } from "node:crypto";
import { canonicalDigest } from "@mission/core";
import { describe, expect, it } from "vitest";
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
  RECOGNIZED_HISTORY_PREDICATES,
  relationForAction,
  signEvidenceEnvelope,
  stalenessBound,
  type UnauthorizedExecutionFlag,
} from "../src/index.js";
import { EVALUATION_CONTEXT_UNCLAIMED_FIXTURE, RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "../src/test-support.js";
import { freshKey, openTestClaims } from "./claim-fixture.js";
import { withCredential } from "./with-credential.js";

const AUDIENCE = "http://localhost:4403/mcp";
const DB = "https://db.test";
const ORDERS = `${DB}/databases/orders`;
const LEDGER = `${DB}/databases/ledger`;
const ISSUER = "https://as.test";
const MISSION = "msn_prereq_1";
const NOW = new Date("2026-09-14T12:00:00Z");
const BACKUP = "db:database.backup";
const EXPORT = "db:database.export";
const DELETE = "db:database.delete";
const HARNESS = "https://harness.example.com";
const W1 = { issuer: HARNESS, id: "work-1" };
const W2 = { issuer: HARNESS, id: "work-2" };
const PDP_ID = "pdp.prereq";
const PEP_ID = "pep.prereq";
const allowFga = { checkWithContext: async () => true } as unknown as Fga;

const pdpKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });
const pepKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });

/** Binds each key to its emitter's role and id; anything else resolves to no key. */
const resolveKey: EvidenceKeyResolver = ({ kid, emitter }) => {
  if (kid === "pre-pdp" && emitter.role === "pdp" && emitter.id === PDP_ID) return { key: pdpKeys.publicKey };
  if (kid === "pre-pep" && emitter.role === "pep" && emitter.id === PEP_ID) return { key: pepKeys.publicKey };
  return undefined;
};

const VALID_UNTIL = "2026-09-14T12:01:00Z";

interface DecisionShape {
  evaluation_id: string;
  /** The operation decided; `null` signs a record whose `action` names none. */
  action?: string | null;
  action_class?: string;
  action_classes?: string[];
  work_item?: unknown;
  sequence?: number;
  /** Members signed as given, beside the shape's own. */
  overrides?: Record<string, unknown>;
}

/** A retained permit, signed by the trusted PDP key: the backup of `consequential_write` for W1 unless overridden. */
async function permit(d: DecisionShape): Promise<Record<string, unknown>> {
  const actionClass = d.action_class ?? "consequential_write";
  const unsigned = {
    evidence_id: `evd_${d.evaluation_id}`,
    evaluation_id: d.evaluation_id,
    mission: { id: MISSION, issuer: ISSUER, policy_view_id: "pv_prereq" },
    ...(d.work_item === undefined ? { work_item: W1 } : d.work_item === null ? {} : { work_item: d.work_item }),
    subject: { id: "alice" },
    resource: { type: "database", id: "orders" },
    action: d.action === null ? {} : { name: d.action ?? BACKUP },
    audience: AUDIENCE,
    action_class: actionClass,
    ...(d.action_classes !== undefined ? { action_classes: d.action_classes } : {}),
    class_source: "deployment",
    decision: "permit",
    conditions: { valid_until: VALID_UNTIL },
    sequence: d.sequence ?? 0,
    emitter: { id: PDP_ID, role: "pdp" },
    evaluated_at: NOW.toISOString(),
    ...d.overrides,
  };
  return {
    ...unsigned,
    evidence_envelope: await signEvidenceEnvelope(unsigned, DECISION_EVIDENCE_MEDIA_TYPE, { kid: "pre-pdp", key: pdpKeys.privateKey }),
  };
}

interface ExecutionShape {
  evaluation_id: string;
  outcome?: "completed" | "failed" | "suppressed";
  work_item?: unknown;
  /** The acted-on facts; `null` omits `result_summary`. */
  result_summary?: Record<string, unknown> | null | string;
  execution_id?: string;
  sequence?: number;
  /** Members signed as given, beside the shape's own. */
  overrides?: Record<string, unknown>;
}

/** A retained Execution Evidence record, signed by the trusted PEP key: completed, W1, on orders at r1 unless overridden. */
async function execution(e: ExecutionShape): Promise<Record<string, unknown>> {
  const summary = e.result_summary === undefined ? { operation_target: ORDERS, revision: "r1" } : e.result_summary;
  const unsigned = {
    execution_id: e.execution_id ?? `exe_${e.evaluation_id}`,
    evaluation_id: e.evaluation_id,
    mission_id: MISSION,
    audience: AUDIENCE,
    outcome: e.outcome ?? "completed",
    outcome_at: NOW.toISOString(),
    ...(e.outcome === "suppressed" ? { error: "target_drift" } : {}),
    sequence: e.sequence ?? 0,
    emitter: { id: PEP_ID, role: "pep" },
    ...(e.work_item === undefined ? { work_item: W1 } : e.work_item === null ? {} : { work_item: e.work_item }),
    ...(summary === null ? {} : { result_summary: summary }),
    ...e.overrides,
  };
  return {
    ...unsigned,
    evidence_envelope: await signEvidenceEnvelope(unsigned, EXECUTION_EVIDENCE_MEDIA_TYPE, { kid: "pre-pep", key: pepKeys.privateKey }),
  };
}

/** The delete step's precondition, as the PDP's own policy names it. */
const BACKUP_COMPLETED: HistoryPredicate = { predicate: "work_item_prerequisite_completed", action: BACKUP, action_class: "consequential_write" };

const reported: UnauthorizedExecutionFlag[] = [];

/** A history binding whose policy selects `selected` for the delete, over `records`. */
function historyBinding(records: ReadonlyArray<unknown>, selected: HistoryPredicate[] = [BACKUP_COMPLETED]): HistoryBinding {
  return {
    policy: (input) => (input.action === DELETE ? selected : []),
    reader: { records: async () => records },
    resolveKey,
    onUnauthorizedExecution: (flag) => reported.push(flag),
  };
}

const view: MissionView = {
  id: MISSION,
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:prereqhash",
  authority_set: [{ type: "mission_resource_access", resource: ORDERS, actions: [DELETE] }] as MissionView["authority_set"],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
};

interface RequestShape {
  workItem?: unknown;
  revision?: unknown;
  target?: string;
}

/** The delete request as the PEP sends it: its work item, its target and the revision it captured there. */
const request = (r: RequestShape = {}): EvaluationRequest =>
  withCredential({
    subject: { id: "alice" },
    resource: {
      type: "database",
      id: "orders",
      properties: {
        audience: AUDIENCE,
        operation_target: r.target ?? ORDERS,
        ...("revision" in r ? (r.revision === undefined ? {} : { revision: r.revision }) : { revision: "r1" }),
      },
    },
    action: { name: DELETE, properties: { idempotency_key: freshKey() } },
    context: {
      mission: { id: MISSION, issuer: ISSUER, authority_hash: "sha-256:prereqhash" },
      action_class: "irreversible_action",
      mission_state_observation: { state: "active", mode: "fresh", freshness_at: NOW.toISOString() },
      ...("workItem" in r ? (r.workItem === undefined ? {} : { work_item: r.workItem }) : { work_item: W1 }),
    },
  } as EvaluationRequest);

function emitter() {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return createDecisionEvidenceEmitter({ signer: { kid: "prereq-test", key: privateKey }, emitterId: AUDIENCE, audience: AUDIENCE });
}

const options = (history: HistoryBinding): EvaluateOptions =>
  ({
    view,
    fga: allowFga,
    modelId: "prereq-test-model",
    now: () => NOW,
    stalenessBound,
    // The database actions' Resource-policy relation, beside the payments table.
    relationForAction: (action: string) => (action.startsWith("db:") ? { relation: "payer", needsAmount: false } : relationForAction(action)),
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
    evaluationContextBinding: EVALUATION_CONTEXT_UNCLAIMED_FIXTURE,
    stateSourcePlacement: "pep",
    claims: openTestClaims({ now: () => NOW }),
    evidence: emitter(),
    history,
  }) as EvaluateOptions;

const historyOf = (decision: { context: Record<string, unknown> }) =>
  (decision.context.decision_evidence as DecisionEvidenceObject).mission_history;

/** A recorded `work_item_prerequisite_completed` entry: its class, the operation it selects, and its outcome. */
const entry = (action: string, outcome: string) => ({ predicate: "work_item_prerequisite_completed", action_class: "consequential_write", action, outcome });
const SATISFIED = [entry(BACKUP, "satisfied")];
const NOT_SATISFIED = [entry(BACKUP, "not_satisfied")];
const UNAVAILABLE = [entry(BACKUP, "unavailable")];

describe("work_item_prerequisite_completed joins the request to a verified permit and its authorized completion (@spec harness#work-item-prerequisite, #815)", () => {
  it("is a recognized predicate type, satisfied by a completed backup of the request's target at its revision for its work item", async () => {
    expect(RECOGNIZED_HISTORY_PREDICATES.has("work_item_prerequisite_completed")).toBe(true);
    const records = [await permit({ evaluation_id: "b1" }), await execution({ evaluation_id: "b1" })];
    const decision = await evaluate(request(), options(historyBinding(records)));
    expect(decision.decision, JSON.stringify(decision.context)).toBe(true);
    expect(historyOf(decision)).toEqual(SATISFIED);
  });

  it("matches the named operation, not its class alone: a completed export of the same class, target, revision and work item does not satisfy", async () => {
    const records = [await permit({ evaluation_id: "x1", action: EXPORT }), await execution({ evaluation_id: "x1" })];
    const decision = await evaluate(request(), options(historyBinding(records)));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(decision)).toEqual(NOT_SATISFIED);
    // The class applies by membership in action_classes, else by action_class: a backup assigned another class but listing this one counts.
    const listed = [
      await permit({ evaluation_id: "b2", action_class: "consequential_read", action_classes: ["consequential_read", "consequential_write"] }),
      await execution({ evaluation_id: "b2" }),
    ];
    const byMembership = await evaluate(request(), options(historyBinding(listed)));
    expect(byMembership.decision, JSON.stringify(byMembership.context)).toBe(true);
    expect(historyOf(byMembership)).toEqual(SATISFIED);
    // A backup to which the named class did not apply does not count.
    const unlisted = [await permit({ evaluation_id: "b3", action_class: "consequential_read" }), await execution({ evaluation_id: "b3" })];
    const otherClass = await evaluate(request(), options(historyBinding(unlisted)));
    expect(otherClass.decision).toBe(false);
    expect(historyOf(otherClass)).toEqual(NOT_SATISFIED);
  });

  it("joins the work item on the permit and on the execution: another work item's backup, or an execution attributed to none, does not satisfy", async () => {
    const other = [await permit({ evaluation_id: "b1", work_item: W2 }), await execution({ evaluation_id: "b1", work_item: W2 })];
    const decision = await evaluate(request(), options(historyBinding(other)));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(decision)).toEqual(NOT_SATISFIED);
    const unattributed = [await permit({ evaluation_id: "b1" }), await execution({ evaluation_id: "b1", work_item: null })];
    const none = await evaluate(request(), options(historyBinding(unattributed)));
    expect(none.decision).toBe(false);
    expect(historyOf(none)).toEqual(NOT_SATISFIED);
    // A permit decided for another work item does not count, whatever its execution carries.
    const split = [await permit({ evaluation_id: "b1", work_item: W2 }), await execution({ evaluation_id: "b1", work_item: W1 })];
    const permitOther = await evaluate(request(), options(historyBinding(split)));
    expect(permitOther.decision).toBe(false);
    expect(historyOf(permitOther)).toEqual(NOT_SATISFIED);
    // Control: the same backup satisfies the work item it was attributed to.
    const forW2 = await evaluate(request({ workItem: W2 }), options(historyBinding(other)));
    expect(forW2.decision, JSON.stringify(forW2.context)).toBe(true);
  });

  it("joins the qualified work item: the same id under another issuer, on the permit or on the execution, does not satisfy", async () => {
    const sameIdOtherIssuer = { issuer: "https://other-harness.example.com", id: W1.id };
    const onPermit = [await permit({ evaluation_id: "b1", work_item: sameIdOtherIssuer }), await execution({ evaluation_id: "b1" })];
    const byPermit = await evaluate(request(), options(historyBinding(onPermit)));
    expect(byPermit.decision).toBe(false);
    expect(byPermit.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(byPermit)).toEqual(NOT_SATISFIED);
    const onExecution = [await permit({ evaluation_id: "b1" }), await execution({ evaluation_id: "b1", work_item: sameIdOtherIssuer })];
    const byExecution = await evaluate(request(), options(historyBinding(onExecution)));
    expect(byExecution.decision).toBe(false);
    expect(byExecution.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(byExecution)).toEqual(NOT_SATISFIED);
    // Control: the backup attributed to that other harness's item satisfies a request for that item.
    const theirs = [
      await permit({ evaluation_id: "b1", work_item: sameIdOtherIssuer }),
      await execution({ evaluation_id: "b1", work_item: sameIdOtherIssuer }),
    ];
    const forTheirs = await evaluate(request({ workItem: sameIdOtherIssuer }), options(historyBinding(theirs)));
    expect(forTheirs.decision, JSON.stringify(forTheirs.context)).toBe(true);
  });

  it("joins the target and the revision the execution acted on: another database, or another revision of this one, does not satisfy", async () => {
    const otherTarget = [await permit({ evaluation_id: "b1" }), await execution({ evaluation_id: "b1", result_summary: { operation_target: LEDGER, revision: "r1" } })];
    const decision = await evaluate(request(), options(historyBinding(otherTarget)));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(decision)).toEqual(NOT_SATISFIED);
    const records = [await permit({ evaluation_id: "b1" }), await execution({ evaluation_id: "b1" })];
    const moved = await evaluate(request({ revision: "r2" }), options(historyBinding(records)));
    expect(moved.decision).toBe(false);
    expect(moved.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(moved)).toEqual(NOT_SATISFIED);
  });

  it("cannot be established without its members, the request's work item or revision, or a readable acted-on target and revision", async () => {
    const records = [await permit({ evaluation_id: "b1" }), await execution({ evaluation_id: "b1" })];
    for (const [label, selected] of [
      ["no action", { predicate: "work_item_prerequisite_completed", action_class: "consequential_write" }],
      ["no action_class", { predicate: "work_item_prerequisite_completed", action: BACKUP }],
      ["unknown class", { predicate: "work_item_prerequisite_completed", action: BACKUP, action_class: "backup" }],
    ] as const) {
      const decision = await evaluate(request(), options(historyBinding(records, [selected as HistoryPredicate])));
      expect(decision.decision, label).toBe(false);
      expect(decision.context.denial_reason, label).toBe("history_not_satisfied");
      expect(historyOf(decision)?.[0]?.outcome, label).toBe("unavailable");
    }
    for (const [label, shape] of [
      ["no work item", { workItem: undefined }],
      ["no revision", { revision: undefined }],
      ["empty revision", { revision: "" }],
      ["non-string revision", { revision: 1 }],
    ] as const) {
      const decision = await evaluate(request(shape as RequestShape), options(historyBinding(records)));
      expect(decision.decision, label).toBe(false);
      expect(decision.context.denial_reason, label).toBe("history_not_satisfied");
      expect(historyOf(decision), label).toEqual(UNAVAILABLE);
    }
    // A completion that does not say what it acted on cannot be ruled in or out.
    const silent = [await permit({ evaluation_id: "b1" }), await execution({ evaluation_id: "b1", result_summary: null })];
    const decision = await evaluate(request(), options(historyBinding(silent)));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(decision)).toEqual(UNAVAILABLE);
    // One readable completion that satisfies establishes it, whatever else is retained.
    const both = [...silent, await permit({ evaluation_id: "b2", sequence: 1 }), await execution({ evaluation_id: "b2" })];
    const established = await evaluate(request(), options(historyBinding(both)));
    expect(established.decision, JSON.stringify(established.context)).toBe(true);
    expect(historyOf(established)).toEqual(SATISFIED);
    // A backup whose completion is undetermined (an authorized digest without its effective counterpart) cannot be ruled in or out.
    const undeterminedDigest = `sha-256:${Buffer.alloc(32, 7).toString("base64url")}`;
    const undetermined = [
      await permit({ evaluation_id: "b1", overrides: { parameter_digest: undeterminedDigest } }),
      await execution({ evaluation_id: "b1", overrides: { authorized_parameter_digest: undeterminedDigest } }),
    ];
    const open = await evaluate(request(), options(historyBinding(undetermined)));
    expect(open.decision).toBe(false);
    expect(open.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(open)).toEqual(UNAVAILABLE);
  });

  it("keeps the History reader's rules: a failed, suppressed or unauthorized backup never satisfies, and a malformed work item or result_summary leaves the history unestablished", async () => {
    const failed = [await permit({ evaluation_id: "b1" }), await execution({ evaluation_id: "b1", outcome: "failed" })];
    const notDone = await evaluate(request(), options(historyBinding(failed)));
    expect(notDone.decision).toBe(false);
    expect(historyOf(notDone)).toEqual(NOT_SATISFIED);
    const suppressed = [await permit({ evaluation_id: "b1" }), await execution({ evaluation_id: "b1", outcome: "suppressed" })];
    const refused = await evaluate(request(), options(historyBinding(suppressed)));
    expect(refused.decision).toBe(false);
    expect(historyOf(refused)).toEqual(NOT_SATISFIED);
    // A completed execution whose effective digest differs from the authorized one is an unauthorized execution: flagged, never the prerequisite.
    const digest = (n: number) => `sha-256:${Buffer.alloc(32, n).toString("base64url")}`;
    const deviated = [
      await permit({ evaluation_id: "b1", overrides: { parameter_digest: digest(1) } }),
      await execution({ evaluation_id: "b1", overrides: { authorized_parameter_digest: digest(1), effective_parameter_digest: digest(2) } }),
    ];
    const flags: UnauthorizedExecutionFlag[] = [];
    const unauthorized = await evaluate(request(), options({ ...historyBinding(deviated), onUnauthorizedExecution: (flag) => flags.push(flag) }));
    expect(unauthorized.decision).toBe(false);
    expect(unauthorized.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(unauthorized)).toEqual(NOT_SATISFIED);
    expect(flags.map((f) => f.execution_id)).toEqual(["exe_b1"]);
    // Each malformed record sits beside a satisfying backup: it leaves the whole history unestablished, never uncounted.
    const satisfying = [await permit({ evaluation_id: "b2", sequence: 1 }), await execution({ evaluation_id: "b2" })];
    const control = await evaluate(request(), options(historyBinding([await permit({ evaluation_id: "b1" }), ...satisfying])));
    expect(control.decision, JSON.stringify(control.context)).toBe(true);
    for (const [label, records] of [
      ["permit without an action name", [await permit({ evaluation_id: "b1", action: null }), await execution({ evaluation_id: "b1" })]],
      ["malformed permit work item", [await permit({ evaluation_id: "b1", work_item: { issuer: HARNESS } }), await execution({ evaluation_id: "b1" })]],
      ["malformed execution work item", [await permit({ evaluation_id: "b1" }), await execution({ evaluation_id: "b1", work_item: "work-1" })]],
      ["result_summary not an object", [await permit({ evaluation_id: "b1" }), await execution({ evaluation_id: "b1", result_summary: "r1" })]],
    ] as const) {
      const decision = await evaluate(request(), options(historyBinding([...records, ...satisfying])));
      expect(decision.decision, label).toBe(false);
      expect(decision.context.denial_reason, label).toBe("history_not_satisfied");
      expect(historyOf(decision), label).toEqual(UNAVAILABLE);
    }
  });
});

/** The export of the same class, selected beside the backup. */
const EXPORT_COMPLETED: HistoryPredicate = { predicate: "work_item_prerequisite_completed", action: EXPORT, action_class: "consequential_write" };

describe("a recorded mission_history entry names the operation its predicate selects (@spec authzen#context-history, runtime-evidence#evidence-extensions, harness#work-item-prerequisite, #2048)", () => {
  it("records two prerequisites of one class for distinct operations as two entries, each naming its own action beside its own outcome, in either selection order", async () => {
    const backupDone = [await permit({ evaluation_id: "p1", action: BACKUP }), await execution({ evaluation_id: "p1" })];
    const exportDone = [await permit({ evaluation_id: "p1", action: EXPORT }), await execution({ evaluation_id: "p1" })];
    for (const [label, records, selected, expected] of [
      ["backup completed, backup selected first", backupDone, [BACKUP_COMPLETED, EXPORT_COMPLETED], [entry(BACKUP, "satisfied"), entry(EXPORT, "not_satisfied")]],
      ["backup completed, export selected first", backupDone, [EXPORT_COMPLETED, BACKUP_COMPLETED], [entry(EXPORT, "not_satisfied"), entry(BACKUP, "satisfied")]],
      ["export completed, backup selected first", exportDone, [BACKUP_COMPLETED, EXPORT_COMPLETED], [entry(BACKUP, "not_satisfied"), entry(EXPORT, "satisfied")]],
      ["export completed, export selected first", exportDone, [EXPORT_COMPLETED, BACKUP_COMPLETED], [entry(EXPORT, "satisfied"), entry(BACKUP, "not_satisfied")]],
    ] as const) {
      const decision = await evaluate(request(), options(historyBinding(records, [...selected])));
      expect(decision.decision, label).toBe(false);
      expect(decision.context.denial_reason, label).toBe("history_not_satisfied");
      expect(historyOf(decision), label).toEqual(expected);
    }
    // Both completed: both satisfied, each entry still naming its own operation, in either order.
    const bothDone = [...backupDone, await permit({ evaluation_id: "p2", action: EXPORT, sequence: 1 }), await execution({ evaluation_id: "p2" })];
    for (const [label, selected, expected] of [
      ["both completed, backup selected first", [BACKUP_COMPLETED, EXPORT_COMPLETED], [entry(BACKUP, "satisfied"), entry(EXPORT, "satisfied")]],
      ["both completed, export selected first", [EXPORT_COMPLETED, BACKUP_COMPLETED], [entry(EXPORT, "satisfied"), entry(BACKUP, "satisfied")]],
    ] as const) {
      const decision = await evaluate(request(), options(historyBinding(bothDone, [...selected])));
      expect(decision.decision, `${label}: ${JSON.stringify(decision.context)}`).toBe(true);
      expect(historyOf(decision), label).toEqual(expected);
    }
  });

  it("records no action on an action_class_completed entry, which selects by class alone, even where policy gave it one, whether evaluated or unavailable", async () => {
    const classCompleted: HistoryPredicate = { predicate: "action_class_completed", action_class: "consequential_write", action: EXPORT };
    const classEntry = (outcome: string) => ({ predicate: "action_class_completed", action_class: "consequential_write", outcome });
    const records = [await permit({ evaluation_id: "b1" }), await execution({ evaluation_id: "b1" })];
    const decision = await evaluate(request(), options(historyBinding(records, [BACKUP_COMPLETED, classCompleted])));
    expect(decision.decision, JSON.stringify(decision.context)).toBe(true);
    expect(historyOf(decision)).toEqual([entry(BACKUP, "satisfied"), classEntry("satisfied")]);
    expect(historyOf(decision)?.[1]).not.toHaveProperty("action");
    // The store cannot be consulted: every entry is unavailable, and the shape is the same.
    const down = {
      ...historyBinding([], [BACKUP_COMPLETED, classCompleted]),
      reader: {
        records: async () => {
          throw new Error("evidence store unavailable");
        },
      },
    };
    const unavailable = await evaluate(request(), options(down));
    expect(unavailable.decision).toBe(false);
    expect(unavailable.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(unavailable)).toEqual([entry(BACKUP, "unavailable"), classEntry("unavailable")]);
    expect(historyOf(unavailable)?.[1]).not.toHaveProperty("action");
  });

  it("records no action for an empty operation selector, whose predicate cannot be established", async () => {
    const records = [await permit({ evaluation_id: "b1" }), await execution({ evaluation_id: "b1" })];
    const emptySelector: HistoryPredicate = { predicate: "work_item_prerequisite_completed", action: "", action_class: "consequential_write" };
    const decision = await evaluate(request(), options(historyBinding(records, [emptySelector])));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("history_not_satisfied");
    expect(historyOf(decision)).toEqual([{ predicate: "work_item_prerequisite_completed", action_class: "consequential_write", outcome: "unavailable" }]);
    expect(historyOf(decision)?.[0]).not.toHaveProperty("action");
  });

  it("signs an entry's action only as a non-empty string and refuses to sign any other", async () => {
    const signer = emitter();
    const input = {
      mission: { id: MISSION, issuer: ISSUER, policy_view_id: "pv_prereq" },
      subject: { id: "alice" },
      resource: { type: "database", id: "orders" },
      action: { name: DELETE },
      action_class: "irreversible_action" as const,
      audience: AUDIENCE,
      evaluation_id: "evaluation",
      decision: "deny" as const,
      denial_reason: "history_not_satisfied" as const,
      evaluated_at: NOW.toISOString(),
      evaluation_request_digest: canonicalDigest({ request: true }),
    };
    for (const action of [7, ""]) {
      const malformed = { predicate: "work_item_prerequisite_completed", action_class: "consequential_write", action, outcome: "unavailable" };
      await expect(signer.emit({ ...input, mission_history: [malformed as never] }), JSON.stringify(action)).rejects.toThrow(
        "mission_history action must be a non-empty string",
      );
    }
    const record = await signer.emit({ ...input, mission_history: [entry(BACKUP, "unavailable") as never] });
    expect(record.mission_history).toEqual([entry(BACKUP, "unavailable")]);
  });
});
