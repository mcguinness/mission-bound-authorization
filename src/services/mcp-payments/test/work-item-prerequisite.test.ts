/**
 * @spec harness#work-item-prerequisite, authzen#context-history,
 * runtime#evaluation-context-binding, runtime#execution-reverification
 * (#815 slice 2, D301, D1223): the destructive-operation witness.
 *
 * A database is deleted only after an authorized, completed backup of that
 * same database, at that same revision, for that same work item. The delete's
 * decision requires `work_item_prerequisite_completed`, which the PDP
 * evaluates over the evidence this PEP retained: its verified Decision
 * Evidence and its own Execution Evidence, whose `result_summary` records the
 * target and revision each effect acted on. Execution Reverification then
 * re-reads the revision before the delete is released.
 *
 * Test-only operation set, never shipped and unreachable from the demo: a
 * simulated revisioned database (`RevisionedDatabase`) with backup, export
 * and delete operations, placed in this PEP's injectable Operation Profile as
 * record crossings, under a test-only Evaluation-Context Binding declaration
 * whose one fact is the database revision (`revision` granularity, the
 * `verified` property). The decision point is a real co-resident one with the
 * history binding, its reader over this PEP's real evidence store. The
 * executor below is the test's resource adapter: it drives the PEP's own
 * admission, release-time reverification, single-use consumption and
 * disposition in the order the server's write path does, and performs the
 * effect on the simulated database. The delete is a plain effect, never a
 * compare-and-swap on the revision: nothing here claims atomic
 * check-and-effect (`enforced`).
 *
 * Controlled clock (D1091): `Date` is fixed at one instant before anything is
 * composed. The FGA layer is a stub, so this file never skips.
 */

import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { canonicalDigest, EvaluationContextBindingDeclarations, type OperationContract } from "@mission/core";
import {
  createEphemeralDecisionPoint,
  type DecisionEvidenceObject,
  type EvaluationRequest,
  type EvidenceKeyResolver,
  type Fga,
  type HistoryBinding,
  type HistoryPredicate,
  type MissionView,
  openEphemeralClaimDomain,
  readWorkItemAttribution,
  relationForAction,
  RUNTIME_POSTURE,
  type UnauthorizedExecutionFlag,
  WORK_ITEM_ATTRIBUTION_EXTENSION,
} from "@mission/pdp";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import {
  type ActionMapping,
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  credentialAuthorityFrom,
  type DecisionEvidence,
  type EnforceResult,
  EvidenceStore,
  type ExecutionEvidence,
  openEphemeralWriteReservationStore,
  PaymentsStore,
  Pep,
  type RequestSignals,
  type RevisionedRecord,
  type RevisionedRecordSource,
  type TokenFacts,
} from "../src/index.js";

const CLOCK_MS = Date.parse("2026-11-03T12:00:00Z");
const ISSUER = "https://as.test";
const MISSION = "msn_815_prereq";
const HARNESS = "https://harness.example.com";
const W1 = { issuer: HARNESS, id: "work-1" };
const W2 = { issuer: HARNESS, id: "work-2" };
const DB = "https://db.test";
const ORDERS = `${DB}/databases/orders`;
const LEDGER = `${DB}/databases/ledger`;
const BACKUP = "db:database.backup";
const EXPORT = "db:database.export";
const DELETE = "db:database.delete";
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

beforeAll(() => {
  vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
  vi.setSystemTime(CLOCK_MS);
});
afterAll(() => {
  vi.useRealTimers();
});

/**
 * The simulated revisioned database: each database carries a revision that
 * moves with every change. Its interface is the record source the PEP reads
 * (`read`); backup, export and delete are its effects, each reporting the
 * revision it acted on as the database held it at that moment.
 */
class RevisionedDatabase implements RevisionedRecordSource {
  private readonly rows = new Map<string, number>();
  readonly backups: Array<{ id: string; revision: string }> = [];

  constructor(...ids: string[]) {
    for (const id of ids) this.rows.set(id, 1);
  }

  revisionOf(id: string): string | undefined {
    const n = this.rows.get(id);
    return n === undefined ? undefined : `r${n}`;
  }

  exists(id: string): boolean {
    return this.rows.has(id);
  }

  /** A change to the database's contents: its revision moves. */
  write(id: string): void {
    const n = this.rows.get(id);
    if (n !== undefined) this.rows.set(id, n + 1);
  }

  read(type: string, id: string): RevisionedRecord | undefined {
    const revision = type === "database" ? this.revisionOf(id) : undefined;
    return revision === undefined ? undefined : { type, id, revision };
  }

  backup(id: string): { revision: string } {
    const revision = this.revisionOf(id) as string;
    this.backups.push({ id, revision });
    return { revision };
  }

  export(id: string): { revision: string } {
    return { revision: this.revisionOf(id) as string };
  }

  /** A plain delete: it compares no revision, so it claims no atomic check-and-effect. */
  delete(id: string): { revision: string } {
    const revision = this.revisionOf(id) as string;
    this.rows.delete(id);
    return { revision };
  }
}

/** The databases' argument-derived operation contract: the target is the database the validated `database_id` names. */
const DATABASE_CONTRACT: OperationContract = Object.freeze({ template: `${DB}/databases/{database_id}` });
const RECORD = { type: "database", argument: "database_id" } as const;

/** The test-only Operation Profile: backup and export are writes of one class; delete is irreversible and keyed. */
const DATABASE_OPERATIONS: Record<string, ActionMapping> = {
  backup_database: { action: BACKUP, actionClass: "consequential_write", target: DATABASE_CONTRACT, needsInvoice: false, record: RECORD },
  export_database: { action: EXPORT, actionClass: "consequential_write", target: DATABASE_CONTRACT, needsInvoice: false, record: RECORD },
  delete_database: {
    action: DELETE,
    actionClass: "irreversible_action",
    target: DATABASE_CONTRACT,
    needsInvoice: false,
    idempotencyKey: true,
    record: RECORD,
  },
};

/** The one descriptor: the database is the target, its revision the one decision-relevant fact. */
const DESCRIPTOR_DOCUMENT = {
  id: `${DB}/descriptors/database-revision`,
  version: "1",
  targets: ["database"],
  facts: [{ name: "revision", resolver: "record:revision", granularity: "revision", normalization: "opaque-string" }],
};
const DESCRIPTOR = { id: DESCRIPTOR_DOCUMENT.id, version: DESCRIPTOR_DOCUMENT.version, digest: canonicalDigest(DESCRIPTOR_DOCUMENT) };

/** A test-only Evaluation-Context Binding claim covering the three operations with the `verified` property. */
const CONTEXT_BINDING = new EvaluationContextBindingDeclarations({
  claims: ["evaluation_context_binding"],
  extensions: {
    evaluation_context_binding: {
      covered_classes: ["consequential_write", "irreversible_action"],
      descriptors: [{ ...DESCRIPTOR, document: DESCRIPTOR_DOCUMENT }],
      operations: [
        { operation: BACKUP, action_class: "consequential_write", property: "verified", descriptor: DESCRIPTOR },
        { operation: EXPORT, action_class: "consequential_write", property: "verified", descriptor: DESCRIPTOR },
        { operation: DELETE, action_class: "irreversible_action", property: "verified", descriptor: DESCRIPTOR },
      ],
    },
  },
});

/** A test-only statement naming `ap-agent`'s harness as the work-item attacher; it claims no class. */
const ATTRIBUTION = readWorkItemAttribution({
  ...structuredClone(RUNTIME_POSTURE),
  extensions: {
    ...structuredClone(RUNTIME_POSTURE.extensions),
    [WORK_ITEM_ATTRIBUTION_EXTENSION]: { attachers: [{ client_id: "ap-agent", harness: HARNESS }], covered_classes: ["consequential_read"] },
  },
});

/** The delete's precondition, as the PDP's own policy names it: the backup operation, of its class. */
const BACKUP_COMPLETED: HistoryPredicate = { predicate: "work_item_prerequisite_completed", action: BACKUP, action_class: "consequential_write" };

const ENTRIES = [
  { type: "mission_resource_access", resource: ORDERS, actions: [BACKUP, EXPORT, DELETE] },
  { type: "mission_resource_access", resource: LEDGER, actions: [BACKUP, EXPORT, DELETE] },
] as MissionView["authority_set"];

const view = (): MissionView => ({
  id: MISSION,
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: `sha-256:${MISSION}`,
  authority_set: ENTRIES,
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
});

const token = (): TokenFacts => ({
  sub: "alice",
  clientId: "ap-agent",
  clientInstanceId: "inst-1",
  mission: { id: MISSION, issuer: ISSUER, authority_hash: `sha-256:${MISSION}` },
  missionClaim: {
    id: MISSION,
    issuer: ISSUER,
    authority_hash: `sha-256:${MISSION}`,
    expires_at: new Date(CLOCK_MS + 60 * 60 * 1000).toISOString(),
    approval_basis: { type: "direct" },
  },
  cnfJkt: "jkt-815-prereq",
  credentialAuthority: credentialAuthorityFrom(ENTRIES),
});

/** The harness's attachment: the reference it propagates, with its work item. */
const attached = (workItem: { issuer: string; id: string }): RequestSignals => ({
  missionReference: { id: MISSION, issuer: ISSUER, workItem },
});

/** The database actions' Resource-policy relation, beside the payments table. */
const relationFor = (action: string) => (action.startsWith("db:") ? { relation: "payer" as const, needsAmount: false } : relationForAction(action));

interface Fixture {
  db: RevisionedDatabase;
  pep: Pep;
  evidence: EvidenceStore;
  reservations: ReturnType<typeof openEphemeralWriteReservationStore>;
  /** Every decision request the PEP sent, as sent. */
  requests: EvaluationRequest[];
  /** Every unauthorized execution the PDP's history read flagged. */
  flags: UnauthorizedExecutionFlag[];
}

function fixture(): Fixture {
  const db = new RevisionedDatabase("orders", "ledger");
  // The PEP's evidence store and key resolver exist only once the decision
  // point does; the history binding reads them through these holders.
  let store: EvidenceStore | undefined;
  let resolver: EvidenceKeyResolver | undefined;
  const flags: UnauthorizedExecutionFlag[] = [];
  const history: HistoryBinding = {
    policy: (input) => (input.action === DELETE ? [BACKUP_COMPLETED] : []),
    // The Mission's complete retained history: every Decision Evidence and
    // Execution Evidence record, never a Refusal Record.
    reader: {
      records: async (mission) =>
        (store?.forMission(mission.id) ?? [])
          .filter((r) => (r.kind === "decision" ? r.content.mission.issuer === mission.issuer : r.kind === "execution"))
          .map((r) => (r as DecisionEvidence | ExecutionEvidence).content),
    },
    resolveKey: (params) => resolver?.(params),
    onUnauthorizedExecution: (flag) => flags.push(flag),
  };
  const claims = openEphemeralClaimDomain({
    owner: RUNTIME_POSTURE.pdps[0] as string,
    statement: RUNTIME_POSTURE,
    settlementKeys: (params) => resolver?.(params),
  });
  const point = createEphemeralDecisionPoint({
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
    emitterId: CANONICAL_RESOURCE,
    audience: CANONICAL_RESOURCE,
    claims,
    evaluationContextBinding: CONTEXT_BINDING,
    history,
  });
  const keys = createEphemeralEvidenceKeys({ decisionPoint: point });
  resolver = keys.resolver;
  const evidence = new EvidenceStore(keys.signing, keys.resolver);
  store = evidence;
  const requests: EvaluationRequest[] = [];
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === MISSION && ref.issuer === ISSUER
      ? { view: view(), observation: { state: "active", version: 1, mode: "fresh", freshness_at: new Date().toISOString() } }
      : undefined;
  const pep = new Pep({
    decide: async (req, options) => {
      requests.push(structuredClone(req));
      return keys.decide(req, { ...options, relationForAction: relationFor });
    },
    payments: new PaymentsStore(),
    evidence,
    fga: alwaysAllowFga,
    modelId: "unit-test-model",
    loadView,
    instanceEpoch: "epoch-815-prereq",
    operationProfile: () => DATABASE_OPERATIONS,
    revisionedRecords: () => db,
    evaluationContextBinding: () => CONTEXT_BINDING,
    workItemAttachers: ATTRIBUTION.attachers,
  });
  return { db, pep, evidence, reservations: openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" }), requests, flags };
}

interface Performed {
  outcome: "denied" | "refused" | "suppressed" | "completed";
  reason?: string;
  res: EnforceResult;
}

/**
 * The resource adapter's write path for one crossing, in the server's order:
 * the decision; admission; the test's `beforeRelease` hook (a change to the
 * database between the decision and the effect); the whole use table again
 * immediately before release, the context re-read included; single-use
 * consumption; the effect; and the completed disposition, carrying the
 * context reverification re-established before the effect and, in
 * `result_summary`, the target and the revision the effect reports it acted
 * on.
 */
async function perform(
  f: Fixture,
  tool: string,
  databaseId: string,
  workItem: { issuer: string; id: string },
  hooks: { beforeRelease?: () => void; extraArgs?: Record<string, unknown> } = {},
): Promise<Performed> {
  const args: Record<string, unknown> = {
    database_id: databaseId,
    ...(tool === "delete_database" ? { idempotency_key: `idem_${randomUUID()}` } : {}),
    ...hooks.extraArgs,
  };
  const res = await f.pep.enforce(tool, args, token(), undefined, attached(workItem));
  if (!res.permitted || !res.attempt || !res.decision) {
    return res.denial_reason !== undefined
      ? { outcome: "denied", reason: res.denial_reason, res }
      : { outcome: "refused", ...(res.refusal_reason !== undefined ? { reason: res.refusal_reason } : {}), res };
  }
  const attempt = res.attempt;
  const admitted = await f.pep.verifyPermitAtUse(attempt);
  if (!admitted.ok) return { outcome: "suppressed", reason: admitted.error, res };
  hooks.beforeRelease?.();
  const live = await f.pep.verifyPermitAtUse(attempt);
  if (!live.ok) return { outcome: "suppressed", reason: live.error, res };
  const contextDigest = f.pep.observeEffectiveContextDigest(attempt);
  const conditions = res.decision.context.conditions as { use_limit?: number; valid_until?: string } | undefined;
  if (conditions?.use_limit !== undefined) {
    const first = f.reservations.consumePermit({
      evaluationId: attempt.evaluationId,
      action: attempt.action,
      executionId: attempt.executionId,
      retainUntilMs: Date.parse(conditions.valid_until ?? "") + 60_000,
    });
    if (!first) {
      await f.pep.suppressExecution(attempt, "permit_consumed");
      return { outcome: "suppressed", reason: "permit_consumed", res };
    }
  }
  const acted = tool === "delete_database" ? f.db.delete(databaseId) : tool === "backup_database" ? f.db.backup(databaseId) : f.db.export(databaseId);
  const recorded = await f.pep.completeExecution(attempt, {
    ...(contextDigest !== undefined ? { effectiveEvaluationContextDigest: contextDigest } : {}),
    resultSummary: { operation_target: attempt.operationTarget, revision: acted.revision },
  });
  if (!recorded.recorded) throw new Error(`no completed disposition: ${recorded.gap}`);
  return { outcome: "completed", res };
}

const decisionsOf = (f: Fixture) => f.evidence.forMission(MISSION).filter((e): e is DecisionEvidence => e.kind === "decision");
const executionsOf = (f: Fixture) => f.evidence.forMission(MISSION).filter((e): e is ExecutionEvidence => e.kind === "execution");
const deleteExecutions = (f: Fixture) =>
  executionsOf(f).filter((e) => decisionsOf(f).some((d) => d.content.evaluation_id === e.content.evaluation_id && d.content.action.name === DELETE));
/** The `mission_history` the delete's Decision Evidence recorded. */
const deleteHistory = (f: Fixture) =>
  (decisionsOf(f).filter((d) => d.content.action.name === DELETE).at(-1)?.content as DecisionEvidenceObject | undefined)?.mission_history;
const lastRequest = (f: Fixture) => f.requests.at(-1);

const SATISFIED = [{ predicate: "work_item_prerequisite_completed", action_class: "consequential_write", outcome: "satisfied" }];
const NOT_SATISFIED = [{ predicate: "work_item_prerequisite_completed", action_class: "consequential_write", outcome: "not_satisfied" }];

describe("a database is deleted only after a completed backup for the same work item, target and revision (@spec harness#work-item-prerequisite, #815)", () => {
  it("deletes after the work item's completed backup of that database at its revision, recorded as acted on", async () => {
    const f = fixture();
    const backup = await perform(f, "backup_database", "orders", W1);
    expect(backup.outcome, JSON.stringify(backup.res)).toBe("completed");
    // The PEP recorded what the backup acted on, as the database reported it, and the work item it attributed.
    const backupRecord = executionsOf(f).at(-1)?.content;
    expect(backupRecord?.outcome).toBe("completed");
    expect(backupRecord?.result_summary).toEqual({ operation_target: ORDERS, revision: "r1" });
    expect(backupRecord?.work_item).toEqual(W1);
    expect(f.db.backups).toEqual([{ id: "orders", revision: "r1" }]);

    const del = await perform(f, "delete_database", "orders", W1);
    expect(del.outcome, JSON.stringify(del.res)).toBe("completed");
    expect(f.db.exists("orders")).toBe(false);
    expect(deleteHistory(f)).toEqual(SATISFIED);
    // The delete request carried the work item, its target and the revision the PEP captured there.
    const sent = lastRequest(f);
    expect(sent?.context.work_item).toEqual(W1);
    expect(sent?.resource.properties.operation_target).toBe(ORDERS);
    expect(sent?.resource.properties.revision).toBe("r1");
    expect(deleteExecutions(f).map((e) => e.content.outcome)).toEqual(["completed"]);
    expect(f.flags).toEqual([]);
  });

  it("takes the request's revision from the database, never from an agent argument", async () => {
    const f = fixture();
    await perform(f, "backup_database", "orders", W1, { extraArgs: { revision: "r9" } });
    expect(lastRequest(f)?.resource.properties.revision).toBe("r1");
    expect(executionsOf(f).at(-1)?.content.result_summary).toEqual({ operation_target: ORDERS, revision: "r1" });
  });

  it("refuses the delete when only another operation of the backup's class completed for that work item, target and revision", async () => {
    const f = fixture();
    const exported = await perform(f, "export_database", "orders", W1);
    expect(exported.outcome, JSON.stringify(exported.res)).toBe("completed");
    expect(executionsOf(f).at(-1)?.content.result_summary).toEqual({ operation_target: ORDERS, revision: "r1" });
    const del = await perform(f, "delete_database", "orders", W1);
    expect(del.outcome).toBe("denied");
    expect(del.reason).toBe("history_not_satisfied");
    expect(deleteHistory(f)).toEqual(NOT_SATISFIED);
    expect(f.db.exists("orders")).toBe(true);
    expect(deleteExecutions(f)).toEqual([]);
  });

  it("refuses the delete when the completed backup was another work item's", async () => {
    const f = fixture();
    expect((await perform(f, "backup_database", "orders", W2)).outcome).toBe("completed");
    expect(executionsOf(f).at(-1)?.content.work_item).toEqual(W2);
    const del = await perform(f, "delete_database", "orders", W1);
    expect(del.outcome).toBe("denied");
    expect(del.reason).toBe("history_not_satisfied");
    expect(deleteHistory(f)).toEqual(NOT_SATISFIED);
    expect(f.db.exists("orders")).toBe(true);
    expect(deleteExecutions(f)).toEqual([]);
  });

  it("refuses the delete when the completed backup was of another database", async () => {
    const f = fixture();
    expect((await perform(f, "backup_database", "ledger", W1)).outcome).toBe("completed");
    expect(executionsOf(f).at(-1)?.content.result_summary).toEqual({ operation_target: LEDGER, revision: "r1" });
    const del = await perform(f, "delete_database", "orders", W1);
    expect(del.outcome).toBe("denied");
    expect(del.reason).toBe("history_not_satisfied");
    expect(deleteHistory(f)).toEqual(NOT_SATISFIED);
    expect(f.db.exists("orders")).toBe(true);
    expect(deleteExecutions(f)).toEqual([]);
  });

  it("refuses the delete when the database changed after the backup: the fresh revision finds no backup", async () => {
    const f = fixture();
    expect((await perform(f, "backup_database", "orders", W1)).outcome).toBe("completed");
    f.db.write("orders");
    const del = await perform(f, "delete_database", "orders", W1);
    // The PEP captured the current revision; the backup acted on the earlier one.
    expect(lastRequest(f)?.resource.properties.revision).toBe("r2");
    expect(del.outcome).toBe("denied");
    expect(del.reason).toBe("history_not_satisfied");
    expect(deleteHistory(f)).toEqual(NOT_SATISFIED);
    expect(f.db.exists("orders")).toBe(true);
    expect(f.db.revisionOf("orders")).toBe("r2");
    expect(deleteExecutions(f)).toEqual([]);
  });

  it("suppresses the permitted delete, target_drift, when the database changes after the decision and before release", async () => {
    const f = fixture();
    expect((await perform(f, "backup_database", "orders", W1)).outcome).toBe("completed");
    const del = await perform(f, "delete_database", "orders", W1, { beforeRelease: () => f.db.write("orders") });
    // The decision was a permit at r1: the prerequisite held when it was evaluated.
    expect(del.res.permitted).toBe(true);
    expect(deleteHistory(f)).toEqual(SATISFIED);
    expect(del.outcome).toBe("suppressed");
    expect(del.reason).toBe("target_drift");
    expect(f.db.exists("orders")).toBe(true);
    const records = deleteExecutions(f).map((e) => ({ outcome: e.content.outcome, error: e.content.error }));
    expect(records).toEqual([{ outcome: "suppressed", error: "target_drift" }]);
  });
});
