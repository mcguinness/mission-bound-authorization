/**
 * @spec authzen#context-history, runtime-evidence#evidence-extensions
 * `mission_history` (#2015, D1223): the PDP's History Context.
 *
 * Which history predicates a decision requires is the PDP's own policy, never
 * the request's. The PDP evaluates each selected predicate against the
 * deployment's retained evidence: its own Decision Evidence and the linked
 * Execution Evidence, each record verified against the trusted signer for its
 * role, every link validated, and the read scoped to the established Mission.
 * Where the store cannot be consulted, a record does not verify, or a link
 * cannot be established, no outcome can be established and every selected
 * predicate is `unavailable`: the decision fails closed. No predicate outcome
 * is ever taken from a request member.
 */
import {
  DECISION_EVIDENCE_MEDIA_TYPE,
  EXECUTION_EVIDENCE_MEDIA_TYPE,
  type EvidenceKeyResolver,
  verifyEvidenceEnvelope,
} from "./runtime-evidence-integrity.js";

/** @spec runtime-evidence#evidence-extensions `mission_history`: an evaluated predicate's outcome. */
export type HistoryOutcome = "satisfied" | "not_satisfied" | "unavailable";

/**
 * A policy-selected history predicate: its `predicate` type and the members
 * that type defines (`action_class` for `action_class_completed`). The PDP's
 * own policy supplies it; an unrecognized type is refused as not establishable.
 */
export interface HistoryPredicate {
  predicate: string;
  readonly [member: string]: unknown;
}

/** @spec runtime-evidence#evidence-extensions `mission_history`: one recorded entry. */
export interface HistoryPredicateResult {
  predicate: string;
  action_class?: string;
  outcome: HistoryOutcome;
}

/** What the PDP's history policy selects predicates from: the operation, never a request-supplied selection. */
export interface HistorySelectionInput {
  action: string;
  actionPhase?: string;
  resource: { type: string; id: string };
  mission: { id: string; issuer: string };
}

/** The PDP's own policy naming the history predicates an operation requires. */
export type HistoryPolicy = (input: HistorySelectionInput) => ReadonlyArray<HistoryPredicate>;

/**
 * The deployment's retained evidence, as stored: complete outer records, each
 * carrying its `evidence_envelope`. A read that cannot be completed rejects;
 * the PDP then treats every selected predicate as `unavailable`.
 */
export interface HistoryEvidenceReader {
  records(mission: { id: string; issuer: string }): Promise<ReadonlyArray<unknown>>;
}

/**
 * @spec authzen#context-history (#2015): this PDP's history binding, bound
 * PDP-side like the operation declarations: an enforcement component that
 * could supply the policy, the store or the key resolver could select
 * favorable predicates or vouch for its own history.
 */
export interface HistoryBinding {
  policy: HistoryPolicy;
  reader: HistoryEvidenceReader;
  /** Resolves each record's key under its emitter's scope and audience. */
  resolveKey: EvidenceKeyResolver;
  /** Emitter roles trusted to sign Decision Evidence. Defaults to `pdp`. */
  decisionEmitterRoles?: ReadonlyArray<string>;
  /** Emitter roles trusted to sign Execution Evidence. Defaults to `pep` and `executor`. */
  executionEmitterRoles?: ReadonlyArray<string>;
}

/** The runtime action classes `action_class_completed` may name: Decision Evidence's `action_class` value space. */
const RUNTIME_ACTION_CLASSES: ReadonlySet<string> = new Set([
  "consequential_read",
  "consequential_write",
  "irreversible_action",
  "external_commitment",
  "privileged_administration",
]);

/** The predicate types this PDP recognizes. */
export const RECOGNIZED_HISTORY_PREDICATES: ReadonlySet<string> = new Set(["action_class_completed"]);

interface VerifiedDecision {
  evaluation_id: string;
  decision: string;
  audience: string | undefined;
  action_class: unknown;
  action_classes: unknown;
  /** The record's (Mission, emitter) stream: its emitter's role and id. */
  stream: string;
  sequence: number;
}

interface VerifiedExecution {
  evaluation_id: string;
  audience: string | undefined;
  outcome: unknown;
}

function objectOf(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}

function recordedEntry(p: HistoryPredicate, outcome: HistoryOutcome): HistoryPredicateResult {
  return {
    predicate: typeof p.predicate === "string" ? p.predicate : String(p.predicate),
    ...(typeof p.action_class === "string" ? { action_class: p.action_class } : {}),
    outcome,
  };
}

/** Every selected predicate recorded `unavailable`: nothing about the history could be established. */
export function unavailableHistory(selected: ReadonlyArray<HistoryPredicate>): HistoryPredicateResult[] {
  return selected.map((p) => recordedEntry(p, "unavailable"));
}

/**
 * Read and verify the Mission's retained evidence. Returns `undefined` when
 * the history cannot be established: the read failed, a record is of no
 * known kind, a signer is not trusted for the record's kind, a signature or
 * the payload binding does not verify, a record names another Mission, a
 * Decision Evidence stream has a gap or a reused `sequence` position, or an
 * Execution Evidence record links to no verified Decision Evidence of the
 * same Mission and audience.
 */
async function verifiedHistory(
  binding: HistoryBinding,
  mission: { id: string; issuer: string },
): Promise<{ decisions: VerifiedDecision[]; executions: VerifiedExecution[] } | undefined> {
  let raw: ReadonlyArray<unknown>;
  try {
    raw = await binding.reader.records(mission);
  } catch {
    return undefined;
  }
  if (!Array.isArray(raw)) return undefined;
  const decisionRoles = binding.decisionEmitterRoles ?? ["pdp"];
  const executionRoles = binding.executionEmitterRoles ?? ["pep", "executor"];
  const decisions: VerifiedDecision[] = [];
  const executions: VerifiedExecution[] = [];
  for (const entry of raw) {
    const record = objectOf(entry);
    const emitter = objectOf(record?.emitter);
    if (!record || !emitter || typeof emitter.role !== "string") return undefined;
    const isDecision = typeof record.evidence_id === "string" && typeof record.decision === "string";
    const isExecution = typeof record.execution_id === "string";
    if (isDecision === isExecution) return undefined;
    if (isDecision) {
      if (!decisionRoles.includes(emitter.role)) return undefined;
      if ((await verifyEvidenceEnvelope(record, DECISION_EVIDENCE_MEDIA_TYPE, binding.resolveKey)).valid !== true) return undefined;
      const recordMission = objectOf(record.mission);
      if (recordMission?.id !== mission.id || recordMission?.issuer !== mission.issuer) return undefined;
      if (typeof record.evaluation_id !== "string") return undefined;
      const sequence = record.sequence;
      if (typeof sequence !== "number" || !Number.isSafeInteger(sequence) || sequence < 0) return undefined;
      decisions.push({
        evaluation_id: record.evaluation_id,
        decision: record.decision as string,
        audience: typeof record.audience === "string" ? record.audience : undefined,
        action_class: record.action_class,
        action_classes: record.action_classes,
        stream: JSON.stringify([emitter.role, emitter.id]),
        sequence,
      });
    } else {
      if (!executionRoles.includes(emitter.role)) return undefined;
      if ((await verifyEvidenceEnvelope(record, EXECUTION_EVIDENCE_MEDIA_TYPE, binding.resolveKey)).valid !== true) return undefined;
      if (record.mission_id !== mission.id || typeof record.evaluation_id !== "string") return undefined;
      executions.push({
        evaluation_id: record.evaluation_id,
        audience: typeof record.audience === "string" ? record.audience : undefined,
        outcome: record.outcome,
      });
    }
  }
  // Completeness (@spec runtime-evidence#decision-evidence-object `sequence`):
  // each (Mission, emitter) Decision Evidence stream is ordered by its
  // `sequence` "so ... gaps are detectable". A position missing between the
  // first and last record read, or one held twice, is a record the store did
  // not return, a permit with no completed execution among them perhaps, so
  // the history cannot be established. The start is deployment-defined, so
  // the stream is read from its lowest position present.
  const streams = new Map<string, number[]>();
  for (const d of decisions) {
    const positions = streams.get(d.stream) ?? [];
    positions.push(d.sequence);
    streams.set(d.stream, positions);
  }
  for (const positions of streams.values()) {
    positions.sort((a, b) => a - b);
    for (let i = 1; i < positions.length; i++) {
      if (positions[i] !== (positions[i - 1] as number) + 1) return undefined;
    }
  }
  // Linkage: every execution names a verified decision of this Mission by its
  // `evaluation_id`, for the same audience, and that decision is a permit.
  for (const execution of executions) {
    const linked = decisions.find((d) => d.evaluation_id === execution.evaluation_id);
    if (!linked || linked.decision !== "permit" || linked.audience !== execution.audience) return undefined;
  }
  return { decisions, executions };
}

/**
 * @spec authzen#context-history `action_class_completed`: the named class
 * applied to a record when its `action_classes` lists that class or, only in
 * a record without `action_classes`, its `action_class` is that class.
 */
function classApplied(decision: VerifiedDecision, actionClass: string): boolean {
  if (decision.action_classes !== undefined) {
    return Array.isArray(decision.action_classes) && decision.action_classes.includes(actionClass);
  }
  return decision.action_class === actionClass;
}

/**
 * Evaluate the policy-selected predicates for the established Mission. Each
 * outcome comes from verified, linked evidence; nothing is read from the
 * request. An empty selection reads nothing.
 */
export async function evaluateHistory(
  binding: HistoryBinding,
  selected: ReadonlyArray<HistoryPredicate>,
  mission: { id: string; issuer: string },
): Promise<HistoryPredicateResult[]> {
  if (selected.length === 0) return [];
  const history = await verifiedHistory(binding, mission);
  if (history === undefined) return unavailableHistory(selected);
  return selected.map((p) => {
    if (p.predicate !== "action_class_completed") return recordedEntry(p, "unavailable");
    const actionClass = p.action_class;
    if (typeof actionClass !== "string" || !RUNTIME_ACTION_CLASSES.has(actionClass)) return recordedEntry(p, "unavailable");
    const permits = history.decisions.filter((d) => d.decision === "permit" && classApplied(d, actionClass));
    if (permits.length === 0) return recordedEntry(p, "not_satisfied");
    const completed = permits.every((d) =>
      history.executions.some((e) => e.evaluation_id === d.evaluation_id && e.outcome === "completed"),
    );
    return recordedEntry(p, completed ? "satisfied" : "not_satisfied");
  });
}
