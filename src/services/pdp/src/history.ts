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
 *
 * Cost and reach: each decision that selects a predicate reads the Mission's
 * whole retained history and verifies every record, one signature each,
 * uncached, so its cost grows linearly with the Mission's records. One record
 * that cannot be used, a Refusal Record or a record signed under a key the
 * resolver no longer publishes among them, leaves the whole history
 * unestablished for every later decision on the Mission.
 */
import { canonicalize, type JsonValue } from "@mission/core";
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

/**
 * What the PDP's history policy selects predicates from: the operation, never
 * a request-supplied selection. `operationTarget` and `audience` are the
 * values the PDP validated, never the AuthZEN resource object's `type` or
 * `id`, which name no operation the PDP checked.
 */
export interface HistorySelectionInput {
  action: string;
  actionPhase?: string;
  operationTarget: string;
  audience: string;
  mission: { id: string; issuer: string };
}

/** The PDP's own policy naming the history predicates an operation requires. */
export type HistoryPolicy = (input: HistorySelectionInput) => ReadonlyArray<HistoryPredicate>;

/**
 * The deployment's retained evidence, as stored: complete outer records, each
 * carrying its `evidence_envelope`. A read that cannot be completed rejects;
 * the PDP then treats every selected predicate as `unavailable`, as it does
 * when the read outlasts {@link HistoryBinding.readTimeoutMs}, after which
 * `signal` is aborted and any later result is ignored.
 */
export interface HistoryEvidenceReader {
  records(mission: { id: string; issuer: string }, options?: { signal: AbortSignal }): Promise<ReadonlyArray<unknown>>;
}

/** The default bound on one history read, in milliseconds. */
export const DEFAULT_HISTORY_READ_TIMEOUT_MS = 5000;

/**
 * @spec authzen#context-history (#2015): this PDP's history binding, bound
 * PDP-side like the operation declarations: an enforcement component that
 * could supply the policy, the store or the key resolver could select
 * favorable predicates or vouch for its own history.
 */
export interface HistoryBinding {
  policy: HistoryPolicy;
  reader: HistoryEvidenceReader;
  /**
   * Resolves each record's key under its emitter's scope and audience. It
   * MUST bind the key to the emitter's `role` as well as its `id`, returning
   * no key for a role the key is not published for, as
   * `buildEvidenceKeyResolver` does: the role checks below read the role the
   * record claims, so a resolver that matched `kid` and `id` alone would let
   * a PEP's key sign a record claiming the `pdp` role.
   */
  resolveKey: EvidenceKeyResolver;
  /** Emitter roles trusted to sign Decision Evidence. Defaults to `pdp`. */
  decisionEmitterRoles?: ReadonlyArray<string>;
  /** Emitter roles trusted to sign Execution Evidence. Defaults to `pep` and `executor`. */
  executionEmitterRoles?: ReadonlyArray<string>;
  /**
   * @spec runtime#input-history, runtime-evidence#evidence-extensions
   * `mission_history` ("an evidence store that could not be consulted within
   * its bound"): how long one read may take, a positive integer of
   * milliseconds, default {@link DEFAULT_HISTORY_READ_TIMEOUT_MS}. A read
   * that outlasts it, or a bound that is not a positive integer, leaves every
   * selected predicate `unavailable`.
   */
  readTimeoutMs?: number;
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
  decision: "permit" | "deny";
  audience: string;
  /** The digests the decision was bound to, where it carries them. */
  parameter_digest: string | undefined;
  evaluation_context_digest: string | undefined;
  action_class: string;
  /** Present only when the record carries it, then an array of strings holding `action_class`. */
  action_classes: string[] | undefined;
  /** The record's (Mission, emitter) stream: its emitter's role and id. */
  stream: string;
  sequence: number;
  /** The signed content: the record's canonical form without its envelope. */
  content: string;
}

interface VerifiedExecution {
  execution_id: string;
  evaluation_id: string;
  /** Absent or empty, `undefined`, which matches no permit. */
  audience: string | undefined;
  /** The linked permit's digests as this record mirrors them, where it carries them. */
  authorized_parameter_digest: string | undefined;
  authorized_evaluation_context_digest: string | undefined;
  outcome: unknown;
  content: string;
}

function objectOf(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}

/** A member that is absent, or else a string: `null` for anything else. */
function optionalString(value: unknown): string | undefined | null {
  return value === undefined || typeof value === "string" ? value : null;
}

/** A REQUIRED boundary identifier: a non-empty string. */
function requiredAudience(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

/**
 * One read of the Mission's records, bounded by `timeoutMs`: rejects when the
 * reader rejects or throws, or when the bound elapses first, aborting the
 * reader's signal. A result arriving after the bound is ignored.
 */
async function boundedRead(
  reader: HistoryEvidenceReader,
  mission: { id: string; issuer: string },
  timeoutMs: number,
): Promise<ReadonlyArray<unknown>> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const read = Promise.resolve().then(() => reader.records(mission, { signal: controller.signal }));
  // A read that settles after the bound settles unobserved, never unhandled.
  read.catch(() => undefined);
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new Error(`no history read within ${timeoutMs} ms`));
    }, timeoutMs);
  });
  try {
    return await Promise.race([read, deadline]);
  } finally {
    clearTimeout(timer);
  }
}

/** A verified record's signed content: the canonical bytes its envelope's payload equals. */
function signedContent(record: Record<string, unknown>): string {
  const { evidence_envelope: _envelope, ...content } = record;
  return canonicalize(content as JsonValue);
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
 * the history cannot be established: the read failed or outlasted its bound,
 * a record is of no known kind, a signer is not trusted for the record's
 * kind, a signature or the payload binding does not verify (a record signed
 * by a key the resolver no longer publishes among them), a record names
 * another Mission, two
 * records conflict (Decision Evidence of one `evaluation_id`, or Execution
 * Evidence of one `execution_id`, with different content, or one permit with
 * more than one disposition), a Decision Evidence stream has a gap or a
 * reused `sequence` position, a record lacks its REQUIRED `audience`, or an
 * Execution Evidence record links to no verified permit of the same Mission
 * and audience or carries authorized digests other than that permit's. A
 * record delivered more than once with the same content counts once.
 */
async function verifiedHistory(
  binding: HistoryBinding,
  mission: { id: string; issuer: string },
): Promise<{ decisions: VerifiedDecision[]; executions: VerifiedExecution[] } | undefined> {
  const timeoutMs = binding.readTimeoutMs ?? DEFAULT_HISTORY_READ_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) return undefined;
  let raw: ReadonlyArray<unknown>;
  try {
    raw = await boundedRead(binding.reader, mission, timeoutMs);
  } catch {
    return undefined;
  }
  if (!Array.isArray(raw)) return undefined;
  const decisionRoles = binding.decisionEmitterRoles ?? ["pdp"];
  const executionRoles = binding.executionEmitterRoles ?? ["pep", "executor"];
  // Keyed by `evaluation_id` and by `execution_id`: a record redelivered with
  // the same content counts once, and two records under one key that differ
  // are a conflict no store order may resolve.
  const decisions = new Map<string, VerifiedDecision>();
  const executions = new Map<string, VerifiedExecution>();
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
      // @spec runtime-evidence#decision-evidence-object `decision`,
      // `action_class`, `action_classes`: a malformed member would drop the
      // record out of the permits a predicate counts, so it leaves the history
      // unestablished rather than uncounted. A present `action_classes` holds
      // strings, "`action_class` among them".
      const decision = record.decision;
      if (decision !== "permit" && decision !== "deny") return undefined;
      const actionClass = record.action_class;
      if (typeof actionClass !== "string") return undefined;
      const actionClasses = record.action_classes;
      if (
        actionClasses !== undefined &&
        (!Array.isArray(actionClasses) ||
          !actionClasses.every((c) => typeof c === "string") ||
          !actionClasses.includes(actionClass))
      ) {
        return undefined;
      }
      // @spec runtime-evidence#decision-evidence-object `audience` (REQUIRED)
      // and the digests an execution's link is checked against.
      const audience = requiredAudience(record.audience);
      if (audience === undefined) return undefined;
      const parameterDigest = optionalString(record.parameter_digest);
      const contextDigest = optionalString(record.evaluation_context_digest);
      if (parameterDigest === null || contextDigest === null) return undefined;
      const content = signedContent(record);
      const prior = decisions.get(record.evaluation_id);
      if (prior !== undefined) {
        if (prior.content !== content) return undefined;
        continue;
      }
      decisions.set(record.evaluation_id, {
        evaluation_id: record.evaluation_id,
        decision,
        audience,
        parameter_digest: parameterDigest,
        evaluation_context_digest: contextDigest,
        action_class: actionClass,
        action_classes: actionClasses as string[] | undefined,
        stream: JSON.stringify([emitter.role, emitter.id]),
        sequence,
        content,
      });
    } else {
      if (!executionRoles.includes(emitter.role)) return undefined;
      if ((await verifyEvidenceEnvelope(record, EXECUTION_EVIDENCE_MEDIA_TYPE, binding.resolveKey)).valid !== true) return undefined;
      if (record.mission_id !== mission.id || typeof record.evaluation_id !== "string") return undefined;
      // @spec runtime-evidence#execution-evidence-object `execution_id`:
      // delivery is at-least-once, "so a consumer MUST deduplicate on
      // `execution_id`".
      const executionId = record.execution_id as string;
      // @spec runtime-evidence#execution-evidence-object `audience` (REQUIRED):
      // an absent one never equals its permit's, which is required above, so
      // the link below fails. `authorized_parameter_digest` and
      // `authorized_evaluation_context_digest` are strings where present.
      const audience = requiredAudience(record.audience);
      const authorizedParameterDigest = optionalString(record.authorized_parameter_digest);
      const authorizedContextDigest = optionalString(record.authorized_evaluation_context_digest);
      if (authorizedParameterDigest === null || authorizedContextDigest === null) return undefined;
      const content = signedContent(record);
      const prior = executions.get(executionId);
      if (prior !== undefined) {
        if (prior.content !== content) return undefined;
        continue;
      }
      executions.set(executionId, {
        execution_id: executionId,
        evaluation_id: record.evaluation_id,
        audience,
        authorized_parameter_digest: authorizedParameterDigest,
        authorized_evaluation_context_digest: authorizedContextDigest,
        outcome: record.outcome,
        content,
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
  for (const d of decisions.values()) {
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
  // @spec runtime-evidence#execution-evidence-object: its
  // `authorized_parameter_digest` is REQUIRED when the permit carries
  // `parameter_digest`, "MUST equal it", and is absent otherwise, and its
  // `authorized_evaluation_context_digest` likewise against the permit's
  // `evaluation_context_digest`: a record that deviates is not linked to what
  // the permit authorized. One permit's executions agree on its disposition:
  // a `completed` record beside a `failed` one leaves what happened
  // unestablished.
  const dispositions = new Map<string, unknown>();
  for (const execution of executions.values()) {
    const linked = decisions.get(execution.evaluation_id);
    if (!linked || linked.decision !== "permit" || linked.audience !== execution.audience) return undefined;
    if (execution.authorized_parameter_digest !== linked.parameter_digest) return undefined;
    if (execution.authorized_evaluation_context_digest !== linked.evaluation_context_digest) return undefined;
    if (dispositions.has(execution.evaluation_id) && dispositions.get(execution.evaluation_id) !== execution.outcome) return undefined;
    dispositions.set(execution.evaluation_id, execution.outcome);
  }
  return { decisions: [...decisions.values()], executions: [...executions.values()] };
}

/**
 * @spec authzen#context-history `action_class_completed`: the named class
 * applied to a record when its `action_classes` lists that class or, only in
 * a record without `action_classes`, its `action_class` is that class. Both
 * members were validated when the record was read.
 */
function classApplied(decision: VerifiedDecision, actionClass: string): boolean {
  if (decision.action_classes !== undefined) return decision.action_classes.includes(actionClass);
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
