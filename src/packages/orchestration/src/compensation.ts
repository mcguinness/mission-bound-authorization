/**
 * @spec orchestration#compensation
 * @spec orchestration#compensation-authority
 * @spec orchestration#unwind-ordering
 *
 * Compensation authority resolution and unwind ordering. Compensation is
 * governed work: it MUST NOT be performed by presenting the terminated
 * Mission's authority. It proceeds only under `resource_policy` or a narrow
 * `active` `separate_mission`; otherwise the orchestrator MUST escalate to
 * human review. Under either basis the compensating decision carries the
 * `evaluation_id` it reverses in `compensates_evaluation_id`.
 */

export type AuthorityBasis = "resource_policy" | "separate_mission";

export interface CompensationRequest {
  /** The `evaluation_id` of the committed step this compensation reverses. */
  reversedEvaluationId: string;
  /** The proposed authority basis, if any. */
  basis?: AuthorityBasis;
  /** True if the caller attempts to reuse the terminated Mission's authority. */
  presentsTerminatedMissionAuthority?: boolean;
  /** For `separate_mission`: is the remedial Mission `active` under its binding? */
  separateMissionActive?: boolean;
  /**
   * For `separate_mission`: is its Authority Set scoped to compensation actions
   * for the terminated Mission's committed steps? Defaults to scoped unless
   * explicitly false (scoping is a property of provisioning).
   */
  separateMissionScopedToCompensation?: boolean;
}

export interface CompensationAuthorityResult {
  decision: "permit" | "deny" | "human_review";
  /** Present only when `decision` is `permit`. */
  authority_basis?: AuthorityBasis;
  /**
   * The runtime-profile binding: the `evaluation_id` of the reversed step. Its
   * normative home is the compensating action's runtime decision
   * (§ compensation-authority); it is surfaced here so the caller can carry it
   * onto both the decision and the Orchestration Evidence record's
   * `compensates_evaluation_id`, never into `linked_evidence`.
   */
  compensates_evaluation_id?: string;
  reason: string;
}

/**
 * Resolve the authority basis for a compensation after a non-active transition.
 * Order matters: a terminated-Mission-authority attempt is refused first; a
 * `separate_mission` that is not `active` does not apply and drops to human
 * review; only a valid, scoped, active `separate_mission` or `resource_policy`
 * permits, binding to the reversed `evaluation_id`.
 */
export function resolveCompensationAuthority(
  req: CompensationRequest,
): CompensationAuthorityResult {
  // The terminated Mission's authority MUST NOT be presented (§ compensation).
  if (req.presentsTerminatedMissionAuthority === true) {
    return { decision: "deny", reason: "terminated_mission_authority_refused" };
  }

  // resource_policy: the resource permits the rollback under its own policy; no
  // Mission-bound credential is presented.
  if (req.basis === "resource_policy") {
    return {
      decision: "permit",
      authority_basis: "resource_policy",
      compensates_evaluation_id: req.reversedEvaluationId,
      reason: "resource_policy",
    };
  }

  // separate_mission: a distinct, narrow, active remedial Mission scoped to
  // compensation for the terminated Mission's committed steps.
  if (req.basis === "separate_mission") {
    if (req.separateMissionActive !== true) {
      return { decision: "human_review", reason: "separate_mission_not_active" };
    }
    if (req.separateMissionScopedToCompensation === false) {
      return { decision: "deny", reason: "separate_mission_out_of_scope" };
    }
    return {
      decision: "permit",
      authority_basis: "separate_mission",
      compensates_evaluation_id: req.reversedEvaluationId,
      reason: "separate_mission",
    };
  }

  // Neither basis applies: the orchestrator MUST NOT compensate; record review.
  return { decision: "human_review", reason: "no_authority_basis" };
}

export interface CompensationStep {
  step_id: string;
  /** Step ids this step depends on (executed before it in the forward order). */
  depends_on?: string[];
}

/**
 * Reverse dependency order (§ unwind-ordering): compensations run in the
 * reverse of the forward dependency order, so dependents are offset before the
 * steps they depend on. Deterministic: a stable topological sort keyed by input
 * order, then reversed. Throws on a dependency cycle.
 */
export function reverseDependencyOrder(steps: CompensationStep[]): string[] {
  const byId = new Map<string, CompensationStep>(steps.map((s) => [s.step_id, s]));
  const visited = new Set<string>();
  const onStack = new Set<string>();
  const forward: string[] = [];

  const visit = (id: string): void => {
    if (visited.has(id)) return;
    if (onStack.has(id)) throw new Error(`cyclic compensation dependency at '${id}'`);
    onStack.add(id);
    const step = byId.get(id);
    for (const dep of step?.depends_on ?? []) {
      if (byId.has(dep)) visit(dep);
    }
    onStack.delete(id);
    visited.add(id);
    forward.push(id);
  };

  for (const s of steps) visit(s.step_id);
  return forward.reverse();
}

export type CompensationOutcome = "completed" | "failed" | "unknown";

export interface CompensationStepResult {
  step_id: string;
  outcome: CompensationOutcome;
}

export interface UnwindTerminalState {
  terminal_state: "compensated" | "compensation_incomplete";
  /** Enumerated steps whose compensation is failed or unknown (§ unwind-ordering). */
  incomplete_steps: string[];
}

/**
 * Terminal state after running compensations. When any required step did not
 * complete, the workflow's terminal state is `compensation_incomplete` and the
 * failed/unknown steps are enumerated so an auditor can see which effects were
 * not offset (§ unwind-ordering).
 */
export function unwindTerminalState(results: CompensationStepResult[]): UnwindTerminalState {
  const incomplete = results.filter((r) => r.outcome !== "completed").map((r) => r.step_id);
  return incomplete.length === 0
    ? { terminal_state: "compensated", incomplete_steps: [] }
    : { terminal_state: "compensation_incomplete", incomplete_steps: incomplete };
}
