/**
 * @spec orchestration#reversibility
 * @spec orchestration#action-class-source
 *
 * Reversibility classes and the floor that maps a runtime action class to the
 * minimum reversibility class a governed step may carry. The class is assigned
 * BEFORE execution and is raise-only: it MUST NOT be lowered by the
 * orchestrator at runtime to avoid review or compensation
 * (draft § reversibility, § action-class-source). The three high-risk classes
 * are the identically-named runtime action classes of the runtime profile;
 * `read_only`/`reversible_write` are a refinement this profile adds.
 */

export type ReversibilityClass =
  | "read_only"
  | "reversible_write"
  | "irreversible_action"
  | "external_commitment"
  | "privileged_administration";

/**
 * The runtime action classes of the runtime profile. The last three are the
 * identically-named classes; `irreversible_action` and `external_commitment`
 * already appear in `services/pdp/src/policy.ts` (staleness bounds). GAP:
 * `privileged_administration` is a NEW runtime action class this profile
 * introduces and is not yet mapped in `pdp/policy.ts` (which floors to the
 * default 300s bound); a deployment adding it must extend that policy.
 */
export type RuntimeActionClass =
  | "non_consequential"
  | "consequential_read"
  | "consequential_write"
  | "irreversible_action"
  | "external_commitment"
  | "privileged_administration";

/** Draft table (§ reversibility): runtime action class -> minimum reversibility. */
export const REVERSIBILITY_FLOOR: Readonly<Record<RuntimeActionClass, ReversibilityClass>> = {
  non_consequential: "read_only",
  consequential_read: "read_only",
  consequential_write: "reversible_write",
  irreversible_action: "irreversible_action",
  external_commitment: "external_commitment",
  privileged_administration: "privileged_administration",
};

/**
 * A deterministic rank so the floor is a total function. read_only <
 * reversible_write < the three high-risk classes; the three high-risk classes
 * are ranked only to break ties for a deterministic max, NOT as a claim that
 * they are mutually ordered by reversibility.
 */
const RANK: Readonly<Record<ReversibilityClass, number>> = {
  read_only: 0,
  reversible_write: 1,
  irreversible_action: 2,
  external_commitment: 3,
  privileged_administration: 4,
};

/** The high-risk classes: an `unknown` outcome here MUST route to human review. */
export const HIGH_RISK_REVERSIBILITY: ReadonlySet<ReversibilityClass> = new Set([
  "irreversible_action",
  "external_commitment",
  "privileged_administration",
]);

/** Trusted sources that MAY define or lower a class (§ action-class-source). */
export type ClassSource =
  | "rs_runtime_profile"
  | "operation_profile"
  | "reviewed_workflow_definition"
  | "resource_policy"
  // Untrusted: a suggestion only; MUST NOT be the sole authority for lowering.
  | "model_output"
  | "agent_plan"
  | "tool_description";

const TRUSTED_CLASS_SOURCES: ReadonlySet<ClassSource> = new Set([
  "rs_runtime_profile",
  "operation_profile",
  "reviewed_workflow_definition",
  "resource_policy",
]);

export function isTrustedClassSource(source: ClassSource): boolean {
  return TRUSTED_CLASS_SOURCES.has(source);
}

/** The minimum reversibility class the runtime action class requires. */
export function floorReversibility(runtimeActionClass: RuntimeActionClass): ReversibilityClass {
  return REVERSIBILITY_FLOOR[runtimeActionClass];
}

/**
 * Enforce the floor: never below the mapped minimum (raise-only). Returns the
 * higher of the proposed class and the floor, so a proposal can raise but
 * never lower below what the runtime action class requires.
 */
export function enforceReversibilityFloor(
  proposed: ReversibilityClass,
  runtimeActionClass: RuntimeActionClass,
): ReversibilityClass {
  const floor = floorReversibility(runtimeActionClass);
  return RANK[proposed] >= RANK[floor] ? proposed : floor;
}

export interface DeriveReversibilityResult {
  reversibility: ReversibilityClass;
  /** Whether a proposal from an untrusted source was adopted. */
  adopted: boolean;
  reason: string;
}

/**
 * Derive the class from a proposal and its source. A proposal from a trusted
 * source is enforced against the floor (raise-only). A proposal from an
 * untrusted source (model output, agent plan, tool description) is NOT adopted;
 * the trusted floor governs, so model output can never be the sole authority
 * for lowering class (§ action-class-source, § unwind-plan-integrity).
 */
export function deriveReversibility(input: {
  runtimeActionClass: RuntimeActionClass;
  proposed?: ReversibilityClass;
  proposedSource: ClassSource;
}): DeriveReversibilityResult {
  const floor = floorReversibility(input.runtimeActionClass);
  if (input.proposed === undefined) {
    return { reversibility: floor, adopted: true, reason: "floor_from_runtime_action_class" };
  }
  if (!isTrustedClassSource(input.proposedSource)) {
    // Unadopted: the floor governs; the untrusted proposal cannot lower it.
    return { reversibility: floor, adopted: false, reason: "untrusted_source_not_adopted" };
  }
  return {
    reversibility: enforceReversibilityFloor(input.proposed, input.runtimeActionClass),
    adopted: true,
    reason: "trusted_source_floored",
  };
}
