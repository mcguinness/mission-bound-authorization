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
 * @spec orchestration#reversibility (#1735, #1994): the profile's partial
 * order. read_only < reversible_write < the three high-risk classes, which
 * carry the same requirements in this profile and share one tier: any one
 * meets the minimum of another, and none ranks above the others.
 */
const TIER: Readonly<Record<ReversibilityClass, number>> = {
  read_only: 0,
  reversible_write: 1,
  irreversible_action: 2,
  external_commitment: 2,
  privileged_administration: 2,
};

/** Whether `proposed` meets the minimum `floor` maps to. */
function meets(proposed: ReversibilityClass, floor: ReversibilityClass): boolean {
  return TIER[proposed] >= TIER[floor];
}

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
 * @spec orchestration#reversibility (#1735, #1994): the minimum for a step
 * one or more runtime classes apply to: a floor that meets each class's
 * minimum. Where several floors share the highest tier, the first in the
 * given order (the assigned class first) is taken; any of them meets every
 * minimum, so the choice decides nothing the rule governs.
 */
export function floorReversibilityOver(runtimeActionClasses: readonly RuntimeActionClass[]): ReversibilityClass {
  const floors = runtimeActionClasses.map(floorReversibility);
  const floor = floors.find((f) => floors.every((g) => meets(f, g)));
  if (floor === undefined) throw new Error("a governed step has at least one runtime action class");
  return floor;
}

/**
 * Enforce the floor: never below the mapped minimum (raise-only). Keeps the
 * proposed class where it meets the minimum of every applicable runtime class,
 * and otherwise takes the floor, so a proposal can raise but never lower below
 * what any applicable class requires.
 */
export function enforceReversibilityFloor(
  proposed: ReversibilityClass,
  runtimeActionClass: RuntimeActionClass | readonly RuntimeActionClass[],
): ReversibilityClass {
  const classes: readonly RuntimeActionClass[] =
    typeof runtimeActionClass === "string" ? [runtimeActionClass] : runtimeActionClass;
  return classes.every((c) => meets(proposed, floorReversibility(c))) ? proposed : floorReversibilityOver(classes);
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
  /**
   * @spec orchestration#reversibility (#1735, #1994): each further runtime
   * class whose predicate the step's operation satisfies.
   */
  additionalRuntimeActionClasses?: readonly RuntimeActionClass[];
  proposed?: ReversibilityClass;
  proposedSource: ClassSource;
}): DeriveReversibilityResult {
  const classes = [input.runtimeActionClass, ...(input.additionalRuntimeActionClasses ?? [])];
  const floor = floorReversibilityOver(classes);
  if (input.proposed === undefined) {
    return { reversibility: floor, adopted: true, reason: "floor_from_runtime_action_class" };
  }
  if (!isTrustedClassSource(input.proposedSource)) {
    // Unadopted: the floor governs; the untrusted proposal cannot lower it.
    return { reversibility: floor, adopted: false, reason: "untrusted_source_not_adopted" };
  }
  return {
    reversibility: enforceReversibilityFloor(input.proposed, classes),
    adopted: true,
    reason: "trusted_source_floored",
  };
}
