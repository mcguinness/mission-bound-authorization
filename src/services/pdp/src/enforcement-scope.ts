/**
 * @spec runtime#runtime-conformance — an executable Enforcement Scope
 * Statement: the structured declaration the draft requires every
 * runtime-conforming deployment to publish, plus the scope predicate a
 * claim is checked against ("A deployment MUST NOT claim runtime
 * enforcement for a resource, action class, authority-entry type, or
 * execution path outside that declared scope").
 *
 * This is a declaration/validation artifact, not a second policy
 * language: `validateEnforcementScopeStatement` checks the statement's own
 * internal completeness (every baseline member present, every claimed
 * extension carrying its attached declaration); `claimsWithinScope` checks
 * one candidate claim against an already-valid statement's declared
 * baseline. Neither evaluates a live decision; that remains `evaluate()`'s
 * job. A real deployment's own resource/action-class/path coverage against
 * what it actually mediates stays an audit property this module does not
 * reach.
 */

/**
 * The baseline declaration every conforming deployment carries, whether or
 * not it also claims a named assurance extension (the six MUST members of
 * {{runtime-conformance}}).
 */
export interface EnforcementScopeBaseline {
  mediated_scope: {
    resources: readonly string[];
    action_classes: readonly string[];
    execution_paths: readonly string[];
    pep_locations: readonly string[];
    /** May be empty: a deployment that excludes no path still declares the (empty) set. */
    excluded_paths: readonly string[];
    mission_establishment_mode: string;
  };
  authority_entry_types: ReadonlyArray<{ type: string; evaluator: string }>;
  pdps: readonly string[];
  state_source: {
    source: string;
    max_staleness_seconds: number;
    pdp_unavailability_posture: string;
  };
  /**
   * One entry per PEP/PDP boundary that is not co-resident; a wholly
   * co-resident deployment declares an empty array (@spec decision-channel:
   * "A co-resident PDP and PEP ... need no separate channel mechanism").
   */
  remote_decision_channels: ReadonlyArray<{ boundary: string; trust_mode: string }>;
  record_integrity_mechanism: string;
}

/**
 * Names of the named assurance extensions and enforcement claims the
 * baseline statement can attach a declaration for ({{runtime-conformance}},
 * the paragraph following the baseline list).
 */
export type EnforcementExtensionName =
  | "custody"
  | "transaction_assurance"
  | "evidence"
  | "high_assurance_agent"
  | "outcome_reconciliation";

export interface EnforcementExtensionDeclarations {
  custody?: ReadonlyArray<{ mediated_class: string; custody_mode: string }>;
  transaction_assurance?: ReadonlyArray<{ mediated_class_or_scope: string; idempotency_claim_domain: string }>;
  evidence?: {
    mechanism: string;
    retention_window: string;
    signing_key_locations: readonly string[];
    agent_isolated_evidence_emission?: ReadonlyArray<{ emitter: string; declaration: string }>;
  };
  high_assurance_agent?: ReadonlyArray<{ row: string; eat_selection: string }>;
  outcome_reconciliation?: {
    window: string;
    responsible_component: string;
    alerting: string;
  };
}

export interface EnforcementScopeStatement extends EnforcementScopeBaseline {
  /** The named extensions and claims this deployment asserts; each MUST
   * have a matching, non-empty entry under `extensions`. */
  claims?: readonly EnforcementExtensionName[];
  extensions?: EnforcementExtensionDeclarations;
}

export interface EnforcementScopeFinding {
  member: string;
  problem: string;
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}
function isNonEmptyStringArray(v: unknown): v is readonly string[] {
  return Array.isArray(v) && v.length > 0 && v.every((x) => isNonEmptyString(x));
}

/**
 * Checks the statement's own internal completeness: every baseline member
 * present and minimally well-formed, and every claimed extension carrying
 * a non-empty attached declaration. Returns one finding per problem; an
 * empty array is a valid statement.
 */
export function validateEnforcementScopeStatement(
  stmt: Partial<EnforcementScopeStatement>,
): EnforcementScopeFinding[] {
  const findings: EnforcementScopeFinding[] = [];
  const push = (member: string, problem: string): void => {
    findings.push({ member, problem });
  };

  const scope = stmt.mediated_scope;
  const scopeOk =
    scope !== undefined &&
    isNonEmptyStringArray(scope.resources) &&
    isNonEmptyStringArray(scope.action_classes) &&
    isNonEmptyStringArray(scope.execution_paths) &&
    isNonEmptyStringArray(scope.pep_locations) &&
    Array.isArray(scope.excluded_paths) &&
    isNonEmptyString(scope.mission_establishment_mode);
  if (!scopeOk) {
    push(
      "mediated_scope",
      "missing the mediated resources/action classes/execution paths, PEP locations, excluded paths, or Mission-establishment mode",
    );
  }

  const entryTypes = stmt.authority_entry_types;
  const entryTypesOk =
    Array.isArray(entryTypes) &&
    entryTypes.length > 0 &&
    entryTypes.every((e) => isNonEmptyString(e.type) && isNonEmptyString(e.evaluator));
  if (!entryTypesOk) {
    push("authority_entry_types", "missing a supported authority-entry type or its evaluator");
  }

  if (!isNonEmptyStringArray(stmt.pdps)) {
    push("pdps", "missing the PDP or PDPs that evaluate Mission-bound decisions");
  }

  const stateSource = stmt.state_source;
  const stateSourceOk =
    stateSource !== undefined &&
    isNonEmptyString(stateSource.source) &&
    typeof stateSource.max_staleness_seconds === "number" &&
    stateSource.max_staleness_seconds > 0 &&
    isNonEmptyString(stateSource.pdp_unavailability_posture);
  if (!stateSourceOk) {
    push(
      "state_source",
      "missing the Mission state source, its maximum staleness bound, or the PDP-unavailability posture",
    );
  }

  const channels = stmt.remote_decision_channels;
  const channelsOk =
    Array.isArray(channels) && channels.every((c) => isNonEmptyString(c.boundary) && isNonEmptyString(c.trust_mode));
  if (!channelsOk) {
    push(
      "remote_decision_channels",
      "a declared boundary is missing its trust mode (an empty array is valid only for a wholly co-resident deployment)",
    );
  }

  if (!isNonEmptyString(stmt.record_integrity_mechanism)) {
    push("record_integrity_mechanism", "missing the append-only, integrity-protection mechanism for its records");
  }

  for (const claim of stmt.claims ?? []) {
    const decl = stmt.extensions?.[claim];
    const attached = Array.isArray(decl) ? decl.length > 0 : decl !== undefined;
    if (!attached) {
      push(`extensions.${claim}`, "claimed but carries no attached declaration");
    }
  }

  return findings;
}

/**
 * One candidate claim of runtime-enforcement conformance, checked against
 * an already-valid statement's declared scope.
 */
export interface EnforcementClaim {
  resource: string;
  action_class?: string;
  authority_entry_type?: string;
  execution_path?: string;
}

/**
 * "A deployment MUST NOT claim runtime enforcement for a resource, action
 * class, authority-entry type, or execution path outside that declared
 * scope." Returns false if any named axis of `claim` is absent from the
 * statement's baseline declaration; a claim naming no axis beyond
 * `resource` is checked on `resource` alone.
 */
export function claimsWithinScope(stmt: EnforcementScopeBaseline, claim: EnforcementClaim): boolean {
  if (!stmt.mediated_scope.resources.includes(claim.resource)) return false;
  if (claim.action_class !== undefined && !stmt.mediated_scope.action_classes.includes(claim.action_class)) {
    return false;
  }
  if (
    claim.authority_entry_type !== undefined &&
    !stmt.authority_entry_types.some((e) => e.type === claim.authority_entry_type)
  ) {
    return false;
  }
  if (claim.execution_path !== undefined && !stmt.mediated_scope.execution_paths.includes(claim.execution_path)) {
    return false;
  }
  return true;
}
