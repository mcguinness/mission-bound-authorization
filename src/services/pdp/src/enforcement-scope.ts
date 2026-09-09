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
 * extension carrying its attached declaration); `claimsWithinScope` runs
 * that same validation and then checks one candidate claim against the
 * declared baseline. Neither evaluates a live decision; that remains `evaluate()`'s
 * job. A real deployment's own resource/action-class/path coverage against
 * what it actually mediates stays an audit property this module does not
 * reach.
 */

/**
 * The per-entry perimeter disposition inside `mediated_scope`: whether an
 * entry is mediated at the point of use, reconstructed after the fact, or
 * not recorded at all ({{runtime-conformance}}).
 */
export type PerimeterDisposition = "mediated" | "reconstructed" | "unrecorded";
/** An excluded path is outside the mediated perimeter, so it is never `mediated`. */
export type ExcludedPathDisposition = Exclude<PerimeterDisposition, "mediated">;
export interface ResourceEntry { resource: string; disposition: PerimeterDisposition }
export interface ExcludedPathEntry { path: string; disposition: ExcludedPathDisposition }
/** A bare excluded path is representable at intake, but never validates. */
export type DeclaredExcludedPath = ExcludedPathEntry | string;

/**
 * The baseline declaration every conforming deployment carries, whether or
 * not it also claims a named assurance extension (the six MUST members of
 * {{runtime-conformance}}).
 */
export interface EnforcementScopeBaseline {
  mediated_scope: {
    resources: ReadonlyArray<string | ResourceEntry>;
    action_classes: readonly string[];
    execution_paths: readonly string[];
    pep_locations: readonly string[];
    /** May be empty: a deployment that excludes no path still declares the (empty) set. */
    excluded_paths: ReadonlyArray<DeclaredExcludedPath>;
    mission_establishment_mode: string;
  };
  authority_entry_types: ReadonlyArray<{ type: string; evaluator: string }>;
  pdps: readonly string[];
  state_source: {
    source: string;
    max_staleness_seconds: number;
    pdp_unavailability_posture: "deny" | "permit_within_bounds";
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
    /** Receipt issuers must already be named PDPs or executing PEPs in this scope. */
    receipt_issuers?: ReadonlyArray<{ emitter: string; key_set: string }>;
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
function object(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** One walker for declaration validation and scope claims. Conflicts poison the
 * entire result; skipping an invalid entry could otherwise widen the claim. */
function indexEntries(entries: unknown[], kind: "resources" | "excluded_paths") {
  const index = new Map<string, PerimeterDisposition>();
  const findings: EnforcementScopeFinding[] = [];
  entries.forEach((entry, i) => {
    const member = `mediated_scope.${kind}[${i}]`;
    const keyMember = kind === "resources" ? "resource" : "path";
    const key = typeof entry === "string" ? entry : object(entry) ? entry[keyMember] : undefined;
    const disposition =
      typeof entry === "string" && kind === "resources"
        ? "mediated"
        : object(entry)
          ? entry.disposition
          : undefined;
    const fail = (problem: string) => findings.push({ member, problem });
    if (!isNonEmptyString(key)) {
      fail("entry requires a non-empty resource or path identifier");
      return;
    }
    if (kind === "excluded_paths" && typeof entry === "string") {
      fail(`excluded path "${key}" requires an explicit disposition; migrate the bare string to an object`);
      return;
    }
    if (disposition !== "mediated" && disposition !== "reconstructed" && disposition !== "unrecorded") {
      fail(`entry "${key}" has a missing or unknown perimeter disposition`);
      return;
    }
    if (kind === "excluded_paths" && disposition === "mediated") {
      fail(`excluded path "${key}" cannot be mediated`);
      return;
    }
    if (index.has(key) && index.get(key) !== disposition) {
      fail(`duplicate key "${key}" has conflicting perimeter dispositions`);
    } else index.set(key, disposition);
  });
  if (findings.length) index.clear();
  return { index, findings };
}

/**
 * Fail-closed projection of an untrusted statement's declared resources:
 * an empty map when `mediated_scope.resources` is absent or malformed, and
 * an empty map when any entry produced a finding, so an unvalidated
 * statement can never widen a claim.
 */
export function resourceDispositions(input: unknown): ReadonlyMap<string, PerimeterDisposition> {
  if (!object(input) || !object(input.mediated_scope) || !Array.isArray(input.mediated_scope.resources)) return new Map();
  return indexEntries(input.mediated_scope.resources, "resources").index;
}

/**
 * Checks the statement's own internal completeness: every baseline member
 * present and minimally well-formed, and every claimed extension carrying
 * a non-empty attached declaration. Returns one finding per problem; an
 * empty array is a valid statement.
 */
export function validateEnforcementScopeStatement(
  input: unknown,
): EnforcementScopeFinding[] {
  const stmt = object(input) ? input : {};
  const findings: EnforcementScopeFinding[] = [];
  const push = (member: string, problem: string): void => {
    findings.push({ member, problem });
  };

  const scope = stmt.mediated_scope;
  const scopeOk =
    object(scope) &&
    Array.isArray(scope.resources) && scope.resources.length > 0 &&
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
  } else {
    findings.push(...indexEntries(scope.resources as unknown[], "resources").findings);
    findings.push(...indexEntries(scope.excluded_paths as unknown[], "excluded_paths").findings);
  }

  const entryTypes = stmt.authority_entry_types;
  const entryTypesOk =
    Array.isArray(entryTypes) &&
    entryTypes.length > 0 &&
    entryTypes.every((e) => object(e) && isNonEmptyString(e.type) && isNonEmptyString(e.evaluator));
  if (!entryTypesOk) {
    push("authority_entry_types", "missing a supported authority-entry type or its evaluator");
  }

  if (!isNonEmptyStringArray(stmt.pdps)) {
    push("pdps", "missing the PDP or PDPs that evaluate Mission-bound decisions");
  }

  const stateSource = stmt.state_source;
  const stateSourceOk =
    object(stateSource) &&
    isNonEmptyString(stateSource.source) &&
    typeof stateSource.max_staleness_seconds === "number" &&
    Number.isFinite(stateSource.max_staleness_seconds) &&
    stateSource.max_staleness_seconds > 0 &&
    (stateSource.pdp_unavailability_posture === "deny" || stateSource.pdp_unavailability_posture === "permit_within_bounds");
  if (!stateSourceOk) {
    push(
      "state_source",
      "missing the Mission state source, its maximum staleness bound, or the PDP-unavailability posture",
    );
  }

  const channels = stmt.remote_decision_channels;
  const channelsOk =
    Array.isArray(channels) && channels.every((c) => object(c) && isNonEmptyString(c.boundary) && isNonEmptyString(c.trust_mode));
  if (!channelsOk) {
    push(
      "remote_decision_channels",
      "a declared boundary is missing its trust mode (an empty array is valid only for a wholly co-resident deployment)",
    );
  }

  if (!isNonEmptyString(stmt.record_integrity_mechanism)) {
    push("record_integrity_mechanism", "missing the append-only, integrity-protection mechanism for its records");
  }

  if (stmt.claims !== undefined && (!Array.isArray(stmt.claims) || !stmt.claims.every(isNonEmptyString))) {
    push("claims", "claims must be an array of non-empty extension names");
  }
  for (const claim of Array.isArray(stmt.claims) ? stmt.claims : []) {
    if (!isNonEmptyString(claim)) continue;
    const decl = object(stmt.extensions) ? stmt.extensions[claim] : undefined;
    const attached = Array.isArray(decl) ? decl.length > 0 : object(decl) && Object.keys(decl).length > 0;
    if (!attached) {
      push(`extensions.${claim}`, "claimed but carries no attached declaration");
    }
  }

  return findings;
}

/**
 * One candidate claim of runtime-enforcement conformance, checked against a
 * statement's declared scope.
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
export function claimsWithinScope(input: unknown, claim: EnforcementClaim): boolean {
  // A malformed exclusion with no interpretable key cannot be skipped safely.
  // Validate here too: callers need not remember a separate precondition.
  if (validateEnforcementScopeStatement(input).length) return false;
  const stmt = input as EnforcementScopeBaseline;
  if (resourceDispositions(stmt).get(claim.resource) !== "mediated") return false;
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
  if (
    claim.execution_path !== undefined &&
    indexEntries([...stmt.mediated_scope.excluded_paths], "excluded_paths").index.has(claim.execution_path)
  ) {
    return false;
  }
  return true;
}

/**
 * The number of seconds an ISO 8601 duration names, or `undefined` when it
 * names no fixed number of them. Days and below only (`P[nD][T[nH][nM][nS]]`):
 * years and months are calendar-relative, so they resolve to no fixed count
 * and are refused rather than approximated. A retention window the deployment
 * cannot resolve to seconds cannot be compared against an audit horizon, and a
 * declaration is validated against that horizon, never as a non-empty string
 * (@spec runtime-evidence#execution-evidence-object).
 */
export function retentionWindowSeconds(value: unknown): number | undefined {
  if (typeof value !== "string") return undefined;
  const parts = /^P(?!$)(?:(\d{1,6})D)?(?:T(?!$)(?:(\d{1,6})H)?(?:(\d{1,6})M)?(?:(\d{1,6})S)?)?$/.exec(value);
  if (!parts) return undefined;
  const seconds =
    Number(parts[1] ?? 0) * 86400 + Number(parts[2] ?? 0) * 3600 + Number(parts[3] ?? 0) * 60 + Number(parts[4] ?? 0);
  return Number.isSafeInteger(seconds) && seconds > 0 ? seconds : undefined;
}

/**
 * The deployment-external facts the evidence declaration is checked against:
 * the Mission audit horizon, "the deployment-declared retention window for
 * the Mission record and its evidence" (@spec mission#mission-record), which
 * the runtime profile makes the floor under an evidence retention window
 * (@spec runtime-evidence#execution-evidence-object).
 */
export interface EvidenceDeclarationContext {
  auditHorizonSeconds: number;
}

/**
 * Validates the `evidence` extension declaration against this deployment's
 * own scope and audit horizon: the checks that need facts beyond the
 * statement's internal completeness, so {@link validateEnforcementScopeStatement}
 * stays the pure structural pass.
 *
 * A declaration and a claim travel together in both directions. A claimed
 * capability with no declaration is incomplete; an attached declaration under
 * no claim is a deployment asserting a capability in its configuration while
 * denying it in its statement, so it is refused at load rather than read as
 * the claim it is not.
 *
 * Every named location and emitter must resolve inside this statement: a
 * receipt issuer that is not a declared PDP or PEP location, or a key set that
 * is not a declared signing-key location, names something unresolvable and is
 * refused at load.
 */
export function evidenceDeclarationFindings(
  input: unknown,
  ctx: EvidenceDeclarationContext,
): EnforcementScopeFinding[] {
  const stmt = object(input) ? input : {};
  const findings: EnforcementScopeFinding[] = [];
  const push = (member: string, problem: string): void => {
    findings.push({ member, problem });
  };
  const declared = object(stmt.extensions) ? stmt.extensions.evidence : undefined;
  const claimed = Array.isArray(stmt.claims) && stmt.claims.includes("evidence");
  if (declared === undefined) {
    if (claimed) push("extensions.evidence", "the evidence capability is claimed with no attached declaration");
    return findings;
  }
  if (!claimed) {
    push("claims", "an evidence declaration is attached while the statement claims no evidence capability");
  }
  if (!object(declared)) {
    push("extensions.evidence", "declaration must be an object");
    return findings;
  }
  if (!isNonEmptyString(declared.mechanism)) {
    push("extensions.evidence.mechanism", "missing the append-only integrity mechanism for retained records");
  }
  const horizon = ctx.auditHorizonSeconds;
  const window = retentionWindowSeconds(declared.retention_window);
  if (window === undefined) {
    push(
      "extensions.evidence.retention_window",
      "must name a duration in seconds resolvable from an ISO 8601 duration of days or below",
    );
  } else if (!Number.isSafeInteger(horizon) || horizon <= 0) {
    push(
      "extensions.evidence.retention_window",
      "the deployment declares no resolvable Mission audit horizon to check it against",
    );
  } else if (window < horizon) {
    push(
      "extensions.evidence.retention_window",
      `${window}s is shorter than the ${horizon}s Mission audit horizon this deployment declares`,
    );
  }
  if (!isNonEmptyStringArray(declared.signing_key_locations)) {
    push(
      "extensions.evidence.signing_key_locations",
      "missing the published location or locations of the evidence signing key sets",
    );
  }
  const locations = isNonEmptyStringArray(declared.signing_key_locations) ? declared.signing_key_locations : [];
  const scope = object(stmt.mediated_scope) ? stmt.mediated_scope : {};
  const components = new Set<string>([
    ...(isNonEmptyStringArray(stmt.pdps) ? stmt.pdps : []),
    ...(isNonEmptyStringArray(scope.pep_locations) ? scope.pep_locations : []),
  ]);
  if (declared.receipt_issuers !== undefined) {
    if (!Array.isArray(declared.receipt_issuers)) {
      push("extensions.evidence.receipt_issuers", "must be an array of {emitter, key_set} designations");
    } else {
      declared.receipt_issuers.forEach((entry, i) => {
        const member = `extensions.evidence.receipt_issuers[${i}]`;
        if (!object(entry) || !isNonEmptyString(entry.emitter) || !isNonEmptyString(entry.key_set)) {
          push(member, "designation requires a non-empty emitter and key set");
          return;
        }
        if (!components.has(entry.emitter)) {
          push(member, `emitter "${entry.emitter}" is not a declared PDP or PEP location of this scope`);
        }
        if (!locations.includes(entry.key_set)) {
          push(member, `key set "${entry.key_set}" is not a declared signing-key location`);
        }
      });
    }
  }
  if (declared.agent_isolated_evidence_emission !== undefined) {
    if (!Array.isArray(declared.agent_isolated_evidence_emission)) {
      push(
        "extensions.evidence.agent_isolated_evidence_emission",
        "must be an array of {emitter, declaration} entries",
      );
    } else {
      declared.agent_isolated_evidence_emission.forEach((entry, i) => {
        const member = `extensions.evidence.agent_isolated_evidence_emission[${i}]`;
        if (!object(entry) || !isNonEmptyString(entry.emitter) || !isNonEmptyString(entry.declaration)) {
          push(member, "entry requires a non-empty emitter and declaration");
        } else if (!components.has(entry.emitter)) {
          push(member, `emitter "${entry.emitter}" is not a declared PDP or PEP location of this scope`);
        }
      });
    }
  }
  return findings;
}
