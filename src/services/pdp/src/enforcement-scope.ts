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

import { IDEMPOTENCY_SCOPE_DIMENSIONS, isScopeDimension, isVolatileScopeMember } from "@mission/core";

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

/**
 * @spec runtime#execution-reverification — one `transaction_assurance`
 * declaration: the mediated class or scope, its idempotency claim domain, and
 * the PUBLISHED execution lease the clause requires for the high-consequence
 * classes ("the Operation Profile MUST define an execution lease or a
 * published maximum execution duration, and run-to-completion applies only
 * within that bound").
 *
 * The lease members extend this declaration rather than replacing it, and
 * they name their units and their consumer: `execution_lease_max_seconds` is
 * whole seconds, and `execution_lease_consumer` is the
 * `mediated_scope.pep_locations` entry that reads the bound and caps its own
 * lease by it. `idempotency_claim_domain` says which component holds the
 * claim; it does not assert a PDP-side domain a deployment does not implement.
 *
 * @spec runtime#idempotency (#917): the remaining members name the Exact
 * claim domain per mediated class, never per key: the PDP that owns it, the
 * enforcement profile and topology it runs under, the published idempotency
 * scope, and the horizon a completed key stays refused for. They are
 * optional here because this module is the structural pass; the claim domain
 * that relies on them refuses a declaration lacking any of them at startup.
 */
export interface TransactionAssuranceDeclaration {
  mediated_class_or_scope: string;
  idempotency_claim_domain: string;
  execution_lease_max_seconds: number;
  execution_lease_consumer: string;
  idempotency_claim_owner?: string;
  idempotency_enforcement_profile?: "exact" | "bounded";
  idempotency_claim_topology?: string;
  idempotency_scope?: readonly string[];
  idempotency_horizon_seconds?: number;
}

/**
 * @spec runtime#permit-binding, runtime#idempotency (#918): one reversible
 * consequential write that elects the "short validity window combined with an
 * idempotency key" permit-lifetime control, and the reservation that control
 * relies on. The PDP makes no claim for it; the enforcing PEP named by
 * `reservation_owner` atomically reserves the (idempotency scope,
 * `idempotency_key`) pair and retains the record for the published posture.
 *
 * `mediated_class_or_scope` is the reversible-write class itself, or one
 * action identifier inside it: a deployment whose class also holds a write
 * that does not elect this control declares the electing operations one by
 * one, so the declaration never covers an operation it does not describe.
 * `transaction_assurance` cannot carry this: its lease members are REQUIRED,
 * and a reversible write publishes no lease.
 */
export interface ReversibleWriteIdempotencyDeclaration {
  mediated_class_or_scope: string;
  permit_lifetime_control: "validity_window_plus_idempotency_key";
  /** The permit's validity window the key control is combined with, in whole seconds. */
  permit_validity_max_seconds: number;
  reservation_domain: string;
  /** The `mediated_scope.pep_locations` entry that holds the reservation. */
  reservation_owner: string;
  idempotency_scope: readonly string[];
  /**
   * @spec runtime#idempotency: "Outside those classes a deployment MAY scope
   * the guarantee to the reconciliation window, and it MUST publish which
   * posture applies." `declared_horizon` names its own `retention_horizon`;
   * `reconciliation_window` uses `extensions.outcome_reconciliation.window`.
   */
  retention_posture: "declared_horizon" | "reconciliation_window";
  /** ISO 8601 duration of days or below; REQUIRED for `declared_horizon`. */
  retention_horizon?: string;
}

/**
 * @spec runtime#permit-binding, runtime#single-use-identifiers (#1080, D333):
 * one reversible consequential write that elects the "single-use decision
 * identifier" permit-lifetime control: the permit carries `use_limit: 1` and
 * the enforcing PEP named by `consumed_identifier_owner` records its
 * `evaluation_id` consumed in `consumed_identifier_domain` and refuses a
 * re-presentation.
 *
 * `retention_posture` is `permit_acceptance_window`: a consumed identifier is
 * kept at least until the end of the window in which the owner still accepts
 * the permit, its `valid_until` plus any clock skew the owner permits on
 * acceptance. The window follows each permit, so the declaration names no
 * fixed horizon; the owner realizes it (the payments PEP accepts no skew and
 * keeps each record until `valid_until` plus a 30 s margin). The key
 * variant's reservation, key-scope, key-window and fixed-horizon members
 * (`reservation_domain`, `reservation_owner`, `idempotency_scope`,
 * `permit_validity_max_seconds`, `retention_horizon`) are refused on it.
 *
 * A reference-statement representation of the control, not a Runtime wire
 * member.
 */
export interface SingleUseDecisionIdentifierDeclaration {
  mediated_class_or_scope: string;
  permit_lifetime_control: "single_use_decision_identifier";
  consumed_identifier_domain: string;
  /** The `mediated_scope.pep_locations` entry that holds the consumed identifiers. */
  consumed_identifier_owner: string;
  retention_posture: "permit_acceptance_window";
}

/**
 * One `reversible_write_idempotency` entry, discriminated on
 * `permit_lifetime_control` (D333): the two controls {{permit-binding}} offers
 * a reversible consequential write.
 */
export type ReversibleWriteControlDeclaration =
  | ReversibleWriteIdempotencyDeclaration
  | SingleUseDecisionIdentifierDeclaration;

/** The one reversible-write class that may elect the idempotency-key control. */
export const REVERSIBLE_WRITE_CLASS = "consequential_write";

export interface EnforcementExtensionDeclarations {
  custody?: ReadonlyArray<{ mediated_class: string; custody_mode: string }>;
  transaction_assurance?: ReadonlyArray<TransactionAssuranceDeclaration>;
  reversible_write_idempotency?: ReadonlyArray<ReversibleWriteControlDeclaration>;
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

  // The `transaction_assurance` declaration carries a published execution
  // lease, so it is shape-validated wherever it appears: a declaration
  // present without the claim still has to be well formed, and a member
  // naming a class or a PEP the baseline does not declare is unresolvable and
  // refused rather than read as a wider claim.
  const txnAssurance = object(stmt.extensions) ? stmt.extensions.transaction_assurance : undefined;
  if (txnAssurance !== undefined) {
    if (!Array.isArray(txnAssurance)) {
      push("extensions.transaction_assurance", "must be an array of per-class declarations");
    } else {
      const classes = scopeOk && object(scope) ? (scope.action_classes as readonly string[]) : [];
      const peps = scopeOk && object(scope) ? (scope.pep_locations as readonly string[]) : [];
      txnAssurance.forEach((raw, i) => {
        const member = `extensions.transaction_assurance[${i}]`;
        const decl = object(raw) ? raw : undefined;
        if (!decl) {
          push(member, "entry must be an object");
          return;
        }
        if (!isNonEmptyString(decl.mediated_class_or_scope)) {
          push(member, "missing the mediated class or scope this declaration covers");
        } else if (!classes.includes(decl.mediated_class_or_scope)) {
          push(
            member,
            `mediated_class_or_scope "${decl.mediated_class_or_scope}" is outside mediated_scope.action_classes`,
          );
        }
        if (!isNonEmptyString(decl.idempotency_claim_domain)) {
          push(member, "missing the idempotency claim domain and the component that holds it");
        }
        if (
          typeof decl.execution_lease_max_seconds !== "number" ||
          !Number.isSafeInteger(decl.execution_lease_max_seconds) ||
          decl.execution_lease_max_seconds <= 0
        ) {
          push(member, "execution_lease_max_seconds must be a positive whole number of seconds");
        }
        if (!isNonEmptyString(decl.execution_lease_consumer)) {
          push(member, "missing the execution_lease_consumer that reads this published bound");
        } else if (!peps.includes(decl.execution_lease_consumer)) {
          push(
            member,
            `execution_lease_consumer "${decl.execution_lease_consumer}" is not a declared mediated_scope.pep_locations entry`,
          );
        }
        // @spec runtime#idempotency (#917): the claim-domain members are
        // shape-checked wherever they appear. Whether they describe a domain
        // a PDP can actually run (one owner, Exact, a supported topology, the
        // required dimensions) is the claim domain's own startup refusal.
        const pdps = isNonEmptyStringArray(stmt.pdps) ? stmt.pdps : [];
        if (decl.idempotency_claim_owner !== undefined) {
          if (!isNonEmptyString(decl.idempotency_claim_owner)) {
            push(member, "idempotency_claim_owner must name the PDP that owns the claim domain");
          } else if (!pdps.includes(decl.idempotency_claim_owner)) {
            push(member, `idempotency_claim_owner "${decl.idempotency_claim_owner}" is not a declared pdps entry`);
          }
        }
        if (
          decl.idempotency_enforcement_profile !== undefined &&
          decl.idempotency_enforcement_profile !== "exact" &&
          decl.idempotency_enforcement_profile !== "bounded"
        ) {
          push(member, "idempotency_enforcement_profile must be exact or bounded");
        }
        if (decl.idempotency_claim_topology !== undefined && !isNonEmptyString(decl.idempotency_claim_topology)) {
          push(member, "idempotency_claim_topology must be a non-empty topology name");
        }
        if (decl.idempotency_scope !== undefined) {
          const scopeList = decl.idempotency_scope;
          if (!isNonEmptyStringArray(scopeList) || new Set(scopeList).size !== scopeList.length) {
            push(member, "idempotency_scope must be a non-empty list of distinct dimension names");
          }
        }
        if (
          decl.idempotency_horizon_seconds !== undefined &&
          (typeof decl.idempotency_horizon_seconds !== "number" ||
            !Number.isSafeInteger(decl.idempotency_horizon_seconds) ||
            decl.idempotency_horizon_seconds <= 0)
        ) {
          push(member, "idempotency_horizon_seconds must be a positive whole number of seconds");
        }
      });
    }
  }

  // @spec runtime#runtime-conformance, runtime#idempotency (#917): the
  // outcome-reconciliation declaration names the window an unresolved claim
  // stays transient for and the component responsible for resolving it. Like
  // `transaction_assurance`, it is shape-checked wherever it appears: a
  // window that resolves to no fixed duration, or a component this scope does
  // not declare, is unresolvable.
  const reconciliation = object(stmt.extensions) ? stmt.extensions.outcome_reconciliation : undefined;
  if (reconciliation !== undefined) {
    const member = "extensions.outcome_reconciliation";
    if (!object(reconciliation)) {
      push(member, "declaration must be an object");
    } else {
      if (retentionWindowSeconds(reconciliation.window) === undefined) {
        push(member, "window must be an ISO 8601 duration of days or below");
      }
      const components = new Set<string>([
        ...(isNonEmptyStringArray(stmt.pdps) ? stmt.pdps : []),
        ...(scopeOk && object(scope) ? (scope.pep_locations as readonly string[]) : []),
      ]);
      if (!isNonEmptyString(reconciliation.responsible_component)) {
        push(member, "missing the component responsible for reconciliation");
      } else if (!components.has(reconciliation.responsible_component)) {
        push(
          member,
          `responsible_component "${reconciliation.responsible_component}" is not a declared PDP or PEP location of this scope`,
        );
      }
      if (!isNonEmptyString(reconciliation.alerting)) {
        push(member, "missing the alerting an unresolved outcome raises");
      }
    }
  }

  findings.push(...reversibleWriteFindings(stmt, scopeOk && object(scope) ? scope : undefined));

  return findings;
}

/** The key variant's members, refused on a single-use declaration (D333). */
const KEY_CONTROL_MEMBERS = [
  "reservation_domain",
  "reservation_owner",
  "idempotency_scope",
  "permit_validity_max_seconds",
  "retention_horizon",
] as const;
/** The single-use variant's own members, refused on a key declaration as ambiguous. */
const SINGLE_USE_MEMBERS = ["consumed_identifier_domain", "consumed_identifier_owner"] as const;

/**
 * @spec runtime#permit-binding, runtime#idempotency (#918): the
 * `reversible_write_idempotency` declarations, shape-checked wherever they
 * appear, like `transaction_assurance`. The class (or the action's class) is
 * a declared mediated class, and no class or operation is declared twice.
 *
 * Each entry is one variant of `permit_lifetime_control` (D333), and carries
 * no member of the other, so it is never ambiguous:
 *
 * - `validity_window_plus_idempotency_key`: the owner is a declared PEP
 *   location; the scope names only fixed-member dimensions and no volatile
 *   member; and the retention horizon resolves to a fixed number of seconds
 *   longer than the permit window, so a duplicate arriving after the permit
 *   expired still finds the record.
 * - `single_use_decision_identifier`: the consumed-identifier owner is a
 *   declared PEP location, the domain is named, and the retention posture is
 *   `permit_acceptance_window`.
 */
function reversibleWriteFindings(
  stmt: Record<string, unknown>,
  scope: Record<string, unknown> | undefined,
): EnforcementScopeFinding[] {
  const findings: EnforcementScopeFinding[] = [];
  const declared = object(stmt.extensions) ? stmt.extensions.reversible_write_idempotency : undefined;
  if (declared === undefined) return findings;
  const push = (member: string, problem: string): void => {
    findings.push({ member, problem });
  };
  if (!Array.isArray(declared)) {
    push("extensions.reversible_write_idempotency", "must be an array of per-class or per-operation declarations");
    return findings;
  }
  const classes = scope ? (scope.action_classes as readonly string[]) : [];
  const peps = scope ? (scope.pep_locations as readonly string[]) : [];
  const reconciliation = object(stmt.extensions) ? stmt.extensions.outcome_reconciliation : undefined;
  const covered = new Set<string>();
  declared.forEach((raw, i) => {
    const member = `extensions.reversible_write_idempotency[${i}]`;
    const decl = object(raw) ? raw : undefined;
    if (!decl) {
      push(member, "entry must be an object");
      return;
    }
    const target = decl.mediated_class_or_scope;
    if (!isNonEmptyString(target)) {
      push(member, "missing the reversible-write class or operation this declaration covers");
    } else if (!classes.includes(REVERSIBLE_WRITE_CLASS)) {
      push(member, `${REVERSIBLE_WRITE_CLASS} is outside mediated_scope.action_classes`);
    } else if (target !== REVERSIBLE_WRITE_CLASS && (classes.includes(target) || !target.includes(":"))) {
      push(
        member,
        `mediated_class_or_scope "${target}" is neither ${REVERSIBLE_WRITE_CLASS} nor an action identifier inside it`,
      );
    } else if (covered.has(target)) {
      push(member, `mediated_class_or_scope "${target}" is declared twice`);
    } else covered.add(target);
    if (decl.permit_lifetime_control === "single_use_decision_identifier") {
      for (const name of KEY_CONTROL_MEMBERS) {
        if (Object.hasOwn(decl, name)) push(member, `a single_use_decision_identifier declaration names no ${name}`);
      }
      if (!isNonEmptyString(decl.consumed_identifier_domain)) {
        push(member, "missing the consumed-identifier domain and the component that holds it");
      }
      if (!isNonEmptyString(decl.consumed_identifier_owner)) {
        push(member, "missing the consumed_identifier_owner that holds the consumed identifiers");
      } else if (!peps.includes(decl.consumed_identifier_owner)) {
        push(
          member,
          `consumed_identifier_owner "${decl.consumed_identifier_owner}" is not a declared mediated_scope.pep_locations entry`,
        );
      }
      if (decl.retention_posture !== "permit_acceptance_window") {
        push(member, "a single_use_decision_identifier declaration's retention_posture must be permit_acceptance_window");
      }
      return;
    }
    if (decl.permit_lifetime_control !== "validity_window_plus_idempotency_key") {
      push(
        member,
        "permit_lifetime_control must be validity_window_plus_idempotency_key or single_use_decision_identifier",
      );
      return;
    }
    for (const name of SINGLE_USE_MEMBERS) {
      if (Object.hasOwn(decl, name)) push(member, `a validity_window_plus_idempotency_key declaration names no ${name}`);
    }
    const permitWindow = decl.permit_validity_max_seconds;
    const permitOk = typeof permitWindow === "number" && Number.isSafeInteger(permitWindow) && permitWindow > 0;
    if (!permitOk) push(member, "permit_validity_max_seconds must be a positive whole number of seconds");
    if (!isNonEmptyString(decl.reservation_domain)) {
      push(member, "missing the reservation domain and the component that holds it");
    }
    if (!isNonEmptyString(decl.reservation_owner)) {
      push(member, "missing the reservation_owner that holds the reservation");
    } else if (!peps.includes(decl.reservation_owner)) {
      push(member, `reservation_owner "${decl.reservation_owner}" is not a declared mediated_scope.pep_locations entry`);
    }
    const dims = decl.idempotency_scope;
    if (
      !isNonEmptyStringArray(dims) ||
      new Set(dims).size !== dims.length ||
      !dims.every(isScopeDimension) ||
      dims.some(isVolatileScopeMember) ||
      !IDEMPOTENCY_SCOPE_DIMENSIONS.every((d) => dims.includes(d))
    ) {
      push(member, `idempotency_scope must name each of ${IDEMPOTENCY_SCOPE_DIMENSIONS.join(", ")} once, and no volatile member`);
    }
    let horizon: number | undefined;
    if (decl.retention_posture === "declared_horizon") {
      horizon = retentionWindowSeconds(decl.retention_horizon);
      if (horizon === undefined) push(member, "retention_horizon must be an ISO 8601 duration of days or below");
    } else if (decl.retention_posture === "reconciliation_window") {
      if (decl.retention_horizon !== undefined) push(member, "a reconciliation_window posture names no retention_horizon of its own");
      horizon = object(reconciliation) ? retentionWindowSeconds(reconciliation.window) : undefined;
      if (horizon === undefined) push(member, "a reconciliation_window posture needs a declared outcome_reconciliation window");
    } else {
      push(member, "retention_posture must be declared_horizon or reconciliation_window");
    }
    if (horizon !== undefined && permitOk && horizon <= (permitWindow as number)) {
      push(member, `the ${horizon}s retention is not longer than the ${permitWindow as number}s permit window`);
    }
  });
  return findings;
}

/**
 * @spec runtime#permit-binding (#918, D333): the permit-lifetime control
 * declaration that covers one request, of either variant: the entry naming
 * its action identifier, else the one naming its class. The most specific
 * entry is selected before any variant is considered, so an operation's own
 * declaration always governs it. Only a `consequential_write` request is ever
 * covered; the high-consequence classes carry the PDP's claim instead.
 */
export function reversibleWriteControlFor(
  stmt: EnforcementScopeStatement,
  actionClass: string | undefined,
  action: string,
): ReversibleWriteControlDeclaration | undefined {
  if (actionClass !== REVERSIBLE_WRITE_CLASS) return undefined;
  const declared = stmt.extensions?.reversible_write_idempotency ?? [];
  return (
    declared.find((d) => d.mediated_class_or_scope === action) ??
    declared.find((d) => d.mediated_class_or_scope === REVERSIBLE_WRITE_CLASS)
  );
}

/**
 * @spec runtime#permit-binding, runtime#idempotency (#918, D333): the
 * declaration that covers one request when the control selected for it
 * ({@link reversibleWriteControlFor}) is the idempotency-key control, else
 * `undefined`. Selection comes first: an operation that elects single use is
 * never covered by a class-wide key declaration.
 */
export function reversibleWriteDeclarationFor(
  stmt: EnforcementScopeStatement,
  actionClass: string | undefined,
  action: string,
): ReversibleWriteIdempotencyDeclaration | undefined {
  const selected = reversibleWriteControlFor(stmt, actionClass, action);
  return selected?.permit_lifetime_control === "validity_window_plus_idempotency_key" ? selected : undefined;
}

/**
 * The retention a declaration publishes, in whole seconds: its own horizon,
 * or the reconciliation window for that posture. `undefined` only for a
 * statement the validator above refuses.
 */
export function reversibleWriteRetentionSeconds(
  stmt: EnforcementScopeStatement,
  decl: ReversibleWriteIdempotencyDeclaration,
): number | undefined {
  return decl.retention_posture === "declared_horizon"
    ? retentionWindowSeconds(decl.retention_horizon)
    : retentionWindowSeconds(stmt.extensions?.outcome_reconciliation?.window);
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
 * A claimed capability with no declaration is incomplete, and is refused: that
 * is the direction that would otherwise let a false assertion stand. The
 * converse is NOT an error. A declaration asserts nothing on its own, so a
 * deployment may publish one while withholding the claim, which is the honest
 * shape for a capability whose applicable obligations are not all met yet: it
 * publishes the value a peer needs without asserting conformance it does not
 * have. `transaction_assurance` ships exactly this shape for the published
 * execution lease maximum (issue #252 C1), and the `evidence` block is
 * intended to reach it the same way (issue #594 W4-8). Refusing it would
 * leave a deployment choosing between asserting a capability it does not meet
 * and publishing nothing at all. Only `claims` asserts.
 *
 * Every named location and emitter must resolve inside this statement,
 * claimed or not: a receipt issuer that is not a declared PDP or PEP location,
 * or a key set that is not a declared signing-key location, names something
 * unresolvable and is refused at load. So is a retention window shorter than
 * the audit horizon, whose floor binds every runtime-enforced deployment
 * independently of any claim.
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
  // A declaration under no claim is a published value, not an assertion, and
  // loads. Everything below still applies to it: what it names has to resolve.
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
