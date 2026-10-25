/**
 * @spec runtime#input-authority-dependency (#830, D798): a declared
 * authority dependency, its observations, and the one evaluation every
 * enforcing component applies.
 *
 * A deployment's policy can make reliance on a Mission depend on an external
 * authority remaining effective. Here that is one dependency: the Mission
 * Subject's continuing delegation to the client acting under the Mission,
 * held while the Subject's account is active in the identity source and the
 * Subject has not withdrawn the delegation. The declaration states the
 * dependency, its source, what it governs, the invalidating changes, its
 * maximum staleness (separate from the Mission-state freshness declaration),
 * its enforcement route and its recovery.
 *
 * - An observation is a read of the authoritative source; its accepted
 *   validity runs from the time it represents (the read), never from a later
 *   re-issue, and ends `max_staleness_seconds` later.
 * - Reliance stops on a known withdrawal, on an observed applicable
 *   invalidation, or when no acceptable observation remains. An outage alone
 *   does not invalidate an observation still within its validity, unless the
 *   declaration requires an online check.
 * - A refusal is classified `withdrawn`, `invalidated`, `stale` or
 *   `unavailable`, so retained evidence keeps a known withdrawal, a stale
 *   observation and an unavailable source apart. The wire refusal is the
 *   enforcing mechanism's own (`resource_policy` at a composed step,
 *   `invalid_grant` at an issuance gate); no new identifier is introduced.
 *
 * Nothing here performs I/O: the resolver's `refresh()` reads the source
 * asynchronously, and every check reads the cached observation synchronously,
 * so no check holds a store transaction across a source read.
 */

/** A principal, issuer-qualified. */
export interface DependencyPrincipal {
  iss: string;
  sub: string;
}

/** The account states the identity source reports. */
export type PrincipalStatus = "active" | "disabled" | "deprovisioned";

/** The changes at the source a declaration may name as invalidating reliance. */
export type InvalidatingChange =
  | "subject_disabled"
  | "subject_deprovisioned"
  | "delegation_withdrawn";

/** The authority source types a declaration may govern (@spec mission#authority-sources). */
export type GovernedAuthoritySource = "user_delegated" | "service_owned" | "organizational";

/** Why reliance on a dependency stopped. */
export type DependencyFailure = "withdrawn" | "invalidated" | "stale" | "unavailable";

/** @spec runtime#input-authority-dependency: one declared authority dependency. */
export interface AuthorityDependencyDeclaration {
  id: string;
  /** The dependency, in words. */
  dependency: string;
  /** Its authoritative source. */
  source: { id: string; description: string };
  /** The state an observation of it represents. */
  observation: string;
  /** What it governs. */
  governs: {
    /** The Missions it applies to, by their recorded authority source. */
    authority_sources: GovernedAuthoritySource[];
    /** In words: future activations, existing Missions, selected entries or actions, or one business approval. */
    scope: string;
  };
  /** Which changes at the source invalidate reliance. */
  invalidating_changes: InvalidatingChange[];
  /** Maximum staleness of an observation, separate from the Mission-state freshness declaration. */
  max_staleness_seconds: number;
  /** Whether reliance requires a successful read of the source, whatever an earlier observation's validity. */
  online_check: boolean;
  /** How it is enforced: direct evaluation, lifecycle-mediated enforcement, or both. */
  enforcement: {
    /** Direct evaluation at the PDP, or at a composed resource-policy step at the PEP. Absent: none. */
    direct?: "pdp" | "pep";
    /** Lifecycle-mediated enforcement through a reconciler. */
    lifecycle: boolean;
    /** Under lifecycle-mediated enforcement, the bound on upstream observation and reconciliation lag. */
    reconciliation_max_lag_seconds?: number;
  };
  /** What restores reliance after it fails. */
  recovery: string;
  /** How responsibility passes to a successor, leaving the original approval's attribution unchanged. */
  responsibility_transfer: string;
}

/** A declaration that is not one this deployment can enforce. */
export class AuthorityDependencyConfigError extends Error {}

const GOVERNED: readonly GovernedAuthoritySource[] = [
  "user_delegated",
  "service_owned",
  "organizational",
];
const CHANGES: readonly InvalidatingChange[] = [
  "subject_disabled",
  "subject_deprovisioned",
  "delegation_withdrawn",
];
const DECLARATION_MEMBERS = [
  "id",
  "dependency",
  "source",
  "observation",
  "governs",
  "invalidating_changes",
  "max_staleness_seconds",
  "online_check",
  "enforcement",
  "recovery",
  "responsibility_transfer",
] as const;

const objectOf = (v: unknown): Record<string, unknown> | undefined =>
  v !== null && typeof v === "object" && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : undefined;

function text(ctx: string, v: unknown): string {
  if (typeof v !== "string" || v.trim() === "")
    throw new AuthorityDependencyConfigError(`${ctx} must be a non-empty string`);
  return v;
}

function onlyMembers(ctx: string, o: Record<string, unknown>, allowed: readonly string[]): void {
  for (const key of Object.keys(o)) {
    if (!allowed.includes(key))
      throw new AuthorityDependencyConfigError(`${ctx} has unknown member ${key}`);
  }
}

/**
 * @spec runtime#input-authority-dependency: the strict reader of a
 * deployment's declarations. Each declaration states every element the
 * Runtime requires; a missing or unknown member, an empty statement, a
 * non-positive staleness, an unknown invalidating change or governed source,
 * and a declaration with no enforcement route are refused, naming the member.
 */
export function parseAuthorityDependencyDeclarations(
  raw: unknown,
): AuthorityDependencyDeclaration[] {
  if (!Array.isArray(raw))
    throw new AuthorityDependencyConfigError("authority_dependencies must be an array");
  const seen = new Set<string>();
  return raw.map((entry, i) => {
    const ctx = `authority_dependencies[${i}]`;
    const o = objectOf(entry);
    if (!o) throw new AuthorityDependencyConfigError(`${ctx} must be an object`);
    onlyMembers(ctx, o, DECLARATION_MEMBERS);
    for (const member of DECLARATION_MEMBERS) {
      if (o[member] === undefined)
        throw new AuthorityDependencyConfigError(`${ctx} is missing ${member}`);
    }
    const id = text(`${ctx}.id`, o.id);
    if (seen.has(id)) throw new AuthorityDependencyConfigError(`${ctx}.id ${id} is declared twice`);
    seen.add(id);
    const source = objectOf(o.source);
    if (!source) throw new AuthorityDependencyConfigError(`${ctx}.source must be an object`);
    onlyMembers(`${ctx}.source`, source, ["id", "description"]);
    const governs = objectOf(o.governs);
    if (!governs) throw new AuthorityDependencyConfigError(`${ctx}.governs must be an object`);
    onlyMembers(`${ctx}.governs`, governs, ["authority_sources", "scope"]);
    const sources = governs.authority_sources;
    if (
      !Array.isArray(sources) ||
      sources.length === 0 ||
      sources.some((s) => !GOVERNED.includes(s as GovernedAuthoritySource))
    ) {
      throw new AuthorityDependencyConfigError(
        `${ctx}.governs.authority_sources must name one or more of ${GOVERNED.join(", ")}`,
      );
    }
    const changes = o.invalidating_changes;
    if (
      !Array.isArray(changes) ||
      changes.length === 0 ||
      changes.some((c) => !CHANGES.includes(c as InvalidatingChange))
    ) {
      throw new AuthorityDependencyConfigError(
        `${ctx}.invalidating_changes must name one or more of ${CHANGES.join(", ")}`,
      );
    }
    const staleness = o.max_staleness_seconds;
    if (typeof staleness !== "number" || !Number.isInteger(staleness) || staleness <= 0) {
      throw new AuthorityDependencyConfigError(
        `${ctx}.max_staleness_seconds must be a positive integer`,
      );
    }
    if (typeof o.online_check !== "boolean")
      throw new AuthorityDependencyConfigError(`${ctx}.online_check must be a boolean`);
    const enforcement = objectOf(o.enforcement);
    if (!enforcement)
      throw new AuthorityDependencyConfigError(`${ctx}.enforcement must be an object`);
    onlyMembers(`${ctx}.enforcement`, enforcement, [
      "direct",
      "lifecycle",
      "reconciliation_max_lag_seconds",
    ]);
    const direct = enforcement.direct;
    if (direct !== undefined && direct !== "pdp" && direct !== "pep") {
      throw new AuthorityDependencyConfigError(`${ctx}.enforcement.direct must be pdp or pep`);
    }
    if (typeof enforcement.lifecycle !== "boolean")
      throw new AuthorityDependencyConfigError(`${ctx}.enforcement.lifecycle must be a boolean`);
    if (direct === undefined && enforcement.lifecycle === false) {
      throw new AuthorityDependencyConfigError(
        `${ctx}.enforcement names no route: direct evaluation, lifecycle-mediated enforcement, or both`,
      );
    }
    const lag = enforcement.reconciliation_max_lag_seconds;
    if (enforcement.lifecycle === true) {
      if (typeof lag !== "number" || !Number.isInteger(lag) || lag <= 0) {
        throw new AuthorityDependencyConfigError(
          `${ctx}.enforcement.reconciliation_max_lag_seconds must be a positive integer under lifecycle-mediated enforcement`,
        );
      }
    } else if (lag !== undefined) {
      throw new AuthorityDependencyConfigError(
        `${ctx}.enforcement.reconciliation_max_lag_seconds applies to lifecycle-mediated enforcement only`,
      );
    }
    return {
      id,
      dependency: text(`${ctx}.dependency`, o.dependency),
      source: {
        id: text(`${ctx}.source.id`, source.id),
        description: text(`${ctx}.source.description`, source.description),
      },
      observation: text(`${ctx}.observation`, o.observation),
      governs: {
        authority_sources: [...new Set(sources as GovernedAuthoritySource[])],
        scope: text(`${ctx}.governs.scope`, governs.scope),
      },
      invalidating_changes: [...new Set(changes as InvalidatingChange[])],
      max_staleness_seconds: staleness,
      online_check: o.online_check,
      enforcement: {
        ...(direct !== undefined ? { direct } : {}),
        lifecycle: enforcement.lifecycle,
        ...(lag !== undefined ? { reconciliation_max_lag_seconds: lag as number } : {}),
      },
      recovery: text(`${ctx}.recovery`, o.recovery),
      responsibility_transfer: text(`${ctx}.responsibility_transfer`, o.responsibility_transfer),
    };
  });
}

/** One principal's record in the identity source, as the source reports it. */
export interface IdentityStateRecord {
  sub: string;
  status: PrincipalStatus;
  /** The clients this principal has withdrawn its delegation from. */
  withdrawn_delegations: readonly string[];
  /** When the authoritative source recorded this record's latest change (RFC 3339), where it says. */
  changed_at?: string;
}

/** A principal's state as one observation of the source represents it. */
export interface PrincipalStateObservation {
  /** Whether the source holds a record for the principal at all. */
  known: boolean;
  status?: PrincipalStatus;
  withdrawnDelegations: readonly string[];
  changedAt?: string;
  /** The time the observation represents: the source read it was taken from (RFC 3339). */
  observedAt: string;
}

/** What the resolver can say about a principal now. */
export interface PrincipalStateView {
  /** The latest acceptable read's observation of the principal; absent when no read has succeeded. */
  observation?: PrincipalStateObservation;
  /** Whether the latest attempt to read the source succeeded. */
  sourceAvailable: boolean;
}

/**
 * @spec runtime#input-authority-dependency, cross-domain#dual-axis: the
 * local identity-state resolver, modeled on the Resource AS's entitlement
 * resolver. It reads the configuration-backed identity source on `refresh()`
 * (async, so a caller does it outside any store transaction), keeps the last
 * successful read with the time it represents, and answers `view()`
 * synchronously from that read. A failed read keeps the last good one and is
 * reported as an unavailable source; the declaration decides what that means
 * for reliance. Principals of another issuer are unknown to it.
 */
export class AuthorityDependencyResolver {
  private snapshot: { bySub: Map<string, IdentityStateRecord>; observedAtMs: number } | undefined;
  private lastAttemptOk = true;
  private readonly now: () => number;

  constructor(
    private readonly opts: {
      /** The issuer whose principals the source describes. */
      issuer: string;
      /** Reads the source. A throw is an unavailable source. */
      read: () => Promise<unknown>;
      /** Parses what `read` returned; a throw is an unavailable source too. */
      parse: (raw: unknown) => readonly IdentityStateRecord[];
      now?: () => number;
    },
  ) {
    this.now = opts.now ?? (() => Date.now());
  }

  /** Read the source once. Resolves whether the read succeeded; a failure keeps the previous observation. */
  async refresh(): Promise<boolean> {
    try {
      const records = this.opts.parse(await this.opts.read());
      const bySub = new Map(records.map((r) => [r.sub, r]));
      this.snapshot = { bySub, observedAtMs: this.now() };
      this.lastAttemptOk = true;
      return true;
    } catch {
      this.lastAttemptOk = false;
      return false;
    }
  }

  /** The time the latest acceptable observation represents, epoch milliseconds. */
  observedAtMs(): number | undefined {
    return this.snapshot?.observedAtMs;
  }

  /** Every record the latest acceptable observation holds. */
  records(): readonly IdentityStateRecord[] {
    return this.snapshot ? [...this.snapshot.bySub.values()] : [];
  }

  view(principal: DependencyPrincipal): PrincipalStateView {
    const snapshot = this.snapshot;
    if (!snapshot) return { sourceAvailable: this.lastAttemptOk };
    const record =
      principal.iss === this.opts.issuer ? snapshot.bySub.get(principal.sub) : undefined;
    const observedAt = new Date(snapshot.observedAtMs).toISOString();
    return {
      sourceAvailable: this.lastAttemptOk,
      observation: record
        ? {
            known: true,
            status: record.status,
            withdrawnDelegations: record.withdrawn_delegations,
            ...(record.changed_at !== undefined ? { changedAt: record.changed_at } : {}),
            observedAt,
          }
        : { known: false, withdrawnDelegations: [], observedAt },
    };
  }
}

/** The evaluation's answer: reliance holds until `validUntilMs`, or it stopped, and why. */
export type DependencyEvaluation =
  | { ok: true; validUntilMs: number; observedAt: string }
  | { ok: false; failure: DependencyFailure; observedAt?: string };

/**
 * @spec runtime#input-authority-dependency: whether `view` establishes the
 * declared dependency for `clientId` at `nowMs`.
 *
 * - No observation at all: `unavailable`.
 * - An observation past its accepted validity: `stale` while the source still
 *   answers, `unavailable` once it does not (no acceptable observation remains
 *   either way).
 * - The source unreachable where the declaration requires an online check:
 *   `unavailable`, whatever the observation's validity.
 * - A Subject the source holds no record of, or one that withdrew the
 *   delegation: `withdrawn`. A Subject disabled or deprovisioned, where the
 *   declaration names that change: `invalidated`.
 * - Otherwise reliance holds until the observation's validity ends.
 */
export function evaluateAuthorityDependency(
  declaration: AuthorityDependencyDeclaration,
  view: PrincipalStateView,
  input: { clientId: string; nowMs: number },
): DependencyEvaluation {
  const observation = view.observation;
  if (!observation) return { ok: false, failure: "unavailable" };
  const observedAt = observation.observedAt;
  const observedAtMs = Date.parse(observedAt);
  const validUntilMs = observedAtMs + declaration.max_staleness_seconds * 1000;
  if (!Number.isFinite(observedAtMs) || input.nowMs >= validUntilMs) {
    return { ok: false, failure: view.sourceAvailable ? "stale" : "unavailable", observedAt };
  }
  if (declaration.online_check && !view.sourceAvailable)
    return { ok: false, failure: "unavailable", observedAt };
  const changes = declaration.invalidating_changes;
  if (!observation.known) return { ok: false, failure: "withdrawn", observedAt };
  if (observation.status === "disabled" && changes.includes("subject_disabled"))
    return { ok: false, failure: "invalidated", observedAt };
  if (observation.status === "deprovisioned" && changes.includes("subject_deprovisioned")) {
    return { ok: false, failure: "invalidated", observedAt };
  }
  if (
    changes.includes("delegation_withdrawn") &&
    observation.withdrawnDelegations.includes(input.clientId)
  ) {
    return { ok: false, failure: "withdrawn", observedAt };
  }
  return { ok: true, validUntilMs, observedAt };
}

/** One retained refusal: which component refused, on which dependency, and why. */
export interface AuthorityDependencyRefusal {
  /** The enforcing component: the PDP, a composed step at the PEP, or an issuance gate at the AS. */
  enforcer: "pdp" | "pep" | "as";
  dependency: string;
  failure: DependencyFailure;
  /** The Mission relied on; absent at an approval decision, before the Mission exists. */
  mission?: { id: string; issuer: string };
  subject: DependencyPrincipal;
  client: string;
  /** The action refused, at the PDP or PEP; the issuance surface at the AS. */
  action: string;
  /** The time the observation relied on represents, where there was one. */
  observed_at?: string;
  at: string;
}

/**
 * @spec runtime#input-authority-dependency ("Retained evidence of such a
 * refusal ... distinguishes a known withdrawal, a stale observation and an
 * unavailable source"): the deployment-local record of each refusal, kept by
 * whichever component enforces. A deployment record, not a Runtime Evidence
 * object: the wire form is not chosen here (#830 Q-c).
 */
export class AuthorityDependencyEvidence {
  private readonly held: AuthorityDependencyRefusal[] = [];

  record(refusal: AuthorityDependencyRefusal): void {
    this.held.push(refusal);
  }

  entries(): readonly AuthorityDependencyRefusal[] {
    return this.held;
  }
}

/** What an enforcing component holds to apply one declared dependency. */
export interface AuthorityDependencyEnforcement {
  declaration: AuthorityDependencyDeclaration;
  resolver: AuthorityDependencyResolver;
  /**
   * The principal and client the dependency is evaluated for under a Mission,
   * from the Mission's own record: undefined when the declaration does not
   * govern the Mission (its authority source is not one the declaration
   * names) or the Mission is not one this deployment holds.
   */
  governed: (mission: {
    id: string;
    issuer: string;
  }) => { subject: DependencyPrincipal; clientId: string } | undefined;
  evidence?: AuthorityDependencyEvidence;
  now?: () => number;
}

/**
 * Apply the declared dependency for one decision or issuance under
 * `mission`: ungoverned Missions pass with no ceiling; a governed one passes
 * with the observation's validity as a ceiling, or is refused and the refusal
 * retained.
 */
export function checkAuthorityDependency(
  enforcement: AuthorityDependencyEnforcement,
  mission: { id: string; issuer: string },
  context: { enforcer: AuthorityDependencyRefusal["enforcer"]; action: string },
): { ok: true; validUntilMs?: number } | { ok: false; failure: DependencyFailure } {
  const governed = enforcement.governed(mission);
  if (!governed) return { ok: true };
  const nowMs = (enforcement.now ?? (() => Date.now()))();
  const evaluated = evaluateAuthorityDependency(
    enforcement.declaration,
    enforcement.resolver.view(governed.subject),
    {
      clientId: governed.clientId,
      nowMs,
    },
  );
  if (evaluated.ok) return { ok: true, validUntilMs: evaluated.validUntilMs };
  enforcement.evidence?.record({
    enforcer: context.enforcer,
    dependency: enforcement.declaration.id,
    failure: evaluated.failure,
    mission: { id: mission.id, issuer: mission.issuer },
    subject: governed.subject,
    client: governed.clientId,
    action: context.action,
    ...(evaluated.observedAt !== undefined ? { observed_at: evaluated.observedAt } : {}),
    at: new Date(nowMs).toISOString(),
  });
  return { ok: false, failure: evaluated.failure };
}
