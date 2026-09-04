/**
 * @spec mission#authority-sources, mission#approval-event, mission#mission-record
 *
 * The Mission's authority source: whose authority the approval draws on, one
 * of `user_delegated`, `service_owned`, or `organizational`. The record member
 * is REQUIRED and immutable, established at the approval event from TRUSTED
 * CONFIGURATION (the catalog this module resolves), never from `ApproveInput`,
 * a submission envelope, or any other client assertion.
 *
 * Approval activates authority the source already holds and manufactures none,
 * so establishment is five SEPARATE gates, each refusing `access_denied`
 * before the integrity anchors are computed and before the record is created:
 *
 * 1. a trusted source resolves for the Agent presenting the request;
 * 2. the Approver may ACTIVATE that source (`activators`);
 * 3. the derived Authority Set lies wholly WITHIN the source ceiling;
 * 4. the subject discipline holds for `service_owned` / `organizational`;
 * 5. an `organizational` policy reference resolves and its digest matches.
 *
 * Gates 2 and 3 stay separate functions on purpose: an organizational owner
 * may be authorized to activate policy without personally holding every
 * operational permission, so activation authority is never read as possession.
 * Gate 3 is an ASSERTION that refuses, never a derivation input: the source
 * ceiling MUST NOT be intersected into `deriveAuthoritySet`, which would
 * silently narrow where the core says the AS "MUST refuse when either
 * relationship cannot be established".
 */

import { isSubsetSet } from "./derive.js";
import { IntentError } from "./intent.js";
import type { AuthorityEntry, AuthoritySource, AuthoritySourceType } from "./types.js";

/** @spec mission#mission-record — the closed `authority_source.type` enum. */
export const AUTHORITY_SOURCE_TYPES: readonly AuthoritySourceType[] = [
  "user_delegated",
  "service_owned",
  "organizational",
];

/**
 * @spec mission#mission-record, mission#lifecycle — the enum is "subject to the
 * forward-compatibility rule of {{lifecycle}}", which admits no fail-open: an
 * unrecognized `type` is refused wherever it appears, at config load and at
 * record hydration alike, rather than widened into the union.
 */
export function isAuthoritySourceType(value: unknown): value is AuthoritySourceType {
  return typeof value === "string" && (AUTHORITY_SOURCE_TYPES as readonly string[]).includes(value);
}

/**
 * One trusted-configuration authority-source declaration, keyed on the Agent
 * (OAuth client) whose Missions draw on it. The deployment declares WHICH
 * authority an agent's Missions draw on; the record's `subject` names the
 * specific principal, and gate 4 holds it to the source's discipline.
 */
export interface AuthoritySourceCatalogEntry {
  /** The Agent (OAuth client) this source is declared for. */
  client_id: string;
  type: AuthoritySourceType;
  /** Approver subjects authorized under local policy to ACTIVATE this source. */
  activators: readonly string[];
  /**
   * The source's own authority: the ceiling the derived Authority Set MUST lie
   * within (gate 3). For `organizational` this is the governed policy's own
   * ceiling, resolved from the governed-policy registry at load.
   */
  ceiling: readonly AuthorityEntry[];
  /**
   * @spec mission#authority-sources — for `service_owned` / `organizational`,
   * the workload or organizational principals this deployment recognizes as
   * resource owners in their own right. A Subject outside this list is refused
   * even when it is not a human principal.
   */
  principals?: readonly string[];
  /**
   * @spec mission#mission-record — REQUIRED for `organizational`, absent
   * otherwise: the stable reference to, and commitment over, the governed
   * organizational policy. The `digest` is computed at load from the governed
   * policy document, never supplied on the wire.
   */
  policy?: { id: string; version: string; digest: string };
}

/**
 * The deployment's authority-source catalog: trusted configuration, injected
 * into the kernel (and the template admin plane), never assembled from a
 * request.
 */
export interface AuthoritySourceCatalog {
  entries: readonly AuthoritySourceCatalogEntry[];
  /**
   * @spec mission#authority-sources — the subjects this deployment declares
   * HUMAN principals. A `service_owned` or `organizational` Mission MUST NOT
   * record one of these as its `subject`.
   */
  humanPrincipals: readonly string[];
}

/**
 * @spec mission#authority-sources — the implicit source of a deployment that
 * declares no catalog: a single user-delegated source bounded by the
 * deployment's own derivation ceiling. Still trusted configuration (the AS's
 * own policy, not client input), so the REQUIRED record member is populated
 * everywhere; the discriminator rule and gate 3 both still apply. A deployment
 * that distinguishes workload or organizational authority declares a catalog.
 */
export function defaultAuthoritySourceEntry(
  clientId: string,
  ceiling: readonly AuthorityEntry[],
): AuthoritySourceCatalogEntry {
  return { client_id: clientId, type: "user_delegated", activators: [], ceiling };
}

/**
 * GATE 1 — a trusted source resolves for this Agent. Fail closed: a catalog
 * that declares no entry for the presenting client refuses, rather than
 * falling back to a permissive default.
 */
export function resolveAuthoritySourceEntry(
  catalog: AuthoritySourceCatalog | undefined,
  clientId: string,
  deploymentCeiling: readonly AuthorityEntry[],
): AuthoritySourceCatalogEntry {
  if (!catalog) return defaultAuthoritySourceEntry(clientId, deploymentCeiling);
  const entry = catalog.entries.find((e) => e.client_id === clientId);
  if (!entry) {
    throw new IntentError(
      "access_denied",
      `no trusted authority source is declared for client '${clientId}'`,
    );
  }
  return entry;
}

/** The immutable record member an entry establishes: `type`, plus `policy` for
 *  `organizational` (`{id, version, digest}` only, never the ceiling). */
export function authoritySourceOf(entry: AuthoritySourceCatalogEntry): AuthoritySource {
  return {
    type: entry.type,
    ...(entry.type === "organizational" && entry.policy
      ? { policy: { ...entry.policy } }
      : {}),
  };
}

/**
 * GATE 2 — the Approver is authorized under local policy to ACTIVATE the
 * established source. Distinct from gate 3 by construction: this function
 * never reads the Authority Set, so an activator holding none of the
 * ceiling's operational permissions still activates.
 *
 * An entry with an EMPTY `activators` list places no activation restriction
 * (the implicit user-delegated source of an uncatalogued deployment); a
 * non-empty list is exhaustive.
 */
export function assertApproverMayActivate(
  entry: AuthoritySourceCatalogEntry,
  approver: { iss: string; sub: string },
): void {
  if (entry.activators.length === 0) return;
  if (!entry.activators.includes(approver.sub)) {
    throw new IntentError(
      "access_denied",
      `approver '${approver.sub}' is not authorized to activate the ${entry.type} authority source`,
    );
  }
}

/**
 * GATE 3 — the derived Authority Set lies wholly within the source's own
 * authority (for `organizational`, within the governed policy the entry
 * resolves). An assertion that REFUSES; it is never an input to derivation.
 */
export function assertWithinSourceCeiling(
  entry: AuthoritySourceCatalogEntry,
  authoritySet: readonly AuthorityEntry[],
): void {
  if (!isSubsetSet(authoritySet as AuthorityEntry[], entry.ceiling as AuthorityEntry[])) {
    throw new IntentError(
      "access_denied",
      `the derived Authority Set exceeds the ${entry.type} authority source's own authority`,
    );
  }
}

/**
 * GATE 4 — subject discipline. A `service_owned` or `organizational` Mission
 * MUST record the workload or organizational principal as `subject` and MUST
 * NOT record a human principal in its place, and that principal MUST be an
 * authorization subject the AS recognizes as a resource owner in its own
 * right. `user_delegated` is the only source whose `sub` carries a delegating
 * person, so the gate is vacuous there.
 */
export function assertSubjectDiscipline(
  catalog: AuthoritySourceCatalog | undefined,
  entry: AuthoritySourceCatalogEntry,
  subject: { iss: string; sub: string },
): void {
  if (entry.type === "user_delegated") return;
  if (catalog?.humanPrincipals.includes(subject.sub)) {
    throw new IntentError(
      "access_denied",
      `a ${entry.type} Mission MUST NOT record the human principal '${subject.sub}' as its subject`,
    );
  }
  if (!entry.principals?.includes(subject.sub)) {
    throw new IntentError(
      "access_denied",
      `'${subject.sub}' is not a principal this deployment recognizes as a resource owner in its own right`,
    );
  }
}

/**
 * GATE 5 — the `organizational` policy reference resolves and its digest
 * matches the governed policy currently loaded. Drift between the record's
 * committed digest and the live governed policy refuses, so a policy edited
 * after approval cannot pass as the one that was consented to.
 */
export function assertPolicyReference(
  entry: AuthoritySourceCatalogEntry,
  source: AuthoritySource,
): void {
  if (entry.type !== "organizational") {
    if (source.policy) {
      throw new IntentError(
        "access_denied",
        `a ${entry.type} authority source carries no governed policy reference`,
      );
    }
    return;
  }
  if (!entry.policy) {
    throw new IntentError(
      "access_denied",
      "the organizational authority source resolves no governed policy",
    );
  }
  const ref = source.policy;
  if (!ref) {
    throw new IntentError(
      "access_denied",
      "an organizational Mission requires a governed policy reference",
    );
  }
  if (
    ref.id !== entry.policy.id ||
    ref.version !== entry.policy.version ||
    ref.digest !== entry.policy.digest
  ) {
    throw new IntentError(
      "access_denied",
      `the governed policy '${ref.id}' has drifted from the reference the Mission committed`,
    );
  }
}

/**
 * The drawdown path (template dispatch, child creation): the successor's
 * source IDENTITY is INHERITED verbatim from the retained predecessor, and
 * only the ceiling assertion re-runs against catalog state current at the
 * moment authority is actually drawn. A catalog whose entry no longer agrees
 * with the inherited `type` refuses rather than rewriting provenance: the
 * record member is immutable, so a drawdown can never change whose authority
 * the Mission draws on.
 */
export function assertInheritedSourceStillHolds(
  entry: AuthoritySourceCatalogEntry,
  inherited: AuthoritySource,
): void {
  if (entry.type !== inherited.type) {
    throw new IntentError(
      "access_denied",
      `the ${inherited.type} authority source this Mission draws down is no longer declared for its Agent`,
    );
  }
  assertPolicyReference(entry, inherited);
}

/**
 * @spec mission#mission-record, mission#lifecycle — parse a persisted
 * `authority_source`, refusing rather than widening. `JSON.parse` on a stored
 * row otherwise admits any string into the union, so hydration is the second
 * fail-closed point (the typed config loader is the first).
 */
export function parseAuthoritySource(raw: unknown, context: string): AuthoritySource {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(`${context}: authority_source must be an object`);
  }
  const obj = raw as Record<string, unknown>;
  if (!isAuthoritySourceType(obj.type)) {
    throw new Error(`${context}: unrecognized authority_source.type '${String(obj.type)}'`);
  }
  const type = obj.type;
  if (type === "organizational") {
    const policy = obj.policy;
    if (policy === null || typeof policy !== "object" || Array.isArray(policy)) {
      throw new Error(`${context}: authority_source.policy is required for organizational`);
    }
    const p = policy as Record<string, unknown>;
    if (typeof p.id !== "string" || typeof p.version !== "string" || typeof p.digest !== "string") {
      throw new Error(`${context}: authority_source.policy needs id, version, and digest`);
    }
    return { type, policy: { id: p.id, version: p.version, digest: p.digest } };
  }
  if (obj.policy !== undefined) {
    throw new Error(`${context}: authority_source.policy is absent outside organizational`);
  }
  return { type };
}
