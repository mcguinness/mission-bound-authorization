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
 * One trusted-configuration authority-source declaration. The deployment
 * declares WHICH authority an Agent's Missions draw on; the record's `subject`
 * names the specific principal, and gate 4 holds it to the source's
 * discipline.
 */
export interface AuthoritySourceCatalogEntry {
  /** Config-local identifier, used in refusal messages only. */
  id: string;
  type: AuthoritySourceType;
  /** The Agents (OAuth clients) whose Missions draw on this source. */
  clients: readonly string[];
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

/** The identity a record's immutable `authority_source` denotes: the tuple a
 *  drawdown re-resolves its source by. */
function sourceIdentity(source: {
  type: AuthoritySourceType;
  policy?: { id: string; version: string };
}): string {
  return source.policy ? `${source.type}:${source.policy.id}:${source.policy.version}` : source.type;
}

/**
 * @spec mission#authority-sources — the implicit source of a deployment that
 * declares no catalog: a single user-delegated source bounded by the
 * deployment's own derivation ceiling. Still trusted configuration (the AS's
 * own policy, not client input), so the REQUIRED record member is populated
 * everywhere; the discriminator rule and gate 3 both still apply. A deployment
 * that distinguishes workload or organizational authority declares a catalog.
 */
export function implicitAuthoritySourceEntry(
  ceiling: readonly AuthorityEntry[],
): AuthoritySourceCatalogEntry {
  return {
    id: "implicit-user-delegated",
    type: "user_delegated",
    clients: [],
    activators: [],
    ceiling,
  };
}

/**
 * @spec mission#approval-event (step 3) — validate a catalog at load. Two
 * source declarations that share a source IDENTITY would make a drawdown's
 * re-resolution ambiguous, and one client declared twice would make
 * establishment ambiguous; both refuse rather than picking a winner.
 */
export function validateAuthoritySourceCatalog(catalog: AuthoritySourceCatalog): void {
  const identities = new Set<string>();
  const clients = new Set<string>();
  for (const entry of catalog.entries) {
    if (!isAuthoritySourceType(entry.type)) {
      throw new Error(`authority source '${entry.id}': unrecognized type '${String(entry.type)}'`);
    }
    if (entry.type === "organizational" && !entry.policy) {
      throw new Error(`authority source '${entry.id}': organizational requires a policy reference`);
    }
    if (entry.type !== "organizational" && entry.policy) {
      throw new Error(`authority source '${entry.id}': policy is absent outside organizational`);
    }
    if (entry.ceiling.length === 0) {
      throw new Error(`authority source '${entry.id}': ceiling must be non-empty`);
    }
    const identity = sourceIdentity(entry);
    if (identities.has(identity)) {
      throw new Error(`authority source '${entry.id}': duplicate source identity '${identity}'`);
    }
    identities.add(identity);
    for (const client of entry.clients) {
      if (clients.has(client)) {
        throw new Error(`authority source '${entry.id}': client '${client}' is declared twice`);
      }
      clients.add(client);
    }
  }
}

/**
 * GATE 1 — a trusted source resolves for this Agent. Fail closed: a catalog
 * that declares no entry for the presenting client refuses, rather than
 * falling back to a permissive default.
 */
export function resolveSourceForClient(
  catalog: AuthoritySourceCatalog | undefined,
  clientId: string,
  deploymentCeiling: readonly AuthorityEntry[],
): AuthoritySourceCatalogEntry {
  if (!catalog) return implicitAuthoritySourceEntry(deploymentCeiling);
  const entry = catalog.entries.find((e) => e.clients.includes(clientId));
  if (!entry) {
    throw new IntentError(
      "access_denied",
      `no trusted authority source is declared for client '${clientId}'`,
    );
  }
  return entry;
}

/**
 * The DRAWDOWN and funnel-backstop resolution: re-resolve the declaration a
 * record's IMMUTABLE `authority_source` denotes, against catalog state current
 * at the moment authority is drawn. Refuses when the identity no longer
 * resolves; it never rewrites the record's member from a fresh lookup, which
 * would let a drawdown change provenance with no approval event.
 *
 * GATE 5 lives here too: an `organizational` record's committed policy
 * `digest` must equal the digest of the governed policy currently loaded, so
 * drift refuses.
 */
export function resolveDeclaredSource(
  catalog: AuthoritySourceCatalog | undefined,
  source: AuthoritySource,
  deploymentCeiling: readonly AuthorityEntry[],
): AuthoritySourceCatalogEntry {
  if (!catalog) {
    if (source.type !== "user_delegated") {
      throw new IntentError(
        "access_denied",
        `this deployment declares no ${source.type} authority source`,
      );
    }
    return implicitAuthoritySourceEntry(deploymentCeiling);
  }
  const identity = sourceIdentity(source);
  const entry = catalog.entries.find((e) => sourceIdentity(e) === identity);
  if (!entry) {
    throw new IntentError(
      "access_denied",
      `the ${source.type} authority source this Mission draws on is no longer declared`,
    );
  }
  assertPolicyDigestMatches(entry, source);
  return entry;
}

/** The immutable record member an entry establishes: `type`, plus `policy` for
 *  `organizational` (`{id, version, digest}` only, never the ceiling). */
export function authoritySourceOf(entry: AuthoritySourceCatalogEntry): AuthoritySource {
  return {
    type: entry.type,
    ...(entry.type === "organizational" && entry.policy ? { policy: { ...entry.policy } } : {}),
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
      `approver '${approver.sub}' is not authorized to activate the ${entry.type} authority source '${entry.id}'`,
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
      `the derived Authority Set exceeds the authority of the ${entry.type} source '${entry.id}'`,
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
 * matches the governed policy currently loaded. A policy edited after approval
 * therefore cannot pass as the one that was consented to.
 */
export function assertPolicyDigestMatches(
  entry: AuthoritySourceCatalogEntry,
  source: AuthoritySource,
): void {
  if (entry.type !== "organizational") return;
  if (!entry.policy) {
    throw new IntentError(
      "access_denied",
      `the organizational authority source '${entry.id}' resolves no governed policy`,
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
