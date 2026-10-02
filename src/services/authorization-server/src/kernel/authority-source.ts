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
 *
 * Gate 1 resolves for the actual principal (#827): a source is selected by the
 * authenticated client AND the issuer-qualified Subject, through one
 * {@link AuthoritySourceResolver} call per approval completion, so two Subjects
 * sharing one agent registration carry distinct ceilings. Gates 2 to 5 then run
 * on that one resolution. Missing, ambiguous, unavailable or inconsistent
 * resolution refuses; ceilings never union and catalog order is never
 * precedence.
 */

import { createHash } from "node:crypto";
import { canonicalize, entryWithinCeiling, type JsonValue } from "@mission/core";
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
  /**
   * The stable internal root key: unique within the catalog, issuer-local, and
   * never on the wire (no `authority_source` member carries it).
   */
  id: string;
  type: AuthoritySourceType;
  /** The Agents (OAuth clients) whose Missions draw on this source. */
  clients: readonly string[];
  /**
   * @spec mission#authority-sources (#827): the Subjects this source applies
   * to, among those its clients present. Absent, it applies to every Subject of
   * its clients. Two entries sharing a client MUST both declare `subjects`, and
   * those lists MUST be disjoint, so exactly one root resolves for any
   * (client, Subject). Selection only: gate 4 still holds a workload Subject to
   * `principals`, so being selected is never being recognized.
   */
  subjects?: readonly string[];
  /**
   * Approver subjects authorized under local policy to ACTIVATE this source.
   * REQUIRED and non-empty: a source nobody may activate is a configuration
   * error, refused at load, never a source every Approver may activate.
   */
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
 * request. REQUIRED: a deployment that declares no catalog has declared no
 * authority for any Agent to draw on, so the kernel refuses construction
 * rather than standing one up on its behalf.
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
 * @spec mission#authority-sources, mission#approval-event (step 3): the
 * catalog BOUND to the one trusted issuer namespace its subject strings
 * denote. Two principals are equal only when `iss` and `sub` are both
 * byte-equal, so a catalog entry naming `bob` names `bob` in exactly this
 * namespace. The issuer is the kernel's configured issuer, bound at kernel
 * construction ({@link bindAuthoritySourceCatalog}); it is never derived from
 * an incoming Subject or Approver.
 *
 * Every gate that authorizes a supplied principal takes this type, never the
 * unbound {@link AuthoritySourceCatalog}: there is no form of a gate whose
 * missing issuer restores a bare-`sub` comparison. A deployment that accepts
 * identities from another namespace maps them first, through its own
 * separately trusted mapping, to a canonical local principal.
 *
 * The catalog is also bound to one `deployment` (#827): the trusted tenant
 * discriminator, the kernel's issuer, set by assembly. Two Authorization
 * Servers that share an identity provider share a principal namespace but
 * never a catalog. `revision` commits to the catalog content a resolution
 * was made against.
 */
export interface BoundAuthoritySourceCatalog extends AuthoritySourceCatalog {
  readonly principalIssuer: string;
  readonly deployment: string;
  readonly revision: string;
}

/**
 * Bind a catalog to the kernel's configured principal issuer and deployment.
 * Refuses an empty value, and refuses a catalog already bound to a different
 * issuer or deployment rather than rebinding it, so one kernel's catalog never
 * authorizes another kernel's principals or serves another kernel's tenant.
 */
export function bindAuthoritySourceCatalog(
  catalog: AuthoritySourceCatalog,
  principalIssuer: string,
  deployment: string,
): BoundAuthoritySourceCatalog {
  if (typeof principalIssuer !== "string" || principalIssuer.length === 0) {
    throw new Error("authority-source catalog: the trusted principal issuer must be a non-empty string");
  }
  if (typeof deployment !== "string" || deployment.length === 0) {
    throw new Error("authority-source catalog: the trusted deployment must be a non-empty string");
  }
  const prior = catalog as Partial<BoundAuthoritySourceCatalog>;
  if (prior.principalIssuer !== undefined && prior.principalIssuer !== principalIssuer) {
    throw new Error(
      `authority-source catalog is bound to issuer '${prior.principalIssuer}', not this kernel's issuer '${principalIssuer}'`,
    );
  }
  if (prior.deployment !== undefined && prior.deployment !== deployment) {
    throw new Error(
      `authority-source catalog is bound to deployment '${prior.deployment}', not this kernel's deployment '${deployment}'`,
    );
  }
  const content = { entries: catalog.entries, humanPrincipals: catalog.humanPrincipals };
  const bytes = canonicalize(JSON.parse(JSON.stringify(content)) as JsonValue);
  const revision = `sha-256:${createHash("sha256").update(bytes).digest("base64url")}`;
  return Object.freeze({ ...content, principalIssuer, deployment, revision });
}

/** A principal of the catalog's trusted issuer namespace, validated. */
export interface LocalPrincipal {
  readonly iss: string;
  readonly sub: string;
}

/**
 * @spec mission#authority-sources, mission#approval-event (step 3): the
 * canonical-principal guard every source gate runs first: an object with a
 * non-empty string `iss` and `sub`, whose `iss` is byte-equal to the bound
 * namespace. No normalization: distinct issuer strings are distinct
 * namespaces. A foreign or malformed principal refuses `access_denied`; it is
 * never rewritten into the local namespace.
 */
export function assertLocalPrincipal(
  catalog: BoundAuthoritySourceCatalog,
  principal: unknown,
  role: "approver" | "subject",
): LocalPrincipal {
  if (principal === null || typeof principal !== "object" || Array.isArray(principal)) {
    throw new IntentError("access_denied", `the ${role} must be an issuer-qualified principal`);
  }
  const { iss, sub } = principal as Record<string, unknown>;
  if (typeof iss !== "string" || iss.length === 0 || typeof sub !== "string" || sub.length === 0) {
    throw new IntentError("access_denied", `the ${role} must carry a non-empty iss and sub`);
  }
  if (iss !== catalog.principalIssuer) {
    throw new IntentError(
      "access_denied",
      `the ${role} is not a principal of this deployment's issuer namespace`,
    );
  }
  return { iss, sub };
}

/** The provenance identity a record's immutable `authority_source` denotes,
 *  compared member by member (type, policy id, policy version), never as a
 *  delimiter-joined string. */
function sameSourceIdentity(
  a: { type: AuthoritySourceType; policy?: { id: string; version: string } },
  b: { type: AuthoritySourceType; policy?: { id: string; version: string } },
): boolean {
  return a.type === b.type && a.policy?.id === b.policy?.id && a.policy?.version === b.policy?.version;
}

/**
 * @spec mission#approval-event (step 3): validate a catalog at load. Repeated
 * modes and shared clients are admitted across disjoint Subjects (#827); what
 * refuses is anything that would let one (client, Subject) select two roots:
 * a duplicate root id, or two entries sharing a client whose `subjects` are
 * absent or intersect. Each comparison is over the structured tuple, so a
 * client or subject string containing a delimiter cannot collide.
 */
export function validateAuthoritySourceCatalog(catalog: AuthoritySourceCatalog): void {
  const ids = new Set<string>();
  for (const entry of catalog.entries) {
    if (typeof entry.id !== "string" || entry.id.length === 0) {
      throw new Error("authority source: id must be a non-empty string");
    }
    if (ids.has(entry.id)) {
      throw new Error(`authority source '${entry.id}': duplicate root id`);
    }
    ids.add(entry.id);
    if (!isAuthoritySourceType(entry.type)) {
      throw new Error(`authority source '${entry.id}': unrecognized type '${String(entry.type)}'`);
    }
    // @spec mission#approval-event (step 3) — gate 2 has no vacuous form: a
    // source naming no Approver who may activate it is a source nobody may
    // activate, so it is refused at load rather than admitting every Approver.
    if (!Array.isArray(entry.activators) || entry.activators.length === 0) {
      throw new Error(`authority source '${entry.id}': activators must be non-empty`);
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
    // A selector that selects no one is a root nobody can draw on: refused at
    // load, like an empty activators list, never read as "every Subject".
    if (entry.subjects !== undefined && (!Array.isArray(entry.subjects) || entry.subjects.length === 0)) {
      throw new Error(`authority source '${entry.id}': subjects, when present, must be non-empty`);
    }
  }
  const entries = catalog.entries;
  for (let i = 0; i < entries.length; i++) {
    for (let j = i + 1; j < entries.length; j++) {
      const a = entries[i] as AuthoritySourceCatalogEntry;
      const b = entries[j] as AuthoritySourceCatalogEntry;
      const client = a.clients.find((c) => b.clients.includes(c));
      if (client === undefined) continue;
      if (a.subjects === undefined || b.subjects === undefined) {
        throw new Error(
          `authority sources '${a.id}' and '${b.id}' both select client '${client}': entries sharing a client must each declare disjoint subjects`,
        );
      }
      const subject = a.subjects.find((s) => b.subjects?.includes(s));
      if (subject !== undefined) {
        throw new Error(
          `authority sources '${a.id}' and '${b.id}' both select subject '${subject}' of client '${client}'`,
        );
      }
    }
  }
}

/** The entries that select a (client, Subject): at most one in a valid catalog. */
function selectingEntries(
  catalog: AuthoritySourceCatalog,
  clientId: string,
  sub: string,
): AuthoritySourceCatalogEntry[] {
  return catalog.entries.filter(
    (e) => e.clients.includes(clientId) && (e.subjects === undefined || e.subjects.includes(sub)),
  );
}

/**
 * The provenance an approval RENDERING shows when the Subject is not yet known
 * (the Approver has not authenticated and no `login_hint` names one). Defined
 * only where every source the client could resolve shares one provenance, so
 * the rendering is true for whichever Subject the decision binds; otherwise it
 * refuses. The decision itself always resolves for the actual Subject.
 */
export function renderableSourceForClient(
  catalog: AuthoritySourceCatalog,
  clientId: string,
): AuthoritySource {
  const candidates = catalog.entries.filter((e) => e.clients.includes(clientId));
  const first = candidates[0];
  if (!first) {
    throw new IntentError(
      "access_denied",
      `no trusted authority source is declared for client '${clientId}'`,
    );
  }
  const provenance = authoritySourceOf(first);
  const bytes = canonicalize(provenance as unknown as JsonValue);
  if (candidates.some((e) => canonicalize(authoritySourceOf(e) as unknown as JsonValue) !== bytes)) {
    throw new IntentError(
      "access_denied",
      `the authority source for client '${clientId}' depends on the Subject, which this rendering does not identify`,
    );
  }
  return provenance;
}

/**
 * @spec mission#authority-sources, mission#approval-event (step 3), #827: the
 * ONE source an approval completion draws on. `rootId` is the stable internal
 * root key; `provenance` is the immutable wire `authority_source`; `principal`
 * is the issuer-qualified Subject whose authority is activated; `entry` is the
 * declaration gates 2 to 5 run on (ceiling, activators, principals, policy);
 * `catalogRevision` is the catalog content it was resolved against.
 */
export interface AuthoritySourceResolution {
  readonly rootId: string;
  readonly deployment: string;
  readonly provenance: AuthoritySource;
  readonly principal: LocalPrincipal;
  readonly clientId: string;
  readonly entry: AuthoritySourceCatalogEntry;
  readonly catalogRevision: string;
}

/**
 * The private, issuer-local record of the root a Mission committed: its root
 * id, deployment, root context (Subject and client) and provenance. Never on
 * the wire and outside every anchor.
 */
export interface AuthoritySourceBinding {
  readonly rootId: string;
  readonly deployment: string;
  readonly principal: LocalPrincipal;
  readonly clientId: string;
  readonly provenance: AuthoritySource;
}

/**
 * A proposed mode or governed policy. It can only CONFIRM the root that
 * resolves for the Subject and client, or refuse; it never selects a root.
 */
export interface AuthoritySourceRequest {
  readonly type: AuthoritySourceType;
  readonly policy?: { readonly id: string; readonly version: string };
}

/**
 * @spec mission#authority-sources (#827): the trusted resolver that replaces a
 * catalog lookup. Synchronous by contract: resolution runs inside the approval
 * completion, which commits in one synchronous store transaction, so a remote
 * resolver needs a snapshot it can answer from and revalidation at commit,
 * never network I/O inside the transaction.
 *
 * - `resolveForApproval`: the root for an approval completion. `deployment`
 *   comes from assembly, `subject` is already held to the bound namespace, and
 *   `clientId` is authenticated.
 * - `resolveCommittedRoot`: the CURRENT declaration of a root a Mission
 *   already committed. It never rebinds: a missing root, a changed provenance
 *   or policy, or a root that no longer selects its own Subject and client
 *   refuses.
 */
export interface AuthoritySourceResolver {
  resolveForApproval(input: {
    deployment: string;
    subject: LocalPrincipal;
    clientId: string;
    sourceRequest?: AuthoritySourceRequest;
  }): AuthoritySourceResolution;
  resolveCommittedRoot(input: {
    deployment: string;
    binding: AuthoritySourceBinding;
  }): AuthoritySourceResolution;
}

/** The resolver over the deployment's trusted JSON catalog. */
export function catalogAuthoritySourceResolver(
  catalog: BoundAuthoritySourceCatalog,
): AuthoritySourceResolver {
  const resolution = (
    entry: AuthoritySourceCatalogEntry,
    principal: LocalPrincipal,
    clientId: string,
  ): AuthoritySourceResolution =>
    Object.freeze({
      rootId: entry.id,
      deployment: catalog.deployment,
      provenance: authoritySourceOf(entry),
      principal,
      clientId,
      entry,
      catalogRevision: catalog.revision,
    });
  const assertDeployment = (deployment: string): void => {
    if (deployment !== catalog.deployment) {
      throw new IntentError("access_denied", "the authority-source catalog serves another deployment");
    }
  };
  return {
    resolveForApproval({ deployment, subject, clientId, sourceRequest }) {
      assertDeployment(deployment);
      const local = assertLocalPrincipal(catalog, subject, "subject");
      if (!catalog.entries.some((e) => e.clients.includes(clientId))) {
        throw new IntentError(
          "access_denied",
          `no trusted authority source is declared for client '${clientId}'`,
        );
      }
      const candidates = selectingEntries(catalog, clientId, local.sub);
      const entry = candidates[0];
      if (!entry) {
        throw new IntentError(
          "access_denied",
          `no trusted authority source is declared for '${local.sub}' through client '${clientId}'`,
        );
      }
      if (candidates.length > 1) {
        throw new IntentError(
          "access_denied",
          `the authority source for '${local.sub}' through client '${clientId}' is ambiguous`,
        );
      }
      if (sourceRequest && !sameSourceIdentity(sourceRequest, entry)) {
        throw new IntentError(
          "access_denied",
          `the requested ${sourceRequest.type} authority source is not the one declared for '${local.sub}'`,
        );
      }
      return resolution(entry, local, clientId);
    },
    resolveCommittedRoot({ deployment, binding }) {
      assertDeployment(deployment);
      if (binding.deployment !== catalog.deployment) {
        throw new IntentError("access_denied", "the committed authority source belongs to another deployment");
      }
      const local = assertLocalPrincipal(catalog, binding.principal, "subject");
      const entry = catalog.entries.find((e) => e.id === binding.rootId);
      if (!entry) {
        throw new IntentError(
          "access_denied",
          `the ${binding.provenance.type} authority source this Mission committed is no longer declared`,
        );
      }
      if (!sameSourceIdentity(entry, binding.provenance)) {
        throw new IntentError(
          "access_denied",
          `the authority source this Mission committed has changed provenance`,
        );
      }
      assertPolicyDigestMatches(entry, binding.provenance);
      if (!selectingEntries(catalog, binding.clientId, local.sub).includes(entry)) {
        throw new IntentError(
          "access_denied",
          `the committed authority source no longer applies to '${local.sub}' through client '${binding.clientId}'`,
        );
      }
      return resolution(entry, local, binding.clientId);
    },
  };
}

/**
 * GATE 1 at an approval completion, behind any resolver: hold the Subject to
 * the bound namespace FIRST (#829), call the resolver once, and accept its
 * answer only when it is consistent with what was asked. A resolver that
 * throws anything other than a refusal is unavailable, and an unavailable or
 * inconsistent resolver refuses `access_denied`: the AS refuses when the
 * source relationship cannot be established.
 */
export function resolveApprovalSource(
  catalog: BoundAuthoritySourceCatalog,
  resolver: AuthoritySourceResolver,
  input: { deployment: string; subject: unknown; clientId: string },
): AuthoritySourceResolution {
  const local = assertLocalPrincipal(catalog, input.subject, "subject");
  let r: AuthoritySourceResolution;
  try {
    r = resolver.resolveForApproval({ deployment: input.deployment, subject: local, clientId: input.clientId });
  } catch (e) {
    if (e instanceof IntentError) throw e;
    throw new IntentError("access_denied", "the authority-source resolver is unavailable");
  }
  const consistent =
    r !== null &&
    typeof r === "object" &&
    typeof r.rootId === "string" &&
    r.rootId === r.entry?.id &&
    r.deployment === input.deployment &&
    r.clientId === input.clientId &&
    r.principal?.iss === local.iss &&
    r.principal?.sub === local.sub &&
    typeof r.catalogRevision === "string" &&
    r.catalogRevision.length > 0 &&
    r.entry.clients.includes(input.clientId) &&
    (r.entry.subjects === undefined || r.entry.subjects.includes(local.sub)) &&
    canonicalize(r.provenance as unknown as JsonValue) ===
      canonicalize(authoritySourceOf(r.entry) as unknown as JsonValue);
  if (!consistent) {
    throw new IntentError(
      "access_denied",
      "the authority-source resolver answered for a different Subject, client, deployment or source",
    );
  }
  return r;
}

/**
 * The funnel backstop for a FRESH approval: the record carries exactly the
 * provenance its one resolution established, byte for byte.
 */
export function assertRecordedSourceResolved(
  recorded: AuthoritySource,
  resolved: AuthoritySourceResolution,
): void {
  if (
    canonicalize(recorded as unknown as JsonValue) !==
    canonicalize(resolved.provenance as unknown as JsonValue)
  ) {
    throw new IntentError(
      "access_denied",
      "the record's authority_source is not the source its approval resolved",
    );
  }
}

/**
 * The DRAWDOWN and funnel-backstop resolution: re-resolve the declaration a
 * record's IMMUTABLE `authority_source` denotes, against catalog state current
 * at the moment authority is drawn. Refuses when the identity no longer
 * resolves; it never rewrites the record's member from a fresh lookup, which
 * would let a drawdown change provenance with no approval event.
 *
 * Refuses, too, when the identity denotes MORE than one root (#827: repeated
 * modes across disjoint Subjects): provenance alone cannot say which root a
 * Mission committed, and the first match is never the answer. An inherited
 * source in such a catalog draws on its committed root instead.
 *
 * GATE 5 lives here too: an `organizational` record's committed policy
 * `digest` must equal the digest of the governed policy currently loaded, so
 * drift refuses.
 */
export function resolveDeclaredSource(
  catalog: AuthoritySourceCatalog,
  source: AuthoritySource,
): AuthoritySourceCatalogEntry {
  const matches = catalog.entries.filter((e) => sameSourceIdentity(e, source));
  const entry = matches[0];
  if (!entry) {
    throw new IntentError(
      "access_denied",
      `the ${source.type} authority source this Mission draws on is no longer declared`,
    );
  }
  if (matches.length > 1) {
    throw new IntentError(
      "access_denied",
      `the ${source.type} authority source this Mission draws on denotes more than one root, so it cannot be re-resolved from provenance alone`,
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
 * The `activators` list is EXHAUSTIVE and never empty: an empty list is
 * refused at catalog load, so this check has no vacuous form and every source
 * names the Approvers who may activate it. The Approver is first held to the
 * catalog's issuer namespace ({@link assertLocalPrincipal}): an activator
 * entry names a principal of that namespace, never a bare `sub` any issuer
 * may claim.
 */
export function assertApproverMayActivate(
  catalog: BoundAuthoritySourceCatalog,
  entry: AuthoritySourceCatalogEntry,
  approver: { iss: string; sub: string },
): void {
  const local = assertLocalPrincipal(catalog, approver, "approver");
  if (!entry.activators.includes(local.sub)) {
    throw new IntentError(
      "access_denied",
      `approver '${local.sub}' is not authorized to activate the ${entry.type} authority source '${entry.id}'`,
    );
  }
}

/**
 * GATE 3 — the derived Authority Set lies wholly within the source's own
 * authority (for `organizational`, within the governed policy the entry
 * resolves). An assertion that REFUSES; it is never an input to derivation.
 * @spec mission#approval-event (step 3) — the shared primitive compares
 * authority, not approval-time provenance, against binding-free configuration.
 */
export function assertWithinSourceCeiling(
  entry: AuthoritySourceCatalogEntry,
  authoritySet: readonly AuthorityEntry[],
): void {
  if (!authoritySet.every(candidate => entryWithinCeiling(candidate, entry.ceiling as AuthorityEntry[]))) {
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
 * person, so the discipline is vacuous there; the namespace check is not, and
 * runs first for every source, so a foreign delegating person is refused too.
 */
export function assertSubjectDiscipline(
  catalog: BoundAuthoritySourceCatalog,
  entry: AuthoritySourceCatalogEntry,
  subject: { iss: string; sub: string },
): void {
  const local = assertLocalPrincipal(catalog, subject, "subject");
  if (entry.type === "user_delegated") return;
  if (catalog.humanPrincipals.includes(local.sub)) {
    throw new IntentError(
      "access_denied",
      `a ${entry.type} Mission MUST NOT record the human principal '${local.sub}' as its subject`,
    );
  }
  if (!entry.principals?.includes(local.sub)) {
    throw new IntentError(
      "access_denied",
      `'${local.sub}' is not a principal this deployment recognizes as a resource owner in its own right`,
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
