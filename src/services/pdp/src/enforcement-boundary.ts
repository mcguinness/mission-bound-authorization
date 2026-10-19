/**
 * @spec runtime#boundary-identifier, runtime#boundary-identifier-change,
 * runtime-oauth#boundary-audience, runtime-evidence#decision-evidence-integrity
 * (#853, D487): the enforcement-boundary identity, and the one place every
 * consumer reads it.
 *
 * Each `mediated` resource entry of the Enforcement Scope Statement is an
 * enforcement boundary, and its resource string is that boundary's one
 * identifier; in the OAuth realization it is the guarded protected
 * resource's exact RFC 9728 `resource` string. A PEP establishes the
 * boundary for a request from this trusted configuration (its own PEP
 * location under the version in force), independently of the credential's
 * `aud` values, their order, and the Authority Set entries. Decision inputs,
 * permit and cache binding, Decision Evidence, Execution Evidence,
 * pre-decision Refusal Records and evidence-key authorization all use the
 * value established here.
 *
 * `aud` is validated against the established boundary, never used to select
 * it: a member names the boundary directly, or through an audience alias the
 * configuration scopes to the validated issuer and token profile. Array
 * order, duplicate aliases and other recipients cannot move the binding.
 *
 * `enforcement_boundaries` is this reference's representation of the
 * statement's versions, which the specification defines in prose: each
 * version's boundary identifiers (each a `mediated_scope.resources` entry),
 * the audience aliases for each, the evidence signing keys authorized for
 * each, and the effective cutover. Earlier versions are retained so evidence
 * produced under them still verifies. It is a reference-statement
 * representation, not a Runtime wire member, and adds no record member,
 * credential claim or credential type.
 */

import { type IdempotencyScope, idempotencyScopeDigest } from "@mission/core";
import type { EvidenceKeyLike, EvidenceKeyResolver } from "./runtime-evidence-integrity.js";

/** The emitter roles whose records carry an `audience` and whose keys are boundary-bound. */
export type BoundaryEvidenceRole = "pdp" | "pep" | "executor";
const BOUNDARY_EVIDENCE_ROLES: readonly string[] = ["pdp", "pep", "executor"];

/**
 * One trusted audience alias: an `aud` value that names a boundary, accepted
 * only from `issuer` (the validated token issuer) for `token_profile` (the
 * credential's JOSE `typ` media type, for example `at+jwt`). Never supplied by
 * a request or a token.
 */
export interface AudienceAliasDeclaration {
  issuer: string;
  token_profile: string;
  alias: string;
}

/** One evidence signing key, by `kid`, that `emitter` in `role` may sign records for a boundary with. */
export interface BoundaryEvidenceKeyAuthorization {
  kid: string;
  emitter: string;
  role: BoundaryEvidenceRole;
}

export interface EnforcementBoundaryDeclaration {
  /** The boundary identifier, compared character for character. */
  boundary: string;
  /** The PEP locations whose routing serves this boundary; each names exactly one boundary per version. */
  pep_locations: readonly string[];
  audience_aliases?: readonly AudienceAliasDeclaration[];
  evidence_keys: readonly BoundaryEvidenceKeyAuthorization[];
}

/** The declared mapping across a change: `boundary` in this version replaces `previous_boundary` of `previous_version`. */
export interface BoundaryReplacement {
  boundary: string;
  previous_version: string;
  previous_boundary: string;
}

export interface BoundaryStatementVersion {
  version: string;
  /** RFC 3339; the cutover instant, at which every producer switches to this version. */
  effective_at: string;
  boundaries: readonly EnforcementBoundaryDeclaration[];
  replaces?: readonly BoundaryReplacement[];
}

/** Every version in effective order. The last is the published target state; earlier ones are retained. */
export interface EnforcementBoundaries {
  versions: readonly BoundaryStatementVersion[];
}

export interface BoundaryFinding {
  member: string;
  problem: string;
}

/** A boundary declaration the reference refuses to load. */
export class BoundaryConfigError extends Error {
  constructor(readonly findings: readonly BoundaryFinding[]) {
    super(`invalid enforcement boundary declaration: ${JSON.stringify(findings)}`);
    this.name = "ConfigError";
  }
}

const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const nonEmpty = (v: unknown): v is string => typeof v === "string" && v.length > 0;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const instant = (v: unknown): number | undefined =>
  typeof v === "string" && RFC3339.test(v) && Number.isFinite(Date.parse(v)) ? Date.parse(v) : undefined;

/** The enforcement boundaries of a statement: its `mediated` `mediated_scope.resources` entries. */
function mediatedResources(stmt: Record<string, unknown>): Set<string> {
  const scope = object(stmt.mediated_scope) ? stmt.mediated_scope : {};
  const out = new Set<string>();
  for (const entry of Array.isArray(scope.resources) ? scope.resources : []) {
    if (typeof entry === "string") out.add(entry);
    else if (object(entry) && entry.disposition === "mediated" && nonEmpty(entry.resource)) out.add(entry.resource);
  }
  return out;
}

/**
 * Validate a statement's `enforcement_boundaries` declaration. Absent is no
 * finding here (a statement may declare none); a PEP establishes no boundary
 * from it. Present, every member must resolve:
 *
 * - versions are uniquely named, with strictly increasing RFC 3339 cutovers;
 * - each version declares each boundary once, each PEP location under at most
 *   one boundary, and at least one authorized evidence key per boundary;
 * - the last version's boundaries are `mediated` resources and its PEP
 *   locations are declared PEP locations of the statement;
 * - a PEP location whose boundary differs from the previous version's carries
 *   the `replaces` record naming that previous boundary, and every `replaces`
 *   record names a boundary of an earlier version.
 *
 * An alias that names more than one boundary is not a load finding: it
 * refuses every token of its issuer and token profile
 * ({@link EnforcementBoundaryContext.validateAudience}).
 */
export function enforcementBoundaryFindings(statement: unknown): BoundaryFinding[] {
  const stmt = object(statement) ? statement : {};
  const declared = stmt.enforcement_boundaries;
  if (declared === undefined) return [];
  const findings: BoundaryFinding[] = [];
  const push = (member: string, problem: string) => findings.push({ member, problem });
  if (!object(declared) || !Array.isArray(declared.versions) || declared.versions.length === 0) {
    push("enforcement_boundaries", "must be an object with a non-empty versions array");
    return findings;
  }
  const versions = declared.versions as unknown[];
  const seenVersions = new Map<string, number>();
  let lastInstant = Number.NEGATIVE_INFINITY;
  versions.forEach((raw, vi) => {
    const member = `enforcement_boundaries.versions[${vi}]`;
    if (!object(raw)) {
      push(member, "version must be an object");
      return;
    }
    if (!nonEmpty(raw.version)) push(member, "missing the version name");
    else if (seenVersions.has(raw.version)) push(member, `version "${raw.version}" is declared twice`);
    else seenVersions.set(raw.version, vi);
    const at = instant(raw.effective_at);
    if (at === undefined) push(member, "effective_at must be an RFC 3339 date-time");
    else if (at <= lastInstant) push(member, "effective_at must be later than the previous version's");
    else lastInstant = at;
    if (!Array.isArray(raw.boundaries) || raw.boundaries.length === 0) {
      push(member, "must declare at least one boundary");
      return;
    }
    const ids = new Set<string>();
    const pepOwner = new Map<string, string>();
    raw.boundaries.forEach((b, bi) => {
      const bm = `${member}.boundaries[${bi}]`;
      if (!object(b) || !nonEmpty(b.boundary)) {
        push(bm, "boundary requires a non-empty identifier");
        return;
      }
      if (ids.has(b.boundary)) push(bm, `boundary "${b.boundary}" is declared twice`);
      ids.add(b.boundary);
      if (!Array.isArray(b.pep_locations) || b.pep_locations.length === 0 || !b.pep_locations.every(nonEmpty)) {
        push(bm, "pep_locations must be a non-empty list of PEP locations");
      } else {
        for (const pep of b.pep_locations as string[]) {
          const owner = pepOwner.get(pep);
          if (owner !== undefined && owner !== b.boundary) push(bm, `PEP location "${pep}" names two boundaries`);
          pepOwner.set(pep, b.boundary);
        }
      }
      if (
        b.audience_aliases !== undefined &&
        (!Array.isArray(b.audience_aliases) ||
          !b.audience_aliases.every((a) => object(a) && nonEmpty(a.issuer) && nonEmpty(a.token_profile) && nonEmpty(a.alias)))
      ) {
        push(bm, "audience_aliases must be a list of {issuer, token_profile, alias}, each non-empty");
      }
      const keys = b.evidence_keys;
      if (
        !Array.isArray(keys) ||
        keys.length === 0 ||
        !keys.every((k) => object(k) && nonEmpty(k.kid) && nonEmpty(k.emitter) && BOUNDARY_EVIDENCE_ROLES.includes(k.role as string))
      ) {
        push(bm, "evidence_keys must name at least one {kid, emitter, role} with role pdp, pep or executor");
      }
    });
  });
  if (findings.length) return findings;

  const typed = versions as BoundaryStatementVersion[];
  typed.forEach((v, vi) => {
    const member = `enforcement_boundaries.versions[${vi}]`;
    const replaces = v.replaces ?? [];
    if (!Array.isArray(replaces)) {
      push(member, "replaces must be an array");
      return;
    }
    for (const r of replaces) {
      const prior = object(r) && nonEmpty(r.previous_version) ? seenVersions.get(r.previous_version) : undefined;
      if (
        !object(r) ||
        !nonEmpty(r.boundary) ||
        !v.boundaries.some((b) => b.boundary === r.boundary) ||
        prior === undefined ||
        prior >= vi ||
        !typed[prior]?.boundaries.some((b) => b.boundary === r.previous_boundary)
      ) {
        push(member, "a replaces record must name a boundary of this version and a boundary of an earlier version");
      }
    }
    if (vi === 0) return;
    const previous = typed[vi - 1] as BoundaryStatementVersion;
    for (const b of v.boundaries) {
      for (const pep of b.pep_locations) {
        const before = previous.boundaries.find((p) => p.pep_locations.includes(pep))?.boundary;
        if (before === undefined || before === b.boundary) continue;
        const recorded = replaces.some(
          (r) => r.boundary === b.boundary && r.previous_version === previous.version && r.previous_boundary === before,
        );
        if (!recorded) {
          push(member, `PEP location "${pep}" moves from "${before}" to "${b.boundary}" with no replaces record`);
        }
      }
    }
  });

  const current = typed[typed.length - 1] as BoundaryStatementVersion;
  const mediated = mediatedResources(stmt);
  const scope = object(stmt.mediated_scope) ? stmt.mediated_scope : {};
  const peps = Array.isArray(scope.pep_locations) ? (scope.pep_locations as unknown[]) : [];
  for (const b of current.boundaries) {
    if (!mediated.has(b.boundary)) {
      push("enforcement_boundaries", `boundary "${b.boundary}" is not a mediated mediated_scope.resources entry`);
    }
    for (const pep of b.pep_locations) {
      if (!peps.includes(pep)) push("enforcement_boundaries", `PEP location "${pep}" is not a declared mediated_scope.pep_locations entry`);
    }
  }
  return findings;
}

/**
 * Why a boundary could not be established; no `audience` is supplied for any
 * of these. `consumer_unprovisioned`: the version in force declares the
 * boundary, but a bound consumer is not yet provisioned for it
 * ({@link BoundaryConsumer}), so no producer uses it.
 */
export type BoundaryUnresolved = "no_version_in_force" | "undeclared_pep_location" | "consumer_unprovisioned";

export type BoundaryEstablishment =
  | { ok: true; boundary: string; version: string }
  | { ok: false; reason: BoundaryUnresolved };

/** Why a credential's `aud` does not validate for the request's boundary. */
export type AudienceRefusal =
  | "audience_absent"
  | "audience_malformed"
  | "audience_mismatch"
  | "alias_ambiguous"
  | BoundaryUnresolved;

export type AudienceValidation = { ok: true; boundary: string; version: string } | { ok: false; reason: AudienceRefusal };

/** The trusted context an `aud` value is validated in: the verified issuer and the credential's `typ` media type. */
export interface AudienceContext {
  issuer: string;
  tokenProfile: string;
}

/** One signing key, as a producer or verifier presents it for authorization. */
export interface EvidenceKeyUse {
  audience: string;
  kid: string;
  emitter: string;
  role: BoundaryEvidenceRole;
}

/** Which versions an evidence-key authorization is read from: the one in force, or any in force so far. */
export type EvidenceAuthorizationScope = "current" | "historical";

/**
 * The declared version in force at `atMs`: the last whose cutover has been
 * reached, or `undefined` before the first (or with no declaration). Every
 * reader of one declaration, a PEP's boundary context and the PDP's claim
 * domain included, selects the version this way.
 */
export function versionInForceAt(declaration: EnforcementBoundaries | undefined, atMs: number): BoundaryStatementVersion | undefined {
  let active: BoundaryStatementVersion | undefined;
  for (const v of declaration?.versions ?? []) if (Date.parse(v.effective_at) <= atMs) active = v;
  return active;
}

/**
 * One PEP location's view of the declaration: the boundary it serves at an
 * instant, the `aud` rule for that boundary, and the evidence-key
 * authorization every producer reads. Constructed from a statement it
 * validates first, so an unresolvable declaration never reaches a request.
 */
export class EnforcementBoundaryContext {
  readonly declaration: EnforcementBoundaries;
  private readonly consumers: BoundaryConsumer[] = [];

  constructor(
    statement: unknown,
    readonly pepLocation: string,
    private readonly clock: () => Date = () => new Date(),
  ) {
    const findings = enforcementBoundaryFindings(statement);
    if (findings.length) throw new BoundaryConfigError(findings);
    const declared = object(statement) ? statement.enforcement_boundaries : undefined;
    this.declaration = (declared as EnforcementBoundaries | undefined) ?? { versions: [] };
  }

  /** The version in force at `at`: the last whose cutover has been reached. */
  versionInForce(at: Date = this.clock()): BoundaryStatementVersion | undefined {
    return versionInForceAt(this.declaration, at.getTime());
  }

  /**
   * @spec runtime#boundary-identifier: the boundary this PEP location serves
   * at `at`, from the declaration alone. Nothing in a request, a credential
   * or an entry is read, and nothing is defaulted or guessed.
   */
  establish(at: Date = this.clock()): BoundaryEstablishment {
    const version = this.versionInForce(at);
    if (!version) return { ok: false, reason: "no_version_in_force" };
    const declared = version.boundaries.find((b) => b.pep_locations.includes(this.pepLocation));
    if (!declared) return { ok: false, reason: "undeclared_pep_location" };
    // @spec runtime#boundary-identifier-change step 1 (#853 review): every
    // consumer accepts the version before any producer uses it. Until each
    // bound consumer is provisioned for it, the boundary is not established:
    // requests, credentials and held permits refuse, and no record is made.
    if (this.consumers.some((c) => !c.provisionedFor(version, declared))) return { ok: false, reason: "consumer_unprovisioned" };
    return { ok: true, boundary: declared.boundary, version: version.version };
  }

  /**
   * @spec runtime#boundary-identifier-change step 1 (#853 review): register a
   * consumer whose bindings are provisioned outside the declaration (a
   * published key set, a settlement verifier, a claim domain's own
   * statement). {@link establish} holds every later request to it.
   */
  bindConsumer(consumer: BoundaryConsumer): void {
    this.consumers.push(consumer);
  }

  /** The bound consumers not provisioned for this location's boundary under the version in force at `at`, by name. */
  unprovisioned(at: Date = this.clock()): string[] {
    const version = this.versionInForce(at);
    const declared = version?.boundaries.find((b) => b.pep_locations.includes(this.pepLocation));
    if (!version || !declared) return [];
    return this.consumers.filter((c) => !c.provisionedFor(version, declared)).map((c) => c.name);
  }

  /**
   * @spec runtime-oauth#boundary-audience (#853, D487): whether `aud` names the
   * boundary established for this request. The boundary is established first;
   * `aud` only validates against it.
   *
   * - Every token of an issuer and token profile whose aliases map one `aud`
   *   value to more than one boundary (or alias another boundary's own
   *   identifier) is refused: that configuration is ambiguous.
   * - `aud` absent, or not a non-empty string or a non-empty array of
   *   non-empty strings, is refused.
   * - A string or an array is read by membership: some member equals the
   *   boundary, or is an alias declared for it under exactly this issuer and
   *   token profile. Members naming other recipients are ignored, never
   *   refused, and order or duplicates change nothing: the result is always
   *   the established boundary, never a member.
   */
  validateAudience(aud: unknown, context: AudienceContext, at: Date = this.clock()): AudienceValidation {
    const established = this.establish(at);
    if (!established.ok) return established;
    const version = this.versionInForce(at) as BoundaryStatementVersion;
    const named = new Map<string, Set<string>>();
    for (const b of version.boundaries) {
      for (const a of b.audience_aliases ?? []) {
        if (a.issuer !== context.issuer || a.token_profile !== context.tokenProfile) continue;
        const set = named.get(a.alias) ?? new Set<string>();
        set.add(b.boundary);
        if (version.boundaries.some((other) => other.boundary === a.alias)) set.add(a.alias);
        named.set(a.alias, set);
      }
    }
    if ([...named.values()].some((set) => set.size > 1)) return { ok: false, reason: "alias_ambiguous" };
    if (aud === undefined) return { ok: false, reason: "audience_absent" };
    const members = typeof aud === "string" ? [aud] : Array.isArray(aud) ? (aud as unknown[]) : undefined;
    if (!members || members.length === 0 || !members.every(nonEmpty)) return { ok: false, reason: "audience_malformed" };
    const names = (members as string[]).some(
      (m) => m === established.boundary || named.get(m)?.has(established.boundary) === true,
    );
    return names ? established : { ok: false, reason: "audience_mismatch" };
  }

  /**
   * @spec runtime-evidence#decision-evidence-integrity (#853, D487): whether
   * the key `use.kid`, held by `use.emitter` in `use.role`, may sign a record
   * whose `audience` is `use.audience`. `current`: the version in force
   * authorizes it (a new decision, refusal or permit). `historical`: some
   * version in force so far does (the final disposition of a permit decided
   * under an earlier version keeps its original identifier). A `replaces`
   * record never authorizes anything.
   */
  authorizesEvidence(use: EvidenceKeyUse, scope: EvidenceAuthorizationScope, at: Date = this.clock()): boolean {
    const now = at.getTime();
    const inForce = this.versionInForce(at);
    const versions =
      scope === "current"
        ? inForce
          ? [inForce]
          : []
        : this.declaration.versions.filter((v) => Date.parse(v.effective_at) <= now);
    return versions.some((v) => keyAuthorizations(v, use.audience, use.kid).some((k) => k.emitter === use.emitter && k.role === use.role));
  }
}

function keyAuthorizations(version: BoundaryStatementVersion, audience: string, kid: string): BoundaryEvidenceKeyAuthorization[] {
  return (version.boundaries.find((b) => b.boundary === audience)?.evidence_keys ?? []).filter((k) => k.kid === kid);
}

/**
 * @spec runtime-evidence#decision-evidence-integrity (#853, D487): the one
 * key authorization the declared versions determine for an (`audience`,
 * `kid`) pair, or `undefined` when they determine none or more than one.
 * Neither a record's `evaluated_at` nor any clock is read: the pair alone
 * selects the version or versions that authorize that key for that
 * boundary, and every one of them must agree on the emitter and role.
 */
export function determinedKeyAuthorization(
  declaration: EnforcementBoundaries,
  audience: string,
  kid: string,
): BoundaryEvidenceKeyAuthorization | undefined {
  const found = new Map<string, BoundaryEvidenceKeyAuthorization>();
  for (const v of declaration.versions) {
    for (const k of keyAuthorizations(v, audience, kid)) found.set(JSON.stringify([k.emitter, k.role]), k);
  }
  return found.size === 1 ? [...found.values()][0] : undefined;
}

/** One published evidence verification key: the key a `kid` selects for an emitter and role. */
export interface BoundaryEvidenceKey {
  kid: string;
  publicKey: EvidenceKeyLike;
  emitterId: string;
  role: BoundaryEvidenceRole;
}

/**
 * @spec runtime-evidence#decision-evidence-integrity (#853, D487): a
 * verifier's key resolver over the declared versions. A record's key
 * resolves only when the versions determine one key authorization for its
 * (`audience`, `kid`) pair ({@link determinedKeyAuthorization}) naming the
 * record's own emitter and role, and exactly one published key matches that
 * `kid`, emitter and role. The record is verified as signed, never
 * reinterpreted: a `replaces` record neither moves its `audience` nor lets a
 * key authorized for the old boundary sign for the new one.
 */
export function buildBoundaryEvidenceKeyResolver(
  declaration: EnforcementBoundaries,
  keys: readonly BoundaryEvidenceKey[],
): EvidenceKeyResolver {
  return ({ kid, emitter, audience }) => {
    if (!nonEmpty(audience)) return undefined;
    const authorized = determinedKeyAuthorization(declaration, audience, kid);
    if (!authorized || authorized.emitter !== emitter.id || authorized.role !== emitter.role) return undefined;
    const matches = keys.filter((k) => k.kid === kid && k.emitterId === emitter.id && k.role === emitter.role);
    const distinct = new Set(matches.map((k) => k.publicKey));
    if (distinct.size !== 1) return undefined;
    return { key: (matches[0] as BoundaryEvidenceKey).publicKey };
  };
}

/**
 * Audit correlation after verification: the boundaries that succeeded
 * `audience` through declared `replaces` records, oldest first. Data for an
 * auditor joining records across a change; it never rewrites a record and
 * never authorizes a key.
 */
export function boundarySuccessors(declaration: EnforcementBoundaries, audience: string): string[] {
  const out: string[] = [];
  let current = audience;
  for (;;) {
    const next = declaration.versions
      .flatMap((v) => v.replaces ?? [])
      .find((r) => r.previous_boundary === current && r.boundary !== audience && !out.includes(r.boundary));
    if (!next) return out;
    out.push(next.boundary);
    current = next.boundary;
  }
}

/**
 * @spec runtime#idempotency, runtime#boundary-identifier-change (#853
 * review): the boundaries `boundary` replaces, through declared `replaces`
 * records followed transitively, nearest first, never `boundary` itself.
 * A rename changes the identifier, not the operations already admitted at
 * the boundary, so a duplicate-effect store reads its records of a
 * replaced identifier as its own (see {@link lineageScopeDigests}). It never
 * authorizes a key or moves a permit.
 */
export function boundaryPredecessors(declaration: EnforcementBoundaries, boundary: string): string[] {
  const out: string[] = [];
  const seen = new Set([boundary]);
  const queue = [boundary];
  const records = [...declaration.versions].reverse().flatMap((v) => v.replaces ?? []);
  for (let current = queue.shift(); current !== undefined; current = queue.shift()) {
    for (const r of records) {
      if (r.boundary !== current || seen.has(r.previous_boundary)) continue;
      seen.add(r.previous_boundary);
      out.push(r.previous_boundary);
      queue.push(r.previous_boundary);
    }
  }
  return out;
}

/**
 * @spec runtime#idempotency, runtime#boundary-identifier-change (#853
 * review): the idempotency scope digests that hold the same operations as
 * `scope` under the identifiers its `audience` replaces ({@link
 * boundaryPredecessors}). The PDP's claim domain and the PEP's write
 * reservations look a key up under these as well as under `scope`, so a
 * keyed operation consumed or reserved before a declared change is found,
 * with its original disposition, by a retry after it. Records stay under the
 * scope they were made in; nothing is rewritten.
 */
export function lineageScopeDigests(declaration: EnforcementBoundaries | undefined, scope: IdempotencyScope): string[] {
  if (declaration === undefined) return [];
  return boundaryPredecessors(declaration, scope.audience).map((audience) => idempotencyScopeDigest({ ...scope, audience }));
}

/**
 * @spec runtime#boundary-identifier-change step 1 (#853 review): a consumer of
 * a boundary identifier whose bindings are provisioned outside the
 * statement: a published evidence key set that binds each key to one
 * audience, a settlement verifier holding key material, a claim domain
 * loaded with its own copy of the statement. A version may be in force only
 * once every consumer is provisioned for it, and a consumer keeps the
 * bindings of earlier versions for their retention window.
 */
export interface BoundaryConsumer {
  /** A name for diagnostics. */
  name: string;
  /** Whether this consumer is provisioned for `boundary` as `version` declares it. */
  provisionedFor(version: BoundaryStatementVersion, boundary: EnforcementBoundaryDeclaration): boolean;
}

/** One evidence verification key a consumer holds: its `kid`, emitter and role, and the audience it is bound to, if any. */
export interface HeldEvidenceKey {
  kid: string;
  emitterId: string;
  role: string;
  audience?: string;
}

/**
 * @spec runtime#boundary-identifier-change step 1 (#853 review): a consumer
 * holding evidence verification keys. It is provisioned for a boundary when
 * it holds, for every key the version authorizes for that boundary in one of
 * `roles`, a key with that `kid`, emitter and role; `audienceBound` also
 * requires the held key to be bound to the boundary itself (a published key
 * set entry's `audience`). `keys` is read at every check, so publishing the
 * new bindings is what makes the consumer ready.
 */
export function evidenceKeyConsumer(input: {
  name: string;
  roles: readonly BoundaryEvidenceRole[];
  audienceBound: boolean;
  keys: (boundary: string) => readonly HeldEvidenceKey[];
}): BoundaryConsumer {
  return {
    name: input.name,
    provisionedFor: (_version, boundary) => {
      const held = input.keys(boundary.boundary);
      return boundary.evidence_keys
        .filter((k) => input.roles.includes(k.role))
        .every((k) =>
          held.some(
            (h) =>
              h.kid === k.kid &&
              h.emitterId === k.emitter &&
              h.role === k.role &&
              (!input.audienceBound || h.audience === boundary.boundary),
          ),
        );
    },
  };
}
