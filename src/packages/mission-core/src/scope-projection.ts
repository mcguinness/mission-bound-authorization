/**
 * @spec mission#scope-projection — the scope-projection mapping and the
 * issuance-time projection an Authorization Server applies before emitting
 * `scope` on a Mission-bound token.
 *
 * The mapping is the trusted, versioned, per-audience statement of how a
 * target Resource Server enforces: `authorization_details` (the target
 * consumes the carried entries, so `scope` is omitted, step 4) or
 * `scope_only` (the AS emits only `scope` values it proves safe, or refuses,
 * steps 3 and 5). An audience the mapping does not name is unknown and fails
 * closed. Each `scope_only` value declares the effective rights the target
 * grants for it and the controls the target enforces independently on that
 * path.
 *
 * The subset condition as implemented is deliberately narrow: a `scope`
 * value is safe only when ONE applicable entry covers it (never a union of
 * entries), and every entry member the mapping cannot show the target
 * enforcing fails closed.
 */

import type { AuthorityEntry } from "./authority-entry.js";
import { compareAmounts, isValidAmount } from "./decimal-amount.js";

/** How the target's enforcement path consumes a Mission-bound token. */
export const SCOPE_PROJECTION_MODES = ["authorization_details", "scope_only"] as const;
export type ScopeProjectionMode = (typeof SCOPE_PROJECTION_MODES)[number];

/** The `resource_match` forms `mission_resource_access` defines. */
export const SCOPE_RESOURCE_MATCHES = ["exact", "prefix"] as const;
export type ScopeResourceMatch = (typeof SCOPE_RESOURCE_MATCHES)[number];

/**
 * The constraint keys a mapping can declare as independently enforced, each
 * with a type-specific "at least as tight" comparison below. A key with no
 * comparison here cannot be declared, so a mapping never claims enforcement
 * this implementation cannot check.
 */
export const SCOPE_CONTROL_KEYS = ["max_amount", "vendors"] as const;

/** The effective rights the target grants for one `scope` value. */
export interface ScopeValueRights {
  type: "mission_resource_access";
  resource: string;
  match: ScopeResourceMatch;
  actions: string[];
}

/** Constraints the target enforces on the `scope` path, with the enforced value. */
export interface ScopeMandatoryControls {
  max_amount?: { amount: string; currency: string };
  vendors?: string[];
}

export interface ScopeValueMapping {
  rights: ScopeValueRights;
  mandatory_controls: ScopeMandatoryControls;
}

/**
 * `mission_aware` is the trusted classification the routing rule reads
 * (@spec mission#rs-enforcement): `true` only for a target that processes
 * the `act` chain and the `mission` claim; a delegated Mission-bound token is
 * never issued to any other.
 */
export type AudienceScopeMapping =
  | { version: string; mission_aware: boolean; mode: "authorization_details" }
  | {
      version: string;
      mission_aware: boolean;
      mode: "scope_only";
      scopes: Record<string, ScopeValueMapping>;
    };

export interface ScopeProjectionMapping {
  audiences: Record<string, AudienceScopeMapping>;
}

/** A mapping validation fault, naming the offending path. */
export class ScopeProjectionMappingError extends Error {
  constructor(
    readonly path: string,
    message: string,
  ) {
    super(`${path} ${message}`);
    this.name = "ScopeProjectionMappingError";
  }
}

/** RFC 6749 Section 3.3 scope-token: %x21 / %x23-5B / %x5D-7E, at least one. */
const SCOPE_TOKEN = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

function obj(v: unknown, path: string): Record<string, unknown> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) {
    throw new ScopeProjectionMappingError(path, "must be an object");
  }
  return v as Record<string, unknown>;
}

function onlyMembers(o: Record<string, unknown>, allowed: readonly string[], path: string): void {
  for (const k of Object.keys(o)) {
    if (!allowed.includes(k))
      throw new ScopeProjectionMappingError(`${path}.${k}`, "is not a known member");
  }
}

function nonEmptyString(v: unknown, path: string): string {
  if (typeof v !== "string" || v.length === 0) {
    throw new ScopeProjectionMappingError(path, "must be a non-empty string");
  }
  return v;
}

function nonEmptyStrings(v: unknown, path: string): string[] {
  if (
    !Array.isArray(v) ||
    v.length === 0 ||
    !v.every((x) => typeof x === "string" && x.length > 0)
  ) {
    throw new ScopeProjectionMappingError(path, "must be a non-empty array of non-empty strings");
  }
  if (new Set(v).size !== v.length)
    throw new ScopeProjectionMappingError(path, "must not repeat a value");
  return v as string[];
}

function parseControls(v: unknown, path: string): ScopeMandatoryControls {
  const o = obj(v, path);
  onlyMembers(o, SCOPE_CONTROL_KEYS, path);
  const out: ScopeMandatoryControls = {};
  if (o.max_amount !== undefined) {
    const cap = obj(o.max_amount, `${path}.max_amount`);
    onlyMembers(cap, ["amount", "currency"], `${path}.max_amount`);
    const amount = nonEmptyString(cap.amount, `${path}.max_amount.amount`);
    const currency = nonEmptyString(cap.currency, `${path}.max_amount.currency`);
    if (!isValidAmount(amount)) {
      throw new ScopeProjectionMappingError(
        `${path}.max_amount.amount`,
        "must be a decimal amount",
      );
    }
    if (!/^[A-Z]{3}$/.test(currency)) {
      throw new ScopeProjectionMappingError(
        `${path}.max_amount.currency`,
        "must be an ISO 4217 code",
      );
    }
    out.max_amount = { amount, currency };
  }
  if (o.vendors !== undefined) out.vendors = nonEmptyStrings(o.vendors, `${path}.vendors`);
  return out;
}

function parseScopeValue(v: unknown, path: string): ScopeValueMapping {
  const o = obj(v, path);
  onlyMembers(o, ["rights", "mandatory_controls"], path);
  const r = obj(o.rights, `${path}.rights`);
  onlyMembers(r, ["type", "resource", "match", "actions"], `${path}.rights`);
  if (r.type !== "mission_resource_access") {
    throw new ScopeProjectionMappingError(`${path}.rights.type`, "must be mission_resource_access");
  }
  const match = r.match;
  if (typeof match !== "string" || !(SCOPE_RESOURCE_MATCHES as readonly string[]).includes(match)) {
    throw new ScopeProjectionMappingError(`${path}.rights.match`, "must be exact or prefix");
  }
  return {
    rights: {
      type: "mission_resource_access",
      resource: nonEmptyString(r.resource, `${path}.rights.resource`),
      match: match as ScopeResourceMatch,
      actions: nonEmptyStrings(r.actions, `${path}.rights.actions`),
    },
    mandatory_controls:
      o.mandatory_controls === undefined
        ? {}
        : parseControls(o.mandatory_controls, `${path}.mandatory_controls`),
  };
}

function parseAudience(v: unknown, path: string): AudienceScopeMapping {
  const o = obj(v, path);
  const version = nonEmptyString(o.version, `${path}.version`);
  if (typeof o.mission_aware !== "boolean") {
    throw new ScopeProjectionMappingError(`${path}.mission_aware`, "must be a boolean");
  }
  const missionAware = o.mission_aware;
  const mode = o.mode;
  if (mode === "authorization_details") {
    onlyMembers(o, ["version", "mission_aware", "mode"], path);
    return { version, mission_aware: missionAware, mode };
  }
  if (mode !== "scope_only") {
    throw new ScopeProjectionMappingError(
      `${path}.mode`,
      `must be one of ${SCOPE_PROJECTION_MODES.join(", ")}`,
    );
  }
  onlyMembers(o, ["version", "mission_aware", "mode", "scopes"], path);
  const scopes = obj(o.scopes, `${path}.scopes`);
  const names = Object.keys(scopes);
  if (names.length === 0)
    throw new ScopeProjectionMappingError(`${path}.scopes`, "must name at least one scope value");
  const out: Record<string, ScopeValueMapping> = {};
  for (const name of names) {
    if (!SCOPE_TOKEN.test(name)) {
      throw new ScopeProjectionMappingError(
        `${path}.scopes.${name}`,
        "is not an RFC 6749 scope-token",
      );
    }
    out[name] = parseScopeValue(scopes[name], `${path}.scopes.${name}`);
  }
  return { version, mission_aware: missionAware, mode, scopes: out };
}

/**
 * Validate a parsed mapping document. Unknown members are rejected at every
 * level, so a member this implementation would silently ignore (a control it
 * has no comparison for, a misspelled mode) can never read as enforcement.
 * Duplicate member names are the caller's parse-time concern (a strict JSON
 * parse), since `JSON.parse` has already kept the last one.
 */
export function parseScopeProjectionMapping(raw: unknown): ScopeProjectionMapping {
  const root = obj(raw, "scope-projection");
  onlyMembers(root, ["audiences"], "scope-projection");
  const audiences = obj(root.audiences, "audiences");
  const out: Record<string, AudienceScopeMapping> = {};
  for (const [aud, value] of Object.entries(audiences)) {
    if (!URL.canParse(aud))
      throw new ScopeProjectionMappingError(`audiences.${aud}`, "must be an absolute URI");
    out[aud] = parseAudience(value, `audiences.${aud}`);
  }
  return { audiences: out };
}

/** The entry members this projection understands; any other member fails closed. */
const KNOWN_ENTRY_MEMBERS = new Set([
  "type",
  "resource",
  "resource_match",
  "actions",
  "constraints",
  "delegation",
  "capability_sources",
]);

/**
 * @spec resource-access#scope-projection — is `value` a safe projection of
 * the single entry `entry`? All of:
 *
 * 1. Resource: the value's rights and the entry name the same `resource`
 *    under the same `resource_match` (absent = `exact`). A `prefix` value is
 *    never safe for an `exact` entry, and a value over a different (broader
 *    ancestor) resource is never safe for a narrower entry. An unrecognized
 *    `resource_match` fails closed.
 * 2. Actions: every action the value grants is one the entry grants, by
 *    literal membership. A value that aggregates actions the entry does not
 *    carry fails, because the target grants every action the value names.
 * 3. Constraints: for EVERY key in the entry's `constraints`, the mapping
 *    declares a mandatory control the target enforces at least as tightly
 *    (`max_amount`: same currency, control amount <= entry amount;
 *    `vendors`: control set within the entry set). Any other key fails
 *    closed; `requires_action_approval: false` is the omitted value and
 *    constrains nothing.
 *
 * An entry carrying `capability_sources` fails: a `scope` cannot carry the
 * per-action tool-source binding the entry records. `delegation` is policy,
 * not authority, and a `scope` confers none, so it is not compared.
 */
export function scopeValueSafeForEntry(value: ScopeValueMapping, entry: unknown): boolean {
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) return false;
  const e = entry as Record<string, unknown>;
  if (Object.keys(e).some((k) => !KNOWN_ENTRY_MEMBERS.has(k))) return false;
  if (e.type !== value.rights.type) return false;
  if (e.capability_sources !== undefined) return false;
  // 1. resource and resource_match, byte-exact.
  const entryMatch = e.resource_match === undefined ? "exact" : e.resource_match;
  if (entryMatch !== "exact" && entryMatch !== "prefix") return false;
  if (entryMatch !== value.rights.match) return false;
  if (e.resource !== value.rights.resource) return false;
  // 2. actions: no aggregation.
  if (!Array.isArray(e.actions)) return false;
  const actions = e.actions as unknown[];
  if (!value.rights.actions.every((a) => actions.includes(a))) return false;
  // 3. every carried constraint independently enforced at least as tightly.
  if (e.constraints === undefined) return true;
  if (e.constraints === null || typeof e.constraints !== "object" || Array.isArray(e.constraints))
    return false;
  const constraints = e.constraints as NonNullable<AuthorityEntry["constraints"]> &
    Record<string, unknown>;
  const controls = value.mandatory_controls;
  for (const key of Object.keys(constraints)) {
    if (key === "max_amount") {
      const cap = constraints.max_amount;
      const control = controls.max_amount;
      if (!cap || !control || control.currency !== cap.currency) return false;
      if (!isValidAmount(cap.amount) || !isValidAmount(control.amount)) return false;
      if (compareAmounts(control.amount, cap.amount) > 0) return false;
    } else if (key === "vendors") {
      const allowed = constraints.vendors;
      const control = controls.vendors;
      if (!Array.isArray(allowed) || !control) return false;
      if (!control.every((v) => allowed.includes(v))) return false;
    } else if (
      key === "requires_action_approval" &&
      constraints.requires_action_approval === false
    ) {
      // The omitted value: it constrains nothing.
    } else {
      return false;
    }
  }
  return true;
}

export type ScopeProjectionOutcome =
  /** Step 4: every audience consumes `authorization_details`; emit no `scope`. */
  | { outcome: "omit"; versions: Record<string, string> }
  /** Steps 1-3: `scope` is exactly these values, each proven safe at every audience. */
  | { outcome: "emit"; scope: string; values: string[]; versions: Record<string, string> }
  /** Step 5: issuance is refused. */
  | { outcome: "refuse"; reason: string };

export interface ScopeProjectionInput {
  /** The trusted mapping; absent means no audience is known. */
  mapping: ScopeProjectionMapping | undefined;
  /** The token's audience or audiences (step 1). */
  audiences: readonly string[];
  /** The token's carried `authorization_details`. */
  entries: readonly unknown[];
  /**
   * The mapping version recorded for this audience when the grant was first
   * issued under, if any. A different current version is a stale mapping.
   */
  pinnedVersion?: (audience: string) => string | undefined;
  /**
   * The token is delegated: it carries an `act` chain (or answers an RFC 8693
   * delegation request). Then every audience must be Mission-aware.
   */
  delegated?: boolean;
}

/**
 * @spec mission#rs-enforcement — the delegated-routing rule: a delegated
 * Mission-bound token (one carrying an `act` chain) is routed only to a
 * Resource Server the deployment knows to be Mission-aware, never to one
 * that authorizes or logs the caller on `client_id` without processing the
 * `act` chain. Returns the refusal reason, or undefined when every audience
 * is classified `mission_aware: true`. An audience the mapping does not name
 * is not known to be Mission-aware, so it fails closed.
 */
export function delegatedRoutingRefusal(
  mapping: ScopeProjectionMapping | undefined,
  audiences: readonly string[],
): string | undefined {
  if (audiences.length === 0) return "the token names no audience";
  for (const aud of audiences) {
    const m = mapping?.audiences[aud];
    if (!m) return `no scope-projection mapping for audience ${aud}`;
    if (m.mission_aware !== true) {
      return `a delegated Mission-bound token is routed only to a Mission-aware Resource Server; audience ${aud} is not classified mission_aware`;
    }
  }
  return undefined;
}

/**
 * @spec mission#scope-projection — the issuance algorithm, per audience
 * (step 6): a delegated token first passes the routing rule
 * ({@link delegatedRoutingRefusal}); then resolve the audience's mapping
 * (unknown fails closed), refuse a
 * mapping whose version differs from the one pinned for the grant (stale),
 * then either omit `scope` (the target consumes `authorization_details`) or
 * emit only values a single carried entry covers. One `scope` claim reaches
 * every audience, so a value is emitted only when it is safe at every
 * audience, a token spanning both modes is refused, and a `scope`-only
 * audience left with no safe value is refused.
 */
export function projectScope(input: ScopeProjectionInput): ScopeProjectionOutcome {
  const audiences = [...new Set(input.audiences)];
  if (audiences.length === 0) return { outcome: "refuse", reason: "the token names no audience" };
  if (input.delegated) {
    const reason = delegatedRoutingRefusal(input.mapping, audiences);
    if (reason) return { outcome: "refuse", reason };
  }
  const versions: Record<string, string> = {};
  const modes = new Set<ScopeProjectionMode>();
  let safe: Set<string> | undefined;
  for (const aud of audiences) {
    const m = input.mapping?.audiences[aud];
    if (!m) return { outcome: "refuse", reason: `no scope-projection mapping for audience ${aud}` };
    const pinned = input.pinnedVersion?.(aud);
    if (pinned !== undefined && pinned !== m.version) {
      return {
        outcome: "refuse",
        reason: `scope-projection mapping for audience ${aud} is stale (version ${m.version}, grant issued under ${pinned})`,
      };
    }
    versions[aud] = m.version;
    modes.add(m.mode);
    if (m.mode !== "scope_only") continue;
    const here = new Set(
      Object.entries(m.scopes)
        .filter(([, value]) => input.entries.some((entry) => scopeValueSafeForEntry(value, entry)))
        .map(([name]) => name),
    );
    safe = safe ? new Set([...safe].filter((s) => here.has(s))) : here;
  }
  if (!modes.has("scope_only")) return { outcome: "omit", versions };
  if (modes.size > 1) {
    return {
      outcome: "refuse",
      reason: "a scope claim cannot be omitted for one audience and emitted for another",
    };
  }
  const values = [...(safe ?? [])].sort();
  if (values.length === 0) {
    return {
      outcome: "refuse",
      reason: "no safe scope projection exists for the applicable entries",
    };
  }
  return { outcome: "emit", scope: values.join(" "), values, versions };
}
