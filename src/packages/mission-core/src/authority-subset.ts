/** Shared strict lineage comparisons and binding-neutral wire/config boundaries. */

import { isActivationPolicyRef } from "./anchors.js";
import type { AuthorityEntry, DelegateMatcher, TerminalWhenCondition } from "./authority-entry.js";
import { canonicalize, type JsonValue } from "./canonicalize.js";
import { type CapabilitySourceBinding, capabilitySourceIdentity } from "./capability-binding.js";
import {
  commonConstraintsNoBroader,
  IMPLEMENTED_COMMON_CONSTRAINTS,
  isImplementedCommonConstraint,
  validCommonConstraint,
} from "./common-constraints.js";
import { compareAmounts, isValidAmount } from "./decimal-amount.js";

/**
 * Provenance is compared between issuer-derived lineage sets, not config
 * ceilings. `capability_sources` is the ONLY member set aside at a config
 * boundary: every other recorded member, `delegation.children`'s
 * `child_creation_policy` included, is compared and carried by the caller.
 */
export function withoutCapabilitySources(entries: readonly AuthorityEntry[]): AuthorityEntry[] {
  return entries.map(({ capability_sources: _bindings, ...authority }) => authority);
}

/** Authority-only comparisons at wire/config boundaries; lineage stays strict. */
export function isSubsetSetIgnoringCapabilitySources(
  candidate: readonly AuthorityEntry[],
  granted: readonly AuthorityEntry[],
): boolean {
  return isSubsetSet(withoutCapabilitySources(candidate), withoutCapabilitySources(granted));
}

/** Assertion, never a narrowing operation: every action must fit one config entry. */
export function entryWithinCeiling(
  entry: AuthorityEntry,
  ceiling: readonly AuthorityEntry[],
): boolean {
  return isSubsetSet(withoutCapabilitySources([entry]), [...ceiling]);
}

/**
 * @spec mission#common-constraints, mission#derivation-policy — the
 * `constraints` member names this engine accepts on an `AuthorityEntry`,
 * config ceiling and client proposal alike (issue #784). This spans the
 * Common Constraint keys the engine implements narrowing for (`max_amount`,
 * `requires_action_approval`, `terminal_when`, and the
 * {@link IMPLEMENTED_COMMON_CONSTRAINTS} of `common-constraints.ts`, #1266)
 * and `vendors`, a deployment-defined key the common registry does not carry
 * at all. Neither direction of the registration/support distinction is
 * automatic: a key registered by the Common Constraints registry is not
 * supported here until every path retains and enforces it, and `vendors`
 * being unregistered does not exempt it from the same obligation. This is
 * the SINGLE declaration of that supported set; every boundary that admits
 * an `AuthorityEntry` (typed config load, PAR intake) reuses it rather than
 * keeping a parallel list that can drift.
 */
export const SUPPORTED_CONSTRAINT_KEYS: readonly string[] = Object.freeze([
  "max_amount",
  "vendors",
  "requires_action_approval",
  "terminal_when",
  ...IMPLEMENTED_COMMON_CONSTRAINTS,
]);

/**
 * @spec resource-access#entry-validation (#1278, D454, D457): the RFC 9396
 * common fields a `mission_resource_access` entry does not use: `resource`
 * identifies where an entry applies, so an entry carrying `locations` is
 * refused. This is the SINGLE declaration every boundary that admits an
 * entry of this type consults (PAR and the other proposal intakes, the typed
 * config loaders, and derivation), so none admits the member and then drops
 * it in a member-by-member rebuild. Refused by name only: the entry's top
 * level stays open to a member another specification defines for this type,
 * such as `capability_sources`.
 */
export const REFUSED_ENTRY_MEMBERS = ["locations"] as const;

/**
 * The first {@link REFUSED_ENTRY_MEMBERS} member `entry` carries, or
 * undefined. Decided by property presence, never by value: `locations: []`,
 * `null`, `""` or any malformed value is refused exactly as a populated array
 * is. The caller applies it to an entry of this type and maps a hit to its
 * boundary's own error (`invalid_authorization_details` on a protocol
 * surface, the loader's configuration error at load).
 */
export function refusedEntryMember(entry: unknown): string | undefined {
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) return undefined;
  return REFUSED_ENTRY_MEMBERS.find((member) => Object.hasOwn(entry, member));
}

/**
 * @spec resource-access#matching-allowed-delegates, child-delegation#fanout
 * (#1373): the members a delegate matcher carries, in
 * `delegation.allowed_delegates` and `delegation.children.allowed_child_actors`
 * alike. This is the SINGLE matcher rule every boundary that admits an entry
 * consults: the proposal intakes' schema check, the typed config loaders and
 * the foreign-grant validator (through {@link isAuthorityEntry}), derivation,
 * and the requested-authority exchanges (through
 * {@link entryDelegateMatcherViolation}). A member outside this set cannot be
 * interpreted, and a member-by-member rebuild would drop it and widen the
 * eligibility the entry commits, so it is refused rather than admitted.
 */
export const DELEGATE_MATCHER_MEMBERS: readonly string[] = Object.freeze(["sub", "sub_profile"]);

/**
 * The violation for the delegate-matcher list `value` at `path`, or
 * undefined. A matcher is refused when it is not an object, carries a member
 * outside {@link DELEGATE_MATCHER_MEMBERS}, carries neither member, or
 * carries one that is not a non-empty string. The caller maps a violation to
 * its boundary's own error.
 */
export function delegateMatcherListViolation(value: unknown, path: string): string | undefined {
  if (!Array.isArray(value)) return `${path} must be an array`;
  for (const m of value) {
    if (m === null || typeof m !== "object" || Array.isArray(m)) {
      return `${path} entries must be objects`;
    }
    const matcher = m as Record<string, unknown>;
    const unknown = Object.keys(matcher).find((k) => !DELEGATE_MATCHER_MEMBERS.includes(k));
    if (unknown !== undefined) return `${path} entries carry no member '${unknown}'`;
    if (matcher.sub === undefined && matcher.sub_profile === undefined) {
      return `${path} entries must carry sub or sub_profile`;
    }
    for (const member of DELEGATE_MATCHER_MEMBERS) {
      const v = matcher[member];
      if (v === undefined) continue;
      if (typeof v !== "string") return `${path}.${member} must be a string`;
      if (v.length === 0) return `${path}.${member} must not be empty`;
    }
  }
  return undefined;
}

/**
 * {@link delegateMatcherListViolation} over the two matcher lists `entry`
 * carries, `delegation.allowed_delegates` then
 * `delegation.children.allowed_child_actors`, or undefined. Each list is read
 * where its parent is an object; the parent's own shape is left to the
 * boundary's other checks. For a boundary that holds a whole entry, not a
 * list: the requested-authority exchanges.
 */
export function entryDelegateMatcherViolation(entry: unknown): string | undefined {
  const delegation = asJsonObject(asJsonObject(entry as JsonValue)?.delegation);
  if (!delegation) return undefined;
  const children = asJsonObject(delegation.children);
  return (
    (delegation.allowed_delegates !== undefined
      ? delegateMatcherListViolation(delegation.allowed_delegates, "delegation.allowed_delegates")
      : undefined) ??
    (children?.allowed_child_actors !== undefined
      ? delegateMatcherListViolation(
          children.allowed_child_actors,
          "delegation.children.allowed_child_actors",
        )
      : undefined)
  );
}

/**
 * Validate the subset engine's supported input before a foreign grant can use
 * it. An entry carrying a {@link REFUSED_ENTRY_MEMBERS} member is unsupported,
 * decided by presence: a destination redeeming a signed grant from a
 * configurable trusted issuer refuses it rather than minting it into a local
 * token, so it never reaches a resource (#1278).
 */
export function isAuthorityEntry(value: unknown): value is AuthorityEntry {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (refusedEntryMember(value) !== undefined) return false;
  const e = value as Record<string, unknown>;
  const strings = (v: unknown): v is string[] =>
    Array.isArray(v) && v.length > 0 && v.every((x) => typeof x === "string" && x.length > 0);
  if (
    e.type !== "mission_resource_access" ||
    typeof e.resource !== "string" ||
    !e.resource ||
    !strings(e.actions)
  )
    return false;
  if (e.constraints !== undefined) {
    if (!e.constraints || typeof e.constraints !== "object" || Array.isArray(e.constraints))
      return false;
    const c = e.constraints as Record<string, unknown>;
    if (Object.keys(c).some((k) => !SUPPORTED_CONSTRAINT_KEYS.includes(k))) return false;
    // @spec resource-access#initial-common-constraints (#1266): each
    // implemented Common Constraint's value syntax, from the shared table.
    for (const key of Object.keys(c)) {
      if (isImplementedCommonConstraint(key) && !validCommonConstraint(key, c[key])) return false;
    }
    if (c.vendors !== undefined && !strings(c.vendors)) return false;
    if (c.requires_action_approval !== undefined && typeof c.requires_action_approval !== "boolean")
      return false;
    if (
      c.terminal_when !== undefined &&
      (!Array.isArray(c.terminal_when) ||
        !c.terminal_when.length ||
        !c.terminal_when.every((x) => conditionCanonicalBytes(x) !== undefined))
    )
      return false;
    if (c.max_amount !== undefined) {
      const cap = c.max_amount as Record<string, unknown> | null;
      if (
        !cap ||
        typeof cap !== "object" ||
        Array.isArray(cap) ||
        Object.keys(cap).some((k) => k !== "amount" && k !== "currency") ||
        typeof cap.currency !== "string" ||
        !/^[A-Z]{3}$/.test(cap.currency) ||
        typeof cap.amount !== "string" ||
        !isValidAmount(cap.amount)
      )
        return false;
    }
  }
  // Delegate narrowing retains known structures; unknown controls cannot be
  // interpreted as permission by this ceiling implementation.
  if (e.delegation !== undefined) {
    const d = e.delegation as Record<string, unknown> | null;
    if (
      !d ||
      typeof d !== "object" ||
      Array.isArray(d) ||
      !Number.isInteger(d.max_depth) ||
      (d.max_depth as number) < 0
    )
      return false;
    if (Object.keys(d).some((k) => !["max_depth", "allowed_delegates", "children"].includes(k)))
      return false;
    const matchers = (v: unknown) => delegateMatcherListViolation(v, "matchers") === undefined;
    if (d.allowed_delegates !== undefined && !matchers(d.allowed_delegates)) return false;
    if (d.children !== undefined) {
      const c = d.children as Record<string, unknown> | null;
      if (
        !c ||
        typeof c !== "object" ||
        Array.isArray(c) ||
        Object.keys(c).some(
          (k) =>
            ![
              "max_children",
              "max_child_depth",
              "allowed_child_actors",
              "child_creation_policy",
            ].includes(k),
        )
      )
        return false;
      for (const k of ["max_children", "max_child_depth"])
        if (c[k] !== undefined && (!Number.isInteger(c[k]) || (c[k] as number) < 0)) return false;
      if (c.allowed_child_actors !== undefined && !matchers(c.allowed_child_actors)) return false;
      // @spec child-delegation#fanout, mission#standing-consent-bases — an
      // activation policy reference, compared for equal presence and identity
      // of `id`, `version`, and `digest` ({@link childrenNoBroader}), never
      // intersected, substituted, or dropped to manufacture a fit.
      if (c.child_creation_policy !== undefined && !isActivationPolicyRef(c.child_creation_policy))
        return false;
    }
  }
  if (
    e.capability_sources !== undefined &&
    (!Array.isArray(e.capability_sources) ||
      !e.capability_sources.every(
        (b) =>
          b &&
          typeof b === "object" &&
          ["action", "tool_id", "source_uri", "source_digest", "operation_ref"].every(
            (k) => typeof b[k] === "string" && b[k].length > 0,
          ),
      ))
  )
    return false;
  return true;
}

/**
 * Narrow per action, including a multi-action entry or a split ceiling. Other
 * dimensions remain byte-identical: an unsupported or too-broad restriction
 * is refused, never dropped or relaxed to manufacture an intersection. A
 * ceiling declaring a `child_creation_policy` binds it under the lineage rule,
 * so a candidate lacking or altering that reference is refused; a ceiling
 * declaring no `children` grant refuses the entry carrying one, exactly as an
 * introduced delegation is refused. A surviving entry keeps the reference and
 * its retained-action `capability_sources` verbatim. Both operands pass
 * {@link isAuthorityEntry} first, so a surviving entry never retains a
 * {@link REFUSED_ENTRY_MEMBERS} member.
 */
export function narrowToCeiling(
  entries: readonly AuthorityEntry[],
  ceiling: readonly AuthorityEntry[],
): AuthorityEntry[] {
  if (!entries.every(isAuthorityEntry) || !ceiling.every(isAuthorityEntry)) return [];
  const out: AuthorityEntry[] = [];
  for (const entry of entries) {
    const actions = entry.actions.filter((action) => {
      try {
        return entryWithinCeiling({ ...entry, actions: [action] }, ceiling);
      } catch {
        return false;
      }
    });
    if (!actions.length) continue;
    if (actions.length === entry.actions.length) {
      out.push(entry);
      continue;
    }
    const { capability_sources, ...rest } = entry;
    const bindings = capability_sources?.filter((b) => actions.includes(b.action));
    out.push({ ...rest, actions, ...(bindings?.length ? { capability_sources: bindings } : {}) });
  }
  return out;
}

type JsonObject = { [k: string]: JsonValue };

function asJsonObject(v: JsonValue | undefined): JsonObject | undefined {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as JsonObject) : undefined;
}

function asNum(v: JsonValue | undefined): number | undefined {
  return typeof v === "number" ? v : undefined;
}

function matcherKey(m: DelegateMatcher): string {
  return JSON.stringify([m.sub ?? null, m.sub_profile ?? null]);
}

function readMatchers(v: JsonValue | undefined): DelegateMatcher[] | undefined {
  if (!Array.isArray(v)) return undefined;
  return v.map((el) => {
    const o = asJsonObject(el);
    const m: DelegateMatcher = {};
    if (o && typeof o.sub === "string") m.sub = o.sub;
    if (o && typeof o.sub_profile === "string") m.sub_profile = o.sub_profile;
    return m;
  });
}

export function conditionCanonicalBytes(condition: unknown): string | undefined {
  if (condition === null || typeof condition !== "object" || Array.isArray(condition))
    return undefined;
  const c = condition as Record<string, unknown>;
  if (typeof c.event_type !== "string") return undefined;
  if (c.discharge_authority !== undefined && typeof c.discharge_authority !== "string")
    return undefined;
  for (const k of Object.keys(c)) {
    if (k !== "event_type" && k !== "discharge_authority") return undefined;
  }
  return canonicalize(condition as JsonValue);
}

/**
 * @spec discharge#subset-extension — a candidate condition array is NO BROADER
 * than a reference array when it contains every reference condition, compared
 * structurally after canonicalization; it MAY add further conditions. Total and
 * non-throwing (a malformed condition on either side fails closed), so
 * `isSubsetEntry` stays a plain predicate.
 */
export function conditionsNoBroader(
  candidate: readonly TerminalWhenCondition[] | undefined,
  reference: readonly TerminalWhenCondition[] | undefined,
): boolean {
  if (!reference?.length) return true; // the reference constrains nothing
  if (!candidate?.length) return false; // dropping a parent condition WIDENS
  const held = new Set<string>();
  for (const c of candidate) {
    const bytes = conditionCanonicalBytes(c);
    if (bytes === undefined) return false;
    held.add(bytes);
  }
  return reference.every((r) => {
    const bytes = conditionCanonicalBytes(r);
    return bytes !== undefined && held.has(bytes);
  });
}

/** @spec mission#subset — entry-wise subset test (resource byte-exact). */
export function isSubsetEntry(candidate: AuthorityEntry, granted: AuthorityEntry): boolean {
  if (candidate.type !== granted.type) return false;
  if (candidate.resource !== granted.resource) return false;
  if (!candidate.actions.every((a) => granted.actions.includes(a))) return false;
  const gCap = granted.constraints?.max_amount;
  const cCap = candidate.constraints?.max_amount;
  if (gCap) {
    if (!cCap) return false;
    if (cCap.currency !== gCap.currency) return false;
    // @spec mission#max-amount — exact decimal-value comparison. A malformed
    // amount on either side fails closed (not a subset) rather than comparing
    // via IEEE-754 float coercion; isSubsetEntry stays a total, non-throwing
    // predicate so its callers (e.g. child-delegation's strict-subset gate)
    // keep treating it as a plain boolean.
    if (!isValidAmount(cCap.amount) || !isValidAmount(gCap.amount)) return false;
    if (compareAmounts(cCap.amount, gCap.amount) > 0) return false;
  }
  const gVendors = granted.constraints?.vendors;
  const cVendors = candidate.constraints?.vendors;
  if (gVendors) {
    if (!cVendors) return false;
    if (!cVendors.every((v) => gVendors.includes(v))) return false;
  }
  // @spec txn-authorization#applicability — a delegated child MUST preserve
  // `requires_action_approval: true`; dropping it (or restating it as `false`,
  // which is equivalent to omission) would WIDEN, so it is not a subset.
  if (
    granted.constraints?.requires_action_approval === true &&
    candidate.constraints?.requires_action_approval !== true
  ) {
    return false;
  }
  // @spec resource-access#subset step 3, resource-access#value-space-comparison
  // (#1266): every implemented Common Constraint the grantor carries, kept
  // and no broader in value space; a malformed value on either side fails.
  if (!commonConstraintsNoBroader(candidate.constraints, granted.constraints)) return false;
  // @spec discharge#subset-extension — a derived entry carries every parent
  // completion condition unchanged and MAY add more: dropping or altering one
  // WIDENS (a verifier cannot tell from opaque event types whether a changed
  // condition discharges earlier or later), so it is not a subset.
  if (
    !conditionsNoBroader(candidate.constraints?.terminal_when, granted.constraints?.terminal_when)
  ) {
    return false;
  }
  // @spec capability-binding#capability-source-binding — MONOTONIC derivation:
  // a candidate retaining a catalog-sourced action carries every binding the
  // grantor recorded for that action, byte-identical, and introduces none the
  // grantor lacks. Dropping the action entirely is narrower and already passes
  // through the actions-subset test above.
  if (!capabilitySourcesNoBroader(candidate, granted)) return false;
  // @spec attenuation#delegation, child-delegation#attenuation — delegation is a
  // GRANT and NARROWS: the direction is the OPPOSITE of the constraint rules
  // above. A candidate that OMITS delegation the grantor has is strictly
  // narrower (the child simply does not re-delegate) and PASSES; a candidate
  // that INTRODUCES delegation the grantor lacks FAILS.
  const gDel = granted.delegation;
  const cDel = candidate.delegation;
  if (cDel && !gDel) return false; // introduces delegation the grantor lacks
  if (gDel && cDel) {
    if (cDel.max_depth > gDel.max_depth) return false;
    // allowed_delegates is a RESTRICTION -> subset direction mirrors vendors.
    if (!matchersSubset(cDel.allowed_delegates, gDel.allowed_delegates)) return false;
    if (!childrenNoBroader(asJsonObject(cDel.children), asJsonObject(gDel.children))) return false;
  }
  // gDel present, cDel absent -> PASS: the child does not re-delegate.
  return true;
}

/**
 * @spec capability-binding#capability-source-binding — the capability clause of
 * the subset rule, in BOTH directions.
 *
 * A binding is a recorded FACT about a catalog-sourced action, not a
 * restriction, so neither the constraint direction nor the delegation
 * direction alone is right:
 *   - every binding the grantor recorded for an action the candidate RETAINS
 *     appears byte-identical in the candidate; retaining a catalog-sourced
 *     action with a dropped or altered binding widens (the candidate would be
 *     bound to a capability the grantor never recorded), so it fails;
 *   - every binding the candidate carries appears byte-identical among the
 *     grantor's; introducing one the grantor lacks is the GRANT direction and
 *     fails, exactly as introducing `delegation` does.
 *
 * Total and non-throwing, like the rest of {@link isSubsetEntry}: comparison
 * is over canonical bytes, with a value that cannot be canonicalized treated
 * as matching nothing (fail closed) rather than throwing.
 */
function capabilitySourcesNoBroader(candidate: AuthorityEntry, granted: AuthorityEntry): boolean {
  const cSources = candidate.capability_sources ?? [];
  const gSources = granted.capability_sources ?? [];
  if (cSources.length === 0 && gSources.length === 0) return true;
  const cKeys = cSources.map(bindingKey);
  const gKeys = gSources.map(bindingKey);
  if (cKeys.includes(null) || gKeys.includes(null)) return false;
  const gSet = new Set(gKeys);
  if (!cKeys.every((k) => gSet.has(k))) return false; // introduces an unrecorded binding
  const cSet = new Set(cKeys);
  return gSources.every(
    (g, i) => !candidate.actions.includes(g.action) || cSet.has(gKeys[i] as string),
  );
}

/** Canonical bytes of one binding, or null when it cannot be canonicalized. */
function bindingKey(binding: CapabilitySourceBinding): string | null {
  try {
    return capabilitySourceIdentity(binding);
  } catch {
    return null;
  }
}

/** A restriction-list subset test mirroring the vendors rule: grantor-absent is
 *  unconstrained (any candidate ⊆); grantor-present + candidate-absent is
 *  broader (fails); both present requires candidate ⊆ granted on identity.
 *
 *  @spec resource-access#subset, resource-access#delegate-eligibility (#1275):
 *  structural only. A grantor without a list defers eligibility to the
 *  authorization server's policy, and a candidate list only restricts that
 *  decision. A `true` here is never authorization to delegate: a caller that
 *  derives a candidate keeps the grantor's inherited origin, and the
 *  authorization server decides eligibility at each delegated issuance. */
function matchersSubset(
  candidate: DelegateMatcher[] | undefined,
  granted: DelegateMatcher[] | undefined,
): boolean {
  if (!granted) return true;
  if (!candidate) return false;
  const gKeys = new Set(granted.map(matcherKey));
  return candidate.every((m) => gKeys.has(matcherKey(m)));
}

/** A cap (max_children/max_child_depth) is no broader: grantor-unbounded admits
 *  any candidate; grantor-bounded + candidate-unbounded is broader (fails). */
function capNoBroader(candidate: number | undefined, granted: number | undefined): boolean {
  if (granted === undefined) return true;
  if (candidate === undefined) return false;
  return candidate <= granted;
}

/**
 * @spec child-delegation#fanout, child-delegation#child-creation — the
 * recorded drawdown policy reference. It is neither a cap nor a restriction
 * list: it becomes the child's approval-basis `root_commitment`, so a verifier
 * cannot rank two references, and a reference the grantor never recorded is
 * not narrower than one it did.
 * Where both sides retain the `children` grant, presence is EQUAL and a present
 * value is byte-identical: introducing it, altering it, or dropping the
 * reference while keeping the grant each fail. A non-string on either side
 * matches nothing (fail closed), keeping this predicate total.
 */
function childPolicyIdentical(
  candidate: JsonValue | undefined,
  granted: JsonValue | undefined,
): boolean {
  if (candidate === undefined && granted === undefined) return true;
  if (!isActivationPolicyRef(candidate) || !isActivationPolicyRef(granted)) return false;
  return (
    candidate.id === granted.id &&
    candidate.version === granted.version &&
    candidate.digest === granted.digest
  );
}

/** `children` is a GRANT: candidate introducing it where the grantor has none
 *  FAILS; candidate omitting the whole grant PASSES (strictly narrower, and the
 *  only narrowing form once a policy reference is retained); both present
 *  narrow member-wise, carrying the policy reference byte-identically. */
function childrenNoBroader(
  candidate: JsonObject | undefined,
  granted: JsonObject | undefined,
): boolean {
  if (candidate && !granted) return false; // introduces the child-creation on-switch
  if (!candidate) return true; // omits -> strictly narrower
  if (!capNoBroader(asNum(candidate.max_children), asNum(granted?.max_children))) return false;
  if (!capNoBroader(asNum(candidate.max_child_depth), asNum(granted?.max_child_depth)))
    return false;
  if (!childPolicyIdentical(candidate.child_creation_policy, granted?.child_creation_policy))
    return false;
  return matchersSubset(
    readMatchers(candidate.allowed_child_actors),
    readMatchers(granted?.allowed_child_actors),
  );
}

export function isSubsetSet(candidate: AuthorityEntry[], granted: AuthorityEntry[]): boolean {
  return candidate.every((c) => granted.some((g) => isSubsetEntry(c, g)));
}
