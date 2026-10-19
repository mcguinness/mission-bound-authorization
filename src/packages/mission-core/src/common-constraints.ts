/**
 * @spec resource-access#common-constraints, resource-access#initial-common-constraints,
 * resource-access#value-space-comparison (#1266, D457): the shared semantics
 * of the Mission Resource Access Common Constraints this reference
 * implements beyond `max_amount` and `requires_action_approval`.
 *
 * One table, one reading. Each key fixes its value syntax, its subset rule,
 * its intersection rule and its enforcement against authoritative facts here,
 * and every path reads them from here: intake and configuration validation,
 * the subset test, derivation and effective-set intersection, credential
 * parsing at a resource server, and the PEP and PDP gates. No path keeps a
 * comparator of its own.
 *
 * Fail closed throughout. A malformed value is never a subset of anything and
 * never intersects; an intersection that is empty is reported, never
 * repaired; and an enforcement fact the resource did not establish never
 * satisfies a bound.
 */

import type { JsonValue } from "./canonicalize.js";
import { compareInstants, type Instant, parseRfc3339Instant } from "./rfc3339-instant.js";

/**
 * The facts a resource server establishes for itself, from its own trusted
 * records and operation contract, never from an agent's arguments. A fact
 * the resource did not establish is absent, and an absent fact satisfies no
 * bound that reads it.
 */
export interface ConstraintFacts {
  /** The RFC 3339 issuance instant of the resource the operation acts on, from the resource's own record. */
  resourceIssuedAt?: string;
  /** The tenant that owns the resource the operation acts on, from the resource's own record. */
  tenant?: string;
}

/** One Common Constraint's definition. */
interface Semantics {
  /** Value syntax. */
  valid(value: unknown): boolean;
  /** Subset rule: `candidate` is no broader than `reference` (both already valid). */
  noBroader(candidate: JsonValue, reference: JsonValue): boolean;
  /** Intersection rule over two valid values; `undefined` when there is no intersection. */
  intersect(a: JsonValue, b: JsonValue): JsonValue | undefined;
  /** Whether the authoritative facts satisfy the bound; an absent fact never does. */
  satisfied(value: JsonValue, facts: ConstraintFacts): boolean;
}

const instant = (v: JsonValue): Instant => parseRfc3339Instant(v) as Instant;

/** `resource_issued_after`: the resource was issued at or after the instant. */
const RESOURCE_ISSUED_AFTER: Semantics = {
  valid: (v) => parseRfc3339Instant(v) !== undefined,
  noBroader: (c, r) => compareInstants(instant(c), instant(r)) >= 0,
  // The later instant; an equal instant keeps the first operand's spelling.
  intersect: (a, b) => (compareInstants(instant(a), instant(b)) >= 0 ? a : b),
  satisfied: (v, facts) => {
    const issued = parseRfc3339Instant(facts.resourceIssuedAt);
    return issued !== undefined && compareInstants(issued, instant(v)) >= 0;
  },
};

/** `resource_issued_before`: the resource was issued at or before the instant. */
const RESOURCE_ISSUED_BEFORE: Semantics = {
  valid: (v) => parseRfc3339Instant(v) !== undefined,
  noBroader: (c, r) => compareInstants(instant(c), instant(r)) <= 0,
  // The earlier instant; an equal instant keeps the first operand's spelling.
  intersect: (a, b) => (compareInstants(instant(a), instant(b)) <= 0 ? a : b),
  satisfied: (v, facts) => {
    const issued = parseRfc3339Instant(facts.resourceIssuedAt);
    return issued !== undefined && compareInstants(issued, instant(v)) <= 0;
  },
};

/**
 * `tenant`: the resource belongs to the named tenant. Exact string
 * comparison (no case folding or other normalization), so two spellings that
 * differ in any way are different tenants.
 */
const TENANT: Semantics = {
  valid: (v) => typeof v === "string" && v.length > 0,
  noBroader: (c, r) => c === r,
  // The common value when equal; differing tenants have no intersection.
  intersect: (a, b) => (a === b ? a : undefined),
  satisfied: (v, facts) => typeof facts.tenant === "string" && facts.tenant === v,
};

const SEMANTICS = {
  resource_issued_after: RESOURCE_ISSUED_AFTER,
  resource_issued_before: RESOURCE_ISSUED_BEFORE,
  tenant: TENANT,
} as const satisfies Record<string, Semantics>;

/** A Common Constraint key whose semantics this module defines. */
export type CommonConstraintKey = keyof typeof SEMANTICS;

/**
 * The Common Constraints this reference implements end to end, in the order
 * their gates run. Each is retained and enforced on every path: intake,
 * configuration load, the subset test, derivation and effective-set
 * intersection, refresh, exchange, introspection, and resource-side
 * enforcement against authoritative facts.
 */
export const IMPLEMENTED_COMMON_CONSTRAINTS: readonly CommonConstraintKey[] = Object.freeze(
  Object.keys(SEMANTICS) as CommonConstraintKey[],
);

/** True when `key` is one of {@link IMPLEMENTED_COMMON_CONSTRAINTS}. */
export function isImplementedCommonConstraint(key: string): key is CommonConstraintKey {
  return Object.hasOwn(SEMANTICS, key);
}

/** Whether `value` is a well-formed value for `key`. */
export function validCommonConstraint(key: CommonConstraintKey, value: unknown): boolean {
  return SEMANTICS[key].valid(value);
}

type Constraints = Readonly<Record<string, unknown>> | undefined;

/**
 * @spec resource-access#subset step 3: for every implemented key the
 * reference carries, the candidate carries the key too, with a value no
 * broader under the key's subset rule. A key the candidate adds narrows it;
 * its value must still be well formed. Total and non-throwing: a malformed
 * value on either side is never a subset.
 */
export function commonConstraintsNoBroader(
  candidate: Constraints,
  reference: Constraints,
): boolean {
  for (const key of IMPLEMENTED_COMMON_CONSTRAINTS) {
    const r = reference?.[key];
    const c = candidate?.[key];
    if (c !== undefined && !SEMANTICS[key].valid(c)) return false;
    if (r === undefined) continue;
    if (c === undefined || !SEMANTICS[key].valid(r)) return false;
    if (!SEMANTICS[key].noBroader(c as JsonValue, r as JsonValue)) return false;
  }
  return true;
}

/** The outcome of intersecting the implemented keys of two `constraints` objects. */
export type CommonConstraintIntersection =
  | { ok: true; values: Partial<Record<CommonConstraintKey, JsonValue>> }
  | { ok: false; key: string; reason: string };

/**
 * @spec resource-access#common-constraints (intersection rule): combine the
 * implemented keys of two `constraints` objects. A key on one side only is
 * carried from that side; a key on both sides takes its intersection rule.
 * An empty intersection fails the combination: the caller refuses (a
 * derivation from a submitted proposal) or drops the fragment (an
 * effective-set projection), and never keeps one operand's value.
 *
 * The two issuance bounds jointly describe one window, so a combination
 * whose `resource_issued_after` is later than its `resource_issued_before`
 * admits no resource and fails the same way.
 */
export function intersectCommonConstraints(
  a: Constraints,
  b: Constraints,
): CommonConstraintIntersection {
  const values: Partial<Record<CommonConstraintKey, JsonValue>> = {};
  for (const key of IMPLEMENTED_COMMON_CONSTRAINTS) {
    const av = a?.[key];
    const bv = b?.[key];
    if (av === undefined && bv === undefined) continue;
    const s = SEMANTICS[key];
    if ((av !== undefined && !s.valid(av)) || (bv !== undefined && !s.valid(bv))) {
      return { ok: false, key, reason: `malformed ${key} value` };
    }
    if (av === undefined || bv === undefined) {
      values[key] = structuredClone((av ?? bv) as JsonValue);
      continue;
    }
    const v = s.intersect(av as JsonValue, bv as JsonValue);
    if (v === undefined) return { ok: false, key, reason: `${key} values have no intersection` };
    values[key] = structuredClone(v);
  }
  const after = values.resource_issued_after;
  const before = values.resource_issued_before;
  if (
    after !== undefined &&
    before !== undefined &&
    compareInstants(instant(after), instant(before)) > 0
  ) {
    return {
      ok: false,
      key: "resource_issued_after",
      reason:
        "resource_issued_after is later than resource_issued_before: the issuance window is empty",
    };
  }
  return { ok: true, values };
}

/** The gates one evaluation reached, in order, and whether every one held. */
export interface CommonConstraintTrace {
  satisfied: boolean;
  /** The keys whose gate ran; a gate after a failed one is never reached. */
  evaluated: CommonConstraintKey[];
}

/**
 * @spec resource-access#rs-enforcement, runtime#input-parameters: evaluate
 * every implemented key an entry's `constraints` carries against the
 * authoritative facts, gate by gate, stopping at the first that fails. A
 * malformed value or an absent fact fails its gate.
 */
export function commonConstraintGates(
  constraints: Constraints,
  facts: ConstraintFacts,
): CommonConstraintTrace {
  const evaluated: CommonConstraintKey[] = [];
  for (const key of IMPLEMENTED_COMMON_CONSTRAINTS) {
    const v = constraints?.[key];
    if (v === undefined) continue;
    evaluated.push(key);
    const s = SEMANTICS[key];
    if (!s.valid(v) || !s.satisfied(v as JsonValue, facts)) return { satisfied: false, evaluated };
  }
  return { satisfied: true, evaluated };
}
