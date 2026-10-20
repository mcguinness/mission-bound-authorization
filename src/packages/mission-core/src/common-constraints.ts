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
import {
  compareInstants,
  type Instant,
  instantFloorMs,
  instantFromMs,
  parseRfc3339Instant,
} from "./rfc3339-instant.js";

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
  /**
   * The current time of the evaluating component's trusted clock, epoch
   * milliseconds, read at the point of use. Never a time the request states.
   */
  now?: number;
  /**
   * Every final recipient the operation reaches (each an `local@domain`
   * address), routing and list expansion applied, from the resource's own
   * records. An empty list is no recipients established.
   */
  recipients?: readonly string[];
  /**
   * The classification label of every piece of data the operation touches,
   * from the resource's own labels. An empty list is no label established.
   */
  dataClassification?: readonly string[];
  /**
   * The identity of the tool or function the operation is exercised through,
   * as the enforcing component dispatched it from its trusted operation
   * contract, never a name the caller claims.
   */
  tool?: string;
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
  /**
   * Whether a (valid) value admits nothing: a list with no member. A
   * combination whose result is empty has no
   * intersection, whether it came from two operands or was carried from one.
   */
  empty?(value: JsonValue): boolean;
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

type Window = { not_before?: string; not_after?: string };
const WINDOW_MEMBERS = new Set(["not_before", "not_after"]);

/** The later of two instant strings, or the one present; an equal instant keeps `a`. */
function later(a: string | undefined, b: string | undefined): string | undefined {
  if (a === undefined) return b;
  if (b === undefined) return a;
  return compareInstants(instant(a), instant(b)) >= 0 ? a : b;
}

/** The earlier of two instant strings, or the one present; an equal instant keeps `a`. */
function earlier(a: string | undefined, b: string | undefined): string | undefined {
  if (a === undefined) return b;
  if (b === undefined) return a;
  return compareInstants(instant(a), instant(b)) <= 0 ? a : b;
}

/** Whether `not_before` is later than `not_after`, so no instant lies between them. */
function inverted(notBefore: string | undefined, notAfter: string | undefined): boolean {
  return (
    notBefore !== undefined &&
    notAfter !== undefined &&
    compareInstants(instant(notBefore), instant(notAfter)) > 0
  );
}

/**
 * `time_window`: the action may be exercised only within the window,
 * evaluated at the point of use against a trusted clock. Both bounds are
 * inclusive; an absent bound is unbounded on its side, so a candidate that
 * omits a bound its reference carries is broader.
 *
 * @spec resource-access#entry-validation (#1376): a window whose
 * `not_before` is later than its `not_after` admits no instant and is
 * malformed, so intake refuses it, as do configuration load, derivation and
 * credential parsing, which read the same check. Equal bounds name one
 * instant and are valid.
 */
const TIME_WINDOW: Semantics = {
  valid: (v) => {
    if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
    const keys = Object.keys(v);
    if (keys.length === 0 || keys.some((k) => !WINDOW_MEMBERS.has(k))) return false;
    if (!keys.every((k) => parseRfc3339Instant((v as Record<string, unknown>)[k]) !== undefined)) {
      return false;
    }
    const w = v as Window;
    return !inverted(w.not_before, w.not_after);
  },
  noBroader: (c, r) => {
    const cw = c as Window;
    const rw = r as Window;
    if (rw.not_before !== undefined) {
      if (cw.not_before === undefined) return false;
      if (compareInstants(instant(cw.not_before), instant(rw.not_before)) < 0) return false;
    }
    if (rw.not_after !== undefined) {
      if (cw.not_after === undefined) return false;
      if (compareInstants(instant(cw.not_after), instant(rw.not_after)) > 0) return false;
    }
    return true;
  },
  // The overlap: the later not_before and the earlier not_after. An empty
  // overlap has no intersection. A valid window is never inverted, so one
  // carried from a single operand is never empty.
  intersect: (a, b) => {
    const aw = a as Window;
    const bw = b as Window;
    const notBefore = later(aw.not_before, bw.not_before);
    const notAfter = earlier(aw.not_after, bw.not_after);
    if (inverted(notBefore, notAfter)) return undefined;
    return {
      ...(notBefore !== undefined ? { not_before: notBefore } : {}),
      ...(notAfter !== undefined ? { not_after: notAfter } : {}),
    };
  },
  satisfied: (v, facts) => {
    if (typeof facts.now !== "number" || !Number.isFinite(facts.now)) return false;
    const now = instantFromMs(facts.now);
    const w = v as Window;
    if (w.not_before !== undefined && compareInstants(now, instant(w.not_before)) < 0) return false;
    if (w.not_after !== undefined && compareInstants(now, instant(w.not_after)) > 0) return false;
    return true;
  },
};

/** One DNS label: letters, digits and hyphens, not starting or ending with a hyphen. */
const DNS_LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

/** True for a DNS name of one or more letter-digit-hyphen labels (no trailing dot). */
function isDnsName(v: unknown): v is string {
  return typeof v === "string" && v.length <= 253 && v.split(".").every((l) => DNS_LABEL.test(l));
}

/**
 * Whether `name` equals `domain` or is a subdomain of it, compared
 * case-insensitively on whole labels: `mail.example.com` is within
 * `example.com`, and `notexample.com` is not.
 */
function withinDomain(name: string, domain: string): boolean {
  const n = name.toLowerCase();
  const d = domain.toLowerCase();
  return n === d || n.endsWith(`.${d}`);
}

/** The domain of a bare `local@domain` address, or `undefined` for anything else. */
function addressDomain(address: unknown): string | undefined {
  if (typeof address !== "string") return undefined;
  const at = address.indexOf("@");
  if (at <= 0 || at !== address.lastIndexOf("@")) return undefined;
  const domain = address.slice(at + 1);
  return isDnsName(domain) ? domain : undefined;
}

/**
 * `recipient_domain`: every recipient the action reaches is within the named
 * domain. Comparison is case-insensitive on whole DNS labels. An action with
 * no established recipient, or with any recipient that is not a bare address
 * or falls outside the domain, is refused.
 */
const RECIPIENT_DOMAIN: Semantics = {
  valid: isDnsName,
  noBroader: (c, r) => withinDomain(c as string, r as string),
  // The narrower value when one is within the other; otherwise none.
  intersect: (a, b) =>
    withinDomain(a as string, b as string)
      ? a
      : withinDomain(b as string, a as string)
        ? b
        : undefined,
  satisfied: (v, facts) => {
    const recipients = facts.recipients;
    if (!Array.isArray(recipients) || recipients.length === 0) return false;
    return recipients.every((r) => {
      const domain = addressDomain(r);
      return domain !== undefined && withinDomain(domain, v as string);
    });
  },
};

/** An array of non-empty strings; empty is allowed and admits nothing. */
function isLabelList(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === "string" && x.length > 0);
}

/** The members of `a` also in `b`, in `a`'s order, each once; `undefined` when none. */
function commonMembers(a: JsonValue, b: JsonValue): JsonValue | undefined {
  const inB = new Set(b as string[]);
  const out = [...new Set((a as string[]).filter((x) => inB.has(x)))];
  return out.length > 0 ? out : undefined;
}

/** The candidate's members are all among the reference's, compared as exact strings. */
function membersWithin(c: JsonValue, r: JsonValue): boolean {
  const inR = new Set(r as string[]);
  return (c as string[]).every((x) => inR.has(x));
}

/**
 * `data_classification`: the action applies only to data whose
 * classification label is among the named values, compared as exact strings.
 * Every label the operation touches must be named; data with no established
 * label is refused. An empty list admits no data.
 */
const DATA_CLASSIFICATION: Semantics = {
  valid: isLabelList,
  noBroader: membersWithin,
  // The common members; an empty result has no intersection.
  intersect: commonMembers,
  empty: (v) => (v as string[]).length === 0,
  satisfied: (v, facts) => {
    const labels = facts.dataClassification;
    if (!Array.isArray(labels) || labels.length === 0) return false;
    const allowed = new Set(v as string[]);
    return labels.every((l) => typeof l === "string" && allowed.has(l));
  },
};

/**
 * `allowed_tools`: the action may be exercised only through a tool whose
 * identity is among the named values, compared as exact strings. An empty
 * list admits no tool; an operation with no established tool identity is
 * refused.
 */
const ALLOWED_TOOLS: Semantics = {
  valid: isLabelList,
  noBroader: membersWithin,
  // The common members; an empty result has no intersection.
  intersect: commonMembers,
  empty: (v) => (v as string[]).length === 0,
  satisfied: (v, facts) => typeof facts.tool === "string" && (v as string[]).includes(facts.tool),
};

const SEMANTICS = {
  resource_issued_after: RESOURCE_ISSUED_AFTER,
  resource_issued_before: RESOURCE_ISSUED_BEFORE,
  tenant: TENANT,
  time_window: TIME_WINDOW,
  recipient_domain: RECIPIENT_DOMAIN,
  data_classification: DATA_CLASSIFICATION,
  allowed_tools: ALLOWED_TOOLS,
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
    // A key on one operand only meets an unbounded other side: the result is
    // that operand's value, which may itself admit nothing.
    const v =
      av === undefined || bv === undefined
        ? ((av ?? bv) as JsonValue)
        : s.intersect(av as JsonValue, bv as JsonValue);
    if (v === undefined || ("empty" in s && s.empty?.(v))) {
      return { ok: false, key, reason: `${key} values have no intersection` };
    }
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

/**
 * @spec resource-access#initial-common-constraints (#1266): the Common
 * Constraints whose input is a fact of the resource the operation acts on:
 * its issuance instant, its tenant, and the classification of its data. For
 * an operation over a collection, each member is a resource the operation
 * acts on, so each is evaluated with its own facts.
 */
export const MEMBER_FACT_CONSTRAINTS: readonly CommonConstraintKey[] = Object.freeze([
  "resource_issued_after",
  "resource_issued_before",
  "tenant",
  "data_classification",
]);

/**
 * One member of a collection as an enforcement point establishes it from its
 * own records: `id`, and each fact the record holds. A fact the record does
 * not hold is absent.
 */
export interface CollectionMemberFacts {
  id: string;
  issued_at?: string;
  tenant?: string;
  data_classification?: string;
}

const MEMBER_FIELDS = new Set(["id", "issued_at", "tenant", "data_classification"]);

/**
 * Read one collection member as {@link ConstraintFacts}: an object whose `id`
 * is a non-empty string and whose other members, each optional, are strings.
 * Anything else is unreadable and returns `undefined`, never a member with
 * the unreadable fact silently absent.
 */
export function collectionMemberConstraintFacts(member: unknown): ConstraintFacts | undefined {
  if (member === null || typeof member !== "object" || Array.isArray(member)) return undefined;
  const m = member as Record<string, unknown>;
  if (Object.keys(m).some((k) => !MEMBER_FIELDS.has(k))) return undefined;
  if (typeof m.id !== "string" || m.id.length === 0) return undefined;
  for (const k of ["issued_at", "tenant", "data_classification"]) {
    if (m[k] !== undefined && typeof m[k] !== "string") return undefined;
  }
  return {
    ...(typeof m.issued_at === "string" ? { resourceIssuedAt: m.issued_at } : {}),
    ...(typeof m.tenant === "string" ? { tenant: m.tenant } : {}),
    ...(typeof m.data_classification === "string" ? { dataClassification: [m.data_classification] } : {}),
  };
}

/**
 * @spec resource-access#common-constraints, #initial-common-constraints
 * (#1266): {@link commonConstraintGates} for an operation over a collection.
 * `members` is each member's own facts; `facts` carries what the whole
 * operation shares (the clock, the dispatched tool, the recipients), and any
 * single-resource fact it carries is not read here. The entry provides
 * authority only when every member satisfies every gate: a member whose fact
 * is missing, malformed or outside the bound denies the whole operation,
 * never narrows it to the members that pass. An empty collection establishes
 * no member fact, so a bound that reads one is not satisfied. Absent
 * `members`, the operation acts on one resource and `facts` is read whole.
 */
export function commonConstraintGatesOverMembers(
  constraints: Constraints,
  facts: ConstraintFacts,
  members: readonly ConstraintFacts[] | undefined,
): CommonConstraintTrace {
  if (members === undefined) return commonConstraintGates(constraints, facts);
  const {
    resourceIssuedAt: _issued,
    tenant: _tenant,
    dataClassification: _labels,
    ...shared
  } = facts;
  if (members.length === 0) return commonConstraintGates(constraints, shared);
  const evaluated: CommonConstraintKey[] = [];
  for (const member of members) {
    const trace = commonConstraintGates(constraints, { ...shared, ...member });
    for (const key of trace.evaluated) if (!evaluated.includes(key)) evaluated.push(key);
    if (!trace.satisfied) return { satisfied: false, evaluated };
  }
  return { satisfied: true, evaluated };
}

/**
 * @spec resource-access#initial-common-constraints (`time_window`, "evaluated
 * at the point of use"): the last epoch millisecond at or before an entry's
 * `time_window.not_after`, or `undefined` when the entry carries no upper
 * bound. A permit issued under the entry is valid no later than this, so a
 * permit relied on later, a retransmitted one or an execution lease derived
 * from it, cannot carry authority past the window.
 */
export function timeWindowEndMs(constraints: Constraints): number | undefined {
  const w = constraints?.time_window;
  if (w === undefined || !TIME_WINDOW.valid(w)) return undefined;
  const notAfter = (w as Window).not_after;
  return notAfter === undefined ? undefined : instantFloorMs(instant(notAfter));
}
