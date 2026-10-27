/**
 * @spec AAT -02 Sections 3.3, 3.4 and 4.5 (#1756): argument constraints of
 * Attenuating Agent Tokens, read losslessly ({@link AatJson}). Well-formedness,
 * the `check` predicate an enforcement point evaluates at the leaf, the
 * structural subsumption relation `child ⊑ parent` chain verification
 * evaluates at every link, and the constraint-map key rules for `optional`
 * and the `"*"` entry.
 *
 * Supported subset: every core type of Table 2 (exact, range, one_of,
 * not_one_of, contains, subset, wildcard, all, any). No extension type is
 * implemented, so any other `constraint_type` is not well-formed here and
 * fails closed (Section 5.2).
 */

import {
  AatJcsError,
  type AatJson,
  AatNumber,
  type AatObject,
  allNumbersAdmissible,
  isAatObject,
  jcs,
} from "./aat-json.js";

/** The members each core type defines (Table 2), beside `constraint_type` and a top-level `optional`. */
// A Map, not an object literal: a `constraint_type` such as "constructor",
// "__proto__" or "toString" must not resolve through Object.prototype (#1775 review).
const TYPE_MEMBERS: ReadonlyMap<string, readonly string[]> = new Map([
  ["exact", ["value"]],
  ["range", ["min", "max", "min_inclusive", "max_inclusive"]],
  ["one_of", ["values"]],
  ["not_one_of", ["excluded"]],
  ["contains", ["required"]],
  ["subset", ["allowed"]],
  ["wildcard", []],
  ["all", ["constraints"]],
  ["any", ["constraints"]],
]);

export const AAT_SUPPORTED_CONSTRAINT_TYPES: readonly string[] = [...TYPE_MEMBERS.keys()];

const has = (o: AatObject, k: string): boolean => Object.hasOwn(o, k);
const typeOf = (c: AatObject): string => c.constraint_type as string;

/**
 * @spec AAT -02 Section 3.4 (well-formed) and Section 3.3 (`optional`): why
 * constraint `c` is not well-formed, or undefined. `level` is its nesting
 * level (1 for a constraint-map entry); a tree deeper than `maxDepth` is
 * refused (MAX_CONSTRAINT_DEPTH), and an `all` or `any` with an empty
 * `constraints` array is refused with it (Section 8 steps 3n and 4o).
 */
export function constraintProblem(c: AatJson, level: number, maxDepth: number): string | undefined {
  if (level > maxDepth) return "constraint tree deeper than MAX_CONSTRAINT_DEPTH";
  if (!isAatObject(c)) return "constraint is not an object";
  const type = c.constraint_type;
  if (typeof type !== "string") return "constraint_type is not a string";
  const members = TYPE_MEMBERS.get(type);
  if (!members) return `unsupported constraint_type ${JSON.stringify(type)}`;
  for (const k of Object.keys(c)) {
    if (k === "constraint_type") continue;
    if (k === "optional") {
      if (level !== 1) return "optional on a nested constraint";
      if (typeof c.optional !== "boolean") return "optional is not a boolean";
      continue;
    }
    if (!members.includes(k)) return `member ${JSON.stringify(k)} is not defined for ${type}`;
  }
  if (!allNumbersAdmissible(c)) return "constraint carries a number that is not admissible";
  switch (type) {
    case "exact": {
      const v = c.value;
      if (
        !(typeof v === "string" || typeof v === "boolean" || v === null || v instanceof AatNumber)
      ) {
        return "exact.value is not a string, number, boolean or null";
      }
      return undefined;
    }
    case "range": {
      for (const bound of ["min", "max"] as const) {
        if (has(c, bound) && !(c[bound] instanceof AatNumber))
          return `range ${bound} is not a number`;
        const flag = `${bound}_inclusive`;
        if (has(c, flag)) {
          if (!has(c, bound)) return `range ${flag} without ${bound}`;
          if (typeof c[flag] !== "boolean") return `range ${flag} is not a boolean`;
        }
      }
      if (c.min instanceof AatNumber && c.max instanceof AatNumber && c.min.value > c.max.value) {
        return "range min is greater than max";
      }
      return undefined;
    }
    case "one_of":
      return Array.isArray(c.values) && c.values.length > 0
        ? undefined
        : "one_of.values is not a non-empty array";
    case "not_one_of":
      return Array.isArray(c.excluded) ? undefined : "not_one_of.excluded is not an array";
    case "contains":
      return Array.isArray(c.required) ? undefined : "contains.required is not an array";
    case "subset":
      return Array.isArray(c.allowed) ? undefined : "subset.allowed is not an array";
    case "all":
    case "any": {
      const clauses = c.constraints;
      if (!Array.isArray(clauses)) return `${type}.constraints is not an array`;
      if (clauses.length === 0) return `${type} with an empty constraints array`;
      for (const clause of clauses) {
        const p = constraintProblem(clause, level + 1, maxDepth);
        if (p) return p;
      }
      return undefined;
    }
    default:
      return undefined;
  }
}

/**
 * @spec AAT -02 Sections 3.3 and 3.4: why a tool's constraint map is not
 * well-formed, or undefined. Every entry is well-formed, and a `"*"` entry is
 * a wildcard with no `optional` member.
 */
export function constraintMapProblem(map: AatObject, maxDepth: number): string | undefined {
  for (const [arg, c] of Object.entries(map)) {
    const p = constraintProblem(c, 1, maxDepth);
    if (p) return `${JSON.stringify(arg)}: ${p}`;
    if (arg === "*" && isAatObject(c) && (typeOf(c) !== "wildcard" || has(c, "optional"))) {
      return 'the "*" entry is not a wildcard without optional';
    }
  }
  return undefined;
}

/** @spec AAT -02 Section 3.3: an empty constraint map is `{"*": wildcard}`. */
export function normalizeConstraintMap(map: AatObject): AatObject {
  if (Object.keys(map).length > 0) return map;
  const wildcard = Object.create(null) as AatObject;
  wildcard.constraint_type = "wildcard";
  const out = Object.create(null) as AatObject;
  out["*"] = wildcard;
  return out;
}

const isOptional = (c: AatJson | undefined): boolean => isAatObject(c) && c.optional === true;
const member = (set: readonly AatJson[], v: AatJson): boolean => {
  const k = jcs(v);
  return set.some((x) => jcs(x) === k);
};

/** @spec AAT -02 Section 3.4 (Table 2): `arg` satisfies well-formed constraint `c`. */
export function constraintChecks(c: AatObject, arg: AatJson): boolean {
  switch (typeOf(c)) {
    case "exact":
      return jcs(arg) === jcs(c.value as AatJson);
    case "range": {
      if (!(arg instanceof AatNumber)) return false;
      const x = arg.value;
      if (c.min instanceof AatNumber) {
        const inclusive = c.min_inclusive !== false;
        if (inclusive ? x < c.min.value : x <= c.min.value) return false;
      }
      if (c.max instanceof AatNumber) {
        const inclusive = c.max_inclusive !== false;
        if (inclusive ? x > c.max.value : x >= c.max.value) return false;
      }
      return true;
    }
    case "one_of":
      return member(c.values as AatJson[], arg);
    case "not_one_of":
      return !member(c.excluded as AatJson[], arg);
    case "contains":
      return Array.isArray(arg) && (c.required as AatJson[]).every((r) => member(arg, r));
    case "subset":
      return Array.isArray(arg) && arg.every((a) => member(c.allowed as AatJson[], a));
    case "wildcard":
      return true;
    case "all":
      return (c.constraints as AatObject[]).every((clause) => constraintChecks(clause, arg));
    case "any":
      return (c.constraints as AatObject[]).some((clause) => constraintChecks(clause, arg));
    default:
      return false; // fail closed: not a supported type
  }
}

/**
 * @spec AAT -02 Section 4.5 (range): a derived bound is at least as tight as
 * the parent's. A missing parent bound is unbounded; a missing derived bound
 * is valid only under a missing parent bound; at an equal bound the derived
 * one is inclusive only where the parent's is.
 */
function boundTighter(
  parent: AatJson | undefined,
  parentInclusive: boolean,
  child: AatJson | undefined,
  childInclusive: boolean,
  dir: "min" | "max",
): boolean {
  if (!(parent instanceof AatNumber)) return true;
  if (!(child instanceof AatNumber)) return false;
  const p = parent.value;
  const c = child.value;
  if (dir === "min" ? c > p : c < p) return true;
  if (c !== p) return false;
  return parentInclusive || !childInclusive;
}

/**
 * @spec AAT -02 Section 4.5 (Table 4): `child ⊑ parent`, for well-formed
 * constraints, comparing them without `optional`. Every pair the table does
 * not list is invalid.
 */
export function constraintSubsumes(parent: AatObject, child: AatObject): boolean {
  const pt = typeOf(parent);
  const ct = typeOf(child);
  if (pt === "wildcard") return true;
  switch (pt) {
    case "exact":
      return ct === "exact" && jcs(child.value as AatJson) === jcs(parent.value as AatJson);
    case "range":
      if (ct === "exact")
        return child.value instanceof AatNumber && constraintChecks(parent, child.value);
      return (
        ct === "range" &&
        boundTighter(
          parent.min,
          parent.min_inclusive !== false,
          child.min,
          child.min_inclusive !== false,
          "min",
        ) &&
        boundTighter(
          parent.max,
          parent.max_inclusive !== false,
          child.max,
          child.max_inclusive !== false,
          "max",
        )
      );
    case "one_of":
      if (ct === "exact") return member(parent.values as AatJson[], child.value as AatJson);
      return (
        ct === "one_of" &&
        (child.values as AatJson[]).length > 0 &&
        (child.values as AatJson[]).every((v) => member(parent.values as AatJson[], v))
      );
    case "not_one_of":
      return (
        ct === "not_one_of" &&
        (parent.excluded as AatJson[]).every((v) => member(child.excluded as AatJson[], v))
      );
    case "contains":
      return (
        ct === "contains" &&
        (parent.required as AatJson[]).every((v) => member(child.required as AatJson[], v))
      );
    case "subset":
      return (
        ct === "subset" &&
        (child.allowed as AatJson[]).every((v) => member(parent.allowed as AatJson[], v))
      );
    case "all":
      // Every parent clause subsumes at least one derived clause; one derived
      // clause may satisfy several parent clauses.
      return (
        ct === "all" &&
        (parent.constraints as AatObject[]).every((cp) =>
          (child.constraints as AatObject[]).some((cd) => constraintSubsumes(cp, cd)),
        )
      );
    case "any":
      // Every derived clause is subsumed by one parent clause, never by a union of them.
      return (
        ct === "any" &&
        (child.constraints as AatObject[]).every((cd) =>
          (parent.constraints as AatObject[]).some((cp) => constraintSubsumes(cp, cd)),
        )
      );
    default:
      return false;
  }
}

/**
 * @spec AAT -02 Section 4.5 and Section 8 steps 4p2 to 4p4: why a derived
 * tool's constraint map does not attenuate its parent's, or undefined. Both
 * maps are normalized first.
 */
export function constraintMapAttenuationProblem(
  parentMap: AatObject,
  childMap: AatObject,
): string | undefined {
  const parent = normalizeConstraintMap(parentMap);
  const child = normalizeConstraintMap(childMap);
  const parentStar = has(parent, "*");
  const childStar = has(child, "*");
  for (const k of Object.keys(child)) {
    if (k !== "*" && !has(parent, k) && !parentStar)
      return `4p2: names ${JSON.stringify(k)}, which the parent neither names nor admits`;
  }
  for (const k of Object.keys(parent)) {
    if (k === "*" || has(child, k)) continue;
    if (!isOptional(parent[k])) return `4p2: omits ${JSON.stringify(k)}, which the parent requires`;
    if (childStar) return `4p2: omits optional ${JSON.stringify(k)} but keeps "*"`;
  }
  if (childStar && !parentStar) return '4p2: adds "*", which the parent does not have';
  for (const k of Object.keys(child)) {
    if (k !== "*" && has(parent, k) && !isOptional(parent[k]) && isOptional(child[k])) {
      return `4p3: makes required ${JSON.stringify(k)} optional`;
    }
  }
  for (const [k, c] of Object.entries(child)) {
    const p = k !== "*" && has(parent, k) ? parent[k] : parent["*"];
    let subsumed: boolean;
    try {
      subsumed = isAatObject(p) && isAatObject(c) && constraintSubsumes(p, c);
    } catch (e) {
      if (!(e instanceof AatJcsError)) throw e;
      return `4p4: the constraint on ${JSON.stringify(k)} carries a string JCS cannot canonicalize`;
    }
    if (!subsumed)
      return `4p4: the constraint on ${JSON.stringify(k)} does not attenuate its parent's`;
  }
  return undefined;
}

/**
 * @spec AAT -02 Section 3.3 and Section 8 step 6b: why `args` fails the
 * tool's constraint map in closed-world mode, or undefined. An argument the
 * map does not name is admitted only by its `"*"` entry (an argument named
 * `"*"` is unnamed), and every named argument without `optional` is required.
 */
export function constraintMapCheckProblem(map: AatObject, args: AatObject): string | undefined {
  const m = normalizeConstraintMap(map);
  for (const [name, value] of Object.entries(args)) {
    const c = name !== "*" && has(m, name) ? m[name] : has(m, "*") ? m["*"] : undefined;
    if (!isAatObject(c)) return `argument ${JSON.stringify(name)} is not admitted (closed world)`;
    let satisfied: boolean;
    try {
      satisfied = constraintChecks(c, value);
    } catch (e) {
      if (!(e instanceof AatJcsError)) throw e;
      return `argument ${JSON.stringify(name)} carries a string JCS cannot canonicalize`;
    }
    if (!satisfied) return `argument ${JSON.stringify(name)} violates its constraint`;
  }
  for (const [name, c] of Object.entries(m)) {
    if (name !== "*" && !isOptional(c) && !has(args, name))
      return `required argument ${JSON.stringify(name)} is absent`;
  }
  return undefined;
}
