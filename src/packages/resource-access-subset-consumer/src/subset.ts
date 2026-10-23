// The Subset Rule (resource-access#subset), steps 1 to 4, over the supported
// subset: exact resources, explicit actions, the nine initial Common
// Constraints and resource_contract.

import { CONSTRAINT_RULES } from "./constraints.js";
import { type ParsedEntry, type ParseResult, parseEntry } from "./entry.js";

/**
 * The three outcomes of the subset check (vectors/mission-resource-access
 * README, Checks, `subset`, D727). `refuse` is a case outcome, not a protocol
 * response, so it carries no `error`: the OAuth error a protocol surface
 * answers for the same input is that surface's (entry-validation).
 */
export interface SubsetResult {
  readonly outcome: "subset" | "not-subset" | "refuse";
  readonly reason: string;
}

function notSubset(reason: string): SubsetResult {
  return { outcome: "not-subset", reason };
}

function refuse(reason: string): SubsetResult {
  return { outcome: "refuse", reason };
}

function failure(operand: string, parsed: ParseResult): string | undefined {
  if (parsed.ok) return undefined;
  const kind = parsed.unsupported ? "unsupported input" : "invalid input";
  return `${operand}: ${kind}: ${parsed.reason}`;
}

/**
 * Whether candidate A is a subset of reference B.
 *
 * Both operands are validated before any comparison result is returned, so
 * an obvious mismatch (different resources, disjoint actions, different
 * currencies) never conceals unsupported or malformed input in either operand
 * (vectors README, Checks, `subset`). Input this consumer cannot compare is
 * refused, never compared as absent or as narrowing:
 *
 * - input outside the subset (a prefix entry, an action family, an entry
 *   member outside the subset, a constraints key outside the nine) is
 *   unsupported input: "an unsupported constraint is unsupported input, so
 *   the entry is never omitted to repair it" (resource-access#common-constraints);
 * - an invalid value (a decimal outside the grammar, a currency that is not
 *   exactly three upper-case ASCII letters, an inverted window, a malformed
 *   resource_contract) is rejected "rather than attempt to parse it"
 *   (resource-access#decimal-values, resource-access#initial-common-constraints,
 *   resource-access#entry-validation); and
 * - an entry carrying locations is refused by name
 *   (resource-access#entry-validation).
 *
 * `not-subset` is returned only for valid, supported inputs that fail the
 * relation, which they can do without the candidate being broader (disjoint
 * actions, or different currencies).
 */
export function subsetCheck(candidate: unknown, reference: unknown): SubsetResult {
  const a = parseEntry(candidate, false);
  const b = parseEntry(reference, false);
  const failures = [failure("candidate", a), failure("reference", b)].filter(
    (f): f is string => f !== undefined,
  );
  if (!a.ok || !b.ok) return refuse(`not comparable: ${failures.join("; ")}`);
  return compare(a.entry, b.entry);
}

function compare(a: ParsedEntry, b: ParsedEntry): SubsetResult {
  // resource-access#subset step 1: "an exact A under an exact B: A.resource
  // equals B.resource literally". Both are exact: parseEntry refuses prefix.
  // The values are already JSON-decoded strings; no normalization applies
  // (resource-access#resource-matching, Exact matching).
  if (a.resource !== b.resource) return notSubset("step 1: the exact resources differ");

  // resource-access#subset step 2: "Every A.actions value is within some
  // B.actions value": with explicit actions only, "a value is within an equal
  // value".
  const outside = a.actions.find((action) => !b.actions.includes(action));
  if (outside !== undefined)
    return notSubset(`step 2: the action ${outside} is not in the reference`);

  // resource-access#subset step 3: "For every key K in B.constraints".
  for (const [key, referenceValue] of b.constraints) {
    const rule = CONSTRAINT_RULES.get(key);
    // parseEntry admits only keys with a rule, so this is unreachable; a key
    // without one could not be compared, which is a refusal, not a result.
    if (rule === undefined) return refuse(`step 3: ${key} has no implemented subset rule`);
    if (!a.constraints.has(key)) {
      // "K MUST also be present in A.constraints, unless B's value is one K's
      // definition makes equivalent to omitting the member
      // (requires_action_approval: false). Otherwise a key absent from A is
      // treated as the broadest possible value and therefore fails this test."
      if (rule.omissionEquivalent(referenceValue)) continue;
      return notSubset(`step 3: the candidate omits ${key}`);
    }
    // "A's value MUST be no broader than B's under K's subset rule".
    if (!rule.noBroader(a.constraints.get(key), referenceValue)) {
      return notSubset(`step 3: the candidate ${key} is not within the reference`);
    }
  }
  // A key present only in A narrows A: every key parseEntry admits is one of
  // the nine, each with defined semantics (resource-access#subset, after the
  // steps: "A key present only in A narrows A only when it has defined
  // semantics").

  // resource-access#subset step 4: "A carries resource_contract exactly when B
  // does, and then with id, version, and digest each equal to B's". Compared
  // member for member; no digest is recomputed. The approval exception
  // belongs to derivation against a policy ceiling, not to this comparison.
  const ac = a.contract;
  const bc = b.contract;
  if (ac === undefined && bc !== undefined)
    return notSubset("step 4: the candidate removes resource_contract");
  if (ac !== undefined && bc === undefined)
    return notSubset("step 4: the candidate adds resource_contract");
  if (ac !== undefined && bc !== undefined) {
    if (ac.id !== bc.id || ac.version !== bc.version || ac.digest !== bc.digest) {
      return notSubset("step 4: the candidate replaces resource_contract");
    }
  }

  return { outcome: "subset", reason: "steps 1 to 4 hold" };
}
