// The Subset Rule (resource-access#subset), steps 1 to 4, over the supported
// subset: exact resources, explicit actions, the nine initial Common
// Constraints and resource_contract.

import { CONSTRAINT_RULES } from "./constraints.js";
import { type ParsedEntry, parseEntry } from "./entry.js";

export interface SubsetResult {
  readonly outcome: "subset" | "not-subset";
  readonly reason: string;
}

function notSubset(reason: string): SubsetResult {
  return { outcome: "not-subset", reason };
}

/**
 * Whether candidate A is a subset of reference B.
 *
 * The check has two outcomes, so input this consumer cannot compare (an entry
 * outside the subset, such as a prefix entry, an action family or a
 * constraints key outside the nine, or an entry that fails validation, such
 * as a malformed decimal) fails closed as not-subset: containment is never
 * established from input the consumer does not implement
 * (resource-access#subset: "When A carries a key whose narrowing the
 * authorization server does not implement, the authorization server refuses
 * the derivation").
 */
export function subsetCheck(candidate: unknown, reference: unknown): SubsetResult {
  const a = parseEntry(candidate, false);
  if (!a.ok) return notSubset(`candidate not comparable: ${a.reason}`);
  const b = parseEntry(reference, false);
  if (!b.ok) return notSubset(`reference not comparable: ${b.reason}`);
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
    if (rule === undefined) return notSubset(`step 3: ${key} has no implemented subset rule`);
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
      return notSubset(`step 3: the candidate ${key} is broader than the reference`);
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
