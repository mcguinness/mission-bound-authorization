// Running mission-resource-access-cases/1 vectors
// (vectors/mission-resource-access/README.md, Format and Checks).

import {
  type ConsumerConfig,
  type ContractDefinition,
  type CurrentContract,
  contractApprovalRefusal,
  parseContractReference,
  parseEntry,
  REFUSAL_ERROR,
} from "./entry.js";
import { resolveTarget, resourceMatchCheck } from "./matching.js";
import { subsetCheck } from "./subset.js";

/** One case, as the README's Format table defines it. */
export interface VectorCase {
  readonly id: string;
  readonly description?: string;
  readonly role?: string;
  readonly requires: readonly string[];
  readonly unless?: readonly string[];
  readonly check: string;
  readonly input: Record<string, unknown>;
  readonly expected: {
    readonly outcome: string;
    readonly reason?: string;
    readonly error?: string;
    readonly entries?: unknown;
  };
  readonly refs?: readonly string[];
}

/** The checks this consumer implements. */
export const IMPLEMENTED_CHECKS: readonly string[] = [
  "subset",
  "entry-validation",
  "resource-match",
  "target-resolution",
];

/** Checks this consumer scopes out, with the reason. */
export const SCOPED_OUT_CHECKS: ReadonlyMap<string, string> = new Map([
  [
    "derive",
    "derive encodes the OAuth binding derivation as well as Resource Access semantics; this Resource Access consumer scopes it out (vectors README, Checks)",
  ],
]);

export type Selection =
  | { readonly run: true }
  | {
      readonly run: false;
      readonly reason:
        | "missing-capability"
        | "inapplicable"
        | "scoped-out"
        | "check-not-implemented";
      readonly detail: string;
    };

/**
 * The README's applicability rule: "It runs a case when it implements every
 * capability in requires and none in unless. Otherwise it reports the case as
 * skipped, naming the missing capability or the implemented one that makes
 * the case inapplicable." A case the capabilities select is then run only
 * when this consumer implements its check.
 */
export function selectCase(c: VectorCase, declared: ReadonlySet<string>): Selection {
  const missing = c.requires.filter((cap) => !declared.has(cap));
  if (missing.length > 0)
    return { run: false, reason: "missing-capability", detail: missing.join(", ") };
  const blocking = (c.unless ?? []).filter((cap) => declared.has(cap));
  if (blocking.length > 0)
    return { run: false, reason: "inapplicable", detail: blocking.join(", ") };
  const scoped = SCOPED_OUT_CHECKS.get(c.check);
  if (scoped !== undefined) return { run: false, reason: "scoped-out", detail: scoped };
  if (!IMPLEMENTED_CHECKS.includes(c.check)) {
    return { run: false, reason: "check-not-implemented", detail: c.check };
  }
  return { run: true };
}

export interface CaseResult {
  readonly outcome: string;
  readonly error?: string;
  /** Explanatory only; never compared. */
  readonly reason: string;
}

/**
 * The entry-validation check: the intake of one proposed entry, before any
 * approval (resource-access#entry-validation, resource-access#resource-contract
 * Approval).
 */
export function entryValidationCheck(entry: unknown, config: ConsumerConfig): CaseResult {
  const parsed = parseEntry(entry);
  if (!parsed.ok) {
    return {
      outcome: "refuse",
      error: REFUSAL_ERROR,
      reason: parsed.unsupported ? `unsupported input: ${parsed.reason}` : parsed.reason,
    };
  }
  const contractRefusal = contractApprovalRefusal(parsed.entry, config);
  if (contractRefusal !== undefined) {
    return { outcome: "refuse", error: REFUSAL_ERROR, reason: contractRefusal };
  }
  return { outcome: "valid", reason: "admitted at proposal intake" };
}

/**
 * An entry-validation case's `contracts` (vectors README, Format and Checks,
 * `entry-validation`): the authorization server's trusted configuration, a
 * list of objects, each a `resource` and the `reference` of the contract
 * version configuration names as current for exactly that resource. An absent
 * `contracts` names no contract current for any resource. Configuration is
 * trusted input, so a malformed one is a malformed case and throws.
 */
export function parseCurrentContracts(value: unknown): readonly CurrentContract[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error("contracts is not an array");
  return value.map((item: unknown, i) => {
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      throw new Error(`contracts[${i}] is not an object`);
    }
    const members = Object.keys(item);
    if (members.length !== 2 || !members.includes("resource") || !members.includes("reference")) {
      throw new Error(`contracts[${i}] does not have exactly the members resource and reference`);
    }
    const { resource, reference } = item as { resource: unknown; reference: unknown };
    if (typeof resource !== "string") throw new Error(`contracts[${i}].resource is not a string`);
    const parsed = parseContractReference(reference);
    if ("refusal" in parsed) throw new Error(`contracts[${i}].reference: ${parsed.refusal}`);
    return { resource, reference: parsed.contract };
  });
}

/**
 * Run one selected case. `definitions` are the contract versions whose
 * documents the consumer holds; which version is current for which resource
 * comes from the case alone.
 */
export function runCase(c: VectorCase, definitions: readonly ContractDefinition[]): CaseResult {
  const input = c.input;
  switch (c.check) {
    case "subset":
      return subsetCheck(input.candidate, input.reference);
    case "entry-validation":
      return entryValidationCheck(input.entry, {
        currentContracts: parseCurrentContracts(input.contracts),
        definitions,
      });
    case "resource-match":
      return resourceMatchCheck(input);
    case "target-resolution":
      return resolveTarget(input);
    default:
      throw new Error(`check ${c.check} is not implemented`);
  }
}
