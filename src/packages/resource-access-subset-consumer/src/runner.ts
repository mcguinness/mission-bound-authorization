// Running mission-resource-access-cases/1 vectors
// (vectors/mission-resource-access/README.md, Format and Checks).

import {
  type ConsumerConfig,
  contractApprovalRefusal,
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
  const parsed = parseEntry(entry, true);
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

/** Run one selected case. */
export function runCase(c: VectorCase, config: ConsumerConfig): CaseResult {
  const input = c.input;
  switch (c.check) {
    case "subset":
      return subsetCheck(input.candidate, input.reference);
    case "entry-validation":
      return entryValidationCheck(input.entry, config);
    case "resource-match":
      return resourceMatchCheck(input);
    case "target-resolution":
      return resolveTarget(input);
    default:
      throw new Error(`check ${c.check} is not implemented`);
  }
}
