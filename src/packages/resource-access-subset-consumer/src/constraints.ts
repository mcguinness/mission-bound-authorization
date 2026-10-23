// The nine initial Common Constraints (resource-access#initial-common-constraints,
// resource-access#iana-common-constraints), each with its value syntax, the
// validity rules resource-access#entry-validation adds, its subset rule, and
// its omission-equivalent value. Comparisons are in value space
// (resource-access#value-space-comparison).
//
// Intersection rules are not implemented: they serve derivation (`derive`),
// which this consumer scopes out.

import { compareDecimal, type DecimalValue, parseDecimal } from "./decimal.js";
import { isValidRecipientDomain, isWithinDomain } from "./dns.js";
import { compareInstant, type Instant, parseInstant } from "./instant.js";

/** One Common Constraint's rules. Method syntax keeps the map assignable. */
export interface ConstraintRule<T> {
  /** Value syntax and validity: the parsed value, or a refusal reason. */
  parse(value: unknown): { value: T } | { refusal: string };
  /** Subset rule: whether candidate is no broader than reference. */
  noBroader(candidate: T, reference: T): boolean;
  /** Whether the value is equivalent to omitting the member (resource-access#subset step 3). */
  omissionEquivalent(value: T): boolean;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyMembers(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Object.keys(value).every((k) => allowed.includes(k));
}

function stringArray(value: unknown): readonly string[] | undefined {
  if (!Array.isArray(value) || !value.every((v) => typeof v === "string")) return undefined;
  return value as string[];
}

const never = (): boolean => false;

interface Amount {
  readonly amount: DecimalValue;
  readonly currency: string;
}

const UPPER_A = 0x41;
const UPPER_Z = 0x5a;

/**
 * Whether a value is a well-formed max_amount currency
 * (resource-access#initial-common-constraints max_amount, Currency): "exactly
 * three characters, each an upper-case ASCII letter (A to Z)". "A value of any
 * other length, one ending in a line terminator included, or carrying any
 * other character is malformed." The test is stated by length and by
 * character, with no pattern whose end anchor could admit a trailing line
 * terminator. `length` counts UTF-16 code units, which here are characters:
 * every admitted unit is an ASCII letter, so a non-ASCII character fails the
 * character test and one outside the Basic Multilingual Plane fails the
 * length test or the character test. Whether ISO 4217 assigns the code is not
 * tested: "A well-formed value is admitted for comparison whether or not ISO
 * 4217 assigns it".
 */
export function isCurrencyCode(value: unknown): value is string {
  if (typeof value !== "string" || value.length !== 3) return false;
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit < UPPER_A || unit > UPPER_Z) return false;
  }
  return true;
}

// resource-access#initial-common-constraints max_amount: "an object with two
// members, amount (REQUIRED, a string containing a decimal number) and
// currency (REQUIRED, a currency code, as the next item defines it)".
const maxAmount: ConstraintRule<Amount> = {
  parse(value) {
    if (!isObject(value) || !hasOnlyMembers(value, ["amount", "currency"])) {
      return { refusal: "max_amount is an object with the members amount and currency only" };
    }
    // resource-access#decimal-values: a malformed decimal is refused, never parsed.
    const amount = parseDecimal(value.amount);
    if (amount === undefined) return { refusal: "max_amount.amount is not a decimal string" };
    // Currency: a malformed value is refused at proposal intake with
    // invalid_authorization_details, and, being invalid input, makes a subset
    // comparison refuse. It is never trimmed or case-folded into a valid one.
    const currency = value.currency;
    if (!isCurrencyCode(currency)) {
      return { refusal: "max_amount.currency is not exactly three upper-case ASCII letters" };
    }
    return { value: { amount, currency } };
  },
  // "no broader when the currency values are equal and the candidate amount is
  // less than or equal to the reference amount, compared in decimal value
  // space; differing currencies fail the comparison". Currency: "Values are
  // compared exactly, character for character, with no trimming, case
  // folding, numeric code, or conversion."
  noBroader: (c, r) => c.currency === r.currency && compareDecimal(c.amount, r.amount) <= 0,
  omissionEquivalent: never,
};

function instantRule(name: string, laterIsNarrower: boolean): ConstraintRule<Instant> {
  return {
    parse(value) {
      const instant = parseInstant(value);
      return instant === undefined
        ? { refusal: `${name} is not an RFC 3339 date-time` }
        : { value: instant };
    },
    noBroader: (c, r) => (laterIsNarrower ? compareInstant(c, r) >= 0 : compareInstant(c, r) <= 0),
    omissionEquivalent: never,
  };
}

// resource_issued_after: "no broader when greater than or equal to the reference".
const resourceIssuedAfter = instantRule("resource_issued_after", true);
// resource_issued_before: "no broader when less than or equal to the reference".
const resourceIssuedBefore = instantRule("resource_issued_before", false);

// tenant: "a string"; "no broader when equal to the reference value", an exact
// string comparison (no case folding is defined for it).
const tenant: ConstraintRule<string> = {
  parse: (value) => (typeof value === "string" ? { value } : { refusal: "tenant is not a string" }),
  noBroader: (c, r) => c === r,
  omissionEquivalent: never,
};

// recipient_domain: "a string containing a DNS name"; validity per
// resource-access#entry-validation; "no broader when equal to the reference
// or a DNS subdomain of it".
const recipientDomain: ConstraintRule<string> = {
  parse: (value) =>
    isValidRecipientDomain(value)
      ? { value }
      : {
          refusal:
            "recipient_domain is not a DNS name in ASCII form with A-label internationalized labels and no trailing dot",
        },
  noBroader: (c, r) => isWithinDomain(c, r),
  omissionEquivalent: never,
};

interface Window {
  readonly notBefore?: Instant;
  readonly notAfter?: Instant;
}

// time_window: "an object with two members, not_before and not_after, each a
// date-time string as defined in RFC3339; at least one MUST be present, and
// an absent member is unbounded on that side".
const timeWindow: ConstraintRule<Window> = {
  parse(value) {
    if (!isObject(value) || !hasOnlyMembers(value, ["not_before", "not_after"])) {
      return { refusal: "time_window is an object with the members not_before and not_after only" };
    }
    if (!("not_before" in value) && !("not_after" in value)) {
      return { refusal: "time_window carries neither not_before nor not_after" };
    }
    const window: { notBefore?: Instant; notAfter?: Instant } = {};
    if ("not_before" in value) {
      const nb = parseInstant(value.not_before);
      if (nb === undefined)
        return { refusal: "time_window.not_before is not an RFC 3339 date-time" };
      window.notBefore = nb;
    }
    if ("not_after" in value) {
      const na = parseInstant(value.not_after);
      if (na === undefined)
        return { refusal: "time_window.not_after is not an RFC 3339 date-time" };
      window.notAfter = na;
    }
    // resource-access#entry-validation: refused when it "has a not_before later
    // than its not_after, a window that admits no instant". Equal bounds admit
    // one instant, since both bounds are inclusive.
    if (
      window.notBefore !== undefined &&
      window.notAfter !== undefined &&
      compareInstant(window.notBefore, window.notAfter) > 0
    ) {
      return { refusal: "time_window has a not_before later than its not_after" };
    }
    return { value: window };
  },
  // "no broader when the candidate window lies within the reference window, an
  // absent candidate bound counting as unbounded and therefore broader than
  // any present reference bound"
  noBroader(c, r) {
    if (r.notBefore !== undefined) {
      if (c.notBefore === undefined || compareInstant(c.notBefore, r.notBefore) < 0) return false;
    }
    if (r.notAfter !== undefined) {
      if (c.notAfter === undefined || compareInstant(c.notAfter, r.notAfter) > 0) return false;
    }
    return true;
  },
  omissionEquivalent: never,
};

function labelSetRule(name: string): ConstraintRule<readonly string[]> {
  return {
    parse(value) {
      const list = stringArray(value);
      return list === undefined
        ? { refusal: `${name} is not an array of strings` }
        : { value: list };
    },
    // "no broader when the candidate array's members are a subset of the
    // reference array's, compared as exact strings"
    noBroader: (c, r) => c.every((v) => r.includes(v)),
    omissionEquivalent: never,
  };
}

const dataClassification = labelSetRule("data_classification");
const allowedTools = labelSetRule("allowed_tools");

// requires_action_approval: "a boolean"; "no broader when the candidate is
// true or equals the reference"; "A value of false is equivalent to omitting
// the member" (also the registry's Omission-Equivalent Value,
// resource-access#iana-common-constraints).
const requiresActionApproval: ConstraintRule<boolean> = {
  parse: (value) =>
    typeof value === "boolean"
      ? { value }
      : { refusal: "requires_action_approval is not a boolean" },
  noBroader: (c, r) => c || c === r,
  omissionEquivalent: (v) => v === false,
};

/**
 * The constraint keys this consumer implements: exactly the subset's nine
 * (supported-subset.json `constraints`). A key outside this map is
 * unsupported input and is refused, never dropped
 * (resource-access#common-constraints).
 */
export const CONSTRAINT_RULES: ReadonlyMap<string, ConstraintRule<unknown>> = new Map<
  string,
  ConstraintRule<unknown>
>([
  ["max_amount", maxAmount as ConstraintRule<unknown>],
  ["resource_issued_after", resourceIssuedAfter as ConstraintRule<unknown>],
  ["resource_issued_before", resourceIssuedBefore as ConstraintRule<unknown>],
  ["tenant", tenant as ConstraintRule<unknown>],
  ["recipient_domain", recipientDomain as ConstraintRule<unknown>],
  ["time_window", timeWindow as ConstraintRule<unknown>],
  ["data_classification", dataClassification as ConstraintRule<unknown>],
  ["allowed_tools", allowedTools as ConstraintRule<unknown>],
  ["requires_action_approval", requiresActionApproval as ConstraintRule<unknown>],
]);
