/**
 * @spec mission#max-amount, mission#common-constraints
 *
 * Exact decimal-value comparison for a monetary `amount` string (the
 * `max_amount` Common Constraint, and any future decimal-valued constraint
 * that reuses its shape). `amount` values are decimal strings, compared by
 * numeric VALUE, never by IEEE-754 binary floating point: `Number.parseFloat`
 * silently rounds values it cannot represent exactly (large integers, long
 * fractional tails) and accepts non-decimal input (`"NaN"`, `"1e300"`,
 * `"Infinity"`) as if it were a bounded amount, which can turn a monetary cap
 * into an unbounded or wrongly-ordered one. This module validates the format
 * first and compares via integer-scaled BigInt arithmetic, which is exact at
 * any digit count.
 *
 * The fractional-digit bound (18) is deliberately generous: a value flowing
 * through `String(aJsNumber)` (e.g. a JS-number round-trip elsewhere in this
 * codebase) can carry up to ~17 significant digits, and BigInt comparison
 * costs nothing extra for the extra headroom. A future Common Constraints
 * registry entry MAY pin a tighter bound; this validator only needs to reject
 * genuinely malformed input, not enforce a specific currency's minor-unit
 * count.
 */

const AMOUNT_FORMAT = /^\d+(\.\d{1,18})?$/;

/**
 * True when `s` is a well-formed decimal amount: one or more digits,
 * optionally followed by `.` and one to eighteen digits. No sign (a monetary
 * cap is never negative), no exponent, no `NaN`/`Infinity`, no thousands
 * separators.
 */
export function isValidAmount(s: string): boolean {
  return AMOUNT_FORMAT.test(s);
}

/**
 * @spec resource-access#initial-common-constraints `max_amount` (#1595, D727):
 * "a `currency` value is exactly three characters, each an upper-case ASCII
 * letter (`A` to `Z`) ... Values are compared exactly, character for
 * character, with no trimming, case folding, numeric code, or conversion. A
 * well-formed value is admitted for comparison whether or not ISO 4217
 * assigns it." The length is checked as a length, so a value ending in a line
 * terminator is refused however a pattern's end anchor behaves. The SINGLE
 * check every boundary that reads a `currency` uses.
 */
export function isCurrencyCode(v: unknown): v is string {
  if (typeof v !== "string" || v.length !== 3) return false;
  for (let i = 0; i < 3; i++) {
    const c = v.charCodeAt(i);
    if (c < 0x41 || c > 0x5a) return false;
  }
  return true;
}

/** Thrown by {@link compareAmounts} when either operand fails {@link isValidAmount}. */
export class InvalidAmountError extends Error {
  constructor(readonly value: string) {
    super(`not a valid decimal amount: ${JSON.stringify(value)}`);
  }
}

/**
 * Exact decimal-value comparison: -1 when `a < b`, 0 when equal, 1 when
 * `a > b`. Compares by scaling both operands to the wider of their fractional
 * lengths and comparing as BigInt, so precision is never lost regardless of
 * magnitude or fractional length. Throws {@link InvalidAmountError} if either
 * operand is not {@link isValidAmount}; callers on a fail-closed path SHOULD
 * check {@link isValidAmount} themselves first when a thrown error is not the
 * wanted refusal shape (e.g. a pure boolean predicate).
 */
export function compareAmounts(a: string, b: string): -1 | 0 | 1 {
  if (!isValidAmount(a)) throw new InvalidAmountError(a);
  if (!isValidAmount(b)) throw new InvalidAmountError(b);
  const [aInt, aFrac = ""] = a.split(".");
  const [bInt, bFrac = ""] = b.split(".");
  const scale = Math.max(aFrac.length, bFrac.length);
  const aScaled = BigInt((aInt as string) + aFrac.padEnd(scale, "0"));
  const bScaled = BigInt((bInt as string) + bFrac.padEnd(scale, "0"));
  if (aScaled < bScaled) return -1;
  if (aScaled > bScaled) return 1;
  return 0;
}
