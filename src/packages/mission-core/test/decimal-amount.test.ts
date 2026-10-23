/**
 * @spec mission#max-amount, mission#common-constraints
 *
 * Exact decimal-value comparison for a monetary `amount` string: never
 * IEEE-754 float, and malformed input is rejected rather than silently
 * coerced (NaN, Infinity, or a wildly-scaled value).
 */

import { describe, expect, it } from "vitest";
import { compareAmounts, InvalidAmountError, isCurrencyCode, isValidAmount } from "../src/index.js";

describe("isValidAmount", () => {
  it("accepts plain decimal amounts", () => {
    expect(isValidAmount("500.00")).toBe(true);
    expect(isValidAmount("500")).toBe(true);
    expect(isValidAmount("0")).toBe(true);
    expect(isValidAmount("0.5")).toBe(true);
    expect(isValidAmount("9007199254740993.00")).toBe(true); // beyond MAX_SAFE_INTEGER
  });

  it("rejects malformed amounts (never silently coerced)", () => {
    expect(isValidAmount("NaN")).toBe(false);
    expect(isValidAmount("Infinity")).toBe(false);
    expect(isValidAmount("1e300")).toBe(false); // exponent notation
    expect(isValidAmount("-5.00")).toBe(false); // no sign (caps are non-negative)
    expect(isValidAmount("")).toBe(false);
    expect(isValidAmount("5.")).toBe(false); // trailing dot, no fractional digit
    expect(isValidAmount(".5")).toBe(false); // no leading digit
    expect(isValidAmount("5,000.00")).toBe(false); // thousands separator
    expect(isValidAmount("5.00.00")).toBe(false); // more than one dot
    expect(isValidAmount("5 ")).toBe(false); // trailing whitespace
  });
});

describe("compareAmounts", () => {
  it("compares equal-precision amounts by value", () => {
    expect(compareAmounts("100.00", "200.00")).toBe(-1);
    expect(compareAmounts("200.00", "100.00")).toBe(1);
    expect(compareAmounts("100.00", "100.00")).toBe(0);
  });

  it("compares amounts with differing fractional-digit counts by exact value (not string length)", () => {
    expect(compareAmounts("100", "100.00")).toBe(0);
    expect(compareAmounts("100.1", "100.10")).toBe(0);
    expect(compareAmounts("100.5", "100.45")).toBe(1);
  });

  it("a value that float-compares wrong compares correctly under exact decimal arithmetic", () => {
    // Both round to the identical IEEE-754 double (2^53), so
    // Number.parseFloat(a) <= Number.parseFloat(b) would wrongly report them
    // equal; BigInt-scaled comparison sees the true 1-unit difference.
    const a = "9007199254740993.00";
    const b = "9007199254740992.00";
    expect(Number.parseFloat(a)).toBe(Number.parseFloat(b)); // the float hazard
    expect(compareAmounts(a, b)).toBe(1);
    expect(compareAmounts(b, a)).toBe(-1);
  });

  it("is exact for arbitrarily large and arbitrarily precise values", () => {
    expect(compareAmounts("1000000000000000000.01", "1000000000000000000.02")).toBe(-1);
    expect(compareAmounts("0.000000000000000001", "0.000000000000000002")).toBe(-1);
  });

  it("throws InvalidAmountError on a malformed operand, on either side", () => {
    expect(() => compareAmounts("NaN", "500.00")).toThrow(InvalidAmountError);
    expect(() => compareAmounts("500.00", "1e300")).toThrow(InvalidAmountError);
  });
});

// @spec resource-access#initial-common-constraints (#1595, D727): "a
// `currency` value is exactly three characters, each an upper-case ASCII
// letter (`A` to `Z`)"; "Values are compared exactly, character for
// character, with no trimming, case folding, numeric code, or conversion."
describe("isCurrencyCode: exactly three upper-case ASCII letters (#1595, D727)", () => {
  it("admits three upper-case ASCII letters, whether or not ISO 4217 assigns the code", () => {
    for (const code of ["USD", "EUR", "JPY", "XYZ", "AAA", "ZZZ"]) {
      expect(isCurrencyCode(code), code).toBe(true);
    }
  });

  it("refuses any other length, a line terminator included, and any other character", () => {
    for (const code of [
      "usd",
      "Usd",
      "uSD",
      "US",
      "USDX",
      "",
      "USD\n",
      "USD\r",
      "USD\u2028",
      " USD",
      "USD ",
      "840",
      "U5D",
      "ÜSD",
      "ＵＳＤ",
      "US-",
      "@SD",
      "US[",
    ]) {
      expect(isCurrencyCode(code), JSON.stringify(code)).toBe(false);
    }
  });

  it("refuses a value that is not a string", () => {
    for (const code of [840, null, undefined, ["USD"], { code: "USD" }]) {
      expect(isCurrencyCode(code), JSON.stringify(code)).toBe(false);
    }
  });
});
