// Exact decimal values (resource-access#decimal-values).
//
// No value here is ever converted to a JavaScript number: the grammar admits
// values (18 fractional digits, unbounded integer digits) that an IEEE 754
// binary double cannot hold exactly, and the draft forbids that conversion.

// resource-access#decimal-values: "MUST match ^[0-9]+(\.[0-9]{1,18})?$".
// JavaScript's `$` (without the m flag) anchors at the end of input only, so
// a trailing newline does not match.
const DECIMAL_GRAMMAR = /^[0-9]+(\.[0-9]{1,18})?$/;

/** A decimal string split into its integer and fractional digit strings. */
export interface DecimalValue {
  readonly integer: string;
  readonly fraction: string;
}

/**
 * Parse a decimal string under the draft's grammar. Any other form
 * (scientific notation, a sign, a separator, "NaN", "Infinity", whitespace)
 * is malformed and yields undefined: the consumer rejects it rather than
 * attempting to parse it (resource-access#decimal-values).
 */
export function parseDecimal(value: unknown): DecimalValue | undefined {
  if (typeof value !== "string" || !DECIMAL_GRAMMAR.test(value)) return undefined;
  const dot = value.indexOf(".");
  if (dot < 0) return { integer: value, fraction: "" };
  return { integer: value.slice(0, dot), fraction: value.slice(dot + 1) };
}

// resource-access#decimal-values: "scaling both values to integers by their
// fractional digit count and comparing the integers". BigInt holds the scaled
// integer exactly whatever its length.
function scaled(value: DecimalValue, scale: number): bigint {
  return BigInt(value.integer + value.fraction.padEnd(scale, "0"));
}

/**
 * Compare two decimal values in value space: negative when a < b, zero when
 * equal ("500", "500.0" and "500.00" are equal,
 * resource-access#value-space-comparison), positive when a > b.
 */
export function compareDecimal(a: DecimalValue, b: DecimalValue): number {
  const scale = Math.max(a.fraction.length, b.fraction.length);
  const x = scaled(a, scale);
  const y = scaled(b, scale);
  if (x < y) return -1;
  if (x > y) return 1;
  return 0;
}
