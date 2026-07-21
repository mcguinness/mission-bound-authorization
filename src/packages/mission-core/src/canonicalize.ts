/**
 * @spec mission#canonicalization
 * JCS (RFC 8785) canonicalization, scoped to the JSON shapes the Mission
 * family commits to: objects, arrays, strings, finite numbers, booleans,
 * null. Member names sort by UTF-16 code units; array order is preserved
 * (core § canonicalization: array order is significant and fixed by the AS).
 */

export type JsonValue = string | number | boolean | null | JsonValue[] | { [k: string]: JsonValue };

export function canonicalize(value: JsonValue): string {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number is not valid JSON");
    // RFC 8785 number serialization is ECMAScript's Number::toString, which
    // JSON.stringify applies to finite numbers.
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalize(v)).join(",")}]`;
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).sort((a, b) => compareUtf16(a, b));
    const members = keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k] as JsonValue)}`);
    return `{${members.join(",")}}`;
  }
  throw new Error(`cannot canonicalize value of type ${typeof value}`);
}

/** RFC 8785 sorts property names as arrays of UTF-16 code units. */
function compareUtf16(a: string, b: string): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i += 1) {
    const d = (a.charCodeAt(i) as number) - (b.charCodeAt(i) as number);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}
