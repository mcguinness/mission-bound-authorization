/**
 * @spec mission#canonicalization
 * JCS (RFC 8785) canonicalization, scoped to the JSON shapes the Mission
 * family commits to: objects, arrays, strings, finite numbers, booleans,
 * null. Member names sort by UTF-16 code units; array order is preserved
 * (core § canonicalization: array order is significant and fixed by the AS).
 */

import { createHash } from "node:crypto";

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
    // Drop members whose value is undefined, matching JSON.stringify / JCS
    // (a JSON object has no undefined members). Prevents a throw on objects
    // that carry optional-but-unset fields (e.g. an absent trace_id).
    const keys = Object.keys(value)
      .filter((k) => value[k] !== undefined)
      .sort((a, b) => compareUtf16(a, b));
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

/**
 * @spec runtime-evidence#receipt-evidence, runtime-evidence#request-digest-worked:
 * a "canonical-object digest": SHA-256 over the JCS canonical bytes of a JSON
 * value directly, encoded `sha-256:` + base64url (no padding). Distinct from
 * {@link computeAnchor} (anchors.ts): that helper hashes a `{typ, iss, value}`
 * domain-separated envelope; this one hashes the value's own canonical bytes
 * with no wrapper, matching the Mission Receipt evidence-reference digest and
 * the Decision/Refusal `evaluation_request_digest` fallback exactly as those
 * sections define them.
 */
export function canonicalDigest(value: JsonValue): string {
  const digest = createHash("sha256").update(canonicalize(value), "utf8").digest();
  return `sha-256:${digest.toString("base64url")}`;
}
