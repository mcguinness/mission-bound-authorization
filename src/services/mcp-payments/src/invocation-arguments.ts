/**
 * @spec AAT -02 Section 3.4 and Section 8 steps 6b and 7f (#1756, D902): the
 * boundary between a transport and the tool-dispatch path for a tool
 * invocation's arguments. A proof of possession that binds an invocation
 * (`hta`) is checked against the arguments AS WRITTEN: duplicate member names
 * refused and numbers in their source spelling. An ordinary JSON parser loses
 * both, and re-serializing its output cannot recover them, so each transport
 * fixes the arguments' JSON text once, at its own boundary, and every later
 * step (dispatch, the check below, proof verification) works from that one
 * text:
 *
 * - HTTP reads the request body once, parses it losslessly
 *   (`parseAatJson`), refuses a body that fails, and dispatches exactly that
 *   parse; a `tools/call`'s original arguments are serialized from the same
 *   parse with their number spellings ({@link originalArgumentsFrom}).
 * - The in-memory channel's object API has no wire text. Its client
 *   serializes the caller's argument object once into a JSON snapshot
 *   ({@link snapshotArguments}), sends that snapshot beside the arguments, and
 *   the server dispatches from the snapshot. The object API cannot carry a
 *   duplicate member or a number's spelling, so this boundary detects neither;
 *   it guarantees only that one snapshot serves proof construction,
 *   verification and dispatch.
 */

import { type AatJson, AatJsonError, aatIsObject, aatSerializeJson, aatToPlainJson, parseAatJson } from "@mission/core";
import type { InvocationArguments } from "./pep.js";

/**
 * The namespaced `_meta` key under which the in-memory client sends its JSON
 * snapshot of a `tools/call`'s arguments, beside the token key.
 */
export const INVOCATION_ARGUMENTS_META_KEY = "io.mission-bound/arguments";

/** `text` parsed losslessly as a JSON object, or undefined when it is not one. */
export function parseOriginalArguments(text: string): AatJson | undefined {
  try {
    const parsed = parseAatJson(text);
    return aatIsObject(parsed) ? parsed : undefined;
  } catch (e) {
    if (e instanceof AatJsonError) return undefined;
    throw e;
  }
}

/** The original arguments' JSON text for a losslessly parsed `arguments` node (absent means `{}`). */
export function originalArgumentsFrom(node: AatJson | undefined): string {
  return node === undefined ? "{}" : aatSerializeJson(node);
}

/** Two JSON-compatible values are equal: the same members, values, and numbers by value. */
export function sameJson(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a) || Array.isArray(b)) {
    return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((x, i) => sameJson(x, b[i]));
  }
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) return false;
  const ka = Object.keys(a);
  const kb = Object.keys(b);
  return (
    ka.length === kb.length &&
    ka.every((k) => Object.hasOwn(b, k) && sameJson((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]))
  );
}

/**
 * The seam's check: the transport's original text parses losslessly as an
 * object, and describes exactly the arguments the transport dispatched.
 */
export function originalArgumentsMatch(invocation: InvocationArguments, args: Record<string, unknown>): boolean {
  const original = parseOriginalArguments(invocation.argumentsJson);
  return original !== undefined && sameJson(aatToPlainJson(original), args);
}

/**
 * The in-memory client's serialization boundary: the caller's argument
 * object serialized ONCE, validated, and returned with the arguments derived
 * from that same text. A later change to the caller's object changes neither.
 * Throws when the object has no JSON form an invocation could carry.
 */
export function snapshotArguments(args: Record<string, unknown>): {
  argumentsJson: string;
  args: Record<string, unknown>;
} {
  const argumentsJson = JSON.stringify(args);
  const parsed = typeof argumentsJson === "string" ? parseOriginalArguments(argumentsJson) : undefined;
  if (parsed === undefined) throw new TypeError("tool arguments must be a JSON object");
  return { argumentsJson, args: aatToPlainJson(parsed) as Record<string, unknown> };
}
