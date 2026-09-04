/**
 * @spec capability-binding#capability-source-binding
 * @spec capability-binding#capability-extraction
 * The capability-source binding a validating server records at derivation for
 * a catalog-sourced action: the stable `tool_id`, the discovery `source_uri`,
 * a `source_digest` over the capability's extracted definition, and an
 * `operation_ref`. These values are part of the approved Mission's derived
 * authority and are therefore covered by `authority_hash`, so this one type is
 * shared by the kernel entry and the PDP's materialized entry: a projection
 * that re-declared it could silently perturb the commitment.
 */

import { createHash } from "node:crypto";
import { canonicalDigest, canonicalize, type JsonValue } from "./canonicalize.js";
import { parseStrictJson } from "./strict-json.js";

/**
 * @spec mission-substrate#default-commitment-construction — the only digest
 * algorithm prefix this document's members are encoded under. A recorded
 * digest carrying any other prefix refuses; it is never treated as sha-256
 * (the verifier rule `verifyAnchor` applies to integrity anchors).
 */
export const CAPABILITY_DIGEST_PREFIX = "sha-256:";

/** A refusal in extraction, digest handling, or binding validation. */
export class CapabilityBindingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CapabilityBindingError";
  }
}

/**
 * @spec capability-binding#capability-source-binding — the COMMITTED shape.
 *
 * Two deliberate differences from the object a PEP presents in
 * `context.capability_source`:
 *   - `action` is present here and absent there. Applicability is per action
 *     (a mixed entry is valid: catalog-sourced actions carry a binding,
 *     first-party actions in the same entry carry none), so a committed
 *     binding has to say which of the entry's actions it covers. The
 *     presented object rides a request that already names one action.
 *   - `executor` is absent here and OPTIONAL there. It is a request-time fact
 *     the PEP asserts after authenticating the serving component, "not part
 *     of the derived authority recorded at derivation"; committing it would
 *     pull it into `authority_hash`.
 *
 * One action MAY name several `tool_id` values; `(action, tool_id)` is
 * unique within an entry, and decision-time lookup is set membership for the
 * action first, then comparison on the matched member.
 */
export interface CapabilitySourceBinding {
  /** The approved action this binding covers. */
  action: string;
  /** A stable capability identifier the executing component invokes. */
  tool_id: string;
  /** The discovery source the capability was resolved from. */
  source_uri: string;
  /**
   * The canonical-object digest over the capability's extracted definition
   * ({@link capabilitySourceDigest}), recorded at derivation.
   */
  source_digest: string;
  /** The source-format-specific operation reference (an MCP tool name). */
  operation_ref: string;
  /**
   * OPTIONAL raw-octet digest over the exact retrieved source representation
   * ({@link catalogDigest}). Strictly stricter than `source_digest`: when
   * recorded, any change to the retrieved source refuses.
   */
  catalog_digest?: string;
}

/**
 * @spec capability-binding#capability-extraction — `source_digest`: the
 * canonical-object digest (JCS canonical bytes, SHA-256, `sha-256:` plus
 * base64url) over the extracted per-capability definition, with NO envelope.
 * Deliberately {@link canonicalDigest} and not `computeAnchor`: the family
 * anchor idiom hashes a `{typ, iss, value}` domain-separated envelope, and
 * this document's `source_digest` is over the extracted definition's own
 * bytes. The draft's published `write_document` vector reproduces under this
 * construction and would not under the anchor one.
 */
export function capabilitySourceDigest(definition: JsonValue): string {
  return canonicalDigest(definition);
}

/**
 * @spec capability-binding#capability-source-binding — `catalog_digest`: a
 * RAW-OCTET digest over the exact retrieved representation. Never a parse and
 * reserialize round trip, and never canonicalized: whitespace, member order,
 * and any other byte of the served document are inside this commitment.
 */
export function catalogDigest(retrieved: string | Uint8Array): string {
  const bytes =
    typeof retrieved === "string" ? Buffer.from(retrieved, "utf8") : Buffer.from(retrieved);
  return `${CAPABILITY_DIGEST_PREFIX}${createHash("sha256").update(bytes).digest("base64url")}`;
}

/**
 * Reject an unrecognized algorithm prefix on a recorded digest, mirroring the
 * integrity-anchor verifier rule: never treat an unknown prefix as sha-256.
 */
export function assertSupportedDigest(value: string, member: string): void {
  if (!value.startsWith(CAPABILITY_DIGEST_PREFIX)) {
    throw new CapabilityBindingError(
      `unrecognized ${member} algorithm prefix: ${value.split(":")[0]}`,
    );
  }
}

/**
 * @spec capability-binding#capability-extraction — for an MCP tool catalog the
 * extracted definition is "the single tool's definition object as retrieved
 * (the member of the catalog's tool list whose name is the capability's)".
 *
 * The catalog text is parsed with {@link parseStrictJson}, so a document
 * carrying duplicate JSON member names refuses BEFORE canonicalization rather
 * than committing to whichever duplicate a lenient parser kept. A missing
 * definition and an ambiguous one (two list members with the same `name`) both
 * refuse; neither is resolved by picking one.
 */
export function extractMcpToolDefinition(catalogText: string, toolName: string): JsonValue {
  const tools = mcpToolList(parseStrictJson(catalogText));
  const matches = tools.filter((t) => isJsonObject(t) && t.name === toolName);
  if (matches.length === 0) {
    throw new CapabilityBindingError(`no tool named ${JSON.stringify(toolName)} in catalog`);
  }
  if (matches.length > 1) {
    throw new CapabilityBindingError(
      `ambiguous tool name ${JSON.stringify(toolName)}: ${matches.length} definitions in catalog`,
    );
  }
  return matches[0] as JsonValue;
}

/**
 * The tool list of a retrieved MCP catalog: either the `tools` array of a
 * `tools/list` result (and of the server card that serves the same
 * derivation), or a bare array of tool definitions. Any other shape has no
 * tool list and refuses rather than being coerced into one.
 */
function mcpToolList(parsed: JsonValue): JsonValue[] {
  if (Array.isArray(parsed)) return parsed;
  if (isJsonObject(parsed) && Array.isArray(parsed.tools)) return parsed.tools;
  throw new CapabilityBindingError("catalog carries no MCP tool list");
}

function isJsonObject(v: JsonValue | undefined): v is { [k: string]: JsonValue } {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** The canonical bytes of a whole binding: its identity for byte-equality. */
export function capabilitySourceIdentity(binding: CapabilitySourceBinding): string {
  return canonicalize(binding as unknown as JsonValue);
}

/**
 * Validate a resolved binding list for ONE Authority Set entry and return it
 * in a reproducible order.
 *
 * Array order is inside `authority_hash` (JCS preserves it), so two identical
 * resolutions must produce identical committed bytes: the returned array is
 * sorted by canonical bytes, the same discipline `unionConditions` applies to
 * `terminal_when`. `(action, tool_id)` is unique, an unrecognized digest
 * prefix refuses, and a malformed member refuses rather than being committed.
 */
export function normalizeCapabilitySources(
  bindings: readonly CapabilitySourceBinding[],
): CapabilitySourceBinding[] {
  const seen = new Set<string>();
  const out = bindings.map((b) => {
    for (const [member, value] of [
      ["action", b.action],
      ["tool_id", b.tool_id],
      ["source_uri", b.source_uri],
      ["source_digest", b.source_digest],
      ["operation_ref", b.operation_ref],
    ] as const) {
      if (typeof value !== "string" || value.length === 0) {
        throw new CapabilityBindingError(`capability source ${member} must be a non-empty string`);
      }
    }
    assertSupportedDigest(b.source_digest, "source_digest");
    if (b.catalog_digest !== undefined) assertSupportedDigest(b.catalog_digest, "catalog_digest");
    const key = canonicalize({ action: b.action, tool_id: b.tool_id });
    if (seen.has(key)) {
      throw new CapabilityBindingError(
        `duplicate capability source for action ${JSON.stringify(b.action)} and tool_id ${JSON.stringify(b.tool_id)}`,
      );
    }
    seen.add(key);
    const normalized: CapabilitySourceBinding = {
      action: b.action,
      tool_id: b.tool_id,
      source_uri: b.source_uri,
      source_digest: b.source_digest,
      operation_ref: b.operation_ref,
      ...(b.catalog_digest !== undefined ? { catalog_digest: b.catalog_digest } : {}),
    };
    return normalized;
  });
  return out.sort((a, b) => {
    const ka = capabilitySourceIdentity(a);
    const kb = capabilitySourceIdentity(b);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
}
