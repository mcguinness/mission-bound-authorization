/**
 * @spec authority-server#reference-propagation — the Mission Reference
 * Propagation channel: the tuple a gateway PEP that does not itself hold the
 * Mission binding receives from the party that does. The channel carries
 * exactly the reference tuple (`issuer`, `mission_id`) and nothing else;
 * state, anchors, authority, and policy data never ride it, and a carriage
 * that smuggles anything else is malformed, refused rather than absorbed.
 *
 * The propagated value is a SELECTION ASSERTION, never authority: parsing
 * success grants nothing. Verification against the credential-carried or
 * locally recorded binding is the PEP's job (`pep.ts`), not this module's.
 */

/** @spec authority-server#mission-reference-field — the HTTP request field. */
export const MISSION_REFERENCE_HEADER = "mission-reference";

/** @spec authority-server#mcp-reference — the `params._meta` key on tools/call. */
export const MCP_REFERENCE_META_KEY = "com.karlmcguinness.mission/reference";

/**
 * A parsed propagation result: the tuple, or the fact that carriage was
 * present but unusable. Malformedness is preserved rather than dropped
 * because it denies (`mission_reference_conflict`) wherever governance
 * requires a reference; silently ignoring a bad reference is the
 * non-conforming behavior the spec names.
 */
export type PropagatedMissionReference = { id: string; issuer: string } | { malformed: true };

/** RFC 9651 Dictionary key: lc-alpha or `*` first, then lc-alnum `_-.*`. */
const SF_KEY = /^[a-z*][a-z0-9_.*-]*$/;
const SF_KEY_CHAR = /[a-z0-9_.*-]/;

/**
 * @spec authority-server#mission-reference-field — strict, field-specific
 * parsing of the `Mission-Reference` Structured Fields Dictionary
 * (RFC 9651). Deliberately NOT a general SF parser: the spec requires
 * rejection, before map collapse, of duplicate members, parameters, Inner
 * Lists, non-String values, and any member other than `id` and `issuer`,
 * so last-duplicate-wins smuggling is foreclosed. Exactly one field line is
 * accepted (`fieldLineCount` comes from the transport's raw header view).
 *
 * Returns `undefined` when the field is absent; the tuple when it parses
 * under every rule; `{ malformed: true }` otherwise.
 */
export function parseMissionReferenceField(
  value: string | string[] | undefined,
  fieldLineCount = 1,
): PropagatedMissionReference | undefined {
  if (value === undefined) return undefined;
  if (Array.isArray(value) || fieldLineCount > 1) return { malformed: true };
  const s = value;
  let i = 0;
  const seen: Record<string, string> = Object.create(null);
  const skipOws = () => {
    while (i < s.length && (s.charAt(i) === " " || s.charAt(i) === "\t")) i++;
  };
  skipOws();
  if (i >= s.length) return { malformed: true };
  while (i < s.length) {
    const keyStart = i;
    while (i < s.length && SF_KEY_CHAR.test(s.charAt(i))) i++;
    const key = s.slice(keyStart, i);
    if (!SF_KEY.test(key)) return { malformed: true };
    if (key in seen) return { malformed: true }; // duplicate, pre-collapse
    if (key !== "id" && key !== "issuer") return { malformed: true }; // closed
    if (s.charAt(i) !== "=") return { malformed: true }; // bare key = Boolean, non-String
    i++;
    if (s.charAt(i) === "(") return { malformed: true }; // Inner List
    if (s.charAt(i) !== '"') return { malformed: true }; // Token/number/byte-seq
    i++;
    let out = "";
    let closed = false;
    while (i < s.length) {
      const ch = s.charAt(i);
      if (ch === "\\") {
        const nxt = s.charAt(i + 1);
        if (nxt !== "\\" && nxt !== '"') return { malformed: true };
        out += nxt;
        i += 2;
      } else if (ch === '"') {
        closed = true;
        i++;
        break;
      } else if (ch < " " || ch > "~") {
        return { malformed: true }; // SF Strings are printable ASCII
      } else {
        out += ch;
        i++;
      }
    }
    if (!closed) return { malformed: true };
    if (s.charAt(i) === ";") return { malformed: true }; // parameter on the member
    seen[key] = out;
    skipOws();
    if (i < s.length) {
      if (s.charAt(i) !== ",") return { malformed: true };
      i++;
      skipOws();
      if (i >= s.length) return { malformed: true }; // trailing comma
    }
  }
  const id = seen.id;
  const issuer = seen.issuer;
  if (id === undefined || issuer === undefined) return { malformed: true };
  if (id.length > 256 || issuer.length > 512) return { malformed: true };
  return { id, issuer };
}

/**
 * @spec authority-server#mcp-reference — the `_meta` carriage names the same
 * tuple with different member names (`mission_id`, `issuer`), under the same
 * closure rules: exactly the two members, both strings, nothing else.
 * JSON parsing has already collapsed duplicate keys upstream (the MCP SDK
 * owns the parse), so pre-collapse duplicate detection is not reachable on
 * this carriage; membership closure and type checks are.
 */
export function parseMcpReferenceMeta(value: unknown): PropagatedMissionReference | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return { malformed: true };
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== 2 || !("mission_id" in record) || !("issuer" in record)) {
    return { malformed: true };
  }
  const missionId = record.mission_id;
  const issuer = record.issuer;
  if (typeof missionId !== "string" || typeof issuer !== "string") {
    return { malformed: true };
  }
  if (missionId.length > 256 || issuer.length > 512) return { malformed: true };
  return { id: missionId, issuer };
}
