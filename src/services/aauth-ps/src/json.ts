/** Nesting beyond this is refused rather than scanned. */
const MAX_DEPTH = 32;

export type StrictJsonResult =
  | { ok: true; value: unknown }
  | { ok: false; why: "malformed" | "duplicate member" | "too deep" };

/**
 * Parse JSON, refusing a document in which any object names a member
 * twice (`JSON.parse` silently keeps the last). Member names are compared
 * after their escapes are decoded, so `"a"` and `"a"` are the same
 * name.
 *
 * @spec mission-aauth-management#endpoint
 */
export function parseStrictJson(text: string): StrictJsonResult {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return { ok: false, why: "malformed" };
  }
  // The text is valid JSON from here, so the scanner needs no error paths.
  let i = 0;
  const skip = () => {
    while (i < text.length && " \t\n\r".includes(text.charAt(i))) i++;
  };
  const string = (): string => {
    const start = i;
    i++;
    while (text.charAt(i) !== '"') i += text.charAt(i) === "\\" ? 2 : 1;
    i++;
    return JSON.parse(text.slice(start, i)) as string;
  };
  const scan = (depth: number): "duplicate member" | "too deep" | undefined => {
    if (depth > MAX_DEPTH) return "too deep";
    skip();
    const c = text.charAt(i);
    if (c === "{" || c === "[") {
      const close = c === "{" ? "}" : "]";
      const names = new Set<string>();
      i++;
      skip();
      if (text.charAt(i) === close) {
        i++;
        return undefined;
      }
      for (;;) {
        if (c === "{") {
          skip();
          const name = string();
          if (names.has(name)) return "duplicate member";
          names.add(name);
          skip();
          i++; // the colon
        }
        const inner = scan(depth + 1);
        if (inner) return inner;
        skip();
        const next = text.charAt(i);
        i++;
        if (next !== ",") return undefined;
      }
    }
    if (c === '"') {
      string();
      return undefined;
    }
    while (i < text.length && !",]} \t\n\r".includes(text.charAt(i))) i++;
    return undefined;
  };
  const problem = scan(0);
  return problem ? { ok: false, why: problem } : { ok: true, value };
}

/**
 * A canonical form of a parsed JSON value: object members sorted by name,
 * at every depth. Two bodies are equal as parsed values exactly when
 * their canonical forms are equal, whatever their member order.
 */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object" && value !== null) {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
      a < b ? -1 : a > b ? 1 : 0,
    );
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}
