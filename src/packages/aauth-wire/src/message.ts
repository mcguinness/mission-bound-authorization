/** Header input accepted by this package. Names are matched case-insensitively. */
export type HeaderInput =
  | Headers
  | Iterable<readonly [string, string]>
  | Record<string, string | readonly string[] | undefined>;

/** An HTTP request as seen by a signer or a verifier. */
export interface HttpRequestMessage {
  method: string;
  /**
   * The absolute target URI, with the path and query exactly as they
   * appear on the wire (for a server, the request line's target).
   */
  url: string;
  headers: HeaderInput;
  /**
   * The content. A verifier passes it whenever the request has one: a
   * covered Content-Digest cannot be checked without it.
   */
  body?: Uint8Array | string | undefined;
}

/** A request with headers grouped by lowercased name, in arrival order. */
export interface NormalizedRequest {
  method: string;
  /** Parsed URI, for the authority and scheme. */
  url: URL;
  /** The target URI without its fragment, unnormalized. */
  targetUri: string;
  /** The path before any normalization or percent-decoding; "/" when empty. */
  path: string;
  /** The query with its leading "?", or "" when absent. */
  query: string;
  fields: Map<string, string[]>;
  body: Uint8Array | undefined;
}

/**
 * Split the path and query out of the URI string itself. WHATWG URL
 * parsing resolves dot segments and re-encodes characters, which would
 * change the values a signer covered.
 *
 * @spec rfc9421#section-2.2.6
 */
function rawPathAndQuery(target: string): { path: string; query: string } {
  const scheme = target.indexOf("://");
  let rest = scheme >= 0 ? target.slice(scheme + 3) : target;
  const start = rest.search(/[/?]/);
  rest = start >= 0 ? rest.slice(start) : "";
  const q = rest.indexOf("?");
  const path = (q >= 0 ? rest.slice(0, q) : rest) || "/";
  return { path, query: q >= 0 ? rest.slice(q) : "" };
}

export function normalizeRequest(message: HttpRequestMessage): NormalizedRequest {
  const fields = new Map<string, string[]>();
  const add = (name: string, value: string) => {
    const key = name.toLowerCase();
    const list = fields.get(key);
    if (list) list.push(value);
    else fields.set(key, [value]);
  };
  const { headers } = message;
  if (typeof Headers !== "undefined" && headers instanceof Headers) {
    headers.forEach((value, name) => {
      add(name, value);
    });
  } else if (Symbol.iterator in Object(headers)) {
    for (const [name, value] of headers as Iterable<readonly [string, string]>) add(name, value);
  } else {
    for (const [name, value] of Object.entries(headers as Record<string, unknown>)) {
      if (value === undefined) continue;
      if (Array.isArray(value)) for (const v of value) add(name, String(v));
      else add(name, String(value));
    }
  }
  const body =
    message.body === undefined
      ? undefined
      : typeof message.body === "string"
        ? new TextEncoder().encode(message.body)
        : message.body;
  const hash = message.url.indexOf("#");
  const targetUri = hash >= 0 ? message.url.slice(0, hash) : message.url;
  return {
    method: message.method,
    url: new URL(targetUri),
    targetUri,
    ...rawPathAndQuery(targetUri),
    fields,
    body,
  };
}

/**
 * The combined field value: each instance trimmed, obsolete line folding
 * replaced by a space, instances joined with ", ".
 *
 * @spec rfc9421#section-2.1
 */
export function combinedFieldValue(request: NormalizedRequest, name: string): string | undefined {
  const values = request.fields.get(name.toLowerCase());
  if (!values) return undefined;
  return values.map((v) => v.replace(/\r?\n[ \t]+/g, " ").trim()).join(", ");
}

/**
 * True when the request carries content: bytes were supplied, or the
 * framing says so (a positive Content-Length, or any Transfer-Encoding),
 * so a caller that omits the body cannot skip the body rules.
 */
export function carriesBody(request: NormalizedRequest): boolean {
  if (request.body !== undefined && request.body.length > 0) return true;
  if (request.fields.has("transfer-encoding")) return true;
  const length = combinedFieldValue(request, "content-length");
  return length !== undefined && length !== "0";
}
