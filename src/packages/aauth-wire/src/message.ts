/** Header input accepted by this package. Names are matched case-insensitively. */
export type HeaderInput =
  | Headers
  | Iterable<readonly [string, string]>
  | Record<string, string | readonly string[] | undefined>;

/** An HTTP request as seen by a signer or a verifier. */
export interface HttpRequestMessage {
  method: string;
  /** The absolute target URI. */
  url: string;
  headers: HeaderInput;
  body?: Uint8Array | string | undefined;
}

/** A request with headers grouped by lowercased name, in arrival order. */
export interface NormalizedRequest {
  method: string;
  url: URL;
  fields: Map<string, string[]>;
  body: Uint8Array | undefined;
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
  return { method: message.method, url: new URL(message.url), fields, body };
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

/** True when the request carries content. */
export function hasBody(request: NormalizedRequest): boolean {
  return request.body !== undefined && request.body.length > 0;
}
