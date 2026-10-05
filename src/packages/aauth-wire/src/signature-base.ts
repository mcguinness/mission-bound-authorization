import {
  type InnerList,
  type Item,
  type Parameters,
  serializeInnerList,
  serializeString,
} from "structured-headers";
import { combinedFieldValue, type NormalizedRequest } from "./message.js";

export class SignatureBaseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SignatureBaseError";
  }
}

/**
 * Derived component values for a request. Response-only components and
 * `@query-param` (which needs a `name` parameter) are not implemented and
 * fail the base, as an unknown derived component must.
 *
 * @spec rfc9421#section-2.2
 */
function derivedValue(request: NormalizedRequest, name: string): string {
  const { url } = request;
  switch (name) {
    case "@method":
      return request.method;
    case "@target-uri":
      return request.targetUri;
    case "@authority":
      // URL lowercases the host and omits the scheme's default port.
      return url.host;
    case "@scheme":
      return url.protocol.slice(0, -1).toLowerCase();
    case "@request-target":
      return `${request.path}${request.query}`;
    case "@path":
      // The path as sent: no dot-segment removal, no re-encoding.
      return request.path;
    case "@query":
      return request.query === "" ? "?" : request.query;
    default:
      throw new SignatureBaseError(`unsupported derived component ${name}`);
  }
}

/**
 * The covered components as an Inner List with the signature parameters,
 * the value of `@signature-params` and of the Signature-Input member.
 *
 * @spec rfc9421#section-2.3
 */
export function signatureParams(components: readonly string[], params: Parameters): InnerList {
  return [components.map((c): Item => [c, new Map()]), params];
}

/**
 * Build the signature base. Every covered component is a bare component
 * name; a component identifier with parameters (`sf`, `key`, `bs`, `req`,
 * `tr`, `name`) is not implemented and fails the base. A duplicate
 * identifier, a missing field and a non-ASCII value fail it too.
 *
 * @spec rfc9421#section-2.5
 */
export function buildSignatureBase(request: NormalizedRequest, params: InnerList): string {
  const [items] = params;
  const seen = new Set<string>();
  const lines: string[] = [];
  for (const [name, componentParams] of items) {
    if (typeof name !== "string") {
      throw new SignatureBaseError("component identifier is not a string");
    }
    if (componentParams.size > 0) {
      throw new SignatureBaseError(`component parameters are not supported (${name})`);
    }
    if (seen.has(name)) throw new SignatureBaseError(`duplicate component ${name}`);
    seen.add(name);
    let value: string;
    if (name.startsWith("@")) {
      value = derivedValue(request, name);
    } else {
      if (name !== name.toLowerCase()) {
        throw new SignatureBaseError(`field component ${name} is not lowercase`);
      }
      const field = combinedFieldValue(request, name);
      if (field === undefined) throw new SignatureBaseError(`covered field ${name} is absent`);
      value = field;
    }
    lines.push(`${serializeString(name)}: ${value}`);
  }
  lines.push(`"@signature-params": ${serializeInnerList(params)}`);
  const base = lines.join("\n");
  // biome-ignore lint/suspicious/noControlCharactersInRegex: the ASCII check is the rule
  if (/[^\x00-\x7f]/.test(base)) throw new SignatureBaseError("signature base is not ASCII");
  return base;
}
