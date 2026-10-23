// RFC 3986 absolute-URI syntax, checked by hand from the RFC 3986 Appendix A
// grammar. The WHATWG URL parser is deliberately not used: it accepts strings
// outside RFC 3986 (for example "https:api.example/orders") and rewrites
// others, and resource-access#resource-matching forbids normalizing an exact
// operand by parsing and reserializing it.

const SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*$/;
const PCT = "%[0-9A-Fa-f]{2}";
const UNRESERVED = "A-Za-z0-9\\-._~";
const SUB_DELIMS = "!$&'()*+,;=";
// pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
const PCHAR = `(?:[${UNRESERVED}${SUB_DELIMS}:@]|${PCT})`;
const SEGMENT = new RegExp(`^${PCHAR}*$`);
const QUERY = new RegExp(`^(?:${PCHAR}|[/?])*$`);
const USERINFO = new RegExp(`^(?:[${UNRESERVED}${SUB_DELIMS}:]|${PCT})*$`);
const REG_NAME = new RegExp(`^(?:[${UNRESERVED}${SUB_DELIMS}]|${PCT})*$`);
const PORT = /^[0-9]*$/;
const IPV_FUTURE = new RegExp(`^[vV][0-9A-Fa-f]+\\.[${UNRESERVED}${SUB_DELIMS}:]+$`);
const H16 = /^[0-9A-Fa-f]{1,4}$/;
const DEC_OCTET = /^(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/;

function isIPv4(text: string): boolean {
  const parts = text.split(".");
  return parts.length === 4 && parts.every((p) => DEC_OCTET.test(p));
}

// RFC 3986 section 3.2.2 IPv6address: eight 16-bit pieces, an optional
// trailing IPv4address counting as two, and at most one "::".
function isIPv6(text: string): boolean {
  const halves = text.split("::");
  if (halves.length > 2) return false;
  const pieces = (half: string): string[] => (half === "" ? [] : half.split(":"));
  const head = pieces(halves[0] ?? "");
  const tail = halves.length === 2 ? pieces(halves[1] ?? "") : [];
  const all = [...head, ...tail];
  // A trailing IPv4address ends the whole address, never precedes "::".
  const ipv4Allowed = halves.length === 1 || tail.length > 0;
  let count = 0;
  for (let i = 0; i < all.length; i++) {
    const piece = all[i] ?? "";
    if (ipv4Allowed && i === all.length - 1 && piece.includes(".")) {
      if (!isIPv4(piece)) return false;
      count += 2;
    } else {
      if (!H16.test(piece)) return false;
      count += 1;
    }
  }
  return halves.length === 2 ? count <= 7 : count === 8;
}

function isHost(host: string): boolean {
  if (host.startsWith("[")) {
    if (!host.endsWith("]")) return false;
    const inner = host.slice(1, -1);
    return isIPv6(inner) || IPV_FUTURE.test(inner);
  }
  // reg-name also covers IPv4address, whose characters are all unreserved.
  return REG_NAME.test(host);
}

/** The parts of an absolute-URI this consumer needs. */
export interface AbsoluteUri {
  readonly scheme: string;
  /** The authority, when the hier-part takes the "//" authority form. */
  readonly authority?: { readonly host: string };
}

function parseAuthority(authority: string): { host: string } | undefined {
  let rest = authority;
  const at = rest.indexOf("@");
  if (at >= 0) {
    if (!USERINFO.test(rest.slice(0, at))) return undefined;
    rest = rest.slice(at + 1);
  }
  let host = rest;
  let port = "";
  if (rest.startsWith("[")) {
    const close = rest.indexOf("]");
    if (close < 0) return undefined;
    host = rest.slice(0, close + 1);
    const after = rest.slice(close + 1);
    if (after !== "") {
      if (!after.startsWith(":")) return undefined;
      port = after.slice(1);
    }
  } else {
    const colon = rest.indexOf(":");
    if (colon >= 0) {
      host = rest.slice(0, colon);
      port = rest.slice(colon + 1);
    }
  }
  if (!isHost(host) || !PORT.test(port)) return undefined;
  return { host };
}

/**
 * Parse an RFC 3986 section 4.3 absolute-URI:
 * absolute-URI = scheme ":" hier-part [ "?" query ]. It has no fragment.
 * Returns undefined for any other string.
 */
export function parseAbsoluteUri(value: unknown): AbsoluteUri | undefined {
  if (typeof value !== "string") return undefined;
  const colon = value.indexOf(":");
  if (colon <= 0) return undefined;
  const scheme = value.slice(0, colon);
  if (!SCHEME.test(scheme)) return undefined;
  let rest = value.slice(colon + 1);
  // absolute-URI admits no fragment, so a "#" anywhere fails the grammar.
  if (rest.includes("#")) return undefined;
  const q = rest.indexOf("?");
  if (q >= 0) {
    if (!QUERY.test(rest.slice(q + 1))) return undefined;
    rest = rest.slice(0, q);
  }
  // hier-part = "//" authority path-abempty / path-absolute / path-rootless / path-empty
  if (rest.startsWith("//")) {
    const afterSlashes = rest.slice(2);
    const slash = afterSlashes.indexOf("/");
    const authorityText = slash >= 0 ? afterSlashes.slice(0, slash) : afterSlashes;
    const path = slash >= 0 ? afterSlashes.slice(slash) : "";
    const authority = parseAuthority(authorityText);
    if (authority === undefined) return undefined;
    // path-abempty = *( "/" segment )
    if (!path.split("/").every((s) => SEGMENT.test(s))) return undefined;
    return { scheme, authority };
  }
  // path-absolute, path-rootless or path-empty: segments of pchar, where the
  // first segment of path-absolute is non-empty ("//" was handled above).
  if (!rest.split("/").every((s) => SEGMENT.test(s))) return undefined;
  return { scheme };
}
