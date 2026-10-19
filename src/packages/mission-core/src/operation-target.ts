/**
 * @spec resource-access#resource-matching, resource-access#rs-enforcement
 * (#1276, D447, D457): the operation target and the Resource Access matcher,
 * one implementation for every enforcement point in this repository.
 *
 * Before matching authority, a resource server (or a PEP acting for it)
 * establishes the operation's target: one absolute URI, from its documented,
 * trusted operation contract, independently of the entries the request
 * presents. There is no fallback to the protected resource's metadata
 * identifier or to the token's audience: an absent, unsupported or ambiguous
 * contract establishes no target, and the operation is refused.
 *
 * Support is partial, and every unsupported form refuses:
 *
 * - Contracts: only an explicit service-level contract, `{ service: <URI> }`,
 *   which names the service identifier as the target of every operation it
 *   covers. A finer contract (one deriving the target from validated
 *   arguments) is `unsupported_contract`.
 * - Matching: only `exact` (the default when `resource_match` is absent), a
 *   literal comparison of the entry's JSON-decoded `resource` with the target.
 *   A `prefix` entry, or any `resource_match` value not recognized here, is
 *   `unsupported`: it provides no authority, and is never read as `exact`.
 */

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/*
 * RFC 3986 `absolute-URI` (Section 4.3), transcribed rule by rule from the
 * ABNF of RFC 3986 Appendix A. Each fragment below is one rule; the composed
 * pattern is anchored, so a string is accepted only when the grammar derives
 * all of it. Rule names are kept in the comments.
 */

/** `HEXDIG` (RFC 5234 Appendix B.1; case-insensitive, RFC 3986 Section 2.1). */
const HEXDIG = "[0-9A-Fa-f]";
/** `pct-encoded = "%" HEXDIG HEXDIG` (Section 2.1): every `%` begins one triplet. */
const PCT_ENCODED = `%${HEXDIG}{2}`;
/** `unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"` (Section 2.3). */
const UNRESERVED = String.raw`A-Za-z0-9\-._~`;
/** `sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="` (Section 2.2). */
const SUB_DELIMS = "!$&'()*+,;=";
/** `pchar = unreserved / pct-encoded / sub-delims / ":" / "@"` (Section 3.3). */
const PCHAR = `(?:[${UNRESERVED}${SUB_DELIMS}:@]|${PCT_ENCODED})`;

/** `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` (Section 3.1). */
const SCHEME = String.raw`[A-Za-z][A-Za-z0-9+\-.]*`;
/** `userinfo = *( unreserved / pct-encoded / sub-delims / ":" )` (Section 3.2.1). */
const USERINFO = `(?:[${UNRESERVED}${SUB_DELIMS}:]|${PCT_ENCODED})*`;

/** `dec-octet` (Section 3.2.2): 0-255 with no leading zero. */
const DEC_OCTET = "(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])";
/** `IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet` (Section 3.2.2). */
const IPV4ADDRESS = String.raw`${DEC_OCTET}\.${DEC_OCTET}\.${DEC_OCTET}\.${DEC_OCTET}`;
/** `h16 = 1*4HEXDIG` (Section 3.2.2). */
const H16 = `${HEXDIG}{1,4}`;
/** `ls32 = ( h16 ":" h16 ) / IPv4address` (Section 3.2.2). */
const LS32 = `(?:${H16}:${H16}|${IPV4ADDRESS})`;
/** `IPv6address` (Section 3.2.2): the nine alternatives of the ABNF, in order. */
const IPV6ADDRESS = `(?:${[
  `(?:${H16}:){6}${LS32}`,
  `::(?:${H16}:){5}${LS32}`,
  `(?:${H16})?::(?:${H16}:){4}${LS32}`,
  `(?:(?:${H16}:){0,1}${H16})?::(?:${H16}:){3}${LS32}`,
  `(?:(?:${H16}:){0,2}${H16})?::(?:${H16}:){2}${LS32}`,
  `(?:(?:${H16}:){0,3}${H16})?::${H16}:${LS32}`,
  `(?:(?:${H16}:){0,4}${H16})?::${LS32}`,
  `(?:(?:${H16}:){0,5}${H16})?::${H16}`,
  `(?:(?:${H16}:){0,6}${H16})?::`,
].join("|")})`;
/** `IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )` (Section 3.2.2). */
const IPVFUTURE = String.raw`[vV]${HEXDIG}+\.[${UNRESERVED}${SUB_DELIMS}:]+`;
/** `IP-literal = "[" ( IPv6address / IPvFuture ) "]"` (Section 3.2.2). */
const IP_LITERAL = String.raw`\[(?:${IPV6ADDRESS}|${IPVFUTURE})\]`;
/**
 * `reg-name = *( unreserved / pct-encoded / sub-delims )` (Section 3.2.2).
 * Every `IPv4address` is also a `reg-name`, so `host` needs only
 * `IP-literal / reg-name` for a syntax check: the first-match-wins rule of
 * Section 3.2.2 decides only how a host is interpreted, and a dotted name
 * that is not a valid IPv4 address (`1.2.3.256`) is a valid `reg-name`.
 */
const REG_NAME = `(?:[${UNRESERVED}${SUB_DELIMS}]|${PCT_ENCODED})*`;
/** `host = IP-literal / IPv4address / reg-name` (Section 3.2.2), captured. */
const HOST = `(?<host>${IP_LITERAL}|${REG_NAME})`;
/** `port = *DIGIT` (Section 3.2.3). */
const PORT = "[0-9]*";
/** `authority = [ userinfo "@" ] host [ ":" port ]` (Section 3.2). */
const AUTHORITY = `(?:${USERINFO}@)?${HOST}(?::${PORT})?`;

/** `segment = *pchar`, `segment-nz = 1*pchar` (Section 3.3). */
const SEGMENT = `${PCHAR}*`;
const SEGMENT_NZ = `${PCHAR}+`;
/**
 * `hier-part = "//" authority path-abempty / path-absolute / path-rootless /
 * path-empty` (Section 3), with `path-abempty = *( "/" segment )`,
 * `path-absolute = "/" [ segment-nz *( "/" segment ) ]`,
 * `path-rootless = segment-nz *( "/" segment )` and `path-empty = 0<pchar>`
 * (Section 3.3).
 */
const HIER_PART = `(?://${AUTHORITY}(?:/${SEGMENT})*|/(?:${SEGMENT_NZ}(?:/${SEGMENT})*)?|${SEGMENT_NZ}(?:/${SEGMENT})*|)`;
/** `query = *( pchar / "/" / "?" )` (Section 3.4). */
const QUERY = `(?:${PCHAR}|[/?])*`;

/**
 * `absolute-URI = scheme ":" hier-part [ "?" query ]` (Section 4.3). It has
 * no fragment, so a `#` anywhere fails the match: an operation target, like
 * an RFC 8707 resource indicator, never carries one. The pattern carries no
 * `u` flag and every class is ASCII, so a space, a control character, DEL or
 * any non-ASCII code point fails it too.
 */
const ABSOLUTE_URI = new RegExp(String.raw`^(?<scheme>${SCHEME}):${HIER_PART}(?:\?${QUERY})?$`);

/**
 * `http` and `https` (RFC 9110, Sections 4.2.1 and 4.2.2): the URI takes the
 * `"//" authority` form, and "a recipient that processes such a URI
 * reference MUST reject it as invalid" when its host is empty. Scheme names
 * compare case-insensitively (RFC 3986 Section 3.1); the operand itself is
 * never rewritten. This is the one scheme-specific check here: other schemes
 * are held to the generic grammar only.
 */
const HTTP_SCHEME = /^https?$/i;

/**
 * Whether `value` is a string holding one RFC 3986 `absolute-URI` (Section
 * 4.3), so with no fragment, in which every `%` begins a `pct-encoded`
 * triplet and every character is one the grammar permits where it appears;
 * an `http` or `https` URI also names a non-empty host. Syntax only: the
 * value is matched as given and never parsed into, or replaced by, a
 * different spelling, so a recorded or committed value keeps the submitted
 * bytes and an `exact` comparison reads it as given. The WHATWG URL parser
 * is not used: it accepts what this grammar refuses (`%zz`, a trailing `%`,
 * `https:x`, `https:///x`) and refuses what it permits (an `IPvFuture`
 * literal, a dotted `reg-name` such as `1.2.3.256`).
 *
 * @spec resource-access#entry-validation, mission#mission-intent (#1310,
 * D480) — the one check every resource identifier the issuer accepts goes
 * through: a Mission Intent's `target_resources`, an entry's `resource` at
 * every intake, configuration load and derivation, and an operation target
 * ({@link isOperationTarget}).
 */
export function isAbsoluteUri(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const m = ABSOLUTE_URI.exec(value);
  if (m === null) return false;
  const { scheme, host } = m.groups ?? {};
  return !HTTP_SCHEME.test(scheme ?? "") || (host !== undefined && host.length > 0);
}

/**
 * Whether `value` is a well-formed operation target: one {@link
 * isAbsoluteUri} value, matched as given.
 */
export function isOperationTarget(value: unknown): value is string {
  return isAbsoluteUri(value);
}

/** The outcome of matching one entry against an operation target. */
export type ResourceMatch = "match" | "no-match" | "unsupported";

/** The `resource_match` forms this implementation enforces. */
export const ENFORCED_RESOURCE_MATCHES: readonly string[] = Object.freeze(["exact"]);

/**
 * Match one entry's `resource` against an operation target under the entry's
 * `resource_match`. `exact` (or absent) compares the JSON-decoded `resource`
 * and the target character for character: no case folding, default-port
 * removal, percent-decoding, query removal or trailing-slash equivalence.
 * Any other `resource_match`, `prefix` included, is `unsupported`, which the
 * caller treats as providing no authority.
 */
export function matchResource(
  entry: { readonly resource: unknown; readonly resource_match?: unknown },
  target: string,
): ResourceMatch {
  const form = entry.resource_match;
  if (form !== undefined && !ENFORCED_RESOURCE_MATCHES.includes(form as string))
    return "unsupported";
  return typeof entry.resource === "string" && entry.resource === target ? "match" : "no-match";
}

/** Whether an entry provides authority over `target`: a `match`, never an `unsupported` entry. */
export function entryMatchesTarget(
  entry: { readonly resource: unknown; readonly resource_match?: unknown },
  target: string,
): boolean {
  return matchResource(entry, target) === "match";
}

/**
 * An explicit service-level operation contract: the documented statement
 * that every operation it covers acts on the service identified by
 * `service`. It is the one contract form this implementation supports.
 */
export interface ServiceLevelContract {
  readonly service: string;
}

/** The contract forms this implementation can evaluate. */
export type OperationContract = ServiceLevelContract;

/** Why no operation target was established. Every reason refuses the operation. */
export type OperationTargetRefusal =
  /** No contract is declared for the operation: no fallback applies. */
  | "no_contract"
  /** A declared contract has a form this implementation does not support. */
  | "unsupported_contract"
  /** The declared contracts yield more than one target. */
  | "ambiguous"
  /** The contract yields a value that is not a well-formed operation target. */
  | "malformed";

export type OperationTargetResolution =
  | { readonly ok: true; readonly target: string }
  | { readonly ok: false; readonly reason: OperationTargetRefusal };

/**
 * The single-target rule: the candidate targets an operation's contract
 * yields establish a target only when they name exactly one value, and that
 * value is a well-formed operation target. None is `no_contract`; two or more
 * distinct values are `ambiguous`.
 */
export function resolveOperationTarget(candidates: readonly unknown[]): OperationTargetResolution {
  const distinct: unknown[] = [];
  for (const c of candidates) if (!distinct.includes(c)) distinct.push(c);
  if (distinct.length === 0) return { ok: false, reason: "no_contract" };
  if (distinct.length > 1) return { ok: false, reason: "ambiguous" };
  const only = distinct[0];
  return isOperationTarget(only) ? { ok: true, target: only } : { ok: false, reason: "malformed" };
}

/**
 * Establish an operation's target from the contract (or contracts) its
 * trusted operation profile declares for it. Absent or empty is
 * `no_contract`; a contract other than `{ service: <URI> }` is
 * `unsupported_contract`; declarations naming different services are
 * `ambiguous`. Nothing here reads an entry, an audience, or a caller
 * argument.
 */
export function establishOperationTarget(declared: unknown): OperationTargetResolution {
  if (declared === undefined || declared === null) return { ok: false, reason: "no_contract" };
  const contracts: readonly unknown[] = Array.isArray(declared) ? declared : [declared];
  const candidates: unknown[] = [];
  for (const contract of contracts) {
    if (
      !isObject(contract) ||
      Object.keys(contract).length !== 1 ||
      !Object.hasOwn(contract, "service")
    ) {
      return { ok: false, reason: "unsupported_contract" };
    }
    candidates.push(contract.service);
  }
  return resolveOperationTarget(candidates);
}
