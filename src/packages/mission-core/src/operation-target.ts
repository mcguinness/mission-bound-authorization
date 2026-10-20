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
 * - Contracts: an explicit service-level contract, `{ service: <URI> }`,
 *   which names the service identifier as the target of every operation it
 *   covers; and an argument-derived contract, `{ template: <URI Template> }`,
 *   which derives a finer target from one of the operation's validated
 *   arguments (the order or invoice the operation acts on). A caller that
 *   supplies no arguments supports only the service-level form, and any other
 *   form is `unsupported_contract`.
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
 * `service`.
 */
export interface ServiceLevelContract {
  readonly service: string;
}

/**
 * An argument-derived operation contract: the documented statement that the
 * target of every operation it covers is `template` with its one variable
 * replaced by the operation's validated argument of that name, for example
 * `https://api.example/orders/{order_id}` for the order an operation reads.
 *
 * `template` is an RFC 6570 URI Template of Level 1 holding exactly one
 * expression, a simple string expansion (Section 3.2.2) whose `varname` uses
 * only ALPHA, DIGIT and `_` (a subset of Section 2.3), placed in the path:
 * the literal before it is a scheme, `://`, an authority and a `/`, with no
 * `?` or `#`. An argument therefore never moves the target to another host
 * and never reaches the query. No operator, modifier, list or second
 * expression is supported: such a template is `unsupported_contract`.
 */
export interface ArgumentDerivedContract {
  readonly template: string;
}

/** The contract forms this implementation can evaluate. */
export type OperationContract = ServiceLevelContract | ArgumentDerivedContract;

/** Why no operation target was established. Every reason refuses the operation. */
export type OperationTargetRefusal =
  /** No contract is declared for the operation: no fallback applies. */
  | "no_contract"
  /** A declared contract has a form this implementation does not support. */
  | "unsupported_contract"
  /**
   * An argument-derived contract's argument is absent, null or empty: the
   * operation names no object, and the service identifier is never
   * substituted for it.
   */
  | "missing_argument"
  /** The declared contracts yield more than one target, or the argument is a list rather than one value. */
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

/** A template split at its one expression. */
interface ParsedTemplate {
  readonly before: string;
  readonly varname: string;
  readonly after: string;
}

/** `scheme "://" authority "/" path` with no `?`, `#` or brace: the literal before the variable. */
const TEMPLATE_HEAD = /^[A-Za-z][A-Za-z0-9+\-.]*:\/\/[^/?#{}]*\/[^?#{}]*$/;
/** The supported `varname`: ALPHA, DIGIT and `_` only. */
const TEMPLATE_VARNAME = /^[A-Za-z0-9_]+$/;

/**
 * Split an argument-derived contract's template at its one expression, or
 * `undefined` for any template outside the supported form: not a string, no
 * expression or more than one, an operator, modifier or list in the
 * expression, or the expression outside the path.
 */
function parseTemplate(template: unknown): ParsedTemplate | undefined {
  if (typeof template !== "string") return undefined;
  const open = template.indexOf("{");
  const close = template.indexOf("}");
  if (open < 0 || close < open) return undefined;
  const before = template.slice(0, open);
  const varname = template.slice(open + 1, close);
  const after = template.slice(close + 1);
  if (!TEMPLATE_HEAD.test(before) || !TEMPLATE_VARNAME.test(varname)) return undefined;
  if (after.includes("{") || after.includes("}")) return undefined;
  return { before, varname, after };
}

/**
 * RFC 6570 simple string expansion of one value (Section 3.2.2): each
 * character outside `unreserved` (RFC 3986 Section 2.3) is UTF-8 encoded and
 * percent-encoded with uppercase hexadecimal digits (RFC 3986 Section 2.1),
 * so `/`, `?`, `#` and `%` in an argument never act as delimiters. A value
 * that is not well-formed UTF-16 (a lone surrogate) cannot be encoded.
 */
function expandValue(value: string): string | undefined {
  try {
    return encodeURIComponent(value).replace(
      /[!'()*]/g,
      (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
    );
  } catch {
    return undefined;
  }
}

/** One expanded value: one or more `unreserved` characters or `pct-encoded` triplets. */
const EXPANDED_VALUE = /^(?:[A-Za-z0-9\-._~]|%[0-9A-F]{2})+$/;

/**
 * A dot-segment (RFC 3986 Section 3.3) as the whole value: `.` and `..`
 * name a different resource once dot-segments are removed (Section 5.2.4), so
 * a value that is one is refused rather than matched as a literal.
 */
const isDotSegment = (value: string): boolean => value === "." || value === "..";

/**
 * Derive the target one argument-derived contract establishes from the
 * operation's validated arguments. Only the argument the template names is
 * read; any other argument, an `operation_target` or `resource` argument
 * included, is never consulted.
 */
function deriveFromTemplate(
  parsed: ParsedTemplate,
  args: Readonly<Record<string, unknown>>,
): OperationTargetResolution {
  const value = Object.hasOwn(args, parsed.varname) ? args[parsed.varname] : undefined;
  if (value === undefined || value === null || value === "") {
    return { ok: false, reason: "missing_argument" };
  }
  if (Array.isArray(value)) return { ok: false, reason: "ambiguous" };
  if (typeof value !== "string" || isDotSegment(value)) return { ok: false, reason: "malformed" };
  const expanded = expandValue(value);
  if (expanded === undefined) return { ok: false, reason: "malformed" };
  const target = `${parsed.before}${expanded}${parsed.after}`;
  return isOperationTarget(target) ? { ok: true, target } : { ok: false, reason: "malformed" };
}

/** Whether `contract` is exactly `{ <member>: <value> }`. */
const isSingleMember = (contract: unknown, member: string): contract is Record<string, unknown> =>
  isObject(contract) && Object.keys(contract).length === 1 && Object.hasOwn(contract, member);

/**
 * Establish an operation's target from the contract (or contracts) its
 * trusted operation profile declares for it, and, for an argument-derived
 * contract, from the operation's validated arguments.
 *
 * Absent or empty is `no_contract`. A `{ service: <URI> }` contract yields its
 * service whatever the arguments. A `{ template: <URI Template> }` contract
 * yields the template expanded with the argument it names, and is
 * `unsupported_contract` when `args` is not supplied: a caller that passes no
 * arguments supports the service-level form only. An absent or empty argument
 * is `missing_argument`, never a fallback to the service identifier; an
 * argument carrying a list is `ambiguous`; a non-string or dot-segment
 * argument is `malformed`. Any other contract form is `unsupported_contract`,
 * and declarations yielding different targets are `ambiguous`. Nothing here
 * reads an entry, an audience, or an argument the contract does not name.
 */
export function establishOperationTarget(
  declared: unknown,
  args?: Readonly<Record<string, unknown>>,
): OperationTargetResolution {
  if (declared === undefined || declared === null) return { ok: false, reason: "no_contract" };
  const contracts: readonly unknown[] = Array.isArray(declared) ? declared : [declared];
  const candidates: unknown[] = [];
  for (const contract of contracts) {
    if (isSingleMember(contract, "service")) {
      candidates.push(contract.service);
      continue;
    }
    const parsed = isSingleMember(contract, "template")
      ? parseTemplate(contract.template)
      : undefined;
    if (parsed === undefined || args === undefined)
      return { ok: false, reason: "unsupported_contract" };
    const derived = deriveFromTemplate(parsed, args);
    if (!derived.ok) return derived;
    candidates.push(derived.target);
  }
  return resolveOperationTarget(candidates);
}

/**
 * @spec authzen#pdp-request consistency check 11 (#1276, D457): whether
 * `target` is a value `contract` establishes for some argument, so a PDP can
 * hold a PEP to the targets its registered operation contracts establish. A
 * service-level contract admits its service alone. An argument-derived
 * contract admits the template expanded with one non-empty, non-dot-segment
 * value in its canonical encoding (every `pct-encoded` triplet names a UTF-8
 * octet outside `unreserved`, in uppercase), and nothing else. The comparison
 * reads `target` as given, with no normalization. This is contract coverage,
 * not entry matching: it grants no authority.
 */
export function contractCanEstablish(contract: unknown, target: unknown): boolean {
  if (!isOperationTarget(target)) return false;
  if (isSingleMember(contract, "service")) return contract.service === target;
  const parsed = isSingleMember(contract, "template")
    ? parseTemplate(contract.template)
    : undefined;
  if (parsed === undefined) return false;
  const { before, after } = parsed;
  if (target.length <= before.length + after.length) return false;
  if (!target.startsWith(before) || !target.endsWith(after)) return false;
  const expanded = target.slice(before.length, target.length - after.length);
  if (!EXPANDED_VALUE.test(expanded)) return false;
  let value: string;
  try {
    value = decodeURIComponent(expanded);
  } catch {
    return false;
  }
  return !isDotSegment(value) && expandValue(value) === expanded;
}
