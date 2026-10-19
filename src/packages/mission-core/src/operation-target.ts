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

/** An RFC 3986 scheme followed by its `:`. */
const SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:/;

/**
 * Characters an RFC 3986 URI never contains: controls, space, `"<>\^`{|}`,
 * DEL and every non-ASCII code point. `#` begins a fragment, which an
 * operation target, like an RFC 8707 resource indicator, never carries.
 */
// biome-ignore lint/suspicious/noControlCharactersInRegex: the class exists to reject control characters.
const NOT_IN_TARGET = /[\u0000- "<>\\^`{|}#\u007f-￿]/;

/**
 * Whether `value` is a well-formed operation target: a string holding one
 * absolute URI with no fragment. Shape only: the value is never parsed into a
 * different spelling, so an `exact` comparison reads the operand as given.
 */
export function isOperationTarget(value: unknown): value is string {
  if (typeof value !== "string" || !SCHEME.test(value) || NOT_IN_TARGET.test(value)) return false;
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
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
  if (form !== undefined && !ENFORCED_RESOURCE_MATCHES.includes(form as string)) return "unsupported";
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
    if (!isObject(contract) || Object.keys(contract).length !== 1 || !Object.hasOwn(contract, "service")) {
      return { ok: false, reason: "unsupported_contract" };
    }
    candidates.push(contract.service);
  }
  return resolveOperationTarget(candidates);
}
