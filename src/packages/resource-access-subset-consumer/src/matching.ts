// Resource-server resource matching and operation-target establishment
// (resource-access#resource-matching), exact matching only.

export interface MatchResult {
  readonly outcome: "match" | "no-match";
  readonly reason: string;
}

export interface ResolutionResult {
  readonly outcome: "refuse-resolution" | "match" | "no-match";
  readonly reason: string;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Match one entry's resource against an established operation target.
 *
 * `resourceJsonText`, where given, is the entry's resource as it appeared in
 * JSON; it is decoded and compared without reserializing it.
 */
export function matchResource(
  entry: unknown,
  target: unknown,
  resourceJsonText?: unknown,
): MatchResult {
  if (!isObject(entry)) return { outcome: "no-match", reason: "the entry is not an object" };
  if (typeof target !== "string") return { outcome: "no-match", reason: "no operation target" };

  // resource-access#resource-access-type resource_match: exact is "the default
  // when the member is absent". A prefix entry is outside the subset, and a
  // resource server treats an entry carrying unsupported input as providing
  // no authority (resource-access#rs-enforcement, Failing closed); an
  // unrecognized value is unenforceable and fails closed.
  if ("resource_match" in entry && entry.resource_match !== "exact") {
    return {
      outcome: "no-match",
      reason:
        entry.resource_match === "prefix"
          ? "prefix matching is outside the subset: the entry provides no authority"
          : "an unrecognized resource_match fails closed",
    };
  }

  let resource: unknown = entry.resource;
  if (resourceJsonText !== undefined) {
    if (typeof resourceJsonText !== "string") {
      return { outcome: "no-match", reason: "the resource JSON text is not text" };
    }
    try {
      resource = JSON.parse(resourceJsonText);
    } catch {
      return { outcome: "no-match", reason: "the resource JSON text does not decode" };
    }
  }
  if (typeof resource !== "string")
    return { outcome: "no-match", reason: "resource is not a string" };

  // resource-access#resource-matching, Exact matching: "the entry's resource,
  // after JSON decoding, and the operation target are compared character for
  // character, including any query component. The comparison applies no case
  // folding, default-port removal, percent-decoding, query removal, or
  // trailing-slash equivalence".
  return resource === target
    ? { outcome: "match", reason: "the exact resource equals the operation target" }
    : { outcome: "no-match", reason: "the exact resource differs from the operation target" };
}

/** The members of a target-resolution or resource-match input this consumer reads. */
export interface ResolutionInput {
  readonly contract?: unknown;
  readonly resolved_target?: unknown;
  readonly metadata_identifier?: unknown;
  readonly entry?: unknown;
  readonly entries?: unknown;
}

/**
 * Establish the operation target from the operation contract, then match the
 * presented entries against it.
 *
 * resource-access#resource-matching, Operation target: the resource server
 * "MUST establish the target independently of the entries the request
 * presents" and "MUST refuse the operation when it cannot establish one
 * unambiguous target"; Operation contract: "There is no fallback to the
 * protected resource's metadata identifier: an operation contract MAY define
 * service-level authority and use that identifier as its target, but an
 * absent or ambiguous contract is not such a definition".
 */
export function resolveTarget(input: ResolutionInput): ResolutionResult {
  const contract = input.contract;
  if (contract === undefined || contract === null) {
    return {
      outcome: "refuse-resolution",
      reason: "no operation contract, and no fallback to the metadata identifier",
    };
  }
  if (!isObject(contract))
    return { outcome: "refuse-resolution", reason: "the operation contract is not an object" };

  // Every target the contract establishes. The entries are never consulted.
  const targets = new Set<string>();
  if ("candidates" in contract) {
    const candidates = contract.candidates;
    if (!Array.isArray(candidates) || !candidates.every((c) => typeof c === "string")) {
      return { outcome: "refuse-resolution", reason: "the contract candidates are not targets" };
    }
    for (const c of candidates) targets.add(c);
  }
  if (typeof input.resolved_target === "string") targets.add(input.resolved_target);
  // A service-level contract uses the metadata identifier as its target.
  if (contract.service_level === true && typeof input.metadata_identifier === "string") {
    targets.add(input.metadata_identifier);
  }
  if (targets.size !== 1) {
    return {
      outcome: "refuse-resolution",
      reason:
        targets.size === 0 ? "the contract establishes no target" : "the contract is ambiguous",
    };
  }
  const [target] = targets;

  // "MUST execute the operation on the target it matched": entries are
  // matched against the resolved target, never the request URI.
  const entries: unknown[] =
    input.entry !== undefined ? [input.entry] : Array.isArray(input.entries) ? input.entries : [];
  const matched = entries.some((e) => matchResource(e, target).outcome === "match");
  return matched
    ? { outcome: "match", reason: "an entry matches the resolved target" }
    : { outcome: "no-match", reason: "no entry matches the resolved target" };
}

/**
 * The resource-match check: an entry against a target the operation contract
 * establishes. An input that states the operation has no contract
 * (`contract: null`) establishes no target, so nothing matches.
 */
export function resourceMatchCheck(input: {
  readonly entry?: unknown;
  readonly target?: unknown;
  readonly entry_resource_json_text?: unknown;
  readonly contract?: unknown;
}): MatchResult {
  if ("contract" in input && input.contract === null) {
    return { outcome: "no-match", reason: "no operation contract establishes a target" };
  }
  return matchResource(input.entry, input.target, input.entry_resource_json_text);
}
