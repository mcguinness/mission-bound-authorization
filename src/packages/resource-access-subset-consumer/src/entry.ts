// A mission_resource_access entry, validated and restricted to the supported
// subset (resource-access#resource-access-type, resource-access#entry-validation,
// vectors/mission-resource-access-subset/supported-subset.json).

import { Buffer } from "node:buffer";
import { CONSTRAINT_RULES } from "./constraints.js";
import { parseAbsoluteUri } from "./uri.js";

export const ENTRY_TYPE = "mission_resource_access";

/** The error code of every refusal (resource-access#entry-validation). */
export const REFUSAL_ERROR = "invalid_authorization_details";

/** The entry members a subset consumer implements (supported-subset.json `members`). */
export const SUBSET_MEMBERS: readonly string[] = [
  "type",
  "resource",
  "resource_match",
  "actions",
  "constraints",
  "resource_contract",
];

/** The resource_match values in the subset (supported-subset.json `resource_match`). */
export const SUBSET_RESOURCE_MATCH: readonly string[] = ["exact"];

/** A resource contract reference (resource-access#resource-access-type resource_contract). */
export interface ContractReference {
  readonly id: string;
  readonly version: string;
  readonly digest: string;
}

/** An entry that passed validation and lies within the subset. */
export interface ParsedEntry {
  readonly resource: string;
  readonly actions: readonly string[];
  /** Parsed constraint values by key. */
  readonly constraints: ReadonlyMap<string, unknown>;
  readonly contract?: ContractReference;
}

export type ParseResult =
  | { readonly ok: true; readonly entry: ParsedEntry }
  | {
      readonly ok: false;
      /** True when the input is valid under the draft but outside the subset. */
      readonly unsupported: boolean;
      readonly reason: string;
    };

// resource-access#resource-access-type actions: "an action identifier whose
// whole value matches [A-Za-z0-9_.:-]+, or an action family: an identifier
// followed by .*".
const ACTION_IDENTIFIER = /^[A-Za-z0-9_.:-]+$/;
// The digest's form: "sha-256: followed by the base64url encoding of the
// digest, without padding" (resource-access#resource-access-type
// resource_contract; binding#integrity-anchors step 4). A SHA-256 digest is 32
// octets, which base64url encodes without padding in 43 characters.
const DIGEST = /^sha-256:([A-Za-z0-9_-]{43})$/;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function refuse(reason: string): ParseResult {
  return { ok: false, unsupported: false, reason };
}

function unsupported(reason: string): ParseResult {
  return { ok: false, unsupported: true, reason };
}

function isCanonicalSha256(encoded: string): boolean {
  // The unpadded base64url of 32 octets: decoding and re-encoding returns the
  // same text only when the unused low bits of the last character are zero.
  // This checks the form of the digest; it never recomputes one.
  const octets = Buffer.from(encoded, "base64url");
  return octets.length === 32 && octets.toString("base64url") === encoded;
}

function parseContract(value: unknown): { contract: ContractReference } | { refusal: string } {
  // resource-access#entry-validation: refused when "its resource_contract is
  // not an object with exactly the members id, version, and digest, or one of
  // them does not have the form resource-access-type gives it".
  if (!isObject(value)) return { refusal: "resource_contract is not an object" };
  const keys = Object.keys(value);
  if (keys.length !== 3 || !["id", "version", "digest"].every((k) => keys.includes(k))) {
    return {
      refusal: "resource_contract does not have exactly the members id, version and digest",
    };
  }
  const { id, version, digest } = value;
  // id: "A string containing an absolute URI that names the contract".
  if (typeof id !== "string" || parseAbsoluteUri(id) === undefined) {
    return { refusal: "resource_contract.id is not an absolute URI" };
  }
  // version: "A non-empty string naming one version of the contract".
  if (typeof version !== "string" || version === "") {
    return { refusal: "resource_contract.version is not a non-empty string" };
  }
  if (typeof digest !== "string") return { refusal: "resource_contract.digest is not a string" };
  const m = DIGEST.exec(digest);
  if (m === null || m[1] === undefined || !isCanonicalSha256(m[1])) {
    return {
      refusal: "resource_contract.digest is not sha-256: and an unpadded base64url SHA-256 digest",
    };
  }
  return { contract: { id, version, digest } };
}

/**
 * Validate an entry and restrict it to the subset.
 *
 * `requireType` is true where the check reads `type` (proposal intake); the
 * vector format gives an entry without `type` where a check does not read it.
 * A present `type` must name this type in every case.
 */
export function parseEntry(value: unknown, requireType: boolean): ParseResult {
  if (!isObject(value)) return refuse("the entry is not a JSON object");

  // resource-access#resource-access-type type: "REQUIRED. A string. mission_resource_access."
  if ("type" in value) {
    if (value.type !== ENTRY_TYPE) return refuse(`type is not ${ENTRY_TYPE}`);
  } else if (requireType) {
    return refuse("type is absent");
  }

  for (const member of Object.keys(value)) {
    // resource-access#entry-validation: "The authorization server MUST refuse
    // an entry carrying locations".
    if (member === "locations")
      return refuse("the entry carries locations, which this type does not use");
    // supported-subset.json `members`: a member outside the subset is
    // unsupported input, refused rather than dropped (subset README).
    if (!SUBSET_MEMBERS.includes(member)) {
      return unsupported(`the entry member ${member} is outside the subset`);
    }
  }

  // resource-access#entry-validation: refused when "its resource is not an
  // absolute-URI (Section 4.3 of RFC3986), so no entry's resource carries a
  // fragment component".
  const resource = value.resource;
  if (typeof resource !== "string") return refuse("resource is absent or not a string");
  const uri = parseAbsoluteUri(resource);
  if (uri === undefined) return refuse("resource is not an RFC 3986 absolute-URI");
  // resource-access#entry-validation: refused when "its resource is an http or
  // https URI without the // authority form naming a non-empty host". The
  // scheme is case-insensitive (RFC 3986 section 3.1).
  const scheme = uri.scheme.toLowerCase();
  if (
    (scheme === "http" || scheme === "https") &&
    (uri.authority === undefined || uri.authority.host === "")
  ) {
    return refuse("an http or https resource lacks the // authority form with a non-empty host");
  }

  // resource-access#resource-access-type resource_match: "exact (the default
  // when the member is absent) or prefix". The subset admits exact only.
  if ("resource_match" in value) {
    const mode = value.resource_match;
    if (mode === "prefix") return unsupported("resource_match prefix is outside the subset");
    if (typeof mode !== "string" || !SUBSET_RESOURCE_MATCH.includes(mode)) {
      // resource-access#entry-validation: refused when "its resource_match is a
      // value the authorization server does not recognize".
      return refuse("resource_match is not a recognized value");
    }
  }

  // resource-access#entry-validation: refused when "its actions array is
  // empty, or one of its values is neither an action identifier nor an action
  // family". One malformed value refuses the whole entry; it is not dropped.
  const actions = value.actions;
  if (!Array.isArray(actions)) return refuse("actions is absent or not an array");
  if (actions.length === 0) return refuse("actions is empty");
  for (const action of actions) {
    if (typeof action !== "string") return refuse("an actions value is not a string");
    if (ACTION_IDENTIFIER.test(action)) continue;
    if (action.endsWith(".*") && ACTION_IDENTIFIER.test(action.slice(0, -2))) {
      // An action family is valid under the draft but outside the subset
      // (supported-subset.json `outside_subset.action_families`): refused as
      // unsupported input, never expanded or compared literally.
      return unsupported(`the action family ${action} is outside the subset`);
    }
    return refuse(
      `the action ${JSON.stringify(action)} is neither an action identifier nor an action family`,
    );
  }

  // resource-access#resource-access-type constraints: "OPTIONAL. An object."
  const constraints = new Map<string, unknown>();
  if ("constraints" in value) {
    const given = value.constraints;
    if (!isObject(given)) return refuse("constraints is not an object");
    for (const [key, raw] of Object.entries(given)) {
      const rule = CONSTRAINT_RULES.get(key);
      // resource-access#common-constraints: a key the consumer does not
      // implement "MUST NOT be dropped while the entry survives"; it is
      // unsupported input and is refused.
      if (rule === undefined)
        return unsupported(`the constraints key ${key} is outside the subset`);
      const parsed = rule.parse(raw);
      if ("refusal" in parsed) return refuse(parsed.refusal);
      constraints.set(key, parsed.value);
    }
  }

  let contract: ContractReference | undefined;
  if ("resource_contract" in value) {
    const parsed = parseContract(value.resource_contract);
    if ("refusal" in parsed) return refuse(parsed.refusal);
    contract = parsed.contract;
  }

  const entry: ParsedEntry =
    contract === undefined
      ? { resource, actions: actions as string[], constraints }
      : { resource, actions: actions as string[], constraints, contract };
  return { ok: true, entry };
}

/** A contract the consumer's trusted configuration names as current. */
export interface ConfiguredContract {
  readonly reference: ContractReference;
  /** The action identifiers the contract defines. */
  readonly actions: readonly string[];
  /** The resources it is current for; absent means every resource. */
  readonly resources?: readonly string[];
}

/** The consumer's trusted resource and deployment configuration. */
export interface ConsumerConfig {
  readonly currentContracts: readonly ConfiguredContract[];
}

/**
 * The approval-time rule for a proposed resource_contract
 * (resource-access#resource-contract Approval): refuse "a proposed entry whose
 * resource_contract does not equal, member for member, the reference of a
 * contract its configuration names as current for the entry's resource and
 * that defines every action and action family the entry lists". Returns a
 * refusal reason, or undefined when the entry passes. A client-proposed
 * reference is never authoritative: only the configuration decides.
 */
export function contractApprovalRefusal(
  entry: ParsedEntry,
  config: ConsumerConfig,
): string | undefined {
  const proposed = entry.contract;
  if (proposed === undefined) return undefined;
  const match = config.currentContracts.find(
    (c) =>
      c.reference.id === proposed.id &&
      c.reference.version === proposed.version &&
      c.reference.digest === proposed.digest &&
      (c.resources === undefined || c.resources.includes(entry.resource)),
  );
  if (match === undefined) {
    return "resource_contract is not the reference of a contract current for the entry resource";
  }
  const undefinedAction = entry.actions.find((a) => !match.actions.includes(a));
  if (undefinedAction !== undefined) {
    return `the referenced contract does not define the action ${undefinedAction}`;
  }
  return undefined;
}
