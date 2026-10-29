/**
 * @spec resource-access#qualified-narrowing, mission#transformation-capabilities
 * (#1377, D1025): the `narrowing` capability an authorization server declares
 * for `mission_resource_access`, and the one relation every narrowing site
 * applies under it.
 *
 * The OAuth binding: "The AS MUST NOT narrow, delegate, or project to `scope`
 * an entry of a type for which it has not declared the corresponding
 * capability; on an undeclared capability the entry is carried as approved."
 * Resource Access lets `narrowing` be declared for a narrowing domain, "a
 * document named by `id` and `digest`"; under it "the authorization server
 * applies {{subset}} ... to a pair of entries both within the domain", and
 * "For any other pair, `narrowing` is undeclared: the entry is carried as
 * approved, and a subset is established only by equality."
 *
 * The domain document's schema is known to {@link narrowingDomainViolation}
 * alone; every other caller reads a validated {@link NarrowingDomain}.
 */

import type { AuthorityEntry } from "./authority-entry.js";
import {
  isSubsetEntry,
  SUPPORTED_CONSTRAINT_KEYS,
  SUPPORTED_ENTRY_MEMBERS,
  unsupportedActionFamily,
  withoutCapabilitySources,
} from "./authority-subset.js";
import { canonicalDigest, canonicalize, type JsonValue } from "./canonicalize.js";
import { isAbsoluteUri } from "./operation-target.js";

/** @spec resource-access#qualified-narrowing: the matching modes a domain can cover. */
const MATCHING_MODES: readonly string[] = Object.freeze(["exact", "prefix"]);

/**
 * @spec resource-access#qualified-narrowing `limitations`: the identifiers
 * Resource Access defines. `delegate-matcher-identity`: a matcher list "is
 * within its reference only when each matcher equals a reference matcher on
 * `sub` and `sub_profile`, so a list narrower by containment is refused".
 */
export const NARROWING_LIMITATIONS: readonly string[] = Object.freeze([
  "delegate-matcher-identity",
]);

/** The members a narrowing domain document carries, and no other. */
const DOMAIN_MEMBERS: readonly string[] = Object.freeze([
  "id",
  "type",
  "capability",
  "resource_match",
  "members",
  "constraints",
  "limitations",
]);

/** The members every domain covers: "including `type`, `resource`, and `actions`". */
const REQUIRED_COVERED_MEMBERS: readonly string[] = Object.freeze(["type", "resource", "actions"]);

/** The integrity-anchor encoded form: `sha-256:` and an unpadded base64url SHA-256. */
const DIGEST_FORM = /^sha-256:[A-Za-z0-9_-]{43}$/;

/** @spec resource-access#qualified-narrowing: a validated narrowing domain document. */
export interface NarrowingDomain {
  id: string;
  type: "mission_resource_access";
  capability: "narrowing";
  resource_match: readonly string[];
  members: readonly string[];
  constraints: readonly string[];
  limitations: readonly string[];
}

/**
 * The `narrowing` capability as a reader resolves it for the type: declared in
 * full (`true`), not declared (`false`, or a qualified value the reader cannot
 * validate), or declared for a domain.
 */
export type NarrowingDeclaration =
  | { readonly kind: "full" }
  | { readonly kind: "undeclared" }
  | { readonly kind: "domain"; readonly domain: NarrowingDomain; readonly digest: string };

/** `narrowing: true`: the subset rule over every member Resource Access specifies. */
export const NARROWING_IN_FULL: NarrowingDeclaration = Object.freeze({ kind: "full" });

/** `narrowing` not declared: every entry is carried as approved. */
export const NARROWING_UNDECLARED: NarrowingDeclaration = Object.freeze({ kind: "undeclared" });

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === "string");
}

/**
 * @spec resource-access#qualified-narrowing: why `document` is not a narrowing
 * domain document of the form Resource Access gives it, or undefined.
 */
export function narrowingDomainViolation(document: unknown): string | undefined {
  if (document === null || typeof document !== "object" || Array.isArray(document)) {
    return "a narrowing domain document is a JSON object";
  }
  const d = document as Record<string, unknown>;
  const extra = Object.keys(d).find((k) => !DOMAIN_MEMBERS.includes(k));
  if (extra !== undefined) return `a narrowing domain document carries no member '${extra}'`;
  if (!isAbsoluteUri(d.id)) return "id must be an absolute URI";
  if (d.type !== "mission_resource_access") return "type must be mission_resource_access";
  if (d.capability !== "narrowing") return "capability must be narrowing";
  if (
    !isStringArray(d.resource_match) ||
    d.resource_match.length === 0 ||
    !d.resource_match.every((m) => MATCHING_MODES.includes(m)) ||
    new Set(d.resource_match).size !== d.resource_match.length
  ) {
    return "resource_match must be a non-empty array of distinct matching modes, exact or prefix";
  }
  if (
    !isStringArray(d.members) ||
    !REQUIRED_COVERED_MEMBERS.every((m) => (d.members as string[]).includes(m))
  ) {
    return "members must be an array of member names including type, resource and actions";
  }
  if (!isStringArray(d.constraints)) return "constraints must be an array of constraints keys";
  if (
    d.limitations !== undefined &&
    (!isStringArray(d.limitations) ||
      !d.limitations.every((l) => NARROWING_LIMITATIONS.includes(l)))
  ) {
    return "limitations must be an array of the limitation identifiers Resource Access defines";
  }
  return undefined;
}

/** @spec resource-access#qualified-narrowing `digest`: SHA-256 over the JCS serialization, `sha-256:` and base64url. */
export function narrowingDomainDigest(document: JsonValue): string {
  return canonicalDigest(document);
}

/** Why a qualified `narrowing` value is not `{ "domain": { "id", "digest" } }` of the given form, or undefined. */
export function qualifiedNarrowingViolation(value: unknown): string | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return "a qualified narrowing value is a JSON object";
  }
  const v = value as Record<string, unknown>;
  const extra = Object.keys(v).find((k) => k !== "domain");
  if (extra !== undefined) return `a qualified narrowing value carries no member '${extra}'`;
  const domain = v.domain;
  if (domain === null || typeof domain !== "object" || Array.isArray(domain))
    return "domain must be an object";
  const ref = domain as Record<string, unknown>;
  const refExtra = Object.keys(ref).find((k) => k !== "id" && k !== "digest");
  if (refExtra !== undefined) return `domain carries no member '${refExtra}'`;
  if (!isAbsoluteUri(ref.id)) return "domain.id must be an absolute URI";
  if (typeof ref.digest !== "string" || !DIGEST_FORM.test(ref.digest)) {
    return "domain.digest must be sha-256: and an unpadded base64url SHA-256";
  }
  return undefined;
}

/** A resolution: the declaration, and the fault that made a declared value count as `false`, if any. */
export interface NarrowingResolution {
  declaration: NarrowingDeclaration;
  fault?: string;
}

/**
 * @spec resource-access#qualified-narrowing, mission#transformation-capabilities:
 * a reader's resolution of one carrier's `narrowing` member, or undefined when
 * the carrier does not declare it (the reader falls through to the next
 * carrier). `true` and `false` keep their meanings. A qualified value resolves
 * to its domain only when `documents` yields, for its `id`, a document of the
 * form Resource Access gives with that `id` and the value's `digest`; "a
 * reader treats a carrier as declaring `narrowing` `false`" otherwise, and the
 * fault says why. That carrier still governs: the result is never undefined
 * for a declared member.
 */
export function resolveNarrowing(
  value: unknown,
  documents: (id: string) => unknown,
): NarrowingResolution | undefined {
  if (value === undefined) return undefined;
  if (value === true) return { declaration: NARROWING_IN_FULL };
  if (value === false) return { declaration: NARROWING_UNDECLARED };
  const violation = qualifiedNarrowingViolation(value);
  if (violation !== undefined) return { declaration: NARROWING_UNDECLARED, fault: violation };
  const { id, digest } = (value as { domain: { id: string; digest: string } }).domain;
  const document = documents(id);
  if (document === undefined)
    return { declaration: NARROWING_UNDECLARED, fault: `no narrowing domain document for ${id}` };
  const formFault = narrowingDomainViolation(document);
  if (formFault !== undefined) return { declaration: NARROWING_UNDECLARED, fault: formFault };
  const d = document as NarrowingDomain;
  if (d.id !== id)
    return { declaration: NARROWING_UNDECLARED, fault: `the document for ${id} names ${d.id}` };
  const computed = narrowingDomainDigest(document as JsonValue);
  if (computed !== digest) {
    return {
      declaration: NARROWING_UNDECLARED,
      fault: `the document for ${id} has digest ${computed}, not ${digest}`,
    };
  }
  return {
    declaration: {
      kind: "domain",
      digest,
      domain: {
        id: d.id,
        type: d.type,
        capability: d.capability,
        resource_match: [...d.resource_match],
        members: [...d.members],
        constraints: [...d.constraints],
        limitations: [...(d.limitations ?? [])],
      },
    },
  };
}

/**
 * @spec resource-access#qualified-narrowing: "An authorization server MUST NOT
 * declare a qualified value whose domain lists a `constraints` key whose subset
 * and intersection rules it does not implement." This implementation's rules
 * cover {@link SUPPORTED_CONSTRAINT_KEYS} and the members of
 * {@link SUPPORTED_ENTRY_MEMBERS}; why `domain` claims more, or undefined.
 */
export function unimplementedDomainClaim(domain: NarrowingDomain): string | undefined {
  const key = domain.constraints.find((k) => !SUPPORTED_CONSTRAINT_KEYS.includes(k));
  if (key !== undefined)
    return `the domain lists the constraints key ${key}, whose rules this implementation does not implement`;
  const member = domain.members.find((m) => !SUPPORTED_ENTRY_MEMBERS.includes(m));
  if (member !== undefined)
    return `the domain lists the member ${member}, which this implementation does not compare`;
  return undefined;
}

/**
 * @spec resource-access#qualified-narrowing: "An entry is within a domain when
 * its `resource_match` (`exact` when absent) is among the domain's
 * `resource_match`, each of its members is among `members`, each of its
 * `constraints` keys is among `constraints`, and each of its actions is an
 * action identifier rather than an action family."
 */
export function entryWithinDomain(entry: AuthorityEntry, domain: NarrowingDomain): boolean {
  const match = entry.resource_match === undefined ? "exact" : entry.resource_match;
  if (typeof match !== "string" || !domain.resource_match.includes(match)) return false;
  // Members are counted on the canonical form, where `resource_match` is
  // present only when it is not `exact`.
  const members = Object.keys(entry).filter((m) => m !== "resource_match" || match !== "exact");
  if (!members.every((m) => domain.members.includes(m))) return false;
  const constraints = entry.constraints;
  if (constraints !== undefined) {
    if (constraints === null || typeof constraints !== "object" || Array.isArray(constraints))
      return false;
    if (!Object.keys(constraints).every((k) => domain.constraints.includes(k))) return false;
  }
  return unsupportedActionFamily(entry) === undefined;
}

/**
 * Whether `declaration` lets the authorization server narrow `candidate`
 * against `reference`: in full, always; undeclared, never; for a domain, when
 * both entries are within it.
 */
export function narrowingPermits(
  declaration: NarrowingDeclaration,
  candidate: AuthorityEntry,
  reference: AuthorityEntry,
): boolean {
  if (declaration.kind === "full") return true;
  if (declaration.kind === "undeclared") return false;
  return (
    entryWithinDomain(candidate, declaration.domain) &&
    entryWithinDomain(reference, declaration.domain)
  );
}

/** An entry in canonical form: `resource_match` present only when it is not `exact`. */
function canonicalEntry(entry: AuthorityEntry): string | undefined {
  const { resource_match, ...rest } = entry as AuthorityEntry & { resource_match?: unknown };
  const form =
    resource_match === undefined || resource_match === "exact" ? rest : { ...rest, resource_match };
  try {
    return canonicalize(form as unknown as JsonValue);
  } catch {
    return undefined;
  }
}

/** @spec mission#subset "equal ({{subset}})": the two entries are equal under the canonical form. */
export function entriesEqual(a: AuthorityEntry, b: AuthorityEntry): boolean {
  const ca = canonicalEntry(a);
  return ca !== undefined && ca === canonicalEntry(b);
}

/**
 * The subset relation under `declaration`: {@link isSubsetEntry} where
 * narrowing is permitted for the pair, and equality otherwise ("a subset is
 * established only by equality").
 */
export function isSubsetEntryUnder(
  declaration: NarrowingDeclaration,
  candidate: AuthorityEntry,
  reference: AuthorityEntry,
): boolean {
  return narrowingPermits(declaration, candidate, reference)
    ? isSubsetEntry(candidate, reference)
    : entriesEqual(candidate, reference);
}

/** Every candidate entry is within some granted entry under `declaration`. */
export function isSubsetSetUnder(
  declaration: NarrowingDeclaration,
  candidate: readonly AuthorityEntry[],
  granted: readonly AuthorityEntry[],
): boolean {
  return candidate.every((c) => granted.some((g) => isSubsetEntryUnder(declaration, c, g)));
}

/** {@link isSubsetSetUnder} at a wire boundary, `capability_sources` set aside on both sides. */
export function isSubsetSetUnderIgnoringCapabilitySources(
  declaration: NarrowingDeclaration,
  candidate: readonly AuthorityEntry[],
  granted: readonly AuthorityEntry[],
): boolean {
  return isSubsetSetUnder(
    declaration,
    withoutCapabilitySources(candidate),
    withoutCapabilitySources(granted),
  );
}

/**
 * The entries of `produced` the authorization server may carry from
 * `presented` under `declaration`: each must be within a presented entry, and
 * where narrowing is not permitted for the pair, equal to it. An entry a
 * projection modified without a declaration is dropped, never carried as if
 * approved.
 */
export function carriedUnder(
  declaration: NarrowingDeclaration,
  produced: readonly AuthorityEntry[],
  presented: readonly AuthorityEntry[],
): AuthorityEntry[] {
  return produced.filter((e) => presented.some((p) => isSubsetEntryUnder(declaration, e, p)));
}
