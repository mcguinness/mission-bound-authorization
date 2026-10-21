/**
 * @spec resource-access#resource-contract, runtime#resource-contract (#249,
 * D553): the resource contract reference an authority entry carries, and the
 * one comparison every party applies to it.
 *
 * Resource Access defines the member: "`resource_contract`: OPTIONAL. An
 * object. A reference to the resource contract under which the resource
 * interprets the entry's `actions` and `constraints`", with exactly `id` ("an
 * absolute URI that names the contract across its versions"), `version` ("a
 * non-empty string naming one version of the contract") and `digest` ("The
 * SHA-256 digest of the JCS serialization of that version's contract
 * document, in the integrity-anchor encoded form").
 *
 * Runtime fixes the digest construction: "the canonical-object digest of the
 * contract document, with the construction and `sha-256:` encoding of
 * {{parameter-digest}}", so {@link resourceContractDigest} is
 * {@link canonicalDigest} over the document, never the `{typ, iss, value}`
 * anchor envelope.
 *
 * Comparison is exact and never a narrowing: "There is no compatibility
 * algorithm and no fallback: a reference resolves only to the contract it
 * names, never to a newer or equivalent version." {@link sameResourceContract}
 * is that equality, absent equal only to absent.
 */

import { canonicalDigest, type JsonValue } from "./canonicalize.js";
import { isAbsoluteUri } from "./operation-target.js";

/** @spec resource-access#resource-access-type `resource_contract`. */
export interface ResourceContractRef {
  id: string;
  version: string;
  digest: string;
}

/** The integrity-anchor encoded form: `sha-256:` and an unpadded base64url SHA-256. */
const DIGEST_FORM = /^sha-256:[A-Za-z0-9_-]{43}$/;

/** The members a reference carries, and no other. */
export const RESOURCE_CONTRACT_MEMBERS: readonly string[] = Object.freeze([
  "id",
  "version",
  "digest",
]);

/**
 * @spec resource-access#entry-validation: "its `resource_contract` is not an
 * object with exactly the members `id`, `version`, and `digest`, or one of
 * them does not have the form {{resource-access-type}} gives it". The
 * violation for `value`, or undefined when it is a well-formed reference. The
 * caller maps a violation to its boundary's own error
 * (`invalid_authorization_details` on a protocol surface).
 */
export function resourceContractViolation(value: unknown): string | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return "resource_contract must be an object";
  }
  const o = value as Record<string, unknown>;
  const extra = Object.keys(o).find((k) => !RESOURCE_CONTRACT_MEMBERS.includes(k));
  if (extra !== undefined) return `resource_contract carries no member '${extra}'`;
  if (!isAbsoluteUri(o.id)) return "resource_contract.id must be an absolute URI";
  if (typeof o.version !== "string" || o.version.length === 0) {
    return "resource_contract.version must be a non-empty string";
  }
  if (typeof o.digest !== "string" || !DIGEST_FORM.test(o.digest)) {
    return "resource_contract.digest must be sha-256: and an unpadded base64url SHA-256";
  }
  return undefined;
}

/** Whether `value` is a well-formed reference ({@link resourceContractViolation}). */
export function isResourceContractRef(value: unknown): value is ResourceContractRef {
  return resourceContractViolation(value) === undefined;
}

/**
 * @spec resource-access#subset step 4, authzen#context-resource-contract:
 * "carries `resource_contract` exactly when B does, and then with `id`,
 * `version`, and `digest` each equal to B's"; "equals, member for member".
 * Absent equals only absent. A present value that is not a well-formed
 * reference equals nothing, itself included, so a malformed member never
 * passes as a match. Total and non-throwing.
 */
export function sameResourceContract(a: unknown, b: unknown): boolean {
  if (a === undefined || b === undefined) return a === undefined && b === undefined;
  if (!isResourceContractRef(a) || !isResourceContractRef(b)) return false;
  return a.id === b.id && a.version === b.version && a.digest === b.digest;
}

/** The reference `value` carries, copied member by member, or undefined. */
export function resourceContractOf(value: unknown): ResourceContractRef | undefined {
  if (!isResourceContractRef(value)) return undefined;
  return { id: value.id, version: value.version, digest: value.digest };
}

/**
 * @spec runtime#resource-contract: the `digest` a contract document's
 * reference carries: SHA-256 over the JCS serialization of the document,
 * `sha-256:` and unpadded base64url.
 */
export function resourceContractDigest(document: JsonValue): string {
  return canonicalDigest(document);
}
