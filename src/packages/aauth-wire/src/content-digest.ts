import { createHash, timingSafeEqual } from "node:crypto";
import {
  type Dictionary,
  isInnerList,
  parseDictionary,
  serializeDictionary,
} from "structured-headers";

export type DigestAlgorithm = "sha-256" | "sha-512";

const HASH: Record<DigestAlgorithm, string> = { "sha-256": "sha256", "sha-512": "sha512" };

/**
 * A Content-Digest field value for `body`.
 *
 * @spec rfc9530#section-2
 */
export function contentDigest(body: Uint8Array, algorithm: DigestAlgorithm = "sha-256"): string {
  const digest = createHash(HASH[algorithm]).update(body).digest();
  const members: Dictionary = new Map([[algorithm, [new Uint8Array(digest), new Map()]]]);
  return serializeDictionary(members);
}

/**
 * True when `fieldValue` carries at least one sha-256 or sha-512 digest and
 * every such digest matches `body`. Digests under other algorithms are
 * ignored; a field with none this package computes does not bind the body.
 *
 * @spec rfc9530#section-2
 */
export function verifyContentDigest(fieldValue: string, body: Uint8Array): boolean {
  let members: Dictionary;
  try {
    members = parseDictionary(fieldValue);
  } catch {
    return false;
  }
  let matched = false;
  for (const [name, member] of members) {
    if (!Object.hasOwn(HASH, name)) continue;
    if (isInnerList(member) || !(member[0] instanceof ArrayBuffer)) return false;
    const expected = createHash(HASH[name as DigestAlgorithm])
      .update(body)
      .digest();
    const given = Buffer.from(member[0]);
    if (given.length !== expected.length || !timingSafeEqual(given, expected)) return false;
    matched = true;
  }
  return matched;
}
