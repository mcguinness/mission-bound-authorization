/**
 * @spec runtime#decision-channel — shared HMAC helpers for the reference
 * remote decision channel ({@link ./server.js} + {@link ./client.js}): a
 * domain-separated keyed MAC over the canonical request/response bytes, so
 * "a signed decision request and response" (the draft's stated alternative
 * to mutual TLS or an equivalent mechanism) has one implementation on both
 * sides of the wire, never two independently maintained ones that can
 * drift apart. The response MAC binds the response bytes to the request
 * that produced them (PEP identity, nonce, issuance time, and a digest of
 * the request bytes, alongside the HTTP status and response body): a
 * response MAC computed over the body alone would let an intermediary
 * replay an old, validly signed permit as the answer to an unrelated
 * later request.
 */

import { createHash, createHmac, timingSafeEqual } from "node:crypto";

/**
 * Domain-separates the two MAC directions so a captured request signature
 * can never be replayed as a valid response signature (or vice versa) over
 * the same shared secret.
 */
export const REQUEST_MAC_DOMAIN = "mission-pdp-decision-request:v1";
export const RESPONSE_MAC_DOMAIN = "mission-pdp-decision-response:v1";

/** SHA-256 hex digest of a UTF-8 string; the response MAC's canonical-request-digest input. */
export function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

/** A keyed, domain-separated hex MAC over an ordered list of UTF-8 parts. */
export function macHex(secret: string, domain: string, parts: readonly string[]): string {
  const h = createHmac("sha256", secret).update(domain, "utf8");
  for (const part of parts) {
    h.update("\u0000", "utf8").update(part, "utf8");
  }
  return h.digest("hex");
}

/** Constant-time hex-MAC comparison; a length mismatch is a mismatch, never a throw. */
export function macEqualHex(a: string, b: string): boolean {
  const ab = Buffer.from(a, "hex");
  const bb = Buffer.from(b, "hex");
  if (ab.length === 0 || ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
