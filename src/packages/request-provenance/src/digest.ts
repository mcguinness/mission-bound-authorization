/**
 * @spec request-provenance#request-digest
 * The request digest: HMAC-SHA-256 under a capture's secret over a
 * domain-separated, length-prefixed encoding of the media type and the exact
 * instruction bytes, carried as `hmac-sha-256:` + base64url (no padding).
 *
 * These functions are pure. They hold no state, keep no secret, and are the
 * one encoding the intake uses (an authorized audit recomputing a digest from
 * a capture record uses the same function).
 */

import { createHmac } from "node:crypto";
import { RequestProvenanceError } from "./errors.js";

/** The domain label, item 1 of the HMAC input, followed by one zero byte. */
export const REQUEST_DIGEST_LABEL = "mission-request-provenance/v1";

/** The `request_digest` prefix, which names this construction only. */
export const REQUEST_DIGEST_PREFIX = "hmac-sha-256:";

/** The capture secret's length in bytes: a fresh 256-bit secret per capture. */
export const CAPTURE_SECRET_BYTES = 32;

const MAX_MEDIA_TYPE_LENGTH = 0xffff_ffff;

/**
 * Whether `mediaType` can be encoded: a non-empty string of printable US-ASCII
 * characters. The draft encodes the media type's US-ASCII bytes exactly as
 * the intake recorded them, with no case folding or parameter reordering; a
 * value outside US-ASCII has no such bytes, so it is refused, never folded.
 */
export function isEncodableMediaType(mediaType: unknown): mediaType is string {
  if (typeof mediaType !== "string" || mediaType.length === 0) return false;
  if (mediaType.length > MAX_MEDIA_TYPE_LENGTH) return false;
  for (let i = 0; i < mediaType.length; i += 1) {
    const c = mediaType.charCodeAt(i);
    if (c < 0x20 || c > 0x7e) return false;
  }
  return true;
}

/**
 * The exact HMAC input of {@link requestDigest}:
 *
 * 1. the US-ASCII bytes of `mission-request-provenance/v1`, then one zero byte;
 * 2. the media type's length as a 4-byte unsigned big-endian integer, then its
 *    US-ASCII bytes exactly as recorded; and
 * 3. the instruction's length as an 8-byte unsigned big-endian integer, then
 *    the instruction's exact bytes.
 */
export function requestDigestInput(mediaType: string, instruction: Uint8Array): Buffer {
  if (!isEncodableMediaType(mediaType)) {
    throw new RequestProvenanceError(
      "invalid_capture",
      "the media type must be a non-empty string of printable US-ASCII characters",
    );
  }
  if (!(instruction instanceof Uint8Array)) {
    throw new RequestProvenanceError("invalid_capture", "the instruction must be its exact bytes");
  }
  const label = Buffer.from(REQUEST_DIGEST_LABEL, "ascii");
  const mediaTypeBytes = Buffer.from(mediaType, "ascii");
  const mediaTypeLength = Buffer.alloc(4);
  mediaTypeLength.writeUInt32BE(mediaTypeBytes.length);
  const instructionLength = Buffer.alloc(8);
  instructionLength.writeBigUInt64BE(BigInt(instruction.byteLength));
  return Buffer.concat([
    label,
    Buffer.from([0]),
    mediaTypeLength,
    mediaTypeBytes,
    instructionLength,
    instruction,
  ]);
}

/**
 * The `request_digest` value: `hmac-sha-256:` followed by the base64url
 * encoding, without padding, of HMAC-SHA-256 under `secret` over
 * {@link requestDigestInput}. `secret` is the capture's 32-byte secret.
 */
export function requestDigest(
  secret: Uint8Array,
  mediaType: string,
  instruction: Uint8Array,
): string {
  if (!(secret instanceof Uint8Array) || secret.byteLength !== CAPTURE_SECRET_BYTES) {
    throw new RequestProvenanceError(
      "invalid_capture",
      `the capture secret must be exactly ${CAPTURE_SECRET_BYTES} bytes`,
    );
  }
  const mac = createHmac("sha256", secret)
    .update(requestDigestInput(mediaType, instruction))
    .digest();
  return `${REQUEST_DIGEST_PREFIX}${mac.toString("base64url")}`;
}
