import { createHash } from "node:crypto";

/**
 * A `mission_s256` value: the unpadded base64url encoding of a SHA-256
 * digest, 43 characters that decode to 32 bytes.
 *
 * @spec aauth#section-8.2
 */
export function isMissionS256(value: unknown): value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) return false;
  // The last character carries two padding bits; a value whose bits are not
  // zero does not round-trip, so it names no digest.
  return Buffer.from(value, "base64url").toString("base64url") === value;
}

/**
 * The mission identifier over the exact bytes given: unpadded base64url
 * SHA-256. Never computed over a reserialization.
 *
 * @spec aauth#section-8.2.1
 */
export function missionS256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("base64url");
}

/** An approved mission blob, before serialization. */
export interface MissionBlob {
  agent: string;
  approved_at: string;
  expires_at: string;
  description: string;
  approved_tools?: { name: string; description: string }[];
  approved_resources?: string[];
}

/**
 * Serialize an approved blob once. The returned bytes are what the PS
 * persists, digests and returns as `mission`.
 *
 * @spec aauth#section-8.2
 */
export function encodeBlob(blob: MissionBlob): Buffer {
  return Buffer.from(JSON.stringify(blob), "utf8");
}

/** An RFC 3339 `date-time` at whole-second precision, in UTC. */
export function rfc3339(seconds: number): string {
  return new Date(seconds * 1000).toISOString().replace(".000Z", "Z");
}

const RFC3339 =
  /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;

/** Seconds since the epoch for an RFC 3339 `date-time`, or undefined when malformed. */
export function parseRfc3339(value: unknown): number | undefined {
  if (typeof value !== "string" || !RFC3339.test(value)) return undefined;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? undefined : Math.floor(ms / 1000);
}
