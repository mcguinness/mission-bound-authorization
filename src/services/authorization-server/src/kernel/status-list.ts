/**
 * @spec status#status-list — Mission Status List, the referenced-token profile
 * of {{I-D.draft-ietf-oauth-status-list}} (-21) as constrained by
 * draft-mcguinness-oauth-mission-status §status-list. A signed, compressed,
 * 2-bit-per-entry bit array: a Mission Issuer publishes reliance bits at opaque
 * indices, a consumer fetches the whole list once per freshness window and
 * reads its Mission's status locally per action. The whole-list fetch covers
 * every index at once, so it reveals no per-mission interest and preserves this
 * profile's anti-oracle posture (@spec status#mission-status-anti-oracle).
 */

import { deflateSync, inflateSync } from "node:zlib";
import { jwtVerify, SignJWT, type CryptoKey } from "jose";
import { type MissionState, TERMINAL_STATES } from "./types.js";

/** typ header of the Status List Token (draft-ietf-oauth-status-list §5.1). */
export const STATUS_LIST_TYP = "statuslist+jwt";
/** Content-Type the whole-list route serves (draft-ietf-oauth-status-list §6). */
export const STATUS_LIST_MEDIA_TYPE = "application/statuslist+jwt";
/** Bits per entry. This profile pins 2 (VALID / INVALID / SUSPENDED + reserved). */
export const STATUS_LIST_BITS = 2;
/** The single default list id; the route is GET /statuslist/{STATUS_LIST_ID}. */
export const STATUS_LIST_ID = "missions";
/**
 * The list capacity. Sized well above the population so random index allocation
 * stays sparse and the published length never leaks the participant count
 * (@spec status#mission-status-anti-oracle). 131072 entries is 32 KiB before
 * compression; a mostly-active population compresses far below that.
 */
export const STATUS_LIST_SIZE = 1 << 17;
/** Default published staleness bound in seconds (both `ttl` and `exp - iat`). */
export const STATUS_LIST_TTL_SECONDS = 300;

/** 2-bit entry values (draft-ietf-oauth-status-list §7.1). 0x03 is reserved. */
export const STATUS_VALID = 0x00;
export const STATUS_INVALID = 0x01;
export const STATUS_SUSPENDED = 0x02;

const ENTRIES_PER_BYTE = 8 / STATUS_LIST_BITS; // 4
const ENTRY_MASK = (1 << STATUS_LIST_BITS) - 1; // 0b11

/** The `status_list` object inside the Status List Token payload. */
export interface StatusListClaim {
  bits: number;
  lst: string;
}

/** The decoded Status List Token payload a consumer reads. */
export interface StatusListPayload {
  iss?: string;
  sub?: string;
  iat?: number;
  exp?: number;
  ttl?: number;
  status_list: StatusListClaim;
}

/** One packed entry: an opaque index and its 2-bit status value. */
export interface StatusEntry {
  idx: number;
  bit: number;
}

/**
 * The whole-list URL: the per-Mission `status_list.uri` and the token's `sub`
 * both equal this value (draft §status-list).
 */
export function statusListUri(issuer: string): string {
  return `${issuer.replace(/\/$/, "")}/statuslist/${STATUS_LIST_ID}`;
}

/**
 * @spec status#status-list Mapping: `active` -> VALID (0x00); `suspended` ->
 * SUSPENDED (0x02); every terminal state -> INVALID (0x01). Reusing
 * TERMINAL_STATES means any future terminal state flows through unchanged. Any
 * unrecognized value fails safe to INVALID (non-active). 0x03 is never emitted.
 */
export function stateToBit(state: MissionState): number {
  if (state === "active") return STATUS_VALID;
  if (state === "suspended") return STATUS_SUSPENDED;
  if (TERMINAL_STATES.has(state)) return STATUS_INVALID;
  return STATUS_INVALID;
}

/** Pack entries LSB-first, ZLIB-compress (RFC 1950), base64url-encode. */
function packAndCompress(entries: ReadonlyArray<StatusEntry>, size: number): string {
  const bytes = new Uint8Array(Math.ceil(size / ENTRIES_PER_BYTE));
  for (const { idx, bit } of entries) {
    if (idx < 0 || idx >= size) continue;
    const byteIdx = Math.floor(idx / ENTRIES_PER_BYTE);
    const shift = (idx % ENTRIES_PER_BYTE) * STATUS_LIST_BITS; // LSB-first within each byte
    bytes[byteIdx] = (bytes[byteIdx] ?? 0) | ((bit & ENTRY_MASK) << shift);
  }
  // deflateSync is RFC 1950 ZLIB framing, NOT raw DEFLATE (draft §status-list).
  return deflateSync(Buffer.from(bytes)).toString("base64url");
}

/** Inflate the `lst` and extract the raw 2-bit value at `idx`. */
function extractBit(claim: StatusListClaim, idx: number): number {
  const bytes = inflateSync(Buffer.from(claim.lst, "base64url"));
  const perByte = 8 / claim.bits;
  const byteIdx = Math.floor(idx / perByte);
  if (idx < 0 || byteIdx >= bytes.length) return STATUS_INVALID; // out of range -> non-active
  const shift = (idx % perByte) * claim.bits;
  const mask = (1 << claim.bits) - 1;
  return ((bytes[byteIdx] ?? 0) >> shift) & mask;
}

export interface SignStatusListOptions {
  issuer: string;
  uri: string;
  kid: string;
  key: CryptoKey;
  now: Date;
  entries: ReadonlyArray<StatusEntry>;
  ttl?: number;
  size?: number;
}

/**
 * @spec status#status-list Sign a Status List Token. Header: typ
 * statuslist+jwt, alg ES256, kid (the as-status kid). Payload: iss, sub (MUST
 * equal the list `uri`), iat, exp, ttl, and status_list { bits: 2, lst }, where
 * `lst` is the packed LSB-first 2-bit array, ZLIB-compressed and base64url.
 */
export async function signStatusListToken(opts: SignStatusListOptions): Promise<string> {
  const ttl = opts.ttl ?? STATUS_LIST_TTL_SECONDS;
  const size = opts.size ?? STATUS_LIST_SIZE;
  const iat = Math.floor(opts.now.getTime() / 1000);
  const lst = packAndCompress(opts.entries, size);
  return new SignJWT({ ttl, status_list: { bits: STATUS_LIST_BITS, lst } })
    .setProtectedHeader({ alg: "ES256", kid: opts.kid, typ: STATUS_LIST_TYP })
    .setIssuer(opts.issuer)
    .setSubject(opts.uri)
    .setIssuedAt(iat)
    .setExpirationTime(iat + ttl)
    .sign(opts.key);
}

export interface VerifyStatusListOptions {
  /** When set, the token's `sub` MUST equal this (the list uri). */
  uri?: string;
  /** Deterministic clock for the iat/exp checks; defaults to wall time. */
  now?: Date;
}

/**
 * @spec status#status-list Consumer verification: verify the signature, require
 * the statuslist+jwt typ, check iat/exp (against `now` when supplied), and
 * require sub == uri when the expected uri is given. Returns the decoded payload.
 */
export async function verifyStatusListToken(
  jws: string,
  jwks: Parameters<typeof jwtVerify>[1],
  opts: VerifyStatusListOptions = {},
): Promise<StatusListPayload> {
  const { payload } = await jwtVerify(jws, jwks, {
    typ: STATUS_LIST_TYP,
    ...(opts.now ? { currentDate: opts.now } : {}),
  });
  const nowMs = (opts.now ?? new Date()).getTime();
  if (typeof payload.iat === "number" && payload.iat * 1000 > nowMs + 30_000) {
    throw new Error("status list token: iat is in the future");
  }
  if (opts.uri !== undefined && payload.sub !== opts.uri) {
    throw new Error("status list token: sub does not equal the list uri");
  }
  const sl = (payload as { status_list?: StatusListClaim }).status_list;
  if (!sl || typeof sl.lst !== "string" || typeof sl.bits !== "number") {
    throw new Error("status list token: missing or malformed status_list");
  }
  return payload as unknown as StatusListPayload;
}

/**
 * The raw 2-bit wire value at `idx` (VALID / INVALID / SUSPENDED / reserved).
 * The reliance-safe reading is `readStatus`; this primitive is for callers that
 * need the exact published bit (e.g. conformance checks).
 */
export function readStatusBit(token: StatusListPayload, idx: number): number {
  return extractBit(token.status_list, idx);
}

/**
 * @spec status#status-list Consult one entry for reliance. VALID within the
 * token's `exp` reports "active"; anything else (INVALID, SUSPENDED, the
 * reserved 0x03, an unknown or out-of-range index) or an expired list reports
 * "non-active". Never fabricates a specific terminal state: which terminal
 * state, the successor, and the version stay on the authoritative surfaces.
 */
export function readStatus(
  token: StatusListPayload,
  idx: number,
  now: Date = new Date(),
): "active" | "non-active" {
  if (typeof token.exp === "number" && token.exp * 1000 <= now.getTime()) {
    return "non-active"; // an expired list is stale state, never permission
  }
  return readStatusBit(token, idx) === STATUS_VALID ? "active" : "non-active";
}

/**
 * The republication seam for the whole-list fetch. It subscribes to the
 * kernel's `onLifecycleCommit` hook by marking the cached token dirty; the route
 * asks for `current()` and gets a freshly signed token whenever a lifecycle
 * transition committed since the last build. The dirty flag is cleared BEFORE
 * the async sign so a transition committing during the sign is not lost (draft
 * §status-list: a committed transition MUST appear in the next published token).
 *
 * It takes a `build` thunk, never the kernel, so kernel.ts (which imports this
 * module) stays free of an import cycle.
 */
export class StatusListPublisher {
  private dirty = true;
  private cached: string | undefined;

  constructor(private readonly build: () => Promise<string>) {}

  markDirty(): void {
    this.dirty = true;
  }

  async current(): Promise<string> {
    if (!this.dirty && this.cached !== undefined) return this.cached;
    this.dirty = false;
    this.cached = await this.build();
    return this.cached;
  }
}
