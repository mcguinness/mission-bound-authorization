/**
 * @spec request-provenance#verification, request-provenance#trust-configuration,
 * request-provenance#entry, request-provenance#assertion,
 * request-provenance#recorded-facts (#939 slice 2a-1)
 *
 * The authorization server's verification of the `mission-request-provenance`
 * Intent Submission Evidence type, as pure functions: verification steps 1 to
 * 9 of the draft, exactly and in order, returning either the step that
 * refused and why, or step 10's reservation key and the exact recorded facts.
 *
 * Nothing here is wired. The module performs no reservation, keeps no replay
 * store and registers no evidence type: step 10 (reserve the pair (`iss`,
 * `jti`)), commit on acceptance and release on refusal belong to the caller,
 * which also maps every refusal to `invalid_mission_intent_evidence` and
 * charges the signature against the verification-work bound (#1962).
 *
 * Trust never comes from the assertion: the signer and its key are looked up
 * by the `iss` claim and the protected `kid` in the AS's own configuration
 * (`config/request-provenance.json`, loaded by `@mission/demo-data`), and an
 * assertion whose header carries `jku`, `x5u`, `jwk` or `x5c` is refused
 * before any key is looked up. A key's `use` and `key_ops` never establish
 * that it may sign provenance; only the configuration's `evidence_types`
 * mapping does, and the key is imported from its curve and coordinates alone.
 */

import { createPublicKey, type KeyObject } from "node:crypto";
import { type JsonValue, parseStrictJson } from "@mission/core";
import type {
  RequestProvenanceConfig,
  RequestProvenanceKeyConfig,
  RequestProvenanceSignerConfig,
} from "@mission/demo-data";
import { compactVerify } from "jose";
import type { IntentSubmissionPresenter } from "./intent.js";

/** The evidence entry's `type`. */
export const REQUEST_PROVENANCE_EVIDENCE_TYPE = "mission-request-provenance";

/** The assertion's protected `typ`, compared exactly. */
export const REQUEST_PROVENANCE_JWT_TYP = "mission-request-provenance+jwt";

/** Header parameters that would carry or locate a key: refused on presence. */
const KEY_HEADER_PARAMETERS = ["jku", "x5u", "jwk", "x5c"] as const;

/**
 * The optional members `channel` defines beside `type`; any other nested
 * member is ignored and never recorded.
 */
const CHANNEL_OPTIONAL_MEMBERS = ["acr", "amr", "auth_time"] as const;

/** `request_digest`'s prefix (request-provenance#request-digest). */
const REQUEST_DIGEST_PREFIX = "hmac-sha-256:";

/** The HMAC-SHA-256 output length the digest encodes. */
const REQUEST_DIGEST_BYTES = 32;

const BASE64URL = /^[A-Za-z0-9_-]*$/;

/** The deployment's declared bounds and authorized signers. `enabled` is the caller's concern. */
export type RequestProvenanceTrust = Omit<RequestProvenanceConfig, "enabled">;

/** What the containing exchange and this AS supply to one verification. */
export interface RequestProvenanceVerificationContext {
  /** This AS's issuer identifier: `aud` must equal it exactly. */
  issuer: string;
  /** The evaluation time. */
  now: Date;
  /** The clock-skew allowance, maximum assertion lifetime, maximum capture age and signers. */
  trust: RequestProvenanceTrust;
  /** The provisional `intent_hash` of the submitted Intent. */
  intentHash: string;
  /**
   * The presenter the containing exchange established: its client, and `cnf`
   * only where the exchange established a confirmation key. A PAR
   * establishes the client alone.
   */
  presenter: IntentSubmissionPresenter;
}

/** A draft Verification step that can refuse (step 10, the reservation, is the caller's). */
export type RequestProvenanceStep = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9;

/**
 * A refusal. The caller refuses the submission with
 * `invalid_mission_intent_evidence`; `reason` is a local diagnostic, not a
 * protocol value.
 */
export interface RequestProvenanceRefusal {
  ok: false;
  step: RequestProvenanceStep;
  reason: string;
}

/** Step 10's key: the pair to reserve, and when the reservation lapses. */
export interface RequestProvenanceReservation {
  iss: string;
  jti: string;
  /**
   * `exp` plus the clock-skew allowance, as a NumericDate (seconds since the
   * epoch): a reservation never outlives it, and a committed pair is
   * retained at least until it (request-provenance#replay).
   */
  expiresAt: number;
}

/** Steps 1 to 9 passed. */
export interface RequestProvenanceAcceptance {
  ok: true;
  reservation: RequestProvenanceReservation;
  /** Exactly the members of request-provenance#recorded-facts. */
  facts: Record<string, JsonValue>;
}

export type RequestProvenanceResult = RequestProvenanceAcceptance | RequestProvenanceRefusal;

function refuse(step: RequestProvenanceStep, reason: string): RequestProvenanceRefusal {
  return { ok: false, step, reason };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

/** An own member only: a parsed `__proto__` member never supplies an inherited one. */
function own(obj: Record<string, unknown>, key: string): unknown {
  return Object.hasOwn(obj, key) ? obj[key] : undefined;
}

/**
 * The claims' string type, read strictly: a non-empty string. An empty
 * identifier names nothing, and an empty `jti` would be a degenerate
 * reservation key; this is strictness the draft implies.
 */
function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

/** NumericDate (RFC 7519): a JSON number, integer or not, that is finite. */
function isNumericDate(v: unknown): v is number {
  return typeof v === "number" && Number.isFinite(v);
}

/**
 * A JSON value exactly as its text states it: every number finite (the strict
 * parser reads an overflowing number such as `1e400` as Infinity), and every
 * object a plain one.
 */
function isExactJson(v: unknown): boolean {
  if (v === null || typeof v === "string" || typeof v === "boolean") return true;
  if (typeof v === "number") return Number.isFinite(v);
  if (Array.isArray(v)) return v.every(isExactJson);
  return isPlainObject(v) && Object.keys(v).every((k) => isExactJson(own(v, k)));
}

/**
 * Exact JSON equality: the same own members with the same values, compared
 * structurally, so it never throws on any value.
 */
function sameJson(a: unknown, b: unknown): boolean {
  if (a === null || b === null || typeof a !== "object" || typeof b !== "object") return a === b;
  if (Array.isArray(a) || Array.isArray(b)) {
    return (
      Array.isArray(a) &&
      Array.isArray(b) &&
      a.length === b.length &&
      a.every((x, i) => sameJson(x, b[i]))
    );
  }
  const left = a as Record<string, unknown>;
  const right = b as Record<string, unknown>;
  const keys = Object.keys(left);
  return (
    keys.length === Object.keys(right).length &&
    keys.every((k) => Object.hasOwn(right, k) && sameJson(own(left, k), own(right, k)))
  );
}

const UTF8 = new TextDecoder("utf-8", { fatal: true });

/**
 * One base64url segment, decoded strictly: the unpadded alphabet with no other
 * characters (RFC 7515 Section 2), and the one canonical encoding of its bytes,
 * so a segment with non-zero trailing bits refuses too.
 */
function decodeBase64url(segment: string): Uint8Array | undefined {
  if (!BASE64URL.test(segment) || segment.length % 4 === 1) return undefined;
  const bytes = Buffer.from(segment, "base64url");
  return bytes.toString("base64url") === segment ? new Uint8Array(bytes) : undefined;
}

/** Decode one base64url segment of the compact serialization to its JSON object. */
function decodeSegment(segment: string): { bytes: Uint8Array; value: Record<string, unknown> } | undefined {
  if (segment.length === 0) return undefined;
  const bytes = decodeBase64url(segment);
  if (bytes === undefined) return undefined;
  let value: JsonValue;
  try {
    value = parseStrictJson(UTF8.decode(bytes));
  } catch {
    // Not UTF-8, not JSON, or a duplicated member name (RFC 7519 Section 4
    // permits refusing duplicates; this verifier does).
    return undefined;
  }
  return isPlainObject(value) ? { bytes, value } : undefined;
}

/**
 * `request_digest`'s form (request-provenance#request-digest): the
 * `hmac-sha-256:` prefix, then the unpadded base64url of exactly 32 bytes in
 * its one canonical encoding. The AS never recomputes the digest; checking its
 * form is strictness the draft implies.
 */
function isRequestDigest(v: unknown): v is string {
  if (typeof v !== "string" || !v.startsWith(REQUEST_DIGEST_PREFIX)) return false;
  return decodeBase64url(v.slice(REQUEST_DIGEST_PREFIX.length))?.length === REQUEST_DIGEST_BYTES;
}

/** A NumericDate as an RFC 3339 timestamp in UTC, its fraction (if any) kept exactly. */
function rfc3339(numericDate: number): string {
  const whole = Math.floor(numericDate);
  const seconds = new Date(whole * 1000).toISOString().slice(0, 19);
  if (whole === numericDate) return `${seconds}Z`;
  // Step 7 bounds captured_at near the verification time, so the decimal
  // form carries no exponent.
  const fraction = String(numericDate).split(".")[1] ?? "";
  return `${seconds}.${fraction}Z`;
}

const IMPORTED_KEYS = new WeakMap<RequestProvenanceKeyConfig, KeyObject>();

/**
 * The configured key, from its curve and coordinates alone: `use`, `key_ops`
 * and any other JWK member play no part in what the key may do.
 */
function configuredKey(key: RequestProvenanceKeyConfig): KeyObject {
  let imported = IMPORTED_KEYS.get(key);
  if (imported === undefined) {
    const { kty, crv, x, y } = key.public_jwk;
    imported = createPublicKey({ key: { kty, crv, x, y }, format: "jwk" });
    IMPORTED_KEYS.set(key, imported);
  }
  return imported;
}

/**
 * Step 1 (request-provenance#entry): the entry carries exactly `type` and
 * `assertion`, `type` is this evidence type, and `assertion` is a string.
 * The synchronous structural check the dispatch's stage 1 can run alone.
 */
export function checkRequestProvenanceEntry(entry: unknown): RequestProvenanceRefusal | undefined {
  if (!isPlainObject(entry)) return refuse(1, "the entry is not a JSON object");
  const members = Object.keys(entry);
  if (members.length !== 2 || !Object.hasOwn(entry, "type") || !Object.hasOwn(entry, "assertion")) {
    return refuse(1, "the entry must carry exactly type and assertion");
  }
  if (entry.type !== REQUEST_PROVENANCE_EVIDENCE_TYPE) {
    return refuse(1, `the entry's type is not ${REQUEST_PROVENANCE_EVIDENCE_TYPE}`);
  }
  if (typeof entry.assertion !== "string") return refuse(1, "assertion is not a string");
  return undefined;
}

/**
 * Verify one `mission-request-provenance` entry: steps 1 to 9 of
 * request-provenance#verification, in order. Never throws for any entry or
 * assertion; every failure is a refusal naming its step.
 */
export async function verifyRequestProvenance(
  entry: unknown,
  context: RequestProvenanceVerificationContext,
): Promise<RequestProvenanceResult> {
  // 1. The entry carries exactly type and assertion, and assertion is a string.
  const shape = checkRequestProvenanceEntry(entry);
  if (shape !== undefined) return shape;
  const assertion = (entry as { assertion: string }).assertion;

  // 2. Decode the JWS. typ exactly mission-request-provenance+jwt, alg not
  // none, kid present, and none of jku, x5u, jwk or x5c.
  const segments = assertion.split(".");
  if (segments.length !== 3) return refuse(2, "the assertion is not a JWS in compact serialization");
  const [headerSegment, payloadSegment, signatureSegment] = segments as [string, string, string];
  const decodedHeader = decodeSegment(headerSegment);
  if (decodedHeader === undefined) return refuse(2, "the protected header is not a JSON object");
  const header = decodedHeader.value;
  if (own(header, "typ") !== REQUEST_PROVENANCE_JWT_TYP) {
    return refuse(2, `the protected typ is not ${REQUEST_PROVENANCE_JWT_TYP}`);
  }
  const alg = own(header, "alg");
  if (!isNonEmptyString(alg)) return refuse(2, "the protected header carries no alg");
  if (alg === "none") return refuse(2, "alg is none");
  const kid = own(header, "kid");
  if (!isNonEmptyString(kid)) return refuse(2, "the protected header carries no kid");
  for (const parameter of KEY_HEADER_PARAMETERS) {
    if (Object.hasOwn(header, parameter)) {
      return refuse(2, `the protected header carries ${parameter}; no key is taken from the assertion`);
    }
  }
  // The claims are decoded here, before verification, only so step 3 can
  // read iss; step 4 confirms they are the bytes the signature covers.
  const decodedClaims = decodeSegment(payloadSegment);
  if (decodedClaims === undefined) return refuse(2, "the claims set is not a JSON object");
  const claims = decodedClaims.value;
  // The signature segment is held to the same decoding before step 4 reads
  // it (RFC 7515 Section 5.2): a padded spelling never reaches the verifier.
  if (signatureSegment.length === 0 || decodeBase64url(signatureSegment) === undefined) {
    return refuse(2, "the signature is not unpadded base64url in its canonical encoding");
  }

  // 3. The signer by the iss claim and kid, in configuration only; the key
  // mapped to this evidence type; alg permitted for that key.
  const iss = own(claims, "iss");
  const signer: RequestProvenanceSignerConfig | undefined =
    typeof iss === "string" ? context.trust.signers.find((s) => s.iss === iss) : undefined;
  if (signer === undefined) return refuse(3, "the configuration authorizes no signer for this iss");
  const key = signer.keys.find((k) => k.kid === kid);
  if (key === undefined) return refuse(3, "the configuration maps no key with this kid to this signer");
  if (!key.evidence_types.includes(REQUEST_PROVENANCE_EVIDENCE_TYPE)) {
    return refuse(3, `the configuration does not map this key to ${REQUEST_PROVENANCE_EVIDENCE_TYPE}`);
  }
  if (!(key.algs as readonly string[]).includes(alg)) {
    return refuse(3, `alg ${alg} is not permitted for this key`);
  }

  // 4. Verify the signature (RFC 8725): under the configured key only, with
  // the one algorithm the configuration permits and the header names.
  try {
    const verified = await compactVerify(assertion, configuredKey(key), { algorithms: [alg] });
    // The claims steps 3 and later read are exactly the verified payload. A
    // JWS whose payload is unencoded (b64 false) signs other bytes, and a JWT
    // never uses one (RFC 7797 Section 7).
    if (Buffer.compare(Buffer.from(verified.payload), Buffer.from(decodedClaims.bytes)) !== 0) {
      return refuse(4, "the verified payload is not the decoded claims set");
    }
  } catch (e) {
    return refuse(4, `the signature does not verify: ${e instanceof Error ? e.message : "verifier error"}`);
  }

  // 5. Every required claim is present with its defined type. Claims the
  // draft does not define are ignored, as RFC 7519 requires, and record nothing.
  const aud = own(claims, "aud");
  const iat = own(claims, "iat");
  const exp = own(claims, "exp");
  const jti = own(claims, "jti");
  const intentHash = own(claims, "intent_hash");
  const presenter = own(claims, "presenter");
  const originator = own(claims, "originator");
  const channel = own(claims, "channel");
  const capturedAt = own(claims, "captured_at");
  const requestDigest = own(claims, "request_digest");
  const captureId = own(claims, "capture_id");
  if (!isNonEmptyString(iss)) return refuse(5, "iss is not a string");
  if (typeof aud !== "string") return refuse(5, "aud is not a string");
  if (!isNumericDate(iat)) return refuse(5, "iat is not a NumericDate");
  if (!isNumericDate(exp)) return refuse(5, "exp is not a NumericDate");
  if (!isNonEmptyString(jti)) return refuse(5, "jti is not a string");
  if (!isNonEmptyString(intentHash)) return refuse(5, "intent_hash is not a string");
  if (!isPlainObject(presenter)) return refuse(5, "presenter is not an object");
  const presenterClientId = own(presenter, "client_id");
  if (!isNonEmptyString(presenterClientId)) return refuse(5, "presenter.client_id is not a string");
  const presenterCnf = own(presenter, "cnf");
  if (presenterCnf !== undefined && !(isPlainObject(presenterCnf) && isExactJson(presenterCnf))) {
    return refuse(5, "presenter.cnf is not a confirmation-method object of exact JSON values");
  }
  if (!isPlainObject(originator)) return refuse(5, "originator is not an object");
  const originatorIss = own(originator, "iss");
  const originatorSub = own(originator, "sub");
  if (!isNonEmptyString(originatorIss) || !isNonEmptyString(originatorSub)) {
    return refuse(5, "originator needs string iss and sub");
  }
  if (!isPlainObject(channel)) return refuse(5, "channel is not an object");
  const channelType = own(channel, "type");
  const acr = own(channel, "acr");
  const amr = own(channel, "amr");
  const authTime = own(channel, "auth_time");
  if (!isNonEmptyString(channelType)) return refuse(5, "channel.type is not a string");
  if (acr !== undefined && typeof acr !== "string") return refuse(5, "channel.acr is not a string");
  if (amr !== undefined && !(Array.isArray(amr) && amr.every((m) => typeof m === "string"))) {
    return refuse(5, "channel.amr is not an array of strings");
  }
  if (authTime !== undefined && !isNumericDate(authTime)) {
    return refuse(5, "channel.auth_time is not a NumericDate");
  }
  if (!isNumericDate(capturedAt)) return refuse(5, "captured_at is not a NumericDate");
  if (!isRequestDigest(requestDigest)) {
    return refuse(5, "request_digest is not hmac-sha-256: and the unpadded base64url of 32 bytes");
  }
  if (captureId !== undefined && !isNonEmptyString(captureId)) {
    return refuse(5, "capture_id is not a string");
  }

  // 6. aud equals this AS's issuer identifier.
  if (aud !== context.issuer) return refuse(6, "aud is not this AS's issuer identifier");

  // 7. The time window. The clock-skew allowance applies where the AS's
  // clock meets the signer's (iat not in the future, exp not passed); the
  // lifetime, the capture age and captured_at against iat compare the
  // signer's own claims and take no allowance.
  const { clock_skew_seconds: skew } = context.trust;
  const now = context.now.getTime() / 1000;
  if (!Number.isFinite(now)) return refuse(7, "the verification clock reads no valid time");
  if (iat > now + skew) return refuse(7, "iat is in the future");
  if (now >= exp + skew) return refuse(7, "exp has passed");
  // exp strictly after iat: otherwise the lifetime check below would pass a
  // negative difference. Strictness the draft implies.
  if (exp <= iat) return refuse(7, "exp is not after iat");
  if (exp - iat > context.trust.max_assertion_lifetime_seconds) {
    return refuse(7, "exp minus iat exceeds the maximum assertion lifetime");
  }
  if (capturedAt > iat) return refuse(7, "captured_at is later than iat");
  if (iat - capturedAt > context.trust.max_capture_age_seconds) {
    return refuse(7, "iat minus captured_at exceeds the maximum capture age");
  }

  // 8. The signer's scope: an originator entry matches on iss and, where it
  // carries sub, on sub. A signer whose one originator carries sub is a
  // user-device signer, and that entry is the AS's own binding of its keys
  // to that originator.
  const originatorAuthorized = signer.originators.some(
    (o) => o.iss === originatorIss && (o.sub === undefined || o.sub === originatorSub),
  );
  if (!originatorAuthorized) return refuse(8, "the signer is not authorized for this originator");
  if (!signer.channel_types.includes(channelType)) {
    return refuse(8, "the signer is not authorized for this channel type");
  }

  // 9. intent_hash equals the provisional intent_hash; presenter agrees with
  // the presenter the containing exchange established.
  if (intentHash !== context.intentHash) {
    return refuse(9, "intent_hash is not the submitted Intent's provisional intent_hash");
  }
  if (presenterClientId !== context.presenter.clientId) {
    return refuse(9, "presenter.client_id is not the client the exchange established");
  }
  const established = context.presenter.cnf;
  if (established === undefined) {
    // No key is inferred from the assertion (D1119 Q3).
    if (presenterCnf !== undefined) {
      return refuse(9, "presenter carries cnf where the exchange established no confirmation key");
    }
  } else {
    // cnf is REQUIRED where the presenter uses proof of possession, and is
    // compared exactly: the same own members, `__proto__` among them, with
    // the same values.
    if (presenterCnf === undefined) {
      return refuse(9, "presenter carries no cnf where the exchange established a confirmation key");
    }
    if (!sameJson(presenterCnf, established)) {
      return refuse(9, "presenter.cnf is not the confirmation key the exchange established");
    }
  }

  // Recorded facts: exactly request-provenance#recorded-facts, built afresh
  // from the defined members only.
  const recordedChannel: Record<string, JsonValue> = { type: channelType };
  for (const member of CHANNEL_OPTIONAL_MEMBERS) {
    const value = own(channel, member);
    if (value !== undefined) recordedChannel[member] = structuredClone(value) as JsonValue;
  }
  const facts: Record<string, JsonValue> = {
    signer: { iss, kid },
    originator: { iss: originatorIss, sub: originatorSub },
    channel: recordedChannel,
    captured_at: rfc3339(capturedAt),
    request_digest: requestDigest,
    assertion_id: jti,
  };
  if (captureId !== undefined) facts.capture_id = captureId;

  return { ok: true, reservation: { iss, jti, expiresAt: exp + skew }, facts };
}
