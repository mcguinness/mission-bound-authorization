/**
 * @spec request-provenance#capture, request-provenance#signing,
 * request-provenance#assertion
 *
 * The trusted request intake's library: capture before shaping, sign only
 * from a retained, workflow-bound capture.
 *
 * `capture` runs before any shaping. It takes the exact instruction bytes,
 * their media type, the origin facts the intake itself established
 * (originator and channel), and the workflow's authenticated presenter,
 * bound to one workflow. It generates a fresh
 * 256-bit secret and a random `capture_id`, computes the request digest,
 * records `captured_at`, and retains the capture record. The secret, the
 * instruction and its media type never leave the record: no return value,
 * assertion or error carries them.
 *
 * `sign` issues an assertion only from a retained capture of the same
 * workflow. It computes `intent_hash` itself over the candidate Intent for the
 * AS that `aud` names, and takes the request digest, originator, channel and
 * presenter only from the capture record; its input has no member for the
 * first three, and a request carrying one is refused. A `presenter` in the
 * signing request is a checked cross-reference: one that differs from the
 * captured presenter is refused, and none is ever signed. Every call mints a
 * fresh `jti`.
 *
 * What a signature certifies is only what the draft says signing binds: the
 * captured request's origin, bound to one AS, one exact Intent and one
 * presenter. It does not attest that the Intent interprets the instruction
 * faithfully, that consent is sufficient, that admission should succeed, or
 * any authority.
 *
 * The capture store is in memory, belongs to one intake instance, and prunes
 * nothing: it is this library slice's store, not a deployed one. A deployed
 * intake service needs an enforceable retention policy for capture records
 * and issued `jti` values (#939, D1119). Intake
 * isolation (that a shaper can neither create or alter capture records nor
 * ask for a signature over a request the intake did not capture) is a
 * property of the deployment around this library, not of the library alone.
 */

import { KeyObject, randomBytes as nodeRandomBytes, type webcrypto } from "node:crypto";
import { canonicalize, intentHash, type JsonValue } from "@mission/core";
import { SignJWT } from "jose";
import { CAPTURE_SECRET_BYTES, isEncodableMediaType, requestDigest } from "./digest.js";
import { RequestProvenanceError } from "./errors.js";

/** The evidence entry's `type`. */
export const REQUEST_PROVENANCE_TYPE = "mission-request-provenance";

/** The assertion's protected `typ`. */
export const REQUEST_PROVENANCE_JWT_TYP = "mission-request-provenance+jwt";

/** The JWS algorithm this library signs with; ES256 is mandatory to implement. */
export const REQUEST_PROVENANCE_ALG = "ES256";

/** Every claim the draft defines for the assertion, in emission order. */
export const ASSERTION_CLAIMS = [
  "iss",
  "aud",
  "iat",
  "exp",
  "jti",
  "intent_hash",
  "presenter",
  "originator",
  "channel",
  "captured_at",
  "request_digest",
  "capture_id",
] as const;

/** Random bytes behind each `capture_id` and `jti`: 128 bits. */
export const IDENTIFIER_BYTES = 16;

export type JsonObject = { [key: string]: JsonValue };

/** The authenticated principal who submitted the instruction. */
export interface Originator {
  iss: string;
  sub: string;
}

/** How the intake authenticated the originator. */
export interface Channel {
  /** A collision-resistant name for the channel. */
  type: string;
  acr?: string;
  amr?: string[];
  /** NumericDate. */
  auth_time?: number;
}

/** The presenter of the workflow: `cnf` where it uses proof of possession. */
export interface Presenter {
  client_id: string;
  cnf?: JsonObject;
}

export interface CaptureRequest {
  /** The authenticated workflow that received the instruction. */
  workflow: string;
  /** The instruction's exact bytes, as received, with no normalization. */
  instruction: Uint8Array;
  /** The media type exactly as the intake recorded it (printable US-ASCII). */
  mediaType: string;
  originator: Originator;
  channel: Channel;
  /** The presenter the intake authenticated for this workflow; the only presenter it signs. */
  presenter: Presenter;
}

/** What `capture` returns: no secret, no instruction, no media type. */
export interface CaptureReceipt {
  captureId: string;
  workflow: string;
  /** NumericDate. */
  capturedAt: number;
  requestDigest: string;
}

export interface SignRequest {
  /** The capture record to sign from. */
  captureId: string;
  /** The workflow asking for the signature; it must be the capture's. */
  workflow: string;
  /** The issuer identifier of the AS the Intent is submitted to. */
  audience: string;
  /** The candidate Mission Intent, over which the intake computes `intent_hash`. */
  intent: JsonObject;
  /**
   * A cross-reference only: where present, it must equal the presenter
   * captured for the workflow, or the request is refused. The assertion
   * always carries the captured presenter.
   */
  presenter?: Presenter;
}

export interface ProvenanceEntry {
  type: typeof REQUEST_PROVENANCE_TYPE;
  assertion: string;
}

export interface SignedProvenance {
  entry: ProvenanceEntry;
  jti: string;
  intentHash: string;
  iat: number;
  exp: number;
}

export interface RequestIntakeConfig {
  /** The signer identifier the assertion's `iss` carries. */
  issuer: string;
  /** The `kid` the AS configuration maps to this signer and evidence type. */
  kid: string;
  /** An ES256 (P-256) private key, used for nothing but this evidence type. */
  signingKey: KeyObject | webcrypto.CryptoKey;
  /** `exp` minus `iat`, in seconds: a positive integer. */
  assertionLifetimeSeconds: number;
  /** The largest `iat` minus `captured_at` the intake signs, in seconds. */
  maxCaptureAgeSeconds: number;
  /** Whether the assertion carries `capture_id` (default true). */
  emitCaptureId?: boolean;
  /** Epoch milliseconds (default `Date.now`). */
  now?: () => number;
  /**
   * The random source (default node:crypto `randomBytes`). Inject one only to
   * reproduce fixed test vectors: every secret, `capture_id` and `jti` comes
   * from it, and a predictable source voids each of their guarantees.
   */
  randomBytes?: (size: number) => Uint8Array;
}

interface CaptureRecord {
  readonly captureId: string;
  readonly workflow: string;
  readonly instruction: Buffer;
  readonly mediaType: string;
  readonly originator: Originator;
  readonly channel: Channel;
  /** The workflow's authenticated presenter, captured with the request. */
  readonly presenter: Presenter;
  readonly capturedAt: number;
  readonly secret: Buffer;
  readonly requestDigest: string;
  /** The `jti` of every assertion issued from this capture. */
  readonly issued: string[];
}

const CAPTURE_MEMBERS = new Set([
  "workflow",
  "instruction",
  "mediaType",
  "originator",
  "channel",
  "presenter",
]);
const SIGN_MEMBERS = new Set(["captureId", "workflow", "audience", "intent", "presenter"]);
const ORIGINATOR_MEMBERS = new Set(["iss", "sub"]);
const CHANNEL_MEMBERS = new Set(["type", "acr", "amr", "auth_time"]);
const PRESENTER_MEMBERS = new Set(["client_id", "cnf"]);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function nonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

function isNumericDate(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
}

function closed(
  obj: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  what: string,
  code: "invalid_capture" | "invalid_sign_request",
): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) {
      throw new RequestProvenanceError(
        code,
        `${what} carries a member the intake does not accept: ${key}`,
      );
    }
  }
}

function readOriginator(v: unknown): Originator {
  if (!isPlainObject(v)) {
    throw new RequestProvenanceError("invalid_capture", "originator must be an object");
  }
  closed(v, ORIGINATOR_MEMBERS, "originator", "invalid_capture");
  if (!nonEmptyString(v.iss) || !nonEmptyString(v.sub)) {
    throw new RequestProvenanceError("invalid_capture", "originator needs string iss and sub");
  }
  return { iss: v.iss, sub: v.sub };
}

function readChannel(v: unknown): Channel {
  if (!isPlainObject(v)) {
    throw new RequestProvenanceError("invalid_capture", "channel must be an object");
  }
  closed(v, CHANNEL_MEMBERS, "channel", "invalid_capture");
  if (!nonEmptyString(v.type)) {
    throw new RequestProvenanceError("invalid_capture", "channel needs a string type");
  }
  const channel: Channel = { type: v.type };
  if (v.acr !== undefined) {
    if (typeof v.acr !== "string") {
      throw new RequestProvenanceError("invalid_capture", "channel acr must be a string");
    }
    channel.acr = v.acr;
  }
  if (v.amr !== undefined) {
    if (!Array.isArray(v.amr) || !v.amr.every((m) => typeof m === "string")) {
      throw new RequestProvenanceError(
        "invalid_capture",
        "channel amr must be an array of strings",
      );
    }
    channel.amr = [...v.amr];
  }
  if (v.auth_time !== undefined) {
    if (!isNumericDate(v.auth_time)) {
      throw new RequestProvenanceError(
        "invalid_capture",
        "channel auth_time must be a NumericDate",
      );
    }
    channel.auth_time = v.auth_time;
  }
  return channel;
}

/** Confirmation members whose value is a key thumbprint string. */
const THUMBPRINT_CNF_MEMBERS = ["jkt", "x5t#S256"];

function readPresenter(v: unknown, code: "invalid_capture" | "invalid_sign_request"): Presenter {
  if (!isPlainObject(v)) {
    throw new RequestProvenanceError(code, "presenter must be an object");
  }
  closed(v, PRESENTER_MEMBERS, "presenter", code);
  if (!nonEmptyString(v.client_id)) {
    throw new RequestProvenanceError(code, "presenter needs a string client_id");
  }
  const presenter: Presenter = { client_id: v.client_id };
  if (Object.hasOwn(v, "cnf")) {
    // Validated before it is copied, and checked again as copied: a member
    // JSON cannot carry exactly (`{jkt: undefined}`) refuses, never vanishes.
    const cnf = exactJson(v.cnf, "presenter cnf", code);
    if (!isPlainObject(cnf) || Object.keys(cnf).length === 0) {
      throw new RequestProvenanceError(
        code,
        "presenter cnf must be a non-empty confirmation-method object",
      );
    }
    for (const member of THUMBPRINT_CNF_MEMBERS) {
      if (Object.hasOwn(cnf, member) && !nonEmptyString(cnf[member])) {
        throw new RequestProvenanceError(
          code,
          `presenter cnf ${member} must be a non-empty string`,
        );
      }
    }
    presenter.cnf = cnf as JsonObject;
  }
  return presenter;
}

/**
 * An exact deep copy of a JSON value, validated before anything is copied:
 * a non-finite number, `undefined`, a function, a symbol, a bigint, a sparse
 * array, a symbol-keyed member, or an object that is not plain is refused,
 * never converted. Every accepted value is preserved as given.
 */
function exactJson(
  v: unknown,
  what: string,
  code: "invalid_capture" | "invalid_sign_request",
): JsonValue {
  const refuse = (why: string): never => {
    throw new RequestProvenanceError(code, `${what} is not exact JSON: ${why}`);
  };
  if (v === null || typeof v === "boolean" || typeof v === "string") return v;
  if (typeof v === "number") return Number.isFinite(v) ? v : refuse("a non-finite number");
  if (Array.isArray(v)) {
    const out: JsonValue[] = [];
    for (let i = 0; i < v.length; i += 1) {
      if (!Object.hasOwn(v, i)) refuse("a sparse array");
      out.push(exactJson(v[i], what, code));
    }
    return out;
  }
  if (isPlainObject(v)) {
    if (Object.getOwnPropertySymbols(v).length > 0) refuse("a symbol-keyed member");
    const entries: [string, JsonValue][] = [];
    for (const [key, value] of Object.entries(v)) {
      if (value === undefined) refuse(`member ${key} is undefined`);
      entries.push([key, exactJson(value, what, code)]);
    }
    // fromEntries defines own properties, so a member named __proto__ stays a member.
    return Object.fromEntries(entries) as JsonObject;
  }
  return refuse(`a ${typeof v}`);
}

function readPositiveInteger(v: unknown, what: string): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v <= 0) {
    throw new RequestProvenanceError("invalid_config", `${what} must be a positive integer`);
  }
  return v;
}

function readSigningKey(key: unknown): KeyObject {
  let keyObject: KeyObject;
  if (key instanceof KeyObject) {
    keyObject = key;
  } else {
    try {
      keyObject = KeyObject.from(key as webcrypto.CryptoKey);
    } catch {
      throw new RequestProvenanceError("invalid_config", "signingKey must be a private key");
    }
  }
  if (
    keyObject.type !== "private" ||
    keyObject.asymmetricKeyType !== "ec" ||
    keyObject.asymmetricKeyDetails?.namedCurve !== "prime256v1"
  ) {
    throw new RequestProvenanceError(
      "invalid_config",
      "signingKey must be a P-256 private key for ES256",
    );
  }
  return keyObject;
}

export interface RequestIntake {
  /** Capture an instruction before shaping, and retain its capture record. */
  capture(request: CaptureRequest): CaptureReceipt;
  /** Issue an assertion from a retained capture of the same workflow. */
  sign(request: SignRequest): Promise<SignedProvenance>;
}

class Intake implements RequestIntake {
  readonly #issuer: string;
  readonly #kid: string;
  readonly #key: KeyObject;
  readonly #lifetime: number;
  readonly #maxCaptureAge: number;
  readonly #emitCaptureId: boolean;
  readonly #now: () => number;
  readonly #random: (size: number) => Uint8Array;
  readonly #captures = new Map<string, CaptureRecord>();
  readonly #issuedJtis = new Set<string>();

  constructor(config: RequestIntakeConfig) {
    if (!isPlainObject(config)) {
      throw new RequestProvenanceError("invalid_config", "config must be an object");
    }
    if (!nonEmptyString(config.issuer)) {
      throw new RequestProvenanceError("invalid_config", "issuer must be a non-empty string");
    }
    if (!nonEmptyString(config.kid)) {
      throw new RequestProvenanceError("invalid_config", "kid must be a non-empty string");
    }
    this.#issuer = config.issuer;
    this.#kid = config.kid;
    this.#key = readSigningKey(config.signingKey);
    this.#lifetime = readPositiveInteger(
      config.assertionLifetimeSeconds,
      "assertionLifetimeSeconds",
    );
    this.#maxCaptureAge = readPositiveInteger(config.maxCaptureAgeSeconds, "maxCaptureAgeSeconds");
    this.#emitCaptureId = config.emitCaptureId ?? true;
    this.#now = config.now ?? Date.now;
    this.#random = config.randomBytes ?? ((size) => nodeRandomBytes(size));
  }

  #seconds(): number {
    const ms = this.#now();
    if (typeof ms !== "number" || !Number.isFinite(ms) || ms < 0) {
      throw new RequestProvenanceError("invalid_config", "the clock returned no valid time");
    }
    return Math.floor(ms / 1000);
  }

  #draw(size: number): Buffer {
    const bytes = this.#random(size);
    if (!(bytes instanceof Uint8Array) || bytes.byteLength !== size) {
      throw new RequestProvenanceError(
        "random_source_failure",
        `the random source returned other than ${size} bytes`,
      );
    }
    return Buffer.from(bytes);
  }

  capture(request: CaptureRequest): CaptureReceipt {
    if (!isPlainObject(request)) {
      throw new RequestProvenanceError("invalid_capture", "capture request must be an object");
    }
    closed(request, CAPTURE_MEMBERS, "capture request", "invalid_capture");
    if (!nonEmptyString(request.workflow)) {
      throw new RequestProvenanceError("invalid_capture", "workflow must be a non-empty string");
    }
    if (!(request.instruction instanceof Uint8Array)) {
      throw new RequestProvenanceError(
        "invalid_capture",
        "the instruction must be its exact bytes",
      );
    }
    if (!isEncodableMediaType(request.mediaType)) {
      throw new RequestProvenanceError(
        "invalid_capture",
        "the media type must be a non-empty string of printable US-ASCII characters",
      );
    }
    const originator = readOriginator(request.originator);
    const channel = readChannel(request.channel);
    const presenter = readPresenter(request.presenter, "invalid_capture");
    // Copy the bytes so a later change to the caller's buffer cannot alter the record.
    const instruction = Buffer.from(request.instruction);
    const capturedAt = this.#seconds();
    const secret = this.#draw(CAPTURE_SECRET_BYTES);
    const captureId = this.#draw(IDENTIFIER_BYTES).toString("base64url");
    if (this.#captures.has(captureId)) {
      throw new RequestProvenanceError(
        "random_source_failure",
        "the random source repeated a capture_id",
      );
    }
    const digest = requestDigest(secret, request.mediaType, instruction);
    this.#captures.set(captureId, {
      captureId,
      workflow: request.workflow,
      instruction,
      mediaType: request.mediaType,
      originator,
      channel,
      presenter,
      capturedAt,
      secret,
      requestDigest: digest,
      issued: [],
    });
    return { captureId, workflow: request.workflow, capturedAt, requestDigest: digest };
  }

  async sign(request: SignRequest): Promise<SignedProvenance> {
    if (!isPlainObject(request)) {
      throw new RequestProvenanceError("invalid_sign_request", "sign request must be an object");
    }
    // Closed input: an intent_hash, a digest, an originator or channel facts
    // from the caller are refused, never used (request-provenance#signing).
    closed(request, SIGN_MEMBERS, "sign request", "invalid_sign_request");
    if (!nonEmptyString(request.captureId) || !nonEmptyString(request.workflow)) {
      throw new RequestProvenanceError(
        "invalid_sign_request",
        "captureId and workflow must be strings",
      );
    }
    if (!nonEmptyString(request.audience)) {
      throw new RequestProvenanceError(
        "invalid_sign_request",
        "audience must be one AS issuer identifier",
      );
    }
    if (!isPlainObject(request.intent)) {
      throw new RequestProvenanceError(
        "invalid_sign_request",
        "intent must be a Mission Intent object",
      );
    }
    // Validated before copying; an accepted Intent is preserved exactly.
    const intent = exactJson(request.intent, "intent", "invalid_sign_request");

    const record = this.#captures.get(request.captureId);
    if (record === undefined) {
      throw new RequestProvenanceError(
        "unknown_capture",
        "this intake holds no such capture record",
      );
    }
    if (record.workflow !== request.workflow) {
      throw new RequestProvenanceError(
        "workflow_mismatch",
        "the capture record belongs to another workflow",
      );
    }
    // The presenter is the one captured for the workflow. A presenter in the
    // request is a cross-reference: it must equal that one exactly.
    if (request.presenter !== undefined) {
      const named = readPresenter(request.presenter, "invalid_sign_request");
      if (
        canonicalize(named as unknown as JsonValue) !==
        canonicalize(record.presenter as unknown as JsonValue)
      ) {
        throw new RequestProvenanceError(
          "presenter_mismatch",
          "the signing request names a presenter other than the one captured for the workflow",
        );
      }
    }
    const iat = this.#seconds();
    if (iat < record.capturedAt) {
      throw new RequestProvenanceError(
        "clock_regressed",
        "the clock reads earlier than captured_at",
      );
    }
    if (iat - record.capturedAt > this.#maxCaptureAge) {
      throw new RequestProvenanceError(
        "capture_too_old",
        "the capture is older than the maximum capture age; a new capture is needed",
      );
    }

    const hash = intentHash(request.audience, intent);
    const jti = this.#draw(IDENTIFIER_BYTES).toString("base64url");
    if (this.#issuedJtis.has(jti)) {
      throw new RequestProvenanceError("random_source_failure", "the random source repeated a jti");
    }
    this.#issuedJtis.add(jti);
    record.issued.push(jti);
    const exp = iat + this.#lifetime;

    const claims: Record<string, JsonValue> = {
      iss: this.#issuer,
      aud: request.audience,
      iat,
      exp,
      jti,
      intent_hash: hash,
      presenter: exactJson(record.presenter, "presenter", "invalid_sign_request"),
      originator: { ...record.originator },
      channel: exactJson(record.channel, "channel", "invalid_sign_request"),
      captured_at: record.capturedAt,
      request_digest: record.requestDigest,
    };
    if (this.#emitCaptureId) claims.capture_id = record.captureId;

    const assertion = await new SignJWT(claims)
      .setProtectedHeader({
        typ: REQUEST_PROVENANCE_JWT_TYP,
        alg: REQUEST_PROVENANCE_ALG,
        kid: this.#kid,
      })
      .sign(this.#key);
    return {
      entry: { type: REQUEST_PROVENANCE_TYPE, assertion },
      jti,
      intentHash: hash,
      iat,
      exp,
    };
  }
}

/** Create a request intake with its own, private capture store. */
export function createRequestIntake(config: RequestIntakeConfig): RequestIntake {
  return new Intake(config);
}
