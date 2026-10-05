import type { KeyObject } from "node:crypto";
import {
  type Dictionary,
  isInnerList,
  type Parameters,
  parseDictionary,
  serializeDictionary,
  Token,
} from "structured-headers";
import {
  assertSigningKey,
  determineAlgorithm,
  httpSign,
  httpVerify,
  SUPPORTED_ALGORITHMS,
  type SupportedAlgorithm,
} from "./algorithms.js";
import { contentDigest, verifyContentDigest } from "./content-digest.js";
import { SignatureError } from "./errors.js";
import { isServerIdentifier } from "./identifiers.js";
import type { JwksResolver } from "./jwks.js";
import { jwkThumbprint } from "./keys.js";
import {
  carriesBody,
  combinedFieldValue,
  type HttpRequestMessage,
  type NormalizedRequest,
  normalizeRequest,
} from "./message.js";
import type { ReplayCache } from "./replay.js";
import { buildSignatureBase, SignatureBaseError, signatureParams } from "./signature-base.js";
import {
  type SignatureKeyMember,
  type SignatureKeyScheme,
  serializeSignatureKey,
} from "./signature-key.js";
import {
  type TokenVerificationOptions,
  type VerifiedToken,
  verifyAgentToken,
  verifyAuthToken,
  verifyPersonToken,
} from "./tokens.js";

/**
 * Components every AAuth signature covers.
 *
 * @spec aauth#section-11.3.3.1
 */
export const BASE_COMPONENTS = ["@method", "@authority", "@path", "signature-key"] as const;

/**
 * Components a request with a body to a PS or AS endpoint, or to any
 * revocation endpoint, additionally covers.
 *
 * @spec aauth#section-11.3.3.1
 */
export const BODY_COMPONENTS = ["content-digest", "content-type"] as const;

/**
 * The metadata documents a server signing under `jwks_uri` names in `dwk`.
 *
 * @spec aauth#section-11.3.2
 */
export const AAUTH_SERVER_DOCUMENTS = [
  "aauth-person.json",
  "aauth-access.json",
  "aauth-agent.json",
  "aauth-resource.json",
] as const;

/**
 * The request's content. A request whose framing declares content that the
 * caller did not supply cannot have its Content-Digest checked; that is a
 * caller error, not a property of the request.
 */
function requireBody(request: NormalizedRequest): Uint8Array {
  if (request.body === undefined && carriesBody(request)) {
    throw new TypeError("the request carries a body; pass it to sign or verify Content-Digest");
  }
  return request.body ?? new Uint8Array();
}

export interface SignRequestOptions {
  alg: SupportedAlgorithm;
  privateKey: KeyObject;
  signatureKey: SignatureKeyMember;
  /** Default `sig`. */
  label?: string;
  /**
   * Covered components. Default: the base components, plus Content-Digest
   * and Content-Type when the request carries a body.
   */
  components?: readonly string[];
  /** Seconds since the epoch; default the current time. */
  created?: number;
  expires?: number;
}

/**
 * Sign a request. Returns the fields to add: Signature-Key, Signature-Input
 * and Signature, plus Content-Digest when a covered digest was absent. The
 * Signature-Key field is set before the base is built, since it is a
 * covered component. `created` is always present; `alg` and `keyid` are
 * never emitted.
 *
 * @spec aauth#section-11.3.3
 * @spec rfc9421#section-3.1
 */
export function signRequest(
  message: HttpRequestMessage,
  options: SignRequestOptions,
): Record<string, string> {
  assertSigningKey(options.alg, options.privateKey);
  const label = options.label ?? "sig";
  const request = normalizeRequest(message);
  const components =
    options.components ??
    (carriesBody(request) ? [...BASE_COMPONENTS, ...BODY_COMPONENTS] : [...BASE_COMPONENTS]);
  const added: Record<string, string> = {};
  const set = (name: string, value: string) => {
    added[name] = value;
    request.fields.set(name, [value]);
  };
  if (components.includes("content-digest") && !request.fields.has("content-digest")) {
    set("content-digest", contentDigest(requireBody(request)));
  }
  set("signature-key", serializeSignatureKey(label, options.signatureKey));
  const params: Parameters = new Map([
    ["created", options.created ?? Math.floor(Date.now() / 1000)],
  ]);
  if (options.expires !== undefined) params.set("expires", options.expires);
  const inner = signatureParams(components, params);
  const base = buildSignatureBase(request, inner);
  const signature = httpSign(options.alg, options.privateKey, Buffer.from(base, "ascii"));
  set("signature-input", serializeDictionary(new Map([[label, inner]])));
  const signatureField: Dictionary = new Map([[label, [new Uint8Array(signature), new Map()]]]);
  set("signature", serializeDictionary(signatureField));
  return added;
}

export type PresentedTokenType = "aa-agent+jwt" | "aa-person+jwt" | "aa-auth+jwt";

export interface VerifyRequestOptions extends Omit<TokenVerificationOptions, "resolver"> {
  resolver: JwksResolver;
  /** Signature-Key schemes accepted. Default `["jwt"]`, what AAuth requires of agents. */
  acceptedSchemes?: readonly SignatureKeyScheme[];
  /** Token types accepted under the `jwt` scheme. Default `["aa-agent+jwt"]`. */
  acceptedTokenTypes?: readonly PresentedTokenType[];
  /** This server's identifier: the `aud` a person or auth token must name. */
  audience?: string;
  /** Algorithms accepted, in preference order. Default Ed25519, ES256. */
  acceptedAlgorithms?: readonly SupportedAlgorithm[];
  /**
   * Require Content-Digest and Content-Type on a request with a body, as a
   * PS, AS or revocation endpoint does.
   */
  requireBodyComponents?: boolean;
  /** Further components this server requires. */
  additionalComponents?: readonly string[];
  /** Signature validity window in seconds. Default 60. */
  windowSeconds?: number;
  replayCache?: ReplayCache;
  /** The label to verify. Default: the only label in Signature-Input. */
  label?: string;
}

export interface VerifiedRequest {
  label: string;
  scheme: SignatureKeyScheme;
  alg: SupportedAlgorithm;
  /** The verified signing key, with its `alg`. */
  publicJwk: Record<string, unknown>;
  /** RFC 7638 thumbprint of the signing key. */
  thumbprint: string;
  created: number;
  coveredComponents: string[];
  /** Under `jwt`: the verified token whose `cnf.jwk` signed the request. */
  token?: VerifiedToken;
  /** Under `jwks_uri`: the signer's identifier, metadata document and key. */
  signer?: { id: string; dwk: string; kid: string };
}

const fail = (code: ConstructorParameters<typeof SignatureError>[0], detail: string) =>
  new SignatureError(code, detail);

function parseField(request: NormalizedRequest, name: string): Dictionary {
  const value = combinedFieldValue(request, name);
  if (value === undefined) throw fail("invalid_signature", `${name} is missing`);
  try {
    return parseDictionary(value);
  } catch {
    throw fail("invalid_signature", `${name} is malformed`);
  }
}

/**
 * Verify a signed AAuth request, in the order the profile sets. Every
 * failure is a {@link SignatureError} carrying 401 and the Signature-Error
 * field.
 *
 * 1. Signature, Signature-Input and Signature-Key present and well-formed
 *    (`invalid_signature`).
 * 2. The required components covered (`invalid_input`, `required_input`).
 * 3. `created` present and inside the window (`invalid_signature` when
 *    older, `clock_skew` when ahead); a past `expires` fails.
 * 4. The Signature-Key member's scheme accepted (`unsupported_scheme`).
 * 5. The key obtained: under `jwt` the token verified and `cnf.jwk` taken;
 *    under `jwks_uri` the key discovered (`invalid_key`, `unknown_key`,
 *    `invalid_jwt`, `expired_jwt`, `clock_skew`, `revoked_jwt`,
 *    `issuer_missing`, `issuer_mismatch`).
 * 6. The algorithm determined from the key (`unsupported_algorithm`,
 *    `invalid_key`).
 * 7. The signature verified (`invalid_signature`).
 *
 * Then a duplicate inside the window is refused, and a covered
 * Content-Digest must match the body; a mismatch is `invalid_signature`,
 * since the covered digest is what binds the body to the signature.
 *
 * @spec aauth#section-11.3.4
 * @spec aauth#section-11.3.4.2
 * @spec signature-key#section-3
 * @spec rfc9421#section-3.2
 */
export async function verifyRequest(
  message: HttpRequestMessage,
  options: VerifyRequestOptions,
): Promise<VerifiedRequest> {
  const request = normalizeRequest(message);
  const nowMs = (options.now ?? Date.now)();
  const nowSeconds = Math.floor(nowMs / 1000);
  const windowSeconds = options.windowSeconds ?? 60;
  const acceptedSchemes = options.acceptedSchemes ?? ["jwt"];
  const acceptedAlgorithms = options.acceptedAlgorithms ?? SUPPORTED_ALGORITHMS;

  // Step 1.
  const signatures = parseField(request, "signature");
  const inputs = parseField(request, "signature-input");
  const keys = parseField(request, "signature-key");
  let label = options.label;
  if (label === undefined) {
    if (inputs.size !== 1) throw fail("invalid_signature", "cannot select a signature label");
    label = [...inputs.keys()][0] as string;
  }
  const input = inputs.get(label);
  const signatureMember = signatures.get(label);
  if (!input || !isInnerList(input)) {
    throw fail("invalid_signature", `Signature-Input has no inner list for ${label}`);
  }
  if (
    !signatureMember ||
    isInnerList(signatureMember) ||
    !(signatureMember[0] instanceof ArrayBuffer)
  ) {
    throw fail("invalid_signature", `Signature has no byte sequence for ${label}`);
  }
  const covered: string[] = [];
  for (const [name] of input[0]) {
    // Component parameters are refused when the base is built (step 7).
    if (typeof name !== "string") throw fail("invalid_signature", "a component is not a string");
    covered.push(name);
  }

  // Step 2.
  const required: string[] = [...BASE_COMPONENTS];
  if (options.requireBodyComponents && carriesBody(request)) required.push(...BODY_COMPONENTS);
  for (const c of options.additionalComponents ?? []) if (!required.includes(c)) required.push(c);
  if (required.some((c) => !covered.includes(c))) {
    throw new SignatureError("invalid_input", "required components are not covered", {
      requiredInput: required,
    });
  }

  // Step 3.
  const created = input[1].get("created");
  if (typeof created !== "number" || !Number.isInteger(created)) {
    throw fail("invalid_signature", "created is missing");
  }
  if (created < nowSeconds - windowSeconds) throw fail("invalid_signature", "created is too old");
  if (created > nowSeconds + windowSeconds) throw fail("clock_skew", "created is in the future");
  const expires = input[1].get("expires");
  if (expires !== undefined) {
    if (typeof expires !== "number" || !Number.isInteger(expires)) {
      throw fail("invalid_signature", "expires is malformed");
    }
    if (expires < nowSeconds) throw fail("invalid_signature", "the signature has expired");
  }

  // Step 4.
  const keyMember = keys.get(label);
  if (!keyMember) throw fail("invalid_signature", `Signature-Key has no member for ${label}`);
  if (isInnerList(keyMember) || !(keyMember[0] instanceof Token)) {
    throw fail("invalid_signature", "Signature-Key member is not a scheme token");
  }
  const scheme = keyMember[0].toString();
  if (!(acceptedSchemes as readonly string[]).includes(scheme)) {
    throw new SignatureError("unsupported_scheme", `scheme ${scheme} is not accepted`, {
      acceptedSchemes,
    });
  }
  const keyParams = keyMember[1];

  // Step 5.
  let jwk: unknown;
  let token: VerifiedToken | undefined;
  let signer: VerifiedRequest["signer"];
  if (scheme === "jwt") {
    const jwt = keyParams.get("jwt");
    if (typeof jwt !== "string") throw fail("invalid_key", "jwt parameter is missing");
    token = await verifyPresentedToken(jwt, options);
    jwk = (token.payload.cnf as { jwk: unknown }).jwk;
  } else {
    const id = keyParams.get("id");
    const dwk = keyParams.get("dwk");
    const kid = keyParams.get("kid");
    if (typeof id !== "string" || typeof dwk !== "string" || typeof kid !== "string") {
      throw fail("invalid_key", "jwks_uri needs id, dwk and kid");
    }
    if (!isServerIdentifier(id)) throw fail("invalid_key", "id is not a server identifier");
    if (!(AAUTH_SERVER_DOCUMENTS as readonly string[]).includes(dwk)) {
      throw fail("invalid_key", `dwk ${dwk} is not an AAuth metadata document`);
    }
    jwk = await options.resolver.resolveKey(id, dwk, kid);
    signer = { id, dwk, kid };
  }

  // Step 6.
  let { alg, key } = determineAlgorithm(jwk, acceptedAlgorithms);
  let publicJwk = jwk as Record<string, unknown>;
  // @spec aauth#section-11.3.3.2: a keyid must name the Signature-Key key.
  const keyid = input[1].get("keyid");
  if (keyid !== undefined) {
    const names = signer ? [signer.kid] : [publicJwk.kid, await jwkThumbprint(publicJwk)];
    if (!names.includes(keyid)) throw fail("invalid_key", "keyid names a different key");
  }

  // Step 7.
  let base: string;
  try {
    base = buildSignatureBase(request, input);
  } catch (err) {
    if (err instanceof SignatureBaseError) throw fail("invalid_signature", err.message);
    throw err;
  }
  const signatureBytes = new Uint8Array(signatureMember[0]);
  const baseBytes = Buffer.from(base, "ascii");
  let verifiedSignature = httpVerify(alg, key, baseBytes, signatureBytes);
  if (!verifiedSignature && signer) {
    // @spec signature-key#section-7.2: a cached key that fails is refreshed
    // once (the issuer may have re-keyed under the same kid).
    const refreshed = await options.resolver.resolveKey(signer.id, signer.dwk, signer.kid, {
      refresh: true,
    });
    ({ alg, key } = determineAlgorithm(refreshed, acceptedAlgorithms));
    publicJwk = refreshed;
    verifiedSignature = httpVerify(alg, key, baseBytes, signatureBytes);
  }
  if (!verifiedSignature) throw fail("invalid_signature", "signature verification failed");
  const thumbprint = await jwkThumbprint(publicJwk);

  // The body is checked before the replay slot is taken, so a copy with a
  // tampered body cannot burn the slot of the genuine request.
  if (covered.includes("content-digest")) {
    const digest = combinedFieldValue(request, "content-digest") ?? "";
    if (!verifyContentDigest(digest, requireBody(request))) {
      throw fail("invalid_signature", "Content-Digest does not match the body");
    }
  }
  if (options.replayCache) {
    const replayKey = JSON.stringify([
      thumbprint,
      created,
      request.method,
      request.url.host,
      request.path,
    ]);
    // Freshness accepts `created` through the whole second at the window's
    // edge, so the entry outlives it by that second.
    const expiresAt = (created + windowSeconds + 1) * 1000;
    if (!options.replayCache.checkAndRecord(replayKey, expiresAt, nowMs)) {
      throw fail("invalid_signature", "duplicate signed request");
    }
  }

  const verified: VerifiedRequest = {
    label,
    scheme: scheme as SignatureKeyScheme,
    alg,
    publicJwk,
    thumbprint,
    created,
    coveredComponents: covered,
  };
  if (token) verified.token = token;
  if (signer) verified.signer = signer;
  return verified;
}

/**
 * Verify the token in a `jwt` Signature-Key member by its `typ`. A person
 * or auth token names this server in `aud`; an agent token has no `aud`.
 * A failing token is a signature failure: its code stands.
 *
 * @spec aauth#section-11.3.2
 * @spec aauth#section-11.5.2
 */
async function verifyPresentedToken(
  jwt: string,
  options: VerifyRequestOptions,
): Promise<VerifiedToken> {
  const accepted = options.acceptedTokenTypes ?? ["aa-agent+jwt"];
  let typ: unknown;
  try {
    const header = JSON.parse(Buffer.from(jwt.split(".")[0] ?? "", "base64url").toString("utf8"));
    typ = (header as { typ?: unknown }).typ;
  } catch {
    throw fail("invalid_jwt", "malformed JWT");
  }
  if (!(accepted as readonly unknown[]).includes(typ)) {
    throw fail("invalid_jwt", `typ ${String(typ)} is not accepted here`);
  }
  const tokenOptions: TokenVerificationOptions = { resolver: options.resolver };
  if (options.now) tokenOptions.now = options.now;
  if (options.iatSkewSeconds !== undefined) tokenOptions.iatSkewSeconds = options.iatSkewSeconds;
  if (options.isRevoked) tokenOptions.isRevoked = options.isRevoked;
  if (typ === "aa-agent+jwt") return verifyAgentToken(jwt, tokenOptions);
  if (options.audience === undefined) {
    throw new TypeError("audience is required to verify a person or auth token");
  }
  const withAudience = { ...tokenOptions, audience: options.audience };
  return typ === "aa-person+jwt"
    ? verifyPersonToken(jwt, withAudience)
    : verifyAuthToken(jwt, withAudience);
}
