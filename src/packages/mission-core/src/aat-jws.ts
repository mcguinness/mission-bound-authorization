/**
 * @spec AAT -02 Sections 3.5, 4.2, 4.6 and 9.11 (#1756): the JWS layer of
 * Attenuating Agent Tokens. Compact serialization split without
 * re-serializing, the protected-header rules (allowlisted `alg`, explicit
 * `typ`, `crit`), public-JWK validation, `alg` consistency with the key, the
 * signature over the exact JWS Signing Input, and the RFC 7638 thumbprint
 * that names a derived token's issuer. A verification key comes only from a
 * trust anchor or a `cnf.jwk` in the chain, never from a header parameter
 * such as `jwk`, so no header member is ever read as a key.
 */

import { createHash, createPublicKey, type KeyObject, verify } from "node:crypto";
import {
  type AatJson,
  AatJsonError,
  type AatObject,
  isAatObject,
  parseAatJson,
} from "./aat-json.js";

/** The algorithms this verifier implements: Ed25519 is required (Section 3.2); ES256 is the AS's root algorithm. */
export const AAT_ALGORITHMS: readonly string[] = ["Ed25519", "ES256"];
export const AAT_JWT_TYP = "aat+jwt";
export const AAT_POP_JWT_TYP = "aat-pop+jwt";
export const AAT_DETAIL_TYPE_NAME = "attenuating_agent_token";

const B64URL_RE = /^[A-Za-z0-9_-]*$/;
const UTF8 = new TextDecoder("utf-8", { fatal: true });
/** Header parameters a `crit` may list that this verifier understands: none (no extension is implemented). */
const UNDERSTOOD_CRIT: ReadonlySet<string> = new Set();
const PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/** Strict base64url (RFC 7515 Appendix C): the URL-safe alphabet, no padding. */
export function b64urlDecode(s: string): Buffer | undefined {
  if (!B64URL_RE.test(s) || s.length % 4 === 1) return undefined;
  return Buffer.from(s, "base64url");
}

export function sha256B64url(text: string): string {
  return createHash("sha256").update(text, "ascii").digest("base64url");
}

export interface AatJwsParts {
  header: string;
  payload: string;
  signature: string;
  /** BASE64URL(header) || '.' || BASE64URL(payload), exactly as presented. */
  signingInput: string;
}

export function splitCompactJws(token: string): AatJwsParts | undefined {
  const parts = token.split(".");
  if (parts.length !== 3) return undefined;
  const [header, payload, signature] = parts as [string, string, string];
  return { header, payload, signature, signingInput: `${header}.${payload}` };
}

/** A base64url segment decoded as UTF-8 text, or undefined. */
export function segmentText(segment: string): string | undefined {
  const bytes = b64urlDecode(segment);
  if (!bytes) return undefined;
  try {
    return UTF8.decode(bytes);
  } catch {
    return undefined;
  }
}

/** A base64url segment parsed as a JSON object (duplicate members refused), or a reason. */
export function segmentObject(segment: string): AatObject | string {
  const text = segmentText(segment);
  if (text === undefined) return "segment is not base64url-encoded UTF-8";
  let v: AatJson;
  try {
    v = parseAatJson(text);
  } catch (e) {
    return e instanceof AatJsonError ? e.message : "segment is not JSON";
  }
  return isAatObject(v) ? v : "segment is not a JSON object";
}

/**
 * @spec AAT -02 Section 3.5 and Section 8 steps 3a, 4a and 7a: why a protected
 * header fails, or undefined. `alg` is on the allowlist (never "none"), `typ`
 * equals the expected value, and a present `crit` is a non-empty array of
 * strings naming only parameters this verifier understands. Other parameters
 * are ignored, and a header `jwk`, `jku`, `x5c` or `x5u` is never read.
 */
export function headerProblem(
  header: AatObject,
  expectedTyp: string,
  algorithms: readonly string[],
): string | undefined {
  const alg = header.alg;
  if (typeof alg !== "string" || alg === "none" || !algorithms.includes(alg))
    return `alg ${JSON.stringify(alg)} is not allowed`;
  if (header.typ !== expectedTyp) return `typ is not ${expectedTyp}`;
  if (Object.hasOwn(header, "crit")) {
    const crit = header.crit;
    if (!Array.isArray(crit) || crit.length === 0 || !crit.every((c) => typeof c === "string")) {
      return "crit is not a non-empty array of strings";
    }
    const unknown = crit.find((c) => !UNDERSTOOD_CRIT.has(c as string));
    if (unknown !== undefined)
      return `crit lists ${JSON.stringify(unknown)}, which is not understood`;
  }
  return undefined;
}

type JwkLike = Readonly<Record<string, unknown>>;
const str = (jwk: JwkLike, k: string): string | undefined =>
  typeof jwk[k] === "string" ? (jwk[k] as string) : undefined;
const bytesOf = (v: string | undefined): number =>
  v === undefined ? -1 : (b64urlDecode(v)?.length ?? -1);

/**
 * @spec AAT -02 Section 8 steps 3l, 4b2: why `jwk` is not a public key this
 * verifier can use, or undefined. It carries no private member, and it is an
 * Ed25519 OKP key (32-byte `x`) or a P-256 EC key on the curve; other members
 * such as `kid`, `use` and `alg` are allowed.
 */
export function publicJwkProblem(jwk: unknown): string | undefined {
  if (typeof jwk !== "object" || jwk === null || Array.isArray(jwk)) return "jwk is not an object";
  const k = jwk as JwkLike;
  const priv = PRIVATE_JWK_MEMBERS.find((m) => Object.hasOwn(k, m));
  if (priv) return `jwk carries the private member ${priv}`;
  const kty = str(k, "kty");
  const crv = str(k, "crv");
  if (kty === "OKP" && crv === "Ed25519") {
    return bytesOf(str(k, "x")) === 32 ? undefined : "Ed25519 x is not 32 bytes";
  }
  if (kty === "EC" && crv === "P-256") {
    if (bytesOf(str(k, "x")) !== 32 || bytesOf(str(k, "y")) !== 32)
      return "P-256 x or y is not 32 bytes";
    try {
      importPublicJwk(k);
      return undefined;
    } catch {
      return "P-256 point is not on the curve";
    }
  }
  return `unsupported key type ${JSON.stringify(kty)}/${JSON.stringify(crv)}`;
}

/** The required members of a validated public JWK (RFC 7638 Section 3.2), in lexicographic order. */
function requiredMembers(jwk: JwkLike): Record<string, string> {
  if (jwk.kty === "OKP") return { crv: jwk.crv as string, kty: "OKP", x: jwk.x as string };
  return { crv: jwk.crv as string, kty: "EC", x: jwk.x as string, y: jwk.y as string };
}

export function importPublicJwk(jwk: JwkLike): KeyObject {
  return createPublicKey({ key: requiredMembers(jwk) as never, format: "jwk" });
}

/** @spec AAT -02 Section 8 steps 3a, 4a, 7a: `alg` is consistent with the key's `kty` and `crv`. */
export function algMatchesKey(alg: string, jwk: JwkLike): boolean {
  if (alg === "Ed25519") return jwk.kty === "OKP" && jwk.crv === "Ed25519";
  if (alg === "ES256") return jwk.kty === "EC" && jwk.crv === "P-256";
  return false;
}

/** The signature over the exact JWS Signing Input verifies under `key` for `alg`. */
export function verifyJwsSignature(alg: string, key: KeyObject, parts: AatJwsParts): boolean {
  const sig = b64urlDecode(parts.signature);
  if (sig?.length !== 64) return false;
  const data = Buffer.from(parts.signingInput, "ascii");
  try {
    if (alg === "Ed25519") return verify(null, data, key, sig);
    if (alg === "ES256") return verify("sha256", data, { key, dsaEncoding: "ieee-p1363" }, sig);
  } catch {
    return false;
  }
  return false;
}

/** @spec RFC 7638 / RFC 9278: the SHA-256 JWK Thumbprint URI of a validated public JWK. */
export function jwkThumbprintUri(jwk: JwkLike): string {
  const thumb = createHash("sha256")
    .update(JSON.stringify(requiredMembers(jwk)))
    .digest("base64url");
  return `urn:ietf:params:oauth:jwk-thumbprint:sha-256:${thumb}`;
}
