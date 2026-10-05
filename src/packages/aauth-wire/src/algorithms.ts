import { createPublicKey, type KeyObject, sign, verify } from "node:crypto";
import { SignatureError } from "./errors.js";

/**
 * The algorithms this package implements: Ed25519 (every party MUST) and
 * ES256 (SHOULD), both fully-specified JOSE identifiers.
 *
 * @spec aauth#section-11.3.1
 */
export const SUPPORTED_ALGORITHMS = ["Ed25519", "ES256"] as const;
export type SupportedAlgorithm = (typeof SUPPORTED_ALGORITHMS)[number];

export function isSupportedAlgorithm(value: unknown): value is SupportedAlgorithm {
  return (SUPPORTED_ALGORITHMS as readonly unknown[]).includes(value);
}

const KEY_SHAPE: Record<SupportedAlgorithm, { kty: string; crv: string; members: string[] }> = {
  Ed25519: { kty: "OKP", crv: "Ed25519", members: ["x"] },
  ES256: { kty: "EC", crv: "P-256", members: ["x", "y"] },
};

/** Members a public key may carry for each key type, used to rebuild it. */
const PUBLIC_MEMBERS: Record<string, string[]> = {
  OKP: ["kty", "crv", "x"],
  EC: ["kty", "crv", "x", "y"],
  RSA: ["kty", "n", "e"],
};

export interface DeterminedKey {
  alg: SupportedAlgorithm;
  key: KeyObject;
}

/**
 * Determine the signature algorithm from a conveyed or referenced key and
 * import it. The key must be structurally complete (else `invalid_key`),
 * carry a fully-specified `alg` this package implements (else
 * `unsupported_algorithm`: absent, the polymorphic `EdDSA`, `none`,
 * symmetric and any other value), and have a `kty` and `crv` that agree
 * with that `alg` (else `invalid_key`).
 *
 * @spec aauth#section-11.3.1
 * @spec aauth#section-11.3.4 (steps 5 and 6)
 * @spec aauth#section-9.4.3.2 (structural checks before key decoding)
 */
export function determineAlgorithm(
  jwk: unknown,
  acceptedAlgorithms: readonly string[] = SUPPORTED_ALGORITHMS,
): DeterminedKey {
  if (typeof jwk !== "object" || jwk === null || Array.isArray(jwk)) {
    throw new SignatureError("invalid_key", "key is not a JWK object");
  }
  const k = jwk as Record<string, unknown>;
  if (typeof k.kty !== "string") {
    throw new SignatureError("invalid_key", "key is missing kty");
  }
  // Own properties only: a kty such as "constructor" must not reach Object.prototype.
  const required = Object.hasOwn(PUBLIC_MEMBERS, k.kty) ? PUBLIC_MEMBERS[k.kty] : undefined;
  if (required?.some((m) => typeof k[m] !== "string")) {
    throw new SignatureError("invalid_key", `key is missing members required for kty ${k.kty}`);
  }
  const alg = k.alg;
  if (alg === undefined) {
    throw new SignatureError("unsupported_algorithm", "key has no alg", { acceptedAlgorithms });
  }
  if (!isSupportedAlgorithm(alg) || !acceptedAlgorithms.includes(alg)) {
    throw new SignatureError("unsupported_algorithm", `alg ${String(alg)} is not accepted`, {
      acceptedAlgorithms,
    });
  }
  const shape = KEY_SHAPE[alg];
  if (
    k.kty !== shape.kty ||
    k.crv !== shape.crv ||
    shape.members.some((m) => typeof k[m] !== "string")
  ) {
    throw new SignatureError("invalid_key", `kty or crv disagrees with alg ${alg}`);
  }
  const publicJwk: Record<string, string> = {};
  for (const m of PUBLIC_MEMBERS[shape.kty] ?? []) publicJwk[m] = k[m] as string;
  let key: KeyObject;
  try {
    key = createPublicKey({ key: publicJwk, format: "jwk" });
  } catch {
    throw new SignatureError("invalid_key", "key material cannot be parsed");
  }
  return { alg, key };
}

/** Check that a private key can produce signatures under `alg`. */
export function assertSigningKey(alg: SupportedAlgorithm, key: KeyObject): void {
  const ok =
    key.type === "private" &&
    (alg === "Ed25519"
      ? key.asymmetricKeyType === "ed25519"
      : key.asymmetricKeyType === "ec" && key.asymmetricKeyDetails?.namedCurve === "prime256v1");
  if (!ok) throw new TypeError(`private key does not match ${alg}`);
}

/**
 * HTTP_SIGN. ECDSA signatures are the 64-byte r||s form.
 *
 * @spec rfc9421#section-3.3.4
 * @spec rfc9421#section-3.3.6
 */
export function httpSign(alg: SupportedAlgorithm, key: KeyObject, data: Uint8Array): Buffer {
  return alg === "Ed25519"
    ? sign(null, data, key)
    : sign("sha256", data, { key, dsaEncoding: "ieee-p1363" });
}

/** HTTP_VERIFY, the counterpart of {@link httpSign}. */
export function httpVerify(
  alg: SupportedAlgorithm,
  key: KeyObject,
  data: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    return alg === "Ed25519"
      ? verify(null, data, key, signature)
      : signature.length === 64 &&
          verify("sha256", data, { key, dsaEncoding: "ieee-p1363" }, signature);
  } catch {
    return false;
  }
}
