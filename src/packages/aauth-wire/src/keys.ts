import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { calculateJwkThumbprint, SignJWT } from "jose";
import type { SupportedAlgorithm } from "./algorithms.js";
import type { AAuthTokenType } from "./tokens.js";

export interface SigningKey {
  alg: SupportedAlgorithm;
  privateKey: KeyObject;
  /** The public JWK with its fully-specified `alg` (and `kid` when given). */
  publicJwk: Record<string, string>;
}

/**
 * Generate a key pair whose public JWK carries the fully-specified `alg`
 * every AAuth key needs.
 *
 * @spec aauth#section-11.3.1
 * @spec aauth#section-11.4
 */
export function generateSigningKey(alg: SupportedAlgorithm = "Ed25519", kid?: string): SigningKey {
  const { privateKey, publicKey } =
    alg === "Ed25519"
      ? generateKeyPairSync("ed25519")
      : generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const exported = publicKey.export({ format: "jwk" }) as Record<string, string>;
  const publicJwk: Record<string, string> = { ...exported, alg };
  if (kid !== undefined) publicJwk.kid = kid;
  return { alg, privateKey, publicJwk };
}

/** RFC 7638 SHA-256 thumbprint, as carried in `agent_jkt`. */
export function jwkThumbprint(jwk: Record<string, unknown>): Promise<string> {
  return calculateJwkThumbprint(jwk as Parameters<typeof calculateJwkThumbprint>[0], "sha256");
}

/**
 * Sign an AAuth token. The claims are taken as given; the caller sets
 * `iss`, `dwk`, `jti`, `iat`, `exp` and the type's own claims.
 *
 * @spec aauth#section-11.5.1
 */
export function mintToken(
  typ: AAuthTokenType,
  claims: Record<string, unknown>,
  key: { alg: SupportedAlgorithm; privateKey: KeyObject; kid: string },
): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: key.alg, typ, kid: key.kid })
    .sign(key.privateKey);
}
