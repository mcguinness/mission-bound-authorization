/**
 * @spec status#historical-key-set, status#signing-key-retention (#831 B3) —
 * the historical key set: the public keys the AS has withdrawn as
 * compromised, each carrying OpenID Federation's `revoked` member, as a JWT
 * (`typ` `jwk-set+jwt`) the AS signs under its active Mission Status signing
 * key, so a response signed under a withdrawn key stays verifiable for audit.
 *
 * It lists the Status role's compromised generations: the keys that signed
 * Mission Status and Lifecycle responses and Discharge Receipts, which this
 * set exists to keep verifiable. Another role's compromised key is the OAuth
 * binding's concern, not this set's.
 *
 * The set changes only when the key ring does, and the AS loads its ring
 * only at boot, so the set is signed once at boot.
 */

import { SignJWT } from "jose";
import type { WithdrawnSigningKey } from "./signing-key-ring.js";

/** The set's JWS `typ` (Status, "Historical Key Set"). */
export const HISTORICAL_KEY_SET_TYP = "jwk-set+jwt";
/** The HTTP `Content-Type` the set is served with, the media type of its `typ`. */
export const HISTORICAL_KEY_SET_MEDIA_TYPE = "application/jwk-set+jwt";
/** Where this AS serves the set; discovery names it `mission_historical_jwks_uri`. */
export const HISTORICAL_JWKS_PATH = "/historical-jwks";

/** An ISO 8601 instant as a NumericDate (RFC 7519): whole seconds since the epoch. */
function numericDate(iso: string): number {
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) throw new Error(`historical key set: ${iso} is not a time`);
  return Math.floor(ms / 1000);
}

/**
 * The listed JWKs: each withdrawn key's public JWK under its original `kid`,
 * with `revoked` carrying `reason` `compromised`, `revoked_at` and, only when
 * a compromise time is established, `compromised_at`.
 */
export function historicalKeys(withdrawn: readonly WithdrawnSigningKey[]): Record<string, unknown>[] {
  return withdrawn.map((w) => ({
    ...w.publicJwk,
    revoked: {
      reason: "compromised",
      revoked_at: numericDate(w.revoked_at),
      ...(w.compromised_at !== undefined ? { compromised_at: numericDate(w.compromised_at) } : {}),
    },
  }));
}

/** The members that identify a public key's material, by key type. */
const MATERIAL: Record<string, readonly string[]> = { EC: ["crv", "x", "y"], OKP: ["crv", "x"], RSA: ["e", "n"] };

function sameMaterial(a: Record<string, unknown>, b: Record<string, unknown>): boolean {
  const members = MATERIAL[String(a.kty)];
  return a.kty === b.kty && members !== undefined && members.every((m) => a[m] === b[m]);
}

/**
 * The signed set, or `undefined` when no key is withdrawn: the AS then
 * publishes no set and advertises no `mission_historical_jwks_uri`.
 *
 * The signer is the active Mission Status signing key, and never a key the
 * set lists: one whose `kid` or material a listed key shares is refused.
 */
export async function signHistoricalKeySet(opts: {
  issuer: string;
  withdrawn: readonly WithdrawnSigningKey[];
  signer: { key: CryptoKey; kid: string; publicJwk: Record<string, unknown> };
  now: Date;
}): Promise<string | undefined> {
  if (opts.withdrawn.length === 0) return undefined;
  const keys = historicalKeys(opts.withdrawn);
  for (const listed of keys) {
    if (listed.kid === opts.signer.kid || sameMaterial(listed, opts.signer.publicJwk)) {
      throw new Error(`historical key set: never signed under a key it lists (${String(listed.kid)})`);
    }
  }
  const alg = opts.signer.publicJwk.alg;
  if (typeof alg !== "string") throw new Error("historical key set: the signer names no alg");
  return new SignJWT({ keys })
    .setProtectedHeader({ alg, kid: opts.signer.kid, typ: HISTORICAL_KEY_SET_TYP })
    .setIssuer(opts.issuer)
    .setIssuedAt(Math.floor(opts.now.getTime() / 1000))
    .sign(opts.signer.key);
}
