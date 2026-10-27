/**
 * @spec status#historical-key-set, status#signing-key-retention (#831 B3) — a
 * Mission Status consumer's hold on an AS's historical key set: the keys the
 * AS withdrew as compromised.
 *
 * - **The signer is configured.** The set verifies only under the consumer's
 *   trusted Status keys (the resolver it verifies Status responses with), never
 *   under any key the AS publishes; a replacement Status key signs only once
 *   the consumer's configuration names it.
 * - **A listed key never serves current reliance.** For a current reliance
 *   decision the consumer verifies under its current keys alone
 *   ({@link excludingCompromised}), and refuses a key the held set lists even
 *   while a cached `jwks_uri` still carries it. A listed key verifies only an
 *   archived response, for audit ({@link auditKeys}).
 * - **When the set cannot be fetched or verified, the consumer holds none**,
 *   and current reliance continues on the `jwks_uri` rule alone: the AS's
 *   withdrawal, bounded by that set's declared freshness, stays the primary
 *   enforcement. Refusing all Status reliance instead is the alternative.
 */

import { freshUntil, type IssuerKeysFetch } from "@mission/core";
import { importJWK, type JWTVerifyGetKey, jwtVerify } from "jose";

/** The set's JWS `typ`. */
export const HISTORICAL_KEY_SET_TYP = "jwk-set+jwt";

/** One key the AS lists as withdrawn for compromise. */
export interface HistoricalKey {
  kid: string;
  jwk: Record<string, unknown>;
  /** NumericDate: when the AS revoked the key. */
  revokedAt: number;
  /** NumericDate: the established compromise time, when one is. */
  compromisedAt?: number;
}

/**
 * The listed keys of a historical key set, after verifying it: `typ` exactly
 * `jwk-set+jwt`, `iss` the expected issuer, and a signature under the
 * consumer's trusted Status keys. Anything else is refused whole.
 */
export async function verifyHistoricalKeySet(
  jws: string,
  opts: { issuer: string; statusKeys: JWTVerifyGetKey; algs: readonly string[] },
): Promise<HistoricalKey[]> {
  const { payload } = await jwtVerify(jws, opts.statusKeys, {
    issuer: opts.issuer,
    typ: HISTORICAL_KEY_SET_TYP,
    algorithms: [...opts.algs],
  });
  if (!Array.isArray(payload.keys)) throw new Error("historical key set: no keys array");
  return payload.keys.map((raw) => {
    const jwk = raw as Record<string, unknown>;
    const revoked = jwk.revoked as Record<string, unknown> | undefined;
    if (
      typeof jwk.kid !== "string" ||
      !revoked ||
      revoked.reason !== "compromised" ||
      typeof revoked.revoked_at !== "number" ||
      (revoked.compromised_at !== undefined && typeof revoked.compromised_at !== "number")
    ) {
      throw new Error("historical key set: a listed key is malformed");
    }
    return {
      kid: jwk.kid,
      jwk,
      revokedAt: revoked.revoked_at,
      ...(typeof revoked.compromised_at === "number" ? { compromisedAt: revoked.compromised_at } : {}),
    };
  });
}

/**
 * A refreshing hold on the set at `uri`: refetched within the freshness its
 * response declares, as the consumer's `jwks_uri` is. A set that cannot be
 * fetched or verified leaves nothing held.
 */
export class HistoricalKeySetHolder {
  #held: { keys: HistoricalKey[]; freshUntil: number } | undefined;
  readonly #opts: {
    uri: string;
    issuer: string;
    statusKeys: JWTVerifyGetKey;
    algs: readonly string[];
    fetch: IssuerKeysFetch;
    now: () => number;
  };

  constructor(opts: {
    uri: string;
    issuer: string;
    statusKeys: JWTVerifyGetKey;
    algs: readonly string[];
    fetch?: IssuerKeysFetch;
    now?: () => number;
  }) {
    this.#opts = {
      ...opts,
      fetch: opts.fetch ?? ((url, init) => fetch(url, init)),
      now: opts.now ?? (() => Date.now()),
    };
  }

  /** The listed keys, fresh; `undefined` when no verified set can be held. */
  async keys(): Promise<readonly HistoricalKey[] | undefined> {
    if (this.#held && this.#opts.now() < this.#held.freshUntil) return this.#held.keys;
    this.#held = undefined;
    const requestTime = this.#opts.now();
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      let res: Response;
      try {
        res = await this.#opts.fetch(this.#opts.uri, { headers: {}, signal: controller.signal });
      } finally {
        clearTimeout(timer);
      }
      const responseTime = this.#opts.now();
      if (res.status !== 200) return undefined;
      const keys = await verifyHistoricalKeySet(await res.text(), this.#opts);
      this.#held = { keys, freshUntil: freshUntil(res.headers, requestTime, responseTime) };
      return keys;
    } catch {
      return undefined;
    }
  }
}

/**
 * The consumer's current keys, refusing a key the held set lists: for a
 * current reliance decision, whatever the cached `jwks_uri` still carries.
 * With no set held, the current keys alone decide.
 */
export function excludingCompromised(current: JWTVerifyGetKey, historical: HistoricalKeySetHolder): JWTVerifyGetKey {
  return async (header, token) => {
    const listed = await historical.keys();
    if (listed?.some((k) => k.kid === header.kid)) {
      throw new Error(`kid ${String(header.kid)} is withdrawn as compromised: never for a current reliance decision`);
    }
    return current(header, token);
  };
}

/**
 * For audit only, never a current reliance decision: a listed key verifies an
 * archived response signed under it; any other `kid` goes to the current keys.
 */
export function auditKeys(current: JWTVerifyGetKey, listed: readonly HistoricalKey[]): JWTVerifyGetKey {
  return async (header, token) => {
    const historical = listed.find((k) => k.kid === header.kid);
    if (historical) {
      const { revoked: _revoked, ...jwk } = historical.jwk;
      return importJWK(jwk as never, typeof header.alg === "string" ? header.alg : undefined) as never;
    }
    return current(header, token);
  };
}
