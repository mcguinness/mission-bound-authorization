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
 * - **What the consumer learns as compromised, it keeps.** Unlike the
 *   `jwks_uri`, an allow-list whose stale copy would admit a withdrawn key,
 *   the set only refuses, and a compromised key is never taken back: no
 *   later set removes a learned revocation, and an outage keeps it. A
 *   learned-compromised key signs no set. A consumer that has never verified
 *   one continues on the `jwks_uri` rule alone: the AS's withdrawal, bounded
 *   by that set's declared freshness, stays the primary enforcement.
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
 * A refreshing hold on the set at `uri`, refetched within the freshness its
 * response declares, as the consumer's `jwks_uri` is.
 *
 * - **What it learns, it keeps.** Every key a verified set lists joins what
 *   the holder has learned and never leaves it: a later set, replayed or
 *   replacing, whether empty or older, adds revocations but never removes
 *   one. A compromised key is never taken back, so this can only refuse too
 *   much. A failed refetch keeps it too; it does not extend the `jwks_uri`'s
 *   freshness.
 * - **A learned-compromised key signs nothing.** A set whose signer the
 *   holder has learned is compromised is refused whole, so it can neither
 *   remove a revocation nor list the current key.
 * - **Bounded and shared.** One deadline covers the fetch and the body read;
 *   concurrent uses share one refresh; after a failure the holder waits
 *   `retryDelayMs` before fetching again, answering from what it holds.
 */
export class HistoricalKeySetHolder {
  /** Every listed key verified so far, by `kid`. */
  readonly #learned = new Map<string, HistoricalKey>();
  #verified = false;
  #freshUntil = Number.NEGATIVE_INFINITY;
  #retryAfter = Number.NEGATIVE_INFINITY;
  #inflight: Promise<void> | undefined;
  readonly #opts: {
    uri: string;
    issuer: string;
    statusKeys: JWTVerifyGetKey;
    algs: readonly string[];
    fetch: IssuerKeysFetch;
    now: () => number;
    timeoutMs: number;
    retryDelayMs: number;
  };

  constructor(opts: {
    uri: string;
    issuer: string;
    statusKeys: JWTVerifyGetKey;
    algs: readonly string[];
    fetch?: IssuerKeysFetch;
    now?: () => number;
    /** The deadline for one fetch and its body. Default 5 s. */
    timeoutMs?: number;
    /** How long a failed refresh suppresses another. Default 30 s. */
    retryDelayMs?: number;
  }) {
    this.#opts = {
      ...opts,
      fetch: opts.fetch ?? ((url, init) => fetch(url, init)),
      now: opts.now ?? (() => Date.now()),
      timeoutMs: opts.timeoutMs ?? 5000,
      retryDelayMs: opts.retryDelayMs ?? 30_000,
    };
  }

  /** Every key learned as compromised; `undefined` until a set has verified. */
  async keys(): Promise<readonly HistoricalKey[] | undefined> {
    const now = this.#opts.now();
    if (now >= this.#freshUntil && now >= this.#retryAfter) {
      this.#inflight ??= this.#refresh().finally(() => {
        this.#inflight = undefined;
      });
      await this.#inflight;
    }
    return this.#verified ? [...this.#learned.values()] : undefined;
  }

  /** The configured Status keys, refusing a signer the holder has learned is compromised. */
  readonly #signers: JWTVerifyGetKey = async (header, token) => {
    if (typeof header.kid === "string" && this.#learned.has(header.kid)) {
      throw new Error(`the historical key set's signer ${header.kid} is withdrawn as compromised`);
    }
    return this.#opts.statusKeys(header, token);
  };

  async #refresh(): Promise<void> {
    const requestTime = this.#opts.now();
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new Error(`no historical key set from ${this.#opts.uri} within ${this.#opts.timeoutMs} ms`));
      }, this.#opts.timeoutMs);
    });
    try {
      const res = await Promise.race([this.#opts.fetch(this.#opts.uri, { headers: {}, signal: controller.signal }), deadline]);
      if (res.status !== 200) throw new Error(`${this.#opts.uri} answered HTTP ${res.status}`);
      const body = await Promise.race([res.text(), deadline]);
      const responseTime = this.#opts.now();
      const keys = await verifyHistoricalKeySet(body, {
        issuer: this.#opts.issuer,
        statusKeys: this.#signers,
        algs: this.#opts.algs,
      });
      for (const key of keys) if (!this.#learned.has(key.kid)) this.#learned.set(key.kid, key);
      this.#verified = true;
      this.#freshUntil = freshUntil(res.headers, requestTime, responseTime);
      this.#retryAfter = Number.NEGATIVE_INFINITY;
    } catch {
      // What was learned stays; the next attempt waits out the retry delay.
      this.#retryAfter = this.#opts.now() + this.#opts.retryDelayMs;
    } finally {
      clearTimeout(timer);
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
