import { createEgressAdmission, createFetchJson, type EgressAdmission } from "./egress.js";
import { SignatureError } from "./errors.js";
import { isServerIdentifier, isWellKnownName } from "./identifiers.js";

/** Fetch a URL and return its status and parsed JSON body. */
export type FetchJson = (url: string) => Promise<{ status: number; body: unknown }>;

export interface JwksResolverOptions {
  /**
   * Default: {@link createFetchJson}, a fetch with a timeout, a size limit
   * and no redirects that connects only to the public addresses it
   * resolved. A replacement must pin its connection to addresses it has
   * checked in the same way (DNS-rebinding defense), and a deployment that
   * admits private destinations admits them here as well as in
   * `admitEgress`.
   *
   * @spec signature-key#section-7.3
   */
  fetchJson?: FetchJson;
  /** Milliseconds since the epoch. */
  now?: () => number;
  /**
   * Egress admission, applied before every metadata or JWKS fetch.
   * Default: {@link createEgressAdmission} with its defaults.
   *
   * @spec aauth#section-11.4
   */
  admitEgress?: EgressAdmission;
  /**
   * Fetch floor: each metadata document, and each issuer's JWKS across all
   * of its documents, is fetched no more than once per this interval.
   */
  minRefreshIntervalMs?: number;
  /** Cached keys are discarded after this age regardless of cache headers. */
  maxAgeMs?: number;
  /** Issuers held at once; the least recently used is evicted. Default 1000. */
  maxIssuers?: number;
}

interface CacheEntry {
  keys: unknown[];
  fetchedAt: number;
}

/**
 * Discovers and caches issuer keys through `{iss}/.well-known/{dwk}`,
 * checking that the metadata's `issuer` equals the identifier it was
 * fetched under. Keys are selected by `kid` alone, so an unselected
 * member the verifier cannot use never fails the lookup. At most one fetch
 * per metadata document per minute, and one fetch of an issuer's JWKS per
 * minute however many of its documents name it, each shared by concurrent
 * callers; an unknown `kid` or a refresh request fetches again once the
 * floor allows, and within the issuer's JWKS floor a document reuses the
 * keys its issuer's last JWKS fetch returned; a failed fetch
 * falls back to cached keys; entries are discarded after 24 hours. The
 * cache is bounded, since unauthenticated callers choose the issuers.
 *
 * @spec aauth#section-11.4
 * @spec signature-key#section-3.6
 * @spec signature-key#section-7.2
 */
export class JwksResolver {
  private readonly fetchJson: FetchJson;
  private readonly now: () => number;
  private readonly admitEgress: EgressAdmission;
  private readonly minRefreshIntervalMs: number;
  private readonly maxAgeMs: number;
  private readonly maxIssuers: number;
  private readonly cache = new Map<string, CacheEntry>();
  private readonly lastAttempt = new Map<string, number>();
  private readonly inflight = new Map<string, Promise<CacheEntry | undefined>>();
  /** Per issuer: the last JWKS fetch, its floor and any fetch in flight. */
  private readonly issuerJwks = new Map<string, { url: string; keys: unknown[] }>();
  private readonly issuerJwksAttempt = new Map<string, number>();
  private readonly issuerJwksInflight = new Map<
    string,
    { url: string; keys: Promise<unknown[]> }
  >();

  constructor(options: JwksResolverOptions = {}) {
    this.fetchJson = options.fetchJson ?? createFetchJson();
    this.now = options.now ?? Date.now;
    this.admitEgress = options.admitEgress ?? createEgressAdmission();
    this.minRefreshIntervalMs = options.minRefreshIntervalMs ?? 60_000;
    this.maxAgeMs = options.maxAgeMs ?? 24 * 60 * 60 * 1000;
    this.maxIssuers = options.maxIssuers ?? 1000;
  }

  /**
   * Resolve the JWK named by `kid` under `issuer`'s `dwk` document. With
   * `refresh`, fetch again if the floor allows (used after a cached key
   * fails verification). Throws `unknown_key`, `issuer_missing` or
   * `issuer_mismatch`.
   */
  async resolveKey(
    issuer: string,
    dwk: string,
    kid: string,
    options: { refresh?: boolean } = {},
  ): Promise<Record<string, unknown>> {
    if (!isServerIdentifier(issuer)) {
      throw new SignatureError("invalid_key", "issuer is not a server identifier");
    }
    if (!isWellKnownName(dwk)) {
      throw new SignatureError("invalid_key", "dwk is not a well-known document name");
    }
    const cacheKey = `${issuer}\n${dwk}`;
    let entry = this.cache.get(cacheKey);
    if (entry && this.now() - entry.fetchedAt > this.maxAgeMs) {
      this.cache.delete(cacheKey);
      entry = undefined;
    }
    let fetched = false;
    if (!entry || options.refresh) {
      const refreshed = await this.fetchIfAllowed(cacheKey, issuer, dwk, entry);
      fetched = refreshed !== entry;
      entry = refreshed;
    }
    let key = entry && selectKey(entry.keys, kid);
    if (!key && entry && !fetched) {
      entry = await this.fetchIfAllowed(cacheKey, issuer, dwk, entry);
      key = entry && selectKey(entry.keys, kid);
    }
    if (!key) throw new SignatureError("unknown_key", `no key ${kid} at ${issuer}`);
    return key;
  }

  private fetchIfAllowed(
    cacheKey: string,
    issuer: string,
    dwk: string,
    cached: CacheEntry | undefined,
  ): Promise<CacheEntry | undefined> {
    const pending = this.inflight.get(cacheKey);
    if (pending) return pending;
    const now = this.now();
    const last = this.lastAttempt.get(cacheKey);
    if (last !== undefined && now - last < this.minRefreshIntervalMs) {
      return Promise.resolve(cached);
    }
    remember(this.lastAttempt, cacheKey, now, this.maxIssuers);
    const attempt = this.discover(issuer, dwk)
      .then((keys) => {
        const entry = { keys, fetchedAt: now };
        remember(this.cache, cacheKey, entry, this.maxIssuers);
        return entry;
      })
      .catch((err: unknown) => {
        // The issuer checks are verdicts about the document, not outages.
        if (err instanceof SignatureError && err.code !== "unknown_key") throw err;
        return cached;
      })
      .finally(() => this.inflight.delete(cacheKey));
    this.inflight.set(cacheKey, attempt);
    return attempt;
  }

  private async discover(issuer: string, dwk: string): Promise<unknown[]> {
    const metadataUrl = new URL(`${issuer}/.well-known/${dwk}`);
    const metadata = await this.get(metadataUrl, "metadata", issuer);
    if (typeof metadata !== "object" || metadata === null) {
      throw new SignatureError("unknown_key", "metadata document is not a JSON object");
    }
    const doc = metadata as Record<string, unknown>;
    if (doc.issuer === undefined) {
      throw new SignatureError("issuer_missing", `${metadataUrl.href} has no issuer`);
    }
    if (doc.issuer !== issuer) {
      throw new SignatureError("issuer_mismatch", `${metadataUrl.href} names another issuer`);
    }
    if (typeof doc.jwks_uri !== "string") {
      throw new SignatureError("unknown_key", "metadata document has no jwks_uri");
    }
    let jwksUrl: URL;
    try {
      jwksUrl = new URL(doc.jwks_uri);
    } catch {
      throw new SignatureError("unknown_key", "jwks_uri is not a URL");
    }
    return this.issuerKeys(issuer, jwksUrl);
  }

  /**
   * The issuer's JWKS, fetched at most once per floor interval across all
   * of the issuer's metadata documents. Within the floor, a document naming
   * the JWKS just fetched reuses its keys; one naming another JWKS cannot
   * be fetched until the floor allows.
   *
   * @spec aauth#section-11.4
   */
  private issuerKeys(issuer: string, url: URL): Promise<unknown[]> {
    const pending = this.issuerJwksInflight.get(issuer);
    if (pending?.url === url.href) return pending.keys;
    const now = this.now();
    const last = this.issuerJwksAttempt.get(issuer);
    if (last !== undefined && now - last < this.minRefreshIntervalMs) {
      const recent = this.issuerJwks.get(issuer);
      if (recent?.url === url.href) return Promise.resolve(recent.keys);
      return Promise.reject(
        new SignatureError("unknown_key", `${issuer}'s JWKS was fetched within the floor`),
      );
    }
    remember(this.issuerJwksAttempt, issuer, now, this.maxIssuers);
    const keys = this.get(url, "jwks", issuer)
      .then((jwks) => {
        const fetched = (jwks as { keys?: unknown } | null)?.keys;
        if (!Array.isArray(fetched)) {
          throw new SignatureError("unknown_key", "JWKS has no keys array");
        }
        remember(this.issuerJwks, issuer, { url: url.href, keys: fetched }, this.maxIssuers);
        return fetched;
      })
      .finally(() => this.issuerJwksInflight.delete(issuer));
    this.issuerJwksInflight.set(issuer, { url: url.href, keys });
    return keys;
  }

  private async get(url: URL, kind: "metadata" | "jwks", issuer: string): Promise<unknown> {
    if (!(await this.admitEgress({ url, kind, issuer }))) {
      throw new SignatureError("unknown_key", `egress to ${url.origin} is not admitted`);
    }
    let result: { status: number; body: unknown };
    try {
      result = await this.fetchJson(url.href);
    } catch {
      throw new SignatureError("unknown_key", `fetch of ${url.href} failed`);
    }
    if (result.status !== 200) {
      throw new SignatureError("unknown_key", `fetch of ${url.href} returned ${result.status}`);
    }
    return result.body;
  }
}

/** Set `key`, most recently used last, evicting the oldest beyond `limit`. */
function remember<V>(map: Map<string, V>, key: string, value: V, limit: number): void {
  map.delete(key);
  map.set(key, value);
  while (map.size > limit) {
    const oldest = map.keys().next().value as string;
    map.delete(oldest);
  }
}

function selectKey(keys: unknown[], kid: string): Record<string, unknown> | undefined {
  for (const k of keys) {
    if (typeof k === "object" && k !== null && (k as { kid?: unknown }).kid === kid) {
      return k as Record<string, unknown>;
    }
  }
  return undefined;
}
