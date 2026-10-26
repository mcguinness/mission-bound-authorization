/**
 * @spec #831 C1, status#signing-key-retention: an issuer's published
 * verification keys as a consumer holds them, refreshed within the
 * freshness the issuer declares and bound to roles the consumer trusts.
 *
 * It lives here because every consumer of an Authorization Server's keys
 * (the resource server, the PDP, the demo's other parties) needs the same
 * discipline and none may depend on the AS package. Like the other core
 * verification rules it is pure but for its injectable `fetch` and clock.
 *
 * The rules, each one a refusal rather than a fallback:
 *
 * - **Trust comes from configuration.** Each role lists the key identifiers
 *   the consumer's trusted configuration authorizes, and may list the
 *   algorithms it accepts (absent: whatever the published key admits). A
 *   key's presence in the key set grants nothing, and no `kid` convention
 *   names a role: a rotation's new generation verifies only once the
 *   consumer's configuration lists it. A consumer changes its configuration
 *   while running through {@link IssuerKeys.setRoles}, which takes effect at
 *   the next resolution. A header's `jku` or `x5u` is never followed.
 * - **Freshness comes only from the response.** The cached set is used for
 *   the freshness lifetime the response explicitly declares (`max-age`, less
 *   any `Age`; RFC 9111 Section 4.2.1). A response that declares none is
 *   stale when received and is given no heuristic lifetime (Section 4.2.2).
 * - **A stale set is revalidated before reuse** (with `If-None-Match` when
 *   the response carried an `ETag`), and if revalidation fails the set is not
 *   used: no stale-if-error.
 * - **Each fetch replaces the set**, never adding to it, so a key the issuer
 *   withdraws stops verifying within the declared lifetime.
 * - **An unknown key triggers a refresh only if trusted**, at most once per
 *   `minRefreshIntervalMs`; concurrent fetches are shared, a fetch times out,
 *   and a failed fetch never admits the key.
 * - **One key never serves two roles**: a set publishing the same key under
 *   two roles' identifiers is refused whole.
 */
import {
  createHash,
  createPublicKey,
  type KeyObject,
  type JsonWebKey as NodeJwk,
} from "node:crypto";

/** One role a consumer verifies under an issuer's keys: what its trusted configuration authorizes. */
export interface IssuerKeyRole {
  /** The key identifiers trusted for this role. */
  kids: readonly string[];
  /**
   * The signature algorithms accepted for this role. Absent: whatever the
   * published key admits (its own `alg` when it names one, and otherwise any
   * algorithm the verifier accepts for the key's type).
   */
  algs?: readonly string[];
}

export type IssuerKeysFetch = (
  url: string,
  init: { headers: Record<string, string>; signal: AbortSignal },
) => Promise<Response>;

export interface IssuerKeysOptions {
  /** The issuer's `jwks_uri`, taken from metadata the consumer has validated. */
  jwksUri: string;
  /** The roles this consumer verifies, each with its trusted key identifiers and algorithms. */
  roles: Readonly<Record<string, IssuerKeyRole>>;
  fetch?: IssuerKeysFetch;
  /** Milliseconds since the epoch. */
  now?: () => number;
  /** A fetch that has not completed within this many milliseconds fails. Default 5000. */
  timeoutMs?: number;
  /** An unknown trusted key refreshes the set at most once per this many milliseconds. Default 30000. */
  minRefreshIntervalMs?: number;
}

export type IssuerKeyRefusal =
  | "no_kid"
  | "untrusted_kid"
  | "algorithm"
  | "unknown_kid"
  | "unavailable";

/** A key a consumer will not rely on, and why. */
export class IssuerKeyError extends Error {
  constructor(
    readonly code: IssuerKeyRefusal,
    message: string,
  ) {
    super(message);
    this.name = "IssuerKeyError";
  }
}

/**
 * The freshness lifetime, in seconds, a response explicitly declares: its
 * `Cache-Control` `max-age`, less its `Age`. Zero when it declares none, or
 * declares `no-store`, `no-cache` or conflicting `max-age` values: such a
 * response is stale when received.
 */
export function explicitFreshnessSeconds(headers: Headers): number {
  const directives = (headers.get("cache-control") ?? "")
    .split(",")
    .map((d) => d.trim().toLowerCase())
    .filter((d) => d.length > 0);
  if (directives.some((d) => d === "no-store" || d === "no-cache" || d.startsWith("no-cache=")))
    return 0;
  const maxAges = directives
    .filter((d) => d.startsWith("max-age="))
    .map((d) => d.slice("max-age=".length).replace(/^"(.*)"$/, "$1"));
  if (maxAges.length !== 1 || !/^\d+$/.test(maxAges[0] as string)) return 0;
  const age = headers.get("age");
  const ageS = age !== null && /^\d+$/.test(age.trim()) ? Number(age.trim()) : 0;
  return Math.max(0, Number(maxAges[0]) - ageS);
}

const THUMBPRINT_MEMBERS: Record<string, readonly string[]> = {
  EC: ["crv", "kty", "x", "y"],
  OKP: ["crv", "kty", "x"],
  RSA: ["e", "kty", "n"],
};

/** The key material's RFC 7638 SHA-256 thumbprint, over its canonical public encoding. */
export function keyThumbprint(key: KeyObject): string | undefined {
  const exported = key.export({ format: "jwk" }) as Record<string, unknown>;
  const members = typeof exported.kty === "string" ? THUMBPRINT_MEMBERS[exported.kty] : undefined;
  if (!members) return undefined;
  const canonical = JSON.stringify(Object.fromEntries(members.map((m) => [m, exported[m]])));
  return createHash("sha256").update(canonical).digest("base64url");
}

interface CachedKey {
  jwk: Record<string, unknown>;
  key: KeyObject;
  role: string;
  thumbprint: string | undefined;
}

interface CachedSet {
  /** The set as fetched, so a change of trusted roles re-selects from it. */
  published: readonly Record<string, unknown>[];
  keys: Map<string, CachedKey>;
  freshUntil: number;
  etag?: string;
}

/** Each trusted kid's role, refusing an algorithm list that is empty and a kid trusted for two roles. */
function indexRoles(roles: Readonly<Record<string, IssuerKeyRole>>): Map<string, string> {
  const roleOfKid = new Map<string, string>();
  for (const [role, config] of Object.entries(roles)) {
    if (config.algs !== undefined && config.algs.length === 0)
      throw new Error(`issuer keys: role ${role} accepts no algorithm`);
    for (const kid of config.kids) {
      const other = roleOfKid.get(kid);
      if (other)
        throw new Error(`issuer keys: kid ${kid} is trusted for both ${other} and ${role}`);
      roleOfKid.set(kid, role);
    }
  }
  return roleOfKid;
}

/** An issuer's verification keys, held by one consumer under its trusted role configuration. */
export class IssuerKeys {
  readonly #opts: IssuerKeysOptions;
  readonly #fetch: IssuerKeysFetch;
  readonly #now: () => number;
  #roles: Readonly<Record<string, IssuerKeyRole>>;
  #roleOfKid: Map<string, string>;
  #cache: CachedSet | undefined;
  #inflight: Promise<void> | undefined;
  #lastUnknownRefresh = Number.NEGATIVE_INFINITY;

  constructor(opts: IssuerKeysOptions) {
    this.#opts = opts;
    this.#fetch = opts.fetch ?? ((url, init) => fetch(url, init));
    this.#now = opts.now ?? (() => Date.now());
    this.#roleOfKid = indexRoles(opts.roles);
    this.#roles = opts.roles;
  }

  /**
   * Replace the trusted roles at once: a consumer's reload of its trusted
   * configuration, taking effect at the next resolution. The cached set is
   * re-selected under the new roles; a replacement under which the set would
   * give one key to two roles is refused, and the roles in force stay. A
   * stale cached set is revalidated at the next resolution, as always.
   */
  setRoles(roles: Readonly<Record<string, IssuerKeyRole>>): void {
    const roleOfKid = indexRoles(roles);
    const keys = this.#cache ? this.#select(this.#cache.published, roleOfKid) : undefined;
    this.#roles = roles;
    this.#roleOfKid = roleOfKid;
    if (this.#cache && keys) this.#cache = { ...this.#cache, keys };
  }

  /**
   * The trusted keys of a fresh copy of the set, by RFC 7638 thumbprint, with
   * each one's role: for a consumer that must keep this issuer's keys apart
   * from another source's. A set that cannot be revalidated refuses.
   */
  async trustedThumbprints(): Promise<ReadonlyMap<string, string>> {
    if (!this.#cache || this.#now() >= this.#cache.freshUntil) await this.#load();
    const out = new Map<string, string>();
    for (const entry of (this.#cache as CachedSet).keys.values()) {
      if (entry.thumbprint) out.set(entry.thumbprint, entry.role);
    }
    return out;
  }

  /**
   * A key resolver for `role`, for `jwtVerify`: the key the header's `kid`
   * names, among that role's trusted keys, under the roles in force, in a
   * fresh copy of the set.
   */
  resolver(role: string): (header: { kid?: unknown; alg?: unknown }) => Promise<KeyObject> {
    if (!this.#roles[role]) throw new Error(`issuer keys: no role ${role}`);
    return async (header) => {
      const config = this.#roles[role];
      const { kid, alg } = header;
      if (typeof kid !== "string") throw new IssuerKeyError("no_kid", "the header names no kid");
      if (!config || !config.kids.includes(kid))
        throw new IssuerKeyError("untrusted_kid", `kid ${kid} is not trusted for ${role}`);
      if (typeof alg !== "string" || (config.algs !== undefined && !config.algs.includes(alg))) {
        throw new IssuerKeyError("algorithm", `alg ${String(alg)} is not accepted for ${role}`);
      }
      if (!this.#cache || this.#now() >= this.#cache.freshUntil) await this.#load();
      let entry = (this.#cache as CachedSet).keys.get(kid);
      if (entry && entry.role !== role) entry = undefined;
      if (
        !entry &&
        this.#now() - this.#lastUnknownRefresh >= (this.#opts.minRefreshIntervalMs ?? 30_000)
      ) {
        this.#lastUnknownRefresh = this.#now();
        await this.#load();
        entry = (this.#cache as CachedSet).keys.get(kid);
        if (entry && entry.role !== role) entry = undefined;
      }
      if (!entry)
        throw new IssuerKeyError("unknown_kid", `${this.#opts.jwksUri} publishes no key ${kid}`);
      if (entry.jwk.alg !== undefined && entry.jwk.alg !== alg) {
        throw new IssuerKeyError(
          "algorithm",
          `kid ${kid} is published for alg ${String(entry.jwk.alg)}, not ${alg}`,
        );
      }
      return entry.key;
    };
  }

  /** Fetch the set now, sharing a fetch already under way. */
  refresh(): Promise<void> {
    return this.#load();
  }

  #load(): Promise<void> {
    if (this.#inflight) return this.#inflight;
    this.#inflight = this.#fetchSet().finally(() => {
      this.#inflight = undefined;
    });
    return this.#inflight;
  }

  async #fetchSet(): Promise<void> {
    const uri = this.#opts.jwksUri;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.#opts.timeoutMs ?? 5000);
    try {
      const headers: Record<string, string> = this.#cache?.etag
        ? { "if-none-match": this.#cache.etag }
        : {};
      const res = await this.#fetch(uri, { headers, signal: controller.signal });
      if (res.status === 304 && this.#cache) {
        this.#cache.freshUntil = this.#now() + explicitFreshnessSeconds(res.headers) * 1000;
        return;
      }
      if (res.status !== 200)
        throw new IssuerKeyError("unavailable", `${uri} answered HTTP ${res.status}`);
      const body = (await res.json()) as { keys?: unknown };
      if (!Array.isArray(body.keys))
        throw new IssuerKeyError("unavailable", `${uri} is not a key set`);
      const published = body.keys as Record<string, unknown>[];
      const fetched = this.#select(published, this.#roleOfKid);
      const etag = res.headers.get("etag");
      this.#cache = {
        published,
        keys: fetched,
        freshUntil: this.#now() + explicitFreshnessSeconds(res.headers) * 1000,
        ...(etag ? { etag } : {}),
      };
    } catch (e) {
      if (e instanceof IssuerKeyError) throw e;
      throw new IssuerKeyError("unavailable", `cannot refresh ${uri}: ${(e as Error).message}`);
    } finally {
      clearTimeout(timer);
    }
  }

  /** The trusted keys a fetched set publishes, by `kid`; a set that gives one key to two roles is refused. */
  #select(
    published: readonly Record<string, unknown>[],
    roleOfKid: Map<string, string>,
  ): Map<string, CachedKey> {
    const out = new Map<string, CachedKey>();
    const holder = new Map<string, string>();
    for (const jwk of published) {
      if (!jwk || typeof jwk !== "object" || typeof jwk.kid !== "string") continue;
      const role = roleOfKid.get(jwk.kid);
      if (!role || out.has(jwk.kid)) continue;
      if (jwk.use !== undefined && jwk.use !== "sig") continue;
      let key: KeyObject;
      try {
        key = createPublicKey({ key: jwk as NodeJwk, format: "jwk" });
      } catch {
        continue;
      }
      const print = keyThumbprint(key);
      if (print) {
        const prior = holder.get(print);
        if (prior && prior !== role) {
          throw new IssuerKeyError(
            "unavailable",
            `${this.#opts.jwksUri} publishes one key for both ${prior} and ${role}`,
          );
        }
        holder.set(print, role);
      }
      out.set(jwk.kid, { jwk, key, role, thumbprint: print });
    }
    return out;
  }
}
