import { createHash, createPublicKey, type JsonWebKey as NodeJwk } from "node:crypto";
import { IssuerKeyError, IssuerKeys, type IssuerKeysFetch, keyThumbprint as materialThumbprint } from "@mission/core";
import { createLocalJWKSet, type JWTHeaderParameters } from "jose";

/**
 * The token classes this resource verifies under the AS's keys. Each class
 * is verified only with keys configured for its role.
 */
export type KeyRole = "accessToken" | "attenuationRoot" | "transactionToken";

/**
 * @spec runtime-oauth#token-validation, RFC 8725 Section 3.12 (#825, D312):
 * the locally configured `kid`s trusted for each token class. A shared
 * JWKS and distinct `typ` or `kid` strings do not by themselves enforce
 * purpose; this pin does. The lists are disjoint, and every `kid` listed
 * must name a key in the class's key source. An empty list means the
 * class is refused.
 */
export interface KeyRoles {
  /** Ordinary and Mission-bound access tokens (`at+jwt`). */
  accessToken: readonly string[];
  /** Attenuation chain roots (`aat+jwt`). */
  attenuationRoot: readonly string[];
  /** Transaction tokens (`mission-txn-token+jwt`), resolved from `txnTokenJwks`. */
  transactionToken: readonly string[];
}

export type KeyResolver = ReturnType<typeof createLocalJWKSet>;

/**
 * @spec #831 C2 (D825): the deployment's per-role algorithm policy. A role
 * listed here verifies only under the listed algorithms, whichever key source
 * the server uses; a role not listed accepts whatever its pinned key admits,
 * again under either source.
 */
export type KeyAlgorithms = Partial<Record<KeyRole, readonly string[]>>;

/** A role's resolver, refusing a header algorithm the policy does not list. */
function underPolicy(resolve: KeyResolver, role: KeyRole, algorithms: KeyAlgorithms | undefined): KeyResolver {
  const allowed = algorithms?.[role];
  if (!allowed) return resolve;
  return ((header: JWTHeaderParameters, token: Parameters<KeyResolver>[1]) => {
    if (typeof header.alg !== "string" || !allowed.includes(header.alg)) {
      throw new Error(`token alg ${String(header.alg)} is not accepted for ${role}`);
    }
    return resolve(header, token);
  }) as KeyResolver;
}

type Jwks = { keys: Record<string, unknown>[] };

/** RFC 7638 required members, in lexicographic order, for each key type a role may hold. */
const THUMBPRINT_MEMBERS: Record<string, readonly string[]> = {
  EC: ["crv", "kty", "x", "y"],
  OKP: ["crv", "kty", "x"],
  RSA: ["e", "kty", "n"],
};

/**
 * RFC 7638 SHA-256 thumbprint of a public key: the key material itself,
 * whatever `kid` it is published under. Computed synchronously, since the
 * pin is checked when the resource server is constructed.
 *
 * The thumbprint is taken over the key's canonical encoding, not the JWK as
 * written. The verifier imports equivalent encodings of one key (base64url
 * with `=` padding, an RSA modulus or exponent with leading zero bytes), and
 * those hash differently as written; importing and re-exporting the public
 * key collapses them to one form.
 */
function keyThumbprint(jwk: Record<string, unknown>, role: KeyRole, kid: string): string {
  const notPublic = () => new Error(`key role pin: ${role} kid ${kid} is not a public EC, OKP or RSA key`);
  if (typeof jwk.kty !== "string" || !THUMBPRINT_MEMBERS[jwk.kty]) throw notPublic();
  let exported: Record<string, unknown>;
  try {
    exported = createPublicKey({ key: jwk as NodeJwk, format: "jwk" }).export({ format: "jwk" }) as Record<
      string,
      unknown
    >;
  } catch {
    throw notPublic();
  }
  const members = typeof exported.kty === "string" ? THUMBPRINT_MEMBERS[exported.kty] : undefined;
  if (!members || members.some((m) => typeof exported[m] !== "string")) throw notPublic();
  const canonical = JSON.stringify(Object.fromEntries(members.map((m) => [m, exported[m]])));
  return createHash("sha256").update(canonical).digest("base64url");
}

/**
 * One key resolver per role, each over only the keys pinned to that role.
 * A token whose header names no `kid` is refused: with a single key in a
 * set, a kid-less header would otherwise select it. Misconfiguration fails
 * at startup, never at the first request: a `kid` in two roles, a `kid`
 * naming no key, and one key published under different `kid`s for two
 * roles, since the private key would then sign for both classes.
 */
export function roleKeyResolvers(
  roles: KeyRoles,
  sources: { jwks: Jwks; txnTokenJwks?: Jwks | undefined },
  algorithms?: KeyAlgorithms,
): Record<KeyRole, KeyResolver> {
  const order = ["accessToken", "attenuationRoot", "transactionToken"] as const;
  const seen = new Map<string, KeyRole>();
  for (const role of order) {
    for (const kid of roles[role]) {
      const other = seen.get(kid);
      if (other) throw new Error(`key role pin: kid ${kid} is configured for both ${other} and ${role}`);
      seen.set(kid, role);
    }
  }
  const sourceOf: Record<KeyRole, Jwks | undefined> = {
    accessToken: sources.jwks,
    attenuationRoot: sources.jwks,
    transactionToken: sources.txnTokenJwks,
  };
  const selected = {} as Record<KeyRole, Record<string, unknown>[]>;
  for (const role of order) {
    const kids = roles[role];
    const keys = (sourceOf[role]?.keys ?? []).filter(
      (k) => typeof k.kid === "string" && kids.includes(k.kid),
    );
    for (const kid of kids) {
      if (!keys.some((k) => k.kid === kid)) {
        throw new Error(`key role pin: ${role} kid ${kid} names no key in its key set`);
      }
    }
    selected[role] = keys;
  }
  // Distinct kids are not distinct keys: compare the key material itself
  // across roles. The same key under two kids within one role (a rotation
  // alias) stays allowed.
  const holder = new Map<string, { role: KeyRole; kid: string }>();
  for (const role of order) {
    for (const key of selected[role]) {
      const kid = key.kid as string;
      const thumbprint = keyThumbprint(key, role, kid);
      const prior = holder.get(thumbprint);
      if (prior && prior.role !== role) {
        throw new Error(
          `key role pin: ${role} kid ${kid} is the same key as ${prior.role} kid ${prior.kid}`,
        );
      }
      holder.set(thumbprint, { role, kid });
    }
  }
  const pinned = (role: KeyRole): KeyResolver => {
    const resolve = createLocalJWKSet({ keys: selected[role] } as never);
    return ((header: JWTHeaderParameters, token: Parameters<KeyResolver>[1]) => {
      if (typeof header.kid !== "string") throw new Error("token header names no kid");
      return resolve(header, token);
    }) as KeyResolver;
  };
  return {
    accessToken: underPolicy(pinned("accessToken"), "accessToken", algorithms),
    attenuationRoot: underPolicy(pinned("attenuationRoot"), "attenuationRoot", algorithms),
    transactionToken: underPolicy(pinned("transactionToken"), "transactionToken", algorithms),
  };
}

/** {@link refreshingRoleKeyResolvers}' resolvers, and the reload of the trusted configuration they resolve under. */
export type RefreshingRoleKeys = Record<KeyRole, KeyResolver> & {
  /**
   * Replace the pinned `kid`s (and the algorithm policy) at once, taking
   * effect at the next resolution: a reload of the deployment's trusted
   * configuration. A replacement that pins one `kid` to two roles, or under
   * which a key set would give one key to two roles, is refused, and the
   * configuration in force stays.
   */
  setRoles(roles: KeyRoles, algorithms?: KeyAlgorithms): void;
};

/** Refuse a `kid` pinned to two roles. */
function disjoint(roles: KeyRoles): void {
  const seen = new Map<string, KeyRole>();
  for (const role of ["accessToken", "attenuationRoot", "transactionToken"] as const) {
    for (const kid of roles[role]) {
      const other = seen.get(kid);
      if (other) throw new Error(`key role pin: kid ${kid} is configured for both ${other} and ${role}`);
      seen.set(kid, role);
    }
  }
}

/**
 * @spec #831 C2: {@link roleKeyResolvers} over the issuers' published key
 * sets rather than a snapshot: each role resolves only its pinned `kid`s,
 * held through `IssuerKeys`, which follows a rotation within the freshness
 * the issuer declares and refuses rather than falls back. The startup checks
 * a snapshot allows (every pinned `kid` names a key; one key, one role) run
 * on each fetch instead: an unpublished pinned `kid` is refused when used,
 * and a set giving one key to two roles is refused whole. A `kid` pinned to
 * two roles still fails at startup. The algorithm policy is the snapshot
 * path's: a listed role verifies only under its list, an unlisted one under
 * whatever its published key admits.
 *
 * With two sources (a transaction-token `jwks_uri` apart from the access
 * token's), one key must still serve one role across both (D825): each
 * resolution compares its key with the other source's trusted keys, read
 * fresh, so the check holds after either set refreshes. A resolution whose
 * other source cannot be revalidated refuses, so an outage of the
 * transaction-token issuer's key set refuses access tokens too, and the
 * reverse.
 */
export function refreshingRoleKeyResolvers(
  roles: KeyRoles,
  sources: { jwksUri: string; txnTokenJwksUri?: string | undefined },
  opts: { now?: () => number; fetch?: IssuerKeysFetch; algorithms?: KeyAlgorithms } = {},
): RefreshingRoleKeys {
  disjoint(roles);
  const { algorithms, ...held } = opts;
  const roleOf = (r: KeyRole, pins: KeyRoles, policy: KeyAlgorithms | undefined) => ({
    kids: pins[r],
    ...(policy?.[r] ? { algs: policy[r] } : {}),
  });
  const shared = sources.txnTokenJwksUri === undefined || sources.txnTokenJwksUri === sources.jwksUri;
  const accessRoles = (pins: KeyRoles, policy: KeyAlgorithms | undefined) => ({
    accessToken: roleOf("accessToken", pins, policy),
    attenuationRoot: roleOf("attenuationRoot", pins, policy),
    ...(shared ? { transactionToken: roleOf("transactionToken", pins, policy) } : {}),
  });
  const txnRoles = (pins: KeyRoles, policy: KeyAlgorithms | undefined) => ({
    transactionToken: roleOf("transactionToken", pins, policy),
  });
  let current = { roles, algorithms };
  const access = new IssuerKeys({ jwksUri: sources.jwksUri, roles: accessRoles(roles, algorithms), ...held });
  const txn = shared
    ? access
    : new IssuerKeys({ jwksUri: sources.txnTokenJwksUri as string, roles: txnRoles(roles, algorithms), ...held });
  const resolverOf = (keys: IssuerKeys, r: KeyRole, other: IssuerKeys | undefined): KeyResolver => {
    const resolve = keys.resolver(r);
    return (async (header: JWTHeaderParameters) => {
      const key = await resolve(header);
      if (other) {
        const print = materialThumbprint(key);
        const holder = print === undefined ? undefined : (await other.trustedThumbprints()).get(print);
        if (holder !== undefined) {
          throw new IssuerKeyError("unavailable", `kid ${String(header.kid)} for ${r} is the same key as the other source's ${holder} key`);
        }
      }
      return key;
    }) as unknown as KeyResolver;
  };
  return {
    accessToken: resolverOf(access, "accessToken", shared ? undefined : txn),
    attenuationRoot: resolverOf(access, "attenuationRoot", shared ? undefined : txn),
    transactionToken: resolverOf(txn, "transactionToken", shared ? undefined : access),
    setRoles(next: KeyRoles, policy?: KeyAlgorithms) {
      disjoint(next);
      access.setRoles(accessRoles(next, policy));
      if (!shared) {
        // Both sources or neither: the access source's replacement is undone when the transaction source refuses.
        try {
          txn.setRoles(txnRoles(next, policy));
        } catch (e) {
          access.setRoles(accessRoles(current.roles, current.algorithms));
          throw e;
        }
      }
      current = { roles: next, algorithms: policy };
    },
  };
}
