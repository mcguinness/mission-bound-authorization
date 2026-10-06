import { createHash } from "node:crypto";
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
 */
function keyThumbprint(jwk: Record<string, unknown>, role: KeyRole, kid: string): string {
  const members = typeof jwk.kty === "string" ? THUMBPRINT_MEMBERS[jwk.kty] : undefined;
  if (!members || members.some((m) => typeof jwk[m] !== "string")) {
    throw new Error(`key role pin: ${role} kid ${kid} is not a public EC, OKP or RSA key`);
  }
  const canonical = JSON.stringify(Object.fromEntries(members.map((m) => [m, jwk[m]])));
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
    accessToken: pinned("accessToken"),
    attenuationRoot: pinned("attenuationRoot"),
    transactionToken: pinned("transactionToken"),
  };
}
