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

/**
 * One key resolver per role, each over only the keys pinned to that role.
 * A token whose header names no `kid` is refused: with a single key in a
 * set, a kid-less header would otherwise select it. Misconfiguration (a
 * `kid` in two roles, or one naming no key) fails at startup, never at
 * the first request.
 */
export function roleKeyResolvers(
  roles: KeyRoles,
  sources: { jwks: Jwks; txnTokenJwks?: Jwks | undefined },
): Record<KeyRole, KeyResolver> {
  const seen = new Map<string, KeyRole>();
  for (const role of ["accessToken", "attenuationRoot", "transactionToken"] as const) {
    for (const kid of roles[role]) {
      const other = seen.get(kid);
      if (other) throw new Error(`key role pin: kid ${kid} is configured for both ${other} and ${role}`);
      seen.set(kid, role);
    }
  }
  const pinned = (role: KeyRole, source: Jwks | undefined): KeyResolver => {
    const kids = roles[role];
    const keys = (source?.keys ?? []).filter((k) => typeof k.kid === "string" && kids.includes(k.kid));
    for (const kid of kids) {
      if (!keys.some((k) => k.kid === kid)) {
        throw new Error(`key role pin: ${role} kid ${kid} names no key in its key set`);
      }
    }
    const resolve = createLocalJWKSet({ keys } as never);
    return ((header: JWTHeaderParameters, token: Parameters<KeyResolver>[1]) => {
      if (typeof header.kid !== "string") throw new Error("token header names no kid");
      return resolve(header, token);
    }) as KeyResolver;
  };
  return {
    accessToken: pinned("accessToken", sources.jwks),
    attenuationRoot: pinned("attenuationRoot", sources.jwks),
    transactionToken: pinned("transactionToken", sources.txnTokenJwks),
  };
}
