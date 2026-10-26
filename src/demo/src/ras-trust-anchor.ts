/**
 * @spec #831 C2: the RAS's trust anchor for the AS issuer in the demo
 * stack, which trusts two keys under that issuer: the stack's own
 * cross-domain grant key, which the AS does not publish, and the AS's
 * continuation key, which it does.
 *
 * A grant naming one of the local keys' `kid`s resolves locally; any other
 * `kid` resolves only through the issuer's published set (an `IssuerKeys`
 * resolver for the continuation role). A `kid` the issuer's set refuses
 * never falls back to a local key.
 */
import { createLocalJWKSet, type JWK, type JWSHeaderParameters } from "jose";

type Resolve = (header: JWSHeaderParameters) => Promise<unknown>;

export function composedTrustAnchor(local: readonly JWK[], published: Resolve): (header: JWSHeaderParameters) => Promise<never> {
  const kids = new Set(local.map((k) => k.kid));
  const resolveLocal = createLocalJWKSet({ keys: [...local] } as never);
  return ((header: JWSHeaderParameters) =>
    typeof header.kid === "string" && kids.has(header.kid) ? resolveLocal(header, undefined as never) : published(header)) as never;
}
