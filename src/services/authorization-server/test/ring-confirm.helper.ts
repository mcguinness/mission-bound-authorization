/**
 * @spec #831 B2: confirm a key ring as a running AS started with it would
 * let `pnpm keys verify` confirm it: the verification reads a `/jwks` that
 * serves the ring's current revision as its `ETag` and its live set. For
 * tests that rotate a ring as setup; signing-key-rotation.test.ts drives the
 * procedure itself against a real AS.
 */
import {
  type AsSigningRole,
  loadSigningKeyRingState,
  type SigningKeyRingVerification,
  verifySigningKeyRing,
} from "../src/index.js";

export async function confirmRing(
  file: string,
  issuer: string,
  roles: Record<AsSigningRole, { kid: string; alg: string }>,
  now?: () => Date,
): Promise<SigningKeyRingVerification> {
  const { keys, revision } = await loadSigningKeyRingState(file, issuer, roles);
  const live = Object.values(keys).flatMap((r) => r.published);
  const served = async (url: string): Promise<Response> =>
    url.endsWith("/.well-known/openid-configuration")
      ? Response.json({ issuer, jwks_uri: `${issuer}/jwks` })
      : new Response(JSON.stringify({ keys: live }), { status: 200, headers: { etag: `"${revision}"` } });
  return verifySigningKeyRing(file, issuer, roles, { fetch: served, ...(now ? { now } : {}) });
}
