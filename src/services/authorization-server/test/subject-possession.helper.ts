/**
 * @spec expansion#request-binding, child-delegation#child-creation (#1210):
 * fixtures for the subject-token possession cases of the child-creation and
 * expansion exchanges. A suite that injects its own AS token signing key
 * (`testTokenSigningJwk`) re-signs a real Mission access token's claims with
 * its `cnf` removed or replaced, and sends one token request whose client
 * authentication is fresh and whose DPoP proof is exactly the one given.
 */
import { type CryptoKey, decodeJwt, SignJWT } from "jose";

/** The AS access-token signing key's header (`TOPOLOGY.keys.asToken`). */
const AS_TOKEN_HEADER = { alg: "RS256", kid: "as-token", typ: "at+jwt" } as const;

/** Re-sign `token`'s claims under the injected AS signing key, with `cnf` replaced (`undefined` removes it). */
export async function resignWithCnf(
  token: string,
  signingKey: CryptoKey,
  cnf: Record<string, unknown> | undefined,
): Promise<string> {
  const { cnf: _dropped, ...claims } = decodeJwt(token) as Record<string, unknown>;
  return new SignJWT(cnf ? { ...claims, cnf } : claims).setProtectedHeader(AS_TOKEN_HEADER).sign(signingKey);
}

/** One POST to `/token`: the client assertion as given (fresh per call), the DPoP proof as given (none when null), no nonce retry. */
export async function tokenRequestOnce(
  issuer: string,
  params: Record<string, string>,
  clientAssertion: string,
  proof: string | null,
): Promise<Response> {
  return fetch(`${issuer}/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...(proof === null ? {} : { dpop: proof }),
    },
    body: new URLSearchParams({
      ...params,
      client_assertion: clientAssertion,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
}

/** An mTLS confirmation (RFC 8705 `x5t#S256`): sender-constrained, but not by a DPoP key. */
export const MTLS_CNF = { "x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2" } as const;
