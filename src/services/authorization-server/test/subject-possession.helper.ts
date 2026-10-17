/**
 * @spec expansion#request-binding, child-delegation#child-creation (#1210):
 * fixtures for the subject-token possession cases of the child-creation and
 * expansion exchanges. A suite that injects its own AS token signing key
 * (`testTokenSigningJwk`) re-signs a real Mission access token's claims with
 * its `cnf` removed or replaced, and sends one token request whose client
 * authentication is fresh and whose DPoP proof is exactly the one given.
 * The invalid or unacceptable subject and actor token cases (#1178) are built
 * the same way, from a real token.
 */
import { TOPOLOGY } from "@mission/demo-data";
import { calculateJwkThumbprint, type CryptoKey, decodeJwt, exportJWK, generateKeyPair, SignJWT } from "jose";

/** The AS access-token signing key's header (`TOPOLOGY.keys.asToken`). */
const AS_TOKEN_HEADER = { alg: TOPOLOGY.keys.asToken.alg, kid: TOPOLOGY.keys.asToken.kid, typ: "at+jwt" };

/** A key pair of the AS access-token signing algorithm, for a suite's `testTokenSigningJwk`. */
export function asTokenSigningKeyPair(): ReturnType<typeof generateKeyPair> {
  return generateKeyPair(TOPOLOGY.keys.asToken.alg, { extractable: true });
}

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

/** A DPoP confirmation of a key no presenter in these suites holds. */
export const UNHELD_KEY_CNF = { jkt: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" } as const;

/** Re-sign `token`'s claims under `signingKey` after `edit` changes them in place. */
export async function resignWith(
  token: string,
  signingKey: CryptoKey,
  edit: (claims: Record<string, unknown>) => void,
): Promise<string> {
  const claims = { ...(decodeJwt(token) as Record<string, unknown>) };
  edit(claims);
  return new SignJWT(claims).setProtectedHeader(AS_TOKEN_HEADER).sign(signingKey);
}

/** `token`'s claims under the AS header but signed by a key the AS does not hold: it fails verification. */
export async function forge(token: string): Promise<string> {
  const { privateKey } = await asTokenSigningKeyPair();
  return resignWith(token, privateKey, () => {});
}

/**
 * @spec RFC 8693 Section 2.2.2 (#1178, D415): a Token Exchange case built
 * from a real, possession-bound Mission access token, and the fragment of the
 * refusal's `error_description` that names its check.
 */
export type SubjectTokenCase = readonly [
  name: string,
  make: (token: string, signingKey: CryptoKey) => Promise<string>,
  description: string,
];

/**
 * The invalid or unacceptable `subject_token`s every exchange that resolves
 * its subject through the shared possession check (Expansion, Child
 * Delegation, the delegation handle, the Dispatch Handoff) refuses before any
 * side effect: each fails verification, names no Mission, names an unknown
 * one, or is bound to a key other than the presenter's proof key.
 */
export const INVALID_SUBJECT_TOKENS: readonly SubjectTokenCase[] = [
  ["an unverifiable subject_token", (token) => forge(token), "subject_token verification failed"],
  [
    "a subject_token without a mission claim",
    (token, key) => resignWith(token, key, (c) => delete c.mission),
    "missing the mission claim",
  ],
  [
    "a subject_token naming an unknown Mission",
    (token, key) =>
      resignWith(token, key, (c) => {
        c.mission = { ...(c.mission as Record<string, unknown>), id: "msn_unknown_1178" };
      }),
    "mission not found",
  ],
  [
    "an mTLS-bound subject_token",
    (token, key) => resignWithCnf(token, key, MTLS_CNF),
    "not a DPoP key this exchange can verify",
  ],
  [
    "a subject_token bound to another key than the proof's",
    (token, key) => resignWithCnf(token, key, UNHELD_KEY_CNF),
    "does not match the subject_token confirmation key",
  ],
];

/** A presenter's DPoP key pair. */
export type PresenterKeys = { privateKey: CryptoKey; publicKey: CryptoKey };

/** An `actor_token` naming `cnf`, signed by `signingKey`, as the presenter carries one on Expansion and Child Delegation. */
async function actorToken(cnf: Record<string, unknown>, signingKey: CryptoKey): Promise<string> {
  return new SignJWT({ cnf })
    .setProtectedHeader({ alg: "ES256" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setIssuedAt()
    .setExpirationTime("2m")
    .sign(signingKey);
}

/**
 * @spec RFC 8693 Section 2.2.2 (#1178, D415): the invalid or unacceptable
 * `actor_token`s the Expansion and Child Delegation exchanges refuse: one
 * that fails verification under the presenter's key, and one that verifies
 * but is not sender-constrained to it.
 */
export const INVALID_ACTOR_TOKENS: readonly (readonly [
  name: string,
  make: (presenter: PresenterKeys) => Promise<string>,
  description: string,
])[] = [
  [
    "an actor_token that fails verification under the presenter's key",
    async (presenter) => {
      const other = await generateKeyPair("ES256", { extractable: true });
      return actorToken({ jkt: await calculateJwkThumbprint(await exportJWK(presenter.publicKey)) }, other.privateKey);
    },
    "actor_token verification failed",
  ],
  [
    "an actor_token not sender-constrained to the presenter's key",
    (presenter) => actorToken(UNHELD_KEY_CNF, presenter.privateKey),
    "not sender-constrained to the presenter key",
  ],
];

/** The members a refusal of an invalid or unacceptable token carries: no Mission diagnostic, denial reason, or issued artifact. */
export const BARE_REFUSAL_MEMBERS = ["error", "error_description"] as const;
