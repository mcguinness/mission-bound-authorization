/**
 * @spec draft-mcguinness-oauth-id-continuation-assertion-00 — the Identity
 * Continuation Assertion (ICA) subject-token validator.
 *
 * An ICA is a short-lived, DPoP-bound JWT minted by a Chain Authority and
 * presented at the token endpoint as an RFC 8693 subject token to continue a
 * Mission's delegation chain across an intra-domain hop (yielding an ID-JAG).
 * It carries a continuation HANDLE (the durable lineage reference) plus the
 * single current-actor `act` node, and deliberately carries NO identity or
 * authorization claims of its own: `sub`, `auth_time`, `acr`, `amr`, `sid`,
 * `scope`, `resource`, `authorization_details`, `audience`, and
 * `requested_token_type` are all forbidden, so the assertion can never restate
 * or widen the authenticated session's authority.
 *
 * Structure mirrors `instance-assertion.ts`: an unverified `iss` peek selects
 * the trusted issuer, then `compactVerify` checks the signature over
 * asymmetric-only algorithms, and the claims (`typ`, `iss`, `aud`) are checked
 * here. Freshness is a separate step ({@link checkContinuationFreshness}) so a
 * caller can apply it at its own rule position. The `newReplayCache` helper is
 * shared.
 */

import { compactVerify, createLocalJWKSet, type JWK } from "jose";

export const IDENTITY_CONTINUATION_JWT_TYP = "oauth-identity-continuation+jwt";
export const IDENTITY_CONTINUATION_TOKEN_TYPE =
  "urn:ietf:params:oauth:token-type:identity-continuation";

/** Max ICA lifetime (seconds): `exp - iat` MUST NOT exceed this. */
export const MAX_CONTINUATION_LIFETIME_S = 300;

/**
 * @spec id-continuation-assertion — the one permitted clock skew (seconds):
 * future skew for `iat`, past skew for `exp`, and the `nbf` tolerance (ICA -02
 * 5.5.3 rule 6: one value that "SHOULD NOT exceed 60 seconds"). The same 30 s
 * as the AS's other skews. The replay cache never evicts in-process, so the
 * reservation outlives `exp` plus this skew.
 */
export const CONTINUATION_CLOCK_SKEW_S = 30;

const CONTINUATION_ALGS = ["ES256", "RS256", "ES384", "ES512", "RS384", "RS512", "PS256"];

/** base64url alphabet, no padding. */
const BASE64URL = /^[A-Za-z0-9_-]+$/;

/** Top-level claims an ICA MUST NOT carry (it asserts continuation, not identity). */
const FORBIDDEN_CLAIMS = [
  "sub",
  "auth_time",
  "acr",
  "amr",
  "sid",
  "scope",
  "resource",
  "authorization_details",
  "audience",
  "requested_token_type",
] as const;

/** Members an `act` node MUST NOT carry on an ICA (single-level, identity-only). */
const FORBIDDEN_ACT_MEMBERS = ["act", "exp", "nbf", "aud", "scope", "cnf"] as const;

export class ContinuationAssertionError extends Error {
  constructor(
    readonly code: "invalid_request" | "invalid_grant",
    message: string,
  ) {
    super(message);
  }
}

/** A trusted Chain Authority issuer of ICAs. */
export interface ContinuationIssuer {
  iss: string;
  jwks: { keys: JWK[] };
}

/** The single current-actor node carried by an ICA (no nesting). */
export interface ContinuationActor {
  iss: string;
  sub: string;
}

export interface ValidatedContinuation {
  iss: string;
  aud: string;
  /** The continuation handle (the durable lineage reference). */
  handle: string;
  act: ContinuationActor;
  cnf: { jkt: string };
  iat: number;
  exp: number;
  nbf?: number;
  jti: string;
}

/**
 * (iss, jti) replay cache; reuse `newReplayCache()` from instance-assertion.ts.
 * The validator only ever CHECKS (`seen`): recording is the redeeming caller's
 * duty, atomic with issuance (#617 review 1).
 */
interface ReplayCache {
  seen: (iss: string, jti: string) => boolean;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * @spec id-continuation-assertion — the freshness rule (ICA -02 5.5.3 rule 6):
 * `exp` follows `iat`, the lifetime is within {@link MAX_CONTINUATION_LIFETIME_S},
 * `iat` is not in the future, `exp` has not passed, and any `nbf` has passed,
 * each within the one skew. `nowS` is the caller's clock (seconds).
 */
export function checkContinuationFreshness(
  ica: Pick<ValidatedContinuation, "iat" | "exp" | "nbf">,
  ctx: { nowS?: number; skewS?: number } = {},
): void {
  const now = ctx.nowS ?? Math.floor(Date.now() / 1000);
  const skew = ctx.skewS ?? CONTINUATION_CLOCK_SKEW_S;
  if (!(ica.exp > ica.iat) || ica.exp - ica.iat > MAX_CONTINUATION_LIFETIME_S) {
    throw new ContinuationAssertionError(
      "invalid_request",
      `continuation assertion lifetime exceeds ${MAX_CONTINUATION_LIFETIME_S}s or exp does not follow iat`,
    );
  }
  if (ica.iat > now + skew) {
    throw new ContinuationAssertionError("invalid_request", "continuation assertion iat is in the future");
  }
  if (ica.exp <= now - skew) {
    throw new ContinuationAssertionError("invalid_request", "continuation assertion expired");
  }
  if (ica.nbf !== undefined && ica.nbf > now + skew) {
    throw new ContinuationAssertionError("invalid_request", "continuation assertion is not yet valid (nbf)");
  }
}

/**
 * Validate an ICA presented as an RFC 8693 subject token. `audience` MUST be
 * the AS issuer identifier (the token-exchange endpoint's own identity), NOT
 * `${issuer}/token`. `presenterJkt` is the DPoP proof thumbprint that the ICA's
 * `cnf.jkt` MUST equal (sender-constraint), and `replay` the cache whose `jti`
 * check it applies. Both are optional, and `freshness: false` skips
 * {@link checkContinuationFreshness}, for a caller that runs those checks at its
 * own rule positions: the continuation exchange checks the presenter key after
 * well-formedness, and freshness and replay after chain state (@spec
 * id-continuation-assertion, ICA -02 5.5.6).
 */
export async function validateContinuationAssertion(
  assertion: string,
  ctx: {
    audience: string;
    issuers: ContinuationIssuer[];
    presenterJkt?: string;
    replay?: ReplayCache;
    freshness?: boolean;
  },
): Promise<ValidatedContinuation> {
  // 1. Locate the issuer by the assertion's iss (unverified payload peek).
  let unverified: Record<string, unknown>;
  try {
    unverified = JSON.parse(Buffer.from(assertion.split(".")[1] ?? "", "base64url").toString());
  } catch {
    throw new ContinuationAssertionError("invalid_request", "malformed continuation assertion");
  }
  const issuer = ctx.issuers.find((i) => i.iss === unverified.iss);
  if (!issuer) {
    throw new ContinuationAssertionError("invalid_grant", "unknown continuation issuer");
  }

  // 2. Verify the signature over an allowlisted asymmetric alg. Unlike
  // jwtVerify, compactVerify checks no time claim: freshness is step 9.
  let payload: Record<string, unknown>;
  let header: Record<string, unknown>;
  try {
    const jwks = createLocalJWKSet({ keys: issuer.jwks.keys } as never);
    const result = await compactVerify(assertion, jwks as never, { algorithms: CONTINUATION_ALGS });
    header = result.protectedHeader as Record<string, unknown>;
    const parsed: unknown = JSON.parse(new TextDecoder().decode(result.payload));
    if (!isPlainObject(parsed)) throw new Error("the claims set is not a JSON object");
    payload = parsed;
  } catch (e) {
    throw new ContinuationAssertionError(
      "invalid_grant",
      `continuation assertion verification failed: ${(e as Error).message}`,
    );
  }

  // 3. The header typ, the issuer, and the audience (the AS issuer identifier).
  if (header.typ !== IDENTITY_CONTINUATION_JWT_TYP) {
    throw new ContinuationAssertionError("invalid_request", "wrong assertion typ");
  }
  if (payload.iss !== issuer.iss) {
    throw new ContinuationAssertionError("invalid_grant", "continuation assertion iss mismatch");
  }
  // @spec id-continuation-assertion — `aud` is "a single string exactly
  // matching the IdP issuer identifier" (ICA -02 3.2), so an array is refused
  // even when it holds that identifier.
  if (typeof payload.aud !== "string") {
    throw new ContinuationAssertionError("invalid_request", "continuation assertion aud MUST be a single string");
  }
  if (payload.aud !== ctx.audience) {
    throw new ContinuationAssertionError("invalid_grant", "continuation assertion aud is not this AS");
  }

  // 4. iat and exp are NumericDate numbers, and so is any nbf.
  const iat = payload.iat;
  const exp = payload.exp;
  const nbf = payload.nbf;
  if (typeof iat !== "number" || typeof exp !== "number") {
    throw new ContinuationAssertionError("invalid_grant", "continuation assertion missing iat/exp");
  }
  if (nbf !== undefined && typeof nbf !== "number") {
    throw new ContinuationAssertionError("invalid_grant", "continuation assertion nbf is not a NumericDate");
  }

  // 5. cnf MUST contain EXACTLY jkt, and cnf.jkt MUST equal the presenter key.
  const cnf = payload.cnf;
  if (!isPlainObject(cnf) || Object.keys(cnf).length !== 1 || typeof cnf.jkt !== "string") {
    throw new ContinuationAssertionError(
      "invalid_grant",
      "continuation assertion cnf MUST contain exactly jkt",
    );
  }
  // An ICA is definitionally DPoP-bound: the sender-constraint is unconditional
  // (applied here, or by the caller that omitted presenterJkt).
  if (ctx.presenterJkt !== undefined && cnf.jkt !== ctx.presenterJkt) {
    throw new ContinuationAssertionError(
      "invalid_request",
      "presenter key does not match assertion cnf.jkt",
    );
  }

  // 6. identity_continuation_handle: 22-256 base64url chars.
  const handle = payload.identity_continuation_handle;
  if (
    typeof handle !== "string" ||
    handle.length < 22 ||
    handle.length > 256 ||
    !BASE64URL.test(handle)
  ) {
    throw new ContinuationAssertionError(
      "invalid_grant",
      "identity_continuation_handle is missing or malformed",
    );
  }

  // 7. No identity/authorization claims: reject any forbidden top-level claim.
  for (const claim of FORBIDDEN_CLAIMS) {
    if (claim in payload) {
      throw new ContinuationAssertionError(
        "invalid_grant",
        `continuation assertion MUST NOT carry ${claim}`,
      );
    }
  }

  // 8. act: a single-level {iss, sub}; no nested act or per-hop authority members.
  const act = payload.act;
  if (!isPlainObject(act)) {
    throw new ContinuationAssertionError("invalid_grant", "continuation assertion missing act");
  }
  if (typeof act.iss !== "string" || act.iss.length === 0) {
    throw new ContinuationAssertionError("invalid_grant", "act missing non-empty iss");
  }
  if (typeof act.sub !== "string" || act.sub.length === 0) {
    throw new ContinuationAssertionError("invalid_grant", "act missing non-empty sub");
  }
  for (const member of FORBIDDEN_ACT_MEMBERS) {
    if (member in act) {
      throw new ContinuationAssertionError("invalid_grant", `act MUST NOT carry ${member}`);
    }
  }

  const jti = payload.jti;
  if (typeof jti !== "string" || jti === "") {
    throw new ContinuationAssertionError("invalid_grant", "continuation assertion missing jti");
  }

  // 9. Freshness (ICA -02 5.5.3 rule 6), unless the caller applies it.
  if (ctx.freshness !== false) {
    checkContinuationFreshness({ iat, exp, ...(nbf !== undefined ? { nbf } : {}) });
  }

  // 10. Single-use jti (per iss): CHECK ONLY.
  //
  // @spec issuance-grant#effective-set-projection (#617 review 1) —
  // "consumption is atomic with issuance". Validation checks the `jti` is
  // unseen; RECORDING belongs to the caller, once the Mission gate admits and
  // before the grant is signed (`recordOnce` in continuation-grant.ts).
  // Recording here (the prior behavior) consumed a single-use assertion on
  // EVERY later failure, including a transient authority-source outage and a
  // Mission gate refusal that a retry would pass, permanently burning a
  // credential whose authorization was intact.
  if (ctx.replay?.seen(issuer.iss, jti)) {
    throw new ContinuationAssertionError("invalid_grant", "assertion replay");
  }

  return {
    iss: issuer.iss,
    aud: ctx.audience,
    handle,
    act: { iss: act.iss, sub: act.sub },
    cnf: { jkt: cnf.jkt },
    iat,
    exp,
    ...(nbf !== undefined ? { nbf } : {}),
    jti,
  };
}
