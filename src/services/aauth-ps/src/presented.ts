import {
  type JwksResolver,
  jwkThumbprint,
  SignatureError,
  type VerifiedToken,
  verifyAuthToken,
  verifyPersonToken,
} from "@mission/aauth-wire";

/** A token-endpoint refusal: an AAuth error code with its HTTP status. */
export class PsError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly detail: string,
    readonly extra: Record<string, unknown> = {},
  ) {
    super(`${code}: ${detail}`);
    this.name = "PsError";
  }
}

const invalidPresented = (detail: string) => new PsError(400, "invalid_presented_token", detail);
const invalidResource = (detail: string) => new PsError(400, "invalid_resource_token", detail);

function headerTyp(jwt: string): unknown {
  try {
    const header = JSON.parse(Buffer.from(jwt.split(".")[0] ?? "", "base64url").toString("utf8"));
    return (header as { typ?: unknown }).typ;
  } catch {
    return undefined;
  }
}

function payloadExp(jwt: string): number | undefined {
  try {
    const payload = JSON.parse(Buffer.from(jwt.split(".")[1] ?? "", "base64url").toString("utf8"));
    const exp = (payload as { exp?: unknown }).exp;
    return typeof exp === "number" ? exp : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The presented token verified by its `typ`, as a person token (Section
 * 7.1.4) or an auth token (Section 9.4.3), with the two substitutions:
 * `aud` must equal the resource token's `iss`, not this PS's identifier,
 * and `cnf.jwk` must match the resource token's `agent_jkt`, not the key
 * that signed the request. The resource's record check on `sub` does not
 * apply. Throws the library's {@link SignatureError}.
 */
async function verifyAsPresented(
  jwt: string,
  resourceToken: VerifiedToken,
  resolver: JwksResolver,
  nowMs: number,
): Promise<VerifiedToken> {
  const rt = resourceToken.payload;
  const options = { resolver, now: () => nowMs, audience: rt.iss as string };
  const typ = headerTyp(jwt);
  let token: VerifiedToken;
  if (typ === "aa-person+jwt") token = await verifyPersonToken(jwt, options);
  else if (typ === "aa-auth+jwt") token = await verifyAuthToken(jwt, options);
  else throw new SignatureError("invalid_jwt", "typ is neither a person token nor an auth token");
  const cnf = (token.payload.cnf as { jwk: Record<string, unknown> }).jwk;
  if ((await jwkThumbprint(cnf)) !== rt.agent_jkt) {
    throw new SignatureError(
      "invalid_jwt",
      "cnf.jwk does not match the resource token's agent_jkt",
    );
  }
  return token;
}

/**
 * AAuth -11 Section 6.7.2 step 3, first half: verify `presented_token`.
 * A failure is `invalid_presented_token`, or `expired_presented_token`
 * when only `exp` fails: an expired token is verified again at a clock
 * just before its `exp`, and only a token that then passes every other
 * check is reported as expired.
 *
 * @spec aauth#section-6.7.2
 * @spec aauth#section-11.9.3
 */
export async function verifyPresentedToken(
  jwt: string,
  resourceToken: VerifiedToken,
  resolver: JwksResolver,
  nowMs: number,
): Promise<VerifiedToken> {
  try {
    return await verifyAsPresented(jwt, resourceToken, resolver, nowMs);
  } catch (err) {
    if (!(err instanceof SignatureError)) throw err;
    if (err.code === "expired_jwt") {
      const exp = payloadExp(jwt);
      if (exp !== undefined) {
        const onlyExp = await verifyAsPresented(
          jwt,
          resourceToken,
          resolver,
          (exp - 1) * 1000,
        ).then(
          () => true,
          () => false,
        );
        if (onlyExp)
          throw new PsError(400, "expired_presented_token", "the presented token has expired");
      }
    }
    throw invalidPresented(err.detail);
  }
}

/** Present on both with the same value, or absent from both. */
function sameOrBothAbsent(a: unknown, b: unknown): boolean {
  return a === b;
}

/**
 * AAuth -11 Section 6.7.2 step 3, second half: the verified presented
 * token against the resource token. `jti` must equal `presented_jti`; the
 * person token's `iss`, or the auth token's `ps`, must equal the resource
 * token's `ps`; `sub`, `mission_s256` and `tenant` must match exactly. Any
 * mismatch or omission is `invalid_resource_token`.
 *
 * @spec aauth#section-6.7.2
 */
export function matchResourceToken(presented: VerifiedToken, resourceToken: VerifiedToken): void {
  const p = presented.payload;
  const r = resourceToken.payload;
  if (p.jti !== r.presented_jti)
    throw invalidResource("presented_jti does not name the presented token");
  const namedPs = presented.typ === "aa-person+jwt" ? p.iss : p.ps;
  if (namedPs !== r.ps)
    throw invalidResource("ps does not match the presented token's person server");
  if (p.sub !== r.sub) throw invalidResource("sub does not match the presented token");
  if (!sameOrBothAbsent(p.mission_s256, r.mission_s256)) {
    throw invalidResource("mission_s256 does not match the presented token");
  }
  if (!sameOrBothAbsent(p.tenant, r.tenant)) {
    throw invalidResource("tenant does not match the presented token");
  }
}
